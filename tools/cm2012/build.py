"""官方资源到完整根系统与动态安装资料的离线流水线。"""
import re
import stat
import uuid

from .archives import Entry, read_tar_bytes, tar_bytes
from .compiler import compile_all
from .device_jobs import create_private_job
from .images import CMDLINE
from .hardware import MODULES, FIRMWARE, validate_support
from .elf import elf_info
from .rootfs import (strip_runtime, validate_accounts, resolve_file, validate_program,
                     validate_remote_root, validate_root, make_seed, make_overlay)
from .artifacts import ram_entries_for, assemble_outputs, verify_output
from .resources import read_lock
from .serial_link import Link


def required_ram_kib(root_bytes, resource_bytes):
    return (2 * root_bytes + resource_bytes + 64 * 1048576 + 1023) // 1024


def require_space(available, required):
    if available < required:
        raise ValueError(f'RAM 空间不足：可用 {available}KiB，需要 {required}KiB')


def check_device(link, config):
    output = link.command('uname -r').replace('\r', '')
    if not re.search(r'(?m)^3\.18\.24_hi3798mv2x$', output):
        raise ValueError('盒子内核不是已验证版本')
    actual = link.command('printf "CM_GEOMETRY "; for field in type erasesize writesize oobsize ecc_strength ecc_step_size; do cat /sys/class/mtd/mtd0/$field | tr "\\n" " "; done; echo').replace('\r', '')
    # 此固定原厂内核的 sysfs 报告 strength=60/step=1024；启动日志中的
    # “ECC:40bits/1K”属于另一报告口径，不能作为 sysfs 字段的预期值。
    if not re.search(r'(?m)^CM_GEOMETRY mlc-nand 2097152 8192 744 60 1024\s*$', actual):
        raise ValueError('NAND 类型、块/页/OOB/ECC 几何不兼容')
    sizes = link.command('for e in /sys/class/mtd/mtd*; do n=${e##*mtd}; case "$n" in *[!0-9]*|"") continue;; esac; printf "CM_SIZE "; cat "$e/size"; done')
    values = list(map(int, re.findall(r'(?m)^CM_SIZE (\d+)\r*$', sizes)))
    if not values or sum(values) != config['profile']['total_bytes']:
        raise ValueError('当前内核 MTD 物理总长度与容量不符')
    apk = link.command('apk --version')
    if 'apk-tools 3.0.5, compiled for armv7.' not in apk:
        raise ValueError('需要 apk 3.0.5 ARMv7；原厂 Android 请先启动 bootstrap RAM 环境')
    return {'total_bytes': sum(values), 'erase_bytes': 2097152, 'write_bytes': 8192,
            'oob_bytes': 744, 'mtd_ecc_strength': 60, 'mtd_ecc_step_bytes': 1024}


def active_snapshot(link):
    result = link.command('sha256sum /lib/apk/db/installed /etc/config/network; pidof procd ubusd hostapd dnsmasq').replace('\r', '')
    hashes = re.findall(r'(?m)^([0-9a-f]{64})\s+(\S+)$', result)
    pids = re.findall(r'(?m)^[0-9]+(?: [0-9]+)*$', result)
    return hashes, pids


def build(root, config, stock, output, *, ssh_host=None):
    from .offline import forbid_network
    forbid_network()
    binaries = compile_all(root)
    seed = make_seed(root, stock, config)
    overlay = make_overlay(root, config, binaries)
    payload = {'seed.tar.gz': Entry(stat.S_IFREG | 0o600, tar_bytes(seed)),
               'overlay.tar.gz': Entry(stat.S_IFREG | 0o600, tar_bytes(overlay)),
               'build-job': Entry(stat.S_IFREG | 0o700, (root / 'tools/cm2012/device/build-job').read_bytes())}
    locks = read_lock(root)
    from .remote_assets import apk_payload, asset_files
    package_files, apk_bytes = apk_payload(root, locks, seed)
    payload.update(package_files)
    payload = read_tar_bytes(tar_bytes(payload))
    packed = tar_bytes(payload)
    required = required_ram_kib(sum(len(e.data) for e in seed.values()) +
                               sum(len(e.data) for e in overlay.values()) + apk_bytes * 16, len(packed))
    job = '/tmp/cm2012-build-' + uuid.uuid4().hex[:12]
    if ssh_host:
        from .ssh_link import SSHLink
        transport = SSHLink(ssh_host)
    else:
        transport = Link(config['port'])
    with transport as link:
        check_device(link, config)
        before = active_snapshot(link)
        free = link.command('df -k /tmp').replace('\r', '')
        available = int(re.search(r'(?m)^tmpfs\s+\d+\s+\d+\s+(\d+)', free).group(1))
        require_space(available, required)
        create_private_job(link, job)
        helper = job + '/serial-transfer'
        if not ssh_host:
            from .installer import upload_helper
            upload_helper(link, helper, binaries['serial-transfer'].read_bytes())
        link.upload(helper, job + '/payload.tar.gz', packed)
        link.command(f'tar -xzf {job}/payload.tar.gz -C {job}')
        # 后台作业保留诊断，短轮询避免串口命令长时间阻塞。
        link.command(f'( (umask 077; : >{job}/job.log) && sh {job}/build-job {job} {required} >{job}/job.log 2>&1; result=$?; (umask 077; echo "$result" >{job}/status)) </dev/null >/dev/null 2>&1 &')
        import time
        for _ in range(120):
            status = link.command(f'if [ -f {job}/status ]; then printf "CM_STATUS "; cat {job}/status; else echo CM_PENDING; fi')
            match = re.search(r'CM_STATUS (\d+)', status)
            if match:
                if match.group(1) != '0':
                    raise RuntimeError('隔离构建失败；诊断保留在 ' + job + '\n' + link.command(f'tail -n 35 {job}/job.log'))
                break
            time.sleep(1)
        else:
            raise TimeoutError('构建作业超时；保留诊断：' + job)
        if active_snapshot(link) != before:
            raise ValueError('构建前后活动系统配置、包数据库或服务 PID 变化')
        print(link.command(f'tail -n 12 {job}/job.log').replace('\r', ''), flush=True)
        detail = link.command(f'cat {job}/result.size {job}/result.sha256').replace('\r', '')
        length = int(re.search(r'(?m)^(\d+)$', detail).group(1))
        digest = re.search(r'(?m)^([0-9a-f]{64})\s', detail).group(1)
        archive = link.download(helper, job + '/result.tar.gz', length, digest)
    from .runtime import prepare_root
    entries = prepare_root(read_tar_bytes(archive))
    entries.update(overlay)
    # 静态程序和 UI 只在主机合并，不占设备隔离 APK 作业的 RAM。
    entries.update(asset_files(root))
    assemble_outputs(root, config, stock, binaries, entries, output)
    print('离线构建完成；本轮没有写入 NAND。诊断目录：' + job, flush=True)
