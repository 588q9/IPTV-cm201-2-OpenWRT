"""官方资源到完整根系统与动态安装资料的离线流水线。"""
import gzip
import hashlib
import json
from pathlib import PurePosixPath
import posixpath
import re
import shlex
import stat
import uuid

from .archives import Entry, cpio_bytes, read_tar_bytes, tar_bytes
from .compiler import compile_all, elf_info
from .images import check_boot, gz, make_boot, make_bundle, sha256
from .hardware import MODULES, FIRMWARE, validate_support
from .layout import bootargs_map
from .profile import geometry_from_log
from .resources import read_lock, verify_resource
from .serial_link import Link

CMDLINE = 'mem=1G mmz=ddr,0,0,48M vmalloc=500M console=ttyAMA0,115200 lpj=974848 loglevel=7 init=/init '


def required_ram_kib(root_bytes, resource_bytes):
    return (2 * root_bytes + resource_bytes + 64 * 1048576 + 1023) // 1024


def require_space(available, required):
    if available < required:
        raise ValueError(f'RAM 空间不足：可用 {available}KiB，需要 {required}KiB')


def locked_packages(locks):
    packages = []
    for name, item in locks.items():
        if item['path'].endswith('.apk'):
            if not re.fullmatch(r'[a-z][a-z0-9+_.-]*', name) or not re.fullmatch(r'[A-Za-z0-9~_.:+-]+', item['version']):
                raise ValueError('APK 名称或版本不能作为固定安装参数')
            packages.append(name + '=' + item['version'])
    return packages


def strip_runtime(entries):
    private = ('etc/dropbear/', 'root/.ssh/', 'tmp/', 'proc/', 'sys/', 'dev/')
    files = {'etc/uhttpd.key', 'etc/uhttpd.crt', 'etc/urandom.seed', 'etc/board.json'}
    return {name: value for name, value in entries.items()
            if name not in files and not any(name.startswith(prefix) for prefix in private)}


def validate_accounts(passwd):
    accounts = {}
    for line in passwd.splitlines():
        fields = line.split(':')
        if len(fields) == 7:
            accounts[fields[0]] = (fields[2], fields[3])
    if accounts.get('network') != ('101', '101') or accounts.get('ubus') != ('81', '81'):
        raise ValueError('服务账户 UID/GID 不符合锁定原根')


def resolve_file(entries, name, executable=False):
    seen = set()
    for _ in range(40):
        if name in seen or name not in entries:
            raise ValueError('关键链接缺失或循环：' + name)
        seen.add(name)
        entry = entries[name]
        if stat.S_ISLNK(entry.mode):
            target = entry.data.decode()
            name = posixpath.normpath(target.lstrip('/') if target.startswith('/') else
                                      posixpath.join(posixpath.dirname(name), target))
            if name == '..' or name.startswith('../'):
                raise ValueError('关键链接越过根目录')
            continue
        if not stat.S_ISREG(entry.mode) or not entry.data or executable and not entry.mode & 0o111:
            raise ValueError('关键文件类型、长度或执行权限错误：' + name)
        return entry
    raise ValueError('关键链接过深')


def validate_program(entries, name, visited=None, executable=True):
    visited = set() if visited is None else visited
    entry = resolve_file(entries, name, executable=executable)
    if name in visited:
        return
    visited.add(name)
    if entry.data.startswith(b'#!'):
        interpreter = shlex.split(entry.data.split(b'\n', 1)[0][2:].decode())[0]
        if not interpreter.startswith('/'):
            raise ValueError('脚本解释器不是绝对路径：' + name)
        validate_program(entries, interpreter.lstrip('/'), visited)
    else:
        info = elf_info(entry.data)
        if info['interpreter']:
            validate_program(entries, info['interpreter'].lstrip('/'), visited)
        for needed in info['needed']:
            for directory in ('lib', 'usr/lib'):
                candidate = directory + '/' + needed
                if candidate in entries:
                    validate_program(entries, candidate, visited, executable=False)
                    break
            else:
                raise ValueError('缺少动态依赖：' + name + ' → ' + needed)


def validate_root(entries):
    needed = ('sbin/init', 'sbin/ubusd', 'usr/sbin/hostapd', 'usr/sbin/uhttpd',
              'usr/sbin/dnsmasq', 'etc/init.d/cm2012-ap', 'etc/cm2012/hostapd.conf',
              'lib/modules/3.18.24_hi3798mv2x/wlan_mt7668_sdio.ko')
    for name in needed:
        resolve_file(entries, name)
    if entries.get('etc/cm2012-internal-root', Entry(0)).data != b'CM2012_INTERNAL_OPENWRT25\n':
        raise ValueError('根系统完成标识缺失')
    for name in needed[:6]:
        validate_program(entries, name)
    validate_accounts(entries.get('etc/passwd', Entry(0)).data.decode())
    validate_support(entries, 'lib/modules/3.18.24_hi3798mv2x/', 'lib/firmware/')


def check_device(link, config):
    output = link.command('uname -r; dmesg | grep "nand: Block:"').replace('\r', '')
    if not re.search(r'(?m)^3\.18\.24_hi3798mv2x$', output):
        raise ValueError('盒子内核不是已验证版本')
    geometry = geometry_from_log(output)
    if geometry['total_bytes'] != config['profile']['total_bytes']:
        raise ValueError('物理 NAND 容量与原厂分区表不一致')
    sizes = link.command('for e in /sys/class/mtd/mtd*; do n=${e##*mtd}; case "$n" in *[!0-9]*|"") continue;; esac; printf "CM_SIZE "; cat "$e/size"; done')
    values = list(map(int, re.findall(r'(?m)^CM_SIZE (\d+)\r*$', sizes)))
    if not values or sum(values) != geometry['total_bytes']:
        raise ValueError('当前内核 MTD 物理总长度与容量不符')
    apk = link.command('apk --version')
    if 'apk-tools 3.0.5, compiled for armv7.' not in apk:
        raise ValueError('需要 apk 3.0.5 ARMv7；原厂 Android 请先启动 bootstrap RAM 环境')
    return geometry


def active_snapshot(link):
    result = link.command('sha256sum /lib/apk/db/installed /etc/config/network /etc/cm2012/hostapd.conf; pidof procd ubusd hostapd dnsmasq').replace('\r', '')
    hashes = re.findall(r'(?m)^([0-9a-f]{64})\s+(\S+)$', result)
    pids = re.findall(r'(?m)^[0-9]+(?: [0-9]+)*$', result)
    return hashes, pids


def make_seed(root, stock, config):
    locks = read_lock(root)
    official = read_tar_bytes(verify_resource(root, locks['openwrt-rootfs']).read_bytes())
    seed = {n: e for n, e in strip_runtime(official).items() if not any(
            n == prefix or n.startswith(prefix + '/') for prefix in
            ('lib/modules', 'etc/modules.d', 'etc/modules-boot.d'))}
    support = read_tar_bytes(stock['support'])
    validate_support(support)
    modules = set(MODULES)
    for name, entry in support.items():
        filename = PurePosixPath(name).name
        if name.startswith('system/lib/modules/') and filename in modules:
            seed[name] = entry
            seed['lib/modules/3.18.24_hi3798mv2x/' + filename] = entry
        elif name.startswith('system/etc/firmware/') and filename in FIRMWARE:
            seed[name] = entry
            seed['lib/firmware/' + filename] = entry
    for filename in modules:
        if 'lib/modules/3.18.24_hi3798mv2x/' + filename not in seed:
            raise ValueError('缺少原厂模块：' + filename)
    seed['etc/inittab'] = Entry(stat.S_IFREG | 0o644,
        b'::sysinit:/etc/init.d/rcS S boot\n::shutdown:/etc/init.d/rcS K shutdown\nttyAMA0::askfirst:/usr/libexec/login.sh\n')
    seed['etc/config/network'] = Entry(stat.S_IFREG | 0o644,
        b"config interface 'loopback'\n\toption device 'lo'\n\toption proto 'static'\n\tlist ipaddr '127.0.0.1/8'\n")
    shadow = official['etc/shadow'].data.decode().splitlines()
    shadow = [f"root:{config['root_hash']}:0:0:99999:7:::" if s.startswith('root:') else s for s in shadow]
    seed['etc/shadow'] = Entry(stat.S_IFREG | 0o600, ('\n'.join(shadow) + '\n').encode())
    return read_tar_bytes(tar_bytes(seed))


def make_overlay(root, config, binaries):
    overlay = {'sbin/ubusd': Entry(stat.S_IFREG | 0o755, binaries['ubusd'].read_bytes())}
    for source, target, mode in (
        ('cm2012-ap', 'etc/init.d/cm2012-ap', 0o755),
        ('cm2012-ap-dhcp', 'usr/libexec/cm2012-ap-dhcp', 0o755),
        ('dnsmasq-ap.conf', 'etc/cm2012/dnsmasq-ap.conf', 0o600),
        ('hostapd.conf', 'etc/cm2012/hostapd.conf', 0o600)):
        data = (root / 'configs/templates' / source).read_text(encoding='utf-8')
        values = {'SSID': config['ssid'], 'PASSWORD': config['ap_password']}
        data = re.sub(r'\{\{(SSID|PASSWORD)\}\}', lambda match: values[match.group(1)], data)
        overlay[target] = Entry(stat.S_IFREG | mode, data.encode())
    return read_tar_bytes(tar_bytes(overlay))


def ram_entries_for(entries):
    result = dict(entries)
    result['init'] = Entry(stat.S_IFREG | 0o755,
        b'#!/bin/sh\nexport INITRAMFS=1\necho CM2012_PUBLIC_RAM_BOOT\nexec /sbin/init\n')
    for name, major, minor in (('console', 5, 1), ('ttyAMA0', 204, 64), ('null', 1, 3), ('zero', 1, 5), ('kmsg', 1, 11)):
        result['dev/' + name] = Entry(stat.S_IFCHR | 0o600, b'', major=major, minor=minor)
    return result


def assemble_outputs(root, config, stock, binaries, entries, output):
    entries = strip_runtime(entries)
    validate_root(entries)
    for directory in ('dev', 'proc', 'sys', 'tmp', 'mnt', 'overlay'):
        entries[directory] = Entry(stat.S_IFDIR | (0o1777 if directory == 'tmp' else 0o755))
    archive = tar_bytes(entries)
    # 内部启动仅包含最小维护根，完整用户空间存入大 userdata。
    minimal = {n: entries[n] for n in ('bin/busybox', 'lib/libc.so', 'lib/libgcc_s.so.1')}
    for directory in ('bin', 'sbin', 'lib', 'dev', 'proc', 'sys', 'tmp', 'newroot'):
        minimal[directory] = Entry(stat.S_IFDIR | 0o755)
    for name in ('sh', 'mount', 'mkdir', 'mknod', 'sleep', 'cat', 'readlink'):
        minimal['bin/' + name] = Entry(stat.S_IFLNK | 0o777, b'busybox')
    minimal['lib/ld-musl-armhf.so.1'] = Entry(stat.S_IFLNK | 0o777, b'libc.so')
    minimal['init'] = Entry(stat.S_IFREG | 0o755, (root / 'tools/internal-root-init').read_bytes().replace(b'\r\n', b'\n'))
    minimal['bin/cm2012-switch-root'] = Entry(stat.S_IFREG | 0o755, binaries['cm2012-switch-root'].read_bytes())
    for name, major, minor in (('console', 5, 1), ('ttyAMA0', 204, 64), ('null', 1, 3), ('zero', 1, 5), ('kmsg', 1, 11)):
        minimal['dev/' + name] = Entry(stat.S_IFCHR | 0o600, b'', major=major, minor=minor)
    internal_ram = gz(cpio_bytes(minimal))
    internal_boot = make_boot(stock['boot'], internal_ram, CMDLINE)
    files, manifest = make_bundle(internal_boot, stock, config['profile'])
    ram = gz(cpio_bytes(ram_entries_for(entries)))
    files.update({'rootfs.tar.gz': archive, 'internal.cpio.gz': internal_ram, 'ram.cpio.gz': ram})
    # 迁移的是自己的原厂硬件参数；不包含原厂 Android 根系统。
    misc, swdev = gzip.decompress(stock['misc'])[:2097152], gzip.decompress(stock['swdevinfo'])
    if len(misc) != 2097152 or len(swdev) != 16777216:
        raise ValueError('核心迁移资料长度不正确')
    files['misc.bin.gz'], files['swdevinfo.bin.gz'] = gz(misc), gz(swdev)
    manifest['files'] = {name: {'size': len(data), 'sha256': sha256(data)} for name, data in files.items()}
    manifest['core_uncompressed'] = {'misc': {'size': len(misc), 'sha256': sha256(misc)},
                                     'swdevinfo': {'size': len(swdev), 'sha256': sha256(swdev)}}
    manifest['resource_lock_sha256'] = sha256((root / 'resources.lock.json').read_bytes())
    manifest['ram_bootargs'] = CMDLINE + 'mtdparts=hinand:' + bootargs_map(config['profile']['total_bytes'])
    from .installer import install_archive
    files['install-resources.tar.gz'] = install_archive(root, manifest, files, binaries)
    manifest['files']['install-resources.tar.gz'] = {'size': len(files['install-resources.tar.gz']),
                                                   'sha256': sha256(files['install-resources.tar.gz'])}
    output.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (output / name).write_bytes(data)
    (output / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8', newline='\n')
    verify_output(output, config, stock)
    return manifest


def verify_output(output, config, stock):
    manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
    required = {'boot.img', 'ptable.bin', 'mlcverify.bin', 'baseparam.bin', 'baseparam2.bin',
                'rootfs.tar.gz', 'internal.cpio.gz', 'ram.cpio.gz',
                'misc.bin.gz', 'swdevinfo.bin.gz', 'install-resources.tar.gz'}
    if set(manifest['files']) != required:
        raise ValueError('输出清单缺少必需产物或包含未知产物')
    for name, info in manifest['files'].items():
        if PurePosixPath(name).name != name:
            raise ValueError('输出清单文件名越界')
        data = (output / name).read_bytes()
        if len(data) != info['size'] or sha256(data) != info['sha256']:
            raise ValueError('输出文件被修改：' + name)
    if manifest['geometry']['total_bytes'] != config['profile']['total_bytes']:
        raise ValueError('输出容量与原厂档案不一致')
    check_boot((output / 'boot.img').read_bytes(), stock['boot'])
    files, expected = make_bundle((output / 'boot.img').read_bytes(), stock, config['profile'])
    for field in ('format', 'geometry', 'partitions', 'preserved_fastboot_sha256'):
        if manifest[field] != expected[field]:
            raise ValueError('输出清单字段不一致：' + field)
    for name, data in files.items():
        if (output / name).read_bytes() != data:
            raise ValueError('输出启动表或核心参数不一致：' + name)
    entries = read_tar_bytes((output / 'rootfs.tar.gz').read_bytes())
    validate_root(entries)
    ram = gz(cpio_bytes(ram_entries_for(entries)))
    if (output / 'ram.cpio.gz').read_bytes() != ram:
        raise ValueError('RAM 镜像与完整根归档不一致')
    if (output / 'boot.img').read_bytes() != make_boot(stock['boot'], (output / 'internal.cpio.gz').read_bytes(), CMDLINE):
        raise ValueError('内部维护根与 boot 镜像不一致')
    for name, original in (('misc', gzip.decompress(stock['misc'])[:2097152]), ('swdevinfo', gzip.decompress(stock['swdevinfo']))):
        if gzip.decompress((output / (name + '.bin.gz')).read_bytes()) != original:
            raise ValueError('核心参数与原厂来源不一致：' + name)
    print('完整产物校验通过：' + str(output), flush=True)
    return manifest


def build(root, config, stock, output):
    from .offline import forbid_network
    forbid_network()
    binaries = compile_all(root)
    seed = make_seed(root, stock, config)
    overlay = make_overlay(root, config, binaries)
    payload = {'seed.tar.gz': Entry(stat.S_IFREG | 0o600, tar_bytes(seed)),
               'overlay.tar.gz': Entry(stat.S_IFREG | 0o600, tar_bytes(overlay)),
               'build-job': Entry(stat.S_IFREG | 0o700, (root / 'tools/cm2012/device/build-job').read_bytes())}
    locks = read_lock(root)
    packages = locked_packages(locks)
    apk_bytes = 0
    for name, item in locks.items():
        if '/apk/' in item['path']:
            data = verify_resource(root, item).read_bytes()
            payload['apk/' + PurePosixPath(item['path']).name] = Entry(stat.S_IFREG | 0o600, data)
            apk_bytes += len(data)
    payload['packages.list'] = Entry(stat.S_IFREG | 0o600, ('\n'.join(packages) + '\n').encode())
    payload = read_tar_bytes(tar_bytes(payload))
    packed = tar_bytes(payload)
    required = required_ram_kib(sum(len(e.data) for e in seed.values()) + apk_bytes * 16, len(packed))
    job = '/tmp/cm2012-build-' + uuid.uuid4().hex[:12]
    with Link(config['port']) as link:
        check_device(link, config)
        before = active_snapshot(link)
        free = link.command('df -k /tmp').replace('\r', '')
        available = int(re.search(r'(?m)^tmpfs\s+\d+\s+\d+\s+(\d+)', free).group(1))
        require_space(available, required)
        link.command('mkdir ' + job)
        helper = job + '/serial-transfer'
        link.put_small(helper, binaries['serial-transfer'].read_bytes(), 0o700)
        link.upload(helper, job + '/payload.tar.gz', packed)
        link.command(f'tar -xzf {job}/payload.tar.gz -C {job}')
        # 后台作业保留诊断，短轮询避免串口命令长时间阻塞。
        link.command(f'(sh {job}/build-job {job} {required} >{job}/job.log 2>&1; echo $? >{job}/status) </dev/null >/dev/null 2>&1 &')
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
    entries = read_tar_bytes(archive)
    assemble_outputs(root, config, stock, binaries, entries, output)
    print('离线构建完成；本轮没有写入 NAND。诊断目录：' + job, flush=True)
