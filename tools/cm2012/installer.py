"""生成本次安装环境与资源包，不执行安装阶段。"""
import re
import stat
import json
import time
import uuid
import gzip
import io
import struct
import hashlib

from .archives import Entry, tar_bytes
from .images import sha256
from .layout import bootargs_map, layout_for

RAM_CHECKS = ('nand-readonly', 'hostapd-enabled', 'nat-rules', 'rpc-present',
              'standard-leases', 'single-wifi-owner')


def retained_boot_layout(header, ram, expected_ram, stock_boot):
    from .archives import read_cpio_bytes
    from .images import kernel_from
    from .build import CMDLINE
    if (len(header) != 2048 or header[:8] != b'ANDROID!' or
            struct.unpack_from('<I', header, 36)[0] != 2048 or
            header[64:576].split(b'\0')[0] != CMDLINE.encode()):
        raise ValueError('保留 boot 的格式或启动入口不兼容')
    kernel = kernel_from(stock_boot)
    size = struct.unpack_from('<I', header, 8)[0]
    ram_size = struct.unpack_from('<I', header, 16)[0]
    if (size != len(kernel) or not 0 < ram_size <= 4 * 1048576 or len(ram) != ram_size or
            struct.unpack_from('<I', header, 24)[0] or struct.unpack_from('<I', header, 40)[0]):
        raise ValueError('保留 boot 的内容长度不兼容')
    digest = hashlib.sha1()
    for data in (kernel, ram, b''):
        digest.update(data); digest.update(struct.pack('<I', len(data)))
    if header[576:608] != digest.digest().ljust(32, b'\0'):
        raise ValueError('保留 boot 的内容摘要不匹配')
    def unpack(data):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                raw = stream.read(16 * 1048576 + 1)
            return read_cpio_bytes(raw)
        except (OSError, EOFError) as error:
            raise ValueError('保留 boot 的维护根损坏') from error
    actual, expected = unpack(ram), unpack(expected_ram)
    # 已部署的同一维护入口可能多一个 BusyBox 标准链接，内容仍逐项一致。
    extra = actual.pop('bin/switch_root', None) if 'bin/switch_root' not in expected else None
    if extra is not None and extra != Entry(stat.S_IFLNK | 0o777, b'busybox'):
        raise ValueError('保留 boot 有未知切根程序')
    if actual != expected:
        raise ValueError('保留 boot 的维护根与已验证入口不一致')
    length = 2048 + ((size + 2047) // 2048 + (ram_size + 2047) // 2048) * 2048
    if length > 12 * 1048576:
        raise ValueError('保留 boot 超过分区边界')
    return length


def inspect_retained_boot(link, job, helper, output, stock):
    """只读核对真正的 ptable、内核与维护根，再绑定本次保留 boot 摘要。"""
    def fetch(path):
        detail = link.command('wc -c <' + path + '; sha256sum ' + path).replace('\r', '')
        size = int(re.findall(r'(?m)^(\d+)$', detail)[-1])
        digest = re.findall(r'(?m)^([0-9a-f]{64})\s', detail)[-1]
        data = link.download(helper, path, size, digest)
        # 传输后清除可能残留在控制台编辑缓冲的字节。
        link.wire.write(b'\x15\r')
        time.sleep(.2)
        link.wire.reset_input_buffer()
        return data
    expected_table = sha256((output / 'ptable.bin').read_bytes())
    table = link.command('for skip in 0 512; do dd if=/dev/mtd1 bs=8192 skip=$skip count=1 2>/dev/null | head -c 2832 | sha256sum; done', 30)
    if re.findall(r'(?m)^([0-9a-f]{64})\s', table.replace('\r', '')) != [expected_table] * 2:
        raise ValueError('持久分区表不是本项目九分区布局，拒绝 userdata 重装')
    header_path = job + '/retained-header.bin'
    link.command('head -c 2048 /dev/mtd7 >' + header_path)
    header = fetch(header_path)
    if len(header) != 2048 or header[:8] != b'ANDROID!' or struct.unpack_from('<I', header, 36)[0] != 2048:
        raise ValueError('保留 boot 头不兼容')
    ksize = struct.unpack_from('<I', header, 8)[0]
    rsize = struct.unpack_from('<I', header, 16)[0]
    if not 0 < ksize < 12 * 1048576 or not 0 < rsize <= 4 * 1048576:
        raise ValueError('保留 boot 长度越界')
    from .images import kernel_from
    kernel_sha = sha256(kernel_from(stock['boot']))
    reply = link.command(f'dd if=/dev/mtd7 bs=2048 skip=1 count={(ksize + 2047) // 2048} 2>/dev/null | head -c {ksize} | sha256sum', 30)
    if not re.search(r'(?m)^' + kernel_sha + r'\s', reply.replace('\r', '')):
        raise ValueError('保留 boot 内核与原厂输入不一致')
    ram_path = job + '/retained-ram.gz'
    skip = 1 + (ksize + 2047) // 2048
    link.command(f'dd if=/dev/mtd7 bs=2048 skip={skip} count={(rsize + 2047) // 2048} 2>/dev/null | head -c {rsize} >' + ram_path, 30)
    size = retained_boot_layout(header, fetch(ram_path), (output / 'internal.cpio.gz').read_bytes(), stock['boot'])
    digest = link.command(f'head -c {size} /dev/mtd7 | sha256sum', 30)
    digest = re.findall(r'(?m)^([0-9a-f]{64})\s', digest.replace('\r', ''))[-1]
    print('持久分区表、保留内核与内部维护根只读核对通过', flush=True)
    return size, digest


def root_digest(entries):
    lines = []
    for name, entry in sorted(entries.items()):
        if any(c in name for c in '\r\n\\\0'):
            raise ValueError('摘要清单文件名不安全')
        if stat.S_ISREG(entry.mode):
            lines.append(sha256(entry.data) + '  ' + name)
    return ('\n'.join(lines) + '\n').encode()


def upload_helper(link, target, data):
    digest = sha256(data)
    candidates = link.command('for p in /usr/libexec/cm2012-serial-transfer /tmp/cm2012-build-*/serial-transfer; do [ ! -f "$p" ] || sha256sum "$p"; done')
    for candidate in re.findall(r'(?m)^' + digest + r'\s+(/[^\s]+)\r*$', candidates):
        if re.fullmatch(r'/tmp/cm2012-build-[a-z0-9]+/serial-transfer|/usr/libexec/cm2012-serial-transfer', candidate):
            link.command('cp ' + candidate + ' ' + target + '; chmod 700 ' + target)
            return
    link.put_small(target, data, 0o700)


def record_ram_acceptance(config, output):
    from .serial_link import Link
    expected = 'mtdparts=hinand:' + bootargs_map(config['profile']['total_bytes'])
    with Link(config['port']) as link:
        link.command('dmesg -n 1')
        cmdline = link.command('cat /proc/cmdline')
        if expected not in cmdline:
            raise ValueError('RAM 验收必须全部 NAND 只读')
        link.command('(test "$(grep -c \'^mtd[0-9]\' /proc/mtd)" = 9 && ! grep -q " / ubifs " /proc/mounts && for n in 0 1 2 3 4 5 6 7 8; do test "$(cat /sys/class/mtd/mtd$n/flags)" = 0x0 || exit 1; done)')
        for _ in range(120):
            ap = link.command('ubus call hostapd.ap0 get_status 2>/dev/null || true')
            if 'ENABLED' in ap:
                break
            time.sleep(1)
        else:
            raise ValueError('热点没有进入 ENABLED；保留 RAM 环境诊断')
        link.command('(for p in dnsmasq hostapd ntpd; do pidof "$p" >/dev/null || exit 1; done)')
        proof = link.command('iptables -t nat -S; ubus -v list cm2012')
        if 'MASQUERADE' not in proof or '"apply"' not in proof:
            raise ValueError('RAM 防火墙或 RPC 基础检查失败')
        link.command('test "$(uci -q get dhcp.main.leasefile)" = /tmp/dhcp.leases && test ! -e /etc/rc.d/S19wpad')
    receipt = {'manifest_sha256': sha256((output / 'manifest.json').read_bytes()),
               'checks': list(RAM_CHECKS)}
    (output / 'ram-acceptance.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print('NAND 只读 RAM 基础检查通过；继续进行真实网络与页面验收', flush=True)


def install(root, config, stock, output, *, erase_internal_root=False):
    if erase_internal_root is not True:
        raise ValueError('安装必须指定 --erase-internal-root')
    from .build import verify_output
    from .ram import ram_test, restore_internal
    from .serial_link import Link
    verify_output(output, config, stock)
    receipt = json.loads((output / 'ram-acceptance.json').read_text(encoding='utf-8'))
    if (receipt.get('manifest_sha256') != sha256((output / 'manifest.json').read_bytes()) or
            receipt.get('checks') != list(RAM_CHECKS)):
        raise ValueError('当前产物没有匹配的只读 RAM 验收记录')
    from .archives import read_tar_bytes
    entries = read_tar_bytes((output / 'rootfs.tar.gz').read_bytes())
    helper_data = entries['usr/libexec/cm2012-serial-transfer'].data
    probe = '/tmp/cm2012-build-' + uuid.uuid4().hex[:12]
    with Link(config['port']) as link:
        link.command('mkdir ' + probe)
        helper = probe + '/serial-transfer'
        upload_helper(link, helper, helper_data)
        retained_size, retained_sha = inspect_retained_boot(link, probe, helper, output, stock)
    # 显式安装入口才开放维护映射；不修改永久 bootargs 或引导分区。
    ram_test(root, config, stock, output, installation=True)
    bundle = (output / 'install-resources.tar.gz').read_bytes()
    job = '/tmp/cm2012-build-' + uuid.uuid4().hex[:12]
    with Link(config['port']) as link:
        link.command('dmesg -n 1')
        link.command('mkdir ' + job)
        helper = job + '/serial-transfer'
        upload_helper(link, helper, helper_data)
        link.upload(helper, job + '/install.tar.gz', bundle)
        link.command('tar -xzf ' + job + '/install.tar.gz -C ' + job)
        stage = job + '/cm2012-install/install-stage'
        # 校验与格式化各自保留日志，永远不调 core/boot/mlc/ptable。
        link.command(f'((sh {stage} check && sh {stage} root CM2012_ERASE_INTERNAL_ROOT {retained_size} {retained_sha}) >{job}/install.log 2>&1; echo $? >{job}/status) </dev/null >/dev/null 2>&1 &')
        for attempt in range(600):
            result = link.command(f'if [ -f {job}/status ]; then cat {job}/status; else echo CM_PENDING; fi')
            if not re.search(r'(?m)^CM_PENDING\r*$', result): break
            time.sleep(1)
            if attempt % 30 == 0:
                print('userdata 安装进行中；串口日志目录：' + job, flush=True)
        else:
            raise TimeoutError('安装未结束；留在 RAM 环境检查 ' + job)
        status = link.command('cat ' + job + '/status')
        if not re.search(r'(?m)^0\r*$', status):
            raise RuntimeError('重装失败；仍留在串口 RAM 环境。日志：' + job + '/install.log')
        print('userdata 全新根系统已写入并逐文件校验；其余分区保留', flush=True)
    restore_internal(config)


def make_install_env(manifest):
    geometry = manifest['geometry']
    expected = layout_for(geometry['total_bytes'], geometry['erase_bytes'])
    actual = tuple((p['name'], p['start_bytes'], p['size_bytes'], p['flags']) for p in manifest['partitions'])
    if actual != expected or geometry['write_bytes'] != 8192 or geometry['type'] != 'mlc-nand':
        raise ValueError('安装清单核心边界或硬件几何改变')
    values = {'FASTBOOT_SHA': manifest['preserved_fastboot_sha256'],
              'TOTAL_BYTES': geometry['total_bytes'], 'DATA_BYTES': expected[-1][2]}
    names = {'BOOT_SHA': 'boot.img', 'PTABLE_SHA': 'ptable.bin', 'MLC_SHA': 'mlcverify.bin',
             'BASEPARAM_SHA': 'baseparam.bin', 'BASEPARAM2_SHA': 'baseparam2.bin',
             'ROOT_SHA': 'rootfs.tar.gz', 'MISC_GZ_SHA': 'misc.bin.gz', 'SWDEV_GZ_SHA': 'swdevinfo.bin.gz'}
    for name, filename in names.items():
        values[name] = manifest['files'][filename]['sha256']
    for name in ('misc', 'swdevinfo'):
        values[name.upper() + '_SHA'] = manifest['core_uncompressed'][name]['sha256']
    for name, value in values.items():
        if name.endswith('_SHA') and not re.fullmatch(r'[a-f0-9]{64}', str(value)):
            raise ValueError('安装摘要字段非法')
    lines = [f'{name}={value}' for name, value in values.items()]
    lines += ["MAP_RW='" + bootargs_map(geometry['total_bytes'], readonly=False) + "'",
              "MAP_RO='" + bootargs_map(geometry['total_bytes']) + "'",
              "MTD_EXPECT='" + ' '.join(f'{n}:{size}' for n, _, size, _ in expected) + "'"]
    for blocks in (1, 2, 6, 8):
        lines.append(f'ERASED_{blocks}=' + sha256(b'\xff' * (blocks * 2097152)))
    return ('\n'.join(lines) + '\n').encode()


def install_archive(root, manifest, files, binaries):
    from .archives import read_tar_bytes
    digests = root_digest(read_tar_bytes(files['rootfs.tar.gz']))
    environment = make_install_env(manifest) + ('ROOT_FILES_SHA=' + sha256(digests) + '\n').encode()
    script = (root / 'tools/cm2012/device/install-stage').read_text(encoding='utf-8')
    script = script.replace('{{ENV_SHA}}', sha256(environment))
    payload = {'cm2012-install/install.env': Entry(stat.S_IFREG | 0o600, environment),
               'cm2012-install/install-stage': Entry(stat.S_IFREG | 0o700, script.encode()),
               'cm2012-install/root-files.sha256': Entry(stat.S_IFREG | 0o600, digests)}
    for name in ('boot.img', 'ptable.bin', 'mlcverify.bin', 'baseparam.bin', 'baseparam2.bin',
                 'rootfs.tar.gz', 'misc.bin.gz', 'swdevinfo.bin.gz'):
        payload['cm2012-install/' + name] = Entry(stat.S_IFREG | 0o600, files[name])
    tools = []
    for name, path in binaries.items():
        if name not in ('ubusd', 'cm2012-switch-root', 'serial-transfer'):
            payload['cm2012-install/' + name] = Entry(stat.S_IFREG | 0o700, path.read_bytes())
            tools.append(sha256(path.read_bytes()) + '  ' + name)
    payload['cm2012-install/tools.sha256'] = Entry(stat.S_IFREG | 0o600, ('\n'.join(tools) + '\n').encode())
    payload['cm2012-install/install-stage'] = Entry(stat.S_IFREG | 0o700,
        script.replace('{{TOOLS_SHA}}', sha256(payload['cm2012-install/tools.sha256'].data)).encode())
    return tar_bytes(payload)
