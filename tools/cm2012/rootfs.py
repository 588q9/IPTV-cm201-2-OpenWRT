"""Root filesystem construction and validation, preserving archive metadata."""
from pathlib import PurePosixPath
import posixpath
import shlex
import stat

from .archives import Entry, read_tar_bytes, tar_bytes
from .elf import elf_info
from .hardware import MODULES, FIRMWARE, validate_support
from .resources import read_lock, verify_resource


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


def validate_remote_root(entries):
    from .remote_assets import REMOTE_PROGRAMS
    for name in REMOTE_PROGRAMS:
        validate_program(entries, name)
    # dlopen dependencies do not appear in the downloader's DT_NEEDED table.
    validate_program(entries, 'usr/lib/libcurl.so.4', executable=False)
    for name in ('www/metacubexd/index.html', 'etc/ssl/certs/ca-certificates.crt',
                 'usr/lib/ddns/update_cloudflare_com_v4.sh',
                 'www/luci-static/resources/view/ddns/overview.js'):
        resolve_file(entries, name)


def validate_root(entries):
    programs = ('sbin/init', 'sbin/ubusd', 'usr/sbin/hostapd', 'usr/sbin/uhttpd',
                'usr/sbin/dnsmasq', 'etc/init.d/cm2012-ap', 'usr/sbin/wpa_supplicant',
                'usr/sbin/xtables-legacy-multi', 'sbin/fw3', 'usr/libexec/cm2012-wifi',
                'usr/libexec/cm2012-wpa-control', 'usr/libexec/cm2012-net-probe',
                'usr/libexec/cm2012-serial-transfer', 'etc/init.d/firewall', 'etc/init.d/sysntpd',
                'usr/libexec/cm2012-network', 'etc/init.d/cm2012-network-guard')
    needed = programs + ('etc/config/cm2012', 'usr/share/rpcd/ucode/cm2012',
              'usr/libexec/cm2012-wireless-lib.uc', 'usr/libexec/cm2012-supplicant.uc',
              'usr/libexec/cm2012-network-lib.uc', 'usr/libexec/cm2012-network-restore.uc',
              'etc/rc.d/S18cm2012-network-guard',
              'usr/share/rpcd/acl.d/luci-app-cm2012.json',
              'usr/share/luci/menu.d/luci-app-cm2012.json',
              'www/luci-static/resources/view/cm2012/wireless.js',
              'lib/modules/3.18.24_hi3798mv2x/wlan_mt7668_sdio.ko')
    for name in needed:
        resolve_file(entries, name)
    if entries.get('etc/cm2012-internal-root', Entry(0)).data != b'CM2012_INTERNAL_OPENWRT25\n':
        raise ValueError('根系统完成标识缺失')
    for name in programs:
        validate_program(entries, name)
    if 'sbin/procd' in entries:
        from .runtime import PROCD_LAUNCHER
        validate_program(entries, 'sbin/procd')
        if resolve_file(entries, 'sbin/procd').data == PROCD_LAUNCHER:
            validate_program(entries, 'usr/libexec/cm2012/procd')
    from .runtime import NETIFD_LAUNCHER
    validate_program(entries,'usr/bin/setsid')
    validate_program(entries,'sbin/netifd')
    if resolve_file(entries,'sbin/netifd').data != NETIFD_LAUNCHER:
        raise ValueError('netifd 缺少原厂内核桥接兼容入口')
    validate_program(entries,'usr/libexec/cm2012/netifd')
    info = elf_info(resolve_file(entries,'usr/lib/cm2012-netlink-compat.so').data)
    if info['interpreter'] or info['needed'] or not info['has_dynamic']:
        raise ValueError('netlink 兼容库不完整')
    validate_accounts(entries.get('etc/passwd', Entry(0)).data.decode())
    validate_support(entries, 'lib/modules/3.18.24_hi3798mv2x/', 'lib/firmware/')
    if 'usr/share/cm2012/remote-assets.json' in entries or 'etc/config/cm2012_proxy' in entries:
        validate_remote_root(entries)


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
    from .runtime import configuration
    for name, data in configuration(config).items():
        seed[name] = Entry(stat.S_IFREG | 0o600, data)
    shadow = official['etc/shadow'].data.decode().splitlines()
    shadow = [f"root:{config['root_hash']}:0:0:99999:7:::" if s.startswith('root:') else s for s in shadow]
    seed['etc/shadow'] = Entry(stat.S_IFREG | 0o600, ('\n'.join(shadow) + '\n').encode())
    return read_tar_bytes(tar_bytes(seed))


def make_overlay(root, config, binaries):
    overlay = {'sbin/ubusd': Entry(stat.S_IFREG | 0o755, binaries['ubusd'].read_bytes())}
    from .runtime import configuration, runtime_files
    overlay.update(runtime_files(root))
    for name, data in configuration(config).items():
        overlay[name] = Entry(stat.S_IFREG | 0o600, data)
    for name, target in (
        ('fw3', 'sbin/fw3'), ('xtables-legacy-multi', 'usr/sbin/xtables-legacy-multi'),
        ('libxtables.so.12', 'usr/lib/libxtables.so.12'),
        ('cm2012-netlink-compat.so', 'usr/lib/cm2012-netlink-compat.so'),
        ('cm2012-proxy-fetch', 'usr/libexec/cm2012-proxy-fetch'),
        ('cm2012-wpa-control', 'usr/libexec/cm2012-wpa-control'),
        ('cm2012-net-probe', 'usr/libexec/cm2012-net-probe')):
        if name in binaries:
            overlay[target] = Entry(stat.S_IFREG | 0o755, binaries[name].read_bytes())
    if 'serial-transfer' in binaries:
        overlay['usr/libexec/cm2012-serial-transfer'] = Entry(stat.S_IFREG | 0o755, binaries['serial-transfer'].read_bytes())
    return read_tar_bytes(tar_bytes(overlay))
