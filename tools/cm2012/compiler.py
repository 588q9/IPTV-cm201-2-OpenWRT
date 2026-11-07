"""从锁定原始源码与官方运行库构建 ARM 程序，不读取历史产物。"""
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile

from .elf import elf_info, elf_check
from .patching import apply_patch
from .archives import read_tar_bytes
from .resources import extract_source, prepare_zip_cache, read_lock, verify_resource

UBUSD_NEEDED = ('libubox.so.20260213', 'libblobmsg_json.so.20260213',
                'libjson-c.so.5', 'libc.so')
FW3_NEEDED = ('libxtables.so.12', 'libuci.so.20250120', 'libubus.so.20251202',
              'libgcc_s.so.1', 'libubox.so.20260213', 'libc.so')


def prepare_toolchain(root, source):
    directory = prepare_zip_cache(source, root / 'local/toolchain', workspace=root / 'local')
    zig = directory / 'zig-windows-x86_64-0.13.0/zig.exe'
    if not zig.is_file():
        raise ValueError('锁定工具链缺少 zig.exe')
    return zig


def compile_proxy_fetch(root, resources, common, run, linklibs, output):
    """Use official API headers; the existing signed libcurl is loaded at runtime."""
    work = root / 'local/build'
    # Only API headers are used: avoid extracting curl's thousands of docs/tests.
    from .resources import checked_directory, remove_generated_tree, source_archive_root
    source = checked_directory(work / 'curl-headers', work)
    remove_generated_tree(source, work)
    include = checked_directory(source / 'curl', work)
    include.mkdir(parents=True, exist_ok=True)
    with tarfile.open(resources['curl-source']) as archive:
        prefix = source_archive_root(archive) + '/include/curl/'
        found = set()
        for member in archive.getmembers():
            if not member.name.startswith(prefix):
                continue
            name = member.name[len(prefix):]
            if not re.fullmatch(r'[A-Za-z0-9_.-]+\.h', name):
                continue
            if not member.isfile():
                raise ValueError('curl API 头文件不是普通文件')
            target = checked_directory(include / name, work)
            target.write_bytes(archive.extractfile(member).read())
            found.add(name)
        if not {'curl.h', 'curlver.h'} <= found:
            raise ValueError('锁定 curl 源码缺少必需 API 头文件')
    objects = []
    for path in (root / 'tools/cm2012/proxy_fetch.c',
                 root / 'tools/cm2012/kernel_entropy.c', root / 'tools/ubusd_compat_start.c'):
        obj = work / 'objects' / ('fetch-' + path.stem + '.o')
        run(common + ['-fPIE', '-std=c99', '-Wall', '-Wextra', '-Werror',
                      '-I' + str(source), '-c', str(path), '-o', str(obj)])
        objects.append(str(obj))
    binary = output / 'cm2012-proxy-fetch'
    run([common[0], 'ld.lld', '-m', 'armelf_linux_eabi', '-pie', '-e', '_start',
         '--dynamic-linker', '/lib/ld-musl-armhf.so.1', '-z', 'max-page-size=4096',
         '--export-dynamic-symbol=mbedtls_entropy_func'] + objects +
        ['libc.so', '-o', str(binary)], cwd=linklibs)
    elf_check(binary, static=False, expected_needed=('libc.so',))
    return binary


def compile_all(root):
    locks = read_lock(root)
    # 完整资源检查在离线编译前执行，缺失时不自动调用 prepare。
    resources = {name: verify_resource(root, item) for name, item in locks.items()}
    work = root / 'local/build'
    work.mkdir(parents=True, exist_ok=True)
    zig = prepare_toolchain(root, resources['zig'])
    source_dirs = {}
    for name in ('ubus-source', 'libubox-source', 'mtd-utils-source'):
        directory = work / name
        source_dirs[name] = extract_source(resources[name], directory, workspace=work)
    ubus, ubox, mtd = (source_dirs[n] for n in ('ubus-source', 'libubox-source', 'mtd-utils-source'))
    patched = apply_patch((ubus / 'ubusd_id.c').read_text(encoding='utf-8'),
                          (root / 'tools/cm2012/patches/ubusd-3.18.patch').read_text(encoding='utf-8'))
    (ubus / 'ubusd_id.c').write_text(patched, encoding='utf-8', newline='\n')
    headers = work / 'include/libubox'
    headers.mkdir(parents=True, exist_ok=True)
    for path in ubox.glob('*.h'):
        shutil.copyfile(path, headers / path.name)
    official = read_tar_bytes(resources['openwrt-rootfs'].read_bytes())
    rawlibs, linklibs = work / 'raw-libs', work / 'link-libs'
    rawlibs.mkdir(exist_ok=True)
    linklibs.mkdir(exist_ok=True)
    from restore_elf_link_sections import restore
    libraries = [('lib/libubox.so.20260213', 'libubox.so.20260213'),
                 ('lib/libblobmsg_json.so.20260213', 'libblobmsg_json.so.20260213'),
                 ('usr/lib/libjson-c.so.5', 'libjson-c.so.5'), ('lib/libc.so', 'libc.so')]
    for source, filename in libraries:
        entry = official[source]
        if stat.S_ISLNK(entry.mode):
            import posixpath
            source = posixpath.normpath(posixpath.join(posixpath.dirname(source), entry.data.decode()))
            entry = official[source]
        path = rawlibs / filename
        path.write_bytes(entry.data)
        restore(path, linklibs / filename)
    output = work / 'bin'
    objects = work / 'objects'
    output.mkdir(exist_ok=True)
    objects.mkdir(exist_ok=True)
    environment = os.environ.copy()
    environment['ZIG_GLOBAL_CACHE_DIR'] = str(root / 'local/zig-global-cache')
    environment['ZIG_LOCAL_CACHE_DIR'] = str(root / 'local/zig-local-cache')
    common = [str(zig), 'cc', '-target', 'arm-linux-musleabihf', '-mcpu=cortex_a15', '-Os']

    def run(args, cwd=root):
        subprocess.run(args, cwd=cwd, env=environment, check=True)

    for filename, source in (('cm2012-switch-root', root / 'tools/internal_switch_root.c'),
                             ('serial-transfer', root / 'tools/cm2012/serial_transfer.c'),
                             ('cm2012-wpa-control', root / 'tools/cm2012/wpa_control.c'),
                             ('cm2012-net-probe', root / 'tools/cm2012/net_probe.c')):
        run(common + ['-static', '-s', str(source), '-o', str(output / filename)])
    netlink_objects = []
    for name in ('netlink_compat','netlink_preload'):
        obj = objects / (name + '.o')
        run(common + ['-fPIC', '-c', str(root / 'tools/cm2012' / (name + '.c')), '-o', str(obj)])
        netlink_objects.append(str(obj))
    run([str(zig),'ld.lld','-m','armelf_linux_eabi','-shared'] + netlink_objects +
        ['-o',str(output / 'cm2012-netlink-compat.so')])
    ubus_flags = ['-fPIE', '-pie', '-std=gnu99', '-D_GNU_SOURCE', '-DUBUS_MAX_MSGLEN=1048576',
                  '-DUBUS_UNIX_SOCKET="/var/run/ubus/ubus.sock"', '-I' + str(headers.parent), '-I' + str(ubus)]
    names = ('ubusd_main', 'ubusd', 'ubusd_proto', 'ubusd_id', 'ubusd_obj', 'ubusd_event', 'ubusd_acl', 'ubusd_monitor')
    objfiles = []
    for source in [ubus / (n + '.c') for n in names] + [root / 'tools/ubusd_compat_start.c']:
        obj = objects / (source.stem + '.o')
        run(common + ubus_flags + ['-c', str(source), '-o', str(obj)])
        objfiles.append(str(obj))
    run([str(zig), 'ld.lld', '-m', 'armelf_linux_eabi', '-pie', '-e', '_start', '--dynamic-linker',
         '/lib/ld-musl-armhf.so.1', '-z', 'max-page-size=4096'] + objfiles +
        [n for _, n in libraries] + ['-o', str(output / 'ubusd')], cwd=linklibs)
    mtdflags = ['-static', '-s', '-D_GNU_SOURCE', '-D_FILE_OFFSET_BITS=64', '-DVERSION="2.1.6"',
                '-std=gnu99', '-I' + str(mtd / 'include')]
    mtdobjs = []
    for name in ('libmtd', 'libmtd_legacy', 'libubi', 'libubigen', 'libscan', 'libcrc32', 'common'):
        obj = objects / (name + '.o')
        run(common + mtdflags + ['-c', str(mtd / 'lib' / (name + '.c')), '-o', str(obj)])
        mtdobjs.append(str(obj))
    programs = [('mtdinfo', 'ubi-utils'), ('ubinfo', 'ubi-utils'), ('ubiformat', 'ubi-utils'),
                ('ubiattach', 'ubi-utils'), ('ubidetach', 'ubi-utils'), ('ubimkvol', 'ubi-utils'),
                ('nandwrite', 'nand-utils'), ('flash_erase', 'misc-utils')]
    for name, folder in programs:
        run(common + mtdflags + [str(mtd / folder / (name + '.c'))] + mtdobjs + ['-o', str(output / name)])
    binaries = {name: output / name for name in ['ubusd', 'cm2012-switch-root', 'serial-transfer',
                 'cm2012-wpa-control', 'cm2012-net-probe', 'cm2012-netlink-compat.so'] +
                 [n for n, _ in programs]}
    from .legacy_firewall import compile_legacy
    binaries.update(compile_legacy(root, resources, official, ubus, headers, linklibs,
                                   common, run, output))
    binaries['cm2012-proxy-fetch'] = compile_proxy_fetch(root, resources, common, run, linklibs, output)
    for name, path in binaries.items():
        if name == 'cm2012-netlink-compat.so':
            info = elf_info(path.read_bytes())
            if info['interpreter'] or info['needed'] or not info['has_dynamic']:
                raise ValueError('netlink 兼容库的动态依赖不匹配')
            continue
        if name == 'libxtables.so.12':
            info = elf_info(path.read_bytes())
            if info['interpreter'] or info['needed'] != ('libc.so',):
                raise ValueError('iptables 运行库依赖不匹配')
            continue
        expected = (UBUSD_NEEDED if name == 'ubusd' else FW3_NEEDED if name == 'fw3' else
                    ('libc.so',) if name == 'cm2012-proxy-fetch' else ())
        elf_check(path, static=name not in ('ubusd', 'fw3', 'cm2012-proxy-fetch'), expected_needed=expected)
    print('锁定源码编译与 ARM 架构检查完成', flush=True)
    return binaries
