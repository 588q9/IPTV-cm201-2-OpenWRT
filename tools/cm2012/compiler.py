"""从锁定原始源码与官方运行库构建 ARM 程序，不读取历史产物。"""
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess

from .archives import read_tar_bytes
from .resources import extract_source, extract_zip, read_lock, verify_resource

UBUSD_NEEDED = ('libubox.so.20260213', 'libblobmsg_json.so.20260213',
                'libjson-c.so.5', 'libc.so')
FW3_NEEDED = ('libxtables.so.12', 'libuci.so.20250120', 'libubus.so.20251202',
              'libgcc_s.so.1', 'libubox.so.20260213', 'libc.so')


def apply_patch(text, patch):
    lines, result, cursor = text.splitlines(keepends=True), [], 0
    chunks = patch.splitlines(keepends=True)
    i = 0
    while i < len(chunks):
        match = re.match(r'@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@', chunks[i])
        if not match:
            i += 1
            continue
        start = int(match.group(1)) - 1
        if start < cursor:
            raise ValueError('源码补丁块重叠')
        result.extend(lines[cursor:start])
        cursor, i = start, i + 1
        while i < len(chunks) and not chunks[i].startswith('@@ '):
            line = chunks[i]
            if line.startswith((' ', '-')):
                if cursor >= len(lines) or lines[cursor] != line[1:]:
                    raise ValueError('源码补丁上下文不匹配')
                if line.startswith(' '):
                    result.append(line[1:])
                cursor += 1
            elif line.startswith('+'):
                result.append(line[1:])
            else:
                break
            i += 1
    result.extend(lines[cursor:])
    return ''.join(result)


def elf_info(data):
    """从程序头解析 ARM32 ELF，动态依赖只接受 Linux 库文件名。"""
    if (len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01' or
            struct.unpack_from('<H', data, 18)[0] != 40):
        raise ValueError('编译输出不是完整 ARM32 ELF')
    offset = struct.unpack_from('<I', data, 28)[0]
    size, count = struct.unpack_from('<HH', data, 42)
    if size != 32 or not count or offset < 52 or offset + size * count > len(data):
        raise ValueError('ELF 程序头长度或范围不正确')
    programs = [struct.unpack_from('<8I', data, offset + i * size) for i in range(count)]
    for program in programs:
        if program[1] + program[4] > len(data) or program[4] > program[5]:
            raise ValueError('ELF 程序段越界')
    loads = [program for program in programs if program[0] == 1]
    dynamic = [program for program in programs if program[0] == 2]
    interpreters = [program for program in programs if program[0] == 3]
    if not loads or len(dynamic) > 1 or len(interpreters) > 1:
        raise ValueError('ELF 装载段或动态段数量错误')
    interpreter = None
    if interpreters:
        program = interpreters[0]
        value = data[program[1]:program[1] + program[4]]
        if not value.endswith(b'\0') or b'\0' in value[:-1]:
            raise ValueError('ELF 解释器字符串不完整')
        try:
            interpreter = value[:-1].decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('ELF 解释器名称非法') from error
    needed = []
    if dynamic:
        program = dynamic[0]
        if not program[4] or program[4] % 8:
            raise ValueError('ELF 动态段长度错误')
        tags = []
        for position in range(program[1], program[1] + program[4], 8):
            tag, value = struct.unpack_from('<II', data, position)
            if tag == 0:
                break
            tags.append((tag, value))
        else:
            raise ValueError('ELF 动态段缺少结束标识')
        addresses = [value for tag, value in tags if tag == 5]
        lengths = [value for tag, value in tags if tag == 10]
        indexes = [value for tag, value in tags if tag == 1]
        if len(addresses) != 1 or len(lengths) != 1 or not lengths[0]:
            raise ValueError('ELF 动态字符串表不完整')
        address, length = addresses[0], lengths[0]
        mapping = [p for p in loads if p[2] <= address and address + length <= p[2] + p[4]]
        if len(mapping) != 1:
            raise ValueError('ELF 动态字符串表不属于有效装载段')
        start = mapping[0][1] + address - mapping[0][2]
        strings = data[start:start + length]
        for index in indexes:
            end = strings.find(b'\0', index) if 0 <= index < length else -1
            if end < 0:
                raise ValueError('ELF 依赖字符串越界或未结束')
            try:
                name = strings[index:end].decode('ascii')
            except UnicodeDecodeError as error:
                raise ValueError('ELF 依赖名称非法') from error
            if not re.fullmatch(r'[A-Za-z0-9_+.-]+', name) or name in ('.', '..'):
                raise ValueError('ELF 依赖含主机路径或非法文件名')
            needed.append(name)
        if len(set(needed)) != len(needed):
            raise ValueError('ELF 依赖名称重复')
    return {'interpreter': interpreter, 'needed': tuple(needed), 'has_dynamic': bool(dynamic)}


def elf_check(path, static=True, expected_needed=None):
    info = elf_info(path.read_bytes())
    if static and (info['has_dynamic'] or info['interpreter']):
        raise ValueError('维护程序不是静态链接：' + path.name)
    if not static and (not info['has_dynamic'] or info['interpreter'] != '/lib/ld-musl-armhf.so.1'):
        raise ValueError('ubusd 动态解释器不匹配')
    if expected_needed is not None and sorted(info['needed']) != sorted(expected_needed):
        raise ValueError('编译输出的动态依赖与锁定运行库不一致：' + path.name)
    return info['needed']


def compile_all(root):
    locks = read_lock(root)
    # 完整资源检查在离线编译前执行，缺失时不自动调用 prepare。
    resources = {name: verify_resource(root, item) for name, item in locks.items()}
    work = root / 'local/build'
    work.mkdir(parents=True, exist_ok=True)
    toolchain = root / 'local/toolchain'
    zig = toolchain / 'zig-windows-x86_64-0.13.0/zig.exe'
    if not zig.exists():
        extract_zip(resources['zig'], toolchain)
    source_dirs = {}
    for name in ('ubus-source', 'libubox-source', 'mtd-utils-source', 'hiloot-source'):
        directory = work / name
        extract_source(resources[name], directory)
        source_dirs[name] = next(path for path in directory.iterdir() if path.is_dir())
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
        expected = UBUSD_NEEDED if name == 'ubusd' else FW3_NEEDED if name == 'fw3' else ()
        elf_check(path, static=name not in ('ubusd', 'fw3', 'libxtables.so.12'), expected_needed=expected)
    print('锁定源码编译与 ARM 架构检查完成', flush=True)
    return binaries
