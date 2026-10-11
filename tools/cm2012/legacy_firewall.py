"""用锁定源码构建静态 iptables legacy 与目标 musl 动态 firewall3。"""
import tarfile
import hashlib
import re
from pathlib import PurePosixPath
from .resources import extract_source


EXTENSIONS = {
    'xt': ('standard', 'tcp', 'udp', 'conntrack', 'comment', 'limit', 'multiport', 'mark',
           'connmark', 'mac', 'pkttype', 'addrtype', 'TCPMSS', 'MARK', 'CONNMARK',
           'DNAT', 'CT'),
    'ipt': ('icmp', 'REJECT', 'MASQUERADE', 'SNAT'),
    'ip6t': ('icmp6', 'REJECT', 'MASQUERADE', 'SNAT'),
}


def case_safe_names(names):
    counts = {}
    for name in names:
        counts[name.casefold()] = counts.get(name.casefold(), 0) + 1
    result = {}
    for name in names:
        p = PurePosixPath(name)
        result[name] = str(p.with_name(p.stem + '_' + hashlib.sha256(name.encode()).hexdigest()[:12] + p.suffix)) if counts[name.casefold()] > 1 else name
    return result


def compile_legacy(root, resources, official, ubus, headers, linklibs, common, run, output):
    work = root / 'local/build/legacy-firewall'
    work.mkdir(parents=True, exist_ok=True)
    sources = {}
    for name in ('iptables-source', 'firewall3-source'):
        directory = work / name
        extract_source(resources[name], directory)
        sources[name] = next(p for p in directory.iterdir() if p.is_dir())
    ipt, fw = sources['iptables-source'], sources['firewall3-source']
    # 上游包含 MARK/mark 等不同文件；Windows 解包会将其覆盖。
    with tarfile.open(resources['iptables-source']) as archive:
        members = [m for m in archive if m.isreg()]
        mapped = case_safe_names([m.name.split('/', 1)[1] for m in members])
        header_names = {PurePosixPath(n).name: PurePosixPath(v).name
                        for n, v in mapped.items() if n != v and n.endswith('.h')}
        for member in members:
            name = member.name.split('/', 1)[1]
            data = archive.extractfile(member).read()
            if name.endswith(('.c', '.h')):
                text = data.decode()
                text = re.sub(r'(#\s*include\s*[<"][^>"\n]*?)([A-Za-z0-9_]+\.h)([>"])',
                              lambda m: m[1] + header_names.get(m[2], m[2]) + m[3], text)
                data = text.encode()
            (ipt / mapped[name]).write_bytes(data)
    uci = work / 'uci-headers'
    from .compiler import apply_patch
    xtables_source = ipt / 'libxtables/xtables.c'
    xtables_source.write_text(apply_patch(xtables_source.read_text(encoding='utf-8'),
        (root / 'tools/cm2012/patches/iptables-register-reset.patch').read_text(encoding='utf-8')),
        encoding='utf-8', newline='\n')
    uci.mkdir(exist_ok=True)
    # 仅提取顶层公开头；fuzz 样本含 Windows 不支持的冒号文件名。
    with tarfile.open(resources['uci-source']) as archive:
        found = set()
        for member in archive:
            parts = member.name.split('/')
            if len(parts) == 2 and parts[1] in ('uci.h', 'uci_blob.h', 'ucimap.h'):
                if not member.isreg() or parts[1] in found:
                    raise ValueError('UCI 头不是唯一普通文件')
                found.add(parts[1])
                (uci / parts[1]).write_bytes(archive.extractfile(member).read())
        if found != {'uci.h', 'uci_blob.h', 'ucimap.h'}:
            raise ValueError('锁定 UCI 源码缺少公开头')
    (uci / 'uci_config.h').write_text('/* Debug typecasts disabled. */\n')
    (ipt / 'config.h').write_text('''#define PACKAGE "iptables"
#define PACKAGE_VERSION "1.8.8"
#define PACKAGE_STRING "iptables 1.8.8"
#define PACKAGE_NAME "iptables"
#define VERSION "1.8.8"
#define XT_LOCK_NAME "/var/run/xtables.lock"
#define SIZEOF_STRUCT_IP6_HDR 40
#define HAVE_LINUX_MAGIC_H 1
#define HAVE_LINUX_DCCP_H 1
#define HAVE_LINUX_IP_VS_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_STDINT_H 1
''', newline='\n')
    (ipt / 'include/xtables-version.h').write_text(
        '#define XTABLES_VERSION "libxtables.so.12"\n#define XTABLES_VERSION_CODE 12\n')
    objects = work / 'objects'
    objects.mkdir(exist_ok=True)
    flags = ['-fPIC', '-std=gnu99', '-D_GNU_SOURCE', '-include', 'sys/types.h', '-DNO_SHARED_LIBS=1', '-DALL_INCLUSIVE',
             '-DENABLE_IPV4', '-DENABLE_IPV6', '-DXTABLES_LIBDIR="/usr/lib/iptables"',
             '-DXTABLES_INTERNAL', '-D__UAPI_DEF_ETHHDR=0', '-I' + str(ipt), '-I' + str(ipt / 'include'),
             '-I' + str(ipt / 'iptables')]

    def obj(source, extra=()):
        path = objects / (hashlib.sha256(str(source.relative_to(root)).encode()).hexdigest()[:16] + '.o')
        if source.is_relative_to(ipt):
            source = ipt / mapped[str(source.relative_to(ipt)).replace('\\', '/')]
        run(common + flags + list(extra) + ['-c', str(source), '-o', str(path)])
        return str(path)

    shared = [obj(ipt / 'libxtables' / (n + '.c')) for n in ('xtables', 'xtoptions', 'getethertype')]
    shared += [obj(ipt / 'libiptc' / (n + '.c')) for n in ('libip4tc', 'libip6tc')]
    for prefix, names in EXTENSIONS.items():
        funcs = []
        for name in names:
            function = 'lib' + prefix + '_' + name + '_init'
            shared.append(obj(ipt / 'extensions' / ('lib' + prefix + '_' + name + '.c'),
                              ['-D_INIT=' + function]))
            funcs.append(function)
        suffix = {'xt': '', 'ipt': '4', 'ip6t': '6'}[prefix]
        generated = work / ('initext' + suffix + '.c')
        generated.write_text('\n'.join('extern void ' + f + '(void);' for f in funcs) +
                             '\nvoid init_extensions' + suffix + '(void) {\n' +
                             '\n'.join(f + '();' for f in funcs) + '\n}\n')
        shared.append(obj(generated))
    commands = ('xtables-legacy-multi', 'iptables-xml', 'iptables-standalone', 'iptables',
                'ip6tables-standalone', 'ip6tables', 'xshared', 'iptables-restore', 'iptables-save')
    cmdobjs = [obj(ipt / 'iptables' / (n + '.c')) for n in commands]
    run(common + ['-static', '-s'] + shared + cmdobjs + ['-lm', '-o', str(output / 'xtables-legacy-multi')])
    # fw3 的扩展保留机制通过 RTLD_NEXT 调用 libxtables 的原始注册函数。
    run([common[0], 'ld.lld', '-m', 'armelf_linux_eabi', '-shared', '-soname', 'libxtables.so.12'] +
        shared[:3] + ['libc.so', '-o', str(output / 'libxtables.so.12')], cwd=linklibs)
    # fw3 使用当前官方根的 libuci/libubus/libubox，不混入旧版本运行库。
    from restore_elf_link_sections import restore
    from .build import resolve_file
    libs = []
    for source in ('lib/libuci.so.20250120', 'lib/libubus.so.20251202', 'lib/libgcc_s.so.1'):
        entry = resolve_file(official, source)
        filename = source.split('/')[-1]
        raw = work / filename
        raw.write_bytes(entry.data)
        restore(raw, linklibs / filename)
        libs.append(filename)
    fwflags = ['-I' + str(uci), '-I' + str(headers.parent), '-I' + str(ubus), '-I' + str(fw)]
    fwobjs = [obj(fw / (n + '.c'), fwflags) for n in
              ('main', 'options', 'defaults', 'zones', 'forwards', 'rules', 'redirects',
               'snats', 'utils', 'ubus', 'ipsets', 'includes', 'iptables', 'helpers')]
    # 命令行已完成链接；fw3 同名对象不会影响静态扩展对象。
    start = obj(root / 'tools/ubusd_compat_start.c')
    run([common[0], 'ld.lld', '-m', 'armelf_linux_eabi', '-pie', '--export-dynamic', '-e', '_start',
         '--dynamic-linker', '/lib/ld-musl-armhf.so.1', '-z', 'max-page-size=4096'] +
        fwobjs + shared[3:] + [start, str(output / 'libxtables.so.12')] + libs + ['libubox.so.20260213', 'libc.so',
         '-o', str(output / 'fw3')], cwd=linklibs)
    return {n: output / n for n in ('xtables-legacy-multi', 'fw3', 'libxtables.so.12')}
