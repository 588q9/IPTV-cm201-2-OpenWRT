"""Assemble and verify complete output artifacts without device orchestration."""
import gzip
import json
from pathlib import PurePosixPath
import stat

from .archives import Entry, cpio_bytes, read_tar_bytes, tar_bytes
from .images import CMDLINE, check_boot, gz, make_boot, make_bundle, sha256
from .layout import bootargs_map
from .rootfs import strip_runtime, validate_root
from .install_bundle import install_archive
from .credentials import protect_root


def ram_entries_for(entries):
    result = dict(entries)
    result['init'] = Entry(stat.S_IFREG | 0o755,
        b'#!/bin/sh\nexport INITRAMFS=1\necho CM2012_PUBLIC_RAM_BOOT\nexec /sbin/init\n')
    for name, major, minor in (('console', 5, 1), ('ttyAMA0', 204, 64), ('null', 1, 3), ('zero', 1, 5), ('kmsg', 1, 11)):
        result['dev/' + name] = Entry(stat.S_IFCHR | 0o600, b'', major=major, minor=minor)
    return result


def assemble_outputs(root, config, stock, binaries, entries, output):
    entries = protect_root(strip_runtime(entries))
    # Host-side assets may add files below directories absent from the seed.
    # Materialize those parents before generating both tar and cpio views.
    entries = dict(entries)
    for name in list(entries):
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                entries.setdefault(str(parent),Entry(stat.S_IFDIR | 0o755))
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
