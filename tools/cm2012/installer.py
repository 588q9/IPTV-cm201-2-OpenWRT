"""生成本次安装环境与资源包，不执行安装阶段。"""
import re
import stat

from .archives import Entry, tar_bytes
from .images import sha256
from .layout import bootargs_map, layout_for


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
    environment = make_install_env(manifest)
    script = (root / 'tools/cm2012/device/install-stage').read_text(encoding='utf-8')
    script = script.replace('{{ENV_SHA}}', sha256(environment))
    payload = {'cm2012-install/install.env': Entry(stat.S_IFREG | 0o600, environment),
               'cm2012-install/install-stage': Entry(stat.S_IFREG | 0o700, script.encode())}
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
