"""原厂本地输入档案与物理 NAND 容量核对，密码不进入公开文件。"""
import binascii
import json
from pathlib import Path
import re
import struct
import sys

from .images import sha256
from .layout import layout_for
from .resources import extract_zip, read_lock, verify_resource

FASTBOOT_SHA = 'fc67ade7ef8d03f8e5fa61fd8371d94324564f14a0a1e0385cb82d48a6a04ce9'
BOOT_SHA = '27ac589b6db53f408054fbe398d0ab9e66001afbae122e98eeb9cf45545d2539'
STOCK_FILES = {'fastboot': 'mtd0-data.bin', 'boot': 'mtd14-data.bin',
               'baseparam': 'baseparam-valid.bin', 'mlc': 'mlcverify-head.bin',
               'ptable': 'mtd1-data.bin', 'support': 'stock-support.tar.gz',
               'misc': 'original-misc-data.bin.gz', 'swdevinfo': 'original-swdevinfo-data.bin.gz'}


def activate_dependencies(root):
    destination = root / 'local/python-deps'
    for name, item in read_lock(root).items():
        if item['path'].endswith('.whl'):
            extract_zip(verify_resource(root, item), destination)
    if str(destination) not in sys.path:
        sys.path.insert(0, str(destination))


def geometry_from_log(log):
    match = re.search(r'nand: Block:(\d+)MB Page:(\d+)KB OOB:(\d+)B ECC:(\d+)bits/1K Chip:(\d+)GB', log)
    if not match:
        raise ValueError('缺少完整物理 NAND 几何信息')
    block, page, oob, ecc, capacity = map(int, match.groups())
    if (block, page, oob, ecc) != (2, 8, 744, 40):
        raise ValueError('NAND 擦除块、页或 ECC 几何不兼容')
    total = capacity * 1024**3
    layout_for(total, block * 1048576)
    return {'total_bytes': total, 'erase_bytes': block * 1048576,
            'write_bytes': page * 1024, 'oob_bytes': oob, 'ecc_bits': ecc}


def total_from_ptable(data):
    if len(data) < 16 or data[:8] != b'PTABLE!!':
        raise ValueError('原厂分区表标识错误')
    crc, count = struct.unpack_from('<II', data, 8)
    end = 16 + count * 88
    if not 1 <= count <= 32 or end > len(data) or crc != binascii.crc_hqx(data[12:end], 0):
        raise ValueError('原厂分区表 CRC 或长度错误')
    cursor, names = 0, set()
    for index in range(count):
        _, name, start, size, _ = struct.unpack_from('<I64sQQI', data, 16 + index * 88)
        name = name.split(b'\0')[0]
        if not name or name in names or start != cursor or size <= 0:
            raise ValueError('原厂分区表包含重复名称、重叠或空洞')
        names.add(name)
        cursor = start + size
    layout_for(cursor, 2097152)
    return cursor


def configure(root, stock_directory, ssid, ap_password, root_password, port='COM3'):
    if not 1 <= len(ssid.encode()) <= 32 or '\n' in ssid or '\r' in ssid:
        raise ValueError('热点名称长度或换行不合法')
    if not 8 <= len(ap_password) <= 63 or any(not 32 <= ord(c) <= 126 for c in ap_password):
        raise ValueError('热点密码须为 8 至 63 位可打印 ASCII')
    if not root_password or '\n' in root_password:
        raise ValueError('管理密码不合法')
    stock = {name: (stock_directory / filename).read_bytes() for name, filename in STOCK_FILES.items()}
    if sha256(stock['fastboot']) != FASTBOOT_SHA or sha256(stock['boot']) != BOOT_SHA:
        raise ValueError('引导器或内核不属于当前已验证的原厂版本')
    total = total_from_ptable(stock['ptable'])
    directory = root / 'local'
    directory.mkdir(exist_ok=True)
    target = directory / 'config.json'
    config = json.loads(target.read_text(encoding='utf-8')) if target.exists() else {}
    activate_dependencies(root)
    from passlib.hash import sha512_crypt
    old_hash = config.get('root_hash')
    root_hash = old_hash if old_hash and sha512_crypt.verify(root_password, old_hash) else sha512_crypt.hash(root_password)
    profile = {name + '_sha256': sha256(data) for name, data in stock.items()}
    profile.update(total_bytes=total, erase_bytes=2097152)
    # 输入路径只保存在忽略目录；构建不再寻找旧私人 OpenWrt 根归档。
    config.update(format=1, port=port, ssid=ssid, ap_password=ap_password, root_hash=root_hash,
                  stock_paths={n: str((stock_directory / f).resolve()) for n, f in STOCK_FILES.items()},
                  profile=profile)
    target.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding='utf-8', newline='\n')
    return config


def load_config(root):
    config = json.loads((root / 'local/config.json').read_text(encoding='utf-8'))
    if config['format'] != 1:
        raise ValueError('本地配置格式不支持')
    stock = {name: Path(path).read_bytes() for name, path in config['stock_paths'].items()}
    for name, data in stock.items():
        if sha256(data) != config['profile'][name + '_sha256']:
            raise ValueError('原厂本地输入摘要变化：' + name)
    if sha256(stock['fastboot']) != FASTBOOT_SHA or sha256(stock['boot']) != BOOT_SHA:
        raise ValueError('原厂版本不兼容')
    if total_from_ptable(stock['ptable']) != config['profile']['total_bytes']:
        raise ValueError('原厂表容量与档案不符')
    return config, stock
