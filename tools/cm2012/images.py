"""来源校验、Android 引导镜像及厂商校验表组装，无硬件副作用。"""
import binascii
import gzip
import hashlib
import io
import struct

from .layout import MIB, layout_for


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def gz(data, level=9):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', compresslevel=level, mtime=0,
                       filename='') as stream:
        stream.write(data)
    return output.getvalue()


def kernel_from(stock):
    if len(stock) < 2048 or stock[:8] != b'ANDROID!':
        raise ValueError('原厂 boot 格式不正确')
    size, page = struct.unpack_from('<I', stock, 8)[0], struct.unpack_from('<I', stock, 36)[0]
    if page != 2048 or not 0 < size <= len(stock) - page:
        raise ValueError('原厂 boot 内核长度或页大小不正确')
    return stock[page:page + size]


def make_boot(stock, ramdisk, cmdline):
    if not cmdline.endswith(' ') or len(cmdline.encode()) >= 512:
        raise ValueError('启动参数长度或末尾分隔空格不正确')
    kernel = kernel_from(stock)
    header = bytearray(stock[:2048])
    # 本项目没有 second stage 或 DT 镜像，不能保留原厂非零长度。
    struct.pack_into('<I', header, 16, len(ramdisk))
    struct.pack_into('<I', header, 24, 0)
    struct.pack_into('<I', header, 40, 0)
    header[64:576] = cmdline.encode().ljust(512, b'\0')
    digest = hashlib.sha1()
    for data in (kernel, ramdisk, b''):
        digest.update(data)
        digest.update(struct.pack('<I', len(data)))
    header[576:608] = digest.digest().ljust(32, b'\0')
    align = lambda data: data + bytes(-len(data) % 2048)
    return bytes(header) + align(kernel) + align(ramdisk)


def check_boot(image, stock):
    if not 2048 <= len(image) <= 12 * MIB or image[:8] != b'ANDROID!':
        raise ValueError('boot 格式错误或超过 12MiB')
    page = struct.unpack_from('<I', image, 36)[0]
    size, ram_size = struct.unpack_from('<I', image, 8)[0], struct.unpack_from('<I', image, 16)[0]
    if page != 2048 or len(image) % page:
        raise ValueError('boot 页大小或对齐错误')
    if image[page:page + size] != kernel_from(stock):
        raise ValueError('内核与已核对原厂 boot 不一致')
    if not image[64:576].split(b'\0')[0].endswith(b' '):
        raise ValueError('启动参数末尾缺少空格')
    offset = page + ((size + page - 1) // page) * page
    end = offset + ram_size
    if not ram_size or (end + page - 1) // page * page != len(image):
        raise ValueError('boot initramfs 长度错误')
    ram = image[offset:end]
    try:
        valid = gzip.decompress(ram).startswith(b'070701')
    except (OSError, EOFError):
        valid = False
    if not valid:
        raise ValueError('boot initramfs 不是 newc')
    digest = hashlib.sha1()
    for data in (kernel_from(stock), ram, b''):
        digest.update(data)
        digest.update(struct.pack('<I', len(data)))
    if image[576:608] != digest.digest().ljust(32, b'\0'):
        raise ValueError('boot 内容摘要错误')


def make_bundle(boot, stock, profile):
    for name in ('fastboot', 'boot', 'baseparam', 'mlc'):
        if sha256(stock[name]) != profile[name + '_sha256']:
            raise ValueError(name + ' 原厂输入摘要不一致')
    total, erase = profile['total_bytes'], profile['erase_bytes']
    parts = layout_for(total, erase)
    check_boot(boot, stock['boot'])
    ptable = bytearray(0xb10)
    ptable[:8] = b'PTABLE!!'
    struct.pack_into('<I', ptable, 12, len(parts))
    for i, (name, start, size, flags) in enumerate(parts):
        struct.pack_into('<I64sQQI', ptable, 16 + i * 88, 0, name.encode(), start, size, flags)
    struct.pack_into('<I', ptable, 8, binascii.crc_hqx(ptable[12:808], 0))
    original = stock['mlc']
    if len(original) < 24 or original[:12] != b'MLCVERIFY!\0\0':
        raise ValueError('mlc 原厂表头错误')
    mlc = bytearray(0xa18)
    mlc[:12] = original[:12]
    struct.pack_into('<II', mlc, 16, 3, struct.unpack_from('<I', original, 20)[0])
    for i, (name, data) in enumerate((('baseparam', stock['baseparam']),
                                     ('baseparam2', stock['baseparam']), ('boot', boot))):
        struct.pack_into('<III64sI', mlc, 24 + i * 80, i, 0, len(data), name.encode(),
                         binascii.crc_hqx(data, 0))
    struct.pack_into('<I', mlc, 12, binascii.crc_hqx(mlc[16:264], 0))
    files = {'boot.img': boot, 'ptable.bin': bytes(ptable), 'mlcverify.bin': bytes(mlc),
             'baseparam.bin': stock['baseparam'], 'baseparam2.bin': stock['baseparam']}
    manifest = {'format': 1, 'geometry': {'total_bytes': total, 'erase_bytes': erase,
                 'write_bytes': 8192, 'type': 'mlc-nand'},
                'preserved_fastboot_sha256': profile['fastboot_sha256'],
                'partitions': [{'name': n, 'start_bytes': s, 'size_bytes': z, 'flags': f}
                               for n, s, z, f in parts],
                'files': {n: {'size': len(data), 'sha256': sha256(data)}
                          for n, data in files.items()}}
    return files, manifest
