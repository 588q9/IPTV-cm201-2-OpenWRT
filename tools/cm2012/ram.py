"""串口 BootROM/RAM 启动；修改只存在内存，不写 NAND。"""
import asyncio
import re
import stat
import struct
import sys
import time
import zlib

from .archives import Entry, cpio_bytes
from .build import CMDLINE, make_seed, verify_output
from .compiler import compile_all
from .images import gz, kernel_from, sha256
from .layout import bootargs_map
from .serial_link import Link


def patch_bootloader(original, expected_sha):
    if len(original) != 2097152 or sha256(original) != expected_sha:
        raise ValueError('RAM 引导器原厂来源不一致')
    if struct.unpack_from('<I', original, 0x282c8)[0] != 0xea00006b:
        raise ValueError('引导器分支与已验证版本不一致')
    patched = bytearray(original)
    struct.pack_into('<I', patched, 0x282c8, 0xea000073)
    if [i for i, pair in enumerate(zip(original, patched)) if pair[0] != pair[1]] != [0x282c8]:
        raise ValueError('RAM 引导修改超出单条分支')
    return bytes(patched)


def bootargs_for(total, ram_size, *, installation=False):
    if not 0 < ram_size < 0x08d00000 - 0x06000000:
        raise ValueError('RAM initramfs 超出已验证装载区间')
    args = CMDLINE + f'initrd=0x06000000,{ram_size:#x} mtdparts=hinand:' + bootargs_map(total, readonly=not installation)
    if len(('setenv bootargs ' + args).encode()) >= 500:
        raise ValueError('RAM 参数超过原厂控制台行限制')
    return args


class NullLog:
    def write(self, text):
        return len(text)

    def flush(self):
        pass


async def connect_after_reset(port, device):
    port.send_break(.15)
    port.write(b'b')
    await device.connect(timeout=30)


def prepare_reset(link):
    # 高速传输会抑制内核控制台日志；SysRq 完成提示必须重新可见。
    link.command('sync; dmesg -n 7')
    link.wire.send_break(.15)
    link.wire.write(b'u')
    link.until(b'Emergency Remount complete', 20)


async def bootrom_console(hiloot_root, config, stock):
    sys.path.insert(0, str(hiloot_root))
    import serial
    import serial_asyncio
    from bootimg import BootParam, Memcpy
    from hiloot import Device
    from utils.serial import SerialLogger
    image = patch_bootloader(stock['fastboot'], config['profile']['fastboot_sha256'])
    params = BootParam.parse_v1(image)
    if (sha256(bytes(params.regs[1])) != '8f2d25d2bf51cf1426950186e0dd9b9176dd25c92e487b1b9fb3c26e821d8931' or
            params.head.size != 0x3000 or params.aux.size != 0x5400 or params.boot.end != 0xd9200):
        raise ValueError('原厂 DDR 或 BootROM 区间与已验证参数不一致')
    # 先加载上游模块、验证 DDR，再在同一连接重启，不能关闭/重开错过 BootROM。
    link = Link(config['port'])
    link.__enter__()
    port = link.wire
    try:
        prepare_reset(link)
    except BaseException:
        link.__exit__(*sys.exc_info())
        raise
    reader = asyncio.StreamReader(limit=131072)
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await serial_asyncio.connection_for_serial(asyncio.get_running_loop(), lambda: protocol, port)
    writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_running_loop())
    sink = NullLog()
    device = Device(reader, writer, 4, SerialLogger(sink))
    device.logbuf = sink
    try:
        await connect_after_reset(port, device)
        print('BootROM 握手成功，正在装载已校验的 DDR 与 RAM 引导副本', flush=True)
        chip = await device.get_chip()
        if chip.chipid != 1 or chip.sysid != 0x37980210:
            raise ValueError('BOOTROM 芯片不匹配')
        for region, label in ((params.head, '原厂头'), (params.aux, '原厂辅助代码')):
            await device.send_region(region, label)
        await asyncio.sleep(.5)
        await device.send_region(params.regs[1], '已验证原厂 LPDDR3')
        await asyncio.sleep(.5)
        await device.send_region(Memcpy.move(0, image, params.boot.end), 'RAM 串口引导副本')
        captured = bytearray()
        async with asyncio.timeout(50):
            while b'fastboot#' not in captured and b'hisilicon #' not in captured:
                part = await reader.read(4096)
                if not part:
                    raise EOFError('BootROM 串口关闭')
                captured.extend(part)
        print('RAM 原厂引导副本已进入命令行；没有写入引导分区', flush=True)
    finally:
        writer.close()
        await asyncio.sleep(.1)


def enter_fast_load(wire, address):
    wire.write(f'loady {address:#x} 921600\r'.encode())
    sink = object.__new__(Link)
    sink.wire = wire
    sink.until(b'press ENTER', 5)
    wire.baudrate = 921600
    # 已核对原厂 cmd_load：打印提示后前后各等待50ms才读回车。
    time.sleep(.2)
    wire.write(b'\r')


def upload_ram(wire, path, address):
    from ymodem.Socket import ModemSocket
    data = path.read_bytes()
    if address == 0x020007c0:
        if not 0 < len(data) < 0x04000000 - address:
            raise ValueError('内核超出 RAM 装载范围')
    elif address == 0x06000000:
        if not 0 < len(data) < 0x08d00000 - address:
            raise ValueError('initramfs 超出 RAM 装载范围')
    else:
        raise ValueError('未验证的 RAM 装载地址')
    enter_fast_load(wire, address)
    sink = object.__new__(Link)
    sink.wire = wire

    def read(count, timeout=3):
        wire.timeout = timeout
        return wire.read(count) or None

    def write(payload, timeout=3):
        wire.write_timeout = timeout
        return wire.write(payload)

    report = [0]
    def progress(index, name, total, sent):
        if time.monotonic() - report[0] > 15 or sent == total:
            print(f'RAM 传输 {path.name}：{sent}/{total}', flush=True)
            report[0] = time.monotonic()
    if not ModemSocket(read, write).send([str(path)], callback=progress):
        wire.write(b'\x18\x18\x18')
        raise RuntimeError('RAM YMODEM 传输失败，未执行镜像')
    time.sleep(.7)
    wire.timeout = .1
    wire.reset_input_buffer()
    wire.baudrate = 115200
    for _ in range(5):
        wire.write(b'\x1b')
        try:
            sink.until(b'fastboot#', 2)
            break
        except TimeoutError:
            pass
    else:
        raise TimeoutError('RAM 传输后未恢复原厂命令行')
    wire.write(f'crc32 {address:#x} {len(data):x}\r'.encode())
    reply = sink.until(b'fastboot#', 20)
    checksum = re.search(rb'==>\s*([0-9a-fA-F]{8})', reply)
    if not checksum or int(checksum.group(1), 16) != zlib.crc32(data) & 0xffffffff:
        raise ValueError('RAM 内容 CRC32 不一致，未执行镜像')


def validate_uimage(kernel):
    at = 0
    if kernel[at:at + 4] != bytes.fromhex('27051956'):
        raise ValueError('内核 uImage 入口与原厂已验证版本不一致')
    header = bytearray(kernel[at:at + 64])
    stored_header = struct.unpack_from('>I', header, 4)[0]
    struct.pack_into('>I', header, 4, 0)
    length = struct.unpack_from('>I', header, 12)[0]
    stored_data = struct.unpack_from('>I', header, 24)[0]
    if (len(kernel) != 64 + length or zlib.crc32(header) & 0xffffffff != stored_header or
            zlib.crc32(kernel[at + 64:at + 64 + length]) & 0xffffffff != stored_data):
        raise ValueError('原厂内核 uImage CRC 不一致')


def checked_ram_boot(wire, args):
    """读回完整参数再执行内核；出现提示符本身不能证明 setenv 成功。"""
    sink = object.__new__(Link)
    sink.wire = wire
    wire.write(('setenv bootargs ' + args + '\r').encode())
    response = sink.until(b'fastboot#', 3)
    if re.search(rb'Unknown command|Usage:|Error|error|too (?:long|many)', response):
        raise ValueError('RAM 启动参数设置失败，未执行内核')
    wire.write(b'printenv bootargs\r')
    reply = sink.until(b'fastboot#', 3).replace(b'\r', b'')
    actual = re.findall(rb'(?m)^bootargs=([^\n]*)\n', reply)
    if actual != [args.encode()]:
        raise ValueError('RAM 启动参数读回不一致，未执行内核')
    wire.write(b'bootm 0x020007c0\r')


def wait_console(wire, timeout=60, log=None, boot_marker=None):
    captured, deadline = bytearray(), time.monotonic() + timeout
    last_enter = float('-inf')
    while time.monotonic() < deadline:
        part = wire.read(8192)
        captured.extend(part)
        if log is not None:
            log.write(part)
        start = 0 if boot_marker is None else captured.find(boot_marker)
        if start >= 0 and b'root@OpenWrt' in captured[start:]:
            return bytes(captured)
        now = time.monotonic()
        if b'Please press Enter' in captured and now - last_enter >= 1:
            wire.write(b'\r')
            last_enter = now
    raise TimeoutError('启动后未检测到串口控制台；保留日志检查当前状态')


def ram_test(root, config, stock, output, bootstrap=False, *, installation=False):
    if bootstrap and installation:
        raise ValueError('bootstrap 不接受安装映射')
    if bootstrap:
        binaries = compile_all(root)
        entries = make_seed(root, stock, config)
        entries['sbin/ubusd'] = Entry(stat.S_IFREG | 0o755, binaries['ubusd'].read_bytes())
        entries['init'] = Entry(stat.S_IFREG | 0o755, b'#!/bin/sh\nexport INITRAMFS=1\nexec /sbin/init\n')
        for name, major, minor in (('console', 5, 1), ('ttyAMA0', 204, 64), ('null', 1, 3), ('zero', 1, 5)):
            entries['dev/' + name] = Entry(stat.S_IFCHR | 0o600, b'', major=major, minor=minor)
        output.mkdir(parents=True, exist_ok=True)
        ram_path = output / 'bootstrap.cpio.gz'
        ram_path.write_bytes(gz(cpio_bytes(entries)))
    else:
        verify_output(output, config, stock)
        ram_path = output / 'ram.cpio.gz'
    # 两个 RAM 分支都从锁定原始源码准备 hiloot，不依赖编译的副作用。
    from .resources import read_lock, verify_resource, extract_source
    hiloot_root = extract_source(verify_resource(root, read_lock(root)['hiloot-source']),
                                 root / 'local/build/hiloot-source', workspace=root / 'local/build')
    kernel = kernel_from(stock['boot'])
    validate_uimage(kernel)
    kernel_path = output / 'kernel.uImage'
    kernel_path.write_bytes(kernel)
    args = bootargs_for(config['profile']['total_bytes'], ram_path.stat().st_size, installation=installation)
    print('即将暂时中断热点并同步内部系统，再执行 RAM 启动', flush=True)
    asyncio.run(bootrom_console(hiloot_root, config, stock))
    import serial
    wire = serial.Serial(None, 115200, timeout=.1, write_timeout=10)
    wire.dtr = wire.rts = False
    wire.port = config['port']
    try:
        wire.open()
        wire.write(b'\r')
        sink = object.__new__(Link)
        sink.wire = wire
        sink.until(b'fastboot#', 3)
        upload_ram(wire, kernel_path, 0x020007c0)
        upload_ram(wire, ram_path, 0x06000000)
        checked_ram_boot(wire, args)
        with (output / 'ram-boot.log').open('wb') as log:
            wait_console(wire, 60, log)
        print('RAM OpenWrt 控制台已就绪；请进行热点与管理页面验收', flush=True)
    finally:
        if wire.is_open:
            wire.close()
    if not bootstrap and not installation:
        from .installer import record_ram_acceptance
        record_ram_acceptance(config, output)


def restore_internal(config):
    """RAM 验收后软件重启，原厂引导器自动加载原内部系统。"""
    with Link(config['port']) as link:
        link.command('sync')
        link.wire.write(b'reboot\r')
        wait_console(link.wire, boot_marker='CM2012 内部 OpenWrt 根系统入口'.encode())
        link.command('dmesg -n 1')
        print('内部 OpenWrt 已重新启动，串口控制台就绪', flush=True)
