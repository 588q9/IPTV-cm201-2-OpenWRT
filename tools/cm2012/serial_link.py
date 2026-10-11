"""串口单连接、短控制命令与带 CRC/摘要的临时文件传输。"""
import hashlib
import re
import shlex
import struct
import time
import uuid
import zlib


def check_device_path(path):
    if not re.fullmatch(r'/tmp/cm2012-build-[a-z0-9]+/[A-Za-z0-9_./-]+', path) or '..' in path:
        raise ValueError('只允许操作本次 RAM 构建目录')
    return path


def exact(wire, count, timeout):
    result, deadline = bytearray(), time.monotonic() + timeout
    while len(result) < count and time.monotonic() < deadline:
        result.extend(wire.read(count - len(result)))
    if len(result) != count:
        raise TimeoutError('串口分块中断')
    return bytes(result)


def receive_frames(wire, length, timeout=5):
    if not 0 < length <= 64 * 1048576:
        raise ValueError('串口资源大小越界')
    data, sequence, failures = bytearray(), 0, 0
    pending, skipped = bytearray(), 0
    report = time.monotonic()

    def fill(count):
        if len(pending) < count:
            pending.extend(exact(wire, count - len(pending), timeout))

    while True:
        fill(4)
        marker = pending[:4]
        if marker == b'CM3E':
            if len(data) != length:
                raise ValueError('传输提前结束')
            wire.write(b'CM3A' + struct.pack('<I', sequence))
            return bytes(data)
        if marker != b'CM3F':
            del pending[0]
            skipped += 1
            if skipped > 4096:
                raise ValueError('串口无法恢复分块同步')
            continue
        fill(16)
        index, size, checksum = struct.unpack('<III', pending[4:16])
        if (index not in (sequence, sequence - 1) or index >= (length + 1023) // 1024 or
                size != min(1024, length - index * 1024)):
            del pending[0]
            skipped += 1
            if skipped > 4096:
                raise ValueError('串口分块头无法恢复')
            continue
        fill(16 + size)
        payload = bytes(pending[16:16 + size])
        if zlib.crc32(payload) & 0xffffffff != checksum:
            failures += 1
            wire.write(b'CM3N' + struct.pack('<I', index))
            if failures > 64:
                raise ValueError('串口块错误过多')
            # 丢失字节可能已读入重传帧的开头，保留缓冲重新寻找边界。
            del pending[0]
            continue
        if index == sequence:
            data.extend(payload)
            sequence += 1
        elif index != sequence - 1 or data[index * 1024:index * 1024 + size] != payload:
            raise ValueError('分块序号不正确')
        del pending[:16 + size]
        skipped = 0
        wire.write(b'CM3A' + struct.pack('<I', index))
        if time.monotonic() - report > 15:
            print(f'串口下载：{len(data)}/{length} 字节', flush=True)
            report = time.monotonic()


def frame_ack(wire, index, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        packet = exact(wire, 8, max(.001, deadline - time.monotonic()))
        if packet[:4] not in (b'CM3A', b'CM3N'):
            raise ValueError('串口确认标识错误')
        if struct.unpack('<I', packet[4:])[0] == index:
            return packet[:4] == b'CM3A'
    return False


def send_frames(wire, data, timeout=2):
    report = time.monotonic()
    for index, offset in enumerate(range(0, len(data), 1024)):
        chunk = data[offset:offset + 1024]
        frame = b'CM3F' + struct.pack('<III', index, len(chunk), zlib.crc32(chunk)) + chunk
        for retry in range(5):
            wire.write(frame)
            try:
                accepted = frame_ack(wire, index, timeout)
            except TimeoutError:
                accepted = False
            if accepted:
                break
        else:
            raise ValueError('上传分块重试失败')
        if time.monotonic() - report > 15:
            print(f'串口上传：{offset + len(chunk)}/{len(data)} 字节', flush=True)
            report = time.monotonic()
    wire.write(b'CM3E')
    if not frame_ack(wire, (len(data) + 1023) // 1024, 5):
        raise ValueError('上传结束未确认')


class Link:
    def __init__(self, port):
        import serial
        self.wire = serial.Serial(None, 115200, timeout=.05, write_timeout=10)
        self.wire.dtr = self.wire.rts = False
        self.wire.port = port

    def __enter__(self):
        self.wire.open()
        if hasattr(self.wire, 'set_buffer_size'):
            self.wire.set_buffer_size(rx_size=65536, tx_size=65536)
        self.wire.write(b'\r')
        time.sleep(.15)
        self.wire.reset_input_buffer()
        return self

    def __exit__(self, *_):
        if self.wire.is_open:
            if self.wire.baudrate != 115200:
                self.wire.write(b'Q')
                time.sleep(.3)
                self.wire.baudrate = 115200
            self.wire.close()

    def until(self, marker, timeout=15, limit=1048576):
        data, deadline = bytearray(), time.monotonic() + timeout
        while time.monotonic() < deadline:
            data.extend(self.wire.read(1))
            if data.endswith(marker):
                return bytes(data)
            if len(data) > limit:
                raise RuntimeError('串口控制响应过长')
        raise TimeoutError('串口控制响应超时')

    def command(self, text, timeout=15):
        token = 'CM_DONE_' + uuid.uuid4().hex[:12]
        separator = ' ' if text.rstrip().endswith(' &') else '; '
        line = text + separator + f'printf "\\n{token}=%s\\n" "$?"'
        if len(line.encode()) > 500 or '\n' in line or '\r' in line:
            raise ValueError('串口控制命令超过控制台行限制')
        # 高速传输/旧驱动可能留下编辑缓冲字节，先清行，避免拼接成另一条命令。
        control = b'\x15' + (line + '\r').encode()
        # 旧内核在无线初始化期间曾发生输入溢出；短段之间留出处理时间。
        for offset in range(0, len(control), 16):
            self.wire.write(control[offset:offset + 16])
            time.sleep(.01)
        output, deadline = bytearray(), time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('盒子命令超时')
            part = self.until(b'\n', remaining)
            match = re.fullmatch(token.encode() + rb'=(\d+)\r*\n', part)
            if match:
                if match.group(1) != b'0':
                    raise RuntimeError('盒子命令失败：' + output.decode(errors='replace')[-2000:])
                break
            output.extend(part)
        self.until(b'# ', 5)
        # 只返回命令状态与输出；调用者不得打印编码载荷的回显。
        return output.decode(errors='replace')

    def put_small(self, path, data, mode=0o600):
        check_device_path(path)
        self.command(f': > {shlex.quote(path)}')
        # 目标 BusyBox 没有 base64；ash 内建 printf 的八进制格式无额外依赖。
        for offset in range(0, len(data), 64):
            encoded = ''.join('\\' + f'{byte:03o}' for byte in data[offset:offset + 64])
            self.command(f"printf '{encoded}' >> {shlex.quote(path)}")
        self.command(f'chmod {mode:o} {shlex.quote(path)}')
        self.hash_check(path, hashlib.sha256(data).hexdigest())

    def hash_check(self, path, expected):
        check_device_path(path)
        output = self.command('sha256sum ' + shlex.quote(path))
        if not re.search(r'(?m)^' + re.escape(expected) + r'\s', output.replace('\r', '')):
            raise ValueError('盒子文件 SHA256 不一致')

    def switch(self, command):
        # 原厂无线日志也写串口；二进制传输期间禁止其混入帧确认。
        # 日志仍保留在 dmesg，RAM 重启入口会恢复所需控制台级别。
        self.command('dmesg -n 1')
        self.wire.write((command + '\r').encode())
        while self.until(b'\n').rstrip(b'\r\n') != b'CM3_SWITCH':
            pass
        self.wire.baudrate = 460800
        time.sleep(.15)
        self.wire.write(b'G')

    def restore(self):
        self.wire.write(b'R')
        self.wire.flush()
        self.wire.baudrate = 115200
        while self.until(b'\n', 5).rstrip(b'\r\n') != b'CM3_RESTORED':
            pass
        # helper 先恢复 termios 再退出；等 ash 提示符，避免其初始化时清掉下一条命令。
        self.until(b'# ', 5)

    def upload(self, helper, path, data):
        check_device_path(helper)
        check_device_path(path)
        if not 0 < len(data) <= 64 * 1048576:
            raise ValueError('上传资源大小越界')
        self.switch(f'{helper} rx {path} {len(data)}')
        send_frames(self.wire, data)
        self.restore()
        self.hash_check(path, hashlib.sha256(data).hexdigest())

    def download(self, helper, path, length, expected):
        check_device_path(helper)
        check_device_path(path)
        self.switch(f'{helper} tx {path}')
        data = receive_frames(self.wire, length, timeout=15)
        self.restore()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('下载文件 SHA256 不一致')
        return data
