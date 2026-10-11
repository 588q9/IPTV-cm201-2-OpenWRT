"""串口块校验和中断测试，传输替身仅代替物理串口。"""
import importlib
from pathlib import Path
import struct
import sys
import unittest
import zlib
import re

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class Wire:
    def __init__(self, data):
        self.data = bytearray(data)
        self.sent = bytearray()

    def read(self, count):
        chunk = bytes(self.data[:count])
        del self.data[:count]
        return chunk

    def write(self, data):
        self.sent.extend(data)
        return len(data)


class SerialTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.serial_link')
        except ModuleNotFoundError:
            self.fail('串口接口尚未实现')

    def test_bad_crc_then_duplicate_frame_does_not_duplicate_data(self):
        module = self.module()
        payload = b'abc'
        frame = b'CM3F' + struct.pack('<III', 0, 3, zlib.crc32(payload)) + payload
        wrong = b'CM3F' + struct.pack('<III', 0, 3, 0) + payload
        wire = Wire(wrong + frame + frame + b'CM3E')
        self.assertEqual(module.receive_frames(wire, 3, timeout=.05), b'abc')
        self.assertEqual(wire.sent, b'CM3N' + struct.pack('<I', 0) +
                         (b'CM3A' + struct.pack('<I', 0)) * 2 + b'CM3A' + struct.pack('<I', 1))

    def test_interrupted_frame_never_returns_partial_file(self):
        module = self.module()
        wire = Wire(b'CM3F' + struct.pack('<III', 0, 3, 0) + b'a')
        with self.assertRaises(TimeoutError):
            module.receive_frames(wire, 3, timeout=.01)

    def test_inserted_byte_between_frames_resynchronizes(self):
        module = self.module()
        payload = b'a' * 1024 + b'b'
        first = b'CM3F' + struct.pack('<III', 0, 1024, zlib.crc32(payload[:1024])) + payload[:1024]
        last = b'CM3F' + struct.pack('<III', 1, 1, zlib.crc32(b'b')) + b'b'
        wire = Wire(first + b'\x67' + last + b'CM3E')
        self.assertEqual(module.receive_frames(wire, len(payload), timeout=.05), payload)

    def test_corrupt_frame_and_residual_bytes_retry_without_partial_result(self):
        module = self.module()
        frame = b'CM3F' + struct.pack('<III', 0, 3, zlib.crc32(b'abc')) + b'abc'
        wire = Wire(frame[:-1] + b'X\x67\xf8\x6a\x93' + frame + b'CM3E')
        self.assertEqual(module.receive_frames(wire, 3, timeout=.05), b'abc')
        self.assertIn(b'CM3N', wire.sent)

    def test_refuse_foreign_target_path(self):
        module = self.module()
        for path in ('/etc/config/network', '/tmp/cm2012-build-x/../etc',
                     '/tmp/cm2012-build-x/input;reboot'):
            with self.assertRaises(ValueError):
                module.check_device_path(path)

    def test_command_echo_and_double_cr_are_not_status(self):
        module = self.module()

        class EchoWire(Wire):
            def write(self, data):
                super().write(data)
                if data.endswith(b'\r'):
                    token = re.search(rb'CM_DONE_[a-z0-9]+', self.sent).group()
                    self.data.extend(self.sent + b'\r\nresult\r\r\n' + token + b'=0\r\r\nroot@OpenWrt:~# ')
                return len(data)

        link = object.__new__(module.Link)
        link.wire = EchoWire(b'')
        self.assertIn('result', link.command('printf result', timeout=.1))
        self.assertTrue(link.wire.sent.startswith(b'\x15'))

    def test_lost_ack_retransmits_same_block_before_advancing(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'send_frames', None)), '可重试上传接口尚未实现')

        class Receiver(Wire):
            def __init__(self):
                super().__init__(b'')
                self.received = bytearray()
                self.sequence = 0
                self.lost = False

            def write(self, frame):
                if frame == b'CM3E':
                    self.data.extend(b'CM3A' + struct.pack('<I', self.sequence))
                    return len(frame)
                index, size, checksum = struct.unpack('<III', frame[4:16])
                chunk = frame[16:]
                if size != len(chunk) or zlib.crc32(chunk) != checksum:
                    raise ValueError('发送的帧被破坏')
                if index == self.sequence:
                    self.received.extend(chunk)
                    self.sequence += 1
                elif index != self.sequence - 1:
                    raise ValueError('丢失确认后跳过了序号')
                if not self.lost:
                    self.lost = True
                else:
                    self.data.extend(b'CM3A' + struct.pack('<I', index))
                return len(frame)

        wire = Receiver()
        payload = bytes(range(256)) * 8
        module.send_frames(wire, payload, timeout=.002)
        self.assertEqual(wire.received, payload)

    def test_stale_ack_cannot_advance_the_next_block(self):
        module = self.module()

        class IndexedReceiver(Wire):
            def write(self, frame):
                self.sent.extend(frame)
                if frame == b'CM3E':
                    self.data.extend(b'CM3A' + struct.pack('<I', 2))
                else:
                    index = struct.unpack('<I', frame[4:8])[0]
                    if index == 1:
                        self.data.extend(b'CM3A' + struct.pack('<I', 0))
                    self.data.extend(b'CM3A' + struct.pack('<I', index))
                return len(frame)

        wire = IndexedReceiver(b'')
        module.send_frames(wire, b'x' * 1025, timeout=.05)
        self.assertEqual(wire.sent.count(b'CM3F'), 2)

    def test_restore_waits_for_shell_before_next_command(self):
        module = self.module()

        class ShellWire(Wire):
            baudrate = 921600

            def flush(self):
                pass

            def write(self, data):
                if data == b'R':
                    self.data.extend(b'CM3_RESTORED\r\r\nroot@OpenWrt:~# ')
                else:
                    if self.data:
                        raise RuntimeError('ash 尚未进入读取阶段，命令会丢失')
                    self.sent.extend(data)
                    if data.endswith(b'\r'):
                        token = re.search(rb'CM_DONE_[a-z0-9]+', self.sent).group()
                        self.data.extend(b'ready\r\n' + token + b'=0\r\nroot@OpenWrt:~# ')
                return len(data)

        link = object.__new__(module.Link)
        link.wire = ShellWire(b'')
        link.restore()
        self.assertIn('ready', link.command('printf ready', timeout=.1))

    def test_kernel_console_noise_cannot_corrupt_transfer_ack(self):
        module = self.module()
        class NoisyConsole(Wire):
            quiet = False
            def __init__(self):
                super().__init__(b''); self.line = bytearray()
            def write(self, data):
                if data == b'G':
                    if not self.quiet: self.data.extend(b'wlan: driver notice\r\n')
                    self.data.extend(b'CM3A' + struct.pack('<I', 0))
                else:
                    self.line.extend(data)
                    if self.line.endswith(b'\r'):
                        if b'dmesg -n 1' in self.line:
                            self.quiet = True
                            token = re.search(rb'CM_DONE_[a-z0-9]+', self.line).group()
                            self.data.extend(token + b'=0\nroot@OpenWrt:~# ')
                        else:
                            self.data.extend(b'CM3_SWITCH\r\n')
                        self.line.clear()
                return len(data)
        link = object.__new__(module.Link); link.wire = NoisyConsole()
        link.switch('/tmp/cm2012-build-test/serial-transfer rx /tmp/cm2012-build-test/a 1')
        self.assertTrue(module.frame_ack(link.wire, 0, .1))

    def test_background_command_keeps_valid_shell_separator(self):
        module = self.module()

        class BackgroundShell(Wire):
            def write(self, data):
                self.sent.extend(data)
                if b'&;' in self.sent:
                    raise ValueError('实际 ash 已验证：& 后面不能紧接分号')
                if data.endswith(b'\r'):
                    token = re.search(rb'CM_DONE_[a-z0-9]+', self.sent).group()
                    self.data.extend(b'started\n' + token + b'=0\nroot@OpenWrt:~# ')
                return len(data)

        link = object.__new__(module.Link)
        link.wire = BackgroundShell(b'')
        self.assertIn('started', link.command('(true) >/dev/null 2>&1 &', timeout=.1))


class ControlPacingTests(unittest.TestCase):
    def test_control_survives_uart_input_overrun_at_busy_startup(self):
        module = importlib.import_module('cm2012.serial_link')
        clock = [0.0]
        class BusyConsole(Wire):
            def __init__(self):
                super().__init__(b''); self.line = bytearray()
            def write(self, data):
                # 忙碌的旧内核一次只能处理16字节；长连续输入会丢状态参数。
                delivered = data if len(data) <= 16 else data.replace(b'$?', b'')
                self.line.extend(delivered)
                if self.line.endswith(b'\r'):
                    import re
                    token = re.search(rb'CM_DONE_[a-z0-9]+', self.line).group()
                    status = b'0' if b'$?' in self.line else b''
                    self.data.extend(b'ok\n' + token + b'=' + status + b'\nroot@OpenWrt:~# ')
                self.sent.extend(data)
                return len(data)
            def read(self, count):
                clock[0] += .02
                return super().read(count)
        wire = BusyConsole()
        link = object.__new__(module.Link); link.wire = wire
        from unittest.mock import patch
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(module.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            self.assertEqual(link.command('cat /proc/cmdline'), 'ok\n')


if __name__ == '__main__':
    unittest.main()
