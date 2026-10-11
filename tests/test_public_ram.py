"""RAM 实验分支修改与所有闪存只读参数保护。"""
import hashlib
import importlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
from test_public_serial import Wire

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class RamTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.ram')
        except ModuleNotFoundError:
            self.fail('RAM 启动接口尚未实现')

    def test_patch_changes_only_approved_branch_in_ram_copy(self):
        module = self.module()
        data = bytearray(2097152)
        struct.pack_into('<I', data, 0x282c8, 0xea00006b)
        digest = hashlib.sha256(data).hexdigest()
        patched = module.patch_bootloader(bytes(data), digest)
        self.assertEqual([i for i, pair in enumerate(zip(data, patched)) if pair[0] != pair[1]], [0x282c8])
        self.assertEqual(patched[0x282c8], 0x73)
        with self.assertRaises(ValueError):
            module.patch_bootloader(patched, digest)

    def test_ram_args_cover_entire_dynamic_flash_readonly(self):
        module = self.module()
        args = module.bootargs_for(17179869184, 10485760)
        parts = args.split('mtdparts=hinand:')[1].split()[0].split(',')
        self.assertEqual(len(parts), 9)
        self.assertTrue(all(part.endswith('ro') for part in parts))
        self.assertEqual(parts[-1], '16336M(userdata)ro')
        self.assertNotIn('ubi.mtd=', args)
        self.assertIn('initrd=0x06000000,0xa00000', args)
        with self.assertRaises(ValueError):
            module.bootargs_for(8589934592, 64 * 1048576)

    def test_uimage_crc_uses_header_at_start_of_kernel_blob(self):
        import zlib
        module = self.module()
        payload = b'kernel-data'
        header = bytearray(64)
        struct.pack_into('>7I', header, 0, 0x27051956, 0, 0, len(payload),
                         0x02000800, 0x02000800, zlib.crc32(payload))
        struct.pack_into('>I', header, 4, zlib.crc32(header))
        module.validate_uimage(bytes(header) + payload)
        with self.assertRaises(ValueError):
            module.validate_uimage(bytes(header) + payload + b'bad')

    def test_bootm_requires_exact_readback_after_setenv(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'checked_ram_boot', None)))
        args = module.bootargs_for(8589934592, 1048576)

        class Console(Wire):
            def __init__(self, response):
                super().__init__(b'')
                self.response = response
            def write(self, data):
                self.sent.extend(data)
                if data.startswith(b'setenv '):
                    self.data.extend(b'fastboot#')
                elif data == b'printenv bootargs\r':
                    self.data.extend(self.response + b'fastboot#')
                return len(data)

        for response in (b'bootargs=old rw ubi.mtd=userdata\n', b'\n',
                         ('bootargs=' + args[:-1] + '\n').encode(),
                         (('bootargs=' + args + '\n') * 2).encode()):
            with self.subTest(response=response):
                wire = Console(response)
                with self.assertRaises(ValueError):
                    module.checked_ram_boot(wire, args)
                self.assertNotIn(b'bootm', wire.sent)

        class BadCommand(Console):
            def write(self, data):
                if data.startswith(b'setenv '):
                    self.sent.extend(data); self.data.extend(b'Unknown command seten\r\nfastboot#'); return len(data)
                return super().write(data)
        wire = BadCommand(('bootargs=' + args + '\r\n').encode())
        with self.assertRaises(ValueError):
            module.checked_ram_boot(wire, args)
        self.assertNotIn(b'bootm', wire.sent)
        wire = Console(('bootargs=' + args + '\r\n').encode())
        module.checked_ram_boot(wire, args)
        self.assertTrue(wire.sent.endswith(b'bootm 0x020007c0\r'))

    def test_fast_baud_enter_waits_for_native_transition(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'enter_fast_load', None)))
        clock = [0.0]
        class Transition(Wire):
            def __init__(self):
                super().__init__(b''); self.baudrate = 115200
            def write(self, data):
                if data.startswith(b'loady '):
                    self.data.extend(b'## Switch baudrate to 921600 bps and press ENTER ...\r\n')
                elif data == b'\r':
                    if clock[0] < .1:
                        raise RuntimeError('原厂尚在两段50毫秒切速等待，回车会丢失')
                    if self.baudrate != 921600:
                        raise RuntimeError('回车速率错误')
                    self.data.extend(b'## Ready for binary (ymodem) download\r\nC')
                self.sent.extend(data); return len(data)
        wire = Transition()
        with patch.object(module.time, 'sleep', side_effect=lambda n: clock.__setitem__(0, clock[0] + n)):
            module.enter_fast_load(wire, 0x020007c0)
        self.assertEqual(wire.baudrate, 921600)
        self.assertTrue(wire.sent.endswith(b'\r'))

    def test_console_handles_split_prompt_and_early_enter_loss(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'wait_console', None)))
        clock = [0.0]
        class StartingConsole(Wire):
            def __init__(self):
                super().__init__(b'')
                self.chunks = [b'booting\nPlease press Ent', b'er to activate this console.\n']
                self.enters = 0
            def read(self, count):
                clock[0] += .25
                if self.chunks:
                    return self.chunks.pop(0)
                if self.enters >= 2:
                    return b'root@OpenWrt:~# '
                return b''
            def write(self, data):
                self.assert_enter(data)
                self.enters += 1
                self.sent.extend(data)
                return len(data)
            def assert_enter(self, data):
                if data != b'\r' or not self.enters and clock[0] < .5:
                    raise AssertionError('只允许在完整激活提示之后发送回车')
        wire = StartingConsole()
        capture = __import__('io').BytesIO()
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]):
            module.wait_console(wire, 5, capture)
        self.assertEqual(wire.enters, 2)
        self.assertIn(b'Please press Enter', capture.getvalue())

        class Silent(Wire):
            def read(self, count):
                clock[0] += .25
                return b''
        wire = Silent(b'')
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(TimeoutError):
                module.wait_console(wire, 1)
        self.assertEqual(wire.sent, b'')


if __name__ == '__main__':
    unittest.main()
