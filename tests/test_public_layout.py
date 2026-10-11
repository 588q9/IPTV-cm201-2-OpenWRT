"""合成硬件资料验证公开组装器，不读取本机备份。"""
import binascii
import gzip
import hashlib
import importlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
MIB = 1048576


def fixture():
    kernel = b'fixture-kernel' * 100
    ram = gzip.compress(b'070701' + b'fixture', mtime=0)
    header = bytearray(2048)
    header[:8] = b'ANDROID!'
    struct.pack_into('<10I', header, 8, len(kernel), 0x02000000, len(ram),
                     0x06000000, 0, 0, 0, 2048, 0, 0)
    header[64:69] = b'test '
    digest = hashlib.sha1()
    for contents in (kernel, ram, b''):
        digest.update(contents)
        digest.update(struct.pack('<I', len(contents)))
    header[576:608] = digest.digest().ljust(32, b'\0')
    pad = lambda x: x + bytes(-len(x) % 2048)
    boot = bytes(header) + pad(kernel) + pad(ram)
    fastboot, baseparam = b'original bootloader', b'parameters'
    mlc = b'MLCVERIFY!\0\0' + bytes(8) + struct.pack('<I', 7)
    stock = {'boot': boot, 'fastboot': fastboot, 'baseparam': baseparam, 'mlc': mlc}
    profile = {n + '_sha256': hashlib.sha256(stock[n]).hexdigest()
               for n in ('boot', 'fastboot', 'baseparam', 'mlc')}
    profile.update(total_bytes=8 * 1024 * MIB, erase_bytes=2 * MIB)
    return boot, stock, profile


class LayoutTests(unittest.TestCase):
    def module(self, name):
        try:
            return importlib.import_module('cm2012.' + name)
        except ModuleNotFoundError:
            self.fail('公开接口尚未实现：' + name)

    def test_dynamic_remainder_and_64bit_ptable(self):
        layout = self.module('layout')
        images = self.module('images')
        boot, stock, profile = fixture()
        for total_mib, remainder_mib in ((4096, 4048), (8192, 8144), (16384, 16336)):
            with self.subTest(total=total_mib):
                profile['total_bytes'] = total_mib * MIB
                parts = layout.layout_for(profile['total_bytes'], 2 * MIB)
                self.assertEqual(parts[-1], ('userdata', 48 * MIB, remainder_mib * MIB, 32))
                files, manifest = images.make_bundle(boot, stock, profile)
                last = struct.unpack_from('<I64sQQI', files['ptable.bin'], 16 + 8 * 88)
                self.assertEqual(last[2:4], (48 * MIB, remainder_mib * MIB))
                self.assertEqual(manifest['geometry']['total_bytes'], total_mib * MIB)

    def test_reject_geometry_that_cannot_use_entire_flash(self):
        module = self.module('layout')
        for total, erase in ((48 * MIB, 2 * MIB), (8193 * MIB, 2 * MIB),
                             (8192 * MIB, MIB), (-1, 2 * MIB), (2**64, 2 * MIB)):
            with self.subTest(total=total, erase=erase):
                with self.assertRaises(ValueError):
                    module.layout_for(total, erase)

    def test_reject_overlap_and_modified_core_layout(self):
        module = self.module('layout')
        parts = list(module.layout_for(8192 * MIB, 2 * MIB))
        parts[-1] = ('userdata', 46 * MIB, 8146 * MIB, 32)
        with self.assertRaises(ValueError):
            module.validate_layout(parts, 8192 * MIB, 2 * MIB)

    def test_source_guards_and_generated_crc(self):
        module = self.module('images')
        boot, stock, profile = fixture()
        for name in ('fastboot', 'baseparam', 'boot', 'mlc'):
            corrupt = dict(stock)
            corrupt[name] += b'changed'
            with self.subTest(source=name):
                with self.assertRaisesRegex(ValueError, name):
                    module.make_bundle(boot, corrupt, profile)
        files, manifest = module.make_bundle(boot, stock, profile)
        self.assertNotIn('fastboot.bin', files)
        table = files['ptable.bin']
        self.assertEqual(struct.unpack_from('<I', table, 8)[0],
                         binascii.crc_hqx(table[12:808], 0))
        mlc = files['mlcverify.bin']
        self.assertEqual(struct.unpack_from('<I', mlc, 12)[0],
                         binascii.crc_hqx(mlc[16:264], 0))
        self.assertEqual(struct.unpack_from('<I', mlc, 24 + 2 * 80 + 76)[0],
                         binascii.crc_hqx(boot, 0))
        self.assertEqual(manifest['files']['boot.img']['sha256'],
                         hashlib.sha256(boot).hexdigest())

    def test_reject_invalid_boot(self):
        module = self.module('images')
        boot, stock, profile = fixture()
        changed_kernel = bytearray(boot)
        changed_kernel[2048] ^= 1
        no_separator = bytearray(boot)
        no_separator[64:69] = b'test\0'
        for image in (bytes(changed_kernel), bytes(no_separator), bytes(12 * MIB + 1)):
            with self.assertRaises(ValueError):
                module.make_bundle(image, stock, profile)


if __name__ == '__main__':
    unittest.main()
