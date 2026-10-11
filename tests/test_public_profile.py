"""容量必须由物理信息与有效分区表交叉确认。"""
import binascii
import importlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class ProfileTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.profile')
        except ModuleNotFoundError:
            self.fail('原厂档案接口尚未实现')

    def test_physical_capacity_64bit_and_geometry(self):
        module = self.module()
        geometry = module.geometry_from_log('nand: Block:2MB Page:8KB OOB:744B ECC:40bits/1K Chip:16GB read-retry ONFI DDR 2.3')
        self.assertEqual(geometry['total_bytes'], 17179869184)
        self.assertEqual(geometry['erase_bytes'], 2097152)
        for line in ('Chip:16GB', 'nand: Block:1MB Page:8KB OOB:744B ECC:40bits/1K Chip:8GB'):
            with self.assertRaises(ValueError):
                module.geometry_from_log(line)

    def test_invalid_original_ptable_crc_or_overlap_rejected(self):
        module = self.module()
        table = bytearray(0xb10)
        table[:8] = b'PTABLE!!'
        struct.pack_into('<I', table, 12, 2)
        struct.pack_into('<I64sQQI', table, 16, 0, b'fastboot', 0, 2097152, 0)
        struct.pack_into('<I64sQQI', table, 104, 0, b'data', 2097152, 8587837440, 32)
        struct.pack_into('<I', table, 8, binascii.crc_hqx(table[12:192], 0))
        self.assertEqual(module.total_from_ptable(bytes(table)), 8589934592)
        table[200] ^= 1  # 有效 CRC 范围之外的保留区不影响表数据。
        table[180] ^= 1
        with self.assertRaises(ValueError):
            module.total_from_ptable(bytes(table))
        struct.pack_into('<Q', table, 104 + 68, 0)
        struct.pack_into('<I', table, 8, binascii.crc_hqx(table[12:192], 0))
        with self.assertRaises(ValueError):
            module.total_from_ptable(bytes(table))


if __name__ == '__main__':
    unittest.main()
