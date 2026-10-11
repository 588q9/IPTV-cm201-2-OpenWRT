"""ARM ELF 动态依赖校验，不需要本机工具链或原厂输入。"""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from cm2012.compiler import elf_check


NEEDED = ('libubox.so.20260213', 'libblobmsg_json.so.20260213',
          'libjson-c.so.5', 'libc.so')


def dynamic_arm_elf(needed=NEEDED, interpreter=b'/lib/ld-musl-armhf.so.1\0'):
    """生成有真实程序头和动态字符串表的最小 ARM32 ELF。"""
    strings = bytearray(b'\0')
    indexes = []
    for name in needed:
        indexes.append(len(strings))
        strings.extend(name.encode() + b'\0')
    dynamic = [(5, 0x1180), (10, len(strings))]
    dynamic.extend((1, index) for index in indexes)
    dynamic.append((0, 0))
    data = bytearray(0x180 + len(strings))
    data[:52] = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01\x01' + bytes(9),
                           3, 40, 1, 0x1000, 52, 0, 0x5000400, 52, 32, 3, 0, 0, 0)
    headers = ((1, 0, 0x1000, 0x1000, len(data), len(data), 5, 4096),
               (3, 0xa0, 0x10a0, 0x10a0, len(interpreter), len(interpreter), 4, 1),
               (2, 0x100, 0x1100, 0x1100, len(dynamic) * 8, len(dynamic) * 8, 6, 4))
    for index, header in enumerate(headers):
        struct.pack_into('<8I', data, 52 + index * 32, *header)
    data[0xa0:0xa0 + len(interpreter)] = interpreter
    for index, item in enumerate(dynamic):
        struct.pack_into('<II', data, 0x100 + index * 8, *item)
    data[0x180:] = strings
    return bytes(data)


class MemoryELF:
    name = 'ubusd'

    def __init__(self, data):
        self.data = data

    def read_bytes(self):
        return self.data


class CompilerTests(unittest.TestCase):
    def test_reject_host_path_in_actual_needed_string_table(self):
        # 原始错误：无 SONAME 的 libc 通过绝对路径链接后生成此依赖。
        for wrong in ('C:\\build\\link-libs\\libc.so', '/host/build/libc.so',
                      '..\\libc.so', '../libc.so'):
            with self.subTest(needed=wrong), self.assertRaises(ValueError):
                elf_check(MemoryELF(dynamic_arm_elf(NEEDED[:-1] + (wrong,))), static=False)

    def test_accept_and_return_four_runtime_library_names(self):
        self.assertEqual(elf_check(MemoryELF(dynamic_arm_elf()), static=False), NEEDED)

    def test_interpreter_must_be_in_program_header_not_incidental_text(self):
        data = dynamic_arm_elf(interpreter=b'/wrong-loader\0')
        data += b'/lib/ld-musl-armhf.so.1\0'
        with self.assertRaises(ValueError):
            elf_check(MemoryELF(data), static=False)

    def test_reject_truncated_elf_as_value_error(self):
        with self.assertRaises(ValueError):
            elf_check(MemoryELF(b'\x7fELF\x01\x01\x01'), static=False)


if __name__ == '__main__':
    unittest.main()
