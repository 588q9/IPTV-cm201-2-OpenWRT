"""Opt-in offline build: CM2012_RUN_COMPILER_INTEGRATION=1 python -m unittest
discover -s tests/integration -p test_compiler.py -v.

Requires prepared locked resources. Does not read device configuration, access
serial ports, or download resources. The ordinary public suite never builds.
"""
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from cm2012 import compiler


@unittest.skipUnless(os.environ.get('CM2012_RUN_COMPILER_INTEGRATION') == '1',
                     'set CM2012_RUN_COMPILER_INTEGRATION=1 to compile locked sources')
class CompilerIntegration(unittest.TestCase):
    def test_compile_from_locked_sources_without_old_analysis(self):
        binaries = compiler.compile_all(ROOT)
        self.assertEqual(set(binaries), {
            'ubusd', 'cm2012-switch-root', 'serial-transfer',
            'cm2012-net-probe', 'cm2012-wpa-control', 'cm2012-netlink-compat.so',
            'xtables-legacy-multi', 'libxtables.so.12', 'fw3',
            'mtdinfo', 'ubinfo', 'ubiformat', 'ubiattach', 'ubidetach',
            'ubimkvol', 'nandwrite', 'flash_erase'})
        for name, path in binaries.items():
            with self.subTest(binary=name):
                info = compiler.elf_info(path.read_bytes())
                if name == 'cm2012-netlink-compat.so':
                    self.assertTrue(info['has_dynamic'])
                    self.assertIsNone(info['interpreter'])
                    self.assertEqual(info['needed'], ())
                elif name == 'libxtables.so.12':
                    self.assertTrue(info['has_dynamic'])
                    self.assertIsNone(info['interpreter'])
                    self.assertEqual(info['needed'], ('libc.so',))
                elif name in ('ubusd', 'fw3'):
                    expected = compiler.UBUSD_NEEDED if name == 'ubusd' else compiler.FW3_NEEDED
                    compiler.elf_check(path, static=False, expected_needed=expected)
                else:
                    compiler.elf_check(path, static=True, expected_needed=())


if __name__ == '__main__':
    unittest.main()
