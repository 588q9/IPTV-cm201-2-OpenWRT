"""原厂输入不能以普通版本字符串冒充模块，也不能遗漏无线固件。"""
from pathlib import Path
import stat
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from cm2012.archives import Entry
from fixtures.arm_module import module_bytes

MODULES = ('cfg80211.ko', 'hi_sdio_detect.ko', 'wlan_mt7668_sdio.ko',
           'ehci-platform.ko', 'ohci-platform.ko', 'xhci-plat-hcd.ko')
FIRMWARE = ('EEPROM_MT7668.bin', 'EEPROM_MT7668_e1.bin', 'mt7668_patch_e1_hdr.bin',
            'mt7668_patch_e2_hdr.bin', 'WIFI_RAM_CODE_MT7668.bin',
            'WIFI_RAM_CODE2_SDIO_MT7668.bin', 'wifi.cfg')


class HardwareTests(unittest.TestCase):
    def support(self):
        result = {'system/lib/modules/' + name: Entry(stat.S_IFREG | 0o644, module_bytes()) for name in MODULES}
        result.update({'system/etc/firmware/' + name: Entry(stat.S_IFREG | 0o644, b'firmware') for name in FIRMWARE})
        return result

    def test_complete_support_and_actual_module_metadata(self):
        from cm2012 import build
        self.assertTrue(callable(getattr(build, 'validate_support', None)))
        build.validate_support(self.support())

    def test_missing_empty_or_linked_firmware_rejected(self):
        from cm2012 import build
        self.assertTrue(callable(getattr(build, 'validate_support', None)))
        for filename in FIRMWARE:
            for entry in (None, Entry(stat.S_IFREG | 0o644), Entry(stat.S_IFLNK | 0o777, b'/etc/private')):
                support = self.support(); path = 'system/etc/firmware/' + filename
                if entry is None:
                    del support[path]
                else:
                    support[path] = entry
                with self.subTest(file=filename, mode=entry), self.assertRaises(ValueError):
                    build.validate_support(support)

    def test_module_string_outside_modinfo_or_wrong_abi_rejected(self):
        from cm2012 import build
        self.assertTrue(callable(getattr(build, 'validate_support', None)))
        for data in (b'3.18.24_hi3798mv2x', b'\x7fELF\x01\x01\x01',
                     module_bytes(b'wrong-kernel') + b'vermagic=3.18.24_hi3798mv2x',
                     module_bytes(b'3.18.24_hi3798mv2x SMP preempt mod_unload ARMv7 p2v8 ')):
            support = self.support()
            support['system/lib/modules/wlan_mt7668_sdio.ko'] = Entry(stat.S_IFREG | 0o644, data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                build.validate_support(support)
