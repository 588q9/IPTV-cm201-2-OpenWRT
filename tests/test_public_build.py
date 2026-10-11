"""隔离构建的空间和产物保护。"""
import importlib
from pathlib import Path
import stat
import sys
import unittest
import tempfile
import json
import gzip
import struct

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class BuildTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.build')
        except ModuleNotFoundError:
            self.fail('完整构建接口尚未实现')

    def test_ram_estimate_includes_two_roots_and_reserve(self):
        module = self.module()
        self.assertEqual(module.required_ram_kib(100 * 1048576, 20 * 1048576), 290816)
        with self.assertRaises(ValueError):
            module.require_space(290815, 290816)

    def test_device_geometry_does_not_depend_on_retained_boot_log(self):
        class Device:
            def command(self, command):
                if command == 'uname -r': return '3.18.24_hi3798mv2x\n'
                if 'CM_GEOMETRY' in command:
                    return 'CM_GEOMETRY mlc-nand 2097152 8192 744 60 1024\n'
                if 'CM_SIZE' in command:
                    return 'CM_SIZE 50331648\nCM_SIZE 8539602944\n'
                if command == 'apk --version': return 'apk-tools 3.0.5, compiled for armv7.\n'
                raise AssertionError('不应依赖已覆盖的 dmesg: ' + command)
        geometry = self.module().check_device(Device(), {'profile': {'total_bytes': 8589934592}})
        self.assertEqual(geometry['mtd_ecc_strength'], 60)
        self.assertEqual(geometry['mtd_ecc_step_bytes'], 1024)

    def test_runtime_secrets_removed_without_removing_stock_firmware(self):
        module = self.module()
        from cm2012.archives import Entry
        entries = {n: Entry(stat.S_IFREG | 0o600, b'value') for n in (
            'etc/dropbear/dropbear_ed25519_host_key', 'etc/uhttpd.key',
            'etc/urandom.seed', 'root/.ssh/id_ed25519', 'lib/firmware/EEPROM_MT7668.bin')}
        cleaned = module.strip_runtime(entries)
        self.assertEqual(set(cleaned), {'lib/firmware/EEPROM_MT7668.bin'})

    def test_completion_marker_not_accepted_without_critical_files(self):
        module = self.module()
        from cm2012.archives import Entry
        entries = {'etc/cm2012-internal-root': Entry(stat.S_IFREG | 0o644,
                    b'CM2012_INTERNAL_OPENWRT25\n')}
        with self.assertRaises(ValueError):
            module.validate_root(entries)

    def test_signed_index_version_is_not_an_apk_world_dependency(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'locked_packages', None)))
        locks = {'index': {'path': 'local/cache/apk/packages.adb', 'version': '2026-10-07'},
                 'hostapd-basic': {'path': 'local/cache/apk/hostapd-basic.apk', 'version': '1.0-r4'}}
        self.assertEqual(module.locked_packages(locks), ['hostapd-basic=1.0-r4'])

    def test_service_account_check_accepts_locked_password_field(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'validate_accounts', None)))
        module.validate_accounts('network:*:101:101:network:/var:/bin/false\nubus:x:81:81:ubus:/var:/bin/false\n')
        with self.assertRaises(ValueError):
            module.validate_accounts('network:x:0:0:network:/var:/bin/false\nubus:x:81:81:ubus:/var:/bin/false\n')

    def test_critical_link_must_resolve_to_an_executable_in_root(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, 'resolve_file', None)))
        from cm2012.archives import Entry
        entries = {'sbin/init': Entry(stat.S_IFLNK | 0o777, b'../bin/tool'),
                   'bin/tool': Entry(stat.S_IFREG | 0o755, b'program')}
        self.assertEqual(module.resolve_file(entries, 'sbin/init', executable=True).data, b'program')
        for target in (b'/missing', b'../../outside', b'/sbin/init'):
            entries['sbin/init'] = Entry(stat.S_IFLNK | 0o777, target)
            with self.assertRaises(ValueError):
                module.resolve_file(entries, 'sbin/init', executable=True)
        entries['sbin/init'] = Entry(stat.S_IFLNK | 0o777, b'../bin/tool')
        entries['bin/tool'] = Entry(stat.S_IFREG | 0o644, b'program')
        with self.assertRaises(ValueError):
            module.resolve_file(entries, 'sbin/init', executable=True)

    def test_incomplete_manifest_is_never_a_complete_output(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            (output / 'manifest.json').write_text(json.dumps({'files': {}, 'geometry': {'total_bytes': 8 * 1024**3}}))
            with self.assertRaises(ValueError):
                module.verify_output(output, {'profile': {'total_bytes': 8 * 1024**3}}, {})

    def test_template_substitution_never_interprets_user_placeholders(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'ubusd'
            binary.write_bytes(b'program')
            for ssid, password in (('{{PASSWORD}}', 'secret123'), ('{{SSID}}', '{{PASSWORD}}'),
                                   ('safe', '{{SSID}}')):
                overlay = module.make_overlay(Path(__file__).resolve().parents[1],
                    {'ssid': ssid, 'ap_password': password}, {'ubusd': binary})
                from cm2012.runtime import quote
                config = overlay['etc/config/cm2012'].data.decode()
                self.assertIn('option ssid ' + quote(ssid), config)
                self.assertIn('option key ' + quote(password), config)

    def test_outputs_deliver_only_the_controlled_ram_artifact(self):
        from cm2012.archives import Entry, read_tar_bytes, tar_bytes
        from test_public_layout import fixture
        module = self.module()
        _, stock, profile = fixture()
        stock.update(misc=gzip.compress(b'\xff' * 2097152, mtime=0),
                     swdevinfo=gzip.compress(b'\xff' * 16777216, mtime=0))
        program = bytearray(84)
        program[:52] = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01\x01' + bytes(9),
                                  2, 40, 1, 0x1000, 52, 0, 0, 52, 32, 1, 0, 0, 0)
        struct.pack_into('<8I', program, 52, 1, 0, 0x1000, 0x1000, 84, 84, 5, 4096)
        entries = {name: Entry(stat.S_IFREG | 0o755, bytes(program)) for name in
                   ('sbin/init', 'sbin/ubusd', 'usr/sbin/hostapd', 'usr/sbin/uhttpd',
                    'usr/sbin/dnsmasq', 'etc/init.d/cm2012-ap', 'bin/busybox',
                    'usr/sbin/wpa_supplicant', 'usr/sbin/xtables-legacy-multi', 'sbin/fw3',
                    'usr/libexec/cm2012-wifi', 'usr/libexec/cm2012-wpa-control',
                    'usr/libexec/cm2012-net-probe', 'usr/libexec/cm2012-serial-transfer',
                    'etc/init.d/firewall', 'etc/init.d/sysntpd',
                    'lib/libc.so', 'lib/libgcc_s.so.1')}
        entries.update({'etc/config/cm2012': Entry(stat.S_IFREG | 0o600, b'config'),
            'usr/share/rpcd/ucode/cm2012': Entry(stat.S_IFREG | 0o644, b'rpc'),
            'usr/libexec/cm2012-wireless-lib.uc': Entry(stat.S_IFREG | 0o644, b'lib'),
            'usr/libexec/cm2012-supplicant.uc': Entry(stat.S_IFREG | 0o644, b'render'),
            'usr/share/rpcd/acl.d/luci-app-cm2012.json': Entry(stat.S_IFREG | 0o644, b'{}'),
            'usr/share/luci/menu.d/luci-app-cm2012.json': Entry(stat.S_IFREG | 0o644, b'{}'),
            'www/luci-static/resources/view/cm2012/wireless.js': Entry(stat.S_IFREG | 0o644, b'view'),
            'etc/cm2012-internal-root': Entry(stat.S_IFREG | 0o644, b'CM2012_INTERNAL_OPENWRT25\n'),
            'etc/passwd': Entry(stat.S_IFREG | 0o644, b'network:*:101:101:n:/var:/bin/false\nubus:*:81:81:u:/var:/bin/false\n')})
        from fixtures.arm_module import module_bytes
        from cm2012.hardware import MODULES, FIRMWARE
        entries.update({'lib/modules/3.18.24_hi3798mv2x/' + name: Entry(stat.S_IFREG | 0o644, module_bytes()) for name in MODULES})
        entries.update({'lib/firmware/' + name: Entry(stat.S_IFREG | 0o644, b'firmware') for name in FIRMWARE})
        entries = read_tar_bytes(tar_bytes(entries))
        module.validate_root(entries)
        incomplete = dict(entries)
        incomplete.pop('sbin/fw3')
        with self.assertRaises(ValueError):
            module.validate_root(incomplete)
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)
            binary = target / 'helper'
            binary.write_bytes(program)
            output = target / 'output'
            manifest = module.assemble_outputs(Path(__file__).resolve().parents[1], {'profile': profile},
                stock, {'cm2012-switch-root': binary}, entries, output)
            self.assertIn('ram.cpio.gz', manifest['files'])
            self.assertNotIn('ram-boot.img', manifest['files'])
            self.assertFalse((output / 'ram-boot.img').exists())


if __name__ == '__main__':
    unittest.main()
