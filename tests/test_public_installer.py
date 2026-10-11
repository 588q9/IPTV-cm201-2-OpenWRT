"""每次安装保护消费本次产物哈希与动态容量。"""
import importlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import tempfile
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from test_public_layout import fixture


class InstallerTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.installer')
        except ModuleNotFoundError:
            self.fail('动态安装保护尚未实现')

    def manifest(self):
        from cm2012.images import make_bundle
        boot, stock, profile = fixture()
        profile['total_bytes'] = 17179869184
        _, manifest = make_bundle(boot, stock, profile)
        for name in ('rootfs.tar.gz', 'misc.bin.gz', 'swdevinfo.bin.gz'):
            manifest['files'][name] = {'sha256': 'a' * 64, 'size': 100}
        manifest['core_uncompressed'] = {'misc': {'sha256': 'b' * 64, 'size': 2097152},
                                        'swdevinfo': {'sha256': 'c' * 64, 'size': 16777216}}
        return manifest

    def test_environment_uses_current_boot_hash_and_dynamic_remainder(self):
        module = self.module()
        manifest = self.manifest()
        env = module.make_install_env(manifest)
        self.assertIn(b'DATA_BYTES=17129537536\n', env)
        original = env
        manifest['files']['boot.img']['sha256'] = 'd' * 64
        changed = module.make_install_env(manifest)
        self.assertNotEqual(original, changed)
        self.assertIn(b'BOOT_SHA=' + b'd' * 64 + b'\n', changed)

    def test_modified_core_boundary_and_shell_injected_hash_fail(self):
        module = self.module()
        manifest = self.manifest()
        manifest['partitions'][7]['start_bytes'] -= 2097152
        with self.assertRaises(ValueError):
            module.make_install_env(manifest)
        manifest = self.manifest()
        manifest['files']['boot.img']['sha256'] = '$(reboot)'
        with self.assertRaises(ValueError):
            module.make_install_env(manifest)

    def test_root_digest_covers_all_regular_files_and_rejects_unsafe_names(self):
        from cm2012.archives import Entry
        import stat
        fn = self.module().root_digest
        entries = {'etc/config/cm2012': Entry(stat.S_IFREG | 0o600, b'private'),
                   'bin/sh': Entry(stat.S_IFLNK | 0o777, b'busybox')}
        digest = fn(entries)
        self.assertIn(b'  etc/config/cm2012\n', digest)
        self.assertNotIn(b'bin/sh', digest)
        for name in ('etc/a\nb', 'etc/a\\b'):
            with self.assertRaises(ValueError): fn({name: entries['etc/config/cm2012']})

    def test_install_never_enters_write_ram_without_flag_and_complete_receipt(self):
        module = self.module()
        with patch('cm2012.ram.ram_test') as boot, patch('cm2012.build.verify_output'):
            with self.assertRaises(ValueError):
                module.install(None, {}, {}, None)
            with tempfile.TemporaryDirectory() as folder:
                output = Path(folder)
                (output / 'manifest.json').write_bytes(b'{}')
                from cm2012.installer import sha256
                (output / 'ram-acceptance.json').write_text(json.dumps({
                    'manifest_sha256': sha256(b'{}'), 'checks': ['nand-readonly']}))
                with self.assertRaises(ValueError):
                    module.install(None, {}, {}, output, erase_internal_root=True)
            boot.assert_not_called()

    def test_retained_boot_must_have_the_exact_verified_internal_entry(self):
        from cm2012.archives import Entry, cpio_bytes
        from cm2012.images import make_boot, gz
        from cm2012.build import CMDLINE
        import stat
        _, stock, _ = fixture()
        entries = {'init': Entry(stat.S_IFREG | 0o755, b'checked internal init'),
                   'bin/sh': Entry(stat.S_IFLNK | 0o777, b'busybox')}
        ram = gz(cpio_bytes(entries))
        boot = make_boot(stock['boot'], ram, CMDLINE)
        fn = self.module().retained_boot_layout
        self.assertEqual(fn(boot[:2048], ram, ram, stock['boot']), len(boot))
        wrong = gz(cpio_bytes({'init': Entry(stat.S_IFREG | 0o755, b'android init')}))
        oldboot = make_boot(stock['boot'], wrong, CMDLINE)
        with self.assertRaises(ValueError):
            fn(oldboot[:2048], wrong, ram, stock['boot'])
        header = bytearray(boot[:2048]); header[64] ^= 1
        with self.assertRaises(ValueError): fn(header, ram, ram, stock['boot'])
        with self.assertRaises(ValueError): fn(boot[:2048], ram[:-1], ram, stock['boot'])


if __name__ == '__main__':
    unittest.main()
