"""每次安装保护消费本次产物哈希与动态容量。"""
import importlib
from pathlib import Path
import sys
import unittest

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


if __name__ == '__main__':
    unittest.main()
