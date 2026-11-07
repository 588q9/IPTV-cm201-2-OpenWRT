"""CLI commands activate only the inputs needed for their behavior."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))


class CliTests(unittest.TestCase):
    def entry(self):
        spec = importlib.util.spec_from_file_location('project_cli_test', TOOLS / 'project.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_restore_needs_serial_settings_but_no_stock_or_full_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'local').mkdir()
            (root / 'local/config.json').write_text(json.dumps({
                'format': 1, 'port': 'COM-test', 'stock_paths': {'boot': str(root / 'missing-stock')},
                'profile': {}}))
            entry = self.entry()
            entry.ROOT = root
            with patch.object(sys, 'argv', ['project.py', 'restore']), \
                 patch('cm2012.resources.read_lock', side_effect=AssertionError('unrelated cache activated')), \
                 patch('cm2012.profile.activate_dependencies') as dependencies, \
                 patch('cm2012.ram.restore_internal') as restore:
                entry.main()
            restore.assert_called_once()
            self.assertEqual(restore.call_args.args[0]['port'], 'COM-test')
            dependencies.assert_called_once_with(root, names=('pyserial',))

    def test_verify_uses_stock_and_outputs_without_resource_cache_or_serial(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            entry = self.entry()
            entry.ROOT = root
            config, stock = {'profile': {'total_bytes': 8589934592}}, {'boot': b'stock'}
            with patch.object(sys, 'argv', ['project.py', 'verify']), \
                 patch('cm2012.resources.read_lock', side_effect=FileNotFoundError('missing unrelated cache')), \
                 patch('cm2012.profile.load_config', return_value=(config, stock)), \
                 patch('cm2012.profile.activate_dependencies') as dependencies, \
                 patch('cm2012.artifacts.verify_output') as verify:
                entry.main()
            verify.assert_called_once_with(root / 'output/current', config, stock)
            dependencies.assert_not_called()

    def test_build_and_install_keep_full_resource_checks_before_device_dispatch(self):
        for command in (['build'], ['install', '--erase-internal-root']):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                entry = self.entry()
                entry.ROOT = root
                missing = {'path': 'local/cache/missing-required-resource'}
                with (patch.object(sys, 'argv', ['project.py'] + command),
                      patch('cm2012.resources.read_lock', return_value={'required': missing}),
                      patch('cm2012.resources.verify_resource', side_effect=FileNotFoundError('missing')) as verify,
                      patch('cm2012.profile.load_config') as configuration,
                      patch('cm2012.build.build') as build,
                      patch('cm2012.installer.install') as install):
                    with self.assertRaises(FileNotFoundError):
                        entry.main()
                verify.assert_called_once_with(root, missing)
                configuration.assert_not_called()
                build.assert_not_called()
                install.assert_not_called()


if __name__ == '__main__':
    unittest.main()
