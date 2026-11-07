"""功能模板职责与组合冲突。"""
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


class TemplateTests(unittest.TestCase):
    def module(self):
        try:
            from cm2012 import template_files
        except ImportError:
            self.fail('模板组合接口尚未实现')
        return template_files

    def test_feature_composition_rejects_file_conflicts_but_accepts_same_directory(self):
        from cm2012.archives import Entry
        module = self.module()
        directory = Entry(stat.S_IFDIR | 0o755)
        self.assertEqual(module.merge_files({'usr': directory}, {'usr': directory}), {'usr': directory})
        with self.assertRaises(ValueError):
            module.merge_files({'file': b'one'}, {'file': b'two'})
        with self.assertRaises(ValueError):
            module.merge_files({'file': b'one'}, {'file': b'one'})

    def test_loader_preserves_declared_mode_and_normalizes_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source').write_bytes(b'one\r\ntwo\r\n')
            files = self.module().load_templates(root, [('source', 'usr/bin/public-tool', 0o755)])
            self.assertEqual(files['usr/bin/public-tool'].data, b'one\ntwo\n')
            self.assertEqual(files['usr/bin/public-tool'].mode, stat.S_IFREG | 0o755)

    def test_uci_configuration_has_one_authority(self):
        from cm2012 import tailscale, proxy, remote
        self.assertFalse(any(n.startswith('etc/config/') for n in tailscale.runtime_files(ROOT)))
        self.assertFalse(any(n.startswith('etc/config/') for n in proxy.runtime_files(ROOT)))
        defaults = remote.configuration()
        for group in [tailscale.configuration(), proxy.configuration()]:
            for name, data in group.items():
                self.assertEqual(defaults[name], data)


if __name__ == '__main__':
    unittest.main()
