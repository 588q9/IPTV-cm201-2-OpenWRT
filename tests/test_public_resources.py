"""锁定文件的缺失、篡改和路径越界保护。"""
import hashlib
import importlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class ResourceTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.resources')
        except ModuleNotFoundError:
            self.fail('资源接口尚未实现')

    def test_missing_or_corrupt_locked_file_fails_without_fallback(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            item = {'path': 'local/cache/item', 'size': 4,
                    'sha256': hashlib.sha256(b'good').hexdigest()}
            with self.assertRaises(FileNotFoundError):
                module.verify_resource(root, item)
            path = root / item['path']
            path.parent.mkdir(parents=True)
            path.write_bytes(b'evil')
            with self.assertRaises(ValueError):
                module.verify_resource(root, item)
            path.write_bytes(b'good')
            self.assertEqual(module.verify_resource(root, item), path.resolve())

    def test_reject_lock_path_outside_workspace(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            for path in ('../secret', '/absolute', 'C:/outside', 'local/../../secret'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    module.resource_path(Path(directory), {'path': path})

    def test_source_extraction_rejects_symlink_parent_and_traversal(self):
        module = self.module()
        for kind, name, link in ((tarfile.REGTYPE, '../escape', ''),
                                  (tarfile.SYMTYPE, 'source/dir', '../../escape')):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = io.BytesIO()
                with tarfile.open(fileobj=data, mode='w') as archive:
                    entry = tarfile.TarInfo(name)
                    entry.type, entry.linkname = kind, link
                    archive.addfile(entry)
                source = root / 'source.tar'
                source.write_bytes(data.getvalue())
                with self.assertRaises(ValueError):
                    module.extract_source(source, root / 'output')
                self.assertFalse((root / 'escape').exists())


if __name__ == '__main__':
    unittest.main()
