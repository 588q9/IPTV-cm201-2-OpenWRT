"""锁定文件的缺失、篡改和路径越界保护。"""
import hashlib
import importlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class ResourceTests(unittest.TestCase):
    def source_archive(self, root, names=('new/source.c',)):
        source = root / 'source.tar'
        with tarfile.open(source, 'w') as archive:
            for name in names:
                entry = tarfile.TarInfo(name)
                entry.size = 4
                archive.addfile(entry, io.BytesIO(b'good'))
        return source

    def test_source_replacement_returns_only_current_root_and_discards_patched_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / 'build/source'
            (destination / 'old').mkdir(parents=True)
            (destination / 'old/stale.c').write_bytes(b'old')
            private = root / 'private.txt'
            private.write_bytes(b'keep')
            source = self.source_archive(root)
            current = self.module().extract_source(source, destination)
            self.assertEqual(current, destination / 'new')
            self.assertEqual(list(destination.iterdir()), [current])
            (current / 'patched.c').write_bytes(b'patch')
            self.module().extract_source(source, destination)
            self.assertFalse((current / 'patched.c').exists())
            self.assertEqual(private.read_bytes(), b'keep')

    def test_source_rejects_multiple_roots_before_changing_existing_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / 'build'
            destination.mkdir()
            (destination / 'keep').write_bytes(b'keep')
            source = self.source_archive(root, ('one/source.c', 'two/source.c'))
            with self.assertRaises(ValueError):
                self.module().extract_source(source, destination)
            self.assertEqual((destination / 'keep').read_bytes(), b'keep')

    def test_source_replacement_rejects_destination_outside_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / 'workspace'
            workspace.mkdir()
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'keep').write_bytes(b'keep')
            with self.assertRaises(ValueError):
                self.module().extract_source(self.source_archive(root), outside, workspace=workspace)
            self.assertEqual((outside / 'keep').read_bytes(), b'keep')

    def test_zip_rejects_windows_aliases_and_links(self):
        for name in ('../outside', 'C:/outside', 'dir\\outside', 'dir/file.',
                     'dir/file ', 'dir/NUL.txt', 'dir/file:stream', 'dir/a?b'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'source.zip'
                with zipfile.ZipFile(source, 'w') as archive:
                    entry = zipfile.ZipInfo('placeholder')
                    entry.filename = name
                    archive.writestr(entry, b'evil')
                with self.assertRaises(ValueError):
                    self.module().extract_zip(source, root / 'out')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.zip'
            with zipfile.ZipFile(source, 'w') as archive:
                entry = zipfile.ZipInfo('link')
                entry.create_system = 3
                entry.external_attr = (0o120777 << 16)
                archive.writestr(entry, b'outside')
            with self.assertRaises(ValueError):
                self.module().extract_zip(source, root / 'out')

    def test_zip_rejects_existing_junction_or_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'keep').write_bytes(b'keep')
            destination = root / 'out'
            destination.mkdir()
            link = destination / 'linked'
            if sys.platform == 'win32':
                import subprocess
                subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(outside)],
                               check=True, capture_output=True)
            else:
                link.symlink_to(outside, target_is_directory=True)
            try:
                source = root / 'source.zip'
                with zipfile.ZipFile(source, 'w') as archive:
                    archive.writestr('linked/keep', b'evil')
                with self.assertRaises(ValueError):
                    self.module().extract_zip(source, destination)
                self.assertEqual((outside / 'keep').read_bytes(), b'keep')
                with self.assertRaises(ValueError):
                    self.module().extract_source(self.source_archive(root), destination)
            finally:
                if sys.platform == 'win32':
                    link.rmdir()
                else:
                    link.unlink()

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
