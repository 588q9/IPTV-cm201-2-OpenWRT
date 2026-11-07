"""curl 头文件和许可均跟随当前锁定源码，不能复用旧目录。"""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


class CurlSourceTests(unittest.TestCase):
    def source(self, root, names):
        path = root / 'curl.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, data in names.items():
                row = tarfile.TarInfo(name)
                row.size = len(data)
                archive.addfile(row, io.BytesIO(data))
        return path

    def test_current_archive_root_replaces_stale_headers(self):
        from cm2012 import compiler
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / 'local/build/curl-headers/curl/old.h'
            old.parent.mkdir(parents=True)
            old.write_bytes(b'old')
            source = self.source(root, {'curl-next/include/curl/curl.h': b'new API',
                                        'curl-next/include/curl/curlver.h': b'new version'})
            with patch('cm2012.compiler.elf_check'):
                compiler.compile_proxy_fetch(root, {'curl-source': source}, ['zig'], lambda *a, **k: None,
                                             root, root)
            self.assertFalse(old.exists())
            self.assertEqual((old.parent / 'curl.h').read_bytes(), b'new API')

    def test_missing_required_headers_fail_before_compiler(self):
        from cm2012 import compiler
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'local/build').mkdir(parents=True)
            source = self.source(root, {'curl-next/COPYING': b'license'})
            calls = []
            with patch('cm2012.compiler.elf_check'), self.assertRaises(ValueError):
                compiler.compile_proxy_fetch(root, {'curl-source': source}, ['zig'],
                                             lambda *a, **k: calls.append(a), root, root)
            self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
