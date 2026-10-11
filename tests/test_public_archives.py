"""根系统链接、权限和确定性归档测试。"""
import importlib
import io
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class ArchiveTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.archives')
        except ModuleNotFoundError:
            self.fail('归档接口尚未实现')

    def archive(self, changed_time):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as stream:
            member = tarfile.TarInfo('./bin/program')
            member.mode, member.size, member.mtime = 0o755, 3, changed_time
            stream.addfile(member, io.BytesIO(b'ELF'))
            member = tarfile.TarInfo('./bin/link')
            member.type, member.linkname = tarfile.SYMTYPE, 'program'
            stream.addfile(member)
        return output.getvalue()

    def test_preserve_executable_and_link_normalize_time(self):
        module = self.module()
        roots = [module.read_tar_bytes(self.archive(t)) for t in (123, 987)]
        result = [module.tar_bytes(root) for root in roots]
        self.assertEqual(result[0], result[1])
        with tarfile.open(fileobj=io.BytesIO(result[0]), mode='r:gz') as stream:
            self.assertEqual(stream.getmember('bin/program').mode, 0o755)
            self.assertEqual(stream.getmember('bin/link').linkname, 'program')
            self.assertTrue(stream.getmember('bin/link').issym())
            self.assertEqual(stream.getmember('bin/program').mtime, 0)

    def test_reject_virtual_root_escape_and_duplicate_file(self):
        module = self.module()
        for names in (('../evil',), ('bin/file', 'bin/file')):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w') as stream:
                for name in names:
                    stream.addfile(tarfile.TarInfo(name))
            with self.assertRaises(ValueError):
                module.read_tar_bytes(output.getvalue())

    def test_newc_content_and_permissions(self):
        module = self.module()
        root = module.read_tar_bytes(self.archive(123))
        cpio = module.cpio_bytes(root)
        self.assertTrue(cpio.startswith(b'070701'))
        self.assertIn(b'bin/program\0', cpio)
        self.assertIn(b'TRAILER!!!\0', cpio)
        self.assertIn(b'ELF', cpio)


if __name__ == '__main__':
    unittest.main()
