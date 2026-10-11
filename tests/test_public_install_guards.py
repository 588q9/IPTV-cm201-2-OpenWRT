"""执行生产 root_target_free 的隔离保护；模拟文件不接触真实 NAND。"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALL_STAGE = ROOT / 'tools/cm2012/device/install-stage'


def production_guard_script():
    """只提取无硬件副作用的保护函数，绝不执行整个安装脚本。"""
    source = INSTALL_STAGE.read_text(encoding='utf-8')
    fail = re.search(r'(?m)^fail\(\) \{[^\n]*\}$', source)
    guard = re.search(r'(?ms)^root_target_free\(\) \{\n.*?^\}\n', source)
    if not fail or not guard:
        raise AssertionError('生产安装脚本缺少可提取的保护函数')
    return '#!/bin/sh\nset -eu\n' + fail.group() + '\n' + guard.group() + '\n'


class InstallGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell = shutil.which('sh')
        if not cls.shell:
            raise unittest.SkipTest('没有 POSIX sh；Windows 必须明确跳过，不能视为已执行保护测试')
        probe = subprocess.run([cls.shell, '-c', 'command -v cat >/dev/null && command -v awk >/dev/null'],
                               capture_output=True, timeout=10)
        if probe.returncode:
            raise unittest.SkipTest('POSIX sh 缺少 cat/awk；保护行为未执行')
        cls.production = production_guard_script()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='cm2012-build-guards-')
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.ubi = self.base / 'mock-ubi'
        self.ubi.mkdir()
        self.mounts = self.base / 'mock-mounts'
        self.mounts.write_text('tmpfs /tmp tmpfs rw 0 0\n', encoding='utf-8', newline='\n')
        self.target = self.base / 'mock-newroot'
        self.script = self.base / 'guard.sh'
        self.script.write_text(self.production + 'root_target_free "$1" "$2" "$3"\n',
                               encoding='utf-8', newline='\n')

    def attach(self, number, mtd=None):
        directory = self.ubi / ('ubi' + str(number))
        directory.mkdir()
        if mtd is not None:
            (directory / 'mtd_num').write_text(str(mtd) + '\n', encoding='ascii', newline='\n')

    def run_guard(self):
        return subprocess.run([self.shell, self.script.as_posix(), self.ubi.as_posix(),
                               self.mounts.as_posix(), self.target.as_posix()],
                              capture_output=True, text=True, encoding='utf-8', timeout=10)

    def assert_rejected(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('停止安装：', result.stderr)

    def test_unused_target_is_allowed(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.target.exists(), '只读保护不得创建解包目录')

    def test_unrelated_ubi1_attachment_is_allowed(self):
        self.attach(1, 7)
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_target_mtd8_attached_as_ubi1_is_rejected(self):
        self.attach(1, 8)
        self.assert_rejected()

    def test_ubi0_in_use_by_another_mtd_is_rejected(self):
        self.attach(0, 7)
        self.assert_rejected()

    def test_ubi0_directory_without_mtd_num_is_rejected(self):
        self.attach(0)
        self.assert_rejected()

    def test_existing_extract_directory_is_rejected(self):
        self.target.mkdir()
        self.assert_rejected()

    def test_mounted_mtdblock8_is_rejected(self):
        self.mounts.write_text('/dev/mtdblock8 /mock-root jffs2 rw 0 0\n',
                               encoding='ascii', newline='\n')
        self.assert_rejected()

    def test_mounted_mtd8_is_rejected(self):
        self.mounts.write_text('/dev/mtd8 /mock-root jffs2 rw 0 0\n',
                               encoding='ascii', newline='\n')
        self.assert_rejected()


if __name__ == '__main__':
    unittest.main()
