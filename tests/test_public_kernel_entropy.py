"""Run the real platform entropy callback with controlled kernel responses."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class KernelEntropyTests(unittest.TestCase):
    def test_kernel_entropy_retries_chunks_and_fails_closed(self):
        cc = shutil.which('cc') or shutil.which('clang')
        zig = ROOT / 'local/toolchain/zig-windows-x86_64-0.13.0/zig.exe'
        if not cc and not zig.exists():
            self.skipTest('C compiler unavailable')
        compiler = [cc] if cc else [str(zig), 'cc']
        env = os.environ.copy()
        if not cc:
            env['ZIG_GLOBAL_CACHE_DIR'] = str(ROOT / 'local/zig-global-cache')
            env['ZIG_LOCAL_CACHE_DIR'] = str(ROOT / 'local/zig-local-cache')
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / ('entropy.exe' if os.name == 'nt' else 'entropy')
            result = subprocess.run(
                compiler + ['-std=c99', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(ROOT / 'tests/fixtures/kernel_entropy_test.c'),
                            '-o', str(binary)],
                env=env, capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            result = subprocess.run([str(binary)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertIn(b'KERNEL_ENTROPY_OK', result.stdout)


if __name__ == '__main__':
    unittest.main()
