"""离线构建进程主动拒绝网络，即使未来代码误加下载也立即失败。"""
from pathlib import Path
import subprocess
import sys
import unittest


class OfflineTests(unittest.TestCase):
    def test_offline_guard_blocks_even_loopback_connect(self):
        source = """
import sys,socket
sys.path.insert(0,'tools')
from cm2012.offline import forbid_network
forbid_network()
try:
    socket.create_connection(('127.0.0.1',9),timeout=.1)
except RuntimeError as error:
    assert '离线' in str(error)
else:
    raise AssertionError('联网未被阻止')
"""
        result = subprocess.run([sys.executable, '-c', source], cwd=Path(__file__).resolve().parents[1], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
