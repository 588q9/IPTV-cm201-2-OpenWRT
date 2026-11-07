"""Opt-in first-party GitHub raw media-type transport, using a public fixture.

No private subscription is read. One anonymous GitHub API request per run.
"""
import os
from pathlib import Path
import shlex
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from cm2012.ssh_link import SSHLink


@unittest.skipUnless(os.environ.get('CM2012_FETCH_SSH'), 'set CM2012_FETCH_SSH for device transport')
class FetchGitHub(unittest.TestCase):
    def setUp(self):
        self.link = SSHLink(os.environ['CM2012_FETCH_SSH'])
        self.link.__enter__()
        self.job = '/tmp/cm2012-build-' + uuid.uuid4().hex[:12]
        self.helper = os.environ.get('CM2012_FETCH_REMOTE', '/usr/libexec/cm2012-proxy-fetch')
        self.link.command('umask 077; mkdir ' + self.job)

    def tearDown(self):
        self.link.command('rm -rf -- ' + self.job)
        self.link.__exit__(None, None, None)

    def fetch(self, url):
        self.link.put_small(self.job + '/url', url.encode())
        args = ['timeout', '45', self.helper, self.job + '/url', self.job + '/download',
                '/etc/ssl/certs/ca-certificates.crt', 'github-rule']
        return int(self.link.command(shlex.join(args) + ' >/dev/null 2>&1; echo $?').strip())

    def test_official_api_returns_file_not_json_metadata(self):
        self.assertEqual(self.fetch('https://api.github.com/repos/octocat/Hello-World/contents/README?ref=master'), 0)
        self.assertEqual(self.link.run('cat ' + self.job + '/download'), b'Hello World!\n')

    def test_api_mode_rejects_other_origins_before_connecting(self):
        self.assertEqual(self.fetch('https://example.invalid/repos/test/file'), 2)
        self.link.command('test ! -e ' + self.job + '/download')


if __name__ == '__main__':
    unittest.main()
