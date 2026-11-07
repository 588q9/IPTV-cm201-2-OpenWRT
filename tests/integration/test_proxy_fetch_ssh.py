"""Opt-in real TLS regressions in an isolated CM2012 RAM directory.

CM2012_FETCH_SSH=192.168.50.1; CM2012_FETCH_REMOTE may select a RAM candidate.
No subscriptions, network configuration changes, or certificate store changes.
"""
import os
from pathlib import Path
import shlex
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from cm2012.ssh_link import SSHLink


@unittest.skipUnless(os.environ.get('CM2012_FETCH_SSH'), 'set CM2012_FETCH_SSH for device TLS regressions')
class FetchSSH(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.link = SSHLink(os.environ['CM2012_FETCH_SSH'])
        cls.link.__enter__()
        cls.job = '/tmp/cm2012-build-' + uuid.uuid4().hex[:12]
        cls.helper = os.environ.get('CM2012_FETCH_REMOTE', '/usr/libexec/cm2012-proxy-fetch')
        cls.link.command('umask 077; mkdir ' + cls.job)
        cls.link.command('openssl req -x509 -newkey rsa:2048 -nodes -days 1 '
                         '-subj /CN=localhost -addext subjectAltName=DNS:localhost '
                         '-keyout ' + cls.job + '/key.pem -out ' + cls.job + '/ca.pem >/dev/null 2>&1')
        responses = {
            'success': b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nfixture-body',
            'redirect': b'HTTP/1.1 302 Found\r\nLocation: /success\r\nContent-Length: 0\r\n\r\n',
            'downgrade': b'HTTP/1.1 302 Found\r\nLocation: http://localhost:1/private-token\r\nContent-Length: 0\r\n\r\n',
            'loop': b'HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\n\r\n',
            'missing': b'HTTP/1.1 404 Missing\r\nContent-Length: 7\r\n\r\nmissing',
            'broken': b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial',
            # No Content-Length: the callback must enforce the limit.
            'large': b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n' + b'x' * (4194304 + 1),
        }
        for name, value in responses.items():
            cls.link.put_small(cls.job + '/' + name, value)
        command = 'cd ' + cls.job + '; exec openssl s_server -accept 127.0.0.1:49443 -cert ca.pem -key key.pem -HTTP -quiet'
        cls.pid = cls.link.command('setsid sh -c ' + shlex.quote(command) + ' </dev/null >' + cls.job + '/server.log 2>&1 & echo $!').strip()
        cls.link.command('sleep 1; kill -0 ' + cls.pid)

    @classmethod
    def tearDownClass(cls):
        if cls.pid.isdigit():
            cls.link.command('kill ' + cls.pid + ' 2>/dev/null || true')
        cls.link.command('rm -rf -- ' + cls.job)
        cls.link.__exit__(None, None, None)

    def fetch(self, path, *, host='localhost', ca=None, port=49443):
        self.link.put_small(self.job + '/url', f'https://{host}:{port}/{path}'.encode())
        args = [self.helper, self.job + '/url', self.job + '/download', ca or self.job + '/ca.pem']
        cmd = 'rm -f ' + self.job + '/download; timeout 45 ' + shlex.join(args)
        result = self.link.command(cmd + ' >' + self.job + '/stdout 2>' + self.job + '/stderr; echo $?').strip()
        output = self.link.run('cat ' + self.job + '/stdout ' + self.job + '/stderr')
        self.assertNotIn(b'private-token', output)
        code = int(result)
        if code:
            self.assertEqual(self.link.command('test ! -e ' + self.job + '/download; echo $?').strip(), '0')
        return code

    def test_verified_download_and_https_redirect(self):
        for path in ['success', 'redirect']:
            self.assertEqual(self.fetch(path), 0)
            self.assertEqual(self.link.run('cat ' + self.job + '/download'), b'fixture-body')

    def test_wrong_host_rejected(self):
        self.assertEqual(self.fetch('success', host='127.0.0.1'), 60)

    def test_untrusted_certificate_rejected(self):
        self.assertEqual(self.fetch('success', ca='/etc/ssl/certs/ca-certificates.crt'), 60)

    def test_http_redirect_rejected(self):
        self.assertEqual(self.fetch('downgrade'), 1)

    def test_redirect_limit(self):
        self.assertEqual(self.fetch('loop'), 47)

    def test_body_size_limit(self):
        self.assertEqual(self.fetch('large'), 63)

    def test_http_failure(self):
        self.assertEqual(self.fetch('missing'), 22)

    def test_interrupted_response(self):
        self.assertEqual(self.fetch('broken'), 18)

    def test_identifies_as_mihomo(self):
        # Generic s_server writes decrypted application bytes to stdout; its
        # canned response arrives via stdin. The -www status page does not echo
        # request headers, so it cannot test the client's identification.
        # Delay the canned reply so the request is read before the client sees
        # Connection: close. The whole feeder/server pipeline has its own group.
        command = 'cd ' + self.job + '; (sleep 5; cat success; sleep 2) | openssl s_server -accept 127.0.0.1:49444 -cert ca.pem -key key.pem -quiet -naccept 1'
        pid = self.link.command('setsid sh -c ' + shlex.quote(command) + ' </dev/null >' + self.job + '/request.log 2>' + self.job + '/www.log & echo $!').strip()
        self.assertTrue(pid.isdigit())
        try:
            self.link.command('sleep 1; kill -0 ' + pid)
            self.assertEqual(self.fetch('', port=49444), 0)
            request = self.link.run('cat ' + self.job + '/request.log')
            self.assertTrue(b'User-Agent: clash.meta' in request,
                            f'client identification absent: request_bytes={len(request)}, '
                            f'agent_header={b"user-agent" in request.lower()}, '
                            f'mihomo_value={b"clash.meta" in request.lower()}')
        finally:
            self.link.command('kill -TERM -' + pid + ' 2>/dev/null || true')


if __name__ == '__main__':
    unittest.main()
