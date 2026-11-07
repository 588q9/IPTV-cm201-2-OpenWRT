"""Exercise the fixed authenticated API against a real local TCP peer."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROBE = (b'GET /proxies/CM2012-DNS/delay?url=https%3A%2F%2F1.1.1.1%2F'
         b'cdn-cgi%2Ftrace&timeout=3000&expected=200 HTTP/1.1\r\n')


@unittest.skipUnless(os.name == 'posix', 'native loopback API needs POSIX sockets and file modes')
class ProxyAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which('cc') or shutil.which('gcc')
        if not cc:
            raise unittest.SkipTest('a native POSIX C compiler is required')
        cls.folder = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.folder.name)
        cls.private = cls.directory / 'private'
        cls.private.mkdir(mode=0o700)
        cls.secret = cls.private / 'secret'
        # A synthetic secret only; never read a machine's installed API key.
        cls.secret.write_bytes(b'a' * 64 + b'\n')
        cls.secret.chmod(0o600)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            cls.port = reservation.getsockname()[1]
        cls.binary = cls.directory / 'proxy-api'
        result = subprocess.run([
            cc, '-std=c99', '-O2', '-Wall', '-Wextra', '-Werror',
            '-DCM2012_PROXY_API_TEST',
            f'-DCM2012_PROXY_API_TEST_SECRET_DIR="{cls.private}"',
            f'-DCM2012_PROXY_API_TEST_PORT={cls.port}',
            '-I', str(ROOT / 'tools/cm2012'),
            str(ROOT / 'tests/fixtures/proxy-api-main.c'), '-o', str(cls.binary)
        ], capture_output=True, timeout=60)
        if result.returncode:
            cls.folder.cleanup()
            raise AssertionError(result.stderr.decode(errors='replace'))

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def exchange(self, command, response, delay=0):
        """Use real socket framing and retain only synthetic request bytes."""
        received = []
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('127.0.0.1', self.port))
            server.listen(1)
            server.settimeout(6)

            def serve():
                try:
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(6)
                        request = b''
                        while b'\r\n\r\n' not in request:
                            chunk = connection.recv(1024)
                            if not chunk:
                                break
                            request += chunk
                        received.append(request)
                        if delay:
                            time.sleep(delay)
                        try:
                            connection.sendall(response)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                except socket.timeout:
                    pass

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            begin = time.monotonic()
            result = subprocess.run([str(self.binary), command], capture_output=True, timeout=6)
            elapsed = time.monotonic() - begin
            worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')
        return result.returncode, received, elapsed

    @staticmethod
    def reply(status, body, headers=b''):
        return (b'HTTP/1.1 ' + status + b'\r\nContent-Length: ' + str(len(body)).encode()
                + b'\r\n' + headers + b'\r\n' + body)

    def test_fixed_commands_authentication_and_success(self):
        cases = [('health', b'GET /version HTTP/1.1\r\n', b'200 OK', b'{"version":"v1.2","meta":true}'),
                 ('dns-probe', PROBE, b'200 OK', b'{"delay":0}'),
                 ('dns-flush', b'POST /cache/dns/flush HTTP/1.1\r\n', b'204 No Content', b'')]
        for command, start, status, body in cases:
            with self.subTest(command=command):
                code, requests, _ = self.exchange(command, self.reply(status, body))
                self.assertEqual(code, 0)
                self.assertEqual(len(requests), 1)
                self.assertTrue(requests[0].startswith(start))
                self.assertIn(b'\r\nAuthorization: Bearer ' + b'a' * 64 + b'\r\n', requests[0])
                self.assertTrue(requests[0].endswith(b'\r\n\r\n'))
                if command == 'dns-flush':
                    self.assertIn(b'\r\nContent-Length: 0\r\n', requests[0])

    def test_json_and_operation_status_contracts(self):
        invalid = [b'{"version":"v1"}', b'{"delay":-1}', b'{"delay":"0"}', b'{"delay":null}',
                   b'{"delay":1,"delay":2}', b'{"delay":1,"version":"v1"}', b'{"delay":01}',
                   b'{"delay":1e999}', b'{"delay":-1e-999}', b'{"delay":0}junk', b'{"delay":0}\x00', b'[]']
        for body in invalid:
            with self.subTest(body=body):
                code, _, _ = self.exchange('dns-probe', self.reply(b'200 OK', body))
                self.assertNotEqual(code, 0)
        for command, status, body in [('health', b'200 OK', b'{}'),
                                       ('health', b'200 OK', b'{"version":""}'),
                                       ('health', b'200 OK', b'{"version":"v1"'),
                                       ('dns-flush', b'200 OK', b''),
                                       ('dns-flush', b'204 No Content', b'{}'),
                                       ('dns-probe', b'302 Found', b'{"delay":1}'),
                                       ('health', b'401 Unauthorized', b'{"version":"v1"}')]:
            with self.subTest(command=command, status=status, body=body):
                code, _, _ = self.exchange(command, self.reply(status, body))
                self.assertNotEqual(code, 0)
        for body in [b'{"delay":1.25}', b'{"delay":1e2}', b' \n{"delay":0}\r\n']:
            code, _, _ = self.exchange('dns-probe', self.reply(b'200 OK', body))
            self.assertEqual(code, 0)

    def test_partial_oversized_and_ambiguous_http_fails_closed(self):
        cases = [b'HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n{"delay":1}',
                 b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n{"delay":1}',
                 b'HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n{"delay":1}',
                 b'HTTP/1.1 200 OK\r\nContent-Length: 11x\r\n\r\n{"delay":1}',
                 self.reply(b'200 OK', b'{"delay":1}', b'Content-Length: 11\r\n'),
                 self.reply(b'200 OK', b'{"delay":1}', b'Transfer-Encoding: chunked\r\n'),
                 b'HTTP/1.1 200\r\n\r\n{"delay":1}',
                 b'HTTP/1.1 200 OK\x01\r\n\r\n{"delay":1}',
                 b'HTTP/1.1 200 OK\r\nContent-Length: 1',
                 self.reply(b'200 OK', b' ' * 4096 + b'{"delay":1}')]
        for response in cases:
            with self.subTest(response=response[:100]):
                code, _, _ = self.exchange('dns-probe', response)
                self.assertNotEqual(code, 0)

    def test_each_operation_has_a_hard_deadline(self):
        for command, limit in [('health', 2), ('dns-probe', 4), ('dns-flush', 2)]:
            with self.subTest(command=command):
                code, _, elapsed = self.exchange(command, b'', delay=limit + 0.8)
                self.assertNotEqual(code, 0)
                self.assertGreater(elapsed, limit - 0.4)
                self.assertLess(elapsed, limit + 0.7)

    def test_secret_permissions_symlinks_and_content_are_private(self):
        def run_rejected():
            # Invalid credentials must fail before opening the API socket.
            with socket.socket() as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('127.0.0.1', self.port))
                server.listen(1)
                server.settimeout(0.05)
                result = subprocess.run([str(self.binary), 'health'], capture_output=True, timeout=3)
                with self.assertRaises(socket.timeout):
                    connection, _ = server.accept()
                    connection.close()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout + result.stderr, b'')

        try:
            for mode in [0o644, 0o400, 0o660]:
                self.secret.chmod(mode)
                run_rejected()
            self.secret.chmod(0o600)
            self.private.chmod(0o755)
            run_rejected()
            self.private.chmod(0o700)
            if os.geteuid() == 0:
                for path in [self.secret, self.private]:
                    os.chown(path, 1, -1)
                    try:
                        run_rejected()
                    finally:
                        os.chown(path, 0, -1)
            for body in [b'A' * 64, b'a' * 63, b'a' * 64 + b'xx']:
                self.secret.write_bytes(body)
                run_rejected()
            self.secret.unlink()
            self.secret.symlink_to(self.directory / 'other')
            (self.directory / 'other').write_bytes(b'a' * 64)
            (self.directory / 'other').chmod(0o600)
            run_rejected()
            self.secret.unlink()
            self.secret.write_bytes(b'a' * 64)
            self.secret.chmod(0o600)
            real_private = self.directory / 'real-private'
            self.private.rename(real_private)
            self.private.symlink_to(real_private, target_is_directory=True)
            try:
                run_rejected()
            finally:
                self.private.unlink()
                real_private.rename(self.private)
        finally:
            self.private.chmod(0o700)
            self.secret.unlink(missing_ok=True)
            self.secret.write_bytes(b'a' * 64 + b'\n')
            self.secret.chmod(0o600)

    def test_no_arbitrary_method_path_or_secret_arguments(self):
        for args in [['GET'], ['health', '/version'], ['dns-probe', 'a' * 64],
                     ['dns-flush', 'POST', '/cache/dns/flush']]:
            with self.subTest(args=args):
                result = subprocess.run([str(self.binary), *args], capture_output=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout + result.stderr, b'')


if __name__ == '__main__':
    unittest.main()
