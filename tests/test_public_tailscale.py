"""Tailscale's local packaging and executable policy contracts."""
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TailscaleTests(unittest.TestCase):
    def test_service_start_uses_fixed_arguments_and_consumes_restart_marker(self):
        shell = shutil.which('sh')
        if not shell:
            self.skipTest('POSIX shell unavailable; native service fixture still required')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = (ROOT / 'configs/templates/cm2012-tailscale-init').read_text(encoding='utf-8')
            source = source.replace('/var/run/cm2012-tailscale', root.as_posix())
            source = source.replace('/usr/libexec/cm2012-tailscale prepare', 'prepare_double')
            (root / 'ready').touch()
            (root / 'restart-required').touch()
            script = root / 'start.sh'
            script.write_text(source + '''
prepare_double() { return 0; }
mkdir() { return 0; }
chmod() { return 0; }
procd_open_instance() { :; }
procd_close_instance() { :; }
procd_set_param() { printf '%s\\n' "$*"; }
start_service
''', encoding='utf-8', newline='\n')
            result = subprocess.run([shell, script.as_posix()], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn(b'command /usr/sbin/tailscaled ', result.stdout)
            self.assertIn(b'--tun=tailscale0 --port=41641', result.stdout)
            self.assertIn(b'--state=/etc/tailscale/tailscaled.state', result.stdout)
            self.assertFalse((root / 'restart-required').exists(), 'successful start must consume restart marker')

    def test_reconcile_keeps_running_daemon_and_suspend_releases_shared_lock(self):
        shell = shutil.which('sh')
        if not shell:
            self.skipTest('POSIX shell unavailable; native service fixture still required')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            lock = root / 'apply.lock'
            source = (ROOT / 'configs/templates/cm2012-tailscale').read_text(encoding='utf-8')
            source = source.replace('/tmp/cm2012-wifi/apply.lock', lock.as_posix())
            source = source.replace('/tmp/cm2012-wifi', root.as_posix())
            source = source.replace('/var/run/cm2012-tailscale', root.as_posix())
            source = source.replace('/usr/bin/ucode /usr/libexec/cm2012-tailscale.uc', 'ucode_double')
            source = source.replace('/etc/init.d/cm2012-tailscale', 'init_double')
            script = root / 'wrapper.sh'
            prefix = '''
ucode_double() { printf '%s\\n' "$1" >> "$TRACE"; case "$1" in prepare) touch "$READY";; clear|suspend) rm -f "$READY";; esac; }
init_double() {
 printf '%s\\n' "$1" >> "$TRACE"
 case "$1" in running) return 0;; restart) return 98;; stop)
  [ ! -d "$LOCK" ] || return 97
  sh "$0" clear;; esac
}
'''
            script.write_text(prefix + source, encoding='utf-8', newline='\n')
            import os
            env = dict(os.environ, TRACE=(root / 'trace').as_posix(), READY=(root / 'ready').as_posix(), LOCK=lock.as_posix())
            result = subprocess.run([shell, script.as_posix(), 'reconcile'], env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual((root / 'trace').read_text().splitlines(), ['prepare', 'running'])
            (root / 'trace').write_text('')
            result = subprocess.run([shell, script.as_posix(), 'suspend'], env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual((root / 'trace').read_text().splitlines(), ['suspend', 'stop', 'clear'])
            self.assertFalse(lock.exists())

    def test_policy_restricts_actual_lan_and_preserves_foreign_firewall(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node is required for the public policy fixture')
        result = subprocess.run([node, str(ROOT / 'tests/fixtures/cm2012-tailscale.cjs')],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout.decode('utf-8', 'replace'))
        self.assertIn(b'TAILSCALE_POLICY_OK', result.stdout)

    def test_package_is_disabled_and_state_private(self):
        self.assertTrue((ROOT / 'tools/cm2012/tailscale.py').exists(),
                        'Tailscale needs an explicit runtime artifact provider')
        from tools.cm2012 import tailscale
        config = tailscale.configuration()
        self.assertEqual(set(config), {'etc/config/cm2012_tailscale'})
        self.assertIn(b"option enabled '0'", config['etc/config/cm2012_tailscale'])
        entries = tailscale.runtime_files(ROOT)
        self.assertTrue(stat.S_ISDIR(entries['etc/tailscale'].mode))
        self.assertEqual(stat.S_IMODE(entries['etc/tailscale'].mode), 0o700)
        from tools.cm2012.rootfs import make_overlay
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'ubusd'
            binary.write_bytes(b'public-test')
            overlay = make_overlay(ROOT, {'ssid': 'public-test', 'ap_password': 'public-test'}, {'ubusd': binary})
        self.assertEqual(stat.S_IMODE(overlay['etc/config/cm2012_tailscale'].mode), 0o600)
        self.assertEqual(overlay['etc/config/cm2012_tailscale'].data, config['etc/config/cm2012_tailscale'])
        self.assertEqual(entries['etc/rc.d/S95cm2012-tailscale'].data, b'../init.d/cm2012-tailscale')
        for path in ['usr/libexec/cm2012-tailscale', 'usr/libexec/cm2012-tailscale.uc',
                     'usr/libexec/cm2012-tailscale-lib.uc', 'usr/share/rpcd/ucode/cm2012_tailscale',
                     'usr/share/rpcd/acl.d/luci-app-cm2012-tailscale.json',
                     'www/luci-static/resources/view/cm2012/tailscale.js']:
            self.assertIn(path, entries)
