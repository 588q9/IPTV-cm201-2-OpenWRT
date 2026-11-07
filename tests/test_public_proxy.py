"""Proxy policy and subscription regressions; no router credentials required."""
from pathlib import Path
import shutil
import subprocess
import unittest
import sys
import stat
import json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from cm2012 import proxy


class ProxyTests(unittest.TestCase):
    def test_geoip_locked_native_asset(self):
        result = subprocess.run([shutil.which("node"), str(ROOT / "tests/fixtures/cm2012-geoip.cjs")], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_image_contains_disabled_control_plane_and_exact_rpc_acl(self):
        config = proxy.configuration()
        self.assertEqual(set(config), {'etc/config/cm2012_proxy'})
        self.assertNotIn(b'http', config['etc/config/cm2012_proxy'])
        files = proxy.runtime_files(ROOT)
        self.assertEqual(stat.S_IMODE(files['etc/cm2012-proxy'].mode), 0o700)
        country = files['etc/cm2012-proxy/Country.mmdb']
        self.assertTrue(stat.S_ISLNK(country.mode))
        self.assertEqual(stat.S_IMODE(country.mode), 0o777)
        self.assertEqual(country.data, b'/usr/share/cm2012/geodata/Country.mmdb')
        acl = json.loads(files['usr/share/rpcd/acl.d/luci-app-cm2012-proxy.json'].data)
        role = acl['luci-app-cm2012-proxy']
        self.assertEqual(role['read'], {'ubus': {'cm2012_proxy': ['status']}})
        self.assertEqual(set(role['write']['ubus']['cm2012_proxy']),
                         {'save_subscription', 'apply', 'confirm', 'rollback', 'disable', 'update_subscription'})
        self.assertFalse(any(name.endswith(('/secret', '/key.pem', '/cert.pem', '/active.json')) for name in files))
        shell = shutil.which('sh')
        self.assertIsNotNone(shell)
        for name, entry in files.items():
            if stat.S_ISREG(entry.mode) and entry.data.startswith(b'#!/bin/sh'):
                with self.subTest(name=name):
                    result = subprocess.run([shell, '-n'], input=entry.data, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_subscription_and_policy_boundaries(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node is required for public runtime regressions')
        result = subprocess.run([node, str(ROOT / 'tests/fixtures/cm2012-proxy.cjs')],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'PROXY_BOUNDARIES_OK', result.stdout)

    def test_subscription_ui_feedback_and_confirmation(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node is required for public UI regressions')
        result = subprocess.run([node, str(ROOT / 'tests/fixtures/cm2012-proxy-ui.cjs')],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'PROXY_UI_ASYNC_ERRORS_VISIBLE_OK', result.stdout)

    def test_recovery_retries_and_expired_update_ownership(self):
        result = subprocess.run([shutil.which('node'), str(ROOT / 'tests/fixtures/cm2012-proxy-recovery.cjs')],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'PROXY_RECOVERY_CASES 9 passed 0 failed', result.stdout)

    def test_native_subscription_download_error_cleanup(self):
        result = subprocess.run([shutil.which('node'), str(ROOT / 'tests/fixtures/cm2012-proxy-fetch.cjs')],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'PROXY_FETCH_ERRORS_PRIVATE_AND_VISIBLE_OK', result.stdout)

    def test_rule_provider_text_parsing_and_native_formats(self):
        result = subprocess.run([shutil.which('node'), str(ROOT / 'tests/fixtures/cm2012-rule-text.cjs')],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'RULE_TEXT_PARSING_AND_NATIVE_FORMATS_OK', result.stdout)

    def test_rule_provider_github_transport_and_bounded_cache(self):
        result = subprocess.run([shutil.which('node'), str(ROOT / 'tests/fixtures/cm2012-provider-transport.cjs')],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'PROVIDER_GITHUB_TRANSPORT_AND_BOUNDED_CACHE_OK', result.stdout)


if __name__ == '__main__':
    unittest.main()
