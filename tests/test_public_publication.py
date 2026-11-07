"""公开提交检查不回显凭据，并检查实际 Git 内容而非忽略目录。"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


class PublicationTests(unittest.TestCase):
    def module(self):
        try:
            from cm2012 import publication
        except ImportError:
            self.fail('公开内容凭据检查尚未实现')
        return publication

    def test_detects_keys_hashes_and_subscriptions_without_returning_values(self):
        secret = 'ghp_' + 'A' * 36
        password_hash = '$6$' + 'exampleSalt$' + 'a' * 86
        subscription = 'https://provider.example.org/subscribe?token=' + 'privatevalue123'
        key = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----'
        files = {'docs/leak.md': ('\n'.join([secret, password_hash, subscription, key])).encode()}
        findings = self.module().scan_files(files)
        self.assertEqual({f['rule'] for f in findings},
                         {'github-token', 'password-hash', 'subscription-token', 'private-key'})
        rendered = json.dumps(findings)
        for value in (secret, password_hash, subscription, key):
            self.assertNotIn(value, rendered)
        self.assertEqual({f['line'] for f in findings}, {1, 2, 3, 4})

    def test_test_urls_are_specific_exceptions_and_known_values_always_win(self):
        synthetic = 'https://subscription.example.invalid/sub?token=synthetic12345'
        secret = 'tskey-auth-' + 'A' * 30
        files = {'tests/example.txt': (synthetic + '\n' + secret).encode()}
        findings = self.module().scan_files(files)
        self.assertEqual([f['rule'] for f in findings], ['tailscale-key'])
        self.assertTrue(any(f['rule'] == 'known-secret' for f in
                            self.module().scan_files(files, known_values=[synthetic])))

    def test_private_artifacts_and_unapproved_binary_are_rejected(self):
        files = {'configs/templates/rootfs.tar.gz': b'not-a-public-artifact',
                 'tools/cm2012/.env': b'NAME=value', 'docs/file.bin': b'\x00data'}
        self.assertEqual({f['rule'] for f in self.module().scan_files(files)},
                         {'private-artifact', 'binary-not-allowed'})

    def test_subscription_path_token_is_detected_from_its_field(self):
        value = 'https://provider.example.org/sub/' + 'opaquevalue' * 5
        files = {'docs/settings.txt': json.dumps({'subscription_url': value}).encode()}
        findings = self.module().scan_files(files)
        self.assertEqual([f['rule'] for f in findings], ['subscription-url'])
        self.assertNotIn(value, json.dumps(findings))

    def test_uci_subscription_quoted_values_detect_opaque_path_credentials(self):
        value = 'https://provider.example.org/sub/' + 'opaquevalue' * 5
        for field in ('subscription_url', 'subscribe_url', 'sub_url'):
            for spacing in (' ', '\t', '  \t '):
                for quote in ("'", '"'):
                    with self.subTest(field=field, spacing=spacing, quote=quote):
                        data = ('config proxy\n\toption' + spacing + field + spacing +
                                quote + value + quote + '\n').encode()
                        findings = self.module().scan_files({'docs/settings.uci': data})
                        self.assertEqual(findings, [
                            {'file': 'docs/settings.uci', 'line': 2, 'rule': 'subscription-url'}])
                        self.assertNotIn(value, json.dumps(findings))

    def test_subscription_field_formats_preserve_url_specific_reserved_exceptions(self):
        value = 'https://provider.example.org/sub/opaquevalue12345'
        reserved = 'https://subscription.example.invalid/sub/opaquevalue12345'
        for template in ('subscription_url: "{}"', 'sub_url = \'{}\'',
                         'option subscription_url \'{}\''):
            with self.subTest(template=template):
                findings = self.module().scan_files({'docs/settings.txt': template.format(value).encode()})
                self.assertEqual([f['rule'] for f in findings], ['subscription-url'])
                data = (template.format(reserved) + '\n' + 'ghp_' + 'Z' * 36).encode()
                findings = self.module().scan_files({'docs/settings.txt': data}, known_values=[reserved])
                self.assertEqual({f['rule'] for f in findings}, {'known-secret', 'github-token'})
                self.assertNotIn(reserved, json.dumps(findings))

    def test_binary_snapshot_requires_exact_bundled_lock_identity(self):
        name, data = 'configs/resource-snapshots/base/packages.adb', b'ADB\x00signed-metadata'
        identity = (len(data), hashlib.sha256(data).hexdigest())
        lock = {'format': 1, 'resources': [{'id': 'base-index', 'bundled_path': name,
                                         'size': identity[0], 'sha256': identity[1]}]}
        files = {name: data, 'resources.lock.json': json.dumps(lock).encode()}
        module = self.module()
        with patch.object(module, 'APPROVED_SNAPSHOTS', {name: identity}, create=True):
            self.assertEqual(module.scan_files(files), [])
            self.assertEqual(module.scan_files(files, known_values=[b'signed-metadata']), [
                {'file': name, 'line': 1, 'rule': 'known-secret'}])
            files[name] = data + b'changed'
            self.assertTrue(any(f['rule'] == 'binary-not-allowed' for f in module.scan_files(files)))

    def snapshot_files(self):
        lock_bytes = (ROOT / 'resources.lock.json').read_bytes()
        rows = json.loads(lock_bytes)['resources']
        names = [row['bundled_path'] for row in rows if row.get('bundled_path')]
        self.assertEqual(len(names), 5)
        return {'resources.lock.json': lock_bytes, **{name: (ROOT / name).read_bytes() for name in names}}

    def test_five_reviewed_binary_snapshots_are_accepted_and_known_secrets_still_win(self):
        files = self.snapshot_files()
        self.assertEqual(sum(len(data) for name, data in files.items() if name != 'resources.lock.json'),
                         1359016)
        self.assertEqual(self.module().scan_files(files), [])
        name = 'configs/resource-snapshots/base/packages.adb'
        # Use a slice only in memory; neither bytes nor their digest enter findings.
        findings = self.module().scan_files(files, known_values=[files[name][32:64]])
        self.assertTrue(any(f['file'] == name and f['rule'] == 'known-secret' for f in findings))

    def test_sixth_binary_cannot_authorize_itself_through_candidate_lock(self):
        files = self.snapshot_files()
        name, data = 'configs/resource-snapshots/extra/packages.adb', b'ADB\x00unreviewed-content'
        lock = json.loads(files['resources.lock.json'])
        lock['resources'].append({'id': 'extra-index', 'bundled_path': name,
                                  'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        files.update({name: data, 'resources.lock.json': json.dumps(lock).encode()})
        self.assertEqual(self.module().scan_files(files), [
            {'file': name, 'line': 1, 'rule': 'binary-not-allowed'}])

    def test_modified_approved_binary_cannot_authorize_itself_through_candidate_lock(self):
        files = self.snapshot_files()
        name = 'configs/resource-snapshots/base/packages.adb'
        data = b'ADB\x00replacement-content'
        lock = json.loads(files['resources.lock.json'])
        for row in lock['resources']:
            if row.get('bundled_path') == name:
                row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        files.update({name: data, 'resources.lock.json': json.dumps(lock).encode()})
        self.assertEqual(self.module().scan_files(files), [
            {'file': name, 'line': 1, 'rule': 'binary-not-allowed'}])

    def test_approved_binary_requires_matching_candidate_lock_metadata(self):
        files = self.snapshot_files()
        name = 'configs/resource-snapshots/base/packages.adb'
        lock = json.loads(files['resources.lock.json'])
        for row in lock['resources']:
            if row.get('bundled_path') == name:
                row['size'] += 1
        files['resources.lock.json'] = json.dumps(lock).encode()
        self.assertTrue(any(f['file'] == name and f['rule'] == 'binary-not-allowed'
                            for f in self.module().scan_files(files)))

    def test_conflicting_duplicate_lock_rows_do_not_approve_binary(self):
        files = self.snapshot_files()
        name = 'configs/resource-snapshots/base/packages.adb'
        lock = json.loads(files['resources.lock.json'])
        row = next(row for row in lock['resources'] if row.get('bundled_path') == name)
        lock['resources'].insert(0, {**row, 'size': row['size'] + 1})
        files['resources.lock.json'] = json.dumps(lock).encode()
        self.assertTrue(any(f['file'] == name and f['rule'] == 'binary-not-allowed'
                            for f in self.module().scan_files(files)))

    def test_git_index_uses_staged_bytes_and_ignores_private_working_files(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
            (root / '.gitignore').write_text('local/\n', encoding='utf-8')
            (root / 'safe.txt').write_text('public', encoding='utf-8')
            subprocess.run(['git', '-C', str(root), 'add', '.gitignore', 'safe.txt'], check=True)
            (root / 'local').mkdir()
            (root / 'local/secret.txt').write_text('ghp_' + 'B' * 36, encoding='utf-8')
            (root / 'safe.txt').write_text('ghp_' + 'C' * 36, encoding='utf-8')
            self.assertEqual(module.scan_files(module.git_files(root, index=True)), [])
            self.assertTrue(module.scan_files(module.git_files(root, working=True)))

    def test_source_package_prefix_is_removed_and_private_members_rejected(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                for name, data in [('source/README.md', b'public'),
                                   ('source/local/config.json', b'private')]:
                    row = tarfile.TarInfo(name)
                    row.size = len(data)
                    archive.addfile(row, io.BytesIO(data))
            files = self.module().archive_files(path)
            self.assertIn('README.md', files)
            self.assertEqual(self.module().scan_files(files), [
                {'file': 'local/config.json', 'line': 1, 'rule': 'private-artifact'}])

    def test_source_package_rejects_escape_and_links_without_extraction(self):
        import tarfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.tar'
            for name, kind in [('../escape', tarfile.REGTYPE), ('link', tarfile.SYMTYPE)]:
                with self.subTest(name=name), tarfile.open(path, 'w') as archive:
                    row = tarfile.TarInfo(name)
                    row.type, row.linkname = kind, '/etc/shadow'
                    archive.addfile(row)
                with self.assertRaises(ValueError):
                    self.module().archive_files(path)


if __name__ == '__main__':
    unittest.main()
