"""增量网络部署的来源、保留配置和精确撤销行为。"""
import importlib
from pathlib import Path
import stat
import sys
import unittest
import shutil
import subprocess
import tempfile
import copy
import io
import json
import tarfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


class RemoteUpdateTests(unittest.TestCase):
    def sample(self):
        from cm2012.archives import Entry, read_tar_bytes
        return read_tar_bytes(self.module().make_update(ROOT, {}, {
            'usr/bin/tool': Entry(stat.S_IFREG | 0o755, b'new')}))

    def rejected_before_ssh(self, data):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / 'update.tar.gz'
            bundle.write_bytes(data)
            with patch('cm2012.ssh_link.SSHLink') as connection:
                with self.assertRaises(ValueError):
                    self.module().deploy(bundle, '192.168.50.1')
                connection.assert_not_called()

    def test_archive_rejects_unlisted_members_aliases_types_and_bad_schema(self):
        from cm2012.archives import Entry, tar_bytes
        original = self.sample()
        for name, entry in [('evil', Entry(stat.S_IFREG | 0o700, b'bad')),
                            ('payload/usr/bin/extra', Entry(stat.S_IFREG | 0o600, b'bad')),
                            ('payload/www/unused', Entry(stat.S_IFDIR | 0o755)),
                            ('update', Entry(stat.S_IFLNK | 0o777, b'/etc/shadow'))]:
            files = dict(original); files[name] = entry
            with self.subTest(name=name): self.rejected_before_ssh(tar_bytes(files))
        base = json.loads(original['update.json'].data)
        malformed = [dict(base, extra=1), dict(base, format=True), dict(base, files=[])]
        for change in ({'extra': 1}, {'before': {}}, {'after': None},
                       {'before': {'kind': 'file', 'mode': True, 'sha256': 'a'*64}}):
            m = copy.deepcopy(base); m['files']['usr/bin/tool'].update(change); malformed.append(m)
        for m in malformed:
            files = dict(original); files['update.json'] = Entry(stat.S_IFREG | 0o600, json.dumps(m).encode())
            with self.subTest(manifest=m): self.rejected_before_ssh(tar_bytes(files))
        for name, kind in [('./update.json', tarfile.REGTYPE),
                           ('payload//usr/bin/tool', tarfile.REGTYPE),
                           ('payload//', tarfile.DIRTYPE),
                           ('payload/usr/bin/tool', tarfile.LNKTYPE),
                           ('payload/usr/bin/tool', tarfile.FIFOTYPE)]:
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w:gz') as archive:
                for n, e in original.items():
                    if stat.S_ISDIR(e.mode): continue
                    t = tarfile.TarInfo(n); t.mode = stat.S_IMODE(e.mode); t.size = len(e.data)
                    archive.addfile(t, io.BytesIO(e.data))
                t = tarfile.TarInfo(name); t.type = kind; t.linkname = 'update.json'
                archive.addfile(t, io.BytesIO(b''))
            with self.subTest(name=name, kind=kind): self.rejected_before_ssh(output.getvalue())
        for raw in (b'{"format":1,"format":1,"files":{}}', b'{"format":1,"files":{},"PRIVATE_SENTINEL"'):
            files = dict(original); files['update.json'] = Entry(stat.S_IFREG | 0o600, raw)
            self.rejected_before_ssh(tar_bytes(files))

    def test_prospective_link_cannot_hide_manifest_parent_with_dotdot(self):
        from cm2012.archives import Entry
        files = {'usr/bin/link': Entry(stat.S_IFLNK | 0o777, b'alias/../public'),
                 'usr/bin/alias': Entry(stat.S_IFLNK | 0o777, b'/usr/lib'),
                 'usr/bin/public': Entry(stat.S_IFREG | 0o755, b'public')}
        with self.assertRaises(ValueError): self.module().make_update(ROOT, {}, files)

    def test_legacy_updater_is_inert_and_upload_is_repacked(self):
        from cm2012.archives import Entry, read_tar_bytes, tar_bytes
        files = self.sample()
        files['update'] = Entry(stat.S_IFREG | 0o700, b'MALICIOUS_UPDATER')
        files['update.uc'] = Entry(stat.S_IFREG | 0o600, b'MALICIOUS_UPDATER')
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / 'update.tar.gz'; bundle.write_bytes(tar_bytes(files))
            with patch('cm2012.ssh_link.SSHLink') as connection:
                self.module().deploy(bundle, '192.168.50.1')
                uploaded = connection.return_value.__enter__.return_value.upload.call_args.args[2]
            self.assertNotIn(b'MALICIOUS_UPDATER', b''.join(e.data for e in read_tar_bytes(uploaded).values()))
            self.assertEqual(read_tar_bytes(uploaded)['update.uc'].data,
                             (ROOT/'tools/cm2012/device/network-update.uc').read_bytes().replace(b'\r\n', b'\n'))
            self.assertNotEqual(uploaded, bundle.read_bytes())

    def test_archive_and_member_resource_caps_apply_before_ssh(self):
        from cm2012.archives import tar_bytes
        module = importlib.import_module('cm2012.update_policy')
        data = tar_bytes(self.sample())
        for key in ('compressed_bytes', 'tar_bytes', 'member_bytes', 'members', 'manifest_bytes', 'payload_bytes'):
            with self.subTest(cap=key), patch.dict(module.POLICY['limits'], {key: 1}):
                self.rejected_before_ssh(data)

    def test_shared_policy_contract(self):
        module = self.module()
        cases = json.loads((ROOT/'tests/fixtures/update-policy-cases.json').read_text(encoding='utf-8'))
        for case in cases:
            with self.subTest(case=case):
                accepted = module.allowed_path(case['name']) and module.allowed_record(case['name'], {
                    'kind': 'link', 'mode': 0o777, 'target': case['target']})
                self.assertEqual(accepted, case['allowed'])

    def test_only_canonical_leaf_paths_are_update_targets(self):
        for name in ('usr', 'www', '/usr/bin/tool', 'usr//bin/tool', 'usr/./bin/tool',
                     'usr/bin/../tool', 'usr/bin/tool/', 'lib/apk', 'lib/firmware', 'lib/modules'):
            with self.subTest(name=name): self.assertFalse(self.module().allowed_path(name))

    def test_incoming_bundle_cannot_replace_existing_uci_before_ssh(self):
        from cm2012.archives import Entry, tar_bytes
        module = self.module()
        before = Entry(stat.S_IFREG | 0o600, b'live-config')
        after = Entry(stat.S_IFREG | 0o600, b'replacement')
        manifest = {'format': 1, 'files': {'etc/config/network': {
            'before': module.fingerprint(before), 'after': module.fingerprint(after)}}}
        self.rejected_before_ssh(tar_bytes({
            'update.json': Entry(stat.S_IFREG | 0o600, json.dumps(manifest).encode()),
            'payload/etc/config/network': after}))

    def test_link_policy_rejects_private_web_chain_loop_and_dangerous_before(self):
        from cm2012.archives import Entry
        link = lambda target: Entry(stat.S_IFLNK | 0o777, target.encode())
        for after in ({'www/leak': link('/etc/shadow')},
                      {'etc/config/leak': link('/usr/bin/tool')},
                      {'usr/bin/leak': link('/etc/config/cm2012_proxy')},
                      {'usr/bin/a': link('b'), 'usr/bin/b': link('/etc/shadow')},
                      {'usr/bin/a': link('b'), 'usr/bin/b': link('a')},
                      {'usr/bin/leak': link('../../../etc/shadow')}):
            with self.subTest(after=after), self.assertRaises(ValueError): self.module().make_update(ROOT, {}, after)
        with self.assertRaises(ValueError):
            self.module().make_update(ROOT, {'usr/bin/tool': link('/etc/shadow')},
                                      {'usr/bin/tool': Entry(stat.S_IFREG | 0o755, b'new')})

    def test_installer_executes_and_preserves_concurrent_edits(self):
        node=shutil.which('node')
        self.assertIsNotNone(node)
        result=subprocess.run([node,str(ROOT/'tests/fixtures/cm2012-update.cjs')],capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn(b'INCREMENTAL_INSTALL_ROLLBACK_OK',result.stdout)

    def module(self):
        try:
            return importlib.import_module('cm2012.remote_update')
        except ModuleNotFoundError:
            self.fail('网络增量更新接口尚未实现')

    def test_delta_preserves_live_credentials_and_excludes_boot(self):
        from cm2012.archives import Entry, read_tar_bytes
        f = lambda data: Entry(stat.S_IFREG | 0o600, data)
        before = {'etc/config/network': f(b'private-live'), 'usr/bin/tool': f(b'old')}
        after = {'etc/config/network': f(b'default'), 'usr/bin/tool': f(b'new'),
                 'etc/config/cm2012_proxy': f(b'disabled')}
        bundle = self.module().make_update(ROOT, before, after)
        files = read_tar_bytes(bundle)
        self.assertNotIn('payload/etc/config/network', files)
        self.assertEqual(files['payload/usr/bin/tool'].data, b'new')
        self.assertEqual(files['payload/etc/config/cm2012_proxy'].data, b'disabled')
        self.assertEqual(files['update.json'].mode & 0o777, 0o600)
        for path in ('dev/mtd0', 'boot.img', 'etc/shadow', 'etc/uhttpd.key',
                     'etc/cm2012-proxy/secret', 'var/lib/tailscale/tailscaled.state'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.module().make_update(ROOT, {}, {path: f(b'forbidden')})

    def test_delta_has_exact_old_and_new_fingerprints(self):
        import json
        from cm2012.archives import Entry, read_tar_bytes
        before = {'usr/bin/tool': Entry(stat.S_IFREG | 0o755, b'old'),
                  'usr/bin/link': Entry(stat.S_IFLNK | 0o777, b'tool')}
        after = {'usr/bin/tool': Entry(stat.S_IFREG | 0o755, b'new'),
                 'usr/bin/link': Entry(stat.S_IFLNK | 0o777, b'other'),
                 'usr/bin/other': Entry(stat.S_IFREG | 0o755, b'new')}
        files = read_tar_bytes(self.module().make_update(ROOT, before, after))
        manifest = json.loads(files['update.json'].data)
        self.assertEqual(manifest['format'], 1)
        self.assertEqual(set(manifest['files']), {'usr/bin/tool', 'usr/bin/link', 'usr/bin/other'})
        self.assertEqual(manifest['files']['usr/bin/link']['before']['target'], 'tool')
        self.assertIsNone(manifest['files']['usr/bin/other']['before'])
        self.assertNotEqual(manifest['files']['usr/bin/tool']['before']['sha256'],
                            manifest['files']['usr/bin/tool']['after']['sha256'])

    def test_only_fixed_public_geoip_link_is_allowed_in_proxy_state(self):
        from cm2012.archives import Entry, read_tar_bytes
        name = 'etc/cm2012-proxy/Country.mmdb'
        target = b'/usr/share/cm2012/geodata/Country.mmdb'
        link = Entry(stat.S_IFLNK | 0o777, target)
        files = read_tar_bytes(self.module().make_update(ROOT, {}, {name: link}))
        self.assertEqual(files['payload/' + name], link)
        for path, entry in (
                (name, Entry(stat.S_IFREG | 0o644, b'not-a-link')),
                (name, Entry(stat.S_IFLNK | 0o777, b'/etc/shadow')),
                (name, Entry(stat.S_IFLNK | 0o700, target)),
                ('etc/cm2012-proxy/Country.mmdb.other', link),
                ('etc/cm2012-proxy/secret', link),
                ('etc/cm2012-proxy/key.pem', link),
                ('etc/cm2012-proxy/cert.pem', link)):
            with self.subTest(path=path, entry=entry), self.assertRaises(ValueError):
                self.module().make_update(ROOT, {}, {path: entry})

    def test_deploy_rejects_tampered_public_geoip_target_before_ssh(self):
        import json
        from cm2012.archives import Entry, read_tar_bytes, tar_bytes
        name = 'etc/cm2012-proxy/Country.mmdb'
        module = self.module()
        valid = Entry(stat.S_IFLNK | 0o777, b'/usr/share/cm2012/geodata/Country.mmdb')
        files = read_tar_bytes(module.make_update(ROOT, {}, {name: valid}))
        bad = Entry(stat.S_IFLNK | 0o777, b'/etc/shadow')
        files['payload/' + name] = bad
        manifest = json.loads(files['update.json'].data)
        manifest['files'][name]['after'] = module.fingerprint(bad)
        files['update.json'] = Entry(stat.S_IFREG | 0o600, json.dumps(manifest).encode())
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / 'tampered.tar.gz'
            bundle.write_bytes(tar_bytes(files))
            with patch('cm2012.ssh_link.SSHLink') as connection, self.assertRaises(ValueError):
                module.deploy(bundle, '192.168.50.1')
            connection.assert_not_called()

    def test_increment_keeps_unrelated_apk_registration(self):
        from cm2012.archives import Entry,read_tar_bytes
        f=lambda data:Entry(stat.S_IFREG|0o600,data)
        before={'lib/apk/db/installed':f(b'base\nextra-user-package\n')}
        after={'lib/apk/db/installed':f(b'base\nnew-ddns-package\n'),'usr/bin/network-tool':f(b'program')}
        files=read_tar_bytes(self.module().make_update(ROOT,before,after))
        self.assertFalse('payload/lib/apk/db/installed' in files)

    def test_ssh_host_and_transfer_paths_cannot_be_options_or_shell(self):
        try:
            module = importlib.import_module('cm2012.ssh_link')
        except ModuleNotFoundError:
            self.fail('SSH 传输接口尚未实现')
        for host in ('-oProxyCommand=evil', 'host;reboot', 'root@host', '', '../host'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                module.SSHLink(host)
        link = module.SSHLink('192.168.50.1')
        with self.assertRaises(ValueError):
            link.upload('', '/etc/shadow', b'bad')


if __name__ == '__main__':
    unittest.main()
