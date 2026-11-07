"""锁定网络资源的离线装配、依赖闭包和 feed 路径保护。"""
import gzip
import hashlib
import importlib
import json
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from cm2012.archives import Entry, tar_bytes


class RemoteAssetTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.remote_assets')
        except ModuleNotFoundError:
            self.fail('网络资源离线装配接口缺失')

    def locked(self, root, ident, path, data, **fields):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if path.endswith('.apk'):
            fields.setdefault('apk_identity', '0123456789abcdef' * 4)
        return {'id': ident, 'path': path, 'url': 'https://example.invalid/' + ident,
                'version': '1.0-r1', 'size': len(data),
                'sha256': hashlib.sha256(data).hexdigest(), **fields}

    def assets(self, root):
        files = {
            'tailscale-arm': ('local/cache/ts.tgz', tar_bytes({
                'tailscale_1.0_arm/tailscale': Entry(stat.S_IFREG | 0o755, b'cli'),
                'tailscale_1.0_arm/tailscaled': Entry(stat.S_IFREG | 0o755, b'daemon')})),
            'mihomo-armv7': ('local/cache/mihomo.gz', gzip.compress(b'core')),
            'yq-arm': ('local/cache/yq', b'parser'),
            'curl-source': ('local/cache/curl-source.tgz', tar_bytes({
                'curl-8.22.0/COPYING': Entry(stat.S_IFREG | 0o644, b'curl license')})),
            'geoip-country-dbip': ('local/cache/country.mmdb.gz', gzip.compress(b'country database')),
            'metacubexd-static': ('local/cache/ui.tgz', tar_bytes({
                'metacubexd-fixed/index.html': Entry(stat.S_IFREG | 0o644, b'<html>ui</html>'),
                'metacubexd-fixed/_nuxt/app.js': Entry(stat.S_IFREG | 0o644, b'local-ui')})),
        }
        records = [self.locked(root, ident, path, data) for ident, (path, data) in files.items()]
        for ident in ('tailscale-license', 'mihomo-license', 'yq-license', 'metacubexd-license'):
            records.append(self.locked(root, ident, 'local/cache/' + ident + '.txt', b'public license'))
        geoip = next(item for item in records if item['id'] == 'geoip-country-dbip')
        geoip.update(uncompressed_size=len(b'country database'),
                     uncompressed_sha256=hashlib.sha256(b'country database').hexdigest())
        (root / 'resources.lock.json').write_text(json.dumps({'format': 1, 'resources': records}))
        return records

    def test_asset_files_include_local_programs_and_complete_dashboard(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.assets(root)
            result = self.module().asset_files(root)
            self.assertEqual(result['usr/sbin/tailscale'].data, b'cli')
            self.assertEqual(result['usr/sbin/tailscaled'].data, b'daemon')
            self.assertEqual(result['usr/bin/mihomo'].data, b'core')
            self.assertEqual(result['usr/bin/yq'].data, b'parser')
            self.assertEqual(result['www/metacubexd/_nuxt/app.js'].data, b'local-ui')
            self.assertTrue(result['usr/bin/mihomo'].mode & 0o111)
            self.assertEqual(result['usr/share/licenses/cm2012-network/curl-source.txt'].data, b'curl license')

    def test_missing_required_license_lock_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            records = self.assets(root)
            records = [row for row in records if row['id'] != 'tailscale-license']
            (root / 'resources.lock.json').write_text(json.dumps({'format': 1, 'resources': records}))
            with self.assertRaises(ValueError):
                self.module().asset_files(root)

    def test_country_database_is_decompressed_with_locked_identity_and_attribution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.assets(root)
            result = self.module().asset_files(root)
            database = result['usr/share/cm2012/geodata/Country.mmdb']
            self.assertEqual(database.data, b'country database')
            self.assertEqual(stat.S_IMODE(database.mode), 0o644)
            manifest = json.loads(result['usr/share/cm2012/remote-assets.json'].data)
            self.assertEqual(manifest['geoip-country-dbip']['uncompressed_size'], len(database.data))
            self.assertEqual(manifest['geoip-country-dbip']['uncompressed_sha256'],
                             hashlib.sha256(database.data).hexdigest())
            notice = result['usr/share/licenses/cm2012-network/geoip-country-dbip.txt'].data.decode()
            for required in ('DB-IP Country Lite', 'https://db-ip.com',
                             'https://creativecommons.org/licenses/by/4.0/', 'unchanged'):
                self.assertIn(required, notice)

    def test_country_database_rejects_missing_lock_or_wrong_decompressed_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            records = self.assets(root)
            for field, value in (('uncompressed_sha256', '0' * 64), ('uncompressed_size', 1),
                                 ('uncompressed_sha256', None), ('uncompressed_size', None)):
                changed = [dict(item) for item in records]
                geoip = next(item for item in changed if item['id'] == 'geoip-country-dbip')
                if value is None:
                    geoip.pop(field)
                else:
                    geoip[field] = value
                (root / 'resources.lock.json').write_text(json.dumps({'format': 1, 'resources': changed}))
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.module().asset_files(root)
            changed = [item for item in records if item['id'] != 'geoip-country-dbip']
            (root / 'resources.lock.json').write_text(json.dumps({'format': 1, 'resources': changed}))
            with self.assertRaises(ValueError):
                self.module().asset_files(root)

    def test_missing_or_modified_network_asset_never_uses_online_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            records = self.assets(root)
            (root / records[2]['path']).unlink()
            with self.assertRaises(FileNotFoundError):
                self.module().asset_files(root)
            (root / records[2]['path']).write_bytes(b'wrong')
            with self.assertRaises(ValueError):
                self.module().asset_files(root)

    def test_asset_manifest_records_package_versions_without_replacing_apk_database(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            records = self.assets(root)
            package = self.locked(root, 'curl', 'local/cache/apk/packages/curl.apk', b'curl',
                                  feed='packages', depends=[])
            records.append(package)
            (root / 'resources.lock.json').write_text(json.dumps({'format': 1, 'resources': records}))
            result = self.module().asset_files(root)
            manifest = json.loads(result['usr/share/cm2012/remote-assets.json'].data)
            self.assertIn('packages', manifest)
            self.assertEqual(manifest['packages'], {'curl': {
                'version': '1.0-r1', 'sha256': hashlib.sha256(b'curl').hexdigest(), 'feed': 'packages'}})

    def test_dashboard_rejects_link_instead_of_packaging_external_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            records = self.assets(root)
            ui = tar_bytes({'ui/index.html': Entry(stat.S_IFLNK | 0o777, b'/etc/shadow')})
            records[-1] = self.locked(root, 'metacubexd-static', 'local/cache/ui.tgz', ui)
            (root / 'resources.lock.json').write_text(json.dumps({'format': 1, 'resources': records}))
            with self.assertRaises(ValueError):
                self.module().asset_files(root)

    def test_apk_payload_preserves_each_feed_index_and_package_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            records = [
                self.locked(root, 'base-index', 'local/cache/apk/base/packages.adb', b'base-index', feed='base'),
                self.locked(root, 'packages-index', 'local/cache/apk/packages/packages.adb', b'packages-index', feed='packages'),
                self.locked(root, 'a', 'local/cache/apk/base/a.apk', b'a', feed='base', depends=[{'name': 'b'}]),
                self.locked(root, 'b', 'local/cache/apk/packages/b.apk', b'b', feed='packages', depends=[{'name': 'libc'}]),
            ]
            seed = {'lib/apk/db/installed': Entry(stat.S_IFREG | 0o644, b'P:libc\nV:1.2.5-r5\np:libc-any\n\n')}
            payload, size = self.module().apk_payload(root, {r['id']: r for r in records}, seed)
            self.assertEqual(payload['apk/base/packages.adb'].data, b'base-index')
            self.assertEqual(payload['apk/packages/packages.adb'].data, b'packages-index')
            self.assertEqual(payload['apk/packages/b.apk'].data, b'b')
            self.assertEqual(payload['repositories.list'].data, b'apk/base/packages.adb\napk/packages/packages.adb\n')
            self.assertEqual(size, 26)

    def test_apk_payload_rejects_path_collision_even_if_bytes_match(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            item = self.locked(root, 'one', 'local/cache/apk/base/packages.adb', b'index', feed='base')
            with self.assertRaises(ValueError):
                self.module().apk_payload(root, {'one': item, 'two': dict(item, id='two')}, {})

    def test_apk_payload_uses_identity_cache_and_constraints_for_overlapping_feed_snapshots(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            records = [
                self.locked(root, 'old-index', 'local/cache/apk/base-old/packages.adb', b'old-index', feed='base-old'),
                self.locked(root, 'index', 'local/cache/apk/base/packages.adb', b'new-index', feed='base'),
                self.locked(root, 'wifi-scripts', 'local/cache/apk/base-old/wifi-scripts-1.0-r1.apk',
                            b'old-wifi', feed='base-old', depends=[]),
            ]
            payload, _ = self.module().apk_payload(root, {r['id']: r for r in records}, {})
            self.assertIn('apk-cache/wifi-scripts-1.0-r1.01234567.apk', payload)
            cached = payload['apk-cache/wifi-scripts-1.0-r1.01234567.apk']
            self.assertTrue(stat.S_ISLNK(cached.mode))
            self.assertEqual(cached.data, b'../apk/base-old/wifi-scripts-1.0-r1.apk')
            self.assertEqual(payload['apk-constraints.list'].data,
                             b'wifi-scripts><X10123456789abcdef0123456789abcdef01234567\n')

    def test_apk_payload_rejects_missing_or_malformed_index_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            index = self.locked(root, 'index', 'local/cache/apk/base/packages.adb', b'index', feed='base')
            package = self.locked(root, 'app', 'local/cache/apk/base/app.apk', b'app', feed='base', depends=[])
            for identity in (None, 'bad', 'f' * 40, 'G' * 64):
                package['apk_identity'] = identity
                with self.subTest(identity=identity), self.assertRaises(ValueError):
                    self.module().apk_payload(root, {'index': index, 'app': package}, {})

    def test_apk_payload_rejects_missing_dependency_and_missing_feed_index(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            index = self.locked(root, 'index', 'local/cache/apk/base/packages.adb', b'index', feed='base')
            package = self.locked(root, 'app', 'local/cache/apk/base/app.apk', b'app', feed='base', depends=[{'name': 'missing-lib'}])
            with self.assertRaises(ValueError):
                self.module().apk_payload(root, {'index': index, 'app': package}, {})
            package['depends'] = []
            with self.assertRaises(ValueError):
                self.module().apk_payload(root, {'app': package}, {})

    def test_apk_closure_requires_exact_version_when_dependency_is_versioned(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            index = self.locked(root, 'index', 'local/cache/apk/base/packages.adb', b'index', feed='base')
            package = self.locked(root, 'app', 'local/cache/apk/base/app.apk', b'app', feed='base', depends=[{'name': 'libc', 'version': 'new'}])
            seed = {'lib/apk/db/installed': Entry(stat.S_IFREG | 0o644, b'P:libc\nV:old\n\n')}
            with self.assertRaises(ValueError):
                self.module().apk_payload(root, {'index': index, 'app': package}, seed)

    def test_remote_root_validation_rejects_missing_program_and_dashboard(self):
        from cm2012 import build
        self.assertTrue(callable(getattr(build, 'validate_remote_root', None)), '根归档缺少网络扩展校验')
        program = bytearray(84)
        program[:52] = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01\x01' + bytes(9),
                                  2, 40, 1, 0x1000, 52, 0, 0, 52, 32, 1, 0, 0, 0)
        struct.pack_into('<8I', program, 52, 1, 0, 0x1000, 0x1000, 84, 84, 5, 4096)
        entries = {name: Entry(stat.S_IFREG | 0o755, bytes(program)) for name in (
            'usr/sbin/tailscale', 'usr/sbin/tailscaled', 'usr/bin/mihomo', 'usr/bin/yq',
            'usr/bin/curl', 'usr/bin/openssl', 'sbin/ip', 'usr/bin/drill', 'usr/bin/timeout',
            'usr/libexec/cm2012-proxy-fetch', 'usr/lib/libcurl.so.4',
            'usr/lib/ddns/dynamic_dns_updater.sh')}
        entries.update({name: Entry(stat.S_IFREG | 0o644, b'data') for name in (
            'www/metacubexd/index.html', 'etc/ssl/certs/ca-certificates.crt',
            'usr/lib/ddns/update_cloudflare_com_v4.sh',
            'www/luci-static/resources/view/ddns/overview.js')})
        build.validate_remote_root(entries)
        for name in ('usr/bin/yq', 'usr/bin/drill', 'usr/bin/timeout', 'www/metacubexd/index.html',
                     'usr/libexec/cm2012-proxy-fetch', 'usr/lib/libcurl.so.4'):
            broken = dict(entries)
            broken.pop(name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                build.validate_remote_root(broken)


if __name__ == '__main__':
    unittest.main()
