"""公开固件的网络配置、服务归属和旧内核兼容回归。"""
from pathlib import Path
import importlib
import stat
import sys
import unittest
import json
import shutil
import subprocess
import os
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


class RuntimeTests(unittest.TestCase):
    def module(self):
        return importlib.import_module('cm2012.runtime')

    def test_defaults_share_standard_dhcp_and_defer_ap_address(self):
        files = self.module().configuration({'ssid': 'public', 'ap_password': 'secret123'})
        network = files['etc/config/network'].decode()
        self.assertIn("config interface 'lan'", network)
        self.assertIn("option device 'ap0'", network)
        self.assertIn("option auto '0'", network)
        self.assertIn("option device 'eth0'", network)
        self.assertIn("option device 'wlan0'", network)
        dhcp = files['etc/config/dhcp'].decode()
        self.assertIn("option leasefile '/tmp/dhcp.leases'", dhcp)
        self.assertIn("option limit '51'", dhcp)
        self.assertIn("option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'", dhcp)

    def test_uci_values_cannot_inject_sections(self):
        module = self.module()
        for value in ('bad\nconfig wifi evil', 'bad\rvalue', 'bad\x00value'):
            with self.assertRaises(ValueError):
                module.configuration({'ssid': value, 'ap_password': 'secret123'})
        text = module.configuration({'ssid': "a'\"\\b", 'ap_password': "s'cret123"})['etc/config/cm2012'].decode()
        self.assertEqual(text.count('config '), 3)
        self.assertIn("option uplink 'ethernet'", text)

    def test_only_known_incompatible_services_are_removed(self):
        from cm2012.archives import Entry
        entries = {name: Entry(stat.S_IFLNK | 0o777, b'../init.d/wpad') for name in
                   ('etc/rc.d/S19wpad', 'etc/rc.d/K21wpad', 'etc/rc.d/S50uhttpd')}
        entries['usr/sbin/nft'] = Entry(stat.S_IFREG | 0o755, b'old')
        entries['sbin/fw4'] = Entry(stat.S_IFREG | 0o755, b'old')
        entries['sbin/fw3'] = Entry(stat.S_IFLNK | 0o777, b'fw4')
        entries['etc/init.d/dnsmasq'] = Entry(stat.S_IFREG | 0o755,
            b'\tprocd_add_jail dnsmasq ubus log\n\tprocd_add_jail_mount /etc/hosts\n\tprocd_close_instance\n')
        clean = self.module().prepare_root(entries)
        self.assertIn('etc/rc.d/S50uhttpd', clean)
        for name in ('etc/rc.d/S19wpad', 'etc/rc.d/K21wpad', 'usr/sbin/nft', 'sbin/fw4', 'sbin/fw3'):
            self.assertNotIn(name, clean)
        self.assertNotIn(b'procd_add_jail', clean['etc/init.d/dnsmasq'].data)
        self.assertIn(b'procd_close_instance', clean['etc/init.d/dnsmasq'].data)

    def test_runtime_files_own_services_and_defer_lan_until_hostapd(self):
        files = self.module().runtime_files(ROOT)
        service = files['etc/init.d/cm2012-ap'].data.decode()
        self.assertIn('/usr/libexec/cm2012-wifi run', service)
        self.assertNotIn('cm2012-ap-dhcp', service)
        worker = files['usr/libexec/cm2012-wifi'].data.decode()
        self.assertLess(worker.index('ENABLED'), worker.index('ifup lan'))
        self.assertIn('ifdown wan', worker)
        self.assertIn('ifdown wwan', worker)
        self.assertNotIn('procd_add_jail', files['etc/init.d/sysntpd'].data.decode())
        self.assertIn('/sbin/fw3', files['etc/init.d/firewall'].data.decode())

    def test_iptables_case_distinct_sources_survive_windows(self):
        from cm2012.legacy_firewall import case_safe_names
        names = ['extensions/libxt_MARK.c', 'extensions/libxt_mark.c',
                 'include/linux/netfilter/xt_MARK.h', 'include/linux/netfilter/xt_mark.h']
        mapped = case_safe_names(names)
        self.assertEqual(len(set(n.casefold() for n in mapped.values())), len(names))
        self.assertEqual(mapped, case_safe_names(names))

    def test_rpc_acl_does_not_grant_generic_execution_or_secret_uci_reads(self):
        acl = json.loads((ROOT / 'configs/templates/cm2012-acl.json').read_text(encoding='utf-8'))['luci-app-cm2012']
        self.assertEqual(acl['read'], {'ubus': {'cm2012': ['status', 'scan']}})
        self.assertEqual(acl['write'], {'ubus': {'cm2012': ['apply', 'confirm', 'rollback']}})
        source = (ROOT / 'configs/templates/cm2012-rpc.uc').read_text(encoding='utf-8')
        status = source.split('status: { call:', 1)[1].split('scan: { call:', 1)[0]
        self.assertNotIn("'key'", status)

    def test_confirmation_requires_current_readiness_and_wired_keys_are_validated(self):
        source = (ROOT / 'configs/templates/cm2012-rpc.uc').read_text(encoding='utf-8')
        confirm = source.split('confirm: {', 1)[1].split('rollback: {', 1)[0]
        self.assertIn("readfile('/tmp/cm2012-wifi/ready')", confirm)
        self.assertIn('valid_text(stakey, 8, 63)', source.split("a.uplink == 'wifi'", 1)[0])
        worker = (ROOT / 'configs/templates/cm2012-wifi').read_text(encoding='utf-8')
        self.assertIn('rm -f "$state/pending/ready"', worker)

    def test_worker_exit_invalidates_readiness(self):
        shell = shutil.which('sh')
        if not shell: self.skipTest('POSIX sh 不可用')
        source = (ROOT / 'configs/templates/cm2012-wifi').read_text(encoding='utf-8')
        cleanup = re.search(r'(?ms)^cleanup\(\) \{\n.*?^\}', source).group()
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'pending').mkdir()
            for name in ('ready', 'pending/ready'):
                (Path(folder) / name).write_text('generation')
            script = cleanup + '\nstate=$1; host_pid=; sta_pid=; cleanup\n'
            path = Path(folder) / 'cleanup.sh'
            path.write_text(script, encoding='utf-8', newline='\n')
            result = subprocess.run([shell, path.as_posix(), Path(folder).as_posix()],
                                    cwd=folder, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((Path(folder) / 'ready').exists())
            self.assertFalse((Path(folder) / 'pending/ready').exists())


if __name__ == '__main__':
    unittest.main()
