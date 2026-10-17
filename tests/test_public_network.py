"""Network configuration and persistent transaction behavior regressions."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import os

ROOT = Path(__file__).resolve().parents[1]


class NetworkTests(unittest.TestCase):
    def test_rollback_cancels_delayed_service_descendants(self):
        if os.name == 'nt':
            self.skipTest('Linux process sessions unavailable; run fixture natively on box')
        self.assertIsNotNone(shutil.which('setsid'), 'setsid is required on Linux CI')
        functions=(ROOT/'configs/templates/cm2012-network').read_text(encoding='utf-8').split('\ncase ',1)[0]
        for name in ('dash','bash'):
            with self.subTest(shell=name):
                shell=shutil.which(name)
                self.assertIsNotNone(shell, name+' is required on Linux CI')
                with tempfile.TemporaryDirectory() as folder:
                    root=Path(folder);source=root/'functions.sh';source.write_text(functions,encoding='utf-8',newline='\n')
                    result=subprocess.run([shell,str(ROOT/'tests/fixtures/cm2012-checker.sh'),source.as_posix(),root.as_posix(),shell],capture_output=True,timeout=20)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    self.assertIn(b'CHECKER_DESCENDANTS_CANCELLED',result.stdout)

    def test_checker_fixture_rejects_failed_session_start(self):
        if os.name == 'nt': self.skipTest('Linux process sessions unavailable')
        shell=shutil.which('dash');self.assertIsNotNone(shell)
        self.assertIsNotNone(shutil.which('setsid'))
        functions=(ROOT/'configs/templates/cm2012-network').read_text(encoding='utf-8').split('\ncase ',1)[0]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'functions.sh';source.write_text(functions,encoding='utf-8',newline='\n')
            failed=root/'failed-shell';failed.write_text('#!/bin/sh\nexit 23\n',newline='\n');failed.chmod(0o700)
            result=subprocess.run([shell,str(ROOT/'tests/fixtures/cm2012-checker.sh'),source.as_posix(),root.as_posix(),failed.as_posix()],capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertNotIn(b'CHECKER_DESCENDANTS_CANCELLED',result.stdout)
            self.assertIn(b'checker exited before child handshake',result.stderr)

    def test_journal_failures_never_report_success(self):
        shell=shutil.which('sh')
        if not shell: self.skipTest('POSIX sh unavailable')
        functions=(ROOT/'configs/templates/cm2012-network').read_text(encoding='utf-8').split('\ncase ',1)[0]
        cases=[('prepare token','sync'),('snapshot','cp'),('snapshot','sync'),('decide rollback','touch')]
        for action,failure in cases:
            with self.subTest(action=action,failure=failure), tempfile.TemporaryDirectory() as folder:
                root=Path(folder);config=root/'config';config.mkdir();journal=root/'journal';state=root/'state';state.mkdir()
                for name in ('cm2012','network','dhcp','firewall'): (config/name).write_text('original')
                if action!='prepare token':
                    journal.mkdir();(journal/'prepared').touch()
                script=root/'test.sh'
                script.write_text(functions+f'\nconfig_dir=$1; journal=$2; state=$3\n{failure}() {{ return 1; }}\nif {action}; then echo FALSE_SUCCESS; exit 8; fi\n[ -d "$journal" ]\n',encoding='utf-8',newline='\n')
                result=subprocess.run([shell,script.as_posix(),config.as_posix(),journal.as_posix(),state.as_posix()],capture_output=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_readiness_rejects_unreadable_uci(self):
        shell=shutil.which('sh')
        if not shell: self.skipTest('POSIX sh unavailable')
        functions=(ROOT/'configs/templates/cm2012-network').read_text(encoding='utf-8').split('\ncase ',1)[0]
        functions=functions.replace('/sbin/fw3 print','true')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'ready').write_text('generation');script=root/'test.sh'
            script.write_text(functions+'''
state=$1
uci() { return 1; }
ubus() { echo '{"up": true}'; }
pidof() { return 0; }
if ready; then echo FALSE_READY; exit 8; fi
''',encoding='utf-8',newline='\n')
            result=subprocess.run([shell,script.as_posix(),root.as_posix()],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_readiness_keeps_legacy_wan_default_when_eth_role_is_absent(self):
        shell = shutil.which('sh')
        if not shell:
            self.skipTest('POSIX sh unavailable')
        functions = (ROOT / 'configs/templates/cm2012-network').read_text(encoding='utf-8').split('\ncase ', 1)[0]
        functions = functions.replace('/sbin/fw3 print', 'true')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'ready').write_text('generation')
            script = root / 'test.sh'
            script.write_text(functions + '''
state=$1
uci() {
 case "$*" in
  '-q show cm2012') return 0;;
  '-q get cm2012.settings.eth_role') return 1;;
  '-q get cm2012.ap.enabled') echo 0;;
  '-q get cm2012.settings.uplink') echo ethernet;;
  *) return 1;;
 esac
}
pidof() { return 0; }
ready
''', encoding='utf-8', newline='\n')
            result = subprocess.run([shell, script.as_posix(), root.as_posix()], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_failed_restore_keeps_journal_and_blocks_recovery(self):
        shell=shutil.which('sh')
        if not shell: self.skipTest('POSIX sh unavailable')
        functions=(ROOT/'configs/templates/cm2012-network').read_text(encoding='utf-8').split('\ncase ',1)[0]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);config=root/'config';config.mkdir();journal=root/'journal'
            state=root/'state';state.mkdir()
            for failure in ('ucode', 'cp', 'mv'):
                with self.subTest(failure=failure):
                    journal.mkdir(exist_ok=True);(journal/'prepared').touch()
                    for name in ('cm2012','network','dhcp','firewall'):
                        (config/name).write_text('changed');(journal/name).write_text('original')
                    applied=journal/'applied';applied.mkdir(exist_ok=True)
                    if failure=='ucode': (applied/'complete').touch()
                    elif (applied/'complete').exists(): (applied/'complete').unlink()
                    script=root/'test.sh'
                    script.write_text(functions+'''
config_dir=$1; journal=$2; state=$3
'''+failure+'''() { return 1; }
if recover; then echo FAILED_RECOVERY_ACCEPTED; exit 8; fi
[ -f "$journal/prepared" ]
''',encoding='utf-8',newline='\n')
                    result=subprocess.run([shell,script.as_posix(),config.as_posix(),journal.as_posix(),state.as_posix()],capture_output=True,timeout=15)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_bridge_netlink_filter_preserves_other_attributes(self):
        cc=shutil.which('cc') or shutil.which('clang')
        zig=ROOT/'local/toolchain/zig-windows-x86_64-0.13.0/zig.exe'
        if not cc and not zig.exists():
            self.skipTest('C compiler unavailable; native device fixture remains required')
        compiler=[cc] if cc else [str(zig),'cc']
        with tempfile.TemporaryDirectory() as folder:
            binary=Path(folder)/('filter.exe' if os.name=='nt' else 'filter')
            env=os.environ.copy()
            if not cc:
                env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'local/zig-global-cache')
                env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'local/zig-local-cache')
            result=subprocess.run(compiler+['-Os',str(ROOT/'tools/cm2012/netlink_compat.c'),
                str(ROOT/'tests/fixtures/netlink_compat.c'),'-o',str(binary)],env=env,capture_output=True,timeout=90)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(binary)],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn(b'NETLINK_BRIDGE_COMPAT_OK',result.stdout)

    def test_rollback_decision_prevents_late_confirmation(self):
        shell=shutil.which('sh')
        if not shell: self.skipTest('POSIX sh unavailable')
        functions=(ROOT/'configs/templates/cm2012-network').read_text(encoding='utf-8').split('\ncase ',1)[0]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);journal=root/'journal';journal.mkdir();state=root/'state';state.mkdir()
            (journal/'token').write_text('token');(journal/'prepared').touch()
            script=root/'test.sh'
            script.write_text(functions+'''
journal=$1; state=$2
decide rollback
if decide confirm token; then exit 8; fi
[ ! -f "$journal/confirmed" ]
[ -f "$journal/rolling-back" ]
rm "$journal/rolling-back"
mkdir "$journal/decision.lock"
(sleep .2; rmdir "$journal/decision.lock") &
wait_decision rollback
[ -f "$journal/rolling-back" ]
''',encoding='utf-8',newline='\n')
            result=subprocess.run([shell,script.as_posix(),journal.as_posix(),state.as_posix()],capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_ap_off_does_not_disable_wired_lan(self):
        shell = shutil.which('sh')
        if not shell:
            self.skipTest('POSIX sh unavailable')
        source = (ROOT / 'configs/templates/cm2012-wifi').read_text(encoding='utf-8')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); state = root / 'state'; state.mkdir()
            calls = root / 'calls'
            library = root / 'functions'
            library.write_text('''
config_load() { :; }
config_get() {
 case "$1" in
 ssid) ssid=public;; key) key=secret123;; enabled) enabled=0;;
 uplink) uplink=wifi;; eth_role) eth_role=lan;; channel) channel=153;;
 country) country=CN;; upstream) upstream=upstream;; esac
}
''', encoding='utf-8', newline='\n')
            config = root / 'config'; config.write_text('fixture')
            empty = root / 'empty.sh'; empty.write_text('#!/bin/sh\nexit 0\n', newline='\n')
            control = root / 'control.sh'
            control.write_text('#!/bin/sh\necho wpa_state=COMPLETED\necho freq=5745\n', newline='\n')
            record = root / 'record.sh'
            record.write_text('#!/bin/sh\necho "$0 $*" >> "' + calls.as_posix() + '"\n', newline='\n')
            script = source.replace('. /lib/functions.sh', '. "'+library.as_posix()+'"')
            script = script.replace('state=/tmp/cm2012-wifi','state="'+state.as_posix()+'"')
            script = script.replace('/etc/config/cm2012','"'+config.as_posix()+'"')
            script = script.replace('/usr/libexec/cm2012-wpa-control','sh "'+control.as_posix()+'"')
            script = script.replace('/usr/sbin/wpa_supplicant','sh "'+empty.as_posix()+'"')
            script = script.replace('ucode /usr/libexec/cm2012-supplicant.uc','true')
            script = script.replace('/etc/init.d/dnsmasq','sh "'+record.as_posix()+'"')
            script = script.replace('ifup ', 'sh "'+record.as_posix()+'" ifup ')
            script = script.replace('ifdown ', 'sh "'+record.as_posix()+'" ifdown ')
            script = script.replace('ubus ', 'sh "'+record.as_posix()+'" ubus ')
            path = root / 'worker.sh'; path.write_text(script,encoding='utf-8',newline='\n')
            subprocess.run([shell,path.as_posix(),'run'],capture_output=True,timeout=10)
            observed = calls.read_text()
            self.assertIn('ifup lan',observed)
            self.assertNotIn('ifdown lan',observed)
            self.assertIn('network.interface.wwan add_device',observed)

    def test_network_validation_and_configuration(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node.js unavailable')
        result = subprocess.run([node, str(ROOT / 'tests/fixtures/cm2012-network.cjs')],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('NETWORK_VALIDATION_AND_RENDERING_OK', result.stdout)

    def test_journal_recovers_all_configs_but_preserves_confirmed_changes(self):
        shell = shutil.which('sh')
        if not shell:
            self.skipTest('POSIX sh unavailable')
        source_path = ROOT / 'configs/templates/cm2012-network'
        self.assertTrue(source_path.exists(), 'persistent transaction helper required')
        source = source_path.read_text(encoding='utf-8')
        functions = source.split('\ncase ', 1)[0]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = root / 'config'; config.mkdir()
            journal = root / 'journal'; state = root / 'state'; state.mkdir()
            original = {}
            for name in ('cm2012', 'network', 'dhcp', 'firewall'):
                original[name] = f'original {name}\n'
                (config / name).write_text(original[name])
            script = root / 'test.sh'
            script.write_text(functions + '''
config_dir=$1; journal=$2; state=$3
prepare test-token
for name in cm2012 network dhcp firewall; do echo changed > "$config_dir/$name"; done
recover
''', encoding='utf-8', newline='\n')
            command = [shell, script.as_posix(), config.as_posix(), journal.as_posix(), state.as_posix()]
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name, text in original.items():
                self.assertEqual((config / name).read_text(), text)
            self.assertFalse(journal.exists())
            script.write_text(functions + '''
config_dir=$1; journal=$2; state=$3
prepare test-token
echo stable > "$config_dir/network"
touch "$journal/confirmed"
recover
''', encoding='utf-8', newline='\n')
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((config / 'network').read_text(), 'stable\n')
            self.assertFalse(journal.exists())

    def test_incomplete_backup_and_second_transaction_cannot_damage_configs(self):
        shell = shutil.which('sh')
        if not shell:
            self.skipTest('POSIX sh unavailable')
        path = ROOT / 'configs/templates/cm2012-network'
        functions = path.read_text(encoding='utf-8').split('\ncase ',1)[0]
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); config=root/'config'; config.mkdir(); state=root/'state'; state.mkdir()
            journal=root/'journal'
            for name in ('cm2012','network','dhcp'):
                (config/name).write_text('original')
            script=root/'probe.sh'
            script.write_text(functions+'''
config_dir=$1; journal=$2; state=$3
if prepare token; then exit 9; fi
[ ! -d "$journal" ]
echo original > "$config_dir/firewall"
prepare first-token
if prepare second-token; then exit 8; fi
[ "$(cat "$journal/token")" = first-token ]
recover
''',encoding='utf-8',newline='\n')
            result=subprocess.run([shell,script.as_posix(),config.as_posix(),journal.as_posix(),state.as_posix()],capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((config/'network').read_text(),'original')


if __name__ == '__main__':
    unittest.main()
