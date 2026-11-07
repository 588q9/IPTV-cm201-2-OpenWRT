"""Execute pinned public DDNS scripts with synthetic credentials; no device/network."""
import importlib
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from cm2012.archives import Entry

FIXTURES = Path(__file__).parent / 'fixtures' / 'ddns-2.8.4-r8'
CF = 'usr/lib/ddns/update_cloudflare_com_v4.sh'
FUNCTIONS = 'usr/lib/ddns/dynamic_dns_functions.sh'
TOKEN = "SYNTHETIC_token_'quoted_$value"


def function(source, name):
    start = source.index(name + '() {')
    return source[start:source.index('\n}', start) + 2]


class CredentialTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.credentials')
        except ModuleNotFoundError:
            self.fail('locked DDNS credential protection helper missing')

    def entries(self):
        return {name: Entry(stat.S_IFREG | 0o755, (FIXTURES / Path(name).name).read_bytes(), 12, 34)
                for name in (CF, FUNCTIONS)}

    def execute(self, entries, *, token=TOKEN, error=False, username='Bearer', registered=False):
        shell = shutil.which('sh')
        self.assertIsNotNone(shell, 'POSIX sh is required for credential execution tests')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'cloudflare.sh').write_bytes(entries[CF].data)
            functions = entries[FUNCTIONS].data.decode()
            (root / 'logger.sh').write_text(function(functions, 'write_log') + '\n' + function(functions, 'urlencode'))
            (root / 'observe-awk.sh').write_text('''#!/bin/sh
printf '%s\\n' "$@" >> "$WORK/awk-argv"
exec "$REAL_AWK" "$@"
''', encoding='utf-8')
            # A real child process captures actual curl argv and its stdin, with no network.
            (root / 'curl.sh').write_text('''#!/bin/sh
printf '%s\\n' "$@" >> "$WORK/argv"
out= err= header=
while [ "$#" -gt 0 ]; do
 case "$1" in
  -o) shift; out=$1;;
  --stderr) shift; err=$1;;
  --header) shift; header=$1; [ "$header" != @- ] || cat >> "$WORK/headers";;
 esac
 shift
done
printf '{"success":true,"result":{"content":"198.51.100.2"}}' > "$out"
if [ "$FAIL_CURL" = 1 ]; then
 printf '{"success":false}' > "$out"
 cat "$WORK/headers" > "$err"
 exit 22
fi
''', encoding='utf-8')
            harness = '''
cd "$WORK" || exit 90
. ./logger.sh
VERBOSE=2; VERBOSE_MODE=2; use_logfile=1; use_syslog=0; LOGFILE=$WORK/log
LUCI_HELPER=1; ddns_loglines=100
awk() { sh "$WORK/observe-awk.sh" "$@"; }
# Actual updater startup operations (dynamic_dns_updater.sh:168-169).
[ -n "$username" ] && urlencode URL_USER "$username"
[ -n "$password" ] && urlencode URL_PASS "$password"
[ -n "$param_enc" ] && urlencode URL_PENC "$param_enc"
[ "$URL_PASS" != "$EXPECTED_ENCODED" ] || printf 'ENCODER_MATCH=yes\\n'
jsonfilter() { case "$*" in *result.content*) printf '198.51.100.2';; *) printf 'id';; esac; }
CURL="sh $WORK/curl.sh"; CURL_SSL=1; use_https=1; use_ipv6=0; force_ipversion=0
domain=host@example.invalid; DATFILE=$WORK/data; ERRFILE=$WORK/err
retry_max_count=1; RETRY_SECONDS=0; __IP=198.51.100.1
IPV4_REGEX='[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'
run() { . ./cloudflare.sh; }
run
result=$?
printf '\\nRESULT=%s REGISTERED=%s\\n' "$result" "$REGISTERED_IP"
exit 0
'''
            import os
            real_awk = subprocess.run([shell, '-c', 'command -v awk'], text=True,
                                      capture_output=True, check=True).stdout.strip()
            env = dict(os.environ, WORK=root.as_posix(), password=token, username=username,
                       FAIL_CURL=str(int(error)), GET_REGISTERED_IP='1' if registered else '',
                       REAL_AWK=real_awk,
                       EXPECTED_ENCODED='SYNTHETIC_token_%27quoted_%24value')
            result = subprocess.run([shell], input=harness, text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            files = {p.name: p.read_text() for p in root.iterdir() if p.name not in
                     ('cloudflare.sh', 'logger.sh', 'curl.sh', 'observe-awk.sh')}
            return result.stdout + result.stderr, files

    def test_startup_encoder_keeps_secrets_out_of_external_argv(self):
        output, files = self.execute(self.module().protect_root(self.entries()))
        self.assertIn('ENCODER_MATCH=yes', output)
        self.assertNotIn(TOKEN, files['awk-argv'])
        self.assertNotIn('SYNTHETIC_token_%27quoted_%24value', files['awk-argv'])
        self.assertNotIn(TOKEN, output + files.get('log', ''))
        self.assertNotIn('SYNTHETIC_token_%27quoted_%24value', output + files.get('log', ''))

    def test_encoder_preserves_assignment_and_literal_url_encoding(self):
        import os
        encoder = function(self.module().protect_root(self.entries())[FUNCTIONS].data.decode(), 'urlencode')
        for value, expected in (('', ''), ('AZaz09-_.~', 'AZaz09-_.~'),
                                ('a b+&=@/%', 'a%20b%2b%26%3d%40%2f%25'),
                                ('a\\b', 'a%5cb'), ('a\nb\n', 'a%00b%00'),
                                ('\r\t', '%00%00'), ('"\'$`', '%22%27%24%60')):
            with self.subTest(expected=expected):
                result = subprocess.run([shutil.which('sh')], text=True, capture_output=True,
                    env=dict(os.environ, INPUT=value, EXPECTED=expected),
                    input=encoder + '\nurlencode encoded "$INPUT"\n[ "$encoded" = "$EXPECTED" ]\n')
                self.assertEqual(result.returncode, 0, 'literal encoding or output-variable assignment failed')

    def test_public_upstream_reproduces_argv_and_console_exposure(self):
        # A quote-free synthetic token allows the vulnerable eval to reach curl.
        token = 'SYNTHETIC_PUBLIC_BASELINE'
        output, files = self.execute(self.entries(), token=token)
        self.assertIn(token, files['argv'])
        self.assertIn(token, files['awk-argv'])
        self.assertIn(token, output)

    def test_authentication_uses_stdin_without_secret_argv_or_diagnostics(self):
        entries = self.module().protect_root(self.entries())
        for username in ('Bearer', 'test@example.invalid'):
            with self.subTest(username=username):
                output, files = self.execute(entries, username=username)
                self.assertIn('RESULT=0', output)
                self.assertNotIn(TOKEN, files['argv'])
                self.assertNotIn(TOKEN, output + files.get('log', ''))
                self.assertIn(TOKEN, files['headers'])
                self.assertEqual(files['argv'].splitlines()[0], '-q')
                self.assertIn('--header\n@-', files['argv'])
                self.assertEqual(files['argv'].count('--request'), 3)
                self.assertIn('PATCH', files['argv'])
                self.assertFalse(any('auth' in name or 'config' in name for name in files))

    def test_error_diagnostics_redact_before_console_and_log(self):
        entries = self.module().protect_root(self.entries())
        output, files = self.execute(entries, error=True)
        self.assertIn('RESULT=1', output)
        self.assertNotIn(TOKEN, output + files['log'] + files['argv'])
        self.assertIn('***PW***', output)

    def test_registered_ip_mode_remains_functional(self):
        output, files = self.execute(self.module().protect_root(self.entries()), registered=True)
        self.assertIn('RESULT=0 REGISTERED=198.51.100.2', output)
        self.assertNotIn('PATCH', files['argv'])

    def test_header_newline_rejected_before_curl(self):
        output, files = self.execute(self.module().protect_root(self.entries()), token='synthetic\nInjected: value')
        self.assertIn('RESULT=127', output)
        self.assertNotIn('argv', files)

    def test_generic_credential_url_rejected_before_wget(self):
        source = self.module().protect_root(self.entries())[FUNCTIONS].data.decode()
        script = function(source, 'do_transfer')
        result = subprocess.run([shutil.which('sh')], text=True, capture_output=True, input=script + '''
write_log() { printf '%s\\n' "$2"; }
password=SYNTHETIC; URL_PASS=SYNTHETIC
WGET_SSL=1; USE_CURL=0; WGET='echo UNSAFE_WGET'
do_transfer 'https://example.invalid/?key=SYNTHETIC'
printf 'RESULT=%s\\n' "$?"
''')
        self.assertIn('RESULT=127', result.stdout)
        self.assertNotIn('UNSAFE_WGET', result.stdout)
        self.assertNotIn('SYNTHETIC', result.stdout + result.stderr)

    def test_patch_is_idempotent_preserves_metadata_and_unrelated_entries(self):
        entries = self.entries()
        entries['etc/config/ddns'] = Entry(stat.S_IFREG | 0o600, b"option enabled '0'\n", 123, 456)
        entries['sbin/tool'] = Entry(stat.S_IFREG | 0o755, b'tool')
        result = self.module().protect_root(entries)
        self.assertEqual(result, self.module().protect_root(result))
        self.assertEqual(result['etc/config/ddns'], entries['etc/config/ddns'])
        self.assertIs(result['sbin/tool'], entries['sbin/tool'])
        for name in (CF, FUNCTIONS):
            self.assertEqual((result[name].mode, result[name].uid, result[name].gid),
                             (entries[name].mode, 12, 34))
        self.assertEqual(self.module().protect_root({}), {})

    def test_unknown_or_partial_scripts_fail_closed(self):
        for name in (CF, FUNCTIONS):
            entries = self.entries()
            entries[name] = Entry(stat.S_IFREG | 0o755, entries[name].data + b'\n# modified\n')
            with self.assertRaisesRegex(ValueError, 'DDNS|ddns'):
                self.module().protect_root(entries)
        with self.assertRaises(ValueError):
            self.module().protect_root({CF: self.entries()[CF]})

    def test_patched_shell_syntax(self):
        for entry in self.module().protect_root(self.entries()).values():
            result = subprocess.run([shutil.which('sh'), '-n'], input=entry.data, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
