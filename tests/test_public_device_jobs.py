"""Private job commands execute in a persistent shell without altering its umask."""
import importlib
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class Commands:
    def __init__(self):
        self.commands = []

    def command(self, command):
        self.commands.append(command)
        return ''


class DeviceJobTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('cm2012.device_jobs')
        except ModuleNotFoundError:
            self.fail('private device job helper missing')

    def test_rejects_unsafe_paths_before_device_access(self):
        for path in ('/tmp', '/tmp/cm2012-build-a/b', '/tmp/cm2012-build-../x',
                     '/tmp/cm2012-build-A', '/tmp/cm2012-build-x;id', '/etc/shadow', ''):
            link = Commands()
            with self.assertRaises(ValueError):
                self.module().create_private_job(link, path)
            self.assertEqual(link.commands, [])

    def execute(self, *, identity='0', exists=False, reported_mode='700'):
        link = Commands()
        self.module().create_private_job(link, '/tmp/cm2012-build-test123')
        self.assertEqual(len(link.commands), 1)
        self.assertLess(len(link.commands[0]), 450, 'serial console command budget')
        # Run in one shell: mutation outside the command would persist until the final umask.
        prelude = '''
umask 022
id() { printf '%s\\n' "$IDENTITY"; }
mkdir() { printf 'MKDIR %s\\n' "$*"; [ "$EXISTS" != 1 ]; }
stat() { printf '%s\\n' "$MODE"; }
'''
        import os
        result = subprocess.run([shutil.which('sh')], text=True, capture_output=True,
                                env=dict(os.environ, IDENTITY=identity, EXISTS=str(int(exists)), MODE=reported_mode),
                                input=prelude + link.commands[0] + '\nresult=$?\nprintf "RESULT=%s UMASK=%s\\n" "$result" "$(umask)"\n')
        return result.stdout

    def test_private_mode_and_umask_are_local(self):
        output = self.execute()
        self.assertIn('RESULT=0 UMASK=0022', output)
        self.assertIn('MKDIR -m 700 /tmp/cm2012-build-test123', output)

    def test_root_preflight_precedes_creation(self):
        output = self.execute(identity='1000')
        self.assertIn('RESULT=1 UMASK=0022', output)
        self.assertNotIn('MKDIR', output)

    def test_never_reuses_existing_directory(self):
        self.assertIn('RESULT=1 UMASK=0022', self.execute(exists=True))

    def test_refuses_directory_with_wrong_mode(self):
        self.assertIn('RESULT=1 UMASK=0022', self.execute(reported_mode='755'))


if __name__ == '__main__':
    unittest.main()
