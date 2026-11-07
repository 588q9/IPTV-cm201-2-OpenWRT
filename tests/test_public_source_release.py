"""源码附件只读取提交树，并保留可核对的内容、权限和摘要。"""
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
TAG = 'v0.2.0-rc.1'
PREFIX = 'cm201-2-system-' + TAG + '/'


class SourceReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'repo'
        self.root.mkdir()
        self.git('init', '--quiet')
        self.git('config', 'core.autocrlf', 'false')
        (self.root / '.gitignore').write_bytes(b'local/\n')
        (self.root / 'README.md').write_bytes(b'public source\n')
        (self.root / 'run.sh').write_bytes(b'#!/bin/sh\nexit 0\n')
        self.commit()
        self.git('update-index', '--chmod=+x', 'run.sh')
        self.git('-c', 'user.name=Source test', '-c', 'user.email=test@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'executable')
        self.commit_id = self.git('rev-parse', 'HEAD').decode().strip()

    def git(self, *args, data=None):
        return subprocess.run(['git', '-C', str(self.root), *args], input=data,
                              capture_output=True, check=True).stdout

    def commit(self):
        self.git('add', '--all')
        self.git('-c', 'user.name=Source test', '-c', 'user.email=test@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'fixture')

    def module(self):
        try:
            return importlib.import_module('cm2012.source_release')
        except ModuleNotFoundError:
            self.fail('提交树源码发布接口尚未实现')

    def output(self, name='release'):
        return self.root / 'local' / name

    def test_commit_bytes_exclude_dirty_untracked_and_ignored_files_and_keep_modes(self):
        (self.root / 'README.md').write_bytes(b'dirty replacement\n')
        (self.root / 'untracked.txt').write_bytes(b'untracked\n')
        self.output().parent.mkdir()
        (self.output().parent / 'private.txt').write_bytes(b'private\n')
        paths = self.module().build_release(self.root, self.commit_id, TAG, self.output())
        with tarfile.open(paths['archive']) as archive:
            self.assertEqual(archive.getnames(),
                             [PREFIX + '.gitignore', PREFIX + 'README.md', PREFIX + 'run.sh'])
            self.assertEqual(archive.extractfile(PREFIX + 'README.md').read(), b'public source\n')
            self.assertEqual(archive.getmember(PREFIX + 'run.sh').mode, 0o755)
            self.assertEqual(archive.getmember(PREFIX + 'README.md').mode, 0o644)
            for member in archive:
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual((member.uname, member.gname), ('', ''))

    def test_repeated_builds_have_identical_archive_manifest_and_matching_sha256(self):
        module = self.module()
        first = module.build_release(self.root, self.commit_id, TAG, self.output('one'))
        second = module.build_release(self.root, self.commit_id, TAG, self.output('two'))
        for key in ('archive', 'manifest', 'checksums'):
            self.assertEqual(first[key].read_bytes(), second[key].read_bytes())
        manifest = json.loads(first['manifest'].read_bytes())
        self.assertEqual((manifest['commit'], manifest['tag']), (self.commit_id, TAG))
        self.assertEqual(manifest['files'], [
            {'path': '.gitignore', 'mode': '100644', 'size': 7,
             'sha256': hashlib.sha256(b'local/\n').hexdigest()},
            {'path': 'README.md', 'mode': '100644', 'size': 14,
             'sha256': hashlib.sha256(b'public source\n').hexdigest()},
            {'path': 'run.sh', 'mode': '100755', 'size': 17,
             'sha256': hashlib.sha256(b'#!/bin/sh\nexit 0\n').hexdigest()},
        ])
        expected = ''.join(hashlib.sha256(first[key].read_bytes()).hexdigest() +
                           '  ' + name + '\n' for key, name in
                           [('archive', 'source.tar.gz'), ('manifest', 'manifest.json')])
        self.assertEqual(first['checksums'].read_text(encoding='ascii'), expected)
        self.assertEqual({p.name for p in self.output('one').iterdir()},
                         {'source.tar.gz', 'manifest.json', 'SHA256SUMS'})

    def test_private_paths_secrets_and_unapproved_binary_fail_before_creating_output(self):
        module = self.module()
        for name, data in [('backup/config.txt', b'private backup\n'),
                           ('leak.txt', ('ghp_' + 'A' * 36).encode()),
                           ('unknown.adb', b'ADB\x00not-reviewed')]:
            with self.subTest(name=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                self.commit()
                with self.assertRaises(ValueError):
                    module.build_release(self.root, 'HEAD', TAG, self.output())
                self.assertFalse(self.output().exists())
                path.unlink()
                self.commit()

    def test_invalid_tags_refs_and_public_output_paths_are_rejected_without_files(self):
        module = self.module()
        for ref, tag in [('--help', TAG), ('HEAD:README.md', TAG), ('HEAD\n', TAG),
                         ('missing-commit', TAG), ('HEAD', '../../bad'),
                         ('HEAD', 'v0.2.0'), ('HEAD', 'v0.2.0-rc.0'),
                         ('HEAD', 'v0.2.0-rc.1\n')]:
            with self.subTest(ref=ref, tag=tag):
                with self.assertRaises(ValueError):
                    module.build_release(self.root, ref, tag, self.output())
                self.assertFalse(self.output().exists())
        with self.assertRaises(ValueError):
            module.build_release(self.root, 'HEAD', TAG, self.root / 'public-release')
        self.assertFalse((self.root / 'public-release').exists())

    def test_symlink_and_gitlink_tree_entries_are_rejected(self):
        module = self.module()
        oid = self.git('hash-object', '-w', '--stdin', data=b'README.md').decode().strip()
        for mode, target in [('120000', oid), ('160000', self.commit_id)]:
            with self.subTest(mode=mode):
                self.git('update-index', '--add', '--cacheinfo', mode, target, 'link')
                self.git('-c', 'user.name=Source test', '-c', 'user.email=test@example.invalid',
                         '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'nonregular')
                with self.assertRaises(ValueError):
                    module.build_release(self.root, 'HEAD', TAG, self.output())
                self.assertFalse(self.output().exists())
                self.git('update-index', '--force-remove', 'link')

    def test_existing_output_is_never_overwritten(self):
        self.output().mkdir(parents=True)
        sentinel = self.output() / 'source.tar.gz'
        sentinel.write_bytes(b'existing release')
        with self.assertRaises(FileExistsError):
            self.module().build_release(self.root, 'HEAD', TAG, self.output())
        self.assertEqual(sentinel.read_bytes(), b'existing release')
        self.assertEqual([p.name for p in self.output().iterdir()], ['source.tar.gz'])

    def test_reviewed_snapshot_bytes_pass_both_gates_but_changed_snapshot_fails(self):
        lock = (ROOT / 'resources.lock.json').read_bytes()
        (self.root / 'resources.lock.json').write_bytes(lock)
        names = [row['bundled_path'] for row in json.loads(lock)['resources']
                 if row.get('bundled_path')]
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        self.commit()
        module = self.module()
        paths = module.build_release(self.root, 'HEAD', TAG, self.output())
        from cm2012 import publication
        self.assertEqual(publication.scan_files(publication.archive_files(paths['archive'])), [])
        (self.root / names[0]).write_bytes(b'ADB\x00changed')
        self.commit()
        with self.assertRaises(ValueError):
            module.build_release(self.root, 'HEAD', TAG, self.output('changed'))
        self.assertFalse(self.output('changed').exists())

    def test_serialized_archive_is_scanned_before_publishing_output(self):
        module = self.module()
        original = tarfile.TarFile.addfile

        def corrupt_archive(archive, member, fileobj=None):
            if member.name == PREFIX + 'README.md':
                payload = ('ghp_' + 'B' * 36).encode()
                member.size = len(payload)
                fileobj = io.BytesIO(payload)
            return original(archive, member, fileobj)

        with patch.object(tarfile.TarFile, 'addfile', corrupt_archive):
            with self.assertRaises(ValueError):
                module.build_release(self.root, 'HEAD', TAG, self.output())
        self.assertFalse(self.output().exists())

    def test_artifact_write_failure_leaves_no_output_and_can_be_retried(self):
        module = self.module()
        original = Path.open

        def fail_manifest(path, *args, **kwargs):
            if path.name == 'manifest.json' and args and args[0] == 'xb':
                raise OSError('injected artifact write failure')
            return original(path, *args, **kwargs)

        with patch.object(Path, 'open', fail_manifest):
            with self.assertRaises(OSError):
                module.build_release(self.root, 'HEAD', TAG, self.output())
        self.assertFalse(self.output().exists())
        paths = module.build_release(self.root, 'HEAD', TAG, self.output())
        self.assertEqual({p.name for p in self.output().iterdir()},
                         {'source.tar.gz', 'manifest.json', 'SHA256SUMS'})
        self.assertTrue(all(path.is_file() for path in paths.values()))

    def test_publish_shell_refuses_tag_races_and_checks_created_tag_before_release(self):
        git_path = Path(shutil.which('git'))
        git_bash = git_path.with_name('bash.exe')
        bash = str(git_bash) if git_bash.is_file() else shutil.which('bash')
        if not bash or not Path(bash).is_file():
            self.skipTest('Git Bash or Bash is required for the workflow smoke')
        workflow = (ROOT / '.github/workflows/source-release.yml').read_text(encoding='utf-8')
        script = textwrap.dedent(workflow.rsplit('        run: |\n', 1)[1])
        fake_gh = r'''
gh() {
  printf '%s\n' "$*" >> "$CALL_LOG"
  if [ "$1 $2" = "release view" ]; then
    [ "$SCENARIO" = existing-release ]
  elif [ "$1" = api ] && [ "$2" = --method ]; then
    [ "$3" = POST ] && [ "$4" = "repos/$GITHUB_REPOSITORY/git/refs" ] &&
      [ "$5" = -f ] && [ "$6" = "ref=refs/tags/$RELEASE_TAG" ] &&
      [ "$7" = -f ] && [ "$8" = "sha=$GITHUB_SHA" ] || return 2
    if [ "$SCENARIO" = raced-tag ]; then
      printf '%s' other-commit > "$TAG_STATE"
      return 1
    fi
    printf '%s' "$GITHUB_SHA" > "$TAG_STATE"
  elif [ "$1" = api ]; then
    if [ "$SCENARIO" = existing-tag ]; then
      printf '%s' other-commit
    elif [ -f "$TAG_STATE" ]; then
      [ "$3" = --jq ] && [ "$4" = '.object.sha' ] || return 2
      if [ "$SCENARIO" = changed-readback ]; then
        printf '%s' other-commit
      else
        cat "$TAG_STATE"
      fi
    else
      return 1
    fi
  elif [ "$1 $2" = "release create" ]; then
    if [ "$SCENARIO" = raced-tag ] || [ "$SCENARIO" = changed-readback ]; then
      printf '%s' other-commit > "$TAG_STATE"
    elif [ ! -f "$TAG_STATE" ]; then
      printf '%s' "$GITHUB_SHA" > "$TAG_STATE"
    fi
    cat "$TAG_STATE" > "$RELEASE_STATE"
  else
    return 2
  fi
}
'''
        for scenario, succeeds, creates_release in [
                ('fresh', True, True), ('raced-tag', False, False),
                ('changed-readback', False, False), ('existing-tag', False, False),
                ('existing-release', True, False)]:
            with self.subTest(scenario=scenario):
                work = self.root / scenario
                work.mkdir()
                env = {**os.environ, 'SCENARIO': scenario, 'GITHUB_SHA': self.commit_id,
                       'GITHUB_REPOSITORY': 'example/source', 'RELEASE_TAG': TAG,
                       'RUNNER_TEMP': work.as_posix(), 'CALL_LOG': (work / 'calls').as_posix(),
                       'TAG_STATE': (work / 'tag').as_posix(),
                       'RELEASE_STATE': (work / 'release').as_posix()}
                result = subprocess.run([bash, '--noprofile', '--norc', '-c', fake_gh + script],
                                        env=env, capture_output=True)
                self.assertEqual(result.returncode == 0, succeeds, result.stderr.decode('utf-8'))
                self.assertEqual((work / 'release').exists(), creates_release)
                if creates_release:
                    self.assertEqual((work / 'release').read_text(), self.commit_id)
                    self.assertIn('--verify-tag', (work / 'calls').read_text())
                if scenario == 'existing-release':
                    self.assertEqual(len((work / 'calls').read_text().splitlines()), 1)


if __name__ == '__main__':
    unittest.main()
