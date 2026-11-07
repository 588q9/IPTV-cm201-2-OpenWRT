"""从明确的 Git 提交生成经过公开检查的确定性源码附件。"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cm2012 import publication

PROJECT = 'cm201-2-system'
RC_TAG = re.compile(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-rc\.[1-9][0-9]*')


def _git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True)
    if result.returncode:
        raise ValueError('无法读取源码提交或确认输出目录已忽略')
    return result.stdout


def build_release(root, ref, tag, output):
    """Return archive/manifest/checksums paths; never package working-tree bytes."""
    if not isinstance(tag, str) or RC_TAG.fullmatch(tag) is None:
        raise ValueError('源码预发布 tag 必须是 v主.次.修订-rc.正整数')
    if (not isinstance(ref, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', ref) is None
            or '..' in ref or '//' in ref or ref.endswith('/')):
        raise ValueError('必须提供安全的明确 Git 引用')
    root, output = Path(root).resolve(), Path(output).resolve()
    if output.is_relative_to(root):
        local = (root / 'local').resolve()
        if not local.is_relative_to(root) or output == local or not output.is_relative_to(local):
            raise ValueError('仓库内源码附件只能写入已忽略的 local/ 子目录')
        _git(root, 'check-ignore', '--quiet', '--no-index', str(output.relative_to(root)))
    else:
        runner = os.environ.get('RUNNER_TEMP')
        if not runner or output == Path(runner).resolve() or not output.is_relative_to(Path(runner).resolve()):
            raise ValueError('仓库外源码附件只能写入 RUNNER_TEMP 子目录')
    if output.exists():
        raise FileExistsError('源码附件输出已存在；拒绝覆盖')
    commit = _git(root, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}').decode().strip()
    modes = {}
    for row in _git(root, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if not row:
            continue
        metadata, raw_name = row.split(b'\t', 1)
        mode, kind, _oid = metadata.split()
        name = raw_name.decode('utf-8')
        path = PurePosixPath(name)
        if mode not in (b'100644', b'100755') or kind != b'blob':
            raise ValueError('源码提交包含非普通文件')
        if path.is_absolute() or '..' in path.parts or '\\' in name:
            raise ValueError('源码提交包含不安全路径')
        modes[name] = mode.decode('ascii')
    files = publication.git_files(root, ref=commit)
    if not files or publication.scan_files(files):
        raise ValueError('源码提交未通过公开检查；未生成附件')
    manifest = {'format': 1, 'project': PROJECT, 'commit': commit, 'tag': tag,
                'archive': 'source.tar.gz', 'files': [
                    {'path': name, 'mode': modes[name], 'size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest()}
                    for name, data in sorted(files.items())]}
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='source-release-', dir=output.parent) as temporary:
        archive_path = Path(temporary) / 'source.tar.gz'
        with archive_path.open('xb') as stream:
            with gzip.GzipFile(filename='', fileobj=stream, mode='wb', mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.GNU_FORMAT) as archive:
                    for name, data in sorted(files.items()):
                        member = tarfile.TarInfo(PROJECT + '-' + tag + '/' + name)
                        member.mode, member.size = int(modes[name], 8) & 0o777, len(data)
                        member.uid, member.gid, member.mtime = 0, 0, 0
                        member.uname, member.gname = '', ''
                        archive.addfile(member, io.BytesIO(data))
        archived_files = publication.archive_files(archive_path)
        if publication.scan_files(archived_files) or archived_files != files:
            raise ValueError('序列化源码包未通过公开或内容一致性检查')
        artifacts = {'source.tar.gz': archive_path.read_bytes(), 'manifest.json': manifest_bytes}
        artifacts['SHA256SUMS'] = ''.join(
            hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
            for name, data in artifacts.items()).encode('ascii')
        for name, data in artifacts.items():
            if name == archive_path.name:
                continue
            with (Path(temporary) / name).open('xb') as stream:
                stream.write(data)
        if output.exists():
            raise FileExistsError('源码附件输出已存在；拒绝覆盖')
        Path(temporary).rename(output)
    return {'archive': output / 'source.tar.gz', 'manifest': output / 'manifest.json',
            'checksums': output / 'SHA256SUMS'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--ref', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        paths = build_release(args.root, args.ref, args.tag, args.output)
    except (OSError, ValueError, tarfile.TarError):
        print('源码附件生成失败；请检查引用、tag、公开检查和输出路径，未回显内容', file=sys.stderr)
        return 1
    for path in paths.values():
        print(path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
