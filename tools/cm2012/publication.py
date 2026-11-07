"""检查 Git 公开内容；结果只包含规则、位置，不回显凭据。"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import urllib.parse
import zipfile


PATTERNS = {
    'private-key': rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----',
    'github-token': rb'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b',
    'tailscale-key': rb'\btskey-(?:auth|api)-[A-Za-z0-9-]{10,}',
    'password-hash': (rb'\$(?:6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}'
                      rb'|5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}'
                      rb'|1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}'
                      rb'|2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'
                      rb'|y\$[^\s:;<>"\x27`]{25,})'),
}
URLS = re.compile(rb'https?://[^\s<>"\x27`\\]+', re.I)
SUBSCRIPTION_FIELDS = re.compile(
    rb'(?:\b(?:subscription_url|subscribe_url|sub_url)["\x27]?\s*[:=]\s*'
    rb'|\boption[ \t]+(?:subscription_url|subscribe_url|sub_url)[ \t]+)'
    rb'["\x27](https?://[^\s<>"\x27`\\]+)', re.I)
PRIVATE_PARTS = {'local', 'output', 'backup', 'downloads', '.ssh', '.aws', '.env'}
PRIVATE_SUFFIXES = {'.log', '.pcap', '.pcapng', '.img', '.bin', '.p12', '.pfx', '.pem', '.key'}
MAX_PUBLIC_FILE = 16 * 1024 * 1024
# Independently reviewed public index identities from provenance.json. Candidate
# lock/provenance files cannot grant new exceptions or replace these identities.
APPROVED_SNAPSHOTS = {
    'configs/resource-snapshots/base-20261011/packages.adb': (
        110335, '382d024b8ed979e0349eaa5f6a2bfbbfe885f49ee9af786a37ee0dc64e7158b9'),
    'configs/resource-snapshots/base/packages.adb': (
        110343, '0fd570f89b95b92585ec55024b25f01430cbe8d6962a9291a6d8291691e72e6f'),
    'configs/resource-snapshots/packages/packages.adb': (
        741652, '1c8e3346c2ba22e2005d8265e8ed0ba1b3ceb4c1f67c71daa9b9391348764e0a'),
    'configs/resource-snapshots/luci/packages.adb': (
        382757, 'a8d63ad5f5c38e096c3c546c0e91c779935f63e8a7bd256e804d89cd2a08829b'),
    'configs/resource-snapshots/target/packages.adb': (
        13929, 'e45dc3f69a3cc346a6bd1c03644c13f47cdd3408fe7247787ec7d52fe02a1aff'),
}


def _private_path(name):
    path = PurePosixPath(name)
    return (any(p in PRIVATE_PARTS or p.startswith('.env.') for p in path.parts) or
            path.suffix.lower() in PRIVATE_SUFFIXES or
            path.name in {'shadow', 'id_rsa', 'id_ed25519', 'authorized_keys', 'config.json'} or
            name.endswith(('.tar.gz', '.tgz', '.cpio.gz', '.zip', '.tar')))


def _snapshot_locks(files):
    """Candidate metadata must agree with independent public index identities."""
    try:
        locks = json.loads(files.get('resources.lock.json', b'{}'))
        result = {}
        for row in locks.get('resources', []):
            name = row.get('bundled_path', '')
            if name in APPROVED_SNAPSHOTS:
                if name in result:
                    return {}
                result[name] = (row['size'], row['sha256'])
        return {name: identity for name, identity in result.items()
                if identity == APPROVED_SNAPSHOTS[name]}
    except (ValueError, TypeError, KeyError, AttributeError):
        return {}


def scan_files(files, *, known_values=()):
    """Return redacted findings for {relative POSIX path: bytes}."""
    findings, snapshots = [], _snapshot_locks(files)
    known = [v.encode() if isinstance(v, str) else v for v in known_values if len(v) >= 8]

    def add(name, rule, data=b'', offset=0):
        findings.append({'file': name, 'line': data.count(b'\n', 0, offset) + 1, 'rule': rule})

    for name, data in sorted(files.items()):
        if _private_path(name):
            add(name, 'private-artifact')
        if len(data) > MAX_PUBLIC_FILE:
            add(name, 'public-file-too-large')
            continue
        for value in known:
            start = data.find(value)
            if start >= 0:
                add(name, 'known-secret', data, start)
        if name in snapshots:
            size, digest = snapshots[name]
            if len(data) == size and hashlib.sha256(data).hexdigest() == digest:
                continue
        try:
            data.decode('utf-8')
            binary = b'\0' in data
        except UnicodeDecodeError:
            binary = True
        if binary:
            add(name, 'binary-not-allowed')
            continue
        for rule, pattern in PATTERNS.items():
            for match in re.finditer(pattern, data):
                add(name, rule, data, match.start())
        subscription_starts = {m.start(1) for m in SUBSCRIPTION_FIELDS.finditer(data)}
        for match in URLS.finditer(data):
            try:
                url = urllib.parse.urlsplit(match.group().decode())
                host = url.hostname or ''
                query = urllib.parse.parse_qs(url.query)
            except ValueError:
                continue
            # Reserved example destinations exempt only this URL rule, never
            # known-secret or key/hash rules, in every directory equally.
            if host.endswith(('.invalid', '.test', '.example')) or host in {'example.com', 'example.net', 'example.org'}:
                continue
            if url.username is not None or url.password is not None:
                add(name, 'url-credential', data, match.start())
            elif match.start() in subscription_starts:
                add(name, 'subscription-url', data, match.start())
            elif any(re.fullmatch(r'token|key|auth|password|secret|access_token', key, re.I)
                     and any(len(value) >= 8 for value in values) for key, values in query.items()):
                add(name, 'subscription-token', data, match.start())
    return findings


def _git(root, *args, data=None):
    result = subprocess.run(['git', '-C', str(root), *args], input=data, capture_output=True)
    if result.returncode:
        raise ValueError('无法读取待公开 Git 内容；请检查引用、暂存冲突和仓库状态')
    return result.stdout


def git_files(root, *, ref=None, index=False, working=False):
    root = Path(root).resolve()
    if sum((ref is not None, index, working)) != 1:
        raise ValueError('必须明确选择一个 Git 引用、暂存区或工作候选范围')
    if working:
        result = {}
        for raw in _git(root, 'ls-files', '-co', '--exclude-standard', '-z').split(b'\0'):
            if not raw:
                continue
            name = raw.decode('utf-8')
            path = root / name
            if path.is_symlink():
                result[name] = str(path.readlink()).encode()
            elif path.is_file() and path.resolve().is_relative_to(root):
                result[name] = path.read_bytes()
        return result
    if ref is not None:
        if not ref or ref.startswith('-') or '\0' in ref:
            raise ValueError('Git 引用无效')
        rows = _git(root, 'ls-tree', '-rz', '--full-tree', ref).split(b'\0')
    else:
        rows = _git(root, 'ls-files', '--stage', '-z').split(b'\0')
    objects = []
    for row in rows:
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, kind_or_oid, oid_or_stage = metadata.split()
        if ref is not None:
            if kind_or_oid != b'blob':
                raise ValueError('公开树包含未审核的子模块')
            oid = oid_or_stage
        else:
            if oid_or_stage != b'0' or mode == b'160000':
                raise ValueError('暂存区包含冲突或未审核的子模块')
            oid = kind_or_oid
        objects.append((oid, name.decode('utf-8')))
    output = _git(root, 'cat-file', '--batch', data=b''.join(oid + b'\n' for oid, _ in objects))
    result, offset = {}, 0
    for oid, name in objects:
        end = output.index(b'\n', offset)
        header = output[offset:end].split()
        if len(header) != 3 or header[0] != oid or header[1] != b'blob':
            raise ValueError('Git 对象格式错误')
        size = int(header[2])
        offset = end + 1
        result[name] = output[offset:offset + size]
        offset += size + 1
    return result


def archive_files(path):
    """Read the source package without extracting it to the filesystem."""
    files = {}

    def add(name, data):
        p = PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts or '\\' in name or name in files:
            raise ValueError('源码包包含重复或越界路径')
        files[name] = data

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for row in archive.infolist():
                if row.is_dir():
                    continue
                if row.file_size > MAX_PUBLIC_FILE:
                    raise ValueError('源码包单文件超限')
                add(row.filename, archive.read(row))
    else:
        with tarfile.open(path) as archive:
            for row in archive:
                if row.isdir():
                    continue
                if not row.isreg() or row.size > MAX_PUBLIC_FILE:
                    raise ValueError('源码包包含非普通文件或超限文件')
                add(row.name, archive.extractfile(row).read())
    # git archive commonly adds one directory prefix.
    if files and 'resources.lock.json' not in files:
        roots = {PurePosixPath(n).parts[0] for n in files}
        if len(roots) == 1 and all('/' in n for n in files):
            files = {n.split('/', 1)[1]: data for n, data in files.items()}
    return files


def known_config_values(path):
    values = []

    def visit(obj, key=''):
        if isinstance(obj, dict):
            for name, value in obj.items():
                visit(value, name)
        elif isinstance(obj, list):
            for value in obj:
                visit(value, key)
        elif isinstance(obj, str) and re.search(r'password|passwd|secret|token|root_hash|subscription|authkey', key, re.I):
            values.append(obj)

    visit(json.loads(Path(path).read_text(encoding='utf-8')))
    return values


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('--ref')
    scope.add_argument('--index', action='store_true')
    scope.add_argument('--working', action='store_true')
    scope.add_argument('--archive', type=Path)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--known-config', type=Path, help='仅本机读取实际秘密进行比对；不输出值')
    args = parser.parse_args(argv)
    try:
        files = archive_files(args.archive) if args.archive else git_files(
            args.root, ref=args.ref, index=args.index, working=args.working)
        known = known_config_values(args.known_config) if args.known_config else ()
        findings = scan_files(files, known_values=known)
        for finding in findings:
            print(json.dumps(finding, ensure_ascii=False))
        if findings:
            print('公开检查未通过：' + str(len(findings)) + ' 项；匹配内容已隐藏', file=sys.stderr)
            return 1
        print('PUBLICATION_PRIVACY_OK files=' + str(len(files)))
        return 0
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile):
        print('公开检查失败；请检查输入类型和格式，未回显输入内容', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
