"""Bounded incremental bundle validation; the repository, never the bundle, supplies code.

The public JSON declaration is also loaded by the trusted on-device updater.
Manifest hashes establish consistency, not publisher authentication.
"""
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

from .archives import Entry, tar_bytes

DEVICE = Path(__file__).resolve().parent / 'device'
POLICY = json.loads((DEVICE / 'update-policy.json').read_text(encoding='utf-8'))
GEOIP_LINK = 'etc/cm2012-proxy/Country.mmdb'
GEOIP_TARGET = POLICY['fixed_links'][GEOIP_LINK]


def canonical_path(name):
    return (isinstance(name, str) and 0 < len(name) <= POLICY['limits']['path_bytes']
            and bool(re.fullmatch(r'[A-Za-z0-9_+./@~-]+', name))
            and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')))


def under(name, roots):
    return any(name == p.rstrip('/') or name.startswith(p) for p in roots)


def allowed_path(name):
    return (canonical_path(name) and not under(name, POLICY['forbidden_roots'])
            and (any(name.startswith(root) for root in POLICY['allowed_roots']) or name in POLICY['allowed_files']))


def link_target(name, target):
    exception = any(target == '/' + path or
                    (name.rsplit('/', 1)[0] == path.rsplit('/', 1)[0] and target == path.rsplit('/', 1)[1])
                    for path in POLICY['public_link_targets'])
    if (not isinstance(target, str) or not 0 < len(target) <= POLICY['limits']['path_bytes']
            or (not exception and not re.fullmatch(r'[A-Za-z0-9_+./@~-]+', target))):
        raise ValueError('更新链接非法')
    parts = [] if target.startswith('/') else name.split('/')[:-1]
    for part in target.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            if not parts:
                raise ValueError('更新链接越界')
            parts.pop()
        else:
            parts.append(part)
    result = '/'.join(parts)
    if ((not allowed_path(result) and result not in POLICY['public_link_targets']) or under(result, POLICY['web_roots'])
            or not (under(result, POLICY['link_roots']) or result in POLICY['link_files'])):
        raise ValueError('更新链接目标不公开')
    return result


def validate_record(name, record, *, before=False):
    if not isinstance(record, dict) or type(record.get('mode')) is not int or not 0 <= record['mode'] <= 0o777:
        raise ValueError('更新类型或权限错误')
    kind = record.get('kind')
    if kind == 'file':
        if set(record) != {'kind', 'mode', 'sha256'} or not isinstance(record['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', record['sha256']):
            raise ValueError('更新摘要非法')
    elif kind == 'link':
        if set(record) != {'kind', 'mode', 'target'} or record['mode'] != 0o777:
            raise ValueError('更新链接非法')
        if (under(name, POLICY['web_roots']) or
                not (under(name, POLICY['link_roots']) or name in POLICY['link_files'] or name in POLICY['fixed_links'])):
            raise ValueError('Web 更新不允许链接')
        if name in POLICY['fixed_links'] and record['target'] != POLICY['fixed_links'][name]:
            raise ValueError('地理数据库链接非法')
        link_target(name, record['target'])
    else:
        raise ValueError('更新记录类型非法')
    if name in POLICY['fixed_links'] and not before and (kind != 'link' or record['target'] != POLICY['fixed_links'][name]):
        raise ValueError('地理数据库链接非法')


def allowed_record(name, record):
    try:
        validate_record(name, record)
        return True
    except ValueError:
        return False


def fingerprint(entry):
    if entry is None:
        return None
    result = {'mode': stat.S_IMODE(entry.mode)}
    if stat.S_ISLNK(entry.mode):
        result.update(kind='link', target=entry.data.decode('utf-8'))
    elif stat.S_ISREG(entry.mode):
        result.update(kind='file', sha256=hashlib.sha256(entry.data).hexdigest())
    else:
        raise ValueError('增量包只接受普通文件或符号链接')
    return result


def validate_links(files, phase):
    records = {name: row[phase] for name, row in files.items()}
    for name, record in records.items():
        if not record or record['kind'] != 'link':
            continue
        seen = {name}
        for _ in range(POLICY['limits']['link_hops']):
            walked = [] if record['target'].startswith('/') else name.split('/')[:-1]
            for part in record['target'].split('/')[:-1]:
                if part in ('', '.'):
                    continue
                if part == '..':
                    if walked:
                        walked.pop()
                else:
                    walked.append(part)
                if records.get('/'.join(walked)) is not None:
                    raise ValueError('更新链接经过非目录')
            target = link_target(name, record['target'])
            # Refuse any manifest link/file used as an ancestor directory.
            if any(str(p) in records and records[str(p)] is not None for p in PurePosixPath(target).parents if str(p) != '.'):
                raise ValueError('更新链接经过非目录')
            if target in seen:
                raise ValueError('更新链接循环')
            seen.add(target)
            record = records.get(target)
            if not record or record['kind'] != 'link':
                break  # The device validates this endpoint and its actual parents.
            name = target
        else:
            raise ValueError('更新链接链过长')


def validate_manifest(manifest):
    if (not isinstance(manifest, dict) or set(manifest) != {'format', 'files'}
            or type(manifest['format']) is not int or manifest['format'] != 1
            or not isinstance(manifest['files'], dict) or not manifest['files']
            or len(manifest['files']) > POLICY['limits']['files']):
        raise ValueError('网络增量包清单无效')
    files = manifest['files']
    for name, row in files.items():
        if not allowed_path(name) or not isinstance(row, dict) or set(row) != {'before', 'after'}:
            raise ValueError('更新路径或记录越界')
        if under(name, POLICY['preserve_existing_roots']) and row['before'] is not None:
            raise ValueError('增量更新必须保留现有配置')
        if row['before'] is not None:
            validate_record(name, row['before'], before=True)
        validate_record(name, row['after'])
        if any(str(p) in files for p in PurePosixPath(name).parents if str(p) != '.'):
            raise ValueError('更新文件位于非目录之下')
    for phase in ('before', 'after'):
        validate_links(files, phase)
    return manifest


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('更新清单包含重复字段')
        result[key] = value
    return result


def canonical_bundle(data):
    """Validate the entire input before any SSH and replace all bundled updater code."""
    limits = POLICY['limits']
    try:
        if len(data) > limits['compressed_bytes']:
            raise ValueError('更新归档过大')
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            raw = stream.read(limits['tar_bytes'] + 1)
        if len(raw) > limits['tar_bytes']:
            raise ValueError('更新展开归档过大')
        entries, directories, total = {}, set(), 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            seen = set()
            for member in archive:
                name = member.name
                # TarInfo strips all trailing slashes on directories. Check the
                # actual final header as well, before accepting its normalized name.
                header = raw[member.offset_data - 512:member.offset_data]
                header_name = header[:100].split(b'\0', 1)[0].decode('utf-8')
                if header[257:263] == b'ustar\0':
                    prefix = header[345:500].split(b'\0', 1)[0].decode('utf-8')
                    if prefix:
                        header_name = prefix + '/' + header_name
                if member.isdir() and header_name.endswith('/'):
                    header_name = header_name[:-1]
                truncated_long_name = len(header[:100].split(b'\0', 1)[0]) == 100 and len(name) > 100 and name.startswith(header_name)
                if not truncated_long_name and not canonical_path(header_name):
                    raise ValueError('更新归档原始路径非法')
                if not canonical_path(name) or name in seen or len(seen) >= limits['members']:
                    raise ValueError('更新归档路径非法或重复')
                seen.add(name)
                if member.isdir():
                    if member.size or member.mode & ~0o777:
                        raise ValueError('更新目录元数据非法')
                    directories.add(name)
                    continue
                if not (member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.SYMTYPE)) or member.sparse:
                    raise ValueError('更新归档类型非法')
                if member.mode & ~0o777 or not 0 <= member.size <= limits['member_bytes']:
                    raise ValueError('更新归档权限或文件大小非法')
                if member.issym() and member.size:
                    raise ValueError('更新符号链接数据非法')
                if not (0 <= member.uid <= 0xffffffff and 0 <= member.gid <= 0xffffffff):
                    raise ValueError('更新归档属主非法')
                content = member.linkname.encode('utf-8') if member.issym() else archive.extractfile(member).read()
                total += len(content)
                if total > limits['payload_bytes']:
                    raise ValueError('更新总负载过大')
                entries[name] = Entry((stat.S_IFLNK if member.issym() else stat.S_IFREG) | member.mode, content, member.uid, member.gid)
            # tar readers stop at the first end marker; reject hidden second archives.
            if any(raw[archive.offset:]):
                raise ValueError('更新归档尾部非法')
        manifest_entry = entries.get('update.json')
        if not manifest_entry or not stat.S_ISREG(manifest_entry.mode) or len(manifest_entry.data) > limits['manifest_bytes']:
            raise ValueError('更新清单不存在或过大')
        manifest = validate_manifest(json.loads(manifest_entry.data, object_pairs_hook=unique_object))
        payload = {'payload/' + name for name in manifest['files']}
        inert = {'update', 'update.uc', 'update-policy.json'}
        if set(entries) - payload - inert - {'update.json'} or not payload <= entries.keys():
            raise ValueError('更新成员与清单不一致')
        for name in inert & entries.keys():
            if not stat.S_ISREG(entries[name].mode):
                raise ValueError('旧更新脚本必须为普通文件')
        parents = {str(p) for name in payload for p in PurePosixPath(name).parents if str(p) != '.'}
        if not directories <= parents or directories & entries.keys():
            raise ValueError('更新归档含额外目录')
        result = {}
        for name, row in manifest['files'].items():
            entry = entries['payload/' + name]
            if fingerprint(entry) != row['after']:
                raise ValueError('网络增量包负载不匹配')
            result['payload/' + name] = entry
        result['update.json'] = Entry(stat.S_IFREG | 0o600, (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode())
        for source, target, mode in [('network-update', 'update', 0o700), ('network-update.uc', 'update.uc', 0o600), ('update-policy.json', 'update-policy.json', 0o600)]:
            result[target] = Entry(stat.S_IFREG | mode, (DEVICE / source).read_bytes().replace(b'\r\n', b'\n'))
        return tar_bytes(result)
    except (OSError, EOFError, UnicodeError, tarfile.TarError, TypeError, KeyError, RecursionError) as error:
        raise ValueError('网络增量包无效') from None
