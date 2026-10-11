"""固定资源缓存；只有 prepare 可以联网，build 仅验证已有文件。"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import urllib.request
import zipfile


def resource_path(root, item):
    raw = item['path']
    name = PurePosixPath(raw)
    if name.is_absolute() or '..' in name.parts or ':' in raw or '\\' in raw:
        raise ValueError('资源路径越界')
    result = (root / raw).resolve()
    if not result.is_relative_to(root.resolve()):
        raise ValueError('资源路径越界')
    return result


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_resource(root, item):
    path = resource_path(root, item)
    if not path.is_file():
        raise FileNotFoundError('缺少锁定资源：' + item['path'])
    if path.stat().st_size != item['size'] or file_sha(path) != item['sha256']:
        raise ValueError('锁定资源被修改：' + item['path'])
    return path


def read_lock(root):
    lock = json.loads((root / 'resources.lock.json').read_text(encoding='utf-8'))
    if lock['format'] != 1:
        raise ValueError('不支持的资源锁格式')
    items = lock['resources']
    if len({item['id'] for item in items}) != len(items):
        raise ValueError('资源标识重复')
    for item in items:
        resource_path(root, item)
        if len(item['sha256']) != 64 or not item['url'].startswith('https://'):
            raise ValueError('资源锁字段不完整')
    return {item['id']: item for item in items}


def prepare(root, import_directory=None):
    for item in read_lock(root).values():
        destination = resource_path(root, item)
        if destination.exists():
            verify_resource(root, item)
            print('已验证：' + item['id'], flush=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_name(destination.name + '.part')
        imported = False
        if import_directory:
            candidates = import_directory.rglob(destination.name)
            for candidate in candidates:
                if candidate.stat().st_size == item['size'] and file_sha(candidate) == item['sha256']:
                    shutil.copyfile(candidate, partial)
                    imported = True
                    break
        if not imported:
            print('下载锁定资源：' + item['id'], flush=True)
            with urllib.request.urlopen(item['url'], timeout=60) as response, partial.open('wb') as out:
                shutil.copyfileobj(response, out)
        if partial.stat().st_size != item['size'] or file_sha(partial) != item['sha256']:
            raise ValueError('下载摘要不匹配，请检查资源锁；不自动更换版本：' + item['id'])
        partial.replace(destination)


def safe_name(raw):
    while raw.startswith('./'):
        raw = raw[2:]
    path = PurePosixPath(raw.rstrip('/'))
    if path.is_absolute() or '..' in path.parts or ':' in raw or '\\' in raw:
        raise ValueError('归档路径越界：' + raw)
    return str(path)


def extract_source(source, destination):
    """源码解包只接受目录与普通文件，不跟随归档链接。"""
    with tarfile.open(source) as archive:
        members = archive.getmembers()
        for member in members:
            safe_name(member.name)
            if not member.isdir() and not member.isreg():
                raise ValueError('源码归档包含链接或特殊文件')
        destination.mkdir(parents=True, exist_ok=True)
        for member in members:
            name = safe_name(member.name)
            path = (destination / name).resolve()
            if not path.is_relative_to(destination.resolve()):
                raise ValueError('源码解包越界')
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as stream, path.open('wb') as out:
                    shutil.copyfileobj(stream, out)


def extract_zip(source, destination):
    with zipfile.ZipFile(source) as archive:
        for name in archive.namelist():
            safe_name(name)
        archive.extractall(destination)
