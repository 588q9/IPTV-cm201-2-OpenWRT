"""固定资源缓存；只有 prepare 可以联网，build 仅验证已有文件。"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile
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


def checked_directory(destination, workspace=None):
    """确认操作目标为边界内的绝对路径，且现有父级没有链接/reparse。"""
    destination = Path(os.path.abspath(destination))
    boundary = Path(os.path.abspath(workspace if workspace is not None else destination.parent))
    if destination == boundary or not destination.is_relative_to(boundary):
        raise ValueError('生成目录越界')
    for path in reversed((destination, *destination.parents)):
        if path.is_symlink() or path.is_junction():
            raise ValueError('生成目录包含链接或 reparse 点')
        if (os.name == 'nt' and path.exists() and
                path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError('生成目录包含 reparse 点')
    if not destination.resolve().is_relative_to(boundary.resolve()):
        raise ValueError('生成目录越界')
    return destination


def checked_tree(destination, workspace=None):
    destination = checked_directory(destination, workspace)
    if destination.exists():
        if not destination.is_dir():
            raise ValueError('生成目录不是目录')
        for directory, folders, files in os.walk(destination, followlinks=False):
            for name in folders + files:
                # The root's ancestors are already checked. Inspect each entry
                # before descending rather than rescanning every ancestor per file.
                info = (Path(directory) / name).lstat()
                if (stat.S_ISLNK(info.st_mode) or
                        getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                    raise ValueError('生成目录包含链接或 reparse 点')
    return destination


def remove_generated_tree(destination, workspace):
    destination = checked_tree(destination, workspace)
    if destination.exists():
        shutil.rmtree(destination)


def extract_source(source, destination, *, workspace=None):
    """源码解包只接受目录与普通文件，不跟随归档链接。"""
    with tarfile.open(source) as archive:
        members = archive.getmembers()
        roots = set()
        for member in members:
            name = PurePosixPath(safe_name(member.name))
            if not name.parts:
                if member.isdir():
                    continue
                raise ValueError('源码归档包含空路径')
            roots.add(name.parts[0])
            if not member.isdir() and not member.isreg():
                raise ValueError('源码归档包含链接或特殊文件')
            if len(name.parts) == 1 and not member.isdir():
                raise ValueError('源码归档缺少顶层目录')
        if len(roots) != 1:
            raise ValueError('源码归档必须包含唯一顶层目录')
        destination = checked_tree(destination, workspace)
        remove_generated_tree(destination, workspace or destination.parent)
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
        return destination / roots.pop()


def zip_members(archive):
    """ZIP 不允许 Windows 别名、大小写冲突及特殊文件。"""
    members, seen = [], set()
    for member in archive.infolist():
        name = safe_name(member.orig_filename)
        parts = PurePosixPath(name).parts
        if not parts or any(part.endswith(('.', ' ')) or
                            any(ord(c) < 32 or c in '<>"|?*' for c in part) or
                            part.split('.')[0].upper() in
                            {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
                             *(f'LPT{i}' for i in range(1, 10))}
                            for part in parts):
            raise ValueError('ZIP 包含 Windows 非法路径或别名')
        mode = member.external_attr >> 16
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValueError('ZIP 包含链接或特殊文件')
        key = name.casefold()
        if key in seen:
            raise ValueError('ZIP 路径重复或大小写冲突')
        seen.add(key)
        members.append((member, name))
    return members


def extract_zip(source, destination):
    with zipfile.ZipFile(source) as archive:
        members = zip_members(archive)
        destination = checked_directory(destination)
        # 在任何写入之前检查全部路径；不用 extractall 的平台名称改写。
        checked = {destination}
        for member, name in members:
            path = destination
            for part in PurePosixPath(name).parts:
                path = path / part
                if path in checked:
                    continue
                checked.add(path)
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                if (stat.S_ISLNK(info.st_mode) or
                        getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                    raise ValueError('ZIP 路径包含链接或 reparse 点')
        destination.mkdir(parents=True, exist_ok=True)
        for member, name in members:
            path = destination / name
            if member.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as stream, path.open('wb') as out:
                    shutil.copyfileobj(stream, out)


def zip_cache_matches(source, destination):
    destination = checked_tree(destination)
    if not destination.is_dir():
        return False
    with zipfile.ZipFile(source) as archive:
        members = zip_members(archive)
        expected = {name for member, name in members if not member.is_dir()}
        actual = {p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file()}
        if actual != expected:
            return False
        for member, name in members:
            path = destination / name
            if member.is_dir():
                if not path.is_dir():
                    return False
            elif not path.is_file() or path.stat().st_size != member.file_size:
                return False
            else:
                with archive.open(member) as stream:
                    if file_sha(path) != hashlib.file_digest(stream, 'sha256').hexdigest():
                        return False
    return True


def prepare_zip_cache(source, destination, *, workspace):
    """完整验证后才发布，健康缓存只读复用。调用方先验证锁定 ZIP。"""
    destination = checked_tree(destination, workspace)
    if zip_cache_matches(source, destination):
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.' + destination.name + '-', dir=destination.parent))
    try:
        extract_zip(source, staging)
        if not zip_cache_matches(source, staging):
            raise ValueError('工具链展开内容与锁定 ZIP 不一致')
        remove_generated_tree(destination, workspace)
        staging.replace(destination)
    finally:
        remove_generated_tree(staging, workspace)
    return destination
