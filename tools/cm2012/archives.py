"""在内存中处理设备根归档，避免 Windows 解包损坏链接和权限。"""
from dataclasses import dataclass
import io
from pathlib import PurePosixPath
import posixpath
import stat
import tarfile

from .images import gz
from .resources import safe_name


@dataclass(frozen=True)
class Entry:
    mode: int
    data: bytes = b''
    uid: int = 0
    gid: int = 0
    major: int = 0
    minor: int = 0


def read_tar_bytes(data):
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            name = safe_name(member.name)
            if name in ('', '.'):
                continue
            if name in result:
                raise ValueError('归档路径重复：' + name)
            mode = member.mode & 0o7777
            payload, major, minor = b'', 0, 0
            if member.isdir():
                mode |= stat.S_IFDIR
            elif member.issym():
                link = member.linkname
                virtual = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
                if virtual == '..' or virtual.startswith('../') or '\\' in link:
                    raise ValueError('根归档链接越界')
                mode |= stat.S_IFLNK
                payload = link.encode()
            elif member.isreg() or member.islnk():
                if member.islnk():
                    safe_name(member.linkname)
                mode |= stat.S_IFREG
                payload = archive.extractfile(member).read()
            elif member.ischr():
                mode |= stat.S_IFCHR
                major, minor = member.devmajor, member.devminor
            elif member.isblk():
                mode |= stat.S_IFBLK
                major, minor = member.devmajor, member.devminor
            else:
                raise ValueError('根归档包含未支持的文件类型：' + name)
            result[name] = Entry(mode, payload, member.uid, member.gid, major, minor)
    for name in list(result):
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                result.setdefault(str(parent), Entry(stat.S_IFDIR | 0o755))
    for name in result:
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.' and not stat.S_ISDIR(result[str(parent)].mode):
                raise ValueError('归档文件位于链接或普通文件之下：' + name)
    return result


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.GNU_FORMAT) as archive:
        for name, entry in sorted(entries.items()):
            safe_name(name)
            member = tarfile.TarInfo(name)
            member.mode, member.uid, member.gid = stat.S_IMODE(entry.mode), entry.uid, entry.gid
            member.mtime, member.uname, member.gname = 0, '', ''
            if stat.S_ISDIR(entry.mode):
                member.type = tarfile.DIRTYPE
            elif stat.S_ISLNK(entry.mode):
                member.type, member.linkname = tarfile.SYMTYPE, entry.data.decode()
            elif stat.S_ISCHR(entry.mode) or stat.S_ISBLK(entry.mode):
                member.type = tarfile.CHRTYPE if stat.S_ISCHR(entry.mode) else tarfile.BLKTYPE
                member.devmajor, member.devminor = entry.major, entry.minor
            else:
                member.size = len(entry.data)
            archive.addfile(member, io.BytesIO(entry.data) if member.isreg() else None)
    return gz(output.getvalue())


def cpio_bytes(entries):
    output = bytearray()

    def add(name, entry, inode):
        encoded = name.encode() + b'\0'
        fields = [inode, entry.mode, entry.uid, entry.gid, 1, 0, len(entry.data),
                  0, 0, entry.major, entry.minor, len(encoded), 0]
        if any(not 0 <= n <= 0xffffffff for n in fields):
            raise ValueError('newc 字段超过 32 位')
        output.extend(b'070701' + ''.join(f'{n:08x}' for n in fields).encode() + encoded)
        output.extend(bytes(-len(output) % 4))
        output.extend(entry.data)
        output.extend(bytes(-len(output) % 4))
    for inode, (name, entry) in enumerate(sorted(entries.items()), 1):
        add(name, entry, inode)
    add('TRAILER!!!', Entry(0), len(entries) + 1)
    return bytes(output)


def read_cpio_bytes(data):
    """严格读取小型内部维护根；不在主机解包任何设备文件。"""
    if len(data) > 16 * 1048576:
        raise ValueError('内部维护根过大')
    result, offset = {}, 0
    while offset + 110 <= len(data):
        header = data[offset:offset + 110]
        if header[:6] != b'070701':
            raise ValueError('维护根不是 newc')
        try:
            fields = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        except ValueError as error:
            raise ValueError('newc 字段非法') from error
        offset += 110
        size, namesize = fields[6], fields[11]
        if not 1 <= namesize <= 256 or offset + namesize > len(data):
            raise ValueError('newc 名称长度非法')
        encoded = data[offset:offset + namesize]
        if encoded[-1:] != b'\0' or b'\0' in encoded[:-1]:
            raise ValueError('newc 名称终止错误')
        name = safe_name(encoded[:-1].decode('utf-8'))
        offset = (offset + namesize + 3) & ~3
        if offset + size > len(data):
            raise ValueError('newc 数据不完整')
        payload = data[offset:offset + size]
        offset = (offset + size + 3) & ~3
        if name == 'TRAILER!!!':
            if size or any(data[offset:]):
                raise ValueError('newc 尾部非法')
            return result
        if name in result or fields[4] != 1 or fields[12] != 0:
            raise ValueError('newc 重复文件或未支持的链接/校验格式')
        result[name] = Entry(fields[1], payload, fields[2], fields[3], fields[9], fields[10])
    raise ValueError('newc 缺少结束标记')
