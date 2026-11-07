"""固定功能模板的读取和无冲突组合。"""
from pathlib import PurePosixPath
import stat

from .archives import Entry


def merge_files(*groups):
    result = {}
    for group in groups:
        for name, entry in group.items():
            if name in result:
                if (isinstance(entry, Entry) and stat.S_ISDIR(entry.mode) and result[name] == entry):
                    continue
                raise ValueError('功能文件目标重复：' + name)
            result[name] = entry
    return result


def load_templates(directory, records):
    result = {}
    for source, target, mode in records:
        for name in (source, target):
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name or not path.parts:
                raise ValueError('模板路径无效')
        if target in result:
            raise ValueError('模板目标重复：' + target)
        result[target] = Entry(stat.S_IFREG | mode,
                               (directory / source).read_bytes().replace(b'\r\n', b'\n'))
    return result
