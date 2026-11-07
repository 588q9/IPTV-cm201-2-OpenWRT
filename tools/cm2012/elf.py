"""ARM ELF metadata and dependency validation."""
import re
import struct


def elf_info(data):
    """从程序头解析 ARM32 ELF，动态依赖只接受 Linux 库文件名。"""
    if (len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01' or
            struct.unpack_from('<H', data, 18)[0] != 40):
        raise ValueError('编译输出不是完整 ARM32 ELF')
    offset = struct.unpack_from('<I', data, 28)[0]
    size, count = struct.unpack_from('<HH', data, 42)
    if size != 32 or not count or offset < 52 or offset + size * count > len(data):
        raise ValueError('ELF 程序头长度或范围不正确')
    programs = [struct.unpack_from('<8I', data, offset + i * size) for i in range(count)]
    for program in programs:
        if program[1] + program[4] > len(data) or program[4] > program[5]:
            raise ValueError('ELF 程序段越界')
    loads = [program for program in programs if program[0] == 1]
    dynamic = [program for program in programs if program[0] == 2]
    interpreters = [program for program in programs if program[0] == 3]
    if not loads or len(dynamic) > 1 or len(interpreters) > 1:
        raise ValueError('ELF 装载段或动态段数量错误')
    interpreter = None
    if interpreters:
        program = interpreters[0]
        value = data[program[1]:program[1] + program[4]]
        if not value.endswith(b'\0') or b'\0' in value[:-1]:
            raise ValueError('ELF 解释器字符串不完整')
        try:
            interpreter = value[:-1].decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('ELF 解释器名称非法') from error
    needed = []
    if dynamic:
        program = dynamic[0]
        if not program[4] or program[4] % 8:
            raise ValueError('ELF 动态段长度错误')
        tags = []
        for position in range(program[1], program[1] + program[4], 8):
            tag, value = struct.unpack_from('<II', data, position)
            if tag == 0:
                break
            tags.append((tag, value))
        else:
            raise ValueError('ELF 动态段缺少结束标识')
        addresses = [value for tag, value in tags if tag == 5]
        lengths = [value for tag, value in tags if tag == 10]
        indexes = [value for tag, value in tags if tag == 1]
        if len(addresses) != 1 or len(lengths) != 1 or not lengths[0]:
            raise ValueError('ELF 动态字符串表不完整')
        address, length = addresses[0], lengths[0]
        mapping = [p for p in loads if p[2] <= address and address + length <= p[2] + p[4]]
        if len(mapping) != 1:
            raise ValueError('ELF 动态字符串表不属于有效装载段')
        start = mapping[0][1] + address - mapping[0][2]
        strings = data[start:start + length]
        for index in indexes:
            end = strings.find(b'\0', index) if 0 <= index < length else -1
            if end < 0:
                raise ValueError('ELF 依赖字符串越界或未结束')
            try:
                name = strings[index:end].decode('ascii')
            except UnicodeDecodeError as error:
                raise ValueError('ELF 依赖名称非法') from error
            if not re.fullmatch(r'[A-Za-z0-9_+.-]+', name) or name in ('.', '..'):
                raise ValueError('ELF 依赖含主机路径或非法文件名')
            needed.append(name)
        if len(set(needed)) != len(needed):
            raise ValueError('ELF 依赖名称重复')
    return {'interpreter': interpreter, 'needed': tuple(needed), 'has_dynamic': bool(dynamic)}


def elf_check(path, static=True, expected_needed=None):
    info = elf_info(path.read_bytes())
    if static and (info['has_dynamic'] or info['interpreter']):
        raise ValueError('维护程序不是静态链接：' + path.name)
    if not static and (not info['has_dynamic'] or info['interpreter'] != '/lib/ld-musl-armhf.so.1'):
        raise ValueError('ubusd 动态解释器不匹配')
    if expected_needed is not None and sorted(info['needed']) != sorted(expected_needed):
        raise ValueError('编译输出的动态依赖与锁定运行库不一致：' + path.name)
    return info['needed']
