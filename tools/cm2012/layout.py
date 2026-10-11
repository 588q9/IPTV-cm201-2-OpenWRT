"""固定必要核心区，按物理 NAND 容量分配全部剩余空间。"""
MIB = 1048576
CORE = (
    ('fastboot', 0, 2, 0), ('partition', 2, 8, 0), ('misc', 10, 2, 0),
    ('mlcverify', 12, 4, 0), ('swdevinfo', 16, 16, 0),
    ('baseparam', 32, 2, 0), ('baseparam2', 34, 2, 0), ('boot', 36, 12, 0),
)


def layout_for(total_bytes, erase_bytes):
    if (type(total_bytes) is not int or type(erase_bytes) is not int or
            not 48 * MIB < total_bytes < 2**64 or erase_bytes != 2 * MIB or
            total_bytes % erase_bytes):
        raise ValueError('NAND 容量或擦除几何不兼容，无法分配全部剩余空间')
    return tuple((n, s * MIB, z * MIB, f) for n, s, z, f in CORE) + (
        ('userdata', 48 * MIB, total_bytes - 48 * MIB, 32),)


def validate_layout(parts, total_bytes, erase_bytes):
    if tuple(parts) != layout_for(total_bytes, erase_bytes):
        raise ValueError('布局存在核心边界变化、重叠、空洞或越界')


def bootargs_map(total_bytes, *, readonly=True):
    parts = layout_for(total_bytes, 2 * MIB)
    return ','.join(f'{size // MIB}M({name})' +
                    ('ro' if readonly or name == 'fastboot' else '')
                    for name, _, size, _ in parts)
