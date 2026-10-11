"""为已剥离节表的运行库生成仅供链接的副本，不部署这些副本。"""
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]

def restore(path, destination=None):
    data = bytearray(path.read_bytes())
    assert data[:6] == b'\x7fELF\x01\x01'
    assert struct.unpack_from('<I', data, 32)[0] == 0
    phoff = struct.unpack_from('<I', data, 28)[0]
    phnum = struct.unpack_from('<H', data, 44)[0]
    phs = [struct.unpack_from('<8I', data, phoff + 32*i) for i in range(phnum)]
    def offset(addr):
        for p in phs:
            if p[0] == 1 and p[2] <= addr < p[2] + p[4]:
                return p[1] + addr - p[2]
        raise ValueError(hex(addr))
    dp = next(p for p in phs if p[0] == 2)
    dynamic = dict(struct.unpack_from('<II', data, i) for i in range(dp[1], dp[1]+dp[4], 8))
    assert dynamic[11] == 16
    symoff = offset(dynamic[6])
    stroff = offset(dynamic[5])
    if 4 in dynamic:
        count = struct.unpack_from('<I', data, offset(dynamic[4])+4)[0]
    else:
        # GNU hash 的桶链终结标志给出最后一个动态符号。
        h = offset(dynamic[0x6ffffef5])
        nb, first, bloom, shift = struct.unpack_from('<4I', data, h)
        buckets = h + 16 + bloom*4
        chains = buckets + nb*4
        last = max(struct.unpack_from('<I', data, buckets+i*4)[0] for i in range(nb))
        while last >= first and not struct.unpack_from('<I', data, chains+(last-first)*4)[0] & 1:
            last += 1
        count = max(first, last+1)
    assert count > 1 and symoff + count*16 <= len(data)
    # 链接器需要有效节索引；这些修正只发生在专用链接副本中。
    first_global = count
    for i in range(count):
        if data[symoff + i*16 + 12] >> 4:
            first_global = min(first_global, i)
        pos = symoff + i*16 + 14
        old = struct.unpack_from('<H', data, pos)[0]
        if 0 < old < 0xff00:
            struct.pack_into('<H', data, pos, 3)
    names = b'\0.dynstr\0.dynsym\0.load\0.shstrtab\0.dynamic\0'
    nameoff = len(data)
    data.extend(names)
    data.extend(b'\0' * (-len(data) % 4))
    shoff = len(data)
    sh = [(0,)*10,
          (1,3,2,dynamic[5],stroff,dynamic[10],0,0,1,0),
          (9,11,2,dynamic[6],symoff,count*16,1,first_global,4,16),
          (17,1,7,0,0,nameoff,0,0,4,0),
          (23,3,0,0,nameoff,len(names),0,0,1,0),
          (33,6,3,dp[2],dp[1],dp[4],1,0,4,8)]
    for s in sh:
        data.extend(struct.pack('<10I', *s))
    struct.pack_into('<I', data, 32, shoff)
    struct.pack_into('<HHH', data, 46, 40, len(sh), 4)
    dest = destination if destination is not None else ROOT / 'analysis/compat-link-libs' / path.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    print(path.name, '链接符号数：', count)

if __name__ == '__main__':
    for p in [ROOT / 'analysis/compat-sysroot/lib/libubox.so.20260213', ROOT / 'analysis/compat-sysroot/lib/libblobmsg_json.so.20260213', ROOT / 'analysis/compat-sysroot/usr/lib/libjson-c.so.5', ROOT / 'analysis/compat-sysroot/lib/libc.so']:
        restore(p)
