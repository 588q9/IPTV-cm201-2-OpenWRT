"""有真实 ELF 节表及 .modinfo 的合成 ARM 内核模块。"""
import struct

VERMAGIC = b'3.18.24_hi3798mv2x SMP mod_unload ARMv7 p2v8 '


def module_bytes(vermagic=VERMAGIC):
    names = b'\0.shstrtab\0.modinfo\0'
    info = b'vermagic=' + vermagic + b'\0'
    start = 52 + 3 * 40
    data = bytearray(start + len(names) + len(info))
    data[:52] = struct.pack('<16sHHIIIIIHHHHHH', b'\x7fELF\x01\x01\x01' + bytes(9),
                           1, 40, 1, 0, 0, 52, 0x5000000, 52, 0, 0, 40, 3, 1)
    struct.pack_into('<10I', data, 52 + 40, 1, 3, 0, 0, start, len(names), 0, 0, 1, 0)
    struct.pack_into('<10I', data, 52 + 80, 11, 1, 0, 0, start + len(names), len(info), 0, 0, 1, 0)
    data[start:] = names + info
    return bytes(data)
