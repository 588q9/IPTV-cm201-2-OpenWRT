"""核对原厂 ARM 模块的实际节表及无线固件集合。"""
import stat
import struct

MODULES = ('cfg80211.ko', 'hi_sdio_detect.ko', 'wlan_mt7668_sdio.ko',
           'ehci-platform.ko', 'ohci-platform.ko', 'xhci-plat-hcd.ko')
FIRMWARE = ('EEPROM_MT7668.bin', 'EEPROM_MT7668_e1.bin', 'mt7668_patch_e1_hdr.bin',
            'mt7668_patch_e2_hdr.bin', 'WIFI_RAM_CODE_MT7668.bin',
            'WIFI_RAM_CODE2_SDIO_MT7668.bin', 'wifi.cfg')
VERMAGIC = b'3.18.24_hi3798mv2x SMP mod_unload ARMv7 p2v8 '


def validate_module(data):
    if (len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01' or
            struct.unpack_from('<HH', data, 16) != (1, 40)):
        raise ValueError('原厂模块不是完整 ARM32 ELF 可重定位文件')
    start = struct.unpack_from('<I', data, 32)[0]
    size, count, names_index = struct.unpack_from('<HHH', data, 46)
    if size != 40 or count < 2 or not 0 < names_index < count or start < 52 or start + size * count > len(data):
        raise ValueError('原厂模块节表长度或范围错误')
    sections = [struct.unpack_from('<10I', data, start + index * size) for index in range(count)]
    for section in sections:
        if section[1] != 8 and section[4] + section[5] > len(data):
            raise ValueError('原厂模块节内容越界')
    strings = sections[names_index]
    if strings[1] != 3:
        raise ValueError('原厂模块缺少节名称表')
    names = data[strings[4]:strings[4] + strings[5]]
    info = []
    for section in sections:
        end = names.find(b'\0', section[0]) if section[0] < len(names) else -1
        if end < 0:
            raise ValueError('原厂模块节名称越界')
        if names[section[0]:end] == b'.modinfo':
            if section[1] != 1:
                raise ValueError('原厂模块 .modinfo 类型错误')
            info.append(data[section[4]:section[4] + section[5]])
    if len(info) != 1:
        raise ValueError('原厂模块缺少唯一 .modinfo')
    versions = [value[9:] for value in info[0].split(b'\0') if value.startswith(b'vermagic=')]
    if versions != [VERMAGIC]:
        raise ValueError('原厂模块实际 vermagic 与已验证内核 ABI 不一致')


def validate_support(entries, module_prefix='system/lib/modules/', firmware_prefix='system/etc/firmware/'):
    for prefix, names in ((module_prefix, MODULES), (firmware_prefix, FIRMWARE)):
        for name in names:
            entry = entries.get(prefix + name)
            if entry is None or not stat.S_ISREG(entry.mode) or not entry.data:
                raise ValueError('缺少完整原厂普通文件：' + prefix + name)
            if prefix == module_prefix:
                validate_module(entry.data)
