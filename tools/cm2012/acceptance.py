"""Record read-only RAM acceptance against the current output manifest."""
import json
import time

from .images import sha256
from .layout import bootargs_map

RAM_CHECKS = ('nand-readonly', 'hostapd-enabled', 'nat-rules', 'rpc-present',
              'standard-leases', 'single-wifi-owner')


def record_ram_acceptance(config, output):
    from .serial_link import Link
    expected = 'mtdparts=hinand:' + bootargs_map(config['profile']['total_bytes'])
    with Link(config['port']) as link:
        link.command('dmesg -n 1')
        cmdline = link.command('cat /proc/cmdline')
        if expected not in cmdline:
            raise ValueError('RAM 验收必须全部 NAND 只读')
        link.command('(test "$(grep -c \'^mtd[0-9]\' /proc/mtd)" = 9 && ! grep -q " / ubifs " /proc/mounts && for n in 0 1 2 3 4 5 6 7 8; do test "$(cat /sys/class/mtd/mtd$n/flags)" = 0x0 || exit 1; done)')
        for _ in range(120):
            ap = link.command('ubus call hostapd.ap0 get_status 2>/dev/null || true')
            if 'ENABLED' in ap:
                break
            time.sleep(1)
        else:
            raise ValueError('热点没有进入 ENABLED；保留 RAM 环境诊断')
        link.command('(for p in dnsmasq hostapd ntpd; do pidof "$p" >/dev/null || exit 1; done)')
        proof = link.command('iptables -t nat -S; ubus -v list cm2012')
        if 'MASQUERADE' not in proof or '"apply"' not in proof:
            raise ValueError('RAM 防火墙或 RPC 基础检查失败')
        link.command('test "$(uci -q get dhcp.main.leasefile)" = /tmp/dhcp.leases && test ! -e /etc/rc.d/S19wpad')
    receipt = {'manifest_sha256': sha256((output / 'manifest.json').read_bytes()),
               'checks': list(RAM_CHECKS)}
    (output / 'ram-acceptance.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print('NAND 只读 RAM 基础检查通过；继续进行真实网络与页面验收', flush=True)
