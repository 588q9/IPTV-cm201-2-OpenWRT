"""固定原厂内核的网络默认值和用户空间兼容处理。"""
import re
import stat
from .archives import Entry


def quote(value):
    if not isinstance(value, str) or any(c in value for c in '\r\n\0'):
        raise ValueError('UCI 值包含换行或空字节')
    return "'" + value.replace("'", "'\\''") + "'"


def configuration(config):
    ssid, password = quote(config['ssid']), quote(config['ap_password'])
    network = """config interface 'loopback'
 option device 'lo'
 option proto 'static'
 list ipaddr '127.0.0.1/8'

config interface 'lan'
 option device 'ap0'
 option proto 'static'
 option ipaddr '192.168.50.1'
 option netmask '255.255.255.0'
 option auto '0'

config interface 'wan'
 option device 'eth0'
 option proto 'dhcp'
 option auto '0'

config interface 'wwan'
 option device 'wlan0'
 option proto 'dhcp'
 option auto '0'
"""
    dhcp = """config dnsmasq 'main'
 option domainneeded '1'
 option boguspriv '1'
 option rebind_protection '1'
 option local '/lan/'
 option domain 'lan'
 option expandhosts '1'
 option authoritative '1'
 option readethers '1'
 option leasefile '/tmp/dhcp.leases'
 option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
 option nonwildcard '1'
 option localservice '1'
 list interface 'lan'

config dhcp 'lan'
 option interface 'lan'
 option start '100'
 option limit '51'
 option leasetime '12h'
 option dhcpv4 'server'
 option dhcpv6 'disabled'
 option ra 'disabled'

config dhcp 'wan'
 option interface 'wan'
 option ignore '1'

config dhcp 'wwan'
 option interface 'wwan'
 option ignore '1'

config odhcpd 'odhcpd'
 option maindhcp '0'
 option leasefile '/tmp/odhcpd.leases'
 option leasetrigger '/usr/sbin/odhcpd-update'
 option loglevel '4'
"""
    firewall = """config defaults
 option input 'REJECT'
 option output 'ACCEPT'
 option forward 'REJECT'
 option syn_flood '1'

config zone
 option name 'lan'
 list network 'lan'
 option input 'ACCEPT'
 option output 'ACCEPT'
 option forward 'ACCEPT'

config zone
 option name 'trusted'
 list network 'wan'
 option input 'ACCEPT'
 option output 'ACCEPT'
 option forward 'REJECT'
 option masq '1'
 option mtu_fix '1'

config zone
 option name 'wan'
 list network 'wwan'
 option input 'REJECT'
 option output 'ACCEPT'
 option forward 'REJECT'
 option masq '1'
 option mtu_fix '1'

config forwarding
 option src 'lan'
 option dest 'trusted'

config forwarding
 option src 'lan'
 option dest 'wan'

config rule
 option name 'Allow-DHCP-Renew'
 option src 'wan'
 option proto 'udp'
 option dest_port '68'
 option family 'ipv4'
 option target 'ACCEPT'
"""
    wifi = f"""config ap 'ap'
 option enabled '1'
 option ssid {ssid}
 option key {password}
 option channel '153'
 option country 'CN'

config sta 'sta'
 option ssid ''
 option key ''

config settings 'settings'
 option uplink 'ethernet'
"""
    return {name: data.encode() for name, data in (
        ('etc/config/network', network), ('etc/config/dhcp', dhcp),
        ('etc/config/firewall', firewall), ('etc/config/cm2012', wifi))}


def prepare_root(entries):
    """只处理该固定资源中的失效后端；不删除任意用户服务。"""
    result = {name: entry for name, entry in entries.items()
              if not name.startswith('usr/share/firewall4/') and name != 'usr/share/firewall4'}
    for name in ('etc/rc.d/S19wpad', 'etc/rc.d/K21wpad', 'sbin/fw3',
                 'sbin/fw4', 'usr/sbin/nft'):
        result.pop(name, None)
    name = 'etc/init.d/dnsmasq'
    if name in result:
        entry = result[name]
        source = entry.data.decode()
        start = source.find('\tprocd_add_jail dnsmasq')
        if start < 0:
            raise ValueError('锁定 dnsmasq 启动脚本缺少预期 jail 区块')
        end = source.find('\tprocd_close_instance', start)
        if end < 0:
            raise ValueError('dnsmasq jail 区块未结束')
        source = source[:start] + '\t# CM201-2 原厂 3.18 内核：由 dnsmasq 自身降权，禁用不兼容 jail。\n' + source[end:]
        result[name] = Entry(entry.mode, source.encode())
    return result


def runtime_files(root):
    result = {}
    for source, target in (
        ('cm2012-ap', 'etc/init.d/cm2012-ap'),
        ('cm2012-wifi', 'usr/libexec/cm2012-wifi'),
        ('firewall', 'etc/init.d/firewall'),
        ('sysntpd', 'etc/init.d/sysntpd')):
        result[target] = Entry(stat.S_IFREG | 0o755,
                              (root / 'configs/templates' / source).read_bytes().replace(b'\r\n', b'\n'))
    result['etc/hotplug.d/iface/20-firewall'] = Entry(stat.S_IFREG | 0o755,
        b'#!/bin/sh\ncase "$ACTION" in ifup|ifupdate|ifdown) /sbin/fw3 reload ;; esac\n')
    result['usr/share/fw3/helpers.conf'] = Entry(stat.S_IFREG | 0o644,
        b'# No optional conntrack helper modules are enabled on the fixed vendor kernel.\n')
    for name in ('iptables', 'iptables-save', 'iptables-restore', 'ip6tables',
                 'ip6tables-save', 'ip6tables-restore'):
        result['usr/sbin/' + name] = Entry(stat.S_IFLNK | 0o777, b'xtables-legacy-multi')
    for source, target in (
        ('cm2012-wireless-lib.uc', 'usr/libexec/cm2012-wireless-lib.uc'),
        ('cm2012-supplicant.uc', 'usr/libexec/cm2012-supplicant.uc'),
        ('cm2012-rpc.uc', 'usr/share/rpcd/ucode/cm2012'),
        ('cm2012-acl.json', 'usr/share/rpcd/acl.d/luci-app-cm2012.json'),
        ('cm2012-menu.json', 'usr/share/luci/menu.d/luci-app-cm2012.json'),
        ('cm2012-wireless.js', 'www/luci-static/resources/view/cm2012/wireless.js')):
        result[target] = Entry(stat.S_IFREG | 0o644,
                              (root / 'configs/templates' / source).read_bytes().replace(b'\r\n', b'\n'))
    return result
