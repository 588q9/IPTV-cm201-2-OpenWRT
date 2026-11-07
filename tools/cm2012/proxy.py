"""CM201-2 Mihomo control plane; no subscriptions or generated keys in images."""
import stat
from .archives import Entry
from .template_files import load_templates, merge_files


def configuration() -> dict[str, bytes]:
    return {'etc/config/cm2012_proxy': b"config proxy 'settings'\n option enabled '0'\n option revision '0'\n option github_rule_api '0'\n"}


def runtime_files(root) -> dict[str, Entry]:
    result = {
        'etc/cm2012-proxy': Entry(stat.S_IFDIR | 0o700),
        'etc/cm2012-proxy/Country.mmdb': Entry(
            stat.S_IFLNK | 0o777, b'/usr/share/cm2012/geodata/Country.mmdb'),
    }
    source_dir = root / 'configs' / 'remote-proxy'
    executable = {
        'cm2012-proxy': 'usr/libexec/cm2012-proxy',
        'cm2012-mihomo': 'etc/init.d/cm2012-mihomo',
        'cm2012-proxy-guard': 'etc/init.d/cm2012-proxy-guard',
        'cm2012-proxy-recover': 'etc/init.d/cm2012-proxy-recover',
    }
    files = {
        'cm2012-proxy-lib.uc': 'usr/libexec/cm2012-proxy-lib.uc',
        'cm2012-proxy-service.uc': 'usr/libexec/cm2012-proxy-service.uc',
        'cm2012-proxy-native.uc': 'usr/libexec/cm2012-proxy-native.uc',
        'cm2012-proxy-cli.uc': 'usr/libexec/cm2012-proxy-cli.uc',
        'cm2012-proxy-rpc.uc': 'usr/share/rpcd/ucode/cm2012_proxy',
        'cm2012-proxy-acl.json': 'usr/share/rpcd/acl.d/luci-app-cm2012-proxy.json',
        'cm2012-proxy-menu.json': 'usr/share/luci/menu.d/luci-app-cm2012-proxy.json',
        'cm2012-proxy.js': 'www/luci-static/resources/view/cm2012/proxy.js',
    }
    result = merge_files(result, load_templates(source_dir, [
        (source, target, 0o755 if source in executable else 0o644)
        for source, target in {**executable, **files}.items()]))
    for start, name in ((17, 'cm2012-proxy-recover'), (94, 'cm2012-mihomo'), (95, 'cm2012-proxy-guard')):
        result[f'etc/rc.d/S{start}{name}'] = Entry(stat.S_IFLNK | 0o777, f'../init.d/{name}'.encode())
    return result
