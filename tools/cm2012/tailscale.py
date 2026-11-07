"""CM201-2 Tailscale service artifacts; credentials only live on the device."""
import stat
from .archives import Entry
from .template_files import load_templates


def configuration():
    return {'etc/config/cm2012_tailscale': b"""config settings 'main'
 option enabled '0'
# Set explicit Tailscale IPv4 CIDRs and TCP management ports locally.
# No sources means no LAN forwarding or management admission.
"""}


def runtime_files(root):
    files = {
        'cm2012-tailscale-init': ('etc/init.d/cm2012-tailscale', 0o755),
        'cm2012-tailscale': ('usr/libexec/cm2012-tailscale', 0o755),
        'cm2012-tailscale.uc': ('usr/libexec/cm2012-tailscale.uc', 0o644),
        'cm2012-tailscale-lib.uc': ('usr/libexec/cm2012-tailscale-lib.uc', 0o644),
        'cm2012-tailscale-rpc.uc': ('usr/share/rpcd/ucode/cm2012_tailscale', 0o644),
        'cm2012-tailscale-acl.json': ('usr/share/rpcd/acl.d/luci-app-cm2012-tailscale.json', 0o644),
        'cm2012-tailscale-menu.json': ('usr/share/luci/menu.d/luci-app-cm2012-tailscale.json', 0o644),
        'cm2012-tailscale.js': ('www/luci-static/resources/view/cm2012/tailscale.js', 0o644),
    }
    result = load_templates(root / 'configs/templates',
                            [(source, target, mode) for source, (target, mode) in files.items()])
    result['etc/tailscale'] = Entry(stat.S_IFDIR | 0o700)
    result['etc/rc.d/S95cm2012-tailscale'] = Entry(stat.S_IFLNK | 0o777, b'../init.d/cm2012-tailscale')
    return result
