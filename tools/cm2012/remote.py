"""网络扩展的默认配置与生命周期协调；不包含用户账户或订阅。"""
import stat
from .archives import Entry
from .template_files import load_templates, merge_files


def configuration():
    from .tailscale import configuration as tailscale_configuration
    from .proxy import configuration as proxy_configuration
    result = {'etc/config/ddns': b"""config ddns 'global'
 option ddns_dateformat '%F %R'
 option ddns_loglines '100'
 option upd_privateip '0'

config service 'cm2012_cloudflare'
 option enabled '0'
 option service_name 'cloudflare.com-v4'
 option lookup_host ''
 option domain ''
 option username 'Bearer'
 option password ''
 option use_ipv6 '0'
 option use_https '1'
 option cacert '/etc/ssl/certs'
 option use_curl '1'
 option ip_source 'web'
 option ip_url 'https://api.ipify.org'
 option check_interval '10'
 option check_unit 'minutes'
 option force_interval '24'
 option force_unit 'hours'
 option use_syslog '0'
 option use_logfile '0'
"""}
    return merge_files(result, tailscale_configuration(), proxy_configuration())


def runtime_files(root):
    from .tailscale import runtime_files as tailscale_files
    from .proxy import runtime_files as proxy_files
    return merge_files(tailscale_files(root), proxy_files(root), load_templates(
        root / 'configs/templates', [('cm2012-remote', 'usr/libexec/cm2012-remote', 0o755)]))
