import json
import shlex
from probe import BASE, JOB, DEVICES, ssh

commands = {
 'cm2012': '''set -e
test -d /tmp/tscompat-20261018-1405
test ! -L /tmp/tscompat-20261018-1405
rm -f /tmp/tscompat-20261018-1405/tailscale /tmp/tscompat-20261018-1405/tailscaled /tmp/tscompat-20261018-1405/netns-exec /tmp/tscompat-20261018-1405/disabled.json /tmp/tscompat-20261018-1405/cm-inside.sh /tmp/tscompat-20261018-1405/daemon.log /tmp/tscompat-20261018-1405/tailscaled.sock /tmp/tscompat-20261018-1405/logs/tailscaled.log.conf
rmdir /tmp/tscompat-20261018-1405/state/dns-cache /tmp/tscompat-20261018-1405/state /tmp/tscompat-20261018-1405/logs /tmp/tscompat-20261018-1405
test ! -L /var/lib/tailscale
test -f /var/lib/tailscale/tailscaled.log.conf
rm /var/lib/tailscale/tailscaled.log.conf
rmdir /var/lib/tailscale
echo TEMPORARY_FILES_REMOVED
if ip link show tscompat0 >/dev/null 2>&1; then echo UNEXPECTED_TEST_INTERFACE; exit 1; fi
if pidof tailscaled >/dev/null 2>&1; then echo UNEXPECTED_DAEMON; exit 1; fi
echo NO_TEST_DAEMON_OR_INTERFACE
sed -n '/MemAvailable:/p' /proc/meminfo
df -k / /tmp
''',
 'sft1200': '''set -e
test -d /tmp/tscompat-20261018-1405
test ! -L /tmp/tscompat-20261018-1405
test -d /root/tscompat-20261018-1405
test ! -L /root/tscompat-20261018-1405
rm /tmp/tscompat-20261018-1405/netns-exec /tmp/tscompat-20261018-1405/tun-probe /root/tscompat-20261018-1405/tailscaled
rmdir /tmp/tscompat-20261018-1405 /root/tscompat-20261018-1405
echo TEMPORARY_FILES_REMOVED
if ip link show tsprobe0 >/dev/null 2>&1; then echo UNEXPECTED_TEST_INTERFACE; exit 1; fi
if pidof tailscaled >/dev/null 2>&1; then echo UNEXPECTED_DAEMON; exit 1; fi
echo NO_TEST_DAEMON_OR_INTERFACE
sed -n '/MemAvailable:/p' /proc/meminfo
df -k /overlay /tmp
'''
}

results=[]
for name, command in commands.items():
    code, out = ssh(DEVICES[name][0], command)
    results.append({'device':name,'exit':code,'output':out})
    print(name, code, out, flush=True)
    (BASE/'cleanup.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    if code:
        raise RuntimeError(name)
