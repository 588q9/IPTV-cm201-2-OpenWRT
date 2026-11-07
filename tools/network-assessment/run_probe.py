import json
import subprocess
import sys
from pathlib import Path
from probe import BASE, OPTS, DEVICES, JOB, ssh, run

SNAPSHOT = "sha256sum /etc/config/* /etc/resolv.conf 2>/dev/null; echo RULES; ip rule show; echo ROUTES; ip route show table all; echo FIREWALL; iptables-save 2>/dev/null | sed '/^#/d' | sha256sum; echo MODULES; cat /proc/modules | awk '{print $1}' | sort; echo PACKAGES; for f in /usr/lib/opkg/status /lib/apk/db/installed /etc/apk/world; do if test -f $f; then sha256sum $f; fi; done"

def main():
    name = sys.argv[1]
    ip, arch = DEVICES[name]
    results = []
    def rec(label, result, fail=True, show=True):
        results.append({'label': label, 'exit': result[0], 'output': result[1]})
        print(label, result[0], result[1] if show else '(evidence saved)', flush=True)
        (BASE / (name + '-runtime.json')).write_text(json.dumps(results, indent=2), encoding='utf-8')
        if result[0] and fail:
            raise RuntimeError(label)
        return result
    def upload(local, remote):
        return run(['scp', '-O'] + OPTS + [str(local), 'root@' + ip + ':' + remote], 180)
    before = rec('host-baseline', ssh(ip, SNAPSHOT), show=False)
    if name == 'cm2012':
        for filename in ['tailscale', 'tailscaled']:
            rec('upload-' + filename, upload(BASE / arch / filename, JOB + '/' + filename))
        for filename in ['disabled.json', 'cm-inside.sh']:
            rec('upload-' + filename, upload(BASE / filename, JOB + '/' + filename))
        rec('program-version', ssh(ip, 'chmod 700 ' + JOB + '/tailscale ' + JOB + '/tailscaled; ' + JOB + '/tailscaled --version'))
        rec('isolated-daemon', ssh(ip, JOB + '/netns-exec /bin/sh ' + JOB + '/cm-inside.sh', 60), fail=False)
    else:
        flash = '/root/tscompat-20261018-1405'
        rec('create-temporary-flash-directory', ssh(ip, 'umask 077; mkdir ' + flash))
        rec('upload-daemon', upload(BASE / arch / 'tailscaled', flash + '/tailscaled'))
        rec('upload-tun-probe', upload(BASE / arch / 'tun-probe', JOB + '/tun-probe'))
        rec('program-and-tun-probe', ssh(ip, 'chmod 700 ' + flash + '/tailscaled ' + JOB + '/tun-probe; sha256sum ' + flash + '/tailscaled; ' + flash + '/tailscaled --version; if ip link show tsprobe0 >/dev/null 2>&1; then echo PROBE_INTERFACE_ALREADY_EXISTS; exit 1; fi; ' + JOB + '/tun-probe; result=$?; if ip link show tsprobe0 >/dev/null 2>&1; then echo PROBE_INTERFACE_LEFTOVER; exit 1; fi; echo NO_PROBE_INTERFACE_LEFTOVER; sed -n /MemAvailable:/p /proc/meminfo; exit $result'), fail=False)
    after = rec('host-after', ssh(ip, SNAPSHOT), show=False)
    print('HOST_SNAPSHOT_MATCH=' + str(before == after), flush=True)

if __name__ == '__main__':
    main()
