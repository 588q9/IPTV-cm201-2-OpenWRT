import json
import os
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
OPTS = ['-oBatchMode=yes', '-oConnectTimeout=8', '-oStrictHostKeyChecking=yes',
        '-oHostKeyAlgorithms=+ssh-rsa', '-oPubkeyAcceptedAlgorithms=+ssh-rsa']
DEVICES = {'cm2012': ('192.168.50.1', 'arm'), 'sft1200': ('192.168.250.1', 'mipsle')}
JOB = '/tmp/tscompat-20261018-1405'

def run(args, timeout=90):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return p.returncode, p.stdout.decode('utf-8', 'replace')

def ssh(ip, command, timeout=90):
    return run(['ssh'] + OPTS + ['root@' + ip, command], timeout)

def main():
    name = sys.argv[1]
    ip, arch = DEVICES[name]
    log = []
    def record(label, result):
        log.append({'label': label, 'exit': result[0], 'output': result[1]})
        print(label, result[0], result[1], flush=True)
        (BASE / (name + '-namespace.json')).write_text(json.dumps(log, indent=2), encoding='utf-8')
        if result[0]:
            sys.exit(result[0])
    record('create-private-directory', ssh(ip, 'umask 077; mkdir ' + JOB))
    record('upload-helper', run(['scp', '-O'] + OPTS + [str(BASE / arch / 'netns-exec'), 'root@' + ip + ':' + JOB + '/netns-exec']))
    record('namespace-check', ssh(ip, 'chmod 700 ' + JOB + '/netns-exec; ' + JOB + '/netns-exec /bin/sh -c ' + "'echo PRIVATE_INTERFACES; ip link show; echo PRIVATE_RULES; ip rule show; echo PRIVATE_SYSFS; ls /sys/class/net; echo PRIVATE_ETC_MOUNT; mount | grep /etc; echo HOST_DBUS_CHECK; for f in /run/dbus/system_bus_socket /var/run/dbus/system_bus_socket; do if test -S $f; then echo EXISTS:$f; fi; done'"))

if __name__ == '__main__':
    main()
