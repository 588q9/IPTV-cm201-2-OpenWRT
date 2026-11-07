#!/bin/sh
set -u
job=/tmp/tscompat-20261018-1405
pid=
finish() {
    if test -n "$pid"; then kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; fi
}
trap finish EXIT HUP INT TERM
ip link set lo up
mkdir -p "$job/state" "$job/logs"
CACHE_DIRECTORY= TS_LOGS_DIR="$job/logs" TS_TUN_DISABLE_UDP_GRO=true TS_TUN_DISABLE_TCP_GRO=true "$job/tailscaled" --config="$job/disabled.json" --state=mem: --statedir="$job/state" --socket="$job/tailscaled.sock" --tun=tscompat0 --port=0 --no-logs-no-support >"$job/daemon.log" 2>&1 &
pid=$!
echo DAEMON_PID=$pid
i=0
while test "$i" -lt 25; do
    if ! kill -0 "$pid" 2>/dev/null; then echo DAEMON_EXITED_EARLY; cat "$job/daemon.log"; exit 1; fi
    if test -S "$job/tailscaled.sock"; then break; fi
    sleep 1
    i=$((i+1))
done
sleep 3
echo LOCAL_STATUS
"$job/tailscale" --socket="$job/tailscaled.sock" status --json
echo DAEMON_MEMORY
sed -n '/VmPeak:/p;/VmRSS:/p;/VmSize:/p;/Threads:/p' /proc/$pid/status
echo ISOLATED_TUN
ip link show tscompat0
echo ISOLATED_RULES
ip rule show
echo ISOLATED_ROUTES
ip route show table all
echo MEMORY_AVAILABLE
sed -n '/MemAvailable:/p' /proc/meminfo
finish
pid=
echo DAEMON_LOG
cat "$job/daemon.log"
