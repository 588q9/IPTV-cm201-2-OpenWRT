#!/bin/sh
# Run the production cancellation against a confirmed session and nested service.
set -e
. "$1"
probe_root=$2
checker_shell=${3:-/bin/sh}
command -v setsid >/dev/null || { echo 'setsid unavailable' >&2; exit 1; }
[ -x "$checker_shell" ] && [ -r /proc/self/stat ] || { echo 'Linux shell/proc prerequisites unavailable' >&2; exit 1; }
marker="$probe_root/late-service-write"
started="$probe_root/child-started"
rm -f "$marker" "$started"
cat > "$probe_root/service.sh" <<'SERVICE'
printf '%s' "$$" > "$2"
sleep 4
touch "$1"
SERVICE
setsid "$checker_shell" -c '
 "$1" "$2" "$3" "$4" &
 wait
' group "$checker_shell" "$probe_root/service.sh" "$marker" "$started" > "$probe_root/checker.log" 2>&1 &
checker=$!
trap 'stop_checker "$checker" || true' EXIT HUP INT TERM
tries=0
while [ ! -s "$started" ]; do
 if ! kill -0 "$checker" 2>/dev/null; then cat "$probe_root/checker.log" >&2; echo 'checker exited before child handshake' >&2; exit 1; fi
 tries=$((tries+1)); [ "$tries" -le 3 ] || { echo 'child handshake timed out' >&2; exit 1; }
 sleep 1
done
kill -0 "$(cat "$started")" 2>/dev/null || { echo 'child handshake PID is not alive' >&2; exit 1; }
group_active "$checker" || { echo 'checker did not establish its process group' >&2; exit 1; }
stop_checker "$checker"
trap - EXIT HUP INT TERM
sleep 5
[ ! -f "$marker" ] || { echo 'service survived cancellation' >&2; exit 1; }
echo CHECKER_DESCENDANTS_CANCELLED
