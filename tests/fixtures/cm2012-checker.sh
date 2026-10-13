#!/bin/sh
# Run against extracted production functions; a nested delayed service must die.
set -e
. "$1"
probe_root=$2
marker="$probe_root/late-service-write"
rm -f "$marker"
setsid sh -c 'sh -c '\''sleep 4; touch "$1"'\'' child "$1"' group "$marker" &
checker=$!
sleep 1
stop_checker "$checker"
sleep 5
[ ! -f "$marker" ]
echo CHECKER_DESCENDANTS_CANCELLED
