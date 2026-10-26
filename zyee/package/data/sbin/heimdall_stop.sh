#!/bin/sh
# Stopped by: zyeed -n heimdall -> /sbin/heimdall_stop.sh
# Stopping the supervisor lets it stop the probe cleanly; the pkill catches a
# probe left behind by a supervisor that died.
LOCK=/tmp/heimdall/heimdall.lock
if [ -f "$LOCK" ]; then
	kill -TERM "$(cat "$LOCK")" 2>/dev/null
	i=0
	while [ -f "$LOCK" ] && [ $i -lt 12 ]; do
		sleep 1
		i=$((i + 1))
	done
fi
pkill -f /opt/heimdall/bin/heimdall-probe 2>/dev/null
rm -f "$LOCK"
exit 0
