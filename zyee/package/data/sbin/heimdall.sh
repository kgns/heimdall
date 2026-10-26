#!/bin/sh
# Started by: zyeed -n heimdall -> /sbin/heimdall.sh, and by /bin/start.sh at
# boot. Foreground anchor for the container that restarts the probe when it
# exits.
B=/opt/heimdall/bin
E=/opt/heimdall/etc
D=/tmp/heimdall
LOG=$D/probe.log
# The EE's start.sh sets LD_LIBRARY_PATH for the host's libraries; the probe
# is a static binary and needs none.
unset LD_LIBRARY_PATH
mkdir -p "$D"

# Single instance: start.sh runs this at every boot and the web UI's
# "Activate" can start it again.
LOCK=$D/heimdall.lock
if [ -f "$LOCK" ] && kill -0 "$(cat "$LOCK" 2>/dev/null)" 2>/dev/null; then
	exit 0
fi
echo $$ >"$LOCK"

# /tmp is tmpfs and counts against the container's 60 MB memory limit, so
# the log is kept under 256 KB (the newest 64 KB survive a trim). Append
# mode lets the probe keep writing at the end after a trim.
cap_log() {
	[ -f "$LOG" ] || return 0
	[ "$(wc -c <"$LOG" 2>/dev/null || echo 0)" -gt 262144 ] || return 0
	tail -c 65536 "$LOG" >"$LOG.t" 2>/dev/null && cat "$LOG.t" >"$LOG"
	rm -f "$LOG.t"
}

PID=
start_probe() {
	"$B/heimdall-probe" run -config "$E/config.yaml" >>"$LOG" 2>&1 &
	PID=$!
	STARTED=$(date +%s)
}

cleanup() {
	[ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null
	# The probe sends what it has buffered before it exits.
	i=0
	while [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null && [ $i -lt 10 ]; do
		sleep 1
		i=$((i + 1))
	done
	rm -f "$LOCK"
	exit 0
}
trap cleanup TERM INT

start_probe
while :; do
	if ! kill -0 "$PID" 2>/dev/null; then
		# A probe that keeps failing at start (bad config, missing token)
		# is retried once a minute instead of in a tight loop.
		if [ $(($(date +%s) - STARTED)) -lt 60 ]; then
			sleep 55 &
			wait $!
		fi
		echo "heimdall.sh: probe exited, restarting" >>"$LOG"
		start_probe
	fi
	cap_log
	# Waiting on a background sleep lets the TERM trap run at once.
	sleep 5 &
	wait $!
done
