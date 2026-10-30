#!/bin/sh
# Supervisor of heimdall-probe on a mesh extender. Started at boot from
# /etc/rc.local (install-boot.sh adds the line) and by `scripts/rt start`;
# restarts the probe when it exits. The probe, its configuration, token and
# salt live in /misc/heimdall, which is flash and survives reboots; the log
# and the local samples stay in /var/tmp, which is RAM.
R=/misc/heimdall
LOG=/var/tmp/heimdall-run.log
PID=/var/tmp/heimdall.pid
SUP=/var/tmp/heimdall-sup.pid

if [ -f "$SUP" ] && kill -0 "$(cat "$SUP" 2>/dev/null)" 2>/dev/null; then
	exit 0
fi
echo $$ >"$SUP"

# The log is kept under 256 KB; the newest 64 KB survive a trim.
cap_log() {
	[ -f "$LOG" ] || return 0
	[ "$(wc -c <"$LOG" 2>/dev/null || echo 0)" -gt 262144 ] || return 0
	tail -c 65536 "$LOG" >"$LOG.t" 2>/dev/null && cat "$LOG.t" >"$LOG"
	rm -f "$LOG.t"
}

# The flow collector needs the gateway's MAC address when it starts, so
# after a boot the probe waits until the gateway answers, for at most three
# minutes.
wait_gateway() {
	i=0
	while [ $i -lt 36 ]; do
		gw=$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')
		if [ -n "$gw" ] && ping -c 1 -W 2 "$gw" >/dev/null 2>&1; then
			return 0
		fi
		sleep 5
		i=$((i + 1))
	done
	echo "heimdall.sh: no answer from the gateway, starting anyway" >>"$LOG"
}

P=
start_probe() {
	cd "$R" || exit 1
	./heimdall-probe run -config config.yaml >>"$LOG" 2>&1 </dev/null &
	P=$!
	echo "$P" >"$PID"
	STARTED=$(date +%s)
}

cleanup() {
	[ -n "$P" ] && kill -TERM "$P" 2>/dev/null
	# The probe sends what it has buffered before it exits.
	i=0
	while [ -n "$P" ] && kill -0 "$P" 2>/dev/null && [ $i -lt 10 ]; do
		sleep 1
		i=$((i + 1))
	done
	rm -f "$PID" "$SUP"
	exit 0
}
trap cleanup TERM INT

wait_gateway
start_probe
while :; do
	if ! kill -0 "$P" 2>/dev/null; then
		# A probe that keeps failing at start is retried once a minute.
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
