#!/bin/sh
# Adds (or with "remove", takes out) the line in /etc/rc.local that starts
# the heimdall supervisor at boot. OpenWrt's done init script runs
# /etc/rc.local at the end of every boot; /etc is on the overlay, which
# keeps changes across reboots but not across a firmware upgrade or a
# factory reset. The first run keeps a copy of the original file in
# /misc/heimdall/rc.local.orig.
set -e
RC=/etc/rc.local
LINE='sh /misc/heimdall/scripts/heimdall.sh >/dev/null 2>&1 &  # heimdall'
[ -f /misc/heimdall/rc.local.orig ] || cp "$RC" /misc/heimdall/rc.local.orig
grep -v '# heimdall$' "$RC" >"$RC.heimdall" || true
if [ "${1:-}" != remove ]; then
	# Before the final "exit 0", or at the end when there is none.
	awk -v line="$LINE" '
		/^exit 0$/ && !done { print line; done = 1 }
		{ print }
		END { if (!done) print line }
	' "$RC.heimdall" >"$RC.heimdall2"
	mv "$RC.heimdall2" "$RC.heimdall"
fi
cat "$RC.heimdall" >"$RC"
rm -f "$RC.heimdall"
cat "$RC"
