#!/bin/sh
# EE container entrypoint, replacing the one the Execution Environment
# generates. The firmware does not start an Execution Unit at cold boot
# (its AutoStart flag is ignored); the container and this script do run at
# every boot, so the supervisor is started here and `zyeed -n heimdall`
# stays the container's foreground process, as in the generated script.
# heimdall.sh holds a lock, so a later "Activate" in the web UI does not
# start a second probe. Re-creating the Execution Environment regenerates
# this file; reinstall the Deployment Unit afterwards.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export LD_LIBRARY_PATH=/lib:/usr/lib:/lib64
/sbin/heimdall.sh >/dev/null 2>&1 &
exec zyeed -n heimdall 2>&1
