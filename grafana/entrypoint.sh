#!/bin/sh
# ECS passes the Cloudflare origin certificate and key as environment
# variables from SSM; Grafana reads them from files.
set -eu
umask 077
mkdir -p /tmp/tls
printf '%s\n' "$TLS_CERT" >/tmp/tls/cert.pem
printf '%s\n' "$TLS_KEY" >/tmp/tls/key.pem
unset TLS_CERT TLS_KEY
exec /run.sh "$@"
