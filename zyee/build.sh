#!/bin/sh
# Build the heimdall ZyEE Deployment Unit:
#   make build-arm64 && zyee/build.sh            -> dist/heimdall_<ver>_arm_cortex-a7.ipk
#
# Contents: the linux-arm64 probe (the EX7501 runs a 64-bit kernel; a static
# Go binary needs no userland), the catalog, the configuration
# (configs/local/zyee.yaml, else configs/zyee.example.yaml) and the device's
# upload token (configs/local/<device>.token). The token makes the .ipk a
# secret: host it only on the LAN, only for the install.
#
# opkg on the router accepts only the arm_cortex-a7, all and noarch
# architectures, so the package is labelled arm_cortex-a7 whatever it
# carries. zyeed requires the URL's file name to start with "<Package>_":
# install the file under the name this script gives it.
set -eu
PKG=heimdall
ARCH=arm_cortex-a7
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HERE="$ROOT/zyee"
# opkg versions are numeric; the commit count orders builds.
VER="${VER:-0.1.$(git -C "$ROOT" rev-list --count HEAD)}"
OUT_DIR="$ROOT/dist"
OUT="$OUT_DIR/${PKG}_${VER}_${ARCH}.ipk"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

BIN="$ROOT/bin/linux-arm64/heimdall-probe"
[ -x "$BIN" ] || { echo "missing $BIN: run make build-arm64" >&2; exit 1; }
CONF="$ROOT/configs/local/zyee.yaml"
[ -f "$CONF" ] || CONF="$ROOT/configs/zyee.example.yaml"
DEVICE="$(sed -n 's/^device: *\([^ #]*\).*/\1/p' "$CONF")"
[ -n "$DEVICE" ] || { echo "$CONF sets no device" >&2; exit 1; }
TOKEN="$ROOT/configs/local/$DEVICE.token"
[ -f "$TOKEN" ] || { echo "missing $TOKEN: run scripts/new-device-token $DEVICE" >&2; exit 1; }

# Check the configuration with the catalog the package carries.
sed "s#/opt/heimdall/catalog#$ROOT/catalog#" "$CONF" >"$STAGE/check.yaml"
"$ROOT/bin/host/heimdall-probe" check -config "$STAGE/check.yaml" >/dev/null 2>"$STAGE/check.err" ||
	{ cat "$STAGE/check.err" >&2; echo "configuration check failed (build-host first?)" >&2; exit 1; }

D="$STAGE/data"
mkdir -p "$D" "$STAGE/ctrl"
cp -R "$HERE/package/data/." "$D/"
install -d "$D/opt/heimdall/bin" "$D/opt/heimdall/etc" "$D/opt/heimdall/catalog/regions"
install -m 0755 "$BIN" "$D/opt/heimdall/bin/heimdall-probe"
install -m 0644 "$ROOT/catalog/targets.yaml" "$D/opt/heimdall/catalog/targets.yaml"
for f in "$ROOT"/catalog/regions/*.yaml; do
	install -m 0644 "$f" "$D/opt/heimdall/catalog/regions/"
done
install -m 0644 "$CONF" "$D/opt/heimdall/etc/config.yaml"
install -m 0600 "$TOKEN" "$D/opt/heimdall/etc/upload.token"
chmod 0755 "$D"/sbin/*.sh "$D"/bin/*.sh

awk 1 "$HERE/package/control" | sed "s/^Version:.*/Version: $VER/" >"$STAGE/ctrl/control"
# No Installed-Size: the router's / is read-only and reports 0 KB free, so
# opkg refuses any package with a known installed size.
( cd "$STAGE/ctrl" && tar --numeric-owner --owner=0 --group=0 -czf "$STAGE/control.tar.gz" ./ )
( cd "$D" && tar --numeric-owner --owner=0 --group=0 -czf "$STAGE/data.tar.gz" ./ )
echo "2.0" >"$STAGE/debian-binary"

mkdir -p "$OUT_DIR"
rm -f "$OUT"
( cd "$STAGE" && tar --numeric-owner --owner=0 --group=0 -czf "$OUT" ./debian-binary ./data.tar.gz ./control.tar.gz )
chmod 0600 "$OUT"
echo "built $OUT (device $DEVICE, config $(basename "$CONF"))"
