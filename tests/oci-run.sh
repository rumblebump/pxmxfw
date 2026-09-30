#!/bin/sh
# Run the container image the way the README says and check it: boots with
# OpenRC, keeps the runtime's addresses, loads the firewall, serves the web
# UI on the LAN, routes and NATs a LAN client out of the WAN, and stops.
#
# Usage (as root): tests/oci-run.sh podman|docker IMAGE.oci.tar

set -eu

RT=$1 TAR=$2
NAME=pxmxfw-test-$RT
WAN=pxmxfw-test-wan LAN=pxmxfw-test-lan
case $RT in
	podman) WANNET=10.201.0 LANNET=10.202.0 ;;
	docker) WANNET=10.203.0 LANNET=10.204.0 ;;
	*) echo "usage: $0 podman|docker IMAGE.oci.tar" >&2; exit 2 ;;
esac
FW_WAN=$WANNET.2 FW_LAN=$LANNET.2

fail() { echo "FAIL ($RT): $*" >&2; "$RT" logs "$NAME" >&2 2>&1 || true; exit 1; }
cleanup() {
	"$RT" rm -f "$NAME" pxmxfw-test-client >/dev/null 2>&1 || true
	"$RT" network rm "$WAN" "$LAN" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

"$RT" load -i "$TAR"
IMAGE=pxmxfw:latest
"$RT" image inspect "$IMAGE" >/dev/null || fail "load did not name the image $IMAGE"

"$RT" network create --subnet "$WANNET.0/24" "$WAN" >/dev/null
"$RT" network create --subnet "$LANNET.0/24" "$LAN" >/dev/null

# The same options as the README. eth0 is the WAN, eth1 the LAN.
if [ "$RT" = podman ]; then
	nets="--network $WAN:interface_name=eth0,ip=$FW_WAN --network $LAN:interface_name=eth1,ip=$FW_LAN"
else
	nets="--network name=$WAN,driver-opt=com.docker.network.endpoint.ifname=eth0,gw-priority=1,ip=$FW_WAN
	      --network name=$LAN,driver-opt=com.docker.network.endpoint.ifname=eth1,ip=$FW_LAN"
fi
# shellcheck disable=SC2086
"$RT" run -d --name "$NAME" --hostname pxmxfw \
	--cap-add NET_ADMIN --cap-add NET_RAW --sysctl net.ipv4.ip_forward=1 \
	$nets "$IMAGE"

x() { "$RT" exec "$NAME" "$@"; }

echo ">> Waiting for the firewall"
for i in $(seq 60); do
	x rc-service pxmxfw-webui status >/dev/null 2>&1 && break
	[ "$i" -lt 60 ] || fail "pxmxfw-webui did not start"
	sleep 1
done
x rc-status -a || true
x cat /etc/network/interfaces
x pxmxfw status
x pxmxfw check || true

for s in pxmxfw nftables pxmxfw-webui; do
	x rc-service "$s" status >/dev/null || fail "service $s is not started"
done
x cat /usr/share/pxmxfw/TARGET | grep -qx oci || fail "TARGET is not oci"
x nft list table inet pxmxfw >/dev/null || fail "firewall table not loaded"
x ip -4 -o addr show dev eth0 | grep -q "inet $FW_WAN/" || fail "eth0 lost the WAN address"
x ip -4 -o addr show dev eth1 | grep -q "inet $FW_LAN/" || fail "eth1 lost the LAN address"
x grep -qx "eth1 addr6=none dhcp=$LANNET.100-$LANNET.200" /etc/pxmxfw/interfaces ||
	fail "eth1 is not the LAN: $(x cat /etc/pxmxfw/interfaces)"
x pxmxfw check --tsv | awk -F '\t' '$1 == "fail" { print; f = 1 } END { exit f }' >&2 ||
	fail "pxmxfw check has failures"

echo ">> Web UI on the LAN address"
x sh -c 'echo root:ci-test-pw | chpasswd'
test "$(curl -ks -o /dev/null -w '%{http_code}' "https://$FW_LAN:8443/")" = 200 || fail "web UI not reachable on $FW_LAN:8443"
curl -fksS -c /tmp/oci-jar -H 'X-Pxmxfw: 1' -d '{"user":"root","password":"ci-test-pw"}' \
	"https://$FW_LAN:8443/api?action=login" >/dev/null || fail "web UI login"
curl -fksS -b /tmp/oci-jar -H 'X-Pxmxfw: 1' "https://$FW_LAN:8443/api?action=file&name=settings" | grep -q '^WAN=eth0' ||
	fail "web UI settings"
rm -f /tmp/oci-jar
# the WAN only answers ping
curl -ks -m 5 -o /dev/null "https://$FW_WAN:8443/" && fail "web UI reachable from the WAN"

echo ">> A LAN client routes through the firewall"
# The client's default route points at the firewall. It pings the WAN
# network's gateway, which only the firewall can reach.
"$RT" run --rm --name pxmxfw-test-client --network "$LAN" --cap-add NET_ADMIN --cap-add NET_RAW "$IMAGE" \
	sh -c "ip route replace default via $FW_LAN && ping -c 3 -W 2 $WANNET.1" ||
	fail "LAN client cannot reach the WAN through the firewall"

echo ">> Stop"
t0=$(date +%s)
"$RT" stop -t 30 "$NAME" >/dev/null
[ $(( $(date +%s) - t0 )) -lt 25 ] || fail "stop took until the kill timeout"
"$RT" logs "$NAME" 2>&1 | tail -n 20

echo "OK ($RT)"
