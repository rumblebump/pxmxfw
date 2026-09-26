#!/bin/sh
# Tests for the pxmxfw scripts. Runs on any Linux with a POSIX shell.
#
#   tests/run.sh            use /bin/sh
#   SH="busybox ash" tests/run.sh
#
# With root and nft installed, generated rulesets are also checked (and
# loaded) by the kernel inside a throwaway network namespace.

set -u
cd "$(dirname "$0")/.." || exit 1
SRC=$(pwd)
SH=${SH:-sh}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
pass=0 fail=0

ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

# Wrapper so the CGI and tests can call pxmxfw like the installed command
cat > "$T/pxmxfw" <<EOF
#!/bin/sh
PXMXFW_LIB=$SRC/rootfs/usr/lib/pxmxfw exec $SH $SRC/rootfs/usr/sbin/pxmxfw "\$@"
EOF
chmod +x "$T/pxmxfw"
PXMXFW=$T/pxmxfw

NFT=
if [ "$(id -u)" = 0 ] && command -v nft >/dev/null && command -v unshare >/dev/null &&
	unshare -n true 2>/dev/null; then
	NFT=1
else
	echo "note: not root or no nft/unshare, skipping kernel checks of the ruleset"
fi

# fresh_etc DIR: a copy of the default config
fresh_etc() { rm -rf "$1"; mkdir -p "$1"; cp "$SRC"/rootfs/etc/pxmxfw/* "$1"/; }

# ---- validation ------------------------------------------------------------

expect_valid() { # kind content
	printf '%s\n' "$2" > "$T/v"
	if "$PXMXFW" validate "$1" "$T/v" >/dev/null 2>&1; then ok; else bad "$1 should accept: $2"; fi
}
expect_invalid() {
	printf '%s\n' "$2" > "$T/v"
	if "$PXMXFW" validate "$1" "$T/v" >/dev/null 2>&1; then bad "$1 should reject: $2"; else ok; fi
}

expect_valid settings 'IPV6=yes'
expect_valid settings 'DNS_UPSTREAM=1.1.1.1 9.9.9.9'
expect_valid settings 'DHCP_LEASE=infinite # comment'
expect_invalid settings 'NAT=yes; reboot'
expect_invalid settings 'DNS_DOMAIN=$(reboot)'
expect_invalid settings 'NAT=maybe'
expect_invalid settings 'WEBUI_PORT=70000'
expect_invalid settings 'DNS_UPSTREAM=1.1.1.300'
expect_invalid settings 'FOO=bar'

I2=$(printf 'eth0 role=wan\neth1 role=lan')
expect_valid interfaces "$I2"
expect_valid interfaces "$(printf '%s\neth2 role=isolated addr=10.0.2.1/24 addr6=fd00:2::1/64 dhcp=10.0.2.100-10.0.2.200 # guests' "$I2")"
expect_valid interfaces "$(printf '%s\neth3 role=off addr=none addr6=none' "$I2")"
expect_invalid interfaces 'eth1 role=lan'                       # no wan
expect_invalid interfaces "$(printf '%s\neth2 role=wan' "$I2")"  # two wans
expect_invalid interfaces "$(printf '%s\neth1 role=off' "$I2")"  # listed twice
expect_invalid interfaces 'eth0 role=wan addr=10.0.0.1/24'      # WAN belongs to Proxmox
expect_invalid interfaces "$(printf '%s\neth2 role=lan addr=10.0.2.1' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan addr=10.0.2.1/33' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan addr6=fd00::1' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan dhcp=10.0.2.100' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=router' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan mtu=9000' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2;x role=lan' "$I2")"

expect_valid services 'tcp 22'
expect_valid services 'udp 60000-60100 # mosh'
expect_invalid services 'tcp 0'
expect_invalid services 'tcp 100-10'
expect_invalid services 'icmp 1'
expect_invalid services 'tcp 22 accept'
expect_invalid services 'tcp *'
expect_invalid services 'tcp 22 # "quoted"'

expect_valid forwards 'tcp 443 192.168.10.10 443 # web server'
expect_invalid forwards 'tcp 443 192.168.10.10'
expect_invalid forwards 'tcp 443 192.168.10.256 443'
expect_invalid forwards 'tcp 443 host 443'

expect_valid hosts '192.168.10.10 nas'
expect_valid hosts '192.168.10.10 nas 52:54:00:12:34:56'
expect_invalid hosts '192.168.10.10 -nas'
expect_invalid hosts '192.168.10.10 nas 52:54:00:12:34'
expect_invalid hosts '192.168.10.10 nas,evil'

# ---- ruleset rendering --------------------------------------------------------

# check_ruleset NAME: render with $T/etc and have the kernel check it
check_ruleset() {
	if ! PXMXFW_ETC=$T/etc "$PXMXFW" render nft > "$T/$1.nft" 2> "$T/err"; then
		bad "render $1: $(cat "$T/err")"; return
	fi
	ok
	[ -n "$NFT" ] || return
	printf 'flush ruleset\ninclude "%s"\n' "$T/$1.nft" > "$T/main.nft"
	if unshare -n sh -c "nft -f '$T/main.nft' && nft list table inet pxmxfw" > "$T/err" 2>&1; then ok
	else bad "nft rejected $1: $(cat "$T/err")"; fi
}

fresh_etc "$T/etc"
check_ruleset default
grep -q 'oifname "eth0" masquerade' "$T/default.nft" && ok || bad "default has NAT"
grep -q 'iifname { "eth1" } oifname "eth0" meta nfproto ipv4 accept' "$T/default.nft" && ok || bad "default routes LAN to WAN, IPv4 only"
grep -q 'iifname { "eth1" } tcp dport { 22, 53, 8080 }' "$T/default.nft" && ! grep -q 'iifname "eth0" tcp dport 8080' "$T/default.nft" && ok ||
	bad "web UI open on LAN only"

printf 'tcp 22 # ssh\nudp 60000-60100\n' >> "$T/etc/services"
printf 'tcp 8443 192.168.10.10 443 # web\nudp 51820 192.168.10.11 51820\n' >> "$T/etc/forwards"
printf 'eth2 role=lan addr=10.0.2.1/24\neth3 role=isolated addr=10.0.3.1/24\neth4 role=off\n' >> "$T/etc/interfaces"
check_ruleset rules
grep -q 'iifname "eth0" tcp dport 8443 dnat ip to 192.168.10.10:443 comment "web"' "$T/rules.nft" && ok || bad "forward rendered"
grep -q 'iifname { "eth1", "eth2" } oifname { "eth1", "eth2" }' "$T/rules.nft" && ok || bad "lans reach each other"
grep -q 'iifname { "eth1", "eth2", "eth3" } oifname "eth0"' "$T/rules.nft" && ok || bad "lan and isolated reach WAN"
grep -q 'eth4' "$T/rules.nft" && bad "role=off interface appears in rules" || ok

sed -i 's/^NAT=.*/NAT=no/; s/^WAN_PING=.*/WAN_PING=no/; s/^WEBUI_WAN=.*/WEBUI_WAN=yes/; s/^IPV6=.*/IPV6=yes/' "$T/etc/pxmxfw.conf"
check_ruleset variants
grep -q masquerade "$T/variants.nft" && bad "NAT=no still masquerades" || ok
grep -q 'iifname "eth0" tcp dport 8080 accept' "$T/variants.nft" && ok || bad "WEBUI_WAN opens the UI on WAN"
grep -q 'nfproto ipv4 accept' "$T/variants.nft" && bad "IPV6=yes still limits forwarding to IPv4" || ok
grep -q 'udp dport { 53, 67, 547 }' "$T/variants.nft" && ok || bad "IPV6=yes allows DHCPv6 from inside"

printf 'eth0 role=wan\neth1 role=off\n' > "$T/etc/interfaces"
check_ruleset nolan
grep -q '{  }' "$T/nolan.nft" && bad "empty interface set in ruleset" || ok

# ---- dnsmasq ------------------------------------------------------------------

fresh_etc "$T/etc"
sed -i 's/^DNSMASQ=.*/DNSMASQ=yes/' "$T/etc/pxmxfw.conf"
printf 'eth0 role=wan\neth1 role=lan dhcp=192.168.10.100-192.168.10.200\neth2 role=isolated addr=10.0.2.1/24 addr6=none\n' > "$T/etc/interfaces"
printf '192.168.10.10 nas 52:54:00:12:34:56\n' > "$T/etc/hosts"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > "$T/dnsmasq.conf" 2>&1 && ok || bad "render dnsmasq: $(cat "$T/dnsmasq.conf")"
grep -qx 'interface=eth1' "$T/dnsmasq.conf" && grep -qx 'interface=eth2' "$T/dnsmasq.conf" && ok || bad "dnsmasq serves every inside interface"
grep -qx 'dhcp-range=set:eth1,192.168.10.100,192.168.10.200,12h' "$T/dnsmasq.conf" && ok || bad "dnsmasq DHCP range"
grep -q 'ra-stateless' "$T/dnsmasq.conf" && bad "IPV6=no still sends router advertisements" || ok
grep -qx 'dhcp-host=52:54:00:12:34:56,192.168.10.10,nas' "$T/dnsmasq.conf" && ok || bad "dnsmasq static lease"
sed -i 's/^IPV6=.*/IPV6=yes/' "$T/etc/pxmxfw.conf"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > "$T/dnsmasq.conf"
grep -qx 'dhcp-range=::,constructor:eth1,ra-stateless,ra-names' "$T/dnsmasq.conf" && ! grep -q 'constructor:eth2' "$T/dnsmasq.conf" &&
	ok || bad "IPv6 router advertisements where addr6 is not none"
if command -v dnsmasq >/dev/null; then
	dnsmasq --test -C "$T/dnsmasq.conf" >/dev/null 2>&1 && ok || bad "dnsmasq --test: $(dnsmasq --test -C "$T/dnsmasq.conf" 2>&1)"
fi
printf 'eth0 role=wan\n' > "$T/etc/interfaces"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > /dev/null 2>&1 && bad "DNSMASQ=yes without inside interface accepted" || ok

# ---- first boot and interface detection ------------------------------------------

boot_env() { env PXMXFW_ETC="$T/etc" PXMXFW_SYSNET="$T/sys" PXMXFW_NET_INTERFACES="$T/interfaces" "$@"; }
mkdir -p "$T/sys/eth0" "$T/sys/eth1" "$T/sys/eth2" "$T/sys/lo"
cat > "$T/interfaces" <<'EOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp

auto eth1
iface eth1 inet static
	address 192.168.50.1/24
EOF
fresh_etc "$T/etc"
if boot_env "$PXMXFW" firstboot > "$T/out" 2>&1; then ok
else bad "firstboot: $(cat "$T/out")"; fi
grep -qx 'eth0 role=wan' "$T/etc/interfaces" && ok || bad "firstboot: eth0 is WAN"
grep -qx 'eth1 role=lan addr6=none dhcp=192.168.50.100-192.168.50.200' "$T/etc/interfaces" && ok ||
	bad "firstboot: eth1 is LAN with a DHCP range from Proxmox's address: $(cat "$T/etc/interfaces")"
grep -qx 'eth2 role=off addr=none addr6=none' "$T/etc/interfaces" && ok || bad "firstboot: other NICs start off"
grep -q '^lo' "$T/etc/interfaces" && bad "firstboot lists lo" || ok
grep -qx 'DNSMASQ=no' "$T/etc/pxmxfw.conf" && grep -qx 'IPV6=no' "$T/etc/pxmxfw.conf" && ok || bad "firstboot leaves dnsmasq and IPv6 off"
[ -e "$T/etc/.firstboot-done" ] && ok || bad "firstboot writes its marker"
boot_env "$PXMXFW" validate interfaces "$T/etc/interfaces" && ok || bad "firstboot output is valid"
cp "$T/etc/interfaces" "$T/before"
boot_env "$PXMXFW" firstboot > /dev/null 2>&1
cmp -s "$T/before" "$T/etc/interfaces" && ok || bad "firstboot runs only once"

mkdir "$T/sys/eth3"
boot_env "$PXMXFW" detect > "$T/out" 2>&1
grep -qx 'eth3 role=off addr=none addr6=none' "$T/etc/interfaces" && grep -q eth3 "$T/out" && ok || bad "detect adds a new NIC as off"
boot_env "$PXMXFW" detect > "$T/out" 2>&1
[ "$(grep -c '^eth3 ' "$T/etc/interfaces")" = 1 ] && ok || bad "detect adds each NIC once"

# old-style netmask, and a single NIC
printf 'iface eth1 inet static\n\taddress 10.20.0.1\n\tnetmask 255.255.0.0\n' > "$T/interfaces"
fresh_etc "$T/etc"
boot_env "$PXMXFW" firstboot > /dev/null 2>&1
grep -q 'dhcp=10.20.0.100-10.20.0.200' "$T/etc/interfaces" && ok || bad "netmask style address"
rm -rf "$T/sys/eth1" "$T/sys/eth2" "$T/sys/eth3"
fresh_etc "$T/etc"
boot_env "$PXMXFW" firstboot > /dev/null 2>&1
! grep -q 'role=lan' "$T/etc/interfaces" && grep -qx 'WEBUI_WAN=yes' "$T/etc/pxmxfw.conf" && ok ||
	bad "single NIC: no LAN, UI reachable on WAN"

# ---- apply --------------------------------------------------------------------

# Fake ip(8) that logs what pxmxfw asks for; eth2 currently has 10.9.9.9/24
mkdir -p "$T/ipbin"
cat > "$T/ipbin/ip" <<EOF
#!/bin/sh
echo "ip \$*" >> "$T/ip.log"
case "\$*" in
	"-4 -o addr show dev eth2") echo "3: eth2    inet 10.9.9.9/24 brd 10.9.9.255 scope global eth2" ;;
esac
exit 0
EOF
chmod +x "$T/ipbin/ip"
mkdir -p "$T/sys/eth1" "$T/sys/eth2" "$T/procsys/net/ipv4" "$T/procsys/net/ipv6/conf/all" "$T/procsys/net/ipv6/conf/eth0"
fresh_etc "$T/etc"
printf 'eth0 role=wan\neth1 role=lan\neth2 role=lan addr=10.0.2.1/24\n' > "$T/etc/interfaces"
printf 'flush ruleset\ninclude "%s"\n' "$T/etc/ruleset.nft" > "$T/main.nft"
PXMXFW_ETC=$T/etc "$PXMXFW" render nft > "$T/etc/ruleset.nft"
printf 'tcp 22\n' > "$T/etc/services"
: > "$T/ip.log"
apply_env="PATH='$T/ipbin:$PATH' PXMXFW_ETC='$T/etc' PXMXFW_SYSNET='$T/sys' PXMXFW_PROCSYS='$T/procsys' PXMXFW_NFT_MAIN='$T/main.nft' PXMXFW_DNSMASQ_CONF='$T/dnsmasq.conf'"
if [ -n "$NFT" ]; then
	if unshare -n sh -c "$apply_env '$PXMXFW' apply && nft list chain inet pxmxfw input" > "$T/out" 2>&1 &&
		grep -q 'tcp dport 22 accept' "$T/out"; then ok
	else bad "apply: $(cat "$T/out")"; fi
	grep -qx 'ip -4 addr del 10.9.9.9/24 dev eth2' "$T/ip.log" && grep -qx 'ip -4 addr add 10.0.2.1/24 dev eth2' "$T/ip.log" &&
		ok || bad "apply replaces the address on eth2: $(cat "$T/ip.log")"
	grep -q 'addr .* dev eth1' "$T/ip.log" && bad "apply touched eth1, which Proxmox manages" || ok
	[ "$(cat "$T/procsys/net/ipv4/ip_forward")" = 1 ] && [ "$(cat "$T/procsys/net/ipv6/conf/all/forwarding")" = 0 ] &&
		ok || bad "apply: IPv4 forwarding on, IPv6 off"
fi

# ---- checks -------------------------------------------------------------------

# A fake nft whose NAT support is missing, as on a host without nft_masq
mkdir -p "$T/fakebin"
cat > "$T/fakebin/nft" <<'EOF'
#!/bin/sh
[ "$1" = -c ] && grep -q masquerade "$3" && { echo "Error: Could not process rule: No such file or directory" >&2; exit 1; }
exit 0
EOF
chmod +x "$T/fakebin/nft"
fresh_etc "$T/etc"
PATH="$T/fakebin:$PATH" PXMXFW_ETC=$T/etc "$PXMXFW" check > "$T/out" 2>&1
grep -q '^fail  NAT (masquerade)' "$T/out" && ok || bad "check reports missing NAT: $(cat "$T/out")"
grep -q '^ok    Port forwarding' "$T/out" && ok || bad "check keeps other features ok"
grep -q '^  modprobe -a .*nft_masq' "$T/out" && grep -q '/etc/modules-load.d/pxmxfw.conf' "$T/out" && ok ||
	bad "check prints host modprobe commands"
PATH="$T/fakebin:$PATH" PXMXFW_ETC=$T/etc "$PXMXFW" check --tsv | awk -F '\t' 'NF != 5 { exit 1 }' && ok ||
	bad "check --tsv has 5 fields per line"

# ---- CGI --------------------------------------------------------------------

cgi() { # METHOD QUERY [BODY] [header value]
	body=${3:-}
	printf '%s' "$body" | env REQUEST_METHOD="$1" QUERY_STRING="$2" CONTENT_LENGTH="${#body}" \
		HTTP_X_PXMXFW="${4:-}" PXMXFW="$PXMXFW" PXMXFW_ETC="$T/etc" \
		$SH "$SRC/rootfs/usr/share/pxmxfw/www/cgi-bin/api"
}
fresh_etc "$T/etc"
cgi GET 'action=file&name=settings' | grep -q '^NAT=yes' && ok || bad "cgi reads settings"
cgi GET 'action=file&name=../../etc/shadow' | head -n1 | grep -q '^Status: 400' && ok || bad "cgi rejects unknown files"
cgi POST 'action=save&name=services' 'tcp 22' | head -n1 | grep -q '^Status: 403' && ok || bad "cgi POST needs X-Pxmxfw"
cgi POST 'action=save&name=services' 'tcp 22 # ssh' 1 | head -n1 | grep -q '^Status: 200' && ok || bad "cgi saves"
grep -qx 'tcp 22 # ssh' "$T/etc/services" && ok || bad "cgi wrote the file"
out=$(cgi POST 'action=save&name=services' 'tcp 22; reboot' 1)
printf '%s\n' "$out" | head -n1 | grep -q '^Status: 422' && ok || bad "cgi rejects invalid rules"
printf '%s\n' "$out" | grep -q '^line 1: ' && ok || bad "cgi reports the line number"
grep -qx 'tcp 22 # ssh' "$T/etc/services" && ok || bad "invalid save leaves the file alone"
find "$T/etc" -name '*.new.*' | grep -q . && bad "cgi leaves temp files" || ok
cgi DELETE 'action=status' | head -n1 | grep -q '^Status: 405' && ok || bad "cgi rejects other methods"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
