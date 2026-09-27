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
expect_valid interfaces "$(printf '%s\nvl10 role=lan type=vlan link=eth1 vid=10 addr=10.0.10.1/24 allow=ping' "$I2")"
expect_valid interfaces "$(printf '%s\nbr0 role=lan type=bridge ports=eth2,eth3 allow=ping,dns\neth2 role=off\neth3 role=off' "$I2")"
expect_valid interfaces "$(printf '%s\nbr0 role=isolated type=bridge allow=none' "$I2")"
expect_invalid interfaces "$(printf '%s\nvl10 role=lan type=vlan link=eth1' "$I2")"              # no vid
expect_invalid interfaces "$(printf '%s\nvl10 role=lan type=vlan link=eth1 vid=4095' "$I2")"
expect_invalid interfaces "$(printf '%s\nvl10 role=lan type=vlan link=eth9 vid=10' "$I2")"      # parent not listed
expect_invalid interfaces "$(printf '%s\nvl10 role=lan vid=10' "$I2")"                          # vid without type=vlan
expect_invalid interfaces "$(printf '%s\nbr0 role=lan type=bridge ports=eth1' "$I2")"           # port has a role
expect_invalid interfaces "$(printf '%s\nbr0 role=lan type=bridge ports=eth2\nbr1 role=lan type=bridge ports=eth2\neth2 role=off' "$I2")"
expect_invalid interfaces "$(printf '%s\nbr0 role=lan type=bridge ports=eth2,' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan allow=ftp' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan allow=ping;reboot' "$I2")"
expect_invalid interfaces 'eth0 role=wan allow=ping'
expect_valid interfaces "$(printf '%s\neth2 role=lan addr=10.0.2.1/24 dhcp=10.0.2.100-10.0.2.200 lease=1d dns=1.1.1.1,9.9.9.9 gateway=none' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan lease=forever' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan dns=1.1.1.1,' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan dns=dns.example' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 role=lan gateway=10.0.2.300' "$I2")"
expect_invalid interfaces 'eth0 role=wan lease=1h'
expect_invalid interfaces 'eth0 role=wan type=bridge' 

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
grep -q 'iifname { "eth1" } tcp dport 8443 accept' "$T/default.nft" && ! grep -q 'iifname "eth0" tcp dport 8443' "$T/default.nft" && ok ||
	bad "web UI open on LAN only"
grep -q 'iifname { "eth1" } tcp dport 22 accept' "$T/default.nft" && grep -q 'iifname { "eth1" } udp dport 67 accept' "$T/default.nft" &&
	grep -q 'iifname { "eth1" } meta l4proto { tcp, udp } th dport 53 accept' "$T/default.nft" && ok || bad "first-boot LAN allows ssh, dns, dhcp"
grep -q 'iifname "eth0" icmp type echo-request accept' "$T/default.nft" && ok || bad "WAN answers ping by default"

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
grep -q 'iifname "eth0" tcp dport 8443 accept' "$T/variants.nft" && ok || bad "WEBUI_WAN opens the UI on WAN"
grep -q 'nfproto ipv4 accept' "$T/variants.nft" && bad "IPV6=yes still limits forwarding to IPv4" || ok
grep -q 'udp dport { 67, 547 }' "$T/variants.nft" && ok || bad "IPV6=yes allows DHCPv6 from inside"
grep -q 'iifname "eth0" icmp' "$T/variants.nft" && bad "WAN_PING=no still answers ping on WAN" || ok

# allow= limits what an inside interface reaches on the firewall
printf 'eth0 role=wan\neth1 role=lan\nvl10 role=lan type=vlan link=eth1 vid=10 addr=10.0.10.1/24 allow=ping\nbr0 role=isolated type=bridge ports=eth2 addr=10.0.20.1/24 allow=none dhcp=10.0.20.100-10.0.20.200\neth2 role=off\n' > "$T/etc/interfaces"
check_ruleset allow
grep -q 'iifname { "eth1", "vl10" } icmp type echo-request accept' "$T/allow.nft" && ok || bad "allow=ping: $(grep icmp "$T/allow.nft")"
grep -q 'iifname { "eth1" } tcp dport 22' "$T/allow.nft" && ok || bad "allow=ping gives no ssh"
grep -q 'iifname { "eth1", "br0" } udp dport' "$T/allow.nft" && grep -q 'iifname { "eth1", "br0" } meta l4proto' "$T/allow.nft" && ok ||
	bad "dhcp= implies dhcp and dns: $(cat "$T/allow.nft")"
grep -q 'iifname { "eth1", "vl10" } oifname { "eth1", "vl10" }' "$T/allow.nft" && ok || bad "a new lan interface is routed"

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
printf 'eth0 role=wan\neth1 role=lan dhcp=192.168.10.100-192.168.10.200 lease=1d dns=1.1.1.1,9.9.9.9 gateway=none\neth2 role=lan addr=10.0.2.1/24 allow=ping\n' > "$T/etc/interfaces"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > "$T/dnsmasq2.conf" 2>&1
grep -qx 'interface=eth1' "$T/dnsmasq2.conf" && ! grep -q 'interface=eth2' "$T/dnsmasq2.conf" && ok || bad "dnsmasq skips allow=ping interfaces"
grep -qx 'dhcp-range=set:eth1,192.168.10.100,192.168.10.200,1d' "$T/dnsmasq2.conf" && ok || bad "per-interface lease time"
grep -qx 'dhcp-option=tag:eth1,option:dns-server,1.1.1.1,9.9.9.9' "$T/dnsmasq2.conf" && ok || bad "per-interface DNS servers"
grep -qx 'dhcp-option=tag:eth1,option:router' "$T/dnsmasq2.conf" && ok || bad "gateway=none sends no router"
if command -v dnsmasq >/dev/null; then
	dnsmasq --test -C "$T/dnsmasq2.conf" >/dev/null 2>&1 && ok || bad "dnsmasq --test per-interface options: $(dnsmasq --test -C "$T/dnsmasq2.conf" 2>&1)"
fi
printf 'eth0 role=wan\neth1 role=lan allow=ping\n' > "$T/etc/interfaces"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > /dev/null 2>&1 && bad "DNSMASQ=yes with no dns interface accepted" || ok
printf 'eth0 role=wan\neth1 role=lan dhcp=192.168.10.100-192.168.10.200\neth2 role=isolated addr=10.0.2.1/24 addr6=none\n' > "$T/etc/interfaces"
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

# VLANs and bridges: created, marked as pxmxfw's, and removed when unlisted
mkdir -p "$T/sys/eth3" "$T/sys/vlold"
echo pxmxfw > "$T/sys/vlold/ifalias"
printf 'eth0 role=wan\neth1 role=lan\neth2 role=lan addr=10.0.2.1/24\nvl10 role=lan type=vlan link=eth1 vid=10 addr=10.0.10.1/24 allow=ping\nbr0 role=lan type=bridge ports=eth3,vl10b addr=10.0.30.1/24\neth3 role=off\nvl10b role=off type=vlan link=eth1 vid=11\n' > "$T/etc/interfaces"
: > "$T/ip.log"
if [ -n "$NFT" ]; then
	unshare -n sh -c "$apply_env '$PXMXFW' apply" > "$T/out" 2>&1 && ok || bad "apply with vlan and bridge: $(cat "$T/out")"
	grep -qx 'ip link add link eth1 name vl10 type vlan id 10' "$T/ip.log" && grep -qx 'ip link set dev vl10 alias pxmxfw' "$T/ip.log" &&
		ok || bad "vlan created: $(cat "$T/ip.log")"
	grep -qx 'ip link add name br0 type bridge' "$T/ip.log" && grep -qx 'ip link set dev eth3 master br0' "$T/ip.log" && ok ||
		bad "bridge created with its port"
	[ "$(grep -n 'vl10b type vlan' "$T/ip.log" | cut -d: -f1)" -lt "$(grep -n 'name br0 type bridge' "$T/ip.log" | cut -d: -f1)" ] &&
		ok || bad "a VLAN that is a bridge port is created first"
	grep -qx 'ip link del dev vlold' "$T/ip.log" && ok || bad "unlisted pxmxfw link removed"
	grep -q 'link del dev eth' "$T/ip.log" && bad "apply deleted a Proxmox NIC" || ok
fi
rm -rf "$T/sys/eth3" "$T/sys/vlold"

# ---- WireGuard ------------------------------------------------------------------

K1=aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5MTE=
K2=YW5vdGhlciB0ZXN0IGtleSBmb3IgcGVlciB0d28gMTI=
expect_valid wireguard "tunnel wg0 port=51820"
expect_valid wireguard "$(printf 'tunnel wg0 port=51820 public=fw.example.com:51820\npeer wg0 key=%s allowed=10.99.0.2/32,192.168.20.0/24 endpoint=203.0.113.9:51820 keepalive=25 # site2' "$K1")"
expect_valid wireguard "$(printf 'tunnel wg0 port=51820\npeer wg0 key=%s allowed=0.0.0.0/0,fd00::/64 endpoint=[2001:db8::1]:51820' "$K1")"
expect_invalid wireguard "tunnel wg0"
expect_invalid wireguard "tunnel wg0 port=0"
expect_invalid wireguard "$(printf 'tunnel wg0 port=51820\ntunnel wg1 port=51820')"
expect_invalid wireguard "peer wg0 key=$K1 allowed=10.0.0.0/8"                       # no tunnel line
expect_invalid wireguard "$(printf 'tunnel wg0 port=51820\npeer wg0 key=notakey allowed=10.0.0.0/8')"
expect_invalid wireguard "$(printf 'tunnel wg0 port=51820\npeer wg0 key=%s' "$K1")"   # no allowed
expect_invalid wireguard "$(printf 'tunnel wg0 port=51820\npeer wg0 key=%s allowed=10.0.0.0/33' "$K1")"
expect_invalid wireguard "$(printf 'tunnel wg0 port=51820\npeer wg0 key=%s allowed=10.0.0.0/8 endpoint=host' "$K1")"
expect_invalid wireguard "$(printf 'tunnel wg0 port=51820\npeer wg0 key=%s allowed=10.0.0.0/8;reboot' "$K1")"

fresh_etc "$T/etc"
printf 'tunnel wg0 port=51820\npeer wg0 key=%s allowed=10.99.0.2/32,192.168.20.0/24 # site2\n' "$K1" > "$T/etc/wireguard"
PXMXFW_ETC=$T/etc "$PXMXFW" render nft > /dev/null 2>&1 && bad "tunnel without an interfaces line accepted" || ok
printf 'wg0 role=lan addr=10.99.0.1/24\n' >> "$T/etc/interfaces"
check_ruleset wireguard
grep -q 'udp dport { 51820 } accept comment "wireguard"' "$T/wireguard.nft" && ok || bad "wireguard port open"
grep -q 'iifname { "eth1", "wg0" } oifname { "eth1", "wg0" }' "$T/wireguard.nft" && ok || bad "tunnel with role lan links the lans"

# apply with fake ip and wg that log what they are asked to do
cat > "$T/ipbin/wg" <<EOF
#!/bin/sh
echo "wg \$*" >> "$T/wg.log"
case "\$1" in
	genkey) echo "$K2" ;;
	pubkey) cat > /dev/null; echo "$K1" ;;
	syncconf) cp "\$3" "$T/wg-\$2.conf" ;;
	show) [ "\$2" = interfaces ] && echo "wg0 wg9" ;;
esac
EOF
chmod +x "$T/ipbin/wg"
cat > "$T/ipbin/ip" <<EOF
#!/bin/sh
echo "ip \$*" >> "$T/ip.log"
case "\$*" in
	"-4 route show dev wg0") printf '10.99.0.0/24 proto kernel scope link src 10.99.0.1\n10.99.0.2 scope link\n172.16.0.0/16 scope link\n' ;;
esac
exit 0
EOF
: > "$T/ip.log"; : > "$T/wg.log"
mkdir -p "$T/sys/wg0"
if [ -n "$NFT" ]; then
	printf 'flush ruleset\ninclude "%s"\n' "$T/etc/ruleset.nft" > "$T/main.nft"
	cp "$T/wireguard.nft" "$T/etc/ruleset.nft"
	unshare -n sh -c "$apply_env '$PXMXFW' apply" > "$T/out" 2>&1 && ok || bad "apply with a tunnel: $(cat "$T/out")"
fi
if [ -n "$NFT" ]; then
	[ "$(cat "$T/etc/wg/wg0.key" 2>/dev/null)" = "$K2" ] && ok || bad "apply creates the tunnel's private key"
	[ "$(stat -c %a "$T/etc/wg/wg0.key" 2>/dev/null)" = 600 ] && ok || bad "private key is mode 600"
	grep -q "^PrivateKey = $K2" "$T/wg-wg0.conf" && grep -q '^ListenPort = 51820' "$T/wg-wg0.conf" &&
		grep -q "^PublicKey = $K1" "$T/wg-wg0.conf" && grep -q '^AllowedIPs = 10.99.0.2/32,192.168.20.0/24' "$T/wg-wg0.conf" &&
		ok || bad "wg syncconf gets the tunnel config: $(cat "$T/wg-wg0.conf" 2>&1)"
	grep -qx 'ip -4 route replace 192.168.20.0/24 dev wg0' "$T/ip.log" && ok || bad "route to the peer's LAN: $(cat "$T/ip.log")"
	grep -qx 'ip -4 route del 172.16.0.0/16 dev wg0' "$T/ip.log" && ok || bad "stale route removed"
	grep -q 'route del 10.99.0.2 ' "$T/ip.log" && bad "wanted host route removed" || ok
	grep -q 'route del 10.99.0.0/24' "$T/ip.log" && bad "kernel route removed" || ok
	grep -qx 'ip link del dev wg9' "$T/ip.log" && ok || bad "unconfigured tunnel removed"
	grep -qx 'ip -4 addr add 10.99.0.1/24 dev wg0' "$T/ip.log" && ok || bad "tunnel address set"
	sed -i 's|^peer.*|peer wg0 key='"$K1"' allowed=0.0.0.0/0|' "$T/etc/wireguard"
	: > "$T/ip.log"
	unshare -n sh -c "$apply_env '$PXMXFW' apply" > /dev/null 2>&1
	grep -q 'route replace 0.0.0.0/0' "$T/ip.log" && bad "a peer took over the default route" || ok
fi
env PATH="$T/ipbin:$PATH" PXMXFW_ETC="$T/etc" PXMXFW_SYSNET="$T/sys" PXMXFW_PROCSYS="$T/procsys" "$PXMXFW" wg-keypair > "$T/out"
grep -qx "private=$K2" "$T/out" && grep -qx "public=$K1" "$T/out" && ok || bad "wg-keypair: $(cat "$T/out")"
env PATH="$T/ipbin:$PATH" PXMXFW_ETC="$T/etc" PXMXFW_SYSNET="$T/sys" PXMXFW_PROCSYS="$T/procsys" "$PXMXFW" status > "$T/out" 2>&1
grep -q "^wg=wg0 .* 51820 present" "$T/out" && ok || bad "status lists the tunnel: $(cat "$T/out")"
grep -q "$K2" "$T/out" && bad "status leaks the private key" || ok

# A real VLAN and bridge, when this kernel can make them (e.g. in CI)
if [ -n "$NFT" ] && unshare -n sh -c 'ip link add d0 type dummy && ip link add link d0 name d0.5 type vlan id 5 && ip link add b0 type bridge' 2>/dev/null; then
	fresh_etc "$T/etc"
	printf 'eth0 role=wan\neth1 role=lan addr=192.168.10.1/24\nvl10 role=lan type=vlan link=eth1 vid=10 addr=10.0.10.1/24 allow=ping\nbr0 role=lan type=bridge ports=eth3 addr=10.0.30.1/24\neth3 role=off\n' > "$T/etc/interfaces"
	PXMXFW_ETC=$T/etc "$PXMXFW" render nft > "$T/etc/ruleset.nft"
	cat > "$T/links.sh" <<EOF
mount -t sysfs sysfs /sys
ip link add eth1 type dummy && ip link add eth3 type dummy
export PXMXFW_ETC='$T/etc' PXMXFW_PROCSYS='$T/procsys' PXMXFW_NFT_MAIN='$T/main.nft' PXMXFW_DNSMASQ_CONF='$T/dnsmasq.conf'
'$PXMXFW' apply > /dev/null || exit 1
ip -d link show dev vl10; ip -4 addr show dev vl10; ip link show dev eth3; ip -4 addr show dev br0
sed -i '/^vl10 /d' '$T/etc/interfaces'
'$PXMXFW' apply > /dev/null || exit 1
ip link show dev vl10 2>/dev/null && echo "vl10 still there"
ip link show dev eth1 > /dev/null || echo "eth1 was removed"
EOF
	if unshare -nm sh "$T/links.sh" > "$T/out" 2>&1 &&
		grep -q 'vl10@eth1' "$T/out" && grep -q 'vlan protocol 802.1Q id 10' "$T/out" && grep -q '10.0.10.1/24' "$T/out" &&
		grep -q 'master br0' "$T/out" && grep -q '10.0.30.1/24' "$T/out" &&
		! grep -q 'still there\|was removed' "$T/out"; then ok
	else bad "real VLAN and bridge: $(cat "$T/out")"; fi
else
	echo "note: cannot create VLAN or bridge interfaces here, skipping that test"
fi

# A real tunnel, when this kernel and system can make one (e.g. in CI)
if [ -n "$NFT" ] && command -v wg >/dev/null && [ "$(command -v wg)" != "$T/ipbin/wg" ] &&
	unshare -n sh -c 'ip link add dev wgtest type wireguard' 2>/dev/null; then
	fresh_etc "$T/etc"
	printf 'tunnel wg0 port=51820\npeer wg0 key=%s allowed=10.99.0.2/32,192.168.20.0/24 # site2\n' "$(wg genkey | wg pubkey)" > "$T/etc/wireguard"
	printf 'eth0 role=wan\nwg0 role=lan addr=10.99.0.1/24\n' > "$T/etc/interfaces"
	PXMXFW_ETC=$T/etc "$PXMXFW" render nft > "$T/etc/ruleset.nft"
	# Own sysfs, so /sys/class/net shows this netns' interfaces
	if unshare -nm sh -c "mount -t sysfs sysfs /sys && PXMXFW_ETC='$T/etc' PXMXFW_PROCSYS='$T/procsys' PXMXFW_NFT_MAIN='$T/main.nft' PXMXFW_DNSMASQ_CONF='$T/dnsmasq.conf' '$PXMXFW' apply >/dev/null &&
		wg show wg0 && ip -4 addr show dev wg0 && ip -4 route show dev wg0" > "$T/out" 2>&1 &&
		grep -q 'listening port: 51820' "$T/out" && grep -q '10.99.0.1/24' "$T/out" && grep -q '192.168.20.0/24' "$T/out"; then ok
	else bad "real WireGuard tunnel: $(cat "$T/out")"; fi
else
	echo "note: cannot create WireGuard interfaces here, skipping the real tunnel test"
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

# ---- extra packages ----------------------------------------------------------

expect_valid packages "$(printf 'nano\nopenssh # remote access\nbind-tools\npy3-yaml\nlibstdc++')"
expect_invalid packages "nano; reboot"
expect_invalid packages "two names"
expect_invalid packages "-flag"
expect_invalid packages "Upper"

# A fake apk that records what it was asked to do
cat > "$T/fakebin/apk" <<EOF
#!/bin/sh
echo "\$*" >> "$T/apk.log"
case \$1 in
	info) printf '%s\n' nano-8.4-r0 openssh-server-10.0_p1-r7 libstdc++-14.2.0-r6 ;;
	search) echo "nano-8.4-r0 - Enhanced clone of the Pico text editor" ;;
	add|del) case "\$*" in *broken*) exit 1 ;; esac ;;
esac
EOF
chmod +x "$T/fakebin/apk"
fresh_etc "$T/etc"
pkg() { PATH="$T/fakebin:$PATH" PXMXFW_ETC=$T/etc "$PXMXFW" "$@"; }
: > "$T/apk.log"
pkg pkg-add nano 'libstdc++' > /dev/null && grep -qx 'add --update-cache -- nano libstdc++' "$T/apk.log" && ok || bad "pkg-add runs apk add"
pkg pkg-add nano > /dev/null && [ "$(grep -cx nano "$T/etc/packages")" = 1 ] && ok || bad "pkg-add lists a package once"
pkg pkg-list | grep -qx 'nano 8.4-r0' && pkg pkg-list | grep -qx 'libstdc++ 14.2.0-r6' && ok || bad "pkg-list shows versions: $(pkg pkg-list)"
pkg pkg-add 'nano;reboot' > /dev/null 2>&1 && bad "pkg-add accepts a bad name" || ok
pkg pkg-add broken > /dev/null 2>&1 && bad "pkg-add ignores apk failure" || ok
grep -qx broken "$T/etc/packages" && bad "failed install is listed" || ok
pkg pkg-del nftables > /dev/null 2>&1 && bad "pkg-del removes a base package" || ok
grep -q 'del -- nftables' "$T/apk.log" && bad "apk del ran for a base package" || ok
pkg pkg-del nano > /dev/null && ! grep -qx nano "$T/etc/packages" && grep -qx 'libstdc++' "$T/etc/packages" && ok ||
	bad "pkg-del removes only that line: $(cat "$T/etc/packages")"
grep -q '^# Extra Alpine packages' "$T/etc/packages" && ok || bad "pkg-del keeps comments"
printf 'openssh\n' >> "$T/etc/packages"
: > "$T/apk.log"
pkg pkg-sync > /dev/null && grep -qx 'add --update-cache -- libstdc++ openssh' "$T/apk.log" && ok || bad "pkg-sync installs the list: $(cat "$T/apk.log")"
pkg pkg-search nano | grep -q '^nano-8.4-r0 - ' && ok || bad "pkg-search"
pkg pkg-search '*' > /dev/null 2>&1 && bad "pkg-search accepts a pattern" || ok

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
