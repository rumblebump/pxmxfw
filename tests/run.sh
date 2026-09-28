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

I2=$(printf 'eth0\neth1')
expect_valid interfaces "$I2"
expect_valid interfaces "$(printf '%s\neth2 addr=10.0.2.1/24 addr6=fd00:2::1/64 dhcp=10.0.2.100-10.0.2.200 # guests' "$I2")"
expect_valid interfaces "$(printf '%s\neth3 addr=none addr6=none' "$I2")"
expect_invalid interfaces 'eth1'                                # no WAN (eth0)
expect_invalid interfaces "$(printf '%s\neth1 addr=none' "$I2")" # listed twice
expect_invalid interfaces 'eth0 addr=10.0.0.1/24'               # WAN belongs to Proxmox
expect_invalid interfaces "$(printf 'eth0 role=wan\neth1 role=lan')" # roles are gone
expect_invalid interfaces "$(printf '%s\neth2 allow=ping' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 addr=10.0.2.1' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 addr=10.0.2.1/33' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 addr6=fd00::1' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 dhcp=10.0.2.100' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 mtu=9000' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2;x' "$I2")"
expect_valid interfaces "$(printf '%s\nvl10 type=vlan link=eth1 vid=10 addr=10.0.10.1/24' "$I2")"
expect_valid interfaces "$(printf '%s\nbr0 type=bridge ports=eth2,eth3\neth2 addr=none\neth3' "$I2")"
expect_valid interfaces "$(printf '%s\nbr0 type=bridge' "$I2")"
expect_invalid interfaces "$(printf '%s\nvl10 type=vlan link=eth1' "$I2")"              # no vid
expect_invalid interfaces "$(printf '%s\nvl10 type=vlan link=eth1 vid=4095' "$I2")"
expect_invalid interfaces "$(printf '%s\nvl10 type=vlan link=eth9 vid=10' "$I2")"      # parent not listed
expect_invalid interfaces "$(printf '%s\nvl10 vid=10' "$I2")"                          # vid without type=vlan
expect_invalid interfaces "$(printf '%s\nbr0 type=bridge ports=eth0' "$I2")"           # WAN as a port
expect_invalid interfaces "$(printf '%s\nbr0 type=bridge ports=eth2\neth2 addr=10.0.2.1/24' "$I2")" # port with an address
expect_invalid interfaces "$(printf '%s\nbr0 type=bridge ports=eth2\nbr1 type=bridge ports=eth2\neth2' "$I2")"
expect_invalid interfaces "$(printf '%s\nbr0 type=bridge ports=eth2,' "$I2")"
expect_valid interfaces "$(printf '%s\neth2 addr=10.0.2.1/24 dhcp=10.0.2.100-10.0.2.200 lease=1d dns=1.1.1.1,9.9.9.9 gateway=none' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 lease=forever' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 dns=1.1.1.1,' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 dns=dns.example' "$I2")"
expect_invalid interfaces "$(printf '%s\neth2 gateway=10.0.2.300' "$I2")"
expect_invalid interfaces 'eth0 lease=1h'
expect_invalid interfaces 'eth0 type=bridge'
expect_invalid settings 'NAT=yes'   # now a masquerade rule
expect_valid settings 'WAN=ens18'
expect_valid settings 'OUTPUT_POLICY=drop'
expect_invalid settings 'OUTPUT_POLICY=reject'

expect_valid rules 'input accept in=eth1 service=ssh,webui # admin'
expect_valid rules 'input accept in=eth1,eth2 src=10.0.0.0/8 proto=tcp dport=22,443,8000-8100'
expect_valid rules 'input drop in=eth0 src=2001:db8::/32,2001:db8:1::1'
expect_valid rules 'forward accept in=eth1 out=eth0 src=192.168.10.0/24 dst=1.1.1.1 proto=udp sport=1024-65535 dport=53'
expect_valid rules 'forward reject proto=tcp,udp dport=25'
expect_valid rules 'forward accept'
expect_valid rules 'output drop out=eth0 proto=icmp'
expect_valid rules 'masquerade out=eth0 src=192.168.10.0/24'
expect_valid rules 'dnat in=eth0 proto=tcp dport=443 to=192.168.10.10:8443 src=203.0.113.0/24 # web'
expect_valid rules 'dnat in=eth0 proto=udp dport=60000-60100 to=192.168.10.11'
expect_invalid rules 'input allow in=eth1'
expect_invalid rules 'input accept out=eth1'
expect_invalid rules 'output accept in=eth1'
expect_invalid rules 'input accept service=ftp'
expect_invalid rules 'input accept service=ssh proto=tcp dport=22'
expect_invalid rules 'forward accept service=ssh'
expect_invalid rules 'forward accept dport=22'                  # ports need a protocol
expect_invalid rules 'forward accept proto=icmp dport=22'
expect_invalid rules 'forward accept proto=gre'
expect_invalid rules 'forward accept src=10.0.0.0/33'
expect_invalid rules 'forward accept src=10.0.0.0/8,fd00::/8'
expect_invalid rules 'forward accept src=10.0.0.0/8 dst=fd00::/8'
expect_invalid rules 'forward accept dport=0 proto=tcp'
expect_invalid rules 'forward accept proto=tcp dport=100-10'
expect_invalid rules 'forward accept in=eth1;reboot'
expect_invalid rules 'forward accept in=eth1 # "quoted"'
expect_invalid rules 'forward accept to=10.0.0.1'
expect_invalid rules 'masquerade'
expect_invalid rules 'masquerade out=eth0 proto=tcp'
expect_invalid rules 'masquerade out=eth0 src=fd00::/8'
expect_invalid rules 'dnat proto=tcp dport=443 to=192.168.10.10'   # needs in=
expect_invalid rules 'dnat in=eth0 dport=443 to=192.168.10.10'
expect_invalid rules 'dnat in=eth0 proto=tcp dport=443 to=host'
expect_invalid rules 'dnat in=eth0 proto=tcp dport=1000-2000 to=192.168.10.10:80'
expect_invalid rules 'dnat in=eth0 proto=tcp dport=80,81 to=192.168.10.10'
expect_invalid rules 'accept in=eth0'
# interface names are checked against the interfaces file
mkdir -p "$T/names"; printf 'eth0\neth1\n' > "$T/names/interfaces"
printf 'forward accept in=eth1 out=eth9\n' > "$T/v"
PXMXFW_ETC=$T/names "$PXMXFW" validate rules "$T/v" > /dev/null 2>&1 && bad "rule naming an unknown interface accepted" || ok
printf 'forward accept in=eth1 out=eth0\n' > "$T/v"
PXMXFW_ETC=$T/names "$PXMXFW" validate rules "$T/v" > /dev/null 2>&1 && ok || bad "rule naming listed interfaces rejected"

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
grep -q 'meta nfproto ipv4 oifname { "eth0" } masquerade' "$T/default.nft" && ok || bad "default has NAT"
grep -q 'iifname { "eth1" } oifname { "eth0" } accept' "$T/default.nft" && ok || bad "default routes LAN to WAN"
grep -q 'meta nfproto ipv6 drop' "$T/default.nft" && ok || bad "IPV6=no routes no IPv6"
grep -q 'iifname { "eth1" } tcp dport 8443 accept' "$T/default.nft" && ! grep -q 'iifname { "eth0" } tcp dport 8443' "$T/default.nft" && ok ||
	bad "web UI open on LAN only"
grep -q 'iifname { "eth1" } tcp dport 22 accept' "$T/default.nft" && grep -q 'iifname { "eth1" } udp dport 67 accept' "$T/default.nft" &&
	grep -q 'iifname { "eth1" } meta l4proto { tcp, udp } th dport 53 accept' "$T/default.nft" && ok || bad "default LAN allows ssh, dns, dhcp"
grep -q 'iifname { "eth0" } icmp type echo-request accept' "$T/default.nft" && ok || bad "WAN answers ping by default"
grep -q 'policy accept;' "$T/default.nft" && grep -q 'hook output' "$T/default.nft" && ok || bad "output chain accepts by default"

cat >> "$T/etc/rules" <<'RULES'
input accept in=eth0 proto=tcp dport=22 # ssh
input accept in=eth0 proto=udp dport=60000-60100
input accept in=eth2 src=10.0.2.0/24 service=ssh # admins
input reject in=eth0 src=2001:db8::/32 proto=tcp dport=25
forward accept in=eth1,eth2 out=eth1,eth2 # lan to lan
forward drop in=eth3 out=eth0 dst=10.0.0.0/8,192.168.0.0/16
forward accept in=eth3 out=eth0 proto=tcp,udp sport=1024-65535 dport=53,853
output drop out=eth0 proto=icmp
dnat in=eth0 proto=tcp dport=8443 to=192.168.10.10:443 # web
dnat in=eth0 proto=udp dport=51820 to=192.168.10.11:51820 src=203.0.113.0/24
masquerade out=eth2 src=10.0.3.0/24
RULES
printf 'eth2 addr=10.0.2.1/24\neth3 addr=10.0.3.1/24\neth4\n' >> "$T/etc/interfaces"
check_ruleset rules
grep -q 'iifname { "eth0" } tcp dport 8443 dnat ip to 192.168.10.10:443 comment "web"' "$T/rules.nft" && ok || bad "dnat rendered"
grep -q 'iifname { "eth0" } ip saddr 203.0.113.0/24 udp dport 51820 dnat ip to 192.168.10.11:51820' "$T/rules.nft" && ok || bad "dnat with src"
grep -q 'iifname { "eth1", "eth2" } oifname { "eth1", "eth2" } accept comment "lan to lan"' "$T/rules.nft" && ok || bad "forward between interfaces"
grep -q 'iifname { "eth2" } ip saddr 10.0.2.0/24 tcp dport 22 accept comment "admins"' "$T/rules.nft" && ok || bad "service from a subnet"
grep -q 'iifname { "eth0" } ip6 saddr 2001:db8::/32 tcp dport 25 reject' "$T/rules.nft" && ok || bad "IPv6 source"
grep -q 'ip daddr { 10.0.0.0/8, 192.168.0.0/16 } drop' "$T/rules.nft" && ok || bad "destination list"
grep -q 'meta l4proto { tcp, udp } th sport 1024-65535 th dport { 53, 853 } accept' "$T/rules.nft" && ok || bad "tcp and udp with both ports"
grep -q 'oifname { "eth0" } meta l4proto { icmp, ipv6-icmp } drop' "$T/rules.nft" && ok || bad "output rule"
grep -q 'oifname { "eth2" } ip saddr 10.0.3.0/24 masquerade' "$T/rules.nft" && ok || bad "masquerade with src"
[ "$(grep -n 'lan to lan' "$T/rules.nft" | cut -d: -f1)" -gt "$(grep -n 'LAN to WAN' "$T/rules.nft" | cut -d: -f1)" ] &&
	[ "$(grep -n 'ip daddr {' "$T/rules.nft" | cut -d: -f1)" -lt "$(grep -n 'th dport { 53, 853 }' "$T/rules.nft" | cut -d: -f1)" ] &&
	ok || bad "rules keep the file's order"
grep -q 'eth4' "$T/rules.nft" && bad "an interface without rules appears in the ruleset" || ok

sed -i 's/^OUTPUT_POLICY=.*/OUTPUT_POLICY=drop/; s/^IPV6=.*/IPV6=yes/' "$T/etc/pxmxfw.conf"
sed -i 's/^eth1$/eth1 addr=192.168.10.1\/24 dhcp=192.168.10.100-192.168.10.200/' "$T/etc/interfaces"
check_ruleset variants
grep -q 'nfproto ipv6 drop' "$T/variants.nft" && bad "IPV6=yes still drops routed IPv6" || ok
grep -q 'udp dport { 67, 547 }' "$T/variants.nft" && ok || bad "IPV6=yes allows DHCPv6 from inside"
grep -q 'hook output priority filter; policy drop;' "$T/variants.nft" && ok || bad "OUTPUT_POLICY=drop"
grep -q 'oifname { "eth1" } udp sport { 67, 547 } accept' "$T/variants.nft" && ok || bad "output drop still answers DHCP"
grep -q 'iifname { "eth1" } udp dport { 67, 547 } accept comment "dhcp range"' "$T/variants.nft" && ok || bad "a dhcp range lets DHCP in"

printf 'eth0\neth1\n' > "$T/etc/interfaces"
printf '# nothing\n' > "$T/etc/rules"
check_ruleset norules
grep -q '{  }' "$T/norules.nft" && bad "empty interface set in ruleset" || ok
grep -q 'masquerade' "$T/norules.nft" && bad "masquerade without a rule" || ok

printf 'eth0\n' > "$T/etc/interfaces"
printf 'forward accept in=eth1 out=eth0\n' > "$T/etc/rules"
PXMXFW_ETC=$T/etc "$PXMXFW" render nft > /dev/null 2>&1 && bad "rule with an unlisted interface accepted by apply" || ok

# ---- dnsmasq ------------------------------------------------------------------

fresh_etc "$T/etc"
sed -i 's/^DNSMASQ=.*/DNSMASQ=yes/' "$T/etc/pxmxfw.conf"
printf 'eth0\neth1 dhcp=192.168.10.100-192.168.10.200\neth2 addr=10.0.2.1/24 addr6=none\n' > "$T/etc/interfaces"
printf 'input accept in=eth2 service=dns\n' > "$T/etc/rules"
printf '192.168.10.10 nas 52:54:00:12:34:56\n' > "$T/etc/hosts"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > "$T/dnsmasq.conf" 2>&1 && ok || bad "render dnsmasq: $(cat "$T/dnsmasq.conf")"
grep -qx 'interface=eth1' "$T/dnsmasq.conf" && grep -qx 'interface=eth2' "$T/dnsmasq.conf" && ok || bad "dnsmasq serves dhcp ranges and dns rules"
grep -q 'interface=eth0' "$T/dnsmasq.conf" && bad "dnsmasq serves the WAN" || ok
grep -qx 'dhcp-range=set:eth1,192.168.10.100,192.168.10.200,12h' "$T/dnsmasq.conf" && ok || bad "dnsmasq DHCP range"
grep -q 'ra-stateless' "$T/dnsmasq.conf" && bad "IPV6=no still sends router advertisements" || ok
grep -qx 'dhcp-host=52:54:00:12:34:56,192.168.10.10,nas' "$T/dnsmasq.conf" && ok || bad "dnsmasq static lease"
printf 'eth0\neth1 dhcp=192.168.10.100-192.168.10.200 lease=1d dns=1.1.1.1,9.9.9.9 gateway=none\neth2 addr=10.0.2.1/24\n' > "$T/etc/interfaces"
printf 'input accept in=eth2 service=ping\n' > "$T/etc/rules"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > "$T/dnsmasq2.conf" 2>&1
grep -qx 'interface=eth1' "$T/dnsmasq2.conf" && ! grep -q 'interface=eth2' "$T/dnsmasq2.conf" && ok || bad "dnsmasq skips interfaces without dns or dhcp"
grep -qx 'dhcp-range=set:eth1,192.168.10.100,192.168.10.200,1d' "$T/dnsmasq2.conf" && ok || bad "per-interface lease time"
grep -qx 'dhcp-option=tag:eth1,option:dns-server,1.1.1.1,9.9.9.9' "$T/dnsmasq2.conf" && ok || bad "per-interface DNS servers"
grep -qx 'dhcp-option=tag:eth1,option:router' "$T/dnsmasq2.conf" && ok || bad "gateway=none sends no router"
if command -v dnsmasq >/dev/null; then
	dnsmasq --test -C "$T/dnsmasq2.conf" >/dev/null 2>&1 && ok || bad "dnsmasq --test per-interface options: $(dnsmasq --test -C "$T/dnsmasq2.conf" 2>&1)"
fi
printf 'eth0\neth1\n' > "$T/etc/interfaces"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > /dev/null 2>&1 && bad "DNSMASQ=yes with no dns interface accepted" || ok
printf 'input accept service=dns\n' > "$T/etc/rules"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > "$T/dnsmasq3.conf" 2>&1
grep -qx 'interface=eth1' "$T/dnsmasq3.conf" && ! grep -q 'interface=eth0' "$T/dnsmasq3.conf" && ok || bad "dns from any interface: every one but the WAN"
printf 'eth0\neth1 dhcp=192.168.10.100-192.168.10.200\neth2 addr=10.0.2.1/24 addr6=none dhcp=10.0.2.100-10.0.2.200\n' > "$T/etc/interfaces"
sed -i 's/^IPV6=.*/IPV6=yes/' "$T/etc/pxmxfw.conf"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > "$T/dnsmasq.conf"
grep -qx 'dhcp-range=::,constructor:eth1,ra-stateless,ra-names' "$T/dnsmasq.conf" && ! grep -q 'constructor:eth2' "$T/dnsmasq.conf" &&
	ok || bad "IPv6 router advertisements where addr6 is not none"
if command -v dnsmasq >/dev/null; then
	dnsmasq --test -C "$T/dnsmasq.conf" >/dev/null 2>&1 && ok || bad "dnsmasq --test: $(dnsmasq --test -C "$T/dnsmasq.conf" 2>&1)"
fi
printf 'eth0\n' > "$T/etc/interfaces"
printf '' > "$T/etc/rules"
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > /dev/null 2>&1 && bad "DNSMASQ=yes without inside interface accepted" || ok

# ---- first boot and interface detection ------------------------------------------

boot_env() { env PXMXFW_ETC="$T/etc" PXMXFW_SYSNET="$T/sys" PXMXFW_NET_INTERFACES="$T/interfaces" "$@"; }
mkdir -p "$T/sys/eth0" "$T/sys/eth1" "$T/sys/eth2" "$T/sys/lo"
cat > "$T/interfaces" <<'EOF2'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp

auto eth1
iface eth1 inet static
	address 192.168.50.1/24
EOF2
fresh_etc "$T/etc"
if boot_env "$PXMXFW" firstboot > "$T/out" 2>&1; then ok
else bad "firstboot: $(cat "$T/out")"; fi
grep -qx 'eth0' "$T/etc/interfaces" && grep -qx 'WAN=eth0' "$T/etc/pxmxfw.conf" && ok || bad "firstboot: eth0 is WAN"
grep -qx 'eth1 addr6=none dhcp=192.168.50.100-192.168.50.200' "$T/etc/interfaces" && ok ||
	bad "firstboot: eth1 is LAN with a DHCP range from Proxmox's address: $(cat "$T/etc/interfaces")"
grep -qx 'eth2 addr=none addr6=none' "$T/etc/interfaces" && ! grep -q 'eth2' "$T/etc/rules" && ok || bad "firstboot: other NICs get no rules"
grep -qx 'input accept in=eth1 service=ping,ssh,dns,dhcp,webui # the LAN reaches the firewall' "$T/etc/rules" &&
	grep -qx 'forward accept in=eth1 out=eth0 # LAN to WAN' "$T/etc/rules" && grep -qx 'masquerade out=eth0 # NAT out of WAN' "$T/etc/rules" &&
	! grep -q 'in=eth0 service=webui' "$T/etc/rules" && ok || bad "firstboot: default rules: $(cat "$T/etc/rules")"
grep -q '^lo' "$T/etc/interfaces" && bad "firstboot lists lo" || ok
grep -qx 'DNSMASQ=no' "$T/etc/pxmxfw.conf" && grep -qx 'IPV6=no' "$T/etc/pxmxfw.conf" && ok || bad "firstboot leaves dnsmasq and IPv6 off"
[ -e "$T/etc/.firstboot-done" ] && ok || bad "firstboot writes its marker"
boot_env "$PXMXFW" validate interfaces "$T/etc/interfaces" && boot_env "$PXMXFW" validate rules "$T/etc/rules" && ok || bad "firstboot output is valid"
cp "$T/etc/interfaces" "$T/before"
boot_env "$PXMXFW" firstboot > /dev/null 2>&1
cmp -s "$T/before" "$T/etc/interfaces" && ok || bad "firstboot runs only once"

mkdir "$T/sys/eth3"
boot_env "$PXMXFW" detect > "$T/out" 2>&1
grep -qx 'eth3 addr=none addr6=none' "$T/etc/interfaces" && grep -q eth3 "$T/out" && ok || bad "detect adds a new NIC"
boot_env "$PXMXFW" detect > "$T/out" 2>&1
[ "$(grep -c '^eth3' "$T/etc/interfaces")" = 1 ] && ok || bad "detect adds each NIC once"

# old-style netmask, and a single NIC
printf 'iface eth1 inet static\n\taddress 10.20.0.1\n\tnetmask 255.255.0.0\n' > "$T/interfaces"
fresh_etc "$T/etc"
boot_env "$PXMXFW" firstboot > /dev/null 2>&1
grep -q 'dhcp=10.20.0.100-10.20.0.200' "$T/etc/interfaces" && ok || bad "netmask style address"
rm -rf "$T/sys/eth1" "$T/sys/eth2" "$T/sys/eth3"
fresh_etc "$T/etc"
boot_env "$PXMXFW" firstboot > /dev/null 2>&1
grep -qx 'input accept in=eth0 service=webui # setup from WAN, remove when the LAN works' "$T/etc/rules" && ! grep -q '^forward' "$T/etc/rules" && ok ||
	bad "single NIC: no LAN, UI reachable on WAN"

# ---- migration from interface roles --------------------------------------------

fresh_etc "$T/etc"
rm -f "$T/etc/rules"
printf 'NAT=yes\nWAN_PING=no\nIPV6=no\nWEBUI_PORT=8443\nWEBUI_WAN=yes\nDNSMASQ=yes\n' > "$T/etc/pxmxfw.conf"
cat > "$T/etc/interfaces" <<'EOF2'
# old style
eth0 role=wan
eth1 role=lan dhcp=192.168.10.100-192.168.10.200 # office
eth2 role=isolated addr=10.0.2.1/24 allow=ping
eth3 role=off addr=none addr6=none
vl10 role=lan type=vlan link=eth1 vid=10 addr=10.0.10.1/24 allow=none
br0 role=lan type=bridge ports=eth4 addr=10.0.30.1/24 allow=ping,webui
eth4 role=off addr=none addr6=none
EOF2
printf 'tcp 22 # ssh\n' > "$T/etc/services"
printf '# forwards\ntcp 443 192.168.10.10 8443 # web\n' > "$T/etc/forwards"
PXMXFW_ETC=$T/etc "$PXMXFW" render nft > /dev/null 2>&1 && bad "render accepts roles" || ok
PXMXFW_ETC=$T/etc "$PXMXFW" migrate > "$T/out" 2>&1 && ok || bad "migrate: $(cat "$T/out")"
[ -e "$T/etc/backup-roles/interfaces" ] && [ -e "$T/etc/backup-roles/services" ] && [ ! -e "$T/etc/services" ] && [ ! -e "$T/etc/forwards" ] &&
	ok || bad "migrate keeps the old files in backup-roles"
grep -q 'role=\|allow=' "$T/etc/interfaces" && bad "migrate leaves roles: $(cat "$T/etc/interfaces")" || ok
grep -qx 'eth1 dhcp=192.168.10.100-192.168.10.200 # office' "$T/etc/interfaces" && ok || bad "migrate keeps the other fields and comments"
grep -qx 'WAN=eth0' "$T/etc/pxmxfw.conf" && ! grep -q 'NAT=\|WAN_PING=\|WEBUI_WAN=' "$T/etc/pxmxfw.conf" && ok || bad "migrate settings: $(cat "$T/etc/pxmxfw.conf")"
for want in 'input accept in=eth0 service=webui # web UI from WAN' 'input accept in=eth0 proto=tcp dport=22 # ssh' \
	'input accept in=eth1 service=ping,ssh,dns,dhcp,webui # what eth1 may reach' 'input accept in=eth2 service=ping # what eth2 may reach' \
	'input accept in=br0 service=ping,webui # what br0 may reach' 'forward accept in=eth1,vl10,br0 out=eth1,vl10,br0 # lan to lan' \
	'forward accept in=eth1,eth2,vl10,br0 out=eth0 # inside to WAN' 'masquerade out=eth0 # NAT out of WAN' \
	'dnat in=eth0 proto=tcp dport=443 to=192.168.10.10:8443 # web'; do
	grep -qxF "$want" "$T/etc/rules" && ok || bad "migrate wrote: $want (got: $(cat "$T/etc/rules"))"
done
grep -q 'service=ping # ping on WAN' "$T/etc/rules" && bad "WAN_PING=no still answers ping" || ok
grep -q 'in=vl10 service' "$T/etc/rules" && bad "allow=none reaches the firewall" || ok
check_ruleset migrated
PXMXFW_ETC=$T/etc "$PXMXFW" render dnsmasq > "$T/out" 2>&1 && grep -qx 'interface=eth1' "$T/out" && ! grep -q 'interface=eth2' "$T/out" &&
	ok || bad "migrated config serves DNS where it did: $(cat "$T/out")"
cp "$T/etc/rules" "$T/before"
PXMXFW_ETC=$T/etc "$PXMXFW" migrate > /dev/null 2>&1
cmp -s "$T/before" "$T/etc/rules" && ok || bad "migrate runs once"

# the web UI listens on all addresses when rules let several interfaces reach it
fresh_etc "$T/etc"
printf 'input accept in=eth0 service=webui\ninput accept in=eth1 service=ssh,webui\n' > "$T/etc/rules"
[ "$(PXMXFW_ETC=$T/etc "$PXMXFW" webui-listen 2>/dev/null)" = 8443 ] && ok || bad "web UI on two interfaces listens everywhere"
printf 'input accept in=eth1 service=ssh\n' > "$T/etc/rules"
[ "$(PXMXFW_ETC=$T/etc "$PXMXFW" webui-listen 2>/dev/null)" = 127.0.0.1:8443 ] && ok || bad "no web UI rule: localhost only"

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
printf 'eth0\neth1\neth2 addr=10.0.2.1/24\n' > "$T/etc/interfaces"
printf 'flush ruleset\ninclude "%s"\n' "$T/etc/ruleset.nft" > "$T/main.nft"
PXMXFW_ETC=$T/etc "$PXMXFW" render nft > "$T/etc/ruleset.nft"
printf 'input accept in=eth0 proto=tcp dport=22\n' >> "$T/etc/rules"
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
printf 'eth0\neth1\neth2 addr=10.0.2.1/24\nvl10 type=vlan link=eth1 vid=10 addr=10.0.10.1/24\nbr0 type=bridge ports=eth3,vl10b addr=10.0.30.1/24\neth3\nvl10b type=vlan link=eth1 vid=11\n' > "$T/etc/interfaces"
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
printf 'wg0 addr=10.99.0.1/24\n' >> "$T/etc/interfaces"
printf 'forward accept in=eth1,wg0 out=eth1,wg0 # sites\n' >> "$T/etc/rules"
check_ruleset wireguard
grep -q 'udp dport { 51820 } accept comment "wireguard"' "$T/wireguard.nft" && ok || bad "wireguard port open"
grep -q 'iifname { "eth1", "wg0" } oifname { "eth1", "wg0" }' "$T/wireguard.nft" && ok || bad "rules route between a tunnel and the lan"

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
	printf 'eth0\neth1 addr=192.168.10.1/24\nvl10 type=vlan link=eth1 vid=10 addr=10.0.10.1/24\nbr0 type=bridge ports=eth3 addr=10.0.30.1/24\neth3 addr=none\n' > "$T/etc/interfaces"
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
	printf 'eth0\nwg0 addr=10.99.0.1/24\n' > "$T/etc/interfaces"
	printf '' > "$T/etc/rules"
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
