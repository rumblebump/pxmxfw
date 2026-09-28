# pxmxfw shell library: read, validate and render the configuration.
#
# Config lives in $PXMXFW_ETC (default /etc/pxmxfw):
#   pxmxfw.conf  KEY=value settings
#   interfaces   "IFACE [addr=..] [addr6=..] [dhcp=START-END] [type=..]"
#   rules        firewall rules: input, output, forward, masquerade, dnat
#   hosts        "ip name [mac] [# comment]"         DNS names / static DHCP leases
#   wireguard    "tunnel NAME port=.." / "peer NAME key=.. allowed=.."  WireGuard
#
# Files are parsed line by line and every value is checked against a strict
# pattern. Nothing is ever sourced or eval'd, because the web UI writes them.

PXMXFW_ETC=${PXMXFW_ETC:-/etc/pxmxfw}
PXMXFW_DNSMASQ_CONF=${PXMXFW_DNSMASQ_CONF:-/etc/dnsmasq.d/pxmxfw.conf}
PXMXFW_NET_INTERFACES=${PXMXFW_NET_INTERFACES:-/etc/network/interfaces}
PXMXFW_SYSNET=${PXMXFW_SYSNET:-/sys/class/net}
PXMXFW_PROCSYS=${PXMXFW_PROCSYS:-/proc/sys}

# ---- validators (return 0 when valid) --------------------------------------

is_iface() {
	case $1 in ''|*[!A-Za-z0-9_.-]*) return 1 ;; esac
	[ ${#1} -le 15 ]
}
is_yesno() { case $1 in yes|no) return 0 ;; esac; return 1; }
is_uint() { case $1 in ''|*[!0-9]*) return 1 ;; esac; [ ${#1} -le 5 ]; }
is_port() { is_uint "$1" && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
is_portrange() {
	case $1 in
		*-*) is_port "${1%-*}" && is_port "${1#*-}" && [ "${1%-*}" -lt "${1#*-}" ] ;;
		*) is_port "$1" ;;
	esac
}
is_proto() { case $1 in tcp|udp) return 0 ;; esac; return 1; }
is_ipv4() {
	case $1 in *[!0-9.]*|.*|*.|*..*) return 1 ;; esac
	_old_ifs=$IFS; IFS=.
	# shellcheck disable=SC2086
	set -- $1
	IFS=$_old_ifs
	[ $# -eq 4 ] || return 1
	for _o; do
		[ ${#_o} -le 3 ] && [ "$_o" -le 255 ] || return 1
	done
}
is_ipv4_cidr() {
	case $1 in */*) ;; *) return 1 ;; esac
	is_ipv4 "${1%/*}" && is_uint "${1#*/}" && [ "${1#*/}" -ge 1 ] && [ "${1#*/}" -le 32 ]
}
is_ipv6_cidr() { # loose: the kernel does the exact check when it is applied
	case $1 in */*) ;; *) return 1 ;; esac
	case ${1%/*} in *:*:*) ;; *) return 1 ;; esac
	case ${1%/*} in *[!0-9A-Fa-f:]*) return 1 ;; esac
	[ ${#1} -le 43 ] && is_uint "${1#*/}" && [ "${1#*/}" -ge 1 ] && [ "${1#*/}" -le 128 ]
}
is_ipv4_list() { # space separated, may be empty
	for _a in $1; do is_ipv4 "$_a" || return 1; done
}
is_mac() {
	printf '%s\n' "$1" | grep -Eqx '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'
}
is_hostname() {
	printf '%s\n' "$1" | grep -Eqx '[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
}
is_domain() {
	printf '%s\n' "$1" | grep -Eqx '[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*'
}
is_lease() { printf '%s\n' "$1" | grep -Eqx '[0-9]{1,6}[mhd]?|infinite'; }
is_comment() { # free text that is safe inside an nft comment "..."
	[ ${#1} -le 64 ] || return 1
	case $1 in *[!A-Za-z0-9\ _.,:/+-]*) return 1 ;; esac
}

# ---- common parsing ------------------------------------------------------

# Remove a trailing "# comment" and surrounding blanks from $1.
_strip() {
	_s=${1%%#*}
	_s=${_s#"${_s%%[![:space:]]*}"}
	_s=${_s%"${_s##*[![:space:]]}"}
	printf '%s' "$_s"
}

# err FILE LINE MESSAGE: report a validation error (LINE 0: whole file)
err() {
	if [ "$2" = 0 ]; then printf '%s: %s\n' "$1" "$3" >&2
	else printf '%s:%s: %s\n' "$1" "$2" "$3" >&2; fi
	_errors=$((_errors + 1))
}

# ---- settings -------------------------------------------------------------

settings_defaults() {
	WAN=eth0
	FIREWALL=rules
	OUTPUT_POLICY=accept
	IPV6=no
	WEBUI_PORT=8443
	DNSMASQ=no
	DNS_UPSTREAM=
	DNS_DOMAIN=lan
	DHCP_LEASE=12h
}

# Load settings from $1 (default $PXMXFW_ETC/pxmxfw.conf) on top of the
# defaults. Returns 1 and prints errors when anything is invalid.
settings_load() {
	_f=${1:-$PXMXFW_ETC/pxmxfw.conf}
	_errors=0
	settings_defaults
	[ -r "$_f" ] || return 0
	_n=0
	while IFS= read -r _line || [ -n "$_line" ]; do
		_n=$((_n + 1))
		_line=$(_strip "$_line")
		[ -n "$_line" ] || continue
		case $_line in
			*=*) ;;
			*) err "$_f" "$_n" "expected KEY=value"; continue ;;
		esac
		_k=${_line%%=*}
		_v=$(_strip "${_line#*=}")
		case $_v in \"*\") _v=${_v#\"}; _v=${_v%\"} ;; esac
		case $_k in
			WAN) is_iface "$_v" && WAN=$_v || err "$_f" "$_n" "WAN: an interface name" ;;
			FIREWALL) case $_v in rules|manual) FIREWALL=$_v ;; *) err "$_f" "$_n" "FIREWALL: rules or manual" ;; esac ;;
			OUTPUT_POLICY) case $_v in accept|drop) OUTPUT_POLICY=$_v ;; *) err "$_f" "$_n" "OUTPUT_POLICY: accept or drop" ;; esac ;;
			NAT|WAN_PING|WEBUI_WAN) err "$_f" "$_n" "$_k was replaced by the rules file (pxmxfw migrate converts it)" ;;
			IPV6) is_yesno "$_v" && IPV6=$_v || err "$_f" "$_n" "IPV6: use yes or no" ;;
			WEBUI_PORT) is_port "$_v" && WEBUI_PORT=$_v || err "$_f" "$_n" "WEBUI_PORT: 1-65535" ;;
			DNSMASQ) is_yesno "$_v" && DNSMASQ=$_v || err "$_f" "$_n" "DNSMASQ: use yes or no" ;;
			DNS_UPSTREAM) is_ipv4_list "$_v" && DNS_UPSTREAM=$_v || err "$_f" "$_n" "DNS_UPSTREAM: space separated IPv4 addresses" ;;
			DNS_DOMAIN) is_domain "$_v" && DNS_DOMAIN=$_v || err "$_f" "$_n" "DNS_DOMAIN: invalid domain" ;;
			DHCP_LEASE) is_lease "$_v" && DHCP_LEASE=$_v || err "$_f" "$_n" "DHCP_LEASE: e.g. 12h, 30m, 1d or infinite" ;;
			*) err "$_f" "$_n" "unknown setting $_k" ;;
		esac
	done < "$_f"
	[ "$_errors" -eq 0 ]
}

settings_write() { # write current settings to stdout
	cat <<-EOF
	# pxmxfw settings. Edit in the web UI or here, then run: pxmxfw apply
	WAN=$WAN
	FIREWALL=$FIREWALL
	OUTPUT_POLICY=$OUTPUT_POLICY
	IPV6=$IPV6
	WEBUI_PORT=$WEBUI_PORT
	DNSMASQ=$DNSMASQ
	DNS_UPSTREAM=$DNS_UPSTREAM
	DNS_DOMAIN=$DNS_DOMAIN
	DHCP_LEASE=$DHCP_LEASE
	EOF
}

# ---- interfaces -------------------------------------------------------------
# One line per network interface:
#   IFACE [addr=A] [addr6=A] [routing=yes|no] [dhcp=START-END] [lease=TIME]
#         [dns=IP,IP] [gateway=IP|none] [routes=NET,NET]
#         [type=vlan link=IFACE vid=N | type=bridge [ports=IFACE,IFACE]] [# comment]
# Interfaces have no role: what may pass is set in the rules file. The WAN
# (WAN= in pxmxfw.conf, eth0 by default) only differs in that Proxmox always
# sets its addresses and it never runs a DHCP server.
# addr:  proxmox (default: Proxmox sets it), none, or IPv4/prefix set by pxmxfw
# addr6: same for IPv6, used only when IPV6=yes
# routing: yes (default): traffic from and to this interface is routed as the
#        forward rules allow. no: nothing is routed from or to it; its clients
#        only reach the firewall itself (as input rules allow) and port
#        forwards (dnat), and DHCP hands out no default route
# dhcp:  IPv4 range dnsmasq hands out on this interface (also lets DHCP and
#        DNS from this interface reach the firewall)
# lease: DHCP lease time on this interface (default: DHCP_LEASE)
# dns:   DNS servers DHCP hands out here (default: the firewall itself)
# gateway: default route DHCP hands out here (default: the firewall itself,
#        none with routing=no; none: clients get no default route)
# routes: networks DHCP tells clients to reach through the firewall (DHCP
#        option 121), for example other LANs when gateway=none
# type:  vlan    created by pxmxfw on top of link, with 802.1Q id vid
#        bridge  created by pxmxfw, joining ports (which carry no address)
#        without type, a NIC from Proxmox or a WireGuard tunnel

# ifaces_each FILE CALLBACK: validate the interfaces file and call CALLBACK
# with: name addr addr6 dhcp comment type link vid ports lease dns gateway
# routing routes. With CALLBACK "-" only validates. Needs the settings (WAN)
# loaded. Sets IF_NAMES (every interface), WAN_IF, DHCP_IFS (with a dhcp= range),
# NOROUTE_IFS (routing=no),
# VLANS ("name:link:vid ..."), BRIDGES ("name:p1,p2 ...") and PORT_IFS
# (bridge ports).
ifaces_each() {
	_f=$1 _cb=$2
	_errors=0
	WAN_IF='' IF_NAMES='' DHCP_IFS='' NOROUTE_IFS='' VLANS='' BRIDGES='' PORT_IFS='' _addrd=''
	_seen=' '
	[ -r "$_f" ] || { err "$_f" 0 "missing"; return 1; }
	_n=0
	while IFS= read -r _line || [ -n "$_line" ]; do
		_n=$((_n + 1))
		_c=
		case $_line in *'#'*) _c=$(_strip "${_line#*#}") ;; esac
		_line=$(_strip "$_line")
		[ -n "$_line" ] || continue
		is_comment "$_c" || { err "$_f" "$_n" "comment may only use letters, digits, spaces and _.,:/+- (max 64)"; continue; }
		# shellcheck disable=SC2086
		set -- $_line
		_name=$1; shift
		is_iface "$_name" || { err "$_f" "$_n" "invalid interface name"; continue; }
		case $_seen in *" $_name "*) err "$_f" "$_n" "$_name listed twice"; continue ;; esac
		_seen="$_seen$_name "
		_addr=proxmox _addr6=proxmox _dhcp='' _bad='' _type='' _link='' _vid='' _ports=''
		_lease='' _dns='' _gw='' _routing=yes _routes=''
		for _kv; do
			case $_kv in
				lease=*) is_lease "${_kv#lease=}" && _lease=${_kv#lease=} || _bad="lease: e.g. 12h, 30m, 1d or infinite" ;;
				dns=*)
					_dns=${_kv#dns=}
					for _d in $(echo "$_dns" | tr ',' ' '); do is_ipv4 "$_d" || _bad="dns: IPv4 addresses separated by commas"; done
					case $_dns in ''|,*|*,|*,,*) _bad="dns: IPv4 addresses separated by commas" ;; esac ;;
				routing=yes|routing=no) _routing=${_kv#routing=} ;;
				routes=*)
					_routes=${_kv#routes=}
					for _d in $(echo "$_routes" | tr ',' ' '); do is_ipv4_cidr "$_d" || _bad="routes: IPv4 networks (ADDR/PREFIX) separated by commas"; done
					case $_routes in ''|,*|*,|*,,*) _bad="routes: IPv4 networks (ADDR/PREFIX) separated by commas" ;; esac ;;
				gateway=none) _gw=none ;;
				gateway=*) is_ipv4 "${_kv#gateway=}" && _gw=${_kv#gateway=} || _bad="gateway: an IPv4 address or none" ;;
				type=vlan|type=bridge) _type=${_kv#type=} ;;
				link=*) is_iface "${_kv#link=}" && _link=${_kv#link=} || _bad="link: an interface name" ;;
				vid=*) _vid=${_kv#vid=}; { is_uint "$_vid" && [ "$_vid" -ge 1 ] && [ "$_vid" -le 4094 ]; } || _bad="vid: 1 to 4094" ;;
				ports=*)
					_ports=${_kv#ports=}
					for _p in $(echo "$_ports" | tr ',' ' '); do is_iface "$_p" || _bad="ports: interface names separated by commas"; done
					case $_ports in ,*|*,|*,,*) _bad="ports: interface names separated by commas" ;; esac ;;
				role=*|allow=*) _bad="${_kv%%=*}= was replaced by the rules file (pxmxfw migrate converts it)" ;;
				addr=proxmox|addr=none) _addr=${_kv#addr=} ;;
				addr=*) is_ipv4_cidr "${_kv#addr=}" && _addr=${_kv#addr=} || _bad="addr: use proxmox, none or IPv4/prefix" ;;
				addr6=proxmox|addr6=none) _addr6=${_kv#addr6=} ;;
				addr6=*) is_ipv6_cidr "${_kv#addr6=}" && _addr6=${_kv#addr6=} || _bad="addr6: use proxmox, none or IPv6/prefix" ;;
				dhcp=*-*)
					_dhcp=${_kv#dhcp=}
					is_ipv4 "${_dhcp%-*}" && is_ipv4 "${_dhcp#*-}" || _bad="dhcp: use START-END IPv4 addresses" ;;
				*) _bad="unknown field $_kv" ;;
			esac
		done
		if [ -z "$_bad" ] && [ "$_name" = "$WAN" ]; then
			[ "$_addr" = proxmox ] && [ "$_addr6" = proxmox ] || _bad="the WAN address is set in Proxmox (addr=proxmox)"
			[ -z "$_dhcp$_lease$_dns$_gw$_routes" ] || _bad="no DHCP server on WAN"
			[ "$_routing" = yes ] || _bad="the WAN is always routed"
			[ -z "$_type" ] || _bad="the WAN is a NIC from Proxmox"
		fi
		if [ -z "$_bad" ]; then
			case $_type in
				vlan) [ -n "$_link" ] && [ -n "$_vid" ] || _bad="type=vlan needs link= and vid=" ;;
				*) [ -z "$_link$_vid" ] || _bad="link= and vid= are only for type=vlan" ;;
			esac
			[ -z "$_ports" ] || [ "$_type" = bridge ] || _bad="ports= is only for type=bridge"
			[ -z "$_routes" ] || [ "$_routing" = yes ] || _bad="routes= needs routing (no routes lead out of an interface with routing=no)"
			[ -z "$_routes" ] || [ -n "$_dhcp" ] || _bad="routes= is handed out by DHCP, so it needs dhcp="
			[ "$_link" != "$_name" ] || _bad="a VLAN cannot be on itself"
			case ,$_ports, in *,"$_name",*) _bad="a bridge cannot be its own port" ;; esac
		fi
		[ -z "$_bad" ] || { err "$_f" "$_n" "$_name: $_bad"; continue; }
		IF_NAMES="$IF_NAMES $_name"
		[ "$_name" != "$WAN" ] || WAN_IF=$_name
		[ -z "$_dhcp" ] || DHCP_IFS="$DHCP_IFS $_name"
		[ "$_routing" = yes ] || NOROUTE_IFS="$NOROUTE_IFS $_name"
		case $_addr in proxmox|none) ;; *) _addrd="$_addrd $_name" ;; esac
		case $_type in
			vlan) VLANS="$VLANS $_name:$_link:$_vid" ;;
			bridge) BRIDGES="$BRIDGES $_name:$_ports"; PORT_IFS="$PORT_IFS $(echo "$_ports" | tr ',' ' ')" ;;
		esac
		[ "$_cb" = - ] || "$_cb" "$_name" "$_addr" "$_addr6" "$_dhcp" "$_c" "$_type" "$_link" "$_vid" "$_ports" "$_lease" "$_dns" "$_gw" "$_routing" "$_routes"
	done < "$_f"
	IF_NAMES=${IF_NAMES# } DHCP_IFS=${DHCP_IFS# } NOROUTE_IFS=${NOROUTE_IFS# } VLANS=${VLANS# } BRIDGES=${BRIDGES# } PORT_IFS=${PORT_IFS# }
	[ "$_errors" -gt 0 ] || ifaces_links "$_f"
	[ -n "$WAN_IF" ] || [ "$_errors" -gt 0 ] || err "$_f" 0 "the WAN $WAN (WAN= in pxmxfw.conf) is not listed"
	[ "$_errors" -eq 0 ]
}

# listed NAME: true when NAME is in the interfaces file (after ifaces_each)
listed() { case " $IF_NAMES " in *" $1 "*) return 0 ;; esac; return 1; }

# ifaces_links FILE: VLAN links and bridge ports must be listed interfaces;
# a bridge port has no address or DHCP of its own and belongs to one bridge.
ifaces_links() {
	for _v in $VLANS; do
		_nm=${_v%%:*} _l=${_v#*:}; _l=${_l%%:*}
		listed "$_l" || err "$1" 0 "$_nm: link $_l is not listed"
	done
	_used=' '
	for _b in $BRIDGES; do
		_nm=${_b%%:*}
		for _p in $(echo "${_b#*:}" | tr ',' ' '); do
			listed "$_p" || err "$1" 0 "$_nm: port $_p is not listed"
			[ "$_p" != "$WAN" ] || err "$1" 0 "$_nm: the WAN cannot be a bridge port"
			case " $_addrd $DHCP_IFS " in *" $_p "*) err "$1" 0 "$_nm: port $_p needs addr=none and no DHCP (the bridge has the address)" ;; esac
			case $_used in *" $_p "*) err "$1" 0 "$_p is a port of two bridges" ;; esac
			_used="$_used$_p "
		done
	done
}

# ---- firewall rules -------------------------------------------------------
# $PXMXFW_ETC/rules, one rule per line, applied in the order listed:
#   input|output|forward accept|drop|reject [MATCH...] [# comment]
#   masquerade out=IFACE[,IFACE] [src=NET] [dst=NET] [# comment]
#   dnat in=IFACE[,IFACE] proto=tcp|udp dport=PORT[-PORT] to=IP[:PORT] [src=NET] [dst=NET] [# comment]
# input is traffic to the firewall itself, output traffic it sends, forward
# traffic it routes between interfaces. MATCH (all optional, each may be a
# comma list; a missing one matches everything):
#   in=IFACE      arrives on (not for output)
#   out=IFACE     leaves through (not for input)
#   ip=4|6        IPv4 or IPv6 only (implied by src and dst)
#   src=NET dst=NET  IPv4 or IPv6 address or ADDR/PREFIX, one family per rule
#   proto=tcp|udp|tcp,udp|icmp|icmpv6|gre|esp|ah|ipip
#   sport=PORT[-PORT] dport=PORT[-PORT]  (need proto tcp and/or udp)
#   tcpflags=FLAGS  (proto=tcp) flags of fin, syn, rst, psh, ack, urg:
#                 syn|fin  any of them set; syn&!ack  syn set and ack not
#   service=ping,ssh,dns,dhcp,webui  services of the firewall (input only,
#                 instead of proto and ports)
# Input and forward drop what no rule accepts, output uses OUTPUT_POLICY.
# With FIREWALL=manual none of these are loaded: the ruleset is whatever
# is in /etc/nftables.d/*.nft.
# Interfaces with routing=no are never routed (forward rules cannot name
# them), apart from dnat port forwards.
# Replies to allowed traffic, loopback, ICMPv6, the WireGuard ports, and DHCP
# and DNS on interfaces with a dhcp= range are always allowed. With IPV6=no
# nothing is routed over IPv6. A dnat rule is also let through forward.

SERVICES=ping,ssh,dns,dhcp,webui

# is_tcpflags V: "syn", "syn|fin" (any set) or "syn&!ack" (all as given)
is_tcpflags() {
	case $1 in *'|'*'&'*|*'&'*'|'*|''|*'|'|'|'*|*'&'|'&'*|*'||'*|*'&&'*) return 1 ;; esac
	case $1 in *'|'*) case $1 in *!*) return 1 ;; esac ;; esac
	for _t in $(echo "$1" | tr '|&' '  '); do
		case ${_t#!} in fin|syn|rst|psh|ack|urg) ;; *) return 1 ;; esac
	done
}
is_iface_list() {
	case $1 in ''|,*|*,|*,,*) return 1 ;; esac
	for _i in $(echo "$1" | tr ',' ' '); do is_iface "$_i" || return 1; done
}
is_port_list() {
	case $1 in ''|,*|*,|*,,*) return 1 ;; esac
	for _i in $(echo "$1" | tr ',' ' '); do is_portrange "$_i" || return 1; done
}
# net_family LIST: print 4 or 6 when LIST is addresses or networks of one family
net_family() {
	case $1 in ''|,*|*,|*,,*) return 1 ;; esac
	_fam=''
	for _i in $(echo "$1" | tr ',' ' '); do
		if is_ipv4 "$_i" || is_ipv4_cidr "$_i"; then _nf=4
		elif is_ipv6_cidr "$_i" || is_ipv6_cidr "$_i/128"; then _nf=6
		else return 1; fi
		[ -z "$_fam" ] || [ "$_fam" = "$_nf" ] || return 1
		_fam=$_nf
	done
	echo "$_fam"
}

# fw_each FILE CALLBACK: validate the rules file and call CALLBACK with
#   KIND ACTION IN OUT SRC DST PROTO SPORT DPORT SERVICE TO FAMILY TCPFLAGS COMMENT
# (unused fields empty; FAMILY 4, 6 or empty). With CALLBACK "-" only
# validates. Interface names must be listed in the interfaces file when
# IF_NAMES is set. Sets WEBUI_IFS, DNS_IFS and DHCPSVC_IFS (interfaces a rule
# accepts that service from; "*" for any).
fw_each() {
	_f=$1 _cb=$2
	_errors=0
	WEBUI_IFS='' DNS_IFS='' DHCPSVC_IFS=''
	[ -r "$_f" ] || return 0
	_n=0
	while IFS= read -r _line || [ -n "$_line" ]; do
		_n=$((_n + 1))
		_c=
		case $_line in *'#'*) _c=$(_strip "${_line#*#}") ;; esac
		_line=$(_strip "$_line")
		[ -n "$_line" ] || continue
		is_comment "$_c" || { err "$_f" "$_n" "comment may only use letters, digits, spaces and _.,:/+- (max 64)"; continue; }
		# shellcheck disable=SC2086
		set -- $_line
		_kind=$1 _act='' _bad=''
		shift
		case $_kind in
			input|output|forward)
				case ${1:-} in accept|drop|reject) _act=$1; shift ;; *) _bad="expected accept, drop or reject after $_kind" ;; esac ;;
			masquerade|dnat) ;;
			*) err "$_f" "$_n" "expected input, output, forward, masquerade or dnat"; continue ;;
		esac
		_in='' _out='' _src='' _dst='' _proto='' _sport='' _dport='' _svc='' _to='' _fam='' _ipv='' _flags=''
		for _kv; do
			_v=${_kv#*=}
			case $_kv in
				in=*) is_iface_list "$_v" && _in=$_v || _bad="in: interface names separated by commas" ;;
				out=*) is_iface_list "$_v" && _out=$_v || _bad="out: interface names separated by commas" ;;
				src=*) _src=$_v; net_family "$_v" > /dev/null || _bad="src: IPv4 or IPv6 addresses or ADDR/PREFIX of one family, separated by commas" ;;
				dst=*) _dst=$_v; net_family "$_v" > /dev/null || _bad="dst: IPv4 or IPv6 addresses or ADDR/PREFIX of one family, separated by commas" ;;
				proto=tcp|proto=udp|proto=tcp,udp|proto=icmp|proto=icmpv6|proto=gre|proto=esp|proto=ah|proto=ipip) _proto=$_v ;;
				proto=udp,tcp) _proto=tcp,udp ;;
				proto=*) _bad="proto: tcp, udp, tcp,udp, icmp, icmpv6, gre, esp, ah or ipip" ;;
				ip=4|ip=6) _ipv=$_v ;;
				ip=*) _bad="ip: 4 or 6" ;;
				tcpflags=*) is_tcpflags "$_v" && _flags=$_v || _bad="tcpflags: fin, syn, rst, psh, ack, urg joined by | (any) or & (all, ! for not set)" ;;
				sport=*) is_port_list "$_v" && _sport=$_v || _bad="sport: ports or PORT-PORT ranges separated by commas" ;;
				dport=*) is_port_list "$_v" && _dport=$_v || _bad="dport: ports or PORT-PORT ranges separated by commas" ;;
				service=*)
					_svc=$_v
					case $_v in ''|,*|*,|*,,*) _bad="service: a list of $SERVICES" ;; esac
					for _s in $(echo "$_v" | tr ',' ' '); do
						case ,$SERVICES, in *,"$_s",*) ;; *) _bad="service: a list of $SERVICES" ;; esac
					done ;;
				to=*)
					_to=$_v
					case $_v in
						*:*) is_ipv4 "${_v%:*}" && is_port "${_v##*:}" || _bad="to: IPv4[:PORT]" ;;
						*) is_ipv4 "$_v" || _bad="to: IPv4[:PORT]" ;;
					esac ;;
				*) _bad="unknown field $_kv" ;;
			esac
		done
		if [ -z "$_bad" ]; then
			_f4='' _f6=''
			[ -z "$_src" ] || _f4=$(net_family "$_src")
			[ -z "$_dst" ] || _f6=$(net_family "$_dst")
			[ -z "$_f4" ] || [ -z "$_f6" ] || [ "$_f4" = "$_f6" ] || _bad="src and dst must both be IPv4 or both IPv6"
			_fam=${_f4:-$_f6}
			[ -z "$_ipv" ] || [ -z "$_fam" ] || [ "$_ipv" = "$_fam" ] || _bad="ip=$_ipv does not match the addresses"
			_fam=${_fam:-$_ipv}
			case $_proto:$_fam in icmp:6) _bad="proto=icmp is IPv4 (use icmpv6)" ;; icmpv6:4) _bad="proto=icmpv6 is IPv6 (use icmp)" ;; esac
			[ -z "$_flags" ] || [ "$_proto" = tcp ] || _bad="tcpflags needs proto=tcp"
			[ -z "$_sport$_dport" ] || case $_proto in tcp|udp|tcp,udp) ;; *) _bad="sport and dport need proto=tcp, udp or tcp,udp" ;; esac
			case $_kind in
				input)
					[ -z "$_out" ] || _bad="out= is not for input (it is traffic to the firewall)"
					[ -z "$_svc" ] || [ -z "$_proto$_sport$_dport" ] || _bad="service= replaces proto, sport and dport" ;;
				output) [ -z "$_in" ] || _bad="in= is not for output (it is traffic from the firewall)" ;;
			esac
			case $_kind in input) ;; *) [ -z "$_svc" ] || _bad="service= is only for input" ;; esac
			case $_kind in dnat) ;; *) [ -z "$_to" ] || _bad="to= is only for dnat" ;; esac
			case $_kind in
				masquerade)
					[ -n "$_out" ] || _bad="masquerade needs out="
					[ -z "$_in$_proto$_sport$_dport$_flags" ] || _bad="masquerade takes out=, src= and dst= only"
					[ "$_fam" != 6 ] || _bad="masquerade is IPv4 only" ;;
				dnat)
					[ -n "$_in" ] && [ -n "$_dport" ] && [ -n "$_to" ] || _bad="dnat needs in=, proto=, dport= and to="
					case $_proto in tcp|udp) ;; *) _bad="dnat needs proto=tcp or proto=udp" ;; esac
					[ -z "$_out$_sport$_flags" ] || _bad="dnat takes in=, proto=, dport=, to=, src= and dst= only"
					case $_dport in *,*) _bad="dnat: one dport or one PORT-PORT range" ;; esac
					case $_dport:$_to in *-*:*:*) _bad="dnat: a port range forwards to the same ports (to=IP without :PORT)" ;; esac
					[ "$_fam" != 6 ] || _bad="dnat is IPv4 only" ;;
			esac
		fi
		if [ -z "$_bad" ] && [ -n "$IF_NAMES" ]; then
			for _i in $(echo "$_in,$_out" | tr ',' ' '); do
				listed "$_i" || _bad="$_i is not in the interfaces file"
				case $_kind:" $NOROUTE_IFS " in forward:*" $_i "*|masquerade:*" $_i "*)
					_bad="$_i has routing=no, so nothing is routed from or to it (use a dnat rule for port forwards)" ;;
				esac
			done
		fi
		[ -z "$_bad" ] || { err "$_f" "$_n" "$_bad"; continue; }
		if [ "$_kind:$_act" = input:accept ] && [ -n "$_svc" ]; then
			_w=${_in:-*}; _w=$(echo "$_w" | tr ',' ' ')
			case ,$_svc, in *,webui,*) WEBUI_IFS="$WEBUI_IFS $_w" ;; esac
			case ,$_svc, in *,dns,*) DNS_IFS="$DNS_IFS $_w" ;; esac
			case ,$_svc, in *,dhcp,*) DHCPSVC_IFS="$DHCPSVC_IFS $_w" ;; esac
		fi
		[ "$_cb" = - ] || "$_cb" "$_kind" "$_act" "$_in" "$_out" "$_src" "$_dst" "$_proto" "$_sport" "$_dport" "$_svc" "$_to" "$_fam" "$_flags" "$_c"
	done < "$_f"
	WEBUI_IFS=${WEBUI_IFS# } DNS_IFS=${DNS_IFS# } DHCPSVC_IFS=${DHCPSVC_IFS# }
	[ "$_errors" -eq 0 ]
}

# ---- host names -----------------------------------------------------------

# rules_each KIND FILE CALLBACK: validate every line of a list file (hosts)
# and call CALLBACK with its fields (comment last, may be empty). With
# CALLBACK "-" only validates. Returns 1 when any line is invalid.
rules_each() {
	_kind=$1 _f=$2 _cb=$3
	_errors=0
	[ -r "$_f" ] || return 0
	_n=0
	while IFS= read -r _line || [ -n "$_line" ]; do
		_n=$((_n + 1))
		_c=
		case $_line in *'#'*) _c=$(_strip "${_line#*#}") ;; esac
		_line=$(_strip "$_line")
		[ -n "$_line" ] || continue
		if ! is_comment "$_c"; then
			err "$_f" "$_n" "comment may only use letters, digits, spaces and _.,:/+- (max 64)"
			continue
		fi
		# shellcheck disable=SC2086
		set -- $_line
		case $_kind in
			hosts)
				{ [ $# -eq 2 ] || { [ $# -eq 3 ] && is_mac "$3"; }; } && is_ipv4 "$1" && is_hostname "$2" ||
					{ err "$_f" "$_n" "expected: IP NAME [MAC]"; continue; } ;;
		esac
		[ "$_cb" = - ] || "$_cb" "$@" "$_c"
	done < "$_f"
	[ "$_errors" -eq 0 ]
}

# ---- WireGuard --------------------------------------------------------------
# $PXMXFW_ETC/wireguard, one tunnel line followed by its peer lines:
#   tunnel NAME port=PORT [public=HOST:PORT] [# comment]
#   peer NAME key=PUBLICKEY allowed=CIDR[,CIDR...] [endpoint=HOST:PORT] [keepalive=SECONDS] [# name]
# NAME is the tunnel interface (e.g. wg0). It also needs a line in the
# interfaces file, which sets its tunnel address; the rules file says what
# may pass through it. The private key is created on the first apply in
# $PXMXFW_ETC/wg/NAME.key.

is_wgkey() { printf '%s\n' "$1" | grep -Eqx '[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]='; }
is_host() { is_ipv4 "$1" || is_domain "$1"; }
is_hostport() {
	case $1 in
		\[*\]:*) _h=${1%]:*}; _h=${_h#\[}; _pt=${1##*]:}
			case $_h in *:*) ;; *) return 1 ;; esac
			case $_h in *[!0-9A-Fa-f:]*) return 1 ;; esac ;;
		*:*) _h=${1%:*}; _pt=${1##*:}; is_host "$_h" || return 1 ;;
		*) return 1 ;;
	esac
	is_port "$_pt"
}
is_allowed_ip() { # IPv4 or IPv6 CIDR; /0 allowed
	case $1 in */*) ;; *) return 1 ;; esac
	_a=${1%/*} _p=${1#*/}
	is_uint "$_p" || return 1
	case $_a in
		*:*) case $_a in *[!0-9A-Fa-f:]*) return 1 ;; esac; [ "$_p" -le 128 ] ;;
		*) is_ipv4 "$_a" && [ "$_p" -le 32 ] ;;
	esac
}

# wg_each FILE CALLBACK: validate the wireguard file and call
#   CALLBACK tunnel NAME PORT PUBLIC COMMENT
#   CALLBACK peer NAME KEY ALLOWED ENDPOINT KEEPALIVE COMMENT
# With CALLBACK "-" only validates. Sets WG_TUNNELS and WG_PORTS.
wg_each() {
	_f=$1 _cb=$2
	_errors=0
	WG_TUNNELS='' WG_PORTS=''
	[ -r "$_f" ] || return 0
	_n=0
	while IFS= read -r _line || [ -n "$_line" ]; do
		_n=$((_n + 1))
		_c=
		case $_line in *'#'*) _c=$(_strip "${_line#*#}") ;; esac
		_line=$(_strip "$_line")
		[ -n "$_line" ] || continue
		is_comment "$_c" || { err "$_f" "$_n" "comment may only use letters, digits, spaces and _.,:/+- (max 64)"; continue; }
		# shellcheck disable=SC2086
		set -- $_line
		_kind=$1 _name=${2:-}
		[ $# -ge 2 ] || { err "$_f" "$_n" "expected: tunnel NAME ... or peer NAME ..."; continue; }
		shift 2
		is_iface "$_name" || { err "$_f" "$_n" "invalid tunnel name"; continue; }
		_bad=''
		case $_kind in
			tunnel)
				_port='' _pub=''
				for _kv; do
					case $_kv in
						port=*) is_port "${_kv#port=}" && _port=${_kv#port=} || _bad="port: 1-65535" ;;
						public=*) is_hostport "${_kv#public=}" && _pub=${_kv#public=} || _bad="public: HOST:PORT" ;;
						*) _bad="unknown field $_kv" ;;
					esac
				done
				[ -n "$_port" ] || _bad=${_bad:-"needs port="}
				case " $WG_TUNNELS " in *" $_name "*) _bad="tunnel $_name listed twice" ;; esac
				case " $WG_PORTS " in *" $_port "*) [ -z "$_port" ] || _bad="port $_port used twice" ;; esac
				[ -z "$_bad" ] || { err "$_f" "$_n" "$_name: $_bad"; continue; }
				WG_TUNNELS="${WG_TUNNELS:+$WG_TUNNELS }$_name"
				WG_PORTS="${WG_PORTS:+$WG_PORTS }$_port"
				[ "$_cb" = - ] || "$_cb" tunnel "$_name" "$_port" "$_pub" "$_c" ;;
			peer)
				_key='' _allowed='' _ep='' _ka=''
				for _kv; do
					case $_kv in
						key=*) is_wgkey "${_kv#key=}" && _key=${_kv#key=} || _bad="key: a WireGuard public key" ;;
						allowed=*)
							_allowed=${_kv#allowed=}
							for _a in $(echo "$_allowed" | tr ',' ' '); do
								is_allowed_ip "$_a" || _bad="allowed: comma separated IP/PREFIX"
							done
							[ -n "$_allowed" ] || _bad="allowed: comma separated IP/PREFIX" ;;
						endpoint=*) is_hostport "${_kv#endpoint=}" && _ep=${_kv#endpoint=} || _bad="endpoint: HOST:PORT" ;;
						keepalive=*) is_uint "${_kv#keepalive=}" && [ "${_kv#keepalive=}" -le 65535 ] && _ka=${_kv#keepalive=} || _bad="keepalive: seconds" ;;
						*) _bad="unknown field $_kv" ;;
					esac
				done
				[ -n "$_key" ] || _bad=${_bad:-"needs key="}
				[ -n "$_allowed" ] || _bad=${_bad:-"needs allowed="}
				case " $WG_TUNNELS " in *" $_name "*) ;; *) _bad="no tunnel line for $_name above this peer" ;; esac
				[ -z "$_bad" ] || { err "$_f" "$_n" "peer: $_bad"; continue; }
				[ "$_cb" = - ] || "$_cb" peer "$_name" "$_key" "$_allowed" "$_ep" "$_ka" "$_c" ;;
			*) err "$_f" "$_n" "expected: tunnel NAME ... or peer NAME ..." ;;
		esac
	done < "$_f"
	[ "$_errors" -eq 0 ]
}

# ---- extra packages -----------------------------------------------------------
# packages: one Alpine package name per line, with an optional "# comment".
# These are installed on top of the template (see pxmxfw pkg-*).

is_pkgname() {
	[ ${#1} -le 64 ] || return 1
	case $1 in ''|[!a-z0-9]*|*[!a-z0-9+._-]*) return 1 ;; esac
}

pkgs_each() { # FILE CALLBACK|-
	_f=$1 _cb=$2
	_errors=0
	[ -r "$_f" ] || return 0
	_n=0
	while IFS= read -r _line || [ -n "$_line" ]; do
		_n=$((_n + 1))
		_line=$(_strip "$_line")
		[ -n "$_line" ] || continue
		# shellcheck disable=SC2086
		set -- $_line
		{ [ $# -eq 1 ] && is_pkgname "$1"; } ||
			{ err "$_f" "$_n" "expected one package name (a-z 0-9 + . _ -)"; continue; }
		[ "$_cb" = - ] || "$_cb" "$1"
	done < "$_f"
	[ "$_errors" -eq 0 ]
}

# validate KIND FILE: KIND is settings, interfaces, rules, hosts, wireguard or packages
validate() {
	case $1 in
		packages) pkgs_each "$2" - ;;
		settings) settings_load "$2" ;;
		interfaces) settings_load 2>/dev/null; ifaces_each "$2" - ;;
		rules)
			# interface names are checked against the saved interfaces file
			settings_load 2>/dev/null
			ifaces_each "$PXMXFW_ETC/interfaces" - 2>/dev/null || IF_NAMES=''
			fw_each "$2" - ;;
		wireguard) wg_each "$2" - ;;
		hosts) rules_each "$1" "$2" - ;;
		*) echo "unknown kind: $1" >&2; return 2 ;;
	esac
}

# config_load: load and cross-check everything. Prints errors, returns 1.
# Also sets DNSMASQ_IFS, the interfaces dnsmasq serves.
config_load() {
	_ok=0
	settings_load || _ok=1
	rules_each hosts "$PXMXFW_ETC/hosts" - || _ok=1
	wg_each "$PXMXFW_ETC/wireguard" - || _ok=1
	ifaces_each "$PXMXFW_ETC/interfaces" - || _ok=1
	fw_each "$PXMXFW_ETC/rules" - || _ok=1
	for _t in $WG_TUNNELS; do
		[ "$_t" != "$WAN" ] || { echo "$PXMXFW_ETC/interfaces: tunnel $_t cannot be the WAN" >&2; _ok=1; }
		listed "$_t" || {
			echo "$PXMXFW_ETC/interfaces: tunnel $_t needs a line, e.g. \"$_t addr=10.99.0.1/24\"" >&2
			_ok=1
		}
	done
	DNSMASQ_IFS=''
	for _i in $DHCP_IFS $DNS_IFS $DHCPSVC_IFS; do
		if [ "$_i" = '*' ]; then _l=$IF_NAMES; else _l=$_i; fi
		for _j in $_l; do
			[ "$_j" != "$WAN" ] || continue
			case " $PORT_IFS $DNSMASQ_IFS " in *" $_j "*) continue ;; esac
			DNSMASQ_IFS="${DNSMASQ_IFS:+$DNSMASQ_IFS }$_j"
		done
	done
	if [ "$DNSMASQ" = yes ] && [ -z "$DNSMASQ_IFS" ]; then
		echo "$PXMXFW_ETC/pxmxfw.conf: DNSMASQ needs an interface other than the WAN with a dhcp= range or a rule accepting service dns or dhcp" >&2
		_ok=1
	fi
	return $_ok
}

# ---- rendering --------------------------------------------------------------

_nft_comment() { [ -n "$1" ] && printf ' comment "%s"' "$1"; }

# nft_set "a b": print { "a", "b" } for use after iifname/oifname
nft_set() {
	printf '{ '
	_first=1
	for _i in $1; do
		[ $_first = 1 ] || printf ', '
		printf '"%s"' "$_i"
		_first=0
	done
	printf ' }'
}

# nft_list "a,b": print a, or { a, b } for more than one
nft_list() {
	case $1 in
		*,*) printf '{ %s }' "$(echo "$1" | sed 's/,/, /g')" ;;
		*) printf '%s' "$1" ;;
	esac
}

# l DEPTH TEXT...: print one ruleset line indented by DEPTH tabs
l() {
	_d=$1; shift
	while [ "$_d" -gt 0 ]; do printf '\t'; _d=$((_d - 1)); done
	printf '%s\n' "$*"
}

# _match IN OUT SRC DST PROTO SPORT DPORT FAMILY [TCPFLAGS]: the nft match of a rule
_match() {
	_m=''
	[ -z "$1" ] || _m="$_m iifname $(nft_set "$(echo "$1" | tr ',' ' ')")"
	[ -z "$2" ] || _m="$_m oifname $(nft_set "$(echo "$2" | tr ',' ' ')")"
	# an IP version without addresses to imply it
	[ -z "$8" ] || [ -n "$3$4" ] || _m="$_m meta nfproto ipv$8"
	_ip=ip
	[ "$8" != 6 ] || _ip=ip6
	[ -z "$3" ] || _m="$_m $_ip saddr $(nft_list "$3")"
	[ -z "$4" ] || _m="$_m $_ip daddr $(nft_list "$4")"
	case $5 in
		tcp|udp)
			[ -n "$6$7" ] || _m="$_m meta l4proto $5"
			[ -z "$6" ] || _m="$_m $5 sport $(nft_list "$6")"
			[ -z "$7" ] || _m="$_m $5 dport $(nft_list "$7")" ;;
		tcp,udp)
			_m="$_m meta l4proto { tcp, udp }"
			[ -z "$6" ] || _m="$_m th sport $(nft_list "$6")"
			[ -z "$7" ] || _m="$_m th dport $(nft_list "$7")" ;;
		icmp)
			case $8 in
				4) _m="$_m meta l4proto icmp" ;;
				6) _m="$_m meta l4proto ipv6-icmp" ;;
				*) _m="$_m meta l4proto { icmp, ipv6-icmp }" ;;
			esac ;;
		icmpv6) _m="$_m meta l4proto ipv6-icmp" ;;
		# by number, so nothing depends on /etc/protocols
		gre) _m="$_m meta l4proto 47" ;;
		esp) _m="$_m meta l4proto 50" ;;
		ah) _m="$_m meta l4proto 51" ;;
		ipip) _m="$_m meta l4proto 4" ;;
	esac
	if [ -n "${9:-}" ]; then
		case $9 in
			*'|'*|*'&'*) ;;
			*) _m="$_m tcp flags & ($9) == $9" ;;
		esac
		case $9 in
			*'|'*) _m="$_m tcp flags & ($(echo "$9" | sed 's/|/ | /g')) != 0" ;;
			*'&'*)
				_mask='' _want=''
				for _t in $(echo "$9" | tr '&' ' '); do
					_mask="${_mask:+$_mask | }${_t#!}"
					case $_t in !*) ;; *) _want="${_want:+$_want | }$_t" ;; esac
				done
				_m="$_m tcp flags & ($_mask) == ${_want:-0}" ;;
		esac
	fi
	printf '%s' "${_m# }"
}

# _svc_match SERVICE: the nft match of a service of the firewall
_svc_match() {
	case $1 in
		ping) printf 'icmp type echo-request' ;;  # ICMPv6 is always allowed
		ssh) printf 'tcp dport 22' ;;
		webui) printf 'tcp dport %s' "$WEBUI_PORT" ;;
		dns) printf 'meta l4proto { tcp, udp } th dport 53' ;;
		dhcp) if [ "$IPV6" = yes ]; then printf 'udp dport { 67, 547 }'; else printf 'udp dport 67'; fi ;;
	esac
}

# fw_each callbacks: KIND ACTION IN OUT SRC DST PROTO SPORT DPORT SERVICE TO FAMILY TCPFLAGS COMMENT
_r_filter() { # rules of the chain in $_chain
	[ "$1" = "$_chain" ] || return 0
	_mt=$(_match "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${12}" "${13}")
	if [ -n "${10}" ]; then
		for _s in $(echo "${10}" | tr ',' ' '); do
			l 2 "${_mt:+$_mt }$(_svc_match "$_s") $2$(_nft_comment "${14}")"
		done
	else
		l 2 "${_mt:+$_mt }$2$(_nft_comment "${14}")"
	fi
}
_r_masq() {
	[ "$1" = masquerade ] || return 0
	_mt=$(_match "" "$4" "$5" "$6" "" "" "" "")
	l 2 "meta nfproto ipv4 $_mt masquerade$(_nft_comment "${14}")"
}
_r_dnat() {
	[ "$1" = dnat ] || return 0
	_mt=$(_match "$3" "" "$5" "$6" "$7" "" "$9" "")
	l 2 "$_mt dnat ip to ${11}$(_nft_comment "${14}")"
}

# Print the nftables ruleset. Needs config_load first. With FIREWALL=manual
# the rules are left to /etc/nftables.d, unless $1 is "rules".
render_nft() {
	if [ "$FIREWALL" = manual ] && [ "${1:-}" != rules ]; then
		l 0 "# Generated by pxmxfw: FIREWALL=manual in $PXMXFW_ETC/pxmxfw.conf, so the"
		l 0 "# firewall rules are the files in /etc/nftables.d/*.nft."
		return 0
	fi
	_rules=$PXMXFW_ETC/rules
	_nosyn='ct state new tcp flags & (fin | syn | rst | ack) != syn drop comment "new TCP without SYN"'
	_dhcp=67
	[ "$IPV6" = no ] || _dhcp='{ 67, 547 }'
	_wg=''
	[ -z "$WG_PORTS" ] || _wg="{ $(echo "$WG_PORTS" | sed 's/ /, /g') }"
	l 0 "# Generated by pxmxfw from $PXMXFW_ETC. Do not edit: run \"pxmxfw apply\"."
	l 0 "table inet pxmxfw {"
	l 1 "chain input {"
	l 2 "type filter hook input priority filter; policy drop;"
	l 0
	l 2 "ct state established,related accept"
	l 2 "ct state invalid drop"
	l 2 "$_nosyn"
	l 2 "iifname \"lo\" accept"
	l 2 "meta l4proto ipv6-icmp accept"
	l 2 "iifname \"$WAN_IF\" udp dport 546 accept comment \"DHCPv6 client\""
	[ -z "$_wg" ] || l 2 "udp dport $_wg accept comment \"wireguard\""
	if [ -n "$DHCP_IFS" ]; then
		l 2 "iifname $(nft_set "$DHCP_IFS") udp dport $_dhcp accept comment \"dhcp range\""
		l 2 "iifname $(nft_set "$DHCP_IFS") meta l4proto { tcp, udp } th dport 53 accept comment \"dns for dhcp clients\""
	fi
	_chain=input
	fw_each "$_rules" _r_filter
	l 1 "}"
	l 0
	l 1 "chain forward {"
	l 2 "type filter hook forward priority filter; policy drop;"
	l 0
	l 2 "ct state established,related accept"
	l 2 "ct state invalid drop"
	l 2 "$_nosyn"
	[ "$IPV6" = yes ] || l 2 "meta nfproto ipv6 drop comment \"IPv6 routing is off\""
	l 2 "ct status dnat accept comment \"port forwards\""
	if [ -n "$NOROUTE_IFS" ]; then
		l 2 "iifname $(nft_set "$NOROUTE_IFS") drop comment \"routing off\""
		l 2 "oifname $(nft_set "$NOROUTE_IFS") drop comment \"routing off\""
	fi
	_chain=forward
	fw_each "$_rules" _r_filter
	l 1 "}"
	l 0
	l 1 "chain output {"
	l 2 "type filter hook output priority filter; policy $OUTPUT_POLICY;"
	l 0
	l 2 "ct state established,related accept"
	l 2 "oifname \"lo\" accept"
	l 2 "meta l4proto ipv6-icmp accept"
	if [ "$OUTPUT_POLICY" = drop ]; then
		l 2 "oifname \"$WAN_IF\" udp dport { 67, 547 } accept comment \"DHCP client\""
		[ -z "$DHCP_IFS" ] || l 2 "oifname $(nft_set "$DHCP_IFS") udp sport $_dhcp accept comment \"dhcp range\""
		[ -z "$_wg" ] || l 2 "udp sport $_wg accept comment \"wireguard\""
	fi
	_chain=output
	fw_each "$_rules" _r_filter
	l 1 "}"
	l 0
	l 1 "chain prerouting {"
	l 2 "type nat hook prerouting priority dstnat; policy accept;"
	fw_each "$_rules" _r_dnat
	l 1 "}"
	l 0
	l 1 "chain postrouting {"
	l 2 "type nat hook postrouting priority srcnat; policy accept;"
	fw_each "$_rules" _r_masq
	l 1 "}"
	l 0 "}"
}

_d_host() { # ip name mac comment
	printf 'host-record=%s,%s\n' "$2" "$1"
	case $3 in *:*) printf 'dhcp-host=%s,%s,%s\n' "$3" "$1" "$2" ;; esac
}
_d_iface() { # name addr addr6 dhcp comment type link vid ports lease dns gateway routing routes
	case " $DNSMASQ_IFS " in *" $1 "*) ;; *) return 0 ;; esac
	echo "interface=$1"
	if [ -n "$4" ]; then
		echo "dhcp-range=set:$1,${4%-*},${4#*-},${10:-$DHCP_LEASE}"
		[ -z "${11}" ] || echo "dhcp-option=tag:$1,option:dns-server,${11}"
		_dg=${12}
		# without routing, clients get no default route unless another router is named
		[ -n "$_dg" ] || [ "${13}" = yes ] || _dg=none
		case $_dg in
			'') ;;
			none) echo "dhcp-option=tag:$1,option:router" ;;
			*) echo "dhcp-option=tag:$1,option:router,$_dg" ;;
		esac
		if [ -n "${14}" ]; then
			# Option 121: clients that take it ignore the router option, so
			# the default route goes in too. The firewall's own address on
			# this interface is the next hop.
			_me=''
			case $2 in proxmox) _me=$(proxmox_address "$1" || true) ;; none) ;; *) _me=$2 ;; esac
			_me=${_me%/*}
			if [ -z "$_me" ]; then
				echo "pxmxfw: $1: routes= needs an address on $1 that pxmxfw knows (addr=IP/PREFIX, or a static one from Proxmox)" >&2
			else
				_dr=''
				for _rn in $(echo "${14}" | tr ',' ' '); do _dr="$_dr,$_rn,$_me"; done
				case $_dg in
					none) ;;
					'') _dr="$_dr,0.0.0.0/0,$_me" ;;
					*) _dr="$_dr,0.0.0.0/0,$_dg" ;;
				esac
				echo "dhcp-option=tag:$1,option:classless-static-route${_dr}"
			fi
		fi
	fi
	if [ "$IPV6" = yes ] && [ "$3" != none ]; then
		echo "dhcp-range=::,constructor:$1,ra-stateless,ra-names"
		# router lifetime 0: not a default router when nothing is routed
		[ "${13}" = yes ] || echo "ra-param=$1,60,0"
	fi
}

# Print the dnsmasq configuration. Needs config_load first.
render_dnsmasq() {
	cat <<-EOF
	# Generated by pxmxfw from $PXMXFW_ETC. Do not edit: run "pxmxfw apply".
	bind-dynamic
	domain-needed
	bogus-priv
	cache-size=1000
	domain=$DNS_DOMAIN
	local=/$DNS_DOMAIN/
	expand-hosts
	dhcp-authoritative
	EOF
	[ "$IPV6" = no ] || echo enable-ra
	if [ -n "$DNS_UPSTREAM" ]; then
		echo no-resolv
		for _s in $DNS_UPSTREAM; do echo "server=$_s"; done
	else
		echo "# upstream servers come from /etc/resolv.conf (set by Proxmox)"
	fi
	ifaces_each "$PXMXFW_ETC/interfaces" _d_iface
	rules_each hosts "$PXMXFW_ETC/hosts" _d_host
}

# ---- Proxmox and the running system ----------------------------------------

# proxmox_method IFACE [inet|inet6]: how Proxmox configured IFACE in the
# ifupdown file it writes on every container start (static, dhcp, auto,
# manual), or nothing when Proxmox has no address for it.
proxmox_method() {
	[ -r "$PXMXFW_NET_INTERFACES" ] || return 0
	awk -v ifc="$1" -v fam="${2:-inet}" '$1 == "iface" && $2 == ifc && $3 == fam { print $4; exit }' "$PXMXFW_NET_INTERFACES"
}

# proxmox_address IFACE: "ADDR/PREFIX" of a static IPv4 set by Proxmox.
proxmox_address() {
	[ -r "$PXMXFW_NET_INTERFACES" ] || return 1
	awk -v ifc="$1" '
		$1 == "iface" { cur = ($2 == ifc && $3 == "inet"); next }
		cur && $1 == "address" { addr = $2 }
		cur && $1 == "netmask" { mask = $2 }
		END {
			if (addr == "") exit 1
			if (addr !~ /\//) {
				n = split(mask, m, "."); bits = 0
				for (i = 1; i <= n; i++) { v = m[i] + 0; while (v > 0) { bits += v % 2; v = int(v / 2) } }
				addr = addr "/" (bits ? bits : 24)
			}
			print addr
		}' "$PXMXFW_NET_INTERFACES"
}

# dhcp_range_for ADDR/PREFIX: print "START-END" (.100 to .200 of the subnet)
# for prefixes of /24 or shorter.
dhcp_range_for() {
	_ip=${1%/*} _p=${1#*/}
	is_ipv4 "$_ip" && is_uint "$_p" && [ "$_p" -ge 8 ] && [ "$_p" -le 24 ] || return 1
	_old_ifs=$IFS; IFS=.
	# shellcheck disable=SC2086
	set -- $_ip
	IFS=$_old_ifs
	_n=$(( ($1 << 24) | ($2 << 16) | ($3 << 8) | $4 ))
	_n=$(( _n & ((0xffffffff << (32 - _p)) & 0xffffffff) ))
	_fmt() { printf '%d.%d.%d.%d' $(( ($1 >> 24) & 255 )) $(( ($1 >> 16) & 255 )) $(( ($1 >> 8) & 255 )) $(( $1 & 255 )); }
	printf '%s-%s\n' "$(_fmt $((_n + 100)))" "$(_fmt $((_n + 200)))"
}

# present_ifaces: network interfaces of this container, except lo
present_ifaces() {
	# callers run with "set -f", so turn globbing on just for this
	case $- in *f*) set +f; _pf=1 ;; *) _pf= ;; esac
	for _p in "$PXMXFW_SYSNET"/*; do
		_n=${_p##*/}
		[ "$_n" != lo ] && [ -d "$_p" ] && echo "$_n"
	done
	[ -z "$_pf" ] || set -f
	return 0
}

# iface_ipv4 IFACE: first IPv4 address on IFACE (without prefix)
iface_ipv4() {
	ip -4 -o addr show dev "$1" 2>/dev/null | awk '{ sub(/\/.*/, "", $4); print $4; exit }'
}
