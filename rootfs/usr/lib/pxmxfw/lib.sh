# pxmxfw shell library: read, validate and render the configuration.
#
# Config lives in $PXMXFW_ETC (default /etc/pxmxfw):
#   pxmxfw.conf  KEY=value settings
#   interfaces   "IFACE role=wan|lan|isolated|off [addr=..] [addr6=..] [dhcp=START-END]"
#   services     "proto port [# comment]"            open on WAN to the firewall
#   forwards     "proto wanport lanip lanport [# c]" port forwards to the LAN
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
	NAT=yes
	WAN_PING=yes
	IPV6=no
	WEBUI_PORT=8443
	WEBUI_WAN=no
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
			NAT) is_yesno "$_v" && NAT=$_v || err "$_f" "$_n" "NAT: use yes or no" ;;
			WAN_PING) is_yesno "$_v" && WAN_PING=$_v || err "$_f" "$_n" "WAN_PING: use yes or no" ;;
			IPV6) is_yesno "$_v" && IPV6=$_v || err "$_f" "$_n" "IPV6: use yes or no" ;;
			WEBUI_PORT) is_port "$_v" && WEBUI_PORT=$_v || err "$_f" "$_n" "WEBUI_PORT: 1-65535" ;;
			WEBUI_WAN) is_yesno "$_v" && WEBUI_WAN=$_v || err "$_f" "$_n" "WEBUI_WAN: use yes or no" ;;
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
	NAT=$NAT
	WAN_PING=$WAN_PING
	IPV6=$IPV6
	WEBUI_PORT=$WEBUI_PORT
	WEBUI_WAN=$WEBUI_WAN
	DNSMASQ=$DNSMASQ
	DNS_UPSTREAM=$DNS_UPSTREAM
	DNS_DOMAIN=$DNS_DOMAIN
	DHCP_LEASE=$DHCP_LEASE
	EOF
}

# ---- interfaces -------------------------------------------------------------
# One line per network interface:
#   IFACE role=ROLE [addr=A] [addr6=A] [dhcp=START-END] [# comment]
# role:  wan       the uplink, exactly one, addresses always set by Proxmox
#        lan       trusted: reaches WAN and every other lan interface
#        isolated  reaches WAN only (e.g. guests, DMZ)
#        off       all traffic from it is dropped (new interfaces start here)
# addr:  proxmox (default: Proxmox sets it), none, or IPv4/prefix set by pxmxfw
# addr6: same for IPv6, used only when IPV6=yes
# dhcp:  IPv4 range dnsmasq hands out on this interface

# ifaces_each FILE CALLBACK: validate the interfaces file and call CALLBACK
# with: name role addr addr6 dhcp comment. With CALLBACK "-" only validates.
# Also sets WAN_IF, LAN_IFS (role lan), ISO_IFS (role isolated), IN_IFS (both).
ifaces_each() {
	_f=$1 _cb=$2
	_errors=0
	WAN_IF='' LAN_IFS='' ISO_IFS='' IN_IFS=''
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
		_role='' _addr=proxmox _addr6=proxmox _dhcp='' _bad=''
		for _kv; do
			case $_kv in
				role=wan|role=lan|role=isolated|role=off) _role=${_kv#role=} ;;
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
		[ -n "$_role" ] || _bad="needs role=wan, lan, isolated or off"
		if [ -z "$_bad" ] && [ "$_role" = wan ]; then
			[ "$_addr" = proxmox ] && [ "$_addr6" = proxmox ] || _bad="the WAN address is set in Proxmox (addr=proxmox)"
			[ -z "$_dhcp" ] || _bad="no DHCP server on WAN"
			[ -z "$WAN_IF" ] || _bad="only one interface can be wan"
		fi
		[ -z "$_bad" ] || { err "$_f" "$_n" "$_name: $_bad"; continue; }
		case $_role in
			wan) WAN_IF=$_name ;;
			lan) LAN_IFS="$LAN_IFS $_name"; IN_IFS="$IN_IFS $_name" ;;
			isolated) ISO_IFS="$ISO_IFS $_name"; IN_IFS="$IN_IFS $_name" ;;
		esac
		[ "$_cb" = - ] || "$_cb" "$_name" "$_role" "$_addr" "$_addr6" "$_dhcp" "$_c"
	done < "$_f"
	LAN_IFS=${LAN_IFS# } ISO_IFS=${ISO_IFS# } IN_IFS=${IN_IFS# }
	[ -n "$WAN_IF" ] || [ "$_errors" -gt 0 ] || err "$_f" 0 "one interface needs role=wan"
	[ "$_errors" -eq 0 ]
}

# ---- rule lists -----------------------------------------------------------

# rules_each KIND FILE CALLBACK: validate every line of a rule file and call
# CALLBACK with its fields (comment last, may be empty). With CALLBACK "-"
# only validates. Returns 1 when any line is invalid.
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
			services)
				[ $# -eq 2 ] && is_proto "$1" && is_portrange "$2" ||
					{ err "$_f" "$_n" "expected: tcp|udp PORT[-PORT]"; continue; } ;;
			forwards)
				[ $# -eq 4 ] && is_proto "$1" && is_port "$2" && is_ipv4 "$3" && is_port "$4" ||
					{ err "$_f" "$_n" "expected: tcp|udp WANPORT LANIP LANPORT"; continue; } ;;
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
# interfaces file, which sets its role and its tunnel address. The private
# key is created on the first apply in $PXMXFW_ETC/wg/NAME.key.

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

# validate KIND FILE: KIND is settings, interfaces, services, forwards, hosts or wireguard
validate() {
	case $1 in
		settings) settings_load "$2" ;;
		interfaces) ifaces_each "$2" - ;;
		wireguard) wg_each "$2" - ;;
		services|forwards|hosts) rules_each "$1" "$2" - ;;
		*) echo "unknown kind: $1" >&2; return 2 ;;
	esac
}

# config_load: load and cross-check everything. Prints errors, returns 1.
config_load() {
	_ok=0
	settings_load || _ok=1
	for _k in services forwards hosts; do
		rules_each "$_k" "$PXMXFW_ETC/$_k" - || _ok=1
	done
	wg_each "$PXMXFW_ETC/wireguard" - || _ok=1
	ifaces_each "$PXMXFW_ETC/interfaces" - || _ok=1
	for _t in $WG_TUNNELS; do
		[ "$_t" != "$WAN_IF" ] || { echo "$PXMXFW_ETC/interfaces: tunnel $_t cannot be the wan" >&2; _ok=1; }
		awk -v t="$_t" '$1 == t { f = 1 } END { exit !f }' "$PXMXFW_ETC/interfaces" 2>/dev/null || {
			echo "$PXMXFW_ETC/interfaces: tunnel $_t needs a line, e.g. \"$_t role=lan addr=10.99.0.1/24\"" >&2
			_ok=1
		}
	done
	if [ "$DNSMASQ" = yes ] && [ -z "$IN_IFS" ]; then
		echo "$PXMXFW_ETC/pxmxfw.conf: DNSMASQ needs an interface with role lan or isolated" >&2
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

# l DEPTH TEXT...: print one ruleset line indented by DEPTH tabs
l() {
	_d=$1; shift
	while [ "$_d" -gt 0 ]; do printf '\t'; _d=$((_d - 1)); done
	printf '%s\n' "$*"
}

_r_service() { # proto port comment
	l 2 "iifname \"$WAN_IF\" $1 dport $2 accept$(_nft_comment "$3")"
}
_r_dnat() { # proto wanport lanip lanport comment
	l 2 "iifname \"$WAN_IF\" $1 dport $2 dnat ip to $3:$4$(_nft_comment "$5")"
}

# Print the nftables ruleset. Needs config_load first.
render_nft() {
	_v4=
	[ "$IPV6" = yes ] || _v4='meta nfproto ipv4 '
	_in=$(nft_set "$IN_IFS")
	l 0 "# Generated by pxmxfw from $PXMXFW_ETC. Do not edit: run \"pxmxfw apply\"."
	l 0 "table inet pxmxfw {"
	l 1 "chain input {"
	l 2 "type filter hook input priority filter; policy drop;"
	l 0
	l 2 "ct state established,related accept"
	l 2 "ct state invalid drop"
	l 2 "iifname \"lo\" accept"
	l 2 "meta l4proto ipv6-icmp accept"
	l 2 "iifname \"$WAN_IF\" udp dport 546 accept comment \"DHCPv6 client\""
	[ -z "$WG_PORTS" ] || l 2 "udp dport { $(echo "$WG_PORTS" | sed 's/ /, /g') } accept comment \"wireguard\""
	if [ "$WAN_PING" = yes ]; then
		l 2 "icmp type echo-request accept"
	elif [ -n "$IN_IFS" ]; then
		l 2 "iifname $_in icmp type echo-request accept"
	fi
	if [ -n "$IN_IFS" ]; then
		l 2 "iifname $_in tcp dport { 22, 53, $WEBUI_PORT } accept comment \"inside: ssh, dns, web UI\""
		if [ "$IPV6" = yes ]; then
			l 2 "iifname $_in udp dport { 53, 67, 547 } accept comment \"inside: dns, dhcp\""
		else
			l 2 "iifname $_in udp dport { 53, 67 } accept comment \"inside: dns, dhcp\""
		fi
	fi
	[ "$WEBUI_WAN" = no ] ||
		l 2 "iifname \"$WAN_IF\" tcp dport $WEBUI_PORT accept comment \"web UI from WAN\""
	rules_each services "$PXMXFW_ETC/services" _r_service
	l 1 "}"
	l 0
	l 1 "chain forward {"
	l 2 "type filter hook forward priority filter; policy drop;"
	l 0
	l 2 "ct state established,related accept"
	l 2 "ct state invalid drop"
	l 2 "ct status dnat accept comment \"port forwards\""
	[ -z "$LAN_IFS" ] ||
		l 2 "iifname $(nft_set "$LAN_IFS") oifname $(nft_set "$LAN_IFS") ${_v4}accept comment \"lan to lan\""
	[ -z "$IN_IFS" ] ||
		l 2 "iifname $_in oifname \"$WAN_IF\" ${_v4}accept comment \"inside to WAN\""
	l 1 "}"
	l 0
	l 1 "chain prerouting {"
	l 2 "type nat hook prerouting priority dstnat; policy accept;"
	rules_each forwards "$PXMXFW_ETC/forwards" _r_dnat
	l 1 "}"
	l 0
	l 1 "chain postrouting {"
	l 2 "type nat hook postrouting priority srcnat; policy accept;"
	[ "$NAT" = no ] ||
		l 2 "meta nfproto ipv4 oifname \"$WAN_IF\" masquerade"
	l 1 "}"
	l 0 "}"
}

_d_host() { # ip name mac comment
	printf 'host-record=%s,%s\n' "$2" "$1"
	case $3 in *:*) printf 'dhcp-host=%s,%s,%s\n' "$3" "$1" "$2" ;; esac
}
_d_iface() { # name role addr addr6 dhcp comment
	case $2 in lan|isolated) ;; *) return 0 ;; esac
	echo "interface=$1"
	[ -z "$5" ] || echo "dhcp-range=set:$1,${5%-*},${5#*-},$DHCP_LEASE"
	if [ "$IPV6" = yes ] && [ "$4" != none ]; then
		echo "dhcp-range=::,constructor:$1,ra-stateless,ra-names"
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
