# pxmxfw
Alpine based lxc firewall for proxmox

A small Alpine Linux container template that routes and filters traffic
for a Proxmox host, using nftables. It comes with a small web UI, optional
DNS and DHCP (dnsmasq, off by default), and checks that tell you which
kernel modules to load on the Proxmox host.

## Download

Each `v*` release has a ready-made template. On the Proxmox host:

```sh
cd /var/lib/vz/template/cache
wget https://github.com/rumblebump/pxmxfw/releases/latest/download/pxmxfw_amd64.tar.gz
```

Or in the web UI: *local* storage, *CT Templates*, *Download from URL*, with
the same link. `SHA256SUMS` in the release lists the checksums.

The newest build of `main` (for testing, not a release) is always at
`https://github.com/rumblebump/pxmxfw/releases/download/edge/pxmxfw_amd64.tar.gz`.
The zipped files under a workflow run's *Artifacts* need a GitHub login, so
Proxmox cannot download those.
Every Monday a scheduled workflow checks for a new Alpine point release and,
if edge was built on an older one, rebuilds edge (the release notes name the
Alpine version).

## Build the template

With [podman](https://podman.io) on any x86_64 Linux, no root needed:

```sh
./build.sh --podman
```

Or as root on an x86_64 Linux host with internet access (a Proxmox node works):

```sh
./build.sh
```

This downloads the Alpine minirootfs (checksum verified), installs
`alpine-base`, `nftables`, `dnsmasq`, `wireguard-tools-wg`, `linux-pam` and
`sqlite-libs`, builds the web UI server from `webui/` with Alpine's Go, adds [Alpine.js](https://alpinejs.dev) and xterm.js (pinned by checksum), applies
the files under `rootfs/`, enables the services and writes
`out/alpine-<version>-pxmxfw-<date>_amd64.tar.gz`. Run `./build.sh -h` for
options (Alpine version, mirror, output dir, local minirootfs).

GitHub Actions runs the tests and the podman build on every push and pull
request and uploads the tarball as a workflow artifact. Pushing a `v*` tag
also attaches it to a GitHub release.

## Create the container

[docs/proxmox-setup.md](docs/proxmox-setup.md) is the full walk-through:
the two bridges, privileged vs unprivileged, nesting, IP forwarding, the
host kernel modules and `pct create`. The short version:

If you built the template yourself, copy it from `out/` to
`/var/lib/vz/template/cache/` first and use its file name below.

```sh
pct create 200 local:vztmpl/pxmxfw_amd64.tar.gz \
  --hostname pxmxfw --ostype alpine --unprivileged 1 \
  --cores 1 --memory 128 --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --net1 name=eth1,bridge=vmbr1,ip=192.168.10.1/24 \
  --password
pct start 200
```

`vmbr0` is the upstream bridge (WAN) and `vmbr1` the protected network
(LAN). Set a root password (`--password`): the web UI logs in as root with it.

## First start

Proxmox writes `/etc/network/interfaces`, `/etc/hostname`, `/etc/hosts` and
`/etc/resolv.conf` into the container on every start, so pxmxfw never edits
them. On the first start it reads what Proxmox set and writes its own
defaults to `/etc/pxmxfw`:

- `eth0` (net0) is the WAN. Its address always comes from Proxmox.
- `eth1` (net1) is a LAN. If it has a static address, the DHCP range
  defaults to `.100` to `.200` of its subnet.
- dnsmasq (DNS and DHCP) and IPv6 routing stay off until you turn them on.
- With only one NIC, the web UI is allowed on the WAN side so you can
  finish the setup; turn that off once a LAN exists.

NICs you add later (`pct set 200 -net2 name=eth2,bridge=vmbr2`) are found at
the next start or when you open the web UI, and start with `role=off`.

### VLANs, bridges and tunnels

**Add interface** on the Interfaces page creates a VLAN (on a NIC, with an
802.1Q ID), a bridge (joining NICs that are switched off) or a WireGuard
tunnel. A new interface starts as `lan`, so it is routed to the other lans
and to WAN, answers ping and reaches nothing else on the firewall. It gets
the first free /24 of the subnet pool (`10.20.0.0/16` unless you change it
there). Tick DHCP to hand out `.100` to `.200`, which also allows DNS and
DHCP.

VLANs need the `8021q` module and bridges the `bridge` module on the
Proxmox host. A kind whose module is not loaded is greyed out, and the
Checks page shows the `modprobe` command.

## Web UI

Open `https://<LAN address>:8443` and log in as `root` (or a member of the
`pxmxfw` group) with that user's password. It has:

- **Status**: firewall, dnsmasq, forwarding, interfaces and addresses.
- **Interfaces**: role of each NIC, addresses for NICs Proxmox does not
  configure, DHCP ranges, and the IPv6 switch.
- **Firewall**: NAT, ping, ports open on WAN, port forwards.
- **DNS & DHCP**: global settings: turn dnsmasq on, upstream servers, the
  local domain, the default lease time, and names outside your subnets.
  Per interface (Interfaces, *DHCP & DNS*): the DHCP range, lease time, DNS
  servers and gateway handed out, fixed addresses and names, and its
  current leases.
- **Checks**: tests each kernel feature the firewall needs (nftables,
  conntrack, NAT, WireGuard), IP forwarding and the interfaces. A container
  cannot load kernel modules, so for anything missing it shows the
  `modprobe` and `/etc/modules-load.d` commands to run on the Proxmox host.
- **Packages**: search, install and remove Alpine packages, and upgrade
  everything. Each change needs a confirmation.
- **Terminal**: a shell in the container ([xterm.js](https://xtermjs.org)),
  as the user you logged in with. Opening it needs a fresh confirmation;
  it closes when you log out or after 15 minutes without typing. Opening
  and closing are in the change log.
- **Security**: two-factor login, access tokens and the log of recent
  changes.

### Login and security

The UI is served by `pxmxfw-webui`, a small Go server (source in `webui/`).

- **HTTPS**: on first start it creates a self-signed certificate in
  `/etc/pxmxfw/tls/webui.crt` and `webui.key`. Replace both files with a
  certificate from your own CA or ACME to get rid of the browser warning,
  then `rc-service pxmxfw-webui restart`.
- **Passwords** are checked by PAM (`/etc/pam.d/pxmxfw`), so password
  changes apply at once and other PAM modules can be added there.
- **Two-factor login (TOTP)**: turn it on under Security with any
  authenticator app. Logins then need the code as well.
- **Security keys** (Nitrokey, YubiKey, any FIDO2 key): add them under
  Security. Logins then need the key, and it confirms changes with a touch.
  Browsers only allow security keys on a host name with a trusted
  certificate, so open the UI by name (for example `https://fw.lan:8443`)
  and install a certificate for that name in `/etc/pxmxfw/tls/`. A key only
  works under the name it was added with. TOTP, if set up, stays usable as
  a fallback.
- **Changes are confirmed**: saving, applying, and managing tokens or 2FA
  ask for a fresh confirmation: a security key touch or TOTP code, or the
  password when neither is set up. A confirmation lasts 5 minutes.
- **Access tokens** for Ansible and scripts: create one under Security and
  send it as `Authorization: Bearer pxm_...`. A `read` token can read status
  and files; a `write` token can also `save` and `apply`, without the
  confirmation step. Tokens cannot manage logins or other tokens.
- Sessions end after 30 minutes idle or 12 hours. Five failed logins from
  one address or for one user block further tries for 5 minutes.
- The UI's own state (sessions, TOTP secrets, token hashes, preferences, the
  change log) is in SQLite at `/var/lib/pxmxfw/webui.db`. The firewall
  config stays in `/etc/pxmxfw`.
- It only listens on the LAN address. Every change also needs an `X-Pxmxfw`
  header (tokens aside), so other web pages cannot make a logged-in browser
  change anything.

Example with a token:

```sh
T=pxm_...
curl -k -H "Authorization: Bearer $T" 'https://192.168.10.1:8443/api?action=file&name=services'
curl -k -H "Authorization: Bearer $T" --data-binary @services 'https://192.168.10.1:8443/api?action=save&name=services'
curl -k -H "Authorization: Bearer $T" -X POST 'https://192.168.10.1:8443/api?action=apply'
```

## WireGuard

Tunnels are interfaces with the same roles as NICs, so a tunnel with role
`lan` joins the networks behind its peers with your other lans. That is how
you connect Proxmox nodes, sites or external machines. On the WireGuard page:

1. **Add tunnel** creates `wg0` with a port and a tunnel address
   (10.99.0.1/24 by default). Fill in the public endpoint (the host and port
   peers connect to), then save and apply. The tunnel's key pair is created
   then and its public key is shown.
2. **Another pxmxfw** (e.g. on another Proxmox node): add a tunnel there
   too, then on each side add the other as a peer with its public key,
   allowed IPs (its tunnel address as /32 plus the LANs behind it) and
   endpoint. Open the WAN port for it where the other side has a firewall
   in front.
3. **An external machine**: **New peer with generated keys** adds a peer
   and shows a ready config (for `wg-quick` or the WireGuard app) with a
   free tunnel address. Its private key is not stored, so copy it then.

Routes for each peer's allowed IPs point into the tunnel; a `/0` is never
routed, so a peer cannot take over the default route. The tunnel's UDP port
is opened automatically. The container needs the `wireguard` module on the
Proxmox host: the Checks page shows the command.

### Extra packages

Packages added in the UI or with `pxmxfw pkg-add NAME` are listed in
`/etc/pxmxfw/packages`, one per line. After editing that file (by hand,
Ansible or git), `pxmxfw pkg-sync` installs whatever is missing, so a new
container can be brought to the same state. `pxmxfw pkg-del` only removes
packages from that list, never the ones the template needs.

## Configuration

Everything lives in small text files in `/etc/pxmxfw`. The web UI edits the
same files, and `pxmxfw apply` turns them into the nftables ruleset and the
dnsmasq config. Nothing else needs editing.

| File | Content |
| --- | --- |
| `pxmxfw.conf` | `KEY=value` settings: `NAT`, `WAN_PING`, `IPV6`, `WEBUI_PORT`, `WEBUI_WAN`, `DNSMASQ`, `DNS_UPSTREAM`, `DNS_DOMAIN`, `DHCP_LEASE` |
| `interfaces` | `IFACE role=wan\|lan\|isolated\|off [addr=proxmox\|none\|IP/PREFIX] [addr6=...] [dhcp=START-END] [lease=TIME] [dns=IP,IP] [gateway=IP\|none] [allow=ping,ssh,dns,dhcp,webui\|none] [type=vlan link=IFACE vid=N \| type=bridge ports=IFACE,...]` |
| `services` | `tcp\|udp PORT[-PORT]`: open on WAN to the firewall itself |
| `forwards` | `tcp\|udp WANPORT LANIP LANPORT`: port forwards |
| `hosts` | `IP NAME [MAC]`: local DNS names, fixed DHCP leases with a MAC |
| `wireguard` | `tunnel NAME port=PORT [public=HOST:PORT]` then `peer NAME key=PUBKEY allowed=CIDR[,CIDR] [endpoint=HOST:PORT] [keepalive=S]` |
| `wg/NAME.key` | a tunnel's private key, created on the first apply |

Roles: `lan` reaches the WAN and every other `lan`; `isolated` reaches the
WAN only; `off` drops everything. `allow` is what a `lan` or `isolated`
interface may reach on the firewall itself; without it, everything (how the
LAN from the first boot starts). VLANs and bridges are created by `pxmxfw
apply` and removed again when their line is removed. With `IPV6=no` (the default) only IPv4 is
forwarded.

```sh
pxmxfw apply      # validate, set addresses, load the rules, update dnsmasq
pxmxfw check      # kernel modules, forwarding, interfaces
pxmxfw status
```

Every value is checked before anything changes, and `apply` gives the same
result however often it runs. To manage the firewall with Ansible, Puppet
or git, write the files in `/etc/pxmxfw` and run `pxmxfw apply`. Extra
hand-written nftables rules go in `/etc/nftables.d/*.nft`.

No SSH server is installed; use `pct enter 200`, or `apk add openssh` and
allow it on WAN in `services` if you need it.

## Tests

```sh
sudo tests/run.sh                    # dash; as root the rules are also loaded
sudo SH="busybox ash" tests/run.sh   # the shell Alpine uses
cd webui && go test -tags libsqlite3 ./...   # web UI server (needs PAM and SQLite headers)
```
