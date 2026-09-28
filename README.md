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
The same root filesystem is also on ghcr.io as an OCI image, for Proxmox
versions that create containers from OCI images:
`ghcr.io/rumblebump/pxmxfw:latest`, `:edge`, or a version such as
`:0.1.0-alpine3.22.6`.

## Releases and CI

The *CI* workflow runs in stages: **test** (Go, shellcheck, rule tests),
**build** (the template), then **test-template** (config and web UI checks
inside the built template) and **security** (a [Trivy](https://trivy.dev) scan
that lists known CVEs with a fix in the run summary), and last **release**
(GitHub releases and ghcr.io images; not for pull requests).

Releases are tagged `v<pxmxfw version>+alpine<Alpine version>`, e.g.
`v0.1.0+alpine3.22.6`. Edge is rebuilt after every merge and every Monday with
fresh Alpine packages. When a build of `main` lands on a newer Alpine than the
last release, it publishes the next patch version automatically, e.g.
`v0.1.1+alpine3.22.7`. For pxmxfw changes, run *CI* on `main` from the Actions
tab with a higher version in *release* (e.g. `0.2.0`), or push such a tag.

[Renovate](https://docs.renovatebot.com) (`renovate.json`) opens PRs for Go
modules, GitHub Actions and Trivy, and merges new Alpine branches (e.g. 3.23)
on its own once CI passes; it needs the Renovate GitHub App installed on the
repository.

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
- Rules: the LAN reaches the WAN (with NAT) and every service of the
  firewall (ping, SSH, DNS, DHCP, web UI); the WAN only gets ping answered.
- dnsmasq (DNS and DHCP) and IPv6 routing stay off until you turn them on.
- With only one NIC, a rule allows the web UI on the WAN side so you can
  finish the setup; remove it once a LAN exists.

NICs you add later (`pct set 200 -net2 name=eth2,bridge=vmbr2`) are found at
the next start or when you open the web UI. No rule names them, so nothing
passes through them until you add rules.

### VLANs, bridges and tunnels

**Add interface** on the Interfaces page creates a VLAN (on a NIC, with an
802.1Q ID), a bridge (joining NICs without an address) or a WireGuard
tunnel. A new interface gets two rules: it reaches the WAN, and it can ping
the firewall. It gets the first free /24 of the subnet pool (`10.20.0.0/16`
unless you change it there). Tick DHCP to hand out `.100` to `.200`, which
also lets DNS and DHCP in on that interface.

VLANs need the `8021q` module and bridges the `bridge` module on the
Proxmox host. A kind whose module is not loaded is greyed out, and the
Checks page shows the `modprobe` command.

## Web UI

Open `https://<LAN address>:8443` and log in as `root` (or a member of the
`pxmxfw` group) with that user's password. It has:

- **Status**: firewall, dnsmasq, forwarding, interfaces and addresses.
- **Interfaces**: addresses for NICs Proxmox does not configure, VLANs,
  bridges, DHCP ranges, and the IPv6 switch.
- **Firewall**: which interfaces reach the firewall's own services (ping,
  SSH, DNS, DHCP, web UI, as a grid), and rule tables: to this firewall,
  forwarding between interfaces, from this firewall, port forwards and NAT.
  Each rule matches on in and out interface, source and destination
  address or network, protocol, and source and destination port. See
  [Firewall rules](#firewall-rules).
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
- It only listens on the address of the interface the rules let reach it
  (on all addresses when rules let more than one interface reach it). Every change also needs an `X-Pxmxfw`
  header (tokens aside), so other web pages cannot make a logged-in browser
  change anything.

Example with a token:

```sh
T=pxm_...
curl -k -H "Authorization: Bearer $T" 'https://192.168.10.1:8443/api?action=file&name=rules'
curl -k -H "Authorization: Bearer $T" --data-binary @rules 'https://192.168.10.1:8443/api?action=save&name=rules'
curl -k -H "Authorization: Bearer $T" -X POST 'https://192.168.10.1:8443/api?action=apply'
```

## WireGuard

Tunnels are interfaces like NICs, so firewall rules say what passes through
them. Forwarding rules between a tunnel and your LANs (for example
`forward accept in=eth1,wg0 out=eth1,wg0`) join the networks behind its
peers with yours. That is how you connect Proxmox nodes, sites or external
machines. On the WireGuard page:

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
| `pxmxfw.conf` | `KEY=value` settings: `WAN` (default `eth0`), `FIREWALL` (`rules` or `manual`), `OUTPUT_POLICY` (`accept` or `drop`), `IPV6`, `WEBUI_PORT`, `DNSMASQ`, `DNS_UPSTREAM`, `DNS_DOMAIN`, `DHCP_LEASE` |
| `interfaces` | `IFACE [addr=proxmox\|none\|IP/PREFIX] [addr6=...] [routing=yes\|no] [dhcp=START-END] [lease=TIME] [dns=IP,IP] [gateway=IP\|none] [routes=NET,NET] [type=vlan link=IFACE vid=N \| type=bridge ports=IFACE,...]` |
| `rules` | firewall rules, see below |
| `hosts` | `IP NAME [MAC]`: local DNS names, fixed DHCP leases with a MAC |
| `wireguard` | `tunnel NAME port=PORT [public=HOST:PORT]` then `peer NAME key=PUBKEY allowed=CIDR[,CIDR] [endpoint=HOST:PORT] [keepalive=S]` |
| `wg/NAME.key` | a tunnel's private key, created on the first apply |

Interfaces have no role: the `rules` file decides what passes. The WAN only
differs in that Proxmox sets its address and it runs no DHCP server. VLANs
and bridges are created by `pxmxfw apply` and removed again when their line
is removed; a bridge's ports carry no address, and rules name the bridge.

Each interface is either **routed** (the default) or **not routed**
(`routing=no`):

- Routed: forwarding rules decide where its traffic may go, and DHCP hands
  out the firewall as gateway (or `gateway=`), its DNS servers (`dns=`,
  the firewall by default) and, with `routes=`, routes to other networks
  through the firewall (DHCP option 121, for example with `gateway=none`
  so clients keep their own default route).
- Not routed: nothing is routed from or to it, whatever the forwarding
  rules say, and DHCP hands out no default route. Its clients only reach
  the firewall itself (what the access grid or input rules allow, such as
  DNS) and port forwards on the firewall's address there (`dnat
  in=eth2 dst=10.0.2.1 proto=tcp dport=80 to=192.168.10.10`).

DHCP and DNS can be turned on for every interface except the WAN.

### Firewall rules

`/etc/pxmxfw/rules` has one rule per line, checked in order; the first rule
that matches decides.

```
input|output|forward accept|drop|reject [in=IF] [out=IF] [src=NET] [dst=NET]
    [ip=4|6] [proto=PROTO] [sport=PORT] [dport=PORT] [tcpflags=FLAGS]
    [service=LIST]
masquerade out=IF [src=NET] [dst=NET]
dnat in=IF proto=tcp|udp dport=PORT to=IP[:PORT] [src=NET] [dst=NET]
```

- `input` is traffic to the firewall itself, `forward` traffic it routes
  from one interface to another, `output` traffic it sends.
- `in` and `out` are interfaces, `src` and `dst` IPv4 or IPv6 addresses or
  networks (`10.0.0.0/8`), `sport` and `dport` ports or ranges
  (`8000-8100`). Each takes a comma list; a field left out matches
  anything.
- `proto` is `tcp`, `udp`, `tcp,udp`, `icmp`, `icmpv6`, `gre`, `esp`, `ah`
  or `ipip`; ports need `tcp` or `udp`. `ip=4` or `ip=6` limits a rule to
  one IP version (addresses in `src` and `dst` already do).
- `tcpflags` (with `proto=tcp`) takes `syn`, `ack`, `fin`, `rst`, `psh`,
  `urg`. `syn|fin` matches when any of them is set, `syn&!ack` when all
  conditions hold (`!` means not set). A single flag means it is set.
- `service=` (input only) names services of the firewall instead of
  protocol and port: `ping`, `ssh`, `dns`, `dhcp`, `webui` (`WEBUI_PORT`).
- `masquerade` gives traffic leaving `out` that interface's address (NAT).
  `dnat` sends connections to `dport` on `in` to another machine (a port
  forward); they pass `forward` without a rule of their own. Both are IPv4
  only.
- `input` and `forward` drop what no rule accepts; `output` uses
  `OUTPUT_POLICY` (default `accept`). Replies to allowed connections,
  loopback, ICMPv6, the WireGuard ports, and DHCP and DNS on an interface
  with a `dhcp=` range always pass. Invalid packets and new TCP connections
  that do not start with a SYN are dropped. With `IPV6=no` (the default)
  nothing is routed over IPv6.

```
input accept in=eth1 service=ping,ssh,dns,dhcp,webui # the LAN reaches the firewall
input accept in=mgmt service=ssh,webui                 # SSH and the web UI from mgmt
input accept in=eth0 src=203.0.113.0/24 proto=tcp dport=22
forward accept in=eth1 out=eth0                        # LAN to WAN
forward accept in=eth2 out=eth1 dst=192.168.10.10 proto=tcp dport=443
masquerade out=eth0
dnat in=eth0 proto=tcp dport=8443 to=192.168.10.10:443
```

**Rules written by hand.** For rules this format cannot express, set
`FIREWALL=manual` (Firewall > General in the web UI). pxmxfw then loads no
rules of its own and the ruleset is `/etc/nftables.d/*.nft`, edited in the
terminal. The first `pxmxfw apply` in this mode writes the current rules to
`/etc/nftables.d/firewall.nft` (table `inet firewall`) as a starting point,
so the switch never leaves the firewall open or locks you out. `apply` checks
the files with `nft -c` before loading anything. Switching back to
`FIREWALL=rules` moves that file to `firewall.nft.off`; switching to manual
again brings it back.

**Upgrading from interface roles.** Configs from before the rules file (with
`role=` and `allow=` on interfaces, `NAT`, `WAN_PING` and `WEBUI_WAN` in
`pxmxfw.conf`, and the `services` and `forwards` files) are converted on the
next start, `pxmxfw apply` or visit to the web UI (or with `pxmxfw
migrate`). The new rules let through exactly what the roles did, so SSH and
the web UI stay reachable where they were. The old files are kept in
`/etc/pxmxfw/backup-roles/`.

```sh
pxmxfw apply      # validate, set addresses, load the rules, update dnsmasq
pxmxfw check      # kernel modules, forwarding, interfaces
pxmxfw status
```

Every value is checked before anything changes, and `apply` gives the same
result however often it runs. To manage the firewall with Ansible, Puppet
or git, write the files in `/etc/pxmxfw` and run `pxmxfw apply`. Other
`/etc/nftables.d/*.nft` files load next to the generated rules; to be let
through, a packet has to pass both, so filter rules there can only drop
more.

No SSH server is installed; use `pct enter 200`, or `apk add openssh` and
allow SSH on the interfaces you want under Firewall.

## Tests

```sh
sudo tests/run.sh                    # dash; as root the rules are also loaded
sudo SH="busybox ash" tests/run.sh   # the shell Alpine uses
cd webui && go test -tags libsqlite3 ./...   # web UI server (needs PAM and SQLite headers)
```
