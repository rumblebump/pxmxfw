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
`alpine-base`, `nftables`, `dnsmasq`, `linux-pam` and `sqlite-libs`, builds
the web UI server from `webui/` with Alpine's Go, adds [Alpine.js](https://alpinejs.dev) (pinned by checksum), applies
the files under `rootfs/`, enables the services and writes
`out/alpine-<version>-pxmxfw-<date>_amd64.tar.gz`. Run `./build.sh -h` for
options (Alpine version, mirror, output dir, local minirootfs).

GitHub Actions runs the tests and the podman build on every push and pull
request and uploads the tarball as a workflow artifact. Pushing a `v*` tag
also attaches it to a GitHub release.

## Create the container

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

## Web UI

Open `https://<LAN address>:8443` and log in as `root` (or a member of the
`pxmxfw` group) with that user's password. It has:

- **Status**: firewall, dnsmasq, forwarding, interfaces and addresses.
- **Interfaces**: role of each NIC, addresses for NICs Proxmox does not
  configure, DHCP ranges, and the IPv6 switch.
- **Firewall**: NAT, ping, ports open on WAN, port forwards.
- **DNS & DHCP**: turn dnsmasq on, upstream servers, local names and fixed
  leases.
- **Checks**: tests each kernel feature the firewall needs (nftables,
  conntrack, NAT, WireGuard), IP forwarding and the interfaces. A container
  cannot load kernel modules, so for anything missing it shows the
  `modprobe` and `/etc/modules-load.d` commands to run on the Proxmox host.
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
- **Changes are confirmed**: saving, applying, and managing tokens or 2FA
  ask for a fresh TOTP code (or the password, without TOTP). A
  confirmation lasts 5 minutes.
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

## Configuration

Everything lives in small text files in `/etc/pxmxfw`. The web UI edits the
same files, and `pxmxfw apply` turns them into the nftables ruleset and the
dnsmasq config. Nothing else needs editing.

| File | Content |
| --- | --- |
| `pxmxfw.conf` | `KEY=value` settings: `NAT`, `WAN_PING`, `IPV6`, `WEBUI_PORT`, `WEBUI_WAN`, `DNSMASQ`, `DNS_UPSTREAM`, `DNS_DOMAIN`, `DHCP_LEASE` |
| `interfaces` | `IFACE role=wan\|lan\|isolated\|off [addr=proxmox\|none\|IP/PREFIX] [addr6=...] [dhcp=START-END]` |
| `services` | `tcp\|udp PORT[-PORT]`: open on WAN to the firewall itself |
| `forwards` | `tcp\|udp WANPORT LANIP LANPORT`: port forwards |
| `hosts` | `IP NAME [MAC]`: local DNS names, fixed DHCP leases with a MAC |

Roles: `lan` reaches the WAN and every other `lan`; `isolated` reaches the
WAN only; `off` drops everything. With `IPV6=no` (the default) only IPv4 is
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
