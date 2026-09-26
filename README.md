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
`alpine-base`, `nftables`, `dnsmasq` and `busybox-extras` (for the web UI's
httpd), adds [Alpine.js](https://alpinejs.dev) (pinned by checksum), applies
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

Open `http://<LAN address>:8080` and log in as `root`. It has:

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

The UI is served by busybox httpd and runs as root, since it changes the
firewall. It copies the root password hash into its config when it starts,
so after changing the password run `rc-service pxmxfw-webui restart`. It only listens on the LAN address, and it refuses changes from
other web pages (every change needs an `X-Pxmxfw` header, which browsers do
not send across sites without a CORS preflight, and the UI never answers
one). The login is HTTP basic auth over plain HTTP, so use it from the LAN
only.

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
```
