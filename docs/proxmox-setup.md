# Setting up pxmxfw on Proxmox

This guide walks through creating the firewall container on a Proxmox VE
host, from the bridges it sits between to the first login. The
[README](../README.md) covers what happens inside the container after that
(interfaces, firewall rules, WireGuard, the config files).

The examples use container ID `200`, `vmbr0` as the upstream bridge and
`vmbr1` as the protected network. Change them to fit your host.

## 1. How it fits together

```
 internet / upstream router
            |
   vmbr0 (host bridge, has the physical NIC)
            |
      eth0 = WAN
   +------------------+
   |  pxmxfw (LXC)    |   routes, filters and NATs between them
   +------------------+
      eth1 = LAN, 192.168.10.1/24
            |
   vmbr1 (host bridge, no host IP)
            |
   VMs and containers, gateway 192.168.10.1
```

The container needs two network devices on **two different bridges**. If
both sat on the same bridge, machines on the LAN could reach the upstream
network directly and the firewall would be bypassed.

## 2. Prepare the bridges

`vmbr0` usually exists already: it is the bridge Proxmox created during
installation, with the physical NIC as its port and the host's own address.

Add `vmbr1` for the LAN, either in the web UI (*Node*, *System*, *Network*,
*Create*, *Linux Bridge*) or in `/etc/network/interfaces` on the host:

```
auto vmbr1
iface vmbr1 inet manual
        bridge-ports none
        bridge-stp off
        bridge-fd 0
#pxmxfw LAN
```

Then `ifreload -a` (or *Apply Configuration* in the web UI).

- **No bridge port** (`bridge-ports none`) keeps the LAN inside this host:
  only VMs and containers on `vmbr1` are behind the firewall.
- **A second physical NIC** as the port (`bridge-ports enp2s0`) puts a real
  switch behind the firewall as well.
- **No host address on `vmbr1`.** If the Proxmox host has an IP on the LAN
  bridge, LAN machines can talk to the host without going through pxmxfw.
  Manage the host over `vmbr0` or a separate management network instead.

A VLAN-aware bridge works too: put both NICs on the same VLAN-aware bridge
with different tags (`tag=10` for WAN, `tag=20` for LAN). They are then as
separate as two bridges, as long as no other port joins both VLANs untagged.

## 3. Privileged or unprivileged

Use an **unprivileged** container. Everything pxmxfw does works in one.

| | Unprivileged (recommended) | Privileged |
| --- | --- | --- |
| Root in the container is | a mapped, unprivileged user on the host | root on the host |
| A bug or break-in in the firewall | stays in the container | can reach the host |
| nftables, NAT, forwarding, VLANs, bridges, WireGuard | work | work |
| Loading kernel modules | not possible, done on the host | also not possible (Proxmox drops `CAP_SYS_MODULE`) |

The firewall is the machine facing the untrusted network, so it is the last
place you want container root to equal host root. Being privileged does not
buy anything here: the modules pxmxfw needs are loaded on the host either
way (section 5).

To turn an existing privileged container into an unprivileged one, back it
up and restore it with *Unprivileged container* ticked (or
`pct restore 200 <backup> --unprivileged 1`).

### Nesting

pxmxfw does **not** need `nesting`. Nesting is for containers that run
their own containers or a systemd that wants to mount `/proc` and `/sys`
itself; Alpine's OpenRC does neither. The Proxmox web UI ticks *Nesting*
by default for new unprivileged containers. It is harmless, but untick it
(or pass `--features nesting=0`) for the tighter setup. No other feature
(`keyctl`, `fuse`, `mount`) is needed either.

### IP forwarding

Nothing to do on the host. `net.ipv4.ip_forward` belongs to the container's
own network namespace, so the container turns it on itself at boot
(`/etc/sysctl.d/pxmxfw.conf`) and on every `pxmxfw apply`. It does not turn
on forwarding on the Proxmox host. IPv6 forwarding follows the `IPV6`
setting, which is off by default.

If the Checks page still reports forwarding as off, set it from the host
in `/etc/pve/lxc/200.conf`:

```
lxc.sysctl.net.ipv4.ip_forward = 1
```

and restart the container.

## 4. Get the template

On the Proxmox host:

```sh
cd /var/lib/vz/template/cache
wget https://github.com/rumblebump/pxmxfw/releases/latest/download/pxmxfw_amd64.tar.gz
wget https://github.com/rumblebump/pxmxfw/releases/latest/download/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

Or in the web UI: *local* storage, *CT Templates*, *Download from URL*,
paste the same link and click *Query URL*. The hash from `SHA256SUMS` can
go in the *Checksum* field (SHA-256).

The newest build of `main`, for testing, is at
`https://github.com/rumblebump/pxmxfw/releases/download/edge/pxmxfw_amd64.tar.gz`
(with its own `SHA256SUMS` next to it). Save it under a different name if
you keep a release template too, for example
`wget -O pxmxfw-edge_amd64.tar.gz <edge link>`.

`pveam` only downloads from Proxmox's own template list, so use `wget` or
the web UI for this one.

## 5. Load the kernel modules on the host

A container cannot load kernel modules, so the host has to. The firewall
itself needs nftables with connection tracking and NAT; the others are only
needed for the features named:

```sh
modprobe -a nf_tables nf_conntrack nft_ct nf_nat nft_chain_nat nft_masq nft_nat
modprobe -a wireguard   # WireGuard tunnels
modprobe -a 8021q       # VLAN interfaces made inside pxmxfw
modprobe -a bridge      # bridge interfaces made inside pxmxfw
```

Many of these are already loaded on a Proxmox host. To keep them after a
reboot, list them in `/etc/modules-load.d/pxmxfw.conf`, one per line:

```sh
printf '%s\n' nf_tables nf_conntrack nft_ct nf_nat nft_chain_nat nft_masq nft_nat \
  wireguard 8021q bridge > /etc/modules-load.d/pxmxfw.conf
```

You can also skip this step and let the container tell you: the **Checks**
page in the web UI (or `pxmxfw check` inside the container) lists every
missing module with the exact `modprobe` and `modules-load.d` lines for the
host.

## 6. Create the container

```sh
pct create 200 local:vztmpl/pxmxfw_amd64.tar.gz \
  --hostname pxmxfw --ostype alpine \
  --unprivileged 1 --features nesting=0 \
  --cores 1 --memory 128 --swap 128 --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --net1 name=eth1,bridge=vmbr1,ip=192.168.10.1/24 \
  --onboot 1 --startup order=1 \
  --password
pct start 200
```

What each part is for:

- `--ostype alpine` makes Proxmox write the network config in Alpine's
  format.
- `--memory 128`, one core and a 1 GB disk are plenty for a small network.
  Add memory if you run many WireGuard peers or a large DHCP range.
- `net0` is the **WAN**. Use `ip=dhcp` if the upstream network hands out
  addresses, or a static address with its gateway:
  `ip=203.0.113.2/24,gw=203.0.113.1`.
- `net1` is the **LAN**. Give it a static address and **no gateway**; this
  address is the gateway for the machines behind it.
- Leave `firewall=1` off on both NICs. Once the Proxmox firewall is on for
  the container, it filters every packet on those NICs by the container's
  own rules, including the forwarded traffic pxmxfw is there to route, and
  its default input policy drops it. Its *IP filter* option drops
  forwarded traffic too, since those packets carry other machines'
  addresses. pxmxfw does the filtering.
- `--onboot 1 --startup order=1` starts the firewall before the guests that
  depend on it.
- `--password` asks for the root password. The web UI logs in as root with
  it.

The same settings in the web UI's *Create CT* wizard: tick *Unprivileged
container*, untick *Nesting*, pick the template, and on *Network* set up
`eth0` on `vmbr0`. Add `eth1` afterwards under the container's *Network*
tab (*Add*, name `eth1`, bridge `vmbr1`, static IPv4, no gateway).

## 7. First start and login

On its first start pxmxfw reads what Proxmox set and writes its defaults to
`/etc/pxmxfw`: `eth0` becomes the WAN, `eth1` a LAN with a DHCP range of
`.100` to `.200` ready, the firewall rules load, and IPv6 routing and
dnsmasq (DNS and DHCP) stay off. The README's
[First start](../README.md#first-start) section has the details.

From a machine on `vmbr1`, open:

```
https://192.168.10.1:8443
```

and log in as `root` with the password from `--password`. The certificate
is self-signed until you replace it, so the browser warns once.

Then:

1. Open **Checks** and fix anything red. Missing modules are loaded on the
   host (section 5), then `pct reboot 200`.
2. Under **Security**, turn on two-factor login (TOTP) or add a security
   key. Security keys need the UI opened by host name with a trusted
   certificate; see the README's
   [Login and security](../README.md#login-and-security).
3. If machines on the LAN should get their addresses from pxmxfw, turn on
   DNS and DHCP on the **DNS & DHCP** page. Otherwise point them at
   `192.168.10.1` as their gateway by hand.

If the container only has one NIC, the web UI is reachable from the WAN
side at first so you can finish the setup. Turn that off once the LAN is
there.

## 8. Connecting guests

Give each VM or container behind the firewall a NIC on `vmbr1`:

```sh
qm set 101 -net0 virtio,bridge=vmbr1      # a VM
pct set 102 -net0 name=eth0,bridge=vmbr1,ip=dhcp   # a container
```

With DHCP on in pxmxfw they get an address, the gateway and DNS from it.
Without it, give them an address in `192.168.10.0/24` with gateway
`192.168.10.1`.

## 9. More networks

- **Another LAN, DMZ or guest network**: add a bridge on the host
  (`vmbr2`), then `pct set 200 -net2 name=eth2,bridge=vmbr2,ip=192.168.20.1/24`.
  The new NIC is found at the next start or when you open the web UI, and
  starts with role `off` until you give it one on the **Interfaces** page.
- **VLANs, bridges and WireGuard tunnels** made inside pxmxfw are added from
  the **Interfaces** and **WireGuard** pages; see the README. They need the
  `8021q`, `bridge` and `wireguard` modules on the host.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Checks shows *module not loaded* | Load it on the host (section 5), then `pct reboot 200`. |
| Checks shows *Network admin rights* failing | An `lxc.cap.drop` line in `/etc/pve/lxc/200.conf` drops `net_admin`. Remove it. |
| LAN machines reach the internet without the firewall | Both NICs are on the same bridge, or the host has an address on the LAN bridge. |
| LAN machines get no reply at all | `firewall=1` or *IP filter* on the container's NICs, or the guest's gateway is not `192.168.10.1`. |
| Web UI not reachable | It listens on the LAN address only. Open it from a machine on `vmbr1`, or use `pct enter 200` and run `pxmxfw status`. |

`pct enter 200` gives a root shell in the container at any time, whatever
the firewall rules say.
