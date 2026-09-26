# pxmxfw
Alpine based lxc firewall for proxmox

A small Alpine Linux container template that routes and filters traffic
between a WAN interface (`eth0`) and a LAN interface (`eth1`) using
nftables, with dnsmasq serving DNS and DHCP on the LAN.

## Build the template

On an x86_64 Linux host with internet access (a Proxmox node works), as root:

```sh
./build.sh
```

This downloads the Alpine minirootfs (checksum verified), installs
`alpine-base`, `nftables` and `dnsmasq`, applies the files under `rootfs/`,
enables the services and writes
`out/alpine-<version>-pxmxfw-<date>_amd64.tar.gz`. Run `./build.sh -h` for
options (Alpine version, mirror, output dir, local minirootfs).

## Create the container

```sh
cp out/alpine-*-pxmxfw-*_amd64.tar.gz /var/lib/vz/template/cache/
pct create 200 local:vztmpl/alpine-<version>-pxmxfw-<date>_amd64.tar.gz \
  --hostname pxmxfw --ostype alpine --unprivileged 1 \
  --cores 1 --memory 128 --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --net1 name=eth1,bridge=vmbr1,ip=192.168.10.1/24 \
  --password
pct start 200
```

`vmbr0` is the upstream bridge and `vmbr1` the protected network. Machines on
`vmbr1` get an address in `192.168.10.100-200` and use the container as
gateway and DNS.

## Configuration

| File | Purpose |
| --- | --- |
| `/etc/nftables.nft` | Firewall rules: drop by default, LAN to WAN allowed, NAT out of WAN, SSH/DNS/DHCP from LAN only. Extra rules go in `/etc/nftables.d/*.nft`. |
| `/etc/dnsmasq.d/pxmxfw.conf` | DNS forwarder and DHCP range for the LAN. |
| `/etc/sysctl.d/pxmxfw.conf` | Enables IPv4/IPv6 forwarding. |

Change the LAN subnet in both the Proxmox `net1` setting and
`pxmxfw.conf`. Apply edits with `rc-service nftables reload` or
`rc-service dnsmasq restart`. No SSH server is installed; use
`pct enter 200`, or `apk add openssh` if you want one.
