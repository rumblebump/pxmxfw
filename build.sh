#!/bin/sh
# Build pxmxfw: the Proxmox LXC template, the VM disk image and/or the
# container image for podman and docker.
#
# Downloads the Alpine minirootfs, installs OpenRC, nftables and dnsmasq,
# builds the web UI server (Go, in webui/) and applies the files under
# rootfs/ (shared by both targets). Then, per target:
#   lxc  adds targets/lxc/rootfs and packs a template tarball for `pct create`
#   vm   adds targets/vm/rootfs, a kernel and a bootloader and writes a qcow2
#        disk for `qm disk import` (targets/vm/mkimage.sh)
#   oci  adds targets/oci/rootfs and writes an OCI image archive for
#        `podman load` / `docker load` (image name pxmxfw:latest)
# Run it with --podman on any x86_64 Linux (no root needed), or as root on
# an x86_64 host (a Proxmox node works; the VM image needs an Alpine host).
#
# Usage: ./build.sh [--podman] [-t lxc|vm|oci|all] [-f TEMPLATE] [-v ALPINE_VERSION] [-m MIRROR] [-o OUTDIR] [-r MINIROOTFS]
#   --podman  build inside an Alpine container with podman
#   -t  what to build: lxc (default), vm, oci, or all (all three from one root filesystem)
#   -f  with -t vm or oci: make the image from this LXC template (.tar.gz) instead
#       of building the root filesystem again (CI does this)
#   -v  Alpine branch, e.g. 3.22 (default: $ALPINE_VERSION or ALPINE_VERSION below)
#   -m  Alpine mirror (default: $ALPINE_MIRROR or https://dl-cdn.alpinelinux.org/alpine)
#   -o  output directory (default: ./out)
#   -r  use a local minirootfs .tar.gz instead of downloading one

set -eu

ALPINE_VERSION=${ALPINE_VERSION:-3.22}
ALPINE_MIRROR=${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}
ARCH=x86_64
OUTDIR=./out
MINIROOTFS=
TARGET=lxc
FROM=
PACKAGES="alpine-base nftables dnsmasq wireguard-tools-wg linux-pam sqlite-libs"
# To build the web UI server (never installed into the template)
BUILD_DEPS="go gcc musl-dev linux-pam-dev sqlite-dev"
PODMAN=

# Alpine.js for the web UI, pinned by checksum
ALPINEJS_VERSION=3.17.4
ALPINEJS_SHA256=81c622da24897c80071c6398253f90890449604d7b132d2509d17f7ac903c7da
# xterm.js and its fit addon for the web terminal
XTERM_VERSION=6.0.0
XTERM_SHA256=908e66e04af6c8dc6b00dd3b54de088e2e81e5ed866284fd6c2fb3c2d1c7a3f6
XTERM_FIT_VERSION=0.11.0
XTERM_FIT_SHA256=26003b4517a132b64e4ff228fd88a5fda3fff5e606c76093f6dcff772e9ecec0

SRCDIR=$(cd "$(dirname "$0")" && pwd)
PXMXFW_VERSION=${PXMXFW_VERSION:-$(cd "$SRCDIR" && git describe --tags --always --dirty 2>/dev/null || echo dev)}

die() { echo "build.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case $1 in
		--podman) PODMAN=1; shift ;;
		-v) ALPINE_VERSION=$2; shift 2 ;;
		-m) ALPINE_MIRROR=$2; shift 2 ;;
		-o) OUTDIR=$2; shift 2 ;;
		-r) MINIROOTFS=$2; shift 2 ;;
		-t) TARGET=$2; shift 2 ;;
		-f) FROM=$2; shift 2 ;;
		-h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) die "unknown option: $1" ;;
	esac
done
TARGET_ARG=$TARGET
case $TARGET in
	lxc|vm|oci) ;;
	# oci works on a copy of the root, so it can come before vm changes it
	all) TARGET="lxc oci vm" ;;
	*) die "-t: lxc, vm, oci or all" ;;
esac
case $TARGET in vm|oci) ;; *) [ -z "$FROM" ] || die "-f only works with -t vm or -t oci" ;; esac
[ -z "$FROM" ] || [ -f "$FROM" ] || die "no such template: $FROM"

if [ -n "$PODMAN" ]; then
	command -v podman >/dev/null || die "podman not found"
	mkdir -p "$OUTDIR"
	OUTDIR=$(cd "$OUTDIR" && pwd)
	set -- -v "$ALPINE_VERSION" -m "$ALPINE_MIRROR" -o /out -t "$TARGET_ARG"
	OPTS=
	if [ -n "$MINIROOTFS" ]; then
		OPTS="-v $(cd "$(dirname "$MINIROOTFS")" && pwd):/minirootfs:ro,Z"
		set -- "$@" -r "/minirootfs/$(basename "$MINIROOTFS")"
	fi
	if [ -n "$FROM" ]; then
		OPTS="$OPTS -v $(cd "$(dirname "$FROM")" && pwd):/from:ro,Z"
		set -- "$@" -f "/from/$(basename "$FROM")"
	fi
	# the VM image mounts /proc and /dev in its root to install the kernel
	case $TARGET in *vm*) OPTS="$OPTS --privileged" ;; esac
	echo ">> Building $TARGET in podman (alpine:$ALPINE_VERSION)"
	# shellcheck disable=SC2086
	exec podman run --rm -e PXMXFW_VERSION="$PXMXFW_VERSION" -e VM_DISK_MB -v "$SRCDIR:/src:ro,Z" -v "$OUTDIR:/out:Z" $OPTS \
		"docker.io/library/alpine:$ALPINE_VERSION" \
		sh -c 'apk add --no-cache curl tar >/dev/null && exec /src/build.sh "$@"' build.sh "$@"
fi

[ "$(id -u)" -eq 0 ] || die "must run as root (needs chroot and root-owned files)"
[ "$(uname -m)" = "$ARCH" ] || die "host must be $ARCH to run apk in the chroot"

WORK=$(mktemp -d)
ROOT=$WORK/rootfs
mkdir -p "$ROOT" "$OUTDIR"
OUTDIR=$(cd "$OUTDIR" && pwd)

cleanup() {
	for m in "$ROOT/dev" "$ROOT/proc" "$WORK/buildroot/dev" "$WORK/buildroot/proc"; do
		mountpoint -q "$m" 2>/dev/null && umount -l "$m"
	done
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Enable services (same effect as rc-update add)
enable_svc() { # runlevel service...
	lvl=$1; shift
	mkdir -p "$ROOT/etc/runlevels/$lvl"
	for s in "$@"; do ln -sf "/etc/init.d/$s" "$ROOT/etc/runlevels/$lvl/$s"; done
}

# overlay DIR: copy DIR's files into the root, owned by root
overlay() {
	cp -a "$1/." "$ROOT/"
	(cd "$1" && find . -mindepth 1) | while read -r f; do chown -h 0:0 "$ROOT/$f"; done
}

# set_rc_sys VALUE: tell OpenRC where it runs ("lxc" skips hardware services)
set_rc_sys() {
	if [ -f "$ROOT/etc/rc.conf" ] && grep -q '^#\{0,1\}rc_sys=' "$ROOT/etc/rc.conf"; then
		sed -i "s/^#\{0,1\}rc_sys=.*/rc_sys=\"$1\"/" "$ROOT/etc/rc.conf"
	else
		echo "rc_sys=\"$1\"" >> "$ROOT/etc/rc.conf"
	fi
}

# oci_image DIR OUT: write DIR as a one-layer OCI image archive (oci-layout,
# index.json, blobs/, plus docker's manifest.json) that podman load and
# docker load accept. The image is
# named pxmxfw:latest; CI pushes it to ghcr.io under other names.
oci_image() {
	L=$WORK/oci-layout out=$2
	mkdir -p "$L/blobs/sha256"
	tar --numeric-owner -cf "$WORK/layer.tar" -C "$1" .
	diffid=$(sha256sum "$WORK/layer.tar" | cut -d' ' -f1)
	gzip -n "$WORK/layer.tar"
	blob() { # FILE: move FILE into blobs/, print "DIGEST SIZE"
		_d=$(sha256sum "$1" | cut -d' ' -f1)
		_s=$(wc -c < "$1" | tr -d ' ')
		mv "$1" "$L/blobs/sha256/$_d"
		echo "$_d $_s"
	}
	read -r layer layersize <<-EOF
	$(blob "$WORK/layer.tar.gz")
	EOF
	created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	cat > "$WORK/config.json" <<-EOF
	{"architecture":"amd64","os":"linux","created":"$created",
	 "config":{"Cmd":["/sbin/init"],"StopSignal":"SIGTERM",
	  "Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
	  "ExposedPorts":{"8443/tcp":{}},
	  "Labels":{"org.opencontainers.image.source":"https://github.com/rumblebump/pxmxfw",
	   "org.opencontainers.image.version":"$PXMXFW_VERSION",
	   "org.opencontainers.image.description":"pxmxfw firewall for podman and docker (needs NET_ADMIN)"}},
	 "rootfs":{"type":"layers","diff_ids":["sha256:$diffid"]},
	 "history":[{"created":"$created","created_by":"pxmxfw build.sh -t oci"}]}
	EOF
	read -r config configsize <<-EOF
	$(blob "$WORK/config.json")
	EOF
	cat > "$WORK/manifest.json" <<-EOF
	{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
	 "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:$config","size":$configsize},
	 "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:$layer","size":$layersize}]}
	EOF
	read -r manifest manifestsize <<-EOF
	$(blob "$WORK/manifest.json")
	EOF
	cat > "$L/index.json" <<-EOF
	{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
	 "manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:$manifest","size":$manifestsize,
	  "annotations":{"org.opencontainers.image.ref.name":"pxmxfw:latest","io.containerd.image.name":"docker.io/library/pxmxfw:latest"}}]}
	EOF
	echo '{"imageLayoutVersion":"1.0.0"}' > "$L/oci-layout"
	# what "docker save" adds for docker's older (non-containerd) image store
	echo "[{\"Config\":\"blobs/sha256/$config\",\"RepoTags\":[\"pxmxfw:latest\"],\"Layers\":[\"blobs/sha256/$layer\"]}]" > "$L/manifest.json"
	tar --numeric-owner -cf "$out" -C "$L" oci-layout index.json manifest.json blobs
	rm -rf "$L"
}

# The root filesystem both targets share
build_rootfs() {
	# 1. Fetch and unpack the minirootfs
	if [ -z "$MINIROOTFS" ]; then
		REL=$ALPINE_MIRROR/v$ALPINE_VERSION/releases/$ARCH
		echo ">> Looking up the latest Alpine $ALPINE_VERSION minirootfs"
		NAME=$(wget -qO- "$REL/latest-releases.yaml" 2>/dev/null || curl -fsSL "$REL/latest-releases.yaml") ||
			die "cannot reach $REL"
		NAME=$(printf '%s\n' "$NAME" | sed -n 's/^ *file: \(alpine-minirootfs-.*\.tar\.gz\)$/\1/p' | head -n1)
		[ -n "$NAME" ] || die "no minirootfs listed in $REL/latest-releases.yaml"
		MINIROOTFS=$WORK/$NAME
		echo ">> Downloading $NAME"
		curl -fsSL -o "$MINIROOTFS" "$REL/$NAME"
		curl -fsSL -o "$MINIROOTFS.sha256" "$REL/$NAME.sha256"
		(cd "$WORK" && sha256sum -c "$NAME.sha256") || die "checksum mismatch for $NAME"
	fi
	echo ">> Unpacking $(basename "$MINIROOTFS")"
	tar -xzf "$MINIROOTFS" -C "$ROOT"
	RELEASE=$(cat "$ROOT/etc/alpine-release")

	# 2. Install packages
	cat > "$ROOT/etc/apk/repositories" <<-EOF
		$ALPINE_MIRROR/v$ALPINE_VERSION/main
		$ALPINE_MIRROR/v$ALPINE_VERSION/community
	EOF
	echo ">> Installing: $PACKAGES"
	if [ -f /etc/alpine-release ]; then
		# On Alpine (e.g. in podman) the build host's apk installs straight
		# into the root, so nothing needs mounting.
		apk --root "$ROOT" --keys-dir "$ROOT/etc/apk/keys" --no-cache --update add $PACKAGES
	else
		cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"
		mount -t proc proc "$ROOT/proc"
		mount --bind /dev "$ROOT/dev"
		chroot "$ROOT" /sbin/apk add --no-cache --update $PACKAGES
		umount "$ROOT/dev" "$ROOT/proc"
	fi
	: > "$ROOT/etc/resolv.conf"   # Proxmox writes this on container start

	# Build the web UI server against Alpine's musl, PAM and SQLite.
	# Alpine's go only bootstraps: GOTOOLCHAIN=auto fetches the (checksummed)
	# Go release named by `toolchain` in webui/go.mod, so the binary gets
	# current Go security fixes without waiting for a new Alpine branch.
	GOBUILD='cd "$1" && CGO_ENABLED=1 GOTOOLCHAIN=auto GOFLAGS=-mod=readonly go build -tags libsqlite3 -trimpath -ldflags "-s -w" -o "$2" .'
	echo ">> Building pxmxfw-webui"
	if [ -f /etc/alpine-release ]; then
		apk add --no-cache $BUILD_DEPS >/dev/null
		sh -c "$GOBUILD" gobuild "$SRCDIR/webui" "$WORK/pxmxfw-webui"
	else
		# Not on Alpine: build in a second, throwaway Alpine chroot
		B=$WORK/buildroot
		mkdir -p "$B"
		tar -xzf "$MINIROOTFS" -C "$B"
		cp "$ROOT/etc/apk/repositories" "$B/etc/apk/repositories"
		cp -L /etc/resolv.conf "$B/etc/resolv.conf"
		cp -a "$SRCDIR/webui" "$B/src"
		mount -t proc proc "$B/proc"
		mount --bind /dev "$B/dev"
		chroot "$B" /sbin/apk add --no-cache $BUILD_DEPS >/dev/null
		chroot "$B" sh -c "$GOBUILD" gobuild /src /pxmxfw-webui
		umount "$B/dev" "$B/proc"
		cp "$B/pxmxfw-webui" "$WORK/pxmxfw-webui"
	fi

	echo ">> Fetching Alpine.js $ALPINEJS_VERSION"
	curl -fsSL -o "$WORK/alpinejs.tgz" "https://registry.npmjs.org/alpinejs/-/alpinejs-$ALPINEJS_VERSION.tgz"
	echo "$ALPINEJS_SHA256  $WORK/alpinejs.tgz" | sha256sum -c - >/dev/null || die "checksum mismatch for Alpine.js"
	echo ">> Fetching xterm.js $XTERM_VERSION"
	curl -fsSL -o "$WORK/xterm.tgz" "https://registry.npmjs.org/@xterm/xterm/-/xterm-$XTERM_VERSION.tgz"
	echo "$XTERM_SHA256  $WORK/xterm.tgz" | sha256sum -c - >/dev/null || die "checksum mismatch for xterm.js"
	curl -fsSL -o "$WORK/xterm-fit.tgz" "https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-$XTERM_FIT_VERSION.tgz"
	echo "$XTERM_FIT_SHA256  $WORK/xterm-fit.tgz" | sha256sum -c - >/dev/null || die "checksum mismatch for the xterm.js fit addon"

	# 3. Apply the project's config
	echo ">> Applying rootfs/ overlay"
	cp -a "$SRCDIR/rootfs/." "$ROOT/"
	tar -xzf "$WORK/alpinejs.tgz" -O package/dist/cdn.min.js > "$ROOT/usr/share/pxmxfw/www/alpine.min.js"
	tar -xzf "$WORK/xterm.tgz" -O package/lib/xterm.js > "$ROOT/usr/share/pxmxfw/www/xterm.js"
	tar -xzf "$WORK/xterm.tgz" -O package/css/xterm.css > "$ROOT/usr/share/pxmxfw/www/xterm.css"
	tar -xzf "$WORK/xterm-fit.tgz" -O package/lib/addon-fit.js > "$ROOT/usr/share/pxmxfw/www/xterm-fit.js"
	install -m 755 "$WORK/pxmxfw-webui" "$ROOT/usr/sbin/pxmxfw-webui"
	# Besides root, members of this group may log in to the web UI
	grep -q '^pxmxfw:' "$ROOT/etc/group" || echo 'pxmxfw:x:990:' >> "$ROOT/etc/group"
	echo "$PXMXFW_VERSION" > "$ROOT/usr/share/pxmxfw/VERSION"
	mkdir -p "$ROOT/etc/nftables.d" "$ROOT/etc/dnsmasq.d"
	grep -q '^conf-dir=/etc/dnsmasq.d' "$ROOT/etc/dnsmasq.conf" ||
		echo 'conf-dir=/etc/dnsmasq.d/,*.conf' >> "$ROOT/etc/dnsmasq.conf"
	# Default ruleset, used until first boot setup regenerates it
	PXMXFW_ETC=$ROOT/etc/pxmxfw PXMXFW_LIB=$ROOT/usr/lib/pxmxfw \
		sh "$ROOT/usr/sbin/pxmxfw" render nft > "$ROOT/etc/pxmxfw/ruleset.nft"
	chown -R 0:0 "$ROOT/etc" "$ROOT/usr/lib/pxmxfw" "$ROOT/usr/share/pxmxfw" "$ROOT/usr/sbin/pxmxfw" "$ROOT/usr/sbin/pxmxfw-webui"

	# 4. Enable the services both targets run
	# dnsmasq is left off; enable it in the web UI (or DNSMASQ=yes + pxmxfw apply)
	enable_svc boot bootmisc hostname networking sysctl syslog pxmxfw nftables
	enable_svc default pxmxfw-webui
	enable_svc shutdown killprocs savecache
}

if [ -n "$FROM" ]; then
	echo ">> Unpacking $(basename "$FROM")"
	tar -xzf "$FROM" -C "$ROOT"
else
	build_rootfs
fi
RELEASE=$(cat "$ROOT/etc/alpine-release")
NAME=$OUTDIR/alpine-$RELEASE-pxmxfw-$(date +%Y%m%d)_amd64

# 5. Per target
for t in $TARGET; do
	case $t in
	lxc)
		overlay "$SRCDIR/targets/lxc/rootfs"
		set_rc_sys lxc
		echo lxc > "$ROOT/usr/share/pxmxfw/TARGET"
		echo ">> Packing $NAME.tar.gz"
		rm -rf "$ROOT/var/cache/apk/"* "$ROOT/tmp/"*
		tar --numeric-owner -czf "$NAME.tar.gz" -C "$ROOT" .
		echo ">> Done: $NAME.tar.gz ($(du -h "$NAME.tar.gz" | cut -f1))"
		;;
	oci)
		# on a copy, so the VM (built next with -t all) keeps its services
		O=$WORK/oci-rootfs
		cp -a "$ROOT" "$O"
		cp -a "$SRCDIR/targets/oci/rootfs/." "$O/"
		(cd "$SRCDIR/targets/oci/rootfs" && find . -mindepth 1) | while read -r f; do chown -h 0:0 "$O/$f"; done
		# docker and podman set the network and the hostname; sysctls come
		# from --sysctl, since /proc/sys is read-only in the container
		R=$ROOT ROOT=$O
		set_rc_sys docker
		ROOT=$R
		rm -f "$O/etc/runlevels/boot/sysctl"
		echo oci > "$O/usr/share/pxmxfw/TARGET"
		rm -rf "$O/var/cache/apk/"* "$O/tmp/"*
		echo ">> Writing the container image $NAME.oci.tar"
		oci_image "$O" "$NAME.oci.tar"
		rm -rf "$O"
		echo ">> Done: $NAME.oci.tar ($(du -h "$NAME.oci.tar" | cut -f1)), load it with: podman load -i $(basename "$NAME").oci.tar"
		;;
	vm)
		[ -f /etc/alpine-release ] || die "the VM image is built on Alpine: use --podman"
		overlay "$SRCDIR/targets/vm/rootfs"
		set_rc_sys ""
		echo vm > "$ROOT/usr/share/pxmxfw/TARGET"
		# No password until one is set on the console (the web UI refuses
		# empty passwords, and there is no ssh server)
		sed -i 's/^root:[^:]*:/root::/' "$ROOT/etc/shadow"
		grep -qx ttyS0 "$ROOT/etc/securetty" 2>/dev/null || echo ttyS0 >> "$ROOT/etc/securetty"
		enable_svc sysinit devfs dmesg mdev hwdrivers
		enable_svc boot modules hwclock
		enable_svc default acpid qemu-guest-agent
		enable_svc shutdown mount-ro
		echo ">> Building the VM disk $NAME.qcow2"
		sh "$SRCDIR/targets/vm/mkimage.sh" "$ROOT" "$NAME.qcow2"
		echo ">> Done: $NAME.qcow2 ($(du -h "$NAME.qcow2" | cut -f1))"
		;;
	esac
done
