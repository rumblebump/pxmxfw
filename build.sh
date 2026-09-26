#!/bin/sh
# Build the pxmxfw Proxmox LXC template.
#
# Downloads the Alpine minirootfs, installs OpenRC, nftables, dnsmasq and
# busybox httpd, applies the files under rootfs/ and packs the result as a
# template tarball for `pct create`. Run it with --podman on any x86_64
# Linux (no root needed), or as root on an x86_64 host (a Proxmox node works).
#
# Usage: ./build.sh [--podman] [-v ALPINE_VERSION] [-m MIRROR] [-o OUTDIR] [-r MINIROOTFS]
#   --podman  build inside an Alpine container with podman
#   -v  Alpine branch, e.g. 3.22 (default: $ALPINE_VERSION or 3.22)
#   -m  Alpine mirror (default: $ALPINE_MIRROR or https://dl-cdn.alpinelinux.org/alpine)
#   -o  output directory (default: ./out)
#   -r  use a local minirootfs .tar.gz instead of downloading one

set -eu

ALPINE_VERSION=${ALPINE_VERSION:-3.22}
ALPINE_MIRROR=${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}
ARCH=x86_64
OUTDIR=./out
MINIROOTFS=
PACKAGES="alpine-base nftables dnsmasq busybox-extras"
PODMAN=

# Alpine.js for the web UI, pinned by checksum
ALPINEJS_VERSION=3.17.4
ALPINEJS_SHA256=81c622da24897c80071c6398253f90890449604d7b132d2509d17f7ac903c7da

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
		-h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) die "unknown option: $1" ;;
	esac
done

if [ -n "$PODMAN" ]; then
	command -v podman >/dev/null || die "podman not found"
	mkdir -p "$OUTDIR"
	OUTDIR=$(cd "$OUTDIR" && pwd)
	set -- -v "$ALPINE_VERSION" -m "$ALPINE_MIRROR" -o /out
	MOUNT_MINI=
	if [ -n "$MINIROOTFS" ]; then
		MOUNT_MINI="-v $(cd "$(dirname "$MINIROOTFS")" && pwd):/minirootfs:ro,Z"
		set -- "$@" -r "/minirootfs/$(basename "$MINIROOTFS")"
	fi
	echo ">> Building in podman (alpine:$ALPINE_VERSION)"
	# shellcheck disable=SC2086
	exec podman run --rm -e PXMXFW_VERSION="$PXMXFW_VERSION" -v "$SRCDIR:/src:ro,Z" -v "$OUTDIR:/out:Z" $MOUNT_MINI \
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
	for m in dev proc; do
		mountpoint -q "$ROOT/$m" 2>/dev/null && umount -l "$ROOT/$m"
	done
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

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

echo ">> Fetching Alpine.js $ALPINEJS_VERSION"
curl -fsSL -o "$WORK/alpinejs.tgz" "https://registry.npmjs.org/alpinejs/-/alpinejs-$ALPINEJS_VERSION.tgz"
echo "$ALPINEJS_SHA256  $WORK/alpinejs.tgz" | sha256sum -c - >/dev/null || die "checksum mismatch for Alpine.js"

# 3. Apply the project's config
echo ">> Applying rootfs/ overlay"
cp -a "$SRCDIR/rootfs/." "$ROOT/"
tar -xzf "$WORK/alpinejs.tgz" -O package/dist/cdn.min.js > "$ROOT/usr/share/pxmxfw/www/alpine.min.js"
echo "$PXMXFW_VERSION" > "$ROOT/usr/share/pxmxfw/VERSION"
mkdir -p "$ROOT/etc/nftables.d" "$ROOT/etc/dnsmasq.d"
grep -q '^conf-dir=/etc/dnsmasq.d' "$ROOT/etc/dnsmasq.conf" ||
	echo 'conf-dir=/etc/dnsmasq.d/,*.conf' >> "$ROOT/etc/dnsmasq.conf"
# Default ruleset, used until first boot setup regenerates it
PXMXFW_ETC=$ROOT/etc/pxmxfw PXMXFW_LIB=$ROOT/usr/lib/pxmxfw \
	sh "$ROOT/usr/sbin/pxmxfw" render nft > "$ROOT/etc/pxmxfw/ruleset.nft"
chown -R 0:0 "$ROOT/etc" "$ROOT/usr/lib/pxmxfw" "$ROOT/usr/share/pxmxfw" "$ROOT/usr/sbin/pxmxfw"

# OpenRC in a container: skip hardware-only services
if [ -f "$ROOT/etc/rc.conf" ]; then
	sed -i 's/^#\{0,1\}rc_sys=.*/rc_sys="lxc"/' "$ROOT/etc/rc.conf"
else
	echo 'rc_sys="lxc"' > "$ROOT/etc/rc.conf"
fi

# 4. Enable services (same effect as rc-update add)
enable() { # runlevel service...
	lvl=$1; shift
	mkdir -p "$ROOT/etc/runlevels/$lvl"
	for s in "$@"; do ln -sf "/etc/init.d/$s" "$ROOT/etc/runlevels/$lvl/$s"; done
}
# dnsmasq is left off; enable it in the web UI (or DNSMASQ=yes + pxmxfw apply)
enable boot bootmisc hostname networking sysctl syslog pxmxfw nftables
enable default pxmxfw-webui
enable shutdown killprocs savecache

# 5. Pack the template
DATE=$(date +%Y%m%d)
OUT=$OUTDIR/alpine-$RELEASE-pxmxfw-${DATE}_amd64.tar.gz
echo ">> Packing $OUT"
rm -rf "$ROOT/var/cache/apk/"* "$ROOT/tmp/"*
tar --numeric-owner -czf "$OUT" -C "$ROOT" .
echo ">> Done: $OUT ($(du -h "$OUT" | cut -f1))"
