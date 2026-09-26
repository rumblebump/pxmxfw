#!/bin/sh
# Build the pxmxfw Proxmox LXC template.
#
# Downloads the Alpine minirootfs, installs OpenRC, nftables and dnsmasq in a
# chroot, applies the files under rootfs/ and packs the result as a template
# tarball for `pct create`. Run as root on an x86_64 Linux host (a Proxmox
# node works fine).
#
# Usage: ./build.sh [-v ALPINE_VERSION] [-m MIRROR] [-o OUTDIR] [-r MINIROOTFS]
#                   [--skip-packages]
#   -v  Alpine branch, e.g. 3.22 (default: $ALPINE_VERSION or 3.22)
#   -m  Alpine mirror (default: $ALPINE_MIRROR or https://dl-cdn.alpinelinux.org/alpine)
#   -o  output directory (default: ./out)
#   -r  use a local minirootfs .tar.gz instead of downloading one
#   --skip-packages  do not run apk; only useful for testing the packing
#                    steps without network access to an Alpine mirror

set -eu

ALPINE_VERSION=${ALPINE_VERSION:-3.22}
ALPINE_MIRROR=${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}
ARCH=x86_64
OUTDIR=./out
MINIROOTFS=
SKIP_PACKAGES=0
PACKAGES="alpine-base nftables dnsmasq"

SRCDIR=$(cd "$(dirname "$0")" && pwd)

die() { echo "build.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case $1 in
		-v) ALPINE_VERSION=$2; shift 2 ;;
		-m) ALPINE_MIRROR=$2; shift 2 ;;
		-o) OUTDIR=$2; shift 2 ;;
		-r) MINIROOTFS=$2; shift 2 ;;
		--skip-packages) SKIP_PACKAGES=1; shift ;;
		-h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) die "unknown option: $1" ;;
	esac
done

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

# 2. Install packages in a chroot
cat > "$ROOT/etc/apk/repositories" <<-EOF
	$ALPINE_MIRROR/v$ALPINE_VERSION/main
	$ALPINE_MIRROR/v$ALPINE_VERSION/community
EOF
if [ "$SKIP_PACKAGES" -eq 0 ]; then
	echo ">> Installing: $PACKAGES"
	cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"
	mount -t proc proc "$ROOT/proc"
	mount --bind /dev "$ROOT/dev"
	chroot "$ROOT" /sbin/apk add --no-cache --update $PACKAGES
	umount "$ROOT/dev" "$ROOT/proc"
	: > "$ROOT/etc/resolv.conf"   # Proxmox writes this on container start
else
	echo ">> Skipping package install (--skip-packages): template will NOT boot a firewall"
fi

# 3. Apply the project's config
echo ">> Applying rootfs/ overlay"
cp -a "$SRCDIR/rootfs/." "$ROOT/"
mkdir -p "$ROOT/etc/nftables.d"
chown -R 0:0 "$ROOT/etc"

# OpenRC in a container: skip hardware-only services
if [ -f "$ROOT/etc/rc.conf" ]; then
	sed -i 's/^#\{0,1\}rc_sys=.*/rc_sys="lxc"/' "$ROOT/etc/rc.conf"
else
	echo 'rc_sys="lxc"' > "$ROOT/etc/rc.conf"
fi

# 4. Enable services (same effect as rc-update add, done by symlink so it
#    also works with --skip-packages)
enable() { # runlevel service...
	lvl=$1; shift
	mkdir -p "$ROOT/etc/runlevels/$lvl"
	for s in "$@"; do ln -sf "/etc/init.d/$s" "$ROOT/etc/runlevels/$lvl/$s"; done
}
enable boot bootmisc hostname networking sysctl syslog
enable default nftables dnsmasq
enable shutdown killprocs savecache

# 5. Pack the template
DATE=$(date +%Y%m%d)
SUFFIX=
[ "$SKIP_PACKAGES" -eq 1 ] && SUFFIX=-nopkgs
OUT=$OUTDIR/alpine-$RELEASE-pxmxfw$SUFFIX-${DATE}_amd64.tar.gz
echo ">> Packing $OUT"
rm -rf "$ROOT/var/cache/apk/"* "$ROOT/tmp/"*
tar --numeric-owner -czf "$OUT" -C "$ROOT" .
echo ">> Done: $OUT ($(du -h "$OUT" | cut -f1))"
