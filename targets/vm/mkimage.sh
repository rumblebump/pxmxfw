#!/bin/sh
# Turn a pxmxfw root filesystem into a bootable VM disk (qcow2).
#
# Usage: targets/vm/mkimage.sh ROOT OUT.qcow2
# Run by build.sh as root on an Alpine build host, after the files under
# targets/vm/rootfs are applied to ROOT. It adds the kernel (linux-virt) and
# an initramfs, then writes a BIOS-bootable disk:
#   partition 1: FAT, mounted at /boot (syslinux, kernel, initramfs)
#   partition 2: ext4, the root filesystem
# Kernel upgrades with apk land in /boot and stay bootable. The qcow2 is
# compressed, so Proxmox imports it as is (qm disk import).
#
# VM_DISK_MB sets the disk size (default 2048); grow it later with
# qm disk resize, then resize2fs after growing partition 2.

set -eu

ROOT=$1
OUT=$2
HERE=$(cd "$(dirname "$0")" && pwd)
DISK_MB=${VM_DISK_MB:-2048}
BOOT_MB=128
ROOT_MB=$((DISK_MB - BOOT_MB - 1))
KERNEL=virt

die() { echo "mkimage.sh: $*" >&2; exit 1; }

[ -f /etc/alpine-release ] || die "run on Alpine (build.sh --podman does that)"
[ "$ROOT_MB" -ge 512 ] || die "VM_DISK_MB is too small"

echo ">> Installing the image tools"
apk add --no-cache dosfstools e2fsprogs mtools qemu-img sfdisk syslinux >/dev/null

WORK=$(mktemp -d)
cleanup() {
	for m in "$ROOT/dev" "$ROOT/proc"; do
		mountpoint -q "$m" 2>/dev/null && umount -l "$m"
	done
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# The kernel's trigger runs mkinitfs inside ROOT, which needs /dev and /proc
echo ">> Installing linux-$KERNEL"
mount -t proc proc "$ROOT/proc"
mount --bind /dev "$ROOT/dev"
cp -L /etc/resolv.conf "$ROOT/etc/resolv.conf"
chroot "$ROOT" /sbin/apk add --no-cache --update "linux-$KERNEL" busybox-mdev-openrc qemu-guest-agent e2fsprogs dosfstools
KVER=$(ls "$ROOT/lib/modules")
[ "$(echo "$KVER" | wc -l)" = 1 ] || die "expected one kernel in $ROOT/lib/modules, found: $KVER"
# Once more, so the initramfs surely has this mkinitfs.conf's drivers
chroot "$ROOT" /sbin/mkinitfs -o "/boot/initramfs-$KERNEL" "$KVER"
: > "$ROOT/etc/resolv.conf"   # udhcpc writes it at boot
umount "$ROOT/dev" "$ROOT/proc"
[ -f "$ROOT/boot/vmlinuz-$KERNEL" ] && [ -f "$ROOT/boot/initramfs-$KERNEL" ] || die "no kernel or initramfs in $ROOT/boot"

# /boot becomes the FAT partition; the root keeps an empty mount point
echo ">> Writing the boot partition"
mkdir "$WORK/boot"
mv "$ROOT/boot/"* "$WORK/boot/"
cp "$HERE/syslinux.cfg" "$WORK/boot/syslinux.cfg"
export MTOOLS_SKIP_CHECK=1
mkfs.vfat -F 32 -n PXMXFW_BOOT -C "$WORK/boot.img" $((BOOT_MB * 1024)) >/dev/null
mcopy -i "$WORK/boot.img" -s "$WORK/boot/"* ::/
syslinux --install "$WORK/boot.img"

echo ">> Writing the root partition"
rm -rf "$ROOT/var/cache/apk/"* "$ROOT/tmp/"*
mkfs.ext4 -q -F -L pxmxfw_root -d "$ROOT" "$WORK/root.img" "${ROOT_MB}M"

echo ">> Assembling the disk"
DISK=$WORK/disk.raw
truncate -s "${DISK_MB}M" "$DISK"
sfdisk -q "$DISK" <<-EOF
	label: dos
	start=2048, size=$((BOOT_MB * 2048)), type=c, bootable
	start=$(((BOOT_MB + 1) * 2048)), type=83
EOF
MB=1048576
dd if="$WORK/boot.img" of="$DISK" bs=$MB seek=1 conv=notrunc 2>/dev/null
dd if="$WORK/root.img" of="$DISK" bs=$MB seek=$((BOOT_MB + 1)) conv=notrunc 2>/dev/null
dd if=/usr/share/syslinux/mbr.bin of="$DISK" bs=440 count=1 conv=notrunc 2>/dev/null
qemu-img convert -c -f raw -O qcow2 "$DISK" "$OUT"
