#!/bin/bash
# make_initramfs551.sh <binary> <mode> [<mode> ...]
#
# Turn 551 needs the same guest as 549/550: busybox, the static differ, and the
# stock nft binary (nftables 1.1.7, static, sha256 77d83a42...).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs551.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs551
mkdir -p initramfs551/bin initramfs551/sbin initramfs551/proc initramfs551/sys initramfs551/dev initramfs551/root initramfs551/tmp initramfs551/etc
cp /usr/bin/busybox initramfs551/bin/busybox
for a in sh mount umount cat echo ls grep poweroff sleep dmesg ip ifconfig head tail wc tr cut sort sed; do ln -sf /bin/busybox initramfs551/bin/$a; done
cp "$REPRO" initramfs551/root/repro
chmod +x initramfs551/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs551/nft
chmod +x initramfs551/nft
{
  echo '#!/bin/busybox sh'
  echo '/bin/busybox --install -s'
  echo 'mount -t proc     proc /proc'
  echo 'mount -t sysfs    sys  /sys'
  echo 'mount -t devtmpfs dev  /dev 2>/dev/null'
  echo 'ip link set lo up 2>/dev/null || echo "WARN: could not bring up lo"'
  echo 'ip addr add 10.0.0.1/32 dev lo 2>/dev/null'
  echo 'ip addr add 10.0.0.2/32 dev lo 2>/dev/null'
  echo 'ip addr add 10.0.0.3/32 dev lo 2>/dev/null'
  echo 'echo "=== VM_BOOT_OK ==="'
  echo 'cat /proc/version'
  echo 'echo "=== NFT_VERSION ==="'
  echo '/nft -v 2>&1 | head -1'
  echo 'echo "=== REPRO_OUTPUT_BEGIN ==="'
  for m in $MODES; do
    echo "echo \"=== MODE_BEGIN $m ===\""
    echo "/root/repro $m; echo \"=== MODE_EXIT $m=\$? ===\""
  done
  echo 'echo "=== REPRO_OUTPUT_END ==="'
  echo 'echo "=== DMESG_TAIL ==="'
  echo 'dmesg | tail -40'
  echo 'sync'
  echo 'echo "=== VM_POWEROFF ==="'
  echo 'poweroff -f'
} > initramfs551/init
chmod +x initramfs551/init
(cd initramfs551 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs551.cpio.gz)
ls -l initramfs551.cpio.gz
