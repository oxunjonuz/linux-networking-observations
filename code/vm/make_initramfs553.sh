#!/bin/bash
# make_initramfs553.sh <binary> <mode> [<mode> ...]
#
# Turn 553: busybox, the static differ553, and the stock nft binary
# (nftables 1.1.7, static, sha256 77d83a42...).  No `ip` command is used by the
# differ: every link, address, neighbour and bridge is created over rtnetlink.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs553.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs553
mkdir -p initramfs553/bin initramfs553/proc initramfs553/sys initramfs553/dev initramfs553/root initramfs553/tmp
cp /usr/bin/busybox initramfs553/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do ln -sf /bin/busybox initramfs553/bin/$a; done
cp "$REPRO" initramfs553/root/repro
chmod +x initramfs553/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs553/nft
chmod +x initramfs553/nft
{
  echo '#!/bin/busybox sh'
  echo '/bin/busybox --install -s'
  echo 'mount -t proc     proc /proc'
  echo 'mount -t sysfs    sys  /sys'
  echo 'mount -t devtmpfs dev  /dev 2>/dev/null'
  echo 'echo "=== VM_BOOT_OK ==="'
  echo 'cat /proc/version'
  echo 'echo "=== NFT_VERSION ==="'
  echo '/nft -v 2>&1 | head -1'
  echo 'echo "=== CONFIG_SYMBOLS ==="'
  echo 'zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(BRIDGE|NF_TABLES_BRIDGE|NF_TABLES_NETDEV)=" || echo NO_CONFIG_GZ'
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
} > initramfs553/init
chmod +x initramfs553/init
(cd initramfs553 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs553.cpio.gz)
ls -l initramfs553.cpio.gz
