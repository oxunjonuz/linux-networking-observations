#!/bin/bash
# make_initramfs556.sh <binary> <mode> [<mode> ...]
#
# Turn 556: busybox, the static differ556, and the stock nft binary (nftables
# 1.1.7, static).  Same as make_initramfs555.sh except for the symbol block:
# F33 needs all four guard branches live in ONE image, so the boot prints the
# six symbols that decide them (plus BRIDGE itself).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs556.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs556
mkdir -p initramfs556/bin initramfs556/proc initramfs556/sys initramfs556/dev initramfs556/root initramfs556/tmp
cp /usr/bin/busybox initramfs556/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do ln -sf /bin/busybox initramfs556/bin/$a; done
cp "$REPRO" initramfs556/root/repro
chmod +x initramfs556/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs556/nft
chmod +x initramfs556/nft
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
  echo 'zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(NF_TABLES_ARP|NETFILTER_FAMILY_ARP|NF_TABLES_BRIDGE|NETFILTER_FAMILY_BRIDGE|NF_TABLES_NETDEV|BRIDGE)=" || echo NO_CONFIG_GZ'
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
} > initramfs556/init
chmod +x initramfs556/init
(cd initramfs556 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs556.cpio.gz)
ls -l initramfs556.cpio.gz
