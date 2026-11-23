#!/bin/bash
# make_initramfs555.sh <binary> <mode> [<mode> ...]
#
# Turn 555: busybox, the static differ555, and the stock nft binary (nftables
# 1.1.7, static).  No `ip` command is used by the differ: every link, address
# and neighbour comes from rtnetlink; /proc/net/arp is read as a file.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs555.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs555
mkdir -p initramfs555/bin initramfs555/proc initramfs555/sys initramfs555/dev initramfs555/root initramfs555/tmp
cp /usr/bin/busybox initramfs555/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do ln -sf /bin/busybox initramfs555/bin/$a; done
cp "$REPRO" initramfs555/root/repro
chmod +x initramfs555/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs555/nft
chmod +x initramfs555/nft
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
  echo 'zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(NF_TABLES_ARP|NETFILTER_FAMILY_ARP|NF_TABLES_BRIDGE|NF_TABLES_NETDEV)=" || echo NO_CONFIG_GZ'
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
} > initramfs555/init
chmod +x initramfs555/init
(cd initramfs555 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs555.cpio.gz)
ls -l initramfs555.cpio.gz
