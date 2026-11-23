#!/bin/bash
# make_initramfs562.sh <binary> <mode> [<mode> ...]
#
# Turn 562: busybox, the static differ562, the stock nft binary.  No new kernel
# -- F39 measures 802.1AD / Q-in-Q on the same T558 image F36..F38 used.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs562.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs562
mkdir -p initramfs562/bin initramfs562/proc initramfs562/sys initramfs562/dev initramfs562/root initramfs562/tmp
cp /usr/bin/busybox initramfs562/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs562/bin/$a
done
cp "$REPRO" initramfs562/root/repro
chmod +x initramfs562/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs562/nft
chmod +x initramfs562/nft
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
	echo 'zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(VLAN_8021Q|BRIDGE|NF_TABLES_BRIDGE|NF_TABLES_NETDEV|NF_TABLES_ARP|NET_EGRESS)=" || echo NO_CONFIG_GZ'
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
} > initramfs562/init
chmod +x initramfs562/init
(cd initramfs562 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs562.cpio.gz)
ls -l initramfs562.cpio.gz
