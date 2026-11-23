#!/bin/bash
# make_initramfs561.sh <binary> <mode> [<mode> ...]
#
# Turn 561: busybox, the static differ561, the stock nft binary.  No new kernel
# -- F39 measures 802.1AD / Q-in-Q on the same T558 image F36..F38 used.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs561.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs561
mkdir -p initramfs561/bin initramfs561/proc initramfs561/sys initramfs561/dev initramfs561/root initramfs561/tmp
cp /usr/bin/busybox initramfs561/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs561/bin/$a
done
cp "$REPRO" initramfs561/root/repro
chmod +x initramfs561/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs561/nft
chmod +x initramfs561/nft
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
} > initramfs561/init
chmod +x initramfs561/init
(cd initramfs561 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs561.cpio.gz)
ls -l initramfs561.cpio.gz
