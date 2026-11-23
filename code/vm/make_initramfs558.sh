#!/bin/bash
# make_initramfs558.sh <binary> <mode> [<mode> ...]
#
# Turn 558: busybox, the static differ558, the stock nft binary, and the
# config symbols this turn is about -- including CONFIG_VLAN_8021Q, which is
# the whole difference between T557 and T558.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs558.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs558
mkdir -p initramfs558/bin initramfs558/proc initramfs558/sys initramfs558/dev initramfs558/root initramfs558/tmp
cp /usr/bin/busybox initramfs558/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs558/bin/$a
done
cp "$REPRO" initramfs558/root/repro
chmod +x initramfs558/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs558/nft
chmod +x initramfs558/nft
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
	echo 'zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(VLAN_8021Q|NET_IPIP|VXLAN|NET_UDP_TUNNEL|BRIDGE|NF_TABLES_BRIDGE|NF_TABLES_NETDEV|NF_TABLES_ARP)=" || echo NO_CONFIG_GZ'
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
} > initramfs558/init
chmod +x initramfs558/init
(cd initramfs558 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs558.cpio.gz)
ls -l initramfs558.cpio.gz
