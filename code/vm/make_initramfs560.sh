#!/bin/bash
# make_initramfs560.sh <binary> <mode> [<mode> ...]
#
# Turn 560: busybox, the static differ560, the stock nft binary.  No new kernel
# -- F38 measures the RECEIVING side of F37's tag, so the kernel is still T558
# and every source file the earlier findings measured is the same bytes.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs560.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs560
mkdir -p initramfs560/bin initramfs560/proc initramfs560/sys initramfs560/dev initramfs560/root initramfs560/tmp
cp /usr/bin/busybox initramfs560/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs560/bin/$a
done
cp "$REPRO" initramfs560/root/repro
chmod +x initramfs560/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs560/nft
chmod +x initramfs560/nft
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
} > initramfs560/init
chmod +x initramfs560/init
(cd initramfs560 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs560.cpio.gz)
ls -l initramfs560.cpio.gz
