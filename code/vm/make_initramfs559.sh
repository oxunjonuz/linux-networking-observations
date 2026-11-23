#!/bin/bash
# make_initramfs559.sh <binary> <mode> [<mode> ...]
#
# Turn 559: busybox, the static differ559, the stock nft binary.  No new kernel
# this turn -- the instrument changes a feature bit of an existing device, so
# the kernel is F36's T558 and every source file the earlier findings measured
# is the same bytes.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs559.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs559
mkdir -p initramfs559/bin initramfs559/proc initramfs559/sys initramfs559/dev initramfs559/root initramfs559/tmp
cp /usr/bin/busybox initramfs559/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs559/bin/$a
done
cp "$REPRO" initramfs559/root/repro
chmod +x initramfs559/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs559/nft
chmod +x initramfs559/nft
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
	echo 'zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(VLAN_8021Q|BRIDGE|NF_TABLES_BRIDGE|NF_TABLES_NETDEV|NF_TABLES_ARP|TUN)=" || echo NO_CONFIG_GZ'
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
} > initramfs559/init
chmod +x initramfs559/init
(cd initramfs559 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs559.cpio.gz)
ls -l initramfs559.cpio.gz
