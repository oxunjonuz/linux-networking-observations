#!/bin/bash
# make_initramfs563.sh <binary> <mode> [<mode> ...]
#
# Turn 563: busybox, the static differ563, the stock nft binary, on the new
# image 7.3.4-T563 (= T558 + PPP + PPPOE).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs563.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs563
mkdir -p initramfs563/bin initramfs563/proc initramfs563/sys initramfs563/dev initramfs563/root initramfs563/tmp
cp /usr/bin/busybox initramfs563/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs563/bin/$a
done
cp "$REPRO" initramfs563/root/repro
chmod +x initramfs563/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs563/nft
chmod +x initramfs563/nft
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
	echo 'echo "=== PPPOE_STACK ==="'
	echo 'ls /proc/net | tr "\n" " "; echo'
	echo 'head -3 /proc/net/pppoe 2>&1'
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
} > initramfs563/init
chmod +x initramfs563/init
(cd initramfs563 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs563.cpio.gz)
ls -l initramfs563.cpio.gz
