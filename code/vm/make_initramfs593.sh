#!/bin/bash
# make_initramfs593.sh <binary> <mode> [<mode> ...]
#
# Turn 593: busybox, the static differ593, the stock nft binary, on the image
# F41..F70 used: 7.3.4-T563.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs593.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs593
mkdir -p initramfs593/bin initramfs593/proc initramfs593/sys initramfs593/dev initramfs593/root initramfs593/tmp
cp /usr/bin/busybox initramfs593/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs593/bin/$a
done
cp "$REPRO" initramfs593/root/repro
chmod +x initramfs593/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs593/nft
chmod +x initramfs593/nft
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
	echo 'echo "=== REPRO_OUTPUT_BEGIN ==="'
	for m in $MODES; do
		echo "echo \"=== MODE_BEGIN $m ===\""
		echo "/root/repro $m; echo \"=== MODE_EXIT $m=\$? ===\""
	done
	echo 'echo "=== REPRO_OUTPUT_END ==="'
	echo 'echo "=== DMESG_TAIL ==="'
	echo 'dmesg | tail -80'
	echo 'sync'
	echo 'echo "=== VM_POWEROFF ==="'
	echo 'poweroff -f'
} > initramfs593/init
chmod +x initramfs593/init
(cd initramfs593 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs593.cpio.gz)
ls -l initramfs593.cpio.gz
