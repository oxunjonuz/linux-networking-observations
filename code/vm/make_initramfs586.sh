#!/bin/bash
# make_initramfs586.sh <binary> <mode> [<mode> ...]
#
# Turn 586: busybox, the static differ586, the stock nft binary, on the image
# F41..F63 used: 7.3.4-T563.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs586.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs586
mkdir -p initramfs586/bin initramfs586/proc initramfs586/sys initramfs586/dev initramfs586/root initramfs586/tmp
cp /usr/bin/busybox initramfs586/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs586/bin/$a
done
cp "$REPRO" initramfs586/root/repro
chmod +x initramfs586/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs586/nft
chmod +x initramfs586/nft
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
} > initramfs586/init
chmod +x initramfs586/init
(cd initramfs586 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs586.cpio.gz)
ls -l initramfs586.cpio.gz
