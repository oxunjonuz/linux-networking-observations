#!/bin/bash
# make_initramfs596.sh <binary> <mode> [<mode> ...]
#
# Turn 596: busybox, the static differ596, the stock nft binary, on the image
# F41..F73 used: 7.3.4-T563.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs596.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs596
mkdir -p initramfs596/bin initramfs596/proc initramfs596/sys initramfs596/dev initramfs596/root initramfs596/tmp
cp /usr/bin/busybox initramfs596/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs596/bin/$a
done
cp "$REPRO" initramfs596/root/repro
chmod +x initramfs596/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs596/nft
chmod +x initramfs596/nft
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
} > initramfs596/init
chmod +x initramfs596/init
(cd initramfs596 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs596.cpio.gz)
ls -l initramfs596.cpio.gz
