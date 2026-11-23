#!/bin/bash
# make_initramfs571.sh <binary> <mode> [<mode> ...]
#
# Turn 571: busybox, the static differ571, the stock nft binary, on the image
# F41..F48 used: 7.3.4-T563 (= T558 + CONFIG_PPP + CONFIG_PPPOE).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs571.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs571
mkdir -p initramfs571/bin initramfs571/proc initramfs571/sys initramfs571/dev initramfs571/root initramfs571/tmp
cp /usr/bin/busybox initramfs571/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs571/bin/$a
done
cp "$REPRO" initramfs571/root/repro
chmod +x initramfs571/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs571/nft
chmod +x initramfs571/nft
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
	echo 'dmesg | tail -40'
	echo 'sync'
	echo 'echo "=== VM_POWEROFF ==="'
	echo 'poweroff -f'
} > initramfs571/init
chmod +x initramfs571/init
(cd initramfs571 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs571.cpio.gz)
ls -l initramfs571.cpio.gz
