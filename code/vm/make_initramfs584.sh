#!/bin/bash
# make_initramfs584.sh <binary> <mode> [<mode> ...]
#
# Turn 584: busybox, the static differ584, the stock nft binary, on the image
# F41..F61 used: 7.3.4-T563 (= T558 + CONFIG_PPP + CONFIG_PPPOE).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs584.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs584
mkdir -p initramfs584/bin initramfs584/proc initramfs584/sys initramfs584/dev initramfs584/root initramfs584/tmp
cp /usr/bin/busybox initramfs584/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs584/bin/$a
done
cp "$REPRO" initramfs584/root/repro
chmod +x initramfs584/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs584/nft
chmod +x initramfs584/nft
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
	echo 'dmesg | tail -60'
	echo 'sync'
	echo 'echo "=== VM_POWEROFF ==="'
	echo 'poweroff -f'
} > initramfs584/init
chmod +x initramfs584/init
(cd initramfs584 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs584.cpio.gz)
ls -l initramfs584.cpio.gz
