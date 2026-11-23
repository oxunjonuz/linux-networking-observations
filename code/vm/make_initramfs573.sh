#!/bin/bash
# make_initramfs573.sh <binary> <mode> [<mode> ...]
#
# Turn 573: busybox, the static differ573, the stock nft binary, on the image
# F41..F50 used: 7.3.4-T563 (= T558 + CONFIG_PPP + CONFIG_PPPOE).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs573.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs573
mkdir -p initramfs573/bin initramfs573/proc initramfs573/sys initramfs573/dev initramfs573/root initramfs573/tmp
cp /usr/bin/busybox initramfs573/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs573/bin/$a
done
cp "$REPRO" initramfs573/root/repro
chmod +x initramfs573/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs573/nft
chmod +x initramfs573/nft
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
} > initramfs573/init
chmod +x initramfs573/init
(cd initramfs573 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs573.cpio.gz)
ls -l initramfs573.cpio.gz
