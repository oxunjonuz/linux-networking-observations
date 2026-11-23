#!/bin/bash
# make_initramfs566.sh <binary> <mode> [<mode> ...]
#
# Turn 566: busybox, the static differ566, the stock nft binary, on the image
# F42 built: 7.3.4-T563 (= T558 + CONFIG_PPP + CONFIG_PPPOE).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs566.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs566
mkdir -p initramfs566/bin initramfs566/proc initramfs566/sys initramfs566/dev initramfs566/root initramfs566/tmp
cp /usr/bin/busybox initramfs566/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs566/bin/$a
done
cp "$REPRO" initramfs566/root/repro
chmod +x initramfs566/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs566/nft
chmod +x initramfs566/nft
{
	echo '#!/bin/busybox sh'
	echo '/bin/busybox --install -s'
	echo 'mount -t proc     proc /proc'
	echo 'mount -t sysfs    sys  /sys'
	echo 'mount -t devtmpfs dev  /dev 2>/dev/null'
	echo 'echo "=== VM_BOOT_OK ==="'
	echo 'cat /proc/version'
	echo 'echo "=== PPP_DEV ==="'
	echo 'ls -l /dev/ppp 2>&1'
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
} > initramfs566/init
chmod +x initramfs566/init
(cd initramfs566 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs566.cpio.gz)
ls -l initramfs566.cpio.gz
