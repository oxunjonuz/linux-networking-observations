#!/bin/bash
# make_initramfs581.sh <binary> <mode> [<mode> ...]
#
# Turn 581: busybox, the static differ581, the stock nft binary, on the image
# F41..F58 used: 7.3.4-T563 (= T558 + CONFIG_PPP + CONFIG_PPPOE).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs581.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs581
mkdir -p initramfs581/bin initramfs581/proc initramfs581/sys initramfs581/dev initramfs581/root initramfs581/tmp
cp /usr/bin/busybox initramfs581/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs581/bin/$a
done
cp "$REPRO" initramfs581/root/repro
chmod +x initramfs581/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs581/nft
chmod +x initramfs581/nft
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
} > initramfs581/init
chmod +x initramfs581/init
(cd initramfs581 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs581.cpio.gz)
ls -l initramfs581.cpio.gz
