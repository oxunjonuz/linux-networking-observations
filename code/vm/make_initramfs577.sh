#!/bin/bash
# make_initramfs577.sh <binary> <mode> [<mode> ...]
#
# Turn 577: busybox, the static differ577, the stock nft binary, on the image
# F41..F54 used: 7.3.4-T563 (= T558 + CONFIG_PPP + CONFIG_PPPOE).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs577.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs577
mkdir -p initramfs577/bin initramfs577/proc initramfs577/sys initramfs577/dev initramfs577/root initramfs577/tmp
cp /usr/bin/busybox initramfs577/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs577/bin/$a
done
cp "$REPRO" initramfs577/root/repro
chmod +x initramfs577/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs577/nft
chmod +x initramfs577/nft
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
} > initramfs577/init
chmod +x initramfs577/init
(cd initramfs577 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs577.cpio.gz)
ls -l initramfs577.cpio.gz
