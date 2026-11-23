#!/bin/bash
# make_initramfs587.sh <binary> <mode> [<mode> ...]
#
# Turn 587: busybox, the static differ587, the stock nft binary, on the image
# F41..F64 used: 7.3.4-T563.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs587.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs587
mkdir -p initramfs587/bin initramfs587/proc initramfs587/sys initramfs587/dev initramfs587/root initramfs587/tmp
cp /usr/bin/busybox initramfs587/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs587/bin/$a
done
cp "$REPRO" initramfs587/root/repro
chmod +x initramfs587/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs587/nft
chmod +x initramfs587/nft
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
} > initramfs587/init
chmod +x initramfs587/init
(cd initramfs587 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs587.cpio.gz)
ls -l initramfs587.cpio.gz
