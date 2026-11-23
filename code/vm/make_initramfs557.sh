#!/bin/bash
# make_initramfs557.sh <binary> <mode> [<mode> ...]
#
# Turn 557: busybox, the static differ557, and the stock nft binary
# (nftables 1.1.7, static).  Same guest as make_initramfs556.sh; what changes
# is that this turn's boots create TUNNEL devices (ipip, vxlan), so the boot
# prints the symbols that decide whether they can exist at all.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPRO=${1:?usage: make_initramfs557.sh <bin> <mode> [<mode>...]}
shift
MODES="$*"
cd "$HERE"
rm -rf initramfs557
mkdir -p initramfs557/bin initramfs557/proc initramfs557/sys initramfs557/dev initramfs557/root initramfs557/tmp
cp /usr/bin/busybox initramfs557/bin/busybox
for a in sh mount cat echo ls grep poweroff dmesg head tail wc tr cut sort sed sleep; do
	ln -sf /bin/busybox initramfs557/bin/$a
done
cp "$REPRO" initramfs557/root/repro
chmod +x initramfs557/root/repro
cp "$HERE/../src/dl23/nftables-1.1.7/src/nft.static" initramfs557/nft
chmod +x initramfs557/nft
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
	echo 'echo "=== CONFIG_SYMBOLS ==="'
	echo 'zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(NET_IPIP|VXLAN|NET_UDP_TUNNEL|INET_TUNNEL|BRIDGE|NF_TABLES_BRIDGE|NF_TABLES_NETDEV|NF_TABLES_ARP)=" || echo NO_CONFIG_GZ'
	echo 'echo "=== TUNNEL_KINDS ==="'
	echo 'grep -c ipip /proc/net/ip_tunnels 2>/dev/null || echo no_ip_tunnels_proc'
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
} > initramfs557/init
chmod +x initramfs557/init
(cd initramfs557 && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > ../initramfs557.cpio.gz)
ls -l initramfs557.cpio.gz
