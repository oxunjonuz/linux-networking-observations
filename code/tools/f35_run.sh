#!/bin/bash
# f35_run.sh [smoke <mode>|tun|grid|verdict|full <letter>|B]
#
#   T = src/linux-7.3.4-T557   T556 (all four nft_nh_write_ok branches live)
#                              + CONFIG_NET_IPIP + CONFIG_VXLAN
#   B = src/linux-7.3.4-B19    stock 7.3.4 (no netdev, no bridge, no arp
#                              family, no tunnels): the ip-family-only control
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd557
declare -A IMG
IMG[T]=src/linux-7.3.4-T557/arch/x86/boot/bzImage
IMG[B]=src/linux-7.3.4-B19/arch/x86/boot/bzImage
for k in T B; do
	[ -f "${IMG[$k]}" ] || echo "### MISSING KERNEL $k (${IMG[$k]})"
done

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f557}
	bash vm/make_initramfs557.sh "$ROOT/vm/build/differ557" $m >/dev/null || exit 1
	cp -f vm/initramfs557.cpio.gz "vm/initrd557/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd557/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f35_initrd_hashes.txt
}

run() {  # run <letter> <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd557/$2 TIMEOUT=${4:-3000} bash vm/run_qemu.sh \
		"$ROOT/${IMG[$1]}" "$ROOT/logs/f35_$3.log" > /dev/null
	grep -cE "^F557 (R|CTL)\|" "$ROOT/logs/f35_$3.log" | sed "s/^/### arms in $3: /"
}

case "$MODE" in
smoke)	# smoke <mode>
	mkinitrd "s$MODE2" "$MODE2"
	run T "s$MODE2.cpio.gz" "smoke_$MODE2" 1200
	;;
tun)	mkinitrd tun f557tun; run T tun.cpio.gz T_tun 1200 ;;
grid)	mkinitrd grid f557grid; run T grid.cpio.gz T_grid 2400 ;;
verdict) mkinitrd ver f557verdict; run T ver.cpio.gz T_ver 1200 ;;
full)	mkinitrd full f557
	run T full.cpio.gz T_rep1 3600
	run T full.cpio.gz T_rep2 3600
	;;
B)	mkinitrd fullB f557
	run B fullB.cpio.gz B_rep1 3600
	;;
esac
echo "### DONE $MODE $MODE2"
