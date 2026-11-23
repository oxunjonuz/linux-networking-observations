#!/bin/bash
# f36_run.sh [smoke <mode>|full <kernel>|...]
#
#   T = src/linux-7.3.4-T557   F35's kernel (no CONFIG_VLAN_8021Q)
#   V = src/linux-7.3.4-T558   T557 + CONFIG_VLAN_8021Q
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
MODE3=${3:-}
mkdir -p logs vm/initrd558
declare -A IMG
IMG[T]=src/linux-7.3.4-T557/arch/x86/boot/bzImage
IMG[V]=src/linux-7.3.4-T558/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f558}
	bash vm/make_initramfs558.sh "$ROOT/vm/build/differ558" $m >/dev/null || exit 1
	cp -f vm/initramfs558.cpio.gz "vm/initrd558/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd558/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f36_initrd_hashes.txt
}

run() {  # run <letter> <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd558/$2 TIMEOUT=${4:-3000} bash vm/run_qemu.sh \
		"$ROOT/${IMG[$1]}" "$ROOT/logs/f36_$3.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <mode> <kernel-letter>
	mkinitrd "s$MODE2" "$MODE2"
	run "${MODE3:-T}" "s$MODE2.cpio.gz" "smoke_$MODE2" 1200
	;;
full)	# full <kernel-letter>
	mkinitrd full f558
	run "$MODE2" full.cpio.gz "${MODE2}_rep1" 3600
	run "$MODE2" full.cpio.gz "${MODE2}_rep2" 3600
	;;
esac
echo "### DONE $MODE $MODE2 $MODE3"
grep -cE "^F558 " "logs/f36_${MODE2:-smoke_$MODE2}.log" 2>/dev/null | sed 's/^/### F558 lines: /'
