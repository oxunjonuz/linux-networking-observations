#!/bin/bash
# f40_run.sh [smoke <mode>|full|mode <mode>]
#
# One kernel: F36..F38's T558.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd562
IMG=src/linux-7.3.4-T558/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f562}
	bash vm/make_initramfs562.sh "$ROOT/vm/build/differ562" $m >/dev/null || exit 1
	cp -f vm/initramfs562.cpio.gz "vm/initrd562/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd562/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f40_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd562/$1 TIMEOUT=${3:-3600} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f40_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <mode>
	mkinitrd "s$MODE2" "$MODE2"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 1800
	;;
full)
	mkinitrd full f562
	run full.cpio.gz rep1 5400
	run full.cpio.gz rep2 5400
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F562 lines: $(grep -ac '^F562' logs/f40_${MODE2:-smoke_$MODE2}.log 2>/dev/null)"
