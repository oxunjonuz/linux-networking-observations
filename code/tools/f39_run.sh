#!/bin/bash
# f39_run.sh [smoke <mode>|full|mode <mode>]
#
# One kernel: F36..F38's T558.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd561
IMG=src/linux-7.3.4-T558/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f561}
	bash vm/make_initramfs561.sh "$ROOT/vm/build/differ561" $m >/dev/null || exit 1
	cp -f vm/initramfs561.cpio.gz "vm/initrd561/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd561/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f39_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd561/$1 TIMEOUT=${3:-3600} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f39_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <mode>
	mkinitrd "s$MODE2" "$MODE2"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 1800
	;;
full)
	mkinitrd full f561
	run full.cpio.gz rep1 5400
	run full.cpio.gz rep2 5400
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F561 lines: $(grep -ac '^F561' logs/f39_${MODE2:-smoke_$MODE2}.log 2>/dev/null)"
