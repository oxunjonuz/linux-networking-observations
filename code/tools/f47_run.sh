#!/bin/bash
# f47_run.sh [smoke <mode>|full|mode <mode>]
#
# One kernel: 7.3.4-T563 (the F41..F45 image; no new build).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd569
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f569}
	bash vm/make_initramfs569.sh "$ROOT/vm/build/differ569" $m >/dev/null || exit 1
	cp -f vm/initramfs569.cpio.gz "vm/initrd569/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd569/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f47_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd569/$1 TIMEOUT=${3:-3600} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f47_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <mode>
	mkinitrd "s$MODE2" "$MODE2"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 1800
	;;
full)
	mkinitrd full iso v6
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F569 lines: $(grep -ac '^F569 A' logs/f47_${MODE2:-smoke_$MODE2}.log 2>/dev/null)"
