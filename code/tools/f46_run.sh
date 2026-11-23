#!/bin/bash
# f46_run.sh [smoke <mode>|full|mode <mode>]
#
# One kernel: 7.3.4-T563 (the F41..F45 image; no new build).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd568
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f568}
	bash vm/make_initramfs568.sh "$ROOT/vm/build/differ568" $m >/dev/null || exit 1
	cp -f vm/initramfs568.cpio.gz "vm/initrd568/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd568/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f46_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd568/$1 TIMEOUT=${3:-3600} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f46_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <mode>
	mkinitrd "s$MODE2" "$MODE2"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 1800
	;;
full)
	mkinitrd full f568
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F568 lines: $(grep -ac '^F568 A' logs/f46_${MODE2:-smoke_$MODE2}.log 2>/dev/null)"
