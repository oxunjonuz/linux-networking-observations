#!/bin/bash
# f51_run.sh [smoke <tag>|full|mode <mode>]
#
# One kernel: 7.3.4-T563 (the F41..F49 image; no new build).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd573
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-flood}
	bash vm/make_initramfs573.sh "$ROOT/vm/build/differ573" $m >/dev/null || exit 1
	cp -f vm/initramfs573.cpio.gz "vm/initrd573/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd573/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f51_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd573/$1 TIMEOUT=${3:-5400} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f51_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <tag>
	mkinitrd "s$MODE2" flood
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 2400
	grep -a "F573" "logs/f51_smoke_$MODE2.log" | head -80
	;;
full)
	mkinitrd full flood
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F573 lines: $(grep -acE '^F573 ' logs/f51_${MODE2:-x}.log 2>/dev/null)"
