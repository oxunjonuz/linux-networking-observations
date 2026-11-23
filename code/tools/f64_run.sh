#!/bin/bash
# f64_run.sh [smoke <tag> <mode>|full|mode <mode>]
#
# One kernel: 7.3.4-T563 (the F41..F63 image; no new build).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd586
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-geom}
	bash vm/make_initramfs586.sh "$ROOT/vm/build/differ586" $m >/dev/null || exit 1
	cp -f vm/initramfs586.cpio.gz "vm/initrd586/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd586/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f64_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd586/$1 TIMEOUT=${3:-5400} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f64_$2.log" > /dev/null
}

case "$MODE" in
smoke)
	mkinitrd "s$MODE2" "${3:-geom:8}"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 2400
	grep -a "F586" "logs/f64_smoke_$MODE2.log" | head -240
	;;
full)
	mkinitrd full geom
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F586 lines: $(grep -acE '^F586 ' logs/f64_${MODE2:-x}.log 2>/dev/null)"
