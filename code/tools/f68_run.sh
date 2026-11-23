#!/bin/bash
# f68_run.sh [smoke <tag> <modespec>|full|mode <modespec>]
#
# One kernel: 7.3.4-T563 (the F41..F66 image; no new build).
# modespec = "cap4[:N]" or "cond4[:N]"
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd590
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> modes...
	local tag=$1; shift
	bash vm/make_initramfs590.sh "$ROOT/vm/build/differ590" "$@" >/dev/null || exit 1
	cp -f vm/initramfs590.cpio.gz "vm/initrd590/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd590/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f68_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd590/$1 TIMEOUT=${3:-5400} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f68_$2.log" > /dev/null
}

case "$MODE" in
smoke)
	mkinitrd "s$MODE2" "${3:-cap4:2 cond4:2}"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 2400
	grep -a "F67 \|F587 \|F590 " "logs/f68_smoke_$MODE2.log" | head -160
	;;
full)
	mkinitrd full cap4 cond4
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	grep -a "F67 \|F587 \|F590 " "logs/f68_$MODE2.log" | head -120
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F587 lines: $(grep -acE '^F590 ' logs/f68_${MODE2:-x}.log 2>/dev/null)"
