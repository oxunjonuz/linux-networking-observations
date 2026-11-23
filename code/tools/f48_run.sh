#!/bin/bash
# f48_run.sh [smoke <mode>|full|mode <mode>]
#
# One kernel: 7.3.4-T563 (the F41..F47 image; no new build).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd570
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f570}
	bash vm/make_initramfs570.sh "$ROOT/vm/build/differ570" $m >/dev/null || exit 1
	cp -f vm/initramfs570.cpio.gz "vm/initrd570/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd570/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f48_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd570/$1 TIMEOUT=${3:-3600} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f48_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <tag> [mode...]
	tag=$MODE2; shift 2 || true
	[ $# -eq 0 ] && set -- "$tag"
	mkinitrd "s$tag" "$@"
	run "s$tag.cpio.gz" "smoke_$tag" 2400
	;;
full)
	mkinitrd full ppp6e th6
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F570 lines: $(grep -acE '^F570 (A|T)' logs/f48_${MODE2:-x}.log 2>/dev/null)"
