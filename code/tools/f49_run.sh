#!/bin/bash
# f49_run.sh [smoke <tag> <mode>|full|mode <mode>]
#
# One kernel: 7.3.4-T563 (the F41..F48 image; no new build).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd571
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-pp6l3}
	bash vm/make_initramfs571.sh "$ROOT/vm/build/differ571" $m >/dev/null || exit 1
	cp -f vm/initramfs571.cpio.gz "vm/initrd571/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd571/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f49_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd571/$1 TIMEOUT=${3:-3600} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f49_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <tag> [mode...]
	tag=$MODE2; shift 2 || true
	[ $# -eq 0 ] && set -- "$tag"
	mkinitrd "s$tag" "$@"
	run "s$tag.cpio.gz" "smoke_$tag" 2400
	grep -a "F571" "logs/f49_smoke_$tag.log" | head -60
	;;
full)
	mkinitrd full pp6l3
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F571 lines: $(grep -acE '^F571 ' logs/f49_${MODE2:-x}.log 2>/dev/null)"
