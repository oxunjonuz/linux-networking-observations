#!/bin/bash
# f63_run.sh [smoke <tag> <mode>|full|mode <mode>]
#
# One kernel: 7.3.4-T563 (the F41..F62 image; no new build).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd585
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-aggr}
	bash vm/make_initramfs585.sh "$ROOT/vm/build/differ585" $m >/dev/null || exit 1
	cp -f vm/initramfs585.cpio.gz "vm/initrd585/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd585/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f63_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd585/$1 TIMEOUT=${3:-5400} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f63_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <tag> [mode]
	mkinitrd "s$MODE2" "${3:-aggr:9}"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 2400
	grep -a "F585" "logs/f63_smoke_$MODE2.log" | head -220
	;;
full)
	mkinitrd full aggr
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F585 lines: $(grep -acE '^F585 ' logs/f63_${MODE2:-x}.log 2>/dev/null)"
