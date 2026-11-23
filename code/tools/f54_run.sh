#!/bin/bash
# f54_run.sh [smoke <tag>|full|mode <mode>]
#
# One kernel: 7.3.4-T563 (the F41..F53 image; no new build).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd576
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-warn xf}
	bash vm/make_initramfs576.sh "$ROOT/vm/build/differ576" $m >/dev/null || exit 1
	cp -f vm/initramfs576.cpio.gz "vm/initrd576/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd576/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f54_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd576/$1 TIMEOUT=${3:-5400} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f54_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <tag>
	mkinitrd "s$MODE2" warn xf
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 2400
	grep -a "F576" "logs/f54_smoke_$MODE2.log" | head -200
	;;
full)
	mkinitrd full warn xf
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F576 lines: $(grep -acE '^F576 ' logs/f54_${MODE2:-x}.log 2>/dev/null)"
