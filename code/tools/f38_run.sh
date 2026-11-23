#!/bin/bash
# f38_run.sh [smoke <mode>|full|mode <mode>]
#
# One kernel: F36/F37's T558.  F38 measures what the receiving kernel makes of
# a frame whose 802.1Q tag sits in its own bytes.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd560
IMG=src/linux-7.3.4-T558/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f560}
	bash vm/make_initramfs560.sh "$ROOT/vm/build/differ560" $m >/dev/null || exit 1
	cp -f vm/initramfs560.cpio.gz "vm/initrd560/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd560/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f38_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd560/$1 TIMEOUT=${3:-3600} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f38_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <mode>
	mkinitrd "s$MODE2" "$MODE2"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 1200
	;;
full)
	mkinitrd full f560
	run full.cpio.gz rep1 3600
	run full.cpio.gz rep2 3600
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 1800
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F560 lines: $(grep -c '^F560' logs/f38_${MODE2:-smoke_$MODE2}.log 2>/dev/null)"
