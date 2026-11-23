#!/bin/bash
# f44_run.sh [smoke <mode>|full|mode <mode>]
#
# One kernel: 7.3.4-T563 = T558 + CONFIG_PPP + CONFIG_PPPOE (the F41 image).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd566
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f566}
	bash vm/make_initramfs566.sh "$ROOT/vm/build/differ566" $m >/dev/null || exit 1
	cp -f vm/initramfs566.cpio.gz "vm/initrd566/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd566/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f44_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd566/$1 TIMEOUT=${3:-3600} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f44_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <mode>
	mkinitrd "s$MODE2" "$MODE2"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 1800
	;;
full)
	mkinitrd full f566
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F566 lines: $(grep -ac "^F566 A" logs/f44_${MODE2:-smoke_$MODE2}.log 2>/dev/null)"
