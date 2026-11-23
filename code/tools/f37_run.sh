#!/bin/bash
# f37_run.sh [smoke <mode>|full|mode <mode>]
#
# One kernel: F36's T558.  The instrument does not change the kernel, it takes
# a feature bit away from a device.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd559
IMG=src/linux-7.3.4-T558/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> [mode...]
	local tag=$1; shift
	local m=${*:-f559}
	bash vm/make_initramfs559.sh "$ROOT/vm/build/differ559" $m >/dev/null || exit 1
	cp -f vm/initramfs559.cpio.gz "vm/initrd559/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd559/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f37_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd559/$1 TIMEOUT=${3:-3600} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f37_$2.log" > /dev/null
}

case "$MODE" in
smoke)	# smoke <mode>
	mkinitrd "s$MODE2" "$MODE2"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 1200
	;;
full)
	mkinitrd full f559
	run full.cpio.gz rep1 3600
	run full.cpio.gz rep2 3600
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 1800
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F559 lines: $(grep -c '^F559' logs/f37_${MODE2:-smoke_$MODE2}.log 2>/dev/null)"
