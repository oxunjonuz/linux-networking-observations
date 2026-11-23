#!/bin/bash
# f71_run.sh -- turn 593 (F71). One kernel: 7.3.4-T563, no new build.
#   smoke <tag> <limit>     build the initrd with gro:<limit> and boot once
#   full                    build `gro`, boot the same image twice
#   mode <modespec>         build and boot one modespec
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd593
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> modes...
	local tag=$1; shift
	bash vm/make_initramfs593.sh "$ROOT/vm/build/differ593" "$@" >/dev/null || exit 1
	cp -f vm/initramfs593.cpio.gz "vm/initrd593/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd593/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f71_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd593/$1 TIMEOUT=${3:-5400} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f71_$2.log" > /dev/null
}

case "$MODE" in
smoke)
	mkinitrd "s$MODE2" "gro:${3:-3}"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 2400
	grep -a "F593 \|F591 PREP\|F593 PREP\|F593 WAIT\|F593 RCV" "logs/f71_smoke_$MODE2.log" | head -200
	;;
full)
	mkinitrd full gro
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	grep -a "F593 " "logs/f71_$MODE2.log" | head -160
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F593 lines: $(grep -acE '^F593 ' logs/f71_${MODE2:-x}.log 2>/dev/null)"
