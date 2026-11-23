#!/bin/bash
# f74_run.sh -- turn 596 (F74). One kernel: 7.3.4-T563, no new build.
#   smoke <tag> [mode] [limit]   build the initrd with <mode>[:limit], boot once
#   full                         build `q h`, boot the same image twice
#   mode <modespec>              build and boot one modespec
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
LIM=${3:-3}
mkdir -p logs vm/initrd596
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> modes...
	local tag=$1; shift
	bash vm/make_initramfs596.sh "$ROOT/vm/build/differ596" "$@" >/dev/null || exit 1
	cp -f vm/initramfs596.cpio.gz "vm/initrd596/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd596/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f74_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd596/$1 TIMEOUT=${3:-7200} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f74_$2.log" > /dev/null
}

case "$MODE" in
smoke)
	mkinitrd "s$MODE2" "${MODE2:-q}:$LIM"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 2400
	grep -a "F596 " "logs/f74_smoke_$MODE2.log" | head -300
	;;
full)
	mkinitrd full q h
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	grep -a "F596 " "logs/f74_$MODE2.log" | head -200
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F596 lines: $(grep -acE '^F596 ' logs/f74_${MODE2:-x}.log 2>/dev/null)"
