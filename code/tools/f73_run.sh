#!/bin/bash
# f73_run.sh -- turn 595 (F73). One kernel: 7.3.4-T563, no new build.
#   smoke <tag> [limit]  build the initrd with chg[:limit] and boot once
#   full                 build `chg cln`, boot the same image twice
#   mode <modespec>      build and boot one modespec
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd595
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> modes...
	local tag=$1; shift
	bash vm/make_initramfs595.sh "$ROOT/vm/build/differ595" "$@" >/dev/null || exit 1
	cp -f vm/initramfs595.cpio.gz "vm/initrd595/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd595/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f73_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd595/$1 TIMEOUT=${3:-5400} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f73_$2.log" > /dev/null
}

case "$MODE" in
smoke)
	mkinitrd "s$MODE2" "chg:${3:-3}"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 2400
	grep -a "F595 " "logs/f73_smoke_$MODE2.log" | head -300
	;;
full)
	mkinitrd full all
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	grep -a "F595 " "logs/f73_$MODE2.log" | head -200
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F595 lines: $(grep -acE '^F595 ' logs/f73_${MODE2:-x}.log 2>/dev/null)"
