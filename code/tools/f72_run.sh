#!/bin/bash
# f72_run.sh -- turn 594 (F72). One kernel: 7.3.4-T563, no new build.
#   smoke <tag> [limit]  build the initrd with zc[:limit] and boot once
#   full                 build `zc`, boot the same image twice
#   mode <modespec>      build and boot one modespec
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
MODE2=${2:-}
mkdir -p logs vm/initrd594
IMG=src/linux-7.3.4-T563/arch/x86/boot/bzImage

mkinitrd() {  # mkinitrd <tag> modes...
	local tag=$1; shift
	bash vm/make_initramfs594.sh "$ROOT/vm/build/differ594" "$@" >/dev/null || exit 1
	cp -f vm/initramfs594.cpio.gz "vm/initrd594/$tag.cpio.gz"
	printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd594/$tag.cpio.gz" | awk '{print $1}')" \
		>> logs/f72_initrd_hashes.txt
}

run() {  # run <initrd-tag> <logtag> [timeout]
	INITRD=$ROOT/vm/initrd594/$1 TIMEOUT=${3:-5400} bash vm/run_qemu.sh \
		"$ROOT/$IMG" "$ROOT/logs/f72_$2.log" > /dev/null
}

case "$MODE" in
smoke)
	mkinitrd "s$MODE2" "zc:${3:-9}"
	run "s$MODE2.cpio.gz" "smoke_$MODE2" 2400
	grep -a "F594 " "logs/f72_smoke_$MODE2.log" | head -240
	;;
full)
	mkinitrd full zc
	run full.cpio.gz rep1 7200
	run full.cpio.gz rep2 7200
	;;
mode)
	mkinitrd "m$MODE2" "$MODE2"
	run "m$MODE2.cpio.gz" "$MODE2" 2400
	grep -a "F594 " "logs/f72_$MODE2.log" | head -160
	;;
esac
echo "### DONE $MODE $MODE2"
echo "### F594 lines: $(grep -acE '^F594 ' logs/f72_${MODE2:-x}.log 2>/dev/null)"
