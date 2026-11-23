#!/bin/bash
# f34_run.sh [smoke|F|P|all|<arm>]
#
#   F = vm/bzImage-6.6.13-fixed    6.6.13 + f342de4e2f33 (the first fix, the
#                                  kernel F2 was measured on)
#   P = src/linux-6.6.162/arch/x86/boot/bzImage   the released kernel that
#                                  carries da107398cbd4 (backport 4b12a3cc3f07)
#
# One arm per boot; the arm travels on the kernel command line (arm=C|Q|D|X).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
declare -A IMG
IMG[F]=vm/bzImage-6.6.13-fixed
IMG[P]=src/linux-6.6.162/arch/x86/boot/bzImage
INITRD=$ROOT/vm/initramfs_f34.cpio.gz
for k in F P; do
	[ -f "${IMG[$k]}" ] || echo "### MISSING KERNEL $k (${IMG[$k]})"
done
run() {  # run <letter> <arm> <rep>
	local k=$1 arm=$2 rep=$3 tag="$1_$2_$3"
	echo "### RUN $tag"
	INITRD=$INITRD TIMEOUT=600 bash vm/run_qemu.sh "$ROOT/${IMG[$k]}" \
		"$ROOT/logs/f34_$tag.log" "arm=$arm" > /dev/null
	grep -hE "F34 UDP|netlink errors|RESULT:|ARM .*_EXIT" \
		"$ROOT/logs/f34_$tag.log" | sed "s/^/  [$tag] /"
}
case "$MODE" in
smoke)	run F C smoke ;;
C|Q|D|X) run F "$MODE" rep1 ;;
F)	run F C rep1; run F C rep2; run F Q rep1; run F Q rep2; run F D rep1; run F X rep1 ;;
P)	run P C rep1; run P Q rep1; run P Q rep2; run P D rep1; run P X rep1 ;;
all)	run F C rep1; run F C rep2; run F Q rep1; run F Q rep2; run F D rep1; run F X rep1
	run P C rep1; run P Q rep1; run P Q rep2; run P D rep1; run P X rep1 ;;
esac
echo "### DONE $MODE"
