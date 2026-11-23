#!/bin/bash
# f29_run.sh [smoke|kern|extra]
#
#   Q = linux-7.2.15        no nft_th_write_ok() at all
#   R = linux-7.3-R19       the release where the guard appeared
#   B = linux-7.3.4-B19     the last release
#   G = linux-7.3.4-P549    B + the guard refinement F27 proposed
#   P = linux-7.3.4-P548    B + the parity fix F26 proposed
#
# F29 asks whether the byte the guard protects outside is reachable inside a
# tunnel frame: the same byte, same boot, through @th (transport base) and
# @ih (inner base).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
mkdir -p logs vm/initrd551
declare -A IMG
IMG[Q]=src/dl72/linux-7.2.15/arch/x86/boot/bzImage
IMG[R]=src/linux-7.3-R19/arch/x86/boot/bzImage
IMG[B]=src/linux-7.3.4-B19/arch/x86/boot/bzImage
IMG[G]=src/linux-7.3.4-P549/arch/x86/boot/bzImage
IMG[P]=src/linux-7.3.4-P548/arch/x86/boot/bzImage
for k in Q R B G P; do
  [ -f "${IMG[$k]}" ] || echo "### MISSING KERNEL $k (${IMG[$k]})"
done

mkinitrd() {  # mkinitrd <tag>
  local tag=$1
  bash vm/make_initramfs551.sh "$ROOT/vm/build/differ551" f551 >/dev/null || exit 1
  cp -f vm/initramfs551.cpio.gz "vm/initrd551/$tag.cpio.gz"
  printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd551/$tag.cpio.gz" | awk '{print $1}')" \
    >> logs/f29_initrd_hashes.txt
}

run() {  # run <kernel-letter> <initrd> <logtag> [timeout]
  echo "INITRD=$ROOT/vm/initrd551/$2 TIMEOUT=${4:-1800} $ROOT/vm/run_qemu.sh $ROOT/${IMG[$1]} $ROOT/logs/f29_$3.log"
}

case "$MODE" in
smoke)
  mkinitrd f551
  run B f551.cpio.gz smoke_B 1800 | xargs -I CMD bash -c 'CMD'
  ;;
kern)
  mkinitrd f551
  : > logs/f29_runlist.txt
  run B f551.cpio.gz B_rep1 1800 >> logs/f29_runlist.txt
  run B f551.cpio.gz B_rep2 1800 >> logs/f29_runlist.txt
  run Q f551.cpio.gz Q_rep1 1800 >> logs/f29_runlist.txt
  run G f551.cpio.gz G_rep1 1800 >> logs/f29_runlist.txt
  run P f551.cpio.gz P_rep1 1800 >> logs/f29_runlist.txt
  run R f551.cpio.gz R_rep1 1800 >> logs/f29_runlist.txt
  echo "### schedule: $(wc -l < logs/f29_runlist.txt) runs, 3 at a time"
  cat logs/f29_runlist.txt | xargs -P 3 -I CMD bash -c 'CMD'
  ;;
extra)
  # one extra boot of a single kernel: f29_run.sh extra <letter> <tag>
  mkinitrd "x$2"
  run "$2" "x$2.cpio.gz" "$3" 1800 | xargs -I CMD bash -c 'CMD'
  ;;
esac
echo "### DONE"
for f in logs/f29_*.log; do
  printf "%-24s boot=%s F551=%s DONE=%s\n" "$(basename "$f")" \
    "$(grep -c VM_BOOT_OK "$f")" "$(grep -c '^F551 ' "$f")" "$(grep -c 'F551 DONE' "$f")"
done
