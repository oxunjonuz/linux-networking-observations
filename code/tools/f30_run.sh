#!/bin/bash
# f30_run.sh [smoke|kern|extra]
#
#   Q = linux-7.2.15        nft_nh_write_ok present (19), nft_th_write_ok absent
#   R = linux-7.3-R19       the release where the transport guard appeared
#   B = linux-7.3.4-B19     the last release
#   G = linux-7.3.4-P549    B + the guard refinement F27 proposed
#   P = linux-7.3.4-P548    B + the parity fix F26 proposed
#
# F30 asks what the *network* guard (nft_nh_write_ok) and the *link* guard
# (nft_ll_write_ok) actually allow, on both families, with the frame and the
# rule counter as the only answers.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
mkdir -p logs vm/initrd552
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
  bash vm/make_initramfs552.sh "$ROOT/vm/build/differ552" f552 >/dev/null || exit 1
  cp -f vm/initramfs552.cpio.gz "vm/initrd552/$tag.cpio.gz"
  printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd552/$tag.cpio.gz" | awk '{print $1}')" \
    >> logs/f30_initrd_hashes.txt
}

run() {  # run <kernel-letter> <initrd> <logtag> [timeout]
  echo "INITRD=$ROOT/vm/initrd552/$2 TIMEOUT=${4:-2400} $ROOT/vm/run_qemu.sh $ROOT/${IMG[$1]} $ROOT/logs/f30_$3.log"
}

case "$MODE" in
smoke)
  mkinitrd f552
  run B f552.cpio.gz smoke_B 2400 | xargs -I CMD bash -c 'CMD'
  ;;
kern)
  mkinitrd f552
  : > logs/f30_runlist.txt
  run B f552.cpio.gz B_rep1 2400 >> logs/f30_runlist.txt
  run B f552.cpio.gz B_rep2 2400 >> logs/f30_runlist.txt
  run Q f552.cpio.gz Q_rep1 2400 >> logs/f30_runlist.txt
  run G f552.cpio.gz G_rep1 2400 >> logs/f30_runlist.txt
  run P f552.cpio.gz P_rep1 2400 >> logs/f30_runlist.txt
  run R f552.cpio.gz R_rep1 2400 >> logs/f30_runlist.txt
  echo "### schedule: $(wc -l < logs/f30_runlist.txt) runs, 3 at a time"
  cat logs/f30_runlist.txt | xargs -P 3 -I CMD bash -c 'CMD'
  ;;
extra)
  # one extra boot of a single kernel: f30_run.sh extra <letter> <tag>
  mkinitrd "x$2"
  run "$2" "x$2.cpio.gz" "$3" 2400 | xargs -I CMD bash -c 'CMD'
  ;;
esac
echo "### DONE"
for f in logs/f30_*.log; do
  printf "%-24s boot=%s F552=%s DONE=%s\n" "$(basename "$f")" \
    "$(grep -c VM_BOOT_OK "$f")" "$(grep -c '^F552 ' "$f")" "$(grep -c 'F552 DONE' "$f")"
done
