#!/bin/bash
# f32_run.sh [smoke|smokeK <letter>|kern|extra <letter> <tag>|bare <letter>]
#
#   A = src/linux-7.3.4-A553     7.3.4-B19 + CONFIG_NF_TABLES_ARP=y (only)
#   M = src/dl72/linux-7.2.15-A553 7.2.15 + the same one symbol
#   B = src/linux-7.3.4-B19      stock config: no arp family
#   Q = src/dl72/linux-7.2.15    stock config: no arp family
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
mkdir -p logs vm/initrd555
declare -A IMG
IMG[A]=src/linux-7.3.4-A553/arch/x86/boot/bzImage
IMG[M]=src/dl72/linux-7.2.15-A553/arch/x86/boot/bzImage
IMG[B]=src/linux-7.3.4-B19/arch/x86/boot/bzImage
IMG[Q]=src/dl72/linux-7.2.15/arch/x86/boot/bzImage
for k in A M B Q; do
  [ -f "${IMG[$k]}" ] || echo "### MISSING KERNEL $k (${IMG[$k]})"
done

mkinitrd() {  # mkinitrd <tag> [mode]
  local tag=$1 m=${2:-f555}
  bash vm/make_initramfs555.sh "$ROOT/vm/build/differ555" "$m" >/dev/null || exit 1
  cp -f vm/initramfs555.cpio.gz "vm/initrd555/$tag.cpio.gz"
  printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd555/$tag.cpio.gz" | awk '{print $1}')" \
    >> logs/f32_initrd_hashes.txt
}

run() {  # run <letter> <initrd> <logtag> [timeout]
  echo "INITRD=$ROOT/vm/initrd555/$2 TIMEOUT=${4:-2400} $ROOT/vm/run_qemu.sh $ROOT/${IMG[$1]} $ROOT/logs/f32_$3.log"
}

case "$MODE" in
smoke)
  mkinitrd f555
  run A f555.cpio.gz smoke_A 2400 | xargs -I CMD bash -c 'CMD'
  ;;
smokeK)   # f32_run.sh smokeK <letter>
  mkinitrd "x$2"
  run "$2" "x$2.cpio.gz" "smoke_$2" 2400 | xargs -I CMD bash -c 'CMD'
  ;;
bare)     # f32_run.sh bare <letter>
  mkinitrd "bare$2" f555bare
  run "$2" "bare$2.cpio.gz" "${2}_bare" 900 | xargs -I CMD bash -c 'CMD'
  ;;
kern)
  mkinitrd f555
  : > logs/f32_runlist.txt
  run A f555.cpio.gz A_rep1 2400 >> logs/f32_runlist.txt
  run A f555.cpio.gz A_rep2 2400 >> logs/f32_runlist.txt
  run M f555.cpio.gz M_rep1 2400 >> logs/f32_runlist.txt
  echo "### schedule: $(wc -l < logs/f32_runlist.txt) runs, 3 at a time"
  cat logs/f32_runlist.txt | xargs -P 3 -I CMD bash -c 'CMD'
  ;;
extra)
  mkinitrd "x$2"
  run "$2" "x$2.cpio.gz" "$3" 2400 | xargs -I CMD bash -c 'CMD'
  ;;
esac
echo "### DONE"
for f in logs/f32_*.log; do
  [ -f "$f" ] || continue
  printf "%-24s boot=%s A=%s F=%s DONE=%s\n" "$(basename "$f")" \
    "$(grep -c VM_BOOT_OK "$f")" "$(grep -c '^F555 A|' "$f")" \
    "$(grep -c '^F555 F|' "$f")" "$(grep -c 'F555 DONE' "$f")"
done
