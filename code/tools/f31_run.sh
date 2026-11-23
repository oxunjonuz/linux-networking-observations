#!/bin/bash
# f31_run.sh [smoke|smokeK|kern|extra <letter> <tag>]
#
#   Q = linux-7.2.15         (DL72)     ip family only -- CONFIG_NF_TABLES_NETDEV/_BRIDGE unset
#   R = linux-7.3-R19        (7.3)      same config, the release where the guards appeared
#   B = linux-7.3.4-B19      (7.3.4)    same config
#   C = linux-7.3.4-C553     B + CONFIG_BRIDGE=y + NF_TABLES_BRIDGE=y + NF_TABLES_NETDEV=y,
#                            nothing else touched (nft_payload.c byte-identical to B19)
#   M = linux-7.2.15-C553    the same two symbols on the last release without the guards
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
mkdir -p logs vm/initrd553
declare -A IMG
IMG[Q]=src/dl72/linux-7.2.15/arch/x86/boot/bzImage
IMG[R]=src/linux-7.3-R19/arch/x86/boot/bzImage
IMG[B]=src/linux-7.3.4-B19/arch/x86/boot/bzImage
IMG[C]=src/linux-7.3.4-C553/arch/x86/boot/bzImage
IMG[M]=src/dl72/linux-7.2.15-C553/arch/x86/boot/bzImage
for k in Q R B C M; do
  [ -f "${IMG[$k]}" ] || echo "### MISSING KERNEL $k (${IMG[$k]})"
done

mkinitrd() {  # mkinitrd <tag>
  local tag=$1
  bash vm/make_initramfs553.sh "$ROOT/vm/build/differ553" f553 >/dev/null || exit 1
  cp -f vm/initramfs553.cpio.gz "vm/initrd553/$tag.cpio.gz"
  printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd553/$tag.cpio.gz" | awk '{print $1}')" \
    >> logs/f31_initrd_hashes.txt
}

run() {  # run <letter> <initrd> <logtag> [timeout]
  echo "INITRD=$ROOT/vm/initrd553/$2 TIMEOUT=${4:-2400} $ROOT/vm/run_qemu.sh $ROOT/${IMG[$1]} $ROOT/logs/f31_$3.log"
}

case "$MODE" in
smoke)
  mkinitrd f553
  run C f553.cpio.gz smoke_C 2400 | xargs -I CMD bash -c 'CMD'
  ;;
smokeK)   # f31_run.sh smokeK <letter>
  mkinitrd "x$2"
  run "$2" "x$2.cpio.gz" "smoke_$2" 2400 | xargs -I CMD bash -c 'CMD'
  ;;
kern)
  mkinitrd f553
  : > logs/f31_runlist.txt
  run C f553.cpio.gz C_rep1 2400 >> logs/f31_runlist.txt
  run C f553.cpio.gz C_rep2 2400 >> logs/f31_runlist.txt
  run B f553.cpio.gz B_rep1 2400 >> logs/f31_runlist.txt
  run R f553.cpio.gz R_rep1 2400 >> logs/f31_runlist.txt
  run Q f553.cpio.gz Q_rep1 2400 >> logs/f31_runlist.txt
  run M f553.cpio.gz M_rep1 2400 >> logs/f31_runlist.txt
  echo "### schedule: $(wc -l < logs/f31_runlist.txt) runs, 3 at a time"
  cat logs/f31_runlist.txt | xargs -P 3 -I CMD bash -c 'CMD'
  ;;
extra)
  mkinitrd "x$2"
  run "$2" "x$2.cpio.gz" "$3" 2400 | xargs -I CMD bash -c 'CMD'
  ;;
esac
echo "### DONE"
for f in logs/f31_*.log; do
  [ -f "$f" ] || continue
  printf "%-24s boot=%s F553=%s L=%s DONE=%s\n" "$(basename "$f")" \
    "$(grep -c VM_BOOT_OK "$f")" "$(grep -c '^F553 ' "$f")" \
    "$(grep -c '^F553L ' "$f")" "$(grep -c 'F553 DONE' "$f")"
done
