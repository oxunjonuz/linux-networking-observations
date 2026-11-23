#!/bin/bash
# f33_run.sh [smoke|smokeOnly <env>|kern|bare <letter>|e]
#
#   T = src/linux-7.3.4-T556   B19 + BRIDGE + NF_TABLES_BRIDGE + NF_TABLES_NETDEV
#                              + NF_TABLES_ARP   <-- all four guard branches live
#   B = src/linux-7.3.4-B19    stock 7.3.4: no netdev, no bridge, no arp family
#   C = src/linux-7.3.4-C553   bridge + netdev, NO arp family   (F31 image)
#   A = src/linux-7.3.4-A553   arp family, NO bridge, NO netdev (F32 image)
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
MODE=${1:-smoke}
mkdir -p logs vm/initrd556
declare -A IMG
IMG[T]=src/linux-7.3.4-T556/arch/x86/boot/bzImage
IMG[B]=src/linux-7.3.4-B19/arch/x86/boot/bzImage
IMG[C]=src/linux-7.3.4-C553/arch/x86/boot/bzImage
IMG[A]=src/linux-7.3.4-A553/arch/x86/boot/bzImage
for k in T B C A; do
  [ -f "${IMG[$k]}" ] || echo "### MISSING KERNEL $k (${IMG[$k]})"
done

mkinitrd() {  # mkinitrd <tag> [mode...]
  local tag=$1; shift
  local m=${*:-f556}
  bash vm/make_initramfs556.sh "$ROOT/vm/build/differ556" $m >/dev/null || exit 1
  cp -f vm/initramfs556.cpio.gz "vm/initrd556/$tag.cpio.gz"
  printf "%s %s\n" "$tag" "$(sha256sum "vm/initrd556/$tag.cpio.gz" | awk '{print $1}')" \
    >> logs/f33_initrd_hashes.txt
}

run() {  # run <letter> <initrd> <logtag> [timeout]
  echo "INITRD=$ROOT/vm/initrd556/$2 TIMEOUT=${4:-2400} $ROOT/vm/run_qemu.sh $ROOT/${IMG[$1]} $ROOT/logs/f33_$3.log"
}

case "$MODE" in
smoke)
  mkinitrd f556
  run T f556.cpio.gz smoke_T 2400 | xargs -I CMD bash -c 'CMD'
  ;;
smokeOnly)	# f33_run.sh smokeOnly <env> [kernel-letter]
  mkinitrd "o$2"
  run "${3:-T}" "o$2.cpio.gz" "smoke_$2" 2400 | xargs -I CMD bash -c 'CMD'
  ;;
bare)		# f33_run.sh bare <letter>  -- families only, ~60 s
  mkinitrd "bare$2" f556bare
  run "$2" "bare$2.cpio.gz" "${2}_bare" 900 | xargs -I CMD bash -c 'CMD'
  ;;
e)		# f33_run.sh e -- ip4 grid + the E arms only
  mkinitrd f556e f556e
  run T f556e.cpio.gz smoke_e 2400 | xargs -I CMD bash -c 'CMD'
  ;;
kern)
  mkinitrd f556
  : > logs/f33_runlist.txt
  run T f556.cpio.gz T_rep1 3600 >> logs/f33_runlist.txt
  run T f556.cpio.gz T_rep2 3600 >> logs/f33_runlist.txt
  ;;
esac
echo "### DONE $MODE"
