#!/bin/bash
# f33_battery.sh -- the counted boots of F33, six VMs in parallel.
#
# The four `bare` boots answer one question only: WHICH FAMILIES EXIST in each
# image.  That is the evidence that the four guard branches could not be put
# side by side before this turn -- not on any image the project had booted.
#
#   T = 7.3.4-T556  BRIDGE + NF_TABLES_BRIDGE + NF_TABLES_NETDEV + NF_TABLES_ARP
#   B = 7.3.4-B19   stock
#   C = 7.3.4-C553  F31's image: bridge + netdev, NO arp
#   A = 7.3.4-A553  F32's image: arp, NO bridge, NO netdev
#
# The two full boots (T_rep1, T_rep2) are the grid: 9 envelopes x 40 cells plus
# 13 E arms each, with the kernel's own counter as the oracle.  Two of them
# make determinism a measurement rather than an assumption.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p logs vm/initrd556

# --- initrds first, sequentially: make_initramfs556.sh rewrites one directory
bash vm/make_initramfs556.sh "$ROOT/vm/build/differ556" f556 >/dev/null || exit 1
cp -f vm/initramfs556.cpio.gz vm/initrd556/full.cpio.gz
bash vm/make_initramfs556.sh "$ROOT/vm/build/differ556" f556bare >/dev/null || exit 1
cp -f vm/initramfs556.cpio.gz vm/initrd556/bare.cpio.gz
sha256sum vm/initrd556/full.cpio.gz vm/initrd556/bare.cpio.gz | tee logs/f33_initrd_hashes.txt

declare -A IMG
IMG[T]=src/linux-7.3.4-T556/arch/x86/boot/bzImage
IMG[B]=src/linux-7.3.4-B19/arch/x86/boot/bzImage
IMG[C]=src/linux-7.3.4-C553/arch/x86/boot/bzImage
IMG[A]=src/linux-7.3.4-A553/arch/x86/boot/bzImage

launch() {  # launch <letter> <initrd> <logtag> <timeout>
  INITRD=$ROOT/vm/initrd556/$2 TIMEOUT=$4 \
    setsid nohup bash vm/run_qemu.sh "$ROOT/${IMG[$1]}" "$ROOT/logs/f33_$3.log" \
    > "$ROOT/logs/f33_$3.out" 2>&1 < /dev/null &
  echo "launched $3 pid $!"
}

case "${1:-all}" in
bare)
  launch B bare.cpio.gz B_bare 900
  launch A bare.cpio.gz A_bare 900
  launch C bare.cpio.gz C_bare 900
  launch T bare.cpio.gz T_bare 900
  ;;
full)
  launch T full.cpio.gz T_rep1 7200
  launch T full.cpio.gz T_rep2 7200
  ;;
esac
echo "### LAUNCHED"
