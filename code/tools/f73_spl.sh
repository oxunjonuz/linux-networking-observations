#!/bin/bash
# the diagnostic boot: differ595b (one probe moved to __ip_append_data), mode
# spl only -- four arms, s512/s5000 against their zerocopy twins.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
bash vm/make_initramfs595.sh "$ROOT/vm/build/differ595b" spl >/dev/null || exit 1
cp -f vm/initramfs595.cpio.gz vm/initrd595/spl.cpio.gz
printf "spl %s\n" "$(sha256sum vm/initrd595/spl.cpio.gz | awk '{print $1}')" >> logs/f73_initrd_hashes.txt
INITRD=$ROOT/vm/initrd595/spl.cpio.gz TIMEOUT=2400 bash vm/run_qemu.sh \
	"$ROOT/src/linux-7.3.4-T563/arch/x86/boot/bzImage" "$ROOT/logs/f73_spl.log" >/dev/null
grep -a "F595 " logs/f73_spl.log | head -200
