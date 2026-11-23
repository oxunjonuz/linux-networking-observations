#!/bin/bash
# f70_two.sh -- build the F70 initramfs once, boot the same image twice.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
IMG=$ROOT/src/linux-7.3.4-T563/arch/x86/boot/bzImage
bash vm/make_initramfs592.sh "$ROOT/vm/build/differ592" cond >/dev/null || exit 1
cp -f vm/initramfs592.cpio.gz vm/initrd592/cond.cpio.gz
printf "cond %s\n" "$(sha256sum vm/initrd592/cond.cpio.gz | awk '{print $1}')" \
	>> logs/f70_initrd_hashes.txt
for rep in rep1 rep2; do
	INITRD=$ROOT/vm/initrd592/cond.cpio.gz TIMEOUT=1800 \
		bash vm/run_qemu.sh "$IMG" "$ROOT/logs/f70_$rep.log" > /dev/null
done
echo "### both done"
