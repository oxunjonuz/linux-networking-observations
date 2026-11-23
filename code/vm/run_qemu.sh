#!/bin/bash
# run_qemu.sh <bzImage> <console-log> [extra kernel cmdline]
# Boots a disposable VM under QEMU (TCG; this host has no /dev/kvm).
# The host kernel is never used for experiments: the guest runs its own bzImage.
set -uo pipefail
BZ=${1:?usage: run_qemu.sh <bzImage> <log> [extra-cmdline]}
LOG=${2:?usage: run_qemu.sh <bzImage> <log> [extra-cmdline]}
EXTRA=${3:-}
HERE=$(cd "$(dirname "$0")" && pwd)
INITRD=${INITRD:-$HERE/initramfs.cpio.gz}
TIMEOUT=${TIMEOUT:-1200}

{
  echo "### run_qemu.sh $(date -u +%FT%TZ)"
  echo "### kernel: $BZ"
  echo "### sha256: $(sha256sum "$BZ" | awk '{print $1}')"
  echo "### initrd: $INITRD"
  echo "### initrd sha256: $(sha256sum "$INITRD" | awk '{print $1}')"
  echo "### cmdline extra: $EXTRA"
} | tee "$LOG"

timeout -k 20 "$TIMEOUT" qemu-system-x86_64 \
  -machine pc -accel tcg,thread=multi -cpu max -smp 2 -m 3072 \
  -kernel "$BZ" -initrd "$INITRD" \
  -append "console=ttyS0,115200 rdinit=/init panic=-1 nokaslr loglevel=7 $EXTRA" \
  -nographic -monitor none -no-reboot -serial stdio \
  < /dev/null >> "$LOG" 2>&1
RC=$?
{
  echo "### qemu exit=$RC"
  echo "### markers:"
  grep -c "VM_BOOT_OK" "$LOG" | sed 's/^/###   VM_BOOT_OK: /'
  grep -E "=== REPRO_EXIT=" "$LOG" || echo "###   no REPRO_EXIT marker"
  grep -E "KASAN|BUG:|WARNING:|Oops|general protection|double free|use-after-free" "$LOG" | head -20
} | tee -a "$LOG"
exit $RC
