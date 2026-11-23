#!/bin/bash
# restore_tree.sh <target-dir>
#
# Unpacks dev-report/code/ into <target-dir> as the tree the run scripts expect:
#   <target>/vm/     instruments (full sources gunzipped), their additions, build
#                    scripts, initramfs builders, run_qemu.sh
#   <target>/tools/  per-finding runners, verifiers, selftests
# The scripts carry an absolute ROOT; it is rewritten to <target-dir> here, so
# nothing points back at the machine the report was written on except the two
# optional paths printed at the end (busybox and the static nft binary).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TARGET=${1:?usage: restore_tree.sh <target-dir>}
mkdir -p "$TARGET/vm" "$TARGET/tools"
cd "$HERE"
for f in full/*.c.gz; do
	b=${f##*/}
	out="$TARGET/vm/${b%.gz}"
	gunzip -c "$f" > "$out"
done
for sub in vm tools; do
	for f in "$sub"/*; do
		[ -e "$f" ] || continue
		cp "$f" "$TARGET/$sub/"
	done
done
# rewrite the hard-coded root of the runner/build/verify scripts
grep -rl 'ROOT=/work/kernel-sec' "$TARGET" | while read -r f; do
	sed -i "s|ROOT=/work/kernel-sec|ROOT=$TARGET|g" "$f"
done
chmod +x "$TARGET"/vm/*.sh "$TARGET"/tools/*.sh 2>/dev/null || true
echo "restored $(ls "$TARGET/vm" | wc -l) files into $TARGET/vm and $(ls "$TARGET/tools" | wc -l) into $TARGET/tools"
echo
echo "two paths the initramfs builders expect, edit them in vm/make_initramfs*.sh if yours differ:"
echo "  /usr/bin/busybox                    (a statically linked busybox)"
echo "  <tree>/src/dl23/nftables-1.1.7/src/nft.static   (nftables 1.1.7, static)"
echo
echo "check integrity of what was unpacked with:  sha256sum -c $HERE/MANIFEST.sha256"
