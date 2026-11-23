#!/bin/bash
# build_f35_differ.sh -- assemble and compile the turn-557 instrument.
#
# differ557.c is GENERATED: differ556.c (the F33 instrument: netlink toolkit,
# veth/rtnetlink, NFLOG reader, AF_PACKET capture, counter read-back, and the
# whole F33 envelope code) with its main() renamed, plus vm/differ557_add.c
# (this turn's envelopes: VLAN frames, real ipip and vxlan decapsulation, the
# meta-iif gate, and the fast netlink path).  Every helper under the new code
# is byte-for-byte the one that produced F30..F33.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f556_main(int argc, char **argv)/' \
	vm/differ556.c > vm/differ557.c
grep -q '^int f556_main' vm/differ557.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ557_add.c >> vm/differ557.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ557 vm/differ557.c \
	2> logs/f35_gcc.log || { echo "GCC_FAIL"; tail -30 logs/f35_gcc.log; exit 1; }
echo "gcc_warnings=$(wc -l < logs/f35_gcc.log)"
cat logs/f35_gcc.log
ls -la vm/build/differ557
sha256sum vm/build/differ557 vm/differ557.c
