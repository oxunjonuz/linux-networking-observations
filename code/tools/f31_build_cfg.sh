#!/bin/bash
# f31_build_cfg.sh -- the two config-variant kernels of turn 553.
#
# Why these exist: the two guards F30 measured (nft_nh_write_ok_ip4/ip6) are two
# of FOUR cases in one switch.  The other two cases sit behind
#   #ifdef CONFIG_NF_TABLES_NETDEV      (nft_nh_write_ok_netdev)
#   #if IS_ENABLED(CONFIG_NF_TABLES_BRIDGE) (nft_nh_write_ok_bridge)
# and BOTH symbols are "not set" in every image this project has booted
# (7.2.15, 7.3, 7.3.4, P548, P549).  So the bridge/ARP branch and the netdev
# branch are not reachable in my own instrument -- the fourth kind of blindness
# after "which messages" (534), "which expressions" (535) and "which config
# symbols" (536).  This script builds the same trees with those two symbols on
# and NOTHING ELSE changed, so the version comparison (7.2.15 vs 7.3.4) and the
# config comparison (B19 vs C553) are both single-variable.
#
#   C553 = src/linux-7.3.4-C553   7.3.4-B19 + CONFIG_BRIDGE=y + NF_TABLES_BRIDGE=y
#                                 + NF_TABLES_NETDEV=y  (no other symbol touched)
#   M553 = src/linux-7.2.15-C553  the same delta on the last release before the
#                                 write-ok family existed at all
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"

build_one() {  # build_one <src-tree> <dst-tree> <jobs>
  local src=$1 dst=$2 jobs=$3
  echo "=== $dst  from $src  -j$jobs"
  rm -rf "$dst"
  cp -a "$src" "$dst" || { echo "COPY_FAIL $dst"; return 1; }
  ( cd "$dst" || exit 1
    ./scripts/config --enable BRIDGE --enable NF_TABLES_BRIDGE --enable NF_TABLES_NETDEV
    make olddefconfig > "$ROOT/logs/f31_olddef_$(basename "$dst").log" 2>&1
    echo "olddef_rc=$?"
    grep -E '^CONFIG_(BRIDGE|NF_TABLES_BRIDGE|NF_TABLES_NETDEV)=' .config
    echo "modules_in_config=$(grep -c '=m$' .config)"
    make -j"$jobs" bzImage > "$ROOT/logs/f31_build_$(basename "$dst").log" 2>&1
    echo "build_rc=$?"
    ls -la arch/x86/boot/bzImage
    sha256sum arch/x86/boot/bzImage
    diff -q "$src/net/netfilter/nft_payload.c" net/netfilter/nft_payload.c \
      && echo "GUARD_FILE_IDENTICAL_TO_$("basename" "$src")"
  )
}

case "${1:-c}" in
c) build_one src/linux-7.3.4-B19 src/linux-7.3.4-C553 10 ;;
m) build_one src/dl72/linux-7.2.15 src/dl72/linux-7.2.15-C553 10 ;;
esac
echo "### DONE $1"
