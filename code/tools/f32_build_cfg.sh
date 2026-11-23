#!/bin/bash
# f32_build_cfg.sh -- the two config-variant kernels of turn 555 (F32).
#
# Why these exist: F31 measured the ARP branch of nft_nh_write_ok() only from
# the BRIDGE family (a frame labelled 0x0806).  The native envelope -- the nft
# `arp` family, i.e. `case NFPROTO_ARP: return nft_nh_write_ok_arp(priv)` -- has
# never been reachable in this project, because CONFIG_NF_TABLES_ARP is
# "not set" in every config we have booted (7.2.15, 7.3, 7.3.4, P548, P549,
# and even the F31 config kernel C553).  Without the symbol `nft add table arp`
# fails before a single rule can be installed.
#
# So: same trees, one symbol on, nothing else touched (single variable).
#
#   A553  = src/linux-7.3.4-B19   + CONFIG_NF_TABLES_ARP=y
#   AM553 = src/dl72/linux-7.2.15 + CONFIG_NF_TABLES_ARP=y
#
# NF_TABLES_ARP lives in net/ipv4/netfilter/Kconfig (inside `if NF_TABLES`),
# selects NETFILTER_FAMILY_ARP and unlocks nft_chain_filter_arp in
# net/netfilter/nft_chain_filter.c (hook_mask = NF_ARP_IN | NF_ARP_OUT only).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"

build_one() {  # build_one <src-tree> <dst-tree> <jobs>
  local src=$1 dst=$2 jobs=$3
  echo "=== $dst  from $src  -j$jobs"
  rm -rf "$dst"
  cp -a "$src" "$dst" || { echo "COPY_FAIL $dst"; return 1; }
  ( cd "$dst" || exit 1
    ./scripts/config --enable NF_TABLES_ARP
    make olddefconfig > "$ROOT/logs/f32_olddef_$(basename "$dst").log" 2>&1
    echo "olddef_rc=$?"
    grep -E '^CONFIG_(NF_TABLES_ARP|NETFILTER_FAMILY_ARP|IPV4|INET)=' .config
    echo "modules_in_config=$(grep -c '=m$' .config)"
    make -j"$jobs" bzImage > "$ROOT/logs/f32_build_$(basename "$dst").log" 2>&1
    echo "build_rc=$?"
    ls -la arch/x86/boot/bzImage
    sha256sum arch/x86/boot/bzImage
    diff -q "$src/net/netfilter/nft_payload.c" net/netfilter/nft_payload.c \
      && echo "GUARD_FILE_IDENTICAL_TO_$(basename "$src")"
    diff -q "$src/net/netfilter/nft_chain_filter.c" net/netfilter/nft_chain_filter.c \
      && echo "CHAIN_FILTER_FILE_IDENTICAL_TO_$(basename "$src")"
  )
}

case "${1:-a}" in
a) build_one src/linux-7.3.4-B19 src/linux-7.3.4-A553 10 ;;
m) build_one src/dl72/linux-7.2.15 src/dl72/linux-7.2.15-A553 10 ;;
esac
echo "### DONE $1"
