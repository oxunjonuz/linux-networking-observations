#!/bin/bash
# f33_build_cfg.sh -- the single config-variant kernel of turn 556.
#
# Why this exists: the four branches of nft_nh_write_ok() have so far been
# measured on three DIFFERENT images, one branch group per image:
#
#   nft_nh_write_ok_ip4/ip6   stock 7.3.4-B19            (F30)
#   nft_nh_write_ok_bridge    src/linux-7.3.4-C553       (F31: BRIDGE+NETDEV)
#   nft_nh_write_ok_netdev    src/linux-7.3.4-C553       (F31, dead code)
#   nft_nh_write_ok_arp       src/linux-7.3.4-A553       (F32: ARP)
#
# F33 asks a different question -- not "does branch X guard byte Y", but "what
# KIND of function is each branch" -- and that question needs the branches
# side by side in ONE boot, because the answer is the SHAPE of each accept-set
# on one identical grid.  Comparing shapes measured in different boots on
# different images is exactly the move this project keeps refusing to make.
#
# T556 = src/linux-7.3.4-B19 + 4 symbols, nothing else:
#   CONFIG_BRIDGE=y  CONFIG_NF_TABLES_BRIDGE=y  CONFIG_NF_TABLES_NETDEV=y
#   CONFIG_NF_TABLES_ARP=y
# Their selects (NETFILTER_FAMILY_BRIDGE, NETFILTER_FAMILY_ARP) are recorded in
# the log and verified by verify556.py; nft_payload.c must be byte-identical to
# the parent, so everything measured is the same code, not a patch.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
SRC=src/linux-7.3.4-B19
DST=src/linux-7.3.4-T556
JOBS=${2:-14}

echo "=== build $DST from $SRC -j$JOBS  $(date -u +%FT%TZ)"
rm -rf "$DST"
cp -a "$SRC" "$DST" || { echo "COPY_FAIL"; exit 1; }
(
  cd "$DST" || exit 1
  ./scripts/config --enable BRIDGE --enable NF_TABLES_BRIDGE \
                   --enable NF_TABLES_NETDEV --enable NF_TABLES_ARP
  make olddefconfig > "$ROOT/logs/f33_olddef_T556.log" 2>&1
  echo "olddef_rc=$?"
  grep -E '^CONFIG_(BRIDGE|NF_TABLES_BRIDGE|NF_TABLES_NETDEV|NF_TABLES_ARP|NETFILTER_FAMILY_BRIDGE|NETFILTER_FAMILY_ARP)=' .config
  echo "modules_in_config=$(grep -c '=m$' .config)"
  make -j"$JOBS" bzImage > "$ROOT/logs/f33_build_T556.log" 2>&1
  echo "build_rc=$?"
  ls -la arch/x86/boot/bzImage
  sha256sum arch/x86/boot/bzImage
  for f in net/netfilter/nft_payload.c net/netfilter/nft_chain_filter.c \
           net/netfilter/nf_tables_api.c net/ipv4/arp.c; do
    if cmp -s "$ROOT/$SRC/$f" "$f"; then echo "IDENTICAL $f"; else echo "DIFFERS $f"; fi
  done
)
echo "### DONE $(date -u +%FT%TZ)"
