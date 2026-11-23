#!/bin/bash
# f41_build_cfg.sh -- T563 = T558 + PPP + PPPOE.
#
# Why: F40 left one line honest -- `meta protocol` has a SECOND carrier of
# pkt->nhoff:
#
#     case htons(ETH_P_PPP_SES):
#             if (!nf_flow_pppoe_proto(skb, &ethertype))
#                     return;
#             nhoff = PPPOE_SES_HLEN;          /* 8, not 6 as F40 wrote */
#             break;
#
# and the symbol is absent from every image this project has booted
# (`# CONFIG_PPP is not set` in T558).  Without CONFIG_PPPOE two things are
# missing: the PPPoE stack that can accept a session frame at all, and a
# session socket to be the receiving side's oracle.  The nft code path itself
# is in nft_meta.c and does not depend on the symbol -- but the *consequence*
# does, and a measurement of the shift alone would leave the receiving side as
# code reading.
#
# Everything that decides the behaviour must stay byte-identical to T558:
# net/netfilter/nft_payload.c, net/netfilter/nft_meta.c,
# net/netfilter/nf_tables_core.c, net/netfilter/nft_chain_filter.c,
# net/ipv4/arp.c, net/core/dev.c.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
SRC=src/linux-7.3.4-T558
DST=src/linux-7.3.4-T563
JOBS=${1:-16}

echo "=== build $DST from $SRC -j$JOBS  $(date -u +%FT%TZ)"
rm -rf "$DST"
cp -a "$SRC" "$DST" || { echo "COPY_FAIL"; exit 1; }
(
	cd "$DST" || exit 1
	./scripts/config --enable PPP --enable PPPOE
	make olddefconfig > "$ROOT/logs/f41_olddef_T563.log" 2>&1
	echo "olddef_rc=$?"
	grep -E '^CONFIG_(PPP|PPPOE|PPPOX|SLHC|PPPOE_HASH_BITS_[0-9])' .config
	echo "--- config delta against T558:"
	diff <(grep -E '^(CONFIG_|# CONFIG_)' "$ROOT/$SRC/.config") \
	     <(grep -E '^(CONFIG_|# CONFIG_)' .config) | tee "$ROOT/logs/f41_cfg_delta_T563.txt"
	echo "delta_lines=$(grep -cE '^[<>]' "$ROOT/logs/f41_cfg_delta_T563.txt")"
	echo "modules_in_config=$(grep -c '=m$' .config)"
	make -j"$JOBS" bzImage > "$ROOT/logs/f41_build_T563.log" 2>&1
	echo "build_rc=$?"
	ls -la arch/x86/boot/bzImage
	sha256sum arch/x86/boot/bzImage
	for f in net/netfilter/nft_payload.c net/netfilter/nft_meta.c \
	         net/netfilter/nf_tables_core.c net/netfilter/nft_chain_filter.c \
	         net/ipv4/arp.c net/core/dev.c net/8021q/vlan_core.c \
	         drivers/net/ppp/pppoe.c include/net/netfilter/nf_flow_table.h; do
		if cmp -s "$ROOT/$SRC/$f" "$f"; then echo "IDENTICAL $f"; else echo "DIFFERS $f"; fi
	done
)
echo "### DONE $(date -u +%FT%TZ)"
