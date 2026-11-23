#!/bin/bash
# f35_build_cfg.sh -- the config-variant kernel of turn 557.
#
# Why: F33 measured the shape of nft_ll_write_ok() on ethernet frames, where
# the guard's boundary (skb_network_header - skb_mac_header) is 14.  The
# question of this turn is whether that number is a property of the WRITE or
# of the ENVELOPE: an 802.1Q frame whose tag was pulled into skb metadata, and
# a packet that came out of a tunnel, are the two envelopes in which the
# network offset is not 14.
#
# A tunnel needs a decapsulating device, and the stock 7.3.4-B19 config has
#     # CONFIG_NET_IPIP is not set
#     # CONFIG_VXLAN is not set
# so no image this project has booted can decapsulate anything.  T557 is
# T556 (all four nft_nh_write_ok() branches live) plus exactly the tunnel
# symbols.  nft_payload.c and the rest of the guard's file must stay
# byte-identical to the parent: what is measured is the same code, not a
# patch -- the envelope changes, the code does not.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
SRC=src/linux-7.3.4-T556
DST=src/linux-7.3.4-T557
JOBS=${1:-14}

echo "=== build $DST from $SRC -j$JOBS  $(date -u +%FT%TZ)"
rm -rf "$DST"
cp -a "$SRC" "$DST" || { echo "COPY_FAIL"; exit 1; }
(
	cd "$DST" || exit 1
	./scripts/config --enable NET_IPIP --enable VXLAN --enable NET_UDP_TUNNEL
	make olddefconfig > "$ROOT/logs/f35_olddef_T557.log" 2>&1
	echo "olddef_rc=$?"
	grep -E '^CONFIG_(NET_IPIP|VXLAN|NET_UDP_TUNNEL|INET_TUNNEL|BRIDGE|NF_TABLES_BRIDGE|NF_TABLES_NETDEV|NF_TABLES_ARP)=' .config
	echo "modules_in_config=$(grep -c '=m$' .config)"
	make -j"$JOBS" bzImage > "$ROOT/logs/f35_build_T557.log" 2>&1
	echo "build_rc=$?"
	ls -la arch/x86/boot/bzImage
	sha256sum arch/x86/boot/bzImage
	for f in net/netfilter/nft_payload.c net/netfilter/nft_chain_filter.c \
	         net/netfilter/nf_tables_api.c net/ipv4/arp.c net/ipv4/ipip.c \
	         drivers/net/vxlan/vxlan_core.c; do
		if cmp -s "$ROOT/$SRC/$f" "$f"; then echo "IDENTICAL $f"; else echo "DIFFERS $f"; fi
	done
)
echo "### DONE $(date -u +%FT%TZ)"
