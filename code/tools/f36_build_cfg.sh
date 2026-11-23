#!/bin/bash
# f36_build_cfg.sh -- the second config-variant kernel: T558 = T557 + 802.1Q.
#
# Why: F35 measured the ll guard through seven envelopes and left one line
# honest: in the ip family a tagged frame never reaches IPv4 on any image this
# project has booted, and the reason is a config line, not the guard.
#
#     # CONFIG_VLAN_8021Q is not set
#
# Without it `vlan_do_receive()` is the stub that returns false, so a frame with
# a non-zero VLAN id is marked PACKET_OTHERHOST in __netif_receive_skb_core()
# and ip_rcv() drops it before the prerouting hook -- and no VLAN device can be
# created at all, so the only envelope in which the ip family meets a tag
# cannot exist.
#
# T558 is T557 plus exactly that symbol (plus whatever it selects).  The guard's
# file and the receive path must stay byte-identical to the parent: what is
# measured is the same code, not a patch.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
SRC=src/linux-7.3.4-T557
DST=src/linux-7.3.4-T558
JOBS=${1:-14}

echo "=== build $DST from $SRC -j$JOBS  $(date -u +%FT%TZ)"
rm -rf "$DST"
cp -a "$SRC" "$DST" || { echo "COPY_FAIL"; exit 1; }
(
	cd "$DST" || exit 1
	./scripts/config --enable VLAN_8021Q
	make olddefconfig > "$ROOT/logs/f36_olddef_T558.log" 2>&1
	echo "olddef_rc=$?"
	grep -E '^CONFIG_(VLAN_8021Q|VLAN_8021Q_GVRP|NET_IPIP|VXLAN|NF_TABLES_BRIDGE|NF_TABLES_ARP|NF_TABLES_NETDEV)=' .config
	echo "--- config delta against T557:"
	diff <(grep -E '^(CONFIG_|# CONFIG_)' "$ROOT/$SRC/.config") \
	     <(grep -E '^(CONFIG_|# CONFIG_)' .config) | tee "$ROOT/logs/f36_cfg_delta_T558.txt"
	echo "delta_lines=$(grep -cE '^[<>]' "$ROOT/logs/f36_cfg_delta_T558.txt")"
	echo "modules_in_config=$(grep -c '=m$' .config)"
	make -j"$JOBS" bzImage > "$ROOT/logs/f36_build_T558.log" 2>&1
	echo "build_rc=$?"
	ls -la arch/x86/boot/bzImage
	sha256sum arch/x86/boot/bzImage
	for f in net/netfilter/nft_payload.c net/netfilter/nft_chain_filter.c \
	         net/netfilter/nf_tables_api.c net/8021q/vlan_core.c \
	         net/core/skbuff.c net/ethernet/eth.c net/ipv4/ip_input.c; do
		if cmp -s "$ROOT/$SRC/$f" "$f"; then echo "IDENTICAL $f"; else echo "DIFFERS $f"; fi
	done
)
echo "### DONE $(date -u +%FT%TZ)"
