# nftables payload writes: guards, envelopes and coordinates

Measurements of the nftables payload store, F29-F61.  Every finding states what
was measured, on which kernel, with which instrument and under which limit; the
instrument that produced the numbers is in `code/` and `HOW_TO_RUN.md` maps each
finding to its modes, runner and log marker.

Each finding is written in six parts:

* **Claim** -- the result in one paragraph.
* **Minimal reproduction** -- the smallest arm that shows it.
* **Run** -- the command that produces the log and the marker to grep.
* **Expected** -- what the kernel source says should happen.
* **Actual** -- what was measured.
* **Limitations** -- what the measurement does not cover.

The reproducing code is the instrument named in **Minimal reproduction**: its
source is in `code/`, the arm named there is the arm it runs, and the exact rule,
byte and counter are printed under **Details**.

The full evidence (tables, byte values, counters) follows under **Details**.

Scope: every rule was installed by root in the initial user namespace.  Nothing
here crosses a privilege boundary and nothing here is a memory-safety claim.
`BUGS_AND_TESTS.md` separates the findings that are potential defects
(observations only) from behaviour that Linux is designed to have, and lists the
invariant each finding would pin as a regression test.


## Index

| finding | subject | instrument | modes | runner |
|---|---|---|---|---|
| F29 | the inner-base store has no guard: the same TCP data-offset byte moves through a tunnel on all five measured kernels | `code/vm/differ551_add.c` | — | `code/tools/f29_run.sh` |
| F30 | the network-header guard is an offset whitelist: `ip6 ecn set` and `ip6 flowlabel set` are silently dead while their IPv4 twins work | `code/vm/differ552_add.c` | — | `code/tools/f30_run.sh` |
| F31 | the store guard switches on the envelope, not on the write | `code/full/differ553.c.gz` | — | `code/tools/f31_run.sh` |
| F32 | the arp family: four declared fields are silently dead, and the output hook adds a 28-byte bound | `code/full/differ555.c.gz` | — | `code/tools/f32_run.sh` |
| F33 | one guard, four types: what each branch of `nft_nh_write_ok()` actually is | `code/vm/differ556_add.c` | `f556bare`, `f556e`, `f556nd` | `code/tools/f33_run.sh` |
| F35 | the `@ll` boundary is the envelope's link-header length, and it is 0 inside an L3 tunnel | `code/vm/differ557_add.c` | `f557bytes`, `f557diag`, `f557diag10`, `f557diag11`, `f557diag2`, `f557diag3`, `f557diag4`, `f557diag5`, `f557diag6`, `f557diag7`, `f557diag8`, `f557diag9`, `f557grid`, `f557tun`, `f557verdict` | `code/tools/f35_run.sh` |
| F36 | in the ip family the tag is gone from the frame by the hook, in every envelope | `code/vm/differ558_add.c` | `f558bytes`, `f558ipv6`, `f558vlan`, `f558why` | `code/tools/f36_run.sh` |
| F37 | one device bit decides whether the 802.1Q tag exists in the frame at all | `code/vm/differ559_add.c` | `f559chain`, `f559feat`, `f559ih`, `f559probe`, `f559smoke`, `f559wire`, `f559wiroff`, `f559wiron` | `code/tools/f37_run.sh` |
| F38 | the receive side of the tag: the guard judges `skb->vlan_all`, and sixteen ethertype bits pick the boundary | `code/vm/differ560_add.c` | `f560arp`, `f560drop`, `f560ndeg`, `f560ndin`, `f560recv` | `code/tools/f38_run.sh` |
| F39 | 802.1AD and Q-in-Q: a second TPID changes no link-layer cell, and the bridge guard refuses a two-tag frame 0/40 | `code/vm/differ561_add.c` | `f561far`, `f561ll`, `f561meta`, `f561ndin`, `f561unlock`, `f561xmit` | `code/tools/f39_run.sh` |
| F40 | the read side of `@nh`: the repair moves the read and leaves the store | `code/vm/differ562_add.c` | `f562ctl`, `f562ih`, `f562pair`, `f562qarp`, `f562rd`, `f562val` | `code/tools/f40_run.sh` |
| F41 | `meta protocol` moves the `@nh` read and not the store, and the ARP frame the guard approves dies | `code/vm/differ563_add.c` | `f563arp`, `f563ctl`, `f563ih`, `f563pair`, `f563ppp`, `f563rd`, `f563st` | `code/tools/f41_run.sh` |
| F42 | a bridge `@nh` write reaches a real IP stack through PPPoE in the PPPOX_BOUND state | `code/vm/differ564_add.c` | `f564b`, `f564l`, `f564v` | `code/tools/f42_run.sh` |
| F43 | `@th` is refused or exact: read and store share `nft_thoff(pkt)` | `code/vm/differ565_add.c` | `f565c`, `f565g`, `f565t`, `f565v` | `code/tools/f43_run.sh` |
| F44 | four pktinfo constructors, one coordinate | `code/vm/differ566_add.c` | `diag`, `dp`, `gd`, `md`, `rf`, `td`, `tm` | `code/tools/f44_run.sh` |
| F45 | IPv6 does not compute `@th`, it walks for it | `code/vm/differ567_add.c` | `dbg`, `diag`, `md`, `mp`, `nh`, `rd`, `td`, `tf`, `xc`, `xf` | `code/tools/f45_run.sh` |
| F46 | `@ll` depends on who built the skb, not on the door | `code/vm/differ568_add.c` | `cs`, `ctl`, `ld`, `ll`, `nh`, `rd`, `th` | `code/tools/f46_run.sh` |
| F47 | a hop-limit store at `@nh` is free at six of seven egress door/class pairs | `code/vm/differ569_add.c` | `iso` | `code/tools/f47_run.sh` |
| F48 | at an egress door `meta protocol` puts a PPPoE frame into two different coordinate systems | `code/vm/differ570_add.c` | `ppp6e`, `th6` | `code/tools/f48_run.sh` |
| F49 | at a ppp0 layer-3 door the base is right and `@ll` does not exist | `code/vm/differ571_add.c` | `ctl`, `rd`, `tapf`, `wr` | `code/tools/f49_run.sh` |
| F50 | a device without an ethernet header can never carry `@ll` into a bridge | `code/vm/differ572_add.c` | — | `code/tools/f50_run.sh` |
| F51 | store visibility among copies, and the frame the bridge learns | `code/vm/differ573_add.c` | — | `code/tools/f51_run.sh` |
| F52 | a tagged frame with a non-zero vid dies before the IPv6 door, and `@ll,12,2` is not the inner ethertype | `code/vm/differ574_add.c` | — | `code/tools/f52_run.sh` |
| F53 | the one configuration where the kernel puts the tag back into the frame between `vlan_do_receive()` and the hook | `code/vm/differ575_add.c` | — | `code/tools/f53_run.sh` |
| F54 | the tag on the wire is composed by the egress device; no store into it survives | `code/vm/differ576_add.c` | `warn`, `xf` | `code/tools/f54_run.sh` |
| F55 | the PCP is the part of the tag a hook can reach, and the channel is `skb->priority` | `code/vm/differ577_add.c` | `pcp` | `code/tools/f55_run.sh` |
| F56 | the tag is bytes or a word according to an offload bit, not the TPID | `code/vm/differ578_add.c` | `ad`, `br` | `code/tools/f56_run.sh` |
| F57 | the privilege boundary: two gates, one line each | `code/vm/differ579_add.c` | `priv`, `probe` | `code/tools/f57_run.sh` |
| F58 | the three write guards answer three different questions, and none of them asks the length | `code/vm/differ580_add.c` | `bounds` | `code/tools/f58_run.sh` |
| F59 | two chains on one ingress hook point get two different guards | `code/vm/differ581_add.c` | `guard` | `code/tools/f59_run.sh` |
| F60 | on a CHECKSUM_PARTIAL datagram the UDP checksum field is the pseudo-header seed, and a transport-base store pays nothing | `code/vm/differ582_add.c` | `opt`, `part` | `code/tools/f60_run.sh` |
| F61 | the forwarded path with CHECKSUM_PARTIAL: who computes the checksum | `code/vm/differ583_add.c` | `fwd` | `code/tools/f61_run.sh` |

## F29 — the inner-base store has no guard: the same TCP data-offset byte moves through a tunnel on all five measured kernels

**Claim.** The transport base is guarded and the inner base is not: the TCP data-offset byte that `nft_th_write_ok()` refuses at `@th` is written at `@ih` through a tunnel, on all five measured kernels, and the store keeps the packet's verdict.

**Minimal reproduction.** instrument `differ551`; one rule in the `ip` forward chain on a VXLAN frame (inner base at skb offset 42, the doff byte at inner offset 54, frame byte 96): `@th,96,8` against `@ih,432,8`.

**Run.** `bash vm/build_f29_differ.sh` then `bash code/tools/f29_run.sh` — log marker `F551`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_payload_set_eval()` calls `nft_th_write_ok()` for the transport base and nothing for the inner base; `nft_payload_csum_write_ok()` returns true for the inner base, on the comment that real L3/L4 headers cannot be mangled.

**Actual.** `@ih,432,8` is applied and delivered 10/10 on 7.2.15, 7.3, 7.3.4, 7.3.4+P549 and 7.3.4+P548 (doff 50 to 60 at frame byte 96); `@th,96,8` changes nothing on the four later kernels and is applied on 7.2.15.

**Limitations.** IPv6 inner headers, tunnel types other than VXLAN, Geneve and ipip, and GSO/CHECKSUM_PARTIAL were not measured; the rule needs root in the initial user namespace, so this is a gap in a guard, not an attack surface.

**Details.**

### What the guard covers, and what it does not

`nft_payload_set_eval()` protects three of the four bases a store can name. For
`NFT_PAYLOAD_TRANSPORT_HEADER` it calls `nft_th_write_ok()`, which on 7.3 and
later refuses any store that would land on the byte at transport offset 12
(the TCP data-offset byte). For `NFT_PAYLOAD_NETWORK_HEADER` and
`NFT_PAYLOAD_LINK_LAYER_HEADER` it calls `nft_nh_write_ok()` and
`nft_ll_write_ok()`. For `NFT_PAYLOAD_INNER_HEADER` it calls nothing:

```c
case NFT_PAYLOAD_INNER_HEADER:
        offset = nft_payload_inner_offset(pkt);
        if (offset < 0)
                goto err;
```

It cannot call the transport guard there: `pkt->tprot` is the *outer* protocol,
and `priv->offset` for the inner base is measured from the end of the outer
UDP/GRE header, so the inner transport header is not at `pkt->thoff`.
`nft_payload_csum_write_ok()` also returns `true` for the inner base, with a
comment saying that "real l3/l4 headers cannot be mangled" — for a tunnel frame
they can: at `@ih,22` the store lands in the inner IPv4 header and at `@ih,42`
in the inner TCP header.

### The frames and the coordinates

| frame | layout | inner base at skb offset | inner-header offset of the doff byte | frame byte |
|---|---|---|---|---|
| `plain` | eth+ip4+TCP | — | — | 46 |
| `vxlan` | eth+ip4+UDP:4789+VXLAN8+eth+ip4+TCP | 42 | 54 | **96** |
| `geneve2` | eth+ip4+UDP:6081+GENEVE(opt_len 2)+eth+ip4+TCP | 42 | 62 | **104** |
| `ipip` | eth+ip4(proto 4)+ip4+TCP | 34 | 32 | **66** |
| `vxudp` | vxlan frame carrying a real (valid, non-zero) outer UDP checksum | 42 | 54 | 96 |

### Measured on five kernels

`Q` = 7.2.15 (no guard), `R` = 7.3, `B` = 7.3.4 (two boots), `G` = 7.3.4 + P549
(the guard compares the doff nibble), `P` = 7.3.4 + P548 (`csum_shift` when the
store starts at an odd offset).

| store | Q | R | B | G | P |
|---|---|---|---|---|---|
| `@th,96,8` (transport base, doff byte) | applied `50>60` | no change | no change | no change | no change |
| `@ih,432,8` on `vxlan` (inner base, same byte) | applied `96:50>60` | applied | applied | applied | applied |
| inner base on `geneve2` | applied `104:50>60` | applied | applied | applied | applied |
| inner base on `ipip` | applied `66:50>60` | applied | applied | applied | applied |
| inner base on a plain frame | no change | no change | no change | no change | no change |

The same result with raw netlink stores instead of nft spellings: the inner-base
arms are delivered 10/10 on all five kernels, while the transport-base arms that
cover the doff byte are delivered 5/5 on 7.2.15 and 0/5 on 7.3, 7.3.4, `G` and
`P`.

Under `policy drop` with a `counter accept` after the store, the counter
separates "the store was refused" from "the packet was dropped for another
reason": `@th,96,8` delivers the frame with counter 1 on 7.2.15 and drops it with
counter 0 on all four later kernels, while `@ih,432,8` delivers it with counter 1
on all five. A store into the inner doff byte is therefore both possible and
verdict-preserving on the kernels where the same byte is protected through the
transport base.

### The inner checksum, for the same frame

| case | Q | R | B | G | P |
|---|---|---|---|---|---|
| store at an even inner offset | valid | valid | valid | valid | valid |
| store at an odd inner offset | invalid | invalid | invalid | invalid | **valid (parity fix)** |
| no `csum_type` fixup | invalid | invalid | invalid | invalid | invalid |
| store that changes the pseudo-header (`@ih,34`) | valid | valid | valid | valid | valid |
| store outside the covered region (`@ih,22`/`@ih,23`) | corrupted | corrupted | corrupted | corrupted | corrupted |

The last row is the one that matters for a guard report:
`nft_payload_csum_write_ok()` returns `true` for the inner base without looking
at the offset, so a store that lands outside the TCP header corrupts the inner
checksum instead of being refused.

### Reproducer (sketch)

Two netns, one veth pair, one hand-built Ethernet+IPv4+UDP+VXLAN+Ethernet+IPv4+TCP
frame injected on the far side and forwarded by the near side:

```
nft add table ip t
nft 'add chain ip t c { type filter hook forward priority 0; policy drop; }'
nft add rule ip t c @ih,432,8 set 0x60 counter accept     # inner base, doff byte
# -> the inner TCP header leaves with doff 6 on every kernel, counter packets 1
```

The transport twin of the same rule (`@th,96,8 set 0x60`) is refused on 7.3 and
later and accepted on 7.2.15.

### Scope

Not a vulnerability: the rule needs root in the initial user namespace, and the
effect is a forwarded packet whose inner TCP header is semantically corrupt (or,
with a hand-written client, a wrong checksum). Not measured here: GRE as an
inner-base store target, inner UDP/SCTP, inner fragments, the bridge and netdev
families, and the `@ih` load half in isolation.

---

## F30 — the network-header guard is an offset whitelist: `ip6 ecn set` and `ip6 flowlabel set` are silently dead while their IPv4 twins work

**Claim.** `nft_nh_write_ok()` is a whitelist of seven offsets for IPv4 and five for IPv6, so nft's own `ip6 ecn set` and `ip6 flowlabel set` spellings land off it and are refused silently, while the IPv4 twins are rounded to an accepted cell and applied.

**Minimal reproduction.** instrument `differ552`; 30 nft spellings (`ip dscp set`, `ip6 ecn set`, `ip6 flowlabel set`, raw `@nh` cells) one rule at a time, in the `ip`/`ip6` forward chain, counter and NFLOG after the store.

**Run.** `bash vm/build_f30_differ.sh` then `bash code/tools/f30_run.sh` — log marker `F552`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `ll` is a boundary (`offset_end <= skb_network_offset`), `nh` is a switch on `priv->offset` over {0,1,4,8,10,12,16}; `stmt_evaluate_payload_need_csum()` rounds every IPv4 network store to an even width at an even offset because `proto_ip` carries `checksum_key`, and `proto_ip6` does not.

**Actual.** 30 spellings on 7.2.15, 7.3, 7.3.4 and two patched 7.3.4 builds: 12 dead, identical on all five kernels. `ip6 ecn set 1` is 1 byte at offset 1 and is refused (NFT_BREAK); `ip ecn set` becomes 2 bytes at offset 0 and survives. Under `policy drop`, a rule that reads "mark ECN, then accept" drops every IPv6 packet (counter 0, nothing delivered).

**Limitations.** Only the spellings nft 1.1.7 generates for the declared fields were measured; other off-list stores are covered by the grid in F33.

**Details.**

### 1. Summary

nft_payload_set_eval() has four bases a store can name.  The transport base was
covered in the earlier report.  This one is about the other two that reach a
check at all: network (nft_nh_write_ok(), nft_payload.c:963) and link
(nft_ll_write_ok(), :986).  They were written in the same commit for the same
sentence -- "a store must not spill into the next header" -- and they are not
the same kind of check:

    ll : offset_end <= skb_network_offset(pkt->skb)          -- a boundary
    nh : switch (priv->offset) { 0, 1, 4, 8, 10, 12, 16 }    -- a whitelist

A boundary costs nothing.  A whitelist silently kills every store that lands
off it, and nft's own spellings do land off it:

  - `ip6 ecn set 1`        -> 1b @ network header + 1   -> refused (NFT_BREAK)
  - `ip6 flowlabel set X`  -> 3b @ network header + 1   -> refused (NFT_BREAK)

while the IPv4 twins of the same two operators are accepted, because nft
rounds every IPv4 network store up to an even width at an even offset
(stmt_evaluate_payload_need_csum() -> desc->checksum_key, which proto_ip has
and proto_ip6 does not).  `ip ecn set` therefore becomes 2b @0 and survives;
`ip6 ecn set` stays 1b @1 and dies.

Measured on 7.2.15, 7.3, 7.3.4 and on two patched 7.3.4 builds: 30 spellings,
12 dead, identical on all five kernels.  A dead store also skips the rest of
the rule, so under `policy drop` a rule that reads "mark ECN, then accept"
drops every IPv6 packet (counter 0, nothing delivered), while the same rule
with an IPv4 spelling delivers it.

### 2. What nft declares, and what the kernel does with it

nft 1.1.7 --debug=netlink, verbatim (network base, forward hook):

    # ip dscp set 0x2e
    [ payload load 2b @ network header + 0 => reg 1 ]
    [ bitwise reg 1 = ( reg 1 & 0xff03 ) ^ 0x00b8 ]
    [ payload write reg 1 => 2b @ network header + 0 csum_type 1 csum_off 10 ]

    # ip6 ecn set ect1
    [ payload load 1b @ network header + 1 => reg 1 ]
    [ bitwise reg 1 = ( reg 1 & 0xcf ) ^ 0x10 ]
    [ payload write reg 1 => 1b @ network header + 1 csum_type 0 csum_off 0 ]

    # ip6 flowlabel set 0x54321
    [ payload load 3b @ network header + 1 => reg 1 ]
    [ bitwise reg 1 = ( reg 1 & 0xf00000 ) ^ 0x054321 ]
    [ payload write reg 1 => 3b @ network header + 1 csum_type 0 csum_off 0 ]

nft_nh_write_ok_ip6() has cases for offsets 0, 2, 7, 8 and 24.  There is no
case 1, so both stores above return false and nft_payload_set_eval() raises
NFT_BREAK.  The rule installs with rc 0 and no message; `nft list chain` prints
it back verbatim:

    ip6 ecn set ect1 counter packets 0 bytes 0 accept

### 3. The predicate, measured as a function (not as a list of examples)

Raw netlink stores, base=network, offsets 0..19 (IPv4) / 0..39 (IPv6) with
length 1 and 2, in a chain with `policy drop` and `accept` after the store.
the counter sits between the store and the verdict, so it says "the store did
not BREAK" independently of what happens to the packet afterwards:

    IPv4 len 1:  - + - - - - - - + - + - + - - - + - - -
    IPv4 len 2:  + - - - + - - - + - + - + - - - + - - -
                 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
    IPv6 len 1:  + - + - - - - + + - ... - + - ... -
    IPv6 len 2:  + - + - - - - - + - ... - + - ... -
                 0 1 2 3 4 5 6 7 8 9 ...        24 ...    39

Exactly the whitelist and its length rules: IPv4 {0/L2, 1/L1, 4/L2, 8/L1|L2,
10/L<=10, 12/L<=8, 16/L<=4} = 11 of 40 (offset,length) pairs; IPv6 {0/L<=4,
2/L<=2, 7/L1, 8/L<=32, 24/L<=16} = 9 of 80.  The two byte-level comparisons are
separate and also measured: at IPv4 offset 0 a store that changes the
version/ihl byte is refused, at offset 8 one that changes the protocol byte is
refused; on IPv6 offset 0 only the version nibble is compared, so a store that
changes traffic class is accepted.

The link guard, same instrument: `ether saddr`, `ether daddr`, `ether type`,
`@ll,0,16` and `@ll,96,16` are accepted (write end <= 14); `@ll,112,8` (end 15)
and `@ll,0,128` (end 16) are refused.  That is exactly `end <=
skb_network_offset` -- no spellings are lost there.

### 4. Why this looks like a shape mismatch rather than a policy

The whitelist in nft_nh_write_ok_ip4() enumerates precisely the offsets nft
happens to emit on IPv4 -- and nft emits even offsets there *because the IPv4
csum fixup cannot handle odd ones* (stmt_evaluate_payload_need_aligned_fetch(),
evaluate.c:3437).  On IPv6 there is no header checksum, so nothing forces the
alignment, and the stores land on 1, 4 and 6.  So the check is calibrated to
the store shapes of one protocol, and the other protocol's shapes fall through.

The three dead IPv4 fields (`ip length`, `ip frag-off`, `ip protocol`) are
arguably deliberate: changing them would break the packet.  But that is a
statement about *meaning*, and the guard states it as a list of offsets.  The
same guard accepts `ip checksum set` (offset 10, any value up to 10 bytes,
i.e. overwriting saddr and daddr too) and refuses `ip6 ecn set`, which cannot
break anything.

### 5. Suggested fix (not applied here beyond a measurement build)

Two independent halves, either of which removes the silent death:

  a) Decide at init, not at eval.  `offset` and `len` are netlink attributes
     and cannot change between packets, and nft_payload_set_init() already
     rejects another static combination with a visible error (NFT_PAYLOAD_CSUM
     _NONE with a non-zero csum_offset is -EINVAL).  A store that can never be
     accepted should fail there, so the user sees a message instead of a rule
     that silently does nothing.

  b) Replace the offset whitelist with the meaning it is trying to protect:
     accept any store whose written bytes keep the fields that must not
     change -- version/ihl (IPv4 offset 0), total length, fragment offset,
     protocol/next-header, and, for IPv6, the version nibble.  The compare is
     already done for two of those cases; the same trick generalises, and it
     is the shape used in the doff patch discussed in the earlier thread.

### 6. Reproducer

Two netns, one veth pair, one hand-built Ethernet+IPv6+TCP frame injected on
the far side, forwarded by the near side:

    nft add table ip6 t
    nft 'add chain ip6 t c { type filter hook forward priority 0; policy drop; }'
    nft add rule ip6 t c 'ip6 ecn set 1' counter accept
    # send one IPv6/TCP frame fd00:98::2 -> fd00:99::2 through the pair
    # -> nothing arrives, counter packets 0
    nft add rule ip6 t c 'ip6 dscp set 0x2e' counter accept
    # -> the frame arrives with traffic class changed, counter packets 1

The same rule written for IPv4 (`ip ecn set 1`) delivers the packet on every
kernel tested.

### 7. Scope

Not a vulnerability: the rule needs root in the initial user namespace, and
the effect is a silently skipped store plus, under a drop policy, a dropped
packet.  No memory is touched.  Measured with nftables 1.1.7 as the only
client, one hook (forward), one veth pair; the ARP, bridge and netdev
dispatchers of the same guard were not measured, and neither was the
GSO/CHECKSUM_PARTIAL path.

---

## F31 — the store guard switches on the envelope, not on the write

**Claim.** Which branch of `nft_nh_write_ok()` judges a store is decided by the family, the chain label and the packet's ethertype, not by the write; at the netdev ingress hook the guard is a constant, at the bridge hook the same bytes are refused under an IPv4 label and accepted under an ARP label.

**Minimal reproduction.** instrument `differ553`; one rule at a time at the netdev ingress hook and at the bridge prerouting hook, one forwarded IPv4 datagram or one ARP-labelled frame; counter read from the rule itself, frame bytes from an NFLOG tap.

**Run.** `bash code/tools/f31_run.sh` — log marker `F553`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_nh_write_ok()` returns true before the `pf` switch when `pkt->hook == NF_INET_INGRESS`; the netdev family has an ingress hook (constant) and an egress hook (a switch on `skb->protocol`); the bridge branch switches on the chain label's ethertype.

**Actual.** At ingress `@nh,336,16 set 0xCAFE` (network offset 42) has counter 1 and frame bytes 56-57 = ca fe; `ip length set 0x0030` has counter 1 at ingress and counter 0 in the `ip` family; `@nh,64,32` has counter 2 with no byte changed. At the bridge hook, the same 4-byte store at offset 8 is applied under the ARP label (bytes 22, 24, 25 changed on the IPv4 header), refused under the IPv4 and 0x9100 labels, and `ip daddr set` is dead under the ARP label.

**Limitations.** IPv6 inside these envelopes, the `arp` family itself, PPPoE/QinQ stacks; the netdev egress hook is measured in F33, not here.

**Details.**

### 1. What this adds to the two-base report

The earlier report covered the transport base and, separately, the network and
link bases.  This section is about the shape of nft_nh_write_ok() itself
(nft_payload.c:963): before it looks at anything the user wrote, it looks at
the envelope -- pf, hook, ethertype -- and three of its four branches decide
the answer from that alone.  Two consequences follow, both measurable:

  (1) in the netdev family the guard is a constant at the ingress hook and a
      live dispatcher at the egress hook;
  (2) in the bridge family the same store into the same frame bytes is
      refused under an IPv4 label and accepted under an ARP label.

Everything below was measured inside disposable QEMU guests on stock nftables
1.1.7 and on two kernels built only to make these branches exist:
CONFIG_NF_TABLES_NETDEV and CONFIG_NF_TABLES_BRIDGE are not set in any image
this project had booted before, and nft_payload.c is byte-identical between the
two new kernels (7.3.4 and 7.2.15) and their parents.

### 2. Statement 1: at the netdev ingress hook the guard is a constant

nft_nh_write_ok() returns true before the pf switch when the hook is ingress:

    if (pkt->hook == NF_INET_INGRESS)     /* nft_payload.c, before the switch */
            return true;

The netdev family has two hooks, ingress and egress.  At ingress this line
decides every store without looking at it -- the branch is a constant.  At the
netdev egress hook the branch is live and dispatches on skb->protocol to the
ip4 or the arp function; measured over the same 40-cell grid in one boot (F33),
14 cells are accepted under an IPv4 label and 25 under ARP, and the columns are
identical to the ip4 and arp columns respectively.

Measured at ingress, base network, one forwarded IPv4 datagram, counter read
from the rule itself:

    @nh,336,16 set 0xCAFE   (network offset 42)  counter 1, frame bytes
                                                 56-57 = ca fe, i.e. @nh
                                                 points at frame byte 14
    ip length set 0x0030                         counter 1 at ingress
                                                 (counter 0 for the same rule
                                                 in the ip family)
    @nh,64,32  (ttl + proto + csum, 4 bytes)     counter 2, no byte changed

The first two rows are the point: the arm that the ip family refuses on all
five kernels (7.2.15, 7.3, 7.3.4, and both +patch builds) is applied at
ingress.  A store at network offset 22 -- the UDP destination port -- moves a
locally delivered datagram from :5000 to :6000 (control without the rule:
:5000 = 1, :6000 = 0), and a store at offset 36 changes payload bytes 8-9
instead, which is the control that shows where @nh actually points.

### 3. Statement 2: the "unknown ethertype" branch is unreachable for 802.1Q

The receive path strips the 802.1Q tag before any bridge hook runs, so the
guard never sees an 0x8100 frame.  Measured: a 62-byte tagged frame arrives at
the bridge hook as 58 bytes with ethertype 0x0800, `meta protocol ip` matches
(counter 1) while `meta protocol 8021q` does not (counter 0).  The fallback
branch ("unknown ethertype -> false") is therefore not what handles VLAN: what
handles it is the IPv4 branch, keyed on a field the stack rewrote on the way.

4. Statement 3: the ARP branch admits into the IPv4 header what the IPv4
    branch forbids

The ARP branch's condition is offset >= 8 && len <= 20, with no check that
offset + len stays inside the 28-byte ARP message.  One frame body, two
labels, the same network offset 8, four bytes written:

    label   raw 4b @nh+8      raw 4b @nh+16     `ip daddr set` (nft's own)
    0x0800  refused           applied           applied
    0x8100  refused           applied           applied   (tag stripped)
    0x9100  refused           refused           refused
    0x0806  APPLIED           applied           refused

Under the ARP label the four-byte store at offset 8 is applied to the same
IPv4 header bytes (22, 24, 25 changed) that the IPv4 branch refuses.  The
label also decides a second time, in another function:
nft_payload_csum_nh_write_ok() requires ethertype == ETH_P_IP, which is why
`ip daddr set` is dead under the ARP label while it is alive under the IP one.

The missing upper bound is measurable on its own: @nh,160,128 (offset 20, 16
bytes) writes 16 bytes on a 60-byte frame, of which bytes 42-49 lie past the
end of the 28-byte ARP message, and is refused on a 42-byte frame.

### 5. What it costs, and what it does not

Under `policy drop`, a store the guard refuses also skips the rest of the rule:
`@nh,... counter; accept` on an ARP-labelled frame delivers it with counter 1,
while on an 0x9100 frame the counter stays 0 and the packet is dropped.

This is not a regression (7.2.15+config and 7.3.4+config give the same table
cell for cell, and nft_nh_write_ok_ip4()/_arp() are the same text in both
trees), and it is not a security issue: the rule needs root in the initial user
namespace.  It is the same class as the two earlier reports -- a guard that
implements "do not spill into the next header" by testing a coordinate rather
than the write -- with one addition: the coordinate is chosen by the envelope,
and the envelope is not always the one the frame carries.

### 6. Not measured

IPv6 inside these envelopes; the `arp` family itself; PPPoE/QinQ stacks
(0x9100 here is simply an unknown ethertype); GSO/CHECKSUM_PARTIAL;
distribution kernels that build these symbols as modules.
The netdev egress hook is measured in F33, not here; this section measures the
ingress hook.  One cell is left as an open observation: the ingress arm
@nh,64,32 leaves the counter at 2 for a single sent frame.

---

## F32 — the arp family: four declared fields are silently dead, and the output hook adds a 28-byte bound

**Claim.** The ARP branch takes only `(offset,len)`: four of nft's nine declared ARP fields are silently dead, and at the output hook the branch additionally bounds the store by the 28-byte ARP message.

**Minimal reproduction.** instrument `differ555`; nine declared `arp` fields and a 96-cell `(offset,len)` grid at the input hook plus 12 cells at the output hook, one rule at a time, counter and NFLOG after the store.

**Run.** `bash code/tools/f32_run.sh` — log marker `F555`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_nh_write_ok_arp()` receives only `const struct nft_payload_set *priv` and its predicate is `(off == 6 && len == 2) || (off >= 8 && len <= 20)`; offsets 0, 2, 4 and 5 are neither the `ar_op` case nor `>= sizeof(struct arphdr)`.

**Actual.** Four declared fields are dead (`htype`, `ptype`, `hlen`, `plen`: counter 0, no log); five are applied (`operation` byte 7 01->02, `saddr ether` byte 13 66->99, `saddr ip` byte 17 09->42, `daddr ether` six bytes, `daddr ip` byte 25 01->09). The predicate reproduced over 96 input-hook cells and 12 output-hook cells.

**Limitations.** IPv6 over ARP envelopes and the bridge/netdev dispatchers are measured in F33; the rule needs root in the initial user namespace.

**Details.**

### The ARP branch of `nft_nh_write_ok()` takes only `(offset,len)`

nft_nh_write_ok_arp() is reached from three envelopes (family arp, bridge with an
ARP-labelled frame, netdev with an ARP-labelled frame) and receives only
`const struct nft_payload_set *priv` -- no pkt, no state, no hook.  Two
consequences are measurable with the stock nft 1.1.7 on a stock 7.3.4 with
CONFIG_NF_TABLES_ARP=y (and identically on 7.2.15 with the same symbol; the four
relevant source files are byte-identical to the unmodified trees).

1. Four declared fields of the family are silently dead.

   nft's own `proto_arp` names nine fields.  All nine install with rc=0 and no
   message; nft's --debug=netlink output for each is `payload write ... @
   network header + <off>`.  With a counter and an NFLOG tap *after* the store:

     arp htype set 0x00ab   -> 2b @ +0    counter 0, no log  (dead)
     arp ptype set 0x86dd   -> 2b @ +2    counter 0, no log  (dead)
     arp hlen  set 8        -> 1b @ +4    counter 0, no log  (dead)
     arp plen  set 16       -> 1b @ +5    counter 0, no log  (dead)
     arp operation set 2    -> 2b @ +6    counter 1, byte 7: 01->02
     arp saddr ether set .. -> 6b @ +8    counter 1, byte 13: 66->99
     arp saddr ip set ..    -> 4b @ +14   counter 1, byte 17: 09->42
     arp daddr ether set .. -> 6b @ +18   counter 1, six bytes
     arp daddr ip set ..    -> 4b @ +24   counter 1, byte 25: 01->09

   The guard's predicate, measured over 96 (offset,length) arms at the input
   hook and 12 at the output hook, is exactly
   `(off == 6 && len == 2) || (off >= 8 && len <= 20)`; nothing about the packet,
   the hook or the direction enters it.  Offsets 0, 2, 4 and 5 are neither the
   ar_op case nor >= sizeof(struct arphdr).

   The user-visible effect is not cosmetic.  In a chain with `policy drop`, a
   rule `arp htype set 2 counter accept` drops every matching ARP packet: the
   store returns false, nft_payload_set_eval() takes the same `goto err` as the
   guard's own refusal, and the rest of the rule -- counter, verdict -- does not
   execute.  Measured: counter 0, no reply from the host, no neighbour entry.

2. The output hook adds a second, invisible bound.

   At NF_ARP_OUT the skb is the kernel's own ARP request, exactly 28 bytes.
   Of the forms the guard permits, those with off+len > 28 fail
   skb_ensure_writable() -- again the same `goto err` -- measured on 12 arms
   (5 alive, e.g. (6,2), (8,6), (14,4), (18,6), (24,4); dead: (20,16), (24,6),
   (26,4), (28,8), (30,16)).  A rule that writes past the message therefore
   silently stops executing on output and silently succeeds on input, because at
   input a padded frame has 46 bytes of linear data.

3. The guard's hole is reachable with plain nft, not only with a custom client.

   In the arp family, `@nh,160,128 set 0x00112233445566778899aabbccddeeff`
   (offset 20, length 16) installs with rc=0 and, at the input hook, writes bytes
   20..35 of the message -- including 8 bytes past its end.  `@nh,224,64` writes
   padding only.  This is the same region F31 reached through the bridge; here it
   is ordinary documented syntax.

   What is *not* reachable: a message whose hlen/plen differ from the device.
   arp_rcv() drops `ar_hln != dev->addr_len || ar_pln != 4` before NF_HOOK
   (net/ipv4/arp.c:989), so the guard never sees such a message: measured as a
   frame visible to an AF_PACKET tap on the receiving device while the rule's
   counter stays 0.

Suggestion, if all of this is worth a patch at all: the four dead fields are a
static property of (base, family, offset, length), and nft_payload_set_init()
already returns -EINVAL for other static nonsense (csum_type none with a non-zero
csum offset).  Refusing at init what can never work is a message the user reads;
NFT_BREAK at run time is not.

Measured on: 7.3.4 and 7.2.15, each with CONFIG_NF_TABLES_ARP=y and no other
config change, plus the unmodified 7.3.4 and 7.2.15 to show the family is absent
there.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F33 — one guard, four types: what each branch of `nft_nh_write_ok()` actually is

**Claim.** Measured on one 40-cell grid in one boot, the four branches of `nft_nh_write_ok()` are: two finite whitelists of points with per-point bounds (`ip4` 14/40, `ip6` 12/40), a point plus a half-plane (`arp` 25/40), and two dispatchers that hand the decision to one of them (`bridge`, `netdev` egress, `default` refuse); at ingress the guard is a constant true.

**Minimal reproduction.** instrument `differ556`, modes `f556bare`, `f556e`, `f556nd`; the same 40-cell `(offset,len)` grid through eleven envelopes in one boot, the kernel's own counter placed after the store as the oracle per cell.

**Run.** `bash vm/build_f33_differ.sh` then `bash code/tools/f33_run.sh` — log marker `F556`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** Each branch's source: `ip4` seven `case`s, `ip6` five `case`s, `arp` a point plus a half-plane, `bridge`/`netdev` switches on label or `skb->protocol` with `default: return false`, and `nft_in_ingress()` returning true before the switch.

**Actual.** `ip4` 14/40, `ip6` 12/40, `nd` 40/40 (ingress constant), `eg4` 14/40, `egA` 25/40, `br4` 14/40, `brA` 25/40, `arp` 25/40; the identities `ip4 = br4 = eg4`, `arp = brA = egA` hold cell by cell. In the netdev family the egress hook is live and its column equals the ip4/arp column.

**Limitations.** Not measured: the `@th` and `@ll` guards on the same grid, and any family outside the five columns.

**Details.**

### The question

The four branches of `nft_nh_write_ok()` were measured one per image in F30, F31
and F32. This section asks a different question about the same guard: *what kind
of function* is each branch. The type is the shape of the set of `(offset,len)`
pairs the branch accepts — and a shape taken across three boots of three images
is not a shape. So one kernel was built in which all four branches are alive
(`T556` = `7.3.4-B19` + `CONFIG_BRIDGE`, `CONFIG_NF_TABLES_BRIDGE`,
`CONFIG_NF_TABLES_NETDEV`, `CONFIG_NF_TABLES_ARP`; `nft_payload.c`,
`nft_chain_filter.c`, `nf_tables_api.c` and `net/ipv4/arp.c` are byte-identical
to the parent), and the same 40-cell grid was run through every envelope in a
single boot.

| image | ip | ip6 | netdev | bridge | arp |
|---|---|---|---|---|---|
| `T556` (all four branches) | ok | ok | **ok** | **ok** | **ok** |
| `B19` stock 7.3.4 | ok | ok | -95 | -95 | -95 |
| `C553` (the F31 image) | ok | ok | ok | ok | -95 |
| `A553` (the F32 image) | ok | ok | -95 | -95 | ok |

`ok` = `nft add table` succeeded, `-95` = `EOPNOTSUPP` from the kernel. In the
`netdev` family the guard has an **egress** hook as well as an ingress one; the
at egress the branch is live and dispatches on `skb->protocol`, and `nft list chain`, printed by the kernel
itself, shows the chain.

### The type of each branch, read from the shape of its accept-set

Grid: `offset` 0..24, `len` 1,2,4,8,16; oracle per cell is the kernel's own
counter placed *after* the store in the same rule.

| envelope | type (from the source) | accepted | cells |
|---|---|---|---|
| `ip4` | a finite list of points with a length (7 `case`s), two of them read the packet | **14/40** | `(0,2) (1,1) (4,2) (8,1) (8,2) (10,1) (10,2) (10,4) (12,1) (12,2) (12,4) (16,1) (16,2) (16,4)` |
| `ip6` | a finite list of points with a length (5 `case`s), `case 0` reads the value | **12/40** | `(0,1) (0,2) (0,4) (2,1) (2,2) (8,1) (8,2) (8,4) (8,16) (24,1) (24,2) (24,4)` |
| `nd` | a constant: `ingress` -> true | **40/40** | all cells |
| `eg4` | a switch on `skb->protocol` -> the `ip4` branch | **14/40** | as `ip4` |
| `egA` | a switch on `skb->protocol` -> the `arp` branch | **25/40** | as `arp` |
| `br4` | a switch on the label -> the `ip4` branch | **14/40** | as `ip4` |
| `brA` | a switch on the label -> the `arp` branch | **25/40** | as `arp` |
| `arp` | a point `(6,2)` plus a half-plane `off>=8 && len<=20` | **25/40** | `(6,2)` and everything with `off>=8 && len<=20` |
| `ll4` / `llN` / `llE` / `llB` | a boundary `off+len <= 14` (ingress: constant true) | **24/40** / **40/40** | the diagonal |

`ip4`/`ip6` are finite sets of points with a bound on the length: the set does
not grow with the length, it consists of seven (five) isolated offsets, each with
its own constant bound. `arp` is a point plus a half-plane; the function receives
only `priv`, so neither the packet, nor the envelope, nor the direction can
influence its verdict. `bridge` and `netdev` are switches that do not judge at
all but hand the decision to one of the three functions above, with `default` =
refuse. `ll` is a boundary: the argument is the end of the write.

### The same cell in twelve envelopes

| cell | ip4 | ip6 | nd | eg4 | egA | br4 | brA | arp | ll4 | llN | llE | llB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `(0,2)` | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 1 | 1 | 1 | 1 |
| `(0,4)` | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 1 |
| `(1,1)` | 1 | 0 | 1 | 1 | 0 | 1 | 0 | 0 | 1 | 1 | 1 | 1 |
| `(6,2)` | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 1 |
| `(8,4)` | 0 | 1 | 1 | 0 | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 1 |
| `(12,4)` | 1 | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 0 |
| `(14,1)` | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 1 | 0 | 1 | 0 | 0 |
| `(16,16)` | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 1 | 0 | 1 | 0 | 0 |
| `(24,4)` | 0 | 1 | 1 | 0 | 1 | 0 | 1 | 1 | 0 | 1 | 0 | 0 |

Three identities are visible as equal columns, and all three are checked cell by
cell: `ip4` = `br4` = `eg4`; `arp` = `brA` = `egA`; `ll4` = `llB` = `llE`.

### Three things that are only visible together

1. **The envelope decides before the guard, and instead of it.** The `arp`
   function takes only `priv`, so its verdict cannot depend on the packet — but
   which *branch* runs is decided by the dispatcher from the family, the chain
   label and the packet's own ethertype. The same `(6,2)` store is refused in
   `ip4` and accepted in `arp` without either function looking at anything new.
2. **"Reads the packet" is a property of the case, not of the type.** Only
   `case 0` of `ip4`/`ip6` compares the written bytes against the version/ihl
   byte; every other accepted offset writes without looking. A guard whose type
   is "a point plus a half-plane" can never read the packet at all.
3. **The free pass exists only in ingress.** `nd` (ingress) and `llN` (ingress)
   are constants that return `true` before `priv` is read, which is why the same
   cell that is refused at every other door is accepted at those two.

### Scope

Not a vulnerability: the rule needs root in the initial user namespace. Not
measured: the `@th` and `@ll` guards on the same grid, and any family outside the
five columns above.

---

## F35 — the `@ll` boundary is the envelope's link-header length, and it is 0 inside an L3 tunnel

**Claim.** `nft_ll_write_ok()` is `off + len <= skb_network_header - skb_mac_header + vlan_hlen`, so the bound is the current envelope's link-header length: 14 on bare Ethernet, 18 with a tag, and 0 inside an L3 tunnel where the write can only end at offset 0.

**Minimal reproduction.** instrument `differ557`, fifteen modes; a `(offset,len)` grid through seven envelopes in one boot, bytes read back through NFLOG, verdicts from the kernel counters.

**Run.** `bash vm/build_f35_differ.sh` then `bash code/tools/f35_run.sh` — log marker `F557`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** The guard substitutes to `priv->offset + priv->len <= skb_network_header - skb_mac_header + vlan_hlen`, i.e. the write must end inside the envelope's link header.

**Actual.** The boundary measured on bare Ethernet is 14 (14 accepted, 16 refused); with a tag in metadata it is 18; inside an ipip tunnel `skb_network_offset()` is 0 and every store with a non-zero end is refused.

**Limitations.** Devices whose link header is not 14 bytes, and the `@nh` guard on the same grid.

**Details.**

### The guard under test

```c
static bool nft_ll_write_ok(const struct nft_pktinfo *pkt, int offset)
{
        if (nft_in_ingress(pkt->state)) return true;
        return offset <= skb_network_offset(pkt->skb);
}
```

It is called with `offset = priv->len + priv->offset + (skb_mac_header - skb->data)
- vlan_hlen`, and `skb_network_offset()` in 7.3 is `skb_network_header() - skb->data`.
Substituting, the condition is

```
priv->offset + priv->len  <=  skb_network_header - skb_mac_header + vlan_hlen
```

i.e. **the write must end inside the current envelope's link header**. On a bare
ethernet frame that number is 14. This section asks what the number is when the
envelope is not a bare ethernet frame.

### One grid, seven envelopes, one boot

36-cell `(offset,len)` grid (`offset` in {0,1,2,4,6,8,10,12,14,16,20,24}, `len` in
{1,2,4}); the tunnel envelopes on a 21-cell grid (`offset` in
{0,6,10,12,14,16,20}). Oracle per cell: the kernel's own counter placed **after**
the store in the same rule — `cnt=1` means the store was passed, `cnt=0` means it
was refused.

| envelope | alive / cells | control (no store) |
|---|---|---|
| ip, plain | **23/36** | 1 |
| ip, plain, fast ACK helper | **23/36** | 1 |
| ip, 802.1Q frame | **0/36** | 0 |
| bridge, plain | **23/36** | 1 |
| bridge, 802.1Q frame | **25/36** | 1 |
| **ipip** L3 tunnel, inner packet | **0/21** | 1 |
| **vxlan** L2 tunnel, inner packet | **11/21** | 1 |

Three facts fall out of the table without any theory: plain ethernet in the **ip**
family and in the **bridge** family give the same accept-set cell for cell (the
family is not the variable); the **ipip** envelope has no live cell at all, not
even `(0,1)`; the **vxlan** envelope gives exactly the plain-ethernet set (11/21).

### The cells that move when the frame is tagged

Same datagram, same hook (bridge prerouting), same grid; the only difference is
four bytes of 802.1Q between the MAC addresses and the ethertype.

| cell | plain (cnt) | 802.1Q (cnt) | why |
|---|---|---|---|
| `(10,4)` | 1 | 0 | straddles the tag: `nft_payload_need_vlan_adjust()` sends it into `nft_payload_set_vlan()`, which only knows offsets 12 and 14 |
| `(12,1)` | 1 | 0 | offset 12 with `len=1` is neither `h_vlan_proto` (len 2/4) nor `h_vlan_TCI` (len 2): the vlan branch refuses it, the plain branch allowed it |
| `(12,4)` | 0 | 1 | offset 12 with `len=4` inserts the whole tag into skb metadata (`__vlan_hwaccel_put_tag`) |
| `(14,2)` | 0 | 1 | `h_vlan_TCI`: writes `skb->vlan_tci`, the tag never appears in the frame |
| `(16,1)` | 0 | 1 | **the ethertype byte**: `vlan_hlen=4` is subtracted from the base, so the limit is **18**, not 14 |
| `(16,2)` | 0 | 1 | **the ethertype**: same branch, full 16-bit store |

`(16,4)` stays dead on both (16+4 = 20 > 18) and every `offset >= 20` cell stays
dead on both: the vlan branch has its own limit, it is not open-ended.

### Under `policy drop` the same rule accepts untagged traffic and drops tagged traffic

Chain policy `drop`, one rule per arm ending in `counter accept`; the control arm
has the same chain and no store.

| arm (offset, len) | plain | 802.1Q |
|---|---|---|
| control (no store) | 1 | 1 |
| `b12_1` (12, 1) | **1** | **0** |
| `b14_2` (14, 2) | **0** | **1** |
| `b16_2` (16, 2) | **0** | **1** |

Read the two columns together: a one-byte store at offset 12 delivers an
untagged frame and discards a tagged one; the two-byte store at offset 16 does
the exact opposite. The control is 1 in both
columns, so neither column means "the frame never arrived".

### The same grid inside real tunnels

The image used for the tunnels is the F33 image plus `CONFIG_NET_IPIP` and
`CONFIG_VXLAN`; `nft_payload.c`, `nft_cmp.c`, `nft_meta.c`, `ipip.c` and
`vxlan_core.c` are byte-identical to the parent. The outer datagram is sent with
`IP_HDRINCL`; the chain is gated on `meta iif == <tunnel device>` so the outer
packet is not counted; the control arm (no store, same gate) is 1 for both.

| envelope | live cells of 21 | identical to |
|---|---|---|
| ipip (L3) | **0** | — |
| vxlan (L2) | **11** | plain ethernet, cell for cell |

Why: `ipip_tunnel_rcv()` calls `skb_reset_mac_header()` right after pulling the
outer header, so `mac_header == data` and the limit is **0** — every `@ll` store
dies, including offset 0. `vxlan_set_mac()` calls `skb_reset_mac_header()` and
then `eth_type_trans()`, so the inner frame is an ordinary ethernet frame and the
limit is 14 again. The envelope, not the write, decides.

### Scope

Not a vulnerability: the rule is installed by root in the initial user namespace.
Not measured: the `@ll` guard on a device whose link header is not 14 bytes, and
the tagged path with `VLAN_FLAG_REORDER_HDR` cleared (measured separately in the
VLAN sections that follow).

---

## F36 — in the ip family the tag is gone from the frame by the hook, in every envelope

**Claim.** At the `ip`/`ip6` hooks the 802.1Q tag is in `skb` metadata, not in the frame bytes, so the link-layer store lands at `skb->data + priv->offset - 18`; a rule can rewrite the ethertype of a forwarded frame, and a store the guard cannot see is refused.

**Minimal reproduction.** instrument `differ558`, modes `f558bytes`, `f558ipv6`, `f558vlan`, `f558why`; a bridge at `br0` forwarding a tagged frame, one store per arm at the bridge prerouting hook, bytes read at both ports.

**Run.** `bash vm/build_f36_differ.sh` then `bash code/tools/f36_run.sh` — log marker `F558`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_payload_set_eval()` treats a frame whose tag sits in metadata specially: for `offset >= offsetof(struct vlan_ethhdr, h_vlan_encapsulated_proto)` it returns true with `vlan_hlen = VLAN_HLEN` and falls through to the ordinary store.

**Actual.** Store (16,2)=0x0806 has counter 1 and the forwarded frame leaves with ethertype 0x0806 instead of 0x0800; (14,2)=0x0000 has counter 1, changes no frame byte and clears `skb->vlan_tci`, so the next hop sees the frame untagged; (12,4)=0x8100 0x0000 has counter 1 with the same effect through `__vlan_hwaccel_put_tag()`; the same (16,2) on an untagged frame is refused, counter 0.

**Limitations.** Only the `ip` family and a bridge forwarding path; ARP under the same envelope is F31's table.

**Details.**

**The link-layer write guard lets a rule rewrite the ethertype of a frame it
forwards, and refuses a store it cannot see.**

`nft_payload_set_eval()` treats a frame whose 802.1Q tag sits in skb metadata
specially: for `offset >= offsetof(struct vlan_ethhdr,
h_vlan_encapsulated_proto)` it returns true with `vlan_hlen = VLAN_HLEN` and
falls through to the ordinary store, so the store lands at
`skb->data + priv->offset - 18`. Measured on 7.3.4 with nftables 1.1.7, a
bridge at `br0` forwarding a tagged frame:

| store | guard | kernel counter | what leaves on the wire |
|---|---|---|---|
| (16,2) = 0x0806 | alive | 1 | the forwarded frame's **ethertype** 0x0800 → 0x0806 |
| (14,2) = 0x0000 | alive | 1 | no frame byte changes; skb->vlan_tci = 0, so the next hop receives the frame as *untagged* |
| (12,4) = 0x8100 0x0000 | alive | 1 | no frame byte changes; same effect through `__vlan_hwaccel_put_tag()` |
| the same (16,2) on an untagged frame | refused | 0 | — |

Two observations that may be worth fixing on their own:

1. The offset the guard permits on a tagged frame is exactly the offset that
   holds the ethertype of the frame that will be forwarded, so the write the
   guard refuses on an untagged frame (16 + 2 > 14) is accepted — and visible —
   on a tagged one. Whatever the intent of "link-layer modifications must not
   spill into the network header", the byte being written here is the
   protocol tag of the frame.
2. `skb->vlan_tci` is written raw (`skb->vlan_tci = ntohs(...)`, and
   `nft_payload_vlan_hdr` for the 4-byte form), with no `VLAN_TAG_PRESENT`
   handling — in 7.3 the presence test is `!!skb->vlan_all`, so any value
   keeps or changes the tag rather than clearing it, and a rule that intends
   "strip the tag" cannot do it with this offset.

An instrument note: a veth pair advertises `NETIF_F_HW_VLAN_CTAG_TX|RX`, so on a veth the
802.1Q tag never exists in the frame bytes at either tap — the tag is metadata
and `AF_PACKET` cannot show it. Byte-level claims about a tagged frame need a
driver without that offload, or two taps plus the far side's own verdict.

Not a vulnerability: the rule is installed by root in the initial user ns.
Consequences: a silently dead store, and a rewritten ethertype on a forwarded
frame.

---

## F37 — one device bit decides whether the 802.1Q tag exists in the frame at all

**Claim.** For a frame whose tag the receive path pulled into metadata, `@ll` offsets are wire offsets and the four bytes the guard opens up are the tag; a two-byte store at (12,2) can leave a frame with no ethertype while the kernel still treats it as IPv4.

**Minimal reproduction.** instrument `differ559`, eight modes; bridge prerouting, one veth pair, one frame per arm, frames read on the egress wire.

**Run.** `bash vm/build_f37_differ.sh` then `bash code/tools/f37_run.sh` — log marker `F559`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_payload_set_eval()` subtracts `vlan_hlen` from the skb offset and `nft_ll_write_ok()` adds it back; `nft_payload_set_vlan()` handles `h_vlan_proto` for len 2; `vlan_hw_offload_capable()` knows only 0x8100 and 0x8021ad.

**Actual.** Control 8100 0064 0800; `@ll,16,2=0806` gives 8100 0064 0806 (tag untouched); `@ll,14,2=0099` writes the TCI; `@ll,12,4=81000000` writes 8100 0000 0800; `@ll,16,2` on an untagged frame is refused (16+2 > 14), counter 0. `@ll,12,2 = 0` leaves the wire with ethertype 0x0000 while `skb->protocol` stays 0x0800 and the bridge keeps forwarding.

**Limitations.** The untagged and single-tag cases only; Q-in-Q is F39, and the `@ll` read side is F52-F56.

**Details.**

Three points, each measured on 7.3.4 with nftables 1.1.7, one hook (bridge
prerouting), one veth pair, one frame per arm.  Nothing here is a vulnerability:
the rule is installed by root in the initial user ns.

1. For a tagged frame the `@ll` offsets are wire offsets, and the four bytes the
   guard opens up are the tag.

   nft_payload_set_eval() subtracts vlan_hlen from the skb offset and
   nft_ll_write_ok() adds it back, so `@ll,16,2` on a frame whose tag the receive
   path pulled into skb metadata writes frame byte 16..17 -- the *inner*
   ethertype, which is exactly what an operator counting on the tagged frame
   expects.  Measured on the wire (the frame the egress driver is handed):

       control       8100 0064 0800 ...   (64 bytes)
       @ll,16,2=0806 8100 0064 0806 ...   (64 bytes, tag untouched)
       @ll,14,2=0099 8100 0099 0800 ...   (the TCI)
       @ll,12,4=81000000 8100 0000 0800 ...
       @ll,16,2 on an untagged frame: refused (16+2 > 14), counter 0

2. A two-byte store can leave a frame with no ethertype at all while the kernel
   still treats it as IPv4.

   `@ll,12,2 = 0` is accepted on a tagged frame (nft_payload_set_vlan() case
   h_vlan_proto, len 2) and sets skb->vlan_proto = 0 while skb->vlan_tci keeps
   its value.  Since vlan_hw_offload_capable() knows only 0x8100 and 0x8021ad,
   validate_xmit_vlan() then inserts the tag itself on *every* device:

       frame on the wire:  00 00 00 64 08 00 ...   (ethertype 0x0000)
       skb->protocol:      0x0800 (unchanged), the bridge keeps forwarding it
       far side:           eth_type_trans() reads 0x0000, IpInReceives +0

   So the frame a peer receives is not IPv4 by its own bytes while every
   nftables expression that reads skb->protocol still calls it IPv4.  On a
   forwarded frame this is a 2-byte rule that silently breaks the ethertype of
   everything it matches.

3. The transport guard is reachable from the bridge family and is envelope-blind;
   it also has a second refusal in front of it that is not a guard.

   nft_do_chain_bridge() builds its pktinfo from eth_hdr(skb)->h_proto (the inner
   ethertype), so a transport-base store works in a bridge chain.  36 cells per
   envelope at the bridge prerouting hook:

       proto 6 (TCP)  31/36 live, dead: (10,4) (12,1) (12,2) (12,4)  <- doff=12
                                                 and (24,4)           <- skb length
       proto 17 (UDP) 35/36 live, dead: (24,4)

   The same set with and without the tag, but the bytes land at wire offset
   38+off when the frame is tagged and 34+off when it is not: the guard's
   coordinates are skb coordinates and the tag is not in the skb.  The extra
   dead cell is skb_ensure_writable(20 + off + len) against a 46-byte datagram,
   i.e. a length bound, not a policy.

   Second-order, and worth stating: two base chains at one hook
   do not share pktinfo.  `pre` (prio 0) writing @ll,16,2=0806 makes the frame's
   inner ethertype 0x0806, and `post` (prio 10) then builds its pktinfo from
   those bytes, falls into nft_set_pktinfo_unspec(), and its transport store is
   silently refused (counter 0, no bytes) while the frame itself is delivered.

Measurement method, for anyone who wants to check it: ETHTOOL_SFEATURES can
clear NETIF_F_HW_VLAN_CTAG_TX on a veth from userspace (ethtool_set_features()
does not require an ndo_set_features op), after which validate_xmit_vlan() puts
the tag into the frame and the TX-side AF_PACKET tap sees the real bytes; with
the bit set the same frame is 60 bytes and tagless, which is why this was hard
to see before.

-- measured, not read: 765 independent checks over two boots, every captured
frame compared byte for byte with a model of validate_xmit_vlan() and
skb_vlan_untag().

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F38 — the receive side of the tag: the guard judges `skb->vlan_all`, and sixteen ethertype bits pick the boundary

**Claim.** The 802.1Q tag is popped before every hook, so the link-layer guard judges `skb->vlan_all` and `skb->protocol`; two frames with the same L2 bytes get different verdicts on two cells from the two ethertype bytes alone.

**Minimal reproduction.** instrument `differ560`, five modes; one frame at a time through bridge prerouting, bridge input, ip6 prerouting and netdev ingress, verdicts from counters, bytes from taps and NFLOG.

**Run.** `bash vm/build_f38_differ.sh` then `bash code/tools/f38_run.sh` — log marker `F560`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `__netif_receive_skb_core()` runs `eth_type_vlan()` and `skb_vlan_untag()` before the taps and before `nf_ingress`; `eth_type_vlan()` knows ETH_P_8021Q and ETH_P_8021AD only.

**Actual.** A tagged frame reaches the far side byte-identical to the untagged one (60 bytes on both taps) while the wire differs by four bytes; a 9100 frame is not popped and arrives at 64 bytes. The plain and 9100 frames give the same 36-cell set (23/36); the tagged and vid-0 frames give 25/36.

**Limitations.** Other TPIDs and the `@nh` base on the same frames.

**Details.**

Kernel 7.3.4-T558, nftables 1.1.7.

Everything below is measured.

### 1. The 802.1Q tag is popped before every hook, so the ll guard judges state
__netif_receive_skb_core() runs eth_type_vlan() -> skb_vlan_untag() at the top
of another_round, i.e. before the packet taps and before nf_ingress, and
skb_vlan_untag() turns the tag into skb->vlan_all and compacts the frame.
Measured: a frame sent with 8100 0064 in its own bytes reaches the far side
byte-identical to the same frame sent without a tag (60 bytes on both taps),
while the wire differs by exactly those four bytes; and the same frame with
9100 in place of 8100 is not popped at all and arrives at 64 bytes with the tag
intact, because eth_type_vlan() knows ETH_P_8021Q and ETH_P_8021AD only.

Consequence for the guard: nft_ll_write_ok()'s boundary is
off + len <= 14 + vlan_hlen, with vlan_hlen = 4 only when
skb_vlan_tag_present(). Two frames with the same eighteen L2 bytes get different
verdicts on two of the cells purely from those two ethertype bytes: the plain
frame and the 9100 frame give the same 36-cell set (23/36), the tagged frame and
the vid-0 frame give the same one (25/36).

### 2. A tag cannot be manufactured by a rule; and on ingress the guard is blind
a rule storing 8100 0064 at @ll,12,4 installs with rc=0 and changes nothing at
all when the frame is untagged: nft_payload_set_vlan() is only entered when
skb_vlan_tag_present() is already true, and before that the same cell is
refused by the ll boundary (16 > 14). The metadata tag is downstream of the
wire; nft stores can edit it, not create it.

At NFPROTO_NETDEV + NF_NETDEV_INGRESS the guard returns true before it looks at
skb->protocol, so all 40 cells are accepted on IP, on 8100 and on 9100 alike.
the acceptance is envelope-blind and therefore also field-blind: one and the
same store @nh,64,8 lands on wire byte 22 (ttl) for the plain frame, 26 (ttl)
for the tagged frame, and 22 for the 9100 frame - where byte 22 is the IPv4 id
field, because that header starts at 18. Accepted, and four bytes off target.

The same branch at hook egress does read skb->protocol and falls through to
"default: return false": sll_protocol 0x0800 gives the ip4 whitelist (14/40),
0x8100 and 0x9100 give 0/40 with a live control. That is the only hook where
the sender chooses what the guard reads.

### 3. The arp branch and the verdict
an 8100 + 0806 frame at bridge prerouting gives the plain ARP table cell for
cell (25/40) and the same hole: @nh,20,16 writes sixteen bytes, eight of them
past the end of the 28-byte ARP message, at wire 38..53 instead of 34..49;
9100 + 0806 gives 0/40 because the envelope is decided before the branch.

Under policy drop, "ip6/ip daddr ... " style stores aside, the plainest example:
@ll,16,2 counter accept drops an untagged frame (the refusal aborts the rule, so
accept never runs and no frame leaves the port) and delivers the tagged one.

This is not a vulnerability: the rule is installed by root in the initial user
namespace. The consequences are a store that is silently not performed, a
dropped packet under policy drop, and a store that lands four bytes before its
target on a frame whose ethertype the kernel does not recognise as a tag.

---

## F39 — 802.1AD and Q-in-Q: a second TPID changes no link-layer cell, and the bridge guard refuses a two-tag frame 0/40

**Claim.** A 802.1Q frame and a 802.1AD frame are indistinguishable to every branch of the guard; a Q-in-Q frame is refused by all 40 network-base cells because one `skb_vlan_untag()` leaves `skb->protocol == 0x8100`, for which the bridge branch has no case.

**Minimal reproduction.** instrument `differ561`, six modes; a bridge with two veth pairs, the 36-cell packet-relative grid and the 40-cell network-base grid per envelope, plus a `meta protocol` expression in front of the store.

**Run.** `bash vm/build_f39_differ.sh` then `bash code/tools/f39_run.sh` — log marker `F561`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_nh_write_ok_bridge()` switches on the label; there is no case for 0x8100, so `default: return false`. `nft_meta_pktinfo_may_update()` reads `h_vlan_encapsulated_proto` at `mac_header + 16`, which after one pop is the real ethertype.

**Actual.** 802.1Q and 802.1AD give the same 25 cells of the 36-cell grid and the same 14 of the 40-cell grid; Q-in-Q is refused 0/40 while `meta protocol` reports 0x0800; with `meta protocol` before the store the same grid goes from 0 to 12 live cells, each landing four bytes before the field it names.

**Limitations.** 802.1ad egress and the `@ll` base; a rule needs root in the initial user namespace.

**Details.**

Kernel 7.3.4-T558, nftables 1.1.7.

`nft_payload_set_eval()` refuses a network-base store unless
`nft_nh_write_ok()` allows the (offset, length) pair.  Which branch of that
function judges the store is decided by `pkt->ethertype`, which for the bridge
family is `skb->protocol` -- the encapsulated protocol the receive path wrote
into the skb.  Measured on 7.3.4 with a bridge and two veth pairs:

1. A 802.1Q frame and a 802.1AD (0x88a8) frame are indistinguishable to every
   branch of the guard: the packet-relative 36-cell grid is the same 25 cells in
   both, and the network-base 40-cell grid is the same 14 cells.  `eth_type_vlan()`
   knowing two TPIDs changes no verdict.

2. A Q-in-Q frame (88a8 8100 0800 ...) is refused by all 40 network-base cells,
   because a single `skb_vlan_untag()` has popped the outer tag and left
   `skb->protocol == 0x8100`; `nft_nh_write_ok_bridge()` has no case for that, so
   `default: return false`.  In the same packet, `meta protocol` reports 0x0800:
   `nft_meta_pktinfo_may_update()` reads `h_vlan_encapsulated_proto` at
   `mac_header + 16`, which after the single pop is the real ethertype.  So the
   guard says "no protocol", `meta protocol` says "ipv4", and the IP stack never
   sees the frame.

3. `pkt->ethertype` is not read-only.  A `meta protocol` expression placed before
   the store in the same rule rewrites it to 0x0800, and the same 40-cell grid
   goes from 0 live cells to 12; the other two cells of the IPv4 list stay dead
   because their value checks read the packet at `skb_network_offset+0` and `+9`,
   where a Q-in-Q frame now carries the inner tag's TCI and the IPv4 id.
   Every store that goes live lands four bytes before the field it names:
   `@nh,8,1` writes the id high byte, not the ttl.  The reason is one line of
   asymmetry: `nft_payload_eval()` computes `skb_network_offset(skb) + pkt->nhoff`
   and `nft_payload_set_eval()` computes `skb_network_offset(skb)`.

4. On the way out, whether a stored `skb->vlan_proto` reaches the wire depends on
   two feature bits, not one: `vlan_hw_offload_capable()` tests
   `NETIF_F_HW_VLAN_CTAG_TX` for 0x8100 and `NETIF_F_HW_VLAN_STAG_TX` for 0x88a8,
   and veth advertises both.  With only the CTAG bit cleared, a
   `(12,2) = 0x88a8` store leaves nothing on the wire at all; with both cleared
   the frame leaves as `88a8 0064 0800 ...` and the peer pops it back.  A
   `(12,2) = 0x0000` store leaves `0000 0064` on the wire in every state.

5. The receive path pops exactly one tag per skb, because `skb_vlan_untag()`
   returns immediately when `skb_vlan_tag_present(skb)` is already true.  A
   Q-in-Q frame arriving from the wire therefore keeps its inner tag in the bytes
   (the far tap shows 64 bytes starting `8100 00c8 0800 ...`) and its protocol
   stays 0x8100: it is never delivered to IPv4.

No memory-safety claim is made, and none is implied: the rules in all of the
above need CAP_NET_ADMIN in the initial user namespace.  The consequences are
silently unapplied stores, frames that leave with a forged or vanished tag, and
stores that land four bytes away from the field they name while the rule's own
counter reports success.

Reproducer and per-cell tables: F39 in the same tree as F29-F38.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F40 — the read side of `@nh`: the repair moves the read and leaves the store

**Claim.** After `meta protocol` on a Q-in-Q frame, the `@nh` read and the `@nh` store use different reference points: the read lands at `data + nhoff + off`, the store at `skb_network_offset + off`, four bytes apart, so a cell compares one field and writes another.

**Minimal reproduction.** instrument `differ562`, six modes; 657 arms in each of two boots at bridge prerouting, a 40-cell read+compare grid and the store grid on the same Q-in-Q frame.

**Run.** `bash vm/build_f40_differ.sh` then `bash code/tools/f40_run.sh` — log marker `F562`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_payload_eval()` computes `skb_network_offset(skb) + pkt->nhoff`; `nft_payload_set_eval()` uses `skb_network_offset(skb)`; `nft_nh_write_ok_ip4()` also uses `priv->offset + skb_network_offset()`.

**Actual.** The read grid is 40/40 live in every envelope and lands at `data + nhoff + off`; the store is not repaired: cell (8,1) compares the ttl and writes the IP id, cell (16,4) compares the daddr and writes the saddr. A rule that stores and then reads the same cell is dead on a plain frame and live on Q-in-Q.

**Limitations.** Only the Q-in-Q and PPPoE carriers of `nhoff` were measured; the `@ll` and `@th` bases are F43-F53.

**Details.**

`nft_payload_eval()` and `nft_payload_set_eval()` do not agree on the reference
point of an `@nh` offset:

    nft_payload_eval:      offset = skb_network_offset(skb) + pkt->nhoff;
    nft_payload_set_eval:  offset = skb_network_offset(skb);

and `nft_nh_write_ok_ip4()` uses `priv->offset + skb_network_offset()`.

`pkt->nhoff` is 0 for every envelope except one: `nft_meta_pktinfo_may_update()`
(entered from `meta protocol`) sets `nhoff = VLAN_HLEN` when `skb->protocol`
is `0x8100` and the encapsulated protocol is IP or IPv6. That is a Q-in-Q frame
after the receive path popped exactly one tag: the inner tag is still in the
bytes, so `skb->data` begins four bytes before the IP header.

Measured on 7.3.4 with 657 arms in each of two boots, bridge prerouting:

1. The read is unguarded and envelope-correct after the repair. A 40-cell grid
   of `(offset,len)` read+compare arms is 40/40 live in every envelope, and it
   lands at `data + nhoff + off`: on a Q-in-Q frame with `meta protocol` in
   front, every cell reads exactly the byte a plain frame reads at the same
   cell. Without `meta protocol` the same cells are refused by the guard
   (12/40), so the read grid is strictly wider than the store grid.

2. The store is not repaired. On the same frame and in the same rule, the cell
   `(8,1)` compares the **ttl** and writes the **IP id**; `(16,4)` compares the
   **daddr** and writes the **saddr**. A rule that stores first and reads the
   same cell afterwards is dead on a plain frame (the store rewrote the byte the
   read returns) and live on Q-in-Q (the store wrote the byte four earlier and
   the read still returns the original). On the wire the frame leaves with a
   rewritten id instead of a rewritten ttl.

3. `@ih` is repaired completely, because both sides use `nft_thoff(pkt)`, which
   is computed from the repaired `nhoff`. So the split is specific to `@nh`.

4. ARP over Q-in-Q is the other failure mode: `nft_meta_pktinfo_may_update()`
   validates only IP and IPv6, so for `0x0806` it assigns `pkt->ethertype` and
   leaves `nhoff = 0`. The guard then dispatches to `nft_nh_write_ok_arp()`,
   whose coordinates are `priv->offset` alone — also relative to `skb->data`,
   i.e. four bytes before the ARP header. Measured on `88a8:100/8100:200/ARP`:

   - `@nh,6,2` — the cell whose whitelist entry is `offsetof(struct arphdr,
     ar_op)` — writes `ar_pro` (capture 20..21: `08 00 → 90 91`);
   - `@nh,8,2` writes `ar_hln/ar_pln`, after which `arp_rcv()` refuses the frame;
   - the real `ar_op` is writable through the `offset >= 8 && len <= 20`
     branch, which is the same door F32 described for the arp family.

5. The two ip4 cells that read the packet read the wrong bytes too: `case 0`
   compares the new first byte against `data[0]`, which on Q-in-Q is the high
   byte of the inner tag's TCI. A store whose whitelist entry exists to keep the
   IPv4 version/ihl intact therefore becomes live exactly when it carries that
   TCI byte, and then rewrites the inner VLAN id (measured: vid 200 → 145), and
   `case 8` compares against the low byte of the IP id.

Not a vulnerability: the rule is installed by root in the initial user ns. The
consequences are stores that silently land on a different field than the one
they name, a store refused for a reason unrelated to the field, and an ARP frame
made invalid by a guard-approved store. The asymmetry is either a bug in the
guard's coordinate or an argument that `@nh` stores should add `pkt->nhoff` the
way reads do; it cannot be both.

Reproduce: 657-armed instrument (`differ562`), kernel 7.3.4, one veth pair in a
bridge, `meta protocol` + `payload @nh` rules, the rule's own counter read
before and after one send as the oracle, captures on both bridge ports.

---

## F41 — `meta protocol` moves the `@nh` read and not the store, and the ARP frame the guard approves dies

**Claim.** On PPPoE, `meta protocol` sets `nhoff = PPPOE_SES_HLEN`, so the `@nh` read lands on the real IPv4 header and the store lands eight bytes earlier; the store grid is the IPv4 whitelist, 14/40, and not one of the 14 cells writes the field it names.

**Minimal reproduction.** instrument `differ563`, seven modes; 438 arms in each of two boots at bridge prerouting on a real PPPoE session frame (`8864 | ver/type code | sid | length | 0x0021 | IPv4/UDP`), plus a real PPP unit on the receiving side.

**Run.** `bash vm/build_f41_differ.sh` then `bash code/tools/f41_run.sh` — log marker `F563`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_meta_pktinfo_may_update()` sets `nhoff = PPPOE_SES_HLEN` (8) for ETH_P_PPP_SES; the read adds `pkt->nhoff`, the store does not; the whitelist is written in the coordinates of the field name.

**Actual.** The read grid is 40/40 live at `data + nhoff + off` and 40/40 dead at the store's coordinate; with `meta protocol` the store grid is 14/40 and every accepted cell writes a PPPoE or preceding IPv4 field instead of the named one, e.g. (0,2) writes the PPPoE version/type at offset 14, (8,1) writes the IP version/ihl at offset 22.

**Limitations.** IPv6 over PPPoE and the egress doors; a rule needs root in the initial user namespace.

**Details.**

`nft_meta_pktinfo_may_update()` has a second carrier of `pkt->nhoff` besides
VLAN:

    case htons(ETH_P_PPP_SES):
            if (!nf_flow_pppoe_proto(skb, &ethertype))
                    return;
            nhoff = PPPOE_SES_HLEN;          /* 8, not 6 */
            break;

so on a PPPoE session frame with `meta protocol` in front the read of an `@nh`
cell lands on the real IPv4 header, and the store of the same cell lands eight
bytes earlier, inside the PPPoE session header. Measured on 7.3.4-T563
(= 7.3.4 + CONFIG_PPP + CONFIG_PPPOE; the files that decide this are
byte-identical to the image F36..F40 measured), 438 arms in each of two boots,
bridge prerouting, one DHCP-less PPPoE session frame (`8864 | ver/type code |
sid | length | 0x0021 | IPv4/UDP`):

1. The read grid is 40/40 live at `data + nhoff + off` (nhoff = 8) and 40/40
   dead at the store's coordinate; without `meta protocol` the read is 40/40 at
   the store's coordinate and the store is 0/40 (the guard has no branch for
   0x8864).
2. The store grid with `meta protocol` is exactly `nft_nh_write_ok_ip4()`'s
   whitelist, 14/40 — and **not one of the 14 cells writes the field it names**:

        (0,2) "ip ver/ihl"   writes pppoe ver/type + code   (off 14)
        (1,1) "ip tos"       writes pppoe code              (off 15)
        (4,2) "ip id"        writes pppoe length            (off 18)
        (8,1) "ip ttl"       writes ip ver/ihl              (off 22)
        (10,1) "ip checksum" writes ip tot_len              (off 24)
        (12,4) "ip saddr"    writes ip id + frag_off        (off 26)
        (16,4) "ip daddr"    writes ip ttl + proto + csum   (off 30)

   The real `saddr` (offset 20) and `daddr` (offset 24) are refused by the
   whitelist, so a rule cannot write them at all. `wrrd` (store, then read the
   same cell) is dead on a plain frame and live here: the store rewrote a byte
   eight bytes before the one the read returns.
3. The receiving side is a real `AF_PPPOX`/`PX_PROTO_OE` session (no pppd, no
   negotiation: `pppoe_connect()` binds when `sid != 0` and queues frames on the
   socket). `recv()` is the stack's own verdict in bytes: the control arm
   delivers 48 bytes, `(4,2) = 0x0004` — the cell the whitelist exists to let a
   rule write the IPv4 id — rewrites the **PPPoE length field** and delivers
   4 bytes, and `(4,2) = 0x9091` drops the datagram entirely. `(12,4)`
   "ip saddr" rewrites the id and fragment offset; `(16,4)` "ip daddr"
   rewrites ttl, protocol and the header checksum of the delivered datagram.

Second half — the ARP frame the guard approves into invalidity, now followed to
the receiver. Three oracles per arm: the releasing chain's counter, the `arp`
family counter at `NF_ARP_IN` (i.e. did the frame pass `arp_rcv()`), and the
reply the kernel sends (plus `/proc/net/arp`):

    frame                          cell        NF_ARP_IN  reply  neighbour
    plain ARP request              -           1          yes    yes
    plain, ar_op = 0x9091          (6,2)       1          no     no
    plain, ar_op = REPLY           (6,2)       1          no     no
    plain, sha[0..1] = 0x9091      (8,2)       1          to 90:91:cc:00:00:66
    Q-in-Q vid 0/0                 -           1          yes    yes
    Q-in-Q, ar_pro = 0x9091        (6,2)       1          no     no
    Q-in-Q, real ar_op = 0x9091    (10,2)      1          no     no
    Q-in-Q, ar_hln/ar_pln          (8,2)       0          no     no
    Q-in-Q vid 0/200               -           0          no     no
    netdev ingress, ar_hln/pln     (4,2)       0          no     no
    netdev ingress, ar_op          (6,2)       1          no     no

Two things follow that a source reading alone does not give. First, a Q-in-Q
frame whose outer tag has **vid 0** does reach the ARP stack — the outer tag is
a priority tag and `check_vlan_id` in `net/core/dev.c` pops the next one too —
so the shifted ARP store (F40) is not just byte surgery: `(8,2)` there really
kills the frame in `arp_rcv()` (0 against 1 for the control), while `(6,2)`
passes `arp_rcv` (1) and dies in `arp_process` at the `ar_pro` check. Second,
the same death is reachable where the guard is the **constant**
`NFT_PAYLOAD_NETWORK_HEADER` at `NF_NETDEV_INGRESS` (`if (pkt->state->hook ==
NF_NETDEV_INGRESS) return true;`): offset 4, which the ARP whitelist refuses
because it is `ar_hln`, is allowed there, and the frame dies before the ARP
hook.

Both halves are the same shape and it is worth stating once: the guard is a
list of coordinates in the header's own frame, and the store's reference point
is `skb_network_offset()`, which is not the header's when the skb still carries
a POPPED tag or a PPPoE session header. The read was repaired for both
envelopes; the store was not.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F42 — a bridge `@nh` write reaches a real IP stack through PPPoE in the PPPOX_BOUND state

**Claim.** On a real PPPoE session delivered to a real PPP unit in PPPOX_BOUND, a bridge `@nh` store lands eight bytes before the field it names and is seen by the IP stack: an `ip id` store becomes the PPPoE length and the frame dies in `ip_rcv`, and in the IPv6 branch one cell rewrites the PPP protocol.

**Minimal reproduction.** instrument `differ564`, modes `f564b`, `f564l`, `f564v`; one rule at a time, one PPPoE session frame at a time, a real `/dev/ppp` unit built with PPPIOCNEWUNIT/PPPIOCATTCHAN/PPPIOCCONNECT and moved to PPPOX_BOUND, a real UDP socket and the kernel counters.

**Run.** `bash vm/build_f42_differ.sh` then `bash code/tools/f42_run.sh` — log marker `F564`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_meta_pktinfo_may_update()` gives `nhoff = PPPOE_SES_HLEN + skb_network_offset`; the read uses it and the store does not, so the store is eight bytes early; the whitelist cells are the IPv4 field coordinates.

**Actual.** Payload 10.1.0.1 -> 10.9.0.7:5000, 18 bytes of 0x77: `ip id = 0x0004` makes the PPPoE length 4, ppp0 hands the IP stack 2 bytes and `ip_rcv` counts InHdrErrors 1; `ip id = 0x9091` makes `skb->len < length` and `pppoe_rcv` drops the frame before the socket; (0,2) and (1,1) write the PPPoE version/code bytes and the datagram is delivered intact.

**Limitations.** One PPPoE session layout, IPv4 and IPv6 payloads only; not a vulnerability, because the rule needs root in the initial user namespace.

**Details.**

The PPPoE store lands eight bytes before the field it names, and in the
IPv6 branch one cell rewrites the PPP protocol.

No patch is proposed: the offsets it reports are the ones the guard already uses.

Three measurements on Linux 7.3.4, nftables in the bridge prerouting hook,
one rule at a time, one PPPoE session frame at a time.  The frame is a real
one: eth | 0x8864 | PPPoE session (sid 99) | 0x0021 | IPv4/UDP, and the
receiving side is a real PPP unit (`/dev/ppp`: PPPIOCNEWUNIT + PPPIOCATTCHAN +
PPPIOCCONNECT with a PPPoX socket moved to PPPOX_BOUND by PPPIOCGCHAN -- the
pppd sequence, without pppd), a real UDP socket bound on the peer address, and
the kernel's own counters.

1. `meta protocol` repairs the READ and not the STORE.

nft_meta.c, PPPoE branch: `nhoff = PPPOE_SES_HLEN + skb_network_offset(skb)`,
i.e. pkt->nhoff = 8 + 14.  nft_payload_eval() reads at
`skb_network_offset + pkt->nhoff + offset`; nft_payload_set_eval() stores at
`skb_network_offset + offset`.  The two are eight bytes apart, and the whole
`(offset,len)` white list of nft_nh_write_ok_ip4() is written in the
coordinates of the field NAME, not of the byte actually written.

Measured, with the payload `10.1.0.1 -> 10.9.0.7:5000`, 18 bytes of 0x77:

  (4,2) "ip id" = 0x0004      -> the PPPoE length becomes 4; ppp0 hands the
                                 IP stack 2 bytes; ip_rcv counts them and
                                 refuses them (InHdrErrors 1)
  (4,2) "ip id" = 0x9091      -> skb->len < length: pppoe_rcv drops the frame
                                 before the socket (0 bytes reach the stack,
                                 the counter still shows the rule ran)
  (0,2) "ver/ihl", (1,1) "tos"-> the PPPoE version/code bytes; the datagram is
                                 delivered intact
  (8,1) "ttl" = 0x45          -> the byte it writes is already 0x45: delivered
  (8,1) "ttl" = 0x90, (8,2), (10,2) "check", (12,4) "saddr", (16,4) "daddr"
                              -> all land inside the bytes covered by the IPv4
                                 header checksum; ip_rcv reports InHdrErrors
                                 and delivers nothing.  The guard never checks
                                 the checksum; the receiver always does.
  (20,4) the real saddr, (24,4) the real daddr, (6,2) the PPP protocol field
                              -> refused by the white list.  The five refused
                                 cells leave the frame byte-identical to the
                                 control: a refusal is not a drop.

2. `@ll` is bounded by 14 and that boundary is the Ethernet header, not the
   link header of the frame.

  @ll,6,2  allowed (8 <= 14) and it writes the SOURCE MAC.  pppoe_rcv() finds
           the session with __get_item(pn, ph->sid, eth_hdr(skb)->h_source,
           dev->ifindex), so the frame is then dropped: nothing reaches ppp0.
  @ll,13,1 allowed, writes the ethertype's low byte (0x8864 -> 0x88ff).  The
           frame is still delivered -- because the dispatch uses the
           skb->protocol that eth_type_trans() cached BEFORE the hook.  The
           same bytes sent from outside with no rule at all are not PPPoE and
           are not delivered.  The write is visible on the wire and invisible
           to the dispatch.
  @ll,14,2 refused (16 > 14): the PPPoE header is outside the "link header".

3. In the IPv6 branch one cell of the white list changes the PATH of the frame.

  nft_nh_write_ok_ip6() allows offset 7 with len 1 -- offsetof(ipv6hdr,
  hop_limit).  On a PPPoE frame the store is at 14 + 7 = 21, which is the low
  byte of the two-byte PPP protocol field.  With an IPv6 datagram
  (PPP protocol 0x0057) the cell writes 0x90, the protocol becomes 0x0090,
  proto_to_npindex() returns -EINVAL, and ppp_receive_nonmp_frame() queues the
  frame for pppd instead of handing it to the IPv6 stack.  What the kernel
  reports: the unit file yields the whole 68-byte frame, ppp0's
  /proc/net/dev counts 66 bytes received, and Ip6InReceives stays 0.  The
  device says "received", the stack says "nothing".

  The rest of the IPv6 list lands elsewhere too: (0,4) and (2,2) reach the
  PPPoE version/code and the SESSION ID (after which the session lookup fails
  and the frame is dropped); (8,16) -- the cell named saddr -- reaches the
  first 16 bytes of the IPv6 header (version, payload length, next header, hop
  limit, and the first 8 saddr bytes), so the same value is harmless and
  0x90... gives version 9 and Ip6InHdrErrors; (24,16) reaches saddr[8..15] and
  daddr[0..7], after which the destination is no longer local.  IPv6 has no
  header checksum, so nothing here is caught by a checksum: the version check
  and the routing table are the only things standing in the way, and one cell
  (7,1) gets past both by choosing a different protocol number.

4. For completeness: the same ARP frame, vid 100, with and without a VLAN
   device on the bridge.  Without it, the frame is PACKET_OTHERHOST and the
   arp family counter stays 0.  With `v1` (vlan 100 on br0) vlan_do_receive()
   returns true, the frame reaches arp_rcv() through v1 (counter 1), the kernel
   replies with 42 bytes and /proc/net/arp names v1 as the interface.  (8,2)
   on a single-tagged frame does not shift (the tag is already in the skb
   metadata) and really writes sha: the reply goes to the written MAC.

None of this is a privilege boundary: the rule is installed by root in the
initial user namespace.  What is worth a maintainer's look is the shape:
nft_nh_write_ok() is presented as a per-family white list of fields, but the
store is expressed in skb coordinates that do not match the coordinates the
list is written in, and the mismatch is the protocol header length.  The
IPv6 branch has a cell that reaches into another header entirely.

Reported as measurements with the instrument, the logs and the verifier on
disk; every number above is a cell of a table that was generated from the log
and checked back against it.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F43 — `@th` is refused or exact: read and store share `nft_thoff(pkt)`

**Claim.** The transport base has no half-way state: read and store take the same `nft_thoff(pkt)` coordinate, so a cell either lands exactly on the field it names or is refused because `pktinfo` was never built.

**Minimal reproduction.** instrument `differ565`, modes `f565c`, `f565g`, `f565t`, `f565v`; 126 arms × 2 boots, four envelopes (bare, 802.1Q, Q-in-Q, PPPoE) carrying the same IPv4/UDP datagram, one rule at a time at bridge prerouting.

**Run.** `bash vm/build_f43_differ.sh` then `bash code/tools/f43_run.sh` — log marker `F565`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_payload_eval()` and `nft_payload_set_eval()` both use `offset = nft_thoff(pkt)`; `pkt->thoff = skb_network_offset + nhoff + iph->ihl*4`, and the only question is whether `NFT_PKTINFO_L4PROTO` was built.

**Actual.** 8 cells per block: bare Ethernet 8/8 live, 802.1Q 8/8, Q-in-Q 0/8 without `meta protocol` and 8/8 with it (sport at frame bytes 38..39), PPPoE 0/8 without and 8/8 with it (bytes 42..43). The store lands exactly on the named field in every live cell.

**Limitations.** `@th` in the inet and netdev families, where `thoff` is built by other constructors (F44/F45).

**Details.**

The transport base is the one base with no half-way state — and the
checksum it never pays for.

No patch is proposed: the measurement names a cost the rule can pay (`csum type inet`)
and does not change the code that charges it.

Six measurements on Linux 7.3.4, nftables in the bridge prerouting hook, one
rule at a time, one frame at a time.  Four envelopes carry the same
IPv4/UDP datagram (10.1.0.1 -> 10.9.0.7:5000, 18 bytes of 0x77): bare
ethernet, one 802.1Q tag, Q-in-Q (0x88a8 + 0x8100), and a real PPPoE session
(eth | 0x8864 | sid 99 | 0x0021 | IPv4).  The receiving side is a real PPP
unit (`/dev/ppp`: PPPIOCNEWUNIT + PPPIOCATTCHAN + PPPIOCCONNECT, the PPPoX
socket moved to PPPOX_BOUND by PPPIOCGCHAN -- the pppd sequence without pppd),
two real UDP sockets (the original port and the port the rule writes), and the
kernel's own counters.  126 arms x 2 boots, byte-identical.

1. `@th` is exact or dead.  There is no third state.

nft_payload_eval() and nft_payload_set_eval() both take
`offset = nft_thoff(pkt)` for NFT_PAYLOAD_TRANSPORT_HEADER, and pkt->thoff is
built by one function, __nft_set_pktinfo_ipv4_validate():

        pkt->thoff = skb_network_offset(skb) + nhoff + iph->ihl*4

with the IP header read at `skb_network_offset + nhoff`.  Read and store share
the coordinate; the only question is whether pktinfo was built at all
(NFT_PKTINFO_L4PROTO).  Measured, 8 cells per cell block, two gates:

  envelope                     no `meta`   with `meta protocol`   the sport cell
  bare ethernet                 8/8 live        8/8 live          bytes 34..35
  802.1Q vid 100                8/8 live        8/8 live          bytes 34..35
  Q-in-Q 0x88a8+0x8100          0/8 live        8/8 live          bytes 38..39
  PPPoE session                 0/8 live        8/8 live          bytes 42..43

No cell is ever "half alive": none of the 64 grid cells is accepted and then
writes a byte other than the one its (offset,len) names.

2. A single 802.1Q tag does not shift the transport base at all.

skb_vlan_untag() runs in __netif_receive_skb_core() before any hook: the tag
goes to skb->vlan_tci, skb_reorder_vlan_header() moves the two MAC addresses
over it, and vlan_set_encap_proto() rewrites skb->protocol.  So at the hook the
frame has no tag in its bytes and `eth_hdr(skb)->h_proto` is already the inner
ethertype: nft_do_chain_bridge() takes the IPv4 branch on a tagged frame
without any help.  The 802.1Q column is the bare column, cell for cell, with
and without `meta protocol` -- and `meta protocol` is a no-op there because
nft_meta_pktinfo_may_update() returns at once when pkt->flags is set.

Q-in-Q keeps the inner tag in the bytes, so `eth_hdr()->h_proto` is 0x8100 and
the whole base is dead until `meta protocol` reads the encapsulated proto at
mac+16 and rebuilds pktinfo with nhoff = VLAN_HLEN.  PPPoE is the same story
with nhoff = PPPOE_SES_HLEN = 8.  Both then land on the true transport header.

3. The TCP doff guard is in the corrected coordinate system.

nft_th_write_ok() refuses cells overlapping `offsetof(struct tcphdr, ack_seq)
+ 4 = 12`.  On a TCP segment inside PPPoE with `meta protocol` exactly the same
four cells are refused as on a bare frame -- (10,4) (12,1) (12,2) (12,4) --
because thoff is now the real TCP header.  Without `meta protocol` all six
cells are refused: pktinfo is never built.  The guard cannot be fooled by the
envelope the way nft_nh_write_ok_ip4() is, where the list is written in the
coordinates of the field name and the store is not (F42).

4. Three bases, one cell, one packet.

The same `(offset,len) = (0,2)` store on the same PPPoE frame, with `meta
protocol`:

  @ll,0,2   accepted, changes frame bytes 0..1     (destination MAC)
  @nh,0,2   accepted, changes frame byte 15         (PPPoE ver/type+code; the
                                                     first byte stays 0x11 by
                                                     the case-0 value check)
  @th,0,2   accepted, changes frame bytes 42..43    (the real UDP sport)

Three coordinate systems in one packet.  The receiver separates them: the
frame whose destination MAC was rewritten never reaches the IP stack
(IpInDelivers 0, no datagram), while the frame whose PPPoE header was rewritten
is delivered intact -- pppoe_rcv() never looks at ver/type or code at all: it
gates on the length field and finds the session by
`__get_item(pn, ph->sid, eth_hdr(skb)->h_source, dev->ifindex)`.

5. `@th` can never reach the header that shifted it.

The smallest frame byte an accepted `@th` store touches is 42 on PPPoE and 38
on Q-in-Q, while the PPP protocol field sits at 20..21 and the inner Q-in-Q tag
at 16..19.  The store offset is thoff + priv->offset, offset >= 0, and thoff
already includes nhoff: the base is *behind* the header that moved it.  That is
why the 0xc000+ PPP protocol branch (pppd's channel queue) is unreachable from
a bridge rule through `@th` -- not for lack of a whitelist entry.

6. The checksum is a wall the guard does not see, and CSUM_INET is the toll.

A datagram with a real UDP checksum (0x08ad) and `@th,2,2` rewritten to port
5001:

  arm                            wire dport  csum   valid  UdpInErrors  delivered
  control                           5000     08ad    yes       0        5000
  store only                        5001     08ad    no       2 / 1    nowhere
  store + CSUM_INET (offset 6)      5001     08ac    yes      0        5001
  sport -> 0x9999 + CSUM_INET       5000     0b54    yes      0        5000
  store into the checksum field     5000     9091    no       2 / 1    nowhere
  the same + CSUM_INET              5000     9091    no       2 / 1    nowhere
  payload byte + CSUM_INET          5000     ef92    yes      0        5000
  payload byte, no CSUM_INET        5000     08ad    no       2 / 1    nowhere

The first line is the point: the guard accepts, the coordinates are exactly
right, the byte on the wire is the one the rule names -- and the receiver drops
the datagram, because the rule rewrote a field covered by the transport
checksum and did not pay for it.  (2 / 1: the bare frame is delivered twice,
once to the local stack and once up from the bridge; the PPPoE frame once.)

CSUM_INET is a separate action, not a consequence of the store:
`csum_offset = offset + priv->csum_offset` (thoff + 6) while the store is
`offset + priv->offset` -- two different bytes of the same expression, and the
0x08ad -> 0x08ac difference is exactly the 5000 -> 5001 increment.

And a store into the checksum field itself cannot be saved: the checksum
update runs first (nft_payload_csum_inet() -> skb_store_bits() of the field)
and skb_store_bits() of the payload follows, so the field ends up holding
exactly the immediate (0x9091 measured), and the datagram dies either way.
Order in one branch, measured rather than inferred.

7. IPv6 has no "not computed", so every unpaid transport write is fatal.

The same frame over IPv6 inside PPPoE (UDP header at byte 62): without `meta
protocol` the cells do not run and the datagram is delivered untouched; with
it, all four cells run and every one of them kills the datagram
(Udp6InErrors +1, nothing delivered).  With CSUM_INET at offset 6 the dport
rewrite is delivered to the *written* port.

Not a vulnerability: the rule is installed by root in the initial user
namespace.  The consequences are: a store that lands exactly in the field it
names and still destroys the datagram; a store into the checksum field that no
amount of checksum maintenance can save; and a dead cell block on any envelope
that moved the transport header, revived or not by one expression earlier in
the chain.

Not measured here: `@th` in the inet and netdev families, where thoff is built
by two other functions (nft_set_pktinfo_ipv4() uses ip_hdrlen() without
skb_network_offset, ..._ingress() uses ihl*4); a tagged PPPoE frame; SCTP and
ICMP checksum types; CHECKSUM_PARTIAL/GSO; the pseudo-header flag
(NFT_PAYLOAD_L4CSUM_PSEUDOHDR) on a saddr/daddr store; conntrack and
defragmentation.

Files: `vm/differ565_add.c`, `tools/verify565.py` (884 checks),
`tools/verify565_selftest.sh` (18/18 mutations).

---

## F44 — four pktinfo constructors, one coordinate

**Claim.** The four `pktinfo` constructors produce one coordinate: whether `thoff` is computed relative to `skb->data` or absolute, it lands on the same wire byte at every door, because `skb->data` is the network header at these hooks.

**Minimal reproduction.** instrument `differ566`, modes `diag`, `dp`, `gd`, `md`, `rf`, `td`, `tm`; 348 arms × 2 boots, four doors (ip L3, inet L3, netdev ingress, inet ingress) with two base chains per door, `@th` read and store per cell.

**Run.** `bash vm/build_f44_differ.sh` then `bash code/tools/f44_run.sh` — log marker `F566`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_set_pktinfo_ipv4()` gives `thoff = ip_hdrlen(skb)`; `__nft_set_pktinfo_ipv4_validate()` gives `skb_network_offset + nhoff + ihl*4`; the ingress constructor gives `ihl*4`; the bridge one uses the validate constructor. `skb->data` is the network header at these hooks.

**Actual.** Eight `@th` cells per door and envelope: the store is accepted and the byte read back is the same on all four doors; the two constructors' coordinates coincide on every cell.

**Limitations.** IPv6 (F45) and the egress doors (F46).

**Details.**

The ingress hook has two doors and they disagree — one of them rewrites
`pf` before the guard reads it.

No patch is proposed: this is a measurement of the guard's input, not a change to it.

Four doors, one frame at a time, one rule at a time, Linux 7.3.4 with nftables
in the initial user namespace.  The doors are the layer-3 hook of family `ip`,
the layer-3 hook of family `inet`, family `netdev` at the ingress hook of a
device, and family `inet` at the ingress hook of the same device.  Two base
chains per door, at priorities 0 and 10 for family `inet` and 40 and 50 for
family `netdev`: the first chain is `counter` + `log` + `accept` and says
whether the hook ran at all, the second carries the `payload` statement and
says whether the guard accepted it.  The logged payload is what
`skb_copy_bits(skb, 0, …)` sees at the hook -- i.e. the frame starting at
`skb->data` -- so the byte a store wrote is read back from the same skb the
rule ran on.  The receiving side is a real PPP unit, two UDP sockets and the
kernel's own counters.  348 arms x 2 boots, byte-identical.

1. Four pktinfo constructors, one coordinate.

        nft_set_pktinfo_ipv4()          pkt->thoff = ip_hdrlen(skb)
        __nft_set_pktinfo_ipv4_validate() pkt->thoff = skb_network_offset(skb) + nhoff + ihl*4
        nft_set_pktinfo_ipv4_ingress()  pkt->thoff = ihl*4
        nft_set_pktinfo_bridge()        the validate one

The first is relative to `skb->data`, the second absolute; both land on the same
wire byte because `skb->data` IS the network header at every one of these hooks
(veth calls eth_type_trans() before netif_rx(), and __netif_receive_skb_core()
does skb_reset_network_header()).  Measured, eight `@th` cells per door and
envelope, `@th` read and `@th` store:

  door            envelope                      hook ran   store accepted
  ip / inet L3    bare, vid 0, PPPoE            2/2/1       8/8 each
  ip / inet L3    802.1Q vid 100                no          -
  ip / inet L3    Q-in-Q (0x88a8+0x8100)        no          -
  netdev ingress  bare, vid 100, vid 0          1           8/8 each
  netdev ingress  Q-in-Q, PPPoE                 1           0/8   (flags = 0)
  inet ingress    bare, vid 100, vid 0          1           8/8 each
  inet ingress    Q-in-Q, PPPoE                 no          -

Every accepted store landed on `data + ihl*4 + off` -- the true transport
header.  The "not reached" rows are not guard refusals: the first chain's
counter is zero, and the frame never appears at that hook (a vid-100 tagged
frame without a vlan device is PACKET_OTHERHOST at ip_rcv(); a Q-in-Q frame
never reaches the IPv4 stack; and nft_do_chain_inet_ingress() returns NF_ACCEPT
for any skb->protocol that is not 0x0800/0x86dd without running the chain).
`meta protocol` repairs the netdev door on Q-in-Q (nhoff 4) and PPPoE
(nhoff 8) -- 8/8 each, at `data+24` and `data+28` -- and cannot repair the inet
door, because the expression sits inside a chain that is never entered.

2. The guard reads a field that the handler rewrites.

nf_register_net_hook() registers an `inet` hook op twice, under NFPROTO_IPV4
and NFPROTO_IPV6, leaving ops->pf as NFPROTO_INET; at packet time state->pf is
whatever the caller of NF_HOOK passed.  At the ingress hook that caller is
nf_ingress(), i.e. NFPROTO_NETDEV -- and nft_do_chain_inet_ingress() overwrites
it before the rules run:

        ingress_state.pf   = NFPROTO_IPV4;
        ingress_state.hook = NF_INET_INGRESS;

Both guards read that field:

        nft_nh_write_ok():  case NFPROTO_NETDEV: if (hook == NF_NETDEV_INGRESS) return true;
        nft_in_ingress():   s->pf == NFPROTO_NETDEV && s->hook == NF_NETDEV_INGRESS

so the same frame at the same hook number on the same device gets two different
answers.  Measured, bare frame, both ingress doors in one boot:

        base    netdev ingress      inet ingress
        @ll     12/12               7/12  (refused: (12,4) (14,2) (16,2) (20,4) (24,4))
        @nh     20/20               9/20  (exactly nft_nh_write_ok_ip4(): (0,1) (0,2) (0,4)
                                          (2,2) (4,4) (6,2) (6,4) (8,2) (18,2) (20,2)
                                          (20,4) refused; (1,1) (4,2) (8,1) (10,2) (10,4)
                                          (12,2) (12,4) (16,2) (16,4) accepted)
        @th     8/8                 8/8

`@ll` at the inet door degrades to `offset <= skb_network_offset()`, so exactly
the cells whose write reaches past the link header are refused.  The "ingress
is a constant" of the earlier analysis is a property of the netdev *branch*,
not of the hook.

3. The two ingress doors share one hook list, and the inet one can drop the
   frame before any rule of either family runs.

nft_set_pktinfo_ipv4_ingress() validates and returns -1, and
nft_do_chain_inet_ingress() turns that into NF_DROP *before* nft_do_chain().
Since both doors are entries of dev->nf_hooks_ingress, an inet ingress chain
drops a malformed IPv4 frame ahead of a netdev chain on the same device:

  frame (0x0800 carried, bad header)   inet ingress chain present   deleted
  version 6                            netdev counter 0, no far     counter 1,
                                       frame, InHdrErrors +1        forwarded,
                                                                    InHdrErrors +2
  ihl = 4                              same                         same
  iph->totlen 300 > skb->len           same, but InTruncatedPkts    same
                                       +1 (the constructor checks
                                       length before the checksum)

A tool that counts a chain's packets is therefore measuring, in part, the other
tables on the same device.  For anyone debugging a missing packet at ingress
this is worth knowing: the drop reason is not visible in the counted chain, and
the only trace is an IP counter being incremented by a rule-less hook.

4. The wire.

A store at the layer-3 doors lands on the copy the bridge passed up to br0, not
on the forwarded skb, so the far frame is unchanged (measured: zero changed
bytes at the far tap for all 16 store arms there).  A store at either ingress
door lands on the skb that is then bridged and is visible (a dport write:
bytes 36..37 for a bare frame; the datagram arrives at the written port, 2
copies).  And the tag path has its own edge: writing `@ll,12,2 = 0x9091` stores
skb->vlan_proto, vlan_hw_offload_capable() does not know 0x9091, and
validate_xmit_vlan() puts the tag back into the frame bytes on the way out --
the frame grows from 60 to 64 bytes while nft believes it wrote a header field.

Reproduction: one static C program (~1100 lines, netlink by hand), busybox
initramfs, two boots; every byte quoted above is extracted from the log by an
independent Python model of the four constructors and the four guards (1692
checks), and every table in the report is generated from the log rather than
typed.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F45 — IPv6 does not compute `@th`, it walks for it

**Claim.** IPv6 builds the transport coordinate by walking extension headers (`ipv6_find_hdr()`), not by a formula; the coordinate is right when the walk succeeds, and the walk's three failure modes carry three different verdicts at the doors.

**Minimal reproduction.** instrument `differ567`, ten modes; 524 arms × 2 boots, five doors (ip L3 as control, ip6 L3, inet L3, netdev ingress, inet ingress), eight `@th` cells per door and envelope, plus extension-header frames.

**Run.** `bash vm/build_f45_differ.sh` then `bash code/tools/f45_run.sh` — log marker `F567`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_set_pktinfo_ipv6()` walks with `ipv6_find_hdr(..., IP6_FH_F_AUTH)`; the validate constructor walks after a version and payload-length check; the ingress constructor returns -1 on failure, which becomes NF_DROP.

**Actual.** The coordinate follows the walk and equals the `skb_copy_bits()` offset wanted; the three failures (a bad version, a truncated header, an unknown next header) are refused at the validate doors and dropped at the ingress door.

**Limitations.** IPv6 fragments and the egress half; the `@nh`/`@ll` bases in IPv6 are F47-F59.

**Details.**

The IPv6 constructor that walks -- one coordinate, three failures, and a
validation that runs before the hook.

No patch is proposed: this is the IPv6 half of the same measurement and it proposes no
change to a line of code.

Linux 7.3.4, nftables in the initial user namespace, one frame at a time, one
rule at a time.  Five doors: family `ip` layer-3 (a control -- an IPv6 frame
never arrives there), family `ip6` layer-3, family `inet` layer-3, family
`netdev` at the ingress hook of a device, and family `inet` at the ingress hook
of the same device.  Two base chains per door (priority 0/10), the first is
`counter` + `log` + `accept` and says whether the hook ran, the second carries
the `payload` statement and says whether the guard accepted it.  The logged
payload is the frame at `skb->data` after the store, so every written byte is
read back from the same skb the rule ran on.  The receiving side is IPv6/UDP
sockets and the kernel's own Ip6 counters.  524 arms x 2 boots, byte-identical.

This is the IPv6 counterpart of the IPv4 measurement: F44 showed that `@th` has
one coordinate across four doors because IPv4 computes it as a formula
(`ihl*4`).  IPv6 does not compute it, it walks.

1. The coordinate follows the walk, and it is the right one.

        nft_set_pktinfo_ipv6()          thoff = ipv6_find_hdr(skb, &thoff=0, -1, &fragoff, IP6_FH_F_AUTH)
        __nft_set_pktinfo_ipv6_validate() the same walk, after a version and payload-length check
        nft_set_pktinfo_ipv6_ingress()  the same walk, but a failure returns -1 -> NF_DROP

`ipv6_find_hdr()` starts at `skb_network_offset(skb) + sizeof(struct ipv6hdr)`
and returns the offset of the byte after the last extension header, measured
from the same origin.  `skb_network_offset()` is `network_header - data`, which
is zero at all of these hooks, so the value the walk returns is exactly the
`skb_copy_bits()` offset wanted -- the same arithmetic that makes the IPv4
relative and absolute formulas agree.

Measured, eight `@th` cells per door and envelope, envelope = bare / hop-by-hop
/ destination-options / hop-by-hop+destination-options:

  door            bare   +8 byte ext   +16 byte ext   bare store lands at
  ip6 / inet L3   8/8    8/8           8/8            data+40+off
  netdev ingress  8/8    8/8           8/8            data+40/48/56+off
  inet ingress    8/8    8/8           8/8            data+40/48/56+off

128 of 128 cells accepted, and on the write side every one landed on the true
transport header: with one 8-byte header the store for offset 0 lands on frame
bytes 62..63, with two on 70..71.  Reads agree with writes (sport, dport, udp
length: 3/3 on both doors and both envelopes).

2. A non-first fragment makes `thoff` zero, and nothing can see it.

        if (nexthdr == NEXTHDR_FRAGMENT) {
                ... if (_frag_off) {
                        if (target < 0 && (!ipv6_ext_hdr(hp->nexthdr) || hp->nexthdr == NEXTHDR_NONE)) {
                                if (fragoff) *fragoff = _frag_off;
                                return hp->nexthdr;          /* *offset is NOT written */
                        }

For a fragment with a non-zero offset, `ipv6_find_hdr()` returns from inside
the loop without assigning `*offset`, so `pkt->thoff` keeps its initial 0 while
the transport header is at 48.  It is invisible: `nft_payload_eval()` and
`nft_payload_set_eval()` both refuse base `th` when `pkt->fragoff` is set, and
that is exactly the case in which the coordinate is wrong -- 0/8 cells accepted
on all four doors.  A first fragment (offset 0) behaves like a plain packet:
8/8, and the datagram is delivered.

3. A packet with no transport header has a `tprot`.

`nexthdr = 59` (NEXTHDR_NONE, no payload): the walk succeeds with
`thoff = 40`, `pkt->flags` gets NFT_PKTINFO_L4PROTO, `pkt->tprot = 59`.  The
`@th` guard therefore accepts (59 != TCP) and the store dies one line later in
`skb_ensure_writable(40+len)` against a 40-byte packet: 0/8 accepted, on every
door.  `meta l4proto` returns 59 for this packet -- a rule `meta l4proto 59
counter` fires on a packet that has no upper-layer header at all, while the
same expression on a packet whose extension-header walk failed does not fire
(no NFT_PKTINFO_L4PROTO).  The kernel does count such a packet in
Ip6InDelivers and hands it to nobody.

4. Three doors, three failure modes, one malformed frame.

Four malformed frames, and the counters are unambiguous:

  frame                        inet ingress  netdev ingress   ip6/inet L3
  payload_len 512, real 26     0/0  (InTrunc) 1/1, th 0/2    0/0  (InTrunc)
  hop-by-hop hdrlen 15, 8 real 0/0  (InHdr)   1/1, th 0/2    0/0  (InHdr)
  dest-opts  hdrlen 15, 8 real 0/0  (InHdr)   1/1, th 0/2    1/1, th 0/2
  nexthdr 59, no payload       1/1, th 0/2    1/1, th 0/2    1/1, th 0/2

Column 1 is the inet-ingress handler returning NF_DROP before `nft_do_chain()`
(Ip6InReceives does not move: the stack never sees the frame).  Column 2 is
`__nft_set_pktinfo_ipv6_validate()` failing and `nft_set_pktinfo_unspec()`
letting the chain run: counter 1, no `@th` store.  Column 3 is the surprise:
two of these frames never reach the layer-3 hook at all, because
`ip6_rcv_core()` -- which runs before NF_INET_PRE_ROUTING -- already checks the
version, `payload_len + sizeof(*ip6h) > skb->len`, and, for nexthdr 0,
`ipv6_parse_hopopts()`.  The `unspec` branch of `nft_set_pktinfo_ipv6()` is
reachable at layer 3 only through an error `ip6_rcv_core()` does not look at:
a malformed extension header that is not hop-by-hop.  One byte of next-header
value (0 vs 60) decides whether the chain runs at all.

5. `@nh` for IPv6: a white list that reads a constant, and a constant that
   reads nothing.

  door                    live cells of 19
  netdev ingress          19/19
  ip6 / inet L3, inet ingress   9/19  (exactly nft_nh_write_ok_ip6()'s branches)

`nft_nh_write_ok_ip6()` case 0 is `length <= 4 && ih->version == 6`, i.e. it
reads a constant out of the register, while `nft_nh_write_ok_ip4()` case 0
compares the value with the packet's own first byte.  So on the IPv6 side, a
store of 0x90 into offset 0 is refused on the three whitelisted doors and
accepted on the netdev ingress door (which returns true unconditionally at
NF_NETDEV_INGRESS) -- and the packet then dies in `ip6_rcv_core()`:
Ip6InHdrErrors.  Same door, a 4-byte store at offset 2 or a 2-byte store at
offset 4 rewrites `payload_len` and the packet dies with Ip6InTruncatedPkts.
a store at offset 6 rewrites `nexthdr` and it dies with Ip6InUnknownProtos.

And a store into `saddr`/`daddr` is whitelisted on every door (offset 24, len
<= 16).  At layer 3 the hook has already passed `ip6_rcv_core()`, so no
validation happens afterwards; but the route lookup for a received packet runs
in `ip6_rcv_finish()`, i.e. AFTER NF_INET_PRE_ROUTING returns.  A rule that
rewrites `daddr` therefore adresses the packet to nowhere: it is neither
delivered nor counted by any readable Ip6 counter.  Four doors, one rule,
one silent loss.

6. One chain, one rule, two families.

A single base chain in family `inet` at prerouting, one `@nh` store, two
frames:

  cell                 IPv6   IPv4      reason
  offset 2, len 2      store  refuse    case 2 is in the ip6 list only
  offset 4, len 2      refuse store     offsetof(iphdr, id) is in the ip4 list only
  offset 7, len 1      store  refuse    hop_limit vs nothing
  offset 0, len 2 60 00  store refuse   ih->version == 6
  offset 0, len 2 45 00  refuse store   same-store-as-packet-byte

and `@th` in the same chain stores at `data+40+off` for the IPv6 frame and at
`data+20+off` for the IPv4 one.  The verdict and the coordinate are properties
of the packet's family, not of the rule.

Not tested: PPPoE carrying extension headers, routing and AH headers
(IP6_FH_F_AUTH stops the walk at AH), 12+ extension headers, IPv6 at
local_in/forward/post_routing, GSO/CHECKSUM_PARTIAL, VLAN-bits offload
combinations.  Every rule here is installed by root in the initial user
namespace; nothing in this report is a privilege boundary crossing.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F46 — `@ll` depends on who built the skb, not on the door

**Claim.** The link-layer base is resolved from `skb_mac_header()` and refused outright when the MAC header was never set, so away from the receive path the same offset is live, dead or erased according to the traffic class that built the skb.

**Minimal reproduction.** instrument `differ568`, seven modes; 428 arms × 2 boots, six doors (inet local_out, postrouting, forward, prerouting, input and netdev egress), three traffic classes, twelve `@ll` cells each.

**Run.** `bash vm/build_f46_differ.sh` then `bash code/tools/f46_run.sh` — log marker `F568`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `@ll` stores are resolved as `skb_mac_header(skb) - skb->data` and refused when `skb_mac_header_was_set()` is false; the header checksum is computed before the hook.

**Actual.** Twelve cells per door and class: local datagrams 0/12 at local_out, postrouting 0/12; forwarded frames 10/12 at postrouting, forward and prerouting with the store erased for one class; delivered frames 10/12 at prerouting and input. The receiving bytes and counters agree.

**Limitations.** Tunnels and devices without an Ethernet header (F49/F50); GSO/CHECKSUM_PARTIAL is F60/F61.

**Details.**

The header checksum is computed before the hook -- who pays for a write
at an egress door, and a repair that is skipped in silence.

This is a measurement, not a fix: nothing below changes a line of code, and the
one repair it describes (`csum type inet`, `csum_offset 10`) already exists. It
asks one question about the report quoted above -- what the store guard means
away from the receive path -- and answers it with bytes at the receiver.

Linux 7.3.4, nftables in the initial user namespace, one packet at a time, one
rule at a time.  Six doors: family `inet` at local_out, postrouting, forward,
prerouting and input, and family `netdev` at the egress hook of a veth device.
Three traffic classes: a datagram generated by a local socket, a frame
injected on the wire and forwarded to a receiving netns, and a frame injected
on the wire and delivered locally.  Two base chains per door (priority
0/10): `counter` + `log` + `accept`, and the `payload` statement.  The
receiving side is a real netns with its own UDP socket and AF_PACKET tap, so
every arm ends in bytes on a wire and in the receiving kernel's counters.
428 arms x 2 boots, identical on every derived fact.

F44/F45 measured five ingress doors.  This is the other half of the geography.

1. Where the MAC header is.

`@ll` stores are resolved as `skb_mac_header(skb) - skb->data` and refused
outright when `skb_mac_header_was_set()` is false.  Measured on twelve cells:

  door            local datagram     forwarded frame     delivered frame
  local_out       0/12               --                  --
  postrouting     0/12               10/12, erased        --
  forward         --                 10/12, erased        --
  prerouting      --                 10/12, erased       10/12
  input           --                 --                  10/12
  netdev egress   10/12 on the wire  10/12 on the wire   --

Two facts hide in that table.  (a) A locally generated packet has no MAC
header at a layer-3 hook: `eth_header()`/`neigh_hh_output()` run *after*
postrouting and `__dev_queue_xmit()` calls `skb_reset_mac_header()` as its
first statement -- so at local_out and postrouting all twelve cells are dead,
while the same chain at the egress hook accepts ten.  (b) At forward and
postrouting a forwarded frame *has* a MAC header and the guard accepts the
store, but the store is written into the header the stack is about to rewrite:
measured `rchg = 0` for all ten accepted cells -- the frame on the wire is
byte-identical to the control.  The only door where an L2 store reaches the
wire is the one after `eth_header()`.

The `NFULA_L2HDR` attribute is *not* an oracle for this: nfnetlink_log emits
it only when `skb_mac_header_len(skb) > 0`, and in the receive path
`skb_reset_mac_len()` runs before `eth_type_trans()` pulls the header, so
`mac_len` is 0 on frames that do have a MAC header.

2. The coordinate is exact where the base is exact, and the price is a
   checksum computed before the hook.

At all five layer-3 hooks `nft_set_pktinfo_ipv4()` sets `nhoff = 0` and
`thoff = ip_hdrlen()`, and `skb_network_offset()` is 0, so `@nh` reads and
writes are the same bytes -- measured with six read-only cells and the
store/read pairs.  What changes between the doors is not the coordinate but
who has already computed the checksums:

  __ip_local_out():  ip_send_check(iph)   BEFORE nf_hook(LOCAL_OUT)
  ip_forward():      ip_decrease_ttl()    BEFORE nf_hook(FORWARD)   (recomputes it)
  ip_rcv():          ip_rcv_core()        BEFORE nf_hook(PRE_ROUTING) (checks it)

A one-byte store into `@nh,8,1` (ttl = 0x90), one cell, six doors:

  local_out, postrouting, forward, egress -> the receiver's ip_rcv drops the
      frame: IpInReceives +1, IpInHdrErrors +1, no delivery, chain counter 1;
  prerouting, input -> delivered, and *no* counter anywhere moves: the header
      checksum was verified before the hook and nobody looks again.

The same cell costs a packet or nothing depending on the door, and the rule,
the guard and the counter say the same thing in both cases.

3. The repair exists, is incremental, and is skipped in silence.

`payload` can carry `csum type inet` with `csum_offset`; for a network-header
store the only offset that is honoured is `offsetof(struct iphdr, check)`,
which is **10**, not 12 as one might guess from `saddr`.  With 10:

  r_ttl10   ttl 0x40->0x90, csum_offset 10  -> field becomes the correct one,
                                                the datagram is delivered
  r_ttl12   the same store, csum_offset 12  -> field unchanged, InHdrErrors
  r_tos10   tos 0x00->0x90, csum_offset 10  -> field becomes a WRONG value,
                                                InHdrErrors
  r_chk10   store into the checksum itself  -> the repair is computed first
                                                and then overwritten by the
                                                immediate, InHdrErrors

`r_ttl10` and `r_tos10` are the same one-byte store of the same value with
the same repair, differing only in the offset (8 against 1): the incremental
replacement writes a correct checksum for an even offset and a wrong one for
an odd offset.  And `csum_offset` that is not 10 is not an error:
`nft_payload_csum_nh_write_ok()` returns false inside an `&&` chain in
`nft_payload_set_eval()`, so the store happens with no repair and no
diagnostic, and the packet dies at the receiver instead.

4. The transport checksum is paid by somebody else.

The same eight `@th` cells, two classes, one egress door:

  locally generated datagram: 5/8 delivered, UdpInErrors 1, and the three
      others are not the checksum at all (a written port with no socket twice,
      a written UDP length once); the checksum field on the wire is NOT a
      valid checksum -- the skb leaves the hook with CHECKSUM_PARTIAL and veth
      carries the flag to the peer, so the receiver never verifies it, and a
      store into the source port changes the delivered datagram;
  frame that arrived from the wire: 0/8 delivered, UdpInErrors 8 -- the
      checksum was final when the hook ran.  `csum type inet` with
      `csum_offset 6` repairs it and the datagram is delivered to the written
      source port.

So the toll for a transport write is not a property of the door: it is the
skb's `ip_summed`, which is decided by who built the packet.

5. A destination written before the route lookup is a different packet.

One cell, `@nh,16,4` (daddr = 90 91 92 93), five doors:

  postrouting, forward (forwarded)  no frame on the wire at all: the neighbour
                                    lookup in ip_finish_output2() uses the
                                    packet's own daddr, finds no entry and the
                                    packet dies in an unresolved ARP queue;
  egress                            the frame goes out (the L2 header and the
                                    neighbour are already resolved) and dies at
                                    the receiver with InHdrErrors;
  prerouting                        the route lookup has not run yet, so the
                                    packet leaves local delivery: InDelivers 0,
                                    InNoRoutes +1, no UDP error at all;
  input                             the route is already resolved: the packet
                                    is delivered to udp_rcv and dropped there
                                    (the pseudo-header) -- UdpInErrors +1.

Every one of those five outcomes has the same rule, the same accepted store
and the same chain counter of 1.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F47 — a hop-limit store at `@nh` is free at six of seven egress door/class pairs

**Claim.** The IPv6 network-base list has no case for offset 4 and none for offset 6, so a payload-length or next-header store is refused everywhere while a hop-limit store is free at six of the seven door/class pairs.

**Minimal reproduction.** instrument `differ569`, mode `iso`; 112 arms × 2 boots, six doors and two classes, `@nh` cells per door with the frame's bytes and the receiving socket as witnesses.

**Run.** `bash vm/build_f47_differ.sh` then `bash code/tools/f47_run.sh` — log marker `F569`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** The IPv6 branch of `nft_nh_write_ok()` is a switch with `case 0` comparing the version nibble, `case 2`, `case 8`, `case 24`; there is no case for 4 or 6.

**Actual.** `@nh,4,2` (payload_len) and `@nh,6,1` (next header) are refused at every door; `@nh,7,1` (hop limit) is accepted at six of seven door/class pairs and the datagram is delivered with the stored value; `@nh,0,4` with a non-6 version nibble is refused.

**Limitations.** Only the cells listed in the section; TCP and tunnels were not measured.

**Details.**

What a network-base store costs in IPv6 -- there is no header checksum,
so the toll moves to the hop limit, and two offsets have no case at all.

No patch is proposed: this measures the guard as it stands and proposes no change.

Linux 7.3.4, nftables in the initial user namespace, one packet at a time, one
rule at a time.  Six doors (local_out, postrouting, forward, prerouting, input
and the netdev egress hook of a veth), two classes (a datagram from a local
IPv6 socket, and a frame injected on the wire and forwarded), two base chains
per door (counter+log+accept, and the payload statement).  The receiver is an
IPv6 socket in its own netns plus that namespace's Ip6/Udp6 counters.
112 arms x 2 boots, identical on every derived fact.

1. The IPv6 network-base list has no case for offset 4 and none for 6.

  @nh,0,4  60 91 92 93  accepted (the written version nibble is 6)
  @nh,0,4  90 91 92 93  refused  -- case 0 compares the *immediate's* version
  @nh,2,2               accepted (flow label)
  @nh,4,2  payload_len  refused  -- no case for offset 4
  @nh,6,1  next header  refused  -- no case for offset 6
  @nh,8,16 saddr        accepted (the list allows len <= 32 here)
  @nh,24,16 daddr       accepted

The refusals are identical at all five layer-3 hooks and at the netdev egress
hook: unlike the ingress side, nothing here depends on the family the hook was
registered with.  A refused store is not a drop -- the packet continues and is
delivered byte-identical to the control.

2. With no header checksum the price of a header store mostly disappears.

One byte into @nh,7,1 (the hop limit), four values, seven door/class pairs:

  hop limit written   64 (as the frame carries it)  delivered everywhere
                      0x90                         delivered everywhere
                      0x00 / 0x01                  delivered at six pairs,
                                                   NO FRAME at prerouting

On IPv4 the same store killed the packet at four doors, because the header
checksum is computed before LOCAL_OUT and verified before PREROUTING.  IPv6 has
no such checksum, so the only thing that can charge for the store is the
forwarding path itself: `ip6_forward()` tests `hop_limit <= 1` *before* it
enters the FORWARD hook.  A store at PREROUTING is therefore seen by that test
and the packet dies in `ip6_forward()`; a store at the FORWARD hook happens
after the test and the frame is forwarded with a hop limit of zero.

The hop limit is decremented in the same gap, and the wire shows it: written at
prerouting, 0x40 leaves as 0x3f and 0x90 as 0x8f; written at forward,
postrouting or the egress hook, the value written is the value on the wire.
the read side sees the same seam -- reading @nh,7,1 and comparing with 0x40
matches at the doors the packet has not been forwarded through yet and matches
nowhere after it, because the byte there is 0x3f.

3. The transport toll is now the UDP pseudo-header, and it belongs to the skb.

One cell, @nh,8,16 = fd00::99, and its control (writing the address the frame
already carries):

  locally generated datagram   both delivered -- the skb leaves the hook with
                               CHECKSUM_PARTIAL and veth carries the flag to
                               the peer, which therefore never verifies it
  frame from the wire          the store costs the datagram: Udp6InErrors at
                               the receiver, no delivery; the control with the
                               same 16 bytes is delivered

Measured from the bytes, the wire field of a locally generated datagram is not
a valid checksum at all (fa2f where the pseudo-header gives 8220), and that is
true of the control arm as well -- it is a property of the sender, not of the
store.

4. A destination written before the route lookup stops being your datagram.

@nh,24,16 = fd00::99 at seven door/class pairs: the store is accepted
everywhere, and then

  local_out, postrouting   the packet is routed to the written address before
                           the route lookup, no neighbour exists, and the door
                           counts EIGHT packets for one datagram (the
                           solicitation retries and the ICMP errors of that
                           queue); nothing reaches the receiver
  prerouting               nothing arrives either
  netdev egress            the L2 header and the neighbour are already
                           resolved, so the frame goes out carrying the
                           written destination and the receiver counts
                           Ip6InAddrErrors

The counter of the door is not a property of the datagram: same rule, same
accepted store, 1 to 8 depending on the door.

Not tested here: IPv6 inside PPPoE, a VLAN-tagged IPv6 frame at an egress hook,
@th in this mode, extension headers at an egress hook, GSO/CHECKSUM_PARTIAL on
real hardware, ICMPv6 and SCTP as the transport.  Every rule here is installed
by root in the initial user namespace.

Reproduction: one static C program (netlink by hand), busybox initramfs, two
boots; every number above is derived from the log by an independent Python
model of the guard and of the door, and the tables are generated from the log
rather than typed.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F48 — at an egress door `meta protocol` puts a PPPoE frame into two different coordinate systems

**Claim.** On a PPPoE frame at the netdev egress hook, `meta protocol` computes `nhoff = 8 + skb_network_offset` (22) while the IPv6 constructor reads the version byte at `skb_network_offset + nhoff` (36, which is `saddr[6]`) and the transport walk starts at 22; the same expression therefore gives the transport base the right answer and the network base the wrong one.

**Minimal reproduction.** instrument `differ570`, modes `ppp6e`, `th6`; 25 arms × 2 boots on a kernel-built PPPoE frame (PF_PPPOX session socket, sid 99, IPv6/UDP payload), one rule at a time at the netdev egress hook.

**Run.** `bash vm/build_f48_differ.sh` then `bash code/tools/f48_run.sh` — log marker `F570`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_meta_pktinfo_may_update()` sets `nhoff = PPPOE_SES_HLEN + skb_network_offset`; `__nft_set_pktinfo_ipv6_validate()` reads the version byte at `skb_network_offset + nhoff` while `ipv6_find_hdr()` starts at `nhoff`; a failed version check calls `nft_set_pktinfo_unspec()`, which resets `nhoff` to 0.

**Actual.** `meta protocol` reports 0x86dd and `meta l4proto` reports nothing; `@nh,7,1` and `@th,0,2` are both refused, for two different reasons (`nft_nh_write_ok_netdev()` has no ETH_P_PPP_SES case; `pkt->flags` is 0); after the failed version check, `@nh` falls back to the PPPoE header.

**Limitations.** One PPPoE layout and the netdev egress hook; the bridge PPPoE path is F41/F42.

**Details.**

`meta protocol` on a PPPoE frame computes one number and two bases read
it differently -- and at an egress door the difference decides whether the frame
is refused or rewritten in its real transport header.

No patch is proposed: this measures the guard as it stands and proposes no change.

Linux 7.3.4, nftables in the initial user namespace, one packet at a time, one
rule at a time.  The frame is built by the kernel: a PF_PPPOX session socket
(sid 99) bound to a veth, `send()` hands it `00 57` + IPv6/UDP, `pppoe_sendmsg()`
adds the session header and the Ethernet header.  On the wire the IPv6 header is
at offset 22 and `skb_network_offset` is 14, because `skb_reset_network_header()`
runs before `dev_hard_header()`.

`nft_meta_pktinfo_may_update()` computes `nhoff = 8 + skb_network_offset` = 22.
`__nft_set_pktinfo_ipv6_validate()` then reads the version byte at
`skb_network_offset + nhoff` = 36 (which is `saddr[6]`) while
`ipv6_find_hdr()` starts the walk at `nhoff` = 22 (the real header).  The same
expression therefore gives the transport base the right answer and the network
base the wrong one; and when the version check fails,
`nft_set_pktinfo_unspec()` resets `nhoff` to 0, so `@nh` silently falls back to
the PPPoE header.

Measured on that door (25 arms x 2 boots):

  - `meta protocol` reports `0x86dd` and `meta l4proto` reports nothing;
  - `@nh,7,1` and `@th,0,2` are both refused, for two different reasons
    (`nft_nh_write_ok_netdev()` has no `ETH_P_PPP_SES` case; `pkt->flags` is 0);
  - with `0x60` at offset 36 in the frame's own source address the version
    check passes, and the same `@th,0,2` write lands at offset 62 -- the real
    UDP source port -- while `@nh,0,4` reads the attacker's four bytes at 36;
  - at the ingress hook of the same device, with the same bytes, `@nh,7,1` is
    accepted (the guard is a constant there) and lands in the PPP protocol
    field.

The same instrument closes the transport base for plain IPv6: `@th,0,2` lands
at `14 + 40` at local_out, postrouting and the netdev egress hook, the local
class is delivered with the written source port, the forwarded class dies on the
UDPv6 checksum until `csum type inet` (`csum_offset 6`) is added, and
`meta l4proto` reports 51 for AH (the walk stops on the auth header) and 17
through a routing header.

Not a vulnerability: the rules are installed by root in the initial user
namespace.  The report is about a guard whose coordinate depends on the hook and
about a validation that looks at one place while the walk parses another.

---

## F49 — at a ppp0 layer-3 door the base is right and `@ll` does not exist

**Claim.** Once the PPP layer has run, the `@ll` base does not collapse onto `@nh`: it disappears, because `skb_mac_header_len()` is 0 while the network header is present; the same `@nh` cell that is refused at one door is a single byte of the header at another.

**Minimal reproduction.** instrument `differ571`, modes `ctl`, `rd`, `tapf`, `wr`; one 88-byte frame (ethernet | PPPoE sid 99 | 00 57 | IPv6/UDP) seen at four doors in one boot: inet prerouting and ip6 prerouting on ppp0, netdev ingress on the veth, and an ip prerouting chain that never sees it.

**Run.** `bash vm/build_f49_differ.sh` then `bash code/tools/f49_run.sh` — log marker `F571`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `ppp_receive_nonmp_frame()` resets `mac_header` to `skb->data` and the receive path calls `skb_reset_mac_len()`, so `skb_mac_header_len()` is 0; `nft_ll_write_ok()` then refuses every non-zero end.

**Actual.** At the ppp0 layer-3 doors `skb_network_offset()` and `pkt->nhoff` are both 0: `@nh,0,4` reads 60 00 00 00, `@nh,4,2` the payload length, `@nh,7,1` the hop limit 40. At the netdev ingress door the same cells read 11 00 00 63 and 57 (the PPPoE header and PPP protocol). `@ll` is refused at ppp0 for every non-zero end.

**Limitations.** Only the ppp0 device and one frame layout; PPPoE at the bridge is F41/F42.

**Details.**

On a device that has no link-layer header, the `@ll` base does not
collapse onto `@nh` -- it disappears -- and the same `@nh` cell that is
refused at one door is a single byte of the header at another.

No patch is proposed: this measures the guards as they stand and proposes no change.

Linux 7.3.4, nftables in the initial user namespace, one packet at a time, one
rule at a time.  One frame, 88 bytes: ethernet | PPPoE session header (sid 99) |
PPP protocol `00 57` | IPv6/UDP 40000->5000.  A PF_PPPOX session socket bound on
a veth, a ppp unit attached to it exactly as pppd does it
(`PPPIOCGCHAN`/`PPPIOCNEWUNIT`/`PPPIOCATTCHAN`/`PPPIOCCONNECT`), the frame
injected on the peer.  The kernel removes the eight bytes of
PPPoE+PPP before the layer-3 hook, so the same frame is presented to four doors
in one boot: `inet` prerouting and `ip6` prerouting on ppp0, the netdev ingress
hook on the veth, and an `ip` prerouting chain that never sees it.

At the layer-3 doors `skb_network_offset()` is 0 and `pkt->nhoff` is 0: `@nh,0,4`
reads `60 00 00 00`, `@nh,4,2` the payload length, `@nh,7,1` the hop limit `40`.
At the netdev ingress door the same cells read `11 00 00 63` (the PPPoE header)
and `57` (the PPP protocol byte).  So `nft_meta_pktinfo_may_update()` adds its
`PPPOE_SES_HLEN` bytes only at doors that see the frame *before* `ppp_input()`;
once the PPP layer has run, no constructor has anything to add.

`@ll` on ppp0 is not a base at all.  `ppp_receive_nonmp_frame()` resets
`mac_header` to `skb->data`, the receive path calls `skb_reset_mac_len()`
(`net/core/dev.c`), so `skb_mac_header_len()` is 0 while
`skb_mac_header_was_set()` is true -- and `nft_payload_eval()` refuses the LL
base on `skb_mac_header_len(skb) == 0`.  Every `@ll` read and every `@ll` write
on ppp0 is refused, including `@ll,0,1`, which the ethernet layer-3 doors accept.
the log agrees twice and inconsistently: `NFULA_L2HDR` is absent (it is gated on
`pf == NFPROTO_NETDEV || NFPROTO_BRIDGE`), while `NFULA_HWHEADER` is present and
carries `dev->hard_header_len` = 22 bytes taken from `skb_mac_header()` -- that
is, the first 22 bytes of the IPv6 header, labelled as the hardware header of a
device of type `ARPHRD_PPP`.

The guard at both layer-3 doors is `nft_nh_write_ok_ip6()` (`pf` is
`NFPROTO_IPV6` in the `inet` family as well).  It is a whitelist: `(4,2)` payload
length and `(6,1)` next header are refused, `(7,1)` hop limit, `(2,2)`, `(8,16)`
and `(24,16)` are accepted, and `case 0` accepts only an immediate whose high
nibble is 6 -- the value, not the length.  The same frame at the netdev ingress
door goes through the constant `true` of `NF_NETDEV_INGRESS`, so `@nh,7,1 = 0x90`
there rewrites the PPP protocol field, `ppp_receive_nonmp_frame()` hands the
frame to the unit queue, and `dev_sw_netstats_rx_add()` has already counted 66
bytes on ppp0 while `Ip6InReceives` stays 0.  Five single-cell writes at that door
die invisibly: the PPPoE length (the `skb->len < len` test in `pppoe_rcv()`), the
session id and the source MAC (`__get_item()`), the protocol byte
(`ppp_skb_is_compressed_proto()`), and the hop limit (the unit queue).  Controls
with the value the frame already carries are delivered, so it is the value and
not the act.

`@th` reaches the same byte by two formulas: `0 + 40` at the layer-3 doors and
`8 + 40 = 48` at the netdev ingress door after `meta protocol` rebuilt the
pktinfo.  `meta protocol` on a PPPoE frame returns the *inner* ethertype
(`0x86dd`) because it asks `nf_flow_pppoe_proto()`, and asking it is also what
makes `@th` usable at that door; without it `pkt->flags` is 0 and the base is
refused.  With `csum type inet` and `csum_offset 6` both doors deliver the
datagram to the written source port 37009.

Two silent non-events: a `csum type inet`
request on the `@nh` base in IPv6 neither fixes anything nor fails --
`nft_payload_csum_nh_write_ok()` returns `false` inside an `&&`, the store lands
and the datagram is delivered with an unmodified checksum request; and a write
to `daddr` that the whitelist allows loses the packet at the route lookup with
`Ip6InNoRoutes` and no other counter moving.

Not a vulnerability: the rules are installed by root in the initial user
namespace.  The report is about a base that ceases to exist on devices without a
link header, about a log attribute that reports IPv6 bytes as a hardware header,
and about a guard whose verdict for the same cell depends on the door.

---

## F50 — a device without an ethernet header can never carry `@ll` into a bridge

**Claim.** `@ll` has two domains at one bridge door: reads run past the link header into the network header while writes stop at `mac_len`, and the guard's verdict is the same at two doors whose consequences are opposite because by the time the layer-3 door runs, the copies for the other ports are already cloned; a ppp device cannot be put in a bridge at all (`br_add_if()` rejects `ARPHRD_ETHER`).

**Minimal reproduction.** instrument `differ572`; one 80-byte IPv6/UDP frame injected on a veth, a bridge `br0` with two ports, the same skb seen at four doors in one boot, four AF_PACKET taps.

**Run.** `bash vm/build_f50_differ.sh` then `bash code/tools/f50_run.sh` — log marker `F572`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `br_add_if()` rejects `dev->type != ARPHRD_ETHER` with `-EINVAL`; `nft_ll_write_ok()` bounds writes at `mac_len` while `nft_payload_copy_vlan()` lets reads run past it.

**Actual.** `br_add_if()` on a ppp device returns rc=-22 while the same call succeeds for both Ethernet ports; the read and store domains differ by the four bytes the guard adds, and the store at the layer-3 door does not reach the copies already made for the other ports.

**Limitations.** Q-in-Q on these doors and the `@nh`/`@th` bases; a rule needs root in the initial user namespace.

**Details.**

`@ll` has two different domains at one door -- reads run past the link
header into the network header, writes stop at `mac_len` -- and the guard's
verdict is the same at two doors whose consequences are opposite, because by
the time the layer-3 door of a bridge runs, the frames for the other ports have
already been cloned.

No patch is proposed: this measures the guards as they stand and proposes no change.

Linux 7.3.4, nftables in the initial user namespace, one packet at a time, one
rule at a time.  One frame, 80 bytes: ethernet broadcast | IPv6 fd02::11 ->
fd02::92 | UDP 40000->5000, injected on a veth; a bridge `br0` with two ports,
IPv6 enabled on the bridge only, so the port's copy of the frame dies in
`ip6_rcv_core()` on the far side and touches no chain of mine.  The same skb is
presented to four doors in one boot: `ip6` prerouting (the layer-3 door of the
bridge, after `br_pass_frame_up()`), `ip6` input (a witness one door later),
`bridge` prerouting (before the bridge makes its copies) and netdev ingress on
the port.

First, the open question from the previous report is closed by refusal: a ppp
device cannot be put in a bridge at all.  `br_add_if()` rejects
`dev->type != ARPHRD_ETHER` with `-EINVAL`, and the netlink call returns exactly
that (`rc=-22`) while the same call succeeds for both ethernet ports.  So the
`@ll` base that does not exist on a device without a link-layer header (my
previous report) cannot be brought into existence by bridging it: the two
refusals are the same fact.

`@ll` at the layer-3 door of the bridge, 36 cells of `(offset, len)`:

* reads: **36/36**.  `skb_mac_header_was_set()` holds, `mac_len` is 14, and the
  read has no upper boundary -- `@ll,14,4` returns `60 00 00 00`, the first four
  bytes of the IPv6 header; `@ll,20,2` returns `11 40`, the next-header and the
  hop limit.  The comment in `nft_ll_write_ok()` says writes must not spill into
  the network header; reads do.
* writes: **23/36**, exactly `off + len <= 14`.  The boundary is `mac_len`, at
  every door: at netdev ingress the same cells are taken without any bound at
  all, and a four-byte store at offset 12 writes the ethertype *and* two bytes
  of the IPv6 header, the version becomes 9 and the packet dies in
  `Ip6InHdrErrors`.  The refusing guard is what saves the packet at layer 3.

One accepted store in the destination MAC (`@ll,0,6`), three doors:

| door | local copy | port copy | delivered |
|---|---|---|---|
| ip6 prerouting (after `br_pass_frame_up`) | unchanged, delivered | byte-identical to the control | yes |
| bridge prerouting | **no local copy at all** | foreign unicast, `rx_otherhost_dropped` | no |
| netdev ingress | **no local copy at all** | foreign unicast | no |

At the bridge and ingress doors the write changes the forwarding decision,
because `br_handle_frame_finish()` reads `eth_hdr(skb)->h_dest` after the hook.
At the layer-3 door it cannot change anything: the port's copy was cloned
before the hook (`br_flood()` -> `deliver_clone()` -> `br_pass_frame_up()`), and
`ip6_rcv_core()` unshared the local one before it.  The same value aimed at the
bridge's own address at the bridge door is a third outcome: local delivery only,
nothing sent to the port.  So one rule, one accepted store, one cell: the frame
can go to the port, stay with the bridge, or die on both sides, decided by the
value.

The guard reads a cache, not the frame.  In one rule at the bridge door,
`[@ll,12,2 = 0800][@nh,10,2]`: the first store lands (the wire carries `0800`),
the second is refused, because `nft_nh_write_ok_bridge()` switches on
`pkt->ethertype`, assigned once in `nft_pktinfo_init()` from `skb->protocol`.
the mirror control on the same door (`@nh,7,1`, a hop-limit cell) is accepted.

Two instrument-level notes that may matter to anyone reading nft logs:
`NFULA_HWHEADER` is copied from `skb_mac_header()` at the moment the `log`
expression runs, so two log expressions in one packet give two different
snapshots of the same 14 bytes -- it is a witness of *when* a store landed, and
the only one for an `@ll` store (the payload attribute starts at `skb->data`,
which such a store never touches).  And at the layer-3 door of a bridge
`NFULA_L2HDR` is absent (it is gated on the family) while `NFULA_IFINDEX_INDEV`
is the bridge, not the port the frame arrived on; `CONFIG_BRIDGE_NETFILTER` is
off in this image, so the physical port is not in the log at all.

Not measured here: VLAN-tagged and Q-in-Q frames on these doors, `@nh`/`@th`
on the two-copy path, the `inet` family, IPv4, GSO/`CHECKSUM_PARTIAL`, and
several devices in one bridge chain.  One sender, one bridge, one frame per
arm; the rule is installed by root in the initial user namespace.

---

## F51 — store visibility among copies, and the frame the bridge learns

**Claim.** A payload store reaches exactly the copies of a frame that the kernel makes after it; for copies made before it the store is not lost by oversight but by copy-on-write -- `__skb_clone()` sets `cloned = 1` on the source as well, so `skb_ensure_writable()` copies the head and the earlier copies keep their bytes.

**Minimal reproduction.** instrument `differ573`; one 80-byte broadcast IPv6/UDP frame, a bridge `br0` with three ports, one rule at one of four doors (bridge prerouting, bridge forward, bridge input, ip6 prerouting), four AF_PACKET taps counting copies.

**Run.** `bash vm/build_f51_differ.sh` then `bash code/tools/f51_run.sh` — log marker `F573`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `__skb_clone()` sets `cloned = 1` on the source; `skb_ensure_writable()` copies the head; `br_flood()` makes the port copies at a known point in the path.

**Actual.** One frame: 1 at bridge prerouting, 2 at forward, 1 at LOCAL_IN, 1 at the ip6 door. A store at prerouting is accepted once and all three copies carry it; the same store at the forward door reaches neither the earlier local copy nor the other port's copy. The bridge learns the stored source MAC, so the next store into the same bytes becomes known unicast and is not flooded.

**Limitations.** Only bridge flooding and one frame; no QinQ or tunnels.

**Details.**

A payload store reaches exactly the copies of a frame that the kernel
makes AFTER it, and for the copies made before it the store is not lost because
anything forgot it -- `__skb_clone()` sets `cloned = 1` on the source as well,
so `skb_ensure_writable()` copies the head and the earlier copies keep the bytes
they were cloned with.  One nft rule at one bridge door changes three copies,
two copies or none, depending on where the door sits relative to `br_flood()`.

No patch is proposed: this measures the guards and the copy-on-write rule as they
stand and proposes no change.

Linux 7.3.4, nftables in the initial user namespace, one frame at a time, one
rule at a time.  Three veth pairs, one bridge `br0` with three ports, IPv6
enabled on the bridge only; frame A is 80 bytes -- ethernet broadcast | IPv6
fd02::11 -> fd02::92 | UDP 40000->5000 | 18 x 0x77.  The same skb is presented
to four doors in one boot: `bridge` prerouting (before `br_flood()`),
`bridge` forward (once per port copy), `bridge` input (the local copy) and
`ip6` prerouting (the local copy, inside the IP stack).  Four AF_PACKET taps
count and record the copies.

The census first, because it decides everything else: one injected frame is
seen once at the bridge prerouting door, twice at the forward door (two ports),
once at `LOCAL_IN` and once at the ip6 door.  A store of eight bytes into the
source MAC at the bridge prerouting door is accepted once and all three copies
carry it -- the clones are made afterwards and share the head.

The same eight bytes stored into the destination at the forward door are
evaluated twice and change exactly the two port copies; the local copy, which
never passes that door, keeps the original.  With the ethertype instead of the
MAC the same rule leaves two copies saying `0806` and the third still `86dd`,
still delivered: the protocol was decided at the ingress `eth_type_trans()` and
`br_pass_frame_up()` does not re-derive it.

The local copy's own door is where the copy-on-write shows.  A store at `ip6`
prerouting is accepted once, lands on the named bytes, the datagram is
delivered -- and no port copy carries it.  Not because the store was refused,
and not because anything re-parsed the frame: `br_flood()` cloned the skb for
the two ports, `__skb_clone()` set `cloned = 1` on the original too, and
`nft_payload_set_eval()` stores through `skb_ensure_writable()`, which calls
`pskb_expand_head()` for a cloned skb.  The local path gets a private copy; the
two ports keep the old head.  Closing the instrument's own tap on the bridge
changes nothing, so the flood's clone alone is enough.

Two smaller things fall out of the same instrument.  A store into the source
teaches the bridge that MAC on the ingress port, so a later rule that aims the
destination at those same bytes turns the frame into a known unicast back to its
ingress port and it is delivered nowhere: one accepted store can disarm the
next one.  And a store of the hop limit at `LOCAL_IN` is visible to a tap on the
bridge device but not to the ports, because that hook runs before
`netif_receive_skb()` -- the only local door whose store a tap can see.

Nothing here is a vulnerability: the rule is installed by root in the initial
user namespace.  What is described is the shape of the guard: "accepted" and
"reached every copy" are different claims, and which copies a store reaches is
decided by the order of the clones, not by the rule.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F52 — a tagged frame with a non-zero vid dies before the IPv6 door, and `@ll,12,2` is not the inner ethertype

**Claim.** With the tag in metadata, `@ll` is not the frame: `nft_payload_copy_vlan()` rebuilds `struct vlan_ethhdr`, so the inner ethertype sits at `@ll,16`, not `@ll,12`; once a VLAN sub-interface exists the tag is cleared and the whole domain shifts four bytes earlier; a tagged frame with a non-zero vid and no VLAN device dies as `PACKET_OTHERHOST` before any IPv6 counter.

**Minimal reproduction.** instrument `differ574`; one bridge with three ports, one 80-byte tagged frame seen at five doors; the tag in metadata and on a VLAN sub-interface; counters from the bridge, the ip6 stack and `rx_otherhost_dropped`.

**Run.** `bash vm/build_f52_differ.sh` then `bash code/tools/f52_run.sh` — log marker `F574`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_payload_copy_vlan()` rebuilds `struct vlan_ethhdr` from `skb->vlan_proto`/`skb->vlan_tci`; `__netif_receive_skb_core()` sets `PACKET_OTHERHOST` when `skb_vlan_tag_get_id(skb) != 0` and `vlan_do_receive()` finds no VLAN device, and `ip6_rcv_core()` returns on that pkt_type before `IPSTATS_MIB_IN`.

**Actual.** A vid-100 frame is counted by the bridge three times (brp 1, brf 2, brl 1), reaches the far end's ingress hook, and never reaches an IPv6 hook (ip6 prerouting 0, Ip6InReceives 0, Ip6InDiscards 0); the only counters that move are `rx_otherhost_dropped` on br0 and both ports. A store into the TCI changes no wire byte and turns the dropped frame into a delivered datagram.

**Limitations.** 802.1ad, two tags, `VLAN_FLAG_REORDER_HDR` cleared, and a VLAN device present are F53-F56.

**Details.**

On a VLAN-tagged frame the `@ll` base is not the frame.  With the tag in
`skb->vlan_proto`/`skb->vlan_tci`, `nft_payload_copy_vlan()` rebuilds `struct
vlan_ethhdr` and the inner ethertype sits at `@ll,16`, not `@ll,12`; once a
VLAN sub-interface exists the tag is cleared and the whole domain shifts four
bytes earlier, so the same rule reads different bytes depending on a piece of
configuration that appears nowhere in it.  And a store into the TCI is a store
into the skb, not into the frame: writing 0 there changes no byte on the wire
and turns a frame the IP stack silently drops (`PACKET_OTHERHOST`, no IPv6
counter moves) into a delivered datagram.

No patch is proposed: this measures the LL base, the store semantics and the guard as
they stand and proposes no change.

What was measured (7.3.4-T563, one bridge with three ports, one frame seen at
five doors -- bridge prerouting, bridge forward, bridge local-in, ip6
prerouting, and netdev ingress at the far end):

* A tagged frame (vid 100) is counted by the bridge three times (`brp` 1,
  `brf` 2, `brl` 1), reaches the far end's ingress hook, and **never reaches an
  IPv6 hook**: `ip6` prerouting 0, `Ip6InReceives` 0, `Ip6InDiscards` 0.  The
  only counters that move are `rx_otherhost_dropped` on `br0` and on both
  ports, because `__netif_receive_skb_core()` sets
  `pkt_type = PACKET_OTHERHOST` when `skb_vlan_tag_get_id(skb) != 0` and
  `vlan_do_receive()` found no VLAN device (`dev.c:6207`), and
  `ip6_rcv_core()` returns on that pkt_type before `IPSTATS_MIB_IN`
  (`ip6_input.c:196` before `:206`).  The same frame with vid 0 is delivered.
* `@ll` on that frame reads the frame **with** its tag: 12..13 = `8100`, 14..15
  = the TCI, 16..17 = `86dd`, 18..19 = the first bytes of the IPv6 header --
  the 84 bytes that were injected, while the AF_PACKET taps show the 80-byte
  post-untag frame.  A rule spelling `@ll,12,2 = 86dd` cannot match a tagged
  frame; the inner ethertype is at 16.
* `@ll,14,2 = 0000` at the bridge door is accepted, writes no byte
  (`nft_payload_set_vlan()` returns before `skb_ensure_writable()`,
  `nft_payload.c:1129`), and the frame that was undeliverable is delivered.
  `@ll,14,4` is refused at evaluation time and leaves no trace: the rule's own
  counter is 0 and it logs nothing.
* `@ll,12,2 = 0806` sets `skb->vlan_proto` only.  Because `veth` advertises
  `NETIF_F_HW_VLAN_CTAG_TX`, `validate_xmit_vlan()` pushes only non-0x8100
  protos into the bytes -- that is the one arm in which the tag is a byte on the
  wire (84 bytes, `0806 0064 86dd` at 12..17).
* `@ll,12,4 = 0000 0000` zeroes both fields at once.  `skb_vlan_tag_present()`
  is `!!skb->vlan_all` (`if_vlan.h:82`) and `__vlan_hwaccel_put_tag()` stores no
  present bit, so the tag is **deleted**: the wire is 80 bytes, no byte changed,
  and the frame is delivered.
* With `br0.100` up the same frame is delivered -- and the LL domain moves four
  bytes earlier: 12 is `86dd` (not `8100`), 14 is `6000` (not the TCI), 16 is
  `0000`, 18 is the payload length.  `vlan_do_receive()` finds the device,
  `VLAN_FLAG_REORDER_HDR` (`vlan.c:276`) skips the re-insertion, the tag is
  cleared (`vlan_core.c:61`) and `nft_payload_eval()` falls back to
  `skb_mac_header() - skb->data` (`nft_payload.c:184`).
* A store into the TCI at the bridge **forward** door is evaluated once per port
  copy and reaches exactly that copy: the far end reads the new TCI while the
  local copy, which never passed that door, keeps vid 100 and stays dead.

Not measured here: 802.1ad, two tags, `VLAN_FLAG_REORDER_HDR` cleared, a VLAN
device on a port, and a physically tagged 0x8100 frame (this veth pair cannot
produce one).  Rules are installed by root in the initial user namespace, so
none of this is a privilege boundary; what it shows is that the meaning of an
`@ll` offset and the fate of a packet depend on state the rule cannot see.

-- a measurement, not a patch

---

## F53 — the one configuration where the kernel puts the tag back into the frame between `vlan_do_receive()` and the hook

**Claim.** Clearing `VLAN_FLAG_REORDER_HDR` on a VLAN sub-interface is the one configuration in which the kernel puts the tag back into the frame bytes before a layer-3 hook; the `@ll` base there is the frame as it came off the wire and the write guard, `off + len <= mac_len`, moves four bytes with it.

**Minimal reproduction.** instrument `differ575`; one bridge with four VLAN sub-interfaces (two with the flag, two without), one 80-byte frame seen at ip6 prerouting and at netdev ingress, 44 arms per boot over two boots.

**Run.** `bash vm/build_f53_differ.sh` then `bash code/tools/f53_run.sh` — log marker `F575`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `vlan_dev_hard_header()` and the reorder path decide whether the tag is bytes or a word; `mac_len` follows the same decision.

**Actual.** Flag set (`br0.100`): at ip6 prerouting `@ll` reads 12 = 86dd, 14 = 6000, 16 = 0000, 18 = 001a, `mac_header` at frame 4, `mac_len` 14. Flag cleared (`br0.101`): 12 = 8100, 14 = 0065, 16 = 86dd, 18 = 6000, 20 = 0000, `mac_header` at 0, `mac_len` 18; the packet socket shows 80 bytes untagged against 84 tagged. NFULA_HWHEADER (14 bytes) and the frame disagree by four bytes for the same message.

**Limitations.** Nested VLANs and other device types were not measured; a store into the tag that reaches a wire is F54.

**Details.**

Clearing VLAN_FLAG_REORDER_HDR on a VLAN sub-interface is the one
configuration in which the kernel puts the tag back into the frame bytes before
the hook runs.  In it, the `@ll` base at a layer-3 door stops being the
"reordered" view and becomes the frame as it came off the wire -- and the write
guard, which is `off + len <= mac_len`, moves four bytes with it.  So the same
rule reads and writes different bytes depending on a per-device flag that
appears nowhere in the rule.  The four bytes are dead for the packet's fate
either way; while they are still metadata (netdev ingress), the same offsets
decide everything instead, and one of them makes the kernel WARN.

No patch is proposed: this measures the LL base, the store semantics and the guard as
they stand and proposes no change.

What was measured (7.3.4-T563; one bridge, four VLAN sub-interfaces on it --
two with the flag, two without -- and one frame seen at ip6 prerouting and at
netdev ingress; 44 arms per boot, two boots, every derived fact identical):

* Flag set (`br0.100`, default): `@ll` at ip6 prerouting is the F52 view --
  12 = 86dd, 14 = 6000, 16 = 0000, 18 = 001a; `skb_mac_header()` sits at frame
  4 and `mac_len` is 14.  Flag cleared (`br0.101`): the same offsets read the
  frame itself -- 12 = 8100, 14 = 0065, 16 = 86dd, 18 = 6000, 20 = 0000;
  `mac_header` is back at 0 and `mac_len` is 18.  A packet socket on the two
  devices shows the same split: 80 bytes untagged against 84 bytes tagged.

* The log carries two witnesses that disagree by four bytes for the same
  message: NFULA_HWHEADER (14 bytes from `mac_header`) ends in 86dd for the
  first and in 8100 for the second, while NFULA_PAYLOAD (from `skb->data`) is
  identical in both, because `data` points at the IPv6 header either way.

* The write guard is `nft_ll_write_ok(pkt, len + off + (mac_header - data))`
  against `skb_network_offset()`, which is 0 at a layer-3 door: the writable
  domain is exactly `mac_len`.  With the flag set `@ll,14,2` and `@ll,16,2` are
  refused (16, 18 > 14) and `@ll,12,2` accepted; with the flag cleared
  `@ll,14,2` and `@ll,16,2` are accepted (16, 18 = 18) and `@ll,18,2` refused
  (20 > 18).  A refused store is invisible except to the rule's own counter:
  the expression breaks before `log` and `counter`, and the packet is delivered
  untouched.

* None of the accepted stores changes the fate of the packet: TCI, TPID, inner
  ethertype and destination MAC are all dead bytes after the hook, since
  `skb->protocol` and `pkt_type` were decided earlier.  This is the exact
  reverse of the tagged-frame case, where the same four bytes are skb metadata,
  a store into them changes no frame byte, and the packet's fate turns on the
  value (writing 0 into the TCI makes an undeliverable frame deliverable).

* While the tag is still metadata -- the netdev ingress hook -- the same
  offsets have two different targets.  Offset 12 is `skb->vlan_proto` and
  offset 14 is `skb->vlan_tci`: storing 0x0066 into the TCI re-targets the
  frame to vid 102, no device matches, and it dies as PACKET_OTHERHOST before
  any IPv6 counter moves.  Storing 0x0806 into offset 12 sets `vlan_proto` to
  0x0806, and the next `vlan_do_receive()` calls `vlan_proto_idx()`, which
  warns:

      invalid VLAN protocol: 0x0806
      WARNING: net/8021q/vlan.h:48 at vlan_do_receive+0x282/0x9a0

  That is the one splat in this campaign and it reproduces on both boots.  The
  16-bit value written by the rule is not validated anywhere before the WARN;
  a privileged rule can therefore produce a kernel warning from a
  configuration the kernel otherwise supports.  Offset 16 and beyond take the
  `vlan_hlen = 4` path instead and land in the frame, four bytes earlier than
  named: a store at 16 writes the frame's inner ethertype, the packet is still
  delivered (the stack already parsed it), and a packet socket that was queued
  at that hook -- the tap is delivered *after* the ingress hooks -- shows
  `8100 0065 0800` where the stack saw `86dd`.

* Two tags (`88a8`/102 outside, `8100`/200 inside, outer flag cleared, inner
  kept): the view at the inner device is one tag assembled from two -- TPID and
  TCI of the outer, and the inner ethertype right behind them (12 = 88a8,
  14 = 0066, 16 = 86dd, 18 = 6000).  The inner tag is gone from the view
  although its device is the one being addressed.

Not measured, plainly: a store into the tag that reaches a wire (the local copy
is never transmitted, so only `HWHEADER` and the packet socket witness it); an
802.1ad frame on a device with the flag set; three or more tags (VLAN_MAX_DEPTH
guards only the priority-tag loop in dev.c); `inet` family chains in this
configuration; checksum fixups on a store into the tag; GSO on real hardware;
a VLAN device as a bridge port (`vlan_core.c:40` skips the re-insertion).

Not a vulnerability: the rule needs root in the initial user namespace, and the
VLAN device needs root to be created.

---

## F54 — the tag on the wire is composed by the egress device; no store into it survives

**Claim.** The 802.1Q tag is a property of the device a frame leaves through: `vlan_dev_hard_header()` builds a fresh header from `vlan->vlan_id` (plus an egress QoS map of `skb->priority`), so a store into the tag bytes or the TCI at a layer-3 door does not survive; at the netdev ingress hook the same offset is `skb->vlan_tci` and the store re-targets the VLAN.

**Minimal reproduction.** instrument `differ576`, modes `warn`, `xf`; a VLAN sub-interface with `VLAN_FLAG_REORDER_HDR` cleared, one rule at a time, the egress frame and the far end's demux as witnesses; the second half reproduces the `invalid VLAN protocol` WARN with one rule `@ll,12,2 = 0806` at netdev ingress.

**Run.** `bash vm/build_f54_differ.sh` then `bash code/tools/f54_run.sh` — log marker `F576`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `vlan_dev_hard_header()` writes `vlan->vlan_id | vlan_dev_get_egress_qos_mask(dev, skb->priority)` into four fresh bytes; `vlan_find_dev()` reaches `vlan_proto_idx()` only when the device has a VLAN above it, and `vlan_proto_idx()` is the function that warns.

**Actual.** `@ll,14,2` writes a byte and the counter says the store was taken, yet the far end demuxes the device's vid and the priority bits do not travel; deleting the four tag bytes changes nothing on the wire. With a tag present and a `vlan_info` on the device, one rule produces one WARN line per frame and every such frame is dropped; a bare veth pair cannot warn at all.

**Limitations.** Only veth and one VLAN layout; the warning's exact call site is read from the source, not instrumented.

**Details.**

The 802.1Q tag is a property of the device a frame leaves through, not
of the frame a rule writes into.  On a VLAN sub-interface with
VLAN_FLAG_REORDER_HDR cleared the tag is physical frame bytes at both layer-3
doors, so `@ll,14,2` writes a byte and the rule's counter says the store was
taken; `vlan_dev_hard_header()` then builds a fresh header from `vlan->vlan_id`
(plus an egress QoS map of `skb->priority`) between the FORWARD hook and the
egress hook of that device, and the far end demuxes the device's vid.  The
priority bits do not travel either.  Deleting the four tag bytes outright does
not change what leaves.  At the netdev ingress hook the same offset is
`skb->vlan_tci` instead, and there the same store does decide the frame's fate
-- it re-targets the VLAN and, with no device for that vid, the frame is
dropped as PACKET_OTHERHOST before any IP counter sees it.

The second half is a minimal reproduction of the
`invalid VLAN protocol` WARN: one veth pair, one
VLAN device, one netdev-ingress table with one chain and one rule storing
0x0806 at `@ll,12,2`, one tagged frame.  The warning is not WARN_ONCE: N
frames print N lines, and every one of them is a frame the kernel then drops.
Two conditions are needed and both are worth stating: the frame must carry a tag
(`skb_vlan_tag_present()` gates the store into `skb->vlan_proto`), and the
receiving device must have a `vlan_info` -- `vlan_find_dev()` only reaches
`vlan_proto_idx()`, the function that warns, when the device has at least one
VLAN above it.  A bare veth pair cannot warn at all.

Measurement only; no patch is implied.  Kernel 7.3.4-T563, one frame per arm,
two boots, every number from the packet's own bytes and from the receiving
device's counters.

Numbers, for the record:

  * the same frame, six doors: the tag is metadata at netdev ingress (vid 101),
    frame bytes at ip6 prerouting and forward, and metadata again from the
    egress door of the egress VLAN device onward -- with vid 102, that device's
    own.  An egress door has no NFULA_HWHEADER in this kernel; the tag is in
    NFULA_L2HDR (18 bytes at the VLAN device, 14 after
    vlan_dev_hard_start_xmit() pops it into metadata).
  * a store of vid 103 at prerouting is accepted and is still readable at the
    forward hook; the egress door of the egress VLAN device reads the device's
    0066 instead, and so does the last door before the wire.
  * the far end runs two VLAN devices of its own; x0.102's rx_packets is 1 in
    every arm that reaches the wire, x0.101's is 0.  The wire frame is 80
    bytes, untagged in the bytes.
  * zeroing the four bytes at 12..15 at prerouting removes the tag from the
    frame, and the frame still leaves with 8100 0066.
  * storing 0x0806 at `@ll,12,2` on the ingress door, with one VLAN device on
    the box: one WARN line per tagged frame, `net/8021q/vlan.h:48 at
    vlan_do_receive`, and the frame is dropped as PACKET_OTHERHOST.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F55 — the PCP is the part of the tag a hook can reach, and the channel is `skb->priority`

**Claim.** Of the tag's four bytes, three bits are reachable from a rule -- the PCP -- and they are not reached through the tag at all: `meta priority set 5` plus an `egress-qos-map 5:3` puts TCI 0x6066 on the wire instead of 0x0066, witnessed by four independent readers.

**Minimal reproduction.** instrument `differ577`, mode `pcp`; table ip6 with `meta priority set 5` in the forward chain, one VLAN device with `egress-qos-map 5:3`, one 80-byte frame; witnesses: the egress door's NFULA_L2HDR, the receiving device's NFULA_VLAN, a far-end `@ll,14,2` read and the AF_PACKET auxdata.

**Run.** `bash vm/build_f55_differ.sh` then `bash code/tools/f55_run.sh` — log marker `F577`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `vlan_dev_hard_header()` writes `vlan_id | vlan_dev_get_egress_qos_mask(dev, skb->priority)`; the map is a hash table whose bucket is `skprio & 0xF` but whose match is the full 32-bit value.

**Actual.** TCI 0x6066 instead of 0x0066, the same number in all four witnesses. A priority value that shares the low nibble but differs above it does not match the map entry.

**Limitations.** The map needs CAP_NET_ADMIN over the device; only one map shape was measured.

**Details.**

Of the four bytes of an 802.1Q tag, three bits are reachable from a
rule -- the PCP -- and they are not reached through the tag at all.

The tag is the egress device's property.  The
vid has a single writer, `vlan_dev_hard_header()`: it writes
`vlan->vlan_id | vlan_dev_get_egress_qos_mask(dev, skb->priority)` into four
fresh bytes.  The vid half ignores `skb->priority` entirely, which is why a
store into the TCI does not survive.  The other half reads it, so a rule *can*
put a PCP on the wire:

    table ip6 f {
      chain fwd { type filter hook forward priority 0;
                  meta priority set 5 }
    }
    # ip link add link x1 name x1.102 type vlan id 102
    # ip link set x1.102 type vlan egress-qos-map 5:3

The frame then leaves with TCI 0x6066 instead of 0x0066 -- readable in the
egress door's `NFULA_L2HDR`, in the receiving device's `NFULA_VLAN` attribute,
in a far-end `@ll,14,2` read (which `nft_payload_copy_vlan()` rebuilds from
`skb->vlan_proto`/`skb->vlan_tci`), and in the AF_PACKET auxdata.  Four
independent witnesses, one number.

Three details that are easy to get wrong, each measured:

  * the map is a hash table with a composite key.  The bucket is
    `skprio & 0xF` but the match is the full 32-bit value, so `meta priority
    set 0x15` does **not** reach a mapping written for 5 although both hash to
    bucket 5 (`vlan_dev_get_egress_qos_mask()`, include/linux/if_vlan.h).  A
    mapping written for 0x15 does reach it.
  * the reader sits in `neigh_resolve_output()`/`neigh_connected_output()`,
    between the FORWARD hook and the device's egress hook.  So a store at
    prerouting or forward changes the PCP; the same store at the egress door
    does not (the four bytes are already in the frame there -- the door's own
    `NFULA_L2HDR` is 18 bytes).
  * the receive side reads the same three bits before any hook:
    `vlan_do_receive()` sets `skb->priority = vlan_get_ingress_priority(...)`
    and clears the tag metadata.  The netdev ingress hook fires before that
    call, ip6 prerouting after it, so one frame reads priority 0 at the first
    door and 5 at the next.  With an ingress map 3:5 and an egress map 5:7 a
    frame that arrives with PCP 3 leaves with PCP 7 and no rule at all.

The PCP is therefore a pair of device tables with the packet stack in between:
the ingress device turns PCP into `skb->priority`, the egress device turns
`skb->priority` back into PCP.  A hook can only step into the middle, and only
if the tables are there.  Two rules that agree on every byte they can write can
still put different bits on the wire because the devices they leave through
disagree -- `skb->priority` is not part of the packet.

Not a vulnerability: the map needs CAP_NET_ADMIN over the device, and the rule
needs root in the initial namespace.  The finding is a boundary of what `@ll`
writes can mean, not a privilege crossing.

Numbers, for the record (kernel 7.3.4-T563, one frame per arm, twenty arms,
two boots, every value from the frame's own bytes and the receiving device's
counters):

  * store 5 at forward, egress map 5->3: wire 6066; map 5->7: e066; no map:
    0066, while `meta priority` at the egress door still reads 5.
  * store 0x15 with a mapping from=5: 0066; with a mapping from=0x15: a066.
  * store at forward or prerouting: 6066; the same store at the egress door:
    0066.
  * same store, second egress device with 5->6: c067, and the far end demuxes
    that device's vid.
  * ingress map 3->5: priority 0 at the netdev ingress door, 5 at ip6
    prerouting; with an egress map 5->7 the wire carries e066 with no rule.
  * in all twenty arms the frame is forwarded once and demuxed by exactly one
    VLAN device: nothing a rule or a map did to `skb->priority` moved it.

---

## F56 — the tag is bytes or a word according to an offload bit, not the TPID

**Claim.** Whether the four tag bytes are frame bytes or a word in the skb is decided by an offload capability bit (`NETIF_F_HW_VLAN_CTAG_TX` / `NETIF_F_HW_VLAN_STAG_TX`), not by the protocol; on a bridged path with VLAN devices as ports the tag is neither at any door.

**Minimal reproduction.** instrument `differ578`, modes `ad`, `br`; 30 arms per boot over two boots; clearing the device's TX VLAN feature with ETHTOOL_SFEATURES moves the same tag from the skb into the frame, witnessed by the packet socket, NFULA_VLAN and the egress L2 header.

**Run.** `bash vm/build_f56_differ.sh` then `bash code/tools/f56_run.sh` — log marker `F578`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `vlan_hw_offload_capable()` maps 0x8100 to `NETIF_F_HW_VLAN_CTAG_TX` and 0x88a8 to `NETIF_F_HW_VLAN_STAG_TX`.

**Actual.** `x1.102` (vlan 102, proto 802.1ad, reorder cleared): wire 80 bytes, tag a word; with `NETIF_F_HW_VLAN_STAG_TX` cleared: wire 84 bytes, bytes 88a8 0066 86dd; `x1.103` with CTAG_TX cleared: wire 84 bytes as well. NFULA_TCI is absent in the byte case and the egress L2 header is 14 bytes with a tci word against 18 without.

**Limitations.** Two device types and one bridge layout; the `@ll` read side is F37/F52.

**Details.**

Whether a four-byte tag is a byte of the frame or a word in the skb is
decided by an offload capability, not by the protocol -- and on a bridged path
with VLAN devices as ports it is neither at any door.

The tag belongs to the egress device.  Two
questions were left open there: the 802.1ad egress path, and the bridged (L2)
path for the same four bytes.  Both are now measured on 7.3.4; 30 arms per boot,
two boots.

1. The TPID only selects which capability bit is consulted.  `vlan_hw_offload_-
   capable()` maps 0x8100 to NETIF_F_HW_VLAN_CTAG_TX and 0x88a8 to
   NETIF_F_HW_VLAN_STAG_TX (include/linux/if_vlan.h), and a veth advertises
   both.  Clearing the bit with ETHTOOL_SFEATURES moves the *same* tag out of
   the skb and into the frame:

     x1.102 = vlan 102, proto 802.1ad, reorder cleared     -> wire 80 B, tag a word
     same device, NETIF_F_HW_VLAN_STAG_TX cleared          -> wire 84 B, bytes
                                                              88a8 0066 86dd
     x1.103 = vlan 103, proto 802.1Q,  NETIF_F_HW_VLAN_CTAG_TX cleared
                                                           -> wire 84 B as well

   Witnesses: the PACKET_OUTGOING copy on the sending device (80 vs 84 bytes),
   `NFULA_TCI` in the receiving device's `NFULA_VLAN` (absent in the byte case),
   and the egress door of the real device, whose `NFULA_L2HDR` is 14 bytes with a
   `vlan_tci` word and 18 bytes without one.

2. One store, two destinations.  With the device's REORDER flag cleared,
   `vlan_dev_hard_header()` has already put the tag in the bytes when the
   netdev egress hook of the VLAN device runs, so `@ll,14,2 = 0x2066` is
   accepted.  Then:

     capability on    vlan_dev_hard_start_xmit() pops the in-band tag into
                      skb->vlan_tci *reading the stored bytes*: the next door
                      sees 88a8:2066 and the wire carries no tag at all;
     capability off   the store stays in the frame: the wire is 84 bytes ending
                      88a8 2066 86dd.

   The receiving device demultiplexes the same vid in both cases.  What a rule
   changes is not the fate but whether its byte ever leaves the machine as a
   byte.

3. With the REORDER flag *default* there is nothing to write at that door: the
   tag is not built until `vlan_dev_hard_start_xmit()`, which runs after the
   egress hook.  `@ll,14,2` there is refused by `nft_ll_write_ok()` (bound =
   skb_mac_len = 14) and the packet is forwarded untouched; `@ll,12,2` is
   accepted and lands in the frame's ethertype.  A read at the same door cannot
   tell the two worlds apart -- `nft_payload_copy_vlan()` rebuilds the 18-byte
   virtual header from skb->vlan_proto / skb_vlan_tag_get() / skb->protocol --
   so read symmetry hides write asymmetry.

4. On a bridge whose port is a VLAN device, the tag exists at no door at all.
   `vlan_do_receive()` skips the byte reinsertion when the device is a bridge
   port (`!netif_is_bridge_port(vlan_dev)`, net/8021q/vlan_core.c) and clears
   the word unconditionally, so `@ll,12,2` at the bridge prerouting door is the
   frame's own ethertype and a rule asking for `8100` misses.  The ingress
   device's REORDER flag -- the flag that moved `@ll` by four bytes on a layer-3
   device -- is not consulted: two ports with opposite flags give the same
   answer.

   On the way out nobody calls `vlan_dev_hard_header()` either (bridged frames
   skip neighbour resolution), so the port's `vlan_dev_hard_start_xmit()` writes
   its *own* vid as a word after the last door: a frame that arrived with vid 101
   leaves with vid 102, a wire of 80 bytes with no tag in it, and the far end
   demultiplexes 102.  Reproducer, in full:

     ip link add br0 type bridge
     ip link add link x1 name x1.101 type vlan id 101 protocol 802.1Q
     ip link set x1.101 type vlan reorder-hdr off
     ip link add link y1 name y1.102 type vlan id 102
     ip link set x1.101 master br0; ip link set y1.102 master br0
     nft add table bridge t
     nft 'add chain bridge t pre { type filter hook prerouting priority 0; }'
     nft add rule bridge t pre counter accept      # counts 1
     nft add rule bridge t pre '@ll,12,2' '0x8100' counter accept
                                                   # counts 0: not a tag
     nft add rule bridge t pre '@ll,14,2 set 0x0067' counter accept
                                                   # refused, packet unaffected

   And the same offset at the egress port's own door is refused for a different
   reason yet again: there the frame is 14 bytes of header and no tag, so the
   bound is mac_len.

5. `Ip6InReceives +2 / Ip6InDiscards +1` on a
   VLAN device with IPv6 disabled is not a second packet.  `ip6_rcv_core()`
   counts IPSTATS_MIB_IN before it checks `idev->cnf.disable_ipv6` and then
   counts IPSTATS_MIB_INDISCARDS for the same skb
   (net/ipv6/ip6_input.c:206,211).

Measured with 9411 independent checks over two boots: every door counter, every
snmp6 delta, every NFLOG message with its header length, VLAN nest, payload and
hop limit at the index that payload implies, both taps, every read/store outcome
and the byte it had to see or replace.

The consequence worth stating plainly: on the bridged path the frame's ethertype
and the tag's word live at the same `@ll` offset on different doors, and which
one a rule touches depends on a flag of a device the rule does not name.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F57 — the privilege boundary: two gates, one line each

**Claim.** Two different gates stand between a user and a payload store: `CAP_NET_ADMIN` in the namespace that owns the netns for the netlink call, and `ctx->net->user_ns == &init_user_ns` for the store itself; a process that owns its own user and network namespace can install a read-and-drop rule but not a store.

**Minimal reproduction.** instrument `differ579`, modes `priv`, `probe`; 19 traffic arms and four credential contexts (root in the initial netns, uid 1000 in the initial netns, uid 1000 in its own user+net namespace), each with the same four expressions.

**Run.** `bash vm/build_f57_differ.sh` then `bash code/tools/f57_run.sh` — log marker `F579`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nfnetlink.c` checks `netlink_net_capable(skb, CAP_NET_ADMIN)`; `nft_payload_set_init()` checks `ctx->net->user_ns != &init_user_ns` and returns -EPERM; `nft_payload_init()` (the read) and `nft_meta_set_init` have no such check.

**Actual.** root in the initial netns: table 0, chain 0, read 0, store 0, meta 0 (all succeed). uid 1000 in the initial netns: -1 for all five. uid 1000 in its own user+netns: table 0, chain 0, read 0, store -1, meta 0; the same process installs a working `@ll,12,2 = 86dd` read+drop rule.

**Limitations.** The check is measured on this tree only; other nft objects were not swept.

**Details.**

Which of these effects need an administrator, and which are decided by
bytes that arrive with the traffic.  The answer is a pair of gates one line
each, and an asymmetry between reading a packet and writing to it.

No new claim about a defect is made here.  What is new is the boundary itself,
measured on 7.3.4 over two boots, 19 traffic arms and four credential contexts.

1. Two gates, and they are not the same gate.

   net/netfilter/nfnetlink.c:659
       if (!netlink_net_capable(skb, CAP_NET_ADMIN))   -> -EPERM
   is CAP_NET_ADMIN in the user namespace that owns the netns: an unprivileged
   user who unshares CLONE_NEWUSER|CLONE_NEWNET passes it.

   net/netfilter/nft_payload.c:1207 (nft_payload_set_init, the store only)
       if (ctx->net->user_ns != &init_user_ns)
               return -EPERM;
   is stricter: a store into a packet needs a netns owned by the initial user
   namespace.  nft_payload_init (the read) and nft_meta_set_init have no such
   check.

   Measured, same four expressions in each context:

     root in the initial netns        table 0  chain 0  read 0  store 0  meta 0
     uid 1000 in the initial netns    -1       -1       -1      -1       -1
     uid 1000 in its own userns+netns  0        0        0      -1        0

   In the third row the same process fully owns the namespace, creates the
   table and the chain, installs a working `@ll,12,2 = 86dd` read + drop rule
   (counter 1, datagram never arrives) -- and is refused at the store with
   -EPERM.  The one modifying expression available to it is meta set, i.e.
   skb->priority / mark / pkttype.

   Corollary for the record: the WARN in vlan_do_receive that F54 reached by
   storing into skb->vlan_proto is not reachable from a non-init user
   namespace, because the store cannot be installed there at all.

2. A chain naming a device of another namespace is created WITHOUT an error,
   and never fires.  nft_netdev_hook_alloc() walks for_each_netdev(net, dev) of
   its own namespace and returns an empty hook list when nothing matches.  Both
   root hooking `nosuchdev` and a namespace owner hooking `x1` get rc 0.  The
   boundary is therefore enumeration, not an errno: with a drop rule in that
   chain the counter stays 0 and the datagram is delivered inside the
   namespace, while the same rule on the namespace's own device counts 1 and
   delivers nothing.  Moving a port across the border (x0 into the child's
   netns, rc 0) moves no authority either.

3. What a sender without any capability in this namespace decides is the
   MEANING of an offset, not the rule.  Rules below are root's; the frames come
   from a process with no capability in the initial namespace.

     rule (root, netdev ingress)             frame                    counter  delivered
     @ll,12,2 = 8100 -> drop                 802.1Q vid 100               1        0
     @ll,12,2 = 86dd -> drop                 802.1Q vid 100 (inner 86dd)  0        1
     @ll,12,2 = 86dd -> drop                 untagged IPv6                1        0
     @ll,16,2 = 0000 -> drop                 untagged, flow label 0       1        0
     @ll,16,2 = 86dd -> drop                 untagged, flow label 0x86dd  1        0
     @ll,16,2 = 86dd -> drop                 802.1Q vid 100               1        0

   The second row is the one to read twice: the same rule that drops untagged
   IPv6 lets a tagged IPv6 frame through to the socket, because the tag moves
   every @ll offset by four and the sender chooses whether to put one on the
   wire.  (The tagged frame has a destiny only because the receiving netns has
   a VID-100 device; without one it dies as PACKET_OTHERHOST before any IPv6
   counter, as reported earlier.)  The fifth row is the same collision one
   field further in: bytes 16..17 are the flow label on an untagged frame and
   the inner ethertype on a tagged one.

     rule (root, ip6 prerouting)             frame                   counter  delivered
     @nh,6,1 = 17 -> drop                    plain UDP                    1        0
     @nh,6,1 = 17 -> drop                    UDP behind hop-by-hop        0        1
     @nh,6,1 = 17 -> drop                    UDP behind a fragment hdr    0        1
     @nh,6,1 = 0  -> drop                    UDP behind hop-by-hop        1        0
     meta l4proto 17 -> drop                 plain UDP                    1        0
     meta l4proto 17 -> drop                 UDP behind hop-by-hop        1        0

   The fourth row is the control that makes the second and third real misses
   rather than refusals, and the last two show the walker is not evaded by the
   same frame.  This is the ordinary answer to "is this a vulnerability": no --
   the kernel gives a correct spelling for the same intent.

4. The bounds, at their exact edges, which is where a 0-day would have to be.
   Reads: @ll,78,2 on an 80-byte frame is in bounds; @ll,79,2 is not, and the
   failure refuses the RULE (NFT_BREAK, counter 0) while the datagram is still
   delivered.  Writes on the netdev ingress door are bounded by nothing:

       static bool nft_ll_write_ok(const struct nft_pktinfo *pkt, int offset)
       {
               if (nft_in_ingress(pkt->state))
                       return true;
               return offset <= skb_network_offset(pkt->skb);
       }

   @ll,13,2 is accepted although 13+2 > 14, and @ll,20,2 lands in the IPv6
   header (next header 0x20) so the datagram dies with Ip6InUnknownProtos +1.
   That door is the one gate 2 protects, which is why this is a property and not
   a hole.

Measured with 902 independent checks over two boots: every arm's counter, sent
length, delivery, datagram length and six snmp6 deltas, each derived from the
frame's bytes and from the door the rule sits on; determinism between the boots
on every arm field; the census of four contexts against the two gates; the
frames rebuilt in Python including the UDPv6 checksum and compared with what the
child printed as it put them on the wire.  The WARN of the earlier link-layer
section is administrator-only, exactly because of gate 2.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F58 — the three write guards answer three different questions, and none of them asks the length

**Claim.** The three guards are an arithmetic boundary (`@ll`), a whitelist (`@nh`) and an exact coordinate (`@th`); none asks the packet's length, so outside the ingress constant the accepted set is a property of the coordinates, and the packet's own length is the only bound left at netdev ingress.

**Minimal reproduction.** instrument `differ580`, mode `bounds`; 55 arms × 2 boots, two hooks (netdev ingress on a veth, ip6 prerouting), one rule per arm, frame bytes read back through NFLOG.

**Run.** `bash vm/build_f58_differ.sh` then `bash code/tools/f58_run.sh` — log marker `F580`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_ll_write_ok()` is `offset <= skb_network_offset(pkt->skb)` and returns true at ingress; at a layer-3 door `skb_network_offset()` is 0, so with `offset = -mac_len + priv->offset` the check is exactly `off + len <= mac_len`.

**Actual.** At ip6 prerouting on a plain Ethernet device, of nine (off,len) cells with len 2 at offsets 12..50 exactly one is accepted (12,2) and eight are refused. At netdev ingress every cell is accepted, and the frame's own length is the only bound: `@ll,18,2` writes frame bytes 14..15 (the version nibble) and produces Ip6InHdrErrors; `@ll,24,4` writes the next header, hop limit and source bytes and produces Ip6InUnknownProtos.

**Limitations.** Only IPv6 Ethernet frames and two hooks; the length question is answered by the cells, not by a length check in the guard.

**Details.**

The four checks that stand between a payload *store* and the frame.  They
do not answer the same question, and none of them asks the packet's length.  All
numbers below are measured on 7.3.4 over two boots, 55 traffic arms, one rule per
arm, two hooks (netdev ingress on a veth, and ip6 prerouting), with the frame's
bytes read back after the store through NFLOG.

1. nft_ll_write_ok() is an arithmetic comparison, and on ingress there is none.

   net/netfilter/nft_payload.c:986
       if (nft_in_ingress(pkt->state))
               return true;
       return offset <= skb_network_offset(pkt->skb);

   skb_network_offset() is network_header - skb->data, which is 0 at a layer-3
   door, so with offset = -mac_len + priv->offset the check is exactly
   "off + len <= mac_len": do not cross the network header.  At ip6 prerouting
   on a plain ethernet device, of nine cells (off,len = 12..50, 2) exactly one is
   accepted (12,2) and eight are refused.  At the netdev ingress hook the same
   expression is accepted for every cell, and the frame's own length is the only
   bound left:

       @ll,18,2 -> frame bytes 14..15 (the version nibble) -> Ip6InHdrErrors
       @ll,24,4 -> frame bytes 20..23 (next header, hop limit, source[0..1])
                   -> Ip6InUnknownProtos
       @ll,16,2 -> frame bytes 12..13 (the ethertype) and the datagram is still
                   delivered, because eth_type_trans() already decided

2. Where the tag is a word, the accepted set of (offset,len) is not an interval.

   nft_payload_need_vlan_adjust() sends a store through
   nft_payload_set_vlan() as soon as off + len > offsetof(struct ethhdr,
   h_proto) = 12, and that function accepts three pairs before returning
   "the tag is a word":

       10,2 accepted (frame byte 10..11)      10,4 refused
       11,2 refused                           12,1 refused
       12,2 accepted  -> skb->vlan_proto      12,4 accepted -> both fields
       13,2 refused                           14,2 accepted -> skb->vlan_tci
       14,4 refused                           15,2 refused
       16,2 accepted  -> frame byte 12..13    18,2 -> 14..15, 20,2 -> 16..17 ...

   A store that straddles offset 12 is refused, and both sides of it are
   accepted; 13 is refused while 16 is accepted.  The word stores change *not
   one byte of the frame* and yet decide which netdevice receives it: writing
   vlan_proto/tci = 8100 0400, or tci = 0400, delivers the frame to the VLAN
   device of vid 1024 and writing 8100 0fff delivers it nowhere and raises
   rx_otherhost_dropped.  So at the ingress hook a rule chooses the demultiplexer
   with four bytes it does not put into any frame.

3. nft_nh_write_ok_ip6() is a closed whitelist keyed by the chain's family
   (pkt->state->pf), never by the packet: offset 0 (len <= 4, version 6 read from
   the register), 2 (len <= 2), 7 (len == 1), 8 (len <= 32), 24 (len <= 16), and
   nothing else.  Measured: 6 accepted, 8 refused, and the refusals include the
   next-header byte at offset 6 while the hop limit at 7 is accepted.  The same
   byte is writable through the other base: @ll,24,4 on the ingress door writes
   the next-header byte and kills the packet, @nh,6,1 refuses and the packet
   arrives.  If one of the two is intended, the other is worth a comment.

   One practical note on the widest lane: len <= 16 + 16 at offset 8 cannot be
   reached with an immediate -- struct nft_data is 16 bytes and nft_value_init
   returns -EOVERFLOW -- but two payload loads into REG32_08..REG32_15 followed
   by a 32-byte register store are accepted and write exactly 32 bytes, ending on
   the last byte of the header.

4. nft_th_write_ok() is TCP-only, and what it protects is the single byte at
   offset 12 (the data offset), not the header and not the ack sequence:

       (0,2) accepted   (8,4) accepted   (10,4) refused   (12,1) refused
       (13,1) accepted  (0,16) refused

   For every other transport protocol the function returns true, and the only
   remaining bound is skb_ensure_writable().  That is a real bound on the buffer
   but it is invisible to the rule's counter: at ip6 prerouting a UDP store of
   (60,4) is accepted by the guard, fails in skb_ensure_writable(), returns
   NFT_BREAK, and the rule's counter still counts the packet while no log
   message and no store exist.  "The counter incremented" is not evidence that
   the store happened; NFLOG's HWHEADER/PAYLOAD at the same hook is.

No defect claim is made here beyond the two asymmetries above (§2: the accepted
set of @ll where the tag is a word; §3: the next-header byte writable through one
base and not the other).  Both are filter semantics reachable only by rules
installed with CAP_NET_ADMIN in the netns' own user namespace (and, for any
store at all, only in a netns owned by the initial user namespace -- the
follow-up before this one).  What is missing is a sentence of
documentation on each of the four checks saying which question it answers,
because they currently read as if they were four spellings of one rule.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F59 — two chains on one ingress hook point get two different guards

**Claim.** Two base chains on the same ingress hook point get two different guards: `nft_do_chain_inet_ingress()` rewrites `state->pf` from NFPROTO_NETDEV to the packet's family before the chain runs, so a netdev chain has unbounded `@ll`/`@nh` while an inet chain at the same point is bounded.

**Minimal reproduction.** instrument `differ581`, mode `guard`; 63 arms × 2 boots over six hooks (netdev ingress, inet ingress on the same device and hook point, ipv4/ipv6/inet prerouting, arp at NF_ARP_IN), one rule per arm, bytes read through NFLOG.

**Run.** `bash vm/build_f59_differ.sh` then `bash code/tools/f59_run.sh` — log marker `F581`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `nft_ll_write_ok()` and `nft_nh_write_ok()` both test `pkt->state->pf`/`pkt->state->hook`, and `nft_do_chain_inet_ingress()` rewrites `state->pf` from NFPROTO_NETDEV to the packet's family before the chain runs.

**Actual.** Same device, same frame, same hook point: `@ll,14,2` in a netdev chain writes frame byte 14 and produces Ip6InHdrErrors 1, Ip6InReceives 0, no delivery; in an inet chain it is refused (counter 1, no log message) and the frame is delivered. `@ll,16,2` and `@nh,6,1` behave the same way.

**Limitations.** ARP is measured only at NF_ARP_IN; other hook points were not swept.

**Details.**

The guard for a payload store is selected by the *chain's* family and the
*hook number*, and the checksum fixup has a guard of its own that fails silently.
All numbers below are measured on 7.3.4 over two boots, 63 arms, one rule per
arm, six hooks (`netdev` ingress on a veth, `inet` ingress on the same device and
the same hook point, `ipv4`/`ipv6`/`inet` prerouting, and the native `arp`
family at `NF_ARP_IN`), with the frame's bytes read back after the store through
NFLOG, the datagrams counted at a bound socket, and -- for ARP -- what the kernel
learned read back from the neighbour table.

1. Two chains on one ingress hook point get two different guards.

   nft_ll_write_ok() and nft_nh_write_ok() both test
   `pkt->state->pf`/`pkt->state->hook`, and nft_do_chain_inet_ingress()
   rewrites `state->pf` from NFPROTO_NETDEV to the packet's family before the
   chain runs:

       pf = NFPROTO_NETDEV, hook = NF_NETDEV_INGRESS:  @ll unbounded, @nh unbounded
       pf = NFPROTO_IPV6,   hook = NF_INET_INGRESS:   off+len <= 14, ip6 whitelist

   Same device `x1`, same frame, same hook point:

       @ll,14,2  netdev: written (frame byte 14) -> Ip6InHdrErrors 1,
                 Ip6InReceives 0, no delivery
       @ll,14,2  inet:   refused (counter 1, no log message), delivered
       @ll,16,2  netdev: written;                     inet: refused
       @nh,6,1   netdev: written -> Ip6InUnknownProtos 1, no delivery
       @nh,6,1   inet:   refused -> delivered

   Note `Ip6InReceives 0` with `Ip6InHdrErrors 1`: the frame died inside the
   ingress hook (`nft_set_pktinfo_ipv6_ingress()` checks `ip6h->version`),
   before ip6_rcv_core() where IPSTATS_MIB_IN is counted.

2. The IPv4 `@nh` whitelist, measured whole (ipv4 prerouting):

       (0,2) accepted only if the version|ihl octet is unchanged; (0,2) with 55
       refused; (1,1) yes, (1,2) no; (4,2) yes, (4,1) no; (8,1) yes; (8,2) yes
       only if the protocol byte is unchanged; (10,10) yes, (10,11) no;
       (12,8) yes, (12,9) no; (16,4) yes, (16,5) no; (20,2) no.

   `(12,8)` writes saddr+daddr and kills the datagram at the UDP checksum
   (UdpInErrors 1) while IpInHdrErrors stays 0; `(10,10)` rewrites the checksum
   field, both addresses and the frame is routed nowhere without a counter.

3. The ARP guard compares a length, never an end.

       nft_nh_write_ok_arp(): offset >= 8 && len <= 20, plus (6,2) for ar_op.

   The message is 28 bytes. Accepted and written: (8,6) -> the kernel learns
   10.59.0.11 -> a0:a1:a2:a3:a4:a5; (14,4) -> the sender address is rewritten,
   so the entry appears under 10.59.0.77 instead; (24,4) -> the target is no
   longer us and nothing is learned at all; (27,2) and (27,14) -> accepted and
   written past the message, into the ethernet padding of the same frame.
   Refused: (6,1), (7,2), (8,21).
   (27,20) is the separating cell: the guard says yes, `skb_ensure_writable()`
   says no (27+20 > 46-byte skb), so the counter counts and nothing is written.

4. `csum type inet` is not one thing, and where its guard says no it says
   nothing.

       nft_payload_set_eval():
           if (csum_type == INET && nft_payload_csum_write_ok(pkt, priv) &&
               nft_payload_csum_inet(...)) goto err;

   A false guard skips the fixup and lets the store happen.

   * `@nh` in ipv4: the fixup repairs the IPv4 header checksum -- which is
     validated in ip_rcv_core(), i.e. BEFORE a prerouting store. Writing saddr
     without the fixup leaves IpInHdrErrors 0 and the datagram dies at the UDP
     checksum instead. At the *ingress* hook the same write without the fixup
     is fatal (IpInHdrErrors 1, no delivery) and with it the datagram is
     delivered: the same attribute is worthless at one door and decisive at
     the other.
   * `@nh` in ipv6: nft_payload_csum_nh_write_ok() is false, the 16-byte source
     address store is applied and the UDPv6 checksum is left stale
     (Udp6InErrors 1); the same intent spelled `csum_flags=1` (pseudo-header
     update) is delivered.
   * `@th` with a UDP datagram whose checksum field is 0 (legal in IPv4):
     `csum type inet` reads 0 and writes a non-zero value that is not the
     checksum of the modified datagram -> UdpInErrors 1; `csum_flags=1` skips
     the datagram (`nft_payload_l4csum_offset()` returns -1) and it is
     delivered; no fixup at all is also delivered.
   * Three load-time refusals, invisible to the counter because the rule does
     not exist: `csum type inet` on base ll, `csum type inet` with
     `csum_offset != 10` on `@nh` in family ipv4, and `csum type inet`
     together with `csum_flags` on `@th` (-EINVAL).

5. `inet` at prerouting is `ip`/`ip6`; `inet` at ingress is a third thing.
   At prerouting `state->pf` is the packet's family (one ops registered in both
   hook lists), so the four prerouting cells (ipv4 vs inet, with and without
   the fixup) agree exactly. The odd door is ingress, not the family.

6. An empty `inet` ingress chain is not a no-op: it runs
   nft_set_pktinfo_ipv6_ingress() before the first rule, and that parses the
   extension header chain. A frame with a broken destination-options header
   reaches the ipv6 prerouting hook when the table is absent (probe 1) and does
   not when it is present (probe 0, Ip6InHdrErrors 1, Ip6InReceives 0). With a
   broken hop-by-hop header both configurations die in ip6_rcv_core() -- which
   is where the hop-by-hop walk lives -- and only Ip6InReceives tells them
   apart.

Not measured here: a real socket path (skb->ip_summed == CHECKSUM_PARTIAL), on
which the `@th` fixup is deliberately skipped; TCP/ICMP csum_offset; SCTP; IPv4
with options; @nh with csum on the netdev ingress door. All rules were installed
by root in the initial user namespace, which F57 measured to be the only context
where a packet store is accepted at all.

---

## F60 — on a CHECKSUM_PARTIAL datagram the UDP checksum field is the pseudo-header seed, and a transport-base store pays nothing

**Claim.** On a datagram whose L4 checksum the stack has left for the device, the checksum field holds the pseudo-header seed (fad2 for IPv6/UDP, 14ad for IPv4/UDP) rather than the real checksum (7a78, 609e); a transport-base store on such a packet pays nothing, because the fixup block is skipped by the same clause that makes the receiver skip verification.

**Minimal reproduction.** instrument `differ582`, modes `opt`, `part`; 54 arms × 2 boots, one topology with two provenances of the same 18 bytes (a real UDP socket = CHECKSUM_PARTIAL, AF_PACKET = CHECKSUM_NONE), witnesses: the tap's `tp_status` (9 against 1), the rule's NFLOG bytes and a layer-3 witness chain.

**Run.** `bash vm/build_f60_differ.sh` then `bash code/tools/f60_run.sh` — log marker `F582`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `udp6_hwcsum_outgoing()` and `udp4_hwcsum()` write `uh->check = ~csum_ipv6_magic(...)` with a zero payload contribution; the whole fixup block is guarded by `(csum_type == INET || csum_flags) && ...`.

**Actual.** Checksum field fad2 (IPv6) and 14ad (IPv4) against real checksums 7a78 and 609e; `tp_status` 9 on all CHECKSUM_PARTIAL arms and 1 on the AF_PACKET twins; a transport-base store changes no byte the fixup would have touched and the datagram is delivered.

**Limitations.** Not measured: a real device that computes the checksum; only veth with feature bits cleared.

**Details.**

On a packet whose L4 checksum the stack has left for the device to
compute, the checksum field is not a checksum, and the fixup that a payload rule
asks for is skipped -- by the same clause that makes the receiver skip
verification.  All numbers below are measured on 7.3.4 over two boots, 54 arms,
one rule per arm, in one topology with two provenances of the same frame: a real
UDP datagram from a socket in a second netns (CHECKSUM_PARTIAL) and the same 18
bytes thrown in with AF_PACKET (CHECKSUM_NONE).  The receiving tap's auxdata
(`tp_status` 9 = USER|CSUMNOTREADY against 1 = USER) is the flag's witness on
all 54 arms; the frame's bytes are read back after the store through the rule's
own NFLOG message and through a witness chain at layer 3; the datagrams are
counted at a bound socket.

1. The checksum field of a CHECKSUM_PARTIAL datagram is the pseudo header.

   udp6_hwcsum_outgoing() and udp4_hwcsum() write

       uh->check = ~csum_ipv6_magic(saddr, daddr, len, IPPROTO_UDP, 0);

   i.e. the pseudo-header sum with a zero payload contribution.  Measured:
   fad2 for IPv6/UDP and 14ad for IPv4/UDP, where the same datagrams' real
   checksums are 7a78 and 609e.  Nothing on the wire distinguishes the two
   meanings; the device that was supposed to add the payload and complement is
   the only thing that does.

2. A transport-base store pays nothing on such a packet.

   The whole fixup block of nft_payload_set_eval() is guarded by

       (csum_type == INET || csum_flags) &&
       ((base != TRANSPORT_HEADER && base != INNER_HEADER) ||
        skb->ip_summed != CHECKSUM_PARTIAL)

   so at @th on CHECKSUM_PARTIAL neither `csum type inet` nor `csum flags` runs,
   and the bounds check `offset + len > skb->len` that lives inside the block is
   skipped with them.  `@th,8,4 = a0a1a2a3` on a socket datagram: the field
   stays fad2, the datagram is delivered, and the field is not a checksum of
   what arrived.  The identical rule on the identical frame with CHECKSUM_NONE:
   the field stays 7a78, the receiver verifies, the datagram dies
   (Udp6InErrors 1).  With `csum type inet` and CHECKSUM_NONE the field becomes
   3a38 -- the correct checksum of the modified datagram -- and it is delivered;
   with `csum type inet` and CHECKSUM_PARTIAL it stays fad2.

   The receiver's half of the same story is skb_csum_unnecessary():

       skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_start_offset(skb) >= 0

   -- no verification.  One flag, two readers, opposite conclusions, and on a
   veth the "somebody else" both of them rely on does not exist: veth advertises
   NETIF_F_HW_CSUM and dev_forward_skb() -> skb_scrub_packet() does not touch
   ip_summed or csum_start, so the flag crosses the wire with the frame.

3. One rule, one frame, two fates -- IPv4 source address.

   `@nh,12,4 = 10.59.0.99` at the netdev ingress door breaks the IPv4 header
   checksum before ip_rcv_core() runs (IpInHdrErrors 1, both provenances).  With
   `csum type inet` the header checksum is repaired (IpInHdrErrors 0) and then:

       CHECKSUM_PARTIAL:  delivered, UDP field 14ad (the old pseudo-header seed)
       CHECKSUM_NONE:     dropped,  UdpInErrors 1 (UDP field 609e is stale)

   Adding `csum flags` makes both deliverable, and the two fields are different
   numbers by design: 1505 is the adjusted seed, 6046 the real checksum of the
   modified datagram.  1505 - 14ad = 0x58, exactly the pseudo-header delta.

4. On IPv6 the source address is not fixed at all.

   nft_payload_csum_nh_write_ok() returns false for NFPROTO_IPV6, and a false
   guard there is not a refusal -- the fixup is skipped and the store is made.
   The CHECKSUM_NONE datagram then dies (7a78 is not 3a47, Udp6InErrors 1); the
   CHECKSUM_PARTIAL one is delivered with a field that no one will ever check.
   `csum flags` walks the same field and keeps it consistent in both worlds.

5. A store into the checksum field itself is applied after the fixup, so the
   fixup cannot save it: with `@th,6,2 = dead` the field is dead and the
   CHECKSUM_NONE datagram dies in both cases; the CHECKSUM_PARTIAL one is
   delivered.

6. IPv4 with options: the @nh guard is a 20-byte template.

   nft_nh_write_ok_ip4() is a switch over offsetof(struct iphdr, ...): 0, 1, 4,
   8, 10, 12, 16.  On a legal 60-byte header (ihl 15) every offset in 17..59 is
   refused (counter 1, no log message, datagram delivered), while (0,2) with the
   same first octet, (8,2) with the same protocol, (12,4) and (16,4) are
   accepted -- the guard never reads ihl.  The delta fixup keeps a 60-byte
   header checksum valid (IpInHdrErrors 0), and its absence is invisible at the
   prerouting door because ip_rcv_core() is already behind it: without the
   fixup IpInHdrErrors is 0 and the datagram dies at the UDP checksum instead.
   @th does follow ihl -- @th,0,2 = 1234 rewrites the source port of an ihl-6
   datagram (recvfrom reports 4660), and @th,20,2 lands at payload offset 12 at
   both ihl because the offset is relative to thoff.

   A frame with ihl 4, and a frame whose total length is below ihl*4, never
   reach the hook (counter 0, IpInHdrErrors 1): ip_rcv_core() refuses them
   first, so the 20-byte template cannot be confused by a lying ihl.  A
   non-first fragment refuses @th (pkt->fragoff); a first fragment accepts it.

7. Not measured, and not claimed: a real device that computes the checksum
   (CHECKSUM_UNNECESSARY/CHECKSUM_COMPLETE), GSO, `csum` for TCP/ICMP/SCTP on
   these two provenances, the forwarded path, bridge/inet-ingress/arp doors in
   this configuration.  All rules were installed by root in the initial user
   namespace, which by F57 is the only context where a packet store is
   installable at all, so none of this is offered as a vulnerability.

Instrument note for anyone repeating this: the AF_PACKET tap is not a witness of
a rule's write.  In both boots all 28 tap records carried the frame before the
store, while the rule's own NFLOG payload carried it after; one earlier build of
the same code showed the opposite for one arm, and no mechanism is known for the
difference.  The NFLOG copy is the witness.

---

## F61 — the forwarded path with CHECKSUM_PARTIAL: who computes the checksum

**Claim.** On a forwarded datagram the price of a payload write is paid by the exit device, in whatever the checksum field holds at the time, and only for packets that arrive with CHECKSUM_PARTIAL: an exit with `NETIF_F_HW_CSUM` carries the pseudo-header seed to the wire, one without it carries a true checksum.

**Minimal reproduction.** instrument `differ583`, mode `fwd`; 25 arms × 2 boots, ip6 forward chain of a router netns, two exit devices that differ in `NETIF_F_HW_CSUM` (bit 3, cleared with ETHTOOL_SFEATURES), two provenances of the same 80 bytes.

**Run.** `bash vm/build_f61_differ.sh` then `bash code/tools/f61_run.sh` — log marker `F583`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `skb_checksum_help()` computes the checksum and sets `ip_summed = CHECKSUM_NONE` when the device cannot checksum; the rule's `csum type inet` fixup runs only if it is reached before that.

**Actual.** With no rule: P = fad4 (to fd03::92) and fad5 (to fd04::92); the true checksums are 7a76 and 7a75. The exit with `NETIF_F_HW_CSUM` puts fad4/fad5 on the wire; the exit without it puts the true checksum. A store into the checksum field turns the receiver's verification on.

**Limitations.** GSO (clearing NETIF_F_HW_CSUM also clears NETIF_F_GSO_UDP_L4) is F62.

**Details.**

On a forwarded datagram the price of a payload write is paid by the EXIT
DEVICE, in whatever the checksum field holds at the time, and only for packets
that arrive carrying CHECKSUM_PARTIAL.  That makes the rule's own checksum
option dead code on that path and makes a store into the checksum field a way
to turn the receiver's verification ON.  All numbers are measured on 7.3.4 over
two boots, 25 arms, one rule per arm in the ip6 forward chain of a router netns,
between a sender netns and a receiver netns, with two exit devices that differ
in one feature bit (NETIF_F_HW_CSUM, bit 3, cleared with ETHTOOL_SFEATURES).

Frame: 14 eth + 40 IPv6 + 8 UDP (43580 -> 5000) + 18 bytes 0x80..0x91.
Two provenances of the same 80 bytes: a real UDP datagram from a socket in the
sender netns (CHECKSUM_PARTIAL; the field carries the pseudo-header seed P) and
the same bytes injected with AF_PACKET (CHECKSUM_NONE; the field carries the
true checksum).  Witnesses per arm: the rule's counter and its own NFLOG message
at the forward door, an AF_PACKET tap on each exit device (outgoing frames, so
after validate_xmit_skb), an AF_PACKET tap on each receiving device (the
arriving flag), and a bound socket in the receiver netns.

1. With no rule at all, the exit device decides what the checksum field means.

   P = fold16(pseudo header) = fad4 (to fd03::92) and fad5 (to fd04::92); the
   true checksums of the same datagrams are 7a76 and 7a75.

       exit with NETIF_F_HW_CSUM  ->  the frame on the wire carries fad4
       exit without it            ->  the frame carries 7a75

   skb_checksum_help() computed the second one and set ip_summed =
   CHECKSUM_NONE; on the first exit nobody computed anything and the flag is
   still CHECKSUM_PARTIAL (the exit tap's auxdata says 9 = USER|CSUMNOTREADY
   against 1 = USER).  Both datagrams are delivered: the receiving stack skips
   verification on CHECKSUM_PARTIAL (skb_csum_unnecessary()) and verifies the
   other one, which is correct.  The flag crossed two netns boundaries because
   skb_scrub_packet() (net/core/skbuff.c:6312) does not touch ip_summed.

2. A payload store is free on the offloading exit and paid on the other one.

   `@th,8,4 = a0a1a2a3` is accepted at the forward door in every arm (counter 1,
   the rule's own message carries the stored bytes).

       exit with the bit     ->  the field is still fad4; delivered; the frame
                                 would fail any CHECKSUM_NONE arithmetic
       exit without the bit  ->  the field is 3a35, which is exactly the true
                                 checksum of the modified datagram; delivered

   So the device that never saw the rule paid for it, and paid correctly --
   because the seed it summed was the pseudo header of the same datagram.

3. `csum type inet` and `csum flags` are dead code on that path.

   Four arms with them are byte-identical to the arms without (whole frame
   compared, both exits).  nft_payload_set_eval() skips the entire fixup block
   when the base is TRANSPORT_HEADER and skb->ip_summed == CHECKSUM_PARTIAL,
   and every socket datagram arrives exactly like that.

4. A store into the checksum field itself: one rule, two fates.

       `@th,6,2 = dead`
       exit with the bit     ->  the wire carries dead, the datagram is
                                 DELIVERED (nobody checks)
       exit without the bit  ->  the device rewrites the field with
                                 ~fold(S0 + 0xdead) = 969d, which is not a
                                 checksum, and sets ip_summed = CHECKSUM_NONE;
                                 the receiver now checks and DROPS it
                                 (Udp6InErrors +1)

   Where the device stays silent, garbage arrives; where it pays, the datagram
   dies.  The payer's arithmetic is a function of the field it finds, not of
   what the rule meant.

5. A source-address store is paid with the OLD pseudo header.

   `@nh,8,16 = fd02::77`: the exit without the bit computes ~fold(S0 + P_old)
   = 7a75 -- the checksum of the datagram as it was before the store -- and the
   receiver, which uses the new source address, drops it.  The same frame
   through the offloading exit is delivered, because it is never checked.
   `csum type inet` changes nothing here: nft_payload_csum_write_ok() refuses
   for NFPROTO_IPV6 with base NETWORK_HEADER.

6. Writing the seed itself reproduces the untouched frame.

   A rule that stores fad5 into the field gets 7a75 on the wire -- byte for
   byte the census frame.  The "payment" is a function of the field.

7. In the CHECKSUM_NONE world no device pays anywhere.

   validate_xmit_skb() asks for help only under CHECKSUM_PARTIAL
   (net/core/dev.c:4107), so the same stores are fatal through both exits and
   only the rule's own `csum type inet` / `csum flags` repair them (3a36,
   delivered).  The same store that is harmless on a socket datagram
   (sp_s_a: delivered, field fad4) kills the AF_PACKET one (sp_p_a: dropped,
   field 7a76).

Not a vulnerability: every rule here was installed by root in the initial user
namespace, which F57 measured to be the only context in which a payload store
installs at all.  What this is: the price of a write is not a property of the
write.  It is a property of the exit device's feature bit, of the flag the
packet happens to carry, and of the bytes already in the field the payer
trusts -- none of which a rule can see or express.

Not measured: GSO (clearing NETIF_F_HW_CSUM also clears NETIF_F_GSO_UDP_L4,
so a segmented datagram takes the segmentation path instead, which is a
separate question), IPv4 on this path, CHECKSUM_UNNECESSARY/COMPLETE, TCP and
ICMP with these stores, and any real NIC: the exits are veth pairs.

---
