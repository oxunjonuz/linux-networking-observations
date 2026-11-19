# Potential defects, expected Linux behaviour, and regression tests

Two rules govern this file.

1. A row in section 1 is an **observation**, never a confirmed bug.  The
   measurement shows behaviour that differs from what the code's own guard, its
   declared field table, or the rule's coordinate promises; the last column
   names the evidence that would settle whether it is a defect.  Nothing here
   has been reported upstream, and every rule involved needs root in the initial
   user namespace.
2. A row in section 2 is behaviour that looks surprising but is what Linux is
   designed to do; the measurement is the anchor, not a complaint.

Section 3 lists, for every finding, the invariant a regression test would pin.
Each test can be run from this bundle: build the instrument and boot it as in
`HOW_TO_RUN.md`, then read the log marker named in the finding.

## 1. Potential defects — observations only

| finding | observation | why it is not called a confirmed bug | what would confirm it |
|---|---|---|---|
| F29 | The inner-base store (`@ih`) writes the TCP data-offset byte that the transport-base guard refuses, through VXLAN, Geneve and ipip. | It needs root in the initial user namespace, and the source states the assumption it rests on ("real l3/l4 headers cannot be mangled") -- which tunnel frames contradict. Reported as a gap in a guard, not as a vulnerability. | An upstream patch that gives the inner base a guard, or a maintainer statement that the current behaviour is intended. |
| F30 | `ip6 ecn set` and `ip6 flowlabel set` install with rc=0 and never change a byte, while their IPv4 twins work. | The whitelist refuses (fail-closed), so the effect is a silent no-op, not a memory-safety issue; only the declared spellings were measured. | A change in nft's rounding for `proto_ip6`, or a kernel case that accepts offset 1. |
| F31 | At the netdev ingress hook the guard is a constant; under an ARP label the branch admits a 4-byte store at offset 8 with no upper bound inside the 28-byte ARP message. | The ingress constant is intended (there is no envelope at ingress); the ARP bound is a coordinate check reachable only by root. | A store past the end of the ARP message that survives in a configuration the maintainers treat as supported. |
| F32 | Four of nft's nine declared ARP fields (`htype`, `ptype`, `hlen`, `plen`) never reach a byte. | The guard refuses (fail-closed); the mismatch is between the declared field table and the guard's predicate. | A guard extended to the four declared offsets, or a statement that they are intentionally dead. |
| F36 | A `@ll` store on a tagged forwarded frame rewrites its ethertype on the wire (0x0800 to 0x0806), while the same store on an untagged frame is refused. | Root-only; the store lands on the byte the coordinate names, and the question is whether that coordinate should be the frame's. | A maintainer decision on `@ll` semantics when the tag is in skb metadata. |
| F37 | A two-byte store at `(12,2)` can leave a frame with ethertype 0x0000 while `skb->protocol` stays 0x0800 and the bridge keeps forwarding it. | Root-only, and it is the result of a store the guard deliberately allows into `skb_vlan_proto`. | A guard that refuses a store which clears the ethertype. |
| F39 | A Q-in-Q frame is refused by all 40 network-base cells, while `meta protocol` reports 0x0800 for the same frame. | The refusal is fail-closed; the two subsystems disagree about the same frame. | A case for 0x8100 in `nft_nh_write_ok_bridge()`. |
| F40 | After `meta protocol` on a Q-in-Q frame, an `@nh` cell compares one field and writes the field four bytes earlier. | Root-only; no memory-safety claim, and the read side is the one that was repaired. | A patch that makes `nft_payload_set_eval()` add `pkt->nhoff`, as the read does. |
| F41 | On PPPoE the `@nh` read lands on the real IPv4 header and the store eight bytes earlier, so none of the 14 accepted cells writes the field it names. | Root-only; the frame is delivered with a rewritten PPPoE header or dropped, never corrupted in memory. | A patch aligning the PPPoE store with the read. |
| F42 | A bridge `@nh` store on a real PPPoE session lands in the PPPoE header and is consumed by the IP stack (an `ip id` store becomes the PPPoE length). | Root-only; the consequence is a delivered or dropped datagram, not memory corruption. | A patch or a maintainer ruling on the PPPoE coordinate. |
| F47 | The IPv6 network-base whitelist has no case for offset 4 (`payload_len`) and none for offset 6 (`next header`), at every door and class. | The guard refuses (fail-closed). | A case added for offsets 4 and 6, with a value check where needed. |
| F48 | At the netdev egress hook on a PPPoE frame, `meta protocol` gives `@th` the right coordinate and `@nh` a coordinate inside the frame by 22 bytes. | Root-only; a rule can be written that reads one base and the other stays dead. | A constructor that validates the version byte at the repaired offset. |
| F50 | `@ll` reads run past the link header while writes stop at `mac_len`, and the same verdict covers two doors whose consequences are opposite. | Root-only; the read-side domain is intentional (it lets a rule read the network header through `@ll`). | A documented statement of the two domains, or a guard that bounds both the same way. |
| F54 | A root rule can trigger the `invalid VLAN protocol` WARN once per frame, and every such frame is then dropped. | It needs root and a device with a `vlan_info`; a WARN is a diagnostic, not a crash, and the frame is dropped cleanly. | A maintainer statement whether the WARN is reachable by design from a payload store. |
| F59 | Two base chains on the same ingress hook point get two different guards: a netdev chain is unbounded at `@ll`/`@nh`, an inet chain at the same point is bounded. | Root-only; it follows from the `pf` rewrite in `nft_do_chain_inet_ingress()` and is only observable with two chains. | A decision that the two chains should share one guard. |

## 2. Expected Linux behaviour

| finding | behaviour | measured anchor |
|---|---|---|
| F35 | The `@ll` bound is the current envelope's link-header length, and 0 inside an L3 tunnel. | Bare Ethernet 14; tagged 18; ipip 0. |
| F38 | The 802.1Q tag is popped before every hook, so the guard judges `skb->vlan_all` and `skb->protocol`. | A tagged frame reaches the far side at 60 bytes; a 9100 frame is not popped. |
| F43 | The transport base is exact or refused: read and store share `nft_thoff(pkt)`. | Q-in-Q 0/8 live without `meta protocol`, 8/8 with it. |
| F44 | Four pktinfo constructors agree on one transport coordinate at every door. | 348 arms, four doors, two priorities each. |
| F45 | IPv6 computes `@th` by walking extension headers, and the walk's failure modes carry three verdicts. | 524 arms, five doors, extension-header frames. |
| F46 | `@ll` exists only where a MAC header was built, so the traffic class decides its verdict away from the receive path. | Local datagrams 0/12 at local_out; forwarded frames 10/12. |
| F49 | On ppp0 `@ll` does not exist and `@nh` is correct: no constructor has anything to add after `ppp_input()`. | Hop limit 40 read at `@nh,7,1`; `@ll` refused for every non-zero end. |
| F51 | A store reaches exactly the copies the kernel makes after it; earlier copies are protected by copy-on-write. | A store at bridge prerouting reaches all three copies; the same store at forward reaches one. |
| F52 | A tag with a non-zero vid and no VLAN device is `PACKET_OTHERHOST` before any IP counter, and a TCI store changes delivery without changing a wire byte. | rx_otherhost_dropped moves; Ip6InReceives stays 0. |
| F53 | `VLAN_FLAG_REORDER_HDR` decides whether the tag is frame bytes or a skb word at the layer-3 doors. | 80 bytes untagged against 84 tagged; mac_len 14 against 18. |
| F55 | The PCP travels through `skb->priority` and the device's egress map, not through a store into the tag. | TCI 0x6066 on the wire, read by four witnesses. |
| F56 | The tag's representation follows the device's offload bits, not the TPID. | Wire 80 bytes with the bit set, 84 without; NFULA_TCI present or absent. |
| F57 | Two privilege gates: `CAP_NET_ADMIN` for the netlink call, and `init_user_ns` for a payload store. | uid 1000 in its own user+netns: table 0, chain 0, read 0, store -1, meta 0. |
| F58 | The three write guards are a boundary, a whitelist and a coordinate; none asks the packet's length. | One of nine `@ll` cells accepted at ip6 prerouting; all accepted at netdev ingress. |
| F60 | On a CHECKSUM_PARTIAL datagram the UDP checksum field is the pseudo-header seed, and the fixup block is skipped. | fad2 (IPv6) and 14ad (IPv4) against real checksums 7a78 and 609e. |
| F61 | On the forwarded path the exit device decides what the checksum field means and who pays for a store. | The same datagram: fad4 on an exit with NETIF_F_HW_CSUM, 7a75 without it. |
| F62 | The two exits segment in different places, so the same payload store is free on one and paid on the other. | One 1262-byte frame against three of 574/574/238. |

## 3. Regression tests

Each row names the invariant a test should pin and the run that measures it. A test is expected to fail if the invariant moves; the numbers to compare against are in the finding's **Actual** line.

| finding | invariant to pin | run |
|---|---|---|
| F29 | The byte at inner transport offset 12 is refused by the transport-base guard and written by the inner-base store; a test that pins the two bases to the same verdict would catch a regression in either direction. | `code/tools/f29_run.sh` (marker `F551`) |
| F30 | `ip6 ecn set` and `ip6 flowlabel set` must either be accepted at the cell they name or refused with an error; a test that installs each spelling and reads the byte back pins this. | `code/tools/f30_run.sh` (marker `F552`) |
| F31 | Every door applies the same verdict to the same `(offset,len)` store on the same bytes; the cell table in F33 is the reference a test should pin. | `code/tools/f31_run.sh` (marker `F553`) |
| F32 | The guard's accept-set is exactly `(6,2)` plus `off>=8 && len<=20` at the input hook, and four declared fields never reach a byte. | `code/tools/f32_run.sh` (marker `F555`) |
| F33 | Each envelope's accept-set is a fixed subset of the 40-cell grid; a change in any branch moves exactly one column. | `code/tools/f33_run.sh` (marker `F556`) |
| F35 | The link-layer guard is a boundary at the envelope's own link-header length; a test pins the accepted/refused cells per envelope. | `code/tools/f35_run.sh` (marker `F557`) |
| F36 | A tagged forwarded frame's ethertype and tag state after a `@ll` store are the same on the wire and in the skb; a test compares the egress frame with the rule's named field. | `code/tools/f36_run.sh` (marker `F558`) |
| F37 | Tagged and untagged frames carrying the same L2 bytes must receive the same verdict at the same cells. | `code/tools/f37_run.sh` (marker `F559`) |
| F38 | The tag's presence in the frame is decided before the hook; the guard's cells follow `skb_vlan_tag_present()`. | `code/tools/f38_run.sh` (marker `F560`) |
| F39 | A two-tag frame is judged in the same coordinates as a one-tag frame, or is refused with a case that names it. | `code/tools/f39_run.sh` (marker `F561`) |
| F40 | For every `@nh` cell the byte read and the byte written are the same byte; a test reads back the cell the rule names. | `code/tools/f40_run.sh` (marker `F562`) |
| F41 | On a PPPoE frame the byte a `@nh` cell names is the byte the store writes, or the store is refused. | `code/tools/f41_run.sh` (marker `F563`) |
| F42 | A `@nh` store on a PPPoE frame either reaches the field it names or is refused; no cell may write the PPPoE header under an IP field name. | `code/tools/f42_run.sh` (marker `F564`) |
| F43 | Read and store share one transport coordinate; a test pins the byte offset per envelope. | `code/tools/f43_run.sh` (marker `F565`) |
| F44 | All pktinfo constructors agree on the transport offset for the same frame; a test compares the byte written through each door. | `code/tools/f44_run.sh` (marker `F566`) |
| F45 | The transport base in IPv6 equals the end of the extension-header walk; a test pins one cell per extension-header shape. | `code/tools/f45_run.sh` (marker `F567`) |
| F46 | `@ll` is accepted exactly where a MAC header exists and the write ends inside it; a test pins the cell table per traffic class. | `code/tools/f46_run.sh` (marker `F568`) |
| F47 | The IPv6 whitelist's accepted offsets are exactly {0,1,2,8,24}; a test stores at 4 and 6 and expects a refusal. | `code/tools/f47_run.sh` (marker `F569`) |
| F48 | At one door `meta protocol` yields one coordinate for every base; a test reads the version byte and the hop limit through `@nh` and `@th` and compares them with the frame. | `code/tools/f48_run.sh` (marker `F570`) |
| F49 | A device with no link-layer header refuses `@ll` and keeps `@nh` correct; a test pins both. | `code/tools/f49_run.sh` (marker `F571`) |
| F50 | A `@ll` store at a bridge door reaches exactly the copies the kernel makes after it; the read and write domains are the same or the difference is documented in the guard. | `code/tools/f50_run.sh` (marker `F572`) |
| F51 | A store reaches the copies made after it and no others; the neighbour/forwarding entry learned from the stored bytes is visible in the bridge table. | `code/tools/f51_run.sh` (marker `F573`) |
| F52 | The inner ethertype is read at the offset the tag state implies, and a dropped vid is counted where the kernel drops it. | `code/tools/f52_run.sh` (marker `F574`) |
| F53 | A per-device flag moves the `@ll` domain and the guard by exactly four bytes; a test pins the offsets on both configurations. | `code/tools/f53_run.sh` (marker `F575`) |
| F54 | The tag on the wire equals the egress device's configuration, not the bytes a rule wrote; a test compares the stored TCI with the wire and pins the WARN to the same condition. | `code/tools/f54_run.sh` (marker `F576`) |
| F55 | The PCP on the wire is a function of `skb->priority` and the device's egress map; a test pins the TCI for a given priority. | `code/tools/f55_run.sh` (marker `F577`) |
| F56 | The tag's representation follows the device's offload bits; a test flips the bit and pins the wire length and NFULA_TCI. | `code/tools/f56_run.sh` (marker `F578`) |
| F57 | The two gates are independent: a read is available in a user-owned netns, a store is not; a test pins both errnos. | `code/tools/f57_run.sh` (marker `F579`) |
| F58 | The accepted cells of each guard are exactly the ones its coordinate arithmetic allows; a test pins the cell tables at both hooks. | `code/tools/f58_run.sh` (marker `F580`) |
| F59 | At one hook point the two chains' guards differ in exactly the way the `pf` rewrite requires; a test pins both verdicts. | `code/tools/f59_run.sh` (marker `F581`) |
| F60 | The checksum field's meaning follows `ip_summed`; a test pins the field's value for both provenances. | `code/tools/f60_run.sh` (marker `F582`) |
| F61 | On the forwarded path the checksum on the wire is a function of the exit device's features and the arriving `ip_summed`; a test pins both exits. | `code/tools/f61_run.sh` (marker `F583`) |
| F62 | The number of frames on the wire and the checksum each carries are a function of the exit device's features; a test pins both exits. | `code/tools/f62_run.sh` (marker `F584`) |
| F63 | A rule reading the UDP header of an aggregate reads the aggregate's header, which is a function of the GRO door; a test pins both doors' values. | `code/tools/f63_run.sh` (marker `F585`) |
| F64 | For a given composition and door, `uh->len` and `uh->check` are fixed; a test pins the four combinations. | `code/tools/f64_run.sh` (marker `F586`) |
| F65 | Delivery time of an un-followed datagram is the flush timeout; a test pins 201 ms and the 402 ms second flow. | `code/tools/f65_run.sh` (marker `F587`) |
| F66 | For each door the last merging payload is fixed by the two inequalities; a test pins 1022/1023 and the two tails. | `code/tools/f66_run.sh` (marker `F588`) |
| F67 | `rmem` after an aggregate equals the sum of the segments' prices below half a buffer and the collapsed head's price above it; a test pins both regimes. | `code/tools/f67_run.sh` (marker `F589`) |
| F68 | The 40-byte family shift is visible in exactly the one cell the arithmetic requires; the queue numbers are family-independent. | `code/tools/f68_run.sh` (marker `F590`) |
| F69 | The fraglist cap is `2H + (n+1)*P <= 65535` and the price total is `(2k-1)*s`; a test pins 39+1 at 1637 bytes and the ladder's first and last cells. | `code/tools/f69_run.sh` (marker `F591`) |
| F70 | `skb_condense()` is called iff `rmem > rcvbuf >> 1`, and the queue's bill collapses only above half a buffer; a test pins the 14080/7680 pair on either side of the boundary. | `code/tools/f70_run.sh` (marker `F592`) |
| F71 | `data_len == end - tail` pulls and one more byte returns; a test pins the three boundaries and the one-enqueue/two-enqueue contrast. | `code/tools/f71_run.sh` (marker `F593`) |
| F72 | Zerocopy is refused by the linear GRO door and merged by the fraglist door; a test pins six-vs-one packet and the per-offset charge. | `code/tools/f72_run.sh` (marker `F594`) |
| F73 | Zerocopy charge equals `960 + PAGE_ALIGN(payload + page offset)`; a test pins 5056/9152/13248 for the three placements. | `code/tools/f73_run.sh` (marker `F595`) |
| F74 | The queue's capacity is `floor(R/charge)` and the charge is set by the sender's page offset; a test pins 17695/17696 and the 7-vs-4 pair. | `code/tools/f74_run.sh` (marker `F596`) |

## 4. What is not in this file

No finding here is called a vulnerability, and no row in section 1 is called a confirmed bug: a confirmation would need a maintainer statement or a patch, neither of which this bundle contains.  Memory safety was not tested anywhere; the privilege boundary is measured in F57 and every other finding assumes the same root context.
