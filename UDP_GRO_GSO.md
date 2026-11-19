# UDP GRO and GSO on the receive and forwarding path

Measurements of the UDP receive path, F62-F74: the aggregate a GRO door builds
and the header it presents to a rule, the two ceilings that end aggregation, the
price a receive queue charges, `skb_condense()`, and the two doors a forwarded
datagram can take into a queue.  The instrument that produced every number is in
`code/`; `HOW_TO_RUN.md` maps each finding to its modes, runner and log marker.

Each finding is written in six parts: **Claim**, **Minimal reproduction**,
**Run**, **Expected**, **Actual**, **Limitations**, followed by **Details** with
the full evidence.  The reproducing code is the instrument the finding names;
its source is in `code/`, and the exact arm, rule and byte are under **Details**.

Scope: every rule was installed by root in the initial user namespace.  The
numbers here are accounting and packet shape, not memory safety; a real NIC, TCP
GRO and tunnels were not measured unless a finding says otherwise.  See
`BUGS_AND_TESTS.md` for the three-way triage and the regression invariant of
each finding.


## Index

| finding | subject | instrument | modes | runner |
|---|---|---|---|---|
| F62 | a UDP-GSO datagram with two exit devices: who segments, and who pays for a FORWARD store | `code/vm/differ584_add.c` | `gso` | `code/tools/f62_run.sh` |
| F63 | GRO hands the rule a packet the sender never sent | `code/vm/differ585_add.c` | `aggr` | `code/tools/f63_run.sh` |
| F64 | an aggregate presents a rule with a header that describes no datagram | `code/vm/differ586_add.c` | `geom` | `code/tools/f64_run.sh` |
| F65 | the packet that nothing follows | `code/vm/differ587_add.c` | `cap`, `flow` | `code/tools/f65_run.sh` |
| F66 | two ceilings, one budget | `code/vm/differ588_add.c` | `cap`, `split` | `code/tools/f66_run.sh` |
| F67 | the head of an aggregate pays for the whole aggregate, and above half a buffer that number collapses | `code/vm/differ589_add.c` | `cond`, `dflt` | `code/tools/f67_run.sh` |
| F68 | the IPv4 twin of the GRO byte cap and of the receive-queue budget | `code/vm/differ590_add.c` | `cap4`, `cond4` | `code/tools/f68_run.sh` |
| F69 | where an aggregate's price comes from, and how the byte cap actually binds | `code/vm/differ591_add.c` | `cap`, `price` | `code/tools/f69_run.sh` |
| F70 | the branch, and its boundary | `code/vm/differ592_add.c` | `cond` | `code/tools/f70_run.sh` |
| F71 | the skb behind `skb_condense()`'s first clause, measured at the function | `code/vm/differ593_add.c` | `gro` | `code/tools/f71_run.sh` |
| F72 | what a user page does to the two UDP GRO doors, measured at the doors | `code/vm/differ594_add.c` | `cl`, `zc` | `code/tools/f72_run.sh` |
| F73 | where the page charge comes from, and who clones on the receive path | `code/vm/differ595_add.c` | `all`, `chg`, `cln`, `spl` | `code/tools/f73_run.sh` |
| F74 | what the offset charge does to the queue, and where the head of a copied datagram comes from | `code/vm/differ596_add.c` | `all`, `h`, `q` | `code/tools/f74_run.sh` |

## F62 — a UDP-GSO datagram with two exit devices: who segments, and who pays for a FORWARD store

**Claim.** On the GSO path the price of a payload write is paid by whoever segments: an exit that keeps `NETIF_F_GSO_UDP_L4` puts one 1262-byte frame with the whole-datagram seed on the wire and the receiver cuts it, while an exit without it cuts on the way out and computes each segment's checksum from the bytes as they stand; the same store is free on one door and paid on the other.

**Minimal reproduction.** instrument `differ584`, mode `gso`; 25 arms × 2 boots, ip6 forward chain of a router netns, one 1200-byte UDP datagram sent with UDP_SEGMENT 512 (segments 512/512/176), two exits differing in NETIF_F_GSO_UDP_L4 and NETIF_F_HW_CSUM.

**Run.** `bash vm/build_f62_differ.sh` then `bash code/tools/f62_run.sh` — log marker `F584`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `validate_xmit_skb()` segments only when the device lacks the feature; `__udp_gso_segment()` computes each segment's checksum from the bytes.

**Actual.** With no rule, y1 puts one 1262-byte frame with checksum ff72 (fold16 of the pseudo header with length 1208) and the receiver gets 512/512/176; y2 puts three frames 574/574/238 with uh->len 520/520/184 and checksums 82af/82af/1f91 valid per frame. `@th,8,4 = a0a1a2a3` is free on y1 and paid on y2; a store into either header field the segmenter reads breaks every segment at once.

**Limitations.** Only veth with feature bits cleared; no real NIC.

**Details.**

On the GSO path the price of a payload write is paid by whoever
segments, and the two exit devices segment in different places.  One carries
the datagram whole to the wire and lets the RECEIVER cut it into
CHECKSUM_PARTIAL pieces that nobody ever verifies; the other cuts it on the way
out and then computes every segment checksum from the bytes as they stand.  The
same four-byte store is therefore free on one door and paid on the other, and a
store into either of the two header fields the segmenter reads breaks every
segment at once -- one of them while leaving the wire looking untouched.
Measured on 7.3.4 over two boots, 25 arms, one rule per arm in the ip6 forward
chain of a router netns, between a sender netns and a receiver netns.

Frame: ONE 1200-byte datagram sent with UDP_SEGMENT = 512 (gso_size 512,
gso_segs 3), so it leaves the sender as a single GSO skb and the segments are
512/512/176.  Exits: y1 keeps NETIF_F_GSO_UDP_L4 (ac1 0000612e), y2 lost it
together with NETIF_F_HW_CSUM through one ETHTOOL_SFEATURES write
(ac1 0000612c) -- the kernel refuses UDP-GSO to a device without checksum
offload, so the two bits travel together.

1. Who segments.  With no rule at all, y1 puts ONE 1262-byte frame on the wire
   whose checksum field is ff72 = fold16(pseudo header with length 1208), i.e.
   a seed for the whole datagram, and the receiver segments it (three datagrams
   512/512/176).  y2 puts THREE frames on the wire, 574/574/238, with uh->len
   520/520/184 and checksums 82af/82af/1f91 that are valid for each frame's own
   bytes; the receiver gets the same three datagrams, byte for byte.

2. The payload store.  `@th,8,4 = a0a1a2a3` (payload 0..3) is free on y1: the
   big frame carries ff72 unchanged and the datagram is delivered; the store
   costs on y2, where the segmenter recomputes frame 0's checksum from the
   modified payload (426f instead of 82af) and leaves frames 1 and 2
   byte-identical.  The same store at payload 512 and at 1196 lands in the
   middle and the last segment respectively (fields 224f and f768), each with
   the same rule.  `csum flags` changes nothing on either door: the four arms
   with it are byte-identical to the two without.

3. The store the segmenter READS.  `__udp_gso_segment()` derives each
   segment's seed as csum16_add(csum16_sub(uh->check, uh->len), htons(newlen))
   (net/ipv4/udp_offload.c:570,600) -- it reads exactly the two header fields a
   rule can rewrite.
   * writing the length field to 0x0020: on y2 the segmenter overwrites the
     length per segment, so the store VANISHES from the wire, and every
     checksum is short by exactly 1208-0x20 = 0x0498 (measured delta fb67 in
     one's complement on all three frames) -> all three datagrams are dropped,
     Udp6InErrors +3.  On y1 the receiver trims the skb to 32 bytes
     (pskb_trim_rcsum, net/ipv6/udp.c:1111) and then refuses to segment it
     (gso_skb->len <= 8 + mss, udp_offload.c:495) -> +3 errors, while a length
     ABOVE the datagram (0xffff) is a short_packet -> +1.  Same door, same
     two-byte store, two different numbers, because a drop below the segmenter
     costs gso_segs and a drop above costs one.
   * writing the checksum field itself to 0xdead: y1 ships dead to the socket
     and still delivers three datagrams, because CHECKSUM_PARTIAL counts as
     "unnecessary" (skbuff.h:4781); y2 derives all three seeds from dead and
     all three die (deltas 20c6 each, +3).

4. What the rule sees.  Every rule counted one packet and logged ONE message of
   1248 bytes -- not one per segment -- and that message carries the header
   after the store (len_a: aa3c13880020ff72) with hop limit 0x3f, because
   ip6_forward() decrements before NF_HOOK.  The rule and the instrument see
   the same packet; they diverge only at the exit device.

5. The same 1262 bytes without GSO (AF_PACKET, CHECKSUM_NONE) are one datagram
   of 1200 on both doors, nobody segments, the stored copy dies on the stale
   checksum (-1) and only the rule's own `csum flags` repairs it (55d2 = the
   true sum of the modified datagram).  So the flag that is dead code on the
   socket path is the only payer on the packet path.

6. A UDP_GRO socket names the segmentation point: through y1 it gets ONE
   1200-byte datagram with gso_size 512 (the skb is still GSO at the socket),
   through y2 three datagrams (there is nothing left to GRO).  With the length
   store it gets 24 bytes -- the trim, and no segmentation afterwards.

Not a vulnerability: every rule here was installed by root in the initial user
namespace, which F57 measured to be the only context in which a payload store
installs at all.  What this is: the price of a write is not a property of the
write.  On a GSO datagram it is a property of WHERE the datagram gets cut, and
the rule cannot see, let alone express, whether the cut happens before or after
its own door.

Not measured: any real NIC (both exits are veth pairs with a bit cleared by
hand), mss that does not divide the payload, more than three segments, the
SKB_GSO_FRAGLIST path (needs GRO on receive), CHECKSUM_UNNECESSARY/COMPLETE,
TCP and ICMP with GSO, IPv4 GSO, and the internal arithmetic of
gso_make_checksum() -- only its result, which matched 150 frames on both boots.

---

## F63 — GRO hands the rule a packet the sender never sent

**Claim.** With Generic Receive Offload the skb a rule evaluates is one packet built out of several datagrams: its UDP header is not any datagram's header, and which header a rule reads depends on a device bit -- 0x00c3 on a router with `rx-udp-gro-forwarding`, 0xfcc2 on a router with `rx-gro-list`, for the same three datagrams and the same rule.

**Minimal reproduction.** instrument `differ585`, mode `aggr`; 26 arms × 2 boots, three netns (sender, router, receiver), one rule on the forward chain, two routers whose GRO doors differ in one device bit.

**Run.** `bash vm/build_f63_differ.sh` then `bash code/tools/f63_run.sh` — log marker `F585`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `udp6_gro_complete()` completes a linear aggregate with `uh->len = total` and `uh->check = ~udp_v6_check(total, saddr, daddr, 0)`; the fraglist branch only calls `udp_set_len(uh, skb->len - nhoff)` and keeps the first datagram's checksum field.

**Actual.** Same three datagrams, same rule, same table: the checksum field the rule reads is 0x00c3 through `rx-udp-gro-forwarding` and 0xfcc2 through `rx-gro-list`; a rule that matches or rewrites `@th,6,2` behaves differently on two routers that agree on everything a rule can name. A store made on an aggregate is not paid for by the fraglist splitter (`__udp_gso_segment_list()` calls `skb_segment_list()`, which copies no payload and computes no checksum).

**Limitations.** Only UDP over IPv6 and the two GRO doors; TCP GRO, tunnels and a real NIC were not measured.

**Details.**

nft_payload evaluates on whatever skb the hook receives.  With Generic
Receive Offload that skb is sometimes not the packet the sender wrote: three
UDP datagrams that share a 5-tuple become ONE skb before ip6_rcv, and the
first datagram's payload is the only part of it that is linear data — the
rest is frag_list.  Two things follow that a rule can observe, both measured
on 7.3.4 with three netns (sender, router, receiver) and 26 arms per boot,
byte-identical across two boots:

1. The checksum field the rule reads depends on a device bit, not on the
   traffic.  A linear aggregate is completed with
       uh->len   = total UDP length
       uh->check = ~udp_v6_check(total, saddr, daddr, 0)
   (udp6_gro_complete(), linear branch), while a fraglist aggregate only gets
       udp_set_len(uh, skb->len - nhoff)
   and keeps the FIRST datagram's checksum field.  Same three datagrams,
   same rule, same table: the rule sees 0x00c3 on a router with
   rx-udp-gro-forwarding and 0xfcc2 on a router with rx-gro-list.  A rule that
   matches or rewrites @th,6,2 therefore behaves differently on two routers
   that agree on everything a rule can name.

2. A store made on an aggregate is not paid for by the fraglist splitter.
   __udp_gso_segment() takes __udp_gso_segment_list() whenever
       skb_pagelen(skb) - sizeof(struct udphdr) == skb_info->gso_size
   and that branch calls skb_segment_list(), which copies no payload and
   computes no checksum -- "features" is passed in and never consulted.  On an
   exit device WITHOUT any checksum offload, a rule's 4-byte payload write
   reaches the wire with the sender's pseudo-header seed in the checksum field
   (0xfcc3/0xfcc3/0xfcc3 for three untouched datagrams, the first of which the
   rule modified), while the same write on a LINEAR aggregate of the same
   datagrams is hashed by skb_checksum_help() (0x426f/0xf1af/0xf0af).  The
   receiver drops neither, because skb_segment_list() leaves the fragments
   CHECKSUM_PARTIAL and UDP does not verify PARTIAL -- so the datagram with a
   wrong checksum is delivered, and a rule that rewrites the checksum field
   itself (0xdead) is delivered as well, whereas the same store on the linear
   shape is hashed into three wrong checksums and all three datagrams are
   dropped.

The branch is also chosen by the rule's own write.  A store that crosses the
end of the aggregate's linear part (the head is exactly one segment) pulls
bytes out of frag_list, so skb_pagelen() changes, the geometry test above
fails, __skb_linearize() + skb_segment() run instead, and the exit device now
pays for every segment -- including the two the rule never touched.  Four
bytes of offset decide who pays for the whole aggregate.

Reproducer and the full grid: 26 arms over {linear, fraglist} x {device with,
without checksum offload} x {store in payload, in length, in checksum, past the
head} x {CHECKSUM_PARTIAL, CHECKSUM_NONE provenance}, using veth only (a real
NIC was not available; the "device without offload" is a veth with
NETIF_F_HW_CSUM cleared, which also clears NETIF_F_GSO_UDP_L4).

Signed-off-by: ...

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F64 — an aggregate presents a rule with a header that describes no datagram

**Claim.** An aggregate's `uh->len` is the sum of the datagrams in it -- a length no datagram has -- and its checksum field is the first datagram's own CHECKSUM_PARTIAL seed on the fraglist path or a seed over the whole aggregate on the linear path.

**Minimal reproduction.** instrument `differ586`, mode `geom`; four compositions (512×3; 512×3+200; 64×512) through both GRO doors, one rule on the forward chain, the header fields read through the rule's NFLOG message.

**Run.** `bash vm/build_f64_differ.sh` then `bash code/tools/f64_run.sh` — log marker `F586`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `udp_gro_complete()` writes `skb->len - nhoff` into `uh->len`; `skb_gro_receive()` completes the header on the linear path, `udp_gro_receive()` merges without touching the head's field on the fraglist path.

**Actual.** 512,512,512 fraglist: `uh->len` 0x0608, `uh->check` fcc2 (seed of 520). 512,512,512,200 fraglist: 0x06d0, fcc2; linear: 0x06d0, 018b (seed of 1744). 64×512 fraglist: 0x8008, fcc2; linear: 0x8008, 7ac3 (seed of 32776). A rule that reads `@th,4,2` sees a length no datagram has; `@th,6,2` addresses 520 bytes of a 1744-byte packet.

**Limitations.** Only UDP and the two GRO doors; the trailing segment's length is F65's subject.

**Details.**

The F63 follow-up measured who pays for a store into a GRO aggregate.  This
one measures what the aggregate IS, because the first question turned out to
depend on the second: the same four datagrams give a rule two different
lengths and two different checksum fields depending only on whether the
aggregate is a fraglist or linear.

  nft_payload evaluates on the skb the hook receives.

  With Generic Receive Offload that skb is one packet built out of several
  datagrams, and its UDP header is not any datagram's header:

   512,512,512           fraglist   uh->len 0x0608  uh->check fcc2 = seed(520)
   512,512,512,200       fraglist   uh->len 0x06d0  uh->check fcc2 = seed(520)
   512,512,512,200       linear     uh->len 0x06d0  uh->check 018b = seed(1744)
   64 x 512              fraglist   uh->len 0x8008  uh->check fcc2 = seed(520)
   64 x 512              linear     uh->len 0x8008  uh->check 7ac3 = seed(32776)

`uh->len` is the sum (udp_gro_complete() writes skb->len - nhoff).  The
checksum field is the first datagram's own CHECKSUM_PARTIAL seed on the
fraglist path -- udp_gro_receive() merges without touching the head's field --
and a seed over the whole aggregate on the linear path, where
skb_gro_receive() completes the header.  A rule that reads @th,4,2 sees a
length no datagram in the packet has; a rule that reads @th,6,2 sees a number
that addresses 520 bytes of a 1744-byte packet.

Two consequences that a rule cannot see at all:

1.  The tail.  When the split happens on a device without GSO the trailing
    segment's length is computed, not derived: 208 = 8 + 200 comes from the
    `if (!skb_is_gso(seg))` clause, the only per-segment arithmetic in
    __udp_gso_segment().  The hop limit says which path ran: the fraglist
    split copies only the MAC header into each fragment, so only the first
    segment carries the router's decrement (63,64,64,64) while the linear
    path copies the whole header (63,63,63,63).

2.  Who pays depends on the store's own offset, not on the shape.  Through a
    device without checksum offload a fraglist aggregate ships the senders'
    seeds (fcc3,fcc3,fcc3,fb8b -- auxdata 9, CHECKSUM_PARTIAL, delivered).
    The same aggregate with the same rule, whose store lands four bytes past
    the head instead of inside it, is linearised: skb_pagelen() - 8 no longer
    equals gso_size, the geometry test fails, and every segment is hashed
    (02b0,01b0,00b0,1248 -- auxdata 129).  The rule did not change; the
    offset did.

Two smaller measurements, offered as data rather than as argument:

  *  UDP_GRO_CNT_MAX is 64 and the datagram that did not fit is a plain
     packet, not a one-datagram aggregate: gro_complete() sets gso_size = 0
     when count == 1.  With 65 datagrams one rule instance reads seed(32776)
     for the aggregate and seed(520) for the 65th, in the same arm.
  *  A store into the length field has three fates: rewritten by
     udp_set_len_short() on an aggregate (the store vanishes, 4 datagrams
     delivered), applied verbatim on a lone datagram (the receiver trims to
     32 bytes and delivers 24), and used as the base of every per-segment
     checksum delta on a linear aggregate (nothing delivered, +4 errors).

Measured on 7.3.4-T563, 26 arms x 2 boots x 2 agreeing attempts, one rule per
arm at ip6/forward, three netns; every number verified byte for byte by
verify586.py (1271 checks) against a reimplementation of csum_ipv6_magic()
and of the aggregate's composition.  Not measured: real NICs (every door here
is a veth with bits cleared by hand), BIG TCP (udp_set_len() writes a zero
length at or above GRO_LEGACY_MAX_SIZE -- out of reach at these sizes), TCP
GRO, CHECKSUM_COMPLETE, and the CHECKSUM_NONE provenance, which could not be
made deterministic on this rig and is therefore not used as evidence.

---

## F65 — the packet that nothing follows

**Claim.** A UDP datagram that begins a GRO flow and is not followed by another is not delivered when it is sent: with `gro_flush_timeout` at 200 ms it reaches the forward chain 201 ms later, and a datagram that starts a flow inside the timer's own poll reaches it one flush period later (402 ms).

**Minimal reproduction.** instrument `differ587`, modes `cap`, `flow`; three netns with `gro_flush_timeout` set on the ingress device, one rule that counts and logs, timestamps from the rule's own log records; 64-datagram arms for the byte cap.

**Run.** `bash vm/build_f65_differ.sh` then `bash code/tools/f65_run.sh` — log marker `F587`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** GRO holds a flow until the timer (`gro_flush_timeout`) or the poll ends the aggregation; `udp_set_len()` has a zero-length branch at GRO_LEGACY_MAX_SIZE.

**Actual.** One send arrives as two packets: an aggregate whose `uh->len` is the sum of three datagrams (0x04d0) with the first datagram's seed 0xfcc2, and a plain packet with the sender's untouched header (0x0208, 0xfcc2); the second flow arrives at 402 ms. The byte cap is 65536 and counts one byte more than the payload: on the fraglist path 64 datagrams merge up to payload 1022 and at 1023 the 64th is refused (63+1); at payload 1200 the aggregate is 54+10. The largest UDP length a rule can read here is 0xff88 (65416).

**Limitations.** One flush timeout (200 ms) and one device; TCP GRO and a real NIC were not measured.

**Details.**

A UDP datagram that begins a GRO flow and is not followed by another one is
not delivered when it is sent.  On 7.3.4-T563 with x0's gro_flush_timeout at
200 ms it reaches the forward chain 201 ms later, and a datagram that starts a
new flow inside the poll that the timer itself runs reaches it one flush period
after that: 402 ms, against 201 ms for the aggregate that preceded it in the
same send.  The rule sees one send as two packets: an aggregate whose uh->len
is the sum of three datagrams (0x04d0, a length no datagram in it has, with the
first datagram's own CHECKSUM_PARTIAL seed 0xfcc2 in the checksum field) and a
plain packet carrying the sender's untouched header (0x0208, 0xfcc2).

A two-byte store into the UDP length field then has three fates, decided by the
shape and not by the door: on a fraglist through a door that segments in
software the splitter puts the head's length back (udp_set_len_short(8+mss)) and
every datagram is delivered (512, 512, 200, 24); on a fraglist through a door
that keeps GSO, and on a linear aggregate, every segment's checksum is computed
against the stored number and the aggregate dies whole (3 errors, only the
24-byte leftover delivered).

The byte cap that ends aggregation is 65536 and it counts one byte more than the
payload: on the fraglist path 64 datagrams merge up to payload 1022
(64 x 1023 < 65536) and at 1023 the 64th is refused (63 + 1).  UDP_GRO_CNT_MAX = 64 binds only below payload
1023; above it the byte cap binds first, and at payload 1200 the aggregate is
54 + 10.  The zero-length branch of udp_set_len() at GRO_LEGACY_MAX_SIZE is
therefore unreachable for UDP on this kernel: both merge paths refuse at
65536, so the largest UDP length a rule can read here is 0xff88 (65416).

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F66 — two ceilings, one budget

**Claim.** The two merge paths test different lengths against the same 65536: the linear path counts `H + k*P` and the fraglist path `2H + k*P`, with H = 48, so with 64 datagrams the linear path merges up to payload 1023 and the fraglist up to 1022; a third 65536 that a rule cannot see is `gso_max_size`, which decides whether the aggregate leaves as one frame.

**Minimal reproduction.** instrument `differ588`, modes `cap`, `split`; one send of 64 equal datagrams through both doors, tails on 63 equal datagrams, and a sweep of `uh->len` at the 65536 boundary.

**Run.** `bash vm/build_f66_differ.sh` then `bash code/tools/f66_run.sh` — log marker `F588`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `skb_gro_receive()` tests `p->len + skb_gro_len()` (payload), `skb_gro_receive_list()` tests `p->len + skb->len` before its `skb_pull()` (L3 + payload), and `p->len` grows by the payload in both.

**Actual.** 64 datagrams of 1023 bytes: linear one packet (`uh->len` 0xffc8 = 65480), fraglist two (0xfbc9 and 0x0407, the second 200 ms later). Tails on 63 equal datagrams: fraglist merges up to 990 and refuses at 991; linear up to 975 and refuses at 976. `gso_features_check()`: `uh->len` 65481 (frame 65535) leaves as one frame, 65482 (65536) as sixty-four segments of 1024.

**Limitations.** IPv6 only for this table (IPv4 is F68); TCP GRO and a real NIC were not measured.

**Details.**

This section answers two questions the previous one left open: what the byte
cap that ends UDP GRO actually counts, and what a socket keeps of the 64
datagrams of one aggregate.

THE CAP.  The two merge paths test different lengths against the same
65536 = GRO_LEGACY_MAX_SIZE.  skb_gro_receive() tests p->len + skb_gro_len(),
i.e. the payload; skb_gro_receive_list() tests p->len + skb->len before its
skb_pull(), i.e. the whole arriving datagram (IPv6 header 40 + UDP 8 +
payload).  p->len grows by the payload in both.  With H = 48:

    linear   : H + k*P      < 65536   ->  P <= 1023 at 64 datagrams
    fraglist : 2H + k*P     < 65536   ->  P <= 1022 at 64 datagrams

One send of 64 datagrams of 1023 bytes, one rule, two doors: the linear shape
reaches the forward chain as ONE packet with uh->len 0xffc8 (65480), the
fraglist shape as TWO (0xfbc9 and 0x0407, the second one 200 ms later as its
own flow).  A shorter tail on 63 equal datagrams walks the same inequality to
the byte: on the fraglist the tail merges up to 990 and is refused at 991, on
the linear path up to 975 and refused at 976.  Both give H = 48, so the
Ethernet header is not counted; the fraglist aggregate stops 48 bytes -- one
IPv6+UDP header -- short of what the linear aggregate may carry (L3 65487
against 65535).

There is a third 65536 that the rule cannot see.  gso_features_check() strips
the GSO feature bits when skb->len >= dev->gso_max_size, so the aggregate
leaves the router as one frame only while the frame is under 65536 bytes: with
uh->len 65481 (frame 65535) the wire carried one frame, with 65482 (65536) it
carried sixty-four segments of 1024.  Six bytes of uh->len are therefore
writable by a rule and still in one frame, and the next byte is not.

THE BUDGET.  A socket with a lazy reader keeps a number of the 64 segmented
datagrams that is a function of SO_RCVBUF alone, and it repeats exactly:
1 + floor((rcvbuf - A) / s) with s = 1280 the per-datagram truesize and A =
81920 = 64 * 1280 the truesize of the whole aggregate, charged to its FIRST
segment.  Measured at rcvbuf 98304/114688/131072/147456/262144: 13/26/39/52/64
kept, and 64 - kept in Udp6InErrors, with the queue bytes in /proc/net/udp6
equal to A + (kept-1)*s.  A buffer below A still accepts one datagram: the
"accept the packet if queue is empty" clause in __udp_enqueue_schedule_skb().
an eager reader never kept fewer and sometimes kept more (39..58 across
eight attempts), which is the part that does not repeat.

WHAT IT COSTS A READER.  Every frame of a 64-datagram aggregate carries the
first datagram's CHECKSUM_PARTIAL seed in the checksum field (0xfcc2 =
fold(pseudo-header(520)) here), not a checksum; a linear aggregate carries the
seed of its whole length (0x00c3 for 1544).  A store into the payload lands at
frame offset 62 and is visible identically at the router's egress tap and at
the receiver's ingress tap -- two witnesses, one frame.

One limit on the evidence, stated because it is a limit: an NFLOG payload
longer than 65531 bytes does not exist (the netlink attribute length is 16
bit), so for an aggregate of uh->len 65488 and above the log carries the
header and the beginning of the payload and silently stops.

Kernel

7.3.4-T563, IPv6 only, all rules installed by root in the initial user
namespace.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F67 — the head of an aggregate pays for the whole aggregate, and above half a buffer that number collapses

**Claim.** Below half a receive buffer the first segment of a fraglist aggregate is charged the sum of the packets that went into it (`p->truesize += skb->truesize`), so k datagrams cost (2k-1)*s; above half a buffer `skb_condense()` overwrites the head's truesize with one datagram's price, and the refusal is decided on that smaller number.

**Minimal reproduction.** instrument `differ589`, modes `cond`, `dflt`; 1200-byte datagrams on five buffers, a 64-datagram arm, and a pair of buffers that differ only in whether the queue is above half; receiver reads `/proc/net/udp6` before a single recv.

**Run.** `bash vm/build_f67_differ.sh` then `bash code/tools/f67_run.sh` — log marker `F589`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** The default `rmem_max` is 212992 = (256+576)*256; `skb_gro_receive_list()` adds each arriving skb's truesize to the head; `skb_condense()` is called only when `rmem > rcvbuf >> 1` and rewrites the head's truesize to `SKB_TRUESIZE(skb_end_offset())`.

**Actual.** 212992 = (256+576)*256 with 576 the only value in [512,640] that fits the two measured truesizes (1280-704, 2304-1728); `SO_RCVBUF(106496)` reproduces the default. 1200-byte datagrams: 133120 keeps 4, 143360 9, 153600 13, 163840 18, 184320 27, with 131328/142848/152064/163584/184320 bytes queued exactly; at 184320 the 27th leaves rmem equal to rcvbuf and is accepted (the test is `>`). Above half: 311296 keeps 54 of 54, 344064 keeps 25 of 54.

**Limitations.** Only UDP over IPv6 and one topology; TCP GRO and a real NIC were not measured.

**Details.**

Kernel 7.3.4-T563, no new build. Instrument: three netns, a rule on the IPv6

forward chain that only counts and logs, and a receiver that reports what the
socket actually kept, what the queue's own byte account says (/proc/net/udp6),
and how many datagrams of each of two flows arrived.

1. The default receive buffer is 212992, and it is what
   `SKB_TRUESIZE(256) * 256` gives: (256 + 576) * 256, where 576 is the
   aligned skb_shared_info plus struct sk_buff, and 576 is what the two
   measured truesizes leave (1280 - 704, 2304 - 1728) — no other value in
   [512, 640] does.  `SO_RCVBUF(v)` is doubled, so 106496 reproduces the
   default and a read-back confirms it.

2. For an aggregate of N datagrams the first segment is charged `N * s`
   (`skb_gro_receive_list()` does `p->truesize += skb->truesize`, so a
   fraglist aggregate's truesize is the SUM of the packets that went into it),
   and each further segment `s`.  1200-byte datagrams on five buffers:
   133120 -> 4 kept, 143360 -> 9, 153600 -> 13, 163840 -> 18, 184320 -> 27,
   with 131328 / 142848 / 152064 / 163584 / 184320 bytes in the queue exactly.
   At 184320 the 27th segment leaves rmem EQUAL to rcvbuf and is accepted,
   because the test is `>`, not `>=`.

3. With the queue already above half, the same aggregate's head is charged ONE
   datagram instead of N, and the
   refusal test is decided on that smaller number too.  A queue holding 162560
   bytes in a 212992 buffer keeps 39 of 64 datagrams, though the head's `N * s`
   (81920) exceeds the 50432 that is left.  The cleanest pair differs only in
   the buffer: 311296 keeps 54 of 54, 344064 keeps 25 of 54 — the SMALLER
   buffer keeps more, because at 311296 rmem is above half and at 344064 it is
   not.

4. Open question: `skb_condense()` sits
   BELOW the refusal test in `__udp_enqueue_schedule_skb()`, so that branch
   cannot be what makes the refusal see the small size; the other condense site
   is `___pskb_trim()`, which would have to be inert exactly when the queue is
   empty, and there is no measurement of that.  Also open: two different socket
   paths give the same total for 64 * 512 — a fraglist aggregate charged
   81920 + 63 * 1280 and 64 datagrams at 2540 each are both 162560 — so a byte
   account alone cannot tell the two shapes apart; only the 1200-byte arms do.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F68 — the IPv4 twin of the GRO byte cap and of the receive-queue budget

**Claim.** On IPv4 the fraglist ceiling moves by exactly 2*(48-28) = 40 bytes relative to IPv6 and the receive-queue accounting moves by nothing: 64 datagrams of 1023 bytes arrive as one packet through the fraglist door where IPv6 gives two, and the queue keeps the same numbers as IPv6 to the byte.

**Minimal reproduction.** instrument `differ590`, modes `cap4`, `cond4`; 25 cap arms and 10 queue arms, two attempts per arm, two boots, three netns on IPv4, a rule on the `ip` forward chain that only counts and logs, receiver reads `/proc/net/udp`.

**Run.** `bash vm/build_f68_differ.sh` then `bash code/tools/f68_run.sh` — log marker `F590`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `skb_gro_receive()` tests `p->len + skb_gro_len()` (payload), `skb_gro_receive_list()` tests `p->len + skb->len` (L3+payload), and `p->len` grows by the payload in both: linear `H + N*P < 65536`, fraglist `2H + N*P < 65536`, H = 28 on IPv4.

**Actual.** 64×1023 through the fraglist door: one packet, `uh->len` 0xffc8 = 65480, one 65514-byte frame on the wire; the same send on IPv6 gave two (0xfbc9 + 0x0407). 64×1024 splits on both families; 64×1022 merges on both. Tails on 63×1024: 995 merges (28+64512+995 = 65535), 996 splits. Queue: 212992 keeps 39 of 54 1200-byte datagrams with 211968 bytes; 133120→4, 143360→9, 153600→13, 163840→18, 184320→27; 311296/344064 keep 54 vs 25.

**Limitations.** IPv4 only for this table; the fraglist byte cap on IPv4 with equal-length datagrams is F69's cell.

**Details.**

Kernel 7.3.4-T563, no new build. Instrument: three netns (sender, router,
receiver) on IPv4, a rule on the `ip` forward chain that only counts and logs,
and a receiver that reports what the socket kept and what the queue's own byte
account says (/proc/net/udp).

1. The two merge points check different lengths against the same 65536:

       skb_gro_receive():      p->len + skb_gro_len()   (payload)
       skb_gro_receive_list(): p->len + skb->len       (L3 + payload)

   while `p->len` grows by the payload in both.  With H = L3+L4 that is
       linear:   H + N*P < 65536
       fraglist: 2H + N*P < 65536
   IPv6 has H = 48, IPv4 has H = 28, so the fraglist ceiling must move by
   2*(48-28) = 40 bytes.  Measured: 64 datagrams of 1023 bytes arrive at the
   IPv4 forward hook as ONE packet (uh->len 0xffc8 = 65480, one 65514-byte
   frame on the wire) through the fraglist door, where the same send on IPv6
   produced two (0xfbc9 + 0x0407).  64 x 1024 splits on both families, and
   64 x 1022 merges on both -- so the 40-byte shift is visible in exactly the
   one cell the arithmetic requires and nowhere else.

2. A tail on 63 equal datagrams walks the same check to the byte on the linear
   path: 63 x 1024 + 995 merges (28 + 64512 + 995 = 65535) and 996 gives 65536
   and is refused.  The same numbers on IPv6, with H = 48, were 975/976.

3. On the fraglist path the binding clause is a different one in the same
   function:

       if (ulen > udp_get_len_short(uh2) || flush)
               pp = p;

   A datagram LONGER than the head of the flow ends it instead of merging.
   With a 1023-byte head the threshold is therefore 1023/1024: 990, 1000,
   1010 and 1020 merge; 1025, 1028, 1029, 1030 and 1031 split -- although the
   byte cap would have allowed up to 1030 (56 + 64449 + 1030 = 65535).  On
   IPv6 the cap (990) binds BEFORE that length rule (1023), which is why the
   IPv6 measurements looked like a pure cap boundary and the IPv4 ones do not.
   A length change ends the flow after one datagram, so the cap is reachable
   only when every datagram has the same length; with equal payloads the cap
   and the count limit compete, and the fraglist door reaches the cap (F69),
   which is the cap measured as a cell.

4. The field the rule reads on a CHECKSUM_PARTIAL datagram is a seed, not a
   sum: `udp4_hwcsum()` writes `~csum_tcpudp_magic(s, d, ulen, 17, 0)`, and
   because `csum_fold()` already complements, the wire carries the folded
   12-byte pseudo-header sum (0x16ff for a 520-byte datagram).  For an
   aggregate the field is different per shape: the linear path recomputes it
   over the TOTAL length (`udp4_gro_complete()`), the fraglist path leaves the
   head datagram's own seed in place.

5. Nothing of the receive-queue accounting depends on the family.  The head of
   an aggregate carries the whole aggregate's truesize below half a receive
   buffer -- k datagrams are charged (2k-1)*s, where s is one datagram's
   price -- and s above it, and the refusal is decided on that collapsed
   number -- on IPv4 with the very
   numbers IPv6 gave: 212992 keeps 39 of 54 1200-byte datagrams with 211968
   bytes queued; the five-buffer sweep is 133120 -> 4, 143360 -> 9, 153600 ->
   13, 163840 -> 18, 184320 -> 27, and the pair 311296 / 344064 keeps 54 vs 25
   -- the smaller buffer keeps more, because at 311296 the queue is above half.
   The datagram price s is 1280 (512-byte payload) and 2304 (1200), the same
   two allocation classes as on IPv6.

6. The fraglist byte cap on IPv4 is reached with equal-length datagrams, and
   those arms belong to F69.  In this instrument the 1100-byte-head arms split
   the burst at a poll boundary after the head, so the tail met a 1023-byte
   head and the cap was not reached.

---

## F69 — where an aggregate's price comes from, and how the byte cap actually binds

**Claim.** The byte cap is reachable only when every datagram has the same length, because a length change ends the flow after one datagram; with equal lengths the fraglist cap splits 40 datagrams of 1637 bytes into 39+1 while the linear door merges them into one, and an aggregate of k datagrams is charged (2k-1)*s because the segmenter keeps the whole truesize on the head.

**Minimal reproduction.** instrument `differ591`, modes `cap`, `price`; 14 cap arms and 19 price arms, two attempts each, two boots; IPv4 three netns, taps on both egress doors, receiver reads `/proc/net/udp`.

**Run.** `bash vm/build_f69_differ.sh` then `bash code/tools/f69_run.sh` — log marker `F591`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `udp_gro_receive_segment()` ends a flow when `ulen != udp_get_len_short(uh2)`; the two doors test `2H + (n+1)*P <= 65535` (fraglist) and `H + (n+1)*P <= 65535` (linear); `skb_segment_list()` subtracts len and data_len from the head and never touches truesize.

**Actual.** 40×1637: fraglist 2 packets (0xf96b = 63851 + 0x066d = 1645), linear 1 (0xffd0 = 65488). 39×1637 + 1636 tail = 65535 merges (0xffcf). The price ladder is (2k-1)*s: 1280, 3840, 6400, 8960, 19200, 39680, 80640, 162560 for k = 1,2,3,4,8,16,32,64 at s = 1280, and 2304 ... 145152 at s = 2304, 26 cells with no miss; the linear door charges k*s (81920 for 64×512). 2540 = 127*1280/64 and 2520 = 126*1280/64, so 20 = 1280/64.

**Limitations.** TCP GRO, CHECKSUM_COMPLETE, tunnels and a real NIC were not measured; why one older measurement of the same aggregate came out one 1280-byte unit short is not established.

**Details.**

Kernel 7.3.4-T563, no new build. Instrument: three netns on IPv4, one rule on

the `ip` forward chain that only counts and logs, taps on both egress doors,
and a receiver that reads the queue's own byte account (/proc/net/udp) before a
single recv.

1. The byte cap is reachable only when every datagram has the same length.
   `udp_gro_receive_segment()` ends a flow on a length change:

       if (ret || ulen != udp_get_len_short(uh2) ||
           NAPI_GRO_CB(p)->count >= UDP_GRO_CNT_MAX)
               pp = p;

   so a long head followed by shorter datagrams is merged ONCE and the flow is
   closed -- which is why long-head arms could never reach the cap.
   With equal payloads the two caps (2H + sum >= 65536, and count >= 64)
   compete, and the byte cap wins for large payloads:

       40 datagrams of 1637 bytes: 2H + 40*1637 = 65536 -> refused on the
       fraglist door (39 + 1), merged on the linear door (one packet,
       uh->len 0xffd0).  39 datagrams of 1637 plus a 1636-byte tail is
       exactly 65535 and merges (uh->len 0xffcf).

   The same 40 datagrams on the two doors differ by one packet and nothing
   else: 39*1637+8 = 0xf96b and 0x066d against a single 0xffd0.

2. Counting is not the cap: 65 datagrams of 512 bytes give 64 + 1 (the count
   limit), and 64 x 1024 give 63 + 1 (the byte cap, count 63 < 64).

3. Why an aggregate of k 512-byte datagrams is charged 127 * 1280 below half a
   receive buffer, i.e. "(2k-1) times one datagram": the fraglist segmenter
   subtracts len and data_len from the head and never touches truesize

       skb->data_len = skb->data_len - delta_len;
       skb->len = skb->len - delta_len;

   so the first segment carries the whole aggregate's truesize and the other
   k-1 carry their own.  Measured as a ladder, s = 1280 (512 B) and 2304
   (1200 B) taken from the k = 1 arms alone: 1280, 3840, 6400, 8960, 19200,
   39680, 80640, 162560 for k = 1,2,3,4,8,16,32,64, and 2304 ... 145152 for
   1200-byte datagrams.  The linear door, whose segments skb_segment() builds
   itself, charges k*s (81920 for 64 x 512) and is split-invariant.

4. `skb_condense()` is what hides this above half a buffer: it is called only
   when `rmem > rcvbuf >> 1` and overwrites the head's truesize with
   SKB_TRUESIZE(skb_end_offset()), i.e. one datagram -- which is why the same
   aggregate measured with the queue already half full shows no doubling.

5. Two side observations, both with numbers.  A linear aggregate of 64
   datagrams whose L3 length is 65533 is one packet to the rule and 64 frames
   on the wire: the device drops the GSO bits when the frame does not fit, one
   frame per datagram.  And NFLOG's ceiling of 65531 bytes is a real truncation
   of a 65533-byte message, not a logging artefact.

6. Not measured: why one of two older measurements of the same 64-datagram
   aggregate came out one 1280-byte unit short (it did not reproduce in twelve
   fresh measurements); TCP GRO; CHECKSUM_COMPLETE; tunnels; a real NIC.  All
   rules were installed by root in the initial user namespace, so this is not
   an unprivileged attack surface -- it is a statement about accounting and
   about where a segmenter's truesize goes.

---

## F70 — the branch, and its boundary

**Claim.** `skb_condense()`'s early return is taken on the head's tailroom, not on a constant: an aggregate head arrives linear and already carries the whole aggregate's truesize, `data_len == 0` skips the block entirely, and the strictly-greater comparison with `rcvbuf >> 1` decides whether the queue's bill collapses.

**Minimal reproduction.** instrument `differ592`, mode `cond`; 9 arms × 2 attempts × 2 boots, a kprobe on `skb_condense()` at DWARF-derived offsets (len 112, data_len 116, tail 188, end 192, truesize 216, flags 126) plus five counters; a filler at 250 ms puts `rmem` exactly on `rcvbuf >> 1`.

**Run.** `bash vm/build_f70_differ.sh` then `bash code/tools/f70_run.sh` — log marker `F592`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `skb_condense()` is called only when `rmem > rcvbuf >> 1`; the early return compares `data_len > end - tail`; the last line sets `skb->truesize = SKB_TRUESIZE(skb_end_offset(skb))`.

**Actual.** Six datagrams of 512 through the fraglist door: head `len=512 dlen=0 tail=556 end=704 ts=7680 fl=0`, segments 2-6 at 1280; `__pskb_pull_tail` 0 calls in all 36 attempts. `SO_RCVBUF(19200)` puts `rmem` exactly on 19200 (`c_eq`): the burst leaves 14080 with 5 calls; one more filler (20480) gives 7680 with 6 calls. Five datagrams of 512 and one of 200: the head arrives at 7360 and the queue gains 7360. The linear door also totals 7680 but each record is 1280.

**Limitations.** All three early-return clauses are unreachable in this instrument except the first; clause 3 needs SKBFL_PURE_ZEROCOPY (F72), clause 2 needs a second consumer (F72).

**Details.**

Kernel 7.3.4-T563 (no new build). Instrument: three netns on IPv4, one veth

pair per door, a sender and a receiver in their own namespaces, and a kprobe on
skb_condense() with fetchargs at the field offsets pahole reads out of this
kernel's own DWARF (len 112, data_len 116, tail 188, end 192, truesize 216,
flags 126). Five more counters: __pskb_pull_tail, __udp_enqueue_schedule_skb,
___pskb_trim, skb_segment_list. Records are attributed to an arm by markers in
trace_marker, because writing to `trace` does not clear it in this kernel.

1. The head of a fraglist aggregate reaches the enqueue path already linear,
   carrying the whole aggregate.

       p:kprobes/cond skb_condense len=+112(%di):u32 dlen=+116(%di):u32 ...

   measures, for six datagrams of 512 bytes arriving as one fraglist aggregate
   on a queue above half a buffer:

       len=512 dlen=0 tail=556 end=704 ts=7680 fl=0     <- the head
       len=512 dlen=0 tail=556 end=704 ts=1280 fl=0     <- segment 2
       ... five more at 1280

   7680 is 6 * 1280: the sum of the merged datagrams' truesizes, exactly what
   skb_gro_receive_list() accumulates. skb_segment_list() subtracts len and
   data_len from this skb and never touches truesize, so the last line of
   skb_condense() -- skb->truesize = SKB_TRUESIZE(skb_end_offset(skb)) --
   rewrites 7680 into 1280. __pskb_pull_tail is called 0 times in all 36
   attempts: the early-return block is skipped because data_len is 0, not
   because a clause inside it failed.

2. The comparison is strictly greater, and the queue can sit on the boundary.

   `rcvbuf >> 1` is 19200 when SO_RCVBUF(19200) is requested. A filler sent one
   datagram at a time (250 ms apart, so it never aggregates) puts rmem exactly
   on 19200, and then the same six-datagram burst leaves the queue 14080 bytes
   heavier with 5 calls of skb_condense(). One more filler datagram -- rmem
   20480 -- and the same burst costs 7680 with 6 calls, the first of them on
   the head at 7680. Two attempts per arm, two boots, four measurements per
   cell, all identical.

3. The same charge can come from two different mechanisms, and the queue
   cannot tell them apart.

   Fraglist door: 6 calls, the first carrying 7680, total 7680.
   Linear door: 6 calls, every one carrying 1280, total 7680.
   On the linear door skb_segment() builds fresh segments and the aggregate
   never reaches the queue, so condense() fires six times and changes nothing.
   Only the probe separates the two; the queue's own byte account cannot.

4. A total truesize is a sum, and condense reprices each part.

   Five datagrams of 512 and one of 200: the head arrives at 7360
   (5 * 1280 + 960), the short one at 960, and after condense the queue gains
   7360 -- the same number, now as five times 1280 plus 960. Every record that
   is not an aggregate head satisfies ts == end + 576 in this kernel; the same
   constant follows from the 1200-byte datagram measured earlier (2304 - 1728).

Nothing here is a kernel bug: it is the price of a documented memory-pressure
branch, and the numbers are what __udp_enqueue_schedule_skb() is supposed to
charge. What is worth knowing is that the queue's byte account cannot be used
to infer which door a datagram came through, while a single field of the skb at
the moment skb_condense() runs can.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F71 — the skb behind `skb_condense()`'s first clause, measured at the function

**Claim.** The first clause of `skb_condense()` is measured at the function: an aggregate delivered whole to a `UDP_GRO` socket reaches the queue with `data_len` 2560 against 148 bytes of tailroom, so the early return is taken by the first clause alone, one enqueue and one call against six and six on a plain socket.

**Minimal reproduction.** instrument `differ593`, mode `gro`; 18 arms × 2 attempts × 2 boots, receiver with two sockets (5000 plain, 5001 `UDP_GRO`), seven kprobes including the enqueue door; three head sizes for the byte boundary.

**Run.** `bash vm/build_f71_differ.sh` then `bash code/tools/f71_run.sh` — log marker `F593`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `skb_condense()` returns early when `data_len > end - tail`; `udp_unexpected_gso()` refuses `SKB_GSO_FRAGLIST` without `ACCEPT_FRAGLIST`, and `UDP_GRO` sets only `ACCEPT_L4`; `ACCEPT_FRAGLIST` is set by `udp_allow_gso()` (vxlan, geneve, bareudp).

**Actual.** Six datagrams of 512 through `rx-udp-gro-forwarding` to the `UDP_GRO` socket: `f593enq len=3072 dlen=2560 tail=556 end=704 ts=7680 fl=0` and one `f593cond` call -- 2560 > 148, clause 1 alone, `__pskb_pull_tail` not called, queue keeps 7680, application gets one 3072-byte datagram. Boundaries 148/140/484 pinned to the byte; above half the same two datagrams cost 1280 against 2240 below; a tap sets `cloned` and blocks the pull (2240, 0 pulls); fraglist on `UDP_GRO` equals fraglist on a plain socket (6 enqueues, 7680).

**Limitations.** `SKBFL_PURE_ZEROCOPY` absent (clause 3 unmeasurable here); the page-frag branch of `skb_gro_receive()` never taken (`head_frag` 0); a real NIC not measured.

**Details.**

Kernel 7.3.4-T563 (no new build). Instrument: three netns on IPv4, the same

veth pairs as before, a sender and a receiver in their own namespaces, and
seven kprobes with fetchargs at the field offsets pahole reads out of this
kernel's own DWARF (len 112, data_len 116, tail 188, end 192, truesize 216,
flags 126). The receiver now has TWO sockets, 5000 plain and 5001 with
UDP_GRO, drained and measured per port, so the same datagrams can be delivered
whole or cut into pieces at will.

1. The skb that reaches the branch with data_len > 0 is the aggregate built by
   rx-udp-gro-forwarding at the sender, delivered whole to a UDP_GRO socket.

       f593enq:  len=3072 dlen=2560 tail=556 end=704 ts=7680 fl=0
       f593cond: len=3072 dlen=2560 tail=556 end=704 ts=7680 fl=0

   Six datagrams of 512 bytes: one enqueue, one call of skb_condense(), and the
   early return is taken by the first clause alone -- 2560 bytes of fragments
   against 148 bytes of tailroom. __pskb_pull_tail is not called and the queue
   keeps the whole 7680. On the plain socket the same six datagrams are cut by
   skb_segment() into six skbs of 1280 and the branch fires six times.

2. The comparison is with the HEAD's tailroom, so the boundary is a property of
   the buffer, not of the traffic. Three head sizes give three boundaries, each
   pinned to the byte (two attempts per arm, two boots; all four measurements of
   each cell identical):

       head 512:  end 704  tail 556  room 148   147,148 pull   149 returns
       head 200:  end 384  tail 244  room 140   139,140 pull   141 returns
       head 1200: end 1728 tail 1244 room 484   483,484 pull   485 returns

   `data_len == end - tail` is not greater, so it pulls: __pskb_pull_tail()
   copies exactly data_len bytes into the tail room (eat = tail + delta - end
   = 0, no expansion) and the last line of skb_condense() reprices the skb to
   SKB_TRUESIZE(end) -- 1280, 960, 2304. One byte more and the queue keeps
   2240, 1920, 3584.

3. A passive AF_PACKET socket on the forwarding device changes that number.
   With the parent's y1/y2 taps open, the same 512+147 pair never pulls:
   dev_queue_xmit_nit() clones the skb, skb_cloned() is the second clause, and
   it returns before __pskb_pull_tail(). Measured, four times each:

       taps closed:  cloned 0, skb_clone 0 calls, pull 1 (eat=147), charge 1280
       taps open:    cloned 1, skb_clone 5/2 calls, pull 0,          charge 2240

   The payload delivered to the application is identical (659 bytes in both
   cases); only the socket's memory account differs, by the price of one
   datagram. This is the third observer effect this instrument has run into --
   the first was that the same tap disables GRO at the receiver -- and it is
   the first one that moves a number rather than a shape.

4. UDP_GRO does nothing for a fraglist aggregate, and the source says why:
   udp_unexpected_gso() refuses SKB_GSO_FRAGLIST unless the socket has
   ACCEPT_FRAGLIST, and UDP_GRO sets only ACCEPT_L4. ACCEPT_FRAGLIST is set by
   udp_allow_gso(), called from vxlan, geneve and bareudp only. Measured: six
   enqueues, six calls, skb_segment_list once, charge 7680 -- identical to a
   plain socket. The aggregate that IS delivered whole is the one from the
   linear door, and it arrives as one datagram of 3072 bytes.

Nothing here is a kernel bug: it is the documented price of a memory-pressure
branch and of a socket option. What is worth knowing is which of the three
things decides the queue's byte account -- the device bit at the sender, the
socket bit at the receiver, or the existence of a monitor on the wire -- and
that none of the three is visible to a rule that reads the packet.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F72 — what a user page does to the two UDP GRO doors, measured at the doors

**Claim.** `skb_gro_receive()` refuses a zerocopy datagram outright, so a zerocopy burst reaches the forwarding hook as six packets through the linear door while the fraglist door merges the same six into one; each enqueue record is charged `end + 576 + PAGE_ALIGN(payload + page offset)` for a zerocopy skb and `end + 576` otherwise, so the sender's buffer alignment sets the price.

**Minimal reproduction.** instrument `differ594`, modes `cl`, `zc`; 13 arms × 2 attempts × 2 boots; sender with SO_ZEROCOPY/MSG_ZEROCOPY, receiver with an optional packet socket and filter, forward chain with a `log` rule so the rule's own packet count is a number.

**Run.** `bash vm/build_f72_differ.sh` then `bash code/tools/f72_run.sh` — log marker `F594`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `skb_gro_receive()` has `if (skb_zcopy(p) || skb_zcopy(skb)) return -ETOOMANYREFS;`; `skb_gro_receive_list()` has no such check; the enqueue price is `end + 576` plus, for zerocopy, `PAGE_ALIGN(payload + page offset)` (F73).

**Actual.** Zerocopy six 512-byte datagrams reach the hook as six packets with `uh->len` 520 each (linear), and as one packet of 3080 (fraglist). One 512-byte zerocopy datagram costs 5056 at page offset 0 and 9152 at offset 3600; 5000 bytes cost 9152 at offset 0; a copied 512-byte datagram costs 1280. Copy counts: six on the linear door, one on the fraglist aggregate. At `SO_RCVBUF` 19200 (R 38400) a 64-datagram zerocopy burst from offset 0 leaves 7 with 57 drops; from offset 3600 it leaves 4.

**Limitations.** IPv6, TCP, tunnels, CHECKSUM_COMPLETE and a real NIC were not measured; the `skb_cloned` bit is set by a tap and blocks the pull.

**Details.**

Kernel 7.3.4-T563 (`1efbc957…2033`), no new build. Same three-netns IPv4 path as before, with

three additions: the sender can set SO_ZEROCOPY and pass MSG_ZEROCOPY, the
receiver can open a packet socket on its device that either keeps every frame
or carries a `ret 0` filter so it keeps none, and the forward chain finally
carries a `log` rule, so "what the rule saw" is a number rather than an
inference. Thirteen arms, two attempts each, two boots, all 52 identical in
every modelled field.

1. skb_gro_receive() refuses a zerocopy datagram outright
   (net/core/gro.c:112: `if (skb_zcopy(p) || skb_zcopy(skb)) return
   -ETOOMANYREFS;`). Six 512-byte datagrams sent with MSG_ZEROCOPY through
   rx-udp-gro-forwarding reach the forwarding hook as SIX packets, each with
   the UDP length field 520. The same six copied datagrams reach it as ONE
   packet with the length field 3080. skb_gro_receive_list() -- the
   rx-gro-list door -- has no such check and merges the same zerocopy burst
   into one packet of 3080. The sender's memory, not the socket, decides.

2. The receiving queue is where zerocopy costs the most. Every enqueue record
   satisfies ts = end + 576 + PAGE_ALIGN(payload + page offset) for a zerocopy
   skb and ts = end + 576 otherwise: one 512-byte datagram is 5056 when its iov
   starts at page offset 0 and 9152 at offset 3600; 5000 bytes are 9152 at
   offset 0; against 1280 for a copied 512-byte
   datagram.  The charge is a page-granular span measured from the iov's own
   start, so the sender's buffer alignment, not the payload size, chooses it
   (F73, F74). With SO_RCVBUF 19200 (sk_rcvbuf 38400) a 64-datagram zerocopy
   burst from offset 0 leaves 7 datagrams and 57 drops, where a copied burst
   would leave 30; the same 64 datagrams from offset 3600 leave 4.

3. The copy happens in the receiver and only one door pays it per datagram.
   ip_local_deliver_finish() calls skb_orphan_frags_rx() ->
   skb_copy_ubufs() for anything with SKBFL_ZEROCOPY_ENABLE. Counted on the
   function: six copies for six datagrams on the linear door, and ONE for the
   fraglist aggregate -- because the aggregate IS its first member, so that
   member's payload is copied and its flag cleared while the five frag_list
   members keep the sender's pages all the way to the receiving socket.

4. SKBFL_PURE_ZEROCOPY -- the only thing that makes skb_frags_readable()
   false, and therefore the third clause of skb_condense()'s early return --
   is written in exactly one place in this tree (net/ipv4/tcp.c:1331). A UDP
   skb cannot carry it; the copy in (3) is the proof that the predicate was
   true, since skb_copy_ubufs() returns -EFAULT for a PURE skb and the caller
   drops the packet.

5. skb_cloned() is a predicate about liveness, not a bit. With the two
   datagrams 512+148 merged into one 668-byte packet and delivered whole:
   no second consumer -> one __pskb_pull_tail of 148 bytes, charge 1280;
   an egress AF_PACKET tap -> no pull, charge 2240; an ingress AF_PACKET tap
   -> the same, through skb_share_check() in ip_rcv_core() instead of
   dev_queue_xmit_nit(); and a packet_type with a `ret 0` filter, which never
   keeps a frame -> no clone at all, the bit is 0, the pull happens and the
   charge is 1280. The last case is the interesting one: merely registering a
   second consumer changes nothing, because __netif_receive_skb_core() calls
   the last packet_type without taking a reference.

Nothing here is a vulnerability: every rule was installed by root in the
initial user namespace, and creating a kprobe needs CAP_SYS_ADMIN.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.

---

## F73 — where the page charge comes from, and who clones on the receive path

**Claim.** The page charge is made in `zerocopy_fill_skb_from_iter()` as `skb->truesize += PAGE_ALIGN(copied + start)`, where `start` is the iov's page offset, so one 512-byte datagram costs 5056 at offset 0 and 9152 at offset 3600; `skb_clone()` on this path is `skb_segment()`'s, once per `frag_list` member, and `MSG_SPLICE_PAGES` is cleared by `__sys_sendto()` before it reaches the kernel.

**Minimal reproduction.** instrument `differ595`, modes `all`, `chg`, `cln`, `spl`; 18 arms × 2 attempts × 2 boots plus one diagnostic boot; the sender changes only the place of the payload in its page; a probe at `skb_clone()` prints the return address (`caller=$stack0:x64`, `nokaslr`).

**Run.** `bash vm/build_f73_differ.sh` then `bash code/tools/f73_run.sh` — log marker `F595`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `net/core/datagram.c:662` does `skb->truesize += PAGE_ALIGN(copied + start)`; `net/core/skbuff.c:4933` is `nskb = skb_clone(list_skb, GFP_ATOMIC)` inside `skb_segment()`; `net/socket.c:2277` does `flags &= ~MSG_INTERNAL_SENDMSG_FLAGS`, the mask including `MSG_SPLICE_PAGES`.

**Actual.** 512 bytes at offset 0: 5056 = 960 + 4096; at offset 3600: 9152 = 960 + 8192; 1200 at 3600: 9152; 4097 at 0: 9152; 5000 at 0: 9152; 5000 at 3600: 13248. The same number is read at `__dev_queue_xmit`, `skb_copy_ubufs`, `ip_forward`, `ip_local_deliver`, `udp_rcv` and `/proc/net/udp`. Five `skb_clone()` calls from one return address `0xffffffff829134c4`, inside `skb_segment()`; `skb_segment_list()` clones none (7680 on the head). `MSG_SPLICE_PAGES`: `__ip_append_data` sees `flags = 0`, `skb_splice_from_iter` 0 calls, the datagram costs 1280 (512 bytes) and 8448 (5000).

**Limitations.** Only veth and this tree; `splice(pipe -> socket)` was not measured.

**Details.**

Kernel 7.3.4-T563 (`1efbc957…2033`), no new build. Same three-netns IPv4 path

as F65-F72. Eighteen arms over two boots, two attempts each, every modelled
field identical between the boots, plus one diagnostic boot of a second binary
that differs by one probe.

1. The charge is `PAGE_ALIGN(payload + page offset)`, and the offset decides.
   `zerocopy_fill_skb_from_iter()` (net/core/datagram.c:662) does
   `skb->truesize += PAGE_ALIGN(copied + start)`, where `start` is the page
   offset `iov_iter_get_pages2()` returns. Measured at the receiving queue for
   one zerocopy datagram, with `SKB_TRUESIZE(384) = 960`:

       512 bytes at offset 0     5056 = 960 + 4096
       512 bytes at offset 3600  9152 = 960 + 8192
       1200 bytes at offset 3600 9152
       4097 bytes at offset 0    9152
       5000 bytes at offset 0    9152
       5000 bytes at offset 3600 13248

   The same 512-byte datagram costs 5056 or 9152 depending on where in its page
   the iov begins -- a property of the sender's buffer that no socket option
   and no receive-side counter exposes. The number is set before the frame
   leaves the sender (`__dev_queue_xmit`), survives the ubuf copy
   (`skb_copy_ubufs`), the router (`ip_forward`) and the receiver
   (`ip_local_deliver`, `udp_rcv`) unchanged, and equals what `/proc/net/udp`
   reports as `rmem` before the application reads anything.

   The charge is not "one page per payload" and not "one page per page
   touched": it is `PAGE_ALIGN(payload + page offset)`, so a payload that
   begins near the end of its page pays for two pages and a payload that
   crosses a page boundary pays for the pages it actually spans.

2. `skb_clone()` on this path is `skb_segment()`'s, once per `frag_list`
   member. Six copied 512-byte datagrams merged by `rx-udp-gro-forwarding`
   produce five `skb_clone()` calls, all from `net/core/skbuff.c:4933`
   (`nskb = skb_clone(list_skb, GFP_ATOMIC)`), and the segments arrive with the
   cloned bit set on the five members and clear on the fresh head. The same six
   datagrams through `rx-gro-list` produce none: `skb_segment_list()` takes its
   members without cloning them, and the head segment carries the whole
   aggregate's truesize (7680). A `log` rule in the forward chain clones
   nothing: the same six datagrams with a counter-only rule clone exactly five
   times.

3. `MSG_SPLICE_PAGES` is not a userspace flag. Passing it to `sendto()` is
   accepted and then dropped: `__sys_sendto()` does
   `flags &= ~MSG_INTERNAL_SENDMSG_FLAGS` (net/socket.c:2277), the mask being
   `MSG_SPLICE_PAGES | MSG_SENDPAGE_NOPOLICY | MSG_SENDPAGE_DECRYPTED |
   MSG_NO_SHARED_FRAGS` (include/linux/socket.h:358). Measured at
   `__ip_append_data()` entry: `flags = 0` for the datagram that asked for it,
   against `MSG_ZEROCOPY` intact for its twin. The datagram is then an ordinary
   copy and the queue charges it `end + 576` (1280 for 512 bytes, 8448 for
   5000) -- no page at all. The only userspace path into
   `skb_splice_from_iter()` is `splice(pipe -> socket)`.

Scope, as before: every rule was installed by root in the initial user
namespace; the syscall filter of (3) is a documented guard, not a defect.
Untouched: IPv6, TCP, tunnels, `CHECKSUM_COMPLETE`, a real NIC.

---

## F74 — what the offset charge does to the queue, and where the head of a copied datagram comes from

**Claim.** The receive queue holds `floor(sk_rcvbuf / charge)` datagrams and the boundary is one byte of the socket's own request (`SO_RCVBUF` 17695 keeps 6, 17696 keeps 7); the same 64 datagrams are 7 or 4 depending on the sender's page offset, which the socket cannot see, and a 200-byte zerocopy datagram can have the offset charge erased by `skb_condense()` above half a buffer.

**Minimal reproduction.** instrument `differ596`, modes `q` (21 arms) and `h` (9 arms); 30 arms × 2 attempts × 2 boots, one process per mode; `SO_RCVBUF` sweep, mixed charge sequences, 200-byte arms, and a sweep of head sizes for the allocation class.

**Run.** `bash vm/build_f74_differ.sh` then `bash code/tools/f74_run.sh` — log marker `F596`; build and boot as in `HOW_TO_RUN.md` §2-5.

**Expected.** `__udp_enqueue_schedule_skb()` refuses when `rmem + size > rcvbuf`, strictly; `skb_condense()` collapses the head's truesize above half a buffer; `kmalloc_reserve()` uses `SKB_SMALL_HEAD_CACHE_SIZE` as the small-head ceiling.

**Actual.** R 38400/51200/76800/102400 with charge 5056 keep 7/10/15/20 (rmem 35392/50560/75840/101120) and with 9152 keep 4/5/8/11 (36608/45760/73216/100672); `SO_RCVBUF` 17695 (R 35390) keeps 6, 17696 (R 35392 = 7*5056) keeps 7; two arms leave rmem equal to rcvbuf and keep all 64 (323584, 585728). Mixed at R 51200: 7 kept with rmem 47680 although floor(51200/9152) = 5; 64 datagrams of 200 bytes keep 18 with 33664 = 4*5056 + 14*960; the head-size step is at payload 325/326 (end 384 → 704, ts 960 → 1280), the small-head object size read from the boot's own slab cache is 704.

**Limitations.** Charges of mixed arms beyond the 16th record are derived from the stride; `SO_RCVBUFFORCE`, IPv6, TCP, tunnels and a real NIC were not measured.

**Details.**

Kernel 7.3.4-T563 (`1efbc957…2033`), no new build. Same three-netns IPv4 path

as F65-F73. Thirty arms over two boots, two attempts each, every modelled field
identical between the boots and between attempts within a boot.

1. The receive queue holds `floor(sk_rcvbuf / charge)` datagrams, and the
   boundary is a byte of the socket's own request. 64 zerocopy datagrams of
   512 bytes, `SO_RCVBUF` doubled by the kernel into `sk_rcvbuf`:

       R = 38400   charge 5056  ->  7 kept, rmem 35392
       R = 51200   charge 5056  -> 10 kept, rmem 50560
       R = 76800   charge 5056  -> 15 kept, rmem 75840
       R = 102400  charge 5056  -> 20 kept, rmem 101120
       R = 38400   charge 9152  ->  4 kept, rmem 36608
       R = 51200   charge 9152  ->  5 kept, rmem 45760
       R = 76800   charge 9152  ->  8 kept, rmem 73216
       R = 102400  charge 9152  -> 11 kept, rmem 100672

   Two arms pin the boundary: `SO_RCVBUF` 17695 (R 35390) keeps 6, and 17696
   (R 35392 = 7 x 5056) keeps 7 -- one byte of the request, one datagram. Two
   more leave `rmem` equal to `sk_rcvbuf` to the byte and keep all 64
   (323584 = 64 x 5056 and 585728 = 64 x 9152), which only works because the
   check in `__udp_enqueue_schedule_skb()` is `rmem + size > rcvbuf`, strictly.

2. The same 64 datagrams are 7 or 4 depending on a byte the receiver cannot
   see. 512 bytes at page offset 0 cost 5056; at offset 3600, 9152; a
   4097-byte payload at offset 0 also costs 9152. The gate record is identical
   in all three -- `len` 512, `dlen` 512, `end` 384, `tail` 44, no clone -- so
   the socket cannot tell them apart, and the number of datagrams it will hold
   before dropping (and therefore where it starts dropping) is decided by the
   sender's buffer alignment. The forward rule's own shape changes nothing: a
   counter-only chain prints the same 7 / 35392 / 57 as one that logs.

3. Above half the buffer the charge can disappear, and that is the receiver's
   own branch. `skb_condense()` pulls a payload into the head when
   `data_len <= end - tail` (340 bytes for a zerocopy skb) and charges
   `SKB_TRUESIZE(end)` = 960. 64 datagrams of 200 bytes at `R` = 38400 keep
   18 with 33664 in the queue -- four at 5056 and fourteen at 960 -- where the
   same datagrams of 512 bytes keep 7. So the page charge a misaligned sender
   inflicts is bounded by whether the payload fits the head's tailroom, and the
   same branch can cut the bill by 57344 bytes.

4. Where a copied skb's `end` comes from: the small-head cache, and the
   boundary is a byte of payload. `kmalloc_reserve()` gives every skb whose
   `SKB_HEAD_ALIGN(size)` is at most `SKB_SMALL_HEAD_CACHE_SIZE` a head of
   exactly that size -- 704 in this kernel, read from the booting kernel's own
   `skbuff_small_head` slab cache -- and `end` is that size minus
   `SKB_DATA_ALIGN(sizeof(struct skb_shared_info))` = 320, so `end` = 384 and
   `truesize` = 960 for **every** copy with a payload up to 325 bytes. One byte
   more (326) and the request `payload + 59` leaves the small head, the
   allocator rounds up to 1024 (there is no 768 class), and `end` jumps to 704
   and the bill to 1280. Measured on the wire for 270, 277, 278, 309, 310 and
   325 (384/960) against 326 and 342 (704/1280) and 5000 (7872/8448).

5. A queue with a mixed charge sequence is not `floor(R / mean)`: the check runs
   for every datagram, so a charge that was refused does not stop a later,
   smaller one. With charges alternating 9152 and 5056 at `R` = 51200 the
   seventh (9152) is refused at 51776 and the eighth (5056) is accepted,
   47680, 7 datagrams where `floor(51200/9152)` = 5 would suggest. The order
   matters as much as the multiset: the same charges starting with 5056 keep 5
   and bill 33472 instead of 37568.

Nothing here is a memory-safety claim: every rule was installed by root in
the initial user namespace, and the effect is
accounting -- the sender's iov alignment, and the receiver's own condense
branch, both move the number of datagrams a socket will hold for a given
`sk_rcvbuf`.

### Scope

Not a vulnerability: the rule was installed by root in the initial user
namespace, and the effect described above is what that rule does to the packet,
the counter or the accounting. The measurement is bounded by the instrument and
the kernels named in this section.
