#!/usr/bin/env python3
"""verify563.py -- independent check of turn 563 / F41.

Two debts closed on one new image, 7.3.4-T563 = T558 + CONFIG_PPP + CONFIG_PPPOE.

The model is written from the kernel source, not from the instrument:

  if_pppox.h                  #define PPPOE_SES_HLEN 8
  nf_flow_table.h             __nf_flow_pppoe_proto() reads the PPP protocol
                              halfword at skb_mac_header + ETH_HLEN + 6
  nft_meta.c                  case htons(ETH_P_PPP_SES):
                                      if (!nf_flow_pppoe_proto(skb, &ethertype))
                                              return;
                                      nhoff = PPPOE_SES_HLEN;      /* 8 */
                              nhoff += skb_network_offset(skb);
                              case htons(ETH_P_8021Q): nhoff = VLAN_HLEN; ...
                              then __nft_set_pktinfo_ipv4_validate(pkt, nhoff)
                              (on failure: nft_set_pktinfo_unspec -> nhoff 0)
                              and pkt->ethertype = ethertype;
  nft_payload.c  (read)       offset = skb_network_offset(skb) + pkt->nhoff
  nft_payload.c  (store)      offset = skb_network_offset(skb)
  nft_payload.c  (transport)  both use nft_thoff(pkt) = netoff + nhoff + ihl*4
  nft_payload.c  nft_nh_write_ok():  NFPROTO_ARP -> arp list,
                              NFPROTO_BRIDGE -> switch (pkt->ethertype) ->
                              ip4 list / ip6 list / arp list,
                              NFPROTO_NETDEV + NF_NETDEV_INGRESS -> true
  nft_chain_filter.c          nft_do_chain_bridge() switches on
                              eth_hdr(skb)->h_proto (0x0800/0x86dd/else unspec)
  net/ipv4/arp.c              arp_rcv():  ar_hln != dev->addr_len || ar_pln != 4
                                          -> drop BEFORE NF_ARP_IN
                              arp_process(): ar_hrd/ar_pro checked by device
                              type, then ar_op must be REQUEST or REPLY
  drivers/net/ppp/pppoe.c     pppoe_rcv(): len = ntohs(ph->length);
                              skb_pull_rcsum(sizeof(*ph)); if (skb->len < len)
                              drop; trim to len; session lookup by
                              (sid, eth_hdr(skb)->h_source, ifindex)
  net/core/dev.c              check_vlan_id loop: an outer tag with vid 0 is a
                              priority tag -- the next tag is popped as well
                              (so a Q-in-Q frame with vid 0 outer AND inner
                              reaches the ARP stack, and one with a non-zero
                              inner vid is PACKET_OTHERHOST)

Frame coordinates: the capture starts at mac_header and skb->data is 14 bytes
further (= cap + 14 after one tag has been popped), so a data-relative offset D
is cap[14+D] and the store of (off,len) lands at cap[14+off] in EVERY envelope.
The ARP header sits at cap 14 for an untagged frame and at cap 18 for a Q-in-Q
frame -- that four-byte displacement IS the shift.

Exit code is non-zero if any check failed.
"""
import gzip
import hashlib
import os
import re
import sys

ROOT = "/work/kernel-sec"
LOG1 = os.environ.get("V563_REP1", ROOT + "/logs/f41_rep1.log")
LOG2 = os.environ.get("V563_REP2", ROOT + "/logs/f41_rep2.log")
KERN = ROOT + "/src/linux-7.3.4-T563"
PARENT = ROOT + "/src/linux-7.3.4-T558"
DIFF = ROOT + "/vm/build/differ563"
INITRD = ROOT + "/vm/initrd563/full.cpio.gz"

N = 0
FAIL = []
SECN = {}


def ck(cond, what, detail="", sec="-"):
    global N
    N += 1
    SECN[sec] = SECN.get(sec, 0) + 1
    if not cond:
        FAIL.append((sec, what, detail))
    return cond


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def u16(b, off):
    return (b[off] << 8) | b[off + 1]


# ---------------------------------------------------------------- frames ----

def csum(b):
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | (b[i + 1] if i + 1 < len(b) else 0)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


MAC_SRC = bytes([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x66])
MAC_THA = bytes([0x22] * 6)


def datagram():
    """the IPv4/UDP datagram the instrument puts inside every envelope"""
    tot = 20 + 8 + 18
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2] = tot >> 8
    ip[3] = tot & 0xFF
    ip[4], ip[5] = 0x12, 0x34
    ip[8], ip[9] = 64, 17
    ip[12:16] = bytes([10, 1, 0, 1])
    ip[16:20] = bytes([10, 9, 0, 7])
    c = csum(bytes(ip))
    ip[10] = c >> 8
    ip[11] = c & 0xFF
    udp = bytes([0x9C, 0x40, 0x13, 0x88, 0x00, 26, 0x00, 0x00]) + b"\x77" * 18
    return bytes(ip) + udp


DG = datagram()


def plain_ip4():
    return b"\xff" * 6 + MAC_SRC + b"\x08\x00" + DG


def pppoe(sid=99, ppp=0x0021):
    hdr = bytes([0x88, 0x64, 0x11, 0x00, sid >> 8, sid & 0xFF,
                 0, 2 + len(DG), ppp >> 8, ppp & 0xFF])
    return b"\xff" * 6 + MAC_SRC + hdr + DG


def plain_arp(spa):
    body = (b"\x00\x01" + b"\x08\x00" + b"\x06\x04" + b"\x00\x01" +
            MAC_SRC + spa.to_bytes(4, "big") + MAC_THA +
            bytes([10, 9, 0, 1]))
    fr = b"\xff" * 6 + MAC_SRC + b"\x08\x06" + body
    return fr + bytes(60 - len(fr))


# tags per frame; a Q-in-Q frame keeps its inner tag in the capture
CELLS = ([(o, l) for o in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24)
          for l in (1, 2, 4)] + [(0, 8), (8, 16), (16, 16), (20, 16)])

FRAMES = {
    "p":    ("ip4", []),
    "ps":   ("pppoe", []),
    "pa":   ("arp", []),
    "tag0": ("arp", [(0x8100, 0x0000)]),
    "q0":   ("arp", [(0x88A8, 0x0000), (0x8100, 0x0000)]),
    "q200": ("arp", [(0x88A8, 0x0000), (0x8100, 0x00C8)]),
}


def base_of(frame, spa):
    kind = FRAMES[frame][0]
    if kind in ("ip4", "pppoe"):
        return plain_ip4()
    return plain_arp(spa)


def wire_of(frame, spa):
    kind, tags = FRAMES[frame]
    if kind == "pppoe":
        return pppoe()
    base = base_of(frame, spa)
    out = base[:12]
    for tp, tci in tags:
        out += bytes([tp >> 8, tp & 0xFF, tci >> 8, tci & 0xFF])
    return out + base[12:]


def cap_of(frame, spa):
    kind, tags = FRAMES[frame]
    if kind == "pppoe":
        return pppoe()
    base = base_of(frame, spa)
    if len(tags) >= 2:
        tp, tci = tags[-1]
        return (base[:12] + bytes([tp >> 8, tp & 0xFF, tci >> 8, tci & 0xFF])
                + base[12:])
    return base


def skb_protocol(frame):
    """skb->protocol after the receive path popped at most one tag"""
    kind, tags = FRAMES[frame]
    if kind == "pppoe":
        return 0x8864
    if not tags:
        return u16(base_of(frame, 0), 12)
    if len(tags) == 1:
        return u16(base_of(frame, 0), 12)
    return tags[-1][0]


def eth_hdr_proto(frame, spa):
    """eth_hdr(skb)->h_proto at the bridge hook = cap[12:14]"""
    return u16(cap_of(frame, spa), 12)


# ---------------------------------------------------------------- pktinfo ---

def valid_ip4(b, off):
    if off + 20 > len(b):
        return False
    if b[off] >> 4 != 4 or (b[off] & 0x0F) < 5:
        return False
    tot = u16(b, off + 2)
    ihl = (b[off] & 0x0F) * 4
    return tot >= ihl >= 20


def pktinfo(frame, spa, gate):
    """pkt->flags/nhoff/thoff/ethertype at the BRIDGE prerouting hook."""
    cap = cap_of(frame, spa)
    eth = eth_hdr_proto(frame, spa)
    if eth == 0x0800:
        return dict(flags=1, nhoff=0, thoff=20, et=0x0800)
    if eth == 0x86DD:
        return dict(flags=1, nhoff=0, thoff=40, et=0x86DD)
    et = skb_protocol(frame)
    nhoff = 0
    flags = 0
    thoff = None
    if gate:
        if skb_protocol(frame) == 0x8864:            # PPPoE
            ppp = u16(cap, 20)
            et = {0x0021: 0x0800, 0x0057: 0x86DD}.get(ppp, 0)
            nhoff = 8
            if et == 0x0800 and valid_ip4(cap, 14 + 8):
                flags, thoff = 1, 8 + 20
            else:
                nhoff = 0
        elif skb_protocol(frame) == 0x8100:          # Q-in-Q
            et = u16(cap, 16)
            nhoff = 4
            if et == 0x0800 and valid_ip4(cap, 14 + 4):
                flags, thoff = 1, 4 + 20
            else:
                nhoff = 0
    return dict(flags=flags, nhoff=nhoff, thoff=thoff, et=et)


# ----------------------------------------------------------------- guards ---

def guard_ip4(data, off, ln, imm):
    def bit(i):
        return data[i] if i < len(data) else 0
    if off == 0:
        return ln == 2 and imm[0] == bit(0)
    if off == 1:
        return ln == 1
    if off == 4:
        return ln == 2
    if off == 8:
        if ln == 1:
            return True
        if ln != 2:
            return False
        return imm[1] == bit(9)
    if off == 10:
        return ln <= 10
    if off == 12:
        return ln <= 8
    if off == 16:
        return ln <= 4
    return False


def guard_arp(off, ln):
    if off == 6:
        return ln == 2
    return off >= 8 and ln <= 20


def guard_bridge(pi, cap, off, ln, imm):
    if pi["et"] == 0x0800:
        return guard_ip4(cap[14:], off, ln, imm)
    if pi["et"] == 0x86DD:
        return False
    if pi["et"] == 0x0806:
        return guard_arp(off, ln)
    return False


def store_ok(frame, spa, gate, off, ln, imm):
    """Does the store of (off,len) happen, and at which capture offset?"""
    cap = cap_of(frame, spa)
    pi = pktinfo(frame, spa, gate)
    if not guard_bridge(pi, cap, off, ln, imm):
        return None
    pos = 14 + off
    if pos + ln > len(cap):
        return None
    return pos


def read_live(frame, spa, gate, off, ln, cv):
    cap = cap_of(frame, spa)
    pi = pktinfo(frame, spa, gate)
    pos = 14 + pi["nhoff"] + off
    if pos + ln > len(cap):
        return False
    return cap[pos:pos + ln] == cv


def th_ok(frame, spa, gate):
    pi = pktinfo(frame, spa, gate)
    return pi["thoff"] if pi["flags"] else None


# --------------------------------------------------------------- the log ----

def parse(path):
    rows = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.replace("\r", "").rstrip("\n")
            if not line.startswith("F563 "):
                continue
            head, _, rest = line[5:].partition("|")
            kv = {"_k": head.strip(), "_raw": rest.split("|")[0].strip()}
            for part in rest.split("|"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    kv[k] = v
            rows.append(kv)
    return rows


def by_kind(rows, kind):
    return [r for r in rows if r["_k"] == kind]


def envparts(r):
    """the log prints env=<frame>.<gate>.<arm>; the arm may itself contain dots"""
    parts = r["env"].split(".")
    fr, gate = parts[0], parts[1]
    arm = ".".join(parts[2:]) if len(parts) > 2 else "-"
    return fr, gate, arm


def hexbytes(s):
    if s in ("-", ""):
        return b""
    return bytes.fromhex(s)


def chg_list(s):
    """'22:45>90,23:00>91' -> [(22, b'\\x45', b'\\x90'), ...]"""
    out = []
    if s in ("-", ""):
        return out
    for part in s.split(","):
        m = re.match(r"^(\d+):(\w+)>(\w+)$", part)
        if m:
            out.append((int(m.group(1)), bytes.fromhex(m.group(2)),
                        bytes.fromhex(m.group(3))))
    return out


# ------------------------------------------------------------ provenance -----

def check_provenance():
    sec = "prov"
    with open(LOG1, "r", errors="replace") as f:
        head = [next(f) for _ in range(8)]
    ks = [h for h in head if h.startswith("### kernel: ")]
    ss = [h for h in head if h.startswith("### sha256: ")]
    ins = [h for h in head if h.startswith("### initrd: ")]
    iss = [h for h in head if h.startswith("### initrd sha256: ")]
    ck(bool(ks) and ks[0].strip().endswith("linux-7.3.4-T563/arch/x86/boot/bzImage"),
       "rep1 booted the T563 image", ks[0].strip() if ks else "missing", sec)
    ck(bool(ss) and ss[0].split()[-1] == sha256(KERN + "/arch/x86/boot/bzImage"),
       "kernel sha in the log == the file on disk",
       (ss[0].split()[-1] if ss else "?") + " vs " +
       sha256(KERN + "/arch/x86/boot/bzImage"), sec)
    ck(bool(iss) and iss[0].split()[-1] == sha256(INITRD),
       "initrd sha in the log == the file on disk", "", sec)
    ck("VM_BOOT_OK" in open(LOG1, errors="replace").read(),
       "the guest reached VM_BOOT_OK", "", sec)
    ck("7.3.4" in open(LOG1, errors="replace").read(), "the guest reports 7.3.4", "", sec)

    # config delta: exactly the PPP/PPPOE block and SLHC
    dall = open(ROOT + "/logs/f41_cfg_delta_T563.txt").read().splitlines()
    d = [l for l in dall if l[:1] in ("<", ">")]
    ck(len(d) == 17, "config delta is 17 changed lines", str(len(d)), sec)
    ck(any("CONFIG_PPP=y" in l for l in d), "PPP is =y", "", sec)
    ck(any("CONFIG_PPPOE=y" in l for l in d), "PPPOE is =y", "", sec)
    ck(any("CONFIG_SLHC=y" in l for l in d), "SLHC is =y", "", sec)
    bad = [l for l in d if not re.search(
        r"PPP|SLHC|PPPOE", l)]
    ck(not bad, "every delta line is PPP/SLHC/PPPOE", str(bad), sec)

    # the files that decide the behaviour are byte-identical to the parent
    for f in ("net/netfilter/nft_payload.c", "net/netfilter/nft_meta.c",
              "net/netfilter/nf_tables_core.c",
              "net/netfilter/nft_chain_filter.c", "net/ipv4/arp.c",
              "net/core/dev.c", "net/8021q/vlan_core.c",
              "drivers/net/ppp/pppoe.c", "include/net/netfilter/nf_flow_table.h"):
        ck(sha256(KERN + "/" + f) == sha256(PARENT + "/" + f),
           "T563 %s is byte-identical to T558" % f, "", sec)

    # the differ inside the initrd is the one that was built
    want = sha256(DIFF)
    got = None
    with gzip.open(INITRD, "rb") as f:
        data = f.read()
    i = 0
    while i + 110 <= len(data):
        if data[i:i + 6] == b"070701":
            namesize = int(data[i + 94:i + 102], 16)
            filesize = int(data[i + 54:i + 62], 16)
            name = data[i + 110:i + 110 + namesize - 1].decode("latin1")
            hdr = 110 + namesize
            hdr += (4 - (i + hdr) % 4) % 4
            body = data[i + hdr:i + hdr + filesize]
            if name in ("./root/repro", "root/repro"):
                got = hashlib.sha256(body).hexdigest()
            i = i + hdr + filesize
            i += (4 - i % 4) % 4
        else:
            i += 1
    ck(got == want, "the differ in the initrd == the built binary",
       "%s vs %s" % (got, want), sec)

    # anchors: the lines the model stands on
    anchors = [
        ("include/uapi/linux/if_pppox.h", "#define PPPOE_SES_HLEN\t8"),
        ("include/net/netfilter/nf_flow_table.h",
         "proto = *((__be16 *)(skb_mac_header(skb) + ETH_HLEN +"),
        ("net/netfilter/nft_meta.c", "case htons(ETH_P_PPP_SES):"),
        ("net/netfilter/nft_meta.c", "nhoff = PPPOE_SES_HLEN;"),
        ("net/netfilter/nft_meta.c", "nhoff += skb_network_offset(skb);"),
        ("net/netfilter/nft_meta.c", "nhoff = VLAN_HLEN;"),
        ("net/netfilter/nft_payload.c",
         "offset = skb_network_offset(skb) + pkt->nhoff;"),
        ("net/netfilter/nft_payload.c", "offset = skb_network_offset(skb);"),
        ("net/netfilter/nft_payload.c",
         "if (pkt->state->hook == NF_NETDEV_INGRESS)"),
        ("net/netfilter/nft_payload.c", "return nft_nh_write_ok_hook_unused;")
        if False else ("net/netfilter/nft_payload.c",
                       "case offsetof(struct arphdr, ar_op):"),
        ("net/netfilter/nft_payload.c",
         "return offset >= sizeof(struct arphdr) && priv->len <= eth_ip;"),
        ("net/netfilter/nft_chain_filter.c",
         "switch (eth_hdr(skb)->h_proto) {"),
        ("net/ipv4/arp.c", "if (arp->ar_hln != dev->addr_len || arp->ar_pln != 4) {"),
        ("net/ipv4/arp.c",
         "if (arp->ar_op != htons(ARPOP_REPLY) &&"),
        ("drivers/net/ppp/pppoe.c", "len = ntohs(ph->length);"),
        ("drivers/net/ppp/pppoe.c", "if (skb->len < len)"),
        ("drivers/net/ppp/pppoe.c",
         "po = __get_item(pn, ph->sid, eth_hdr(skb)->h_source, dev->ifindex);"),
        ("net/core/dev.c", "} else if (eth_type_vlan(skb->protocol)) {"),
    ]
    for path, needle in anchors:
        txt = open(KERN + "/" + path, errors="replace").read()
        ck(needle in txt, "anchor %r in %s" % (needle[:40], path), "", sec)

    # the pppoe stack really is in this image
    ck("pppoe" in open(LOG1, errors="replace").read().split("=== PPPOE_STACK ===")[-1][:400],
       "the guest lists a pppoe proc entry", "", sec)


# ------------------------------------------------------------- sections -----

def check_rep(rows):
    """the four R/P/A sections derived arm by arm"""
    rep = "-"
    seen = 0
    for r in by_kind(rows, "REP"):
        rep = r["rep"]
    spa = {}
    for r in by_kind(rows, "REP"):
        spa[r["rep"]] = int(r["spa"], 16)
        base = base_of(r["rep"], int(r["spa"], 16))
        ck(int(r["plainlen"]) == len(base), "REP %s plainlen" % r["rep"], r["plainlen"])
        ck(int(r["caplen"]) == len(cap_of(r["rep"], int(r["spa"], 16))),
           "REP %s caplen" % r["rep"], r["caplen"])
        ck(int(r["wlen"]) == len(wire_of(r["rep"], int(r["spa"], 16))),
           "REP %s wlen" % r["rep"], r["wlen"])
        ck(int(r["sproto"], 16) == (wire_of(r["rep"], int(r["spa"], 16))[12] << 8 |
                                    wire_of(r["rep"], int(r["spa"], 16))[13]),
           "REP %s sproto" % r["rep"], r["sproto"])

    # ---------------- rd ----------------
    sec = "rd"
    nrd = 0
    for r in by_kind(rows, "R"):
        if r.get("sec") != "rd":
            continue
        nrd += 1
        env = r["env"]                      # "<frame>.<gate>"
        fr, gate_s, armname = envparts(r)
        gate = 1 if gate_s == "meta" else 0
        off, ln = int(r["off"]), int(r["len"])
        r["_arm"] = armname
        cand = r["cand"]
        cv = hexbytes(r["cv"])
        live = int(r["live"])
        s = spa.get(fr, 0)
        # the candidate the instrument compared against must be the byte the
        # model says is at that coordinate
        cap = cap_of(fr, s)
        if cand == "A":
            p = 14 + off
        elif cand == "B":
            p = 22 + off
        else:
            ck(False, "rd unknown candidate", cand, sec)
            continue
        ck(cv == cap[p:p + ln], "rd %s cand %s is cap[%d:]" % (env, cand, p),
           "%s vs %s" % (cv.hex(), cap[p:p + ln].hex()), sec)
        want = 1 if read_live(fr, s, gate, off, ln, cv) else 0
        ck(live == want, "rd %s off=%d len=%d live" % (env, off, ln),
           "log %d model %d" % (live, want), sec)
    ck(nrd == 240, "rd arms counted", str(nrd), sec)

    # p.bare: nothing on a plain frame moves the read off A
    for r in by_kind(rows, "R"):
        if r.get("sec") == "rd" and envparts(r)[0] == "p":
            ck(r["cand"] != "A" or int(r["live"]) == 1,
               "p read is alive at A everywhere", r["env"], sec)
            if r["cand"] == "B":
                cap = cap_of("p", 0)
                same = cap[14 + int(r["off"]):14 + int(r["off"]) + int(r["len"])] == \
                    cap[22 + int(r["off"]):22 + int(r["off"]) + int(r["len"])]
                ck(int(r["live"]) == (1 if same else 0),
                   "p B-candidate live only where the bytes coincide",
                   r["env"] + " " + armname, sec)
    # ps.bare: the read is live at A, never at B (but where bytes coincide)
    for r in by_kind(rows, "R"):
        if (r.get("sec") == "rd" and envparts(r)[:2] == ("ps", "bare")
                and r["cand"] == "A"):
            ck(int(r["live"]) == 1, "ps bare read alive at A", armname, sec)
    # ps.meta: the read moved to B -- 8 bytes, not 4
    liveB = liveA = 0
    for r in by_kind(rows, "R"):
        if r.get("sec") == "rd" and envparts(r)[:2] == ("ps", "meta"):
            if r["cand"] == "B":
                liveB += int(r["live"])
            if r["cand"] == "A" and int(r["live"]):
                liveA += 1
    ck(liveB >= 36, "ps.meta: the read is alive at B", str(liveB), sec)
    cap = cap_of("ps", 0)
    coin = sum(1 for off, ln in CELLS
               if cap[14 + off:14 + off + ln] == cap[22 + off:22 + off + ln])
    ck(liveA == coin, "ps.meta: the read is dead at A except where two candidates "
       "are the same bytes", "%d vs %d" % (liveA, coin), sec)

    # ---------------- st ----------------
    sec = "st"
    nst = 0
    for r in by_kind(rows, "R"):
        if r.get("sec") != "st":
            continue
        nst += 1
        fr, gate_s, armname = envparts(r)
        gate = 1 if gate_s == "meta" else 0
        off, ln = int(r["off"]), int(r["len"])
        r["_arm"] = armname
        imm = hexbytes(r["imm"])
        s = spa.get(fr, 0)
        live = int(r["live"])
        pos = store_ok(fr, s, gate, off, ln, imm)
        ck(live == (1 if pos else 0), "st %s %s live" % (r["env"], armname),
           "log %d model %s" % (live, pos), sec)
        if pos:
            cap = cap_of(fr, s)
            want = []
            for i in range(ln):
                if cap[pos + i] != imm[i]:
                    want.append((pos + i, bytes([cap[pos + i]]), bytes([imm[i]])))
            got = chg_list(r["wchgs"])
            ck(got == want, "st %s %s bytes" % (r["env"], armname),
               "%s vs %s" % (got, want), sec)
        else:
            ck(r["wchgs"] == "-", "st %s dead means no bytes" % armname, "", sec)
    ck(nst == 80, "st arms counted", str(nst), sec)
    # bare: every cell dead, because the guard has no branch for 0x8864
    for r in by_kind(rows, "R"):
        if r.get("sec") == "st" and envparts(r)[:2] == ("ps", "bare"):
            ck(int(r["live"]) == 0, "ps bare store dead", armname, sec)
    # the ip4 whitelist, on the PPPoE frame, in data-relative coordinates
    whitelist = {(0, 2), (1, 1), (4, 2), (8, 1), (8, 2), (10, 1), (10, 2),
                 (10, 4), (12, 1), (12, 2), (12, 4), (16, 1), (16, 2), (16, 4)}
    got = {(int(r["off"]), int(r["len"])) for r in by_kind(rows, "R")
           if r.get("sec") == "st" and envparts(r)[:2] == ("ps", "meta")
           and int(r["live"])}
    ck(got == whitelist, "ps.meta live set == nft_nh_write_ok_ip4() whitelist",
       "%s vs %s" % (sorted(got), sorted(whitelist)), sec)

    # ---------------- pair ----------------
    sec = "pair"
    npair = 0
    for r in by_kind(rows, "R"):
        if r.get("sec") != "pair":
            continue
        npair += 1
        fr, gate_s, armname = envparts(r)
        gate = 1 if gate_s == "meta" else 0
        off, ln = int(r["off"]), int(r["len"])
        r["_arm"] = armname
        imm = hexbytes(r["imm"])
        cv = hexbytes(r["cv"])
        s = spa.get(fr, 0)
        cap = bytearray(cap_of(fr, s))
        pos = store_ok(fr, s, gate, off, ln, imm)
        pi = pktinfo(fr, s, gate)
        rpos = 14 + pi["nhoff"] + off
        rd_ok = cap[rpos:rpos + ln] == cv if r["rd"] == "1" else None
        stored = False
        if r["wr"] == "1" and pos:
            if r["rd"] != "1" or r["first"] == "1" or rd_ok:
                cap[pos:pos + ln] = imm
                stored = True
        if r["rd"] == "1":
            want = 1 if cap[rpos:rpos + ln] == cv else 0
        else:
            want = 1 if pos else 0
        ck(int(r["live"]) == want, "pair %s %s live" % (r["env"], armname),
           "log %s model %d" % (r["live"], want), sec)
        if stored:
            base = cap_of(fr, s)
            chg = [(pos + i, bytes([base[pos + i]]), bytes([imm[i]]))
                   for i in range(ln) if base[pos + i] != imm[i]]
            ck(chg_list(r["wchgs"]) == chg, "pair %s bytes" % armname,
               "%s vs %s" % (chg_list(r["wchgs"]), chg), sec)
    ck(npair == 24, "pair arms counted", str(npair), sec)
    # the asymmetry: store-then-read is dead on p and alive on ps+meta
    wrrd = {}
    for r in by_kind(rows, "R"):
        if r.get("sec") == "pair":
            fr, g, an = envparts(r)
            wrrd[(fr + "." + g, an)] = int(r["live"])
    for cell in ("wrrd_8.b", "wrrd_16.d"):
        ck(wrrd[("p.bare", cell)] == 0, "p wrrd %s dead" % cell, "", sec)
        ck(wrrd[("ps.meta", cell)] == 1, "ps+meta wrrd %s alive" % cell, "", sec)
        ck(wrrd[("ps.meta", cell.replace("wrrd", "wr"))] == 1,
           "ps+meta wr %s alive" % cell, "", sec)

    # ---------------- ih ----------------
    sec = "ih"
    nih = 0
    for r in by_kind(rows, "R"):
        if r.get("sec") != "ih":
            continue
        nih += 1
        fr, gate_s, armname = envparts(r)
        gate = 1 if gate_s == "meta" else 0
        off, ln = int(r["off"]), int(r["len"])
        s = spa.get(fr, 0)
        r["_arm"] = armname
        th = th_ok(fr, s, gate)
        kind = armname.split("_")[0]
        if th is None:
            want = 0
        else:
            cap = cap_of(fr, s)
            pos = 14 + th + off
            if kind == "wr":
                want = 1 if pos + ln <= len(cap) else 0
            else:
                cv = hexbytes(r["cv"])
                want = 1 if cap[pos:pos + ln] == cv else 0
        ck(int(r["live"]) == want, "ih %s %s live" % (r["env"], armname),
           "log %s model %d" % (r["live"], want), sec)
    ck(nih == 60, "ih arms counted", str(nih), sec)
    # on ps+meta the transport base is the true UDP header: wire 42
    for r in by_kind(rows, "R"):
        if (r.get("sec") == "ih" and envparts(r)[:2] == ("ps", "meta")
                and envparts(r)[2] == "wr_0_2"):
            ch = chg_list(r["wchgs"])
            ck(len(ch) == 2 and ch[0][0] == 42, "ps+meta ih store lands at 42",
               str(ch), sec)
            ck(ch[0][1] == b"\x9c" and ch[0][2] == b"\x90",
               "ps+meta ih store overwrites the UDP sport", str(ch), sec)

    # ---------------- pppd ----------------
    sec = "pppd"
    npp = 0
    pp = [r for r in by_kind(rows, "P") if r.get("sec") == "pppd"]
    sock = [r for r in by_kind(rows, "PPSOCK")]
    ck(bool(sock) and int(sock[0]["rc"]) >= 3,
       "the PPPoX session socket bound", str(sock[:1]), sec)
    for r in pp:
        npp += 1
        fr, gate_s, armname = envparts(r)
        gate = 1 if gate_s == "meta" else 0
        off, ln = int(r["off"]), int(r["len"])
        imm = hexbytes(r["imm"])
        s = spa.get(fr, 0)
        cap = bytearray(cap_of(fr, s))
        pos = store_ok(fr, s, gate, off, ln, imm) if r["wr"] == "1" else None
        if pos:
            cap[pos:pos + ln] = imm
        live = int(r["live"])
        want_live = 1 if (pos or (r["wr"] == "0")) else 0
        ck(live == want_live, "pppd %s live" % armname,
           "log %d model %s" % (live, want_live), sec)
        # pppoe_rcv: len = the length halfword at cap[18:20]; data after the
        # 6-byte header; drop if the frame is shorter than len; trim to len
        length = u16(cap, 18)
        avail = len(cap) - 20
        if avail < length:
            want_n, want_body = -1, b""
        else:
            want_n = length
            want_body = bytes(cap[20:20 + length])
        got_n = int(r["rxn"])
        ck(got_n == want_n, "pppd %s recv length" % armname,
           "log %s model %s (length field %d)" % (got_n, want_n, length), sec)
        if got_n > 0:
            got = hexbytes(r["rxhex"])
            ck(got == want_body[:len(got)], "pppd %s recv bytes" % armname,
               "%s vs %s" % (got.hex(), want_body.hex()), sec)
            ck(len(got) == min(got_n, 40), "pppd %s hex window" % armname, "", sec)
        got_hex = hexbytes(r.get("whex", ""))
        want_hex = bytes(cap[:len(got_hex)])
        ck(got_hex == want_hex, "pppd %s wire bytes" % armname,
           "%s vs %s" % (got_hex.hex(), want_hex.hex()), sec)
    ck(npp == 12, "pppd arms counted", str(npp), sec)
    # the cells the whitelist would need to write the real addresses are dead
    tg = {envparts(r)[2]: int(r["live"]) for r in pp}
    ck(tg.get("tsaddr") == 0 and tg.get("trdaddr") == 0,
       "the real saddr/daddr cells are refused", str(tg), sec)
    ck(tg.get("id_bare") == 0, "no store without the meta gate", "", sec)
    # the store that names "ipv4 id" changes the delivered datagram's length
    ck({envparts(r)[2]: int(r["rxn"]) for r in pp}.get("id_small") == 4,
       "cell 4 (ipv4 id) truncates the delivered datagram to 4 bytes", "", sec)

    # ---------------- arpd ----------------
    sec = "arpd"
    na = 0
    arms = [r for r in by_kind(rows, "A") if r.get("sec") == "arpd"]
    brmac = None
    for r in by_kind(rows, "BRMAC"):
        brmac = hexbytes(r["_raw"])
    ck(brmac is not None and len(brmac) == 6, "br0 MAC read", str(brmac), sec)
    for r in arms:
        na += 1
        fr = r["frame"]
        s = int(r["spa"], 16)
        off, ln = int(r["off"]), int(r["len"])
        wr = r["wr"] == "1"
        imm = hexbytes(r["imm"])
        cap = bytearray(cap_of(fr, s))
        # the store: cap[14+off]; the guard is the ARP list in the bridge
        # family and the constant `true` at netdev ingress
        if wr:
            allowed = True if r["env"] == "nd" else guard_arp(off, ln)
            pos = 14 + off
            if allowed and pos + ln <= len(cap):
                cap[pos:pos + ln] = imm
            elif allowed:
                allowed = False
            got_hex = hexbytes(r.get("whex", ""))
            want_hex = bytes(cap[:len(got_hex)])
            ck(got_hex == want_hex, "arpd %s store bytes" % r["arm"],
               "%s vs %s" % (got_hex.hex(), want_hex.hex()), sec)
        # receiving side: a Q-in-Q frame loses its inner tag (vid 0 outer is a
        # priority tag, net/core/dev.c check_vlan_id); a non-zero inner vid is
        # PACKET_OTHERHOST
        kind, tags = FRAMES[fr]
        inner_vid = tags[-1][1] & 0x0FFF if len(tags) >= 2 else 0
        deliv = bytearray(cap)
        reaches_pkt = True
        if len(tags) >= 2:
            deliv = bytearray(cap[:12] + cap[16:])
            if inner_vid:
                reaches_pkt = False
        proto = u16(deliv, 12) if len(deliv) > 13 else 0
        hlen, plen = deliv[14 + 4], deliv[14 + 5]
        reached = reaches_pkt and proto == 0x0806 and hlen == 6 and plen == 4
        hrd = u16(deliv, 14)
        prt = u16(deliv, 16)
        op = u16(deliv, 20)
        answered = reached and hrd in (1, 6) and prt == 0x0800 and op == 1
        ck(int(r["arc"]) == (1 if reached else 0),
           "arpd %s reaches NF_ARP_IN" % r["arm"],
           "log %s model %s (hlen %d plen %d proto %04x)" %
           (r["arc"], reached, hlen, plen, proto), sec)
        ck((int(r["repn"]) > 0) == answered, "arpd %s reply" % r["arm"],
           "log %s model %s (op %d)" % (r["repn"], answered, op), sec)
        ck((r["ent"] != "-") == answered, "arpd %s neighbour entry" % r["arm"],
           r["ent"], sec)
        if answered:
            rep = hexbytes(r["rephex"])
            ck(rep[:6] == deliv[22:28], "arpd %s reply goes to the sha" % r["arm"],
               "%s vs %s" % (rep[:6].hex(), deliv[22:28].hex()), sec)
            ck(rep[6:12] == brmac, "arpd %s reply comes from br0" % r["arm"],
               rep[6:12].hex(), sec)
            ck(rep[38:42] == s.to_bytes(4, "big"),
               "arpd %s reply asks the sender's address" % r["arm"],
               "%s vs %s" % (rep[38:42].hex(), s.to_bytes(4, "big").hex()), sec)
            if r["ent"] != "-":
                ck(r["ent"].split(";")[3] == ":".join(
                    "%02x" % b for b in deliv[22:28]),
                   "arpd %s entry holds the sha of the frame" % r["arm"],
                   r["ent"], sec)
    ck(na == 16, "arpd arms counted", str(na), sec)
    A = {r["arm"]: r for r in arms}
    # the F40 sentence, now measured: the shifted ar_hln cell kills the frame
    ck(A["br_q0_hln"]["arc"] == "0" and A["br_q0_ctl"]["arc"] == "1",
       "Q-in-Q: control reaches the ARP hook, the ar_hln store does not", "", sec)
    # ... and the same death is reachable where the guard is the constant
    ck(A["nd_pa_hln"]["arc"] == "0", "ingress: the hlen store kills the frame", "", sec)
    # the frame whose ar_pro was rewritten is still ARP to arp_rcv
    ck(A["br_q0_pro"]["arc"] == "1" and A["br_q0_pro"]["repn"] == "-1",
       "Q-in-Q: ar_pro store passes arp_rcv, dies in arp_process", "", sec)
    # a non-zero inner vid hides the frame from the ARP stack entirely
    ck(A["br_q200_ctl"]["arc"] == "0", "Q-in-Q inner vid 200 never reaches ARP", "", sec)
    ck(A["br_tag0_ctl"]["arc"] == "1" and A["br_tag0_ctl"]["repn"] != "-1",
       "a single vid-0 tag does not hide the frame", "", sec)


def check_determinism(rows1, rows2):
    sec = "det"
    def norm(rows, brmac):
        out = []
        for r in rows:
            if r["_k"] not in ("R", "P", "A"):
                continue
            d = dict(r)
            d.pop("ipin", None)
            d.pop("_arm", None)
            d.pop("_raw", None)
            d.pop("reppkt", None)
            d.pop("wpt", None)
            d.pop("rpt", None)
            for k in ("whex", "rhex", "reqhex", "rephex", "ent"):
                if k in d and brmac:
                    d[k] = d[k].replace(brmac.hex(), "BRMAC")
            out.append(tuple(sorted(d.items())))
        return out
    b1 = b2 = None
    for r in by_kind(rows1, "BRMAC"):
        b1 = hexbytes(r["_raw"])
    for r in by_kind(rows2, "BRMAC"):
        b2 = hexbytes(r["_raw"])
    a, b = norm(rows1, b1), norm(rows2, b2)
    ck(len(a) == len(b), "rep1 and rep2 have the same number of arms",
       "%d vs %d" % (len(a), len(b)), sec)
    diff = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
    ck(not diff, "rep1 == rep2 arm for arm (br0 MAC and ipin masked)",
       "first differences at %s" % diff[:5], sec)


def check_splat(paths):
    sec = "splat"
    pat = re.compile(r"KASAN|BUG:|WARNING:|Oops|general protection|"
                     r"double free|use-after-free|Call Trace")
    for p in paths:
        bad = []
        for line in open(p, errors="replace"):
            if pat.search(line):
                bad.append(line.strip()[:120])
        ck(not bad, "no splat in %s" % os.path.basename(p), str(bad[:3]), sec)
    for p in paths:
        txt = open(p, errors="replace").read()
        ck("=== MODE_EXIT f563=0 ===" in txt, "MODE_EXIT 0 in %s" % os.path.basename(p),
           "", sec)


def main():
    check_provenance()
    rows1 = parse(LOG1)
    rows2 = parse(LOG2)
    check_rep(rows1)
    check_determinism(rows1, rows2)
    check_splat([LOG1, LOG2])
    print("checks=%d failed=%d" % (N, len(FAIL)))
    for s in sorted(SECN):
        print("  %-6s %d" % (s, SECN[s]))
    if FAIL:
        print("--- first 25 failures ---")
        for sec, what, detail in FAIL[:25]:
            print("[%s] %s | %s" % (sec, what, detail))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
