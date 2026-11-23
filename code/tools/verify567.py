#!/usr/bin/env python3
"""verify567.py -- independent check of turn 567 / F45.

Question left by F44: `@th` has one coordinate across four doors because IPv4
computes it as a formula (`ihl*4`).  The IPv6 constructors do not: they take
`thoff` from `ipv6_find_hdr()`, which WALKS the extension-header chain and
also fills `tprot` and `fragoff`.  And: does a failed IPv6 parse drop IPv4
frames on the same device?

What this script does NOT do: it does not read the instrument's intent.  It
reads the LOG, rebuilds every frame from the logged bytes, ports
`ipv6_find_hdr()` and `ip6_rcv_core()` to Python, ports the three IPv6 pktinfo
constructors and every write guard of `nft_payload.c`, and then compares the
predicted verdict, the predicted byte and the predicted delivery with what the
log says the hook saw (NFLOG payload), what the counters say, and what the
receiver's sockets got.

Exit 0 = every check passed, 1 = a discrepancy (printed).
"""
import gzip
import hashlib
import os
import re
import sys

ROOT = "/work/kernel-sec"
IMG = ROOT + "/src/linux-7.3.4-T563/arch/x86/boot/bzImage"
SRC = ROOT + "/src/linux-7.3.4-T563"
BIN = ROOT + "/vm/build/differ567"
INITRD = ROOT + "/vm/initrd567/full.cpio.gz"
LOGS = os.environ.get(
    "F45_LOGS",
    "/work/kernel-sec/logs/f45_rep1.log,/work/kernel-sec/logs/f45_rep2.log"
).split(",")

ok = 0
bad = 0
fails = []


def check(cond, what, detail=""):
    global ok, bad
    if cond:
        ok += 1
    else:
        bad += 1
        fails.append("%s%s" % (what, (": " + detail) if detail else ""))
    return cond


def eq(got, want, what, extra=""):
    return check(got == want, what,
                 "got %r want %r%s" % (got, want, (" " + extra) if extra else ""))


def read(path):
    with open(path, "rb") as f:
        return f.read()


def text(path):
    # CRLF: this image's serial console ends lines with \r\n.  Tenth reminder.
    return read(path).decode("utf-8", "replace").replace("\r\n", "\n")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def hx(s):
    if not s or s == "-":
        return b""
    return bytes.fromhex(s)


# ------------------------------------------------------------- constants

V6SRC = bytes.fromhex("fd000000000000000000000000980001")
V6DST = bytes.fromhex("fd000000000000000000000000990009")
V4DST = bytes.fromhex("0a090007")
MAC_SRC = bytes.fromhex("aabbcc000066")
IP6_MAX_EXT_HDRS_CNT = 12          # include/net/ipv6.h
NEXTHDR_HOP = 0
NEXTHDR_ROUTING = 43
NEXTHDR_FRAGMENT = 44
NEXTHDR_NONE = 59
NEXTHDR_DEST = 60
NEXTHDR_AUTH = 51

NH, TH, LL = 1, 2, 3               # nft_payload bases used here


def ipv6_ext_hdr(n):
    return n in (NEXTHDR_HOP, NEXTHDR_ROUTING, NEXTHDR_FRAGMENT,
                 NEXTHDR_AUTH, NEXTHDR_NONE, NEXTHDR_DEST)


def be16(b, o):
    return (b[o] << 8) | b[o + 1]


def be32(b, o):
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


# ------------------------------------------------------------- the walk

class Walk(object):
    def __init__(self, proto=None, thoff=0, fragoff=0, err=False, why=""):
        self.proto = proto
        self.thoff = thoff
        self.fragoff = fragoff
        self.err = err
        self.why = why


def ipv6_find_hdr(l3, skb_len):
    """Port of ipv6_find_hdr(skb, &thoff=0, target=-1, &fragoff, IP6_FH_F_AUTH).

    data-relative: skb_network_offset() == 0 in every door of this instrument
    (skb_network_offset() is `network_header - data`, skbuff.h:3264)."""
    if len(l3) < 40:
        return Walk(err=True, why="short")
    nexthdr = l3[6]
    start = 40
    cnt = 0
    while True:
        if (not ipv6_ext_hdr(nexthdr)) or nexthdr == NEXTHDR_NONE:
            break
        cnt += 1
        if cnt > IP6_MAX_EXT_HDRS_CNT:
            return Walk(err=True, why="too-many-exthdrs")
        if start + 2 > skb_len:
            return Walk(err=True, why="opt-hdr-pointer")
        if nexthdr == NEXTHDR_ROUTING:
            if start + 2 > skb_len:
                return Walk(err=True, why="rt-hdr-pointer")
        if nexthdr == NEXTHDR_FRAGMENT:
            if start + 4 > skb_len:
                return Walk(err=True, why="frag-pointer")
            foff = be16(l3, start + 2) & ~0x7
            if foff:
                nxt = l3[start]
                if (not ipv6_ext_hdr(nxt)) or nxt == NEXTHDR_NONE:
                    # `*offset` is NOT written on this return path
                    return Walk(proto=nxt, thoff=0, fragoff=foff)
                return Walk(err=True, why="frag-nonfirst-ext")
            hdrlen = 8
        elif nexthdr == NEXTHDR_AUTH:
            break                      # IP6_FH_F_AUTH and target < 0
        else:
            hdrlen = (l3[start + 1] + 1) * 8
        if skb_len - start < hdrlen:
            return Walk(err=True, why="exthdr-longer-than-skb")
        nexthdr = l3[start]
        start += hdrlen
    return Walk(proto=nexthdr, thoff=start)


def ipv6_parse_tlv_ok(l3, skb_len):
    """The part of ip6_rcv_core()'s hop-by-hop parse that decides our frames:
    walk every extension header from offset 40 and require each one to fit."""
    if len(l3) < 40:
        return False, "short"
    nexthdr = l3[6]
    start = 40
    cnt = 0
    while ipv6_ext_hdr(nexthdr) and nexthdr != NEXTHDR_NONE:
        cnt += 1
        if cnt > IP6_MAX_EXT_HDRS_CNT:
            return False, "too-many"
        if start + 2 > skb_len:
            return False, "trunc-opt"
        if nexthdr == NEXTHDR_FRAGMENT:
            hdrlen = 8
        elif nexthdr == NEXTHDR_AUTH:
            hdrlen = (l3[start + 1] + 2) * 4
        else:
            hdrlen = (l3[start + 1] + 1) * 8
        if skb_len - start < hdrlen:
            return False, "trunc-body"
        nexthdr = l3[start]
        start += hdrlen
    return True, "ok"


def ip6_rcv_core_ok(l3):
    """Does the frame survive ip6_rcv_core() and reach NF_INET_PRE_ROUTING?

    Checks that matter here (net/ipv6/ip6_input.c): version == 6;
    payload_len + 40 <= skb->len else INTRUNCATEDPKTS; if nexthdr is
    hop-by-hop, ipv6_parse_hopopts() must succeed else INHDRERRORS.
    """
    if len(l3) < 40:
        return False, "short"
    if l3[0] >> 4 != 6:
        return False, "version"
    plen = be16(l3, 4)
    if plen + 40 > len(l3):
        return False, "truncated"
    if l3[6] == NEXTHDR_HOP:
        good, why = ipv6_parse_tlv_ok(l3, len(l3))
        if not good:
            return False, "hopopts:" + why
    return True, "ok"


KNOWN_L4 = (6, 17, 58, 59)     # TCP, UDP, ICMPv6, NEXTHDR_NONE


def stack_fate(door, state, fr, post):
    """(Ip6InReceives, drop counter or None, delivered, unknown proto) for the
    packet the stack finally sees.

    `post` is the packet AFTER the rule wrote into it (or the original bytes
    when nothing was written).  The door decides which gate the write lands in
    front of: the ingress doors write BEFORE ip6_rcv_core(), the layer-3 doors
    AFTER it.  The IPv6 route lookup runs after NF_INET_PRE_ROUTING in both
    cases (ipv6_rcv()'s okfn is ip6_rcv_finish), so a write to the destination
    address moves the packet even at a hook that is "too late" to validate it.
    """
    if fr["sproto"] != 0x86dd:
        return 0, None, False, False
    l3orig = frame_l3(fr)
    if state["ieg"] and ieg_drops(fr):
        kind = "trun" if be16(l3orig, 4) + 40 > len(l3orig) else "hdr"
        return 0, kind, False, False
    if door in ("ip6p", "inp"):
        good, why = ip6_rcv_core_ok(l3orig)      # the UNWRITTEN packet
        if not good:
            return 2, ("trun" if why == "truncated" else "hdr"), False, False
        l3 = post
    else:
        l3 = post                                # the WRITTEN packet
        if len(l3) < 40 or (l3[0] >> 4) != 6:
            return 2, "hdr", False, False
        if be16(l3, 4) + 40 > len(l3):
            return 2, "trun", False, False
        if l3[6] == NEXTHDR_HOP and not ipv6_parse_tlv_ok(l3, len(l3))[0]:
            return 2, "hdr", False, False
    if not ipv6_parse_tlv_ok(l3, len(l3))[0]:
        return 2, "hdr", False, False
    w = ipv6_find_hdr(l3, len(l3))
    if w.err or w.fragoff:
        return 2, None, False, False
    if l3[24:40] != V6DST:
        return 2, None, False, False
    if w.proto not in KNOWN_L4:
        return 2, None, False, True
    return 2, None, True, False


# ------------------------------------------------------------- the guards

class Pkt(object):
    """struct nft_pktinfo after a constructor."""

    def __init__(self, l4=False, tprot=0, thoff=0, fragoff=0, ethertype=0,
                 skb_len=0, why="ok"):
        self.l4 = l4
        self.tprot = tprot
        self.thoff = thoff
        self.fragoff = fragoff
        self.ethertype = ethertype
        self.skb_len = skb_len
        self.why = why


def pktinfo_ipv6(l3, skb_len):
    """nft_set_pktinfo_ipv6(): walk, unspec on failure, NO length check."""
    w = ipv6_find_hdr(l3, skb_len)
    if w.err:
        return Pkt(skb_len=skb_len, why="unspec:" + w.why)
    return Pkt(l4=True, tprot=w.proto, thoff=w.thoff, fragoff=w.fragoff,
               ethertype=0x86dd, skb_len=skb_len)


def pktinfo_ipv6_validate(l3, skb_len):
    """__nft_set_pktinfo_ipv6_validate(pkt, 0): version + length + walk."""
    if len(l3) < 40:
        return Pkt(skb_len=skb_len, why="unspec:short")
    if l3[0] >> 4 != 6:
        return Pkt(skb_len=skb_len, why="unspec:version")
    plen = be16(l3, 4)
    if plen + 40 > skb_len:
        return Pkt(skb_len=skb_len, why="unspec:truncated")
    return pktinfo_ipv6(l3, skb_len)


def pktinfo_ipv6_ingress(l3, skb_len):
    """nft_set_pktinfo_ipv6_ingress(): returns -1 -> the handler returns
    NF_DROP."""
    if skb_len < 40:
        return None
    if l3[0] >> 4 != 6:
        return None
    plen = be16(l3, 4)
    if plen + 40 > skb_len:
        return None
    p = pktinfo_ipv6(l3, skb_len)
    if p.why != "ok":
        return None
    return p


def pktinfo_ipv4(l3, skb_len):
    """nft_set_pktinfo_ipv4(): no validation at all."""
    ihl = (l3[0] & 0xf) * 4
    return Pkt(l4=True, tprot=l3[9], thoff=ihl,
               fragoff=be16(l3, 6) & 0x1fff, ethertype=0x0800,
               skb_len=skb_len)


def th_guard(pkt, off, ln):
    """nft_payload_set_eval() for base th, plus skb_ensure_writable()."""
    if not pkt.l4 or pkt.fragoff:
        return False, "no-l4proto-or-frag"
    if pkt.tprot == 6:                       # nft_th_write_ok, doff = 12
        doff = 12
        if not (off > doff or off + ln <= doff):
            return False, "tcp-doff"
    coord = pkt.thoff + off
    if coord + ln > pkt.skb_len:
        return False, "length"
    return True, coord


def nh_ok_ip6(off, ln, imm):
    """nft_nh_write_ok_ip6(): every branch, plus the length limits of the
    write path (skb_ensure_writable is checked by the caller)."""
    if off == 0:
        return ln <= 4 and (imm[0] >> 4) == 6
    if off == 2:
        return ln <= 2
    if off == 7:
        return ln == 1
    if off == 8:
        return ln <= 32
    if off == 24:
        return ln <= 16
    return False


def nh_ok_ip4(l3, off, ln, imm):
    """nft_nh_write_ok_ip4(): case 0 compares the VALUE with the packet."""
    if off == 0:
        return ln == 2 and imm[0] == l3[0]
    if off == 1:
        return ln == 1
    if off == 4:
        return ln == 2
    if off == 8:
        if ln == 1:
            return True
        if ln != 2:
            return False
        return imm[1] == l3[off + 1]
    if off == 10:
        return ln <= 10
    if off == 12:
        return ln <= 8
    if off == 16:
        return ln <= 4
    return False


# ------------------------------------------------------------- doors

DKEY = {"ip4p": "ipp", "ip6p": "ip6p", "inp": "inp", "ndg": "ndg",
        "ieg": "ieg"}

DOORS = {
    # tag   family  hook   dev     pf for the guards          ctor
    "ip4p": dict(fam="ip4", hook=0, dev=None, pf="ip4"),
    "ip6p": dict(fam="ip6", hook=0, dev=None, pf="ip6"),
    "inp": dict(fam="inet", hook=0, dev=None, pf="auto"),
    "ndg": dict(fam="netdev", hook=0, dev="s1", pf="netdev"),
    "ieg": dict(fam="inet", hook=5, dev="s1", pf="ip6"),
}


def frame_l3(fr):
    return fr["wire"][14:]


def pktinfo(door, fr):
    l3 = frame_l3(fr)
    skb_len = len(l3)
    if fr["sproto"] == 0x0800:
        if door in ("ip4p", "inp"):
            return pktinfo_ipv4(l3, skb_len)
        return None                     # ip6/netdev doors never see IPv4
    if door == "ip4p":
        return None                     # family ip never gets ETH_P_IPV6
    if door in ("ip6p", "inp"):
        return pktinfo_ipv6(l3, skb_len)
    if door == "ndg":
        return pktinfo_ipv6_validate(l3, skb_len)
    if door == "ieg":
        return pktinfo_ipv6_ingress(l3, skb_len)
    return None


def ieg_drops(fr):
    """Does the inet-ingress handler drop this frame before any chain?"""
    if fr["sproto"] not in (0x0800, 0x86dd):
        return False
    if fr["sproto"] == 0x0800:
        l3 = frame_l3(fr)
        if len(l3) < 20:
            return True
        if len(l3) < be16(l3, 2):
            return True
        if (l3[0] & 0xf) < 5 or l3[0] >> 4 != 4:
            return True
        if be16(l3, 2) < (l3[0] & 0xf) * 4:
            return True
        return False
    return pktinfo_ipv6_ingress(frame_l3(fr), len(frame_l3(fr))) is None


def reach(door, fr, state):
    """Is the chain of `door` executed for this frame, given which ingress
    tables exist (`state` = {'ieg': bool, 'ndg': bool})?"""
    if door == "ieg":
        return state["ieg"] and not ieg_drops(fr)
    if door == "ndg":
        if not state["ndg"]:
            return False
        return not (state["ieg"] and ieg_drops(fr))
    if door == "ip4p":
        return fr["sproto"] == 0x0800
    # layer-3 doors
    if fr["sproto"] == 0x0800:
        return door == "inp"
    if state["ieg"] and ieg_drops(fr):
        return False
    good, why = ip6_rcv_core_ok(frame_l3(fr))
    return good


def count_mult(door, fr):
    """How many times the chain runs for one transmitted frame.

    IPv4 is weak-host: the bridge's flooded copy comes back on r0 and is
    delivered a second time, so the layer-3 hook runs twice (F44's ipin=2).
    IPv6 is strict (ip6_rcv_core: the copy arrives on r0, the address lives on
    br0) -- measured as Ip6InDiscards+1 and Ip6InDelivers+1.
    """
    if fr["sproto"] == 0x0800 and door in ("ip4p", "inp"):
        return 2
    return 1


# ------------------------------------------------------------- the log

def parse_kv(line):
    out = {}
    for part in line.split("|")[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


class Log(object):
    def __init__(self, path):
        self.path = path
        self.hdr = {}
        self.frames = {}
        self.arms = []
        self.xc = []
        self.diag = []
        self.md = []
        self.modes = []
        self.splat = []
        self.env = {}
        t = text(path)
        for ln in t.split("\n"):
            if ln.startswith("### sha256:"):
                self.hdr["ksha"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("### initrd sha256:"):
                self.hdr["isha"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("### initrd:"):
                self.hdr["ipath"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("F567 FRAME|"):
                p = ln.split("|")
                self.frames[p[1]] = dict(
                    tag=p[1], wlen=int(p[2].split("=")[1]),
                    wire=hx(p[3].split("=", 1)[1]), sproto=None)
            elif ln.startswith("F567 A|"):
                self.arms.append(parse_kv(ln))
            elif ln.startswith("F567 XC|"):
                self.xc.append(parse_kv(ln))
            elif ln.startswith("F567 DIAG|env="):
                self.diag.append(parse_kv(ln))
            elif ln.startswith("F567 MD|"):
                self.md.append(ln.strip())
            elif ln.startswith("=== MODE_EXIT"):
                self.modes.append(ln.strip())
            elif ln.startswith("F567 V6ON") or ln.startswith("F567 SOCK") \
                    or ln.startswith("F567 ADDR") or ln.startswith("F567 V6ADDR"):
                k = ln.split("|")[0].replace("F567 ", "")
                self.env[k] = ln.strip()
            if re.search(r"KASAN|BUG:|Oops|WARNING:|general protection", ln):
                self.splat.append(ln)
        for tag, fr in self.frames.items():
            fr["sproto"] = 0x86dd if fr["wire"][12:14] == b"\x86\xdd" \
                else 0x0800


# ------------------------------------------------------------- provenance

def cpio_extract(blob, name):
    """newc: the padding aligns the OFFSET IN THE ARCHIVE, not the name
    (the mistake of F43/F44, made again here and caught by the smoke)."""
    i = 0
    while i + 110 <= len(blob):
        hdr = blob[i:i + 110]
        if hdr[:6] != b"070701":
            return None
        namesz = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        nm = blob[i + 110:i + 110 + namesz - 1].decode()
        off = (i + 110 + namesz + 3) & ~3
        if nm in (name, "./" + name):
            return blob[off:off + filesize]
        i = (off + filesize + 3) & ~3
    return None


def main():
    logs = [Log(p) for p in LOGS]
    L1 = logs[0]

    # ---- provenance -----------------------------------------------------
    eq(L1.hdr.get("ksha"), sha(read(IMG)), "kernel sha in the log == the file")
    check(bool(L1.hdr.get("isha")), "initrd sha recorded in the log")
    ipath = L1.hdr.get("ipath", "")
    if ipath and os.path.exists(ipath):
        eq(L1.hdr.get("isha"), sha(read(ipath)), "initrd sha == the initrd file")
        payload = read(ipath)
        try:
            blob = gzip.decompress(payload)
        except OSError:
            blob = payload
        got = cpio_extract(blob, "root/repro")
        check(got is not None, "differ567 found inside the initramfs")
        if got:
            eq(sha(got), sha(read(BIN)),
               "the differ inside the initramfs == the built binary")

    # ---- source anchors -------------------------------------------------
    def anchor(path, needle, what):
        body = text(os.path.join(SRC, path))
        check(needle in body, "anchor: " + what, needle[:70])

    anchor("include/net/netfilter/nf_tables_ipv6.h",
           "protohdr = ipv6_find_hdr(pkt->skb, &thoff, -1, &frag_off, &flags);",
           "nft_set_pktinfo_ipv6 walks the chain")
    anchor("include/net/netfilter/nf_tables_ipv6.h",
           "\tpkt->thoff = thoff;", "the walk result IS pkt->thoff")
    anchor("include/net/netfilter/nf_tables_ipv6.h",
           "if (pkt_len + sizeof(*ip6h) > skb_len)\n\t\treturn -1;",
           "the validate variant checks the payload length")
    anchor("include/net/netfilter/nf_tables_ipv6.h",
           "__IP6_INC_STATS(nft_net(pkt), idev, IPSTATS_MIB_INTRUNCATEDPKTS);",
           "ingress: truncated -> INTRUNCATEDPKTS")
    anchor("include/net/netfilter/nf_tables_ipv6.h",
           "__IP6_INC_STATS(nft_net(pkt), idev, IPSTATS_MIB_INHDRERRORS);",
           "ingress: bad header -> INHDRERRORS")
    anchor("include/net/netfilter/nf_tables_ipv6.h",
           "\tif (protohdr < 0 || thoff > U16_MAX) {\n\t\tnft_set_pktinfo_unspec(pkt);",
           "layer-3 IPv6 falls back to unspec, it does not drop")
    anchor("net/netfilter/nft_chain_filter.c",
           "\t\tif (nft_set_pktinfo_ipv6_ingress(&pkt) < 0)\n\t\t\treturn NF_DROP;",
           "inet ingress drops when the constructor fails")
    anchor("net/netfilter/nft_chain_filter.c",
           "switch (skb->protocol) {", "inet ingress switches on skb->protocol")
    anchor("net/netfilter/nft_chain_filter.c",
           "\tcase NFPROTO_IPV6:\n\t\tnft_set_pktinfo_ipv6(&pkt);",
           "nft_do_chain_inet builds IPv6 pktinfo the same way")
    anchor("net/netfilter/nft_chain_filter.c",
           "nft_set_pktinfo_ipv6(&pkt);\n\n\treturn nft_do_chain(&pkt, priv);",
           "nft_do_chain_ipv6 uses the non-validating constructor")
    anchor("net/netfilter/nft_payload.c",
           "if (!(pkt->flags & NFT_PKTINFO_L4PROTO) || pkt->fragoff)",
           "the th base refuses BOTH read and write without pktinfo")
    anchor("net/netfilter/nft_payload.c",
           "\tunsigned int doff = offsetof(struct tcphdr, ack_seq) + sizeof(__be32);",
           "nft_th_write_ok: doff == 12")
    anchor("net/netfilter/nft_payload.c",
           "\t\treturn priv->len <= 4 && ih->version == 6;",
           "ip6 case 0 compares a CONSTANT, not the packet")
    anchor("net/netfilter/nft_payload.c",
           "\t\treturn priv->len <= 16 + 16;", "ip6 saddr: len <= 32")
    anchor("net/netfilter/nft_payload.c",
           "\t\tif (pkt->state->hook == NF_NETDEV_INGRESS)\n\t\t\treturn true;",
           "netdev ingress: @nh is unconditional")
    anchor("include/net/netfilter/nf_tables.h",
           "static inline unsigned int nft_thoff(const struct nft_pktinfo *pkt)\n"
           "{\n\treturn pkt->thoff;", "nft_thoff() is pkt->thoff, no offset")
    anchor("include/linux/skbuff.h",
           "return skb_network_header(skb) - skb->data;",
           "skb_network_offset() is data-relative")
    anchor("net/ipv6/exthdrs_core.c",
           "unsigned int start = skb_network_offset(skb) + sizeof(struct ipv6hdr);",
           "ipv6_find_hdr starts at the network header")
    anchor("net/ipv6/exthdrs_core.c",
           "\t\t\tif (skb->len - start < hdrlen)\n\t\t\t\treturn -EBADMSG;",
           "an extension header longer than the skb is EBADMSG")
    anchor("net/ipv6/exthdrs_core.c",
           "\t\t\t\t\tif (fragoff)\n\t\t\t\t\t\t*fragoff = _frag_off;\n"
           "\t\t\t\t\treturn hp->nexthdr;",
           "non-first fragment returns WITHOUT writing *offset")
    anchor("net/ipv6/ip6_input.c",
           "if (pkt_len + sizeof(struct ipv6hdr) > skb->len) {",
           "ip6_rcv_core drops a truncated packet BEFORE prerouting")
    anchor("net/ipv6/ip6_input.c",
           "idev, IPSTATS_MIB_INTRUNCATEDPKTS);",
           "ip6_rcv_core counts INTRUNCATEDPKTS itself")
    anchor("net/ipv6/ip6_input.c",
           "\t\tif (ipv6_parse_hopopts(skb) < 0) {\n"
           "\t\t\t__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);",
           "ip6_rcv_core parses hop-by-hop BEFORE prerouting")

    # ---- the environment the instrument printed -------------------------
    for L in logs:
        check(any("disable_ipv6" not in e for e in L.env.values()),
              "the instrument printed its IPv6 state")
        eq("F567 V6ON|br0=0|s1=1|s0=1", L.env.get("V6ON"),
           "IPv6 is on for br0 only (%s)" % os.path.basename(L.path))
        check("rc=0" in L.env.get("V6ADDR", "x"), "fd00::99:9 added to br0")
        check("u6a=" in L.env.get("SOCK", "x") and "-1" not in L.env["SOCK"],
              "IPv6 sockets bound", L.env.get("SOCK"))

    # ---- the frames the instrument built --------------------------------
    want_frames = ["v6", "hb", "do", "hbdo", "fr0", "frn", "none", "mexth",
                   "mdobad", "mtrunc", "mver", "t6", "p4"]
    for tag in want_frames:
        check(tag in L1.frames, "frame present: " + tag)
    F = L1.frames

    def l3(tag):
        return frame_l3(F[tag])

    for tag, fr in L1.frames.items():
        eq(fr["wlen"], len(fr["wire"]),
           "the logged length of %s is the length of the logged bytes" % tag)
    eq(len(l3("v6")), 66, "v6 is 40+26 bytes of L3")
    eq(be16(l3("v6"), 4), 26, "v6 payload_len")
    eq(len(l3("hb")), 74, "hb carries 8 ext bytes")
    eq(len(l3("hbdo")), 82, "hbdo carries 16 ext bytes")
    eq(l3("hb")[40], 17, "hb: hop-by-hop next header is UDP")
    eq(l3("hb")[41], 0, "hb: hdrlen 0 -> 8 bytes")
    eq(l3("mexth")[41], 15, "mexth claims 128 bytes of hop-by-hop")
    eq(l3("mdobad")[40], 17, "mdobad: dest-opts next header is UDP")
    eq(l3("mdobad")[41], 15, "mdobad claims 128 bytes of dest-opts")
    eq(l3("frn")[42:44], b"\x00\x08", "frn: fragment offset 8 bytes")
    eq(l3("fr0")[42:44], b"\x00\x00", "fr0: fragment offset 0")
    eq(l3("none")[6], 59, "none: nexthdr 59")
    eq(len(l3("none")), 40, "none: no payload at all")
    eq(be16(l3("mtrunc"), 4), 512, "mtrunc claims 512 bytes")
    eq(l3("mver")[0] >> 4, 5, "mver: version 5")
    eq(l3("t6")[6], 6, "t6: TCP")
    eq(F["p4"]["wire"][12:14], b"\x08\x00", "p4 is an IPv4 frame")

    # ---- the walk itself, checked against the frames --------------------
    w = ipv6_find_hdr(l3("v6"), len(l3("v6")))
    eq((w.err, w.proto, w.thoff), (False, 17, 40), "walk(v6) = UDP at 40")
    w = ipv6_find_hdr(l3("hb"), len(l3("hb")))
    eq((w.err, w.proto, w.thoff), (False, 17, 48), "walk(hb) = UDP at 48")
    w = ipv6_find_hdr(l3("do"), len(l3("do")))
    eq((w.err, w.proto, w.thoff), (False, 17, 48), "walk(do) = UDP at 48")
    w = ipv6_find_hdr(l3("hbdo"), len(l3("hbdo")))
    eq((w.err, w.proto, w.thoff), (False, 17, 56), "walk(hbdo) = UDP at 56")
    w = ipv6_find_hdr(l3("fr0"), len(l3("fr0")))
    eq((w.err, w.proto, w.thoff, w.fragoff), (False, 17, 48, 0),
       "walk(fr0) = UDP at 48, fragoff 0")
    w = ipv6_find_hdr(l3("frn"), len(l3("frn")))
    eq((w.err, w.proto, w.thoff, w.fragoff), (False, 17, 0, 8),
       "walk(frn) = UDP, fragoff 8, and thoff UNWRITTEN (0)")
    w = ipv6_find_hdr(l3("none"), len(l3("none")))
    eq((w.err, w.proto, w.thoff), (False, 59, 40), "walk(none) = 59 at 40")
    for tag in ("mexth", "mdobad"):
        w = ipv6_find_hdr(l3(tag), len(l3(tag)))
        eq((w.err, w.why), (True, "exthdr-longer-than-skb"),
           "walk(%s) is EBADMSG" % tag)
    good, why = ip6_rcv_core_ok(l3("mdobad"))
    eq(good, True, "mdobad survives ip6_rcv_core (only HOP is parsed there)")
    good, why = ip6_rcv_core_ok(l3("mexth"))
    eq((good, why), (False, "hopopts:trunc-body"),
       "mexth dies in ip6_rcv_core, before any hook")
    good, why = ip6_rcv_core_ok(l3("mtrunc"))
    eq((good, why), (False, "truncated"), "mtrunc dies in ip6_rcv_core")

    # ---- state per section ---------------------------------------------
    STATE = {
        "dbg": dict(ieg=False, ndg=False),
        "diag": dict(ieg=True, ndg=True),
        "td": dict(ieg=True, ndg=True),
        "tf": dict(ieg=True, ndg=True),
        "nh": dict(ieg=True, ndg=True),
        "xf": dict(ieg=True, ndg=True),
        "rd": dict(ieg=True, ndg=True),
        "mp": dict(ieg=True, ndg=True),
        "xc": dict(ieg=True, ndg=True),
        "md_both_ndg": dict(ieg=True, ndg=True),
        "md_both_ieg": dict(ieg=True, ndg=True),
        "md_ndg_only": dict(ieg=False, ndg=True),
        "md_inp_l3": dict(ieg=False, ndg=True),
        "md_ip6p_l3": dict(ieg=False, ndg=True),
        "mp_l3": dict(ieg=False, ndg=True),
        "md_ieg_only": dict(ieg=True, ndg=False),
        "md_again_ieg": dict(ieg=True, ndg=True),
        "md_again_ndg": dict(ieg=True, ndg=True),
    }

    # ---- the arms -------------------------------------------------------
    seen = {}
    for L in logs:
        for a in L.arms:
            key = (a["sec"], a["door"], a["env"], a["arm"])
            seen.setdefault(key, []).append(a)

    def post_of(a):
        return hx(a.get("post", "-"))

    def model_write(door, tag, state, base, off, ln, imm):
        """-> (predicted counter delta per copy, predicted post bytes)"""
        fr = F[tag]
        cnt = 1 if reach(door, fr, state) else 0
        if not cnt:
            return 0, b""
        p = pktinfo(door, fr)
        if p is None:
            return 0, b""
        l3b = bytearray(frame_l3(fr))
        skb_len = len(l3b)
        if base == NH:
            if fr["sproto"] == 0x0800:
                good = nh_ok_ip4(bytes(l3b), off, ln, imm)
            elif DOORS[door]["pf"] == "netdev":
                good = True
            else:
                good = nh_ok_ip6(off, ln, imm)
            coord = off
            if coord + ln > skb_len:
                good = False
        elif base == TH:
            good, coord = th_guard(p, off, ln)
        else:
            good = False
            coord = 0
        if good:
            l3b[coord:coord + ln] = imm[:ln]
        return cnt, bytes(l3b)

    def model_write_allowed(door, tag, state, base, off, ln, imm):
        fr = F[tag]
        if not reach(door, fr, state):
            return False
        p = pktinfo(door, fr)
        if p is None:
            return False
        if base == NH:
            if fr["sproto"] == 0x0800:
                return nh_ok_ip4(frame_l3(fr), off, ln, imm) and \
                    off + ln <= len(frame_l3(fr))
            if DOORS[door]["pf"] == "netdev":
                return off + ln <= len(frame_l3(fr))
            return nh_ok_ip6(off, ln, imm) and \
                off + ln <= len(frame_l3(fr))
        if base == TH:
            good, _ = th_guard(p, off, ln)
            return good
        return False

    def model_delivered(post, port):
        """Would the IPv6 stack deliver these bytes to [fd00::99:9]:port?"""
        if len(post) < 40 or post[0] >> 4 != 6:
            return False
        if post[24:40] != V6DST:
            return False
        plen = be16(post, 4)
        if plen + 40 > len(post):
            return False
        w = ipv6_find_hdr(post, len(post))
        if w.err or w.proto != 17 or w.fragoff:
            return False
        u = w.thoff
        if u + 8 > len(post):
            return False
        ulen = be16(post, u + 4)
        if ulen < 8 or u + ulen > len(post):
            return False
        if be16(post, u + 2) != port:
            return False
        acc = 0
        pseudo = post[8:40] + bytes([0, 0, 0, ulen, 0, 0, 0, 17])
        data = post[u:u + ulen]
        for i in range(0, len(pseudo) - 1, 2):
            acc += (pseudo[i] << 8) | pseudo[i + 1]
        for i in range(0, len(data) - 1, 2):
            acc += (data[i] << 8) | data[i + 1]
        if len(data) & 1:
            acc += data[-1] << 8
        while acc >> 16:
            acc = (acc & 0xffff) + (acc >> 16)
        return (acc & 0xffff) == 0xffff

    n_writes = 0
    for (sec, door, env, arm), rows in seen.items():
        state = STATE[sec]
        for a in rows:
            where = "%s/%s/%s/%s" % (sec, door, env, arm)
            if env not in F:
                check(False, "unknown frame in the log: " + where)
                continue
            base = int(a["base"])
            off = int(a["off"])
            ln = int(a["len"])
            mode = int(a["mode"])
            imm = hx(a.get("imm", "-"))
            lives = int(a["lives"])
            mult = count_mult(door, F[env])
            fr = F[env]
            if fr["sproto"] == 0x86dd:
                post_bytes = post_of(a) if mode == 1 else b""
                if not post_bytes:
                    post_bytes = frame_l3(fr)   # no write, or a refused one
                i6in, kind, deliv, unk = stack_fate(door, state, fr,
                                                    post_bytes)
                eq(int(a["i6in"]), i6in,
                   "Ip6InReceives: the bridge copy returns on r0 " + where)
                eq(int(a["i6deliv"]), 1 if deliv else 0,
                   "Ip6InDelivers iff the packet the stack sees is still "
                   "deliverable " + where)
                eq(int(a["i6trun"]), 1 if kind == "trun" else 0,
                   "Ip6InTruncatedPkts " + where)
                eq(int(a["i6hdr"]), 1 if kind == "hdr" else 0,
                   "Ip6InHdrErrors " + where)
                eq(int(a["i6unk"]), 1 if unk else 0,
                   "Ip6InUnknownProtos " + where)

            if mode == 0:                       # control: counter only
                want = mult if reach(door, F[env], state) else 0
                eq(lives, want, "control counter " + where)
                # and the delivery oracle on the untouched frame
                if F[env]["sproto"] == 0x86dd:
                    ok5000 = reach("inp", F[env], state) and \
                        model_delivered(frame_l3(F[env]), 5000)
                    eq(1 if int(a["u6a"]) > 0 else 0, 1 if ok5000 else 0,
                       "socket 5000 vs the untouched frame " + where)
                continue

            if mode == 1:
                cnt, want_post = model_write(door, env, state, base, off, ln,
                                             imm)
                if cnt == 0:
                    eq(lives, 0, "unreachable arm writes nothing " + where)
                    eq(post_of(a), b"",
                       "unreachable arm logs no payload " + where)
                    continue
                n_writes += 1
                # a refused write is NFT_BREAK: the rest of the rule -- the
                # log and the counter -- never runs
                refused = (post_of(a) == b"")
                eq(refused, want_post == frame_l3(F[env]) and
                   not model_write_allowed(door, env, state, base, off, ln,
                                           imm),
                   "refusal shows up as an empty NFLOG payload " + where)
                if refused:
                    eq(lives, 0, "a refused write leaves the counter at 0 " +
                       where)
                    continue
                eq(int(a["cnts"]), cnt * mult,
                   "the rule runs once per copy " + where)
                eq(lives, cnt * mult,
                   "the chain counter counts the rule " + where)
                eq(post_of(a), want_post,
                   "NFLOG payload == model of the write " + where)
                check(int(a["rchg"]) >= 0, "rchg recorded " + where)
                # delivery: from the bytes the stack finally saw
                u6a = int(a["u6a"])
                u6b = int(a["u6b"])
                check((u6a > 0) == model_delivered(want_post, 5000),
                      "socket 5000 vs the bytes " + where,
                      "u6a=%d post=%s" % (u6a, want_post.hex()))
                check((u6b > 0) == model_delivered(want_post, 5001),
                      "socket 5001 vs the bytes " + where,
                      "u6b=%d" % u6b)
                continue

            if mode == 2:                       # read + compare
                p = pktinfo(door, F[env]) if reach(door, F[env], state) else None
                if p is None:
                    eq(lives, 0, "unreachable read " + where)
                    continue
                if not p.l4 or p.fragoff:
                    eq(lives, 0, "read refused without pktinfo " + where)
                    continue
                at = p.thoff + off
                src = frame_l3(F[env])
                want = 1 if (at + ln <= p.skb_len and
                             src[at:at + ln] == imm[:ln]) else 0
                eq(lives, want * mult, "read compares the walked field " + where)
                continue

            if mode in (3, 4):                  # meta l4proto / protocol
                if not reach(door, F[env], state):
                    eq(lives, 0, "unreachable meta " + where)
                    continue
                p = pktinfo(door, F[env])
                if p is None:
                    eq(lives, 0, "no pktinfo, no meta " + where)
                    continue
                if mode == 3:
                    want = 1 if (p.l4 and bytes([p.tprot]) == imm[:ln]) else 0
                else:
                    et = 0x0800 if F[env]["sproto"] == 0x0800 else 0x86dd
                    want = 1 if bytes([et >> 8, et & 0xff]) == imm[:ln] else 0
                eq(lives, want * mult, "meta verdict " + where)
                continue

            check(False, "unknown mode " + where)

    check(n_writes > 200, "the battery contains many write arms", str(n_writes))

    # ---- the cross-family section ---------------------------------------
    for L in logs:
        for x in L.xc:
            tag = x["env"]
            fr = F[tag]
            state = STATE["xc"]
            for door in ("ip4p", "ip6p", "inp", "ndg", "ieg"):
                want = count_mult(door, fr) if reach(door, fr, state) else 0
                eq(int(x[DKEY[door]]), want, "cross-family counter %s/%s" %
                   (os.path.basename(L.path), tag + "/" + door))
            # the delivery oracles: IPv4 delivered twice (weak host), IPv6 once
            if fr["sproto"] == 0x0800:
                eq(int(x["u4"]), 2, "IPv4 delivered twice (bridge copy returns)")
                eq(int(x["u6"]), 0, "no IPv6 socket traffic for an IPv4 frame")
            else:
                eq(int(x["u4"]), 0, "no IPv4 socket traffic for an IPv6 frame")
                want = 1 if (reach("inp", fr, state) and
                             model_delivered(frame_l3(fr), 5000)) else 0
                eq(int(x["u6"]), want,
                   "IPv6 socket oracle %s/%s" % (os.path.basename(L.path), tag))

    # ---- the diagnostic section -----------------------------------------
    for L in logs:
        for d in L.diag:
            tag = d["env"]
            fr = F[tag]
            state = STATE["diag"]
            for door in ("ip4p", "ip6p", "inp", "ndg", "ieg"):
                want = count_mult(door, fr) if reach(door, fr, state) else 0
                eq(int(d[DKEY[door]]), want, "diag counter %s/%s" %
                   (os.path.basename(L.path), tag + "/" + door))
            good, why = ip6_rcv_core_ok(frame_l3(fr)) \
                if fr["sproto"] == 0x86dd else (True, "v4")
            dead_early = fr["sproto"] == 0x86dd and ieg_drops(fr)
            if fr["sproto"] == 0x86dd:
                if dead_early:
                    eq(int(d["i6in"]), 0,
                       "dropped at the ingress door, the stack never sees it "
                       + tag)
                else:
                    eq(int(d["i6in"]), 2,
                       "Ip6InReceives counts the frame twice (bridge copy) "
                       + tag)

    # ---- determinism ----------------------------------------------------
    if len(logs) > 1:
        def norm(L):
            out = []
            for a in L.arms:
                out.append("|".join("%s=%s" % (k, a[k]) for k in sorted(a)))
            return out
        a1, a2 = norm(logs[0]), norm(logs[1])
        eq(len(a1), len(a2), "both boots ran the same number of arms")
        diff = [i for i in range(min(len(a1), len(a2))) if a1[i] != a2[i]]
        eq(len(diff), 0, "rep1 == rep2, arm for arm",
           str([a1[i] for i in diff[:2]]))

    # ---- no splat -------------------------------------------------------
    for L in logs:
        eq(len(L.splat), 0, "no KASAN/BUG/Oops/WARNING in " +
           os.path.basename(L.path), str(L.splat[:2]))
        check(any("=0" in m for m in L.modes) or L.modes,
              "the mode ran to completion in " + os.path.basename(L.path),
              str(L.modes))

    print("checks=%d ok=%d bad=%d" % (ok + bad, ok, bad))
    print("VERIFY567 OK" if bad == 0 else "VERIFY567 FAILED")
    for f in fails[:40]:
        print("FAIL " + f)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
