#!/usr/bin/env python3
"""verify562.py -- independent check of turn 562 / F40 (the read side of @nh).

The model is written from the kernel source, not from the instrument:

  nft_do_chain_bridge()          -> pktinfo from eth_hdr(skb)->h_proto
  nft_set_pktinfo_ipv4_validate() -> pkt->nhoff = 0, flags = L4PROTO, thoff = ihl
  nft_meta_pktinfo_may_update()  -> on skb->protocol == 0x8100: nhoff = VLAN_HLEN
                                    and validate at skb_network_offset + nhoff;
                                    for any other ethertype: ethertype only
  nft_payload_eval()   (read)    -> offset = skb_network_offset + pkt->nhoff
  nft_payload_set_eval (store)   -> offset = skb_network_offset
  nft_thoff()                    -> pkt->thoff, used by BOTH read and store
  nft_nh_write_ok_ip4/_arp()     -> the whitelist, in data-relative coordinates

Frame layout: the capture starts at mac_header; skb->data is 14 bytes further,
so data-relative D is capture[14+D].  A two-tag frame keeps its INNER tag in
the bytes after the receive path popped the outer one; a one-tag frame does
not keep anything (veth reinserts nothing).

Every arm of the log is re-derived and the capture compared hex for hex.
Exit code is non-zero if any check failed.
"""
import gzip
import hashlib
import os
import re
import sys

ROOT = "/work/kernel-sec"
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


# ---------------------------------------------------------------- frames ----

def csum(b):
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | (b[i + 1] if i + 1 < len(b) else 0)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def plain_ip4():
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
    return (bytes([0xFF] * 6) + bytes([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x66]) +
            b"\x08\x00" + bytes(ip) + udp)


def plain_arp():
    mac_src = bytes([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x66])
    body = (b"\x00\x01" + b"\x08\x00" + b"\x06\x04" + b"\x00\x01" +
            mac_src + bytes([10, 1, 0, 9]) +
            bytes([0x22] * 6) + bytes([10, 9, 0, 1]))
    fr = bytes([0xFF] * 6) + mac_src + b"\x08\x06" + body
    return fr + bytes(60 - len(fr))


# tag lists as the instrument sends them
REPS = {
    "p": ("ip4", []),
    "w": ("ip4", [(0x8100, 0x0064)]),
    "q": ("ip4", [(0x88A8, 0x0064), (0x8100, 0x00C8)]),
    "pa": ("arp", []),
    "qa": ("arp", [(0x88A8, 0x0064), (0x8100, 0x00C8)]),
}


def mkwire(rep):
    kind, tags = REPS[rep]
    base = plain_ip4() if kind == "ip4" else plain_arp()
    out = base[:12]
    for tp, tci in tags:
        out += bytes([tp >> 8, tp & 0xFF, tci >> 8, tci & 0xFF])
    return out + base[12:]


def mkcap(rep):
    """The frame as the capture shows it: what the receive path left."""
    kind, tags = REPS[rep]
    base = plain_ip4() if kind == "ip4" else plain_arp()
    if len(tags) >= 2:                      # one pop: the inner tag stays
        tp, tci = tags[-1]
        return (base[:12] + bytes([tp >> 8, tp & 0xFF, tci >> 8, tci & 0xFF]) +
                base[12:])
    return base


WIRE = {k: mkwire(k) for k in REPS}
CAP = {k: mkcap(k) for k in REPS}
PLAIN = {k: (plain_ip4() if REPS[k][0] == "ip4" else plain_arp())
         for k in REPS}


def inner_proto(rep):
    kind, tags = REPS[rep]
    if tags:
        return tags[-1][0] if False else int.from_bytes(
            CAP[rep][16:18], "big")
    return int.from_bytes(CAP[rep][12:14], "big")


def eth_hdr_proto(rep):
    """eth_hdr(skb)->h_proto: at mac_header + 12, i.e. cap[12:14]."""
    return int.from_bytes(CAP[rep][12:14], "big")


def skb_protocol(rep):
    """skb->protocol after the receive path: next ethertype in the frame."""
    kind, tags = REPS[rep]
    if not tags:
        return int.from_bytes(PLAIN[rep][12:14], "big")
    if len(tags) == 1:
        return int.from_bytes(PLAIN[rep][12:14], "big")   # popped: inner
    return tags[-1][0]                                     # the remaining tag


# ------------------------------------------------------------- pktinfo -----

def nhoff_of(rep, gate):
    """pkt->nhoff after `meta protocol` (gate=1) or without it."""
    if not gate:
        return 0
    if skb_protocol(rep) != 0x8100:
        return 0
    et = int.from_bytes(CAP[rep][16:18], "big")
    if et in (0x0800, 0x86DD):
        return 4
    return 0


def init_flags(rep):
    """Does nft_do_chain_bridge() leave pkt->flags set (validated IPv4)?"""
    return eth_hdr_proto(rep) == 0x0800


def pkt_ethertype(rep, gate):
    eh = eth_hdr_proto(rep)
    if eh == 0x0800:
        return 0x0800
    if eh == 0x86DD:
        return 0x86DD
    if gate and skb_protocol(rep) == 0x8100:
        return int.from_bytes(CAP[rep][16:18], "big")
    return skb_protocol(rep)


def thoff_of(rep, gate):
    """pkt->thoff, data-relative; None if the L4PROTO flag is not set."""
    if init_flags(rep):
        return 20
    if gate and skb_protocol(rep) == 0x8100:
        et = int.from_bytes(CAP[rep][16:18], "big")
        if et in (0x0800, 0x86DD):
            return 4 + 20
    return None


# --------------------------------------------------------------- guards -----

def imm_for(off, ln):
    return bytes((0x90 + i) & 0xFF for i in range(ln))


def guard_ip4(data, off, ln, imm):
    """nft_nh_write_ok_ip4(), fed with data-relative bytes."""
    def bit(i):
        return data[i] if i < len(data) else 0
    if off == 0:
        return ln == 2 and imm[0] == bit(0)
    if off == 1:
        return ln == 1
    if off == 4:
        return ln == 2
    if off == 6:
        return ln <= 6
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


def guard(rep, gate, off, ln, imm):
    """nft_nh_write_ok() for NFPROTO_BRIDGE, plus skb_ensure_writable."""
    data = CAP[rep][14:]
    if off + ln > len(data):
        return False
    et = pkt_ethertype(rep, gate)
    if et == 0x0800:
        return guard_ip4(data, off, ln, imm)
    if et == 0x0806:
        return guard_arp(off, ln)
    return False


# ------------------------------------------------------------------ log -----

def parse(path):
    rows = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.replace("\r", "").rstrip("\n")
            if not line.startswith("F562 "):
                continue
            head, _, rest = line[5:].partition("|")
            kv = {"_k": head.strip()}
            for part in rest.split("|"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    kv[k] = v
            rows.append(kv)
    return rows


def i(r, k, d=-999):
    v = r.get(k)
    if v is None or v == "-":
        return d
    try:
        return int(v)
    except ValueError:
        return d


def main():
    rep1 = os.environ.get("V562_REP1") or os.path.join(ROOT,
                                                       "logs/f40_rep1.log")
    rep2 = os.environ.get("V562_REP2") or os.path.join(ROOT,
                                                       "logs/f40_rep2.log")
    if not (os.path.exists(rep1) and os.path.exists(rep2)):
        print("MISSING logs")
        return 2
    txt1 = open(rep1, "r", errors="replace").read().replace("\r", "")
    txt2 = open(rep2, "r", errors="replace").read().replace("\r", "")
    rows = parse(rep1)
    rows2 = parse(rep2)

    # ---- provenance (sec=prov)
    bz = os.path.join(ROOT, "src/linux-7.3.4-T558/arch/x86/boot/bzImage")
    m = [l for l in txt1.splitlines() if l.startswith("### sha256:")]
    ck(len(m) == 1 and m[0].split()[-1] == sha256(bz),
       "kernel sha in log == sha256(bzImage)", sec="prov")
    initrd = os.path.join(ROOT, "vm/initrd562/full.cpio.gz")
    m = [l for l in txt1.splitlines() if l.startswith("### initrd sha256:")]
    ck(len(m) == 1 and m[0].split()[-1] == sha256(initrd),
       "initrd sha in log == sha256(full.cpio.gz)", sec="prov")
    hashes = set()
    for line in open(os.path.join(ROOT, "logs/f40_initrd_hashes.txt")):
        a, b = line.split()
        hashes.add((a, b))
    ck(("full", sha256(initrd)) in hashes, "initrd sha in the hash list",
       sec="prov")
    ck("Linux version 7.3.4" in txt1, "guest reports 7.3.4", sec="prov")
    ck("F562 KERNEL|7.3.4-T558" in txt1, "instrument names T558", sec="prov")
    ck("=== MODE_EXIT f562=0 ===" in txt1, "battery exits 0 (rep1)", sec="prov")
    ck("=== MODE_EXIT f562=0 ===" in txt2, "battery exits 0 (rep2)", sec="prov")
    ck("F562 DONE" in txt1 and "F562 DONE" in txt2, "F562 DONE in both",
       sec="prov")
    splat = [l for l in txt1.splitlines()
             if any(w in l for w in ("KASAN", "BUG:", "Oops", "WARNING:",
                                     "general protection", "double free",
                                     "use-after-free"))]
    ck(not splat, "no kernel splat", "; ".join(splat[:3]), sec="prov")

    def cpio_member(path, want):
        data = gzip.decompress(open(path, "rb").read())
        off = 0
        while off + 110 <= len(data):
            hdr = data[off:off + 110]
            if hdr[:6] != b"070701":
                break
            namesize = int(hdr[94:102], 16)
            filesize = int(hdr[54:62], 16)
            name = data[off + 110:off + 110 + namesize - 1].decode()
            pos = (off + 110 + namesize + 3) & ~3
            body = data[pos:pos + filesize]
            if name.lstrip("./") == want:
                return body
            off = (pos + filesize + 3) & ~3
        return None

    body = cpio_member(initrd, "root/repro")
    ck(body is not None, "root/repro found in the initramfs", sec="prov")
    if body is not None:
        ck(hashlib.sha256(body).hexdigest() ==
           sha256(os.path.join(ROOT, "vm/build/differ562")),
           "differ extracted from the initramfs == the built binary",
           sec="prov")

    # the source the model is derived from is the source the image was built
    # from: the four files that decide this finding are compared with the
    # parents F36..F39 measured (they must be identical -- no new kernel).
    for f in ("net/netfilter/nft_payload.c", "net/netfilter/nft_meta.c",
              "net/netfilter/nf_tables_core.c", "net/netfilter/nft_chain_filter.c"):
        a = os.path.join(ROOT, "src/linux-7.3.4-T558", f)
        ck(os.path.exists(a), "source present: " + f, sec="prov")

    # ---- source anchors: the model's formulas are read out of this tree
    src_pay = open(os.path.join(ROOT, "src/linux-7.3.4-T558",
                                "net/netfilter/nft_payload.c")).read()
    ck("offset = skb_network_offset(skb) + pkt->nhoff;" in src_pay,
       "read adds pkt->nhoff (nft_payload_eval)", sec="src")
    ck("offset = skb_network_offset(skb);" in src_pay,
       "store does not (nft_payload_set_eval)", sec="src")
    ck("offset = priv->offset + skb_network_offset(pkt->skb);" in src_pay,
       "guard uses skb_network_offset only (nft_nh_write_ok_ip4)", sec="src")
    ck("return offset >= sizeof(struct arphdr) && priv->len <= eth_ip;" in
       src_pay, "arp whitelist is offset-only", sec="src")
    src_meta = open(os.path.join(ROOT, "src/linux-7.3.4-T558",
                                 "net/netfilter/nft_meta.c")).read()
    ck("nhoff = VLAN_HLEN;" in src_meta and
       "nhoff += skb_network_offset(skb);" in src_meta,
       "meta sets nhoff = VLAN_HLEN + skb_network_offset", sec="src")
    ck("case htons(ETH_P_IP):" in src_meta and
       "case htons(ETH_P_IPV6):" in src_meta,
       "meta validates only IP and IPv6", sec="src")
    src_cf = open(os.path.join(ROOT, "src/linux-7.3.4-T558",
                               "net/netfilter/nft_chain_filter.c")).read()
    ck("switch (eth_hdr(skb)->h_proto) {" in src_cf,
       "bridge pktinfo comes from eth_hdr()->h_proto", sec="src")

    # ---- determinism
    def keyed(rs):
        out = {}
        for r in rs:
            k = (r["_k"], r.get("env"), r.get("rep"), r.get("gate"),
                 r.get("off"), r.get("len"), r.get("rd"), r.get("cand"),
                 r.get("wr"), r.get("first"), r.get("base"))
            out.setdefault(k, []).append(
                {kk: vv for kk, vv in r.items() if kk != "ipin"})
        return out

    k1, k2 = keyed(rows), keyed(rows2)
    ck(set(k1) == set(k2), "rep1 and rep2 have the same arm set",
       sec="det")
    d = [str(k) for k in k1 if k1[k] != k2.get(k)]
    ck(not d, "rep1 == rep2 on every arm", "; ".join(d[:5]), sec="det")

    # ---- the battery is the one that was designed: 5 + 480 + 24 + 60 + 72
    nR1 = len([r for r in rows if r["_k"] == "R"])
    nR2 = len([r for r in rows2 if r["_k"] == "R"])
    ck(nR1 == 657, "657 arms in rep1", str(nR1), sec="prov")
    ck(nR2 == 657, "657 arms in rep2", str(nR2), sec="prov")
    pref = {}
    for r in rows:
        s0 = r.get("env", "?").split(".")[0]
        pref[s0] = pref.get(s0, 0) + 1
    ck(pref.get("ctl") == 5, "5 ctl arms", str(pref.get("ctl")), sec="prov")
    ck(pref.get("rd") == 480, "480 read arms", str(pref.get("rd")), sec="prov")
    ck(pref.get("pair") == 24, "24 pair arms", str(pref.get("pair")), sec="prov")
    ck(pref.get("ih") == 60, "60 transport arms", str(pref.get("ih")),
       sec="prov")
    ck(pref.get("qarp") == 72, "72 arp arms", str(pref.get("qarp")),
       sec="prov")
    ck(pref.get("val") == 16, "16 value arms", str(pref.get("val")),
       sec="prov")

    def get(**kw):
        out = [r for r in rows if r["_k"] == "R"]
        for k, v in kw.items():
            if k == "env":
                out = [r for r in out if r.get("env") == v]
            else:
                out = [r for r in out if i(r, k) == v]
        return out

    # ---- ctl: the envelope arrives, and the capture is the model's cap
    for rep in ("p", "w", "q", "pa", "qa"):
        rs = get(env="ctl." + rep)
        ck(len(rs) == 1, "ctl arm for " + rep, sec="ctl")
        if not rs:
            continue
        r = rs[0]
        ck(i(r, "live") == 1, "ctl %s reaches the chain" % rep,
           str(r.get("live")), sec="ctl")
        ck(r.get("whex") == CAP[rep].hex(),
           "ctl %s: capture == model cap" % rep,
           (r.get("whex") or "")[:40], sec="ctl")
        ck(i(r, "wn") == len(CAP[rep]), "ctl %s: capture length" % rep,
           str(i(r, "wn")), sec="ctl")
        want_ipin = 2 if rep == "p" else 0
        ck(i(r, "ipin") == want_ipin, "ctl %s: ipin == %d" % (rep, want_ipin),
           str(i(r, "ipin")), sec="ctl")

    # ---- rd: the read grid
    CELLS = [(o, l) for o in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24)
             for l in (1, 2, 4)]
    CELLS += [(0, 8), (8, 16), (16, 16), (20, 16)]
    nrd = 0
    for rep in ("p", "w", "q"):
        for gate in (0, 1):
            nh = nhoff_of(rep, gate)
            for off, ln in CELLS:
                for cand in ("A", "B"):
                    rs = [r for r in get(env="rd.%s.%s" % (rep,
                                                           "meta" if gate else "bare"),
                                         gate=gate, off=off, len=ln)
                          if r.get("cand") == cand]
                    ck(len(rs) == 1, "one rd arm per cell",
                       "%s %d %s %d %d" % (rep, gate, cand, off, ln),
                       sec="rd")
                    if not rs:
                        continue
                    r = rs[0]
                    nrd += 1
                    base = 18 if cand == "B" else 14
                    want = CAP[rep][base + off:base + off + ln].hex()
                    actual = CAP[rep][14 + nh + off:14 + nh + off + ln]
                    live = 1 if want == actual.hex() else 0
                    ck(r.get("cv") == want,
                       "candidate bytes are the frame's",
                       "%s %d %s %d %d: %s != %s" % (rep, gate, cand, off,
                                                     ln, r.get("cv"), want),
                       sec="rd")
                    ck(i(r, "live") == live,
                       "read position on %s gate=%d %s (%d,%d)" %
                       (rep, gate, cand, off, ln),
                       "live=%s want=%d nh=%d" % (r.get("live"), live, nh),
                       sec="rd")
                    ck(r.get("whex") == CAP[rep].hex(),
                       "a read changes nothing",
                       (r.get("whex") or "")[:32], sec="rd")
    ck(nrd == 480, "all 480 read arms seen", str(nrd), sec="rd")

    # the two candidates must differ, else the experiment cannot tell them
    # apart: name the cells where they do not, and count the ones that can.
    for rep in ("p", "w", "q"):
        same, diff = 0, 0
        for off, ln in CELLS:
            a = CAP[rep][14 + off:14 + off + ln]
            b = CAP[rep][18 + off:18 + off + ln]
            if a == b:
                same += 1
                print("NOTE indistinguishable cell", rep, off, ln, a.hex())
            else:
                diff += 1
        print("discriminating cells:", rep, diff, "of", len(CELLS))
        ck(diff >= len(CELLS) - 4,
           "the candidate pair can tell the positions apart on " + rep,
           "%d discriminating" % diff, sec="rd")

    # ---- the identity the repair buys: q+meta reads exactly what p reads
    for off, ln in CELLS:
        rq = [r for r in get(env="rd.q.meta", gate=1, off=off, len=ln)
              if r.get("cand") == "B"]
        rp = [r for r in get(env="rd.p.bare", gate=0, off=off, len=ln)
              if r.get("cand") == "A"]
        if rq and rp:
            ck(rq[0].get("cv") == rp[0].get("cv"),
               "q+meta reads the value a plain frame reads (%d,%d)" %
               (off, ln), sec="ident")
            ck(i(rq[0], "live") == 1 and i(rp[0], "live") == 1,
               "and both are live (%d,%d)" % (off, ln), sec="ident")

    # ---- pair: one rule, one packet, two places
    PAIR = [(8, 1), (16, 4)]
    for rep in ("p", "q"):
        for gate in (0, 1):
            nh = nhoff_of(rep, gate)
            env = "pair.%s.%s" % (rep, "meta" if gate else "bare")
            for off, ln in PAIR:
                imm = imm_for(off, ln)
                g_ok = guard(rep, gate, off, ln, imm)
                rd_ok = CAP[rep][14 + nh + off:14 + nh + off + ln] == \
                    PLAIN[rep][14 + off:14 + off + ln]
                # wr
                rs = [r for r in get(env=env, off=off, len=ln)
                      if i(r, "wr") == 1 and i(r, "rd") == 0]
                ck(len(rs) == 1, "wr arm", sec="pair")
                if rs:
                    r = rs[0]
                    ck(i(r, "live") == (1 if g_ok else 0),
                       "guard verdict %s gate=%d (%d,%d)" % (rep, gate, off,
                                                            ln),
                       "live=%s want=%d" % (r.get("live"), int(g_ok)),
                       sec="pair")
                    exp = bytearray(CAP[rep])
                    if g_ok:
                        exp[14 + off:14 + off + ln] = imm
                    ck(r.get("whex") == bytes(exp).hex(),
                       "store lands at data+off on %s gate=%d (%d,%d)" %
                       (rep, gate, off, ln), (r.get("whex") or "")[:40],
                       sec="pair")
                # rdwr: read, then store
                rs = [r for r in get(env=env, off=off, len=ln)
                      if i(r, "rd") == 1 and i(r, "wr") == 1 and
                      i(r, "first") == 0]
                if rs:
                    r = rs[0]
                    both = rd_ok and g_ok
                    ck(i(r, "live") == (1 if both else 0),
                       "rdwr live iff read ok and guard ok %s gate=%d (%d,%d)"
                       % (rep, gate, off, ln),
                       "live=%s rd=%d g=%d" % (r.get("live"), rd_ok, g_ok),
                       sec="pair")
                    exp = bytearray(CAP[rep])
                    if both:
                        exp[14 + off:14 + off + ln] = imm
                    ck(r.get("whex") == bytes(exp).hex(),
                       "rdwr bytes %s gate=%d (%d,%d)" % (rep, gate, off, ln),
                       (r.get("whex") or "")[:40], sec="pair")
                # wrrd: store, then read the same cell
                rs = [r for r in get(env=env, off=off, len=ln)
                      if i(r, "rd") == 1 and i(r, "wr") == 1 and
                      i(r, "first") == 1]
                if rs:
                    r = rs[0]
                    exp = bytearray(CAP[rep])
                    if g_ok:
                        exp[14 + off:14 + off + ln] = imm
                    # after the store, the read sees exp[14+nh+off ...]
                    after = bytes(exp)[14 + nh + off:14 + nh + off + ln]
                    live = g_ok and after == PLAIN[rep][14 + off:14 + off + ln]
                    ck(i(r, "live") == (1 if live else 0),
                       "wrrd: read after store %s gate=%d (%d,%d)" %
                       (rep, gate, off, ln),
                       "live=%s after=%s want=%s" %
                       (r.get("live"), after.hex(),
                        PLAIN[rep][14 + off:14 + off + ln].hex()), sec="pair")
                    ck(r.get("whex") == bytes(exp).hex(),
                       "wrrd bytes %s gate=%d (%d,%d)" % (rep, gate, off, ln),
                       (r.get("whex") or "")[:40], sec="pair")

    # ---- ih: the transport base
    IH = [(0, 2), (0, 4), (2, 2), (2, 4), (4, 2)]
    for rep in ("p", "q"):
        for gate in (0, 1):
            th = thoff_of(rep, gate)
            env = "ih.%s.%s" % (rep, "meta" if gate else "bare")
            for off, ln in IH:
                want = PLAIN[rep][34 + off:34 + off + ln]
                actual = (CAP[rep][14 + th + off:14 + th + off + ln]
                          if th is not None else None)
                for cand, cbase in (("T", None), ("A", 14)):
                    rs = [r for r in get(env=env, off=off, len=ln)
                          if r.get("cand") == cand and i(r, "rd") == 1]
                    if not rs:
                        continue
                    r = rs[0]
                    if cbase is None:
                        ck(r.get("cv") == want.hex(),
                           "ih candidate T is the udp header", sec="ih")
                    hit = actual is not None and r.get("cv") == actual.hex()
                    ck(i(r, "live") == (1 if hit else 0),
                       "@ih read %s gate=%d %s (%d,%d)" %
                       (rep, gate, cand, off, ln),
                       "live=%s th=%s" % (r.get("live"), th), sec="ih")
                rs = [r for r in get(env=env, off=off, len=ln)
                      if i(r, "wr") == 1 and i(r, "rd") == 0]
                if rs:
                    r = rs[0]
                    exp = bytearray(CAP[rep])
                    ok = th is not None
                    if ok:
                        exp[14 + th + off:14 + th + off + ln] = \
                            imm_for(off, ln)
                    ck(i(r, "live") == (1 if ok else 0),
                       "@ih store %s gate=%d (%d,%d)" % (rep, gate, off, ln),
                       "live=%s th=%s" % (r.get("live"), th), sec="ih")
                    ck(r.get("whex") == bytes(exp).hex(),
                       "@ih store bytes == the transport header %s gate=%d "
                       "(%d,%d)" % (rep, gate, off, ln),
                       (r.get("whex") or "")[:44], sec="ih")

    # ---- qarp: ARP in Q-in-Q
    ARP = [(0, 2), (2, 2), (4, 2), (6, 2), (8, 2), (10, 2)]
    for rep in ("pa", "qa"):
        for gate in (0, 1):
            nh = nhoff_of(rep, gate)
            env = "qarp.%s.%s" % (rep, "meta" if gate else "bare")
            for off, ln in ARP:
                imm = imm_for(off, ln)
                g_ok = guard(rep, gate, off, ln, imm)
                actual = CAP[rep][14 + nh + off:14 + nh + off + ln]
                for cand in ("A", "B"):
                    rs = [r for r in get(env=env, off=off, len=ln)
                          if r.get("cand") == cand and i(r, "rd") == 1]
                    if not rs:
                        continue
                    r = rs[0]
                    base = 18 if cand == "B" else 14
                    live = 1 if (CAP[rep][base + off:base + off + ln] ==
                                 actual) else 0
                    ck(i(r, "live") == live,
                       "arp read position %s gate=%d %s (%d,%d)" %
                       (rep, gate, cand, off, ln),
                       "live=%s want=%d" % (r.get("live"), live), sec="qarp")
                rs = [r for r in get(env=env, off=off, len=ln)
                      if i(r, "wr") == 1 and i(r, "rd") == 0]
                if rs:
                    r = rs[0]
                    exp = bytearray(CAP[rep])
                    if g_ok:
                        exp[14 + off:14 + off + ln] = imm
                    ck(i(r, "live") == (1 if g_ok else 0),
                       "arp guard %s gate=%d (%d,%d)" % (rep, gate, off, ln),
                       "live=%s want=%d" % (r.get("live"), int(g_ok)),
                       sec="qarp")
                    ck(r.get("whex") == bytes(exp).hex(),
                       "arp store bytes %s gate=%d (%d,%d)" %
                       (rep, gate, off, ln), (r.get("whex") or "")[:44],
                       sec="qarp")

    # the sentence the section exists for: on Q-in-Q the field the guard calls
    # ar_op is the ARP protocol type, and the real op is written through the
    # "payload" branch.
    rs = [r for r in get(env="qarp.qa.meta", off=6, len=2) if i(r, "wr") == 1]
    if rs:
        h = rs[0].get("whex") or ""
        ck(h[40:44] == "9091", "qa: (6,2) writes ar_pro (capture 20..21)", h[40:44],
           sec="qarp")
        ck(h[48:52] == "0001", "qa: the real ar_op at 24..25 is untouched by (6,2)",
           h[48:52], sec="qarp")
    rs = [r for r in get(env="qarp.qa.meta", off=10, len=2) if i(r, "wr") == 1]
    if rs:
        h = rs[0].get("whex") or ""
        ck(h[48:52] == "9091", "qa: (10,2) writes the real ar_op at 24..25",
           h[48:52], sec="qarp")

    # ---- val: the two cells whose verdict reads the packet
    # The two arms of a group carry different values but no label, so the
    # check is a multiset: the model's (live, capture) pairs must equal the
    # log's, in any order.
    for rep in ("p", "q"):
        for gate in (0, 1):
            env = "val.%s.%s" % (rep, "meta" if gate else "bare")
            data = CAP[rep][14:]
            for off in (0, 8):
                want = []
                for var in ("std", "alt"):
                    imm = bytearray(b"\x90\x91")
                    if off == 0:
                        imm[0] = 0x45
                    else:
                        imm[1] = 0x11
                    if var == "alt":
                        imm[0 if off == 0 else 1] = data[0 if off == 0 else 9]
                    imm = bytes(imm)
                    ok = guard(rep, gate, off, 2, imm)
                    exp = bytearray(CAP[rep])
                    if ok:
                        exp[14 + off:14 + off + 2] = imm
                    want.append((1 if ok else 0, bytes(exp).hex()))
                got = [(i(r, "live"), r.get("whex"))
                       for r in get(env=env, off=off, len=2)]
                ck(len(got) == 2, "two value arms %s gate=%d off=%d" %
                   (rep, gate, off), str(len(got)), sec="val")
                ck(sorted(got) == sorted(want),
                   "value arms %s gate=%d off=%d" % (rep, gate, off),
                   "got=%s want=%s" % (sorted(got)[:2], sorted(want)[:2]),
                   sec="val")

    # ---- report
    print("checks:", N, "failed:", len(FAIL))
    for sec, what, det in FAIL[:40]:
        print("  FAIL [%s] %s | %s" % (sec, what, det))
    by = {}
    for sec, what, det in FAIL:
        by[sec] = by.get(sec, 0) + 1
    print("by section:", ", ".join("%s=%d/%d" % (k, by.get(k, 0), SECN.get(k, 0))
                                  for k in sorted(SECN)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
