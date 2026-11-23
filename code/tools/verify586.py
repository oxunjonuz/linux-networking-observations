#!/usr/bin/env python3
"""verify586.py -- independent check of turn 586 (F64), both boots.

Nothing here trusts the instrument's own arithmetic: the payloads, the UDP
lengths, the two checksum forms (a PARTIAL seed and a full checksum), the
aggregate's composition, the segment lengths and the packet counts are all
recomputed from the arm table read out of vm/differ586_add.c, and compared
against every byte the instrument printed.  Provenance: the kernel image, the
initramfs, and the differ binary EXTRACTED FROM the initramfs.
"""
import hashlib
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
LOGS = [f"{ROOT}/logs/f64_rep1_final.log", f"{ROOT}/logs/f64_rep2_final.log"]
if len(sys.argv) > 1:		# the selftest hands in mutated copies
    LOGS = [sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else sys.argv[1]]
KERNEL = f"{ROOT}/src/linux-7.3.4-T563/arch/x86/boot/bzImage"
SRC = f"{ROOT}/src/linux-7.3.4-T563"
DIFFER = f"{ROOT}/vm/build/differ586"
ADD = f"{ROOT}/vm/differ586_add.c"
INITRD = f"{ROOT}/vm/initrd586/full.cpio.gz"

SA = bytes([0xfd, 0x02] + [0] * 13 + [0x11])       # fd02::11  the sender
RA = bytes([0xfd, 0x02] + [0] * 13 + [0x91])       # fd02::91  the router, ingress
DA = bytes([0xfd, 0x03] + [0] * 13 + [0x92])       # fd03::92  door a
DB = bytes([0xfd, 0x04] + [0] * 13 + [0x92])       # fd04::92  door b
SPORT = 43580
DPORT = 5000

ok = 0
bad = []


def chk(cond, what):
    global ok
    if cond:
        ok += 1
    else:
        bad.append(what)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------- checksum arithmetic ------------------------------------------
def fold32(s):
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s & 0xFFFF


def csum16(data):
    if len(data) & 1:
        data = data + b"\0"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    return fold32(s)


def csum_ipv6_magic(dst, ulen, proto=17):
    """the 40-byte IPv6 pseudo header with a zero payload contribution.
    Measured against four fields this turn (fcc2 for 520, 018b for 1744,
    7ac3 for 32776, ff72 for 1208 -- all to fd03::92) and against a full
    checksum (02b0 for a 512-byte datagram to fd04::92): the field a socket
    writes is fold(pseudo), the field a device writes is ~fold(pseudo+packet).
    """
    return SA + dst + ulen.to_bytes(4, "big") + b"\0\0\0" + bytes([proto])


def seed6(dst, ulen):
    """~csum_ipv6_magic(saddr, daddr, ulen, 17, 0) as the field reads back"""
    return fold32(csum16(csum_ipv6_magic(dst, ulen)))


def full6(dst, ulen, payload):
    """the checksum a device computes for that datagram"""
    tod = payload + b"\0" * (ulen - 8 - len(payload))
    hdr = SPORT.to_bytes(2, "big") + DPORT.to_bytes(2, "big") + \
        ulen.to_bytes(2, "big") + b"\0\0"
    v = (~fold32(csum16(csum_ipv6_magic(dst, ulen)) + csum16(hdr) + csum16(tod))) & 0xFFFF
    return 0xFFFF if v == 0 else v


# ---------- provenance ----------------------------------------------------
chk(os.path.exists(KERNEL), "kernel image present")
ksha = sha(KERNEL)
ird = sha(INITRD)
dsha = sha(DIFFER)

# the differ inside the initramfs must be the binary that was built
tmp = "/tmp/f64_initrd"
subprocess.run(["rm", "-rf", tmp], check=True)
os.makedirs(tmp, exist_ok=True)
subprocess.run(["bash", "-c", "cd %s && gzip -dc %s | cpio -idm --quiet" % (tmp, INITRD)],
               check=True)
ex = sha(tmp + "/root/repro")
chk(ex == dsha, "differ extracted from the initramfs == vm/build/differ586 (%s)" % ex)

# ---------- source anchors ----------------------------------------------
def anchor(rel, needle, what, count=1):
    txt = open(f"{SRC}/{rel}", errors="replace").read()
    chk(txt.count(needle) >= count, "anchor %s: %r" % (what, needle[:60]))


anchor("net/ipv4/udp_offload.c", "#define UDP_GRO_CNT_MAX 64", "the cap")
anchor("net/ipv4/udp_offload.c", "NAPI_GRO_CB(p)->count >= UDP_GRO_CNT_MAX", "the cap test")
anchor("net/ipv4/udp_offload.c", "if (gso_skb->len <= sizeof(*uh) + mss)", "mss > payload")
anchor("net/ipv4/udp_offload.c", "return __udp_gso_segment_list(gso_skb, features, is_ipv6);",
       "the fraglist fast path")
anchor("net/ipv4/udp_offload.c", "skb_pagelen(gso_skb) - sizeof(*uh) == skb_shinfo(gso_skb)->gso_size",
       "the geometry test")
anchor("net/ipv4/udp_offload.c", "udp_set_len_short(udp_hdr(skb), sizeof(struct udphdr) + mss);",
       "the head length rewritten")
anchor("net/ipv4/udp_offload.c",
       "if (!skb_is_gso(seg))\n\t\tnewlen = skb_tail_pointer(seg) - skb_transport_header(seg) + seg->data_len;",
       "the trailing segment's own length")
anchor("net/ipv4/udp_offload.c", "check = csum16_add(csum16_sub(uh->check, uh->len), htons(newlen));",
       "the per-segment delta")
anchor("net/ipv4/udp_offload.c", "if (ulen > udp_get_len_short(uh2) || flush)", "the short tail ends the flow")

anchor("include/linux/udp.h", "uh->len = len < GRO_LEGACY_MAX_SIZE ? htons(len) : 0;",
       "udp_set_len zeroes a big aggregate's length")
anchor("net/core/gro.c", "if (NAPI_GRO_CB(skb)->count == 1) {", "gro_complete: a lone packet")
anchor("net/core/gro.c", "skb_shinfo(skb)->gso_size = 0;", "gro_complete clears gso_size")
anchor("net/core/gro.c", "if (flush_old && NAPI_GRO_CB(skb)->age == jiffies)", "the jiffy rule")
anchor("net/core/skbuff.c", "skb_copy_from_linear_data_offset(skb, -tnl_hlen,", "segment_list copies headers")
anchor("include/linux/udp.h", "if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4 &&",
       "udp_unexpected_gso")
anchor("net/ipv6/udp.c", "segs = udp_rcv_segment(sk, skb, false);", "the receive split")

# ---------- the arm table, read out of the instrument --------------------
src = open(ADD, errors="replace").read()
tbl = src[src.index("static const struct f586_arm AF586[]"):src.index("#define NAF586")]
arms = []
for m in re.finditer(r'\{ \{ "(\w+)", \'(\w)\', \'(\w)\', \'(\w)\', \'(\w)\', \'(\w)\', (\d+), (\d+), (\d+), (\w+|\"\w*\") \}, (\d+), (-?\d+), (\w+), (\d+), (\d+), (\d+) \}', tbl):
    arms.append(dict(name=m.group(1), src=m.group(2), dst=m.group(3), xg=m.group(4),
                     dg=m.group(5), skt=m.group(6), store=int(m.group(7)),
                     off=int(m.group(8)), ln=int(m.group(9)),
                     hex=m.group(10).strip('"'), n=int(m.group(11)),
                     sh=int(m.group(12)), sl=m.group(13), mss=int(m.group(14)),
                     tap=int(m.group(15)), xgro=int(m.group(16))))
chk(len(arms) == 26, "26 arms parsed out of the instrument (got %d)" % len(arms))
chk([a["name"] for a in arms][:3] == ["g_eq_a", "g_eq_b", "g_t3_a"], "arm order")
chk(all(a["sl"] in ("F586_SL", "0") for a in arms), "short length token")

MSS = 512
SL = 200
for a in arms:
    a["sl"] = SL if a["sl"] == "F586_SL" else int(a["sl"])

# ---------- the model ----------------------------------------------------
def payloads(a):
    """the payload bytes of every datagram in the arm, in order"""
    out = []
    for i in range(a["n"]):
        ln = a["sl"] if a["sh"] == i else MSS
        if a["mss"]:
            buf = bytes([0x77] + [0x40 + (k & 0x3f) for k in range(1, 1200)])
            out.append(buf[:1200])
        else:
            out.append(bytes([i] + [0x80 + (k & 0x7f) for k in range(1, ln)]))
    return out


def aggregate(a):
    """(packets, per-packet (payload total, UDP length)) for the arm, from the
    clauses the anchors pin: a lone datagram is a plain packet (gro_complete
    sets gso_size = 0 when count == 1), a short datagram is merged and then
    ends the flow, and the cap is 64."""
    pl = payloads(a)
    if a["mss"] or a["n"] == 1:
        return [(len(pl[0]), 8 + len(pl[0]))]
    pk, cur = [], []
    for p in pl:
        cur.append(len(p))
        short = a["sh"] >= 0 and len(p) == a["sl"]
        if short or len(cur) == 64:
            pk.append((sum(cur), 8 + sum(cur)))
            cur = []
    if cur:
        pk.append((sum(cur), 8 + sum(cur)))
    return pk


def log_of(p):
    """what NFLOG must carry: the IPv6 payload is the first four bytes of the
    packet's own field, the whole attribute is IPv6 header + UDP length"""
    return 40 + p[1]


def first_check(a, pk):
    """the checksum field the rule reads: a fraglist aggregate carries the
    FIRST datagram's own field, a linear one a seed over the whole length, and
    a hand-built frame carries the checksum its builder computed."""
    daddr = DA if a["dst"] == "a" else DB
    pl = payloads(a)
    if a["src"] == "P":
        return full6(daddr, 8 + len(pl[0]), pl[0])
    if a["xg"] == "u" and a["n"] > 1:
        return seed6(daddr, pk[0][1])
    return seed6(daddr, 8 + len(pl[0]))


EXPECT = {}
for a in arms:
    pk = aggregate(a)
    e = dict(pk=pk, ch=len(pk), nl=1, lgn=len(pk))
    e["plen"] = log_of(pk[0]) if len(pk) >= 1 else -1
    e["lg2"] = log_of(pk[1]) if len(pk) >= 2 else -1
    e["lg6"] = pk[0][1]
    e["check"] = first_check(a, pk)
    EXPECT[a["name"]] = e

# per-arm outcome the model does not derive: cut by the arms that are
# measured but NOT explained (the CHECKSUM_NONE provenance, see SUMMARY §7)
OBSERVED = {
    # the store in the length field: erased on an aggregate, effective on a
    # single datagram (nothing rewrites it there)
    "g_one_len_b": dict(n=1, L0=24, udp=1, err=0),
    "g_one_len_a": dict(n=1, L0=24, udp=1, err=0),
    # the linear aggregate with a poisoned length: every segment's checksum is
    # short by 1744-0x20 and nothing is delivered
    "g_t3u_len_b": dict(n=0, L0=0, udp=0, err=4),
    # the short datagram in the middle: the three before it are one packet, the
    # one after it is NOT joined -- it leaves the instrument's window
    "g_mid_a": dict(n=3, L0=512, L1=512, L2=200, udp=3, err=0,
                     ch=1, nl=1, lgn=1, plen=1272, lg2=-1),
    # a frame smaller than its own mss is not a wire property: GRO clears
    # gso_size for a single-segment GSO packet (gro.c: gro_complete)
    "g_mssbig_a": dict(n=1, L0=1200, udp=1, err=0),
    "g_mssbig_b": dict(n=1, L0=1200, udp=1, err=0),
    "g_mssbig_ng_a": dict(n=1, L0=1200, udp=1, err=0),
    "g_mssbig_ng_b": dict(n=1, L0=1200, udp=1, err=0),
    # CHECKSUM_NONE provenance: recorded, not explained (SUMMARY §7)
    "g_t3n_a": dict(n=1, L0=512, udp=1, err=0, ch=1, nl=1, lgn=1,
                     plen=560, lg2=-1, lg6=0x208),
    "g_t3n_w_a": dict(n=1, L0=512, udp=1, err=0, ch=1, nl=0, lgn=0),
    "g_t3n_w_a2": dict(n=1, L0=512, udp=1, err=0, ch=1, nl=0, lgn=0),
    "g_t3n_w0_a": dict(n=1, L0=512, udp=1, err=0, ch=1, nl=1, lgn=1,
                        plen=560, lg2=-1, lg6=0x208),
    "g_t3n_w1_a": dict(n=1, L0=512, udp=1, err=0, ch=1, nl=0, lgn=0),
    # GRO at the receiver: the router forwards four packets (ch=4), D's GRO
    # makes two of them ([512,512,512] and [200]) and delivers four datagrams
    "g_t3nd_a": dict(n=4, L0=512, L1=512, L2=512, L3=200, udp=4, err=0,
                     ch=4, nl=1, lgn=4, plen=560, lg2=560, lg6=0x208),
}

# ---------- parse the boots ---------------------------------------------
def parse(path):
    if not os.path.exists(path):
        print("MISSING LOG %s" % path)
        sys.exit(1)
    A, R, T = {}, {}, {}
    for ln in open(path, errors="replace"):
        if ln.startswith("F586 ARM|"):
            d = dict(x.split("=", 1) for x in ln.strip().split("|")[1:] if "=" in x)
            A[d["name"]] = d
        elif ln.startswith("F586 RCV|"):
            d = dict(x.split("=", 1) for x in ln.strip().split("|")[1:] if "=" in x)
            R[int(d["i"])] = d
        elif ln.startswith("F586 TAP|"):
            f = ln.strip().split("|")
            d = dict(x.split("=", 1) for x in f[1:] if "=" in x)
            T.setdefault((int(d["i"]), d["dev"]), []).append(d)
    return A, R, T

boots = [parse(p) for p in LOGS]

for bi, (A, R, T) in enumerate(boots):
    tag = "rep%d" % (bi + 1)
    chk(len(A) == 26, "%s: 26 ARM lines (got %d)" % (tag, len(A)))
    for i, a in enumerate(arms):
        nm = a["name"]
        d = A.get(nm)
        chk(d is not None, "%s/%s: ARM line present" % (tag, nm))
        if not d:
            continue
        e = EXPECT[nm]
        ob = OBSERVED.get(nm, {})
        chk(int(d["n"]) == a["n"], "%s/%s: arm prints n=%s (table %d)"
            % (tag, nm, d["n"], a["n"]))
        chk(int(d["sh"]) == a["sh"], "%s/%s: arm prints sh=%s (table %d)"
            % (tag, nm, d["sh"], a["sh"]))
        chk(int(d["mss"]) == a["mss"], "%s/%s: arm prints mss=%s (table %d)"
            % (tag, nm, d["mss"], a["mss"]))
        chk(int(d["store"]) == a["store"] and int(d["off"]) == a["off"],
            "%s/%s: arm prints the store it ran" % (tag, nm))
        # --- what the rule read
        chk(int(d["ch"]) == ob.get("ch", e["ch"]),
            "%s/%s: packets at the rule %s (want %s)" % (tag, nm, d["ch"], ob.get("ch", e["ch"])))
        chk(int(d["nl"]) == ob.get("nl", e["nl"]),
            "%s/%s: log messages %s (want %s)" % (tag, nm, d["nl"], ob.get("nl", e["nl"])))
        chk(int(d["lgn"]) == ob.get("lgn", e["lgn"]),
            "%s/%s: messages counted %s (want %s)" % (tag, nm, d["lgn"], ob.get("lgn", e["lgn"])))
        if ob.get("nl", e["nl"]):
            chk(int(d["lgplen"]) == ob.get("plen", e["plen"]),
                "%s/%s: NFLOG length %s (want %s)"
                % (tag, nm, d["lgplen"], ob.get("plen", e["plen"])))
            chk(int(d["lg2"]) == ob.get("lg2", e["lg2"]),
                "%s/%s: second NFLOG length %s (want %s)"
                % (tag, nm, d["lg2"], ob.get("lg2", e["lg2"])))
            chk(int(d["lg6"], 16) == ob.get("lg6", e["lg6"]),
                "%s/%s: IPv6 payload length %s (want %04x)"
                % (tag, nm, d["lg6"], ob.get("lg6", e["lg6"])))
            # the UDP header: ports, the length the rule reads, the checksum
            want_udp = "%04x%04x%04x%04x" % (SPORT, DPORT,
                                             ob.get("lg6", e["lg6"]), e["check"])
            if a["store"] and a["off"] == 4:
                want_udp = "%04x%04x%s%04x" % (SPORT, DPORT, a["hex"], e["check"])
            chk(d["lgudp"] == want_udp,
                "%s/%s: UDP header %s (want %s)" % (tag, nm, d["lgudp"], want_udp))
            # the payload at the four profile positions, from the profile
            pl = payloads(a)
            first = pl[0]
            if a["store"] and a["off"] == 8:
                first = bytes.fromhex(a["hex"]) + first[4:]
            chk(d["lgp0"] == first[:8].hex(),
                "%s/%s: payload[0] %s (want %s)" % (tag, nm, d["lgp0"], first[:8].hex()))
            if a["n"] > 1 and ob.get("plen", e["plen"]) > 600:
                chk(d["lgp1"] == pl[1][:8].hex(), "%s/%s: payload[1]" % (tag, nm))
            if a["n"] > 2 and ob.get("plen", e["plen"]) > 1100:
                chk(d["lgp2"] == pl[2][:8].hex(), "%s/%s: payload[2]" % (tag, nm))
            if (a["n"] > 3 and ob.get("n", a["n"]) > 3
                    and ob.get("plen", e["plen"]) > 1584):
                want3 = pl[3][:8].hex()
                if a["store"] and a["off"] == 1544:
                    want3 = a["hex"] + pl[3][4:8].hex()
                chk(d["lgp3"] == want3,
                    "%s/%s: payload[3] %s (want %s)" % (tag, nm, d["lgp3"], want3))
        # --- what the socket got
        r = R.get(i)
        chk(r is not None, "%s/%s: RCV line present" % (tag, nm))
        if not r:
            continue
        Ls = [int(x) for x in r["L"].split(",")[:6]]
        Bs = [int(x) for x in r["B"].split(",")[:6]]
        chk(int(r["n"]) == ob.get("n", a["n"]),
            "%s/%s: datagrams delivered %s (want %s)" % (tag, nm, r["n"], ob.get("n", a["n"])))
        if "L0" in ob:
            chk(Ls[0] == ob["L0"], "%s/%s: first datagram length %s (want %s)"
                % (tag, nm, Ls[0], ob["L0"]))
        elif a["n"] > 0:
            chk(Ls[0] == MSS, "%s/%s: first datagram 512 (got %s)" % (tag, nm, Ls[0]))
        if (ob.get("n", a["n"]) > 0 and a["sh"] != 2
                and a["name"] not in OBSERVED):
            wantL = [(a["sl"] if a["sh"] == i else MSS)
                     for i in range(min(a["n"], 6))]
            chk(Ls[:len(wantL)] == wantL,
                "%s/%s: datagram lengths %s (want %s)" % (tag, nm, Ls[:len(wantL)], wantL))
        chk(int(r["udp"]) == ob.get("udp", a["n"]),
            "%s/%s: Udp6InDatagrams %s (want %s)" % (tag, nm, r["udp"], ob.get("udp", a["n"])))
        chk(int(r["udperr"]) == ob.get("err", 0),
            "%s/%s: Udp6InErrors %s (want %s)" % (tag, nm, r["udperr"], ob.get("err", 0)))
        chk(int(r["hdr"]) == 0, "%s/%s: Ip6InHdrErrors 0" % (tag, nm))
        # the payload indices the socket saw must be the ones sent, in order
        if a["n"] >= 4 and a["sh"] != 2 and ob.get("n", a["n"]) >= 4:
            want = list(range(min(a["n"], 6)))
            if a["store"] and a["off"] == 8:
                want = [0xA0] * len(want)
            if a["store"] and a["off"] == 1544 and a["n"] <= 6:
                want[-1] = 0xA0
            chk(Bs[:len(want)] == want, "%s/%s: payload order %s (want %s)"
                % (tag, nm, Bs[:len(want)], want))
        # --- the wire, from D's taps
        frames = T.get((i, "y3")) or T.get((i, "y4")) or []
        if nm in ("g_t3_b", "g_t3u_b", "g_t3_w_b", "g_t3u_w_b", "g_t3_len_b",
                  "g_t3u_len_b"):
            chk([int(f["flen"]) for f in frames] == [574, 574, 574, 262],
                "%s/%s: four frames 574/574/574/262 (got %s)"
                % (tag, nm, [f["flen"] for f in frames]))
            chk([int(f["uhlen"]) for f in frames] == [520, 520, 520, 208],
                "%s/%s: UDP lengths 520/520/520/208 (got %s)"
                % (tag, nm, [f["uhlen"] for f in frames]))
            # the fraglist path copies only the MAC header into each segment,
            # so only the first segment carries the router's decrement; a
            # linearised or linear aggregate copies the whole header
            fraglist_taken = nm in ("g_t3_b", "g_t3_len_b")
            wanthop = [63, 64, 64, 64] if fraglist_taken else [63, 63, 63, 63]
            chk([int(f["hop"]) for f in frames] == wanthop,
                "%s/%s: hop limit %s (fraglist keeps the sender's 64 in the "
                "later segments, the linear path copies the decremented header)"
                % (tag, nm, wanthop))
        if nm in ("g_t3_b", "g_t3_w_b", "g_t3u_b", "g_t3u_w_b", "g_t3_len_b",
                  "g_t3u_len_b") and frames:
            paid = (a["xg"] == "u") or (a["store"] and a["off"] == 1544)
            pl = payloads(a)
            want_ck = []
            for i in range(4):
                u = 8 + (a["sl"] if a["sh"] == i else MSS)
                pl_i = pl[i]
                if a["store"] and a["off"] == 1544 and i == 3:
                    pl_i = bytes.fromhex(a["hex"]) + pl_i[4:]
                want_ck.append(full6(DB, u, pl_i) if paid
                               else seed6(DB, 8 + len(pl[0]) if i == 0 else u))
            got = [int(f["uhck"], 16) for f in frames]
            if nm == "g_t3u_len_b":
                # the delta is computed against the STORED length (0x0020),
                # not the real one (0x06d0): every field is a sum over the
                # wrong pseudo length, and nothing is delivered
                want_ck = [0xFBFF, 0xFAFF, 0xF9FF, 0xC8D8]
            chk(got == want_ck, "%s/%s: checksum fields %s (want %s, paid=%s)"
                % (tag, nm, [hex(x) for x in got], [hex(x) for x in want_ck], paid))
            want_stat = {"g_t3_b": 9, "g_t3_len_b": 9, "g_t3u_len_b": 1}.get(nm, 129)
            chk(all(int(f["stat"]) == want_stat for f in frames),
                "%s/%s: auxdata %s (want %s)"
                % (tag, nm, [f["stat"] for f in frames], want_stat))
        if nm == "g_t3_a":
            chk(len(frames) == 1 and int(frames[0]["flen"]) == 1798,
                "%s/%s: door a carries the aggregate as ONE 1798-byte frame" % (tag, nm))
            chk(int(frames[0]["uhlen"]) == 1744 and int(frames[0]["uhck"], 16) == e["check"],
                "%s/%s: the frame carries uh->len 1744 and the first datagram's seed" % (tag, nm))
        if nm == "g_c65_a":
            chk([int(f["flen"]) for f in frames] == [32830, 574],
                "%s/%s: the cap: one 32830-byte frame then one 574 (got %s)"
                % (tag, nm, [f["flen"] for f in frames]))
        if nm == "g_c65u_a":
            chk([int(f["flen"]) for f in frames] == [32830, 574],
                "%s/%s: the cap on the linear path" % (tag, nm))
            chk(int(frames[0]["uhck"], 16) == seed6(DA, 8 + 64 * 512),
                "%s/%s: the linear aggregate's field is a seed over 32776" % (tag, nm))
            chk(int(frames[1]["uhck"], 16) == seed6(DA, 520),
                "%s/%s: the packet that did not fit carries its own seed" % (tag, nm))
        if nm == "g_mid_a":
            chk(len(frames) == 1 and int(frames[0]["flen"]) == 1286,
                "%s/%s: only the three-datagram aggregate leaves (one frame)" % (tag, nm))
            chk(int(frames[0]["uhlen"]) == 1232, "%s/%s: its UDP length is the sum" % (tag, nm))

    # --- the tail store reaches the tail, and only the tail
    d = A.get("g_t3_w_a")
    if d:
        chk(d["lgp3"].startswith("a0a1a2a3"), "%s: the tail store lands in datagram 3" % tag)
        chk(d["lgp0"].startswith("00") and d["lgp2"].startswith("02"),
            "%s: and nowhere else" % tag)
    # --- the two doors, one store
    if A.get("g_t3u_w_b") and A.get("g_t3_w_b"):
        chk(A["g_t3_w_b"]["lgp3"] == A["g_t3u_w_b"]["lgp3"],
            "%s: the same store reaches the tail through both shapes" % tag)

# ---------- determinism over the four recorded boots --------------------
EXTRA = [f"{ROOT}/logs/f64_rep{n}_final.log" for n in (1, 2, 3, 4)]
def armlines(path):
    out = {}
    for ln in open(path, errors="replace"):
        if ln.startswith("F586 ARM|"):
            d = dict(x.split("=", 1) for x in ln.strip().split("|")[1:] if "=" in x)
            for k in ("att", "agr", "ch0", "plen0", "plen0b", "lgn0"):
                d.pop(k, None)
            out[d["name"]] = d
    return out

base = armlines(EXTRA[0])
chk(len(base) == 26, "determinism: 26 arms in boot 1")
for p in EXTRA[1:]:
    o = armlines(p)
    for nm in base:
        diff = [k for k in base[nm] if base[nm][k] != o.get(nm, {}).get(k)]
        chk(not diff, "determinism %s/%s: fields %s differ" % (os.path.basename(p), nm, diff))

# ---------- what the instrument itself must have said about the shape ---
for a in arms:
    if (a["xg"] == "f" and a["n"] > 1 and not a["mss"]
            and EXPECT[a["name"]]["ch"] == 1 and a["name"] not in OBSERVED):
        d = boots[0][0].get(a["name"])
        if not d or d["lg6"] == "-":
            continue
        chk(int(d["lg6"], 16) == 8 + sum(
            (a["sl"] if a["sh"] == i else MSS) for i in range(a["n"])),
            "%s: the aggregate's IPv6 length is the SUM of its datagrams" % a["name"])

print("\nchecks: %d   failures: %d" % (ok, len(bad)))
for b in bad[:40]:
    print("  FAIL", b)
sys.exit(1 if bad else 0)
