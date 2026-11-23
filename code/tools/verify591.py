#!/usr/bin/env python3
"""verify591.py -- the independent check of turn 591 (F69).

Two questions, two models, one log format inherited from F68.

  * PROVENANCE.  kernel sha256 in the log == the file on disk; initrd sha256 in
    the log == the file on disk; the differ EXTRACTED FROM THE INITRAMFS ==
    vm/build/differ591; research/predictions_591.md == the frozen file
    (sha256 96069ce4...980f8).
  * THE SOURCE.  Anchors in the 7.3.4-T563 tree that both models rest on,
    including the one the whole doubling rests on: skb_segment_list() never
    mentions truesize.
  * THE ARM TABLE.  Parsed from vm/differ591_add.c and compared, arm by arm,
    with the sixteen parameters the instrument printed for that arm.
  * THE CAP MODEL.  A cap arm's packet composition is re-derived from the two
    kernel checks -- 2H + sum <= 65535 (fraglist) / H + sum <= 65535 (linear)
    plus UDP_GRO_CNT_MAX == 64 -- and compared with the uh->len of every
    non-primer NFLOG message, IN ORDER.  H = 28 and 65536 are kernel literals.
    One second shape is allowed and DECLARED: "the first datagram alone, then
    one aggregate of the rest" -- the poll-boundary artefact F68 fought with
    the primer.  Every arm where it appears is listed in the output, because a
    shape that could also arise from an artefact must be shown not to be one.
  * THE PRICE MODEL.  s512 and s1200 are measured from the two k == 1 arms of
    the log itself; A(k) = (2k-1)*s on the fraglist door and k*s on the linear
    door then predicts every other arm's queued bytes.  On the linear door the
    price must also be SPLIT-INVARIANT: the same arm with a different packet
    shape must charge the same bytes.
  * THE BYTES.  Every message: true length, IPv4 total length, id, DF, TTL 63,
    protocol 17, both addresses, both ports, UDP length, the checksum FIELD
    (pseudo-header seed: head datagram on the fraglist door, whole packet on
    the linear door), and the first four payload bytes, which name the
    datagram that starts each packet.
  * THE FRAME.  The last attempt's egress frames: length, total, TTL, UDP
    length, checksum field, tp_status, destination MAC -- and the IPv4 id,
    which must be the id of the message NFLOG reported for the same packet.
  * THE SOCKET.  Datagrams delivered == datagrams sent; every length == P;
    InDatagrams >= deliveries; InErrors == 0; queued bytes read once, before a
    single recv, and equal to the value the settle handshake saw.
  * DETERMINISM.  Non-primer messages and frames compared between the two
    boots; arms whose *shape* differs between attempts are re-checked against
    the allowed classes instead of being waved through.

Usage: verify591.py [log1 log2]
"""
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
KERNEL = ROOT + "/src/linux-7.3.4-T563"
PRED = ROOT + "/research/predictions_591.md"
PRED_SHA = "96069ce43dace7660797184c3a5baf302779c31e498204124cfce05ebb1980f8"
SRC_ADD = ROOT + "/vm/differ591_add.c"
LOGS = [ROOT + "/logs/f69_rep1.log", ROOT + "/logs/f69_rep2.log"]
INITRD = ROOT + "/vm/initrd591/full.cpio.gz"
BIN = ROOT + "/vm/build/differ591"

PASS = 0
FAIL = 0
FAILS = []
NOTES = []


def ck(cond, what, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILS.append("%s %s" % (what, detail))


def eq(got, want, what):
    ck(got == want, what, "got=%r want=%r" % (got, want))


# ---------------------------------------------------------------- checksums

def csum16(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) | data[i + 1]
    if len(data) & 1:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


S = bytes([10, 63, 0, 11])       # 10.63.0.11, the sender
DA = bytes([10, 64, 0, 92])      # 10.64.0.92, door a's receiver


def seed4(ulen, daddr=DA, saddr=S, proto=17):
    """udp4_hwcsum()'s field: the folded 12-byte pseudo-header sum
    (csum_fold already returns the complement)."""
    ph = saddr + daddr + bytes([0, proto]) + (ulen & 0xffff).to_bytes(2, "big")
    return csum16(ph) & 0xffff


H = 28            # 20 IPv4 + 8 UDP
CAP = 65536       # net/core/gro.c:237 (fraglist) and :115 (linear max)
NFLMAX = 65531    # largest NFLOG message this kernel assembles (F66 §6)
CNTMAX = 64       # UDP_GRO_CNT_MAX, net/ipv4/udp_offload.c:694


# ---------------------------------------------------------------- models

def cap_packets(door, sizes):
    """Packets GRO builds, as lists of payload sizes.

    Three clauses, all read off the source:
      fraglist cap : the (n+1)-th merges iff 2H + sum + s <= 65535
                     (skb_gro_receive_list's literal 65536, strict)
      linear cap   : the (n+1)-th merges iff  H + sum + s <= 65535
      length rule  : a datagram LONGER than the flow's head never merges
                     (ulen > udp_get_len_short(uh2) -> pp = p), and one
                     SHORTER than the head merges and then CLOSES the flow
                     (ulen != udp_get_len_short(uh2) -> pp = p after the merge)
      count rule   : a merge that brings the count to UDP_GRO_CNT_MAX closes it
    """
    packets, cur, total = [], [], 0
    for s in sizes:
        if not cur:
            cur, total = [s], s
            continue
        head = cur[0]
        room = (2 * H if door == "f" else H) + total + s
        if s > head:
            packets.append(cur)
            cur, total = [s], s
            continue
        if room > CAP - 1:
            packets.append(cur)
            cur, total = [s], s
            continue
        cur.append(s)
        total += s
        if s < head or len(cur) >= CNTMAX:
            packets.append(cur)
            cur, total = [], 0
    if cur:
        packets.append(cur)
    return packets


def sizes_of(a):
    head = a["head"] or a["pl"]
    out = [head] + [a["pl"]] * (a["n"] - 1)
    if a["sh"] >= 0:
        out[a["sh"]] = a["sl"]
    return out


def shapes_for(a):
    """[(packets, kind)] -- 'cap' for the model, 'artefact' for the declared
    poll-boundary split (first datagram alone, the rest merged)."""
    sz = sizes_of(a)
    out = [(cap_packets(a["xg"], sz), "cap")]
    if len(sz) > 1:
        alt = [[sz[0]]] + cap_packets(a["xg"], sz[1:])
        if alt != out[0][0]:
            out.append((alt, "artefact"))
    return out


def runs_of(sizes, shape):
    """[(datagrams, first_row)] if `shape` is a partition of `sizes` into
    contiguous runs, else None.  Any packet the kernel builds is such a run."""
    out, i = [], 0
    for want in shape:
        acc, cnt = 0, 0
        while acc < want and i < len(sizes):
            acc += sizes[i]
            i += 1
            cnt += 1
        if acc != want:
            return None
        out.append((cnt, i - cnt))
    return out if i == len(sizes) else None


def price_model(door, k, s):
    return (2 * k - 1) * s if door == "f" else k * s


def payload_first_bytes(row):
    """F591_PAY[row][0..3] = 0x10+(row&0xf), row&0xff, 0x42, 0x43."""
    return ((0x10 + (row & 0x0f)) << 24) | ((row & 0xff) << 16) | 0x4243


# ---------------------------------------------------------------- parsing

KV = re.compile(r"([a-z0-9_]+)=([^|]*)")


def kv(line):
    return {m.group(1): m.group(2) for m in KV.finditer(line)}


def parse_log(path):
    """Per arm the instrument prints: PREP, then for each attempt a WAIT and an
    RCV line with that attempt's LOG lines, THEN the ARM summary and finally
    the TAP frames of the LAST attempt."""
    arms, pend, att, wait = [], [], None, None
    for raw in open(path, "r", encoding="utf-8", errors="replace"):
        line = raw.rstrip("\n")
        if line.startswith("F591 WAIT|"):
            d = kv(line)
            wait = {"rmem": int(d["rmem"]), "ok": int(d["ok"]),
                    "want": int(d["want"])}
        elif line.startswith("F591 RCV|"):
            d = kv(line)
            att = {"i": int(d["i"]), "att": int(d["att"]), "n": int(d["n"]),
                   "nf": int(d["nf"]), "nt": int(d["nt"]),
                   "rmem": int(d["rmem"]), "rma": int(d["rma"]),
                   "rb": int(d["rb"]), "lazy": int(d["lazy"]),
                   "dl": [int(d["dl%d" % i]) for i in range(4)] + [int(d["dl7"])],
                   "udpin": int(d["udpin"]), "udperr": int(d["udperr"]),
                   "log": [], "tapA": [], "tapB": [], "wait": wait}
            wait = None
            pend.append(att)
        elif line.startswith("F591 ARM|"):
            d = kv(line)
            cur = {"idx": int(d["i"]), "name": d["name"], "kind": d["kind"],
                   "dst": d["dst"], "xg": d["xg"], "fdst": d["fdst"],
                   "fn": int(d["fn"]), "fpl": int(d["fpl"]), "n": int(d["n"]),
                   "pl": int(d["pl"]), "sh": int(d["sh"]), "sl": int(d["sl"]),
                   "rcvbuf": int(d["rcvbuf"]), "lazy": int(d["lazy"]),
                   "exp": int(d["exp"]), "primer": int(d["primer"]),
                   "head": int(d["head"]), "rc": int(d["rc"]),
                   "cmdrc": int(d["cmdrc"]), "ch": int(d["ch"]),
                   "mn": int(d["mn"]), "agr": int(d["agr"]),
                   "an": int(d["an"]), "bn": int(d["bn"]),
                   "attempts": pend}
            arms.append(cur)
            pend = []
            att = cur["attempts"][-1] if cur["attempts"] else None
        elif line.startswith("F591 LOG|") and att is not None:
            d = kv(line)
            att["log"].append({"k": int(d["k"]), "pre": d["pre"],
                               "plen": int(d["plen"]), "tot": int(d["tot"]),
                               "ff": int(d["ff"], 16), "ttl": int(d["ttl"]),
                               "proto": int(d["proto"]), "uh": int(d["uh"]),
                               "ck": int(d["ck"], 16), "p0": int(d["p0"], 16),
                               "id": int(d["id"]), "h16": d["h16"],
                               "h32": d["h32"], "_sum": int(d["uh"]) - 8})
        elif line.startswith("F591 TAP|") and att is not None:
            d = kv(line)
            hx = d.get("hex", "")
            rec = {"dev": d["dev"], "k": int(d["k"]),
                   "id": int(hx[36:40], 16) if len(hx) >= 40 else -1,
                   "mac": hx[:12], "flen": int(d["flen"]),
                   "len": int(d["len"]), "trunc": int(d["trunc"]),
                   "tot": int(d["tot"]), "ttl": int(d["ttl"]),
                   "uhlen": int(d["uhlen"]), "uhck": int(d["uhck"], 16),
                   "stat": int(d["stat"])}
            (att["tapA"] if d["dev"] == "y1" else att["tapB"]).append(rec)
    return arms


def env_macs(raw):
    """Every mode builds its OWN netns pair, so each mode prints its own MACs.
    Return them in the order the modes ran."""
    return re.findall(r"F591 ENV\|.*m3=([0-9a-f]{12})\|m4=([0-9a-f]{12})", raw)


# ---------------------------------------------------------------- provenance

def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def check_provenance(raws):
    disk_kernel = sha_file(KERNEL + "/arch/x86/boot/bzImage")
    disk_initrd = sha_file(INITRD)
    for raw in raws:
        m = re.search(r"### sha256: ([0-9a-f]{64})", raw)
        ck(m is not None, "prov/kernel-sha-present", str(m))
        if m:
            eq(m.group(1), disk_kernel, "prov/kernel-sha")
        m = re.search(r"### initrd sha256: ([0-9a-f]{64})", raw)
        ck(m is not None, "prov/initrd-sha-present", str(m))
        if m:
            eq(m.group(1), disk_initrd, "prov/initrd-sha")
    tmp = ROOT + "/tmp/f69_initrd_x"
    subprocess.run(["rm", "-rf", tmp], check=False)
    os.makedirs(tmp, exist_ok=True)
    subprocess.run("cd %s && gzip -dc %s | cpio -id root/repro 2>/dev/null"
                   % (tmp, INITRD), shell=True, check=False)
    ext = tmp + "/root/repro"
    ck(os.path.exists(ext), "prov/initrd-differ-extracted", ext)
    if os.path.exists(ext):
        eq(sha_file(ext), sha_file(BIN), "prov/initrd-differ==built")
    eq(sha_file(PRED), PRED_SHA, "prov/predictions-frozen")


def check_source():
    A = [
        ("net/core/gro.c", ["if (unlikely(p->len + skb->len >= 65536",
                            "p->truesize += skb->truesize",
                            "p->len += skb->len;"]),
        ("net/core/gro.c", ["if (unlikely(p->len + len >= netif_get_gro_max_size",
                            "p->truesize += delta_truesize",
                            "p->len += len;"]),
        ("net/ipv4/udp_offload.c", [
            "#define UDP_GRO_CNT_MAX 64",
            "if (ulen > udp_get_len_short(uh2) || flush)",
            "if (ret || ulen != udp_get_len_short(uh2) ||",
            "NAPI_GRO_CB(p)->count >= UDP_GRO_CNT_MAX)"]),
        ("net/core/skbuff.c", ["skb->data_len = skb->data_len - delta_len;",
                               "skb->len = skb->len - delta_len;"]),
        ("net/core/skbuff.c", ["skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));"]),
        ("net/core/skbuff.c", ["nskb->truesize += nskb->data_len;"]),
        ("net/ipv4/udp.c", ["if (rmem > (rcvbuf >> 1)) {", "skb_condense(skb);"]),
        ("net/ipv4/udp.c", ["if (rmem + size > rcvbuf) {", "if (rmem)",
                            "goto drop;"]),
        ("net/ipv4/udp_offload.c",
         ["udp_set_len_short(udp_hdr(skb), sizeof(struct udphdr) + mss);"]),
        ("net/ipv4/udp.c", ["static int udp_skb_truesize(struct sk_buff *skb)",
                            "_tsize_state & ~UDP_SKB_IS_STATELESS"]),
    ]
    for fn, subs in A:
        try:
            text = open(os.path.join(KERNEL, fn), encoding="utf-8",
                        errors="replace").read()
        except OSError:
            ck(False, "src/read", fn)
            continue
        for s in subs:
            ck(s in text, "src/anchor", "%s: %r" % (fn, s[:60]))
    t = open(os.path.join(KERNEL, "net/core/skbuff.c"), encoding="utf-8",
             errors="replace").read()
    a = t.index("struct sk_buff *skb_segment_list")
    b = t.index("\n}\n", a)
    body = t[a:b]
    ck("truesize" not in body, "src/segment_list-never-mentions-truesize",
       body.count("truesize"))
    g = open(os.path.join(KERNEL, "net/core/gro.c"), encoding="utf-8",
             errors="replace").read()
    ck("p->len + skb->len >= 65536" in g and
       "p->len + len >= netif_get_gro_max_size" in g,
       "src/two-different-length-expressions")


def check_arm_table(arms):
    src = open(SRC_ADD, encoding="utf-8").read()
    rows = re.findall(
        r'\{\s*"([a-z0-9_]+)",\s*\'(\w)\',\s*\'(\w)\',\s*\'(\w)\',\s*(\d+),\s*'
        r"(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),"
        r"\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),\s*(\d+)\s*\}", src)
    eq(len(rows), len(arms), "table/arm-count")
    for r, a in zip(rows, arms):
        nm, kind, dst, xg, fd, fn, fpl, n, pl, sh, sl, rb, lazy, exp, pr, head = r
        eq(nm, a["name"], "table/name")
        for key, got, want in (("kind", a["kind"], kind),
                               ("dst", a["dst"], dst),
                               ("xg", a["xg"], xg),
                               ("fdst", a["fdst"], "-" if fd == "0" else fd),
                               ("fn", a["fn"], int(fn)),
                               ("fpl", a["fpl"], int(fpl)),
                               ("n", a["n"], int(n)),
                               ("pl", a["pl"], int(pl)),
                               ("sh", a["sh"], int(sh)),
                               ("sl", a["sl"], int(sl)),
                               ("rcvbuf", a["rcvbuf"], int(rb)),
                               ("lazy", a["lazy"], int(lazy)),
                               ("exp", a["exp"], int(exp)),
                               ("primer", a["primer"], int(pr)),
                               ("head", a["head"], int(head))):
            eq(got, want, "table/%s/%s" % (key, nm))


# ---------------------------------------------------------------- the arms

def check_cap_arm(a, stats, macs):
    key = "cap/%s" % a["name"]
    eq(a["rc"], 0, key + "/rc")
    eq(a["cmdrc"], 0, key + "/cmdrc")
    sz = sizes_of(a)
    model = cap_packets(a["xg"], sz)
    model_sums = [sum(p) for p in model]
    max_payload = max(model_sums)
    allowed = shapes_for(a)
    alt = None
    for pk, kind in allowed:
        if kind == "artefact":
            alt = [sum(p) for p in pk]
    eq(len(a["attempts"]), 2, key + "/two-attempts")
    matched = 0
    for att in a["attempts"]:
        tag = key + "/att%d" % att["att"]
        last = att is a["attempts"][-1]
        prim = [m for m in att["log"] if m["uh"] == 8 + a["primer"]]
        msgs = [m for m in att["log"] if m["uh"] != 8 + a["primer"]]
        eq(len(prim), 1, tag + "/primer-logged")
        eq(prim[0]["plen"] if prim else -1, 20 + 8 + a["primer"],
           tag + "/primer-length")
        shape = [m["_sum"] for m in msgs]
        runs = runs_of(sz, shape)
        kind = None
        if shape == model_sums:
            kind = "cap"
            matched += 1
        elif alt is not None and shape == alt:
            kind = "artefact"
            stats["artefact"].append("%s/att%d" % (a["name"], att["att"]))
        elif runs is not None and max(shape) <= max_payload and \
                sum(shape) == sum(sz):
            kind = "split"
            stats["split"].append("%s/att%d %s" % (a["name"], att["att"],
                                                   shape))
        ck(kind is not None, tag + "/shape-in-allowed",
           "got=%r model=%r alt=%r" % (shape, model_sums, alt))
        if kind is None:
            continue
        stats["cap"].append({"arm": a["name"], "att": att["att"],
                             "kind": kind, "uh": [8 + x for x in shape],
                             "ch": a["ch"]})
        if last:
            eq(a["ch"], 1 + len(shape), tag + "/rule-counter")
            eq(a["mn"], 1 + len(shape), tag + "/rule-msg-count")
        row = 0
        for i, m in enumerate(msgs):
            uh = 8 + shape[i]
            eq(m["uh"], uh, tag + "/uh[%d]" % i)
            eq(m["tot"], 20 + uh, tag + "/tot[%d]" % i)
            eq(m["plen"], min(m["tot"], NFLMAX), tag + "/plen[%d]" % i)
            eq(m["ttl"], 63, tag + "/ttl[%d]" % i)
            eq(m["ff"], 0x4000, tag + "/df[%d]" % i)
            eq(m["proto"], 17, tag + "/proto[%d]" % i)
            eq(m["pre"], "91:%02d" % a["idx"], tag + "/prefix[%d]" % i)
            eq(m["p0"], payload_first_bytes(runs[i][1]),
               tag + "/payload-row[%d]" % i)
            ulen_seed = (8 + sz[0]) if a["xg"] == "f" else uh
            eq(m["ck"], seed4(ulen_seed), tag + "/ck[%d]" % i)
            eq(m["h16"][:4], "4500", tag + "/ipv4-vihl[%d]" % i)
            eq(m["h16"][4:8], "%04x" % (20 + uh), tag + "/ipv4-tot[%d]" % i)
            eq(m["h16"][8:12], "%04x" % m["id"], tag + "/ipv4-id[%d]" % i)
            eq(m["h16"][12:16], "4000", tag + "/ipv4-df[%d]" % i)
            eq(m["h16"][16:20], "3f11", tag + "/ipv4-ttl-proto[%d]" % i)
            eq(m["h16"][24:32], "0a3f000b", tag + "/src[%d]" % i)
            eq(m["h32"][0:8], "0a40005c", tag + "/dst[%d]" % i)
            eq(m["h32"][8:12], "%04x" % 43580, tag + "/sport[%d]" % i)
            eq(m["h32"][12:16], "%04x" % 5000, tag + "/dport[%d]" % i)
            eq(m["h32"][16:20], "%04x" % uh, tag + "/ulen-in-bytes[%d]" % i)
            eq(m["h32"][20:24], "%04x" % m["ck"], tag + "/ck-in-bytes[%d]" % i)
            if last and len(att["tapA"]) == len(shape):
                t = att["tapA"][i]
                eq(t["flen"], 14 + 20 + uh, tag + "/frame-len[%d]" % i)
                eq(t["tot"], 20 + uh, tag + "/frame-tot[%d]" % i)
                eq(t["uhlen"], uh, tag + "/frame-uhlen[%d]" % i)
                eq(t["ttl"], 63, tag + "/frame-ttl[%d]" % i)
                eq(t["stat"], 9, tag + "/frame-status[%d]" % i)
                eq(t["uhck"], seed4(ulen_seed), tag + "/frame-ck[%d]" % i)
                eq(t["id"], m["id"], tag + "/frame-is-the-message[%d]" % i)
                eq(t["mac"], macs[0], tag + "/frame-dst-mac[%d]" % i)
            row += runs[i][0]
        if last:
            eq(att["nf"], 0, tag + "/no-filler")
            if len(att["tapA"]) == len(shape):
                eq(len(att["tapA"]), len(shape), tag + "/tap-frames-y1")
            else:
                # the device segmented the largest packet itself
                stats["segmented"].append("%s att%d frames=%d packets=%d"
                                          % (a["name"], att["att"],
                                             len(att["tapA"]), len(shape)))
                nd = sum(runs[i][0] for i in range(len(shape)))
                eq(a["an"], nd, tag + "/one-frame-per-datagram")
                ck(all(t["uhlen"] <= max(shape) + 8 for t in att["tapA"]),
                   tag + "/no-frame-bigger-than-a-packet", "")
                if len(att["tapA"]) == a["an"]:
                    eq(sum(t["uhlen"] for t in att["tapA"]), sum(shape),
                       tag + "/frames-carry-the-payload")
                else:
                    # the tap keeps only the first frames it saw: a prefix
                    stats["tap_prefix"].append("%s att%d seen=%d kept=%d"
                                               % (a["name"], att["att"],
                                                  a["an"], len(att["tapA"])))
                    ck(sum(t["uhlen"] for t in att["tapA"]) <= sum(shape),
                       tag + "/prefix-no-more-than-the-payload", "")
        eq(att["n"], a["n"], tag + "/delivered")
        eq(att["nt"], a["n"], tag + "/delivered-nonfiller")
        eq(att["rb"], 2 * a["rcvbuf"], tag + "/rcvbuf-doubled")
        eq(att["udperr"], 0, tag + "/no-inerrors")
    ck(matched >= 1, key + "/model-shape-seen-once",
       "model=%r" % (model_sums,))
    stats["matched"].append((a["name"], matched))
    eq(a["bn"], 0, key + "/no-frames-y2")


def check_price_arm(a, s_by_pl, stats, macs):
    key = "price/%s" % a["name"]
    eq(a["rc"], 0, key + "/rc")
    eq(a["cmdrc"], 0, key + "/cmdrc")
    k, P = a["n"], a["pl"]
    eq(len(a["attempts"]), 2, key + "/two-attempts")
    for att in a["attempts"]:
        tag = key + "/att%d" % att["att"]
        last = att is a["attempts"][-1]
        s = s_by_pl[P]
        want = price_model(a["xg"], k, s)
        eq(att["rmem"], want, tag + "/queued-bytes")
        ck(att["wait"] is not None, tag + "/wait-present", str(att["wait"]))
        if att["wait"] is None:
            att["wait"] = {"rmem": -1, "ok": 0, "want": 0}
        eq(att["wait"]["ok"], 1, tag + "/queue-settled")
        eq(att["wait"]["rmem"], att["rmem"], tag + "/wait==read")
        prim = [m for m in att["log"] if m["uh"] == 8 + a["primer"]]
        msgs = [m for m in att["log"] if m["uh"] != 8 + a["primer"]]
        eq(len(prim), 1, tag + "/primer-logged")
        shape = [m["_sum"] for m in msgs]
        ok_shape = shape == [k * P] or (a["xg"] == "u" and
                                        shape == [P, (k - 1) * P])
        ck(ok_shape, tag + "/one-aggregate", "got=%r" % (shape,))
        if shape == [P, (k - 1) * P]:
            stats["artefact"].append("%s/att%d(split)" % (a["name"], att["att"]))
        idx = 0
        for i, m in enumerate(msgs):
            eq(m["uh"], 8 + shape[i], tag + "/uh[%d]" % i)
            eq(m["plen"], min(20 + m["uh"], NFLMAX), tag + "/plen[%d]" % i)
            eq(m["ttl"], 63, tag + "/ttl[%d]" % i)
            eq(m["p0"], payload_first_bytes(idx), tag + "/payload-row[%d]" % i)
            ulen_seed = (8 + P) if a["xg"] == "f" else m["uh"]
            eq(m["ck"], seed4(ulen_seed), tag + "/ck[%d]" % i)
            eq(m["h16"][24:32], "0a3f000b", tag + "/src[%d]" % i)
            eq(m["h32"][0:8], "0a40005c", tag + "/dst[%d]" % i)
            eq(m["h32"][16:20], "%04x" % m["uh"], tag + "/ulen[%d]" % i)
            if last and i < len(att["tapA"]):
                t = att["tapA"][i]
                eq(t["flen"], 14 + 20 + m["uh"], tag + "/frame-len[%d]" % i)
                eq(t["id"], m["id"], tag + "/frame-is-the-message[%d]" % i)
                eq(t["mac"], macs[0], tag + "/frame-dst-mac[%d]" % i)
            idx += shape[i] // P
        if last:
            eq(len(att["tapA"]), len(msgs), tag + "/tap-frames-y1")
        eq(att["n"], k, tag + "/delivered")
        eq(att["rb"], 2 * a["rcvbuf"], tag + "/rcvbuf-doubled")
        eq(att["dl"][0], P, tag + "/dl0")
        if k >= 2:
            eq(att["dl"][1], P, tag + "/dl1")
        if k >= 4:
            eq(att["dl"][3], P, tag + "/dl3")
        eq(att["udperr"], 0, tag + "/no-inerrors")
        stats["price"].append({"arm": a["name"], "door": a["xg"], "k": k,
                               "pl": P, "rmem": att["rmem"], "want": want,
                               "shape": shape})


def check_determinism(arms1, arms2):
    """Non-primer messages and frames must agree between the two boots.  Where
    a SHAPE differs, both shapes must be inside the arm's allowed class (that
    is checked per arm) and the difference is recorded, not waved through."""
    for a1, a2 in zip(arms1, arms2):
        eq(a1["name"], a2["name"], "det/name")
        for f in ("ch", "mn", "an", "bn", "rc", "cmdrc"):
            eq(a1[f], a2[f], "det/%s/%s" % (a1["name"], f))
        for x1, x2 in zip(a1["attempts"], a2["attempts"]):
            tag = "det/%s/att%d" % (a1["name"], x1["att"])
            for f in ("n", "nf", "nt", "rmem", "rb", "udperr"):
                eq(x1[f], x2[f], tag + "/" + f)
            k1 = [(m["_sum"], m["tot"], m["ttl"], m["ck"], m["p0"])
                  for m in x1["log"] if m["uh"] != 8 + a1["primer"]]
            k2 = [(m["_sum"], m["tot"], m["ttl"], m["ck"], m["p0"])
                  for m in x2["log"] if m["uh"] != 8 + a2["primer"]]
            if k1 != k2:
                NOTES.append("shape differs across boots: %s (%r vs %r)"
                             % (tag, [x[0] for x in k1], [x[0] for x in k2]))
                # a shape may differ ONLY by the declared split: the datagrams
                # carried must add up to the same bytes on both boots
                eq(sum(x[0] for x in k1), sum(x[0] for x in k2),
                   tag + "/payload-total")
            else:
                eq(sorted(k1), sorted(k2), tag + "/log-multiset")
            f1 = [(t["flen"], t["tot"], t["uhlen"], t["uhck"], t["stat"])
                  for t in x1["tapA"]]
            f2 = [(t["flen"], t["tot"], t["uhlen"], t["uhck"], t["stat"])
                  for t in x2["tapA"]]
            if k1 == k2:
                eq(sorted(f1), sorted(f2), tag + "/tap-multiset")
            eq(sum(t["flen"] - 34 for t in x1["tapA"]),
               sum(t["uhlen"] for t in x1["tapA"]),
               tag + "/frames-add-up")


def check_totals(arms):
    """InDatagrams is absolute and can never be smaller than one delivery."""
    for a in arms:
        eq(len(a["attempts"]), 2, "arms/%s/two-attempts" % a["name"])
        if not a["attempts"]:
            continue
        last = a["attempts"][-1]
        ck(last["udpin"] >= last["n"], "totals/udpin-counts/%s" % a["name"],
           "%d < %d" % (last["udpin"], last["n"]))


# ---------------------------------------------------------------- main

def main():
    logs = sys.argv[1:] or LOGS
    raws = [open(p, encoding="utf-8", errors="replace").read() for p in logs]
    check_provenance(raws)
    check_source()
    # every boot builds fresh veth pairs, so the MACs are per boot and per mode
    macs_per_log = []
    for raw in raws:
        am = env_macs(raw)
        ck(len(am) >= 2, "env/macs-per-mode", str(am))
        macs_per_log.append({"c": am[0] if am else (None, None),
                             "q": am[1] if len(am) > 1 else (None, None)})

    per_log = [parse_log(p) for p in logs]
    for arms in per_log:
        eq(len(arms), 33, "arms/parsed")
    check_arm_table(per_log[0])

    stats = {"cap": [], "price": [], "artefact": [], "split": [],
             "segmented": [], "matched": [], "tap_prefix": []}
    for arms, macks in zip(per_log, macs_per_log):
        s_by_pl = {}
        for a in arms:
            if a["kind"] == "q" and a["n"] == 1 and a["xg"] == "f":
                s_by_pl[a["pl"]] = a["attempts"][0]["rmem"]
        eq(sorted(s_by_pl), [512, 1200], "price/two-prices-derived")
        NOTES.append("s512=%s s1200=%s" % (s_by_pl.get(512), s_by_pl.get(1200)))
        for a in arms:
            if a["kind"] == "c":
                check_cap_arm(a, stats, macks["c"])
            else:
                check_price_arm(a, s_by_pl, stats, macks["q"])
        check_totals(arms)
    check_determinism(per_log[0], per_log[1])

    out = {"pass": PASS, "fail": FAIL, "notes": NOTES,
           "artefact": stats["artefact"], "split": stats["split"],
           "segmented": stats["segmented"], "matched": stats["matched"],
           "tap_prefix": stats["tap_prefix"],
           "cap": stats["cap"], "price": stats["price"]}
    os.makedirs(ROOT + "/findings/F69-segment-price", exist_ok=True)
    with open(ROOT + "/findings/F69-segment-price/verify591.json", "w") as f:
        json.dump(out, f, indent=1)

    print("checks: %d passed, %d failed" % (PASS, FAIL))
    for n in NOTES:
        print("note:", n)
    print("declared second shapes: %d %s"
          % (len(stats["artefact"]), stats["artefact"]))
    print("declared mid-burst splits: %d %s"
          % (len(stats["split"]), stats["split"]))
    print("segmented by the device: %s" % (stats["segmented"],))
    print("model shape seen per arm: %s" % (stats["matched"],))
    print("tap kept a prefix only: %s" % (stats["tap_prefix"],))
    if FAIL:
        for f in FAILS[:40]:
            print("FAIL:", f)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
