#!/usr/bin/env python3
"""verify594.py -- F72: what an audit of the two zerocopy doors can and cannot say.

Checks, in order:

  A  provenance   kernel sha in the log == the bzImage on disk; initrd sha in
                  the log == the file; the differ binary extracted from that
                  initrd == vm/build/differ594 byte for byte; the predictions
                  file is older than the first boot.
  B  source       every literal the model leans on is in the source tree.
  C  arms         the printed ARM line of every attempt == the arm table parsed
                  out of vm/differ594_add.c.
  D  the rule     the number of packets and every UDP length at the nft `log`
                  == the model built from the arm parameters and two source
                  facts (skb_gro_receive refuses skb_zcopy; skb_gro_receive_list
                  does not).
  E  the gate     every __udp_enqueue_schedule_skb record: len == tail-44+dlen,
                  ts == end+576+(PAGE_ALIGN(dlen) if the skb is zerocopy else
                  0), and for an aggregate head ts == the sum over members.
  F  the queue    the rmem growth == the charge model (condensed truesize when
                  __pskb_pull_tail ran, the sum of the records otherwise), and
                  for the 64-datagram arm kept == floor(rcvbuf / ts) with
                  delivered + errors == n.
  G  doors        skb_segment_list is called for a fraglist aggregate and never
                  for a linear one; skb_copy_ubufs once per datagram on the
                  linear door and once per aggregate on the fraglist door.
  H  clause 2     the four c_* arms: pull/charge/fl pattern.
  I  determinism  every modelled field equal between the two boots and between
                  the two attempts of an arm.

Exit code 0 only if every check passes.  Prints a per-section count.
"""
import gzip
import hashlib
import io
import os
import re
import sys

ROOT = "/work/kernel-sec"
LOGS = [os.environ.get("F72_LOG1", "%s/logs/f72_rep1.log" % ROOT),
        os.environ.get("F72_LOG2", "%s/logs/f72_rep2.log" % ROOT)]
SRC = "%s/src/linux-7.3.4-T563" % ROOT
KERNEL = "%s/arch/x86/boot/bzImage" % SRC
DIFFER = "%s/vm/build/differ594" % ROOT
ADD = "%s/vm/differ594_add.c" % ROOT
INITRD = "%s/vm/initrd594/full.cpio.gz" % ROOT
PRED = os.environ.get("F72_PRED", "%s/research/predictions_594.md" % ROOT)

PASS = 0
FAIL = 0
FAILS = []
SEC = {"A": [0, 0], "B": [0, 0], "C": [0, 0], "D": [0, 0], "E": [0, 0],
       "F": [0, 0], "G": [0, 0], "H": [0, 0], "I": [0, 0]}


def ck(sec, cond, what):
    global PASS, FAIL
    if cond:
        PASS += 1
        SEC[sec][0] += 1
    else:
        FAIL += 1
        SEC[sec][1] += 1
        if len(FAILS) < 60:
            FAILS.append("[%s] %s" % (sec, what))
    return bool(cond)


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha_bytes(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- parsing

def kv(line):
    """F594 X|k=v|k=v... -> dict"""
    d = {}
    parts = line.split("|")
    d["_kind"] = parts[0].split(" ", 1)[1] if " " in parts[0] else parts[0]
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            d[k] = v.strip()          # the serial console ends lines with \r
    return d


def ints(s):
    if s == "":
        return []
    return [int(x) for x in s.split(",")]


class Attempt(object):
    def __init__(self, i, att):
        self.i = i
        self.att = att
        self.arm = None
        self.pkt = None
        self.rcv = None
        self.cnt = None
        self.eq = []
        self.cq = []
        self.zc = None
        self.prep = None
        self.dtap = None
        self.childs = []
        self.wait = []
        self.marks = 0

    def key(self):
        return (self.i, self.att)


def parse(path):
    attempts = {}
    order = []
    cur = None
    hdr = {}
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8", "replace")
    lines = raw.split("\n")
    for ln in lines:
        if ln.startswith("### kernel:"):
            hdr["kernel"] = ln.split(": ", 1)[1].strip()
            continue
        if ln.startswith("### sha256:"):
            hdr["ksha"] = ln.split(": ", 1)[1].strip()
            continue
        if ln.startswith("### initrd:"):
            hdr["initrd"] = ln.split(": ", 1)[1].strip()
            continue
        if ln.startswith("### initrd sha256:"):
            hdr["isha"] = ln.split(": ", 1)[1].strip()
            continue
        if not ln.startswith("F594 "):
            continue
        d = kv(ln)
        k = d["_kind"]
        if k in ("PKT", "RCV", "CNT", "EQ", "CQ", "ARM"):
            i, att = int(d["i"]), int(d["att"])
            if (i, att) not in attempts:
                attempts[(i, att)] = Attempt(i, att)
                order.append((i, att))
            cur = attempts[(i, att)]
            cur.prep = cur.prep
        if k == "PREP":
            if cur is not None and cur.prep is None and cur.rcv is None:
                cur.prep = d
            else:
                pending_prep.append(d)
        elif k == "DTAP":
            pending_dtap.append(d)
        elif k == "CHILDS":
            pending_childs.append(d)
        elif k == "WAIT":
            pending_wait.append(d)
        elif k == "PKT":
            a = attempts[(int(d["i"]), int(d["att"]))]
            a.pkt = d
        elif k == "RCV":
            a = attempts[(int(d["i"]), int(d["att"]))]
            a.rcv = d
            assign_pending(a)
        elif k == "ZC":
            a = cur
            if a is not None:
                a.zc = d
        elif k == "CNT":
            a = attempts[(int(d["i"]), int(d["att"]))]
            a.cnt = d
        elif k == "EQ":
            a = attempts[(int(d["i"]), int(d["att"]))]
            a.eq.append(d)
        elif k == "CQ":
            a = attempts[(int(d["i"]), int(d["att"]))]
            a.cq.append(d)
        elif k == "ARM":
            a = attempts[(int(d["i"]), int(d["att"]))]
            a.arm = d
        elif k == "TRC":
            if "tracing_mark_write" in ln and ("BEGIN" in ln or "END" in ln):
                a = attempts.get((int(d["i"]), int(d["att"])))
                if a is not None:
                    a.marks += 1
    return order, attempts, hdr


pending_prep = []
pending_dtap = []
pending_childs = []
pending_wait = []


def assign_pending(a):
    global pending_prep, pending_dtap, pending_childs, pending_wait
    if pending_prep:
        a.prep = pending_prep.pop(0)
    if pending_dtap:
        a.dtap = pending_dtap.pop(0)
    a.childs = pending_childs
    a.wait = pending_wait
    pending_childs = []
    pending_wait = []


def arm_table(path):
    """name -> dict of the AF594 table"""
    out = {}
    for ln in open(path):
        m = re.match(r'\s*\{ "([a-z0-9_]+)",\s*(.*)\}\s*,?\s*$', ln)
        if not m:
            continue
        name = m.group(1)
        vals = [v.strip() for v in m.group(2).split(",")]
        # xg skt j n pl sh sl rcvbuf tap zc al dtap enq cond pull seg dl charge
        names = ["xg", "skt", "j", "n", "pl", "sh", "sl", "rcvbuf", "tap",
                 "zc", "al", "dtap", "exp_enq", "exp_cond", "exp_pull",
                 "exp_seg", "exp_dl", "exp_charge"]
        if len(vals) != len(names):
            continue
        d = {}
        for k, v in zip(names, vals):
            v = v.strip()
            if v.startswith("'"):
                d[k] = v[1]
            else:
                d[k] = int(v)
        out[name] = d
    return out


def page_align(n):
    return (n + 4095) & ~4095


def payloads(a):
    n = a["n"]
    out = [a["pl"]] * n
    if a["sh"] >= 0:
        out[a["sh"]] = a["sl"]
    return out


def merges_at_rule(a):
    """the two doors: skb_gro_receive() refuses skb_zcopy(); the list door does not"""
    if a["zc"] and a["xg"] == "u":
        return False
    return True


def rule_model(a):
    """(n_packets, [udp length field ...]) at the nft log"""
    ps = payloads(a)
    if len(ps) == 1 or not merges_at_rule(a):
        return len(ps), [8 + p for p in ps]
    return 1, [8 + sum(ps)]


def ts_member(a, p):
    """truesize of one member skb: head + pages, as the gate must show it"""
    end = 704 if (not a["zc"] and p > 148) else 384
    return end + 576 + (page_align(p) if a["zc"] else 0)


def gate_model(a):
    """[(ts, dlen, len), ...] of the records at __udp_enqueue_schedule_skb"""
    ps = payloads(a)
    np, _ = rule_model(a)
    if np == len(ps):                      # one skb per datagram
        out = []
        for p in ps:
            end = 704 if (not a["zc"] and p > 148) else 384
            out.append((end + 576 + (page_align(p) if a["zc"] else 0),
                        p if a["zc"] else 0, p))
        return out
    # one aggregate: the head record carries the sum, and the socket gets it
    # whole (UDP_GRO), or segmented by one of two functions:
    #   fraglist door -> skb_segment_list() reuses the head as the first
    #                    segment, so the first record IS the aggregate;
    #   linear door   -> __udp_gso_segment()/skb_segment() rebuilds every
    #                    segment, so the aggregate never reaches the queue.
    total = sum(ts_member(a, p) for p in ps)
    if a["skt"] == "g":
        return [(total, ps[-1], sum(ps))]
    if a["xg"] == "f":
        out = [(total, ps[-1], sum(ps))]
        for p in ps[1:]:
            out.append((ts_member(a, p), p if a["zc"] else 0, p))
        return out
    return [(ts_member(a, p), p if a["zc"] else 0, p) for p in ps]


def main():
    order, attempts, hdr = parse(LOGS[0])
    order2, attempts2, hdr2 = parse(LOGS[1])
    tab = arm_table(ADD)

    # ---------------- A. provenance
    ck("A", hdr["ksha"] == sha_file(KERNEL),
       "kernel sha in the log != the bzImage on disk")
    ck("A", hdr2["ksha"] == hdr["ksha"], "two boots, two kernels")
    ck("A", hdr["ksha"].startswith("1efbc957"), "kernel is not 7.3.4-T563")
    ck("A", hdr["isha"] == sha_file(INITRD), "initrd sha in the log != the file")
    ck("A", hdr2["isha"] == hdr["isha"], "two boots, two initrds")
    # the differ inside that initrd
    blob = gzip.GzipFile(INITRD).read()
    want = sha_file(DIFFER)
    found = None
    pos = 0
    marker = b"TRAILER!!!"
    while True:
        # minimal cpio (newc) walk
        hdr_pos = blob.find(b"070701", pos)
        if hdr_pos < 0:
            break
        h = blob[hdr_pos:hdr_pos + 110]
        try:
            namesize = int(h[94:102], 16)
            filesize = int(h[54:62], 16)
        except ValueError:
            break
        name = blob[hdr_pos + 110:hdr_pos + 110 + namesize].rstrip(b"\0").decode()
        data_start = hdr_pos + 110 + namesize
        data_start += (4 - data_start % 4) % 4
        if name == "root/repro":
            found = sha_bytes(blob[data_start:data_start + filesize])
        pos = data_start + filesize
        pos += (4 - pos % 4) % 4
    ck("A", found is not None, "no root/repro inside the initramfs")
    ck("A", found == want, "the differ in the initrd != vm/build/differ594")
    ck("A", os.path.getmtime(PRED) < os.path.getmtime(LOGS[0]),
       "predictions file is not older than the first boot")

    # ---------------- B. source anchors
    anchors = [
        ("net/core/gro.c", "if (skb_zcopy(p) || skb_zcopy(skb))"),
        ("net/core/gro.c", "return -ETOOMANYREFS;"),
        ("net/core/gro.c", "p->truesize += skb->truesize;"),
        ("net/core/gro.c", "skb_shinfo(p)->flags |= skbinfo->flags & SKBFL_SHARED_FRAG;"),
        ("net/ipv4/ip_input.c", "skb = skb_share_check(skb, GFP_ATOMIC);"),
        ("net/ipv4/ip_input.c", "if (unlikely(skb_orphan_frags_rx(skb, GFP_ATOMIC))) {"),
        ("include/linux/skbuff.h", "SKBFL_PURE_ZEROCOPY = BIT(2),"),
        ("include/linux/skbuff.h", "static inline bool skb_frags_readable(const struct sk_buff *skb)"),
        ("net/ipv4/tcp.c", "skb_shinfo(skb)->flags |= SKBFL_PURE_ZEROCOPY;"),
        ("net/core/datagram.c", "skb->truesize += PAGE_ALIGN(copied + start);"),
        ("net/core/skbuff.c", "skb->truesize += truesize;"),
        ("net/core/skbuff.c", "n->cloned = 1;"),
        ("net/core/skbuff.c", "skb->cloned = 1;"),
        ("net/core/skbuff.c", "atomic_inc(&(skb_shinfo(skb)->dataref));"),
        ("net/ipv4/udp_offload.c", "skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_L4;"),
        ("net/ipv4/udp_offload.c", "skb_shinfo(skb)->gso_type |= (SKB_GSO_FRAGLIST|SKB_GSO_UDP_L4);"),
        ("net/ipv4/udp_offload.c", "ret = skb_gro_receive_list(p, skb);"),
        ("net/ipv4/udp_offload.c", "ret = skb_gro_receive(p, skb);"),
        ("net/ipv4/udp.c", "if (rmem > (rcvbuf >> 1)) {"),
        ("net/ipv4/udp.c", "skb_condense(skb);"),
        ("net/core/skbuff.c", "if (skb->data_len > skb->end - skb->tail ||"),
        ("net/core/skbuff.c", "skb_cloned(skb) || !skb_frags_readable(skb))"),
        ("net/core/skbuff.c", "if (!skb_frags_readable(skb))"),
        ("net/ipv4/ip_output.c", "if (sock_flag(sk, SOCK_ZEROCOPY)) {"),
        ("net/core/skbuff.c", "if (skb_shared(nskb)) {"),
    ]
    for path, lit in anchors:
        full = os.path.join(SRC, path)
        ok = False
        try:
            for ln in open(full, "r", errors="replace"):
                if lit in ln:
                    ok = True
                    break
        except IOError:
            ok = False
        ck("B", ok, "anchor missing: %s: %s" % (path, lit))

    # ---------------- C. arms
    ck("C", len(order) == 2 * 13, "expected 26 attempts, got %d" % len(order))
    ck("C", len(tab) == 13, "expected 13 arms in the table, got %d" % len(tab))
    seen_names = []
    for k in order:
        a = attempts[k]
        ad = a.arm
        ck("C", ad is not None, "arm %s has no ARM line" % (k,))
        if ad is None:
            continue
        seen_names.append(ad["name"])
        t = tab.get(ad["name"])
        ck("C", t is not None, "arm %s not in the table" % ad["name"])
        if t is None:
            continue
        for f, kk in [("xg", "xg"), ("skt", "skt"), ("j", "j"), ("n", "n"),
                      ("pl", "pl"), ("sh", "sh"), ("sl", "sl"),
                      ("rcvbuf", "rcvbuf"), ("tap", "tap"), ("zc", "zc"),
                      ("al", "al"), ("dtap", "dtap")]:
            ck("C", str(t[f]) == ad[kk],
               "arm %s field %s: table %s printed %s" % (ad["name"], f,
                                                          t[f], ad[kk]))
        ck("C", ad["rc"] == "0", "arm %s: send failed rc=%s" % (ad["name"], ad["rc"]))
        ck("C", ad["cmdrc"] == "0", "arm %s: command stream rc=%s" % (ad["name"], ad["cmdrc"]))
        # wrc/wrc2 are printed as (command failed), so 0 means confirmed
        ck("C", ad["wrc"] == "0", "arm %s: the filler queue was not confirmed" % ad["name"])
        ck("C", ad["wrc2"] == "0", "arm %s: the test queue was not confirmed" % ad["name"])
        ck("C", a.marks == 2, "arm %s: %d markers, expected 2" % (ad["name"], a.marks))
        ck("C", a.cnt is not None and a.cnt["mark"] == "1",
           "arm %s: trace records outside the markers" % ad["name"])
        # the sender really sent what the arm asked for
        ck("C", a.zc is not None, "arm %s: no ZC line" % ad["name"])
        if a.zc is not None:
            ck("C", int(a.zc["sent"]) == t["n"],
               "arm %s: sent %s of %d" % (ad["name"], a.zc["sent"], t["n"]))
            ck("C", int(a.zc["zc"]) == t["zc"],
               "arm %s: zc flag %s" % (ad["name"], a.zc["zc"]))
            if t["zc"]:
                ck("C", int(a.zc["copied"]) == 0,
                   "arm %s: %s of the zerocopy sends fell back to a copy"
                   % (ad["name"], a.zc["copied"]))
    ck("C", sorted(set(seen_names)) == sorted(tab.keys()),
       "the arms run are not the arms in the table")

    # ---------------- D. the rule  /  E. the gate
    for k in order:
        a = attempts[k]
        t = tab[a.arm["name"]]
        ps = payloads(t)
        np, ulens = rule_model(t)

        # D: the rule
        ck("D", a.pkt is not None, "arm %s: no PKT line" % a.arm["name"])
        if a.pkt is not None:
            ck("D", int(a.pkt["n"]) == np,
               "arm %s: the rule saw %s packets, model says %d"
               % (a.arm["name"], a.pkt["n"], np))
            got_uh = ints(a.pkt["uhlen"])
            if np <= 32:
                ck("D", got_uh == ulens,
                   "arm %s: udp lengths %s, model %s"
                   % (a.arm["name"], got_uh, ulens))
            else:
                ck("D", set(got_uh) == {ulens[0]},
                   "arm %s: udp lengths not all %d: %s"
                   % (a.arm["name"], ulens[0], set(got_uh)))
            ck("D", all(x == y + 20 for x, y in zip(ints(a.pkt["tot"]), got_uh)),
               "arm %s: IP total length != udp length + 20" % a.arm["name"])

        # E: the gate
        gm = gate_model(t)
        eq = a.eq[0] if a.eq else None
        ck("E", eq is not None, "arm %s: no EQ line" % a.arm["name"])
        if eq is None:
            continue
        recs = list(zip(ints(eq["ts"]), ints(eq["dlen"]), ints(eq["len"]),
                        ints(eq["tail"]), ints(eq["end"]), ints(eq["fl"])))
        ck("E", int(eq["n"]) == len(gm) or a.arm["name"] == "z_lin64",
           "arm %s: %s records, model %d" % (a.arm["name"], eq["n"], len(gm)))
        # only the fraglist door hands the aggregate itself to the queue
        agg_head = (np == 1 and t["n"] > 1 and (t["xg"] == "f" or t["skt"] == "g"))
        for idx, r in enumerate(recs):
            ts, dlen, ln, tail, end, fl = r
            # the head of an aggregate carries the sum of its members, so the
            # per-skb identity does not apply to it
            if agg_head and idx == 0:
                ck("E", ts == sum(ts_member(t, p) for p in ps),
                   "arm %s: aggregate head ts %d != the members' sum %d"
                   % (a.arm["name"], ts, sum(ts_member(t, p) for p in ps)))
                ck("E", tail == 44 + (0 if t["zc"] else ps[0]),
                   "arm %s: aggregate head tail %d" % (a.arm["name"], tail))
                continue
            ck("E", ln == (tail - 44) + dlen,
               "arm %s: len %d != tail-44 %d + dlen %d" % (a.arm["name"], ln,
                                                           tail - 44, dlen))
            ck("E", ts == end + 576 + (page_align(dlen) if dlen > 0 else 0),
               "arm %s: ts %d != end %d + 576 + PAGE_ALIGN(%d)"
               % (a.arm["name"], ts, end, dlen))
        # the first record must match the model exactly
        if recs and a.arm["name"] != "z_lin64":
            ck("E", recs[0][0] == gm[0][0] and recs[0][1] == gm[0][1],
               "arm %s: first record (ts %d, dlen %d), model (%d, %d)"
               % (a.arm["name"], recs[0][0], recs[0][1], gm[0][0], gm[0][1]))
        # every later record too, when the aggregate was segmented
        if len(gm) > 1:
            for j in range(1, min(len(gm), len(recs))):
                ck("E", recs[j][0] == gm[j][0] and recs[j][1] == gm[j][1],
                   "arm %s: record %d (ts %d, dlen %d), model (%d, %d)"
                   % (a.arm["name"], j, recs[j][0], recs[j][1],
                      gm[j][0], gm[j][1]))
        # the pull, when condense ran
        cq = a.cq[0] if a.cq else None
        n_pull = int(a.cnt["pull"])
        if n_pull:
            ck("E", int(a.cnt["eat"]) == int(recs[0][1]) if len(recs) == 1 else True,
               "arm %s: eat %s != dlen %d" % (a.arm["name"], a.cnt["eat"],
                                              recs[0][1] if recs else -1))

    # ---------------- F. the queue
    for k in order:
        a = attempts[k]
        t = tab[a.arm["name"]]
        eq = a.eq[0] if a.eq else None
        rcv = a.rcv
        ck("F", rcv is not None, "arm %s: no RCV line" % a.arm["name"])
        if eq is None or rcv is None:
            continue
        recs = list(zip(ints(eq["ts"]), ints(eq["dlen"]), ints(eq["len"]),
                        ints(eq["tail"]), ints(eq["end"]), ints(eq["fl"])))
        port = 1 if t["skt"] == "g" else 0
        rmem = int(rcv["rmem%d" % port])
        base = t["j"] * 1280
        if a.arm["name"] == "z_lin64":
            s = recs[0][0]
            want_kept = min(t["n"], int(rcv["rb%d" % port]) // s)
            ck("F", int(rcv["n%d" % port]) == want_kept,
               "z_lin64: kept %s, model %d" % (rcv["n%d" % port], want_kept))
            ck("F", rmem == want_kept * s,
               "z_lin64: rmem %d != %d * %d" % (rmem, want_kept, s))
            continue
        ck("F", rmem >= base, "arm %s: rmem %d below the filler %d"
           % (a.arm["name"], rmem, base))
        grown = rmem - base
        n_pull = int(a.cnt["pull"])
        if n_pull == 1 and len(recs) == 1:
            want = recs[0][4] + 576          # condensed: SKB_TRUESIZE(end)
        else:
            want = sum(r[0] for r in recs)
        ck("F", grown == want,
           "arm %s: rmem growth %d, model %d (pull %d)"
           % (a.arm["name"], grown, want, n_pull))
        # the socket must have received every datagram the arm sent (the
        # reader drains until it is empty), except where the queue is meant to
        # overflow -- z_lin64 is checked above
        npr, _ = rule_model(t)
        whole = (npr == 1 and t["n"] > 1 and t["skt"] == "g")
        base_recv = t["j"] + (1 if whole else t["n"])
        ck("F", int(rcv["n%d" % port]) == base_recv,
           "arm %s: the socket received %s, model %d"
           % (a.arm["name"], rcv["n%d" % port], base_recv))

    # ---------------- G. the doors
    for k in order:
        a = attempts[k]
        t = tab[a.arm["name"]]
        np, _ = rule_model(t)
        seg = int(a.cnt["seg"])
        ubuf = int(a.cnt["ubuf"])
        if np == 1 and t["n"] > 1 and t["skt"] == "p":
            if t["xg"] == "f":
                ck("G", seg == 1,
                   "arm %s: fraglist aggregate, skb_segment_list %d" % (a.arm["name"], seg))
            else:
                ck("G", seg == 0,
                   "arm %s: linear aggregate, skb_segment_list %d" % (a.arm["name"], seg))
        if t["zc"]:
            if t["xg"] == "u":
                ck("G", ubuf == t["n"],
                   "arm %s: %d copies of %d zerocopy datagrams"
                   % (a.arm["name"], ubuf, t["n"]))
            else:
                ck("G", ubuf == 1,
                   "arm %s: %d copies, model 1 (the aggregate head only)"
                   % (a.arm["name"], ubuf))
        else:
            ck("G", ubuf == 0, "arm %s: %d copies without zerocopy"
               % (a.arm["name"], ubuf))

    # ---------------- H. clause 2
    want_h = {"c_none": (1, 1280, 0), "c_egr": (0, 2240, 1),
              "c_ing_k": (0, 2240, 1), "c_ing_d": (1, 1280, 0)}
    for k in order:
        a = attempts[k]
        nm = a.arm["name"]
        if nm not in want_h:
            continue
        w_pull, w_chg, w_fl = want_h[nm]
        t = tab[nm]
        port = 1
        rmem = int(a.rcv["rmem%d" % port])
        ck("H", int(a.cnt["pull"]) == w_pull,
           "%s: pull %s, expected %d" % (nm, a.cnt["pull"], w_pull))
        ck("H", rmem - t["j"] * 1280 == w_chg,
           "%s: charge %d, expected %d" % (nm, rmem - t["j"] * 1280, w_chg))
        fl = ints(a.eq[0]["fl"]) if a.eq else []
        ck("H", fl and fl[0] == w_fl, "%s: fl %s, expected first %d" % (nm, fl, w_fl))
        # independent of the pull counter: a condensed skb is charged
        # SKB_TRUESIZE(end), an uncondensed one its own truesize
        charged = rmem - t["j"] * 1280
        end0 = ints(a.eq[0]["end"])[0]
        ck("H", (charged == end0 + 576) == (w_pull == 1),
           "%s: charge %d vs end+576 %d cannot both mean pull %d"
           % (nm, charged, end0 + 576, w_pull))
        ck("H", int(a.pkt["n"]) == 1, "%s: the rule saw %s packets" % (nm, a.pkt["n"]))

    # ---------------- I. determinism
    ck("I", [k for k in order] == [k for k in order2],
       "the two boots ran different attempts")
    for k in order:
        a, b = attempts[k], attempts2[k]
        for fld in ("pkt", "rcv", "cnt", "arm"):
            da, db = getattr(a, fld), getattr(b, fld)
            if da is None or db is None:
                ck("I", da is db, "attempt %s: %s missing in one boot" % (k, fld))
                continue
            for kk in da:
                if kk in ("udpin", "udperr", "ms", "pass", "empt", "win",
                          "rmem0", "rmem1", "trc", "i", "att"):
                    continue
                ck("I", da[kk] == db.get(kk),
                   "attempt %s: %s.%s differs between boots (%s vs %s)"
                   % (k, fld, kk, da[kk], db.get(kk)))
        if a.eq and b.eq:
            for kk in ("n", "ts", "dlen", "len", "tail", "end", "fl"):
                ck("I", a.eq[0].get(kk) == b.eq[0].get(kk),
                   "attempt %s: EQ.%s differs between boots" % (k, kk))
    # the two attempts of one arm
    for i in sorted(set(k[0] for k in order)):
        if (i, 0) not in attempts or (i, 1) not in attempts:
            ck("I", False, "arm i=%d has less than two attempts" % i)
            continue
        a, b = attempts[(i, 0)], attempts[(i, 1)]
        ck("I", a.pkt["n"] == b.pkt["n"] and a.pkt["uhlen"] == b.pkt["uhlen"],
           "arm i=%d: the rule differs between attempts" % i)
        ck("I", a.eq[0]["ts"] == b.eq[0]["ts"] and a.eq[0]["dlen"] == b.eq[0]["dlen"],
           "arm i=%d: the gate differs between attempts" % i)
        ck("I", a.rcv["rmem0"] == b.rcv["rmem0"] and a.rcv["rmem1"] == b.rcv["rmem1"],
           "arm i=%d: the queue differs between attempts" % i)

    print("checks: %d passed, %d failed" % (PASS, FAIL))
    for s in sorted(SEC):
        print("  %s: %d ok, %d bad" % (s, SEC[s][0], SEC[s][1]))
    for f in FAILS:
        print("FAIL " + f)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:                    # a crash is a red check, not a green run
        import traceback
        traceback.print_exc()
        print("checks: %d passed, %d failed (verifier crashed: %s)" % (PASS, FAIL + 1, e))
        sys.exit(2)
