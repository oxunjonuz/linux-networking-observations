#!/usr/bin/env python3
"""verify593.py -- the independent check of turn 593 (F71).

The turn had one question: can clause 1 of skb_condense()

    if (skb->data_len) {
            if (skb->data_len > skb->end - skb->tail ||
                skb_cloned(skb) || !skb_frags_readable(skb))
                    return;
            __pskb_pull_tail(skb, skb->data_len);
    }

ever be the thing that decides, and at which byte?  F70 measured that no skb
with data_len > 0 reached the gate at all in 36 attempts.  This checks that the
new instrument produces one, and that the decision on it is a measured cell:

  * PROVENANCE.  kernel sha256 in the log == the file on disk; initrd sha256 in
    the log == the file on disk; the differ EXTRACTED FROM THE INITRAMFS ==
    vm/build/differ593; research/predictions_593.md == the frozen file
    (sha256 taken before the first boot, recorded below).
  * THE SOURCE.  Anchors in the 7.3.4-T563 tree on which the whole reading
    rests: skb_condense's three clauses and its unconditional truesize reset;
    __pskb_pull_tail's `tail += delta; data_len -= delta`; the strict `>` in the
    queue branch; udp_unexpected_gso() refusing SKB_GSO_FRAGLIST unless
    ACCEPT_FRAGLIST; UDP_GRO setting ACCEPT_L4 only; udp_allow_gso() (the only
    setter of ACCEPT_FRAGLIST) called from tunnel drivers only; and
    skb_gro_receive()'s `p->data_len += len` with `delta_truesize = skb->truesize`.
  * THE OFFSETS.  pahole, re-run here on the same vmlinux: the six offsets the
    instrument printed must be the DWARF offsets, sizeof(struct sk_buff) must
    be 232, and byte 126 bit 0 must be `cloned`.
  * THE ARM TABLE.  Parsed from vm/differ593_add.c, compared arm by arm with
    the twelve parameters the instrument printed.
  * THE QUEUE.  The filler must land exactly on j*1280, rcvbuf read back must
    be twice the request, and the queue growth must equal the truesize the
    enqueue probe reports -- or, when the pull fired, SKB_TRUESIZE(end).
  * THE GATE AND THE BRANCH.  The __udp_enqueue_schedule_skb record and the
    skb_condense record of the same skb must agree on len, data_len, tail, end,
    truesize and `cloned`: the gate and the branch see one skb.
  * THE DECISION.  On every condense record the model decides:
        pull  <=>  data_len > 0  and  data_len <= end - tail  and  not cloned
    and the model's answer must equal the measured number of __pskb_pull_tail
    calls, and the eaten count must equal data_len.
  * THE TAP.  Two arms differ in nothing but the parent's y1/y2 taps:
    g_t512_147 (closed) and g_t512_147t (open).  The open one must show
    cloned == 1, pull == 0, charge 2240; the closed one cloned == 0, pull == 1,
    charge 1280.  That is the whole of clause 2, and the whole of why F70 never
    saw clause 1.
  * THE BYTE.  Three head sizes, three tailrooms, three boundaries:
    512 -> 148/149, 200 -> 140/141, 1200 -> 484/485.
  * DELIVERY.  What the socket receives: one datagram of the aggregate's
    length when the skb is delivered whole, n datagrams when it is segmented,
    and Udp InDatagrams rising by exactly (filler + enqueues).
  * DETERMINISM.  Both attempts of every arm, and both boots.

Usage: verify593.py [log1 log2]
"""
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
KERNEL = ROOT + "/src/linux-7.3.4-T563"
PRED = ROOT + "/research/predictions_593.md"
PRED_SHA = "6c1c79a9e9c9079e825379fd8d284116fee393e6e17d286566b5087f2d13078b"
SRC_ADD = ROOT + "/vm/differ593_add.c"
LOGS = [ROOT + "/logs/f71_rep1.log", ROOT + "/logs/f71_rep2.log"]
INITRD = ROOT + "/vm/initrd593/full.cpio.gz"
BIN = ROOT + "/vm/build/differ593"
IMG = KERNEL + "/arch/x86/boot/bzImage"

S = 1280            # SKB_TRUESIZE(end_of 512-byte datagram); measured below
TS_CONST = 576      # SKB_TRUESIZE(x) = x + 576 (F67, re-derived in F70)
SKB_HEAD = 232      # sizeof(struct sk_buff), pahole; SKB_DATA_ALIGN -> 256
END = {512: 704, 200: 384, 1200: 1728}   # measured/predicted ends, checked below

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
    return cond


def note(s):
    NOTES.append(s)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def rd(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


def kv(line):
    out = {}
    for part in line.rstrip("\n").split("|")[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def ilist(s):
    return [int(x) for x in s.split(",")] if s else []


# ---------------------------------------------------------------- the arms
def parse_arms(path):
    """the arm table, straight from the instrument's own source"""
    src = rd(path)
    head = "static const struct f593_arm AF593[] = {"
    if head not in src:
        return []
    body = src.split(head, 1)[1].split("};", 1)[0]
    arms = []
    for line in body.splitlines():
        m = re.match(r'\s*\{\s*"([a-z0-9_]+)",\s*\'(\w)\',\s*\'(\w)\',\s*'
                     r'(-?\d+),\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),'
                     r'\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),'
                     r'\s*(-?\d+),\s*(-?\d+),\s*(-?\d+)\s*\}', line)
        if m:
            arms.append({
                "name": m.group(1), "xg": m.group(2), "skt": m.group(3),
                "j": int(m.group(4)), "n": int(m.group(5)),
                "pl": int(m.group(6)), "sh": int(m.group(7)),
                "sl": int(m.group(8)), "rcvbuf": int(m.group(9)),
                "tap": int(m.group(10)), "exp_enq": int(m.group(11)),
                "exp_cond": int(m.group(12)), "exp_pull": int(m.group(13)),
                "exp_seg": int(m.group(14)), "exp_dl": int(m.group(15)),
                "exp_charge": int(m.group(16)),
            })
    return arms


def parse_log(path):
    """Attempts, keyed by (arm index, attempt).  Attribution is by the line's
    OWN i=/att= fields wherever it has them (RCV, CNT, EQ, CQ, TRC); PREP and
    WAIT carry none and are attributed to the attempt whose ARM line follows
    them.  Splitting on ARM lines alone would misattribute every EQ/CQ line,
    because the instrument prints them after its own ARM line."""
    txt = rd(path)
    recs = {}
    order = []
    pending = []       # PREP/WAIT lines of the attempt being built
    cur_key = None
    for ln in txt.splitlines():
        if ln.startswith("F593 ARM|"):
            a = kv(ln)
            key = (int(a["i"]), int(a["att"]))
            rec = recs.setdefault(key, {"arm": None, "prep": [], "wait": [],
                                        "rcv": [], "cnt": [], "eq": [],
                                        "cq": [], "trc": [], "raw": []})
            rec["arm"] = a
            rec["prep"] += [kv(x) for x in pending
                            if x.startswith("F593 PREP|")]
            rec["wait"] += [kv(x) for x in pending
                            if x.startswith("F593 WAIT|")]
            pending = []
            if key not in order:
                order.append(key)
            cur_key = key
            continue
        if ln.startswith("F593 PREP|") or ln.startswith("F593 WAIT|"):
            pending.append(ln)
            continue
        if not ln.startswith("F593 "):
            continue
        head = ln.split("|")[1] if "|" in ln else ""
        m = None
        if head.startswith("i="):
            m = head
        if m:
            f = kv(ln)
            key = (int(f["i"]), int(f["att"]))
            rec = recs.setdefault(key, {"arm": None, "prep": [], "wait": [],
                                        "rcv": [], "cnt": [], "eq": [],
                                        "cq": [], "trc": [], "raw": []})
            rec["raw"].append(ln)
            if ln.startswith("F593 RCV|"):
                rec["rcv"].append(f)
            elif ln.startswith("F593 CNT|"):
                rec["cnt"].append(f)
            elif ln.startswith("F593 EQ|"):
                rec["eq"].append(f)
            elif ln.startswith("F593 CQ|"):
                rec["cq"].append(f)
            elif ln.startswith("F593 TRC|"):
                rec["trc"].append(ln)
            if key not in order:
                order.append(key)
    return recs, txt, order


def probe_records(rec, ev):
    """every f593<ev> record the dump attributed to this attempt, in order"""
    out = []
    for ln in rec["trc"]:
        if "f593%s:" % ev not in ln:
            continue
        f = {}
        tail = ln.split("f593%s:" % ev, 1)[1]
        for key in ("len", "dlen", "tail", "end", "ts", "fl", "eat"):
            m = re.search(r"\b%s=(-?\d+)" % key, tail)
            if m:
                f[key] = int(m.group(1))
        out.append(f)
    return out


# ---------------------------------------------------------------- the model
def end_of(pl):
    """skb->end of a received datagram of this payload, as measured by the
    probe on this very kernel (checked in the log before being used)"""
    if pl in END:
        return END[pl]
    # payloads below 200 get the same 704-byte chunk as 200 (measured here);
    # payloads from 201 to 512 get the 1024-byte chunk.
    return 704 if pl > 200 else 384


def ts_of(pl):
    return end_of(pl) + TS_CONST


def agg_truesize(a):
    """what the head carries into the enqueue gate.  Measured here to be the
    SUM of the datagrams' truesizes: skb_gro_receive() takes the `merge:`
    branch on this veth (head_frag 0), where delta_truesize = skb->truesize."""
    total = 0
    for k in range(a["n"]):
        pl = a["sl"] if k == a["sh"] else a["pl"]
        total += ts_of(pl)
    return total


def agg_dlen(a):
    """data_len of the aggregate: the payloads of the datagrams that were
    merged into the head (all but the first), one byte each"""
    total = 0
    for k in range(1, a["n"]):
        total += a["sl"] if k == a["sh"] else a["pl"]
    return total


def decides_pull(dlen, tailroom, cloned):
    """the kernel's own predicate, in the order the kernel asks it"""
    if not dlen:
        return False
    if dlen > tailroom or cloned:
        return False
    return True


# ---------------------------------------------------------------- the checks
def check_provenance(logs):
    pred_sha = sha(PRED)
    ck(pred_sha == PRED_SHA, "PRED_SHA",
       "%s != %s" % (pred_sha, PRED_SHA))
    init_sha = sha(INITRD)
    bin_sha = sha(BIN)
    for path in logs:
        if not os.path.exists(path):
            continue
        txt = rd(path)
        k = re.search(r"^### sha256: ([0-9a-f]{64})$", txt, re.M)
        ck(k and k.group(1) == sha(IMG), "LOG_KERNEL_SHA", path)
        i = re.search(r"^### initrd sha256: ([0-9a-f]{64})$", txt, re.M)
        ck(i and i.group(1) == init_sha, "LOG_INITRD_SHA", path)
        ck("VM_BOOT_OK" in txt, "BOOT_MARKER", path)
    # the differ, extracted from the initramfs that actually booted
    ex = subprocess.run(
        "zcat %s | cpio -i --to-stdout root/repro 2>/dev/null | sha256sum"
        % INITRD, shell=True, capture_output=True, text=True)
    got = ex.stdout.split()[0] if ex.stdout.strip() else "none"
    ck(got == bin_sha, "DIFFER_FROM_INITRAMFS", "%s != %s" % (got, bin_sha))
    for m in ("gro",):
        ck(("/root/repro %s" % m) in subprocess.run(
            "zcat %s | cpio -i --to-stdout init 2>/dev/null" % INITRD,
            shell=True, capture_output=True, text=True).stdout,
           "INIT_MODE", m)


SRC_ANCHORS = [
    ("net/core/skbuff.c", "if (skb->data_len > skb->end - skb->tail ||"),
    ("net/core/skbuff.c", "skb_cloned(skb) || !skb_frags_readable(skb))"),
    ("net/core/skbuff.c", "__pskb_pull_tail(skb, skb->data_len);"),
    ("net/core/skbuff.c", "skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));"),
    ("net/core/skbuff.c", "skb->tail     += delta;"),
    ("net/core/skbuff.c", "skb->data_len -= delta;"),
    ("net/ipv4/udp.c", "if (rmem + size > rcvbuf) {"),
    ("net/ipv4/udp.c", "if (rmem > (rcvbuf >> 1)) {"),
    ("net/ipv4/udp.c", "skb_condense(skb);"),
    ("net/ipv4/udp.c", "size = skb->truesize;"),
    ("net/ipv4/udp.c", "udp_assign_bit(GRO_ENABLED, sk, valbool);"),
    ("net/ipv4/udp.c", "udp_assign_bit(ACCEPT_L4, sk, valbool);"),
    ("include/linux/udp.h", "static inline bool udp_unexpected_gso"),
    ("include/linux/udp.h", "skb_shinfo(skb)->gso_type & SKB_GSO_FRAGLIST &&"),
    ("include/linux/udp.h", "!udp_test_bit(ACCEPT_FRAGLIST, sk))"),
    ("include/linux/udp.h", "udp_set_bit(ACCEPT_L4, sk);"),
    ("include/linux/udp.h", "udp_set_bit(ACCEPT_FRAGLIST, sk);"),
    ("net/core/gro.c", "p->data_len += skb->len;"),
    ("net/core/gro.c", "p->data_len += len;"),
    ("net/core/gro.c", "delta_truesize = skb->truesize;"),
    ("net/ipv4/udp_offload.c",
     "skb_shinfo(skb)->gso_type |= (SKB_GSO_FRAGLIST|SKB_GSO_UDP_L4);"),
]


def check_source():
    for f, s in SRC_ANCHORS:
        t = rd(os.path.join(KERNEL, f))
        ck(s in t, "SRC_ANCHOR", "%s :: %s" % (f, s))
    # the one place that sets ACCEPT_FRAGLIST must be udp_allow_gso(), and its
    # callers must be tunnel drivers only
    g = subprocess.run(
        "grep -rln 'udp_allow_gso(' %s --include=*.c" % KERNEL,
        shell=True, capture_output=True, text=True).stdout.split()
    base = sorted(os.path.basename(x) for x in g)
    ck(base == ["bareudp.c", "geneve.c", "vxlan_core.c"], "ALLOW_GSO_CALLERS",
       str(base))
    # UDP_GRO's case block must not mention ACCEPT_FRAGLIST
    t = rd(os.path.join(KERNEL, "net/ipv4/udp.c"))
    blk = t.split("case UDP_GRO:", 1)
    ok = len(blk) == 2 and "ACCEPT_FRAGLIST" not in blk[1].split("break;", 1)[0]
    ck(ok, "UDP_GRO_NO_FRAGLIST")


def check_offsets(logs):
    ex = subprocess.run("pahole -C sk_buff %s/vmlinux" % KERNEL,
                        shell=True, capture_output=True, text=True).stdout
    got = {}
    for f in ("len", "data_len", "tail", "end", "truesize"):
        m = re.search(r"\b%s;\s+/\*\s+(\d+)\s+\d+ \*/" % f, ex)
        if m:
            got[f] = int(m.group(1))
    sz = re.search(r"/\* size:\s+(\d+)", ex)
    ck(sz and int(sz.group(1)) == SKB_HEAD, "SIZEOF_SKB", sz.group(1) if sz else "?")
    m = re.search(r"cloned:1;\s+/\*\s+126:\s+0", ex)
    ck(bool(m), "CLONED_AT_126")
    want = (got.get("len"), got.get("data_len"), got.get("tail"),
            got.get("end"), got.get("truesize"))
    ck(want == (112, 116, 188, 192, 216), "PAHOLE_OFFSETS", str(want))
    for path in logs:
        if not os.path.exists(path):
            continue
        t = rd(path)
        m = re.search(r"^F593 PROBE\|ok=1\|mask=(\w+)\|path=(\S+)\|"
                      r"off=(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)$", t, re.M)
        ck(bool(m), "PROBE_LINE", path)
        if m:
            ck(m.group(1) == "7f", "PROBE_MASK", m.group(1))
            offs = tuple(int(m.group(k)) for k in range(3, 9))
            ck(offs == (112, 116, 188, 192, 216, 126), "PROBE_OFFSETS",
               str(offs))
        # the kernel's own echo of the definitions
        for ev, frag in (("cond", "skb_condense"), ("enq",
                                                    "__udp_enqueue_schedule_skb")):
            ck(("F593 DEF|p:kprobes/f593%s %s len=+112(%%di)" % (ev, frag))
               in t or ("F593 DEF|p:kprobes/f593%s %s len=+112(%%si)"
                        % (ev, frag)) in t, "KERNEL_ECHO", ev)
        ck("F593 DEF|p:kprobes/f593pull __pskb_pull_tail eat=%si:s32" in t,
           "KERNEL_ECHO_PULL")


def main():
    logs = sys.argv[1:] or LOGS
    arms = parse_arms(SRC_ADD)
    ck(len(arms) == 18, "ARM_TABLE_LEN", str(len(arms)))
    check_provenance(logs)
    check_source()
    check_offsets(logs)

    per_log = {}
    for path in logs:
        if not os.path.exists(path):
            ck(False, "LOG_MISSING", path)
            continue
        recs, txt, order = parse_log(path)
        per_log[path] = (recs, txt, order)
        ck(len(recs) == 2 * len(arms), "ATTEMPT_COUNT",
           "%s: %d" % (path, len(recs)))

    for path, (recs, txt, order) in per_log.items():
        tag = os.path.basename(path)
        # ---------------- the arm table against the printed parameters
        for (i, att), rec in recs.items():
            a = rec["arm"]
            if not a:
                ck(False, "ARM_MISSING", "%s i=%d att=%d" % (tag, i, att))
                continue
            A = arms[i]
            for k in ("name", "xg", "skt", "j", "n", "pl", "sh", "sl",
                      "rcvbuf", "tap", "exp_enq", "exp_cond", "exp_pull",
                      "exp_seg", "exp_dl", "exp_charge"):
                v = A[k]
                gv = a[k]
                if isinstance(v, int):
                    ck(int(gv) == v, "ARM_PARAM", "%s i=%d %s" % (tag, i, k))
                else:
                    ck(gv == v, "ARM_PARAM", "%s i=%d %s" % (tag, i, k))

        # ---------------- per attempt
        for (i, att), rec in sorted(recs.items()):
            if not rec["arm"]:
                continue
            A = arms[i]
            w = "%s i=%02d att=%d %s" % (tag, i, att, A["name"])
            port = 5001 if A["skt"] == "g" else 5000
            exp_f = A["j"] * S
            # the buffer
            ck(len(rec["prep"]) == 1, "PREP_COUNT", w)
            if rec["prep"]:
                p = rec["prep"][0]
                ck(int(p["req"]) == A["rcvbuf"], "PREP_REQ", w)
                ck(int(p["rb0"]) == 2 * A["rcvbuf"], "PREP_RB0", w)
                ck(int(p["rb1"]) == 2 * A["rcvbuf"], "PREP_RB1", w)
                ck(int(p["rmem0"]) == 0, "PREP_RMEM0", w)
                ck(int(p["d0"]) == 0 and int(p["d1"]) == 0, "PREP_DRAIN", w)
            # the queue, exactly where the model says
            ck(len(rec["wait"]) == 2, "WAIT_COUNT", w)
            if len(rec["wait"]) == 2:
                w1, w2 = rec["wait"]
                ck(int(w1["port"]) == port, "WAIT_PORT", w)
                ck(int(w1["want"]) == (exp_f if A["j"] else -1), "WAIT_WANT", w)
                ck(int(w1["ok"]) == 1, "WAIT_OK1", w)
                ck(int(w1["rmem"]) == exp_f, "WAIT_RMEM",
                   "%s %s != %d" % (w, w1["rmem"], exp_f))
                ck(int(w2["ok"]) == 1, "WAIT_OK2", w)
            # the counters
            ck(len(rec["cnt"]) == 1, "CNT_COUNT", w)
            ck(len(rec["rcv"]) == 1, "RCV_COUNT", w)
            if not (rec["cnt"] and rec["rcv"]):
                continue
            c = rec["cnt"][0]
            r = rec["rcv"][0]
            ck(int(c["mark"]) == 1, "MARK", w)
            ck(int(c["enq"]) == A["exp_enq"], "ENQ", "%s %s" % (w, c["enq"]))
            ck(int(c["cond"]) == A["exp_cond"], "COND", "%s %s" % (w, c["cond"]))
            ck(int(c["seg"]) == A["exp_seg"], "SEG", "%s %s" % (w, c["seg"]))
            ck(int(c["trim"]) == 0, "TRIM_ZERO", w)

            # the gate record and the branch record must be one skb
            eq = rec["eq"][0] if rec["eq"] else None
            cq = rec["cq"][0] if rec["cq"] else None
            if eq:
                ck(int(eq["n"]) == A["exp_enq"], "EQ_N", w)
                # byte 126: cloned.0 nohdr.1 fclone.2..3 peeked.4 head_frag.5.
                # Every skb this instrument delivers has head_frag clear -- the
                # reason skb_gro_receive() takes the `merge:` branch and charges
                # the FULL truesize of every merged datagram.
                for f in ilist(eq["fl"]):
                    ck((f & 0x20) == 0, "NO_HEAD_FRAG", "%s fl=%d" % (w, f))
                ck(ilist(eq["dlen"])[0] == A["exp_dl"], "EQ_DLEN",
                   "%s %s" % (w, eq["dlen"]))
                # the gate sees the skb BEFORE skb_condense(): the head of a
                # fraglist aggregate or a whole-delivered aggregate carries
                # the sum of the datagrams' truesizes; a fresh segment built
                # by skb_segment() carries one datagram's worth.
                if A["xg"] == "f" or A["exp_enq"] == 1:
                    ts_model = agg_truesize(A)
                else:
                    ts_model = ts_of(A["pl"])
                ck(ilist(eq["ts"])[0] == ts_model, "EQ_TS",
                   "%s %s vs %d" % (w, eq["ts"], ts_model))
            if eq and cq:
                e0 = {k: ilist(eq[k])[0] for k in
                      ("len", "dlen", "tail", "end", "ts", "fl")}
                c0 = {k: ilist(cq[k])[0] for k in
                      ("len", "dlen", "tail", "end", "ts", "fl")}
                ck(e0 == c0, "GATE_EQ_BRANCH", "%s %s %s" % (w, e0, c0))
            # the decision, from the record alone
            if cq:
                dlen = ilist(cq["dlen"])[0]
                tail = ilist(cq["tail"])[0]
                end = ilist(cq["end"])[0]
                fl = ilist(cq["fl"])[0]
                ck(tail <= end, "TAIL_LE_END", w)
                want_pull = decides_pull(dlen, end - tail, fl)
                got_pull = int(c["pull"])
                ck(want_pull == (got_pull > 0), "DECISION",
                   "%s dlen=%d room=%d cloned=%d want=%s got=%d"
                   % (w, dlen, end - tail, fl, want_pull, got_pull))
                if got_pull:
                    ck(int(c["eat"]) == dlen, "EAT", "%s %s vs %d"
                       % (w, c["eat"], dlen))
                ck(got_pull == A["exp_pull"], "PULL", "%s %s" % (w, c["pull"]))
            else:
                ck(int(c["pull"]) == 0, "PULL_NOCOND", w)

            # the queue: growth == the truesize the probe reported, or
            # SKB_TRUESIZE(end) when the pull rewrote it
            dv = int(r["rmem1" if A["skt"] == "g" else "rmem0"])
            growth = dv - exp_f
            ck(growth == A["exp_charge"], "CHARGE", "%s %d != %d"
               % (w, growth, A["exp_charge"]))
            if cq and A["exp_enq"] == 1:
                # one enqueue: the charge is that skb's truesize, rewritten
                # to SKB_TRUESIZE(end) when the pull fired
                end = ilist(cq["end"])[0]
                pulled = int(c["pull"]) > 0
                model = end + TS_CONST if pulled else ilist(cq["ts"])[0]
                ck(growth == model, "CHARGE_MODEL",
                   "%s growth=%d model=%d" % (w, growth, model))

            # what the socket receives
            n1 = int(r["n1"] if A["skt"] == "g" else r["n0"])
            hl1 = ilist(r["hl1"] if A["skt"] == "g" else r["hl0"])
            if A["exp_enq"] == 1:
                ck(n1 == A["j"] + 1, "RCV_WHOLE_N", "%s %d" % (w, n1))
                if eq:
                    ck(hl1[1] == ilist(eq["len"])[0], "RCV_WHOLE_LEN",
                       "%s %s vs %s" % (w, hl1, eq["len"]))
            else:
                ck(n1 == A["j"] + A["n"], "RCV_SEG_N", "%s %d" % (w, n1))
                ck(hl1[1] == (A["sl"] if A["sh"] >= 0 else A["pl"]),
                   "RCV_SEG_LEN", "%s %s" % (w, hl1))
            ck(int(r["rmem0"]) == 0 if A["skt"] == "g" else True,
               "OTHER_SOCKET_EMPTY", w)
            ck(int(r["udperr"]) == 0, "UDPERR_ZERO", w)

        # ---------------- Udp InDatagrams rises by exactly what was enqueued
        prev = None
        for key in order:
            if not recs[key]["rcv"]:
                ck(False, "RCV_MISSING", "%s %s" % (tag, key))
                continue
            r = recs[key]["rcv"][0]
            cur = int(r["udpin"])
            if prev is not None:
                A = arms[key[0]]
                want = A["j"] + A["exp_enq"]
                ck(cur - prev == want, "UDPIN_DELTA",
                   "%s %s: %d vs %d" % (tag, key, cur - prev, want))
            prev = cur

        # ---------------- the boundaries, named one by one
        def cell(name):
            for (i, att), rec in recs.items():
                if rec["arm"] and arms[i]["name"] == name:
                    return rec
            return None

        for lo, hi in (("g_t512_147", "g_t512_149"),
                       ("g_t200_140", "g_t200_141"),
                       ("g_t1200_484", "g_t1200_485")):
            a, b = cell(lo), cell(hi)
            ck(a is not None and b is not None, "BOUNDARY_PRESENT", lo)
            if a and b:
                ck(int(a["cnt"][0]["pull"]) == 1, "BOUNDARY_PULLS", lo)
                ck(int(b["cnt"][0]["pull"]) == 0, "BOUNDARY_RETURNS", hi)

        # ---------------- the tap cell
        for (i, att), rec in recs.items():
            if not rec["arm"]:
                continue
            A = arms[i]
            if A["name"] == "g_t512_147t":
                if not (rec["cq"] and rec["cnt"] and rec["rcv"]):
                    ck(False, "TAP_RECORDS", "%s i=%02d att=%d" % (tag, i, att))
                    continue
                cq = rec["cq"][0]
                ck(ilist(cq["fl"])[0] == 1, "TAP_CLONED", tag)
                ck(int(rec["cnt"][0]["pull"]) == 0, "TAP_NO_PULL", tag)
                ck(int(rec["cnt"][0]["clone"]) > 0, "TAP_CLONE_CALLS", tag)
                ck(int(rec["rcv"][0]["rmem1"]) - 16 * S == 2240, "TAP_CHARGE",
                   tag)
            if A["name"] == "g_t512_147":
                if not (rec["cq"] and rec["cnt"]):
                    ck(False, "NOTAP_RECORDS", "%s i=%02d att=%d" % (tag, i, att))
                    continue
                cq = rec["cq"][0]
                ck(ilist(cq["fl"])[0] == 0, "NOTAP_NOT_CLONED", tag)
                ck(int(rec["cnt"][0]["pull"]) == 1, "NOTAP_PULLS", tag)
                ck(int(rec["cnt"][0]["clone"]) == 0, "NOTAP_NO_CLONES", tag)

        # ---------------- the aggregate of six: clause 1 alone
        for (i, att), rec in recs.items():
            if not rec["arm"]:
                continue
            if arms[i]["name"] == "g_pg6_gt":
                if not (rec["cq"] and rec["cnt"] and rec["rcv"]):
                    ck(False, "PG6_RECORDS", "%s i=%02d att=%d" % (tag, i, att))
                    continue
                cq = rec["cq"][0]
                ck(ilist(cq["dlen"])[0] == 2560, "PG6_DLEN", tag)
                ck(ilist(cq["fl"])[0] == 0, "PG6_NOT_CLONED", tag)
                ck(ilist(cq["end"])[0] - ilist(cq["tail"])[0] == 148,
                   "PG6_ROOM", tag)
                ck(int(rec["cnt"][0]["pull"]) == 0, "PG6_CLAUSE1_RETURNS", tag)
                ck(int(rec["rcv"][0]["rmem1"]) - 16 * S == 7680, "PG6_CHARGE",
                   tag)
            if arms[i]["name"] == "g_pg6_lo":
                if not (rec["cnt"] and rec["rcv"]):
                    ck(False, "PG6LO_RECORDS", "%s i=%02d att=%d" % (tag, i, att))
                    continue
                ck(int(rec["cnt"][0]["cond"]) == 0, "PG6LO_NO_CONDENSE", tag)
                ck(int(rec["rcv"][0]["rmem1"]) == 7680, "PG6LO_CHARGE", tag)

        # ---------------- the fraglist on a UDP_GRO socket: P1
        for (i, att), rec in recs.items():
            if not rec["arm"]:
                continue
            if arms[i]["name"] == "g_fl_gro":
                if not (rec["cnt"] and rec["rcv"]):
                    ck(False, "FLGRO_RECORDS", "%s i=%02d att=%d" % (tag, i, att))
                    continue
                ck(int(rec["cnt"][0]["enq"]) == 6, "FLGRO_ENQ6", tag)
                ck(int(rec["cnt"][0]["seg"]) == 1, "FLGRO_SEGMENTED", tag)
                ck(int(rec["rcv"][0]["rmem1"]) - 16 * S == 7680, "FLGRO_CHARGE",
                   tag)

    # ---------------- determinism inside a boot and between boots
    for path, (recs, txt, order) in per_log.items():
        tag = os.path.basename(path)
        skip = {"pass", "empt", "ms", "t1", "tl", "udpin", "udperr", "rmem",
                "rmem0", "rmem1", "rma0", "rma1", "win", "clone", "i", "att"}
        for i in range(len(arms)):
            a = recs.get((i, 0))
            b = recs.get((i, 1))
            if not (a and b and a["arm"] and b["arm"]):
                ck(False, "DET_PAIR", "%s i=%d" % (tag, i))
                continue
            for part in ("cnt", "eq", "cq"):
                if not (a[part] and b[part]):
                    ck(bool(a[part]) == bool(b[part]), "DET_PRESENT",
                       "%s i=%d %s" % (tag, i, part))
                    continue
                x = {k: v for k, v in a[part][0].items() if k not in skip}
                y = {k: v for k, v in b[part][0].items() if k not in skip}
                ck(x == y, "DET_ATT", "%s i=%d %s %s %s" % (tag, i, part, x, y))
    if len(logs) == 2:
        r1 = per_log[logs[0]][0]
        r2 = per_log[logs[1]][0]
        for i in range(len(arms)):
            for part in ("cnt", "eq", "cq"):
                a = r1.get((i, 0))
                b = r2.get((i, 0))
                if not (a and b and a["arm"] and b["arm"]):
                    ck(False, "DET_BOOT_PAIR", "i=%d" % i)
                    continue
                if not (a[part] and b[part]):
                    ck(bool(a[part]) == bool(b[part]), "DET_BOOT_PRESENT",
                       "i=%d %s" % (i, part))
                    continue
                skip = {"pass", "empt", "ms", "t1", "tl", "udpin", "udperr",
                        "rmem", "rmem0", "rmem1", "rma0", "rma1", "win",
                        "clone", "i", "att"}
                x = {k: v for k, v in a[part][0].items() if k not in skip}
                y = {k: v for k, v in b[part][0].items() if k not in skip}
                ck(x == y, "DET_BOOT", "i=%d %s %s %s" % (i, part, x, y))

    # ---------------- the boundary numbers, printed as the turn's summary
    if not per_log:
        print("CHECKS %d, FAIL %d" % (PASS, FAIL))
        for f in FAILS[:40]:
            print("FAIL:", f)
        print(json.dumps({"checks": PASS, "fail": FAIL,
                          "fails": FAILS[:60]}, ensure_ascii=False))
        return 1
    recs = per_log[list(per_log.keys())[0]][0]
    for i, A in enumerate(arms):
        rec = recs.get((i, 0))
        if not rec or not rec["arm"] or not rec["cq"]:
            continue
        cq = rec["cq"][0]
        note("%-12s dlen=%-5d room=%-4d cloned=%d pull=%d eat=%-4s charge=%d"
             % (A["name"], ilist(cq["dlen"])[0],
                ilist(cq["end"])[0] - ilist(cq["tail"])[0],
                ilist(cq["fl"])[0], int(rec["cnt"][0]["pull"]),
                rec["cnt"][0]["eat"],
                int(rec["rcv"][0]["rmem1"]) - A["j"] * S))

    print("CHECKS %d, FAIL %d" % (PASS, FAIL))
    for f in FAILS[:40]:
        print("FAIL:", f)
    for n in NOTES:
        print("NOTE:", n)
    print(json.dumps({"checks": PASS, "fail": FAIL,
                      "fails": FAILS[:60]}, ensure_ascii=False))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
