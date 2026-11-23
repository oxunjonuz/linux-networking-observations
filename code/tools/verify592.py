#!/usr/bin/env python3
"""verify592.py -- the independent check of turn 592 (F70).

The turn asked one question directly instead of inferring it: what does
skb_condense() actually see, and does the `>` in `rmem > (rcvbuf >> 1)` bite at
the boundary?  Two instruments answer it, and this file checks that they agree:

  * PROVENANCE.  kernel sha256 in the log == the file on disk; initrd sha256 in
    the log == the file on disk; the differ EXTRACTED FROM THE INITRAMFS ==
    vm/build/differ592; research/predictions_592.md == the frozen file
    (sha256 recorded below, taken before the first boot).
  * THE SOURCE.  Anchors in the 7.3.4-T563 tree that the model rests on: the
    drop check comes BEFORE the condense branch, the branch is the strict `>`,
    skb_condense's three early-return clauses and its unconditional
    truesize reset, and skb_segment_list() never touching truesize.
  * THE OFFSETS.  pahole, run here again on the same vmlinux, must give the
    same field offsets the instrument printed and the kernel echoed back in
    kprobe_events.
  * THE ARM TABLE.  Parsed from vm/differ592_add.c and compared, arm by arm,
    with the fourteen parameters the instrument printed for that arm.
  * THE QUEUE.  The filler must land EXACTLY on exp_f (a queue at the half
    boundary is the whole point), rcvbuf read back must be twice the request,
    the delta must equal exp_delta, and the delta must equal what the model
    predicts from the position of exp_f relative to half -- the strict `>`.
  * THE PROBE.  Per attempt and only between its markers: the number of
    skb_condense calls, __pskb_pull_tail calls (0), skb_segment_list calls,
    ___pskb_trim calls, the truesize and data_len of every call in order, and
    SKB_TRUESIZE arithmetic: every call that is not the aggregate's head must
    carry ts == end + 576, while the head carries the whole aggregate's
    truesize (n*1280, or 5*1280 + 960 with a short tail).
  * AGREEMENT.  The queue delta must be explainable by the probe's own record:
    if the probe saw the head (ts == n*s) the charge is n*s, if it did not the
    charge is (2n-1)*s.  Two instruments, one story.
  * DETERMINISM.  Both attempts of every arm, and both boots.

Usage: verify592.py [log1 log2]
"""
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
KERNEL = ROOT + "/src/linux-7.3.4-T563"
PRED = ROOT + "/research/predictions_592.md"
PRED_SHA = "0d574b40f71700a77abd79a37a35b07ef2bc51d9c9dac6d2bd229b58bc7d9783"
SRC_ADD = ROOT + "/vm/differ592_add.c"
LOGS = [ROOT + "/logs/f70_rep1.log", ROOT + "/logs/f70_rep2.log"]
INITRD = ROOT + "/vm/initrd592/cond.cpio.gz"
BIN = ROOT + "/vm/build/differ592"
IMG = KERNEL + "/arch/x86/boot/bzImage"

S = 1280          # SKB_TRUESIZE of one 512-byte datagram (F69, re-measured here)
TS_CONST = 576    # SKB_TRUESIZE(x) = x + 576 in this kernel; derived below, and
                  # consistent with 1280/704, 2304/1728 measured in F66/F67/F69
HALF_STRICT = True   # udp.c: `if (rmem > (rcvbuf >> 1))` -- strictly greater

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


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def rd(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


# ---------------------------------------------------------------- the arms
def parse_arms(path):
    """the arm table, straight from the instrument's own source"""
    src = rd(path)
    body = src.split("static const struct f592_arm AF592_COND[] = {", 1)
    if len(body) != 2:
        return []
    body = body[1].split("};", 1)[0]
    arms = []
    for line in body.splitlines():
        m = re.match(r'\s*\{\s*"([a-z0-9_]+)",\s*\'(\w)\',\s*(-?\d+),\s*'
                     r'(-?\d+),\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),'
                     r'\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),'
                     r'\s*(-?\d+),\s*(-?\d+)\s*\}', line)
        if m:
            arms.append({
                "name": m.group(1), "xg": m.group(2),
                "j": int(m.group(3)), "n": int(m.group(4)),
                "pl": int(m.group(5)), "sh": int(m.group(6)),
                "sl": int(m.group(7)), "rcvbuf": int(m.group(8)),
                "exp_f": int(m.group(9)), "exp_delta": int(m.group(10)),
                "exp_calls": int(m.group(11)), "exp_t0": int(m.group(12)),
                "exp_pull": int(m.group(13)), "exp_seg": int(m.group(14)),
            })
    return arms


def kv(line):
    out = {}
    for part in line.rstrip("\n").split("|")[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def parse_log(path):
    """attempts, keyed by (arm index, attempt); each block is the set of lines
    between the previous ARM line and this one"""
    txt = rd(path)
    lines = txt.splitlines()
    blocks = []
    cur = []
    for ln in lines:
        if ln.startswith("F592 ARM|"):
            blocks.append((kv(ln), cur))
            cur = []
        else:
            cur.append(ln)
    out = {}
    for arm, block in blocks:
        key = (int(arm["i"]), int(arm["att"]))
        rec = {"arm": arm, "prep": [], "wait": [], "rcv": [], "cnt": [],
               "seq": [], "trc": [], "raw": block}
        for ln in block:
            if ln.startswith("F591 PREP|"):
                rec["prep"].append(kv(ln))
            elif ln.startswith("F591 WAIT|"):
                rec["wait"].append(kv(ln))
            elif ln.startswith("F591 RCV|"):
                rec["rcv"].append(kv(ln))
            elif ln.startswith("F592 CNT|"):
                rec["cnt"].append(kv(ln))
            elif ln.startswith("F592 SEQ|"):
                rec["seq"].append(kv(ln))
            elif ln.startswith("F592 TRC|"):
                rec["trc"].append(ln)
        out[key] = rec
    return out, txt


def trace_records(rec):
    """every f592cond record the dump attributed to this attempt, in order"""
    out = []
    for ln in rec["trc"]:
        if "f592cond:" not in ln:
            continue
        f = {}
        for key in ("len", "dlen", "tail", "end", "ts", "fl"):
            m = re.search(r"\b%s=(-?\d+)" % key, ln.split("f592cond:", 1)[1])
            if m:
                f[key] = int(m.group(1))
        out.append(f)
    return out


# ---------------------------------------------------------------- the model
def above(rmem, half):
    """udp.c: `if (rmem > (rcvbuf >> 1))` -- strictly greater"""
    return rmem > half if HALF_STRICT else rmem >= half


def end_of(pl):
    """skb->end of a received datagram of this payload, as the probe reports
    it: 704 for 512 bytes, 384 for 200 (both read off the log, not assumed)"""
    return 704 if pl == 512 else 384


def own_price(pl):
    """SKB_TRUESIZE(end) for one datagram of this payload"""
    return end_of(pl) + TS_CONST


def head_truesize(a):
    """the truesize the aggregate's head carries into the enqueue path: the
    sum of the truesizes of the datagrams merged into it (F67 §4:
    skb_gro_receive_list does p->truesize += skb->truesize)"""
    n, pl, sh, sl = a["n"], a["pl"], a["sh"], a["sl"]
    if n == 1:
        return own_price(pl)
    total = 0
    for k in range(n):
        total += own_price(sl if k == sh else pl)
    return total


def model_seq(a, half):
    """Walk every enqueue of the arm in order, one datagram or segment at a
    time, and return (delta, calls_inside_the_arm, head_condensed).

    Each enqueue checks rmem > half; if true skb_condense() rewrites the skb's
    truesize to SKB_TRUESIZE(end) (the aggregate head loses n*s; a segment
    keeps its own price), otherwise the skb keeps what it arrived with.
    """
    rmem = 0
    for _ in range(a["j"]):
        rmem += own_price(512)          # the filler never aggregates
    calls = 0
    head_condensed = False
    delta = 0
    n = a["n"]
    if a["xg"] == "u" or n == 1:
        steps = [(own_price(a["pl"]), own_price(a["pl"]))] * n
    else:
        steps = [(head_truesize(a), own_price(a["pl"]))]
        for k in range(1, n):
            pl = a["sl"] if k == a["sh"] else a["pl"]
            steps.append((own_price(pl), own_price(pl)))
    for i, (arrived_with, priced_at) in enumerate(steps):
        if above(rmem, half):
            calls += 1
            if i == 0 and a["xg"] == "f" and n > 1:
                head_condensed = True
            cost = priced_at
        else:
            cost = arrived_with
        rmem += cost
        delta += cost
    return delta, calls, head_condensed


def main():
    logs = sys.argv[1:] or LOGS

    # ---- provenance -----------------------------------------------------
    ksha = sha(IMG)
    isha = sha(INITRD)
    dsha = sha(BIN)
    hdr = rd(logs[0]).splitlines()[:6]
    hdr_ksha = ""
    hdr_isha = ""
    for ln in hdr:
        if ln.startswith("### sha256: "):
            hdr_ksha = ln.split(": ", 1)[1].strip()
        if ln.startswith("### initrd sha256: "):
            hdr_isha = ln.split(": ", 1)[1].strip()
    ck(hdr_ksha == ksha, "prov/kernel-sha", hdr_ksha[:12] + " vs " + ksha[:12])
    ck(hdr_isha == isha, "prov/initrd-sha", hdr_isha[:12] + " vs " + isha[:12])
    ck(sha(PRED) == PRED_SHA, "prov/predictions-unchanged", sha(PRED)[:12])
    # the differ that actually ran: unpacked from the initramfs
    tmp = "/tmp/f70_initrd"
    subprocess.run("rm -rf %s && mkdir -p %s" % (tmp, tmp), shell=True)
    subprocess.run("cd %s && gzip -dc %s | cpio -id --quiet root/repro"
                   % (tmp, INITRD), shell=True)
    if os.path.exists(tmp + "/root/repro"):
        ck(sha(tmp + "/root/repro") == dsha, "prov/differ-in-initramfs",
           sha(tmp + "/root/repro")[:12])
    else:
        ck(False, "prov/differ-in-initramfs", "not found")

    # ---- the source -----------------------------------------------------
    udp = rd(KERNEL + "/net/ipv4/udp.c")
    i_drop = udp.find("if (rmem + size > rcvbuf) {")
    i_branch = udp.find("if (rmem > (rcvbuf >> 1)) {")
    i_cond = udp.find("skb_condense(skb);", i_branch if i_branch > 0 else 0)
    ck(i_drop > 0 and i_branch > i_drop, "src/drop-before-branch",
       "%d %d" % (i_drop, i_branch))
    ck(i_branch > 0 and 0 < i_cond - i_branch < 200, "src/branch-calls-condense",
       "%d" % (i_cond - i_branch))
    ck("rmem > (rcvbuf >> 1)" in udp, "src/branch-is-strict-greater", "")
    ck("rmem >= (rcvbuf >> 1)" not in udp, "src/branch-not-greater-equal", "")
    skb = rd(KERNEL + "/net/core/skbuff.c")
    body = skb.split("void skb_condense(struct sk_buff *skb)", 1)[-1].split("\n}", 1)[0]
    ck("skb->data_len > skb->end - skb->tail" in body, "src/clause-tailroom", "")
    ck("skb_cloned(skb)" in body, "src/clause-cloned", "")
    ck("!skb_frags_readable(skb)" in body, "src/clause-readable", "")
    ck("__pskb_pull_tail(skb, skb->data_len)" in body, "src/linearise", "")
    ck("skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));" in body,
       "src/reset-truesize", "")
    seg = skb.split("struct sk_buff *skb_segment_list(", 1)[-1].split("\n}", 1)[0]
    ck("truesize" not in seg, "src/segment-list-leaves-truesize", "")

    # ---- the offsets ----------------------------------------------------
    off = None
    try:
        out = subprocess.run(["pahole", "-C", "sk_buff", KERNEL + "/vmlinux"],
                             capture_output=True, text=True, timeout=600).stdout
        off = {}
        for field, name in ((112, "len"), (116, "data_len"), (188, "tail"),
                            (192, "end"), (216, "truesize")):
            m = re.search(r"\b%s;\s*/\*\s+(\d+)\s+\d+ \*/" % name, out)
            if m:
                off[name] = int(m.group(1))
    except Exception as e:                                   # noqa: BLE001
        NOTES.append("pahole failed: %s" % e)
    txt1 = rd(logs[0])
    m = re.search(r"F592 PROBE\|ok=(\d)\|mask=([0-9a-f]+)\|path=([^|]+)\|"
                  r"off=(-?\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+)", txt1)
    ck(m is not None, "probe/line-present", "")
    if m:
        ck(m.group(1) == "1", "probe/ok", m.group(1))
        ck(m.group(2) == "1f", "probe/all-five-events", m.group(2))
        used = [int(m.group(i)) for i in range(4, 10)]
        ck(used == [112, 116, 188, 192, 216, 126], "probe/offsets-printed",
           str(used))
        if off and len(off) == 5:
            ck(used[0] == off["len"] and used[1] == off["data_len"] and
               used[2] == off["tail"] and used[3] == off["end"] and
               used[4] == off["truesize"], "probe/offsets-match-pahole",
               str(off))
        else:
            ck(False, "probe/offsets-match-pahole", "pahole gave %r" % (off,))
    # the kernel's own echo of the definition
    ck("F592 DEF|p:kprobes/f592cond skb_condense len=+112(%di):u32 "
       "dlen=+116(%di):u32 tail=+188(%di):u32 end=+192(%di):u32 "
       "ts=+216(%di):u32 fl=+126(%di):u8" in txt1, "probe/kernel-echo", "")
    defs = [ln for ln in txt1.splitlines() if ln.startswith("F592 DEF|")]
    ck(len(defs) == 5, "probe/def-lines-complete", str(len(defs)))
    for ev in ("f592pull __pskb_pull_tail", "f592enq __udp_enqueue_schedule_skb",
               "f592trim ___pskb_trim", "f592seg skb_segment_list"):
        ck(any(ev in d for d in defs), "probe/def-" + ev.split()[0], "")

    # ---- the arms, both boots ------------------------------------------
    arms = parse_arms(SRC_ADD)
    ck(len(arms) == 9, "table/arms-parsed", str(len(arms)))
    byname = {a["name"]: a for a in arms}
    stats = {"delta": {}, "calls": {}, "head_ts": {}, "trim": 0}

    for log in logs:
        attempts, txt = parse_log(log)
        tag = os.path.basename(log)
        ck(len(attempts) == len(arms) * 2, tag + "/attempt-count",
           str(len(attempts)))
        ck("F592 RUN|mode=cond|arms=9|run=9" in txt, tag + "/run-line", "")
        for idx, a in enumerate(arms):
            for att in (0, 1):
                rec = attempts.get((idx, att))
                if rec is None:
                    ck(False, tag + "/missing-attempt", "%s/%d" % (a["name"], att))
                    continue
                t = "%s/%s/att%d" % (tag, a["name"], att)
                arm = rec["arm"]
                # the printed table row must be the source row
                for k, v in (("name", a["name"]), ("xg", a["xg"]),
                             ("j", str(a["j"])), ("n", str(a["n"])),
                             ("pl", str(a["pl"])), ("sh", str(a["sh"])),
                             ("sl", str(a["sl"])), ("rcvbuf", str(a["rcvbuf"])),
                             ("exp_f", str(a["exp_f"])),
                             ("exp_delta", str(a["exp_delta"])),
                             ("exp_calls", str(a["exp_calls"])),
                             ("exp_t0", str(a["exp_t0"]))):
                    ck(arm.get(k) == v, t + "/arm-field-" + k,
                       "%r vs %r" % (arm.get(k), v))
                ck(arm.get("rc") == "0", t + "/send-rc", arm.get("rc", "?"))
                ck(arm.get("cmdrc") == "0", t + "/cmdrc", arm.get("cmdrc", "?"))
                ck(len(rec["prep"]) == 1, t + "/prep-count",
                   str(len(rec["prep"])))
                ck(len(rec["wait"]) == 2, t + "/wait-count",
                   str(len(rec["wait"])))
                ck(len(rec["rcv"]) == 1, t + "/rcv-count", str(len(rec["rcv"])))
                ck(len(rec["cnt"]) == 1, t + "/cnt-count", str(len(rec["cnt"])))
                # --- the buffer and the filler's landing point
                if rec["prep"]:
                    p = rec["prep"][-1]
                    ck(int(p["req"]) == a["rcvbuf"], t + "/prep-req", p["req"])
                    ck(int(p["rb"]) == 2 * a["rcvbuf"], t + "/prep-doubling",
                       p["rb"])
                if len(rec["wait"]) >= 1:
                    w = rec["wait"][0]
                    ck(int(w["want"]) == a["exp_f"], t + "/filler-want",
                       w["want"])
                    ck(int(w["rmem"]) == a["exp_f"], t + "/filler-rmem-exact",
                       w["rmem"])
                # --- the queue after the burst
                if rec["rcv"]:
                    r = rec["rcv"][-1]
                    ck(int(r["rb"]) == 2 * a["rcvbuf"], t + "/rcv-rb", r["rb"])
                    ck(int(r["n"]) == a["j"] + a["n"], t + "/rcv-datagrams",
                       r["n"])
                    ck(int(r["nf"]) == a["j"], t + "/rcv-filler-datagrams",
                       r["nf"])
                    ck(int(r["nt"]) == a["n"], t + "/rcv-test-datagrams",
                       r["nt"])
                    # the filler may be charged nothing extra, and the test's
                    # datagrams must all arrive: delivered == j + n is already
                    # checked above; now the charge.
                    half = a["rcvbuf"]
                    mdelta, mcalls, mhead = model_seq(a, half)
                    if a["exp_delta"] >= 0:
                        delta = int(r["rmem"]) - a["exp_f"]
                        stats["delta"].setdefault(a["name"], []).append(delta)
                        ck(delta == a["exp_delta"], t + "/delta-table",
                           "%d vs %d" % (delta, a["exp_delta"]))
                        ck(delta == mdelta, t + "/delta-model",
                           "%d vs %d" % (delta, mdelta))
                    else:
                        stats["delta"].setdefault(a["name"], []).append(
                            int(r["rmem"]) - a["exp_f"])
                # --- the probe
                if rec["cnt"]:
                    c = rec["cnt"][-1]
                    ck(c["mark"] == "1", t + "/markers-seen", c["mark"])
                    recs = trace_records(rec)
                    ck(len(recs) == int(c["cond"]), t + "/records==counter",
                       "%d vs %s" % (len(recs), c["cond"]))
                    stats["trim"] += int(c["trim"])
                    if a["exp_calls"] >= 0:
                        ck(int(c["cond"]) == a["exp_calls"], t + "/calls-table",
                           "%s vs %d" % (c["cond"], a["exp_calls"]))
                    half = a["rcvbuf"]
                    mdelta, mcalls, mhead = model_seq(a, half)
                    if a["xg"] == "f":
                        ck(int(c["cond"]) == mcalls, t + "/calls-model",
                           "%s vs %d" % (c["cond"], mcalls))
                    if a["exp_pull"] >= 0:
                        ck(int(c["pull"]) == a["exp_pull"], t + "/pull",
                           c["pull"])
                    if a["exp_seg"] >= 0:
                        ck(int(c["seg"]) == a["exp_seg"], t + "/segmenter",
                           c["seg"])
                    # inside the markers only the TEST is enqueued: the filler
                    # came before BEGIN, and the primer goes to a port with no
                    # socket (P14's number was j+n for the whole arm; the
                    # window shows n, and n exactly says the primer added none)
                    ck(int(c["enq"]) == a["n"], t + "/enqueue-count",
                       c["enq"])
                    stats["calls"].setdefault(a["name"], []).append(
                        int(c["cond"]))
                    # --- the arithmetic of every record
                    for k, f in enumerate(recs):
                        ck(f.get("dlen") == 0, t + "/dlen-zero[%d]" % k,
                           str(f.get("dlen")))
                        ck(f.get("len") in (a["pl"], a["sl"]),
                           t + "/len-is-a-datagram[%d]" % k, str(f.get("len")))
                        ck(f.get("end", 0) - f.get("tail", 0) > 0,
                           t + "/tailroom[%d]" % k, "")
                        head = (k == 0 and mhead)
                        if head:
                            ck(f.get("ts") == head_truesize(a),
                               t + "/head-carries-aggregate[%d]" % k,
                               "%s vs %s" % (f.get("ts"), head_truesize(a)))
                            stats["head_ts"].setdefault(a["name"], []).append(
                                f.get("ts"))
                        else:
                            ck(f.get("ts") == f.get("end", 0) + TS_CONST,
                               t + "/ts-is-skb-truesize[%d]" % k,
                               "%s vs %s" % (f.get("ts"),
                                             f.get("end", 0) + TS_CONST))
                    if recs and a["exp_t0"] >= 0:
                        ck(recs[0].get("ts") == a["exp_t0"], t + "/first-ts",
                           "%s vs %d" % (recs[0].get("ts"), a["exp_t0"]))
                    # --- the two instruments must tell one story
                    if a["exp_delta"] >= 0 and rec["rcv"]:
                        delta = int(rec["rcv"][-1]["rmem"]) - a["exp_f"]
                        saw_head = (bool(recs) and a["n"] > 1 and a["xg"] == "f"
                                    and recs[0].get("ts") == head_truesize(a))
                        ck(saw_head == mhead, t + "/probe-agrees-on-the-head",
                           "probe=%s model=%s" % (saw_head, mhead))
                        ck(delta == mdelta, t + "/probe-explains-delta",
                           "%d vs %d" % (delta, mdelta))
        # --- determinism inside one boot
        for a in arms:
            d = [stats["delta"][a["name"]][i] for i in (0, 1)
                 if a["name"] in stats["delta"] and
                 len(stats["delta"][a["name"]]) > i]
            c = stats["calls"].get(a["name"], [])
            if len(c) >= 2:
                ck(len(set(c[:2])) == 1, tag + "/" + a["name"] + "/calls-stable",
                   str(c[:2]))

    # ---- the cells the turn is about -----------------------------------
    for name, want in (("c_eq", (2 * 6 - 1) * S), ("c_gt", 6 * S),
                       ("c_lin", 6 * S), ("c_zero", (2 * 6 - 1) * S),
                       ("c_lt", (2 * 6 - 1) * S), ("c_one", S)):
        d = stats["delta"].get(name, [])
        ck(len(d) == 4 and set(d) == {want}, "cell/" + name + "-delta",
           "%r vs %d" % (d, want))
    ck(stats["delta"].get("c_eq") != stats["delta"].get("c_gt"),
       "cell/strict-inequality-bites",
       "%r %r" % (stats["delta"].get("c_eq"), stats["delta"].get("c_gt")))
    ck(stats["calls"].get("c_eq") == [5, 5, 5, 5], "cell/c_eq-five-calls",
       str(stats["calls"].get("c_eq")))
    ck(stats["calls"].get("c_gt") == [6, 6, 6, 6], "cell/c_gt-six-calls",
       str(stats["calls"].get("c_gt")))
    ck(stats["calls"].get("c_zero") == [0, 0, 0, 0], "cell/c_zero-no-calls",
       str(stats["calls"].get("c_zero")))
    ck(stats["head_ts"].get("c_gt") == [7680, 7680, 7680, 7680],
       "cell/c_gt-head-7680", str(stats["head_ts"].get("c_gt")))
    ck(stats["head_ts"].get("c_tail") == [7360, 7360, 7360, 7360],
       "cell/c_tail-head-7360", str(stats["head_ts"].get("c_tail")))
    ck("c_eq" not in stats["head_ts"], "cell/c_eq-no-head-record",
       str(stats["head_ts"].get("c_eq")))
    ck(stats["trim"] == 0, "obs/no-trim-path-in-any-arm", str(stats["trim"]))

    # ---- report ---------------------------------------------------------
    print("checks: %d passed, %d failed" % (PASS, FAIL))
    print("deltas:", json.dumps(stats["delta"], sort_keys=True))
    print("calls :", json.dumps(stats["calls"], sort_keys=True))
    print("head ts:", json.dumps(stats["head_ts"], sort_keys=True))
    for n in NOTES:
        print("note:", n)
    os.makedirs(ROOT + "/findings/F70-condense", exist_ok=True)
    with open(ROOT + "/findings/F70-condense/verify592.json", "w") as f:
        json.dump({"checks_pass": PASS, "checks_fail": FAIL,
                   "fails": FAILS, "stats": stats,
                   "arms": arms}, f, indent=1)
    if FAIL:
        for f in FAILS[:40]:
            print("FAIL:", f)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
