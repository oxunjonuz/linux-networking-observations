#!/usr/bin/env python3
"""verify592_selftest.py -- can verify592.py go RED?

Each entry is ONE textual mutation of a COPY of the verifier.  The mutated copy
is run on the same two logs and must exit 1 -- a recorded FAIL, not a traceback.
If the sample is not found exactly once in the source the entry is REFUSED
(SAMPLE_NOT_FOUND): a mutation that never landed proves nothing.

Every entry changes a CLAUSE of a model or a byte-level claim -- something whose
being wrong must change the verdict on this data.  The first entry is the hole
F68 §9 wrote down by name ("строгость > не проверена, мутация half-inclusive
выжила"): here it must die, because an arm sits exactly on the boundary.

The last entry is a noop and must stay green: a suite that is red no matter what
is as worthless as one that is green no matter what.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
SRC = ROOT + "/tools/verify592.py"
LOGS = [ROOT + "/logs/f70_rep1.log", ROOT + "/logs/f70_rep2.log"]

MUT = [
    # --- the branch itself
    ("half-inclusive", "HALF_STRICT = True   # udp.c:",
     "HALF_STRICT = False  # udp.c:"),
    ("never-condense", "        if above(rmem, half):", "        if False:"),
    ("always-condense", "        if above(rmem, half):", "        if True:"),
    ("head-keeps-own", "    if n == 1:\n        return own_price(pl)",
     "    if n >= 1:\n        return own_price(pl)"),
    # --- the arithmetic of the records
    ("ts-const", "TS_CONST = 576    #", "TS_CONST = 512    #"),
    ("tail-price", '    return 704 if pl == 512 else 384',
     '    return 704 if pl == 512 else 704'),
    ("dlen", 'ck(f.get("dlen") == 0, t + "/dlen-zero[%d]" % k,',
     'ck(f.get("dlen") == 1, t + "/dlen-zero[%d]" % k,'),
    ("len-is-datagram", 'ck(f.get("len") in (a["pl"], a["sl"]),',
     'ck(f.get("len") == a["pl"],'),
    ("head-ts-check", 'ck(f.get("ts") == head_truesize(a),',
     'ck(f.get("ts") == head_truesize(a) + S,'),
    # --- the queue
    ("delta-table", 'ck(delta == a["exp_delta"], t + "/delta-table",',
     'ck(delta == a["exp_delta"] + 1, t + "/delta-table",'),
    ("filler-exact", 'ck(int(w["rmem"]) == a["exp_f"], t + "/filler-rmem-exact",',
     'ck(int(w["rmem"]) == a["exp_f"] + 1, t + "/filler-rmem-exact",'),
    ("doubling", 'ck(int(p["rb"]) == 2 * a["rcvbuf"], t + "/prep-doubling",',
     'ck(int(p["rb"]) == a["rcvbuf"], t + "/prep-doubling",'),
    ("filler-datagrams", 'ck(int(r["nf"]) == a["j"], t + "/rcv-filler-datagrams",',
     'ck(int(r["nf"]) == a["j"] - 1, t + "/rcv-filler-datagrams",'),
    # --- the probe
    ("enqueue-count", 'ck(int(c["enq"]) == a["n"], t + "/enqueue-count",',
     'ck(int(c["enq"]) == a["n"] + 1, t + "/enqueue-count",'),
    ("segmenter", 'ck(int(c["seg"]) == a["exp_seg"], t + "/segmenter",',
     'ck(int(c["seg"]) == a["exp_seg"] + 1, t + "/segmenter",'),
    ("markers", 'ck(c["mark"] == "1", t + "/markers-seen", c["mark"])',
     'ck(c["mark"] == "0", t + "/markers-seen", c["mark"])'),
    ("records==counter", 'ck(len(recs) == int(c["cond"]), t + "/records==counter",',
     'ck(len(recs) == int(c["cond"]) + 1, t + "/records==counter",'),
    ("only-fraglist-has-a-head", 'if i == 0 and a["xg"] == "f" and n > 1:',
     'if i == 0 and n > 1:'),
    ("offsets", 'ck(used == [112, 116, 188, 192, 216, 126], "probe/offsets-printed",',
     'ck(used == [112, 116, 188, 192, 220, 126], "probe/offsets-printed",'),
    # --- the cells of the turn
    ("strict-bites", 'ck(stats["delta"].get("c_eq") != stats["delta"].get("c_gt"),',
     'ck(stats["delta"].get("c_eq") == stats["delta"].get("c_gt"),'),
    ("c_eq-delta", '("c_eq", (2 * 6 - 1) * S), ("c_gt", 6 * S),',
     '("c_eq", 6 * S), ("c_gt", 6 * S),'),
    ("c_gt-head", 'ck(stats["head_ts"].get("c_gt") == [7680, 7680, 7680, 7680],',
     'ck(stats["head_ts"].get("c_gt") == [1280, 1280, 1280, 1280],'),
    ("trim", 'ck(stats["trim"] == 0, "obs/no-trim-path-in-any-arm", str(stats["trim"]))',
     'ck(stats["trim"] == 1, "obs/no-trim-path-in-any-arm", str(stats["trim"]))'),
    # --- provenance
    ("predictions-sha", 'ck(sha(PRED) == PRED_SHA, "prov/predictions-unchanged",',
     'ck(sha(PRED) == "0" * 64, "prov/predictions-unchanged",'),
    ("differ-sha", 'ck(sha(tmp + "/root/repro") == dsha, "prov/differ-in-initramfs",',
     'ck(sha(tmp + "/root/repro") == "0" * 64, "prov/differ-in-initramfs",'),
    # --- the noop
    ("noop", "HALF_STRICT = True   # udp.c:",
     "HALF_STRICT = True    # udp.c:"),
]


def main():
    ok = bad = refused = 0
    base = subprocess.run([sys.executable, SRC] + LOGS, capture_output=True,
                          text=True)
    baseline = 0
    for l in base.stdout.splitlines():
        if l.startswith("checks: "):
            baseline = int(l.split()[1])
    print("baseline: %d checks, rc=%d" % (baseline, base.returncode))
    if base.returncode != 0:
        print("baseline is RED -- the selftest would prove nothing")
        for l in base.stdout.splitlines():
            if l.startswith("FAIL:"):
                print(" ", l)
        return 1
    for name, old, new in MUT:
        src = open(SRC, encoding="utf-8").read()
        if src.count(old) != 1:
            print("SAMPLE_NOT_FOUND %-22s (found %d)" % (name, src.count(old)))
            refused += 1
            continue
        d = tempfile.mkdtemp(prefix="f70mut_")
        p = os.path.join(d, "v.py")
        open(p, "w", encoding="utf-8").write(src.replace(old, new))
        r = subprocess.run([sys.executable, p] + LOGS, capture_output=True,
                           text=True)
        crashed = "Traceback" in r.stderr
        npass = 0
        for l in r.stdout.splitlines():
            if l.startswith("checks: "):
                npass = int(l.split()[1])
        if name == "noop":
            if r.returncode == 0 and not crashed:
                print("green  %-22s (as it must)" % name)
                ok += 1
            else:
                print("RED    %-22s noop must stay green!" % name)
                bad += 1
        elif crashed:
            print("CRASH  %-22s %s" % (name,
                                       r.stderr.strip().splitlines()[-1][:90]))
            bad += 1
        elif r.returncode == 1:
            first = [l for l in r.stdout.splitlines() if l.startswith("FAIL:")]
            print("red    %-22s %s" % (name, first[0][:88] if first else ""))
            ok += 1
        elif npass < baseline:
            print("red*   %-22s by check count (%d < %d)"
                  % (name, npass, baseline))
            ok += 1
        else:
            print("SURVIVED %-20s rc=%d checks=%d" % (name, r.returncode, npass))
            bad += 1
        shutil.rmtree(d, ignore_errors=True)
    print("\nselftest: %d red as required, %d bad, %d refused; of %d mutations"
          % (ok, bad, refused, len(MUT)))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
