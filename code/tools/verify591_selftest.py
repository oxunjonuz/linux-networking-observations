#!/usr/bin/env python3
"""verify591_selftest.py -- can verify591.py go RED?

Each entry is ONE textual mutation of a COPY of the verifier.  The mutated copy
is run on the same two logs and must exit 1 -- a recorded FAIL, not a traceback.
If the sample is not found exactly once in the source the entry is REFUSED
(SAMPLE_NOT_FOUND): a mutation that never landed proves nothing.  A mutation
that leaves the verdict green but lowers the number of executed checks is
counted as detected by count (red*).

The last entry is a noop and must stay green: a suite that is red no matter what
is as worthless as one that is green no matter what.

Every entry here changes a CLAUSE of a model or a byte-level claim -- something
whose being wrong must change the verdict on this data.  Guards that cannot
change the verdict on this data (widening "is this shape a contiguous run",
since no observed shape is non-contiguous) are deliberately NOT listed: their
survival would say nothing about the model, and counting them either way would
be dishonest.  They are named in SUMMARY.md instead.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
SRC = ROOT + "/tools/verify591.py"
LOGS = [ROOT + "/logs/f69_rep1.log", ROOT + "/logs/f69_rep2.log"]

MUT = [
    ("H-26", 'H = 28            # 20 IPv4 + 8 UDP',
     'H = 26            # 20 IPv4 + 8 UDP'),
    ("cap-edge", 'if room > CAP - 1:', 'if room > CAP:'),
    ("cntmax-inclusive", 'if s < head or len(cur) >= CNTMAX:',
     'if s < head or len(cur) > CNTMAX:'),
    ("doors-swapped", 'room = (2 * H if door == "f" else H) + total + s',
     'room = (H if door == "f" else 2 * H) + total + s'),
    ("no-doubling", 'return (2 * k - 1) * s if door == "f" else k * s',
     'return k * s'),
    ("double-ladder", 'return (2 * k - 1) * s if door == "f" else k * s',
     'return (2 * k + 1) * s if door == "f" else k * s'),
    ("cntmax-63", 'CNTMAX = 64       # UDP_GRO_CNT_MAX, net/ipv4/udp_offload.c:694',
     'CNTMAX = 63       # UDP_GRO_CNT_MAX, net/ipv4/udp_offload.c:694'),
    ("nflmax", 'NFLMAX = 65531    # largest NFLOG message this kernel assembles (F66 §6)',
     'NFLMAX = 65535    # largest NFLOG message this kernel assembles (F66 §6)'),
    ("payload-row", 'eq(m["p0"], payload_first_bytes(runs[i][1]),',
     'eq(m["p0"], payload_first_bytes(runs[i][1] + 1),'),
    ("primer-not-counted", 'eq(a["ch"], 1 + len(shape), tag + "/rule-counter")',
     'eq(a["ch"], len(shape), tag + "/rule-counter")'),
    ("tap-frames", 'eq(len(att["tapA"]), len(shape), tag + "/tap-frames-y1")',
     'eq(len(att["tapA"]), len(shape) + 1, tag + "/tap-frames-y1")'),
    ("inerrors-cap", 'eq(att["nf"], 0, tag + "/no-filler")',
     'eq(att["nf"], 1, tag + "/no-filler")'),
    ("frame-uhlen", 'eq(t["uhlen"], uh, tag + "/frame-uhlen[%d]" % i)',
     'eq(t["uhlen"], uh + 1, tag + "/frame-uhlen[%d]" % i)'),
    ("one-frame-per-dgram", 'eq(a["an"], nd, tag + "/one-frame-per-datagram")',
     'eq(a["an"], nd + 1, tag + "/one-frame-per-datagram")'),
    ("wait-read", 'eq(att["wait"]["rmem"], att["rmem"], tag + "/wait==read")',
     'eq(att["wait"]["rmem"], att["rmem"] + 1, tag + "/wait==read")'),
    ("price-bytes", 'eq(att["rmem"], want, tag + "/queued-bytes")',
     'eq(att["rmem"], want + 1280, tag + "/queued-bytes")'),
    ("s-baked-in", 's_by_pl[a["pl"]] = a["attempts"][0]["rmem"]',
     's_by_pl[a["pl"]] = 1280'),
    ("delivered-cap", 'eq(att["n"], a["n"], tag + "/delivered")',
     'eq(att["n"], a["n"] + 1, tag + "/delivered")'),
    ("dl1", 'eq(att["dl"][1], P, tag + "/dl1")',
     'eq(att["dl"][1], P + 1, tag + "/dl1")'),
    ("pred-frozen", 'eq(sha_file(PRED), PRED_SHA, "prov/predictions-frozen")',
     'eq(sha_file(PRED), "0" * 64, "prov/predictions-frozen")'),
    ("anchor-inverted", 'ck("truesize" not in body, "src/segment_list-never-mentions-truesize",',
     'ck("truesize" in body, "src/segment_list-never-mentions-truesize",'),
    ("matched-once", 'ck(matched >= 1, key + "/model-shape-seen-once",',
     'ck(matched >= 3, key + "/model-shape-seen-once",'),
    ("sport", 'eq(m["h32"][8:12], "%04x" % 43580, tag + "/sport[%d]" % i)',
     'eq(m["h32"][8:12], "%04x" % 43581, tag + "/sport[%d]" % i)'),
    ("arm-count", 'eq(len(arms), 33, "arms/parsed")',
     'eq(len(arms), 31, "arms/parsed")'),
    ("noop", 'PASS = 0', 'PASS = 0  # noop: this mutation changes nothing'),
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
        return 1
    for name, old, new in MUT:
        src = open(SRC, encoding="utf-8").read()
        if src.count(old) != 1:
            print("SAMPLE_NOT_FOUND %-22s (found %d)" % (name, src.count(old)))
            refused += 1
            continue
        d = tempfile.mkdtemp(prefix="f69mut_")
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
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
