#!/usr/bin/env python3
"""verify590_selftest.py -- can verify590.py go RED?

One single-fault mutation at a time into a COPY of the verifier, then the copy
is run against the same two boots.  A mutation is noticed exactly when the copy
exits non-zero.  A copy that crashes with a traceback is NOT a pass: a verifier
that falls over instead of saying "no" is a defect of its own (F65 §8.5).

The list is printed with the survivors, and a survivor is a place to look, not
a verdict.
"""
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
SRC = ROOT + "/tools/verify590.py"
TMP = "/tmp/v590_mut.py"
LOGS = [ROOT + "/logs/f68_rep1.log", ROOT + "/logs/f68_rep2.log"]

MUTATIONS = [
    ("H-48", "H = 28          # 20 IPv4 + 8 UDP", "H = 48          # 20 IPv4 + 8 UDP"),
    ("CAP-1", "CAP = 65536", "CAP = 65535"),
    ("length-rule-off-model", "            if s > rest[0]:", "            if s > rest[0] + 40:"),
    ("length-rule-off-alt", "            if x > head:\n                break", "            if x > head + 40:\n                break"),
    ("seed-not-complemented", "return csum16(ph) & 0xffff", "return (~csum16(ph)) & 0xffff"),
    ("ttl-64", 'eq(int(x["ttl"]), 63', 'eq(int(x["ttl"]), 64'),
    ("df-wrong", "eq(int(x[\"ff\"], 16), 0x4000", "eq(int(x[\"ff\"], 16), 0x2000"),
    ("dst-offset", 'eq(h32[0:4], dst', 'eq(h32[4:8], dst'),
    ("src-offset", 'eq(h16[12:16], S', 'eq(h16[8:12], S'),
    ("A512-1", 'eq(A512, 162560', 'eq(A512, 162561'),
    ("s512-1", 'eq(s512, 1280', 'eq(s512, 1281'),
    ("s1200-1", 'eq(s1200, 2304', 'eq(s1200, 2305'),
    ("half-inclusive", "if queue_before > (R >> 1):", "if queue_before >= (R >> 1):"),
    ("primer-plen", 'eq(int(x["plen"]), 20 + 8 + A["primer"]', 'eq(int(x["plen"]), 21 + 8 + A["primer"]'),
    ("nflmax", "NFLMAX = 65531", "NFLMAX = 65535"),
    ("p0-index", '0x10 + (pos & 0x0f)', '0x10 + ((pos + 1) & 0x0f)'),
    ("uhlen-off-by-1", 'eq(int(x["uh"]), ulen', 'eq(int(x["uh"]), ulen + 1'),
    ("fraglist-uses-linear-ck", '''                            elif A["xg"] == "f":
                                want = seed4(S, DA if A["dst"] == "a" else DB,
                                             8 + grp[0])''',
     '''                            elif A["xg"] == "f":
                                want = seed4(S, DA if A["dst"] == "a" else DB, ulen)'''),
    ("ch-ignores-primer", 'want_ch = len(pk) + (1 if A["primer"] else 0)',
     'want_ch = len(pk)'),
    ("kept-off-by-1", "    more = budget // s\n    kept = 1 + more", "    more = budget // s\n    kept = more"),
    ("no-kernel-sha", 'eq(d["sha"], disk_sha, "kernel-sha-in-log")', 'pass'),
    ("no-prediction-sha", '"b71d82f48cafad0185a47466c7c7d4b76c006f5631f659b8816f8d245f938379"',
     '"0000000000000000000000000000000000000000000000000000000000000000"'),
    ("no-anchor-length-rule", 'anchor("net/ipv4/udp_offload.c", "if (ulen > udp_get_len_short(uh2) || flush)",\n           "length-rule")', 'pass'),
]


BASE_CHECKS = [0]


def run_one(tag, old, new):
    src = open(SRC).read()
    n = src.count(old)
    if n < 1:
        return ("SKIP", "the sample is not in the source (count=%d)" % n)
    open(TMP, "w").write(src.replace(old, new))
    r = subprocess.run([sys.executable, TMP] + LOGS, capture_output=True, text=True)
    tail = (r.stdout or "").strip().split("\n")[-1] if r.stdout else ""
    if "Traceback" in (r.stderr or ""):
        return ("CRASH", (r.stderr or "").strip().split("\n")[-1])
    if r.returncode != 0:
        return ("RED", tail)
    # deleting a check leaves the run green: the COUNT is the witness
    try:
        tot = int(re.search(r"(\d+) passed", r.stdout).group(1)) + \
              int(re.search(r"(\d+) failed", r.stdout).group(1))
    except Exception:                                        # noqa: BLE001
        return ("RED", "no count in the output")
    if tot < BASE_CHECKS[0]:
        return ("RED", "check count fell %d -> %d" % (BASE_CHECKS[0], tot))
    return ("SURVIVED", tail)


def main():
    base = subprocess.run([sys.executable, SRC] + LOGS, capture_output=True, text=True)
    print("baseline rc=%d | %s" % (base.returncode, base.stdout.strip().split("\n")[-1]))
    if base.returncode != 0:
        print("BASELINE IS NOT GREEN -- the campaign would prove nothing")
        return 1
    BASE_CHECKS[0] = (int(re.search(r"(\d+) passed", base.stdout).group(1)) +
                      int(re.search(r"(\d+) failed", base.stdout).group(1)))
    ok = 0
    bad = []
    for tag, old, new in MUTATIONS:
        res, note = run_one(tag, old, new)
        print("%-24s %-9s %s" % (tag, res, note))
        if res == "RED":
            ok += 1
        else:
            bad.append((tag, res, note))
    print("mutations noticed: %d/%d" % (ok, len(MUTATIONS)))
    for t, r, n in bad:
        print("  SURVIVOR/CRASH", t, r, n)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
