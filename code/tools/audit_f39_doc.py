#!/usr/bin/env python3
"""audit_f39_doc.py -- every number this document prints, checked against the logs.

The document is the last place where a number can drift: the verifier checks
the logs, not the prose.  Each cell below is (regex over SUMMARY.md,
value re-derived from the logs).  A cell that does not match is printed and the
script exits non-zero.
"""
import importlib.util
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F39-8021ad-qinq/SUMMARY.md")

spec = importlib.util.spec_from_file_location("v", os.path.join(
    ROOT, "tools/verify561.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

rows = v.parse(os.path.join(ROOT, "logs/f39_rep1.log"))
farA = v.parse(os.path.join(ROOT, "logs/f39_farA.log"))
doc = open(DOC, errors="replace").read()

N = 0
FAIL = []


def cell(pattern, want, what):
    global N
    N += 1
    m = re.search(pattern, doc)
    if not m:
        FAIL.append((what, "row not found: %r" % pattern))
        return
    got = m.group(1)
    if got != want:
        FAIL.append((what, "doc=%r log=%r" % (got, want)))


def live(env, rep_tag=None):
    sub = v.getr(rows, "R", env=env)
    return len([x for x in sub if int(x["live"]) > 0 and x["arm"] != "ctl"])


def dead(env):
    sub = v.getr(rows, "R", env=env)
    out = sorted((int(x["off"]), int(x["len"])) for x in sub
                 if int(x["live"]) == 0 and x["arm"] != "ctl")
    return out


# ---- 1. meta protocol
for rep in v.ORDER:
    mt = [x for x in v.getr(rows, "M", rep=rep) if x["want"] != "-"]
    val = [x["want"] for x in mt if int(x["live"]) > 0]
    cell(r"\| `%s` \| \*\*(%s)\*\* \|" % (rep, "[0-9a-f]{4}"),
         val[0] if val else "-", "meta %s" % rep)

# ---- 2. ll live counts
for rep, n in (("p", 23), ("w", 25), ("s88", 25), ("q", 25), ("q81", 25),
               ("x91", 23)):
    cell(r"\| `%s` \| \*\*(\d+)/36\*\* \|" % rep, str(live("ll." + rep)),
         "ll %s live" % rep)
    assert n == live("ll." + rep), (rep, n, live("ll." + rep))

# the dead sets printed in the table
cell(r"\| `p` \| \*\*23/36\*\* \| (.+?) \|",
     "(12,4) (14,\\*) (16,\\*) (20,\\*) (24,\\*)", "dead set p (shape)")
tagged = dead("ll.q")
pdead = dead("ll.p")
assert (12, 4) in pdead and (10, 4) not in pdead
assert (10, 4) in tagged and (12, 2) not in tagged
# every tagged rep has the same dead set
assert dead("ll.w") == dead("ll.s88") == dead("ll.q") == dead("ll.q81") == tagged
assert dead("ll.p") == dead("ll.x91") == pdead

# ---- 2b. the byte table
q16_2 = v.one(rows, "R", env="ll.q", arm="g16_2")["wchgs"]
w16_2 = v.one(rows, "R", env="ll.w", arm="g16_2")["wchgs"]
cell(r"\| \(16,2\) \| `([^`]+)` \| `([^`]+)` \|", w16_2, "ll w (16,2) bytes")
q14 = v.one(rows, "R", env="ll.q", arm="g14_2")["wchgs"]
cell(r"\| \(14,2\) \| в кадре ничего \(`([^`]+)`\) \| в кадре ничего \|",
     "wchgs=" + q14, "ll (14,2) invisible")
assert re.search(r"\| \(20,1\) \| мёртва \| мёртва", doc)
assert (20, 1) in dead("ll.q")

# ---- 3. nh
cell(r"\| `w` \| 0800 \| \*\*(\d+)/40\*\* \|",
     str(live("unlock.w.bare")), "nh w")
cell(r"\| `q` \| 8100 \| \*\*(\d+)/40\*\* \|",
     str(live("unlock.q.bare")), "nh q")

# ---- 4. unlock
for env, pat in (("unlock.w.bare", r"\| `w`, только запись \| \*\*(\d+)/40\*\* \|"),
                 ("unlock.w.meta", r"\| `w`, meta \+ запись \| \*\*(\d+)/40\*\* \|"),
                 ("unlock.q.bare", r"\| `q`, только запись \| \*\*(\d+)/40\*\* \|"),
                 ("unlock.q.meta", r"\| `q`, meta \+ запись \| \*\*(\d+)/40\*\* \|")):
    cell(pat, str(live(env)), env)
assert (0, 2) not in [(int(x["off"]), int(x["len"]))
                      for x in v.getr(rows, "R", env="unlock.q.meta")
                      if int(x["live"]) > 0]
assert (8, 2) not in [(int(x["off"]), int(x["len"]))
                      for x in v.getr(rows, "R", env="unlock.q.meta")
                      if int(x["live"]) > 0]

# ---- 5. xmit
for state, wnp, tagp, rnp in (
        ("A_11", 60, "08004500", 60), ("A_11", 60, "08004500", 60)):
    pass
XT = {
    ("A_11", "ctl"): ("60", "60"),
    ("A_11", "p8100"): ("60", "60"),
    ("A_11", "p88a8"): ("60", "60"),
    ("A_11", "p0000"): ("64", "64"),
    ("B_01", "p88a8"): ("60", "60"),
    ("C_00", "p88a8"): ("64", "60"),
    ("C_00", "p8100"): ("64", "60"),
}
for (state, arm), (wn, rn) in XT.items():
    x = v.one(rows, "R", env="xmit.%s.%s" % (state, arm), arm=arm)
    assert x["wn"] == wn and x["rn"] == rn, (state, arm, x["wn"], x["rn"])
assert re.search(r"\| \| \(12,2\)=`88a8` \| \*\*60\*\* \| 60 \|", doc)
assert re.search(r"\| \| \(12,2\)=`88a8` \| \*\*64, `88a8 0064`\*\* \| 60 \|", doc)
a = v.one(rows, "R", env="xmit.A_11.p0000", arm="p0000")
c = v.one(rows, "R", env="xmit.C_00.p88a8", arm="p88a8")
assert a["whex"][24:32] == "00000064", a["whex"]
assert c["whex"][24:32] == "88a80064", c["whex"]
cell(r"\| \| \(12,2\)=`0000` \| 64, `([^`]+)` \| 64 \|",
     "0000 0064", "A p0000 tag")

# ---- 6. far
for rep, wn, rn, ip in (("p", "60", "60", "1"), ("w", "64", "60", "0"),
                        ("s88", "64", "60", "0"), ("q", "68", "64", "0"),
                        ("q81", "68", "64", "0"), ("x91", "64", "64", "0")):
    x = v.one(farA, "FAR", rep=rep)
    assert x["wn"] == wn and x["rn"] == rn and x["ipin"] == ip, (rep, x)
assert re.search(r"\| `q` \| 68 \| \*\*64, `8100 00c8 0800…`\*\* \| \*\*0\*\* \|", doc)
assert re.search(r"\| `p` \| 60 \| 60 \| \*\*\+1\*\* \|", doc)

# ---- 9. ingress
for rep, n in (("p", 40), ("q", 40)):
    sub = [x for x in v.getr(rows, "R", env="ndin." + rep)
           if int(x["live"]) > 0 and x["arm"] != "ctl"]
    assert len(sub) == n, (rep, len(sub))
assert re.search(r"\| `p` \| \*\*40/40\*\* \| байт 22 кадра — ttl "
                 r"\(`40`→`90`\) \|", doc)
assert re.search(r"\| `q` \| \*\*40/40\*\* \| байт 22 кадра — \*\*id\*\*, "
                 r"старший байт \(`12`→`90`\) \|", doc)
assert v.one(rows, "R", env="ndin.p", arm="g8_1")["wchgs"] == "22:40>90"
assert v.one(rows, "R", env="ndin.q", arm="g8_1")["wchgs"] == "22:12>90"

# ---- header claims that are checkable
m = re.search(r"sha `([0-9a-f]{8})…`", doc)
N += 1
if not m or m.group(1) != v.sha256(os.path.join(
        ROOT, "src/linux-7.3.4-T558/arch/x86/boot/bzImage"))[:8]:
    FAIL.append(("kernel sha in the header", "mismatch"))
n1 = len([l for l in open(os.path.join(ROOT, "logs/f39_rep1.log"),
                          errors="replace") if l.startswith("F561 ")])
N += 1
if not re.search(r"577 строк `F561`", doc):
    FAIL.append(("577 lines per boot", str(n1)))
N += 1
if n1 != 577:
    FAIL.append(("577 lines per boot (log)", str(n1)))

print("cells=%d failed=%d" % (N, len(FAIL)))
for w, d in FAIL:
    print("FAIL %s | %s" % (w, d))
sys.exit(0 if not FAIL else 1)
