#!/usr/bin/env python3
"""audit_f35_doc.py -- does findings/F35-ll-envelope/SUMMARY.md still say what
the logs say?

Two independent checks:

  A. regenerate the document with tools/f35_summary.py into a temporary
     directory and require it to be byte-identical to the file on disk (the
     document is derived, not written);

  B. re-derive six numbers with regexes of its own -- not the generator's --
     and require each to appear in the document text.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F35-ll-envelope/SUMMARY.md"
JSON = ROOT + "/findings/F35-ll-envelope/summary.json"
OK = []
FAIL = []


def check(name, cond, detail=""):
    if cond:
        OK.append(name)
    else:
        FAIL.append((name, detail))


def read(path):
    with open(path, "rb") as f:
        return f.read().decode("latin-1")


# the document is UTF-8 (it has em dashes and Cyrillic); the console logs are
# latin-1 with CRLF.  Reading the document as latin-1 was a real miss here:
# every em dash in a checked line became mojibake and the check failed.
def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


doc = read_bytes(DOC).decode("utf-8")

# ---- A. the document is what the generator produces -----------------------
tmp = tempfile.mkdtemp(prefix="f35audit")
subprocess.run([sys.executable, ROOT + "/tools/f35_summary.py", "--out", tmp],
               check=True, capture_output=True)
check("A.summary_md_identical",
      read_bytes(tmp + "/SUMMARY.md") == read_bytes(DOC))
check("A.summary_json_identical",
      read_bytes(tmp + "/summary.json") == read_bytes(JSON))

# ---- B. independent re-derivation ----------------------------------------
logs = {}
for tag in ("T_rep1", "T_rep2"):
    logs[tag] = read("%s/logs/f35_%s.log" % (ROOT, tag))


def cells(tag, env):
    out = {}
    for m in re.finditer(r"F557 R\|env=%s\|arm=g(\d+)_(\d+)[^\n]*?cnt=(\d+)"
                         % env, logs[tag]):
        out[(int(m.group(1)), int(m.group(2)))] = int(m.group(3))
    return out


def alive(tag, env):
    return sum(1 for v in cells(tag, env).values() if v == 1)


FACTS = {
    "plain ip alive/36": (alive("T_rep1", "p4"), 36),
    "plain bridge alive/36": (alive("T_rep1", "pB"), 36),
    "vlan bridge alive/36": (alive("T_rep1", "vB"), 36),
    "ipip alive/21": (alive("T_rep1", "ipip"), 21),
    "vxlan alive/21": (alive("T_rep1", "vxlan"), 21),
}
for name, (n, tot) in FACTS.items():
    check("B.of.%s" % name.replace(" ", "_").replace("/", "_"),
          ("**%d/%d**" % (n, tot)) in doc, "%d/%d not in doc" % (n, tot))
check("B.vlan_ip_zero", ("**%d/%d**" % (alive("T_rep1", "v4"), 36)) in doc)

# the six cells that move, re-derived
pB, vB = cells("T_rep1", "pB"), cells("T_rep1", "vB")
moved = sorted(c for c in pB if pB.get(c) != vB.get(c))
check("B.six_cells_move", len(moved) == 6, str(moved))
for c in moved:
    check("B.cell.%d_%d_in_doc" % c, ("(%d,%d)" % c) in doc)

# the verdict block
for env, text in (("bp", "| `b16_2` | plain | — | **0** |"),
                  ("bv", "| `b16_2` | 802.1Q | — | **1** |")):
    check("B.verdict.%s_line" % env, text in doc, text)

# both boots agree, cell for cell -- checked here again, not only in verify557
same = all(cells("T_rep1", e) == cells("T_rep2", e)
           for e in ("p4", "v4", "pB", "vB", "ipip", "vxlan", "p4s"))
check("B.two_boots_identical", same)

print("audit_f35_doc: %d cells checked, %d mismatches" % (len(OK), len(FAIL)))
for name, detail in FAIL:
    print("FAIL %s %s" % (name, detail))
sys.exit(1 if FAIL else 0)
