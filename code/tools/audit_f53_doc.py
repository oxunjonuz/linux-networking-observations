#!/usr/bin/env python3
"""audit_f53_doc.py [--self]

Every row of the tables that tools/f575_summary.py prints from the log must
appear **verbatim** in findings/F53-vlan-reorder/SUMMARY.md: the document's
tables are the output of the summary script, not a set typed by hand.

--self additionally performs three single-cell substitutions in a copy of the
document and requires each of them to be caught.
"""
import re
import subprocess
import sys

DOC = "findings/F53-vlan-reorder/SUMMARY.md"
doc = open(DOC).read()
doc_lines = {l.rstrip() for l in doc.splitlines()}

tables = subprocess.run([sys.executable, "tools/f575_summary.py",
                         "logs/f53_rep1.log"], capture_output=True, text=True).stdout
blocks = [b for b in re.split(r"(?m)^### ", tables) if b.startswith("T")]

rows = cells = bad = 0
for blk in blocks:
    for line in blk.splitlines():
        if not line.startswith("|"):
            continue
        rows += 1
        cells += sum(1 for c in line.strip("|").split("|") if c.strip())
        if set(line.replace("|", "").strip()) <= {"-", ":"}:
            continue
        if line.rstrip() not in doc_lines:
            bad += 1
            if bad <= 10:
                print("MISSING ROW %r" % line[:90])
print("audit: %d table rows, %d cells, %d rows missing" % (rows, cells, bad))

if bad == 0 and "--self" in sys.argv:
    subs = [("| `@ll,12,2` = `8100` | ch=0 | ch=1 | the tag's TPID |",
             "| `@ll,12,2` = `8100` | ch=0 | ch=0 | the tag's TPID |"),
            ("| `br0.101` | 101 | `8100` | absent | **off** |",
             "| `br0.101` | 101 | `8100` | `flags=1` | **off** |"),
            ("| `e_w18` | g6 | write `0000` @18 | 0 | yes | 1 | 1 | 0 |",
             "| `e_w18` | g6 | write `0000` @18 | 1 | yes | 1 | 1 | 0 |")]
    caught = 0
    for a, b in subs:
        if a not in doc:
            print("PROBE MISSING %r" % a)
            continue
        edited = doc.replace(a, b, 1)
        lines = {l.rstrip() for l in edited.splitlines()}
        miss = sum(1 for blk in blocks for line in blk.splitlines()
                   if line.startswith("|") and line.rstrip() not in lines)
        if miss:
            caught += 1
        else:
            print("PROBE NOT CAUGHT %r" % a)
    print("substitutions caught: %d/3" % caught)
    if caught != 3:
        sys.exit(2)

sys.exit(1 if bad else 0)
