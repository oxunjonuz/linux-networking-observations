#!/usr/bin/env python3
"""f33_splice.py -- put the generated tables into SUMMARY.md.

The three tables marked F33T1/F33T2/F33T3 are produced by tools/f33_summary.py
and pasted in unchanged: the document is not allowed to carry a number that was
typed by hand.  Everything between a marker and the next blank line is
replaced; the prose around it is untouched.

usage: python3 tools/f33_splice.py [--check]
       --check  only report whether the document already matches the logs
"""
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F33-guard-type-table/SUMMARY.md"


def blocks(tag):
    out = subprocess.run([sys.executable, ROOT + "/tools/f33_summary.py", tag],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("f33_summary.py failed: " + out.stderr[-500:])
    cur, acc = None, {}
    for line in out.stdout.splitlines():
        m = re.match(r"^<!-- (F33T\d) -->$", line)
        if m:
            cur = m.group(1)
            acc[cur] = []
            continue
        if cur and line.startswith("|"):
            # only table rows: f33_summary also prints a few diagnostic lines
            # after the last marker, and they are not part of the document
            acc[cur].append(line)
    return acc


def main():
    check_only = "--check" in sys.argv
    bl = blocks("T_rep1")
    txt = open(DOC).read().splitlines()
    out, i = [], 0
    changed = 0
    while i < len(txt):
        line = txt[i]
        m = re.match(r"^<!-- (F33T\d) -->$", line)
        out.append(line)
        i += 1
        if m and m.group(1) in bl:
            # drop the old body up to the first blank line
            j = i
            while j < len(txt) and txt[j].strip():
                j += 1
            new = bl[m.group(1)]
            if txt[i:j] != new:
                changed += 1
                print("%s: body replaced (%d -> %d lines)"
                      % (m.group(1), j - i, len(new)))
            out.extend(new)
            i = j
            continue
    if check_only:
        print("f33_splice: %d table(s) would change" % changed)
        sys.exit(1 if changed else 0)
    open(DOC, "w").write("\n".join(out) + "\n")
    print("f33_splice: %d table(s) changed" % changed)


if __name__ == "__main__":
    main()
