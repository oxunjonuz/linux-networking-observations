#!/usr/bin/env python3
"""audit_f36_doc.py -- re-derive every table in F36/SUMMARY.md from the logs.

The SUMMARY is not trusted: f36_summary.py regenerates the tables from
logs/f36_{V_rep1,V_rep2,T_rep1}.log, and every generated `|` row must appear
verbatim in SUMMARY.md.  Single-cell substitutions in a COPY of the document
must break it (checked here as well, so the audit itself is shown to be able
to fail).
"""
import os
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F36-vlan-envelope/SUMMARY.md")


def generated():
    out = subprocess.run([sys.executable, os.path.join(ROOT, "tools/f36_summary.py")],
                         cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("f36_summary.py failed: " + out.stderr[-400:])
    return out.stdout


def rows(text):
    return [l for l in text.splitlines() if l.startswith("|")]


def audit(doc_text, gen_text):
    bad = []
    g = rows(gen_text)
    for r in g:
        if r not in doc_text:
            bad.append(r)
    return g, bad


def main():
    gen = generated()
    doc = open(DOC).read()
    g, bad = audit(doc, gen)
    cells = sum(len([c for c in r.split("|") if c.strip()]) for r in g)
    print("rows=%d cells=%d missing=%d" % (len(g), cells, len(bad)))
    for r in bad:
        print("MISSING %s" % r[:120])
    # the audit must be able to fail: three single-cell substitutions
    muts = 0
    caught = 0
    for old, new in (("| 23/36 / 23/36 / 23/36 | yes |",
                      "| 23/36 / 23/36 / 22/36 | yes |"),
                     ("| `13:00>06` | `13:00>06` |", "| `unchanged` | `13:00>06` |"),
                     ("| 1 | +2 | `unchanged` | `unchanged` |",
                      "| 1 | +0 | `unchanged` | `unchanged` |")):
        muts += 1
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write(doc.replace(old, new, 1))
            tmp = f.name
        try:
            _, b2 = audit(open(tmp).read(), gen)
            if b2:
                caught += 1
        finally:
            os.unlink(tmp)
    print("mutations=%d caught=%d" % (muts, caught))
    ok = not bad and caught == muts
    print("SUMMARY|%s|cells=%d|missing=%d|mutations=%d|caught=%d"
          % ("PASS" if ok else "FAIL", cells, len(bad), muts, caught))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
