#!/usr/bin/env python3
"""audit_f37_doc.py -- re-derive every table in F37/SUMMARY.md from the logs.

The SUMMARY is not trusted: f37_summary.py regenerates the tables from
logs/f37_rep1.log and every generated `|` row must appear verbatim in the
document.  Three single-cell substitutions in a COPY of the document must break
the audit, so the audit itself is shown to be able to fail.
"""
import os
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F37-tag-on-the-wire/SUMMARY.md")


def generated():
    out = subprocess.run([sys.executable, os.path.join(ROOT, "tools/f37_summary.py")],
                         cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("f37_summary.py failed: " + out.stderr[-400:])
    return out.stdout


def rows(text):
    return [x for x in text.splitlines() if x.startswith("|")]


def audit(doc_text, gen_text):
    g = rows(gen_text)
    bad = [r for r in g if r not in doc_text]
    return g, bad


def main():
    gen = generated()
    doc = open(DOC).read()
    g, bad = audit(doc, gen)
    cells = sum(len([c for c in r.split("|") if c.strip()]) for r in g)
    print("rows=%d cells=%d missing=%d" % (len(g), cells, len(bad)))
    for r in bad:
        print("MISSING %s" % r[:140])
    muts, caught = 0, 0
    for old, new in (("| 64 | `810000640800` | 60 |", "| 64 | `810000640900` | 60 |"),
                     ("**31/36**", "**32/36**"),
                     ("| `810000640800` | `1f90` |", "| `810000640800` | `1f91` |")):
        muts += 1
        if old not in doc:
            print("MUT-ANCHOR-MISSING %r" % old)
            continue
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
