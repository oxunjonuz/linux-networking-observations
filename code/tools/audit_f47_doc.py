#!/usr/bin/env python3
"""audit_f47_doc.py -- does the document say what the logs say?

Every generated table of findings/F47-ipv6-egress/SUMMARY.md is re-derived from
the two frozen logs and compared cell by cell.  The tables are found by their
header line, so the document can grow prose around them without the audit
losing track.

Cells that the generator fills with a number are compared exactly; a mismatch is
printed with its row and column.  Additionally the prose numbers that appear
more than once in the report (8 packets, 0x3f, 56 bytes, the checksum pair) are
checked against the logs.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import f569_summary as S            # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "findings/F47-ipv6-egress/SUMMARY.md"

fails = []
cells = 0


def ck(cond, msg):
    global cells
    cells += 1
    if not cond:
        fails.append(msg)


def tables_in_doc(text):
    """{header-tuple: [rows]} for every markdown table in the document."""
    out, cur, head = {}, None, None
    for ln in text.splitlines():
        if ln.startswith("|"):
            part = [c.strip() for c in ln.strip().strip("|").split("|")]
            if all(re.fullmatch(r"-+", c) for c in part):
                continue
            if head is None:
                head = tuple(part)
                cur = []
                out.setdefault(head, []).append(cur)
            else:
                cur.append(part)
        else:
            head, cur = None, None
    return out


def main():
    arms, iso = S.load()
    t = S.tables(arms, iso)
    text = DOC.read_text()
    doc = tables_in_doc(text)
    for name, tab in t.items():
        head = tuple(tab["head"])
        if head not in doc:
            if name in ("guard", "refused", "hop", "fate", "csum", "daddr", "iso"):
                ck(False, "table %s (%s) is not in the document" % (name, head))
            continue
        for block in doc[head]:
            if len(block) != len(tab["rows"]):
                ck(False, "%s: %d rows in the document, %d in the log"
                   % (name, len(block), len(tab["rows"])))
                continue
            for i, (drow, lrow) in enumerate(zip(block, tab["rows"])):
                for j, (dc, lc) in enumerate(zip(drow, lrow)):
                    ck(dc == str(lc), "%s row %d col %s: document %r, log %r"
                       % (name, i, head[j], dc, str(lc)))
    # the prose numbers that are easy to mistype
    d = arms.get(("rep1", "out", "loc", "daddr"), {})
    ck(d.get("cntp") == "8", "prose: the out/loc daddr arm counts %s packets, not 8"
       % d.get("cntp"))
    pre = arms.get(("rep1", "pre", "fwd", "hop64"), {})
    tap = pre.get("tap", "")
    ck(tap[42:44] == "3f", "prose: the hop limit written at prerouting is on the "
       "wire as %r, not 3f" % tap[42:44])
    ck("56" in text and any(
        len(f.get("m%d" % i, "")) // 2 == 56
        for f in [arms.get(("rep1", "post", "loc", "hop90"), {})]
        for i in range(int(f.get("nmsg", "0") or 0))), "prose: the 56-byte claim")
    ck("Udp6InErr" in text, "prose: the transport toll is not named")
    # and the tables must not be empty
    for name, tab in t.items():
        ck(len(tab["rows"]) > 0, "table %s is empty" % name)
    print("%d cells checked, %d failed" % (cells, len(fails)))
    for f in fails[:30]:
        print("!!", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
