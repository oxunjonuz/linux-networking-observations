#!/usr/bin/env python3
"""f37_summary.py -- the tables of F37/SUMMARY.md, DERIVED from the logs.

Every `|` row printed here is regenerated from logs/f37_{rep1,rep2}.log; with
--splice the blocks in findings/F37-tag-on-the-wire/SUMMARY.md between
`<!-- gen:NAME -->` and `<!-- end:NAME -->` are rewritten from the same rows, so
the document cannot drift from the measurement (audit_f37_doc.py checks that).
"""
import os
import re
import sys

ROOT = "/work/kernel-sec"
sys.path.insert(0, os.path.join(ROOT, "tools"))
import verify559 as V  # noqa: E402

DOC = os.path.join(ROOT, "findings/F37-tag-on-the-wire/SUMMARY.md")
LOGS = ("rep1",)


def load():
    p = os.path.join(ROOT, "logs/f37_%s.log" % LOGS[0])
    return V.parse(p)


def hx(b, lo, hi):
    return b[lo:hi].hex() if b else "-"


def table_bit(A):
    rows = ["| stage | r1 avail bit 7 | r1 active bit 7 | SFEATURES rc | "
            "tagged control on the wire |", "|---|---|---|---|---|"]
    feat = {}
    for f in A["feat"]:
        if f.get("dev") == "r1":
            feat.setdefault(f.get("stage"), f)
    f0 = feat.get("init", {})
    rows.append("| init (nothing asked) | %s | %s | — | — |"
                % (f0.get("avail_tx", "?"), f0.get("act_tx", "?")))
    for stage in ("clear", "restore", "clear2"):
        s = [x for x in A["set"] if x.get("stage") == stage]
        f = feat.get(stage, {})
        if not s:
            continue
        s = s[0]
        state = {"clear": "clear", "restore": "restored", "clear2": "clear"}[stage]
        ctl = V.hexs(A["run"].get((state, "wire", "ctl"), {}))
        rows.append("| %s | %s | %s | %s (F_UNSUPPORTED=%s, F_WISH=%s) | %d bytes: `%s` |"
                    % (stage, f.get("avail_tx", "?"), f.get("act_tx", "?"),
                       s.get("rc"), s.get("f_unsup"), s.get("f_wish"),
                       len(ctl), hx(ctl, 12, 18)))
    return rows


def table_wire(A):
    rows = ["| state of bit 7 | arm | store | wire len | wire 12..17 | "
            "far len | far 12..17 | ipin |", "|---|---|---|---|---|---|---|---|"]
    order = ["ctl", "s16_2", "s14_99", "s14_0", "s12_2z", "s12_4z",
             "ctl_plain", "s16_2_plain"]
    for state in ("on", "clear", "restored"):
        for arm in order:
            f = A["run"].get((state, "wire", arm))
            if not f:
                continue
            st = V.ARMS.get(arm)
            store = "none" if st is None else "(%d,%d)=`%s`" % (
                st[0], st[1], st[2].hex())
            w = V.hexs(f)
            r = V.rhexs(f)
            rows.append("| %s | `%s` | %s | %d | `%s` | %d | `%s` | %s |"
                        % (state, arm, store, len(w), hx(w, 12, 18), len(r),
                           hx(r, 12, 18), f.get("ipin")))
    return rows


def table_grid(A):
    rows = ["| combo | proto | tag | live/36 | dead cells | live byte on the "
            "wire | on the far tap |", "|---|---|---|---|---|---|---|"]
    for combo, (proto, tagged) in (("p6T", (6, True)), ("p6P", (6, False)),
                                   ("uT", (17, True)), ("uP", (17, False))):
        if ("clear", combo, "ctl") not in A["run"]:
            continue
        dead, live = [], 0
        for (off, ln) in V.CELLS:
            f = A["run"].get(("clear", combo, "g%d_%d" % (off, ln)))
            if not f:
                continue
            if f.get("live") == "1":
                live += 1
            else:
                dead.append("(%d,%d)" % (off, ln))
        base = 38 if tagged else 34
        rows.append("| `%s` | %d | %s | **%d/36** | %s | `%d+off` | `34+off` |"
                    % (combo, proto, "yes" if tagged else "no", live,
                       " ".join(dead) if dead else "—", base))
    return rows


def table_chain(A):
    rows = ["| arm | what `pre` writes | post's store | wire 12..17 | wire 38..39 |",
            "|---|---|---|---|---|"]
    for arm, what in (("a_none", "nothing"),
                      ("b_et", "(16,2)=`0806`"),
                      ("c_tci", "(14,2)=`0099`")):
        f = A["c"].get(arm)
        if not f:
            continue
        w = V.hexs(f)
        verdict = "alive (counter 1)" if f.get("live") == "1" else "**dead (counter 0)**"
        rows.append("| `%s` | %s | %s | `%s` | `%s` |"
                    % (arm, what, verdict, hx(w, 12, 18), hx(w, 38, 40)))
    return rows


BLOCKS = {"bit": table_bit, "wire": table_wire, "grid": table_grid,
          "chain": table_chain}


def splice(doc, name, rows):
    start = "<!-- gen:%s -->" % name
    end = "<!-- end:%s -->" % name
    i = doc.index(start) + len(start)
    j = doc.index(end)
    return doc[:i] + "\n" + "\n".join(rows) + "\n" + doc[j:]


def main():
    A = load()
    rows = []
    for name, fn in BLOCKS.items():
        r = fn(A)
        rows.extend(r)
    if "--splice" in sys.argv:
        doc = open(DOC).read()
        for name, fn in BLOCKS.items():
            doc = splice(doc, name, fn(A))
        open(DOC, "w").write(doc)
        print("spliced %d blocks into %s" % (len(BLOCKS), DOC))
        return 0
    print("\n".join(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
