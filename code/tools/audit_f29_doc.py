#!/usr/bin/env python3
"""audit_f29_doc.py -- recompute every cell of F29's tables from the logs.

The SUMMARY is prose about numbers; this script makes the numbers checkable.
It parses the markdown tables in findings/F29-inner-store-base/SUMMARY.md,
rebuilds the same table from logs/f29_*_rep*.log, and compares cell by cell.
A "×5" cell means "the same value on all five kernels" and is expanded before
the comparison, so the shorthand is itself a checked claim.

Exit 0 only when every cell agrees.
"""
import binascii
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F29-inner-store-base/SUMMARY.md")
LOG = os.path.join(ROOT, "logs")
K = ["Q", "R", "B", "G", "P"]

CELLS = 0
BAD = []


def check(what, got, want):
    global CELLS
    CELLS += 1
    if got != want:
        BAD.append((what, got, want))
        print("MISMATCH %s: doc %r log %r" % (what, got, want))


def logs():
    out = {}
    for k in K:
        with open(os.path.join(LOG, "f29_%s_rep1.log" % k), errors="replace") as fh:
            out[k] = [l for l in fh.read().split("\n") if l.startswith("F551")]
    with open(os.path.join(LOG, "f29_B_rep2.log"), errors="replace") as fh:
        out["B2"] = [l for l in fh.read().split("\n") if l.startswith("F551")]
    return out


def field(line, key):
    m = re.search(r"\|%s=([^|]*)" % key, line)
    return m.group(1) if m else None


def line_with(L, prefix):
    hits = [l for l in L if l.startswith(prefix)]
    return hits[0] if hits else None


def a_row(L, tag):
    l = line_with(L, "F551 A.%s|" % tag)
    n = field(l, "nchg")
    if n == "0":
        return "нет"
    chg = field(l, "chg")
    return chg


def tables(md):
    """all markdown tables as lists of rows of cells"""
    out, cur = [], []
    for line in md.split("\n"):
        if line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue
            cur.append(cells)
        else:
            if cur:
                out.append(cur)
                cur = []
    if cur:
        out.append(cur)
    return out


def expand(cells, n=5):
    """a '×5' cell means: the previous value, repeated down the five columns"""
    out = []
    for c in cells:
        if c == "×5" and out:
            while len(out) < n:
                out.append(out[-1])
        elif c != "" or len(out) < n:
            out.append(c)
    while len(out) < n:
        out.append(out[-1] if out else "")
    return out[:n]


def main():
    md = open(DOC, encoding="utf-8").read()
    L = logs()

    # ---- table 1: the same byte through two bases, five kernels
    a_expected = {
        "@th,96,8 set 0x60": "th.do6",
        "@th,104,8 set 0x02": "th.flags",
        "@ih,432,8 set 0x60": "ih.vx.do6",
        "@ih,440,8 set 0x02": "ih.vx.flags",
        "@ih,432,16 set 0x6018": "ih.vx.do6w",
        "@ih,496,8 set 0x60": "ih.gn.do6",
        "@ih,256,8 set 0x60": "ih.ipip.do6",
    }
    seen = 0
    for tab in tables(md):
        if not tab or len(tab[0]) != 6:
            continue
        head = tab[0]
        if not head[0].startswith("форма"):
            continue
        for row in tab[1:]:
            label = row[0].strip("`")
            tag = None
            for key, t in a_expected.items():
                if label.startswith(key):
                    tag = t
                    break
            if tag is None:
                continue
            seen += 1
            want = expand(row[1:])
            got = []
            for k in K:
                # the doc prints the change, or "нет" when nothing moved
                v = a_row(L[k], tag)
                if v == "нет":
                    got.append("нет")
                else:
                    got.append(v.replace("**", ""))
            for i, k in enumerate(K):
                check("table1 %s %s" % (label, k), got[i], want[i].strip("`").replace("**", ""))
    check("table1 rows found", seen, 7)

    # ---- the two extra rows of table 1 (no tunnel / below the inner IP)
    for k in K:
        check("notunnel %s plain" % k, a_row(L[k], "ih.plain.do6"), "нет")
        check("notunnel %s tun0" % k, a_row(L[k], "ih.vx.tun0"), "42:08>64")
        check("notunnel %s eth" % k, a_row(L[k], "ih.vx.eth"), "50:02>aa")

    # ---- table 3: the guard's predicate at the netlink level
    pred = {
        "transport, диапазон задевает байт 12": (["B.t.11.2", "B.t.12.1", "B.t.12.2",
                                                  "B.t.12.4", "B.t.12.same"], "5/5 доставлено"),
        "transport, `13.1` (не задевает)": (["B.t.13.1"], "1/1"),
        "**inner, 10 плеч**": (["B.i.50.8", "B.i.52.2", "B.i.53.2", "B.i.54.1", "B.i.54.2",
                                "B.i.54.4", "B.i.55.1", "B.i.56.2", "B.i.gn.62.1",
                                "B.i.ipip.32.1"], ""),
        "inner на кадре без туннеля": (["B.i.plain.54.1"], "0/1"),
    }
    for tab in tables(md):
        if not tab or len(tab[0]) != 6 or not tab[0][0].startswith("плечи"):
            continue
        for row in tab[1:]:
            key = row[0]
            hit = [k for k in pred if k in key or key in k]
            if not hit:
                continue
            arms, _ = pred[hit[0]]
            cells = expand(row[1:])
            for i, k in enumerate(K):
                caps = [int(field(line_with(L[k], "F551 %s|" % a), "cap")) for a in arms]
                n = len(arms)
                got = "%d/%d" % (sum(caps), n)
                doc = cells[i].replace("**", "").strip()
                if doc.startswith("**"):
                    doc = doc[2:]
                # the doc writes "5/5 доставлено", "0/5", "10/10", "1/1", "0/1"
                want = re.match(r"(\d+/\d+)", doc)
                check("table3 %s %s" % (key, k), got, want.group(1) if want else doc)

    # ---- table 4: the consequence
    c_rows = {
        "`@th,96,8 set 0x60 counter accept`": ("C.th.do6", "counter"),
        "`@ih,432,8 set 0x60 counter accept`": ("C.ih.vx.do6", "counter"),
        "`counter accept` без записи": ("C.ctl.accept", "counter"),
        "без правила вовсе": ("C.ctl.norule", "counter"),
        "`@ih,432,8 … accept` на кадре без туннеля": ("C.ih.plain.do6", "counter"),
    }
    for tab in tables(md):
        if not tab or len(tab[0]) != 6 or not tab[0][0].startswith("правило"):
            continue
        for row in tab[1:]:
            key = row[0].strip()
            hit = [k for k in c_rows if k in key]
            if not hit:
                continue
            tag, _ = c_rows[hit[0]]
            cells = expand(row[1:])
            for i, k in enumerate(K):
                l = line_with(L[k], "F551 %s|" % tag)
                counter = field(l, "counter_after")
                cap = field(l, "cap")
                doc = cells[i].replace("**", "")
                num = re.search(r"(\d+)", doc)
                want = num.group(1) if num else "none"
                got = counter if counter != "none" else "none"
                check("table4 %s %s counter" % (key, k), got, want)
                # and the delivery bit, where the doc names it
                if "отброшено" in doc:
                    check("table4 %s %s cap" % (key, k), cap, "0")
                elif "доставлено" in doc:
                    check("table4 %s %s cap" % (key, k), cap, "1")

    # ---- table 5: the inner checksum
    d_rows = {
        "`i.50.8`, `i.52.2`, `i.54.1`, `i.54.2`, `i.54.4`, `i.56.2`, `D.align.54`":
            (["B.i.50.8", "B.i.52.2", "B.i.54.1", "B.i.54.2", "B.i.54.4", "B.i.56.2",
              "D.align.54"], "1"),
        "`i.53.2`, `i.55.1`, `D.odd.55`": (["B.i.53.2", "B.i.55.1", "D.odd.55"], "0"),
        "`D.none.55`": (["D.none.55"], "0"),
        "`D.saddr.34`": (["D.saddr.34"], "1"),
    }
    for tab in tables(md):
        if not tab or len(tab[0]) != 7 or not tab[0][0].startswith("плечо"):
            continue
        for row in tab[1:]:
            key = row[0].strip()
            hit = [k for k in d_rows if k in key]
            if not hit:
                continue
            arms, _ = d_rows[hit[0]]
            cells = expand(row[2:])
            for i, k in enumerate(K):
                vals = [field(line_with(L[k], "F551 %s|" % a), "itcsum") for a in arms]
                doc = cells[i].replace("**", "")
                # the doc uses ✓ / ✗ ; the parity fix makes P the exception
                want_valid = "✗" not in doc
                if "**✓**" in doc:
                    want_valid = True
                if "**✗**" in doc:
                    want_valid = False
                got_valid = all(v == "1" for v in vals)
                check("table5 %s %s" % (hit[0][:24], k), got_valid, want_valid)

    # ---- the coordinates named in the prose
    coords = {"vxlan": ("ih.vx.do6", "96:50>60"), "geneve": ("ih.gn.do6", "104:50>60"),
              "ipip": ("ih.ipip.do6", "66:50>60")}
    for name, (tag, want) in coords.items():
        check("coord %s" % name, a_row(L["B"], tag), want)
    for k in K:
        check("coord th.do6 %s" % k,
              a_row(L[k], "th.do6"), "46:50>60" if k == "Q" else "нет")

    # ---- counts the prose claims
    for k in K:
        n = len([l for l in L[k] if l.startswith("F551 ") and not l.startswith("F551NL")])
        check("lines %s" % k, n, 63)
        check("A arms %s" % k, len([l for l in L[k] if l.startswith("F551 A.")]), 17)
        check("B arms %s" % k, len([l for l in L[k] if l.startswith("F551 B.")]), 23)
        check("C arms %s" % k, len([l for l in L[k] if l.startswith("F551 C.")]), 8)
        check("D arms %s" % k, len([l for l in L[k] if l.startswith("F551 D.")]), 6)

    # ---- the netlink message the prose quotes
    quote = ("[ payload write reg 1 => 2b @ inner header + 54 csum_type 0 "
             "csum_off 0 csum_flags 0x1 ]")
    check("prose netlink quote present in doc", quote in md, True)
    norm = lambda t: re.sub(r"\s+", " ", t)
    for k in K:
        check("netlink quote in log %s" % k,
              any(norm(quote) in norm(l) for l in L[k]), True)

    print("\n=== %d cells, %d mismatches ===" % (CELLS, len(BAD)))
    return 0 if not BAD else 1


if __name__ == "__main__":
    sys.exit(main())
