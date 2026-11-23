#!/usr/bin/env python3
"""audit_f44_doc.py -- does SUMMARY.md say what the log measured?

The tables were pasted from tools/f44_summary.py, which derives them from
logs/f44_rep{1,2}.log into findings/F44-ingress-two-doors/summary.json.  This
script goes the other way: it parses the document's tables and compares every
cell with that JSON.  A number typed by hand into a table is a hard error, and
a table that drifted from the log reddens here even when verify566.py is green
-- the two scripts share no code path.

  audit_f44_doc.py            check the real document
  audit_f44_doc.py --mutants  three single-number substitutions in a copy,
                              each must redden at least one cell
"""
import json
import re
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F44-ingress-two-doors/SUMMARY.md"
JSN = ROOT + "/findings/F44-ingress-two-doors/summary.json"
VER = ROOT + "/logs/f44_verify.txt"

ok = 0
bad = 0
fails = []


def check(cond, what, detail=""):
    global ok, bad
    if cond:
        ok += 1
    else:
        bad += 1
        fails.append("%s%s" % (what, (": " + detail) if detail else ""))
    return cond


def eq(got, want, what):
    return check(got == want, what, "got %r want %r" % (got, want))


def cells(s):
    return [c.strip() for c in s.strip().strip("|").split("|")]


def tables(doc, needle):
    """every table whose header line contains the needle"""
    lines = doc.split("\n")
    out = []
    for i, ln in enumerate(lines):
        if ln.startswith("|") and needle in ln:
            rows = []
            for j in range(i + 2, len(lines)):
                if not lines[j].startswith("|"):
                    break
                rows.append(cells(lines[j]))
            out.append(rows)
    return out


def strip_ticks(s):
    return s.replace("`", "").strip()


def nz(s):
    return s.replace("*", "").replace("`", "").replace(" ", "").strip()


def run(doc, j, verbose=True):
    global ok, bad, fails
    ok, bad, fails = 0, 0, []

    # ---- §2 grid: passes / live / payload / L2HDR ------------------------
    tabs = tables(doc, "| дверь | конверт | проходов | записей | payload | L2HDR |")
    check(len(tabs) == 1, "§2 has the grid table", str(len(tabs)))
    if tabs:
        rows = {strip_ticks(r[0]) + "/" + strip_ticks(r[1]): r for r in tabs[0]}
        eq(len(rows), 20, "§2 grid has 20 rows")
        for r in j["td"]:
            k = "%s/%s" % (r["door"], r["env"])
            row = rows.get(k)
            if not check(row is not None, "§2 grid has a row for " + k):
                continue
            eq(row[2], str(r["passes"]), "§2 passes %s" % k)
            eq(row[3], "**%d/8**" % r["store_live"], "§2 live %s" % k)
            eq(row[4], str(r["payload_len"]) if r["passes"] else "--",
               "§2 payload length %s" % k)
            eq(row[5], str(r["l2"]) if r["passes"] else "--", "§2 L2HDR %s" % k)

    # ---- §2 byte table ---------------------------------------------------
    tabs = tables(doc, "| дверь | конверт | t0_2 |")
    check(len(tabs) == 1, "§2 has the byte table", str(len(tabs)))
    if tabs:
        rows = {strip_ticks(r[0]) + "/" + strip_ticks(r[1]): r for r in tabs[0]}
        eq(len(rows), 20, "§2 byte table has 20 rows")
        keys = ("t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4", "t12_4", "t16_2")
        for r in j["td"]:
            k = "%s/%s" % (r["door"], r["env"])
            row = rows.get(k)
            if not row:
                check(False, "§2 byte table has a row for " + k)
                continue
            for i, c in enumerate(keys):
                want = r["cells"][c]["at"]
                eq(row[2 + i], str(want) if want >= 0 else "--",
                   "§2 byte %s %s" % (k, c))

    # ---- §2 reads and the socket oracle ---------------------------------
    tabs = tables(doc, "| дверь | (0,2) | (2,2) | (6,2) |")
    check(len(tabs) == 1, "§2 has the read table")
    if tabs:
        for row, r in zip(tabs[0], j["rf"]):
            eq(strip_ticks(row[0]), r["door"], "read table door order")
            eq([row[1], row[2], row[3]],
               [str(r["reads"]["r0_2"]), str(r["reads"]["r2_2"]),
                str(r["reads"]["r6_2"])], "read counts %s" % r["door"])

    tabs = tables(doc, "| дверь | конверт | проходов | записей | u5000 | u5001 |")
    check(len(tabs) == 1, "§2 has the socket table")
    if tabs:
        rows = {strip_ticks(r[0]) + "/" + strip_ticks(r[1]): r for r in tabs[0]}
        for r in j["dp"]:
            k = "%s/%s" % (r["door"], r["env"])
            row = rows.get(k)
            if not check(row is not None, "socket table row " + k):
                continue
            eq(row[2], str(r["livep"]), "socket passes %s" % k)
            eq(row[3], str(r["lives"]), "socket store live %s" % k)
            eq(row[4], str(r["u5000"]), "socket u5000 %s" % k)
            eq(row[5], str(r["u5001"]), "socket u5001 %s" % k)

    # ---- §3 meta ---------------------------------------------------------
    tabs = tables(doc, "| дверь | конверт | проходов | записей | первый изменённый байт |")
    check(len(tabs) == 1, "§3 has the meta table")
    if tabs:
        rows = {strip_ticks(r[0]) + "/" + strip_ticks(r[1]).split()[0]: r
                for r in tabs[0]}
        for r in j["tm"]:
            k = "%s/%s" % (r["door"], r["env"])
            row = rows.get(k)
            if not check(row is not None, "§3 row " + k):
                continue
            eq(nz(row[2]), str(r["passes"]), "§3 passes %s" % k)
            eq(nz(row[3]), "%d/8" % r["store_live"], "§3 live %s" % k)
            eq(nz(row[4]), str(r["at"]) if r["at"] >= 0 else "—",
               "§3 first byte %s" % k)

    # ---- §4 the two guard tables ----------------------------------------
    tabs = tables(doc, "| дверь | конверт | живых | отказано |")
    check(len(tabs) == 2, "§4 has two guard tables", str(len(tabs)))
    for tab, key, tot in ((tabs[0], "gd", 12), (tabs[1] if len(tabs) > 1 else [], "gn", 20)):
        rows = {strip_ticks(r[0]) + "/" + strip_ticks(r[1]): r for r in tab if len(r) >= 4}
        for r in j[key]:
            k = "%s/%s" % (r["door"], r["env"])
            row = rows.get(k)
            if not check(row is not None, "§4 %s row %s" % (key, k)):
                continue
            eq(nz(row[2]), "%d/%d" % (r["n_live"], tot),
               "§4 %s live %s" % (key, k))
            want = ", ".join("(%d,%d)" % (a, b) for a, b in r["refused"]) or "--"
            eq(row[3].replace(" ", ""), want.replace(" ", ""),
               "§4 %s refused list %s" % (key, k))

    # ---- §5 the drop -----------------------------------------------------
    tabs = tables(doc, "| проход | кадр | проходов | записей | ipin | ihdr | itrun | дальний тап |")
    check(len(tabs) == 1, "§5 has the drop table")
    if tabs:
        label = {"md_both": "обе двери", "md_ndg": "только netdev",
                 "md_ieg": "только inet"}
        rows = {(r[0], strip_ticks(r[1])): r for r in tabs[0]}
        for r in j["md"]:
            k = (label[r["sec"]], r["env"])
            row = rows.get(k)
            if not check(row is not None, "§5 row %s/%s" % k):
                continue
            eq(nz(row[2]), str(r["livep"]), "§5 passes %s/%s" % k)
            eq(nz(row[3]), str(r["lives"]), "§5 store live %s/%s" % k)
            eq(nz(row[4]), str(r["ipin"]), "§5 ipin %s/%s" % k)
            eq(nz(row[5]), str(r["ihdr"]), "§5 ihdr %s/%s" % k)
            eq(nz(row[6]), str(r["itrun"]), "§5 itrun %s/%s" % k)
            want = "нет кадра" if r["rn"] < 0 else "%d байт" % r["rn"]
            eq(nz(row[7]), nz(want), "§5 far tap %s/%s" % k)

    # ---- §6 the far tap --------------------------------------------------
    tabs = tables(doc, "| плечо | изменения на дальнем тапе | длина кадра |")
    check(len(tabs) == 1, "§6 has the far-tap table")
    if tabs:
        body = "\n".join("|".join(r) for r in tabs[0])
        for r in j["far"]:
            tag = "%s/%s/%s/%s" % (r["sec"], r["door"], r["env"], r["arm"])
            if not check(tag in body, "§6 names the arm " + tag):
                continue
            row = [x for x in tabs[0] if tag in x[0]][0]
            if r["rchg"] == 0:
                eq(row[1], "**ничего**", "§6 says nothing changed for " + tag)
            elif r["rchg"] <= 4:
                eq(nz(row[1]), nz(r["rchgs"]),
                   "§6 diff bytes for " + tag)
            else:
                check(row[1].startswith("%d байта" % r["rchg"]),
                      "§6 diff count for " + tag, row[1])
            want_len = "**60 → 64**" if r["rhex_len"] == 64 else str(r["rhex_len"])
            eq(row[2], want_len, "§6 frame length for " + tag)

    # ---- §9 numbers derived from the log, not typed ----------------------
    m = re.search(r"\*\*(\d+) проверки, 0 расхождений\*\*", doc)
    if check(m is not None, "§9 quotes the verifier's check count"):
        try:
            vt = open(VER, "rb").read().decode("utf-8", "replace")
        except IOError:
            vt = ""
        mm = re.search(r"checks: (\d+) ok, (\d+) failed", vt)
        if check(mm is not None, "logs/f44_verify.txt has a summary line"):
            eq(int(m.group(1)), int(mm.group(1)),
               "the check count in §9 equals the verifier's own count")
            eq(int(mm.group(2)), 0, "and the verifier reported no failure")
    eq("348 плеч в каждой из двух загрузок" in doc, True,
       "§0 quotes 348 arms per boot")
    eq(j["provenance"]["arms_rep1"], 348, "summary.json agrees: 348 arms in rep1")
    eq(j["provenance"]["arms_rep2"], 348, "summary.json agrees: 348 arms in rep2")
    eq(j["provenance"]["deterministic"], True, "and the two boots are identical")
    eq(j["provenance"]["splat"], False, "no splat in the log")
    eq(j["provenance"]["initrd_sha256"] == "" , False, "initrd sha recorded")
    eq(j["provenance"]["differ_sha256"] == "", False, "differ sha recorded")

    if verbose:
        print("audit: %d cells, %d mismatches" % (ok, bad))
        for f in fails[:20]:
            print("MISMATCH:", f)
    return bad


def main():
    doc = open(DOC, "rb").read().decode("utf-8", "replace")
    j = json.load(open(JSN))
    bad = run(doc, j)
    if len(sys.argv) > 1 and sys.argv[1] == "--mutants":
        muts = []
        # three single-number substitutions in a copy of the document
        for a, b, name in (("| `ieg` | `p` | 1 | **8/8** | 46 | 0 |",
                            "| `ieg` | `p` | 1 | **7/8** | 46 | 0 |",
                            "one live cell in §2"),
                           ("| `ieg` | `p` | **9/20** |",
                            "| `ieg` | `p` | **8/20** |",
                            "the @nh count in §4"),
                           ("| только netdev | `badver` | 1 | **1** | 2 | 2 | 0 | **60 байт** |",
                            "| только netdev | `badver` | 1 | **1** | 2 | 1 | 0 | **60 байт** |",
                            "one counter in §5")):
            if a not in doc:
                print("MUTANT_NOT_APPLICABLE:", name)
                bad += 1
                continue
            muts.append((name, doc.replace(a, b)))
        for name, mdoc in muts:
            n = run(mdoc, j, verbose=False)
            if n == 0:
                print("MUTANT_SURVIVED:", name)
                bad += 1
            else:
                print("mutant caught: %s (%d cells red)" % (name, n))
    print("AUDIT %s" % ("OK" if bad == 0 else "FAILED"))
    sys.exit(0 if bad == 0 else 1)


if __name__ == "__main__":
    main()
