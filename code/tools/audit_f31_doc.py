#!/usr/bin/env python3
"""audit_f31_doc.py -- recompute every cell of SUMMARY.md from the raw logs.

The SUMMARY is prose written after the fact; this script treats it as a set of
claims and re-derives each one from logs/f31_*.log.  Cell counts are printed so
the number in the document can be checked against this run.
"""
import os
import re
import sys

ROOT = "/work/kernel-sec"
LOG = os.path.join(ROOT, "logs")
DOC = os.path.join(ROOT, "findings/F31-envelope-guard/SUMMARY.md")

cells = 0
bad = []
doc = open(DOC, encoding="utf-8").read()


def cmp(cell_desc, ok, got, want):
    global cells
    cells += 1
    if not ok:
        bad.append("%s: got %r want %r" % (cell_desc, got, want))


def arms(path):
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        m = re.match(r"^F553 (?P<tag>[^|]+)\|label=(?P<label>[^|]*)\|rule=(?P<rule>[^|]*)"
                     r"\|cap=(?P<cap>\d+)\|flen=(?P<flen>\d+)\|nchg=(?P<nchg>\d+)"
                     r"\|chg=(?P<chg>[^|]*)\|cnt=(?P<cnt>\d+)", line)
        if m:
            d = m.groupdict()
            for k in ("cap", "flen", "nchg", "cnt"):
                d[k] = int(d[k])
            out[d["tag"]] = d
        if line.startswith("F553L "):
            tag = line.split("|")[0].split()[1]
            out[tag] = {
                "p5000": int(re.search(r"p5000=(\d+)", line).group(1)),
                "p6000": int(re.search(r"p6000=(\d+)", line).group(1)),
                "cnt": int(re.search(r"\|cnt=(\d+)", line).group(1)),
                "pay": re.search(r"pay=([0-9a-f]*)", line).group(1),
            }
        if line.startswith("F553 ") and "SKIP=" in line:
            out[line.split("|")[0].split()[1]] = {"skip": True}
    return out


K = ["Q", "R", "B", "C", "M"]
A = {k: arms(os.path.join(LOG, "f31_%s_rep1.log" % k)) for k in K}


def fam(path):
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.search(r"netdev=(\d)\|bridge=(\d)\|ip=(\d)", line)
        if line.startswith("F553 FAM|") and m:
            return "/".join(m.groups())
    return "?"


def cfg(tree):
    out = {}
    for line in open(os.path.join(ROOT, "src", tree, ".config")):
        for s in ("CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE", "CONFIG_NF_TABLES_NETDEV"):
            if line.startswith(s + "="):
                out[s] = line.strip().split("=", 1)[1]
    return out


# ---------- markdown tables ----------
def tables(text):
    out, cur = [], []
    for line in text.splitlines():
        if line.startswith("|"):
            cur.append([c.strip() for c in line.strip().strip("|").split("|")])
        else:
            if len(cur) > 2:
                out.append([r for r in cur if not all(re.fullmatch(r":?-+:?", c) for c in r)])
            cur = []
    if len(cur) > 2:
        out.append([r for r in cur if not all(re.fullmatch(r":?-+:?", c) for c in r)])
    return out


T = tables(doc)

# ---------- §1: config symbols and reachability ----------
t1 = [t for t in T if t[0][0].startswith("ядро")][0]
TREES = {"Q": "dl72/linux-7.2.15", "R": "linux-7.3-R19", "B": "linux-7.3.4-B19",
         "C": "linux-7.3.4-C553", "M": "dl72/linux-7.2.15-C553"}
for row in t1[1:]:
    k = row[0].split("—")[0].strip()
    if k not in K:
        # the header row of the second table style is skipped below
        continue
    syms = cfg(TREES[k])
    for i, s in enumerate(("CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE",
                           "CONFIG_NF_TABLES_NETDEV"), start=1):
        want = syms.get(s, "not set")
        cell = row[i].replace("**", "")
        if want == "y":
            cmp("%s %s" % (k, s), cell == "y", cell, "y")
        else:
            cmp("%s %s" % (k, s), cell == "not set", cell, "not set")
    got = fam(os.path.join(LOG, "f31_%s_rep1.log" % k))
    cell = row[4].replace("**", "")
    cmp("%s reachability" % k, cell == got, cell, got)

# ---------- §2: the A/B table ----------
t2 = [t for t in T if t[0][0].startswith("правило")][0]
ROWS2 = [
    ("@nh,336,16 set 0xcafe", {"Q": "sa.raw42", "R": "sa.raw42", "B": "sa.raw42",
                               "C": "sa.raw42", "M": "sa.raw42"}),
    ("@nh,64,32 set 0x3e11aabb", {"Q": "sa.raw8", "R": "sa.raw8", "B": "sa.raw8",
                                  "C": "sa.raw8", "M": "sa.raw8"}),
    ("@nh,64,8 set 0x20", {"Q": "sa.raw8ttl", "R": "sa.raw8ttl", "B": "sa.raw8ttl",
                           "C": "sa.raw8ttl", "M": "sa.raw8ttl"}),
    ("@nh,128,32 set 0x0a090007", {"Q": "sa.raw16", "R": "sa.raw16", "B": "sa.raw16",
                                   "C": "sa.raw16", "M": "sa.raw16"}),
    ("ip length set 0x0030", {"Q": "sa.kw.length", "R": "sa.kw.length",
                              "B": "sa.kw.length", "C": "sa.kw.length",
                              "M": "sa.kw.length"}),
    ("ip daddr set 10.9.0.7", {"Q": "sa.kw.daddr", "R": "sa.kw.daddr",
                               "B": "sa.kw.daddr", "C": "sa.kw.daddr",
                               "M": "sa.kw.daddr"}),
    ("SKIP", None),
    ("@nh,336,16", {"Q": "sb.raw42", "R": "sb.raw42", "B": "sb.raw42",
                    "C": "sb.raw42", "M": "sb.raw42"}),
    ("@nh,64,32", {"Q": "sb.raw8", "R": "sb.raw8", "B": "sb.raw8",
                   "C": "sb.raw8", "M": "sb.raw8"}),
    ("@nh,64,8", {"Q": "sb.raw8ttl", "R": "sb.raw8ttl", "B": "sb.raw8ttl",
                  "C": "sb.raw8ttl", "M": "sb.raw8ttl"}),
    ("@nh,128,32", {"Q": "sb.raw16", "R": "sb.raw16", "B": "sb.raw16",
                    "C": "sb.raw16", "M": "sb.raw16"}),
    ("ip length set 0x0030", {"Q": "sb.kw.length", "R": "sb.kw.length",
                              "B": "sb.kw.length", "C": "sb.kw.length",
                              "M": "sb.kw.length"}),
    ("ip daddr set 10.9.0.7", {"Q": "sb.kw.daddr", "R": "sb.kw.daddr",
                               "B": "sb.kw.daddr", "C": "sb.kw.daddr",
                               "M": "sb.kw.daddr"}),
]
rows2 = t2[1:]
cmp("§2 row count", len(rows2) == len(ROWS2), len(rows2), len(ROWS2))
for row, (key, tags) in zip(rows2, ROWS2):
    if key == "SKIP":
        # the row that announces the netdev half: every cell must say skip
        for i, k in enumerate(K, start=1):
            if k in ("C", "M"):
                cmp("§2 skip row %s" % k, row[i] == "—", row[i], "—")
            else:
                cmp("§2 skip row %s" % k, row[i] == "skip", row[i], "skip")
        continue
    for i, k in enumerate(K, start=1):
        d = A[k].get(tags[k])
        if d is None or d.get("skip"):
            want = "skip"
        else:
            want = "%d/%d/%d" % (d["cnt"], d["nchg"], d["cap"])
        cmp("§2 %s %s" % (k, tags[k]), row[i].replace("**", "") == want,
            row[i].replace("**", ""), want)

# ---------- §3: the label table ----------
t3 = [t for t in T if t[0][0].startswith("правило") and "0x9100" in " ".join(t[0])][0]
LAB = ["0x0800", "0x8100", "0x9100", "0x0806"]
ROWS3 = [
    ("@nh,128,32", "br.raw16.%s"),
    ("@nh,64,32", "br.raw8.%s"),
    ("ip daddr set 10.9.9.9", "br.kw.%s"),
    ("meta protocol 8021q", {1: "br.meta.tag.q"}),
    ("meta protocol ip", {0: "br.meta.untag.ip", 1: "br.meta.tag.ip",
                          2: "br.meta.91.ip", 3: "br.meta.arpip.ip"}),
    ("meta protocol 0x9100", {2: "br.meta.91.91"}),
]
rows3 = t3[1:]
cmp("§3 row count", len(rows3) == len(ROWS3), len(rows3), len(ROWS3))
for row, (key, pat) in zip(rows3, ROWS3):
    for j, lab in enumerate(LAB, start=1):
        cell = row[j]
        if isinstance(pat, dict):
            if j - 1 not in pat:
                cmp("§3 %s %s n/a" % (key, lab), cell == "—", cell, "—")
                continue
            tag = pat[j - 1]
        else:
            tag = pat % lab
        d = A["C"][tag]
        if isinstance(pat, dict):
            m = re.search(r"cnt (\d)", cell)
            cmp("§3 %s %s meta cnt" % (key, lab),
                m is not None and int(m.group(1)) == d["cnt"], cell, d["cnt"])
            continue
        n = cell.count("мёртв") + cell.count("жив")
        cmp("§3 %s %s one word" % (key, lab), n == 1, cell, "жив|мёртв")
        if "жив" in cell:
            cmp("§3 %s %s cnt" % (key, lab), d["cnt"] >= 1, d["cnt"], ">=1")
            m = re.search(r"\((\d+)\)", cell)
            if m:
                cmp("§3 %s %s bytes" % (key, lab), int(m.group(1)) == d["nchg"],
                    m.group(1), d["nchg"])
        elif "мёртв" in cell:
            cmp("§3 %s %s cnt" % (key, lab), d["cnt"] == 0, d["cnt"], 0)
            cmp("§3 %s %s nchg" % (key, lab), d["nchg"] == 0, d["nchg"], 0)
        else:
            m = re.search(r"cnt (\d)", cell)
            cmp("§3 %s %s meta cnt" % (key, lab), m is not None and
                int(m.group(1)) == d["cnt"], cell, d["cnt"])

# ---------- §5: the local socket table ----------
t5 = [t for t in T if t[0][0].startswith("правило на ingress")][0]
rows5 = t5[1:]
TAGS5 = ["sd.ctl", "sd.nh22", "sd.nh36"]
cmp("§5 row count", len(rows5) == 3, len(rows5), 3)
for row, tag in zip(rows5, TAGS5):
    d = A["C"][tag]
    for j, key in ((1, "p5000"), (2, "p6000")):
        cell = row[j].replace("*", "")
        cmp("§5 %s %s" % (tag, key), cell == str(d[key]), cell, d[key])
    cmp("§5 %s cnt" % tag, int(row[3].replace("*", "")) == d["cnt"], row[3], d["cnt"])
    pay = row[4].replace("`", "").replace("…", "").replace(" ", "")
    cmp("§5 %s pay" % tag, d["pay"].startswith(pay[:4]), pay, d["pay"][:8])

# ---------- §6/§7 numbers from the prose ----------
o = A["C"]["br.arpov.pad"]
cmp("§6 overshoot cnt", o["cnt"] == 1, o["cnt"], 1)
cmp("§6 overshoot bytes", o["nchg"] == 16, o["nchg"], 16)
cmp("§6 first changed byte is 34", o["chg"].startswith("34:"), o["chg"][:3], "34:")
cmp("§6 byte 42 is past the message", "42:" in o["chg"], o["chg"], "42:…")
cmp("§6 short frame refused", A["C"]["br.arpov.raw"]["cnt"] == 0,
    A["C"]["br.arpov.raw"]["cnt"], 0)
cmp("§6 short frame still delivered", A["C"]["br.arpov.raw"]["cap"] == 1,
    A["C"]["br.arpov.raw"]["cap"], 1)
cmp("§7 arp-labelled delivered", A["C"]["br.drp.raw8.arpip"]["cap"] == 1,
    A["C"]["br.drp.raw8.arpip"]["cap"], 1)
cmp("§7 arp-labelled counter", A["C"]["br.drp.raw8.arpip"]["cnt"] == 1,
    A["C"]["br.drp.raw8.arpip"]["cnt"], 1)
cmp("§7 0x9100 not delivered", A["C"]["br.drp.raw8.91"]["cap"] == 0,
    A["C"]["br.drp.raw8.91"]["cap"], 0)
cmp("§7 0x9100 counter", A["C"]["br.drp.raw8.91"]["cnt"] == 0,
    A["C"]["br.drp.raw8.91"]["cnt"], 0)
cmp("§7 control not delivered", A["C"]["br.drp.ctl.untag"]["cap"] == 0,
    A["C"]["br.drp.ctl.untag"]["cap"], 0)

# the "58 bytes instead of 62" claim in §4
ctl = None
for line in open(os.path.join(LOG, "f31_C_rep1.log"), encoding="utf-8", errors="replace"):
    if line.startswith("F553 br.ctl.0x8100|"):
        ctl = re.search(r"hex=([0-9a-f]*)$", line.rstrip("\r\n")).group(1)
cmp("§4 tagged frame length", len(ctl) // 2 == 58, len(ctl) // 2, 58)
cmp("§4 tagged frame label", ctl[24:28] == "0800", ctl[24:28], "0800")

# the two sentences in §8 that carry numbers
cmp("§8 C == M", all(
    (A["C"].get(t, {}).get("cnt") == A["M"].get(t, {}).get("cnt"))
    for t in A["C"] if not A["C"][t].get("skip")), True, True)

print("audit_f31_doc: %d cells, %d mismatches" % (cells, len(bad)))
for b in bad:
    print("  -", b)
sys.exit(1 if bad else 0)
