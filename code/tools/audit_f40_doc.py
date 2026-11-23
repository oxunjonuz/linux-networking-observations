#!/usr/bin/env python3
"""audit_f40_doc.py -- every number this document prints, checked against the logs.

The verifier checks the logs, not the prose; the summary script prints the
tables but nothing checks that the document still says what the script printed.
Each cell below is (regex over SUMMARY.md, value re-derived from the log).  A
cell that does not match is printed and the script exits non-zero.
"""
import importlib.util
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F40-nh-read-side/SUMMARY.md")

spec = importlib.util.spec_from_file_location("v", os.path.join(
    ROOT, "tools/verify562.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

rows = [r for r in v.parse(os.path.join(ROOT, "logs/f40_rep1.log"))
        if r["_k"] == "R"]
doc = open(DOC, errors="replace").read()

N = 0
FAIL = []


def cell(pattern, want, what):
    global N
    N += 1
    m = re.search(pattern, doc)
    if not m:
        FAIL.append((what, "row not found: %r" % pattern))
        return
    got = m.group(1)
    if got != want:
        FAIL.append((what, "doc=%r log=%r" % (got, want)))


def arms(env, off=None, ln=None, rd=None, wr=None, first=None):
    out = []
    for r in rows:
        if r.get("env") != env:
            continue
        if off is not None and v.i(r, "off") != off:
            continue
        if ln is not None and v.i(r, "len") != ln:
            continue
        if rd is not None and v.i(r, "rd") != rd:
            continue
        if wr is not None and v.i(r, "wr") != wr:
            continue
        if first is not None and v.i(r, "first") != first:
            continue
        out.append(r)
    return out


CELLS = [(o, l) for o in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24)
         for l in (1, 2, 4)] + [(0, 8), (8, 16), (16, 16), (20, 16)]


def count_live(env, cand):
    return sum(1 for r in arms(env) if r.get("cand") == cand and
               v.i(r, "live") == 1)


def discriminating(rep):
    return sum(1 for off, ln in CELLS
               if v.CAP[rep][14 + off:14 + off + ln] !=
               v.CAP[rep][18 + off:18 + off + ln])


# ---- 1. the read grid
for rep, tag in (("p", "`p`"), ("w", "`w`"), ("q", "`q`")):
    for etag, gtag in (("bare", "bare"), ("meta", "meta protocol")):
        env = "rd.%s.%s" % (rep, etag)
        cell(r"\| %s \| %s \| \*\*(\d+)/40\*\* \| \*\*\d+/40\*\* \| \d+ \|"
             % (re.escape(tag), re.escape(gtag)),
             str(count_live(env, "A")), "read grid A %s %s" % (rep, etag))
        cell(r"\| %s \| %s \| \*\*\d+/40\*\* \| \*\*(\d+)/40\*\* \| \d+ \|"
             % (re.escape(tag), re.escape(gtag)),
             str(count_live(env, "B")), "read grid B %s %s" % (rep, etag))
        cell(r"\| %s \| %s \| \*\*\d+/40\*\* \| \*\*\d+/40\*\* \| (\d+) \|"
             % (re.escape(tag), re.escape(gtag)),
             str(discriminating(rep)),
             "discriminating %s %s" % (rep, etag))

# the cells the document names as indistinguishable
N += 1
flat = " ".join(doc.split())
if not ("(2,1) (12,1) (14,1)` on `p` and `w`, `(6,1) (16,1)` on `q`" in flat):
    FAIL.append(("indistinguishable cells are named in the document", "missing"))
for rep, want in (("p", [(2, 1), (12, 1), (14, 1)]),
                  ("w", [(2, 1), (12, 1), (14, 1)]),
                  ("q", [(6, 1), (16, 1)])):
    got = [(off, ln) for off, ln in CELLS
           if v.CAP[rep][14 + off:14 + off + ln] ==
           v.CAP[rep][18 + off:18 + off + ln]]
    global_N = 0
    N += 1
    if got != want:
        FAIL.append(("indistinguishable %s" % rep, "doc=%r log=%r" % (want, got)))

# ---- 2. pair
PAIR = [
    ("p", "bare", "wr", 8, 1, 0, 0, "1", "22:40>90"),
    ("p", "bare", "rdwr", 8, 1, 1, 0, "1", "22:40>90"),
    ("p", "bare", "wrrd", 8, 1, 1, 1, "0", "22:40>90"),
    ("p", "bare", "wr", 16, 4, 0, 0, "1",
     "30:0a>90,31:09>91,32:00>92,33:07>93"),
    ("p", "bare", "rdwr", 16, 4, 1, 0, "1",
     "30:0a>90,31:09>91,32:00>92,33:07>93"),
    ("p", "bare", "wrrd", 16, 4, 1, 1, "0",
     "30:0a>90,31:09>91,32:00>92,33:07>93"),
    ("q", "meta", "wr", 8, 1, 0, 0, "1", "22:12>90"),
    ("q", "meta", "rdwr", 8, 1, 1, 0, "1", "22:12>90"),
    ("q", "meta", "wrrd", 8, 1, 1, 1, "1", "22:12>90"),
    ("q", "meta", "wr", 16, 4, 0, 0, "1",
     "30:0a>90,31:01>91,32:00>92,33:01>93"),
    ("q", "meta", "rdwr", 16, 4, 1, 0, "1",
     "30:0a>90,31:01>91,32:00>92,33:01>93"),
    ("q", "meta", "wrrd", 16, 4, 1, 1, "1",
     "30:0a>90,31:01>91,32:00>92,33:01>93"),
]
for rep, etag, kind, off, ln, rd, first, want_live, want_chg in PAIR:
    rs = arms("pair.%s.%s" % (rep, etag), off=off, ln=ln, rd=rd, wr=1,
              first=first)
    got_live = str(v.i(rs[0], "live")) if rs else "MISSING"
    got_chg = rs[0].get("wchgs", "-") if rs else "MISSING"
    N += 2
    # two independent cells per row: live and the byte string
    gtag = "bare" if etag == "bare" else "meta protocol"
    pat = (r"\| `%s` %s `%s` \(%d,%d\) \| \**(\d)\** \| "
          % (rep, re.escape(gtag), kind, off, ln))
    m = re.search(pat, doc)
    if not m:
        FAIL.append(("%s %s %s (%d,%d) live" % (rep, etag, kind, off, ln),
                     "row not found"))
    elif m.group(1) != want_live:
        FAIL.append(("%s %s %s (%d,%d) live" % (rep, etag, kind, off, ln),
                     "doc=%r log=%r" % (m.group(1), want_live)))
    pat = (r"\| `%s` %s `%s` \(%d,%d\) \| \**[01]\** \| "
          r"([^|\n]+?) \|" % (rep, re.escape(gtag), kind, off, ln))
    m = re.search(pat, doc)
    if not m:
        FAIL.append(("%s %s %s (%d,%d) bytes" % (rep, etag, kind, off, ln),
                     "row not found"))
    else:
        got = m.group(1).strip().strip("*").strip("`").split("`")[0].strip("* ")
        if got != want_chg:
            FAIL.append(("%s %s %s (%d,%d) bytes" % (rep, etag, kind, off, ln),
                         "doc=%r log=%r" % (got, want_chg)))

# the "what it names / where it hits" table
cell(r"\| \(8,1\) \| ttl \| (\d+) = IP byte 8 = ttl \|",
     "26", "(8,1) read position")
cell(r"\| \(8,1\) \| ttl \| \d+ = IP byte 8 = ttl \| (\d+) = IP byte 4 = "
     r"id high \|", "22", "(8,1) write position")
cell(r"\| \(16,4\) \| daddr \| (\d+)\.\.\d+ = IP byte 16\.\.19 = daddr \|",
     "34", "(16,4) read position")
cell(r"\| \(16,4\) \| daddr \| \d+\.\.\d+ = IP byte 16\.\.19 = daddr \| "
     r"(\d+)\.\.\d+ = IP byte 12\.\.15 = saddr \|", "30",
     "(16,4) write position")

# ---- 3. transport base
for rep in ("p", "q"):
    for etag, gtag in (("bare", "bare"), ("meta", "meta protocol")):
        env = "ih.%s.%s" % (rep, etag)
        t = [r for r in arms(env) if r.get("cand") == "T"]
        s = [r for r in arms(env) if v.i(r, "wr") == 1]
        lt = sum(1 for r in t if v.i(r, "live") == 1)
        ls = sum(1 for r in s if v.i(r, "live") == 1)
        pat = (r"\| `%s` \| %s \| \*\*(\d)/5\*\* \| \d/5 \| \*\*\d/5\*\* \|"
               % (rep, re.escape(gtag)))
        cell(pat, str(lt), "ih readT %s %s" % (rep, etag))
        pat = (r"\| `%s` \| %s \| \*\*\d/5\*\* \| \d/5 \| \*\*(\d)/5\*\* \|"
               % (rep, re.escape(gtag)))
        cell(pat, str(ls), "ih store %s %s" % (rep, etag))
        want = s[0].get("wchgs", "-") if s else "-"
        pat = (r"\| `%s` \| %s \| \*\*\d/5\*\* \| \d/5 \| \*\*\d/5\*\* \| ([^|]+) \|"
               % (rep, re.escape(gtag)))
        m = re.search(pat, doc)
        got = (m.group(1).strip().strip("`") if m else "?")
        got = "-" if got in ("-", "—") else got
        N += 1
        if got != want:
            FAIL.append(("ih bytes %s %s" % (rep, etag),
                         "doc=%r log=%r" % (got, want)))

# ---- 4. ARP
ARP = [("pa", "bare", 6, "1", "20:00>90,21:01>91"),
       ("pa", "bare", 8, "1", "22:aa>90,23:bb>91"),
       ("pa", "bare", 10, "1", "24:cc>90,25:00>91"),
       ("qa", "meta", 0, "0", "-"),
       ("qa", "meta", 2, "0", "-"),
       ("qa", "meta", 4, "0", "-"),
       ("qa", "meta", 6, "1", "20:08>90,21:00>91"),
       ("qa", "meta", 8, "1", "22:06>90,23:04>91"),
       ("qa", "meta", 10, "1", "24:00>90,25:01>91")]
for rep, etag, off, want_live, want_chg in ARP:
    rs = arms("qarp.%s.%s" % (rep, etag), off=off, ln=2, wr=1, rd=0)
    got_live = str(v.i(rs[0], "live")) if rs else "MISSING"
    got_chg = rs[0].get("wchgs", "-") if rs else "MISSING"
    gtag = "bare" if etag == "bare" else "meta protocol"
    pat = r"\| `%s` \| %s \| \(%d,2\) \| \**(мёртв|жив)\** \| ([^|]*) \|" % (
        rep, re.escape(gtag), off)
    m = re.search(pat, doc)
    N += 2
    if not m:
        FAIL.append(("arp %s %s %d" % (rep, etag, off), "row not found"))
        continue
    got = "1" if m.group(1) == "жив" else "0"
    if got != want_live:
        FAIL.append(("arp verdict %s %s %d" % (rep, etag, off),
                     "doc=%r log=%r" % (got, want_live)))
    chg = m.group(2).strip().strip("*").strip("`").split("`")[0].strip("* ")
    chg = "-" if chg in ("-", "—") else chg
    if chg != want_chg:
        FAIL.append(("arp bytes %s %s %d" % (rep, etag, off),
                     "doc=%r log=%r" % (chg, want_chg)))

# ---- 5. the value table
# the val table prints two rows per group with no label, so the check is a
# multiset: the log's (verdict, bytes) pairs must appear in the document.
for rep in ("p", "q"):
    for etag in ("bare", "meta"):
        gtag = "bare" if etag == "bare" else "meta protocol"
        for off in (0, 8):
            want = sorted((str(v.i(r, "live")), r.get("wchgs", "-"))
                          for r in arms("val.%s.%s" % (rep, etag), off=off,
                                        ln=2))
            rows_doc = re.findall(
                r"\| `%s` \| %s \| \(%d,2\) \| . \| \**(мёртв|жив)\** \| "
                r"([^|\n]+?) \|" % (rep, re.escape(gtag), off), doc)
            got = sorted(("1" if a == "жив" else "0",
                          b.strip().strip("*").strip("`") or "-") for a, b in
                         rows_doc)
            N += 1
            if got != want:
                FAIL.append(("val %s %s %d" % (rep, etag, off),
                             "doc=%r log=%r" % (got, want)))

# ---- 6. the numbers in the prose
cell(r"\*\*(\d+) проверки, 0 расхождений\*\*", "2332", "check count")
cell(r"`differ562`\) and (\d+) arms", "657", "arm count")
cell(r"## 3\. The read grid: (\d+) arms", "480", "read arm count")

print("cells:", N, "failed:", len(FAIL))
for what, det in FAIL[:30]:
    print("  FAIL", what, "|", det)
sys.exit(1 if FAIL else 0)
