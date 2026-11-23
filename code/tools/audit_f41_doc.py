#!/usr/bin/env python3
"""audit_f41_doc.py -- the numbers in findings/F41's SUMMARY.md, against the log.

The summary generator and the verifier share a parser; this script does not use
either of them for the document side: it reads SUMMARY.md as text, takes the
table rows apart, and re-derives each number from logs/f41_rep1.log with its
own small arithmetic.  A number in the document that the log does not carry is
a finding against the document.
"""
import re
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F41-pppoe-and-arp-death/SUMMARY.md"
LOG = ROOT + "/logs/f41_rep1.log"

N = 0
FAIL = []
SEC = "-"


def ck(cond, what, detail=""):
    global N
    N += 1
    if not cond:
        FAIL.append((SEC, what, detail))


def rows():
    out = []
    for line in open(LOG, errors="replace"):
        line = line.replace("\r", "").rstrip("\n")
        if not line.startswith("F563 "):
            continue
        head, _, rest = line[5:].partition("|")
        kv = {"_k": head.strip()}
        for part in rest.split("|"):
            if "=" in part:
                k, _, v = part.partition("=")
                kv[k] = v
        out.append(kv)
    return out


R = rows()


def sec(name):
    return [r for r in R if r.get("sec") == name and r["_k"] in ("R", "P", "A")]


def parts(r):
    p = r["env"].split(".")
    return p[0], p[1], ".".join(p[2:])


doc = open(DOC, errors="replace").read()
lines = [l.strip() for l in doc.splitlines() if l.strip().startswith("|")]
cells = [[c.strip() for c in l.strip("|").split("|")] for l in lines]


def find_row(*needles):
    for c in cells:
        if all(n in "|".join(c) for n in needles):
            return c
    return None


def unbold(s):
    return s.replace("**", "").strip()


# ---- §3 read grid: three rows of (A, B) live counts ------------------------
SEC = "doc3"
GRID = [(o, l) for o in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24)
        for l in (1, 2, 4)] + [(0, 8), (8, 16), (16, 16), (20, 16)]
for fr, gate, label in (("p", "bare", ""), ("ps", "bare", ""),
                        ("ps", "meta", "**8**")):
    row = find_row("`%s`" % fr, "`meta protocol`" if gate == "meta" else "без meta")
    ck(row is not None, "row %s/%s exists in the doc" % (fr, gate))
    if not row:
        continue
    a = [r for r in sec("rd") if parts(r)[:2] == (fr, gate) and r["cand"] == "A"]
    b = [r for r in sec("rd") if parts(r)[:2] == (fr, gate) and r["cand"] == "B"]
    la = sum(1 for r in a if int(r["live"]))
    lb = sum(1 for r in b if int(r["live"]))
    ck(unbold(row[3]) == "%d/40" % la, "§3 %s/%s A" % (fr, gate),
       "%s vs %d" % (row[3], la))
    ck(unbold(row[4]) == "%d/40" % lb, "§3 %s/%s B" % (fr, gate),
       "%s vs %d" % (row[4], lb))

# ---- §4 store grid -------------------------------------------------------
SEC = "doc4"
row = find_row("`ps`", "без meta", "0/40")
ck(row is not None, "§4 the bare row is 0/40")
row = find_row("`ps`", "`meta protocol`", "14/40")
ck(row is not None, "§4 the meta row is 14/40")
live = sorted((int(r["off"]), int(r["len"])) for r in sec("st")
              if parts(r)[:2] == ("ps", "meta") and int(r["live"]))
ck(len(live) == 14, "§4 the log has 14 live cells", str(len(live)))
if row:
    ck(all("(%d,%d)" % c in row[3] for c in live),
       "§4 every live cell of the log is named in the doc", row[3])
bare = [r for r in sec("st") if parts(r)[:2] == ("ps", "bare") and int(r["live"])]
ck(not bare, "§4 the log has no live cell without meta", str(len(bare)))

# ---- §5 what each live cell writes --------------------------------------
SEC = "doc5"
PPPOE = [(12, 2, "ethertype 0x8864"), (14, 1, "pppoe ver/type"),
         (15, 1, "pppoe code"), (16, 2, "pppoe session id"),
         (18, 2, "pppoe length"), (20, 2, "ppp protocol"), (22, 1, "ip ver/ihl"),
         (23, 1, "ip tos"), (24, 2, "ip tot_len"), (26, 2, "ip id"),
         (28, 2, "ip frag_off"), (30, 1, "ip ttl"), (31, 1, "ip proto"),
         (32, 2, "ip checksum"), (34, 4, "ip saddr"), (38, 4, "ip daddr"),
         (42, 2, "udp sport"), (44, 2, "udp dport"), (46, 2, "udp len")]


def fieldname(pos, ln):
    names = [n for (p, l, n) in PPPOE if p < pos + ln and pos < p + l]
    return " + ".join(names) if names else "?"


for off, ln in live:
    row = None
    for c in cells:
        if len(c) == 4 and c[0] == "(%d,%d)" % (off, ln) and \
                re.fullmatch(r"\d+(\.\.\d+)?", c[2]):
            row = c
            break
    ck(row is not None, "§5 row (%d,%d) exists" % (off, ln))
    if row:
        ck(unbold(row[3]) == fieldname(14 + off, ln),
           "§5 (%d,%d) writes %r" % (off, ln, fieldname(14 + off, ln)),
           "%s vs %s" % (row[3], fieldname(14 + off, ln)))

# ---- §6 pair -------------------------------------------------------------
SEC = "doc6"
for fr, gate in (("p", "bare"), ("ps", "bare"), ("ps", "meta")):
    for cellname in ("8", "16"):
        row = find_row("`%s`%s" % (fr, "" if gate == "bare" else "+meta"),
                       "(%s)" % cellname)
        ck(row is not None, "§6 row %s/%s cell %s" % (fr, gate, cellname))
        if not row:
            continue
        for idx, kind in ((2, "wr"), (3, "rdwr"), (4, "wrrd")):
            got = None
            for r in sec("pair"):
                p = parts(r)
                if p[:2] == (fr, gate) and p[2].split("_")[0] == kind and \
                        p[2].split("_")[1].startswith(cellname):
                    got = int(r["live"])
            ck(unbold(row[idx]) == str(got),
               "§6 %s/%s cell %s %s" % (fr, gate, cellname, kind),
               "%s vs %s" % (row[idx], got))

# ---- §7 ih ---------------------------------------------------------------
SEC = "doc7"
for fr, gate in (("p", "bare"), ("ps", "bare"), ("ps", "meta")):
    row = find_row("`%s`%s" % (fr, "" if gate == "bare" else "+meta"), "/5")
    ck(row is not None, "§7 row %s/%s" % (fr, gate))
    if not row:
        continue
    d = {}
    for r in sec("ih"):
        p = parts(r)
        if p[:2] == (fr, gate):
            k = p[2].split("_")[0]
            d[k] = d.get(k, 0) + (1 if int(r["live"]) else 0)
    for idx, kind in ((1, "rdT"), (2, "rdW"), (3, "wr")):
        ck(unbold(row[idx]) == "%d/5" % d.get(kind, 0),
           "§7 %s/%s %s" % (fr, gate, kind), "%s vs %s" % (row[idx], d.get(kind, 0)))

# ---- §8 the receiver's bytes --------------------------------------------
SEC = "doc8"
for r in sec("pppd"):
    arm = parts(r)[2]
    row = find_row("`%s`" % arm)
    ck(row is not None, "§8 row %s exists" % arm)
    if not row:
        continue
    want = r["rxn"] if r["rxn"] != "-1" else "отброшен"
    got = unbold(row[3])
    ok = (got == "отброшен") if want == "отброшен" else bool(
        re.match(r"^(\d+) ", got) and int(re.match(r"^(\d+) ", got).group(1)) == int(want))
    ck(ok, "§8 %s recv" % arm, "%s vs %s" % (row[3], want))
    ck(unbold(row[2]) == ("жив" if int(r["live"]) else "мёртв"),
       "§8 %s guard verdict" % arm, row[2])
    if r["rxn"] != "-1":
        raw = row[4].replace("`", "").replace("**", "").replace(" ", "")
        dochex = raw.lower()
        if len(dochex) >= 8 and re.fullmatch(r"[0-9a-f]+", dochex):
            ck(r["rxhex"].startswith(dochex[:len(dochex)]) or
               dochex.startswith(r["rxhex"][:len(dochex)]),
               "§8 %s delivered bytes" % arm,
               "%s vs %s" % (dochex, r["rxhex"]))

# ---- §9 the ARP death table ---------------------------------------------
SEC = "doc9"
arp_rows = [c for c in cells if len(c) == 7 and c[0] in ("br", "nd")
            and c[3] != "что пишет"]
ck(len(arp_rows) == 16, "§9 has 16 rows", str(len(arp_rows)))
by = {}
for r in sec("arpd"):
    by[r["arm"]] = r
labels = {
    "br_pa_ctl": ("br", "`pa`"), "br_pa_opbad": ("br", "`pa`"),
    "br_pa_oprepl": ("br", "`pa`"), "br_pa_sha0": ("br", "`pa`"),
    "br_pa_sha2": ("br", "`pa`"), "br_tag0_ctl": ("br", "`tag0`"),
    "br_q0_ctl": ("br", "`q0`"), "br_q0_pro": ("br", "`q0`"),
    "br_q0_op": ("br", "`q0`"), "br_q0_hln": ("br", "`q0`"),
    "br_q200_ctl": ("br", "`q200`"), "nd_pa_ctl": ("nd", "`pa`"),
    "nd_pa_hln": ("nd", "`pa`"), "nd_pa_op": ("nd", "`pa`"),
    "nd_pa_sha0": ("nd", "`pa`"), "nd_q0_hln": ("nd", "`q0`"),
}
used = set()
for c in arp_rows:
    # match by (env, frame, cell) in order of appearance
    cand = [k for k, v in labels.items()
            if v == (c[0], c[1]) and k not in used and
            (c[2] == "—") == (by[k]["wr"] == "0")]
    if not cand:
        ck(False, "§9 doc row has no log arm", str(c[:3]))
        continue
    k = cand[0]
    used.add(k)
    r = by[k]
    ck(unbold(c[4]) == r["arc"], "§9 %s NF_ARP_IN" % k,
       "%s vs %s" % (c[4], r["arc"]))
    ck(c[5].startswith("да" if r["repn"] != "-1" else "нет"), "§9 %s reply" % k,
       "%s vs %s" % (c[5], r["repn"] != "-1"))
    ent = r["ent"].split(";")[3] if r["ent"] != "-" else "нет"
    ck(ent in c[6], "§9 %s neighbour" % k, "%s vs %s" % (c[6], ent))
ck(len(used) == 16, "§9 every log arm appears in the doc", str(len(used) - 16))

# ---- the provenance numbers quoted in the running text -------------------
SEC = "docprov"
import subprocess
_v = subprocess.run([sys.executable, ROOT + "/tools/verify563.py"],
                    capture_output=True, text=True).stdout.splitlines()[0]
_checks = _v.split("checks=")[1].split()[0]
ck("%s проверок" % _checks in doc,
   "the verifier's own count (%s) is the one the document quotes" % _checks, _v)
ck("17/17" in doc, "the selftest count")
ck("438 плеч" in doc, "the arm count per boot")
ck("17 строк" in doc, "the config delta size")

print("doc checks=%d failed=%d" % (N, len(FAIL)))
for s, w, d in FAIL[:20]:
    print("  [%s] %s | %s" % (s, w, d))
sys.exit(1 if FAIL else 0)
