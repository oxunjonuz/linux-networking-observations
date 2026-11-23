#!/usr/bin/env python3
"""f40_summary.py -- the tables of findings/F40 are PRINTED FROM THE LOGS.

Nothing here types a number: every cell is counted out of logs/f40_rep1.log
with verify562's own parser and models, so the document and the evidence are
the same bytes twice.  Output: markdown tables on stdout and summary.json.
"""
import importlib.util
import json
import os
import sys

ROOT = "/work/kernel-sec"
spec = importlib.util.spec_from_file_location("v", os.path.join(
    ROOT, "tools/verify562.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

rows = v.parse(os.path.join(ROOT, "logs/f40_rep1.log"))
R = [r for r in rows if r["_k"] == "R"]


def i(r, k, d=-999):
    return v.i(r, k, d)


def grp(**kw):
    out = []
    for r in R:
        ok = True
        for k, val in kw.items():
            if k in ("off", "len", "gate", "rd", "wr", "first"):
                ok = ok and i(r, k) == val
            else:
                ok = ok and r.get(k) == val
        if ok:
            out.append(r)
    return out


CELLS = [(o, l) for o in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24)
         for l in (1, 2, 4)] + [(0, 8), (8, 16), (16, 16), (20, 16)]

S = {}

# ---- 1. read grid
print("### read grid (40 cells x 2 candidates)\n")
print("| представление | gate | живых A | живых B | различающих клеток |")
print("|---|---|---|---|---|")
g1 = {}
for rep, tag in (("p", "`p`"), ("w", "`w`"), ("q", "`q`")):
    for gate, etag, gtag in ((0, "bare", "bare"),
                             (1, "meta", "meta protocol")):
        env = "rd.%s.%s" % (rep, etag)
        a = [r for r in grp(env=env) if r.get("cand") == "A"]
        b = [r for r in grp(env=env) if r.get("cand") == "B"]
        la = sum(1 for r in a if i(r, "live") == 1)
        lb = sum(1 for r in b if i(r, "live") == 1)
        dis = sum(1 for off, ln in CELLS
                  if v.CAP[rep][14 + off:14 + off + ln] !=
                  v.CAP[rep][18 + off:18 + off + ln])
        print("| %s | %s | **%d/40** | **%d/40** | %d |" % (tag, gtag, la, lb,
                                                             dis))
        g1["%s.%s" % (rep, etag)] = {"liveA": la, "liveB": lb,
                                     "discriminating": dis}
S["read_grid"] = g1

# the cells where A and B are the same bytes
same = {}
for rep in ("p", "w", "q"):
    same[rep] = [(off, ln) for off, ln in CELLS
                 if v.CAP[rep][14 + off:14 + off + ln] ==
                 v.CAP[rep][18 + off:18 + off + ln]]
S["indistinguishable"] = same
print("\nindistinguishable cells:", json.dumps(same))

# ---- 2. pair
print("\n### pair: one rule, one packet\n")
print("| правило | жив | байты, которые изменились |")
print("|---|---|---|")
pair = {}
for rep in ("p", "q"):
    for gate, etag, gtag in ((0, "bare", "bare"),
                             (1, "meta", "meta protocol")):
        env = "pair.%s.%s" % (rep, etag)
        for off, ln in ((8, 1), (16, 4)):
            for kind, kname in ((0, "wr"), (1, "rdwr"), (2, "wrrd")):
                rs = [r for r in grp(env=env, off=off, len=ln)
                      if i(r, "rd") == (0 if kind == 0 else 1) and
                      i(r, "wr") == 1 and i(r, "first") == (1 if kind == 2
                                                            else 0)]
                if not rs:
                    print("| `%s` %s (%d,%d) | MISSING | |" % (rep, gtag, off,
                                                               ln))
                    continue
                r = rs[0]
                ch = r.get("wchgs", "-")
                key = "%s.%s.%s.%d_%d" % (rep, etag, kname, off, ln)
                pair[key] = {"live": i(r, "live"), "chg": ch}
                print("| `%s` %s `%s` (%d,%d) | %d | %s |" %
                      (rep, gtag, kname, off, ln, i(r, "live"), ch))
S["pair"] = pair

# ---- 3. transport base
print("\n### transport base\n")
print("| представление | gate | живых readT | живых readW | store | байты |")
print("|---|---|---|---|---|---|")
ih = {}
for rep in ("p", "q"):
    for gate, etag, gtag in ((0, "bare", "bare"),
                             (1, "meta", "meta protocol")):
        env = "ih.%s.%s" % (rep, etag)
        t = [r for r in grp(env=env) if r.get("cand") == "T"]
        w = [r for r in grp(env=env) if r.get("cand") == "A" and i(r, "rd") == 1]
        st = [r for r in grp(env=env) if i(r, "wr") == 1]
        lt = sum(1 for r in t if i(r, "live") == 1)
        lw = sum(1 for r in w if i(r, "live") == 1)
        ls = sum(1 for r in st if i(r, "live") == 1)
        chg = st[0].get("wchgs", "-") if st else "-"
        print("| `%s` | %s | **%d/5** | %d/5 | **%d/5** | %s |" %
              (rep, gtag, lt, lw, ls, chg))
        ih["%s.%s" % (rep, etag)] = {"readT": lt, "readW": lw, "store": ls,
                                     "chg": chg}
S["ih"] = ih

# ---- 4. ARP in Q-in-Q
print("\n### ARP in Q-in-Q: what the guard calls the cell, and what it writes\n")
print("| представление | gate | cell | guard | байты, которые изменились |")
print("|---|---|---|---|---|")
arp = {}
for rep in ("pa", "qa"):
    for gate, etag, gtag in ((0, "bare", "bare"),
                             (1, "meta", "meta protocol")):
        env = "qarp.%s.%s" % (rep, etag)
        for off, ln in ((0, 2), (2, 2), (4, 2), (6, 2), (8, 2), (10, 2)):
            rs = [r for r in grp(env=env, off=off, len=ln) if i(r, "wr") == 1]
            if not rs:
                continue
            r = rs[0]
            arp["%s.%s.%d" % (rep, etag, off)] = {"live": i(r, "live"),
                                                  "chg": r.get("wchgs", "-")}
            print("| `%s` | %s | (%d,%d) | %s | %s |" %
                  (rep, gtag, off, ln,
                   "**жив**" if i(r, "live") else "мёртв",
                   r.get("wchgs", "-")))
S["arp"] = arp

# ---- 5. value-dependent cells
print("\n### the two cells whose verdict reads the packet\n")
print("| представление | gate | cell | значение | вердикт | байты |")
print("|---|---|---|---|---|---|")
val = {}
for rep in ("p", "q"):
    for gate, etag, gtag in ((0, "bare", "bare"),
                             (1, "meta", "meta protocol")):
        env = "val.%s.%s" % (rep, etag)
        for off in (0, 8):
            got = [r for r in grp(env=env, off=off, len=2)]
            vs = []
            for r in got:
                vs.append({"live": i(r, "live"), "chg": r.get("wchgs", "-")})
            val["%s.%s.%d" % (rep, etag, off)] = vs
            for r in got:
                print("| `%s` | %s | (%d,2) | — | %s | %s |" %
                      (rep, gtag, off,
                       "**жив**" if i(r, "live") else "мёртв",
                       r.get("wchgs", "-")))
S["val"] = val

# ---- 6. controls
print("\n### controls\n")
ctl = {}
for rep in ("p", "w", "q", "pa", "qa"):
    r = grp(env="ctl." + rep)[0]
    ctl[rep] = {"live": i(r, "live"), "wn": i(r, "wn"), "ipin": i(r, "ipin")}
    print("| `%s` | %d | %d | %d |" % (rep, i(r, "live"), i(r, "wn"),
                                       i(r, "ipin")))
S["ctl"] = ctl

S["finding"] = "F40"
S["turn"] = 562
S["title"] = ("the read side of @nh: the repair of pktinfo moves the read and "
              "leaves the store")
S["kernel"] = "7.3.4-T558"
json.dump(S, open(os.path.join(ROOT,
                               "findings/F40-nh-read-side/summary.json"), "w"),
          indent=1, sort_keys=True)
print("\nsummary.json written")
