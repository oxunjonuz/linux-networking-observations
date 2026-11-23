#!/usr/bin/env python3
"""f41_mutate.py <rep1> <rep2> <outdir> <mutation>

One field at a time, in a copy of the two logs.  Nothing else moves, so a
verifier that stays green after a mutation is not looking at that field.
"""
import os
import sys

REP1, REP2, OUT, MUT = sys.argv[1:5]


def parse_line(line):
    head, _, rest = line[5:].partition("|")
    kv = {"_k": head.strip()}
    for part in rest.split("|"):
        if "=" in part:
            k, _, v = part.partition("=")
            kv[k] = v
    return kv


def set_field(lines, sel, field, new):
    for i, l in enumerate(lines):
        if not l.startswith("F563 "):
            continue
        kv = parse_line(l)
        if all(kv.get(k) == v for k, v in sel.items()):
            old = kv[field]
            if "|%s=%s|" % (field, old) in l:
                lines[i] = l.replace("|%s=%s|" % (field, old),
                                     "|%s=%s|" % (field, new), 1)
            else:
                lines[i] = l.replace("%s=%s" % (field, old),
                                     "%s=%s" % (field, new), 1)
            return lines[i] != l
    return False


M = {
    # name: (file, selector, field, new value, or a plain (old, new) string)
    "rd_cv":       ("rep1", {"sec": "rd", "env": "p.bare.p.bare.g8_1",
                             "off": "8", "len": "1", "cand": "A"}, "cv", "41"),
    "rd_live":     ("rep1", {"sec": "rd", "env": "ps.meta.ps.meta.g8_1",
                             "off": "8", "len": "1", "cand": "A"}, "live", "1"),
    "st_live":     ("rep1", {"sec": "st", "env": "ps.bare.s4_2"}, "live", "1"),
    "st_bytes":    ("rep1", {"sec": "st", "env": "ps.meta.s4_2"}, "wchgs",
                    "18:00>90"),
    "pair_wrrd":   ("rep1", {"sec": "pair", "env": "ps.meta.wrrd_8.b"},
                    "live", "0"),
    "pair_bytes":  ("rep1", {"sec": "pair", "env": "ps.meta.wr_16.d"}, "wchgs",
                    "30:40>90"),
    "ih_live":     ("rep1", {"sec": "ih", "env": "ps.bare.rdT_0_2"}, "live", "1"),
    "ih_bytes":    ("rep1", {"sec": "ih", "env": "ps.meta.wr_0_2"}, "wchgs",
                    "40:9c>90,41:40>91"),
    "ppp_rxn":     ("rep1", {"sec": "pppd", "env": "ps.meta.id_small"},
                    "rxn", "48"),
    "ppp_rx":      ("rep1", {"sec": "pppd", "env": "ps.meta.ctl"}, "rxhex",
                    "10214500"),
    "arp_arc":     ("rep1", {"sec": "arpd", "arm": "br_q0_hln"}, "arc", "1"),
    "arp_reply":   ("rep1", {"sec": "arpd", "arm": "br_pa_opbad"}, "repn", "42"),
    "arp_ent":     ("rep1", {"sec": "arpd", "arm": "br_pa_ctl"}, "ent",
                    ";0x1;0x2;aa:bb:cc:00:00:99;;br0"),
    "arp_bytes":   ("rep1", {"sec": "arpd", "arm": "br_q0_pro"}, "whex",
                    "ffffffffffffaabbcc0000668100000008060001080090910001aabbcc000066000000000000"),
    "det":         ("rep2", {"sec": "pair", "env": "ps.meta.wr_16.d"},
                    "live", "0"),
    "ksha":        ("rep1", None, None,
                    ("### sha256: ", "### sha256: 00")),
    "mode":        ("rep1", None, None,
                    ("=== MODE_EXIT f563=0 ===", "=== MODE_EXIT f563=1 ===")),
}

if MUT not in M:
    print("unknown mutation", MUT)
    sys.exit(2)
which, sel, field, new = M[MUT]
src = REP1 if which == "rep1" else REP2
lines = open(src, errors="replace").read().split("\n")
if sel is None:
    old, rep = new
    hit = False
    for i, l in enumerate(lines):
        if old in l:
            lines[i] = l.replace(old, rep, 1)
            hit = True
            break
    if not hit:
        print("anchor not found", MUT)
        sys.exit(3)
else:
    if not set_field(lines, sel, field, new):
        print("anchor not found", MUT)
        sys.exit(3)
os.makedirs(OUT, exist_ok=True)
for name, path in (("rep1.log", REP1), ("rep2.log", REP2)):
    if path == src:
        open(os.path.join(OUT, name), "w").write("\n".join(lines))
    else:
        open(os.path.join(OUT, name), "w").write(
            open(path, errors="replace").read())
print("mutated", MUT)
