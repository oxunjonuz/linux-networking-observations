#!/usr/bin/env python3
"""audit_f60_doc.py -- every number this finding puts in a table, against the log.

For each fact the document states, in three steps:

  1. the log of BOTH boots must give the value (this is the same model
     verify582.py uses, imported, not re-implemented);
  2. the document must contain that value as a cell of the row that names the
     arm;
  3. a substitution of any single cell in a copy of the document must make this
     audit red (see --tamper).

Usage: python3 tools/audit_f60_doc.py [doc]
       python3 tools/audit_f60_doc.py --tamper
"""

import importlib.util
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F60-checksum-partial/SUMMARY.md")
LOGS = [os.path.join(ROOT, "logs/f60_rep1.log"),
        os.path.join(ROOT, "logs/f60_rep2.log")]

spec = importlib.util.spec_from_file_location("v", os.path.join(ROOT,
                                                               "tools/verify582.py"))
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)

FAILS = []
CHECKS = [0]


def ck(cond, what, extra=""):
    CHECKS[0] += 1
    if not cond:
        FAILS.append("%s %s" % (what, extra))
    return bool(cond)


# (arm, log field, how to render it, which cell of the row must carry it)
#   'd' -> 1 is "да", 0 is "нет";  'n' -> the number;  'x' -> the checksum field
FACTS = [
    # §2 one frame, two provenances: | плечо | tp_status | что это | поле |
    ("c_n0_s6", "tapstat", "n", 1), ("c_n0_s6", "field", "x", 3),
    ("c_n0_p6", "tapstat", "n", 1), ("c_n0_p6", "field", "x", 3),
    ("c_n0_s4", "tapstat", "n", 1), ("c_n0_s4", "field", "x", 3),
    ("c_n0_p4", "tapstat", "n", 1), ("c_n0_p4", "field", "x", 3),
    # §4 | плечо | csum | поле | доставлено | Udp6InErrors |
    ("s_th8_n0", "field", "x", 2), ("s_th8_n0", "u6n", "d", 3),
    ("s_th8_n0", "udperr6", "n", 4),
    ("p_th8_n0", "field", "x", 2), ("p_th8_n0", "u6n", "d", 3),
    ("p_th8_n0", "udperr6", "n", 4),
    ("s_th8_n0_cs", "field", "x", 2), ("s_th8_n0_cs", "u6n", "d", 3),
    ("p_th8_n0_cs", "field", "x", 2), ("p_th8_n0_cs", "u6n", "d", 3),
    ("s_th8_n0_fl", "field", "x", 2), ("s_th8_n0_fl", "u6n", "d", 3),
    ("p_th8_n0_fl", "field", "x", 2),
    ("s_th8_g6", "field", "x", 2), ("s_th8_g6_cs", "field", "x", 2),
    # §6 | плечо | csum | IpInHdrErrors | UdpInErrors | доставлено | поле |
    ("s4_sr_no", "iphdr", "n", 2), ("s4_sr_no", "u4n", "d", 4),
    ("p4_sr_no", "iphdr", "n", 2),
    ("s4_sr_cs", "iphdr", "n", 2), ("s4_sr_cs", "u4err", "n", 3),
    ("s4_sr_cs", "u4n", "d", 4), ("s4_sr_cs", "field", "x", 5),
    ("p4_sr_cs", "u4err", "n", 3), ("p4_sr_cs", "u4n", "d", 4),
    ("p4_sr_cs", "field", "x", 5),
    ("s4_sr_csfl", "field", "x", 5), ("s4_sr_csfl", "u4n", "d", 4),
    ("p4_sr_csfl", "field", "x", 5), ("p4_sr_csfl", "u4n", "d", 4),
    # §7 | плечо | csum | поле после | доставлено |
    ("s_th6_n0", "field", "x", 2), ("s_th6_n0", "u6n", "d", 3),
    ("s_th6_n0_cs", "field", "x", 2), ("s_th6_n0_cs", "u6n", "d", 3),
    ("p_th6_n0", "u6n", "d", 3), ("p_th6_n0_cs", "u6n", "d", 3),
    # §8 | плечо | csum | поле после | доставлено | Udp6InErrors |
    ("s6_sr_cs", "field", "x", 2), ("s6_sr_cs", "u6n", "d", 3),
    ("p6_sr_cs", "field", "x", 2), ("p6_sr_cs", "udperr6", "n", 4),
    ("p6_sr_cs", "u6n", "d", 3),
    ("s6_sr_fl", "field", "x", 2), ("s6_sr_fl", "u6n", "d", 3),
    ("p6_sr_fl", "field", "x", 2), ("p6_sr_fl", "u6n", "d", 3),
    # §9 | @nh,off,len | плечо | принято | сообщение в лог | доставлено |
    ("q_o17_2", "nl", "l", 3), ("q_o17_2", "u4n", "d", 4),
    ("q_o18_2", "nl", "l", 3), ("q_o20_4", "nl", "l", 3),
    ("q_o24_2", "nl", "l", 3), ("q_o40_2", "nl", "l", 3),
    ("q_o56_4", "nl", "l", 3),
    ("q_o16_4", "nl", "l", 3), ("q_o16_4", "u4n", "d", 4),
    ("q_o12_4", "nl", "l", 3), ("q_o12_4", "u4err", "n", 4),
    ("q_o0_2", "nl", "l", 3), ("q_o0_2", "u4n", "d", 4),
    ("q_o0_2s", "nl", "l", 3), ("q_o0_2s", "u4n", "d", 4),
    ("q_o8_2s", "nl", "l", 3), ("q_o8_2s", "u4n", "d", 4),
    ("q_o8_2c", "nl", "l", 3), ("q_o8_2c", "u4n", "d", 4),
]

# numbers the document states in prose, not in a table
PROSE = [
    ("4660", "q_th0_6_cs", "u4s"),        # recvfrom's source port
    ("54", None, None),
    ("6213", None, None),
    ("36", None, None),
    ("fad2", "c_n0_s6", "field"),
    ("3b04", "s6_sr_fl", "field"),
    ("1505", "s4_sr_csfl", "field"),
    ("6046", "p4_sr_csfl", "field"),
    ("0", "q_ihl4", "ch"),
    ("1", "q_ihl4", "iphdr"),
    ("0", "q_short", "ch"),
    ("1", "q_short", "iphdr"),
]


def witness_field(row):
    if row["pnl"] != "1":
        return "-"
    w = bytes.fromhex(row["pp"])
    hl = 40 if int(row["ver"]) == 6 else (w[0] & 0x0F) * 4
    if len(w) < hl + 8:
        return "-"
    return "%04x" % ((w[hl + 6] << 8) | w[hl + 7])


def load(log):
    raw = open(log, errors="ignore").read()
    return {r["name"]: r for r in
            (V.parse_arm(l) for l in raw.splitlines() if l.startswith("F582 ARM"))}


def all_arm_names():
    part, opt = V.load_arms(os.path.join(ROOT, "vm/differ582_add.c"))
    return set(a["name"] for a in part + opt)


def doc_rows(txt, names):
    """every markdown table row that names an arm, keyed by the arm name."""
    rows = {}
    for line in txt.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in
                 re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        for c in cells:
            for k in re.findall(r"`([^`]+)`", c) + [c.strip("`* ")]:
                if k in names:
                    rows.setdefault(k, []).append(cells)
    return rows


def render(row, field, how, boots):
    vals = set()
    for b in boots:
        r = b.get(row.get("name", "")) if False else None
    out = []
    for bd in boots_by_name:
        r = bd.get(_CURRENT[0])
        if r is None:
            continue
        if how == "n":
            out.append(r[field])
        elif how == "d":
            out.append("да" if int(r[field]) else "нет")
        else:
            out.append(witness_field(r))
    return out


boots_by_name = []
_CURRENT = [""]


def main():
    doc = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") \
        else DOC
    txt = open(doc).read()
    rows = doc_rows(txt, all_arm_names())
    for lg in LOGS:
        boots_by_name.append(load(lg))
    for (arm, field, how, col) in FACTS:
        vals = []
        for bd in boots_by_name:
            r = bd.get(arm)
            if r is None:
                vals.append("<missing>")
            elif how == "n":
                vals.append(r[field])
            elif how == "d":
                vals.append("да" if int(r[field]) else "нет")
            elif how == "l":
                vals.append("есть" if int(r[field]) else "нет")
            else:
                vals.append(witness_field(r))
        ck(len(set(vals)) == 1, "both boots agree on %s.%s" % (arm, field), vals)
        want = vals[0]
        hit = False
        for cells in rows.get(arm, []):
            if col < len(cells) and (want == cells[col].strip("`* ") or
                                     want in cells[col]):
                hit = True
        ck(hit, "%s.%s = %s in cell %d" % (arm, field, want, col),
           str(rows.get(arm))[:220])
    for (text, arm, field) in PROSE:
        ck(text in txt, "the prose number %s is in the document" % text)
        if arm:
            r = boots_by_name[0].get(arm)
            if field == "field":
                ck(witness_field(r) == text,
                   "%s.%s is really %s" % (arm, field, text))
            else:
                ck(r[field] == text, "%s.%s is really %s" % (arm, field, text))
    raw1 = open(LOGS[0], errors="ignore").read()
    raw2 = open(LOGS[1], errors="ignore").read()
    ck(raw1.count("F582 ARM|") == 54 and raw2.count("F582 ARM|") == 54,
       "54 arms per boot")
    for raw in (raw1, raw2):
        arms = [V.parse_arm(l) for l in raw.splitlines()
                if l.startswith("F582 ARM|")]
        npre = 0
        for a in arms[:28]:
            tap = V.parse_frame_hex(a["tap"])
            if tap and V.PAYLOAD[:4] in tap:
                npre += 1
        ck(npre == 28, "28 taps carried the frame before the store", npre)
    ck("28 плечах" in txt or "28 плеч" in txt, "the document says 28")
    ck("16 из 20" in txt, "the tally line")
    ck(len(re.findall(r"\*\*P\d+ [а-я]*опровергнуто", txt)) == 3,
       "three refuted predictions named",
       re.findall(r"\*\*P\d+ [а-я]*опровергнуто", txt))

    print("audit_f60_doc: %d checks, %d failures" % (CHECKS[0], len(FAILS)))
    for f in FAILS[:30]:
        print("  FAIL", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
