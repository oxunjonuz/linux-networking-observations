#!/usr/bin/env python3
"""audit_f43_doc.py -- does SUMMARY.md say what the log measured?

The document was written from findings/F43-th-base/summary.json, which
tools/f565_summary.py derives from logs/f43_rep{1,2}.log.  This script goes
the other way: it parses the tables in the document and compares every cell
with the derived JSON.  A number typed by hand into a table is then a hard
error, and a table that drifted from the log reddens here even when
verify565.py is green -- the two scripts share no code path.

  audit_f43_doc.py            check the real document
  audit_f43_doc.py --mutants  apply three single-number substitutions to a
                              copy and require each to redden at least one cell
"""
import json
import re
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F43-th-base/SUMMARY.md"
JSN = ROOT + "/findings/F43-th-base/summary.json"

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


def table(doc, header_needle):
    """the rows under the first table whose header contains the needle"""
    lines = doc.split("\n")
    for i, ln in enumerate(lines):
        if ln.startswith("|") and header_needle in ln:
            rows = []
            for j in range(i + 2, len(lines)):
                if not lines[j].startswith("|"):
                    break
                rows.append(cells(lines[j]))
            return rows
    return []


def nums(s):
    return [int(x) for x in re.findall(r"\d+", s)]


def run(doc, j, verbose=True):
    global ok, bad, fails
    ok, bad, fails = 0, 0, []

    # ---- §2 envelopes ----------------------------------------------------
    rows = table(doc, "| конверт | кадр на проводе")
    check(len(rows) == 6, "§2 has six envelope rows", str(len(rows)))
    seen = {}
    for r in rows:
        tag = r[0].replace("`", "").split()[0]
        seen[tag] = r
    for tag in ("p", "w", "q", "ps", "ps6"):
        r = seen.get(tag)
        if not r:
            check(False, "§2 has a row for %s" % tag)
            continue
        e = j["envelopes"][tag]
        eq(nums(r[1])[0], e["wire_len"], "§2 %s: wire length" % tag)
        eq(nums(r[2])[0], e["hook_len"], "§2 %s: hook length" % tag)
        eq(int(r[3].replace("*", "").replace("`", ""), 16), e["h_proto"],
           "§2 %s: eth_hdr()->h_proto" % tag)
        eq(int(r[4].replace("*", "").replace("`", ""), 16), e["skb_protocol"],
           "§2 %s: skb->protocol" % tag)
        eq(nums(r[5])[0], e["hook_ip"], "§2 %s: IP offset in the hook frame" % tag)
        eq(nums(r[6])[0], e["hook_l4"], "§2 %s: UDP offset in the hook frame" % tag)
    r = seen.get("pt")
    if r:
        eq(nums(r[1]), [j["envelopes"]["pt"]["wire_len"],
                        j["envelopes"]["pst"]["wire_len"]],
           "§2 TCP row: both frame lengths")
        eq(nums(r[6]), [j["envelopes"]["pt"]["hook_l4"],
                        j["envelopes"]["pst"]["hook_l4"]],
           "§2 TCP row: both transport offsets")

    # ---- §3 the grid -----------------------------------------------------
    rows = table(doc, "| конверт | gate 0 | gate 1 |")
    check(len(rows) == 4, "§3 has four envelope rows", str(len(rows)))
    for r in rows:
        env = r[0].strip("`")
        g = j["grid"][env]
        eq(nums(r[1])[0], g["gate0"]["live"], "§3 %s: live cells gate 0" % env)
        eq(nums(r[2])[0], g["gate1"]["live"], "§3 %s: live cells gate 1" % env)
        for col, (gate, arm) in ((3, ("gate0", "t0_2")), (4, ("gate1", "t0_2")),
                                 (5, ("gate0", "t16_2")), (6, ("gate1", "t16_2"))):
            want = g[gate]["cells"][arm]["changed"]
            cell = r[col].strip()
            if cell == "—":
                eq(want, [], "§3 %s %s/%s: no bytes changed" % (env, gate, arm))
            else:
                eq(nums(cell), want, "§3 %s %s/%s: the bytes the store touched"
                   % (env, gate, arm))

    # ---- §5 TCP ----------------------------------------------------------
    rows = table(doc, "| плечо | живых | мёртвые |")
    check(len(rows) == 3, "§5 has three rows", str(len(rows)))
    want_live = [("pt", "0"), ("pst", "0"), ("pst", "1")]
    for r, (env, gate) in zip(rows, want_live):
        k = "%s_g%s" % (env, gate)
        t = j["tcp"][k]
        eq(nums(r[1])[0], t["live"], "§5 %s: live cells" % k)
        dead = [a for a, v in t["cells"].items() if v["live"] == 0]
        if env == "pst" and gate == "0":
            eq(len(dead), 6, "§5 pst g0: all six dead")
        else:
            eq(sorted(dead), ["t10_4", "t12_1", "t12_2", "t12_4"],
               "§5 %s: exactly the ack_seq cells are dead" % k)
        for a in dead:
            if env != "pst" or gate != "0":
                pairs = re.findall(r"\((\d+),(\d+)\)", r[2])
                check(any(int(x) == t["cells"][a]["off"] and
                          int(y) == t["cells"][a]["len"] for x, y in pairs),
                      "§5 %s: the dead cell %s is listed" % (k, a))

    # ---- §6 three bases --------------------------------------------------
    rows = table(doc, "| база | жив | байты кадра")
    check(len(rows) == 3, "§6 has three rows", str(len(rows)))
    for r, key in zip(rows, ("ll0", "nh0", "th0")):
        v = j["reach"][key]
        eq(nums(r[1])[0], v["live"], "§6 %s: live" % key)
        eq(nums(r[2].split("(")[0]), v["changed"], "§6 %s: changed bytes" % key)
        eq(nums(r[3])[0], v["ideliv"], "§6 %s: IpInDelivers" % key)
        if v["u5000"] < 0:
            check("—" in r[4], "§6 %s: nothing at 5000" % key)
        else:
            eq(nums(r[4])[0], v["u5000"], "§6 %s: recv() on 5000" % key)

    # ---- §7 reach --------------------------------------------------------
    m = re.search(r"\*\*42\*\* на PPPoE-кадре \(`q`: \*\*38\*\*\)", doc)
    check(m is not None, "§7 states 42 (PPPoE) and 38 (Q-in-Q)")
    eq(j["reach"]["th_min_byte_pppoe"], 42, "the log: min @th byte on PPPoE")
    eq(j["reach"]["th_min_byte_qinq"], 38, "the log: min @th byte on Q-in-Q")

    # ---- §8 the checksum table ------------------------------------------
    rows = table(doc, "| плечо | dport на проводе")
    check(len(rows) == 8, "§8 has eight rows", str(len(rows)))
    arms = ["ctl", "dp_nc", "dp_cs", "sp_cs", "ck_nc", "ck_cs", "pay_cs", "pay_nc"]
    for r, a in zip(rows, arms):
        bn, ps = j["csum"]["pu"][a], j["csum"]["psu"][a]
        check(a.split("_")[0] in r[0], "§8 row %s is the arm it names" % a, r[0])
        eq(nums(r[1])[0], bn["dport"], "§8 %s: dport on the wire" % a)
        eq(int(r[2].strip("`*"), 16), int(bn["csum_field"], 16),
           "§8 %s: the checksum field" % a)
        want_ok = bn["csum_status"] == "ok"
        check(("неверна" in r[3]) != want_ok, "§8 %s: the checksum verdict" % a)
        eq(nums(r[4]), [bn["udperr"], ps["udperr"]],
           "§8 %s: UdpInErrors in both envelopes" % a)
        if bn["u5001"] > 0:
            check("5001" in r[5], "§8 %s: delivered to the written port" % a)
        elif bn["u5000"] > 0:
            check("5000" in r[5] and "никуда" not in r[5],
                  "§8 %s: delivered to 5000" % a)
        else:
            check("никуда" in r[5], "§8 %s: delivered nowhere" % a)
        eq(ps["dport"], bn["dport"], "§8 %s: the same dport in PPPoE" % a)
        eq(ps["csum_field"], bn["csum_field"],
           "§8 %s: the same checksum field in PPPoE" % a)

    # ---- §9 IPv6 ---------------------------------------------------------
    rows = table(doc, "| gate | клетки `@th`")
    check(len(rows) == 4, "§9 has four rows", str(len(rows)))
    eq(nums(rows[0][2])[0], sum(v["live"] for k, v in j["v6"]["gate0"].items()
                                if k.startswith("t")), "§9 g0: live cells")
    eq(nums(rows[1][2])[0], sum(v["live"] for k, v in j["v6"]["gate1"].items()
                                if k.startswith("t")), "§9 g1: live cells")
    check(j["v6"]["gate1"]["dp_cs"]["u6_5001"] == 18, "the log: dp_cs reaches 5001")
    check(j["v6"]["gate1"]["dp_nc"]["u6err"] >= 1, "the log: dp_nc is counted")
    eq(j["v6"]["udp_byte_in_frame"], 62, "the log: the udp6 header is at 62")

    # ---- §10/§11/§12/§13 headline numbers -------------------------------
    eq(j["arms_per_boot"], 126, "the log: arms per boot")
    eq(j["determinism"]["lines"], 141, "the log: F565 lines per boot")
    eq(j["determinism"]["differing"], 0, "the log: the boots agree")
    check("126 плеч" in doc, "§0 states 126 arms")
    check("`141` строка" in doc, "§0 states 141 lines")
    check("15 из 15" in doc, "§11 states 15/15 predictions")
    check("**884 проверки, 0 расхождений**" in doc,
          "§13 states the verifier's own count")
    check("**167 клеток, 0 расхождений**" in doc,
          "§13 states the document audit's count")
    check("**18/18**" in doc, "§13 states the mutation count")
    check(len(j["splat"]) == 0 if isinstance(j["splat"], list) else True,
          "the log has no splat")

    return ok, bad, fails


def main():
    doc = open(DOC, encoding="utf-8").read()
    j = json.load(open(JSN))
    ok, bad, fails = run(doc, j)
    print("doc checks: %d ok, %d failed" % (ok, bad))
    for f in fails[:40]:
        print("FAIL: " + f)

    if "--mutants" in sys.argv:
        # three single-number substitutions; each must redden at least one cell
        subs = [("| `q` | **0/8** |", "| `q` | **8/8** |"),   # §3 q live count
                ("`08ac`", "`08ad`"),                          # §8 dp_cs checksum
                ("| **15** (байт 14", "| **14** (байт 14")]    # §6 nh0 bytes
        mok = 0
        for i, (a, b) in enumerate(subs):
            if a not in doc:
                print("MUTANT %d: anchor not found: %r" % (i, a))
                continue
            ok2, bad2, f2 = run(doc.replace(a, b, 1), j, verbose=False)
            if bad2 >= 1:
                mok += 1
                print("MUTANT %d caught by %d cell(s): %s" % (i, bad2, f2[0]))
            else:
                print("MUTANT %d SURVIVED" % i)
        print("mutants caught: %d/3" % mok)
        if mok != 3:
            return 1
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
