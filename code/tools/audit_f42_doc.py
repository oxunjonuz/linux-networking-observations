#!/usr/bin/env python3
"""audit_f42_doc.py -- check SUMMARY.md against the log, cell by cell.

The tables in the document are DERIVED by f42_summary.py, but the document is
typed, and the tool that prints a table is the last thing that should check
it.  This program parses the markdown tables out of SUMMARY.md, finds the arm
by name in the log, and compares every numeric cell.  It also checks the
prose numbers that the document states as facts.
"""
import os
import re
import sys

DOC = os.environ.get("F42_DOC", "/work/kernel-sec/findings/F42-pppoe-bound/SUMMARY.md")
LOG = "/work/kernel-sec/logs/f42_rep1.log"

ok = 0
bad = 0
fails = []


def check(cond, what, detail=""):
    global ok, bad
    if cond:
        ok += 1
    else:
        bad += 1
        fails.append(what + (": " + detail if detail else ""))


def kv(line):
    d = {}
    for p in line.split("|")[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            d[k] = v
    return d


def num(s):
    if s in ("-", "—", ""):
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def main():
    doc = open(DOC, encoding="utf-8").read().replace("\r\n", "\n")
    log = open(LOG, encoding="utf-8", errors="replace").read().replace("\r\n", "\n")
    B = {kv(x)["arm"]: kv(x) for x in log.split("\n") if x.startswith("F564 B|")}
    V = {kv(x)["arm"]: kv(x) for x in log.split("\n") if x.startswith("F564 V|")}
    L = {}
    for x in log.split("\n"):
        if x.startswith("F564 L|") and "arm=" in x:
            d = kv(x)
            L[d["arm"]] = d

    lines = doc.split("\n")
    # ---- the three arm tables, dispatched by their header row --------
    n_b = n_v = n_l = 0
    kind = None
    for line in lines:
        if "| off,len | live |" in line:
            kind = "v6" if "| i6in |" in line else "b"
            continue
        if "| pass | arm | live | arc |" in line:
            kind = "l"
            continue
        if not line.startswith("|"):
            kind = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and set(cells[0]) <= set("-: "):
            continue
        if kind == "b" and len(cells) == 10:
            arm = cells[1].strip("`")
            d = B[arm]
            off, ln = [int(x) for x in cells[2].split(",")]
            check(off == int(d["off"]) and ln == int(d["len"]),
                  "§3 %s: off,len" % arm, "%s vs %s,%s" % (cells[2], d["off"], d["len"]))
            for i, key in ((3, "live"), (4, "ipin"), (5, "ihdr"), (6, "ideliv"),
                           (7, "prx"), (8, "udp4"), (9, "urn")):
                check(num(cells[i]) == int(d[key]), "§3 %s: %s" % (arm, key),
                      "%r vs %r" % (cells[i], d[key]))
            n_b += 1
        elif kind == "v6" and len(cells) == 10:
            arm = cells[1].strip("`")
            d = V[arm]
            off, ln = [int(x) for x in cells[2].split(",")]
            check(off == int(d["off"]) and ln == int(d["len"]), "§6 %s: off,len" % arm)
            for i, key in ((3, "live"), (4, "i6in"), (5, "i6hdr"), (6, "i6deliv"),
                           (7, "prx"), (8, "urn"), (9, "udp6")):
                check(num(cells[i]) == int(d[key]), "§6 %s: %s" % (arm, key),
                      "%r vs %r" % (cells[i], d[key]))
            n_v += 1
        elif kind == "l" and len(cells) == 6:
            arm = cells[1].strip("`")
            d = L[arm]
            check(cells[0] == d["pass"], "§7 %s: pass" % arm)
            for i, key in ((2, "live"), (3, "arc")):
                check(num(cells[i]) == int(d[key]), "§7 %s: %s" % (arm, key),
                      "%r vs %r" % (cells[i], d[key]))
            rp = num(cells[4])
            check((rp is None and int(d["repn"]) < 0) or rp == int(d["repn"]),
                  "§7 %s: repn" % arm, "%r vs %r" % (cells[4], d["repn"]))
            if d["ent"]:
                check(cells[5] == d["ent"], "§7 %s: /proc/net/arp" % arm,
                      "%r vs %r" % (cells[5], d["ent"]))
            else:
                check(cells[5] in ("-", "—"), "§7 %s: empty arp entry" % arm)
            n_l += 1

    check(n_b == 19, "§3 has 19 arm rows", str(n_b))
    check(n_v == 11, "§6 has 11 arm rows", str(n_v))
    check(n_l == 6, "§7 has 6 arm rows", str(n_l))

    # ---- the classification table of section 3 ----------------------
    groups = {
        "pppoe header": ["vt", "tos", "id4", "idbig"],
        "unchanged byte": ["ttlsame"],
        "checksum": ["ttl", "ttl2", "csum", "saddr", "daddr"],
        "refused": ["bare", "trsaddr", "trdaddr", "nh6", "ll14"],
        "mac": ["ll6"],
        "ethertype": ["ll13"],
    }
    for fam, arms in groups.items():
        for a in arms:
            d = B.get(a)
            check(d is not None, "classification: %s exists in the log" % a)
    for a in ("ttl", "ttl2", "csum", "saddr", "daddr"):
        check(int(B[a]["ihdr"]) == 1 and int(B[a]["udp4"]) == -1,
              "classification: %s is a checksum death" % a)
    for a in ("bare", "trsaddr", "trdaddr", "nh6", "ll14"):
        check(int(B[a]["live"]) == 0 and int(B[a]["ipin"]) == 1 and
              int(B[a]["udp4"]) == 18, "classification: %s was refused but delivered" % a)
        check(B[a]["rhex"] == B["ctl"]["rhex"], "classification: %s left the frame unchanged" % a)
    check(int(B["id4"]["prx"]) == 2 and int(B["id4"]["ihdr"]) == 1,
          "classification: id4 hands 2 bytes to the stack")
    check(int(B["idbig"]["prx"]) == 0 and int(B["idbig"]["live"]) == 1,
          "classification: idbig is live but never reaches the stack")
    check(int(B["ttlsame"]["udp4"]) == 18, "classification: ttlsame is harmless")
    check(int(B["ll6"]["prx"]) == 0 and int(B["ll6"]["live"]) == 1,
          "classification: ll6 is live and loses the session")

    # ---- the ll13 / pre88ff pair (section 5) ------------------------
    check(int(B["ll13"]["udp4"]) == 18 and int(B["pre88ff"]["udp4"]) == -1,
          "§5: ll13 delivered, pre88ff not")
    check(B["ll13"]["rhex"][24:28] == "88ff", "§5: ll13 changed the ethertype byte",
          B["ll13"]["rhex"][24:28])
    check(int(B["pre88ff"]["live"]) == 0, "§5: pre88ff had no rule")

    # ---- IPv6 section ------------------------------------------------
    check(int(V["hop"]["urn"]) == 68, "§6: hop queued 68 bytes on the unit")
    check(V["hop"]["urhex"][:4] == "0090", "§6: hop wrote 0x0090", V["hop"]["urhex"][:4])
    check(int(V["hop"]["prx"]) == 66, "§6: hop still counted 66 bytes on ppp0")
    check(int(V["hop"]["i6in"]) == 0, "§6: hop never reached ip6")
    check(int(V["hopsame"]["udp6"]) == 18, "§6: hopsame delivered")
    check(int(V["hdr_same"]["udp6"]) == 18, "§6: hdr_same delivered")
    check(int(V["hdr_bad"]["i6hdr"]) == 1 and int(V["hdr_bad"]["i6deliv"]) == 0,
          "§6: hdr_bad is a version error")
    check(int(V["dst"]["i6deliv"]) == 0 and int(V["dst"]["i6in"]) == 1,
          "§6: dst reaches ip6 and is not delivered")
    for a in ("dscp", "flow2"):
        check(int(V[a]["prx"]) == 0 and int(V[a]["live"]) == 1,
              "§6: %s is live and loses the session" % a)
    for a in ("one", "three", "six"):
        check(int(V[a]["live"]) == 0 and int(V[a]["udp6"]) == 18,
              "§6: %s is refused and delivered" % a)

    # ---- VLAN section ------------------------------------------------
    check(int(L["ctl_novlan"]["arc"]) == 0 and int(L["sha_novlan"]["arc"]) == 0,
          "§7: no vlan device, no ARP")
    check(int(L["ctl_vlan"]["arc"]) == 1 and int(L["ctl_vlan"]["repn"]) == 42,
          "§7: with v1 the frame is answered")
    check(L["ctl_vlan"]["ent"].endswith(";v1"), "§7: the entry names v1")
    check(L["sha_vlan"]["rephex"].startswith("9091cc000066"),
          "§7: the reply went to the written MAC", L["sha_vlan"]["rephex"][:12])
    check(int(L["op_vlan"]["arc"]) == 1 and int(L["op_vlan"]["repn"]) == -1,
          "§7: unknown ar_op passes arp_rcv, no reply")
    check(int(L["hln_vlan"]["live"]) == 0 and int(L["hln_vlan"]["arc"]) == 1,
          "§7: (4,2) is refused and the frame is delivered")

    # ---- prose numbers ----------------------------------------------
    check("36 плеч" in doc, "prose: 36 arms per boot")
    check("`1efbc957…2033`" in doc, "prose: the kernel sha prefix")
    check("восемнадцатью байтами" in doc, "prose: 18 bytes to the socket")
    check("68" in doc and "0x0090" in doc, "prose: 68 bytes / 0x0090")
    check("**895 проверок, 0 расхождений**" in doc, "prose: the verifier count")
    check("**29/29**" in doc, "prose: the selftest count")

    print("doc audit: %d ok, %d failed" % (ok, bad))
    for f in fails[:40]:
        print("FAIL: " + f)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
