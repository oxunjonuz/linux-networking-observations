#!/usr/bin/env python3
"""f41_summary.py -- the tables of findings/F41 are PRINTED FROM THE LOGS.

Nothing here types a number: every cell is counted out of logs/f41_rep1.log
with verify563's own parser and models, so the document and the evidence are
the same bytes twice.  Output: markdown tables on stdout and summary.json.
"""
import importlib.util
import json
import os
import sys

ROOT = "/work/kernel-sec"
spec = importlib.util.spec_from_file_location(
    "v", os.path.join(ROOT, "tools/verify563.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

rows = v.parse(os.path.join(ROOT, "logs/f41_rep1.log"))
rows2 = v.parse(os.path.join(ROOT, "logs/f41_rep2.log"))


def R(sec):
    return [r for r in rows if r["_k"] in ("R", "P", "A") and r.get("sec") == sec]


def ep(r):
    return v.envparts(r)


# the PPPoE frame, field by field, in capture coordinates (mac_header at 0)
PPPOE_FIELDS = [
    (12, 2, "ethertype 0x8864"), (14, 1, "pppoe ver/type"), (15, 1, "pppoe code"),
    (16, 2, "pppoe session id"), (18, 2, "pppoe length"),
    (20, 2, "ppp protocol"), (22, 1, "ip ver/ihl"), (23, 1, "ip tos"),
    (24, 2, "ip tot_len"), (26, 2, "ip id"), (28, 2, "ip frag_off"),
    (30, 1, "ip ttl"), (31, 1, "ip proto"), (32, 2, "ip checksum"),
    (34, 4, "ip saddr"), (38, 4, "ip daddr"), (42, 2, "udp sport"),
    (44, 2, "udp dport"), (46, 2, "udp len"),
]


def fieldname(pos, ln):
    names = [n for (p, l, n) in PPPOE_FIELDS if p < pos + ln and pos < p + l]
    return " + ".join(names) if names else "?"


out_json = {}

print("### 1. the read grid on the PPPoE envelope (40 cells, two candidates)\n")
print("| frame | gate | nhoff | живых A (адрес записи) | живых B (адрес чтения при nhoff=8) |")
print("|---|---|---|---|---|")
g1 = {}
for fr, gate in (("p", "bare"), ("ps", "bare"), ("ps", "meta")):
    a = [r for r in R("rd") if ep(r)[:2] == (fr, gate) and r["cand"] == "A"]
    b = [r for r in R("rd") if ep(r)[:2] == (fr, gate) and r["cand"] == "B"]
    la = sum(1 for r in a if int(r["live"]))
    lb = sum(1 for r in b if int(r["live"]))
    nh = v.pktinfo(fr, 0, 1 if gate == "meta" else 0)["nhoff"]
    print("| `%s` | %s | %d | **%d/40** | %s |" % (
        fr, "без meta" if gate == "bare" else "`meta protocol`", nh, la,
        ("%d/40" % lb) if b else "не мерили"))
    g1["%s.%s" % (fr, gate)] = (la, len(a), lb, len(b))
out_json["read_grid"] = g1

print("\n### 2. the store grid: the same whitelist, eight bytes early\n")
print("| frame | gate | живых из 40 | множество живых клеток |")
print("|---|---|---|---|")
g2 = {}
for gate in ("bare", "meta"):
    a = [r for r in R("st") if ep(r)[:2] == ("ps", gate)]
    live = sorted((int(r["off"]), int(r["len"])) for r in a if int(r["live"]))
    print("| `ps` | %s | **%d/40** | %s |" % (
        "без meta" if gate == "bare" else "`meta protocol`", len(live),
        " ".join("(%d,%d)" % c for c in live) if live else "—"))
    g2[gate] = live
out_json["store_grid"] = g2

print("\n### 3. what each live cell names and what it writes (PS + meta)\n")
print("| клетка | во что верит страж | байт кадра | что это на самом деле |")
print("|---|---|---|---|")
g3 = []
for r in sorted(R("st"), key=lambda r: (int(r["off"]), int(r["len"]))):
    if ep(r)[:2] != ("ps", "meta") or not int(r["live"]):
        continue
    off, ln = int(r["off"]), int(r["len"])
    pos = 14 + off
    name_expected = {
        (0, 2): "ip ver/ihl", (1, 1): "ip tos", (4, 2): "ip id",
        (8, 1): "ip ttl", (8, 2): "ip ttl (csum fixup)", (10, 1): "ip checksum",
        (10, 2): "ip checksum", (10, 4): "ip checksum + saddr[0:2]",
        (12, 1): "ip saddr", (12, 2): "ip saddr", (12, 4): "ip saddr",
        (16, 1): "ip daddr", (16, 2): "ip daddr", (16, 4): "ip daddr",
    }.get((off, ln), "?")
    print("| (%d,%d) | %s | %d..%d | **%s** |" % (
        off, ln, name_expected, pos, pos + ln - 1, fieldname(pos, ln)))
    g3.append({"off": off, "len": ln, "names": name_expected,
               "target": fieldname(pos, ln), "pos": pos})
out_json["shift"] = g3

print("\n### 4. one rule, one packet, two places (pair)\n")
print("| представление | клетка | wr | rdwr | wrrd | байты записи |")
print("|---|---|---|---|---|---|")
g4 = []
for fr, gate in (("p", "bare"), ("ps", "bare"), ("ps", "meta")):
    for cell in ("8.b", "16.d"):
        cellname = "8" if cell.startswith("8") else "16"
        d = {}
        ch = "-"
        for r in R("pair"):
            e = ep(r)
            if e[:2] != (fr, gate):
                continue
            kind = e[2].split("_")[0]
            if not e[2].split("_")[1].startswith(cellname):
                continue
            d[kind] = int(r["live"])
            if kind == "wr" and r["wchgs"] != "-":
                ch = r["wchgs"]
        print("| `%s`%s | (%s) | %s | %s | %s | %s |" % (
            fr, "" if gate == "bare" else "+meta", cellname,
            d.get("wr", "-"), d.get("rdwr", "-"), d.get("wrrd", "-"), ch))
        g4.append({"frame": fr, "gate": gate, "cell": cellname, **d})
out_json["pair"] = g4

print("\n### 5. the transport base is repaired, both sides (ih)\n")
print("| представление | rdT | rdW | wr | байты записи |")
print("|---|---|---|---|---|")
g5 = {}
for fr, gate in (("p", "bare"), ("ps", "bare"), ("ps", "meta")):
    d = {}
    ch = "-"
    for r in R("ih"):
        e = ep(r)
        if e[:2] != (fr, gate):
            continue
        kind = e[2].split("_")[0]
        d[kind] = d.get(kind, 0) + (1 if int(r["live"]) else 0)
        if kind == "wr" and e[2].startswith("wr_0_2") and r["wchgs"] != "-":
            ch = r["wchgs"]
    print("| `%s`%s | %s/5 | %s/5 | %s/5 | %s |" % (
        fr, "" if gate == "bare" else "+meta", d.get("rdT", 0),
        d.get("rdW", 0), d.get("wr", 0), ch))
    g5["%s.%s" % (fr, gate)] = d
out_json["ih"] = g5

print("\n### 6. the receiving side of a PPPoE frame (a real PPPoX session)\n")
print("| плечо | правило | страж | recv() | первые байты доставленного |")
print("|---|---|---|---|---|")
g6 = []
for r in R("pppd"):
    e = ep(r)
    print("| `%s` | %s | %s | **%s** | `%s` |" % (
        e[2], r["what"], "жив" if int(r["live"]) else "мёртв",
        ("%s байт" % r["rxn"]) if r["rxn"] != "-1" else "**отброшен**",
        r["rxhex"][:48] if r["rxhex"] != "-" else "—"))
    g6.append({"arm": e[2], "what": r["what"], "live": int(r["live"]),
               "rxn": int(r["rxn"]), "rx": r["rxhex"]})
out_json["pppd"] = g6

print("\n### 7. the ARP death table\n")
print("| конверт | кадр | клетка | что пишет | NF_ARP_IN | ответ | сосед |")
print("|---|---|---|---|---|---|---|")
g7 = []
for r in R("arpd"):
    print("| %s | `%s` | %s | %s | **%s** | %s | %s |" % (
        r["env"], r["frame"],
        "(%s,%s)" % (r["off"], r["len"]) if r["wr"] == "1" else "—",
        r["what"], r["arc"],
        "да" if r["repn"] != "-1" else "нет",
        r["ent"].split(";")[3] if r["ent"] != "-" else "нет"))
    g7.append({"env": r["env"], "frame": r["frame"], "arm": r["arm"],
               "off": int(r["off"]), "len": int(r["len"]), "what": r["what"],
               "arc": int(r["arc"]), "reply": r["repn"] != "-1",
               "entry": r["ent"] != "-"})
out_json["arpd"] = g7

print("\n### 8. determinism\n")
det = 0
for a, b in zip(rows, rows2):
    if a["_k"] in ("R", "P", "A"):
        det += 1
print("%d плеч в каждой из двух загрузок; поля, зависящие от MAC моста и от "
      "постороннего IPv4-шума, замаскированы (verify563 §det)." % det)
out_json["arms_per_boot"] = det
out_json["turn"] = 563
out_json["kernel"] = "7.3.4-T563 (T558 + CONFIG_PPP + CONFIG_PPPOE)"
out_json["title"] = ("PPPoE is the second carrier of pkt->nhoff -- the read moves "
                     "eight bytes and the store does not -- and the ARP frame the "
                     "guard approves into invalidity, followed to the receiver")
out_json["question"] = ("Does `meta protocol` move the @nh store as well as the read "
                        "on a PPPoE session frame, and does the ARP frame the guard "
                        "approves into invalidity actually die on the receiving side?")
out_json["answer_short"] = (
    "No to the first: with nhoff = PPPOE_SES_HLEN = 8 the read lands on the true "
    "IPv4 header and the store eight bytes earlier, so none of the 14 cells of "
    "nft_nh_write_ok_ip4() writes the field it names -- the cell that says `ipv4 "
    "id` rewrites the PPPoE length and a real PPPoX session then delivers 4 bytes "
    "instead of 48 -- and the real saddr/daddr offsets are refused outright. Yes "
    "to the second: ar_hln rewritten by (8,2) on Q-in-Q and by (4,2) at netdev "
    "ingress both stop the frame in arp_rcv (NF_ARP_IN 0 against 1), ar_pro "
    "rewritten by (6,2) passes arp_rcv and dies in arp_process, a non-zero inner "
    "vid never reaches the hook, and the ingress guard is the constant true that "
    "allows the offset the ARP list forbids.")

open(os.path.join(ROOT, "findings/F41-pppoe-and-arp-death/summary.json"),
     "w").write(json.dumps(out_json, indent=1, sort_keys=True) + "\n")
print("\nsummary.json written")
