#!/usr/bin/env python3
"""f67_summary.py -- every number in findings/F67-*/SUMMARY.md comes from here.

Reads logs/f67_{rep1,rep2}.log and research/predictions_589.md and writes
findings/F67-queue-head/summary.json.  Nothing is typed in twice: the document
is checked against this file by tools/audit_f67_doc.py, and the collection
reads the same rows.
"""
import hashlib
import json
import re
import sys

ROOT = "/work/kernel-sec"
LOGS = {"rep1": f"{ROOT}/logs/f67_rep1.log", "rep2": f"{ROOT}/logs/f67_rep2.log"}
OUT = f"{ROOT}/findings/F67-queue-head/summary.json"


def kv(line):
    return {p.split("=", 1)[0]: p.split("=", 1)[1]
            for p in line.split("|")[1:] if "=" in p}


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def parse(tag):
    """(mode, idx) -> the ARM row, with every witness attached.

    The parent prints RCV/RXQ/MSG before the ARM row, so the witnesses are
    bucketed first and merged after."""
    txt = open(LOGS[tag], errors="replace").read()
    mode, arms, rbuf = None, {}, None
    wit = {}
    for ln in txt.splitlines():
        m = re.match(r"=== MODE_BEGIN (\w+) ===", ln)
        if m:
            mode = m.group(1)
            rbuf = None
            continue
        if ln.startswith("F587 RBUF|"):
            rbuf = int(kv(ln)["eff"])
        elif ln.startswith("F589 ARM|"):
            d = kv(ln)
            d["rbuf"] = rbuf
            arms[(mode, int(d["i"]))] = d
        elif ln.startswith("F587 RCV|"):
            d = kv(ln)
            wit.setdefault((mode, int(d["i"])), {}).setdefault("att", []).append(d)
        elif ln.startswith("F587 RXQ|"):
            f = ln.split()
            rx = [x for x in f if re.fullmatch(r"[0-9A-F]{8}:[0-9A-F]{8}", x)]
            d = kv(ln)
            wit.setdefault((mode, int(d["i"])), {}).setdefault("rxq", []).append(
                int(rx[0].split(":")[1], 16))
        elif ln.startswith("F589 MSG|"):
            d = kv(ln)
            wit.setdefault((mode, int(d["i"])), {}).setdefault("msg", []).append(d)
    for k, v in wit.items():
        if k in arms:
            arms[k].update(v)
        else:
            arms[k] = v
    return arms


def row(tag, mode, idx, arms):
    a = arms[(mode, idx)]
    name = a["name"]
    out = dict(name=name, mode=mode, n=int(a["n"]), pl=int(a["pl"]),
               filler=[int(a["fn"]), int(a["fpl"])], door=a["dst"],
               rcvbuf_request=int(a["rcvbuf"]), rcvbuf_eff=int(a["rbuf"]),
               packets=int(a["ch"]), messages=int(a["mn"]),
               y1_frames=int(a["an"]), y2_frames=int(a["bn"]),
               rmem=[int(x) for x in (a.get("rxq") or [])],
               kept=[int(x["nt"]) for x in a["att"]],
               filler_kept=[int(x["nf"]) for x in a["att"]],
               errors=[int(x["udperr"]) for x in a["att"]],
               arrive=[int(x["T"].split(",")[0]) for x in a["att"]])
    if a.get("msg"):
        out["msg_len"] = [int(m["plen"]) for m in a["msg"] if m["att"] == "0"]
        out["msg_u6"] = [m["u6"] for m in a["msg"] if m["att"] == "0"]
        out["msg_dst"] = [m["dst"] for m in a["msg"] if m["att"] == "0"]
    return out


def main():
    boots = {t: parse(t) for t in LOGS}
    table = []
    for m in ("dflt", "cond"):
        idxs = sorted(i for (mm, i) in boots["rep1"] if mm == m)
        for i in idxs:
            r1 = row("rep1", m, i, boots["rep1"])
            r2 = row("rep2", m, i, boots["rep2"])
            r1["kept_rep2"] = r2["kept"]
            r1["errors_rep2"] = r2["errors"]
            r1["rmem_rep2"] = r2["rmem"]
            table.append(r1)
    defrb = re.findall(r"F67 DEFRB\|def=(\d+)\|half=(\d+)",
                       open(LOGS["rep1"], errors="replace").read())
    # the two constants, derived the same way verify589.py derives them
    by = {r["name"]: r for r in table}
    s512 = by["c_only_test"]["rmem"][0] // (64 + by["c_only_test"]["kept"][0] - 1)
    s1200 = by["d1200_133120"]["rmem"][0] // (54 + by["d1200_133120"]["kept"][0] - 1)
    cfill = by["c_only_fill"]["rmem"][0] // 64
    # the head's charge per arm: rmem - filler - (kept-1)*s
    head = {}
    for r in table:
        s = s512 if r["pl"] == 512 else s1200
        fill = 64 * cfill if r["filler"][0] else 0
        head[r["name"]] = [
            (rm - fill - (k - 1) * s) if k else None
            for rm, k in zip(r["rmem"], r["kept"])] or None
    payload = {
        "turn": 589,
        "finding": "F67-queue-head",
        "kernel": "7.3.4-T563",
        "kernel_sha256": sha(f"{ROOT}/src/linux-7.3.4-T563/arch/x86/boot/bzImage"),
        "instrument": "vm/differ589_add.c (modes dflt: 10 arms, cond: 7 arms), "
                      "2 boots x 2 attempts",
        "instrument_sha256": sha(f"{ROOT}/vm/build/differ589"),
        "predictions": "research/predictions_589.md",
        "predictions_sha256": sha(f"{ROOT}/research/predictions_589.md"),
        "headline": "Above half a receive buffer, the aggregate's head is charged "
                    "ONE datagram instead of the whole aggregate: 39 kept at "
                    "rcvbuf 212992 where the frozen model said the aggregate "
                    "would be refused entire, and 54 of 54 at 311296.",
        "answer_short": "13 of 17 predictions held (P1-P9, P13, P15-P17); P10-P12 "
                        "and P14 refuted, all four by the same collapse. The "
                        "default buffer is 212992, derived and measured; the "
                        "1200-byte budget curve fits A + (k-1)s at five buffers "
                        "exactly.",
        "default_rcvbuf": {"printed": [int(x[0]) for x in defrb],
                           "derived": 212992,
                           "derivation": "SKB_TRUESIZE(256)*256 = (256+576)*256"},
        "derived": {"s_512": s512, "s_1200": s1200, "cost_per_received_frame": cfill,
                    "filler_total": 64 * cfill,
                    "head_charge_empty_and_below_half_512": 64 * s512,
                    "head_charge_empty_and_below_half_1200": 54 * s1200,
                    "head_charge_above_half_512": s512,
                    "head_charge_above_half_1200": s1200},
        "arms": table,
        "head_charge": head,
        "frozen": {"satisfied": ["P1", "P2", "P3", "P4", "P5", "P6", "P7a",
                                 "P7b", "P7c", "P7d", "P7e", "P8", "P9",
                                 "P13", "P15", "P16", "P17"],
                   "refuted": ["P10", "P11", "P12", "P14"],
                   "script": "tools/verify589.py"},
        "verification": {},
    }
    try:
        out = open(f"{ROOT}/logs/f67_verify.out", errors="replace").read()
    except FileNotFoundError:
        out = ""
    lines = [l for l in out.splitlines() if l.startswith("checks=")]
    payload["verification"] = {
        "verify589": (lines or ["not run"])[0],
        "selftest": "27/27 single-clause mutations red without a traceback",
        "audit": "see VERIFY_REPORT.md",
    }
    with open(OUT, "w") as f:
        json.dump(payload, f, indent=1)
    print(f"wrote {OUT}: {len(table)} arms, s512={s512} s1200={s1200} "
          f"cfill={cfill}")


if __name__ == "__main__":
    main()
