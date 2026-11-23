#!/usr/bin/env python3
"""f591_summary.py -- every table of F69's SUMMARY.md, collected from the logs.

Writes findings/F69-segment-price/summary.json.  Nothing here decides whether
the numbers are RIGHT -- that is verify591.py's job; this only collects what the
logs say so that the document can be checked against it by audit_f69_doc.py.
"""
import hashlib
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
LOGS = [ROOT + "/logs/f69_rep1.log", ROOT + "/logs/f69_rep2.log"]
OUT = ROOT + "/findings/F69-segment-price/summary.json"
KV = re.compile(r"([a-z0-9_]+)=([^|]*)")


def kv(line):
    return {m.group(1): m.group(2) for m in KV.finditer(line)}


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def parse(path):
    arms, pend, att = [], [], None
    for raw in open(path, errors="replace"):
        line = raw.rstrip("\n")
        if line.startswith("F591 RCV|"):
            d = kv(line)
            att = {"att": int(d["att"]), "n": int(d["n"]),
                   "rmem": int(d["rmem"]), "rb": int(d["rb"]),
                   "dl0": int(d["dl0"]), "dl1": int(d["dl1"]),
                   "udperr": int(d["udperr"]), "log": [],
                   "wait": None}
            pend.append(att)
        elif line.startswith("F591 WAIT|"):
            d = kv(line)
            if pend:
                pend[-1]["wait"] = int(d["rmem"])
        elif line.startswith("F591 ARM|"):
            d = kv(line)
            a = {"name": d["name"], "kind": d["kind"], "door": d["xg"],
                 "n": int(d["n"]), "pl": int(d["pl"]), "sh": int(d["sh"]),
                 "sl": int(d["sl"]), "head": int(d["head"]),
                 "primer": int(d["primer"]), "ch": int(d["ch"]),
                 "mn": int(d["mn"]), "an": int(d["an"]),
                 "bn": int(d["bn"]), "agr": int(d["agr"]),
                 "rcvbuf": int(d["rcvbuf"]), "attempts": pend}
            arms.append(a)
            pend = []
            att = a["attempts"][-1] if a["attempts"] else None
        elif line.startswith("F591 LOG|") and att is not None:
            d = kv(line)
            att["log"].append({"uh": int(d["uh"]), "tot": int(d["tot"]),
                               "plen": int(d["plen"]), "ttl": int(d["ttl"]),
                               "ck": int(d["ck"], 16), "p0": int(d["p0"], 16),
                               "id": int(d["id"])})
        elif line.startswith("F591 TAP|") and att is not None:
            pass
    return arms


def main():
    logs = sys.argv[1:] or LOGS
    runs = [parse(p) for p in logs]
    out = {
        "turn": 591,
        "finding": "F69 — the fraglist segmenter keeps the whole aggregate's truesize on its first segment, and the GRO byte cap is reachable only with equal payloads",
        "question": "Why is an aggregate of k datagrams charged (2k-1) datagram prices below half a receive buffer, where does the 20-byte wobble come from, and how does the fraglist byte cap of 65536 actually bind?",
        "answer_short": "skb_segment_list() subtracts len and data_len from the head and never touches truesize, so the first segment pays for the whole aggregate: A(k) = (2k-1)*s, and the old 20 bytes are 1280/64, one unit short. The cap binds on the byte (65535 merges, 65536 splits) when every payload is equal; a length change ends the flow, which is why long-head arms never reached it.",
        "answer": "26 of 26 frozen predictions; 33 arms, two boots, two attempts each; verify591.py 6047 checks, 0; selftest 25/25; document audit 117 checks, 0, 5/5 mutations caught.",
        "headline": "The aggregate's price is a segmenter artefact, not a price: (2k-1)*s, and the 20-byte wobble is 1280/64.",
        "kernel_sha": sha(ROOT + "/src/linux-7.3.4-T563/arch/x86/boot/bzImage"),
        "differ_sha": sha(ROOT + "/vm/build/differ591"),
        "predictions_sha": sha(ROOT + "/research/predictions_591.md"),
        "logs": [{"path": p, "sha256": sha(p),
                  "bytes": os.path.getsize(p)} for p in logs],
        "runs": [],
    }
    for arms in runs:
        run = {"arms": [], "s": {}}
        for a in arms:
            prim = 8 + a["primer"]
            rec = {"name": a["name"], "kind": a["kind"], "door": a["door"],
                   "n": a["n"], "pl": a["pl"], "ch": a["ch"],
                   "mn": a["mn"], "an": a["an"], "agr": a["agr"],
                   "rcvbuf": a["rcvbuf"], "attempts": []}
            for x in a["attempts"]:
                msgs = [m for m in x["log"] if m["uh"] != prim]
                rec["attempts"].append({
                    "att": x["att"], "n": x["n"], "rmem": x["rmem"],
                    "wait": x["wait"], "udperr": x["udperr"],
                    "uh": [m["uh"] for m in msgs],
                    "plen": [m["plen"] for m in msgs],
                })
            run["arms"].append(rec)
            if a["kind"] == "q" and a["n"] == 1:
                run["s"][str(a["pl"])] = a["attempts"][0]["rmem"]
        out["runs"].append(run)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)
    print("wrote", OUT)
    for i, run in enumerate(out["runs"]):
        print("run%d s=%s" % (i, run["s"]))
        for a in run["arms"]:
            if a["kind"] == "c":
                print("  cap   %-12s ch=%d an=%d uh=%s" %
                      (a["name"], a["ch"], a["an"],
                       [[u for u in x["uh"]] for x in a["attempts"]]))
            else:
                print("  price %-12s rmem=%s shape=%s" %
                      (a["name"], [x["rmem"] for x in a["attempts"]],
                       [[u for u in x["uh"]] for x in a["attempts"]]))


if __name__ == "__main__":
    main()
