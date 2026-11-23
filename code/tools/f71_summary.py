#!/usr/bin/env python3
"""f71_summary.py -- build findings/F71-condense-clause1/summary.json from the
logs, one row per arm, both boots side by side.  Pure transcription: every
number is read out of the log, nothing is computed from a prediction."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify593 as V   # noqa: E402

OUT = V.ROOT + "/findings/F71-condense-clause1/summary.json"
LOGS = [V.ROOT + "/logs/f71_rep1.log", V.ROOT + "/logs/f71_rep2.log"]


def row(rec):
    A = rec["arm"]
    c = rec["cnt"][0]
    r = rec["rcv"][0]
    eq = rec["eq"][0] if rec["eq"] else None
    cq = rec["cq"][0] if rec["cq"] else None
    port = "rmem1" if A["skt"] == "g" else "rmem0"
    out = {
        "name": A["name"], "warden": {"xg": A["xg"], "skt": A["skt"],
                                      "j": int(A["j"]), "n": int(A["n"]),
                                      "pl": int(A["pl"]), "sh": int(A["sh"]),
                                      "sl": int(A["sl"]),
                                      "tap": int(A["tap"])},
        "measured": {
            "enq": int(c["enq"]), "cond": int(c["cond"]),
            "pull": int(c["pull"]), "eat": int(c["eat"]),
            "seg": int(c["seg"]), "trim": int(c["trim"]),
            "clone": int(c["clone"]),
            "charge": int(r[port]) - int(A["j"]) * V.S,
            "delivered_n": int(r["n1"] if A["skt"] == "g" else r["n0"]),
            "delivered_last": V.ilist(r["hl1"] if A["skt"] == "g"
                                      else r["hl0"]),
            "rmem_before_read": int(r[port]),
            "udpin": int(r["udpin"]),
        },
    }
    if eq:
        out["gate"] = {k: V.ilist(eq[k])[0] for k in
                       ("len", "dlen", "tail", "end", "ts", "fl")}
    if cq:
        out["branch"] = {k: V.ilist(cq[k])[0] for k in
                         ("len", "dlen", "tail", "end", "ts", "fl")}
        out["room"] = out["branch"]["end"] - out["branch"]["tail"]
    return out


def main():
    arms = V.parse_arms(V.SRC_ADD)
    res = {"turn": 593, "finding": "F71-condense-clause1",
           "kernel": "7.3.4-T563",
           "predictions_sha256": V.PRED_SHA,
           "boots": []}
    for path in LOGS:
        recs, txt, order = V.parse_log(path)
        boot = {"log": os.path.basename(path), "arms": []}
        for i in range(len(arms)):
            rec = recs.get((i, 0))
            if rec:
                boot["arms"].append(row(rec))
        res["boots"].append(boot)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    print(OUT, len(res["boots"][0]["arms"]), "arms")


if __name__ == "__main__":
    main()
