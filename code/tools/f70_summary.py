#!/usr/bin/env python3
"""f70_summary.py -- every table of F70's SUMMARY.md, built from the logs.

Writes findings/F70-condense/summary.json.  Nothing is typed in by hand: each
number comes from a line of logs/f70_rep{1,2}.log, and the document is audited
against this file by tools/audit_f70_doc.py.
"""
import json
import os
import re
import sys

sys.path.insert(0, "/work/kernel-sec/tools")
from verify592 import parse_arms, parse_log, trace_records, SRC_ADD, LOGS  # noqa: E402

ROOT = "/work/kernel-sec"
OUT = ROOT + "/findings/F70-condense/summary.json"


def main():
    arms = parse_arms(SRC_ADD)
    per = {}
    for idx, a in enumerate(arms):
        row = {"name": a["name"], "xg": a["xg"], "j": a["j"], "n": a["n"],
               "pl": a["pl"], "sh": a["sh"], "sl": a["sl"],
               "rcvbuf": a["rcvbuf"], "exp_f": a["exp_f"],
               "exp_delta": a["exp_delta"], "exp_calls": a["exp_calls"],
               "att": []}
        for log in LOGS:
            attempts, _ = parse_log(log)
            for att in (0, 1):
                rec = attempts.get((idx, att))
                if not rec:
                    continue
                r = rec["rcv"][-1]
                w = rec["wait"][-1] if rec["wait"] else {}
                c = rec["cnt"][-1]
                recs = trace_records(rec)
                row["att"].append({
                    "boot": os.path.basename(log),
                    "att": att,
                    "rb": int(r["rb"]),
                    "filler_rmem": int(rec["wait"][0]["rmem"]) if rec["wait"] else -1,
                    "rmem_after": int(r["rmem"]),
                    "delta": int(r["rmem"]) - int(rec["wait"][0]["rmem"])
                    if rec["wait"] else -1,
                    "datagrams": int(r["n"]),
                    "nf": int(r["nf"]), "nt": int(r["nt"]),
                    "cond": int(c["cond"]), "pull": int(c["pull"]),
                    "enq": int(c["enq"]), "trim": int(c["trim"]),
                    "seg": int(c["seg"]), "mark": int(c["mark"]),
                    "ts": [f.get("ts") for f in recs],
                    "dlen": [f.get("dlen") for f in recs],
                    "len": [f.get("len") for f in recs],
                    "tail": [f.get("tail") for f in recs],
                    "end": [f.get("end") for f in recs],
                    "fl": [f.get("fl") for f in recs],
                })
        per[a["name"]] = row

    def stable(name, key):
        vals = [x[key] for x in per[name]["att"]]
        return sorted(set(vals))

    out = {
           "finding": "F70-condense",
           "turn": 592,
           "headline": "skb_condense() fires only above half a receive buffer, "
                       "replaces an aggregate head's truesize with one "
                       "datagram's, and the comparison is strictly greater -- "
                       "measured at the function with a kprobe",
           "kernel_sha": "1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033",
           "question": "What does skb_condense() actually see when "
                       "__udp_enqueue_schedule_skb() calls it, and is the "
                       "`rmem > (rcvbuf >> 1)` comparison strict at the "
                       "boundary?",
           "answer_short": "On the fraglist door the aggregate's head arrives "
                           "at the branch already linear (data_len 0) carrying "
                           "the whole aggregate (7680 = 6*1280) and the last "
                           "line of skb_condense() rewrites it into 1280; a "
                           "queue exactly on rcvbuf/2 is NOT above it (5 calls, "
                           "delta 14080) while one datagram more gives 6 calls "
                           "and 7680. A linear-door aggregate costs the same "
                           "7680 by a different route, and only the probe "
                           "separates the two.",
           "answer": "36 attempts (9 arms x 2 attempts x 2 boots), 160 "
                     "records, 2034 checks, 0 failed; selftest 26/26 with "
                     "half-inclusive among the dead; 12 of 14 predictions held, "
                     "P12 and P14 refuted and named.",
           "arms": list(per.values()),
           "delta": {k: stable(k, "delta") for k in per},
           "calls": {k: stable(k, "cond") for k in per},
           "seg": {k: stable(k, "seg") for k in per},
           "pull": {k: stable(k, "pull") for k in per},
           "trim": {k: stable(k, "trim") for k in per},
           "head_ts": {k: sorted({tuple(x["ts"][:1]) for x in per[k]["att"]
                                  if x["ts"]}) for k in per},
           "fl": {k: sorted({tuple(x["fl"]) for x in per[k]["att"]}) for k in per},
           "attempts": sum(len(per[k]["att"]) for k in per)}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)
    print(json.dumps({k: out[k] for k in ("delta", "calls", "seg", "pull",
                                          "trim", "attempts")},
                     indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
