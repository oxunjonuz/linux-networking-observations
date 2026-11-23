#!/usr/bin/env python3
"""audit_f66_doc.py -- does the document say what the log says?

Every number in findings/F66-gro-budget/SUMMARY.md is traced back to
summary.json (which is generated from the log) or recomputed from the kernel
arithmetic.  Then three single substitutions are made in a COPY of the
document and the audit must catch each one: a check that cannot fail because
the document mutated underneath would prove nothing.
"""
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = f"{ROOT}/findings/F66-gro-budget/SUMMARY.md"
SUM = f"{ROOT}/findings/F66-gro-budget/summary.json"
ADD = f"{ROOT}/vm/differ588_add.c"

ok = 0
bad = []


def chk(cond, what):
    global ok
    if cond:
        ok += 1
    else:
        bad.append(what)


def fold(s):
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s & 0xFFFF


def csum16(b):
    if len(b) & 1:
        b = b + b"\0"
    return fold(sum((b[i] << 8) | b[i + 1] for i in range(0, len(b), 2)))


SA = bytes([0xfd, 0x02] + [0] * 13 + [0x11])
DA = bytes([0xfd, 0x03] + [0] * 13 + [0x92])


def seed(ulen):
    return fold(csum16(SA + DA + ulen.to_bytes(4, "big") + b"\0\0\0" +
                       bytes([17])))


def audit(doc, summary, add_src):
    ok0 = ok

    # ---- the split table ------------------------------------------------
    want = {
        "q1024_lazy": (1, 63, 81920), "q4096_lazy": (1, 63, 81920),
        "q8192_lazy": (1, 63, 81920), "q16384_lazy": (1, 63, 81920),
        "q32768_lazy": (1, 63, 81920),
        "q49152_lazy": (13, 51, 97280), "q57344_lazy": (26, 38, 113920),
        "q65536_lazy": (39, 25, 130560), "q73728_lazy": (52, 12, 147200),
        "q131072_lazy": (64, 0, 162560), "q262144_lazy": (64, 0, 162560),
        "q1048576_lazy": (64, 0, 162560),
    }
    by_name = {r["name"]: r for r in summary["split"]}
    for name, (kept, err, rxq) in want.items():
        r = by_name.get(name)
        chk(r is not None, f"summary has {name}")
        if not r:
            continue
        chk(r["kept"] == [kept, kept], f"summary kept {name} == {kept}")
        chk(r["errors"] == [err, err], f"summary errors {name} == {err}")
        chk(r.get("queue_bytes") == [rxq, rxq],
            f"summary queue {name} == {rxq}")
        row = None
        for ln in doc.splitlines():
            if ln.startswith(f"| `{name}`"):
                row = ln
                break
        chk(row is not None, f"doc row {name}")
        if not row:
            continue
        chk(f"**{kept}**" in row, f"doc {name}: kept {kept} in the row")
        chk(f"| {err} |" in row or f"| {err} | " in row or err == 0,
            f"doc {name}: errors {err} in the row")
        chk(str(rxq) in row, f"doc {name}: queue {rxq} in the row")

    # ---- the derived constants -----------------------------------------
    chk(summary["derived"]["per_datagram_truesize_512"] == 1280,
        "summary: s == 1280")
    chk(summary["derived"]["aggregate_truesize_64x512"] == 81920,
        "summary: A == 81920")
    chk(64 * 1280 == 81920, "A is 64 datagrams of s")
    chk(81920 + 38 * 1280 == 130560, "39 kept == 130560 bytes")
    chk(81920 + 63 * 1280 == 162560, "64 kept == 162560 bytes")
    chk(81920 + 12 * 1280 == 97280, "13 kept == 97280 bytes")
    chk(81920 + 25 * 1280 == 113920, "26 kept == 113920 bytes")
    chk(81920 + 51 * 1280 == 147200, "52 kept == 147200 bytes")
    for line in ("130560", "162560", "97280", "113920", "147200", "81920"):
        chk(line in doc, f"doc carries the queue byte count {line}")

    # ---- the cap table --------------------------------------------------
    cap = {r["name"]: r for r in summary["cap"]}
    want_cap = {
        "ku1022_f": (1, 40 + 65416), "ku1023_f": (2, 40 + 64457),
        "ku1023_u": (1, 40 + 65480), "ku1024_u": (2, 40 + 64520),
        "tf990": (1, 40 + 8 + 63 * 1023 + 990),
        "tf991": (2, 40 + 8 + 63 * 1023),
        "tu975": (1, 40 + 8 + 63 * 1024 + 975),
        "tu976": (2, 40 + 8 + 63 * 1024),
    }
    for name, (pk, firstlen) in want_cap.items():
        r = cap.get(name)
        chk(r is not None, f"summary has cap arm {name}")
        if not r:
            continue
        chk(r["packets"] == pk, f"summary {name}: {pk} packets")
        chk(r["first_len"] == min(firstlen, 65531),
            f"summary {name}: first message {firstlen} (or the 65531 cut)")
    # the arithmetic behind the two ceilings, recomputed here
    chk(96 + 64 * 1022 < 65536 and 96 + 64 * 1023 >= 65536,
        "fraglist: 1022 merges, 1023 does not")
    chk(48 + 64 * 1023 < 65536 and 48 + 64 * 1024 >= 65536,
        "linear: 1023 merges, 1024 does not")
    chk(96 + 63 * 1023 + 990 < 65536 and 96 + 63 * 1023 + 991 >= 65536,
        "fraglist tail: 990 merges, 991 does not")
    chk(48 + 63 * 1024 + 975 < 65536 and 48 + 63 * 1024 + 976 >= 65536,
        "linear tail: 975 merges, 976 does not")

    # the document's numbers must EQUAL the recomputed boundaries, not merely
    # appear somewhere: mutating one of them has to break this.
    def first_ok(shape, N):
        H = 2 * 48 if shape == "f" else 48
        for P in range(1, 4096):
            if H + N * P >= 65536:
                return P - 1
        return -1

    def tail_ok(shape, P):
        H = 2 * 48 if shape == "f" else 48
        for sl in range(0, P + 1):
            if H + 63 * P + sl >= 65536:
                return sl - 1
        return -1

    chk(first_ok("f", 64) == 1022, "recomputed fraglist ceiling 1022")
    chk(first_ok("u", 64) == 1023, "recomputed linear ceiling 1023")
    chk(tail_ok("f", 1023) == 990, "recomputed fraglist tail 990")
    chk(tail_ok("u", 1024) == 975, "recomputed linear tail 975")
    chk(f"P ≤ **{first_ok('f', 64)}**" in doc,
        f"doc states the fraglist ceiling {first_ok('f', 64)}")
    chk(f"P ≤ **{first_ok('u', 64)}**" in doc,
        f"doc states the linear ceiling {first_ok('u', 64)}")
    chk(f"sl ≤ **{tail_ok('f', 1023)}**" in doc,
        f"doc states the fraglist tail flip {tail_ok('f', 1023)}")
    chk(f"sl ≤ **{tail_ok('u', 1024)}**" in doc,
        f"doc states the linear tail flip {tail_ok('u', 1024)}")
    chk(96 + 63 * 1023 + 963 < 65536,
        "tf963 merges -> H != 62")
    chk(54 + 65481 < 65536 and 54 + 65482 >= 65536,
        "the frame ceiling sits between uh->len 65481 and 65482")
    for s in ("0xff88", "0xffc8", "0xfbc9", "0x0407", "0xfc08", "65416",
              "65480", "64457", "64520", "990", "991", "975", "976",
              "65535", "65536", "65531"):
        chk(s in doc, f"doc carries {s}")

    # ---- the seeds ------------------------------------------------------
    chk(seed(520) == 0xFCC2, "seed(520) == fcc2 (the fraglist aggregate's field)")
    chk(seed(1031) == 0xFEC1, "seed(1031) == fec1 (a 1023-byte datagram)")
    chk(seed(1544) == 0x00C3, "seed(1544) == 00c3 (a linear aggregate)")
    for s in ("fcc2", "00c3", "fec1"):
        chk(s in doc, f"doc carries the seed {s}")

    # ---- the arm names the document mentions exist in the instrument ----
    for name in list(want) + list(want_cap):
        chk(f'"{name}"' in add_src, f"arm {name} exists in differ588_add.c")
    chk(len(re.findall(r'^\t\{ "', add_src, re.M)) == 42,
        "forty-two arms in the instrument")

    # ---- the tap claims -------------------------------------------------
    for s in ("`t3_store_a`", "1584", "1598", "62", "48", "tp_status"):
        chk(s in doc, f"doc carries the witness detail {s}")
    chk(14 + 40 + 8 == 62, "the store's frame offset is 62")
    chk(40 + 8 == 48, "the store's message offset is 48")
    chk(54 + 1544 == 1598, "the frame is 54 bytes longer than uh->len")
    return ok - ok0


doc = open(DOC, errors="replace").read()
summary = json.load(open(SUM))
add_src = open(ADD, errors="replace").read()
audit(doc, summary, add_src)

# ---- three single substitutions must be caught --------------------------
MUT = [
    ("kept 39 -> 40", "| **39** | 25 | 130560 |", "| **40** | 25 | 130560 |"),
    ("the linear cap 1023 -> 1022", "P ≤ **1023**", "P ≤ **1022**"),
    ("the tail flip 990 -> 962", "sl ≤ **990**", "sl ≤ **962**"),
]
caught = 0
for name, old, new in MUT:
    assert doc.count(old) == 1, f"mutation anchor {name}"
    mutated = doc.replace(old, new)
    before = len(bad)
    ok_before = ok
    audit(mutated, summary, add_src)
    if len(bad) > before:
        caught += 1
        ok = ok_before
        bad[:] = bad[:before]
    else:
        bad.append(f"document mutation NOT caught: {name}")

print(f"checks={ok} failures={len(bad)} mutations_caught={caught}/3")
for b in bad[:20]:
    print("FAIL:", b)
sys.exit(1 if bad else 0)
