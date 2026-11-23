#!/usr/bin/env python3
"""verify589_selftest.py -- can verify589.py go red, and only for a reason?

Each case is ONE substitution in a copy of the rep1 log, run through
verify589.py as if both boots were that copy, plus a noop that must stay
green.  A verifier that passes everything is not a verifier; a verifier that
crashes instead of failing is not one either, so every mutation must exit
non-zero WITHOUT a traceback.

Case 28 keeps the queue numbers and moves only the filler's frame count: if it
stays green the tap witness is not being read at all.
"""
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
VER = f"{ROOT}/tools/verify589.py"
SRC = f"{ROOT}/logs/f67_rep1.log"
TMP = "/tmp/f67_selftest.log"

text = open(SRC, errors="replace").read()


def run(t):
    open(TMP, "w").write(t)
    p = subprocess.run([sys.executable, VER, TMP, TMP],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def one_line(pattern, repl, count=1):
    new, n = re.subn(pattern, repl, text, count=count, flags=re.M)
    assert n == count, f"pattern not found once: {pattern}"
    return new


def arm_field(name, field, value):
    """replace one field on the ARM row of one arm"""
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("F589 ARM|") and f"|name={name}|" in ln:
            lines[i] = re.sub(rf"\|{field}=[^|]*", f"|{field}={value}", ln,
                              count=1)
            return "\n".join(lines) + "\n"
    raise AssertionError(f"no ARM row for {name}")


def nth_rcv_field(idx, field, value, att=None):
    """replace a field on the idx-th RCV line (optionally of one attempt)"""
    lines = text.splitlines()
    seen = 0
    for i, ln in enumerate(lines):
        if not ln.startswith("F587 RCV|"):
            continue
        if f"i={idx:02d}" not in ln:
            continue
        if att is not None and f"att={att}" not in ln:
            continue
        lines[i] = re.sub(rf"\|{field}=[^|]*", f"|{field}={value}", ln, count=1)
        return "\n".join(lines) + "\n", seen
    raise AssertionError(f"no RCV line for i={idx}")


cases = []
cases.append(("noop", text, 0))

cases.append(("kept 39 -> 40 on d54_lazy_b",
              nth_rcv_field(2, "nt", 40)[0], 1))
cases.append(("kept 43 -> 44 on the 1200 mixed arm",
              nth_rcv_field(3, "nt", 44)[0], 1))
cases.append(("the filler loses one datagram",
              nth_rcv_field(0, "nf", 63)[0], 1))
cases.append(("Udp6InErrors off by one",
              nth_rcv_field(2, "udperr", 14)[0], 1))
cases.append(("Udp6InDatagrams off by one",
              nth_rcv_field(2, "udp", 38)[0], 1))
cases.append(("a datagram arrives too early for a lazy reader",
              nth_rcv_field(2, "T", "120,120,120,120,120,120,0,0")[0], 1))
cases.append(("the read-back buffer is not 2v",
              nth_rcv_field(2, "rb", "99999")[0], 1))
cases.append(("the reader is reported eager",
              nth_rcv_field(2, "lazy", "0")[0], 1))
cases.append(("Ip6InHdrErrors is not zero",
              nth_rcv_field(2, "hdr", "3")[0], 1))
cases.append(("DEFRB is not the derived default",
              one_line(r"F67 DEFRB\|def=212992", "F67 DEFRB|def=425984"), 1))
cases.append(("the first RXQ read is short by one segment",
              one_line(r"00000000000000000000000000000000:0000 07 00000000:00033C00",
                       "00000000000000000000000000000000:0000 07 00000000:00033B00"),
              1))
cases.append(("one rmem loses a whole head",
              one_line(r":0003FE00 ", ":00027B00 "), 1))
cases.append(("a message is one datagram shorter",
              one_line(r"i=03\|att=0\|k=1\|plen=64848\|u6=fd28",
                       "i=03|att=0|k=1|plen=64848|u6=0bd8"), 1))
cases.append(("a message length is wrong",
              one_line(r"i=03\|att=0\|k=1\|plen=64848",
                       "i=03|att=0|k=1|plen=64849"), 1))
cases.append(("a message carries the wrong destination",
              one_line(r"i=03\|att=0\|k=1\|plen=64848\|u6=fd28\|dst=fd030000",
                       "i=03|att=0|k=1|plen=64848|u6=fd28|dst=fd040000"), 1))
cases.append(("the payload's first byte is wrong",
              one_line(r"\|p0=e04142", "|p0=004142"), 1))
cases.append(("the arm's rcvbuf is misprinted",
              arm_field("c_fill_test1200_311", "rcvbuf", 155647), 1))
cases.append(("the rule counted one packet fewer",
              arm_field("d64x1200_lazy", "ch", 1), 1))
cases.append(("the message count is wrong",
              arm_field("c_fill_test", "mn", 3), 1))
cases.append(("the two attempts disagree",
              arm_field("c_only_test", "agr", 0), 1))
cases.append(("an arm is renamed",
              one_line(r"name=c_fill_test1200_344", "name=c_fill_test1200_345"), 1))
cases.append(("an arm disappears",
              one_line(r"^F589 ARM\|i=05.*\n", "", 1), 1))
cases.append(("the y2 witness loses a frame",
              arm_field("c_only_fill", "bn", 63), 1))
cases.append(("the y1 witness loses a frame",
              arm_field("c_only_test", "an", 0), 1))
cases.append(("the initrd in the header is not the one on disk",
              one_line(r"### initrd sha256: 084ca450",
                       "### initrd sha256: 184ca450"), 1))
cases.append(("the kernel in the header is not the image",
              one_line(r"### sha256: 1efbc957", "### sha256: 2efbc957"), 1))
cases.append(("the cond block is gone",
              text[:text.index("=== MODE_BEGIN cond ===")] +
              text[text.index("=== MODE_EXIT cond="):], 1))

green_bad = []
for name, t, want_fail in cases:
    if name == "noop":
        rc, out = run(t)
        if rc != 0:
            green_bad.append(f"noop went red: {out.strip().splitlines()[-1]}")
        continue
    rc, out = run(t)
    if rc == 0:
        green_bad.append(f"{name}: stayed GREEN")
    elif "Traceback" in out:
        green_bad.append(f"{name}: crashed instead of failing")

n = len(cases) - 1
print(f"selftest: {n - len(green_bad)}/{n} mutations red without a traceback, "
      f"noop {'green' if not any('noop' in g for g in green_bad) else 'RED'}")
for g in green_bad:
    print("FAIL " + g)
sys.exit(1 if green_bad else 0)
