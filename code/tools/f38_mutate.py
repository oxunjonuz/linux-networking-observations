#!/usr/bin/env python3
"""f38_mutate.py <log> <rule> -- change ONE field of one log line.

Used by verify560_selftest.sh: every rule must make verify560.py go red with a
FAIL line, and the mutation must not be able to pass for the wrong reason.
Exits 1 (with a message) when the anchor is missing -- a mutation that silently
did nothing would be a hole in the selftest, not a pass (F34..F37 lesson).
"""
import sys

RULES = {
    # name:        (line must contain ...,  old, new, occurrence)
    "live_to_dead":  ("|env=recv.w100|arm=g16_2|", "|live=1|", "|live=0|", 1),
    "dead_to_live":  ("|env=recv.p|arm=g16_1|", "|live=0|", "|live=1|", 1),
    "ingress_dead":  ("|env=ndin.x91|arm=g20_1|", "|live=1|", "|live=0|", 1),
    "egress_alive":  ("|env=ndeg.s8100|arm=g0_2|", "|live=0|", "|live=1|", 1),
    "arp_past":      ("|env=arp.aw100|arm=x20_16|", "38:22>90", "34:22>90", 1),
    "wire_byte":     ("|env=recv.x91|arm=ctl|", "91000064", "91000065", 1),
    # the p control's wheel and rhex are the same bytes: anchor INSIDE the
    # rhex field, or the mutation lands in the wheel and tests another check
    "far_byte":      ("|env=recv.p|arm=ctl|",
                      "|rhex=ffffffffffffaabbcc00006608004500002e123400004011547a0a0100010a0900079c40",
                      "|rhex=ffffffffffffaabbcc00006608004500002e123400004011547a0a0100010a0900079c41",
                      1),
    "probe_m100":    ("|env=recv.m100|arm=ctl|", "4500002e", "4500002f", 1),
    "tagstore_rc":   ("F560 TAGSTORE|", "|rc=0|", "|rc=4294967282|", 1),
    "ttl_index":     ("|env=ndin.w100|arm=g8_1|", "26:40>90", "22:40>90", 1),
    "drop_refused":  ("|env=drop.drop|arm=p16_2|", "|rn=-1|", "|rn=60|", 1),
    "drop_delivered": ("|env=drop.drop|arm=w16_2|", "|rn=60|", "|rn=-1|", 1),
    "mode_exit":     ("=== MODE_EXIT f560=", "f560=0", "f560=1", 1),
    "kernel_sha":    ("### sha256: ", "459f02a5", "459f02a6", 1),
    "splat":         ("=== DMESG_TAIL ===", "=== DMESG_TAIL ===",
                      "KASAN: wild-memory-access in selftest\n=== DMESG_TAIL ===",
                      1),
    "arm_dropped":   ("|env=ndeg.s0800|arm=g10_1|", None, None, 0),
}


def main():
    if len(sys.argv) != 3:
        print("usage: f38_mutate.py <log> <rule>")
        return 2
    path, rule = sys.argv[1], sys.argv[2]
    if rule not in RULES:
        print("unknown rule %r" % rule)
        return 2
    anchor, old, new, n = RULES[rule]
    with open(path, "rb") as f:
        text = f.read().decode("utf-8", "replace")
    lines = text.split("\n")
    hit = None
    for i, line in enumerate(lines):
        if anchor in line:
            hit = i
            break
    if hit is None:
        print("anchor not found: %r" % anchor)
        return 1
    if rule == "arm_dropped":
        del lines[hit]
        print("dropped line %d" % hit)
    else:
        if old not in lines[hit]:
            print("field not found in line %d: %r" % (hit, old))
            return 1
        lines[hit] = lines[hit].replace(old, new, n)
        print("mutated line %d: %r -> %r" % (hit, old, new))
    with open(path, "wb") as f:
        f.write("\n".join(lines).encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
