#!/usr/bin/env python3
"""f42_mutate.py <log-in> <log-out> <mutation> -- one field at a time.

The mutations are named; every one of them must make verify564.py fail.
A mutation that the verifier does not notice is a hole in the verifier, not a
result about the kernel.
"""
import sys

MUT = {}


def mut(name):
    def deco(fn):
        MUT[name] = fn
        return fn
    return deco


def sub_once(s, old, new):
    if old not in s:
        raise SystemExit("mutation target not found: %r" % old)
    return s.replace(old, new, 1)


def sub_arm(s, arm, old, new):
    """replace one substring on the line of one arm only"""
    out = []
    hit = 0
    for line in s.split("\n"):
        if ("|arm=%s|" % arm) in line and old in line:
            line = line.replace(old, new, 1)
            hit += 1
        out.append(line)
    if hit != 1:
        raise SystemExit("arm %s: %d hits" % (arm, hit))
    return "\n".join(out)


@mut("frame_pppoe_len")
def _(s):
    # the PPPoE length in the logged frame: 0030 -> 0032
    return sub_once(s, "006300300021", "006300320021")


@mut("frame_sid")
def _(s):
    return sub_once(s, "006300300021", "006200300021")


@mut("frame_payload")
def _(s):
    return sub_once(s, "7777777777777777", "7777777777777776")


@mut("frame_ethertype")
def _(s):
    return sub_once(s, "006688641100", "006688651100")


@mut("v6frame_len")
def _(s):
    return sub_once(s, "F564 V6|frame|len=88|", "F564 V6|frame|len=87|")


@mut("v6frame_proto")
def _(s):
    return sub_once(s, "006300440057", "006300440021")


@mut("udp4_bytes")
def _(s):
    return sub_arm(s, "ctl", "udp4=18", "udp4=17")


@mut("ctl_prx")
def _(s):
    return sub_arm(s, "ctl", "prx=46", "prx=45")


@mut("ctl_ipin")
def _(s):
    return sub_arm(s, "ctl", "ideliv=1", "ideliv=0")


@mut("ttl_ihdr")
def _(s):
    return sub_arm(s, "ttl", "ihdr=1", "ihdr=0")


@mut("daddr_ihdr")
def _(s):
    return sub_arm(s, "daddr", "ihdr=1", "ihdr=0")


@mut("ttlsame_delivery")
def _(s):
    return sub_arm(s, "ttlsame", "udp4=18", "udp4=-1")


@mut("id4_prx")
def _(s):
    return sub_arm(s, "id4", "prx=2", "prx=46")


@mut("idbig_prx")
def _(s):
    return sub_arm(s, "idbig", "prx=0", "prx=46")


@mut("ll6_live")
def _(s):
    return sub_arm(s, "ll6", "live=1", "live=0")


@mut("ll13_ipin")
def _(s):
    return sub_arm(s, "ll13", "ipin=1", "ipin=0")


@mut("pre88ff")
def _(s):
    return sub_arm(s, "pre88ff", "udp4=-1", "udp4=18")


@mut("hop_urn")
def _(s):
    return sub_arm(s, "hop", "urn=68", "urn=0")


@mut("hop_urhex")
def _(s):
    return sub_arm(s, "hop", "urhex=0090", "urhex=0057")


@mut("hdrbad_hdr")
def _(s):
    return sub_arm(s, "hdr_bad", "i6hdr=1", "i6hdr=0")


@mut("hdrbad_deliv")
def _(s):
    return sub_arm(s, "hdr_bad", "i6deliv=0", "i6deliv=1")


@mut("novlan_arc")
def _(s):
    return sub_arm(s, "ctl_novlan", "arccnt=0", "arccnt=1")


@mut("shavlan_reply")
def _(s):
    return sub_arm(s, "sha_vlan", "rephex=9091", "rephex=9191")


@mut("opvlan_reply")
def _(s):
    return sub_arm(s, "op_vlan", "repn=-1", "repn=42")


@mut("livedelta")
def _(s):
    return sub_arm(s, "vt", "cnt=1|live=1", "cnt=0|live=1")


@mut("rhex")
def _(s):
    return sub_arm(s, "vt", "rhex=ffffffffffffaabbcc0000668864119100",
                   "rhex=ffffffffffffaabbcc0000668864110000")


def main():
    if len(sys.argv) != 4:
        print("usage: f42_mutate.py <in> <out> <name>")
        return 2
    name = sys.argv[3]
    if name not in MUT:
        print("unknown mutation; known: " + " ".join(sorted(MUT)))
        return 2
    s = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    out = MUT[name](s)
    open(sys.argv[2], "w", encoding="utf-8").write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
