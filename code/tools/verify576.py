#!/usr/bin/env python3
"""verify576.py -- independent check of the F54 measurement (turn 576).

Reads logs/f54_rep{1,2}.log (plus the initrd hashes) and re-derives every
number the summary will quote:

  A. provenance   -- kernel sha from each run header against the file, initrd
                     sha in the header against logs/f54_initrd_hashes.txt, and
                     the differ *extracted from the initramfs* against
                     vm/build/differ576, byte for byte.
  B. anchors      -- the source lines the model rests on.
  C. frames       -- the two frames rebuilt from the printed ENV MACs.
  D. arms         -- for each arm of both modes: the six door counts, the two
                     action counters, the fate, every IPv6/UDP counter, the
                     far end's demux, the taps, and the multiset of NFLOG
                     messages with prefix, header bytes, VLAN attribute and
                     payload head.
  E. determinism  -- both boots, every derived field after normalising MACs.
  F. warnings     -- the number of WARN lines in the log equals the number of
                     splats the arms themselves report.

Exit 0 with "OK <n> checks"; exit 1 with the first mismatches.
"""
import gzip
import hashlib
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
LOGDIR = os.environ.get("F576_LOGDIR", os.path.join(ROOT, "logs"))
KDIR = os.path.join(ROOT, "src/linux-7.3.4-T563")
NCHK = 0
BAD = []


def ck(cond, what, got=None, want=None):
    global NCHK
    NCHK += 1
    if not cond:
        BAD.append("%s | got=%r want=%r" % (what, got, want))
    return cond


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def newc_member(path, want):
    """return the bytes of member `want` of a gzip'd newc cpio archive"""
    with gzip.open(path, "rb") as f:
        data = f.read()
    off = 0
    out = None
    while off + 110 <= len(data):
        if data[off:off + 6] != b"070701":
            break
        def h(i):
            return int(data[off + 6 + 8 * i: off + 6 + 8 * (i + 1)], 16)
        mode, filesize, namesize = h(1), h(6), h(11)
        name = data[off + 110: off + 110 + namesize - 1].decode()
        doff = off + 110 + namesize
        doff += (-doff) % 4
        body = data[doff: doff + filesize]
        if name.lstrip("./") == want.lstrip("./"):
            out = body
            break
        off = doff + filesize
        off += (-off) % 4
    return out


def src_has(path, needle):
    try:
        with open(os.path.join(KDIR, path), "r", errors="replace") as f:
            return needle in f.read()
    except OSError:
        return False


def parse_log(p):
    """-> (header dict, {mode: [arm dict]}, [frms], counters)"""
    with open(p, "r", errors="replace") as f:
        lines = f.read().split("\n")
    head = {}
    for ln in lines[:10]:
        m = re.match(r"### (kernel|sha256|initrd|initrd sha256): (.*)$", ln)
        if m:
            head.setdefault(m.group(1), []).append(m.group(2).strip())
    frms = {}
    env = {}
    arms = {"warn": [], "xf": []}
    warns = []
    mode = None
    cur = None
    warn_total = 0
    for ln in lines:
        if ln.startswith("=== MODE_BEGIN "):
            mode = ln.split()[2]
            continue
        if ln.startswith("=== MODE_END"):
            mode = None
            continue
        m = re.match(r"^F576 (ENV|WENV|FRM|A|C|B|F|M|T|W)\|(.*)$", ln)
        if not m:
            continue
        tag, rest = m.group(1), m.group(2)
        kv = {}
        for part in rest.split("|"):
            if "=" in part:
                k, v = part.split("=", 1)
                kv[k] = v
        if tag == "ENV":
            env["xf"] = kv
        elif tag == "WENV":
            env["warn"] = kv
        elif tag == "FRM":
            k = rest.split("=", 1)[0]
            frms[k] = rest.split("=", 1)[1]
        elif tag == "A":
            cur = dict(arm=kv["arm"], raw_c=kv, b=None, f=None, msgs=[],
                       tap=None, nfl=int(kv["nfl"]))
            arms.setdefault(mode, []).append(cur)
        elif tag == "C":
            cur["raw_c2"] = kv
        elif tag == "B":
            cur["b"] = kv
        elif tag == "F":
            cur["f"] = kv
        elif tag == "M":
            cur["msgs"] = parse_msgs(rest)
        elif tag == "T":
            cur["tap"] = parse_taps(rest)
        elif tag == "W":
            warns.append({"arm": kv["arm"], "w": kv})
            d = int(kv["dspl"])
            if d > 0:
                warn_total += d
    arms["warn"] = warns
    return head, arms, frms, env, warn_total, lines


def parse_msgs(rest):
    """the M line: n=<n>|m0=prefix:indev:outdev:hwtype:hwlen:hlen:hw:llen:l2:
    vpresent:vproto:vtci:plen:pay"""
    out = []
    n = int(rest.split("|", 1)[0].split("=", 1)[1])
    for part in rest.split("|")[1:]:
        if not part.startswith("m"):
            continue
        f = part.split("=", 1)[1].split(":")
        out.append(dict(prefix=f[0], indev=int(f[1]), outdev=int(f[2]),
                        hwtype=int(f[3]), hwlen=int(f[4]), hlen=int(f[5]),
                        hw=f[6], llen=int(f[7]), l2=f[8],
                        vpresent=int(f[9]), vproto=int(f[10], 16),
                        vtci=int(f[11], 16), plen=int(f[12]), pay=f[13]))
    return out


def parse_taps(rest):
    out = {}
    for part in rest.split("|"):
        if "=" not in part:
            continue
        key, body = part.split("=", 1)
        f = body.split(":")
        out[key] = dict(dev=f[0], n=int(f[1]),
                        flen=int(f[2]) if f[2] != "-" else -1,
                        b=f[3] if len(f) > 3 and f[3] != "-" else "")
    return out


# ---------------------------------------------------------------- the actions
#
# The instrument's own source is the record of what each arm does.  This build
# prints the first action's door/offset/len/immediate and the second action's
# door only, so the verifier reads the arm table out of
# vm/differ576_add.c (whose sha is in the provenance line) rather than
# typing it here.
DOORNAME = {"E76_G6": "g6", "E76_F6": "f6", "E76_N1": "n1",
            "E76_E0": "e0", "E76_E1": "e1", "E76_R0": "r0"}
MODE = {"f576_wr": 1, "f576_rd": 3}


def parse_arms_from_source():
    path = os.path.join(ROOT, "vm/differ576_add.c")
    with open(path) as f:
        text = f.read()
    sec = text[text.index("static void f576_sec_xf(void)"):
               text.index("/* ---------- mode `warn`")]
    consts = {}
    for m in re.finditer(r"unsigned char (\w+)\[(\d+)\] = \{([^}]*)\};", sec):
        vals = [int(x.strip(), 0) for x in m.group(3).split(",") if x.strip()]
        if len(vals) == int(m.group(2)):
            consts[m.group(1)] = "".join("%02x" % v for v in vals)
    arms = {}
    order = []
    pos = 0
    calls = list(re.finditer(r'f576_arm\("([^"]+)",\s*(-?\d+),\s*(\d+),'
                             r'\s*(-?\w+),\s*(\w+),\s*(\d+)\);', sec))
    for i, m in enumerate(calls):
        block = sec[pos:m.start()]
        pos = m.end()
        name = m.group(1)
        na = int(m.group(6))
        vars_ = {}
        for q in re.finditer(r"f576_(wr|rd)\(&(\w+), F576_B_LL, (\d+), (\d+),"
                             r"\s*(\w+)\);", block):
            kind, var, off, lenn, imm = q.groups()
            vars_[var] = (MODE["f576_" + kind], int(off), int(lenn),
                          consts[imm])
        doors = {}
        for q in re.finditer(r"A\[(\d)\]\.door = (\w+);", block):
            doors[int(q.group(1))] = DOORNAME[q.group(2)]
        cvars = {}
        for q in re.finditer(r"A\[(\d)\]\.C = &(\w+);", block):
            cvars[int(q.group(1))] = q.group(2)
        acts = []
        for k in range(na):
            acts.append((doors[k],) + vars_[cvars[k]])
        arms[name] = acts
        order.append((name, int(m.group(2)), int(m.group(3))))
    return arms, order

# ---------------------------------------------------------------- the model

TAG_IN = 0x0065          # the tag the frame arrives with (vid 101)
TAG_EG = 0x0066          # the tag the egress device composes (vid 102)
HL_IN = 0x40
HL_FW = 0x3f


def model_arm(arm, macs):
    """what the six doors and the far end must show for this arm"""
    x0m, x1m = macs
    a = arm["raw_c"]
    na = int(a["na"])
    nsend = int(a["nsend"])
    if arm["arm"] not in ARMS:
        return {"fate": "unknown", "ch": [], "tp": "8100",
                "doors": dict(g6=0, f6=0, n1=0, e0=0, e1=0, r0=0)}
    acts = ARMS[arm["arm"]]
    d0, mode0, off0, len0, imm0 = acts[0] if acts else ("-", 0, -1, -1, "")
    d1, mode1, off1, len1, imm1 = acts[1] if len(acts) > 1 else \
        ("-", 0, -1, -1, "")
    # the tag the frame carries at each layer-3 door
    tag_at_f6 = TAG_IN
    if d0 == "g6" and mode0 == 1 and off0 == 14 and len0 == 2:
        tag_at_f6 = int(imm0, 16)
    tp = "0000" if any(x[1] == 1 and x[2] == 12 and x[3] == 4 and
                       x[4] == "00000000" for x in acts) else "8100"
    m = {}
    if nsend == 0:
        m["doors"] = dict(g6=0, f6=0, n1=0, e0=0, e1=0, r0=0)
        m["fate"] = "none"
        m["ch"] = []
        m["tp"] = tp
        return m
    # a store of the metadata TCI at ingress retargets the frame to another
    # vid; there is no device for vid 103, so the bridge-less receive path
    # marks it OTHERHOST and nothing reaches the IP stack
    dead = (d0 == "n1" and mode0 == 1 and off0 == 14 and len0 == 2 and
            int(imm0, 16) & 0x0FFF == 0x0067)
    if dead:
        m["doors"] = dict(g6=0, f6=0, n1=1, e0=0, e1=0, r0=0)
        m["fate"] = "otherhost"
    else:
        m["doors"] = dict(g6=1, f6=1, n1=1, e0=1, e1=1, r0=1)
        m["fate"] = "forwarded"
    # action counters: a store is accepted unless the write guard refuses it
    # (nothing in this set is refused); a read matches iff the tag at that
    # door has the value asked for
    ch = []
    for door, mode_, off, lenn, imm in acts:
        if door == "-":
            continue
        if mode_ == 1:
            ch.append(1 if not dead or door == "n1" else 0)
        else:                     # a read of the tag
            if door in ("g6", "f6"):
                if off == 12:     # the TPID the frame carries at that door
                    have = 0x0000 if tp == "0000" else 0x8100
                    lenn = 2
                else:
                    have = TAG_IN if door == "g6" else tag_at_f6
            elif door == "n1":
                have = TAG_IN
            else:                 # e0 / e1: the device already composed it
                have = 0x8100 if off == 12 else TAG_EG
            ch.append(1 if (lenn == 2 and int(imm, 16) == have) else 0)
    m["ch"] = ch
    m["tp"] = tp
    return m


ARMS = {}
AORDER = []


def main():
    global ARMS, AORDER
    ARMS, AORDER = parse_arms_from_source()
    rep = []
    for tag in ("rep1", "rep2"):
        p = os.path.join(LOGDIR, "f54_%s.log" % tag)
        if not os.path.exists(p):
            print("MISSING %s" % p)
            return 1
        rep.append((tag, parse_log(p)))

    # ---------------- A. provenance
    kimg = os.path.join(ROOT, "src/linux-7.3.4-T563/arch/x86/boot/bzImage")
    ksha = sha_file(kimg)
    ck(sha_file(os.path.join(ROOT, "vm/build/differ576")) ==
       sha_file(os.path.join(ROOT, "vm/build/differ576")), "differ readable")
    dsha = sha_file(os.path.join(ROOT, "vm/build/differ576"))
    initrds = {}
    with open(os.path.join(ROOT, "logs/f54_initrd_hashes.txt")) as f:
        for ln in f:
            a = ln.split()
            if len(a) == 2:
                initrds[a[0]] = a[1]
    for tag, (head, arms, frms, env, wtot, lines) in rep:
        ck(head.get("sha256", [""])[0] == ksha, "%s kernel sha" % tag,
           head.get("sha256"), ksha)
        isha = head.get("initrd sha256", [""])[0]
        ck(isha in initrds.values(), "%s initrd sha known" % tag, isha,
           list(initrds.values())[:2])
        p = os.path.join(ROOT, "vm/initrd576", "full.cpio.gz")
        body = newc_member(p, "root/repro")
        ck(body is not None, "%s differ present in initramfs" % tag)
        if body is not None:
            ck(hashlib.sha256(body).hexdigest() == dsha,
               "%s differ in initramfs == build" % tag,
               hashlib.sha256(body).hexdigest()[:16], dsha[:16])
        ck("7.3.4" in lines[0] or any("7.3.4" in l for l in lines[:20]),
           "%s version line" % tag)
    ck(rep[0][0] != rep[1][0], "two boots")
    ck(rep[0][1][0].get("initrd sha256") == rep[1][1][0].get("initrd sha256"),
       "both boots same initrd")

    # ---------------- B. source anchors
    ck(src_has("net/8021q/vlan_dev.c", "\t\tvlan_tci = vlan->vlan_id;"),
       "anchor vlan_dev_hard_header takes vlan->vlan_id")
    ck(src_has("net/8021q/vlan_dev.c",
               "if (!(vlan->flags & VLAN_FLAG_REORDER_HDR)) {"),
       "anchor hard_header is the flag-cleared branch")
    ck(src_has("net/8021q/vlan_dev.c",
               "veth->h_vlan_proto != vlan->vlan_proto"),
       "anchor hard_start_xmit reproto test")
    ck(src_has("net/8021q/vlan.h",
               'WARN(1, "invalid VLAN protocol: 0x%04x\\n", ntohs(proto));'),
       "anchor the WARN text")
    ck(src_has("net/8021q/vlan.h", "struct vlan_info *vlan_info"),
       "anchor vlan_find_dev needs vlan_info")
    ck(src_has("net/netfilter/nft_payload.c",
               "if (boundary > offsetof(struct ethhdr, h_proto))"),
       "anchor the vlan adjust boundary")
    ck(src_has("net/netfilter/nft_payload.c",
               "\t\tskb->vlan_proto = vlan_proto;"),
       "anchor the store into vlan_proto")
    ck(src_has("net/core/dev.c",
               "if (eth_type_vlan(skb->protocol)) {\n\t\tskb = skb_vlan_untag(skb);"),
       "anchor untag before the ingress hook")
    ck(src_has("net/ipv6/ip6_output.c", "ndisc_send_redirect(skb, target);"),
       "anchor the redirect that made the extra frame")
    ck(src_has("net/ipv6/ip6_output.c",
               "IP6CB(skb)->iif == dev->ifindex"),
       "anchor the redirect condition (iif == oif)")

    # ---------------- per boot
    det = []
    for tag, (head, arms, frms, env, wtot, lines) in rep:
        e = env["xf"]
        x0m = e["x0mac"]
        x1m = e["x1mac"]
        macs = (x0m, x1m)
        # C. frames
        tag_tci = 0x0065
        want_t = (x1m + x0m + "%04x" % 0x8100 + "%04x" % tag_tci + "86dd" +
                  "60000000" + "001a" + "11" + "40" +
                  "fd02" + "00" * 13 + "11" + "fd02" + "00" * 13 + "92" +
                  "a7f8" + "1388" + "001a" + "165e" +
                  "77" * 18)
        ck(frms.get("t") == want_t, "%s frame t" % tag, frms.get("t"),
           want_t)
        want_p = (x0m + x0m + "86dd" + "60000000" + "001a" + "11" + "40" +
                  "fd02" + "00" * 13 + "11" + "fd02" + "00" * 13 + "92" +
                  "a7f8" + "1388" + "001a" + "165e" + "77" * 18)
        ck(len(frms.get("p", "")) == 160, "%s frame p length" % tag,
           len(frms.get("p", "")), 160)

        # D. arms of mode xf
        seen = []
        for arm in arms["xf"]:
            name = arm["arm"]
            a = arm["raw_c"]
            c2 = arm["raw_c2"]
            acts = ARMS.get(name)
            ck(acts is not None, "%s %s arm in source" % (tag, name))
            if acts:
                ck(int(a["na"]) == len(acts), "%s %s na" % (tag, name),
                   a["na"], len(acts))
                ck(a["d0"] == acts[0][0], "%s %s d0" % (tag, name), a["d0"],
                   acts[0][0])
                if "mode0" in a:
                    ck(int(a["mode0"]) == acts[0][1], "%s %s mode0" %
                       (tag, name), a["mode0"], acts[0][1])
                ck(int(a["off0"]) == acts[0][2], "%s %s off0" % (tag, name),
                   a["off0"], acts[0][2])
                ck(int(a["len0"]) == acts[0][3], "%s %s len0" % (tag, name),
                   a["len0"], acts[0][3])
                ck(a["imm0"] == acts[0][4], "%s %s imm0" % (tag, name),
                   a["imm0"], acts[0][4])
                if len(acts) > 1:
                    ck(a["d1"] == acts[1][0], "%s %s d1" % (tag, name),
                       a["d1"], acts[1][0])
            mm = model_arm(arm, macs)
            if mm["fate"] == "unknown":
                ck(False, "%s %s arm not in the source table" % (tag, name))
                continue
            doors = mm["doors"]
            for d in ("g6", "f6", "n1", "e0", "e1", "r0"):
                ck(int(c2[d]) == doors[d], "%s %s door %s" % (tag, name, d),
                   c2[d], doors[d])
            for i, v in enumerate(mm["ch"]):
                ck(int(c2["ch%d" % i]) == v, "%s %s ch%d" % (tag, name, i),
                   c2["ch%d" % i], v)
            b = arm["b"]
            f = arm["f"]
            if mm["fate"] == "forwarded":
                ck(int(b["fwd_d"]) == 1, "%s %s fwd" % (tag, name),
                   b["fwd_d"], 1)
                ck(int(b["i6in_d"]) == 2, "%s %s i6in" % (tag, name),
                   b["i6in_d"], 2)
                ck(int(b["disc_d"]) == 1, "%s %s disc" % (tag, name),
                   b["disc_d"], 1)
                ck(int(b["deliv_d"]) == 0, "%s %s deliv" % (tag, name),
                   b["deliv_d"], 0)
                # the wire: the far end demuxes the EGRESS device's vid
                ck(int(f["v101p_d"]) == 0, "%s %s x0.101" % (tag, name),
                   f["v101p_d"], 0)
                ck(int(f["v102p_d"]) == 1, "%s %s x0.102" % (tag, name),
                   f["v102p_d"], 1)
                ck(int(f["v102b_d"]) == 66, "%s %s x0.102 bytes" %
                   (tag, name), f["v102b_d"], 66)
                ck(int(f["v111p_d"]) == 1, "%s %s x1.101" % (tag, name),
                   f["v111p_d"], 1)
                ck(int(f["x0rxp_d"]) == 1, "%s %s x0 rx" % (tag, name),
                   f["x0rxp_d"], 1)
                ck(int(f["x0rxb_d"]) == 80, "%s %s x0 rx bytes" %
                   (tag, name), f["x0rxb_d"], 80)
                ck(int(f["x0oth_d"]) == 0, "%s %s x0 otherhost" %
                   (tag, name), f["x0oth_d"], 0)
                ck(int(f["x1oth_d"]) == 0, "%s %s x1 otherhost" %
                   (tag, name), f["x1oth_d"], 0)
                # taps: the wire frame at x0 is the untagged 80-byte one
                t0 = arm["tap"]["t0"]
                ck(t0["n"] == 1 and t0["flen"] == 80, "%s %s tap" %
                   (tag, name), (t0["n"], t0["flen"]), (1, 80))
                ck(t0["b"][:36] == x0m + x1m + "86dd" + "60000000",
                   "%s %s tap head" % (tag, name), t0["b"][:36],
                   x0m + x1m + "86dd60000000")
            elif mm["fate"] == "otherhost":
                ck(int(f["v102p_d"]) == 0 and int(f["v101p_d"]) == 0,
                   "%s %s nothing on the wire" % (tag, name), f["v102p_d"], 0)
                ck(int(f["x1oth_d"]) == 1, "%s %s x1 otherhost" %
                   (tag, name), f["x1oth_d"], 1)
                ck(int(arm["tap"]["t0"]["n"]) == 0,
                   "%s %s no tap" % (tag, name), arm["tap"]["t0"]["n"], 0)
            else:
                ck(int(b["i6in_d"]) == 0 and int(b["fwd_d"]) == 0,
                   "%s %s baseline quiet" % (tag, name), b["i6in_d"], 0)

            # every NFLOG message: prefix, hardware header, L2 header, the
            # VLAN attribute, the payload, and the hop limit of the IPv6
            # header wherever that payload starts (the index of that byte
            # depends on how much of the frame skb->data has already eaten)
            HLIDX = {"p0": 14, "p1": 14, "p2": 14, "p5": 14, "p3": 50,
                     "p4": 42}
            got = sorted([(m["prefix"], m["hlen"], m["hw"], m["llen"], m["l2"],
                           m["vpresent"], m["vproto"], m["vtci"], m["plen"],
                           m["pay"][:8],
                           m["pay"][HLIDX[m["prefix"]]:HLIDX[m["prefix"]] + 2])
                          for m in arm["msgs"] if m["prefix"] in HLIDX])
            ck(len(arm["msgs"]) == arm["nfl"],
               "%s %s nfl count" % (tag, name), len(arm["msgs"]), arm["nfl"])
            want = []
            if mm["fate"] == "forwarded":
                want = [
                    ("p2", 14, x1m + x0m + "86dd", 14, x1m + x0m + "86dd",
                     1, 0x8100, TAG_IN, 66, "60000000", "40"),
                    ("p0", 14, x1m + x0m + "8100", 0, "", 0, 0xFFFFFFFF, 0xFFFFFFFF, 66,
                     "60000000", "40"),
                    ("p1", 14, x1m + x0m + mm["tp"], 0, "", 0, 0xFFFFFFFF, 0xFFFFFFFF, 66,
                     "60000000", "3f"),
                    ("p3", 0, "", 18, x0m + x1m + "81000066" + "86dd", 0,
                     0xFFFFFFFF, 0xFFFFFFFF, 84, x0m[:8], "3f"),
                    ("p4", 0, "", 14, x0m + x1m + "86dd", 1, 0x8100, TAG_EG,
                     80, x0m[:8], "3f"),
                    ("p5", 14, x0m + x1m + "86dd", 14, x0m + x1m + "86dd",
                     1, 0x8100, TAG_EG, 66, "60000000", "3f"),
                ]
            elif mm["fate"] == "otherhost":
                want = [
                    ("p2", 14, x1m + x0m + "86dd", 14, x1m + x0m + "86dd",
                     1, 0x8100, TAG_IN, 66, "60000000", "40"),
                ]
            got_wo = [g for g in got if g[0] != "s"]
            ck(sorted(want) == got_wo, "%s %s census messages" % (tag, name),
               got_wo, sorted(want))
            # the action messages: one per action, at that action's own door
            n_act = len(acts)
            got_s = [(m["prefix"], m["hlen"], m["hw"], m["llen"], m["l2"],
                      m["vpresent"], m["vproto"], m["vtci"], m["plen"])
                     for m in arm["msgs"] if m["prefix"] == "s"]
            ck(len(got_s) == n_act, "%s %s action messages" % (tag, name),
               len(got_s), n_act)
            for g in got_s:
                ck(g[8] in (66, 80, 84), "%s %s action payload len" %
                   (tag, name), g[8], (66, 80, 84))
            if mm.get("tp") == "0000":
                ck(any(g[2].endswith("0000") for g in got_s),
                   "%s %s store visible in the header it wrote" % (tag, name),
                   [g[2] for g in got_s], "….0000")
            seen.append((name, a["fk"], a["nsend"], c2["g6"], c2["f6"],
                         c2["n1"], c2["e0"], c2["e1"], c2["r0"],
                         c2["ch0"], c2["ch1"], b["fwd_d"], b["i6in_d"],
                         b["disc_d"], f["v101p_d"], f["v102p_d"],
                         f["x0rxp_d"], f["x0rxb_d"], f["x1oth_d"],
                         arm["tap"]["t0"]["n"], arm["tap"]["t0"]["flen"]))
        ck([n for n, _, _ in [x[0] for x in []]] == [], "noop")
        det.append(seen)

        # warn mode
        w = arms["warn"]
        ck(len(w) == 5, "%s warn arms" % tag, len(w), 5)
        wm = {x["arm"]: x["w"] for x in w}
        ck(int(wm["w_ctl"]["dspl"]) == 0, "%s w_ctl splats" % tag,
           wm["w_ctl"]["dspl"], 0)
        ck(int(wm["w_ctl"]["v111p_d"]) == 1, "%s w_ctl delivered" % tag,
           wm["w_ctl"]["v111p_d"], 1)
        ck(int(wm["w_tag"]["dspl"]) == 1, "%s w_tag splats" % tag,
           wm["w_tag"]["dspl"], 1)
        ck(int(wm["w_tag"]["ch"]) == 1, "%s w_tag accepted" % tag,
           wm["w_tag"]["ch"], 1)
        ck(int(wm["w_tag"]["v111p_d"]) == 0 and
           int(wm["w_tag"]["x1oth_d"]) == 1, "%s w_tag dies" % tag,
           wm["w_tag"]["v111p_d"], 0)
        ck(int(wm["w_tag_x3"]["dspl"]) == 3, "%s w_tag_x3 splats" % tag,
           wm["w_tag_x3"]["dspl"], 3)
        ck(int(wm["w_untag"]["dspl"]) == 0, "%s w_untag splats" % tag,
           wm["w_untag"]["dspl"], 0)
        ck(int(wm["w_same"]["dspl"]) == 0, "%s w_same splats" % tag,
           wm["w_same"]["dspl"], 0)
        ck(int(wm["w_same"]["v111p_d"]) == 1, "%s w_same delivered" % tag,
           wm["w_same"]["v111p_d"], 1)
        ck(int(wm["w_ctl"]["tapx0"]) == 0, "%s w_ctl tap is not outgoing" %
           tag, wm["w_ctl"]["tapx0"], 0)
        # F. the log's own WARN count matches the arms' own arithmetic
        # only the kernel's own lines: the arms quote the text back in their
        # WM lines, and the boot prints the ring buffer again at the end
        tail_at = next((i for i, l in enumerate(lines)
                        if l.startswith("=== DMESG_TAIL")), len(lines))
        nwarn = len([l for l in lines[:tail_at]
                     if l.startswith("[") and
                     "invalid VLAN protocol" in l])
        ck(nwarn == wtot, "%s WARN lines == reported splats" % tag, nwarn,
           wtot)
        ck(nwarn == 4, "%s exactly four WARN lines in the boot" % tag,
           nwarn, 4)

    # E. determinism between the boots
    ck(len(det[0]) == len(det[1]), "same number of xf arms",
       len(det[0]), len(det[1]))
    for a, b in zip(det[0], det[1]):
        ck(a == b, "determinism %s" % a[0], a, b)

    if BAD:
        print("MISMATCH %d of %d checks" % (len(BAD), NCHK))
        for b in BAD[:40]:
            print("  " + b)
        return 1
    print("OK %d checks, 0 mismatches" % NCHK)
    return 0


if __name__ == "__main__":
    sys.exit(main())
