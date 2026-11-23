#!/usr/bin/env python3
"""verify577.py -- independent check of the F55 measurement (turn 577).

Reads logs/f55_rep{1,2}.log and re-derives every number the summary quotes.

The model is the source, not the instrument:

  vlan_dev_hard_header() writes  vlan->vlan_id | mask, where
  mask = vlan_dev_get_egress_qos_mask(dev, skb->priority): bucket
  `prio & 0xF`, full 32-bit equality, value already shifted (PCP << 13).
  The reader runs inside neigh_connected_output() -> dev_hard_header(),
  i.e. after the ip6 forward hook and before the device's egress hook.
  On receive vlan_do_receive() sets skb->priority from the INGRESS map
  keyed by the arriving PCP, after the netdev ingress hook and before
  ip6 prerouting.

So, for one arm, the priority at each door and the TCI on the wire are a
function of (frame PCP, the maps the kernel reports, the stores at doors).
The verifier computes them and compares against four independent witnesses:
the far end's NFULA_VLAN, the far end's rebuilt @ll read, the egress door's
L2 header bytes, and the AF_PACKET auxdata of the tap.

  A. provenance   -- kernel sha from each header against the file; initrd sha
                     in the header against logs/f55_initrd_hashes.txt; the
                     differ *extracted from the initramfs* against the binary.
  B. anchors      -- the source lines the model rests on.
  C. frames       -- the three frames rebuilt from the printed ENV MACs,
                     UDPv6 checksum recomputed.
  D. maps         -- every arm's QoS readback equals the design.
  E. arms         -- per arm: the priority at each door, the expected TCI, the
                     six door counts, both action counters, every IPv6/UDP
                     counter, the far end's demux, the tap and its auxdata, and
                     every NFLOG message with its header, VLAN attribute,
                     length and payload head.
  F. determinism  -- both boots, every line after normalising MACs.
  G. warnings     -- no splat, no BUG, no panic in either log.

Exit 0 with "OK <n> checks"; exit 1 with the first mismatches.
"""
import gzip
import hashlib
import os
import re
import struct
import sys

ROOT = "/work/kernel-sec"
LOGDIR = os.environ.get("F577_LOGDIR", os.path.join(ROOT, "logs"))
KDIR = os.path.join(ROOT, "src/linux-7.3.4-T563")
NCHK = 0
BAD = []

SRC = bytes([0xfd, 0x02] + [0] * 13 + [0x11])
D2 = bytes([0xfd, 0x02] + [0] * 13 + [0x92])
D3 = bytes([0xfd, 0x03] + [0] * 13 + [0x92])
SPORT = 43200
DPORT = 5000
PAY = b"\x77" * 18


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
    with gzip.open(path, "rb") as f:
        data = f.read()
    off = 0
    while off + 110 <= len(data):
        if data[off:off + 6] != b"070701":
            break

        def h(i):
            return int(data[off + 6 + 8 * i: off + 6 + 8 * (i + 1)], 16)

        filesize, namesize = h(6), h(11)
        name = data[off + 110: off + 110 + namesize - 1].decode()
        doff = off + 110 + namesize
        doff += (-doff) % 4
        body = data[doff: doff + filesize]
        if name.lstrip("./") == want.lstrip("./"):
            return body
        off = doff + filesize
        off += (-off) % 4
    return None


def src_has(path, needle):
    try:
        with open(os.path.join(KDIR, path), "r", errors="replace") as f:
            return needle in f.read()
    except OSError:
        return False


# ---------------- the model of vlan_dev_*_priority() ----------------

def eg_lookup(m, prio):
    """vlan_dev_get_egress_qos_mask(): the bucket is prio & 0xF, the match is
    the full 32-bit value, the returned word is (to << VLAN_PRIO_SHIFT)."""
    if not m:
        return 0
    bucket = prio & 0xF
    for k in m:
        if (k & 0xF) == bucket and k == prio:
            return (m[k] << 13) & 0xE000
    return 0


def in_lookup(m, pcp):
    """vlan_get_ingress_priority(): the ingress map is indexed by the PCP."""
    if not m:
        return 0
    return m.get(pcp, 0)


# ---------------- frames ----------------

def csum16(data, acc=0):
    if len(data) % 2:
        data = data + b"\x00"
    for i in range(0, len(data), 2):
        acc += (data[i] << 8) | data[i + 1]
        acc = (acc & 0xFFFF) + (acc >> 16)
    return acc


def udp6_csum(src, dst, udp_len, udp):
    acc = csum16(src + dst)
    acc += udp_len + 17
    acc = csum16(udp, acc)
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    c = (~acc) & 0xFFFF
    return c if c else 0xFFFF


def ip6_udp(dst, hlim=0x40):
    udp_len = 8 + len(PAY)
    udp = struct.pack(">HHHH", SPORT, DPORT, udp_len, 0) + PAY
    c = udp6_csum(SRC, dst, udp_len, udp)
    udp = struct.pack(">HHHH", SPORT, DPORT, udp_len, c) + PAY
    ip = struct.pack(">IHBB", 0x60000000, udp_len, 17, hlim) + SRC + dst
    return ip + udp


def build_tagged(dmac, smac, tci, dst):
    return (dmac + smac + b"\x81\x00" + struct.pack(">H", tci) + b"\x86\xdd"
            + ip6_udp(dst))


def build_plain(dmac, smac, dst, hlim=0x3F):
    return dmac + smac + b"\x86\xdd" + ip6_udp(dst, hlim)


# ---------------- log parsing ----------------

def parse_log(p):
    with open(p, "r", errors="replace") as f:
        text = f.read()
    lines = text.split("\n")
    head = {}
    for ln in lines[:12]:
        m = re.match(r"### (kernel|sha256|initrd|initrd sha256): (.*)$", ln)
        if m:
            head.setdefault(m.group(1), []).append(m.group(2).strip())
    env = {}
    frms = {}
    arms = []
    q = []
    cur = None
    mode = None
    for ln in lines:
        if ln.startswith("=== MODE_BEGIN "):
            mode = ln.split()[2]
            continue
        if not ln.startswith("F577 "):
            continue
        body = ln[5:]
        tag = body.split("|", 1)[0]
        rest = body.split("|", 1)[1] if "|" in body else ""
        kv = {}
        for part in rest.split("|"):
            if "=" in part:
                k, v = part.split("=", 1)
                kv[k] = v
        if tag == "ENV":
            env = kv
        elif tag == "SETTLE":
            env["settle"] = kv
        elif tag == "FRM":
            for k, v in kv.items():
                frms[k] = v
        elif tag == "Q":
            q.append(kv)
        elif tag == "A":
            cur = {"kv": kv, "q": q[-3:], "mode": mode}
            arms.append(cur)
        elif tag in ("C", "B", "F", "M", "T", "Q2"):
            if cur is not None:
                cur[tag] = kv
    return head, env, frms, arms, text


def parse_map(s):
    """'5:3,21:5' -> {5: 3, 21: 5}; '-' -> {}"""
    out = {}
    if s == "-" or not s:
        return out
    for part in s.split(","):
        f, t = part.split(":")
        out[int(f)] = int(t)
    return out


def maps_from_q(qlist):
    m = {}
    for kv in qlist:
        m[kv["dev"]] = {"eg": parse_map(kv.get("eg", "-")),
                        "in": parse_map(kv.get("in", "-"))}
    return m


def msgs(mline):
    """the M line -> list of dicts, split on ':' with 14 fields"""
    out = []
    n = int(mline["n"])
    for i in range(n):
        raw = mline.get("m%d" % i)
        if raw is None:
            break
        f = raw.split(":")
        if len(f) != 14:
            out.append({"bad": raw})
            continue
        out.append({
            "prefix": f[0], "indev": int(f[1]), "outdev": int(f[2]),
            "hwtype": int(f[3]), "hwlen": int(f[4]), "hlen": int(f[5]),
            "h": f[6], "llen": int(f[7]), "l": f[8],
            "vpresent": int(f[9]), "vproto": int(f[10], 16),
            "vtci": int(f[11], 16) if f[11] != "ffffffff" else -1,
            "plen": int(f[12]), "p": f[13],
        })
    return out


def main():
    logs = [os.path.join(LOGDIR, "f55_rep1.log"),
            os.path.join(LOGDIR, "f55_rep2.log")]
    for p0 in logs:
        if not os.path.isfile(p0):
            print("FAIL missing log %s" % p0)
            return 1
    parsed = []

    # ---------------- A. provenance ----------------
    kfile = os.path.join(KDIR, "arch/x86/boot/bzImage")
    ksha = sha_file(kfile)
    with open(os.path.join(ROOT, "logs/f55_initrd_hashes.txt")) as f:
        hashes = dict(ln.split() for ln in f if ln.strip())
    binp = os.path.join(ROOT, "vm/build/differ577")
    bsha = sha_file(binp)
    for p in logs:
        head, env, frms, arms, text = parse_log(p)
        base = os.path.basename(p)
        ck(kfile in head.get("kernel", []), "%s kernel path" % base,
           head.get("kernel"), kfile)
        ck(ksha in [x.lower() for x in head.get("sha256", [])],
           "%s kernel sha" % base, head.get("sha256"), ksha)
        ck(env.get("l0") == "84", "%s frame length" % base, env.get("l0"), 84)
        initrd = head.get("initrd", [None])[0]
        ck(initrd is not None and hashes.get("full") ==
           head.get("initrd sha256", [None])[0],
           "%s initrd sha vs hash file" % base,
           head.get("initrd sha256"), hashes.get("full"))
        if initrd:
            body = newc_member(initrd, "root/repro")
            ck(body is not None and hashlib.sha256(body).hexdigest() == bsha,
               "%s differ extracted from initramfs" % base,
               hashlib.sha256(body).hexdigest() if body else None, bsha)
        parsed.append((base, head, env, frms, arms, text))

    # ---------------- B. anchors ----------------
    anchors = [
        ("include/linux/if_vlan.h", "egress_priority_map[skprio & 0xF]"),
        ("include/linux/if_vlan.h", "mp->priority == skprio"),
        ("net/8021q/vlan_dev.c", "u32 bucket = skb_prio & 0xF;"),
        ("net/8021q/vlan_dev.c",
         "vlan_qos = (vlan_prio << VLAN_PRIO_SHIFT) & VLAN_PRIO_MASK;"),
        ("net/8021q/vlan_dev.c",
         "vlan_tci |= vlan_dev_get_egress_qos_mask(dev, skb->priority);"),
        ("net/8021q/vlan_dev.c", "vhdr = skb_push(skb, VLAN_HLEN);"),
        ("net/8021q/vlan_core.c",
         "skb->priority = vlan_get_ingress_priority(vlan_dev, skb->vlan_tci);"),
        ("net/netfilter/nft_meta.c", "skb->priority = value;"),
        ("net/core/neighbour.c",
         "err = dev_hard_header(skb, dev, ntohs(skb->protocol),"),
        ("net/packet/af_packet.c", "aux.tp_vlan_tci = skb_vlan_tag_get(skb);"),
        ("net/core/dev.c", "if (nf_ingress(skb, &pt_prev, &ret, orig_dev) < 0)"),
        ("net/core/dev.c", "\t\tif (vlan_do_receive(&skb))"),
    ]
    for path, needle in anchors:
        ck(src_has(path, needle), "anchor %s :: %r" % (path, needle[:40]))

    # the reader's position: nf_ingress before vlan_do_receive in dev.c
    try:
        with open(os.path.join(KDIR, "net/core/dev.c"), errors="replace") as f:
            dev = f.read()
        i_ing = dev.index("nf_ingress(skb, &pt_prev, &ret, orig_dev)")
        i_vdr = dev.index("if (vlan_do_receive(&skb))")
        ck(i_ing < i_vdr, "nf_ingress precedes vlan_do_receive", i_ing, i_vdr)
    except ValueError:
        ck(False, "dev.c order anchors found")

    # ---------------- per boot ----------------
    for base, head, env, frms, arms, text in parsed:
        mac0 = bytes.fromhex(env["x0mac"])
        mac1 = bytes.fromhex(env["x1mac"])
        idx = {"x0": int(env["x0"]), "x1": int(env["x1"]),
               "x1.101": int(env["d101"]), "x1.102": int(env["d102"]),
               "x1.103": int(env["d103"]), "x0.102": int(env["a102"]),
               "x0.103": int(env["a103"])}
        # C. frames
        ck(frms.get("f0") == build_tagged(mac1, mac0, 0x0065, D2).hex(),
           "%s frame f0" % base, frms.get("f0"))
        ck(frms.get("f3") == build_tagged(mac1, mac0, 0x6065, D2).hex(),
           "%s frame f3" % base, frms.get("f3"))
        ck(frms.get("fb") == build_tagged(mac1, mac0, 0x0065, D3).hex(),
           "%s frame fb" % base, frms.get("fb"))
        ck(env["settle"]["v6"] == "0" and env["settle"]["fwd"] == "1",
           "%s settle sysctls" % base, env["settle"])

        # D/E. arms
        for arm in arms:
            a = arm["kv"]
            name = a["arm"]
            c = arm.get("C", {})
            b = arm.get("B", {})
            f = arm.get("F", {})
            t = arm.get("T", {})
            m = arm.get("M", {})
            maps = maps_from_q(arm["q"])
            ck(len(maps) == 3, "%s %s three Q readbacks" % (base, name),
               sorted(maps), ["x1.101", "x1.102", "x1.103"])

            fk = a["fk"]
            frm = {"0": (0x0065, D2, 102, "f0"), "3": (0x6065, D2, 102, "f3"),
                   "B": (0x0065, D3, 103, "fb")}[fk]
            pcp_in = (frm[0] >> 13) & 7
            dst = frm[1]
            vid = frm[2]
            egdev = "x1.102" if vid == 102 else "x1.103"

            # the intents the design fixes (the instrument's own configuration)
            intents = {
                "n0": {}, "ctl": {egdev: {"eg": {5: 3}}},
                "rd_e0": {egdev: {"eg": {5: 3}}}, "p5_nomap": {},
                "p5_m3": {egdev: {"eg": {5: 3}}},
                "p15_m5": {egdev: {"eg": {5: 3}}},
                "p15_m15": {egdev: {"eg": {0x15: 5}}},
                "p5_m7": {egdev: {"eg": {5: 7}}},
                "p6_m3": {egdev: {"eg": {5: 3}}},
                "p5_e0": {egdev: {"eg": {5: 3}}},
                "p5_g6": {egdev: {"eg": {5: 3}}},
                "p5_rm": {}, "ctl_b": {"x1.103": {"eg": {5: 6}}},
                "p5_b": {"x1.102": {"eg": {5: 3}},
                         "x1.103": {"eg": {5: 6}}},
                "ing3_prio": {"x1.101": {"in": {3: 5}}},
                "ing_n1_g6": {"x1.101": {"in": {3: 5}}},
                "ing3_e": {"x1.101": {"in": {3: 5}},
                           "x1.102": {"eg": {5: 7}}},
                "ing0_e": {"x1.101": {"in": {3: 5}},
                           "x1.102": {"eg": {5: 7}}},
                "rd_f6": {}, "rd_r0": {egdev: {"eg": {5: 3}}},
            }
            intent = intents.get(name)
            ck(intent is not None, "%s %s known arm name" % (base, name),
               name, sorted(intents))
            if intent is None:
                intent = {}
            for dev in ("x1.101", "x1.102", "x1.103"):
                want = intent.get(dev, {"eg": {}, "in": {}})
                got = maps[dev]
                ck(got["eg"] == want.get("eg", {}),
                   "%s %s map eg %s" % (base, name, dev), got["eg"],
                   want.get("eg", {}))
                ck(got["in"] == want.get("in", {}),
                   "%s %s map in %s" % (base, name, dev), got["in"],
                   want.get("in", {}))

            # the model
            acts = []
            for i in (0, 1):
                door = a["a%d" % i]
                if door == "-":
                    continue
                reads = []
                for suf in ("a", "b"):
                    off = int(a["r%d%s" % (i, suf)].split(":")[0])
                    ln = int(a["r%d%s" % (i, suf)].split(":")[1])
                    imm = a["r%d%s" % (i, suf)].split(":")[2]
                    if off >= 0:
                        reads.append((off, ln, imm))
                acts.append({"door": door, "set": int(a["set%d" % i]),
                             "cmp": int(a["cmp%d" % i]), "reads": reads})

            ing = in_lookup(maps["x1.101"]["in"], pcp_in)
            prio = {"n1": 0, "g6": ing}
            p = ing
            for door in ("g6", "f6"):
                for act in acts:
                    if act["door"] == door and act["set"]:
                        p = act["set"]
                prio[door] = p
            p_header = p
            tci = vid | eg_lookup(maps[egdev]["eg"], p_header)
            pe = p
            for act in acts:
                if act["door"] in ("e0", "e3") and act["set"]:
                    pe = act["set"]
            prio["e0"] = p
            prio["e3"] = p
            # bytes at each door for @ll reads
            tagged = {"n1": 0x0065 if pcp_in == 0 else 0x6065,
                      "g6": 0x0065 if pcp_in == 0 else 0x6065,
                      "f6": 0x0065 if pcp_in == 0 else 0x6065,
                      "e0": tci, "e3": tci, "r0": tci}
            llbytes = {}
            for door in ("n1", "g6", "f6", "e0", "e3", "r0"):
                llbytes[door] = {12: "8100",
                                 14: "%04x" % tagged[door]}

            exp_ch = []
            for act in acts:
                ok = 1
                if act["cmp"] and act["cmp"] != prio.get(act["door"], 0):
                    ok = 0
                for off, ln, imm in act["reads"]:
                    if llbytes.get(act["door"], {}).get(off) != imm:
                        ok = 0
                exp_ch.append(ok)

            # ---- assertions ----
            if a["a0"] != "-":
                ck(a["rc0"] == "0", "%s %s rc0 accepted" % (base, name),
                   a["rc0"], 0)
            ck(a.get("rc1", "-99") in ("0", "-99"),
               "%s %s rc1 accepted" % (base, name), a.get("rc1"), 0)
            if name != "n0":
                ck(int(a["snt"]) == 1, "%s %s sent" % (base, name),
                   a["snt"], 1)
                for k2, want in (("f6", 1), ("g6", 1), ("n1", 1), ("r0", 1)):
                    ck(c[k2] == str(want), "%s %s door %s" % (base, name, k2),
                       c[k2], want)
                ck(c["e0"] == ("1" if vid == 102 else "0"),
                   "%s %s door e0" % (base, name), c["e0"],
                   1 if vid == 102 else 0)
                ck(c["e3"] == ("1" if vid == 103 else "0"),
                   "%s %s door e3" % (base, name), c["e3"],
                   1 if vid == 103 else 0)
                ck(b["i6in_d"] == "2", "%s %s i6in" % (base, name),
                   b["i6in_d"], 2)
                ck(b["disc_d"] == "1", "%s %s disc" % (base, name),
                   b["disc_d"], 1)
                ck(b["fwd_d"] == "1", "%s %s fwd" % (base, name),
                   b["fwd_d"], 1)
                for k2 in ("deliv_d", "hdr_d", "nor_d", "addr_d", "unk_d",
                           "trunc_d", "mcast_d", "u6in_d", "u6err_d",
                           "u6nop_d"):
                    ck(b[k2] == "0", "%s %s %s" % (base, name, k2), b[k2], 0)
                ck(f["v102_d"] == ("1" if vid == 102 else "0"),
                   "%s %s demux 102" % (base, name), f["v102_d"])
                ck(f["v103_d"] == ("1" if vid == 103 else "0"),
                   "%s %s demux 103" % (base, name), f["v103_d"])
                ck(f["v101_d"] == "0", "%s %s demux 101" % (base, name),
                   f["v101_d"], 0)
                ck(f["x0rxp_d"] == "1" and f["x0rxb_d"] == "80",
                   "%s %s far end wire bytes" % (base, name),
                   (f["x0rxp_d"], f["x0rxb_d"]), ("1", "80"))
                ck(f["b101_d"] == "1" and f["b101b_d"] == "66",
                   "%s %s ingress device rx" % (base, name),
                   (f["b101_d"], f["b101b_d"]), ("1", "66"))
                ck(f["b102_d"] == "0" and f["b103_d"] == "0",
                   "%s %s box vlan devices do not receive" % (base, name),
                   (f["b102_d"], f["b103_d"]), ("0", "0"))
                # the tap: bytes and auxdata
                ck(t.get("auxn") == "1", "%s %s auxdata present" % (base, name),
                   t.get("auxn"), 1)
                ck(int(t.get("atci", "-1")) == tci,
                   "%s %s auxdata tci" % (base, name), t.get("atci"),
                   "%04x" % tci)
                ck(int(t.get("atpid", "-1")) == 0x8100,
                   "%s %s auxdata tpid" % (base, name), t.get("atpid"), 0x8100)
                st = int(t.get("astat", "0"))
                ck(st & 1 and st & 0x10 and st & 0x40,
                   "%s %s aux status bits" % (base, name), st)
                t0 = t.get("t0", "")
                ck(t0.startswith("x0:1:80:"), "%s %s tap count/len" %
                   (base, name), t0[:12])
                tb = t0.split(":")[3] if t0.count(":") >= 3 else ""
                want_b = build_plain(mac0, mac1, dst).hex()
                ck(tb == want_b, "%s %s tap bytes" % (base, name), tb,
                   want_b)
            else:
                ck(c["f6"] == "0" and c["g6"] == "0" and c["e0"] == "0" and
                   c["e3"] == "0" and c["r0"] == "0" and c["n1"] == "0",
                   "%s n0 no doors" % base, c)
                ck(b["i6in_d"] == "0" and b["fwd_d"] == "0",
                   "%s n0 quiet" % base, b)

            # the action counters
            for i, want in enumerate(exp_ch):
                got = c["ch%d" % i]
                ck(got == str(want), "%s %s ch%d" % (base, name, i), got, want)

            # the NFLOG messages
            ms = msgs(m)
            nwire = len(ms)
            nwant = 5 + sum(exp_ch)
            if name == "n0":
                nwant = 0
            ck(nwire == nwant, "%s %s nflog messages" % (base, name), nwire,
               nwant)
            bypref = {}
            for mm in ms:
                if "bad" in mm:
                    ck(False, "%s %s bad M field" % (base, name), mm)
                    continue
                bypref.setdefault(mm["prefix"], []).append(mm)
            if name != "n0":
                n1 = bypref.get("p4", [])
                ck(len(n1) == 1, "%s %s msg n1" % (base, name), len(n1), 1)
                if n1:
                    mm = n1[0]
                    ck(mm["indev"] == idx["x1"], "%s %s n1 indev" %
                       (base, name), mm["indev"], idx["x1"])
                    ck(mm["hlen"] == 14 and mm["llen"] == 14,
                       "%s %s n1 header lengths" % (base, name),
                       (mm["hlen"], mm["llen"]), (14, 14))
                    ck(mm["h"] == (mac1 + mac0 + b"\x86\xdd").hex(),
                       "%s %s n1 hardware header" % (base, name), mm["h"],
                       (mac1 + mac0 + b"\x86\xdd").hex())
                    ck(mm["vpresent"] == 1 and mm["vproto"] == 0x8100 and
                       mm["vtci"] == tagged["n1"],
                       "%s %s n1 vlan attr" % (base, name),
                       (mm["vpresent"], hex(mm["vproto"]), hex(mm["vtci"])),
                       (1, hex(0x8100), hex(tagged["n1"])))
                    ck(mm["plen"] == 66 and mm["p"][:40] ==
                       ip6_udp(dst, 0x40)[:20].hex(),
                       "%s %s n1 payload" % (base, name), mm["p"][:16])
                for pref, door, hlim in (("p1", "g6", 0x40),
                                         ("p0", "f6", 0x3F)):
                    mm_l = bypref.get(pref, [])
                    ck(len(mm_l) == 1, "%s %s msg %s" % (base, name, pref),
                       len(mm_l), 1)
                    if mm_l:
                        mm = mm_l[0]
                        ck(mm["indev"] == idx["x1.101"],
                           "%s %s %s indev" % (base, name, pref), mm["indev"],
                           idx["x1.101"])
                        ck(mm["hlen"] == 14 and mm["llen"] == 0,
                           "%s %s %s header lengths" % (base, name, pref),
                           (mm["hlen"], mm["llen"]), (14, 0))
                        ck(mm["h"] == (mac1 + mac0 + b"\x81\x00").hex(),
                           "%s %s %s hardware header" % (base, name, pref),
                           mm["h"])
                        ck(mm["plen"] == 66 and
                           mm["p"][:40] == ip6_udp(dst, hlim)[:20].hex(),
                           "%s %s %s payload" % (base, name, pref),
                           mm["p"][:16])
                # egress door
                pref = "p2" if vid == 102 else "p3"
                mm_l = bypref.get(pref, [])
                ck(len(mm_l) == 1, "%s %s msg %s" % (base, name, pref),
                   len(mm_l), 1)
                if mm_l:
                    mm = mm_l[0]
                    ck(mm["outdev"] == idx[egdev],
                       "%s %s %s outdev" % (base, name, pref), mm["outdev"],
                       idx[egdev])
                    ck(mm["hlen"] == 0 and mm["llen"] == 18,
                       "%s %s %s header lengths" % (base, name, pref),
                       (mm["hlen"], mm["llen"]), (0, 18))
                    want_l2 = (mac0 + mac1 + b"\x81\x00" +
                               struct.pack(">H", tci) + b"\x86\xdd").hex()
                    ck(mm["l"] == want_l2,
                       "%s %s %s L2 header" % (base, name, pref), mm["l"],
                       want_l2)
                    ck(mm["plen"] == 84 and mm["p"][:40] ==
                       (want_l2 + ip6_udp(dst, 0x3F).hex())[:40],
                       "%s %s %s payload head" % (base, name, pref),
                       mm["p"][:20])
                # the far end
                mm_l = bypref.get("p5", [])
                ck(len(mm_l) == 1, "%s %s msg r0" % (base, name), len(mm_l), 1)
                if mm_l:
                    mm = mm_l[0]
                    ck(mm["indev"] == idx["x0"], "%s %s r0 indev" %
                       (base, name), mm["indev"], idx["x0"])
                    ck(mm["vpresent"] == 1 and mm["vproto"] == 0x8100 and
                       mm["vtci"] == tci,
                       "%s %s r0 vlan attr" % (base, name),
                       (mm["vpresent"], hex(mm["vproto"]), hex(mm["vtci"])),
                       (1, hex(0x8100), "%04x" % tci))
                    ck(mm["h"] == (mac0 + mac1 + b"\x86\xdd").hex(),
                       "%s %s r0 hardware header" % (base, name), mm["h"])
                    ck(mm["plen"] == 66 and mm["p"][:40] ==
                       ip6_udp(dst, 0x3F)[:20].hex(),
                       "%s %s r0 payload" % (base, name), mm["p"][:16])
                # every matched action logged once with prefix s
                nswant = sum(exp_ch)
                ck(len(bypref.get("s", [])) == nswant,
                   "%s %s s messages" % (base, name),
                   len(bypref.get("s", [])), nswant)

    # ---------------- F. determinism ----------------
    a1 = [ln for ln in parsed[0][5].split("\n") if ln.startswith("F577 ")]
    a2 = [ln for ln in parsed[1][5].split("\n") if ln.startswith("F577 ")]
    norm1 = [re.sub(r"[0-9a-f]{12}", "MAC", ln) for ln in a1]
    norm2 = [re.sub(r"[0-9a-f]{12}", "MAC", ln) for ln in a2]
    ck(len(norm1) == len(norm2) and norm1 == norm2,
       "determinism: both boots line-identical after MAC normalisation",
       len(norm1), len(norm2))

    # ---------------- G. warnings ----------------
    for base, head, env, frms, arms, text in parsed:
        for bad in ("WARNING:", "BUG:", "Oops", "kernel panic",
                    "Call Trace"):
            ck(bad not in text, "%s no %r" % (base, bad))

    if BAD:
        print("FAIL %d/%d" % (len(BAD), NCHK))
        for b in BAD[:40]:
            print("  " + b)
        return 1
    print("OK %d checks, 0 mismatches" % NCHK)
    return 0


if __name__ == "__main__":
    sys.exit(main())
