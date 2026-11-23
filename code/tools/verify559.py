#!/usr/bin/env python3
"""verify559.py -- independent checks over the turn-559 logs (F37).

Nothing here trusts the instrument's own lines.  Two models are written down
once, from the source, and every captured frame is compared to them byte for
byte:

  wire  the frame the egress driver is handed, i.e. after validate_xmit_vlan():
        the skb frame (the tag is NOT in it -- it is metadata) with the tag
        re-inserted at 12..15 IF the tag is present AND the egress device
        cannot offload this vlan_proto for a tag that the device was asked to
        offload.  `vlan_hw_offload_capable()` is true only for 0x8100/CTAG_TX
        and 0x8021ad/STAG_TX.
  far   the frame at the peer's receive tap, i.e. after skb_vlan_untag(): the
        wire frame with the 4 tag bytes removed IF its ethertype is 0x8100,
        otherwise the wire frame itself.

The store model is the operator's own reading of `@ll,off,len`: with the tag
present the write lands on frame byte `off` (nft subtracts vlan_hlen from the
skb offset, and the xmit path adds it back).

Run: python3 tools/verify559.py [--logs rep1,rep2] [--logdir DIR]
"""
import gzip
import hashlib
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
TREE = "src/linux-7.3.4-T558"
OFFS = [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24]
LENS = [1, 2, 4]
CELLS = [(o, l) for o in OFFS for l in LENS]
TAG = bytes([0x81, 0x00, 0x00, 0x64])
MACS = bytes([0xff] * 6) + bytes([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x66])

CHECKS = []
LOGDIR = os.path.join(ROOT, "logs")


def chk(name, ok, detail=""):
    CHECKS.append({"name": name, "ok": bool(ok), "detail": str(detail)[:400]})
    return ok


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def cpio_member(path, want):
    """Extract one member of a newc cpio.gz by name, padding-aware."""
    data = gzip.open(path, "rb").read()
    i = 0
    while i + 110 <= len(data):
        hdr = data[i:i + 110]
        if hdr[:6] != b"070701":
            break
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        nameoff = i + 110
        name = data[nameoff:nameoff + namesize - 1].decode("latin-1")
        doff = nameoff + namesize
        doff = (doff + 3) & ~3
        body = data[doff:doff + filesize]
        if name == want or name.endswith("/" + want):
            return body
        i = (doff + filesize + 3) & ~3
    return None


# ---------------------------------------------------------------- the frames

def csum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) | data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mk_ip4(proto=17, ttl=64, ihl4=5):
    """f556_mk_ip4(): ethernet + IPv4(ihl4, proto) + UDP/8 + 18 x 0x77."""
    hl = ihl4 * 4
    tot = hl + 8 + 18
    ip = bytearray(hl)
    ip[0] = 0x40 | ihl4
    ip[2] = tot >> 8
    ip[3] = tot & 0xFF
    ip[4] = 0x12
    ip[5] = 0x34
    ip[8] = ttl
    ip[9] = proto
    ip[12:16] = bytes([10, 1, 0, 1])
    ip[16:20] = bytes([10, 9, 0, 7])
    c = csum(ip)
    ip[10] = c >> 8
    ip[11] = c & 0xFF
    u = bytearray([0x9C, 0x40, 0x13, 0x88, 0x00, 26, 0x00, 0x00]) + b"\x77" * 18
    return bytes(MACS) + b"\x08\x00" + bytes(ip) + bytes(u)


PLAIN = mk_ip4()
TCPP = mk_ip4(proto=6)
TAGGED = PLAIN[:12] + TAG + PLAIN[12:]
TCPTAG = TCPP[:12] + TAG + TCPP[12:]
DATALEN = len(PLAIN) - 14            # 46: skb->len at the bridge hook


def untag(w):
    return w[:12] + w[16:]


def wire_model(state, arm, tagged=True, proto=17):
    """the frame the egress driver gets, from the source, one byte at a time."""
    fr = mk_ip4(proto=proto)
    skb = bytearray(fr)
    vproto, tci = 0x8100, 0x0064
    present = tagged
    st = ARMS.get(arm)
    if st is not None and tagged:
        off, ln, imm = st
        if off >= 16:
            skb[off - 4:off - 4 + ln] = imm      # vlan_hlen subtracted by nft
        elif (off, ln) == (12, 2):
            vproto = (imm[0] << 8) | imm[1]       # skb->vlan_proto
        elif (off, ln) == (12, 4):
            vproto = (imm[0] << 8) | imm[1]       # __vlan_hwaccel_put_tag
            tci = (imm[2] << 8) | imm[3]
        elif (off, ln) == (14, 2):
            tci = (imm[0] << 8) | imm[1]          # skb->vlan_tci
        else:
            raise SystemExit("no model for store %r" % (st,))
    elif st is not None and not tagged:
        off, ln, imm = st
        # no tag -> nft_ll_write_ok(): off + len <= 14
        if off + ln <= 14:                        # 12/2, 12/4, 14/2 are handled
            pass                                  # by nft_payload_set_vlan, no tag
    present = present and (vproto != 0 or tci != 0)
    if not present:
        return bytes(skb)
    offloadable = (vproto == 0x8100 and state != "clear")
    if offloadable:
        return bytes(skb)                         # the tag stays in metadata
    return bytes(skb[:12]) + bytes([vproto >> 8, vproto & 0xFF,
                                    tci >> 8, tci & 0xFF]) + bytes(skb[12:])


def far_model(w):
    if w[12:14] == b"\x81\x00":
        return untag(w)
    return w


# the eight arms of the wire table: (off, len, immediate)
ARMS = {
    "s16_2": (16, 2, bytes([0x08, 0x06])),
    "s14_99": (14, 2, bytes([0x00, 0x99])),
    "s14_0": (14, 2, bytes([0x00, 0x00])),
    "s12_2z": (12, 2, bytes([0x00, 0x00])),
    "s12_4z": (12, 4, bytes([0x81, 0x00, 0x00, 0x00])),
    "s16_2_plain": (16, 2, bytes([0x08, 0x06])),
}


def grid_live(proto, off, ln):
    """two refusals, both from the source, neither about the envelope:
     * nft_th_write_ok(): for TCP a write covering transport byte 12 is refused
       (doff = offsetof(struct tcphdr, ack_seq) + 4 = 12);
     * skb_ensure_writable(offset + len) with offset = thoff + off: the
       datagram is 46 bytes, so 20 + off + len > 46 cannot be written."""
    if proto == 6 and off <= 12 < off + ln:
        return False
    if 20 + off + ln > DATALEN:
        return False
    return True


# ---------------------------------------------------------------- parsing

def fields(line):
    out = {}
    for tok in line.split("|")[1:]:
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k] = v
    return out


def parse(path):
    lines = [x.rstrip("\r") for x in
             open(path, "rb").read().decode("latin-1").split("\n")]
    d = {"run": {}, "c": {}, "feat": [], "set": [], "sect": [], "probe": [],
         "kern": [], "initrd": [], "mode_exit": [], "splat": 0}
    for ln in lines:
        if ln.startswith("F559 R|"):
            f = fields(ln)
            d["run"][(f.get("state"), f.get("env"), f.get("arm"))] = f
        elif ln.startswith("F559 C|"):
            f = fields(ln)
            d["c"][f.get("arm")] = f
        elif ln.startswith("F559 FEAT|"):
            d["feat"].append(fields(ln))
        elif ln.startswith("F559 SET|"):
            d["set"].append(fields(ln))
        elif ln.startswith("F559 SECTION|"):
            d["sect"].append(fields(ln))
        elif ln.startswith("F559 PROBE|"):
            d["probe"].append(fields(ln))
        elif ln.startswith("### kernel: "):
            d["kern"].append(ln.split(": ", 1)[1].strip())
        elif ln.startswith("### initrd: "):
            d["initrd"].append(ln.split(": ", 1)[1].strip())
        elif ln.startswith("=== MODE_EXIT"):
            d["mode_exit"].append(ln.strip())
        elif re.search(r"KASAN|BUG:|WARNING:|Oops|general protection|"
                       r"double free|use-after-free|segfault", ln):
            d["splat"] += 1
    d["mode_exit"] = [x for x in d["mode_exit"] if "f559=0" in x]
    return d


def hexs(f):
    v = f.get("whex", "-")
    if v in ("-", ""):
        return b""
    try:
        return bytes.fromhex(v)
    except ValueError:
        return b""


def rhexs(f):
    v = f.get("rhex", "-")
    if v in ("-", ""):
        return b""
    try:
        return bytes.fromhex(v)
    except ValueError:
        return b""


def main():
    global LOGDIR
    args = sys.argv[1:]
    logs = ["rep1", "rep2"]
    while args:
        a = args.pop(0)
        if a == "--logs":
            logs = args.pop(0).split(",")
        elif a == "--logdir":
            LOGDIR = args.pop(0)
    parsed = {}
    for tag in logs:
        p = os.path.join(LOGDIR, "f37_%s.log" % tag)
        chk("log exists: %s" % tag, os.path.exists(p), p)
        if os.path.exists(p):
            parsed[tag] = parse(p)
    if not parsed:
        print("SUMMARY|checks=%d|passed=0|failed=%d" % (len(CHECKS), len(CHECKS)))
        return 1
    A = parsed[logs[0]]

    # ---------- provenance ----------
    for tag, d in parsed.items():
        chk("%s: one kernel line" % tag, len(d["kern"]) == 1, d["kern"])
        if d["kern"]:
            kp = d["kern"][0]
            chk("%s: kernel on disk" % tag, os.path.exists(os.path.join(ROOT, kp)), kp)
            if os.path.exists(os.path.join(ROOT, kp)):
                want = sha256(os.path.join(ROOT, kp))
                chk("%s: kernel sha256 == file on disk" % tag,
                    want in open(os.path.join(LOGDIR, "f37_%s.log" % tag),
                                 "rb").read().decode("latin-1"), want)
        chk("%s: mode exit 0" % tag, len(d["mode_exit"]) == 1, d["mode_exit"])
        chk("%s: 0 splats" % tag, d["splat"] == 0, d["splat"])
        # the differ inside the initrd is the one that was built
        if d["initrd"]:
            ip = d["initrd"][0]
            chk("%s: initrd on disk" % tag, os.path.exists(ip), ip)
            if os.path.exists(ip):
                body = cpio_member(ip, "repro")
                chk("%s: differ in initrd == vm/build/differ559" % tag,
                    body is not None and hashlib.sha256(body).hexdigest() ==
                    sha256(os.path.join(ROOT, "vm/build/differ559")),
                    (len(body) if body else None))

    # ---------- the kernel is the same tree that F36 measured ----------
    npayload = os.path.join(ROOT, TREE, "net/netfilter/nft_payload.c")
    txt = open(npayload, encoding="latin-1").read()
    chk("nft_payload.c carries nft_th_write_ok",
        "nft_th_write_ok" in txt, "")
    chk("doff is ack_seq + 4",
        "offsetof(struct tcphdr, ack_seq) + sizeof(__be32)" in txt, "")
    chk("ll guard is ingress-or-boundary",
        "if (nft_in_ingress(pkt->state))" in txt, "")
    chk("set_vlan takes off 12/14 and subtracts VLAN_HLEN above 16",
        "offsetof(struct vlan_ethhdr, h_vlan_TCI)" in txt and
        "*vlan_hlen = VLAN_HLEN" in txt, "")
    chk("validate_xmit_vlan inserts when the device cannot offload",
        "__vlan_hwaccel_push_inside" in open(
            os.path.join(ROOT, TREE, "net/core/dev.c"), encoding="latin-1").read(), "")
    chk("vlan_hw_offload_capable is 0x8100/CTAG_TX only",
        "proto == htons(ETH_P_8021Q) && features & NETIF_F_HW_VLAN_CTAG_TX"
        in open(os.path.join(ROOT, TREE, "include/linux/if_vlan.h"),
                encoding="latin-1").read(), "")

    # ---------- the feature bit, derived from the enum ----------
    nfh = open(os.path.join(ROOT, TREE, "include/linux/netdev_features.h"),
               encoding="latin-1").read()
    body = nfh.split("enum {", 1)[1].split("NETDEV_FEATURE_COUNT", 1)[0]
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S).replace("/**/", "")
    entries = [x.strip() for x in body.split(",") if x.strip()]
    # the enum's own rule: an entry that aliases an earlier one does NOT take a
    # new bit (NETIF_F_TSO_BIT = NETIF_F_GSO_SHIFT, NETIF_F_GSO_LAST = ..._ACCECN_BIT)
    bitpos, nbits = {}, 0
    for e in entries:
        name = e.split("=")[0].strip()
        if "=" in e:
            rhs = e.split("=", 1)[1].strip()
            if not rhs.isdigit():
                bitpos[name] = bitpos.get(rhs)
                continue
        bitpos[name] = nbits
        nbits += 1
    txbit = bitpos["NETIF_F_HW_VLAN_CTAG_TX_BIT"]
    rxbit = bitpos["NETIF_F_HW_VLAN_CTAG_RX_BIT"]
    nwords = (nbits + 31) // 32
    chk("enum: HW_VLAN_CTAG_TX is bit 7", txbit == 7, txbit)
    chk("enum: HW_VLAN_CTAG_RX is bit 8", rxbit == 8, rxbit)
    chk("enum: ETHTOOL_DEV_FEATURE_WORDS = ceil(%d/32) = %d" % (nbits, nwords),
        nwords == 2, (nbits, nwords))
    for f in A["feat"]:
        chk("FEAT %s/%s: nwords == %d" % (f.get("stage"), f.get("dev"), nwords),
            f.get("nwords") == str(nwords), f.get("nwords"))
        chk("FEAT %s/%s: rc=0" % (f.get("stage"), f.get("dev")),
            f.get("rc") == "0", f.get("rc"))
    # veth advertises the TX bit and, at init, has it active
    for dev in ("i0", "i1", "s0", "s1", "r0", "r1"):
        f = [x for x in A["feat"] if x.get("stage") == "init" and x.get("dev") == dev]
        chk("init %s: avail_tx=1 act_tx=1 act_rx=1" % dev,
            f and f[0].get("avail_tx") == "1" and f[0].get("act_tx") == "1"
            and f[0].get("act_rx") == "1", f)

    # ---------- the causal link: bit -> bytes -> bit ----------
    sets = {s.get("stage"): s for s in A["set"]}
    for stage, want in (("clear", "0"), ("restore", "1"), ("clear2", "0")):
        s = sets.get(stage)
        chk("SET %s: accepted (rc=0, no F_UNSUPPORTED, no F_WISH)" % stage,
            s and s.get("rc") == "0" and s.get("f_unsup") == "0"
            and s.get("f_wish") == "0", s)
        f = [x for x in A["feat"] if x.get("stage") == stage and x.get("dev") == "r1"]
        chk("SET %s: r1 act_tx == %s afterwards" % (stage, want),
            f and f[0].get("act_tx") == want, f)

    # ---------- the wire table: 8 arms x 3 states, byte for byte ----------
    for state in ("on", "clear", "restored"):
        for arm in ("ctl", "s16_2", "s14_99", "s14_0", "s12_2z", "s12_4z"):
            f = A["run"].get((state, "wire", arm))
            if not chk("wire %s/%s present" % (state, arm), f is not None, ""):
                continue
            w = hexs(f)
            m = wire_model(state, arm, True)
            chk("wire %s/%s: bytes == model (%d)" % (state, arm, len(m)),
                w == m, "got %s want %s" % (w.hex(), m.hex()))
            far = rhexs(f)
            fm = far_model(m)
            chk("wire %s/%s: far tap == untag(wire)" % (state, arm),
                far == fm, "got %s want %s" % (far.hex(), fm.hex()))
            chk("wire %s/%s: len(far)=%d" % (state, arm, len(fm)),
                f.get("rn") == str(len(fm)), f.get("rn"))
        for arm in ("ctl_plain", "s16_2_plain"):
            f = A["run"].get((state, "wire", arm))
            if not chk("wire %s/%s present" % (state, arm), f is not None, ""):
                continue
            w = hexs(f)
            m = wire_model(state, arm, False)
            chk("wire %s/%s: bytes == model (%d)" % (state, arm, len(m)),
                w == m, "got %s want %s" % (w.hex(), m.hex()))
    # the three states differ only through the bit
    on_w = hexs(A["run"].get(("on", "wire", "ctl"), {}))
    cl_w = hexs(A["run"].get(("clear", "wire", "ctl"), {}))
    rs_w = hexs(A["run"].get(("restored", "wire", "ctl"), {}))
    chk("ctl: offload on -> 60 bytes, no tag", len(on_w) == 60 and on_w[12:14] == b"\x08\x00",
        on_w.hex())
    chk("ctl: offload cleared -> 64 bytes, tag at 12..15",
        len(cl_w) == 64 and cl_w[12:16] == TAG, cl_w.hex())
    chk("ctl: restored -> back to 60 bytes", rs_w == on_w, rs_w.hex())
    chk("tagged frame sent == plain frame with 4 bytes inserted",
        len(TAGGED) == 64 and TAGGED[:12] == PLAIN[:12] and TAGGED[16:] == PLAIN[12:], "")
    chk("frame's own IP checksum is valid", csum(PLAIN[14:34]) == 0,
        hex(csum(PLAIN[14:34])))

    # live/dead per arm and the verdict oracle
    for state in ("on", "clear", "restored"):
        for arm in ("s16_2", "s14_99", "s14_0", "s12_2z", "s12_4z"):
            f = A["run"].get((state, "wire", arm), {})
            chk("wire %s/%s: the store ran (live=1)" % (state, arm),
                f.get("live") == "1", f.get("live"))
        f = A["run"].get((state, "wire", "s16_2_plain"), {})
        chk("wire %s/s16_2_plain: dead (16+2 > 14, no tag)" % state,
            f.get("live") == "0", f.get("live"))
    # IpInReceives is the far side's own decision about a tagged frame
    ip = {(s, a): A["run"].get((s, "wire", a), {}).get("ipin")
          for s in ("on",) for a in ("ctl", "s14_0", "s14_99", "s12_4z", "s12_2z")}
    chk("on/ctl: vid 100 -> far side does not receive it (ipin=0)",
        ip[("on", "ctl")] == "0", ip)
    chk("on/s14_0: vid 0 -> far side receives it (ipin=2)", ip[("on", "s14_0")] == "2", ip)
    chk("on/s12_4z: put_tag vid 0 -> received", ip[("on", "s12_4z")] == "2", ip)
    chk("on/s12_2z: ethertype zeroed -> not IPv4 at the far side (ipin=0)",
        ip[("on", "s12_2z")] == "0", ip)

    # ---------- the transport grid ----------
    combos = {"p6T": (6, True), "p6P": (6, False), "uT": (17, True),
              "uP": (17, False)}
    for combo, (proto, tagged) in combos.items():
        f = A["run"].get(("clear", combo, "ctl"))
        if not chk("grid %s: control present" % combo, f is not None, ""):
            continue
        wc = hexs(f)
        chk("grid %s: control wire is %d bytes" % (combo, 18 + DATALEN if tagged else 14 + DATALEN),
            len(wc) == (18 + DATALEN if tagged else 14 + DATALEN), len(wc))
        live = 0
        for (off, ln) in CELLS:
            key = ("clear", combo, "g%d_%d" % (off, ln))
            f = A["run"].get(key)
            if not chk("grid %s (%d,%d) present" % (combo, off, ln), f is not None, ""):
                continue
            want = grid_live(proto, off, ln)
            got = f.get("live") == "1"
            chk("grid %s (%d,%d): live=%s" % (combo, off, ln, want), want == got,
                "live=%s chg=%s" % (f.get("live"), f.get("wchgs")))
            if not want:
                chk("grid %s (%d,%d): dead cell wrote nothing" % (combo, off, ln),
                    f.get("wchgs") == "-", f.get("wchgs"))
                continue
            live += 1
            imm = bytes([0x90 + i for i in range(ln)])
            base = 38 if tagged else 34
            exp = bytearray(wc)
            exp[base + off:base + off + ln] = imm
            chk("grid %s (%d,%d): wire == control with %d byte(s) at %d"
                % (combo, off, ln, ln, base + off), hexs(f) == bytes(exp),
                "got %s want %s" % (hexs(f).hex(), bytes(exp).hex()))
            fexp = bytearray(far_model(wc))
            fexp[34 + off:34 + off + ln] = imm
            chk("grid %s (%d,%d): far tap writes at %d (4 less when tagged)"
                % (combo, off, ln, 34 + off), rhexs(f) == bytes(fexp),
                "got %s want %s" % (rhexs(f).hex(), bytes(fexp).hex()))
        exp_live = 36 - (4 if proto == 6 else 0) - 1
        chk("grid %s: %d/%d cells live" % (combo, exp_live, 36), live == exp_live, live)

    # ---------- two chains at one hook ----------
    C = A["c"]
    for arm in ("a_none", "b_et", "c_tci"):
        chk("chain %s present" % arm, arm in C, sorted(C))
    if "a_none" in C:
        f = C["a_none"]
        w = hexs(f)
        chk("chain a_none: post's transport store is alive", f.get("live") == "1", f)
        chk("chain a_none: it wrote 1f90 at wire 38..39",
            w[38:40] == b"\x1f\x90", w.hex())
    if "b_et" in C:
        f = C["b_et"]
        w = hexs(f)
        chk("chain b_et: pre rewrote the inner ethertype (wire 17=06)",
            w[16:18] == b"\x08\x06", w.hex())
        chk("chain b_et: post's transport store is DEAD", f.get("live") == "0", f)
        chk("chain b_et: post wrote nothing", w[38:40] == b"\x9c\x40", w.hex())
    if "c_tci" in C:
        f = C["c_tci"]
        w = hexs(f)
        chk("chain c_tci: pre wrote only metadata (wire 15=99)",
            w[14:16] == b"\x00\x99", w.hex())
        chk("chain c_tci: post stayed alive", f.get("live") == "1", f)
        chk("chain c_tci: and wrote 1f90 at 38..39", w[38:40] == b"\x1f\x90", w.hex())

    # ---------- determinism ----------
    if len(parsed) > 1:
        B = parsed[logs[1]]
        chk("rep1 == rep2: every F559 R line", A["run"] == B["run"],
            "n=%d vs %d" % (len(A["run"]), len(B["run"])))
        chk("rep1 == rep2: every F559 C line", A["c"] == B["c"], "")
        chk("rep1 == rep2: FEAT/SET lines", A["feat"] == B["feat"] and
            A["set"] == B["set"], "")
        chk("rep1 == rep2: grid totals",
            sum(1 for k, v in A["run"].items() if v.get("live") == "1") ==
            sum(1 for k, v in B["run"].items() if v.get("live") == "1"), "")

    bad = [c for c in CHECKS if not c["ok"]]
    for c in bad:
        print("FAIL %s | %s" % (c["name"], c["detail"]))
    print("SUMMARY|checks=%d|passed=%d|failed=%d"
          % (len(CHECKS), len(CHECKS) - len(bad), len(bad)))
    out = {"checks": len(CHECKS), "passed": len(CHECKS) - len(bad),
           "failed": len(bad), "failures": bad, "logs": logs}
    with open(os.path.join(LOGDIR, "verify559.json"), "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
