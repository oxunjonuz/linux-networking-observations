#!/usr/bin/env python3
"""verify561.py -- independent check of turn 561 / F39 (802.1AD, Q-in-Q).

The model below is written from the kernel source, not from the instrument:
  eth_type_trans()          -> skb->protocol = frame[12:14]
  __netif_receive_skb_core  -> one skb_vlan_untag() per skb, and none if a tag
                               is already present in metadata
  skb_reorder_vlan_header   -> popped frame = frame[0:12] + frame[16:]
  nft_payload_set_eval      -> ll offsets are wire offsets minus vlan_hlen
  nft_nh_write_ok_*()       -> per-branch lists
  nft_meta_pktinfo_may_update() -> what `meta protocol` reports
  validate_xmit_vlan()      -> tag inserted iff not vlan_hw_offload_capable()
  veth: dev_forward_skb() keeps skb->vlan_* inside one netns, so a tag that is
        NOT inserted into the bytes travels to the peer as metadata.

Every arm of the log is re-derived and compared byte for byte.  A check that
fails is printed; the script exits non-zero if any did.
"""
import gzip
import hashlib
import os
import sys

ROOT = "/work/kernel-sec"
N = 0
FAIL = []


def ck(cond, what, detail=""):
    global N
    N += 1
    if not cond:
        FAIL.append((what, detail))
    return cond


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- frames ----

def csum(b):
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | (b[i + 1] if i + 1 < len(b) else 0)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def plain_frame():
    tot = 20 + 8 + 18
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2] = tot >> 8
    ip[3] = tot & 0xFF
    ip[4], ip[5] = 0x12, 0x34
    ip[8], ip[9] = 64, 17
    ip[12:16] = bytes([10, 1, 0, 1])
    ip[16:20] = bytes([10, 9, 0, 7])
    c = csum(bytes(ip))
    ip[10] = c >> 8
    ip[11] = c & 0xFF
    udp = bytes([0x9C, 0x40, 0x13, 0x88, 0x00, 26, 0x00, 0x00]) + b"\x77" * 18
    return (bytes([0xFF] * 6) + bytes([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x66]) +
            b"\x08\x00" + bytes(ip) + udp)


REPS = {
    "p": [],
    "w": [(0x8100, 0x0064)],
    "s88": [(0x88A8, 0x0064)],
    "q": [(0x88A8, 0x0064), (0x8100, 0x00C8)],
    "q81": [(0x8100, 0x0064), (0x8100, 0x00C8)],
    "x91": [(0x9100, 0x0064)],
}
ORDER = ["p", "w", "s88", "q", "q81", "x91"]


def mkframe(tags):
    base = plain_frame()
    out = base[:12]
    for tp, tci in tags:
        out += bytes([tp >> 8, tp & 0xFF, tci >> 8, tci & 0xFF])
    return out + base[12:]


FRAMES = {k: mkframe(v) for k, v in REPS.items()}

VLAN_TPIDS = (0x8100, 0x88A8)
FEAT_DEFAULT = {"ctag": True, "stag": True}


def rx_state(frame):
    """The skb as the receive path leaves it (one pop at most)."""
    tp = int.from_bytes(frame[12:14], "big")
    if tp in VLAN_TPIDS:
        tci = int.from_bytes(frame[14:16], "big")
        inner = int.from_bytes(frame[16:18], "big")
        proto = int.from_bytes(frame[16:18], "big") if inner >= 0x600 \
            else 0x0002
        return {"frame": frame[:12] + frame[16:], "proto": proto,
                "vp": tp, "tci": tci, "present": True}
    return {"frame": frame, "proto": int.from_bytes(frame[12:14], "big"),
            "vp": 0, "tci": 0, "present": False}


def meta_value(rep):
    st = rx_state(FRAMES[rep])
    eh = int.from_bytes(st["frame"][12:14], "big")
    if eh == 0x0800:
        return 0x0800            # ipv4_validate: flags set, early return
    if eh == 0x86DD:
        return 0x86DD
    if st["proto"] == 0x8100:
        return int.from_bytes(st["frame"][16:18], "big")
    return st["proto"]


def ll_apply(st, off, ln, imm):
    """nft_payload_set_eval(), base ll.  Returns (live, new_state)."""
    fr = bytearray(st["frame"])
    vp, tci, pres = st["vp"], st["tci"], st["present"]
    if pres and off + ln > 12:
        if off >= 16:
            if off + ln > 18:
                return False, st
            fr[off - 4:off - 4 + ln] = imm[:ln]
            return True, {"frame": bytes(fr), "proto": st["proto"],
                          "vp": vp, "tci": tci, "present": pres}
        if off == 12 and ln == 2:
            vp = int.from_bytes(imm[:2], "big")
        elif off == 12 and ln == 4:
            vp = int.from_bytes(imm[:2], "big")
            tci = int.from_bytes(imm[2:4], "big")
        elif off == 14 and ln == 2:
            tci = int.from_bytes(imm[:2], "big")
        else:
            return False, st
        pres = (vp != 0 or tci != 0)
        return True, {"frame": bytes(fr), "proto": st["proto"], "vp": vp,
                      "tci": tci, "present": pres}
    if off + ln > 14:
        return False, st
    fr[off:off + ln] = imm[:ln]
    return True, {"frame": bytes(fr), "proto": st["proto"], "vp": vp,
                  "tci": tci, "present": pres}


def imm_for(off, ln):
    imm = bytearray(16)
    for i in range(min(ln, 16)):
        imm[i] = (0x90 + i) & 0xFF
    if off == 0:
        imm[0] = 0x45
    if off == 8 and ln >= 2:
        imm[1] = 0x11
    return bytes(imm[:ln])


IP4_ALIVE = {
    (0, 2): "value", (1, 1): True, (4, 2): True, (8, 1): True,
    (8, 2): "value", (10, 1): True, (10, 2): True, (10, 4): True,
    (12, 1): True, (12, 2): True, (12, 4): True,
    (16, 1): True, (16, 2): True, (16, 4): True,
}


def nh_guard_ip4(st, off, ln, imm):
    """nft_nh_write_ok_ip4(): the two cells that read the packet."""
    if (off, ln) == (0, 2):
        return imm[0] == st["frame"][14]
    if (off, ln) == (8, 2):
        return imm[1] == st["frame"][14 + 9]
    return True


def nh_apply(st, off, ln, imm):
    """base network: the store lands at data+off, i.e. frame[14+off]."""
    fr = bytearray(st["frame"])
    pos = 14 + off
    if pos + ln > len(fr):
        return False, st
    fr[pos:pos + ln] = imm[:ln]
    return True, {"frame": bytes(fr), "proto": st["proto"], "vp": st["vp"],
                  "tci": st["tci"], "present": st["present"]}


def capable(feat, vp):
    if vp == 0x8100:
        return feat["ctag"]
    if vp == 0x88A8:
        return feat["stag"]
    return False


def deliver(proto, present, tci):
    """Would ip_rcv() count this skb?  PACKET_OTHERHOST is dropped first."""
    if proto != 0x0800:
        return 0
    if present and tci != 0:
        return 0
    return 1


def pipeline(st, feat, bridge=True):
    """(wire, far_frame, far_proto, ipin) for one post-store state."""
    if st["present"] and capable(feat, st["vp"]):
        wire = st["frame"]
        far = {"frame": wire, "proto": int.from_bytes(wire[12:14], "big"),
               "present": True, "tci": st["tci"], "vp": st["vp"]}
    elif st["present"]:
        tag = bytes([st["vp"] >> 8, st["vp"] & 0xFF,
                     st["tci"] >> 8, st["tci"] & 0xFF])
        wire = st["frame"][:12] + tag + st["frame"][12:]
        far = rx_state(wire)
    else:
        wire = st["frame"]
        far = rx_state(wire)
    ipin = deliver(far["proto"], far["present"], far["tci"])
    if bridge:
        ipin += deliver(st["proto"], st["present"], st["tci"])
    return wire, far["frame"], ipin


def hexs(b):
    return b.hex()


# ------------------------------------------------------------------ log ----

def parse(path):
    rows = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.replace("\r", "").rstrip("\n")
            if not line.startswith("F561 "):
                continue
            head, _, rest = line[5:].partition("|")
            kv = {"_k": head.strip()}
            for part in rest.split("|"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    kv[k] = v
            rows.append(kv)
    return rows


def getr(rows, kind, **kw):
    out = [r for r in rows if r["_k"] == kind]
    for k, v in kw.items():
        out = [r for r in out if r.get(k) == v]
    return out


def one(rows, kind, **kw):
    r = getr(rows, kind, **kw)
    return r[0] if len(r) == 1 else None


def main():
    rep1 = os.environ.get("V561_REP1", os.path.join(ROOT,
                                                    "logs/f39_rep1.log"))
    rep2 = os.environ.get("V561_REP2", os.path.join(ROOT,
                                                    "logs/f39_rep2.log"))
    for p in (rep1, rep2):
        if not os.path.exists(p):
            print("MISSING", p)
            return 2
    txt1 = open(rep1, "r", errors="replace").read().replace("\r", "")
    txt2 = open(rep2, "r", errors="replace").read().replace("\r", "")
    rows = parse(rep1)
    rows2 = parse(rep2)

    # ---- provenance
    bz = os.path.join(ROOT, "src/linux-7.3.4-T558/arch/x86/boot/bzImage")
    m = [l for l in txt1.splitlines() if l.startswith("### sha256:")]
    ck(len(m) == 1 and m[0].split()[-1] == sha256(bz),
       "kernel sha in log == sha256(bzImage)")
    m = [l for l in txt1.splitlines() if l.startswith("### initrd sha256:")]
    initrd = os.path.join(ROOT, "vm/initrd561/full.cpio.gz")
    ck(len(m) == 1 and m[0].split()[-1] == sha256(initrd),
       "initrd sha in log == sha256(full.cpio.gz)")
    hashes = set()
    for line in open(os.path.join(ROOT, "logs/f39_initrd_hashes.txt")):
        a, b = line.split()
        hashes.add((a, b))
    ck(("full", sha256(initrd)) in hashes, "initrd sha in the hash list")
    ck("Linux version 7.3.4" in txt1, "guest /proc/version is 7.3.4")
    ck("=== VM_BOOT_OK ===" in txt1, "VM_BOOT_OK in rep1")
    ck("F561 DONE" in txt1 and "F561 DONE" in txt2, "F561 DONE in both boots")
    ck("=== MODE_EXIT f561=0 ===" in txt1, "the full battery exits 0")
    ck("=== MODE_BEGIN f561 ===" in txt1, "the full battery starts")
    splat = [l for l in txt1.splitlines()
             if any(w in l for w in ("KASAN", "BUG:", "Oops", "WARNING:",
                                     "general protection"))]
    ck(not splat, "no kernel splat", "; ".join(splat[:3]))

    def cpio_member(path, want):
        data = gzip.decompress(open(path, "rb").read())
        off = 0
        while off + 110 <= len(data):
            hdr = data[off:off + 110]
            if hdr[:6] != b"070701":
                break
            namesize = int(hdr[94:102], 16)
            filesize = int(hdr[54:62], 16)
            name = data[off + 110:off + 110 + namesize - 1].decode()
            pos = (off + 110 + namesize + 3) & ~3
            body = data[pos:pos + filesize]
            if name.lstrip("./") == want:
                return body
            off = (pos + filesize + 3) & ~3
        return None

    # the feature-bit numbers the instrument uses, derived from the enum (an
    # alias in an enum does not consume a value: this is the check that would
    # have caught the turn using 46 = STAG_RX instead of 45 = STAG_TX)
    import re as _re
    hdr = open(os.path.join(
        ROOT, "src/linux-7.3.4-T558/include/linux/netdev_features.h")).read()
    ebody = _re.search(r"enum \{(.*?)\n\};", hdr, _re.S).group(1)
    ebody = _re.sub(r"/\*.*?\*/", "", ebody, flags=_re.S)
    bits, nxt = {}, 0
    for it in [x.strip() for x in ebody.split(",") if x.strip()]:
        mm = _re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*"
                       r"([A-Za-z_][A-Za-z0-9_]*))?$", it)
        if not mm:
            continue
        if mm.group(2):
            bits[mm.group(1)] = bits[mm.group(2)]
        else:
            bits[mm.group(1)] = nxt
            nxt += 1
    csrc = open(os.path.join(ROOT, "vm/differ561_add.c")).read()
    m = _re.search(r"#define F561_CTAG_TX_BIT\s+(\d+)", csrc)
    ck(m and int(m.group(1)) == bits["NETIF_F_HW_VLAN_CTAG_TX_BIT"],
       "CTAG_TX bit number == the enum")
    m = _re.search(r"#define F561_STAG_TX_BIT\s+(\d+)", csrc)
    ck(m and int(m.group(1)) == bits["NETIF_F_HW_VLAN_STAG_TX_BIT"],
       "STAG_TX bit number == the enum (%d)" %
       bits["NETIF_F_HW_VLAN_STAG_TX_BIT"])

    body_far = cpio_member(os.path.join(ROOT,
                                        "vm/initrd561/mf561far.cpio.gz"),
                           "root/repro")
    ck(body_far is not None and hashlib.sha256(body_far).hexdigest() ==
       sha256(os.path.join(ROOT, "vm/build/differ561")),
       "the far-mode initramfs carries the same differ binary")

    body = cpio_member(initrd, "root/repro")
    ck(body is not None, "root/repro found in the initramfs")
    if body is not None:
        ck(hashlib.sha256(body).hexdigest() == sha256(
            os.path.join(ROOT, "vm/build/differ561")),
           "differ extracted from the initramfs == the built binary")

    # ---- determinism
    def keyed(rs):
        out = {}
        for r in rs:
            k = (r["_k"], r.get("env"), r.get("arm"), r.get("rep"),
                 r.get("want"), r.get("off"), r.get("len"), r.get("gate"),
                 r.get("ctl"))
            out.setdefault(k, []).append(
                {kk: vv for kk, vv in r.items() if kk != "ipin"})
        return out

    k1, k2 = keyed(rows), keyed(rows2)
    ck(set(k1) == set(k2), "rep1 and rep2 have the same arm set")
    diff = [str(k) for k in k1 if k1[k] != k2.get(k)]
    ck(not diff, "rep1 == rep2 on every arm", "; ".join(diff[:5]))

    # ---- 1. far: one pop or two.
    # The battery runs this section first, right after the interfaces come up,
    # and its IpInReceives delta carries boot-time noise (rep1: p=3, rep2:
    # p=1 w=2 -- recorded, not explained).  The delivery oracle is therefore
    # the same mode run alone in two fresh boots; the frame bytes are checked
    # against the battery as well.
    farA = parse(os.path.join(ROOT, "logs/f39_farA.log"))
    farB = parse(os.path.join(ROOT, "logs/f39_farB.log"))
    for tag, rs in (("farA", farA), ("farB", farB)):
        ck(len(rs) > 0, "%s parsed" % tag)
        txt = open(os.path.join(ROOT, "logs/f39_%s.log" % tag),
                   errors="replace").read().replace("\r", "")
        ck("=== MODE_EXIT f561far=0 ===" in txt, "%s exits 0" % tag)
        ck("F561 DONE" in txt, "%s reaches F561 DONE" % tag)
        mm = [l for l in txt.splitlines() if l.startswith("### initrd sha256:")]
        ck(len(mm) == 1 and ("mf561far", mm[0].split()[-1]) in hashes,
           "%s: initrd sha is one this turn recorded" % tag)
    noisy = []
    for rep in ORDER:
        r = one(rows, "FAR", rep=rep)
        rA = one(farA, "FAR", rep=rep)
        rB = one(farB, "FAR", rep=rep)
        if not ck(r is not None and rA is not None and rB is not None,
                  "far arm present for %s" % rep):
            continue
        wire = FRAMES[rep]
        far = rx_state(wire)
        ipin = deliver(far["proto"], far["present"], far["tci"])
        ck(r["whex"] == hexs(wire), "far %s: the wire" % rep, r["whex"])
        ck(r["rhex"] == hexs(far["frame"]), "far %s: the far tap" % rep,
           r["rhex"])
        ck(all(x["whex"] == r["whex"] and x["rhex"] == r["rhex"]
               for x in (rA, rB)),
           "far %s: three runs agree on the bytes" % rep)
        ck(int(rA["ipin"]) == ipin and int(rB["ipin"]) == ipin,
           "far %s: IpInReceives == %d in both dedicated boots" % (rep, ipin),
           "%s/%s" % (rA["ipin"], rB["ipin"]))
        if int(r["ipin"]) != ipin:
            noisy.append("%s: battery %s vs model %d" % (rep, r["ipin"], ipin))
    print("NOTE far ipin noise in the battery: %s" % ("; ".join(noisy) or "-"))

    # ---- 2. meta
    for rep in ORDER:
        want = meta_value(rep)
        mt = [x for x in getr(rows, "M", rep=rep) if x["want"] != "-"]
        ck(len(mt) == 8, "meta %s: eight candidates" % rep)
        live = [int(x["want"], 16) for x in mt if int(x["live"]) > 0]
        ck(live == [want], "meta %s reports %04x" % (rep, want),
           str([hex(v) for v in live]))
        ctl = [x for x in getr(rows, "M", rep=rep) if x["want"] == "-"]
        ck(len(ctl) == 1 and int(ctl[0]["live"]) == 1,
           "meta %s: the frame reaches the chain" % rep)

    # ---- 3. ll
    ll_live = {}
    for rep in ORDER:
        st0 = rx_state(FRAMES[rep])
        ctl = one(rows, "R", env="ll.%s" % rep, arm="ctl")
        if not ck(ctl is not None, "ll %s: control arm" % rep):
            continue
        ck(int(ctl["live"]) == 1, "ll %s: control is live" % rep)
        w0, f0, i0 = pipeline(st0, FEAT_DEFAULT)
        ck(ctl["whex"] == hexs(w0), "ll %s: control on the wire" % rep,
           ctl["whex"])
        ck(ctl["rhex"] == hexs(f0), "ll %s: control at the far tap" % rep,
           ctl["rhex"])
        ck(int(ctl["ipin"]) == i0, "ll %s: control ipin == %d" % (rep, i0),
           ctl["ipin"])
        live = set()
        for off in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24):
            for ln in (1, 2, 4):
                arm = "g%d_%d" % (off, ln)
                a = one(rows, "R", env="ll.%s" % rep, arm=arm)
                if not ck(a is not None, "ll %s %s present" % (rep, arm)):
                    continue
                ok, st = ll_apply(st0, off, ln, imm_for(off, ln))
                ck(int(a["live"]) == int(ok),
                   "ll %s %s: verdict %d" % (rep, arm, ok), a["live"])
                if ok:
                    live.add((off, ln))
                w, f, ip = pipeline(st, FEAT_DEFAULT) if ok else (w0, f0, i0)
                if ok:
                    ck(a["whex"] == hexs(w),
                       "ll %s %s: wire bytes" % (rep, arm), a["whex"])
                    ck(a["rhex"] == hexs(f),
                       "ll %s %s: far bytes" % (rep, arm), a["rhex"])
                ck(int(a["ipin"]) == ip, "ll %s %s: ipin == %d" %
                   (rep, arm, ip), a["ipin"])
        ll_live[rep] = live
        ck(len(live) == {"p": 23, "w": 25, "s88": 25, "q": 25, "q81": 25,
                         "x91": 23}[rep],
           "ll %s: %d live cells" % (rep, len(live)), str(len(live)))
    ck(ll_live["w"] == ll_live["q"], "ll: w and q live sets identical")
    ck(ll_live["w"] == ll_live["s88"], "ll: w and s88 live sets identical")
    ck(ll_live["w"] == ll_live["q81"], "ll: w and q81 live sets identical")
    ck(ll_live["p"] == ll_live["x91"], "ll: p and x91 live sets identical")
    ck((20, 1) not in ll_live["q"], "ll q: the real ethertype is unreachable")

    st0 = rx_state(FRAMES["q"])
    _, st = ll_apply(st0, 16, 2, imm_for(16, 2))
    w, _, _ = pipeline(st, FEAT_DEFAULT)
    ctl = one(rows, "R", env="ll.q", arm="ctl")
    cw = bytes.fromhex(ctl["whex"])
    ch = [i for i in range(min(len(w), len(cw))) if w[i] != cw[i]]
    ck(ch == [12, 13] and w[12] == 0x90 and w[13] == 0x91,
       "ll q (16,2) changes wire bytes 12..13 to 9091", str(ch))

    # ---- 4. unlock
    for rep in ("w", "q"):
        st0 = rx_state(FRAMES[rep])
        for gate in (0, 1):
            env = "%s.%s" % (rep, "meta" if gate else "bare")
            et = meta_value(rep) if gate else st0["proto"]
            ctl = one(rows, "R", env="unlock.%s" % env, arm="ctl")
            if not ck(ctl is not None, "unlock %s: control" % env):
                continue
            ck(int(ctl["live"]) == 1, "unlock %s: control live" % env)
            live = 0
            for off in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24):
                for ln in (1, 2, 4):
                    arm = "g%d_%d" % (off, ln)
                    a = one(rows, "R", env="unlock.%s" % env, arm=arm)
                    if not ck(a is not None,
                             "unlock %s %s present" % (env, arm)):
                        continue
                    g = IP4_ALIVE.get((off, ln)) if et == 0x0800 else None
                    ok = False
                    if g is not None:
                        ok = (nh_guard_ip4(st0, off, ln, imm_for(off, ln))
                              if g == "value" else True)
                    if ok:
                        ok, st = nh_apply(st0, off, ln, imm_for(off, ln))
                    ck(int(a["live"]) == int(ok),
                       "unlock %s %s: verdict %d" % (env, arm, ok),
                       a["live"])
                    if ok:
                        live += 1
                        w, f, ip = pipeline(st, FEAT_DEFAULT)
                        ck(a["whex"] == hexs(w),
                           "unlock %s %s: wire bytes" % (env, arm),
                           a["whex"])
                        ck(int(a["ipin"]) == ip,
                           "unlock %s %s: ipin == %d" % (env, arm, ip),
                           a["ipin"])
                    else:
                        w, f, ip = pipeline(st0, FEAT_DEFAULT)
                        ck(int(a["ipin"]) == ip,
                           "unlock %s %s: ipin == %d" % (env, arm, ip),
                           a["ipin"])
            for i in range(4):
                arm = "x%d_%d" % ((0, 8, 16, 20)[i], (8, 16, 16, 16)[i])
                a = one(rows, "R", env="unlock.%s" % env, arm=arm)
                if a is not None:
                    ck(int(a["live"]) == 0,
                       "unlock %s %s: wide arm dead" % (env, arm))
            want = {("w", 0): 14, ("w", 1): 14, ("q", 0): 0, ("q", 1): 12}
            ck(live == want[(rep, gate)],
               "unlock %s: %d live cells" % (env, live), str(live))

    # ---- 5. xmit
    st0 = rx_state(FRAMES["w"])
    stores = {
        "ctl": None,
        "p8100": (12, 2, bytes([0x81, 0x00])),
        "p88a8": (12, 2, bytes([0x88, 0xA8])),
        "p0000": (12, 2, bytes([0x00, 0x00])),
        "t88a8": (12, 4, bytes([0x88, 0xA8, 0x00, 0x64])),
    }
    feats = {"A_11": {"ctag": True, "stag": True},
             "B_01": {"ctag": False, "stag": True},
             "C_00": {"ctag": False, "stag": False}}
    for sname, feat in feats.items():
        for aname in ("ctl", "p8100", "p88a8", "p0000", "t88a8"):
            env = "%s.%s" % (sname, aname)
            a = one(rows, "R", env="xmit.%s" % env, arm=aname)
            if not ck(a is not None, "xmit %s present" % env):
                continue
            st = st0
            if stores[aname]:
                off, ln, imm = stores[aname]
                ok, st = ll_apply(st0, off, ln, imm)
                ck(ok, "xmit %s: store accepted" % env)
            w, f, ip = pipeline(st, feat)
            ck(a["whex"] == hexs(w), "xmit %s: wire bytes" % env, a["whex"])
            ck(a["rhex"] == hexs(f), "xmit %s: far bytes" % env, a["rhex"])
            ck(int(a["ipin"]) == ip, "xmit %s: ipin == %d" % (env, ip),
               a["ipin"])

    def wx(env, arm):
        r = one(rows, "R", env="xmit.%s" % env, arm=arm)
        return r["whex"] if r else ""

    ck(wx("A_11.p88a8", "p88a8") == hexs(st0["frame"]),
       "default features: 0x88a8 store leaves no tag on the wire")
    ck(wx("B_01.p88a8", "p88a8") == hexs(st0["frame"]),
       "CTAG cleared, STAG set: 0x88a8 store still leaves no tag")
    ck(wx("C_00.p88a8", "p88a8")[:32] == "ffffffffffffaabbcc00006688a80064",
       "both cleared: 0x88a8 tag on the wire")
    ck(wx("B_01.p8100", "p8100")[:32] == "ffffffffffffaabbcc00006681000064",
       "CTAG cleared: 0x8100 tag inserted")
    ck(wx("A_11.p0000", "p0000")[:32] == "ffffffffffffaabbcc00006600000064",
       "default features: 0x0000 store does leave a tag")

    # ---- 6. ndin
    for rep in ("p", "q"):
        st0 = rx_state(FRAMES[rep])
        ctl = one(rows, "R", env="ndin.%s" % rep, arm="ctl")
        if not ck(ctl is not None, "ndin %s: control" % rep):
            continue
        _, _, ip0 = pipeline(st0, FEAT_DEFAULT)
        ck(int(ctl["ipin"]) == ip0, "ndin %s: control ipin == %d" %
           (rep, ip0), ctl["ipin"])
        live = 0
        changed = {}
        for off in (0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24):
            for ln in (1, 2, 4):
                arm = "g%d_%d" % (off, ln)
                a = one(rows, "R", env="ndin.%s" % rep, arm=arm)
                if not ck(a is not None, "ndin %s %s present" % (rep, arm)):
                    continue
                ok, st = nh_apply(st0, off, ln, imm_for(off, ln))
                ck(int(a["live"]) == 1, "ndin %s %s: live" % (rep, arm),
                   a["live"])
                live += 1
                w, f, ip = pipeline(st, FEAT_DEFAULT)
                ck(a["whex"] == hexs(w),
                   "ndin %s %s: wire bytes" % (rep, arm), a["whex"])
                ck(int(a["ipin"]) == ip, "ndin %s %s: ipin == %d" %
                   (rep, arm, ip), a["ipin"])
                if (off, ln) == (8, 1):
                    cw = bytes.fromhex(ctl["whex"])
                    changed = [i for i in range(min(len(w), len(cw)))
                               if w[i] != cw[i]]
        for i in range(4):
            arm = "x%d_%d" % ((0, 8, 16, 20)[i], (8, 16, 16, 16)[i])
            a = one(rows, "R", env="ndin.%s" % rep, arm=arm)
            if a is not None:
                live += 1
                ck(int(a["live"]) == 1, "ndin %s %s: live" % (rep, arm))
        ck(live == 40, "ndin %s: 40/40 live" % rep, str(live))
        ck(changed == [22], "ndin %s: (8,1) writes frame byte 22" % rep,
           str(changed))
    ck(rx_state(FRAMES["q"])["frame"][18] == 0x45,
       "ndin q: the IPv4 header starts at frame byte 18")
    ck(rx_state(FRAMES["p"])["frame"][14] == 0x45,
       "ndin p: the IPv4 header starts at frame byte 14")

    print("checks=%d failed=%d" % (N, len(FAIL)))
    for w, d in FAIL[:40]:
        print("FAIL %s | %s" % (w, d))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
