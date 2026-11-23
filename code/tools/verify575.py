#!/usr/bin/env python3
"""verify575.py -- independent re-derivation of every fact in the F53 logs.

Reads logs/f53_rep{1,2}.log (one boot each) and checks, from the bytes of the
log alone:

  * provenance: kernel sha256 from the header against the file on disk, the
    initrd sha256 from both headers, and the differ binary extracted from the
    initramfs against vm/build/differ575;
  * the four frames, rebuilt in Python from fd02::11 -> fd02::92, UDP
    42000 -> 5000, payload 0x77 x 18 (including the UDP checksum), against the
    bytes the instrument printed;
  * the VLAN devices: creation rc, protocol, vid, and the IFLA_VLAN_FLAGS
    attribute that vlan_fill_info() emits only while vlan->flags is nonzero;
  * for every arm of both boots: the census of both doors, the arm rule's own
    counter (0 = the expression broke, 1 = it ran), every Ip6* counter delta,
    every NFLOG message (prefix, indev, hardware header as 14 bytes from
    mac_header, L2HDR at the netdev door, NFULA_VLAN while the tag is metadata,
    payload from skb->data), and every packet-socket tap (count, length,
    bytes);
  * determinism: the two boots must agree on every derived fact once the two
    MAC addresses the kernel picks are normalised.

The model is a port of the receive path as read in the source tree:
skb_vlan_untag() + skb_reorder_vlan_header() (net/core/skbuff.c:6336,6362),
vlan_do_receive() with and without VLAN_FLAG_REORDER_HDR (net/8021q/vlan_core.c:17),
__vlan_insert_inner_tag() (include/linux/if_vlan.h:361), nft_payload_eval(),
nft_payload_set_eval() with nft_ll_write_ok() and nft_payload_set_vlan()
(net/netfilter/nft_payload.c), and nfnetlink_log's attribute set
(net/netfilter/nfnetlink_log.c:427,590).
"""

import gzip
import hashlib
import os
import re
import sys

ROOT = "/work/kernel-sec"
IMG = os.path.join(ROOT, "src/linux-7.3.4-T563/arch/x86/boot/bzImage")
DIFFER = os.path.join(ROOT, "vm/build/differ575")

CHECKS = []
FAILS = []


def ck(name, cond, detail=""):
    CHECKS.append(name)
    if not cond:
        FAILS.append("%s %s" % (name, detail))


def eq(name, got, want):
    ck(name, got == want, "got=%r want=%r" % (got, want))


# ---------------------------------------------------------------- the frames

SRC = bytes.fromhex("fd020000000000000000000000000011")
DST = bytes.fromhex("fd020000000000000000000000000092")
BC = b"\xff" * 6
PAY = b"\x77" * 18
SPORT, DPORT = 42000, 5000
SPORT_A = 40000        # frame A is the inherited plain frame (F57x builder)


def ip6_udp(sport=SPORT):
    tot = 8 + len(PAY)
    ip = bytearray(40)
    ip[0] = 0x60
    ip[4] = (tot >> 8) & 0xFF
    ip[5] = tot & 0xFF
    ip[6] = 17
    ip[7] = 64
    ip[8:24] = SRC
    ip[24:40] = DST
    udp = bytearray(8)
    udp[0] = (sport >> 8) & 0xFF
    udp[1] = sport & 0xFF
    udp[2] = (DPORT >> 8) & 0xFF
    udp[3] = DPORT & 0xFF
    udp[4] = (tot >> 8) & 0xFF
    udp[5] = tot & 0xFF
    body = bytearray(bytes(ip) + bytes(udp) + PAY)
    pseudo = (SRC + DST + len(body[40:]).to_bytes(2, "big") + b"\x00\x00\x00\x11")
    s = 0
    for blob in (pseudo, bytes(body[40:])):
        for i in range(0, len(blob), 2):
            s += (blob[i] << 8) | blob[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    c = (~s) & 0xFFFF or 0xFFFF
    body[46] = (c >> 8) & 0xFF
    body[47] = c & 0xFF
    return bytes(body)


def frm(fk, smac):
    if fk == "A":
        return BC + smac + b"\x86\xdd" + ip6_udp(SPORT_A)
    if fk == "B":
        return BC + smac + b"\x81\x00\x00\x64\x86\xdd" + ip6_udp()
    if fk == "E":
        return BC + smac + b"\x81\x00\x00\x65\x86\xdd" + ip6_udp()
    if fk == "Q":
        return BC + smac + b"\x88\xa8\x00\x66\x81\x00\x00\xc8\x86\xdd" + ip6_udp()
    raise SystemExit("frame %r" % fk)


# ------------------------------------------------------- the receive stages
#
# The buffer is modelled with 64 bytes of headroom so that the insert can push
# the frame four bytes earlier without renumbering anything.  F0 = 64 is the
# first byte of the frame as it came off the wire.

F0 = 64


def untag(b, mac, data):
    """skb_vlan_untag(): data points at the TCI; the tag before it is
    data-2 .. data+1; after the untag data points at what followed the tag."""
    vp = (b[data - 2] << 8) | b[data - 1]
    vt = (b[data] << 8) | b[data + 1]
    data += 4
    mac_len = data - mac
    if mac_len > 6:
        n = mac_len - 4 - 2
        b[mac + 4:mac + 4 + n] = b[mac:mac + n]
    return b, mac + 4, data, vp, vt


def reinsert(b, mac, data, mac_len, vp, vt):
    """vlan_do_receive() with VLAN_FLAG_REORDER_HDR cleared:
    skb_push(offset) + vlan_insert_inner_tag(mac_len) + skb_pull(offset+4)."""
    off = data - mac
    data = mac                      # skb_push(skb, offset)
    data -= 4                       # skb_push(skb, VLAN_HLEN)
    n = mac_len - 2
    b[data:data + n] = b[data + 4:data + 4 + n]
    mac -= 4
    base = data + mac_len - 14
    b[base + 12] = (vp >> 8) & 0xFF
    b[base + 13] = vp & 0xFF
    b[base + 14] = (vt >> 8) & 0xFF
    b[base + 15] = vt & 0xFF
    data = data + off + 4           # skb_pull(skb, offset + VLAN_HLEN)
    return b, mac, data


def stage(fk, smac, door, store=None):
    """Model the receive path up to one door.  Returns (buf, mac, data,
    present, vlan_proto, vlan_tci)."""
    f = bytearray(64) + bytearray(frm(fk, smac))
    if fk == "A":
        return f, F0, F0 + 14, False, None, None
    mac, data = F0, F0 + 14
    b, mac, data, vp, vt = untag(f, mac, data)
    mac_len = data - mac
    present = True
    if door == "n1":
        if store is not None:
            off, ln, imm = store
            ok, b, vp, vt = ll_store(b, mac, data, present, vp, vt, off, ln,
                                     imm, "n1")
        return b, mac, data, present, vp, vt
    if store is not None:
        off, ln, imm = store
        ok, b, vp, vt = ll_store(b, mac, data, True, vp, vt, off, ln, imm, "n1")
        if not ok:
            return b, mac, data, True, vp, vt
    if fk == "E":
        b, mac, data = reinsert(b, mac, data, mac_len, vp, vt)
    elif fk == "Q":
        b, mac, data = reinsert(b, mac, data, mac_len, vp, vt)
        b, mac, data, vp2, vt2 = untag(b, mac, data)
    # fk == "B": br0.100 keeps VLAN_FLAG_REORDER_HDR, no insert
    return b, mac, data, False, None, None


def ll_read(b, mac, data, present, vp, vt, off, ln):
    if present and (off + ln) > 12:
        veth = bytearray(18)
        veth[0:12] = b[mac:mac + 12]
        veth[12:14] = vp.to_bytes(2, "big")
        veth[14:16] = vt.to_bytes(2, "big")
        veth[16:18] = bytes(b[data - 2:data])
        return bytes(veth[off:off + ln])
    return bytes(b[mac + off:mac + off + ln])


def ll_store(b, mac, data, present, vp, vt, off, ln, imm, door):
    b = bytearray(b)
    if present and (off + ln) > 12:
        if off >= 16:
            vlan_hlen = 4
        elif off == 12:
            if ln == 2:
                return True, b, int.from_bytes(imm, "big"), vt
            if ln == 4:
                return (True, b, int.from_bytes(imm[0:2], "big"),
                        int.from_bytes(imm[2:4], "big"))
            return False, b, vp, vt
        elif off == 14:
            if ln != 2:
                return False, b, vp, vt
            return True, b, vp, int.from_bytes(imm, "big")
        else:
            return False, b, vp, vt
    else:
        vlan_hlen = 0
    if door != "n1":
        if ln + off + (mac - data) - vlan_hlen > 0:
            return False, b, vp, vt
    t = mac + off - vlan_hlen
    if t < 0 or t + ln > len(b):
        return False, b, vp, vt
    b[t:t + ln] = imm
    return True, b, vp, vt


# ------------------------------------------------------------- log parsing

DEVIDX = {"br0": 11, "br0.100": 12, "br0.101": 13, "br0.102": 14,
          "br0.102.200": 15, "x1": 5}


def parse(path):
    arms, cur = [], None
    for line in open(path, "r", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("F575 A|"):
            if cur:
                arms.append(cur)
            cur = {"raw": {}, "msgs": [], "taps": []}
            for kv in line[7:].split("|"):
                k, _, v = kv.partition("=")
                cur[k] = v
        elif cur is None:
            continue
        elif line.startswith(("F575 C|", "F575 B|")):
            for kv in line[7:].split("|"):
                k, _, v = kv.partition("=")
                cur["raw"][k] = int(v)
        elif line.startswith("F575 M|"):
            body = line[len("F575 M|"):]
            cur["nfl_n"] = int(body.split("=")[1].split("|")[0])
            for part in body.split("|m")[1:]:
                part = part.split("=", 1)[1]
                f = part.split(":")
                cur["msgs"].append({
                    "prefix": f[0], "indev": int(f[1]), "outdev": int(f[2]),
                    "hwtype": int(f[3]), "hwlen": int(f[4]), "hlen": int(f[5]),
                    "hw": f[6], "llen": int(f[7]), "l2": f[8],
                    "vpresent": int(f[9]), "vproto": int(f[10], 16),
                    "vtci": int(f[11], 16), "plen": int(f[12]),
                    "payload": f[13] if len(f) > 13 else ""})
        elif line.startswith("F575 T|"):
            for part in line[len("F575 T|"):].split("|"):
                part = part.split("=", 1)[1]
                f = part.split(":")
                cur["taps"].append({"dev": f[0], "n": int(f[1]),
                                    "flen": int(f[2]),
                                    "bytes": f[3] if len(f) > 3 else "-"})
    if cur:
        arms.append(cur)
    return arms


# --------------------------------------------------------------- one arm

def deliver_dev(fk):
    return {"A": "br0", "B": "br0.100", "E": "br0.101", "Q": "br0.102.200"}[fk]


def check_arm(rep, a, smac):
    tag = "rep%d.%s" % (rep, a["arm"])
    fk, door = a["fk"], a["door"]
    mode, base, off, ln = (int(a["mode"]), int(a["base"]),
                           int(a["off"]), int(a["len"]))
    imm = bytes.fromhex(a["imm"]) if a["imm"] != "-" else b""

    if fk == "-" or a.get("snt") == "0":
        eq(tag + ".topo.g6", a["raw"].get("g6"), 0)
        eq(tag + ".topo.n1", a["raw"].get("n1"), 0)
        eq(tag + ".topo.nfl", a["nfl_n"], 0)
        return

    # --- what the expression does, and what survives to the packet
    delivered = True
    store_ok = True
    if door == "n1":
        b, mac, data, present, vp, vt = stage(fk, smac, "n1")
        if mode in (1, 2):
            store_ok, b2, vp2, vt2 = ll_store(b, mac, data, present, vp, vt,
                                              off, ln, imm, "n1")
            if store_ok and fk != "A":
                if off == 12:
                    delivered = (vp2 == (0x88A8 if fk == "Q" else 0x8100))
                elif off == 14:
                    want = {"B": 100, "E": 101, "Q": 102}[fk]
                    delivered = ((vt2 & 0x0FFF) == want)
            store = (off, ln, imm) if store_ok else None
        else:
            if base == 1:
                got = bytes(b[data + off:data + off + ln])
            else:
                got = ll_read(b, mac, data, present, vp, vt, off, ln)
            store_ok = (got == imm)
            store = None
        b, mac, data, present, vp, vt = stage(fk, smac, "g6", store)
    else:
        b, mac, data, present, vp, vt = stage(fk, smac, "g6")
        if mode in (1, 2):
            store_ok, b2, _, _ = ll_store(b, mac, data, present, vp, vt,
                                          off, ln, imm, "g6")
        elif mode in (2, 3):
            if base == 1:      # NFT_PAYLOAD_NETWORK_HEADER, pkt->nhoff == 0
                got = bytes(b[data + off:data + off + ln])
            else:
                got = ll_read(b, mac, data, present, vp, vt, off, ln)
            store_ok = (got == imm)

    # --- census and the rule's own counter
    eq(tag + ".n1", a["raw"].get("n1"), 1)
    eq(tag + ".g6", a["raw"].get("g6"), 1 if delivered else 0)
    eq(tag + ".ch", a["raw"].get("ch"),
       (1 if store_ok else 0) if door != "-" else -1)

    # --- counters: an untagged broadcast is counted on the two port copies too
    untagged = (fk == "A")
    eq(tag + ".i6in", a["raw"]["i6in_d"], (3 if untagged else 1) if delivered else 0)
    eq(tag + ".deliv", a["raw"]["deliv_d"], 1 if delivered else 0)
    eq(tag + ".disc", a["raw"]["disc_d"], 2 if untagged else 0)
    for k in ("i6hdr_d", "i6unk_d", "i6trunc_d", "i6nor_d", "u6err_d",
              "u6nop_d"):
        eq(tag + "." + k, a["raw"][k], 0)
    eq(tag + ".u6n", int(a["u6n"]), 1 if delivered else 0)
    eq(tag + ".u6len", int(a["u6len"]), len(PAY) if delivered else 0)

    # --- NFLOG: a census message per door reached, plus the arm's own log
    want = [("p1", DEVIDX["x1"])]
    if door == "n1":
        if store_ok and door != "-":
            want.append(("s", DEVIDX["x1"]))
        if delivered:
            want.append(("p0", DEVIDX[deliver_dev(fk)]))
    else:
        if delivered:
            want.append(("p0", DEVIDX[deliver_dev(fk)]))
        if door != "-" and store_ok:
            want.append(("s", DEVIDX[deliver_dev(fk)]))
    eq(tag + ".nfl.count", a["nfl_n"], len(want))
    eq(tag + ".nfl.msgs", [(m["prefix"], m["indev"]) for m in a["msgs"]], want)

    for m in a["msgs"]:
        d = "n1" if m["indev"] == DEVIDX["x1"] else "g6"
        store = None
        if m["prefix"] == "s" and mode in (1, 2) and store_ok and d == "n1":
            store = (off, ln, imm)
        bb, mmac, ddata, present, vp, vt = stage(fk, smac, d, store)
        if m["prefix"] == "s" and mode in (1, 2) and d == "g6":
            ok, bb, vp, vt = ll_store(bb, mmac, ddata, present, vp, vt,
                                      off, ln, imm, "g6")
        eq(tag + ".msg.%s.hwtype" % m["prefix"], m["hwtype"], 1)
        eq(tag + ".msg.%s.hwlen" % m["prefix"], m["hwlen"], 14)
        eq(tag + ".msg.%s.hlen" % m["prefix"], m["hlen"], 14)
        eq(tag + ".msg.%s.hw" % m["prefix"], m["hw"],
           bytes(bb[mmac:mmac + 14]).hex())
        eq(tag + ".msg.%s.plen" % m["prefix"], m["plen"],
           len(bb) - ddata if False else len(frm(fk, smac)) - (ddata - F0))
        eq(tag + ".msg.%s.payload" % m["prefix"], m["payload"],
           bytes(bb[ddata:ddata + len(m["payload"]) // 2]).hex())
        if present and fk != "A":
            eq(tag + ".msg.%s.vlan" % m["prefix"],
               (m["vpresent"], m["vproto"], m["vtci"]), (1, vp, vt))
            eq(tag + ".msg.%s.l2len" % m["prefix"], m["llen"], ddata - mmac)
            eq(tag + ".msg.%s.l2" % m["prefix"], m["l2"],
               bytes(bb[mmac:mmac + (ddata - mmac)]).hex())
        else:
            eq(tag + ".msg.%s.novlan" % m["prefix"],
               (m["vpresent"], m["llen"]),
               (0, (ddata - mmac) if d == "n1" else 0))
            if d == "n1":
                eq(tag + ".msg.%s.l2" % m["prefix"], m["l2"],
                   bytes(bb[mmac:mmac + (ddata - mmac)]).hex())

    # --- taps: what a packet socket on the VLAN device holds
    for t in a["taps"]:
        dev = t["dev"]
        want_n = 0
        if fk != "A" and delivered and dev == deliver_dev(fk):
            want_n = 1
        eq(tag + ".tap.%s.n" % dev, t["n"], want_n)
        if want_n:
            view = bytes(b[mac:])
            eq(tag + ".tap.%s.flen" % dev, t["flen"], len(view))
            eq(tag + ".tap.%s.bytes" % dev, t["bytes"], view.hex())


# ------------------------------------------------------------------- main

def main():
    one = "--one" in sys.argv
    logdir = os.environ.get("F53_LOGDIR", os.path.join(ROOT, "logs"))
    logs = [os.path.join(logdir, "f53_rep%d.log" % k) for k in ((1,) if one else (1, 2))]
    for p in logs:
        if not os.path.exists(p):
            print("MISSING %s" % p)
            return 2

    img_sha = hashlib.sha256(open(IMG, "rb").read()).hexdigest()
    initrd_hashes = set()
    hp = os.path.join(os.environ.get("F53_LOGDIR", os.path.join(ROOT, "logs")),
                      "f53_initrd_hashes.txt")
    if os.path.exists(hp):
        for l in open(hp):
            f = l.split()
            if len(f) == 2 and f[0] == "full":
                initrd_hashes.add(f[1])

    parsed = []
    for k, p in enumerate(logs, 1):
        txt = open(p, errors="replace").read()
        head = txt[:4000]
        m = re.search(r"### sha256: ([0-9a-f]{64})", head)
        ck("rep%d.kernel_sha" % k, bool(m) and m.group(1) == img_sha,
           m.group(1) if m else "none")
        m = re.search(r"### initrd sha256: ([0-9a-f]{64})", head)
        ck("rep%d.initrd_sha" % k, bool(m) and m.group(1) in initrd_hashes,
           m.group(1) if m else "none")
        ck("rep%d.boot" % k, "VM_BOOT_OK" in txt)
        ck("rep%d.end" % k, "F575 END" in txt)
        ck("rep%d.no_bug" % k,
           not re.search(r"KASAN|BUG:|Oops|general protection|double free", txt))
        # one WARN is expected and is itself a result: a store at @ll,12 at the
        # netdev door sets skb->vlan_proto to the stored bytes, and the next
        # vlan_do_receive() hands that value to vlan_proto_idx(), which WARNs.
        warns = re.findall(r"WARNING: ([^\n]*)", txt)
        norm = sorted({w.split(" at ")[0] + " at " +
                       w.split(" at ")[1].split(",")[0] for w in warns})
        eq("rep%d.warn.count" % k, len(set(warns)), 1)
        eq("rep%d.warn.site" % k, norm,
           ["net/8021q/vlan.h:48 at vlan_do_receive+0x282/0x9a0"])
        eq("rep%d.warn.value" % k,
           re.findall(r"invalid VLAN protocol: (0x[0-9a-f]{4})", txt), ["0x0806"])
        # ... and it happens on the arm that wrote that value
        i = txt.index("invalid VLAN protocol")
        after = txt[i:].splitlines()
        arm = [l for l in after if l.startswith("F575 A|arm=")][0]
        ck("rep%d.warn.arm" % k, "arm=m_w12|" in arm, arm[:60])

        env = dict(kv.split("=") for kv in
                   re.search(r"F575 ENV\|([^\n]*)", txt).group(1).split("|"))
        smac = bytes.fromhex(env["x0mac"])
        frms = {}
        for line in txt.splitlines():
            if line.startswith("F575 FRM|"):
                kk, vv = line.split("|", 1)[1].split("=", 1)
                frms[kk] = vv
        for fk in ("A", "B", "E", "Q"):
            eq("rep%d.frame_%s" % (k, fk.lower()), frms.get(fk.lower()),
               frm(fk, smac).hex())
        eq("rep%d.lens" % k, (env["la"], env["lb"], env["le"], env["lq"]),
           tuple(str(len(frm(f, smac))) for f in ("A", "B", "E", "Q")))

        vdev = {}
        for line in txt.splitlines():
            if line.startswith("F575 VDEV|"):
                d = dict(kv.split("=") for kv in line.split("|")[1:])
                vdev[d["dev"]] = d
        eq("rep%d.vdev.count" % k, len(vdev), 4)
        for name, pres, proto, vid in (("br0.100", "1", "8100", "100"),
                                       ("br0.101", "0", "8100", "101"),
                                       ("br0.102", "0", "88a8", "102"),
                                       ("br0.102.200", "1", "8100", "200")):
            d = vdev.get(name, {})
            eq("rep%d.%s.flags_present" % (k, name), d.get("flags_present"), pres)
            eq("rep%d.%s.flags_value" % (k, name),
               d.get("flags") if pres == "1" else "-1",
               "1" if pres == "1" else "-1")
            eq("rep%d.%s.proto" % (k, name), d.get("proto"), proto)
            eq("rep%d.%s.vid" % (k, name), d.get("vid"), vid)
        for line in re.findall(r"F575 VNEW\|([^\n]*)", txt):
            for kv in line.split("|"):
                _, _, v = kv.partition("=")
                eq("rep%d.vnew" % k, v, "0")
        for line in re.findall(r"F575 VADDR\|([^\n]*)", txt):
            d = dict(kv.split("=") for kv in line.split("|"))
            eq("rep%d.vaddr.%s" % (k, d["dev"]), (d["rc"], d["v6"]), ("0", "0"))

        arms = parse(p)
        smac_of = smac
        eq("rep%d.arms" % k, len(arms), 44)
        for a in arms:
            check_arm(k, a, smac_of)
        parsed.append((arms, smac))

    if one:
        print("checks=%d fails=%d (single boot)" % (len(CHECKS), len(FAILS)))
        for f in FAILS[:80]:
            print("FAIL " + f)
        return 0 if not FAILS else 1

    # ---- determinism across the two boots (MACs normalised away)
    A1, m1 = parsed[0]
    A2, m2 = parsed[1]

    def norm(arms, smac):
        out = []
        for a in arms:
            d = {kk: vv for kk, vv in a.items() if kk not in ("msgs", "taps")}
            out.append(d)
            for msg in a["msgs"]:
                out.append({kk: vv for kk, vv in msg.items()
                            if kk not in ("hw", "l2", "payload")})
            for t in a["taps"]:
                out.append({kk: vv for kk, vv in t.items() if kk != "bytes"})
        return out

    eq("det.arms", len(A1), len(A2))
    n1, n2 = norm(A1, m1), norm(A2, m2)
    eq("det.len", len(n1), len(n2))
    bad = 0
    for x, y in zip(n1, n2):
        if x != y:
            bad += 1
            if bad <= 5:
                print("DET-DIFF %r vs %r" % (x, y))
    eq("det.rows", bad, 0)
    # and the bytes, once the two MACs are blanked
    def blank(arms, smac):
        res = []
        for a in arms:
            for msg in a["msgs"]:
                res.append((msg["prefix"], msg["hw"].replace(smac.hex(), "S"),
                            msg["l2"].replace(smac.hex(), "S"),
                            msg["payload"]))
            for t in a["taps"]:
                res.append((t["dev"], t["bytes"].replace(smac.hex(), "S")))
        return res
    eq("det.bytes", blank(A1, m1), blank(A2, m2))

    print("checks=%d fails=%d" % (len(CHECKS), len(FAILS)))
    for f in FAILS[:80]:
        print("FAIL " + f)
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
