#!/usr/bin/env python3
"""verify574.py -- independent check of the turn-574 instrument (F52).

Reads logs/f52_rep{1,2}.log and checks, from the log's own bytes and from the
kernel source, everything the report will claim:

  * provenance: the kernel sha in the log header against the file, the initrd
    sha in the header against vm/initrd574/full.cpio.gz, and the differ that
    the initramfs actually carries against vm/build/differ574;
  * the three frames, byte for byte, against their own construction;
  * 20 source anchors, quoted from the tree;
  * every arm: the census of five doors, the fate of the local copy, the four
    taps, every NFLOG message, and the store/read outcome -- all recomputed by
    a Python model of the VLAN receive path (skb_vlan_untag ->
    vlan_do_receive -> the OTHERHOST assignment -> nft's LL reconstruction).

The model is written from the source, not from the numbers: if a number
disagrees, the script says so and exits 1.
"""
import gzip
import hashlib
import io
import os
import re
import sys

ROOT = "/work/kernel-sec"
LOGS = sys.argv[1:] or ["logs/f52_rep1.log", "logs/f52_rep2.log"]
KERNEL = "src/linux-7.3.4-T563/arch/x86/boot/bzImage"
INITRD = "vm/initrd574/full.cpio.gz"
DIFFER = "vm/build/differ574"

NCHECK = 0
FAIL = []


def chk(cond, what):
    global NCHECK
    NCHECK += 1
    if not cond:
        FAIL.append(what)
    return bool(cond)


def eq(got, want, what):
    return chk(got == want, "%s: got %r want %r" % (what, got, want))


# ---------------------------------------------------------------- provenance

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def cpio_member(blob, shape):
    """Return the bytes of ./name from a newc cpio.gz blob."""
    raw = gzip.decompress(blob)
    off = 0
    while True:
        if raw[off:off + 6] not in (b"070701", b"070702"):
            raise SystemExit("cpio: bad magic at %d" % off)
        hdr = raw[off:off + 110]
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = raw[off + 110:off + 110 + namesize - 1].decode()
        data_at = off + 110 + namesize
        data_at += (4 - data_at % 4) % 4
        if name.endswith("/" + os.path.basename(shape)):
            return raw[data_at:data_at + filesize]
        off = data_at + filesize
        off += (4 - off % 4) % 4
        if name == "TRAILER!!!":
            raise SystemExit("cpio: member not found")


# ---------------------------------------------------------------- the model

PAY = 18
SPORT, DPORT = 40000, 5000
SRC6 = bytes.fromhex("fd0200000000000000000000000011" + "00" * 0)
SRC6 = bytes([0xfd, 0x02] + [0] * 13 + [0x11])
DST6 = bytes([0xfd, 0x02] + [0] * 13 + [0x92])


def ipv6(sport=SPORT, dport=DPORT, pay=PAY):
    tot = 8 + pay
    h = bytearray(40 + tot)
    h[0] = 0x60
    h[4] = tot >> 8
    h[5] = tot & 0xFF
    h[6] = 17
    h[7] = 0x40
    h[8:24] = SRC6
    h[24:40] = DST6
    h[40] = sport >> 8
    h[41] = sport & 0xFF
    h[42] = dport >> 8
    h[43] = dport & 0xFF
    h[44] = 0x00
    h[45] = 0x1A
    h[46] = 0x22
    h[47] = 0x16
    h[48:] = bytes([0x77] * pay)
    return bytes(h)


ETH = {"dst": None, "src": None}


def frame(fk, x0mac):
    body = ipv6()
    bc = b"\xff" * 6
    if fk == "A":
        return bc + x0mac + b"\x86\xdd" + body
    tci = b"\x00\x64" if fk == "B" else b"\x00\x00"
    return bc + x0mac + b"\x81\x00" + tci + b"\x86\xdd" + body


def l3_layout(fk, tag_present):
    """The bytes nft's `@ll` domain shows, as a function of the skb state.

    tag_present: skb->vlan_tag_present() -- then nft_payload_copy_vlan()
    rebuilds struct vlan_ethhdr: the first 12 bytes from the header, then
    h_vlan_proto = skb->vlan_proto, h_vlan_TCI = the tag, and
    h_vlan_encapsulated_proto = skb->protocol, then the data past ETH_HLEN.
    Otherwise the domain is skb_mac_header .. which after skb_vlan_untag() is
    the 14-byte header the frame now shows (the tag is gone from the bytes).
    """
    body = ipv6()
    eth14 = b"\xff" * 6 + ETH["x0"] + b"\x86\xdd"
    if not tag_present:
        return eth14 + body, 14
    proto = ETH["vlan_proto"]
    tci = ETH["vlan_tci"]
    return eth14[:12] + proto + tci + b"\x86\xdd" + body, 18


# ---------------------------------------------------------------- parsing

A_LINE = re.compile(r"^F574 A\|(.*)$")
C_LINE = re.compile(r"^F574 C\|(.*)$")
B_LINE = re.compile(r"^F574 B\|(.*)$")
M_LINE = re.compile(r"^F574 M\|(.*)$")
T_LINE = re.compile(r"^F574 T\|(.*)$")


def kv(s):
    out = {}
    for part in s.split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
        elif part.startswith("m") or part.startswith("t"):
            continue
    return out


def parse_arms(text):
    arms = []
    cur = None
    for line in text.splitlines():
        if line.startswith("F574 A|"):
            cur = {"a": kv(line[7:]), "c": None, "b": None, "m": None, "t": None}
            arms.append(cur)
        elif cur is not None and line.startswith("F574 C|"):
            cur["c"] = kv(line[7:])
        elif cur is not None and line.startswith("F574 B|"):
            cur["b"] = kv(line[7:])
        elif cur is not None and line.startswith("F574 M|"):
            cur["m"] = line[7:]
        elif cur is not None and line.startswith("F574 T|"):
            cur["t"] = line[7:]
    return arms


def taps(s):
    """'t0=x1:1:80:hex|t1=...' -> {dev: (n, flen, bytes)}"""
    out = {}
    for part in s.split("|"):
        if not part.startswith("t") or "=" not in part:
            continue
        _, rest = part.split("=", 1)
        dev, n, flen, hx = rest.split(":", 3)
        out[dev] = (int(n), int(flen),
                    bytes.fromhex(hx) if hx not in ("-", "") else b"")
    return out


def msgs(s):
    """'n=2|m0=p0:5:-1:66:hex|...' -> (n, [(prefix, indev, outdev, len, bytes)])"""
    out = []
    n = 0
    for part in s.split("|"):
        if part.startswith("n="):
            n = int(part[2:])
        elif part.startswith("m"):
            _, rest = part.split("=", 1)
            prefix, ind, outd, plen, hx = rest.split(":")
            out.append((prefix, int(ind), int(outd), int(plen),
                        bytes.fromhex(hx)))
    return n, out


def cval(c, key):
    if c is None or key not in c:
        return None
    return int(c[key].split(",")[0])


def cch(c, key):
    if c is None or key not in c:
        return None
    v = c[key].split(",")
    return int(v[0]) if len(v) < 2 else int(v[1])


# ---------------------------------------------------------------- main check

def main():
    ok_all = True
    ksha = sha256_file(os.path.join(ROOT, KERNEL))
    isha = sha256_file(os.path.join(ROOT, INITRD))
    dbytes = open(os.path.join(ROOT, DIFFER), "rb").read()

    for rel in LOGS:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            print("no such log:", path)
            return 1
        text = open(path, "r", errors="replace").read()
        print("== %s (%d bytes)" % (rel, len(text)))

        # --- provenance
        m = re.search(r"### sha256: ([0-9a-f]{64})", text)
        eq(m.group(1) if m else None, ksha, rel + " kernel sha")
        m = re.search(r"### initrd sha256: ([0-9a-f]{64})", text)
        eq(m.group(1) if m else None, isha, rel + " initrd sha")
        member = cpio_member(open(os.path.join(ROOT, INITRD), "rb").read(),
                             "repro")
        eq(hashlib.sha256(member).hexdigest(),
           hashlib.sha256(dbytes).hexdigest(), rel + " differ from initramfs")

        # --- environment and frames
        x0 = re.search(r"F574 ENV\|.*?x0mac=([0-9a-f]{12})", text)
        x0mac = bytes.fromhex(x0.group(1))
        ETH["x0"] = x0mac
        eq(len(text.split("F574 START")), 2, rel + " one run")
        for fk, line in (("A", "a"), ("B", "b"), ("C", "c")):
            m = re.search(r"F574 FRM\|%s=([0-9a-f]+)" % line, text)
            want = frame(fk, x0mac)
            eq(m.group(1) if m else None, want.hex(), rel + " frame " + fk)
        for key, want in (("la", 80), ("lb", 84), ("lc", 84)):
            m = re.search(r"F574 ENV\|.*?%s=(\d+)" % key, text)
            eq(int(m.group(1)) if m else None, want, rel + " " + key)

        arms = parse_arms(text)
        names = [a["a"]["arm"] for a in arms]
        eq(len(arms), 33, rel + " arm count")
        eq(names[0], "topo", rel + " first arm")

        vlan_dev = False
        for a in arms:
            name = a["a"]["arm"]
            fk = a["a"]["fk"]
            door = a["a"]["door"]
            d2 = a["a"].get("d2", "-")
            mode = int(a["a"]["mode"])
            base = int(a["a"]["base"])
            off = int(a["a"]["off"])
            ln = int(a["a"]["len"])
            imm = bytes.fromhex(a["a"]["imm"]) if a["a"]["imm"] != "-" else b""
            if name == "vd_c":
                vlan_dev = True
            if fk == "A":
                continue
            pre = "%s %s" % (rel, name)
            base_tci = 0x0064 if fk == "B" else 0x0000

            # ---- the store: what it writes, and whether it writes anything
            proto = 0x8100
            tci = base_tci
            refused = False
            kind = None
            if mode == 1 or mode == 2:
                if base != 0:
                    kind = "nh"
                elif off >= 16:
                    kind = "byte"            # vlan_hlen = 4, a real byte write
                elif off == 12:
                    if ln == 2:
                        kind = "proto"
                        proto = int.from_bytes(imm, "big")
                    elif ln == 4:
                        kind = "both"
                        proto = int.from_bytes(imm[:2], "big")
                        tci = int.from_bytes(imm[2:], "big")
                    else:
                        refused = True
                elif off == 14:
                    if ln == 2:
                        kind = "tci"
                        tci = int.from_bytes(imm, "big")
                    else:
                        refused = True
                elif off + ln <= 12:
                    kind = "byte"
                else:
                    refused = True
            # the two doors that see the same skb, in order
            door_pre = (mode == 1 and door in ("brp",))
            door_fwd = (mode == 1 and door == "brf")
            door_loc = (mode == 1 and door == "brl")

            def state(p):
                # vlan_all != 0 is what skb_vlan_tag_present() asks
                return (p, t) if (p | t) else (None, 0)

            p_loc, t_loc = 0x8100, base_tci
            p_prt, t_prt = 0x8100, base_tci
            if door_pre and not refused:
                p_loc, t_loc = proto, tci
                p_prt, t_prt = proto, tci
            if door_loc and not refused:
                p_loc, t_loc = proto, tci
            if door_fwd and not refused:
                p_prt, t_prt = proto, tci
            pres_loc = bool(p_loc | t_loc)
            pres_prt = bool(p_prt | t_prt)
            vid_loc = t_loc & 0x0FFF
            vid_prt = t_prt & 0x0FFF

            dst = b"\xff" * 6
            inner = b"\x86\xdd"
            if mode == 1 and off == 0 and ln == 6 and door_pre and not refused:
                dst = imm
            if mode == 1 and off == 16 and ln == 2 and not refused:
                inner = imm

            wire_tagged = pres_prt and p_prt != 0x8100
            local_ok = ((not pres_loc) or vid_loc == 0 or vlan_dev)
            if mode == 1 and off == 0 and ln == 6 and door_pre:
                local_ok = False              # unknown unicast: no local copy
            no_local = not local_ok and (mode == 1 and off == 0 and ln == 6
                                        and door_pre)
            broth = 1 if (pres_loc and vid_loc != 0 and not vlan_dev and
                          not no_local) else 0
            port_ok = (not wire_tagged) and ((not pres_prt) or vid_prt == 0)
            yoth = 1 if (pres_prt and vid_prt != 0 and not wire_tagged) else 0
            in6 = 1 if local_ok else 0
            brl = 0 if no_local else 1
            brf = 2
            u6n = 1 if local_ok else 0
            deliv = 1 if local_ok else 0
            i6in = deliv + (2 if port_ok else 0)
            disc = 2 if port_ok else 0

            eq(cval(a["c"], "brp"), 1, pre + " brp")
            eq(cval(a["c"], "brf"), brf, pre + " brf")
            eq(cval(a["c"], "brl"), brl, pre + " brl")
            eq(cval(a["c"], "in6"), in6, pre + " in6")
            eq(cval(a["c"], "ndy"), 1, pre + " ndy")
            eq(int(a["a"]["u6n"]), u6n, pre + " u6n")
            eq(int(a["b"]["deliv_d"]), deliv, pre + " deliv")
            eq(int(a["b"]["broth_d"]), broth, pre + " br0 otherhost")
            eq(int(a["b"]["y0oth_d"]), yoth, pre + " y0 otherhost")
            eq(int(a["b"]["z0oth_d"]), yoth, pre + " z0 otherhost")
            eq(int(a["b"]["i6in_d"]), i6in, pre + " Ip6InReceives")
            eq(int(a["b"]["disc_d"]), disc, pre + " Ip6InDiscards")
            eq(int(a["b"]["brrxp_d"]), 0 if no_local else 1,
               pre + " br0 rx_packets")

            # ---- the rule's own counter and its log
            def fires(d, o, l_, im, mode_):
                if mode_ == 1:
                    if refused:
                        return 0
                    return 2 if d == "brf" else 1
                if mode_ == 3:
                    if d == "in6":
                        if not local_ok:
                            return 0
                        lay, at = l3_layout("B", False)
                    else:
                        ETH["vlan_proto"] = p_prt.to_bytes(2, "big")
                        ETH["vlan_tci"] = t_prt.to_bytes(2, "big")
                        lay, at = l3_layout("B", pres_prt)
                    if base_ == 1:
                        return 1 if im == lay[at + o:at + o + l_] else 0
                    return 1 if o + l_ <= len(lay) and im == lay[o:o + l_] else 0
                return 0

            base_ = base
            f1 = fires(door, off, ln, imm, mode)
            eq(cch(a["c"], door) if door != "-" else -1,
               -1 if door == "-" else f1, pre + " ch counter")
            f2 = 0
            if d2 != "-":
                f2 = fires(d2, off, ln, imm, mode)
                eq(cch(a["c"], "c2"), f2, pre + " c2")

            if os.environ.get("V574_DEBUG") == name:
                print("DBG", name, "pres_loc", pres_loc, "vid_loc", vid_loc,
                      "local_ok", local_ok, "in6", in6, "f1", f1, "f2", f2,
                      "brf", brf, "brl", brl, "vlan_dev", vlan_dev)
            nfl = 1 + brf + brl + in6 + 1 + f1 + (f2 if d2 != "-" else 0)
            eq(int(a["a"]["nfl"]), nfl, pre + " nfl")
            n, mm = msgs(a["m"] or "n=0")
            eq(n, nfl, pre + " nfl parsed")
            if wire_tagged:
                wire = (dst + x0mac + p_prt.to_bytes(2, "big") +
                        t_prt.to_bytes(2, "big") + inner + ipv6())
            else:
                wire = dst + x0mac + inner + ipv6()
            # eth_type_trans() pulls ETH_HLEN from whatever the wire carries;
            # a 0x8100 tag never is a byte here (veth advertises CTAG TX), so
            # the far end untags nothing and its data is the IPv6 header
            want_pay = ipv6()
            for (prefix, ind, outd, plen, bb) in mm:
                if prefix == "p4":
                    want_pay = wire[14:]
                eq(plen, len(want_pay), pre + " msg len " + prefix)
                eq(bb, want_pay[:len(bb)], pre + " msg payload " + prefix)
                want_pay = ipv6()

            # ---- the taps
            tp = taps(a["t"] or "")
            x1 = tp.get("x1", (0, -1, b""))
            y0 = tp.get("y0", (0, -1, b""))
            z0 = tp.get("z0", (0, -1, b""))
            br0 = tp.get("br0", (0, -1, b""))
            eq(x1[0], 1, pre + " tap x1 count")
            eq(br0[0], 0 if no_local else 1, pre + " tap br0 count")
            eq(y0[0], 1, pre + " tap y0 count")
            eq(z0[0], 1, pre + " tap z0 count")
            for dev, t in tp.items():
                eq(t[1], len(t[2]) if t[0] else -1, pre + " tap flen " + dev)
            want = wire
            eq(len(y0[2]), len(want), pre + " y0 tap len")
            eq(y0[2], want, pre + " y0 tap bytes")
            eq(z0[2], want, pre + " z0 tap bytes")
            if not no_local:
                eq(br0[2], dst + x0mac + inner + ipv6(), pre + " br0 tap bytes")

        # --- source anchors
        for (f, ln_no, frag) in SOURCE_ANCHORS:
            src = open(os.path.join(ROOT, "src/linux-7.3.4-T563", f),
                       "r", errors="replace").read().splitlines()
            chk(0 < ln_no <= len(src) and frag in src[ln_no - 1],
                "%s anchor %s:%d" % (rel, f, ln_no))
        print("   checks so far: %d, failures: %d" % (NCHECK, len(FAIL)))

    # ---- determinism between the two boots, with the MACs normalised
    if len(LOGS) > 1 and all(os.path.exists(os.path.join(ROOT, l))
                             for l in LOGS):
        norm = []
        for rel in LOGS:
            t = open(os.path.join(ROOT, rel), errors="replace").read()
            m = re.search(r"F574 ENV\|.*?x0mac=([0-9a-f]{12})", t)
            b = re.search(r"F574 ENV\|.*?br0mac=([0-9a-f]{12})", t)
            t = t.replace(m.group(1), "MAC0").replace(b.group(1), "MAC1")
            norm.append([ln for ln in t.splitlines()
                         if ln.startswith("F574 ") or
                         ln.startswith("### sha256")])
        eq(len(norm[0]), len(norm[1]), "determinism: line count")
        same = 0
        for a, b in zip(norm[0], norm[1]):
            if a == b:
                same += 1
            else:
                FAIL.append("determinism: %r != %r" % (a[:70], b[:70]))
        eq(same, len(norm[0]), "determinism: identical lines")

    print("\n%d checks, %d mismatches" % (NCHECK, len(FAIL)))
    for f in FAIL[:40]:
        print("  MISMATCH", f)
    return 0 if not FAIL else 1


def base_is_ll_storemac(a):
    return (a["a"]["mode"] == "1" and a["a"]["off"] == "0" and
            a["a"]["len"] == "6")


def read_fires(a, door, tag, proto, tci, vlan_dev, in6):
    """Does the read rule match? The bytes are recomputed, not remembered."""
    off = int(a["a"]["off"])
    ln = int(a["a"]["len"])
    base = int(a["a"]["base"])
    imm = bytes.fromhex(a["a"]["imm"])
    if door == "in6":
        if not in6:
            return False
        lay, ip6_at = l3_layout("B", False)   # the tag is gone for good here
    else:
        ETH["vlan_proto"], ETH["vlan_tci"] = proto, tci
        lay, ip6_at = l3_layout("B", proto == b"\x81\x00")
    if base == 1:                             # the network base
        return imm == lay[ip6_at + off:ip6_at + off + ln]
    return imm == lay[off:off + ln]


SOURCE_ANCHORS = [
    ("net/core/dev.c", 6101, "another_round:"),
    ("net/core/dev.c", 6120, "if (eth_type_vlan(skb->protocol)) {"),
    ("net/core/dev.c", 6121, "skb = skb_vlan_untag(skb);"),
    ("net/core/dev.c", 6175, "if (vlan_do_receive(&skb))"),
    ("net/core/dev.c", 6181, "rx_handler = rcu_dereference(skb->dev->rx_handler);"),
    ("net/core/dev.c", 6203, "if (unlikely(skb_vlan_tag_present(skb)) && !netdev_uses_dsa(skb->dev)) {"),
    ("net/core/dev.c", 6207, "if (skb_vlan_tag_get_id(skb)) {"),
    ("net/core/dev.c", 6211, "skb->pkt_type = PACKET_OTHERHOST;"),
    ("net/core/dev.c", 6245, "__vlan_hwaccel_clear_tag(skb);"),
    ("net/core/skbuff.c", 6336, "static struct sk_buff *skb_reorder_vlan_header(struct sk_buff *skb)"),
    ("net/core/skbuff.c", 6347, "if (likely(mac_len > VLAN_HLEN + ETH_TLEN)) {"),
    ("net/core/skbuff.c", 6358, "skb->mac_header += VLAN_HLEN;"),
    ("net/core/skbuff.c", 6383, "skb_pull_rcsum(skb, VLAN_HLEN);"),
    ("net/core/skbuff.c", 6384, "vlan_set_encap_proto(skb, vhdr);"),
    ("net/ipv6/ip6_input.c", 196, "if (skb->pkt_type == PACKET_OTHERHOST) {"),
    ("net/ipv6/ip6_input.c", 197, "dev_core_stats_rx_otherhost_dropped_inc(skb->dev);"),
    ("net/ipv6/ip6_input.c", 206, "__IP6_UPD_PO_STATS(net, idev, IPSTATS_MIB_IN, skb->len);"),
    ("net/netfilter/nft_payload.c", 35, "veth->h_vlan_proto = skb->vlan_proto;"),
    ("net/netfilter/nft_payload.c", 149, "static bool nft_payload_need_vlan_adjust(u32 offset, u32 len)"),
    ("net/netfilter/nft_payload.c", 177, "if (skb_vlan_tag_present(skb) &&"),
    ("net/netfilter/nft_payload.c", 184, "offset = skb_mac_header(skb) - skb->data;"),
    ("net/netfilter/nft_payload.c", 789, "nft_payload_set_vlan(const u32 *src, struct sk_buff *skb, u16 offset, u8 len,"),
    ("net/netfilter/nft_payload.c", 796, "if (offset >= offsetof(struct vlan_ethhdr, h_vlan_encapsulated_proto)) {"),
    ("net/netfilter/nft_payload.c", 819, "skb->vlan_tci = vlan_tci;"),
    ("net/netfilter/nft_payload.c", 1129, "if (!vlan_hlen)"),
    ("net/8021q/vlan_core.c", 18, "vlan_dev = vlan_find_dev(skb->dev, vlan_proto, vlan_id);"),
    ("net/8021q/vlan_core.c", 41, "if (!(vlan_dev_priv(vlan_dev)->flags & VLAN_FLAG_REORDER_HDR) &&"),
    ("net/8021q/vlan_core.c", 61, "__vlan_hwaccel_clear_tag(skb);"),
    ("net/8021q/vlan.c", 276, "vlan->flags = VLAN_FLAG_REORDER_HDR;"),
    ("net/bridge/br_input.c", 352, "const unsigned char *dest = eth_hdr(skb)->h_dest;"),
]

if __name__ == "__main__":
    sys.exit(main())
