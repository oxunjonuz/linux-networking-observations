#!/usr/bin/env python3
"""verify581.py -- independent check of the F59 instrument (differ581, mode `guard`).

No number in findings/F59-three-guards/ is trusted unless this file reproduces
it from the raw log of BOTH boots.

 1. PROVENANCE  -- kernel/initrd sha256 from each log header against the files;
    the differ EXTRACTED from the initramfs (gzip -> cpio -> root/repro) against
    vm/build/differ581.
 2. SOURCE ANCHORS -- every kernel sentence the finding quotes.
 3. FRAMES -- F1..F6 rebuilt in Python (UDPv6/UDPv4 checksums included).
 4. THE ARM TABLE parsed out of the instrument's own source.
 5. EVERY ARM, EVERY BOOT: the guard per door (transcribed from the source), the
    store offset relative to skb->data, the bytes a checksum fixup writes
    (csum_replace4), the logged HWHEADER / L2HDR / PAYLOAD, the counter, the
    probe, the fate counters, the socket, and what the kernel learned from ARP.
 6. THE VALIDATING INGRESS DOOR: two broken frames, with and without `inet`.
 7. DETERMINISM: the two boots must agree on every field.

Usage: python3 tools/verify581.py [log1 [log2]] [-q]
"""

import gzip
import hashlib
import os
import re
import sys

ROOT = "/work/kernel-sec"
KERNEL = os.path.join(ROOT, "src/linux-7.3.4-T563/arch/x86/boot/bzImage")
DIFFER = os.path.join(ROOT, "vm/build/differ581")
SRC = os.path.join(ROOT, "vm/differ581_add.c")
TREE = os.path.join(ROOT, "src/linux-7.3.4-T563")

FAILS = []
CHECKS = [0]


def ck(cond, what, extra=""):
    CHECKS[0] += 1
    if not cond:
        FAILS.append("%s %s" % (what, extra))
    return bool(cond)


def eq(got, want, what):
    return ck(got == want, what, "got=%r want=%r" % (got, want))


# ---------------------------------------------------------------- frames ---

A6_S = bytes.fromhex("fd020000000000000000000000000011")
A6_D = bytes.fromhex("fd020000000000000000000000000091")
BC = b"\xff" * 6
SM = bytes.fromhex("020000000080")
ETH_SRC_ARP = bytes.fromhex("aabbcc000066")
ETH_THA_ARP = bytes.fromhex("222222222222")
IP4_S = bytes([10, 59, 0, 11])
IP4_D = bytes([10, 59, 0, 1])
IP4_Y = bytes([10, 59, 0, 77])
IP4_X = bytes([10, 59, 0, 99])
SPORT, DPORT, PAY = 43580, 5000, 18


def onessum(b):
    s = 0
    for i in range(0, len(b) - 1, 2):
        s += (b[i] << 8) | b[i + 1]
    if len(b) & 1:
        s += b[-1] << 8
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def unfold32(b):
    s = 0
    for i in range(0, len(b) - 1, 2):
        s += (b[i] << 8) | b[i + 1]
    if len(b) & 1:
        s += b[-1] << 8
    return s & 0xffffffff


def fold32(w):
    w &= 0xffffffff
    while w >> 16:
        w = (w & 0xffff) + (w >> 16)
    return w & 0xffff


def csum_replace4(old16, fsum, tsum):
    """net/checksum.h csum_replace4() + nft_csum_replace()'s 0 -> CSUM_MANGLED_0."""
    tmp = ((~old16) & 0xffff) + (~fsum & 0xffffffff) + 1
    new = fold32((tmp & 0xffffffff) + tsum)
    v = (~new) & 0xffff
    return 0xffff if v == 0 else v


def csum16(b):
    return (~onessum(b)) & 0xffff


def mk_udp6(broken=0):
    tot = 8 + PAY
    elen = 8 if broken else 0
    pl = elen if broken else tot
    ip = bytearray(40)
    ip[0] = 0x60
    ip[4] = pl >> 8
    ip[5] = pl & 0xff
    ip[6] = {0: 17, 1: 0, 2: 60}[broken]
    ip[7] = 64
    ip[8:24] = A6_S
    ip[24:40] = A6_D
    f = bytearray(BC + SM + b"\x86\xdd" + bytes(ip))
    if broken:
        return bytes(f + bytes([0x00, 0xff, 0, 0, 0, 0, 0, 0]))
    udp = bytearray(8 + PAY)
    udp[0] = SPORT >> 8
    udp[1] = SPORT & 0xff
    udp[2] = DPORT >> 8
    udp[3] = DPORT & 0xff
    udp[4] = tot >> 8
    udp[5] = tot & 0xff
    udp[8:] = b"\x77" * PAY
    pseudo = A6_S + A6_D + bytes([0, 17, tot >> 8, tot & 0xff])
    c = csum16(pseudo + bytes(udp)) or 0xffff
    udp[6] = c >> 8
    udp[7] = c & 0xff
    return bytes(f + udp)


def mk_udp4(udp_csum=True):
    tot = 8 + PAY
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2] = (20 + tot) >> 8
    ip[3] = (20 + tot) & 0xff
    ip[4] = 0x12
    ip[5] = 0x34
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = IP4_S
    ip[16:20] = IP4_D
    hc = csum16(bytes(ip))
    ip[10] = hc >> 8
    ip[11] = hc & 0xff
    udp = bytearray(8 + PAY)
    udp[0] = SPORT >> 8
    udp[1] = SPORT & 0xff
    udp[2] = DPORT >> 8
    udp[3] = DPORT & 0xff
    udp[4] = tot >> 8
    udp[5] = tot & 0xff
    udp[8:] = b"\x77" * PAY
    if udp_csum:
        pseudo = IP4_S + IP4_D + bytes([0, 17, tot >> 8, tot & 0xff])
        c = csum16(pseudo + bytes(udp)) or 0xffff
        udp[6] = c >> 8
        udp[7] = c & 0xff
    return bytes(BC + SM + b"\x08\x00" + bytes(ip) + bytes(udp))


def mk_arp():
    f = bytearray(BC + ETH_SRC_ARP + b"\x08\x06")
    f += bytes([0, 1, 0x08, 0x00, 6, 4, 0, 1])
    f += SM + IP4_S + ETH_THA_ARP + IP4_D
    f += bytes(max(0, 60 - len(f)))
    return bytes(f)


FRAMES = {1: mk_udp6(0), 2: mk_udp4(True), 3: mk_udp4(False), 4: mk_arp(),
          5: mk_udp6(1), 6: mk_udp6(2)}

# ---------------------------------------------------------------- guards ---

def nh_ok_ip6(off, ln, imm):
    if off == 0:
        return ln <= 4 and (imm[0] >> 4) == 6
    if off == 2:
        return ln <= 2
    if off == 7:
        return ln == 1
    if off == 8:
        return ln <= 32
    if off == 24:
        return ln <= 16
    return False


def nh_ok_ip4(off, ln, imm, frame):
    hdr = frame[14:34]
    if off == 0:
        return ln == 2 and imm[0] == hdr[0]
    if off == 1:
        return ln == 1
    if off == 4:
        return ln == 2
    if off == 8:
        if ln == 1:
            return True
        if ln != 2:
            return False
        return imm[1] == hdr[9]
    if off == 10:
        return ln <= 10
    if off == 12:
        return ln <= 8
    if off == 16:
        return ln <= 4
    return False


def nh_ok_arp(off, ln):
    if off == 6:
        return ln == 2
    return off >= 8 and ln <= 20


def guard(door, base, off, ln, imm, frame):
    if base == 0:
        if door == 0:
            return True                      # nft_in_ingress(): NETDEV+ingress
        return off + ln <= 14
    if base == 1:
        if door == 0:
            return True                      # NF_NETDEV_INGRESS shortcut
        if door == 4:
            return nh_ok_arp(off, ln)
        if door in (1, 2):
            return nh_ok_ip6(off, ln, imm)
        return nh_ok_ip4(off, ln, imm, frame)
    if base == 2:
        return True                          # nft_th_write_ok() is TCP only
    return False


def init_rc(row):
    """nft_payload_set_init() / nft_payload_validate_inet_csum_offset()."""
    if row["ct"] != 1 and not row["cf"]:
        return 0
    if row["cf"] and row["base"] == 0:
        return -22
    if row["ct"] == 1:
        if row["base"] == 0:
            return -22
        if row["base"] == 1 and row["door"] == 3:   # ctx->family == NFPROTO_IPV4
            return 0 if row["co"] == 10 else -22
        if row["base"] == 2:
            if row["cf"]:
                return -22
            return 0 if row["co"] in (6, 16, 2) else -22
    return 0


def base_off(base, frame):
    if base == 0:
        return -14
    if base == 1:
        return 0
    return 40 if len(frame) in (80, 62) else 20


def skb_len(frame):
    return len(frame) - 14


def csum_writes(door, base, off, ln, imm, ct, co, cf, frame):
    """(list of (rel_offset, 2 bytes)) the checksum machinery writes."""
    bo = base_off(base, frame)
    o = bo + off
    out = []
    if ct == 1:
        ok = False
        if base == 1:
            if door in (0, 1, 3, 5) and co == 10:
                ok = True            # pf IPv4 (inet ingress is rewritten to it)
        elif base == 2:
            ok = co == 6             # UDP
        if ok and o + ln <= skb_len(frame):
            at = bo + co
            old = frame[14 + at:14 + at + 2]
            if len(old) == 2:
                v = csum_replace4((old[0] << 8) | old[1],
                                  unfold32(frame[14 + o:14 + o + ln]),
                                  unfold32(imm))
                out.append((at, bytes([v >> 8, v & 0xff])))
    if cf and base in (1, 2):
        if o + ln <= skb_len(frame):
            # nft_payload_l4csum_offset() finds the transport checksum itself
            at = (40 if len(frame) in (80, 62) else 20) + 6
            cur = frame[14 + at:14 + at + 2]
            skip = False
            if base == 2 and cur == b"\x00\x00":
                skip = True          # nft_payload_l4csum_offset(): UDP csum 0
            if not skip and len(cur) == 2:
                v = csum_replace4((cur[0] << 8) | cur[1],
                                  unfold32(frame[14 + o:14 + o + ln]),
                                  unfold32(imm))
                out.append((at, bytes([v >> 8, v & 0xff])))
    return out


def model_arm(row, frame):
    m = {"written": False, "frame": frame}
    if row["store"] and init_rc(row) == 0:
        imm = imm_of(row)
        if guard(row["door"], row["base"], row["off"], row["ln"], imm, frame):
            f = bytearray(frame)
            for (at, val) in csum_writes(row["door"], row["base"], row["off"],
                                         row["ln"], imm, row["ct"], row["co"],
                                         row["cf"], frame):
                f[14 + at:14 + at + 2] = val
            o = base_off(row["base"], frame) + row["off"]
            if o + row["ln"] <= skb_len(frame) and -o <= 14:
                f[14 + o:14 + o + row["ln"]] = imm
                m["written"] = True
                m["frame"] = bytes(f)
    f = m["frame"]
    m["hw"] = f[0:14]
    m["l2"] = f[0:14] if row["door"] == 0 else b""
    m["p"] = f[14:14 + skb_len(frame)]
    return m


def fate_ip6(frame):
    if (frame[14] >> 4) != 6:
        return dict(rcv=0, hdrerr=1, deliv=0, ukproto=0, udp6=0, udperr6=0,
                    sock=0, pnl=0)
    nh = frame[20]
    if nh == 0:
        return dict(rcv=1, hdrerr=1, deliv=0, ukproto=0, udp6=0, udperr6=0,
                    sock=0, pnl=0)
    if nh == 60:
        return dict(rcv=1, hdrerr=1, deliv=0, ukproto=0, udp6=0, udperr6=0,
                    sock=0, pnl=1)
    if nh != 17:
        return dict(rcv=1, hdrerr=0, deliv=0, ukproto=1, udp6=0, udperr6=0,
                    sock=0, pnl=1)
    pseudo = frame[22:54] + bytes([0, 17, frame[18], frame[19]])
    seg = frame[54:54 + ((frame[18] << 8) | frame[19])]
    if (onessum(pseudo + seg) & 0xffff) != 0xffff:
        return dict(rcv=1, hdrerr=0, deliv=1, ukproto=0, udp6=0, udperr6=1,
                    sock=0, pnl=1)
    return dict(rcv=1, hdrerr=0, deliv=1, ukproto=0, udp6=1, udperr6=0,
                sock=1, pnl=1)


def fate_ip4(frame, at_ingress):
    ip = frame[14:34]
    if (ip[0] >> 4) != 4 or (ip[0] & 15) < 5:
        return dict(ipin=1, iphdr=1, ipdeliv=0, u4=0, u4err=0, sock=0)
    hdr_ok = (onessum(ip) & 0xffff) == 0xffff
    if at_ingress and not hdr_ok:
        return dict(ipin=1, iphdr=1, ipdeliv=0, u4=0, u4err=0, sock=0)
    if ip[16:20] != IP4_D:
        return dict(ipin=1, iphdr=0, ipdeliv=0, u4=0, u4err=0, sock=0)
    tot = (ip[2] << 8) | ip[3]
    seg = frame[34:14 + tot]
    chk = (seg[6] << 8) | seg[7]
    if chk:
        pseudo = ip[12:16] + ip[16:20] + bytes([0, 17,
                                                (len(seg) >> 8) & 0xff,
                                                len(seg) & 0xff])
        if (onessum(pseudo + seg) & 0xffff) != 0xffff:
            return dict(ipin=1, iphdr=0, ipdeliv=1, u4=0, u4err=1, sock=0)
    return dict(ipin=1, iphdr=0, ipdeliv=1, u4=1, u4err=0, sock=1)


def fate_arp(frame):
    arp = frame[14:42]
    op = (arp[6] << 8) | arp[7]
    sha = ":".join("%02x" % b for b in arp[8:14])
    spa = arp[14:18]
    tpa = arp[24:28]
    out = {}
    if op == 1 and tpa == IP4_D:
        if spa == IP4_S:
            out["arp11"] = sha
        elif spa == IP4_Y:
            out["arp77"] = sha
    return out

# --------------------------------------------------------------- parsing ---

def parse_arm_table():
    src = open(SRC).read()
    body = src.split("static const struct f581_arm A581[] = {", 1)[1]
    body = body.split("\n};", 1)[0]
    rows = []
    for chunk in re.findall(r"\{[^{}]*\}", body):
        m = re.search(r'"([^"]+)"', chunk)
        if not m:
            continue
        name = m.group(1)
        rest = chunk.replace(m.group(0), "NAME")
        hexstr = None
        hm = re.search(r'"(?:[0-9a-f]{2})+?"', rest)
        if hm:
            hexstr = hm.group(0)[1:-1]
            rest = rest.replace(hm.group(0), "HEX")
        ct = 1 if "NFT_PAYLOAD_CSUM_INET" in rest else 0
        rest = (rest.replace("NFT_PAYLOAD_CSUM_INET", "1")
                    .replace("B581_LL", "0").replace("B581_NH", "1")
                    .replace("B581_TH", "2"))
        nums = [int(x) for x in re.findall(r"\b\d+\b", rest)]
        row = dict(name=name, fid=nums[0], door=nums[1], base=nums[2],
                   store=nums[3], off=nums[4], ln=nums[5], hex=hexstr,
                   ct=ct, co=nums[7] if len(nums) > 7 else 0,
                   cf=nums[8] if len(nums) > 8 else 0)
        rows.append(row)
    return rows


def imm_of(row):
    if not row["ln"]:
        return b""
    if row["hex"]:
        return bytes.fromhex(row["hex"])
    return bytes((0xa0 + i) & 0xff for i in range(row["ln"]))


def kv(line):
    d = {}
    for part in line.strip().split("|")[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v
    return d


def parse_log(path):
    boot = dict(arms={}, bad=[], frmpy={}, env=None, chains=None, vdev=None,
                kernel=None, initrd=None, initrd_path=None, badlog=[])
    for line in open(path, "rb").read().decode("utf-8", "replace").splitlines():
        if line.startswith("### sha256: "):
            boot["kernel"] = line.split()[-1]
        elif line.startswith("### initrd: "):
            boot["initrd_path"] = line.split()[-1]
        elif line.startswith("### initrd sha256: "):
            boot["initrd"] = line.split()[-1]
        elif line.startswith("F581 ARM|"):
            d = kv(line)
            boot["arms"][int(d["i"])] = d
        elif line.startswith("F581 BAD|"):
            boot["bad"].append(kv(line))
        elif line.startswith("F581 FRMPY|"):
            d = kv(line)
            boot["frmpy"][int(d["id"])] = bytes.fromhex(d["hex"])
        elif line.startswith("F581 ENV|"):
            boot["env"] = kv(line)
        elif line.startswith("F581 CHAINS|"):
            boot["chains"] = kv(line)
        elif line.startswith("F581 VDEV|"):
            boot["vdev"] = kv(line)
        elif re.search(r"WARNING:|BUG:|Call Trace", line):
            boot["badlog"].append(line)
    return boot


def differ_from_initramfs(path):
    data = gzip.decompress(open(path, "rb").read())
    off = 0
    while off + 110 <= len(data):
        hdr = data[off:off + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            break
        fields = [int(hdr[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        filesize, namesize = fields[6], fields[11]
        name = data[off + 110:off + 110 + namesize - 1].decode()
        body_at = off + 110 + namesize
        body_at += (-body_at) % 4
        body = data[body_at:body_at + filesize]
        if name == "root/repro":
            return body
        off = body_at + filesize
        off += (-off) % 4
    return None


ANCHORS = [
    ("net/netfilter/nft_payload.c",
     "return s->pf == NFPROTO_NETDEV && s->hook == NF_NETDEV_INGRESS;"),
    ("net/netfilter/nft_payload.c",
     "\tif (nft_in_ingress(pkt->state))\n\t\treturn true;"),
    ("net/netfilter/nft_payload.c",
     "\tcase NFPROTO_NETDEV:\n\t\tif (pkt->state->hook == NF_NETDEV_INGRESS)\n\t\t\treturn true;"),
    ("net/netfilter/nft_payload.c",
     "\tcase offsetof(struct arphdr, ar_op):\n\t\treturn priv->len == 2;"),
    ("net/netfilter/nft_payload.c",
     "\treturn offset >= sizeof(struct arphdr) && priv->len <= eth_ip;"),
    ("net/netfilter/nft_payload.c",
     "\tconst unsigned int eth_ip = 2 * (ETH_ALEN + 4);"),
    ("net/netfilter/nft_payload.c",
     "\tcase offsetof(struct iphdr, check):\n\t\treturn priv->len <= 2 + 4 + 4;"),
    ("net/netfilter/nft_payload.c",
     "\tcase offsetof(struct iphdr, ttl):"),
    ("net/netfilter/nft_payload.c",
     "\tcase NFPROTO_IPV6:\n\t\treturn false;\n\tcase NFPROTO_BRIDGE:"),
    ("net/netfilter/nft_payload.c",
     "if (priv->csum_type == NFT_PAYLOAD_CSUM_INET &&\n\t\t    nft_payload_csum_write_ok(pkt, priv) &&"),
    ("net/netfilter/nft_payload.c",
     "\tcase IPPROTO_UDP:\n\t\tif (!nft_payload_udp_checksum(skb, nft_thoff(pkt)))\n\t\t\treturn -1;"),
    ("net/netfilter/nft_payload.c",
     "\tif (ctx->net->user_ns != &init_user_ns)\n\t\treturn -EPERM;"),
    ("net/netfilter/nft_chain_filter.c",
     "\t\t/* Original hook is NFPROTO_NETDEV and NF_NETDEV_INGRESS. */"),
    ("net/netfilter/core.c",
     "\t\t\terr = __nf_register_net_hook(net, NFPROTO_IPV4, reg);"),
    ("net/ipv6/ip6_input.c", "\tif (hdr->nexthdr == NEXTHDR_HOP) {"),
    ("net/ipv4/arp.c",
     "\t\t\t\tn = neigh_event_ns(&arp_tbl, sha, &sip, dev);"),
    ("include/net/checksum.h",
     "\t__wsum tmp = csum_sub(~csum_unfold(*sum), (__force __wsum)from);"),
]

# ------------------------------------------------------------------ checks --

def check_provenance(boot, tag):
    if not boot.get("env") or not boot.get("kernel") or not boot.get("initrd_path"):
        ck(False, tag + " log has no provenance header / ENV line")
        return False
    ksha = hashlib.sha256(open(KERNEL, "rb").read()).hexdigest()
    eq(boot["kernel"], ksha, tag + " kernel sha256")
    isha = hashlib.sha256(open(boot["initrd_path"], "rb").read()).hexdigest()
    eq(boot["initrd"], isha, tag + " initrd sha256 header vs file")
    ext = differ_from_initramfs(boot["initrd_path"])
    ck(ext is not None, tag + " differ extracted from initramfs")
    if ext is not None:
        eq(hashlib.sha256(ext).hexdigest(),
           hashlib.sha256(open(DIFFER, "rb").read()).hexdigest(),
           tag + " differ in initramfs == built binary")
    eq(boot["env"]["uid"], "0", tag + " root in the initial user ns")
    return True


def check_anchors():
    for path, needle in ANCHORS:
        txt = open(os.path.join(TREE, path), encoding="utf-8",
                   errors="replace").read()
        ck(needle in txt, "anchor %s: %r" % (path, needle[:46]))


def check_arm(boot, i, row, tag):
    d = boot["arms"][i]
    name = row["name"]
    frame = FRAMES[row["fid"]]
    imm = imm_of(row)
    eq(d["name"], name, "%s arm %d name" % (tag, i))
    # the row's printed parameters must be the ones the source table declares
    for fld in ("fid", "door", "base", "store", "off", "len", "ct", "co", "cf"):
        eq(int(d[fld]), row["ln" if fld == "len" else fld],
           "%s %s printed %s" % (tag, name, fld))
    eq(int(d["flen"]), len(frame), "%s %s flen" % (tag, name))
    eq(int(d["snd"]), len(frame), "%s %s sent" % (tag, name))
    if row["store"]:
        eq(d["hex"], imm.hex(), "%s %s immediate" % (tag, name))
    eq(int(d["rc"]), init_rc(row), "%s %s rule load" % (tag, name))
    installed = init_rc(row) == 0
    eq(int(d["ch"]), 1 if installed else 0, "%s %s counter" % (tag, name))
    m = model_arm(row, frame)
    logged = m["written"] or not row["store"]
    eq(int(d["nl"]), 1 if logged else 0, "%s %s log message" % (tag, name))
    if logged:
        eq(d["pre"], "59:%02d" % i, "%s %s prefix" % (tag, name))
        eq(d["hw"], m["hw"].hex(), "%s %s HWHEADER" % (tag, name))
        eq(d["l2"], m["l2"].hex(), "%s %s L2HDR" % (tag, name))
        eq(d["p"], m["p"].hex(), "%s %s PAYLOAD" % (tag, name))
        eq(d["indev"], boot["env"]["x1"] + ":x1", "%s %s indev" % (tag, name))
        eq(d["vlan"], "none", "%s %s no VLAN nest" % (tag, name))
    else:
        eq(d["pre"], "-", "%s %s no prefix" % (tag, name))
    if row["fid"] in (1, 5, 6):
        w = fate_ip6(m["frame"])
        for k, f in (("rcv", "Ip6InReceives"), ("hdrerr", "Ip6InHdrErrors"),
                     ("deliv", "Ip6InDelivers"),
                     ("ukproto", "Ip6InUnknownProtos"),
                     ("udp6", "Udp6InDatagrams"), ("udperr6", "Udp6InErrors")):
            eq(int(d[k]), w[k], "%s %s %s" % (tag, name, f))
        eq(int(d["u6n"]), w["sock"], "%s %s udp6 socket" % (tag, name))
        eq(int(d["u6l"]), 18 if w["sock"] else -1,
           "%s %s udp6 datagram length" % (tag, name))
        eq(int(d["trunc"]), 0, "%s %s Ip6InTruncatedPkts" % (tag, name))
        eq(int(d["pnl"]), w["pnl"], "%s %s prerouting probe" % (tag, name))
        if w["pnl"]:
            eq(d["pindev"], boot["env"]["x1"] + ":x1",
               "%s %s probe indev" % (tag, name))
    elif row["fid"] in (2, 3):
        w = fate_ip4(m["frame"], row["door"] in (0, 1))
        for k, f in (("ipin", "IpInReceives"), ("iphdr", "IpInHdrErrors"),
                     ("ipdeliv", "IpInDelivers"), ("u4", "UdpInDatagrams"),
                     ("u4err", "UdpInErrors")):
            eq(int(d[k]), w[k], "%s %s %s" % (tag, name, f))
        eq(int(d["u4n"]), w["sock"], "%s %s udp4 socket" % (tag, name))
        eq(int(d["u4l"]), 18 if w["sock"] else -1,
           "%s %s udp4 datagram length" % (tag, name))
        eq(int(d["pnl"]), 0, "%s %s no ipv6 probe" % (tag, name))
    else:
        w = fate_arp(m["frame"])
        for k in ("arp11", "arp77", "arp99"):
            eq(d[k], w.get(k, "-"), "%s %s %s" % (tag, name, k))


def check_bad(boot, tag):
    eq(len(boot["bad"]), 4, tag + " four BAD rows")
    for r in boot["bad"]:
        fid = int(r["fid"])
        present = r["stage"] == "inet_present"
        eq(int(r["snd"]), len(FRAMES[fid]), "%s BAD f%d sent" % (tag, fid))
        eq(int(r["ch"]), 1, "%s BAD f%d netdev counter" % (tag, fid))
        want_pnl = 0 if (fid == 5 or present) else 1
        eq(int(r["pnl"]), want_pnl, "%s BAD f%d prerouting probe" % (tag, fid))
        eq(int(r["rcv"]), 0 if present else 1,
           "%s BAD f%d Ip6InReceives" % (tag, fid))
        eq(int(r["hdrerr"]), 1, "%s BAD f%d Ip6InHdrErrors" % (tag, fid))
        eq(int(r["deliv"]), 0, "%s BAD f%d delivers nothing" % (tag, fid))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    log1 = args[0] if args else os.path.join(ROOT, "logs/f59_rep1.log")
    log2 = args[1] if len(args) > 1 else os.path.join(ROOT, "logs/f59_rep2.log")
    for lg in (log1, log2):
        if not os.path.exists(lg):
            print("log not found: %s" % lg)
            return 1
    b1 = parse_log(log1)
    b2 = parse_log(log2) if log2 != log1 else None
    ok1 = check_provenance(b1, "rep1")
    ok2 = check_provenance(b2, "rep2") if b2 else ok1
    if not (ok1 and ok2):
        print("checks=%d fails=%d (no usable log)" % (CHECKS[0], len(FAILS)))
        for f in FAILS[:10]:
            print("  FAIL " + f)
        return 1
    check_anchors()
    rows = parse_arm_table()
    eq(len(rows), 63, "arm table parsed out of the instrument source")
    for tag, boot in (("rep1", b1), ("rep2", b2)):
        if not boot:
            continue
        eq(int(boot["chains"]["rc"]), 0, tag + " chains installed")
        eq(len(boot["arms"]), len(rows), tag + " every arm has a row")
        for i, row in enumerate(rows):
            if i in boot["arms"]:
                check_arm(boot, i, row, tag)
            else:
                ck(False, "%s arm %d missing" % (tag, i), row["name"])
        for fid, want in FRAMES.items():
            eq(boot["frmpy"].get(fid), want, "%s FRMPY %d" % (tag, fid))
        check_bad(boot, tag)
        ck(not boot["badlog"], tag + " no kernel warning",
           str(boot["badlog"][:2]))
    if b2:
        for i in sorted(set(b1["arms"]) & set(b2["arms"])):
            d1, d2 = b1["arms"][i], b2["arms"][i]
            if d1 != d2:
                for k in sorted(set(d1) | set(d2)):
                    if d1.get(k) != d2.get(k):
                        FAILS.append("determinism arm %d %s: %r vs %r"
                                     % (i, k, d1.get(k), d2.get(k)))
        eq(b1["bad"], b2["bad"], "determinism of the BAD section")
    print("checks=%d fails=%d" % (CHECKS[0], len(FAILS)))
    for f in FAILS[:80]:
        print("  FAIL " + f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
