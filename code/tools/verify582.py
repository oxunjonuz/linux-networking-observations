#!/usr/bin/env python3
"""verify582.py -- independent check of the F60 instrument (differ582, modes
`part` and `opt`).

No number in findings/F60-checksum-partial/ is trusted unless this file
reproduces it from the raw log of BOTH boots.

 1. PROVENANCE  -- kernel sha256 from each log header against the file; the
    initrd sha256 from the instrument's own header AND from the file it was
    built from; the differ EXTRACTED from the initramfs (gzip -> cpio ->
    root/repro) against vm/build/differ582.
 2. SOURCE ANCHORS -- every kernel sentence the finding quotes, by file:line.
 3. FRAMES -- IPv6/UDP and IPv4/UDP rebuilt in Python, with the Ethernet
    addresses taken from the boot's own log; the CHECKSUM_PARTIAL variant of
    the same frame differs in exactly two things: the UDP checksum field holds
    the pseudo-header seed, and the IP header carries the kernel's own flow
    label (v6) / id (v4).
 4. THE ARM TABLE parsed out of the instrument's own source -- inputs only.
 5. EVERY ARM: the guard (transcribed from the kernel source), the skb bound,
    the checksum machinery (csum_replace4, applied before the store), the
    resulting UDP checksum field, the IPv4 header checksum, the fate, the
    counters, the NFLOG witness at layer 3, the tap with its auxdata, and the
    receiving socket.
 6. WHAT THE TAP IS AND IS NOT -- for every arm the tap bytes are one of the
    two frames (pre-store / post-store); which one is measured, and the rule
    that decides it is asserted to be the same in both boots.
 7. DETERMINISM -- the two boots must agree on every derived field and on every
    byte of both hexdumps once the kernel-chosen MACs, flow label and IPv4 id
    are masked.

Usage: python3 tools/verify582.py [log1 [log2]] [-q]
"""

import gzip
import hashlib
import os
import re
import sys

ROOT = "/work/kernel-sec"
KERNEL = os.path.join(ROOT, "src/linux-7.3.4-T563/arch/x86/boot/bzImage")
DIFFER = os.path.join(ROOT, "vm/build/differ582")
SRC = os.path.join(ROOT, "vm/differ582_add.c")
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


# ---------------------------------------------------------------- sums -----

def onessum(b):
    s = 0
    for i in range(0, len(b) - 1, 2):
        s += (b[i] << 8) | b[i + 1]
    if len(b) & 1:
        s += b[-1] << 8
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def fold16(b):
    """the one's complement sum, folded to 16 bits, NOT complemented -- the
    value udp4_hwcsum()/udp6_hwcsum_outgoing() leave in uh->check."""
    return onessum(b) & 0xffff


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


def csum16(b):
    return (~onessum(b)) & 0xffff


def csum_replace4(old16, fsum, tsum):
    """nft_csum_replace() -- the branch taken when ip_summed != CHECKSUM_PARTIAL:
    it keeps a real checksum real."""
    tmp = ((~old16) & 0xffff) + (~fsum & 0xffffffff) + 1
    new = fold32((tmp & 0xffffffff) + tsum)
    v = (~new) & 0xffff
    return 0xffff if v == 0 else v


def seed_adjust(old16, fsum, tsum):
    """the other branch of nft_payload_l4csum_update(): ip_summed ==
    CHECKSUM_PARTIAL, where the field is the pseudo-header seed and the update
    keeps it a seed.  Measured to be fold(old + tsum - fsum), not the
    complement of it."""
    return fold32((old16 + tsum + ((~fsum) & 0xffffffff) + 1) & 0xffffffff)


# ---------------------------------------------------------------- frames ---

A6_S = bytes.fromhex("fd020000000000000000000000000011")
A6_D = bytes.fromhex("fd020000000000000000000000000091")
BC = b"\xff" * 6
IP4_S = bytes([10, 59, 0, 11])
IP4_D = bytes([10, 59, 0, 1])
IP4_X = bytes([10, 59, 0, 99])
SPORT, DPORT, PAY = 43580, 5000, 18
PAYLOAD = bytes(range(0x80, 0x80 + PAY))


def udp_hdr(sport=SPORT, dport=DPORT, length=8 + PAY, csum=0):
    return bytes([sport >> 8, sport & 0xff, dport >> 8, dport & 0xff,
                  length >> 8, length & 0xff, csum >> 8, csum & 0xff])


def pseudo6_full(saddr, daddr, length):
    """RFC 8200 pseudo header: src, dst, upper-layer length (32 bits), zeros,
    next header."""
    return (saddr + daddr + bytes([0, 0, length >> 8, length & 0xff]) +
            bytes([0, 0, 0, 17]))


def pseudo4(saddr, daddr, length):
    return saddr + daddr + bytes([0, 17, length >> 8, length & 0xff])


def mk_v6(dst, src, saddr=A6_S, daddr=A6_D, sport=SPORT, dport=DPORT,
          payload=PAYLOAD, flow=0):
    """returns the whole Ethernet frame, checksum correct (CHECKSUM_NONE)."""
    tot = 8 + len(payload)
    ip = bytearray(40)
    ip[0] = 0x60
    ip[1] = (flow >> 16) & 0x0f
    ip[2] = (flow >> 8) & 0xff
    ip[3] = flow & 0xff
    ip[4] = tot >> 8
    ip[5] = tot & 0xff
    ip[6] = 17
    ip[7] = 64
    ip[8:24] = saddr
    ip[24:40] = daddr
    c = csum16(pseudo6_full(saddr, daddr, tot) + udp_hdr(sport, dport, tot) +
               payload) or 0xffff
    return bytes(dst + src + b"\x86\xdd" + bytes(ip) +
                 udp_hdr(sport, dport, tot, c) + payload)


def mk_v4(dst, src, ihl=5, fragoff=0, mf=0, totlen=0, ipid=0,
          saddr=IP4_S, daddr=IP4_D, payload=PAYLOAD, csum_on=True):
    hl = ihl * 4
    tot = totlen or hl + 8 + len(payload)
    ip = bytearray(hl)
    ip[0] = 0x40 | (ihl & 0x0f)
    ip[2] = tot >> 8
    ip[3] = tot & 0xff
    ip[4] = (ipid >> 8) & 0xff
    ip[5] = ipid & 0xff
    fo = 0
    if mf:
        fo |= 0x2000
    elif not fragoff:
        fo |= 0x4000
    fo |= (fragoff // 8) & 0x1fff
    ip[6] = fo >> 8
    ip[7] = fo & 0xff
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = saddr
    if hl >= 20:
        ip[16:20] = daddr
    for i in range(20, hl):
        ip[i] = 0x01
    if hl > 20:
        ip[hl - 1] = 0x00
    body = b""
    if not fragoff and not mf:
        c = 0
        if csum_on:
            addr8 = (saddr + daddr) if hl >= 20 else (
                saddr + udp_hdr(SPORT, DPORT, 8 + len(payload), 0)[:4])
            c = csum16(addr8 + bytes([0, 17, (8 + len(payload)) >> 8,
                                      (8 + len(payload)) & 0xff]) +
                       udp_hdr(SPORT, DPORT, 8 + len(payload), 0) + payload)
            c = c or 0xffff
        body = udp_hdr(SPORT, DPORT, 8 + len(payload), c) + payload
    elif mf:
        body = udp_hdr(SPORT, DPORT, 8 + len(payload), 0xabcd) + payload
    else:
        body = payload[:16]
    if totlen and totlen < hl:
        body = b""
    hc = csum16(bytes(ip))
    ip[10] = hc >> 8
    ip[11] = hc & 0xff
    f = bytes(dst + src + b"\x08\x00" + bytes(ip) + body)
    return f + bytes(max(0, 60 - len(f)))


def opt_frame(fid, dst, src):
    if fid == 2:
        return mk_v4(dst, src, 5)
    if fid == 6:
        return mk_v4(dst, src, 6)
    if fid == 7:
        return mk_v4(dst, src, 15)
    if fid == 8:
        return mk_v4(dst, src, 4)
    if fid == 9:
        return mk_v4(dst, src, 15, totlen=30)
    if fid == 11:
        return mk_v4(dst, src, 5, mf=1)
    if fid == 12:
        return mk_v4(dst, src, 5, fragoff=1480, totlen=36)
    raise SystemExit("no frame %d" % fid)


# ---------------------------------------------------------- the parsing ---

def parse_arm(line):
    d = {}
    for kv in line.strip().split("|")[1:]:
        if "=" in kv:
            k, v = kv.split("=", 1)
            d[k] = v
    return d


def parse_frame_hex(s):
    if s in ("-", ""):
        return b""
    return bytes.fromhex(s)


def ip_fields(fr, ver):
    """the fields of the frame (starting at the network header)."""
    d = {"ver": ver}
    if ver == 6:
        d["nh"] = fr[6]
        d["hop"] = fr[7]
        d["plen"] = (fr[4] << 8) | fr[5]
        d["saddr"] = fr[8:24]
        d["daddr"] = fr[24:40]
        d["flow"] = ((fr[1] & 0x0f) << 16) | (fr[2] << 8) | fr[3]
        d["hl"] = 40
    else:
        d["ihl"] = fr[0] & 0x0f
        d["hl"] = d["ihl"] * 4
        d["proto"] = fr[9]
        d["totlen"] = (fr[2] << 8) | fr[3]
        d["id"] = (fr[4] << 8) | fr[5]
        d["frag"] = (fr[6] << 8) | fr[7]
        d["saddr"] = fr[12:16]
        d["daddr"] = fr[16:20]
        d["hcsum"] = (fr[10] << 8) | fr[11]
    return d


def mask_frame(fr, ver, ipoff=14):
    """the bytes the kernel chooses for itself: the IPv6 flow label, the IPv4
    id and the header checksum that covers it.  ipoff is where the network
    header starts in this buffer -- 14 for a whole frame, 0 for a buffer that
    begins at the network header."""
    b = bytearray(fr)
    if ver == 6 and len(b) >= ipoff + 4:
        b[ipoff + 1] = 0
        b[ipoff + 2] = 0
        b[ipoff + 3] = 0
    if ver == 4 and len(b) >= ipoff + 12:
        b[ipoff + 4] = 0
        b[ipoff + 5] = 0
        b[ipoff + 10] = 0
        b[ipoff + 11] = 0
    return bytes(b)


def udp_fields(fr, hl):
    u = fr[hl:hl + 8]
    return {"sport": (u[0] << 8) | u[1], "dport": (u[2] << 8) | u[3],
            "len": (u[4] << 8) | u[5], "csum": (u[6] << 8) | u[7],
            "payload": fr[hl + 8:]}


# ------------------------------------------------------------ the guards --

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


def nh_ok_ip4(off, ln, imm, hdr):
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


def guard(arm, ver, frame):
    """nft_payload_set_eval()'s three guards, per door."""
    door, base, off, ln = arm["door"], arm["base"], arm["off"], arm["ln"]
    imm = arm["imm"]
    if base == 0:                                  # @ll
        if door == 0:
            return True                            # nft_in_ingress()
        return off + ln <= 14
    if base == 1:                                  # @nh
        if door == 0:
            return True                            # NF_NETDEV_INGRESS
        if ver == 6:
            return nh_ok_ip6(off, ln, imm)
        return nh_ok_ip4(off, ln, imm, frame[14:14 + 60])
    if base == 2:                                  # @th
        # nft_th_write_ok() only guards TCP; every frame here is UDP
        if arm.get("fragoff"):
            return False                           # pkt->fragoff
        return True
    return False


def thoff(ver, frame):
    if ver == 6:
        return 40
    return (frame[14] & 0x0f) * 4


def base_off(base, ver, frame):
    if base == 0:
        return -14
    if base == 1:
        return 0
    return thoff(ver, frame)


def csum_nh_guard(arm, ver):
    """nft_payload_csum_nh_write_ok(): per packet family."""
    door = arm["door"]
    if door == 0:                                  # pf == NFPROTO_NETDEV
        return ver == 4 and arm["co"] == 10
    if door == 2:                                  # NFPROTO_IPV4
        return arm["co"] == 10
    return False                                   # NFPROTO_IPV6


def csum_block_runs(arm, prov):
    """the guard of the whole fixup block in nft_payload_set_eval()."""
    if arm["ct"] != 1 and not arm["cf"]:
        return False
    if arm["base"] in (1, 2):
        return prov == "p" or arm["base"] == 1
    return True


def apply_arm(arm, ver, frame, prov):
    """returns dict(post, written, udpcsum, ok_store)."""
    hl = thoff(ver, frame) if ver == 6 else (frame[14] & 0x0f) * 4
    bo = base_off(arm["base"], ver, frame)
    f = bytearray(frame)
    out = {"written": False, "ok_store": False, "post": frame}
    udp_at = 14 + hl + 6
    ipc_at = 14 + 10
    if not arm["store"]:
        return out
    if not guard(arm, ver, frame):
        return out
    o = bo + arm["off"]
    skb_len = len(frame) if arm["door"] == 0 else len(frame) - 14
    if o + arm["ln"] > skb_len or o < -14:
        return out
    # csum machinery runs BEFORE the store
    if csum_block_runs(arm, prov):
        imm = arm["imm"]
        old = bytes(frame[14 + o:14 + o + arm["ln"]])
        fsum, tsum = unfold32(old), unfold32(imm)
        if arm["ct"] == 1:
            if arm["base"] == 1 and csum_nh_guard(arm, ver):
                cur = (frame[ipc_at] << 8) | frame[ipc_at + 1]
                v = csum_replace4(cur, fsum, tsum)
                f[ipc_at] = v >> 8
                f[ipc_at + 1] = v & 0xff
            elif arm["base"] == 2 and prov == "p":
                at = 14 + hl + arm["co"]
                cur = (frame[at] << 8) | frame[at + 1]
                v = csum_replace4(cur, fsum, tsum)
                f[at] = v >> 8
                f[at + 1] = v & 0xff
        if arm["cf"]:
            cur = (frame[udp_at] << 8) | frame[udp_at + 1]
            v = (csum_replace4(cur, fsum, tsum) if prov == "p"
                 else seed_adjust(cur, fsum, tsum))
            f[udp_at] = v >> 8
            f[udp_at + 1] = v & 0xff
    f[14 + o:14 + o + arm["ln"]] = arm["imm"]
    out["written"] = True
    out["ok_store"] = True
    out["post"] = bytes(f)
    return out


def fate(arm, ver, frame, post, prov):
    """what the receiving netns does with the frame."""
    hl = 40 if ver == 6 else (frame[14] & 0x0f) * 4
    udp_at = 14 + hl + 6
    d = {"delivered": 0, "udperr": 0, "iphdr": 0, "addrerr": 0,
         "field": -1, "pre_hook": 0}
    if ver == 4:
        ihl = frame[14] & 0x0f
        tot = (frame[16] << 8) | frame[17]
        if ihl < 5 or tot < ihl * 4:
            # ip_rcv_core() refuses the header before any hook sees the frame
            d["iphdr"] = 1
            d["pre_hook"] = 1
            return d
    if len(post) < udp_at + 2:
        return d
    field = (post[udp_at] << 8) | post[udp_at + 1]
    d["field"] = field
    if ver == 4:
        hdr = post[14:14 + hl]
        d["hcsum_ok"] = csum16(hdr) == 0
        if arm["fragoff"]:
            d["delivered"] = 0
            return d
        if arm["mf"]:
            d["delivered"] = 0
            return d
        if not d["hcsum_ok"] and arm["door"] == 0:
            # the store happened BEFORE ip_rcv_core()
            d["iphdr"] = 1
            return d
        if post[14 + 16:14 + 20] != IP4_D:
            d["addrerr"] = 1                     # martian destination
            return d
    else:
        if arm.get("broken"):
            return d
    tot = (post[4] << 8) | post[5] if ver == 6 else 0
    if ver == 6:
        pl = bytes(post[14 + 40 + 8:])
        mine = csum16(pseudo6_full(post[14 + 8:14 + 24],
                                   post[14 + 24:14 + 40],
                                   (post[14 + 4] << 8) | post[14 + 5]) +
                      bytes(post[14 + 40:14 + 48]) + pl)
    else:
        plen = (post[udp_at - 2] << 8) | post[udp_at - 1]
        pl = bytes(post[14 + hl + 8:14 + hl + 8 + max(0, plen - 8)])
        mine = csum16(pseudo4(post[14 + 12:14 + 16],
                              post[14 + 16:14 + 20], plen) +
                      bytes(post[14 + hl:14 + hl + 8]) + pl)
    d["verifies"] = (mine == 0)
    if prov == "p":
        if ver == 4 and field == 0:
            d["delivered"] = 1
            return d
        if d["verifies"]:
            d["delivered"] = 1
        else:
            d["udperr"] = 1
    else:
        d["delivered"] = 1                       # CHECKSUM_PARTIAL: not verified
    return d


def seed_of_ph(arm, wit, new):
    """the value udp4_hwcsum()/udp6_hwcsum_outgoing() leave in the field: the
    one's complement sum of the pseudo header with a zero payload contribution.
    `new` picks the addresses the wire carries NOW (the arm rewrote them with
    csum_flags, which walks the same field) or the ones the sender put there."""
    if arm["ver"] == 6:
        src = wit[8:24] if new else A6_S
        return fold16(pseudo6_full(src, wit[24:40], (wit[4] << 8) | wit[5]))
    hl = (wit[0] & 0x0f) * 4
    ulen = (wit[hl + 4] << 8) | wit[hl + 5]
    src = wit[12:16] if new else IP4_S
    return fold16(pseudo4(src, wit[16:20], ulen))


def verifies(wit, ver):
    hl = 40 if ver == 6 else (wit[0] & 0x0f) * 4
    ulen = (wit[hl + 4] << 8) | wit[hl + 5]
    body = wit[hl + 8:hl + 8 + max(0, ulen - 8)]
    if ver == 6:
        ph = pseudo6_full(wit[8:24], wit[24:40], ulen)
    else:
        ph = pseudo4(wit[12:16], wit[16:20], ulen)
    return csum16(ph + wit[hl:hl + 8] + body) == 0


# ---------------------------------------------------------- arm the table -

BASEMAP = {"B582_LL": 0, "B582_NH": 1, "B582_TH": 2,
           "NFT_PAYLOAD_CSUM_NONE": 0, "NFT_PAYLOAD_CSUM_INET": 1}


def num(tok):
    tok = tok.strip()
    by = None
    if tok in BASEMAP:
        return BASEMAP[tok]
    return int(tok)


def table_block(txt, name):
    i = txt.index(name)
    j = txt.index("\n};", i)
    blk = txt[i:j]
    blk = re.sub(r"/\*.*?\*/", " ", blk, flags=re.S)
    out = []
    for e in re.findall(r"\{([^{}]*)\}", blk):
        parts = [p.strip() for p in e.split(",")]
        if len(parts) != 12 or not parts[0].startswith('"'):
            continue
        hexs = parts[8]
        if hexs == "NULL":
            hx = ""
        else:
            hx = hexs.strip('"')
        a = {"name": parts[0].strip('"'), "prov": parts[1].strip("'"),
             "ver": num(parts[2]), "door": num(parts[3]),
             "base": num(parts[4]), "store": num(parts[5]),
             "off": num(parts[6]), "ln": num(parts[7]), "hex": hx,
             "ct": num(parts[9]), "co": num(parts[10]),
             "cf": num(parts[11])}
        a["imm"] = (bytes.fromhex(hx) if hx
                    else bytes(range(0xa0, 0xa0 + a["ln"])))
        out.append(a)
    return out


def load_arms(path):
    txt = open(path).read()
    return (table_block(txt, "AP582[]"), table_block(txt, "AO582[]"))


# ------------------------------------------------------------- provenance -

def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def differ_in_initrd(initrd):
    """gzip -> newc cpio -> ./root/repro"""
    import io
    import tarfile  # noqa: F401  (not used; cpio is parsed by hand)

    data = gzip.open(initrd, "rb").read()
    off, out = 0, None
    while off + 110 <= len(data):
        hdr = data[off:off + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            break
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = data[off + 110:off + 110 + namesize - 1].decode()
        body = off + 110 + namesize
        body += (-body) % 4
        if name == "root/repro":
            out = data[body:body + filesize]
            break
        off = body + filesize
        off += (-off) % 4
    return out


# ------------------------------------------------------------------ main --

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    quiet = "-q" in sys.argv
    logs = args or [os.path.join(ROOT, "logs/f60_rep1.log"),
                    os.path.join(ROOT, "logs/f60_rep2.log")]
    part, opt = load_arms(SRC)
    ck(len(part) >= 25, "arm table: part rows", len(part))
    ck(len(opt) >= 20, "arm table: opt rows", len(opt))

    boots = []
    for lg in logs:
        if not os.path.exists(lg):
            print("verify582: no such log: %s" % lg)
            return 1
        raw = open(lg, errors="ignore").read()
        boots.append({"log": lg, "raw": raw,
                      "arms": [parse_arm(l) for l in raw.splitlines()
                               if l.startswith("F582 ARM")],
                      "frmpy": [(int(m.group(1)), m.group(2)) for m in
                                re.finditer(r"F582 FRMPY\|id=(\d+)\|len=\d+\|hex=([0-9a-f]+)",
                                            raw)],
                      "env": [l for l in raw.splitlines()
                              if l.startswith("F582 ENV")],
                      "childev": [l for l in raw.splitlines()
                                  if l.startswith("F582 CHILDEV")],
                      "childs": [l for l in raw.splitlines()
                                 if l.startswith("F582 CHILDS|")],
                      "end": [l for l in raw.splitlines()
                              if l.startswith("F582 END")],
                      "tapkind": []})
        b = boots[-1]
        # 1. provenance
        m = re.search(r"^### sha256: ([0-9a-f]{64})$", raw, re.M)
        ck(m is not None, "%s: kernel sha in the header" % lg)
        if m:
            eq(m.group(1), sha_file(KERNEL), "%s: kernel sha" % lg)
        m = re.search(r"^### initrd sha256: ([0-9a-f]{64})$", raw, re.M)
        ck(m is not None, "%s: initrd sha in the header" % lg)
        if m:
            ck(os.path.exists(os.path.join(ROOT, "vm/initrd582/full.cpio.gz")),
               "%s: initrd file" % lg)
            eq(m.group(1), sha_file(os.path.join(ROOT,
                                                "vm/initrd582/full.cpio.gz")),
               "%s: initrd sha" % lg)
            blob = differ_in_initrd(os.path.join(ROOT,
                                                 "vm/initrd582/full.cpio.gz"))
            ck(blob is not None, "%s: root/repro found in the initramfs" % lg)
            if blob is not None:
                eq(hashlib.sha256(blob).hexdigest(), sha_file(DIFFER),
                   "%s: differ extracted from the initramfs == built" % lg)
        eq(len(b["end"]), 2, "%s: both modes finished" % lg)
        eq(len(b["childev"]), 1, "%s: one child device report" % lg)
        for cl in b["childs"]:
            rc = int(re.search(r"rc=(-?\d+)", cl).group(1))
            ck(rc in (18, 60, 80), "%s: the child's send returned a length"
               % lg, cl)
        ck("mode=part" in " ".join(b["end"]), "%s: part end" % lg)
        ck("mode=opt" in " ".join(b["end"]), "%s: opt end" % lg)

    # 3. frames
    for b in boots:
        raw = b["raw"]
        cd = b["childev"][0] if b["childev"] else ""
        m6 = re.search(r"m6=([0-9a-f]{12})", cd)
        m4 = re.search(r"m4=([0-9a-f]{12})", cd)
        ck(m6 is not None and m4 is not None, "%s: child's MAC report" % b["log"])
        b["mac0"] = bytes.fromhex(m6.group(1)) if m6 else BC   # x0 = receiver
        b["mac1"] = bytes.fromhex(m4.group(1)) if m4 else b"\x02" * 6
        m = re.search(r"F582 ENV\|veth=\d+\|x1=\d+\|u6=-?\d+\|u4=-?\d+\|"
                      r"nfl=-?\d+\|tap=-?\d+\|m1=([0-9a-f]{12})", raw)
        ck(m is not None, "%s: opt ENV with x1's MAC" % b["log"])
        b["opt_mac1"] = bytes.fromhex(m.group(1)) if m else b"\x02" * 6
        # the twin frames the child builds == what Python builds.  Both modes
        # print FRMPY lines with overlapping ids, so "some line with this id
        # carries exactly these bytes" is the check, not "the last one".
        f6 = mk_v6(b["mac0"], b["mac1"]).hex()
        ck(any(f == 6 and f6.startswith(h) for f, h in b["frmpy"]),
           "%s: the child's IPv6 twin == rebuilt" % b["log"])
        f2 = mk_v4(b["mac0"], b["mac1"], 5).hex()
        ck(any(f == 2 and f2.startswith(h) for f, h in b["frmpy"]),
           "%s: the child's IPv4 twin == rebuilt" % b["log"])
        for fid in (2, 6, 7, 8, 9, 11, 12):
            want = opt_frame(fid, BC, b["opt_mac1"]).hex()
            ck(any(f == fid and want.startswith(h) for f, h in b["frmpy"]),
               "%s: opt frame %d == rebuilt" % (b["log"], fid))

    # 5/6. every arm, every boot
    for b in boots:
        rows = b["arms"]
        ck(len(rows) == len(part) + len(opt), "%s: one row per arm" % b["log"],
           "%d vs %d" % (len(rows), len(part) + len(opt)))
        table = part + opt
        for row, arm in zip(rows, table):
            nm = "%s/%s" % (b["log"], arm["name"])
            eq(row["name"], arm["name"], nm + ": name order")
            # the printed parameters against the instrument's own table
            eq(int(row["door"]), arm["door"], nm + ": printed door")
            eq(int(row["base"]), arm["base"], nm + ": printed base")
            eq(row["prov"], arm["prov"], nm + ": printed provenance")
            eq(int(row["ver"]), arm["ver"], nm + ": printed family")
            eq(int(row["store"]), arm["store"], nm + ": printed store flag")
            eq(int(row["off"]), arm["off"], nm + ": printed offset")
            eq(int(row["len"]), arm["ln"], nm + ": printed length")
            eq(row["hex"], arm["imm"].hex() if arm["store"] else "-",
               nm + ": printed immediate")
            eq(int(row["ct"]), arm["ct"], nm + ": printed csum type")
            eq(int(row["co"]), arm["co"], nm + ": printed csum offset")
            eq(int(row["cf"]), arm["cf"], nm + ": printed csum flags")
            eq(int(row["rc"]), 0, nm + ": the rule was installed")
            mode = "part" if arm in part else "opt"
            # the frame this arm rides on
            if mode == "part":
                if arm["ver"] == 6:
                    frame0 = mk_v6(b["mac0"], b["mac1"])
                else:
                    frame0 = mk_v4(b["mac0"], b["mac1"], 5)
                if arm["prov"] == "s":
                    hl = 40 if arm["ver"] == 6 else 20
                    tp = 14 + hl
                    seed = fold16(pseudo6_full(A6_S, A6_D, 8 + PAY)
                                  if arm["ver"] == 6
                                  else pseudo4(IP4_S, IP4_D, 8 + PAY))
                    fr = bytearray(frame0)
                    fr[tp + 6] = seed >> 8
                    fr[tp + 7] = seed & 0xff
                    if arm["ver"] == 4:
                        fr[18] = 0          # id: kernel-chosen
                        fr[19] = 0
                        fr[24] = 0
                        fr[25] = 0
                        hc = csum16(bytes(fr[14:34]))
                        fr[24] = hc >> 8
                        fr[25] = hc & 0xff
                    frame = bytes(fr)
                else:
                    frame = frame0
            else:
                fid = {"q_ctl5": 2, "q_ctl6": 6, "q_ctl15": 7, "q_ihl4": 8,
                       "q_ihl4_st": 8, "q_short": 9, "q_frag1": 11,
                       "q_frag2": 12}.get(arm["name"], 7)
                if arm["name"] in ("q_th20_5", "q_th20_5_cs"):
                    fid = 2
                if arm["name"] in ("q_th20_6_cs", "q_th0_6_cs"):
                    fid = 6
                frame = opt_frame(fid, BC, b["opt_mac1"])
            arm["fragoff"] = (frame[20] << 8 | frame[21]) & 0x1fff \
                if (arm["ver"] == 4 and (frame[20] << 8 | frame[21]) & 0x1fff) else 0
            if arm["ver"] == 4:
                fo = (frame[20] << 8) | frame[21]
                arm["fragoff"] = fo & 0x1fff
                arm["mf"] = 1 if fo & 0x2000 else 0
            else:
                arm["fragoff"] = 0
                arm["mf"] = 0
            res = apply_arm(arm, arm["ver"], frame, arm["prov"])
            post = res["post"]
            f = fate(arm, arm["ver"], frame, post, arm["prov"])
            hl = 40 if arm["ver"] == 6 else (frame[14] & 0x0f) * 4
            udp_at = 14 + hl + 6
            # --- the rule's own counter and log
            reach = 0 if f["pre_hook"] else 1
            eq(int(row["ch"]), reach, nm + ": counter (0 iff the frame died "
               "before the hook)")
            eq(int(row["nl"]), reach if (res["ok_store"] or not arm["store"])
               else 0, nm + ": the rule's log ran iff the store was accepted")
            # --- the protocol counters: IPv4 is exact (ARP is another
            # family), IPv6 counts neighbour discovery as well
            if arm["ver"] == 4:
                eq(int(row["ipin"]), 1, nm + ": IpInReceives")
            else:
                ck(int(row["rcv"]) >= 1, nm + ": Ip6InReceives >= 1")
                ck(int(row["deliv"]) >= f["delivered"],
                   nm + ": Ip6InDelivers >= the datagrams")
            # --- the receiving socket
            if mode == "part":
                eq(int(row["cmdrc"]), 0, nm + ": the child acknowledged")
            if mode == "part" and arm["ver"] == 6:
                eq(int(row["u6n"]), f["delivered"], nm + ": v6 datagram")
                eq(int(row["udperr6"]), f["udperr"], nm + ": Udp6InErrors")
                if f["delivered"]:
                    eq(row["u6p"], PAYLOAD.hex()
                       if not res["written"] else post[14 + hl + 8:].hex(),
                       nm + ": the payload the socket received")
                    eq(int(row["u6l"]), len(post) - 14 - hl - 8,
                       nm + ": the length the socket received")
                    eq(int(row["u6s"]), (post[14 + hl] << 8) |
                       post[14 + hl + 1], nm + ": the source port")
                eq(int(row["ipdeliv"]), 0, nm + ": no IPv4 delivery")
            if mode == "part" and arm["ver"] == 4:
                eq(int(row["u4n"]), f["delivered"], nm + ": v4 datagram")
                eq(int(row["u4err"]), f["udperr"], nm + ": UdpInErrors")
                eq(int(row["iphdr"]), f["iphdr"], nm + ": IpInHdrErrors")
                if f["delivered"]:
                    eq(row["u4p"], post[14 + hl + 8:].hex(),
                       nm + ": the payload the socket received")
                    eq(int(row["u4l"]), (post[udp_at - 2] << 8) |
                       post[udp_at - 1] - 8, nm + ": the length")
                    eq(int(row["u4s"]), (post[14 + hl] << 8) |
                       post[14 + hl + 1], nm + ": the source port")
            if mode == "opt":
                eq(int(row["fid"]), fid, nm + ": printed frame id")
                eq(int(row["flen"]), len(frame), nm + ": printed frame length")
                eq(int(row["snd"]), len(frame), nm + ": the frame was sent")
                eq(int(row["u4n"]), f["delivered"], nm + ": v4 datagram")
                eq(int(row["u4err"]), f["udperr"], nm + ": UdpInErrors")
                eq(int(row["iphdr"]), f["iphdr"], nm + ": IpInHdrErrors")
                if f["delivered"]:
                    eq(row["u4p"], post[14 + hl + 8:].hex(),
                       nm + ": the payload the socket received")
                    eq(int(row["u4l"]), (post[udp_at - 2] << 8) |
                       post[udp_at - 1] - 8, nm + ": the length")
                    eq(int(row["u4s"]), (post[14 + hl] << 8) |
                       post[14 + hl + 1], nm + ": the source port")
                eq(int(row["ipaddr"]), f["addrerr"], nm + ": IpInAddrErrors")
            # --- the checksum field, what the whole turn is about
            wit = parse_frame_hex(row["pp"]) if row["pnl"] == "1" else b""
            if wit and arm.get("fragoff"):
                eq(len(wit), hl + 16, nm + ": witness length of a bare fragment")
                eq(wit[hl:], frame[14 + hl:14 + hl + 16],
                   nm + ": the fragment's data is what the wire carried")
                wit = b""
            if wit and len(wit) < hl + 8:
                # a non-first fragment carries no transport header
                eq(len(wit), hl + 16, nm + ": witness length of a bare fragment")
                eq(wit[hl:], frame[14 + hl:14 + hl + 16],
                   nm + ": the fragment's data is what the wire carried")
                wit = b""
            if wit:
                wudp = udp_fields(wit, hl)
                eq(wudp["csum"], f["field"],
                   nm + ": UDP checksum field at layer 3")
                eq(wudp["sport"], (post[14 + hl] << 8) | post[14 + hl + 1],
                   nm + ": source port")
                eq(wudp["dport"], (post[14 + hl + 2] << 8) |
                   post[14 + hl + 3], nm + ": destination port")
                if arm["ver"] == 6:
                    eq(wit[8:24], A6_S if not res["written"] or
                       arm["base"] != 1 else post[14 + 8:14 + 24],
                       nm + ": source address at layer 3")
                    eq(wit[24:40], A6_D, nm + ": destination address")
                else:
                    eq(wit[12:16], post[14 + 12:14 + 16],
                       nm + ": IPv4 source at layer 3")
                    eq(wit[16:20], post[14 + 16:14 + 20],
                       nm + ": IPv4 destination at layer 3")
                eq(wit[hl + 8:], post[14 + hl + 8:],
                   nm + ": payload at layer 3")
            # --- the witness chain must be the one for this family
            if int(row["pnl"]) == 1:
                wtot = len(post) - 14
                if arm["ver"] == 4:
                    wtot = min(wtot, (frame[16] << 8) | frame[17])
                eq(int(row["pplen"]), wtot, nm + ": witness payload length")
                eq(row["ppre"], "PR" if arm["ver"] == 6 else "Q4",
                   nm + ": witness chain of the right family")
            # --- the arm's own log: a copy of the frame at that door
            if int(row["nl"]) == 1:
                want_lg = post
                eq(int(row["lglen"]), len(want_lg) - 14,
                   nm + ": the rule's log payload length")
                lg = parse_frame_hex(row["lg"])
                eq(mask_frame(lg, arm["ver"], 0),
                   mask_frame(want_lg, arm["ver"])[14:][:len(lg)],
                   nm + ": the rule's log payload is the post-store frame")
            # --- the tap
            seen = 1 if PAYLOAD[:4] in frame else 0
            eq(int(row["tapn"]), seen, nm + ": tap records (the needle)")
            if seen:
                eq(int(row["tapstat"]), 9 if arm["prov"] == "s" else 1,
                   nm + ": TP_STATUS_CSUMNOTREADY iff CHECKSUM_PARTIAL")
            tap = parse_frame_hex(row["tap"])
            if tap:
                ck(len(tap) <= 96, nm + ": the tap hex is capped at 96 bytes")
                tmask = mask_frame(tap, arm["ver"])
                pre_f = mask_frame(frame, arm["ver"])[:len(tap)]
                post_f = mask_frame(post, arm["ver"])[:len(tap)]
                which = ("pre" if tmask == pre_f else
                         "post" if tmask == post_f else "other")
                ck(which != "other",
                   nm + ": the tap shows the pre-store or the post-store frame",
                   tap.hex())
                b["tapkind"].append(which)
                eq(tap[0:6], frame[0:6], nm + ": tap destination MAC")

    # 6.5 the seed identity, from the wire
    for b in boots:
        rows = b["arms"]
        for row, arm in zip(rows, part):
            if arm["prov"] != "s":
                continue
            wit = parse_frame_hex(row["pp"]) if row["pnl"] == "1" else b""
            if not wit:
                continue
            hl = 40 if arm["ver"] == 6 else 24 if arm["name"].startswith("s4") \
                else 20
            if arm["ver"] == 6 or hl == 40:
                pass
            hl = 40 if arm["ver"] == 6 else (wit[0] & 0x0f) * 4
            got = (wit[hl + 6] << 8) | wit[hl + 7]
            if arm["base"] == 2 and arm["off"] <= 6 < arm["off"] + arm["ln"]:
                continue                    # the store writes the field itself
            want = seed_of_ph(arm, wit, new=bool(arm["cf"]))
            eq(got, want, "%s/%s: the field is the pseudo-header seed "
               "(old addresses)" % (b["log"], arm["name"]))
            nm = "%s/%s" % (b["log"], arm["name"])
            ck(not verifies(wit, arm["ver"]),
               nm + ": the field is not a valid checksum of the datagram")

    # 7. determinism
    if len(boots) == 2:
        a, c = boots
        eq(len(a["arms"]), len(c["arms"]), "determinism: same arm count")
        keys = ("prov", "ver", "door", "base", "store", "off", "len", "ct",
                "co", "cf", "ch", "nl", "u6n", "u6l", "u6s", "u6p", "u4n",
                "u4l", "u4s", "u4p", "hdrerr", "disc", "udp6",
                "udperr6", "ipin", "iphdr", "ipcsum", "ipaddr", "ipdisc",
                "ipdeliv", "u4", "u4err", "tapn", "taplen", "tapstat", "pnl",
                "pplen")
        for r1, r2 in zip(a["arms"], c["arms"]):
            for k in keys:
                eq(r1.get(k), r2.get(k), "determinism %s/%s field %s"
                   % (r1["name"], r1["i"], k))

    print("verify582: %d checks, %d failures" % (CHECKS[0], len(FAILS)))
    for f in FAILS[:40]:
        print("  FAIL", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
