#!/usr/bin/env python3
"""verify551.py -- independent verification of F29 (turn 551).

The claim under test: the guard `nft_th_write_ok()` protects a *base*, not a
byte.  The same byte of the same kind of header -- the data-offset byte of a
TCP header -- is refused when it is named through the transport base and
moved when it is named through the inner base of a forwarded tunnel frame.

Nothing here trusts the differ.  Every frame is re-parsed from the hex the log
carries, in Python, with its own checksum arithmetic; every position is
derived from the bytes, never from the offsets the C code printed.  The differ's
own `chg`/`itcsum`/`oucsum` fields are then compared against the recomputation:
a disagreement is a failure, not a rounding error.

Usage:  python3 tools/verify551.py [--logdir logs] [--allow-missing]
Exit:   0 = every check passed, 1 = at least one failed (each printed as FAIL).
"""
import binascii
import glob
import gzip
import hashlib
import io
import os
import re
import sys

ROOT = "/work/kernel-sec"
LOGDIR = os.environ.get("F29_LOGDIR", os.path.join(ROOT, "logs"))

KERNELS = {
    "Q": dict(rel="linux-7.2.15", img="src/dl72/linux-7.2.15/arch/x86/boot/bzImage",
              guard=False, parity=False, name="7.2.15"),
    "R": dict(rel="linux-7.3-R19", img="src/linux-7.3-R19/arch/x86/boot/bzImage",
              guard=True, parity=False, name="7.3.0"),
    "B": dict(rel="linux-7.3.4-B19", img="src/linux-7.3.4-B19/arch/x86/boot/bzImage",
              guard=True, parity=False, name="7.3.4"),
    "G": dict(rel="linux-7.3.4-P549", img="src/linux-7.3.4-P549/arch/x86/boot/bzImage",
              guard=True, parity=False, name="7.3.4"),
    "P": dict(rel="linux-7.3.4-P548", img="src/linux-7.3.4-P548/arch/x86/boot/bzImage",
              guard=True, parity=True, name="7.3.4"),
}

LOGS = {}          # kernel letter -> list of log texts (rep1, rep2, ...)
CTL = {}           # (letter, logname, kind) -> captured no-rule datagram

CHECKS = []
FAILS = []


def check(name, cond, detail=""):
    CHECKS.append(name)
    if not cond:
        FAILS.append((name, detail))
        print("FAIL %s | %s" % (name, detail))
    return bool(cond)


def eq(name, got, want):
    return check(name, got == want, "got %r want %r" % (got, want))


# ---------------------------------------------------------------- checksums

def fold(acc):
    while acc >> 16:
        acc = (acc & 0xffff) + (acc >> 16)
    return acc


def sum16(data, acc=0):
    if len(data) & 1:
        data = data + b"\0"
    for i in range(0, len(data), 2):
        acc += (data[i] << 8) | data[i + 1]
    return fold(acc)


def tcp_csum(tcp, saddr, daddr):
    """the checksum the header carries, computed from scratch"""
    ph = saddr + daddr + b"\0\x06" + bytes([len(tcp) >> 8, len(tcp) & 0xff])
    return (~fold(sum16(tcp, sum16(ph)))) & 0xffff


def tcp_ok(tcp, saddr, daddr):
    """valid iff the sum over header+payload, checksum field included, folds to 0"""
    ph = saddr + daddr + b"\0\x06" + bytes([len(tcp) >> 8, len(tcp) & 0xff])
    return fold(sum16(tcp, sum16(ph))) == 0xffff


def udp_ok(udp, saddr, daddr):
    return fold(sum16(udp, sum16(saddr + daddr + b"\0\x11" +
                                 bytes([len(udp) >> 8, len(udp) & 0xff])))) == 0xffff


def ip_ok(ip):
    return fold(sum16(ip[:20])) == 0xffff


# ---------------------------------------------------------------- frame parsing

def parse_frame(hexstr):
    """Parse a whole Ethernet frame and return every position this turn needs.
    Raises ValueError when the frame is not what this file builds."""
    f = binascii.unhexlify(hexstr)
    o = dict(frame=f, flen=len(f))
    if f[12:14] != b"\x08\x00":
        raise ValueError("outer ethertype")
    ip = f[14:]
    o["ip"] = ip
    ihl = (ip[0] & 0x0f) * 4
    if ihl != 20 or ip[9] not in (4, 6, 17):
        raise ValueError("outer IPv4")
    o["proto"] = ip[9]
    o["iplen"] = (ip[2] << 8) | ip[3]
    if o["iplen"] != len(ip):
        raise ValueError("outer tot_len %d != %d" % (o["iplen"], len(ip)))
    if o["proto"] == 6:
        tcp = ip[20:]
        o["tcp_off"] = 34
        o["tcp"] = tcp
        o["saddr"] = ip[12:16]
        o["daddr"] = ip[16:20]
        o["kind"] = 0
        return o
    if o["proto"] == 4:
        l3 = 20                       # datagram coordinates: right after the IP header
        o["inner_ip_off"] = l3
        l4 = l3 + 20
        o["inner_l4_off"] = l4
        o["kind"] = 3
    else:
        ulen = (ip[24] << 8) | ip[25]
        if ulen != len(ip) - 20:
            raise ValueError("udp len %d" % ulen)
        dport = (ip[22] << 8) | ip[23]
        o["dport"] = dport
        if dport == 4789:
            tun = 28
            if ip[tun] != 0x08:
                raise ValueError("vxlan flags")
            kind = 4 if ip[26:28] != b"\0\0" else 1
            l3 = tun + 8 + 14
        elif dport == 6081:
            tun = 28
            optlen = ip[tun] & 0x3f
            kind = 2
            if optlen != 2:
                raise ValueError("geneve opt_len %d" % optlen)
            l3 = tun + 8 + 4 * optlen + 14
        else:
            raise ValueError("udp dport %d" % dport)
        if ip[l3 - 2:l3] != b"\x08\x00":
            raise ValueError("inner ethertype")
        o["inner_ip_off"] = l3
        l4 = l3 + 20
        o["inner_l4_off"] = l4
        o["kind"] = kind
        o["udp_off"] = 20
        o["udp"] = ip[20:20 + ulen]
    # the inner IP header must be IPv4/TCP and the inner TCP header must start
    # where the parse says it does
    inner = ip[o["inner_ip_off"]:o["inner_ip_off"] + 20]
    if (inner[0] & 0xf0) != 0x40 or inner[9] != 6:
        raise ValueError("inner IPv4/TCP")
    tcp = ip[o["inner_l4_off"]:o["inner_l4_off"] + 24]
    if len(tcp) != 24:
        raise ValueError("inner tcp short")
    o["inner_tcp"] = tcp
    o["inner_saddr"] = inner[12:16]
    o["inner_daddr"] = inner[16:20]
    o["tcp"] = tcp                 # the TCP header this turn is about
    o["saddr"] = inner[12:16]
    o["daddr"] = inner[16:20]
    o["inner_totlen"] = (inner[2] << 8) | inner[3]
    return o


def base_pos(o, base):
    """where the base nft/kernel means starts, in datagram coordinates"""
    if base == 2:      # transport
        return o["tcp_off"] - 14
    if base == 3:      # inner = right after the outer L4 header
        return 20 + 8 if o["proto"] != 4 else 20
    raise ValueError("base %r" % (base,))


# ---------------------------------------------------------------- log parsing

def kv(line):
    """F551 tag|k=v|k=v|frame=..|cap=..  ->  (tag, dict, frame, cap)"""
    parts = line.split("|")
    tag = parts[0]
    d = {}
    frame = cap = None
    for p in parts[1:]:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        if k == "frame":
            frame = v
        elif k == "cap" and (v == "" or len(v) > 2):
            cap = v                      # the captured datagram, in hex
        else:
            d[k] = v                     # including cap=<count>
    return tag, d, frame, cap


def load_controls():
    for letter in LOGS:
        for path, text in LOGS[letter]:
            for line in lines_of(text, "F551 B.ctl.kind"):
                tag, d, frame, cap = kv(line[len("F551 "):])
                kind = int(tag.split("kind")[1])
                if cap:
                    CTL[(letter, os.path.basename(path), kind)] = binascii.unhexlify(cap)


def load_logs():
    for letter in KERNELS:
        texts = []
        for path in sorted(glob.glob(os.path.join(LOGDIR, "f29_%s_rep*.log" % letter))):
            with open(path, "r", errors="replace") as fh:
                texts.append((path, fh.read()))
        LOGS[letter] = texts


def lines_of(text, prefix):
    return [l for l in text.split("\n") if l.startswith(prefix)]


# ---------------------------------------------------------------- sections

def check_provenance():
    for letter, meta in KERNELS.items():
        for path, text in LOGS[letter]:
            base = os.path.basename(path)
            want = hashlib.sha256(open(os.path.join(ROOT, meta["img"]), "rb").read()).hexdigest()
            m = re.search(r"^### sha256: ([0-9a-f]{64})$", text, re.M)
            check("prov.%s.%s.kernel_sha" % (letter, base), m and m.group(1) == want,
                  "log %s kernel %s" % (m and m.group(1), want))
            m = re.search(r"^### initrd sha256: ([0-9a-f]{64})$", text, re.M)
            initrd = os.path.join(ROOT, "vm/initrd551/f551.cpio.gz")
            want_i = hashlib.sha256(open(initrd, "rb").read()).hexdigest()
            check("prov.%s.%s.initrd_sha" % (letter, base), m and m.group(1) == want_i,
                  "log %s initrd %s" % (m and m.group(1), want_i))
            # the differ inside the initramfs is the one on disk
            differ = os.path.join(ROOT, "vm/build/differ551")
            want_d = hashlib.sha256(open(differ, "rb").read()).hexdigest()
            blob = gzip.decompress(open(initrd, "rb").read())
            got = None
            i = 0
            while i + 110 <= len(blob):
                hdr = blob[i:i + 110]
                if hdr[:6] != b"070701":
                    break
                namesize = int(hdr[94:102], 16)
                filesize = int(hdr[54:62], 16)
                name = blob[i + 110:i + 110 + namesize - 1].decode()
                off = i + 110 + namesize
                off += (-off) % 4
                if name == "root/repro":
                    got = hashlib.sha256(blob[off:off + filesize]).hexdigest()
                i = off + filesize
                i += (-i) % 4
            check("prov.%s.%s.differ_in_initrd" % (letter, base), got == want_d,
                  "initrd has %s want %s" % (got, want_d))
            m = re.search(r"^Linux version (\S+)", text, re.M)
            check("prov.%s.%s.boot_version" % (letter, base),
                  m and m.group(1) == meta["name"],
                  "log %s want %s" % (m and m.group(1), meta["name"]))
            check("prov.%s.%s.nft_version" % (letter, base),
                  "nftables v1.1.7" in text, "nft version line missing")
            check("prov.%s.%s.done" % (letter, base), "F551 DONE" in text, "no F551 DONE")


def check_builder():
    for letter in LOGS:
        for path, text in LOGS[letter]:
            base = "%s.%s" % (letter, os.path.basename(path))
            for line in lines_of(text, "F551 FRAME|"):
                tag, d, frame, cap = kv(line[len("F551 "):])
                kind = int(d["kind"])
                try:
                    o = parse_frame(frame)
                except ValueError as e:
                    check("frame.%s.kind%d.parse" % (base, kind), False, str(e))
                    continue
                check("frame.%s.kind%d.parse" % (base, kind), True)
                eq("frame.%s.kind%d.kind" % (base, kind), o["kind"], kind)
                eq("frame.%s.kind%d.doff5" % (base, kind), o["tcp"][12], 0x50)
                eq("frame.%s.kind%d.flags18" % (base, kind), o["tcp"][13], 0x18)
                if kind == 0:
                    want = -1          # no inner TCP header exists here
                else:
                    want = 1 if tcp_ok(o["tcp"], o["saddr"], o["daddr"]) else 0
                eq("frame.%s.kind%d.itcsum" % (base, kind), int(d["itcsum"]), want)
                # the doff byte sits where the turn says it does, derived from
                # the frame's own headers
                if kind in (1, 4):
                    eq("frame.%s.kind%d.doffpos" % (base, kind), o["inner_l4_off"] + 12, 82)
                    eq("frame.%s.kind%d.inner_base_is_tunnel_payload" % (base, kind),
                       base_pos(o, 3) + 8 + 14 + 20, o["inner_l4_off"])
                if kind == 2:
                    eq("frame.%s.kind%d.doffpos" % (base, kind), o["inner_l4_off"] + 12, 90)
                if kind == 3:
                    eq("frame.%s.kind%d.doffpos" % (base, kind), o["inner_l4_off"] + 12, 52)
                    eq("frame.%s.kind%d.inner_base_is_thoff" % (base, kind),
                       base_pos(o, 3), o["inner_ip_off"])
                if kind in (1, 2, 3, 4):
                    eq("frame.%s.kind%d.inner_eth_or_ip" % (base, kind),
                       o["inner_l4_off"] - o["inner_ip_off"], 20)
                if kind in (1, 2, 4):
                    # the outer UDP checksum is zero except in the kind built to
                    # carry a real one
                    zero = o["udp"][6:8] == b"\0\0"
                    eq("frame.%s.kind%d.udp_csum_zero" % (base, kind), zero, kind != 4)
                    if kind == 4:
                        check("frame.%s.kind4.udp_valid" % base,
                              udp_ok(o["udp"], o["ip"][12:16], o["ip"][16:20]))
                check("frame.%s.kind%d.ip_valid" % (base, kind), ip_ok(o["ip"]))


def rule_geometry(rule):
    """'@ih,432,8 set 0x60' -> ('ih', 54, 1)"""
    m = re.match(r"@(\w+),(\d+),(\d+) set ", rule)
    if not m:
        return None
    kw, bits, ln = m.group(1), int(m.group(2)), int(m.group(3))
    if bits % 8:
        return None
    return kw, bits // 8, ln // 8


NL_GEOMETRY = {
    # tag -> (base word, byte offset, length, csum_type)
    "th.do6":      ("transport header", 12, 2, 0),
    "th.flags":    ("transport header", 12, 2, 0),
    "ih.vx.do6":   ("inner header", 54, 2, 0),
    "ih.vx.flags": ("inner header", 54, 2, 0),
    "ih.vx.do6w":  ("inner header", 54, 2, 0),
    "ih.gn.do6":   ("inner header", 62, 2, 0),
    "ih.ipip.do6": ("inner header", 32, 2, 0),
    "ih.vx.eth":   ("inner header", 8, 8, 0),
    "ih.vx.tun0":  ("inner header", 0, 8, 0),
    "ih.udp.do6":  ("inner header", 54, 2, 0),
    "ih.udp.flag": ("inner header", 54, 2, 0),
    "ih.plain.do6": ("inner header", 54, 2, 0),
}


def section_a(letter, path, text):
    base = "%s.%s" % (letter, os.path.basename(path))
    meta = KERNELS[letter]
    nl = {}
    for line in lines_of(text, "F551NL "):
        m = re.match(r"F551NL (\S+) +\[ payload write reg 1 => (\d+)b @ ([a-z ]+) \+ (\d+) "
                     r"csum_type (\d+) csum_off (\d+) csum_flags (0x[0-9a-f]+) \]", line)
        if m:
            nl[m.group(1)] = m.groups()[1:]
    for line in lines_of(text, "F551 A."):
        tag, d, frame, cap = kv(line[len("F551 "):])
        name = tag[2:]
        rule = d["rule"]
        if rule == "none":
            continue
        geo = rule_geometry(rule)
        if geo is None:
            check("a.%s.%s.geometry_parsed" % (base, name), False, rule)
            continue
        kw, off, ln = geo
        eq("a.%s.%s.nftrc" % (base, name), int(d["nftrc"]), 0)
        # nft's own message: the declared base and byte offset
        if name in nl:
            blen, bname, boff, ct, co, cf = nl[name]
            eq("nl.%s.%s.base" % (base, name), bname.strip(),
               "transport header" if kw == "th" else "inner header")
            # nft widens a 1-byte store to the aligned 2-byte window it
            # read-modify-writes, so the declared byte must fall inside it
            check("nl.%s.%s.offset_is_bits_over_8" % (base, name),
                  int(boff) <= off < int(boff) + int(blen),
                  "nft writes [%s,%s) rule says %d" % (boff, int(boff) + int(blen), off))
            eq("nl.%s.%s.csum_type" % (base, name), int(ct), 0)
            if kw == "ih":
                eq("nl.%s.%s.pseudohdr_flag" % (base, name), cf, "0x1")
            else:
                eq("nl.%s.%s.no_pseudohdr_flag" % (base, name), cf, "0x0")
        else:
            check("nl.%s.%s.message_present" % (base, name), False, "no payload write line")
        sent = binascii.unhexlify(frame)
        o = parse_frame(frame)
        bpos = base_pos(o, 3 if kw == "ih" else 2)
        ref = CTL.get((letter, os.path.basename(path), o["kind"]), o["ip"])
        got = binascii.unhexlify(cap) if int(d.get("cap") or 0) == 1 else b""
        if kw == "th":
            # this chain's policy is accept, so the frame is delivered either
            # way; the guard shows up as a frame byte that did NOT move
            covers = off <= 12 < off + ln
            refused = bool(meta["guard"] and covers)
            eq("a.%s.%s.cap_policy_accept" % (base, name), int(d.get("cap") or 0), 1)
            if refused:
                eq("a.%s.%s.guard_refused" % (base, name), int(d["nchg"]), 0)
                continue
            check("a.%s.%s.applied" % (base, name), int(d["nchg"]) > 0, "no byte moved")
        if kw == "ih" and name == "ih.plain.do6":
            # a plain frame has no tunnel: the inner base resolves past the end
            # of the frame and the store breaks
            eq("a.%s.%s.no_tunnel_no_store" % (base, name), int(d.get("cap") or 0), 1)
            eq("a.%s.%s.no_change" % (base, name), int(d["nchg"]), 0)
            continue
        eq("a.%s.%s.cap" % (base, name), int(d.get("cap") or 0), 1)
        if not got:
            continue
        eq("a.%s.%s.iplen" % (base, name), len(got), o["iplen"])
        diffs = [i for i in range(len(got)) if got[i] != ref[i]]
        lo, hi = bpos + off, bpos + off + ln
        inside = [i for i in diffs if lo <= i < hi]
        check("a.%s.%s.store_landed" % (base, name), inside,
              "no byte changed in [%d,%d); diffs %r" % (lo, hi, diffs))
        others = [i for i in diffs if not (lo <= i < hi)]
        udp_field = range(26, 28)
        ok_others = all((i in udp_field and o["udp"][6:8] != b"\0\0") for i in others) if others else True
        check("a.%s.%s.only_store_and_l4csum" % (base, name), ok_others,
              "unexpected changes at %r" % (others,))
        tcpdg = o["inner_l4_off"] if o.get("inner_l4_off") is not None else o["tcp_off"] - 14
        if "do6" in name:
            eq("a.%s.%s.doff_moved" % (base, name), got[tcpdg + 12], 0x60)
        if "flag" in name:
            eq("a.%s.%s.flags_moved" % (base, name), got[tcpdg + 13], 0x02)
        if kw == "ih":
            it = 1 if tcp_ok(got[o["inner_l4_off"]:o["inner_l4_off"] + 24],
                             got[o["inner_ip_off"] + 12:o["inner_ip_off"] + 16],
                             got[o["inner_ip_off"] + 16:o["inner_ip_off"] + 20]) else 0
            eq("a.%s.%s.itcsum_recomputed" % (base, name), int(d["itcsum"]), it)
            # nft's @ih store carries csum_type 0: no fixup, so any store that
            # touches the TCP header leaves its checksum stale
            touched_tcp = (bpos + off) >= o["inner_l4_off"] and \
                          (bpos + off) < o["inner_l4_off"] + 24
            if touched_tcp:
                eq("a.%s.%s.no_fixup_stale" % (base, name), it, 0)
            if o["kind"] == 4:
                ou = 1 if udp_ok(got[20:o["iplen"]], got[12:16], got[16:20]) else 0
                eq("a.%s.%s.oucsum_recomputed" % (base, name), int(d["oucsum"]), ou)
                eq("a.%s.%s.oucsum_valid" % (base, name), ou, 1)


B_EXPECT = {
    # tag: (delivered_when_guard, delivered_when_no_guard)
    "t.11.2": (0, 1),
    "t.12.1": (0, 1),
    "t.12.2": (0, 1),
    "t.12.4": (0, 1),
    "t.13.1": (1, 1),
    "t.12.same": (0, 1),
}


def section_b(letter, path, text):
    base = "%s.%s" % (letter, os.path.basename(path))
    meta = KERNELS[letter]
    ctl = {}
    for line in lines_of(text, "F551 B.ctl.kind"):
        tag, d, frame, cap = kv(line[len("F551 "):])
        kind = int(tag.split("kind")[1])
        if int(d.get("cap") or 0) != 1:
            check("b.%s.ctl%d.cap" % (base, kind), False, "control frame not captured")
            continue
        sent = binascii.unhexlify(frame)
        got = binascii.unhexlify(cap)
        ctl[kind] = got
        eq("b.%s.ctl%d.same_len" % (base, kind), len(got), len(sent) - 14)
        check("b.%s.ctl%d.ttl" % (base, kind), got[8] == sent[14 + 8] - 1,
              "ttl %d -> %d" % (sent[14 + 8], got[8]))
        check("b.%s.ctl%d.ipcsum" % (base, kind), ip_ok(got))
        diffs = [i for i in range(len(got)) if got[i] != sent[14 + i]]
        eq("b.%s.ctl%d.only_ttl_and_ipcsum" % (base, kind),
           sorted(set(diffs) - {8, 10, 11}), [])
    for line in lines_of(text, "F551 B."):
        tag, d, frame, cap = kv(line[len("F551 "):])
        name = tag[2:]
        if name.startswith("ctl."):
            continue
        o = parse_frame(frame)
        got = binascii.unhexlify(cap) if cap else b""
        delivered = 1 if int(d.get("cap") or 0) == 1 else 0
        bname = "transport" if d["base"] == "2" else "inner"
        off, ln = int(d["off"]), int(d["len"])
        if name in B_EXPECT:
            want = B_EXPECT[name][0] if meta["guard"] else B_EXPECT[name][1]
            eq("b.%s.%s.delivered" % (base, name), delivered, want)
        elif name == "i.plain.54.1":
            # no tunnel: nft_payload_inner_offset() points past the frame
            eq("b.%s.%s.no_tunnel_refused" % (base, name), delivered, 0)
        elif bname == "inner":
            eq("b.%s.%s.delivered" % (base, name), delivered, 1)
        # when delivered, the store landed where the declaration says
        if delivered:
            bpos = base_pos(o, int(d["base"]))
            refb = CTL.get((letter, os.path.basename(path), o["kind"]), o["ip"])
            diffs = [i for i in range(len(got)) if got[i] != refb[i]]
            inside = [i for i in diffs if bpos + off <= i < bpos + off + ln]
            check("b.%s.%s.store_landed" % (base, name), inside,
                  "no byte changed in [%d,%d)" % (bpos + off, bpos + off + ln))
            # checksum fixup: on the inner base the covered header is the inner
            # TCP header, which starts at bpos+42 for vxlan/geneve2 and bpos+20
            # for ipip; the store is aligned exactly when its offset inside that
            # header is even
            if d["csum"].split(",")[0] == "1" and bname == "inner":
                tcp_start = o["inner_l4_off"] - 14
                aligned = ((bpos + off) - tcp_start) % 2 == 0
                valid = 1 if tcp_ok(got[o["inner_l4_off"]:o["inner_l4_off"] + 24],
                                    got[o["inner_ip_off"] + 12:o["inner_ip_off"] + 16],
                                    got[o["inner_ip_off"] + 16:o["inner_ip_off"] + 20]) else 0
                eq("b.%s.%s.itcsum_matches_parity" % (base, name), int(d["itcsum"]), valid)
                if meta["parity"]:
                    eq("b.%s.%s.parity_fixed" % (base, name), valid, 1)
                else:
                    eq("b.%s.%s.parity_behaviour" % (base, name), valid, 1 if aligned else 0)
            elif d["csum"].split(",")[0] == "0" and bname == "inner":
                valid = 1 if tcp_ok(got[o["inner_l4_off"]:o["inner_l4_off"] + 24],
                                    got[o["inner_ip_off"] + 12:o["inner_ip_off"] + 16],
                                    got[o["inner_ip_off"] + 16:o["inner_ip_off"] + 20]) else 0
                eq("b.%s.%s.no_fixup_stays_bad" % (base, name), valid, 0)


C_EXPECT = {
    "ctl.norule": dict(cap=0, counter="none"),
    "ctl.accept": dict(cap=1, counter="1"),
    "ctl.accept.vx": dict(cap=1, counter="1"),
    "th.do6": dict(cap=0, counter="0"),
    "th.flags": dict(cap=1, counter="1"),
    "ih.vx.do6": dict(cap=1, counter="1"),
    "ih.vx.flags": dict(cap=1, counter="1"),
    "ih.plain.do6": dict(cap=0, counter="0"),
}


def section_c(letter, path, text):
    base = "%s.%s" % (letter, os.path.basename(path))
    meta = KERNELS[letter]
    for line in lines_of(text, "F551 C."):
        tag, d, frame, cap = kv(line[len("F551 "):])
        name = tag[2:]
        if name not in C_EXPECT:
            continue
        want = dict(C_EXPECT[name])
        if name == "th.do6" and not meta["guard"]:
            want = dict(cap=1, counter="1")
        eq("c.%s.%s.cap" % (base, name), int(d.get("cap") or 0), want["cap"])
        got_counter = d["counter_after"]
        eq("c.%s.%s.counter" % (base, name), got_counter, want["counter"])
        eq("c.%s.%s.counter_before" % (base, name), d["counter_before"],
           "none" if name == "ctl.norule" else "0")
        if want["cap"] == 1 and cap:
            o = parse_frame(frame)
            got = binascii.unhexlify(cap)
            refc = CTL.get((letter, os.path.basename(path), o["kind"]), o["ip"])
            diffs = [i for i in range(len(got)) if got[i] != refc[i]]
            if name.startswith("ctl."):
                eq("c.%s.%s.no_store" % (base, name), len(diffs), 0)
            else:
                eq("c.%s.%s.one_byte" % (base, name), len(diffs), 1)
            if "do6" in name:
                tcpb = (o["inner_l4_off"] if o["kind"] else o["tcp_off"] - 14) + 12
                eq("c.%s.%s.doff" % (base, name), got[tcpb], 0x60)
            if "flags" in name:
                tcpb = (o["inner_l4_off"] if o["kind"] else o["tcp_off"] - 14) + 13
                eq("c.%s.%s.flags" % (base, name), got[tcpb], 0x02)


def section_d(letter, path, text):
    base = "%s.%s" % (letter, os.path.basename(path))
    meta = KERNELS[letter]
    for line in lines_of(text, "F551 D."):
        tag, d, frame, cap = kv(line[len("F551 "):])
        name = tag[2:]
        o = parse_frame(frame)
        got = binascii.unhexlify(cap) if cap else b""
        eq("d.%s.%s.delivered" % (base, name), int(d.get("cap") or 0), 1)
        if not got:
            continue
        valid = 1 if tcp_ok(got[o["inner_l4_off"]:o["inner_l4_off"] + 24],
                            got[o["inner_ip_off"] + 12:o["inner_ip_off"] + 16],
                            got[o["inner_ip_off"] + 16:o["inner_ip_off"] + 20]) else 0
        if int(d["itcsum"]) >= 0:
            eq("d.%s.%s.itcsum_recomputed" % (base, name), int(d["itcsum"]), valid)
        else:
            tot = (got[o["inner_ip_off"] + 2] << 8) | got[o["inner_ip_off"] + 3]
            eq("d.%s.%s.no_inner_length" % (base, name), tot > len(got) or tot < 20, True)
        if name == "D.align.54":
            eq("d.%s.%s.aligned_valid" % (base, name), valid, 1)
        if name == "D.odd.55":
            eq("d.%s.%s.odd_parity" % (base, name), valid, 1 if meta["parity"] else 0)
        if name == "D.none.55":
            eq("d.%s.%s.no_fixup" % (base, name), valid, 0)
        if name == "D.saddr.34":
            eq("d.%s.%s.pseudo_header_fixed" % (base, name), valid, 1)
        if name in ("D.ip.22", "D.ip.23"):
            # a store outside the region the checksum covers: the kernel fixes
            # it anyway, so the checksum cannot be right except by accident
            check("d.%s.%s.outside_region_corrupted" % (base, name), valid == 0,
                  "checksum valid after a store the TCP checksum does not cover")


def check_determinism():
    for letter in ("B",):
        if len(LOGS[letter]) < 2:
            check("det.%s.two_boots" % letter, False, "need two boots")
            continue
        def norm(t):
            out = []
            for l in t.split("\n"):
                if not l.startswith("F551 "):
                    continue
                l = re.sub(r"p551_\d+", "p551_PID", l)
                out.append(l)
            return out
        a = norm(LOGS[letter][0][1])
        b = norm(LOGS[letter][1][1])
        check("det.%s.same_lines" % letter, a == b,
              "first difference: %r vs %r" % (
                  next((x for x, y in zip(a, b) if x != y), None),
                  next((y for x, y in zip(a, b) if x != y), None)))
        check("det.%s.count" % letter, len(a) > 40, "only %d lines" % len(a))


def check_splat():
    pat = re.compile(r"KASAN|BUG:|Oops|WARNING:|general protection|use-after-free")
    for letter in LOGS:
        for path, text in LOGS[letter]:
            hits = [l for l in text.split("\n") if pat.search(l)]
            check("splat.%s.%s" % (letter, os.path.basename(path)), not hits,
                  "%d hit(s): %r" % (len(hits), hits[:2]))


def main():
    allow_missing = "--allow-missing" in sys.argv
    load_logs()
    load_controls()
    for letter in KERNELS:
        if not LOGS[letter]:
            check("log.%s.present" % letter, allow_missing, "no log for %s" % letter)
    check_provenance()
    check_builder()
    for letter in KERNELS:
        for path, text in LOGS[letter]:
            section_a(letter, path, text)
            section_b(letter, path, text)
            section_c(letter, path, text)
            section_d(letter, path, text)
    check_determinism()
    check_splat()
    print("\n=== %d checks, %d failed ===" % (len(CHECKS), len(FAILS)))
    for name, detail in FAILS:
        print("FAILED: %s | %s" % (name, detail))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
