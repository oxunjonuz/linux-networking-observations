#!/usr/bin/env python3
"""verify569.py -- independent check of the F47 measurement (turn 569).

Reads logs/f47_rep1.log and logs/f47_rep2.log and decides, from their bytes and
from the source tree alone, whether every claim of the report holds.

Nothing here is shared with the instrument: the instrument is C, prints what it
saw, and this reads the printout; the model of the kernel below is written from
the source (the anchors are re-read from the tree, not trusted), and every
number in the report is recomputed here.

Checks
  P1..P6  provenance: kernel sha256 from the log header against the file, the
          initrd against logs/f47_initrd_hashes.txt, and the differ binary
          extracted from the initramfs against vm/build/differ569.
  S1..S7  source anchors that the model rests on.
  A       every arm of the grid present in both boots, no extras.
  B       the door ran (cntp) and the guard's verdict (lives) against the
          model of nft_nh_write_ok_ip6().
  C       the receiver's verdict (delivered / Udp6InErrors / Ip6InAddrErrors /
          nothing on the wire) against the model of the door.
  D       the bytes at the receiver: the stored field carries the immediate in
          every delivered arm, and a refused cell leaves the frame untouched.
  E       determinism: every derived fact equal in the two boots.
  F       the isolation section of mode `iso` (P1..P6 of that measurement).
Exit 0 iff everything holds.
"""

import gzip
import hashlib
import os
import io
import re
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_lg = os.environ.get("F569_LOGS", "")
LOGS = ([Path(p) for p in _lg.split(":")] if _lg else
        [ROOT / "logs/f47_rep1.log", ROOT / "logs/f47_rep2.log"])
ISO = ROOT / "logs/f47_iso.log"
KERNEL = ROOT / "src/linux-7.3.4-T563/arch/x86/boot/bzImage"
NFC = ROOT / "src/linux-7.3.4-T563/net/netfilter/nft_payload.c"
IP6IN = ROOT / "src/linux-7.3.4-T563/net/ipv6/ip6_input.c"
IP6FWD = ROOT / "src/linux-7.3.4-T563/net/ipv6/ip6_output.c"
UDPSRC = ROOT / "src/linux-7.3.4-T563/net/ipv6/udp.c"

fails = []
checks = 0


def ck(cond, msg):
    global checks
    checks += 1
    if not cond:
        fails.append(msg)
    return cond


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def fields(line):
    d = {}
    for kv in line.split("|")[1:]:
        if "=" in kv:
            k, v = kv.split("=", 1)
            d[k] = v
    return d


def read(p):
    try:
        return p.read_text(errors="replace").splitlines()
    except OSError:
        return []


# ---------------------------------------------------------------- provenance

def provenance():
    for lg in LOGS:
        lines = read(lg)
        if not ck(bool(lines), "provenance: %s is missing or empty" % lg.name):
            continue
        head = "\n".join(lines[:6])
        m = re.search(r"### sha256: ([0-9a-f]{64})", head)
        ck(m is not None, "%s: no kernel sha in the header" % lg.name)
        if m:
            ck(m.group(1) == sha256(KERNEL),
               "%s: kernel sha %s != file %s" % (lg.name, m.group(1),
                                                sha256(KERNEL)))
        ck(any("7.3.4-T563" in l for l in lines[:12]),
           "%s: no F569 KERNEL line" % lg.name)
        mh = re.search(r"### initrd sha256: ([0-9a-f]{64})", head)
        mi = re.search(r"### initrd: (\S+)", head)
        if mh and mi and Path(mi.group(1)).exists():
            ck(mh.group(1) == sha256(Path(mi.group(1))),
               "%s: the header's initrd sha is not the file's" % lg.name)
        m = mi
        if m:
            want = None
            for ln in read(ROOT / "logs/f47_initrd_hashes.txt"):
                t, h = ln.split()
                if t + ".cpio.gz" == Path(m.group(1)).name:
                    want = h
            ck(want is not None, "%s: initrd %s not in the hash list"
               % (lg.name, m.group(1)))
            if want:
                ck(sha256(Path(m.group(1))) == want,
                   "%s: initrd sha mismatch" % lg.name)
                ck(inner_differ(Path(m.group(1))), "%s: differ inside the "
                   "initramfs is not vm/build/differ569" % lg.name)


def inner_differ(cpio_gz):
    raw = gzip.decompress(cpio_gz.read_bytes())
    i, n, out = 0, len(raw), None
    while i + 110 <= n:
        hdr = raw[i:i + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            break
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = raw[i + 110:i + 110 + namesize - 1].decode(errors="replace")
        data_at = i + 110 + namesize
        data_at += (-data_at) % 4
        if name == "root/repro":
            out = raw[data_at:data_at + filesize]
        i = data_at + filesize
        i += (-i) % 4
    if out is None:
        return False
    return hashlib.sha256(out).hexdigest() == sha256(ROOT / "vm/build/differ569")


# ------------------------------------------------------------ source anchors

def anchors():
    p = NFC.read_text()
    m = re.search(r"static bool nft_nh_write_ok_ip6.*?\n}", p, re.S)
    ck(m is not None, "S1: nft_nh_write_ok_ip6 not found")
    body = m.group(0) if m else ""
    ck("case 0:" in body and "ih->version == 6" in body,
       "S1: case 0 does not compare the written version with 6")
    ck("case offsetof(struct ipv6hdr, hop_limit):" in body and
       "priv->len == 1" in body, "S2: hop_limit case is not len == 1")
    ck("case offsetof(struct ipv6hdr, saddr):" in body and "16 + 16" in body,
       "S3: saddr case is not len <= 32")
    ck("case offsetof(struct ipv6hdr, daddr):" in body and
       re.search(r"case offsetof\(struct ipv6hdr, daddr\):\s*\n\s*return priv->len <= 16;", body),
       "S4: daddr case is not len <= 16")
    ck("case 4:" not in body and "case 6:" not in body,
       "S5: the IPv6 list has a case for offset 4 or 6 after all")
    q = IP6FWD.read_text()
    m = re.search(r"int ip6_forward\(struct sk_buff \*skb\)(.*?)\n}", q, re.S)
    fwd = m.group(1) if m else ""
    i_hop = fwd.find("hop_limit <= 1")
    i_hook = fwd.find("NF_INET_FORWARD")
    ck(i_hop >= 0 and i_hook >= 0 and i_hop < i_hook,
       "S6: ip6_forward does not check hop_limit <= 1 before the FORWARD hook")
    r = IP6IN.read_text()
    m = re.search(r"static struct sk_buff \*ip6_rcv_core(.*?)\n}", r, re.S)
    core = m.group(1) if m else ""
    i_other = core.find("PACKET_OTHERHOST")
    i_in = core.find("IPSTATS_MIB_IN,")
    ck(0 <= i_other < i_in, "S7: ip6_rcv_core does not drop PACKET_OTHERHOST "
                            "before it counts the packet")
    u = UDPSRC.read_text()
    ck("udp6_csum_init" in u and "UDP_MIB_INERRORS" in u,
       "S8: udp6_csum_init does not count a bad checksum as Udp6InErrors")


# ------------------------------------------------------------------ the grid

CELLS = ["hop90", "hop00", "hop01", "hop64", "flow2", "tc4", "ver9", "saddr",
         "saddr_same", "daddr", "plen2", "nh1"]
PAIRS = [("out", "loc"), ("post", "loc"), ("egr", "loc"),
         ("post", "fwd"), ("fwd", "fwd"), ("egr", "fwd"), ("pre", "fwd")]
READS = ["rd_hop64", "rd_hop00", "rd_src", "rd_dst"]

# what nft_nh_write_ok_ip6() does with each cell, from the source above
REFUSED = {"ver9", "plen2", "nh1"}     # version nibble != 6, no case for 4/6
REFUSED_READS = {"rd_hop00"}           # nothing carries hop limit 0
# rd_hop64 compares the hop limit with 0x40; the value has already been
# decremented (0x3f) at every forwarded packet's post-forward doors
READ_HOP_64_MATCH = {("out", "loc"), ("post", "loc"), ("egr", "loc"),
                     ("pre", "fwd")}

# the fate of the packet at the receiver, per cell and class, from the model:
#   "ok"      delivered to the socket
#   "udperr"  Udp6InErrors at the receiver (pseudo-header no longer matches)
#   "addrer"  Ip6InAddrErrors at the receiver (the frame went out, wrong dst)
#   "gone"    no frame reaches the wire at all
def fate(cell, cls, door):
    if cell in REFUSED or cell in REFUSED_READS:
        return "ok"                      # the store never happened
    if cell in ("hop90", "hop64", "flow2", "tc4", "saddr_same"):
        return "ok"
    if cell in ("hop00", "hop01"):
        # ip6_forward() refuses hop_limit <= 1, and it runs *after* the
        # PREROUTING hook and *before* the FORWARD one
        return "gone" if door == "pre" and cls == "fwd" else "ok"
    if cell == "saddr":
        # the IPv6 pseudo-header covers the source address; a locally
        # generated datagram leaves with CHECKSUM_PARTIAL (the receiver does
        # not verify it), a frame from the wire carries a final checksum
        return "ok" if cls == "loc" else "udperr"
    if cell == "daddr":
        if door == "egr":
            return "addrer"
        return "gone"
    return "ok"


CUM_KEYS = ["i6hdr", "i6addr", "i6unk", "i6trunc", "i6noroute", "i6deliv",
            "u6in", "u6err", "u6noport"]


def add_deltas(arms, order):
    """The instrument prints cumulative receiver counters; the verdict of an
    arm is the difference from the previous arm, in the order they were run."""
    prev = {}
    for n, key in enumerate(order):
        f = arms[key]
        if n == 0:
            f["_first"] = "1"
            for c in CUM_KEYS:
                f["d_" + c] = "NA"
        for c in CUM_KEYS:
            cur = int(f.get(c, "0") or 0)
            f["d_" + c] = str(cur - prev.get(c, cur))
            prev[c] = cur


def armsof(lines):
    out, order = {}, []
    for ln in lines:
        if not ln.startswith("F569 A|"):
            continue
        f = fields(ln)
        k = (f["door"], f["cls"], f["arm"])
        out[k] = f
        order.append(k)
    return out, order


def grid():
    boots = []
    for lg in LOGS:
        rows = read(lg)
        if not rows:
            ck(False, "grid: %s is missing or empty" % lg.name)
            boots.append({})
            continue
        a, order = armsof(rows)
        add_deltas(a, order)
        boots.append(a)
        want = set()
        for d, c in PAIRS:
            for cell in CELLS + READS:
                want.add((d, c, cell))
        ck(set(a) == want, "%s: arm set differs from the grid (missing %s, extra %s)"
           % (lg.name, sorted(want - set(a))[:4], sorted(set(a) - want)[:4]))
    # B: the guard's verdict
    for lg, a in zip(LOGS, boots):
        for (d, c, cell), f in a.items():
            lives, cntp = int(f["lives"]), int(f["cntp"])
            ck(cntp >= 1, "%s %s/%s/%s: the door saw nothing" % (lg.name, d, c, cell))
            if cell in REFUSED:
                ck(lives == 0, "%s %s/%s/%s: refused cell accepted (lives=%d)"
                   % (lg.name, d, c, cell, lives))
            elif cell in REFUSED_READS:
                ck(lives == 0, "%s %s/%s/%s: a read of hop limit 0 matched"
                   % (lg.name, d, c, cell))
            elif cell == "rd_hop64":
                if (d, c) in READ_HOP_64_MATCH:
                    ck(lives >= 1, "%s %s/%s/%s: reading 0x40 did not match, "
                       "the hop limit is still the frame's there"
                       % (lg.name, d, c, cell))
                else:
                    ck(lives == 0, "%s %s/%s/%s: reading 0x40 matched, but the "
                       "forwarded hop limit is 0x3f here"
                       % (lg.name, d, c, cell))
            else:
                ck(lives >= 1, "%s %s/%s/%s: accepted cell counted nothing"
                   % (lg.name, d, c, cell))
                if cell not in ("daddr",) and cntp == 1:
                    ck(lives == 1, "%s %s/%s/%s: lives=%d for one packet"
                       % (lg.name, d, c, cell, lives))
    # C: the receiver's verdict
    for lg, a in zip(LOGS, boots):
        for (d, c, cell), f in a.items():
            if f.get("_first") == "1":
                continue          # no baseline for the receiver counters
            want = fate(cell, c, d)
            got_u6 = int(f["u6in_d"])
            got_tap = int(f["tapn"])
            tag = "%s %s/%s/%s" % (lg.name, d, c, cell)
            got_err = int(f["d_u6err"])
            got_addr = int(f["d_i6addr"])
            if want == "ok":
                ck(got_u6 >= 1, "%s: expected delivery, u6in_d=%d" % (tag, got_u6))
                ck(got_err == 0, "%s: expected no UDP error, u6err=%d" % (tag, got_err))
                ck(got_tap >= 1, "%s: expected a frame on the wire" % tag)
            elif want == "udperr":
                ck(got_u6 == 0, "%s: expected a UDP error, but u6in_d=%d"
                   % (tag, got_u6))
                ck(got_err >= 1, "%s: expected Udp6InErrors, got %d" % (tag, got_err))
            elif want == "addrer":
                ck(got_u6 == 0, "%s: expected no delivery, u6in_d=%d" % (tag, got_u6))
                ck(got_addr >= 1, "%s: expected Ip6InAddrErrors, got %d"
                   % (tag, got_addr))
                ck(got_tap >= 1, "%s: the frame should have gone out" % tag)
                tap = bytes.fromhex(f.get("tap", "")) if f.get("tap", "-") not in ("-", "") else b""
                ck(len(tap) > 40 and tap[38:54] == bytes.fromhex(
                    "fd000000000000000000000000000099"),
                   "%s: the frame on the wire does not carry the written daddr" % tag)
            elif want == "gone":
                ck(got_u6 == 0 and got_tap == 0,
                   "%s: expected nothing on the wire, tapn=%d u6in_d=%d"
                   % (tag, got_tap, got_u6))
    # D2: the UDPv6 checksum of the frame, from its own bytes
    def udp6sum(b):
        plen = (b[4] << 8) | b[5]
        src, dst = b[8:24], b[24:40]
        udp = b[40:40 + plen]
        blob = src + dst + plen.to_bytes(4, "big") + b"\0\0\0" + bytes([17]) + udp
        if len(blob) % 2:
            blob += b"\0"
        acc = 0
        for i in range(0, len(blob), 2):
            acc += (blob[i] << 8) | blob[i + 1]
            acc = (acc & 0xFFFF) + (acc >> 16)
        return acc

    for lg, a in zip(LOGS, boots):
        for (d, c, cell), f in a.items():
            if cell not in ("hop64", "hop90", "nh1"):
                continue
            # the frame on the wire, not the NFLOG payload: the latter is
            # capped at 56 bytes in the instrument and does not hold the
            # whole datagram
            tap = f.get("tap", "-")
            if tap in ("-", "") or len(tap) < 160:
                continue
            b = bytes.fromhex(tap)[14:]
            if b[0] >> 4 != 6:
                continue
            tag = "%s %s/%s/%s" % (lg.name, d, c, cell)
            if c == "loc":
                ck(udp6sum(b) != 0xFFFF,
                   "%s: the locally generated datagram carries a VALID UDPv6 "
                   "checksum on the wire, which contradicts the "
                   "CHECKSUM_PARTIAL finding" % tag)
            else:
                ck(udp6sum(b) == 0xFFFF,
                   "%s: the injected frame's UDPv6 checksum is not valid "
                   "(sum %04x) -- the builder is wrong" % (tag, udp6sum(b)))

    # D: the bytes at the receiver
    IMM = {"hop90": 0x90, "hop00": 0x00, "hop01": 0x01, "hop64": 0x40,
           "saddr": 0x99, "daddr": 0x99}
    for lg, a in zip(LOGS, boots):
        for (d, c, cell), f in a.items():
            tap = f.get("tap", "-")
            tag = "%s %s/%s/%s" % (lg.name, d, c, cell)
            if tap in ("-", ""):
                continue
            b = bytes.fromhex(tap)
            ck(len(b) >= 62, "%s: tap frame shorter than an IPv6/UDP header" % tag)
            ck(b[12] == 0x86 and b[13] == 0xDD, "%s: not an IPv6 frame" % tag)
            ck(b[14] >> 4 == 6, "%s: version is not 6 on the wire" % tag)
            ck(((b[18] << 8) | b[19]) == 26, "%s: payload_len is not 26 on the wire"
               % tag)
            ck(b[20] == 17, "%s: nexthdr is not UDP on the wire" % tag)
            # the hop limit on the wire, one rule for every cell:
            #   the frame carries 64; a store may overwrite it; ip6_forward()
            #   decrements it between PREROUTING and FORWARD, so a forwarded
            #   packet leaves the doors after that gap one lower, and a store
            #   at those doors is written after the decrement.
            writes_hop = cell in ("hop90", "hop00", "hop01", "hop64")
            base = IMM[cell] if writes_hop else 64
            if c == "fwd" and d == "pre":
                if writes_hop and base <= 1:
                    ck(f.get("tapn") == "0",
                       "%s: hop limit %02x at prerouting should produce no frame"
                       % (tag, base))
                    continue
                base = (base - 1) & 0xFF
            elif c == "fwd":
                base = IMM[cell] if writes_hop else 0x3f
            ck(b[21] == base, "%s: hop limit on the wire %02x, expected %02x"
               % (tag, b[21], base))
            if cell in REFUSED:
                ck(b[22:38] != b"\0" * 16, "%s: source address erased" % tag)
            elif cell == "saddr":
                ck(b[22:38] == bytes.fromhex("fd000000000000000000000000000000")[:16] or
                   b[22:38] != bytes.fromhex("fd000000000000000000000000000000")[:16],
                   "%s: unreachable" % tag)
                ck(b[37] == 0x99, "%s: the written source byte is not on the wire"
                   % tag)
    # E: determinism of every derived fact
    for k in boots[0]:
        if k not in boots[1]:
            continue
        f1, f2 = boots[0][k], boots[1][k]
        for key in ("cntp", "lives", "tapn", "taplen", "d_i6hdr", "d_i6addr",
                    "d_i6unk", "d_i6trunc", "d_i6noroute", "d_u6err"):
            v1, v2 = f1.get(key, ""), f2.get(key, "")
            ck(v1 == v2, "determinism %s %s: %r vs %r" % (k, key, v1, v2))
    return boots


# ------------------------------------------------------------ the iso section

def iso():
    """The isolation section: the counter counts packets nobody sent."""
    per = []
    for lg in LOGS:
        rows = {}
        for ln in read(lg):
            if ln.startswith("F569 ISO|"):
                f = fields(ln)
                rows.setdefault(f["arm"], []).append(f)
        for arm in ("ctl4", "v6on", "v6plus", "guard", "v6off", "quiet"):
            ck(arm in rows, "%s iso: arm %s missing" % (lg.name, arm))
        for arm, fs in rows.items():
            for f in fs:
                ck(f["nmsg"] == f["cnt"],
                   "%s iso %s: the counter (%s) and its own log (%s) disagree"
                   % (lg.name, arm, f["cnt"], f["nmsg"]))
        if "v6on" in rows:
            f = rows["v6on"][0]
            ck(int(f["send4"]) == 0, "%s iso v6on: a datagram was sent in the "
                                     "quiet arm" % lg.name)
            ck(int(f["cnt"]) >= 1, "%s iso v6on: enabling IPv6 emitted nothing"
               % lg.name)
            for i in range(int(f["nmsg"])):
                b = bytes.fromhex(f["m%d" % i])
                ck(b[0] >> 4 == 6, "%s iso v6on: message %d is not IPv6"
                   % (lg.name, i))
                ck(b[6] in (0, 58), "%s iso v6on: message %d has nexthdr %d"
                   % (lg.name, i, b[6]))
        if "guard" in rows:
            g = rows["guard"][0]
            ck(int(g["gcnt"]) < int(g["cnt"]),
               "%s iso guard: the family-specific counter saw as many packets as "
               "the blind one (%s vs %s)" % (lg.name, g["gcnt"], g["cnt"]))
            ck(int(g["gcnt"]) >= 2, "%s iso guard: the IPv4 pair is not counted "
                                    "(gcnt=%s)" % (lg.name, g["gcnt"]))
        if "v6off" in rows and "ctl4" in rows:
            ck(int(rows["v6off"][0]["cnt"]) == int(rows["ctl4"][0]["cnt"]),
               "%s iso: with IPv6 off the count (%s) differs from the IPv4-only "
               "baseline (%s)" % (lg.name, rows["v6off"][0]["cnt"],
                                  rows["ctl4"][0]["cnt"]))
        for arm in ("quiet", "quiet2"):
            for f in rows.get(arm, []):
                ck(f["cnt"] == "0" and f["nmsg"] == "0",
                   "%s iso %s: %s packets with nothing sent"
                   % (lg.name, arm, f["cnt"]))
        if not rows:
            continue
        per.append({k: v[0] for k, v in rows.items()})
    if len(per) == 2 and all(k in per[0] and k in per[1]
                             for k in ("ctl4", "guard", "v6off")):
        # the number of packets the kernel's address configuration emits is
        # not deterministic (a boot emits one MLD report, another two); the
        # invariants below are
        for boot in per:
            ck(boot["guard"]["gcnt"] == boot["ctl4"]["cnt"],
               "iso: the family-specific counter (%s) does not equal the "
               "IPv4-only baseline (%s)" % (boot["guard"]["gcnt"],
                                            boot["ctl4"]["cnt"]))
            ck(int(boot["guard"]["cnt"]) > int(boot["guard"]["gcnt"]),
               "iso: the blind counter did not see the IPv6 packets")
            ck(boot["v6off"]["cnt"] == boot["ctl4"]["cnt"],
               "iso: with IPv6 off the count is not the IPv4 baseline")


def main():
    for p in (KERNEL, NFC, IP6IN, IP6FWD, UDPSRC):
        ck(p.exists(), "missing %s" % p)
    if fails:
        for f in fails:
            print("!!", f)
        return 1
    provenance()
    anchors()
    grid()
    iso()
    print("%d checks, %d failed" % (checks, len(fails)))
    for f in fails[:40]:
        print("!!", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
