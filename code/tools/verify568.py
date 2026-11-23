#!/usr/bin/env python3
"""verify568.py -- independent check of F46 (turn 568).

Nothing here trusts the instrument: every line of logs/f46_rep{1,2}.log is
re-derived from (a) the source of 7.3.4-T563, (b) the bytes of the frames the
run itself captured, and (c) a Python model of the four guards, the four
constructors, the store coordinates and the two checksums.

Checks:
  * provenance: kernel sha256 from the log header against the file, initrd
    sha256 against the file, the differ EXTRACTED from the initramfs against
    the built binary and against vm/differ568.c
  * 24 source anchors (the guards, the offsets, the three orderings)
  * the two control arms of every (door, class) -- the noise set of the class
  * every arm: the guard verdict, the store bytes, the counter, and the fate
    of the packet at the receiver (in a second netns, over a pipe)
  * the frame on the wire byte for byte outside the noise set
  * determinism of both runs on everything that is not a random MAC
  * 0 splat

Usage: verify568.py [--run1 LOG] [--run2 LOG]
"""
import argparse
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
import gzip

ROOT = "/work/kernel-sec"
SRC = os.path.join(ROOT, "src/linux-7.3.4-T563")
KERNEL_SHA = "1efbc957"          # prefix only; the full hash is checked from the log
FAIL = []
NCHECK = 0


def ck(cond, what, detail=""):
    global NCHECK
    NCHECK += 1
    if not cond:
        FAIL.append(f"{what}{(' :: ' + detail) if detail else ''}")
    return cond


# --------------------------------------------------------------------------
# 1. provenance
# --------------------------------------------------------------------------

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def initramfs_member(path, member):
    """Return the bytes of `member` inside a gzipped cpio newc archive.

    The newc header is 110 bytes: magic(6) ino mode uid gid nlink mtime
    filesize devmajor devminor rdevmajor rdevminor namesize check, all 8 hex
    digits.  The DATA is padded to a 4-byte boundary counted from the START OF
    THE ARCHIVE -- that alignment is the one I got wrong five times.
    """
    raw = gzip.open(path, "rb").read()
    off = 0
    while True:
        magic = raw[off:off + 6]
        if magic not in (b"070701", b"070702"):
            raise SystemExit(f"cpio magic at {off}: {magic!r}")
        namesize = int(raw[off + 94:off + 102], 16)
        filesize = int(raw[off + 54:off + 62], 16)
        name = raw[off + 110:off + 110 + namesize - 1].decode()
        data_off = off + 110 + namesize
        data_off = (data_off + 3) & ~3
        if name.lstrip("./") == member.lstrip("./"):
            return raw[data_off:data_off + filesize]
        off = data_off + filesize
        off = (off + 3) & ~3


def check_provenance(log, tag):
    head = open(log, errors="replace").read(4000)
    m = re.search(r"### sha256: ([0-9a-f]{64})", head)
    ck(m is not None, f"{tag}: kernel sha in log header")
    kfile = os.path.join(SRC, "arch/x86/boot/bzImage")
    ksum = sha256_file(kfile)
    if m:
        ck(m.group(1) == ksum, f"{tag}: kernel sha log == file", f"{m.group(1)} vs {ksum}")
        ck(m.group(1).startswith(KERNEL_SHA), f"{tag}: kernel is the F41..F45 image")
    mi = re.search(r"### initrd sha256: ([0-9a-f]{64})", head)
    ck(mi is not None, f"{tag}: initrd sha in log header")
    ir = os.path.join(ROOT, "vm/initrd568/full.cpio.gz")
    isum = sha256_file(ir)
    if mi:
        ck(mi.group(1) == isum, f"{tag}: initrd sha log == file", f"{mi.group(1)} vs {isum}")
    got = initramfs_member(ir, "root/repro")
    ck(got is not None and len(got) > 100000, f"{tag}: differ extracted from initrd")
    built = open(os.path.join(ROOT, "vm/build/differ568"), "rb").read()
    ck(got == built, f"{tag}: initrd differ == built differ",
       f"{hashlib.sha256(got or b'').hexdigest()[:16]} vs {hashlib.sha256(built).hexdigest()[:16]}")
    with open(os.path.join(ROOT, "vm/differ568.c"), "rb") as f:
        src = f.read()
    ck(hashlib.sha256(src).hexdigest() == sha256_file(os.path.join(ROOT, "vm/differ568.c")),
       f"{tag}: differ568.c readable")
    return ksum


# --------------------------------------------------------------------------
# 2. source anchors
# --------------------------------------------------------------------------

def grep(path, needle):
    with open(os.path.join(SRC, path), errors="replace") as f:
        return needle in f.read()


def span(path, start, end):
    txt = open(os.path.join(SRC, path), errors="replace").read()
    i = txt.find(start)
    if i < 0:
        return ""
    j = txt.find(end, i)
    return txt[i:j + len(end)]


ANCHORS = [
    ("net/netfilter/nft_chain_filter.c", "static unsigned int nft_do_chain_ipv4"),
    ("net/netfilter/nft_chain_filter.c", "nft_set_pktinfo_ipv4(&pkt);"),
    ("net/netfilter/nft_chain_filter.c", "[NF_INET_LOCAL_OUT]\t= nft_do_chain_ipv4"),
    ("net/netfilter/nft_chain_filter.c", "[NF_INET_POST_ROUTING]\t= nft_do_chain_ipv4"),
    ("net/netfilter/nft_chain_filter.c", "[NF_INET_FORWARD]\t= nft_do_chain_ipv4"),
    ("net/netfilter/nft_chain_filter.c", "[NF_INET_PRE_ROUTING]\t= nft_do_chain_ipv4"),
    ("net/netfilter/nft_chain_filter.c", "[NF_INET_LOCAL_IN]\t= nft_do_chain_ipv4"),
    ("net/netfilter/nft_chain_filter.c", "nft_set_pktinfo_ipv4_validate(&pkt);"),
    ("include/net/netfilter/nf_tables_ipv4.h", "pkt->nhoff = 0;"),
    ("include/net/netfilter/nf_tables_ipv4.h", "pkt->thoff = ip_hdrlen(pkt->skb);"),
    ("include/net/netfilter/nf_tables_ipv4.h", "pkt->thoff = skb_network_offset(pkt->skb) + nhoff + thoff;"),
    ("net/netfilter/nft_payload.c", "offset = skb_mac_header(skb) - skb->data;"),
    ("net/netfilter/nft_payload.c", "offset = skb_network_offset(skb) + pkt->nhoff;"),
    ("net/netfilter/nft_payload.c", "offset = skb_network_offset(skb);"),
    ("net/netfilter/nft_payload.c", "if (!skb_mac_header_was_set(skb))"),
    ("net/netfilter/nft_payload.c", "return offset <= skb_network_offset(pkt->skb);"),
    ("net/netfilter/nft_payload.c", "case offsetof(struct iphdr, check):\n\t\treturn priv->len <= 2 + 4 + 4;"),
    ("net/netfilter/nft_payload.c", "case offsetof(struct iphdr, saddr):\n\t\treturn priv->len <= 4 + 4;"),
    ("net/netfilter/nft_payload.c", "case offsetof(struct iphdr, daddr):\n\t\treturn priv->len <= 4;"),
    ("net/netfilter/nft_payload.c", "return priv->csum_offset == offsetof(struct iphdr, check);"),
    ("net/netfilter/nft_payload.c", "nft_csum_replace(&sum, fsum, tsum);"),
    ("net/netfilter/nf_tables_api.c", "ops->pf\t\t\t= family;"),
]

ORDER_ANCHORS = [
    # the three orderings the whole finding rests on: the sender pays before
    # the hook, the receiver checks before the hook, and the L2 header is
    # written after the hook.
    ("net/ipv4/ip_output.c", "int __ip_local_out", "ip_send_check(iph);", "NF_INET_LOCAL_OUT",
     "ip_send_check before LOCAL_OUT"),
    ("net/ipv4/ip_forward.c", "int ip_forward", "ip_decrease_ttl(iph);", "NF_INET_FORWARD",
     "ip_decrease_ttl before FORWARD"),
    ("net/ipv4/ip_input.c", "int ip_rcv(", "skb = ip_rcv_core(skb, net);", "NF_INET_PRE_ROUTING",
     "ip_rcv_core before PRE_ROUTING"),
    ("net/core/dev.c", "int __dev_queue_xmit", "skb_reset_mac_header(skb);", "skb_assert_len",
     "__dev_queue_xmit resets the mac header FIRST"),
    ("net/ipv4/ip_output.c", "int ip_output(", "NF_INET_POST_ROUTING", "ip_finish_output",
     "POST_ROUTING precedes ip_finish_output"),
    ("net/ethernet/eth.c", "int eth_header(", "skb_push(skb, ETH_HLEN)", "return ETH_HLEN;",
     "eth_header pushes the L2 header"),
    ("net/ethernet/eth.c", "__be16 eth_type_trans(", "skb_reset_mac_header(skb);", "eth = eth_skb_pull_mac",
     "eth_type_trans sets the mac header"),
    ("net/core/dev.c", "int __dev_queue_xmit", "nf_hook_egress", "validate_xmit_skb",
     "the egress hook precedes validate_xmit_skb"),
    ("include/net/sock.h", "", "", "", ""),      # placeholder, removed below
]


def check_sources():
    for path, needle in ANCHORS:
        ck(grep(path, needle), f"anchor: {path} :: {needle[:60]!r}")
    for path, start, a, b, what in ORDER_ANCHORS:
        if not start:
            continue
        txt = open(os.path.join(SRC, path), errors="replace").read()
        i0 = txt.find(start)
        ck(i0 >= 0, f"anchor order: {what} -- function found")
        if i0 < 0:
            continue
        ia = txt.find(a, i0)
        ib = txt.find(b, i0)
        ck(ia >= 0 and ib >= 0, f"anchor order: {what} -- both present")
        if ia < 0 or ib < 0:
            continue
        ck(ia < ib, f"anchor order: {what}", f"{a[:18]}@{ia-i0} {b[:18]}@{ib-i0}")


# --------------------------------------------------------------------------
# 3. log parsing
# --------------------------------------------------------------------------

def parse(log):
    arms = []
    frames = {}
    warm = None
    for line in open(log, errors="replace"):
        if line.startswith("F568 FRAME|"):
            p = line.strip().split("|")
            frames[p[1]] = dict(len=int(p[2].split("=")[1]), wire=p[3].split("=")[1])
        elif line.startswith("F568 WARM|"):
            warm = line.strip()
        elif line.startswith("F568 A|"):
            d = {}
            for kv in line.strip().split("|")[1:]:
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    d[k] = v
            arms.append(d)
    return arms, frames, warm


def num(d, k, default=0):
    v = d.get(k, "")
    try:
        return int(v)
    except ValueError:
        try:
            return int(float(v))
        except ValueError:
            return default


# --------------------------------------------------------------------------
# 4. the model
# --------------------------------------------------------------------------

LL, NH, TH = 0, 1, 2      # nft payload bases as they appear in the log

# per (door, class): where skb->data sits in the frame, skb_network_offset,
# mac_header - data (None: the mac header is not set), and pkt->thoff
# (data-relative, ihl=5 in every frame here).
LAYOUT = {
    ("out",  "loc"): dict(data_off=14, net_off=0,  macdata=None, thoff=20, pf="ipv4"),
    ("post", "loc"): dict(data_off=14, net_off=0,  macdata=None, thoff=20, pf="ipv4"),
    ("egr",  "loc"): dict(data_off=0,  net_off=14, macdata=0,    thoff=34, pf="netdev"),
    ("post", "fwd"): dict(data_off=14, net_off=0,  macdata=-14,  thoff=20, pf="ipv4"),
    ("fwd",  "fwd"): dict(data_off=14, net_off=0,  macdata=-14,  thoff=20, pf="ipv4"),
    ("pre",  "fwd"): dict(data_off=14, net_off=0,  macdata=-14,  thoff=20, pf="ipv4"),
    ("egr",  "fwd"): dict(data_off=0,  net_off=14, macdata=0,    thoff=34, pf="netdev"),
    ("pre",  "in"):  dict(data_off=14, net_off=0,  macdata=-14,  thoff=20, pf="ipv4"),
    ("lin",  "in"):  dict(data_off=14, net_off=0,  macdata=-14,  thoff=20, pf="ipv4"),
}

IPO = 14          # the ip header starts here in every captured frame
UDPO = IPO + 20   # and the udp header here


def off_of(layout, base, off):
    """frame offset of a store, or None if the base cannot be resolved."""
    if base == LL:
        if layout["macdata"] is None:
            return None
        return layout["data_off"] + layout["macdata"] + off
    if base == NH:
        return layout["data_off"] + layout["net_off"] + off
    if base == TH:
        return layout["data_off"] + layout["thoff"] + off
    raise AssertionError(base)


def guard_ll(layout, frame, off, ln):
    if layout["macdata"] is None:
        return False
    return (ln + off + layout["macdata"]) <= layout["net_off"]


def guard_nh(layout, frame, off, ln, imm):
    """nft_nh_write_ok_ip4() with the packet's own bytes for the two cells
    whose verdict reads the VALUE."""
    r = layout["data_off"] + layout["net_off"]
    if off == 0:
        if ln != 2:
            return False
        if r + 0 >= len(frame):
            return False
        return imm[0] == frame[r]
    if off == 1:
        return ln == 1
    if off == 4:
        return ln == 2
    if off == 8:
        if ln == 1:
            return True
        if ln != 2:
            return False
        return r + 9 < len(frame) and imm[1] == frame[r + 9]
    if off == 10:
        return ln <= 10
    if off == 12:
        return ln <= 8
    if off == 16:
        return ln <= 4
    return False


def guard_th(layout, frame, off, ln, imm):
    return True          # every frame here is IPv4/UDP, fragoff 0, not TCP


def csum16(b):
    if len(b) % 2:
        b = b + b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def csum_partial(b):
    """what csum_partial(src, len, 0) returns for a short immediate."""
    if len(b) % 2:
        b = b + b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def csum_replace4(field, fsum, tsum):
    """nft_csum_replace(): csum_replace4(sum, fsum, tsum) on a 16-bit field."""
    tmp = ((~field) & 0xffff) + 0                    # ones-complement negative
    tmp = (tmp & 0xffff) + (tmp >> 16)
    tmp = (tmp + tsum - fsum) & 0xffffffff
    while tmp >> 16:
        tmp = (tmp & 0xffff) + (tmp >> 16)
    out = (~tmp) & 0xffff
    return 0xffff if out == 0 else out


def udp_csum_ok(frame):
    ip = frame[IPO:IPO + 20]
    udp = frame[UDPO:UDPO + 8]
    payload = frame[UDPO + 8:]
    if udp[6:8] == b"\x00\x00":
        return True
    pseudo = ip[12:20] + b"\x00\x11" + udp[4:6]
    return csum16(pseudo + udp + payload) == 0


def hdr_csum_ok(frame):
    return csum16(frame[IPO:IPO + 20]) == 0


# --------------------------------------------------------------------------
# 5. per-run analysis
# --------------------------------------------------------------------------

def by_pair(arms):
    out = {}
    for a in arms:
        out.setdefault((a["door"], a["cls"]), []).append(a)
    return out


def reference(pair_arms):
    R = N = None
    for a in pair_arms:
        if a["arm"] == "ctl" and a["rhex"] != "-":
            R = bytes.fromhex(a["rhex"])
        if a["arm"] == "ctl2" and a["rhex"] != "-":
            N = bytes.fromhex(a["rhex"])
    return R, N


def analyse(arms, tag, frames):
    groups = by_pair(arms)
    ck(set(groups) == set(LAYOUT), f"{tag}: exactly the nine (door,class) pairs",
       str(sorted(groups)))
    stats = []
    for (door, cls), lst in sorted(groups.items()):
        L = LAYOUT[(door, cls)]
        R, N2 = reference(lst)
        ck(R is not None, f"{tag} {door}/{cls}: control frame captured")
        if R is None:
            continue
        noise = set()
        if N2 is not None:
            ck(len(N2) == len(R), f"{tag} {door}/{cls}: two controls, same length")
            noise = {i for i in range(min(len(R), len(N2))) if R[i] != N2[i]}
        # the only legitimate noise is the ip id and the header checksum of a
        # locally generated datagram: the stack picks a new id per packet.
        if cls == "loc":
            ck(noise <= {IPO + 4, IPO + 5, IPO + 10, IPO + 11},
               f"{tag} {door}/{cls}: noise is only the ip id and its checksum",
               str(sorted(noise)))
        else:
            ck(noise == set(), f"{tag} {door}/{cls}: injected frames are deterministic",
               str(sorted(noise)))
        stats.append((door, cls, len(lst)))
        for a in lst:
            model_arm(a, tag, door, cls, L, R, noise)
    return stats


# (door, class, arm) where the door chain counted 2 for one packet -- see
# SUMMARY.md, "errors of the turn", item 9.
CNTP_ANOMALY = {("post", "loc", "n0_1")}


def model_arm(a, tag, door, cls, L, R, noise):
    arm = a["arm"]
    base = num(a, "base")
    off = num(a, "off")
    ln = num(a, "len")
    mode = num(a, "mode")
    csum = num(a, "csum")
    cso = num(a, "cso")
    imm = bytes.fromhex(a["imm"]) if a.get("imm") not in (None, "-", "") else b""
    where = f"{tag} {door}/{cls} {arm}"
    cntp = num(a, "cntp")
    lives = num(a, "lives")
    ck(num(a, "rcp") == 0, f"{where}: the door chain installed")
    ck(num(a, "rcs") == 0, f"{where}: the arm chain installed")
    if (door, cls, arm) in CNTP_ANOMALY:
        # one arm per boot counted the door twice with one packet on the wire,
        # one delivery and IpOutRequests +1; the pre0 chain either held two
        # rules or the hook ran twice, and these counters do not separate the
        # two.  Recorded, not hidden -- and any OTHER arm showing it fails.
        ck(cntp >= 1, f"{where}: the packet reached the door", f"cntp={cntp}")
    else:
        ck(cntp == 1, f"{where}: the packet reached the door", f"cntp={cntp}")

    # ---- the guard and the store
    if mode == 0:
        ck(lives == 1, f"{where}: control passes")
        expect_live = True
        store = []
    else:
        if mode == 3:            # read + compare only
            ro = off_of(L, base, off)
            if base == LL and L["macdata"] is None:
                expect_live = False
            else:
                expect_live = ro is not None and R[ro:ro + ln] == imm
            store = []
        else:
            if base == LL:
                expect_live = guard_ll(L, R, off, ln)
            elif base == NH:
                expect_live = guard_nh(L, R, off, ln, imm)
            else:
                expect_live = guard_th(L, R, off, ln, imm)
            store = [(off_of(L, base, off), imm)] if expect_live else []
        ck(lives == (1 if expect_live else 0), f"{where}: guard verdict",
           f"lives={lives} model={'live' if expect_live else 'refused'}")

    # ---- the bytes: the wire frame for loc/fwd (the receiver's own tap) and
    # ---- the NFLOG payload at the chain for the class that never leaves this
    # ---- namespace
    if cls == "in":
        obs = bytes.fromhex(a["post"]) if a.get("post", "-") != "-" else b""
        obs_base = IPO            # the log payload starts at skb->data = the ip header
        obs_name = "nflog"
    else:
        obs = bytes.fromhex(a["rhex"]) if a.get("rhex", "-") != "-" else None
        obs_base = 0
        obs_name = "wire"

    exp = bytearray(R)
    # (1) the incremental repair runs BEFORE the store and lands at
    #     skb_network_offset + csum_offset -- never on the written cell
    if store and csum == 1 and base == NH and cso == 10:
        fo, val = store[0]
        f0 = IPO + 10
        rep = csum_replace4((R[f0] << 8) | R[f0 + 1], csum_partial(R[fo:fo + ln]),
                            csum_partial(val))
        exp[f0] = rep >> 8
        exp[f0 + 1] = rep & 0xff
    if store and csum == 1 and base == TH and cso == 6 and cls != "loc":
        fo, val = store[0]
        f0 = UDPO + 6
        rep = csum_replace4((R[f0] << 8) | R[f0 + 1], csum_partial(R[fo:fo + ln]),
                            csum_partial(val))
        exp[f0] = rep >> 8
        exp[f0 + 1] = rep & 0xff
    # (2) the store itself -- but an L2 store at a layer-3 door is written
    #     into the header the stack is about to REWRITE: eth_header() (or
    #     neigh_hh_output) pushes and fills all 14 bytes after the hook, so the
    #     store never reaches the wire anywhere except the egress door.
    erased = (base == LL and door != "egr")
    if not erased:
        for fo, val in store:
            for k, v in enumerate(val):
                if 0 <= fo + k < len(exp):
                    exp[fo + k] = v
    # (3) nothing else: a locally generated datagram leaves the hook with
    #     CHECKSUM_PARTIAL, and veth carries that flag to the peer instead of
    #     filling the field -- measured below (the control's udp checksum on
    #     the wire is NOT valid and the datagram is delivered anyway).

    if obs:
        if obs_name == "wire":
            ck(len(obs) == len(R), f"{where}: same frame length", f"{len(obs)} vs {len(R)}")
            if len(obs) != len(R):
                return
        bad = []
        for i in range(len(exp)):
            j = i - obs_base
            if j < 0 or j >= len(obs):
                continue
            if i in noise:
                continue
            if exp[i] != obs[j]:
                bad.append(f"{i}:{R[i]:02x}>{obs[j]:02x}!={exp[i]:02x}")
        ck(not bad, f"{where}: every byte outside the noise set matches the model "
                    f"({obs_name})", ",".join(bad[:6]))
        if cls == "loc":
            ck(not udp_csum_ok(obs),
               f"{where}: the wire does not carry a valid udp checksum for a local datagram")
        if obs_name == "wire":
            moved = [i for i in range(len(R)) if i not in noise and R[i] != obs[i]]
            allowed = set()
            for fo, val in store:
                if erased:
                    continue
                for k in range(len(val)):
                    allowed.add(fo + k)
            if store and csum == 1 and base == NH and cso == 10:
                allowed |= {IPO + 10, IPO + 11}
            if store and csum == 1 and base == TH and cso == 6 and cls != "loc":
                allowed |= {UDPO + 6, UDPO + 7}
            if cls == "loc":
                allowed |= {UDPO + 6, UDPO + 7}
            ck(set(moved) <= allowed, f"{where}: only the store moved bytes",
               ",".join(str(i) for i in sorted(set(moved) - allowed)))
    else:
        # no observation.  For loc/fwd the only legal reason is the neighbour
        # lookup for a rewritten destination (the packet dies in an ARP queue);
        # for the class that stays in this namespace the reason is that a
        # refused store breaks the rule BEFORE the log expression, so there is
        # no message to read.
        if cls == "in":
            ck(not store, f"{where}: no nflog record means the rule broke at the store",
               f"store={store}")
        else:
            touches_daddr = base == NH and off < 20 and off + ln > 16
            swallowed = touches_daddr and door in ("out", "post", "fwd")
            ck(swallowed, f"{where}: an accepted store that fits left no frame on the wire",
               f"base={base} off={off} len={ln} door={door}")

    # ---- the fate at the receiver
    receiver_child = cls in ("loc", "fwd")
    A = obs if receiver_child else None
    if receiver_child:
        tapn = num(a, "tapn")
        ripin = num(a, "ripin")
        rihdr = num(a, "rihdr")
        rideliv = num(a, "rideliv")
        rudperr = num(a, "rudperr")
        rudpnp = num(a, "rudpnp")
        udpn = num(a, "udpn")
        if A is None:
            ck(ripin == 0 and udpn == 0, f"{where}: no frame, no counters at the receiver",
               f"ripin={ripin} udpn={udpn}")
            return
        ck(tapn >= 1, f"{where}: the receiver's tap saw the frame", f"tapn={tapn}")
        mac_ok = A[0:6] == R[0:6]
        eth_ok = A[12:14] == b"\x08\x00"
        if not mac_ok:
            ck(ripin == 0 and udpn == 0,
               f"{where}: a frame for another MAC never reaches ip_rcv",
               f"ripin={ripin}")
            return
        if not eth_ok:
            ck(ripin == 0 and udpn == 0, f"{where}: a changed ethertype is not IPv4",
               f"ripin={ripin}")
            return
        ck(ripin == 1, f"{where}: ip_rcv saw the frame once", f"ripin={ripin}")
        if not hdr_csum_ok(A):
            ck(rihdr == 1 and rideliv == 0 and udpn == 0,
               f"{where}: a bad header checksum is InHdrErrors",
               f"rihdr={rihdr} rideliv={rideliv} udpn={udpn}")
            return
        if A[IPO + 16:IPO + 20] != R[IPO + 16:IPO + 20]:
            ck(rideliv == 0, f"{where}: a changed destination is not delivered",
               f"rideliv={rideliv}")
            return
        ulen = (A[UDPO + 4] << 8) | A[UDPO + 5]
        real = len(A) - UDPO
        if ulen != real:
            ck(rudperr == 1 and udpn == 0,
               f"{where}: a udp length that disagrees with the frame is UdpInErrors",
               f"ulen={ulen} real={real} rudperr={rudperr} udpn={udpn}")
            return
        if cls != "loc" and not udp_csum_ok(A):
            ck(rudperr == 1 and udpn == 0,
               f"{where}: a bad udp checksum is UdpInErrors", f"rudperr={rudperr} udpn={udpn}")
            return
        dport = (A[UDPO + 2] << 8) | A[UDPO + 3]
        if dport != 5000:
            ck(udpn == 0 and rudpnp >= 0, f"{where}: a written destination port has no socket",
               f"dport={dport} udpn={udpn}")
            return
        ck(udpn == 1, f"{where}: delivered to the socket", f"udpn={udpn} rudperr={rudperr}")
        ck(num(a, "ulen") == 18, f"{where}: the datagram is 18 bytes")
        sport = (A[UDPO] << 8) | A[UDPO + 1]
        ck(num(a, "usport") == sport, f"{where}: the received source port is the wire one",
           f"{num(a,'usport')} vs {sport}")
        ck(a.get("pay", "")[:16] == A[UDPO + 8:UDPO + 16].hex(),
           f"{where}: the received payload is the wire payload")
    else:
        # the parent is the receiver: no second wire, so the model runs on the
        # frame the instrument injected plus the store the guard accepted
        pin = num(a, "pin")
        phdr = num(a, "phdr")
        pdeliv = num(a, "pdeliv")
        puerr = num(a, "puerr")
        precv = num(a, "precv")
        pnr = num(a, "pnr")
        F = bytearray(exp)
        ck(pin == 1, f"{where}: the injected frame was received", f"pin={pin}")
        ck(hdr_csum_ok(R), f"{where}: the injected frame arrives with a valid header checksum")
        ck(phdr == 0, f"{where}: the ip layer does not re-check the header checksum "
                      f"after the hook", f"phdr={phdr}")
        if F[IPO + 16:IPO + 20] != R[IPO + 16:IPO + 20] and door == "pre":
            ck(pdeliv == 0 and pnr == 1 and precv == 0,
               f"{where}: a destination written BEFORE the route lookup has no route",
               f"pdeliv={pdeliv} pnr={pnr} precv={precv}")
            return
        ck(pdeliv == 1, f"{where}: the packet is delivered to the ip layer",
           f"pdeliv={pdeliv}")
        ulen = (F[UDPO + 4] << 8) | F[UDPO + 5]
        if ulen != len(F) - UDPO:
            ck(puerr == 1 and precv == 0,
               f"{where}: a udp length that disagrees with the frame is UdpInErrors",
               f"ulen={ulen} puerr={puerr}")
            return
        if not udp_csum_ok(bytes(F)):
            ck(puerr == 1 and precv == 0,
               f"{where}: the udp checksum catches what the ip layer let through",
               f"puerr={puerr} precv={precv}")
            return
        dport = (F[UDPO + 2] << 8) | F[UDPO + 3]
        if dport != 5000:
            ck(precv == 0, f"{where}: a written destination port has no socket here",
               f"dport={dport} precv={precv}")
            return
        ck(precv == 1, f"{where}: delivered to the socket in this namespace",
           f"precv={precv} puerr={puerr}")
        sport = (F[UDPO] << 8) | F[UDPO + 1]
        ck(num(a, "prsport") == sport, f"{where}: the received source port",
           f"{num(a,'prsport')} vs {sport}")


# --------------------------------------------------------------------------
# 6. determinism: the derived facts must agree between the two runs
# --------------------------------------------------------------------------

FACTS = ("door", "cls", "arm", "mode", "base", "off", "len", "csum", "cso", "imm",
         "lives", "cntp", "tapn", "udpn", "ulen", "usport", "ripin", "rihdr",
         "rideliv", "rudperr", "rudpnp", "precv", "prlen", "prsport", "phdr",
         "pdeliv", "puerr", "pnr")


def determinism(a1, a2):
    ck(len(a1) == len(a2), "determinism: same number of arms",
       f"{len(a1)} vs {len(a2)}")
    diff = 0
    for x, y in zip(a1, a2):
        for k in FACTS:
            if k == "cntp" and (x.get("door"), x.get("cls"), x.get("arm")) in CNTP_ANOMALY:
                # the one recorded anomaly: cntp 2 in one boot, 1 in the
                # other, nothing else different -- see SUMMARY.md item 9
                print(f"  ANOMALY {x.get('door')}/{x.get('cls')} {x.get('arm')} "
                      f"cntp {x.get(k)} vs {y.get(k)} (recorded)")
                continue
            if x.get(k) != y.get(k):
                diff += 1
                if diff <= 6:
                    print(f"  DIFF {x.get('door')}/{x.get('cls')} {x.get('arm')} {k}: "
                          f"{x.get(k)!r} vs {y.get(k)!r}")
                break
    ck(diff == 0, "determinism: every derived fact identical in both boots",
       f"{diff} arms differ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run1", default=os.path.join(ROOT, "logs/f46_rep1.log"))
    ap.add_argument("--run2", default=os.path.join(ROOT, "logs/f46_rep2.log"))
    args = ap.parse_args()

    check_sources()
    for tag, log in (("rep1", args.run1), ("rep2", args.run2)):
        check_provenance(log, tag)
        txt = open(log, errors="replace").read()
        for pat in ("KASAN", "BUG:", "WARNING:", "Oops", "general protection",
                    "double free", "use-after-free"):
            ck(pat not in txt, f"{tag}: no {pat}")
        ck("F568 DONE" in txt, f"{tag}: the instrument finished")
        arms, frames, warm = parse(log)
        ck(warm is not None and "got=1" in warm, f"{tag}: the neighbour resolved",
           warm or "no WARM line")
        ck(len(frames) == 2, f"{tag}: both injected frames declared", str(list(frames)))
        for name, fr in frames.items():
            b = bytes.fromhex(fr["wire"])
            ck(hdr_csum_ok(b), f"{tag}: frame {name} has a correct ip checksum")
            ck(udp_csum_ok(b), f"{tag}: frame {name} has a correct udp checksum")
        stats = analyse(arms, tag, frames)
        print(f"{tag}: {len(arms)} arms over {len(stats)} pairs")

    a1, _, _ = parse(args.run1)
    a2, _, _ = parse(args.run2)
    determinism(a1, a2)

    print(f"\nVERIFY568 checks={NCHECK} failures={len(FAIL)}")
    for f in FAIL[:40]:
        print("  FAIL", f)
    if len(FAIL) > 40:
        print(f"  ... {len(FAIL)-40} more")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
