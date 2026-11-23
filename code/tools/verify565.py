#!/usr/bin/env python3
"""verify565.py -- independent check of turn 565 / F43.

The transport base `@th` across four envelopes and two `meta protocol` gates,
the TCP doff guard, the three coordinate systems side by side, and the
checksum path (NFT_PAYLOAD_CSUM_INET) that no earlier turn measured.

What this script does NOT do: it does not read the C instrument's intent.  It
reads the LOG, rebuilds every frame from the logged bytes, derives the hook
layout from the frame itself (tag count, PPPoE header, IP version), and then
recomputes the pktinfo that nf_tables builds in the bridge family, the verdict
of every write guard that stands in the way, the byte each accepted store must
land on, and -- for the checksum section -- whether the datagram is valid from
its own bytes, which is checked against what the receiver's sockets actually
returned.

Exit 0 = every check passed, 1 = a discrepancy (printed).
"""
import gzip
import hashlib
import io
import os
import re
import struct
import sys

ROOT = "/work/kernel-sec"
IMG = ROOT + "/src/linux-7.3.4-T563/arch/x86/boot/bzImage"
SRC = ROOT + "/src/linux-7.3.4-T563"
BIN = ROOT + "/vm/build/differ565"
LOGS = os.environ.get(
    "F43_LOGS",
    "/work/kernel-sec/logs/f43_rep1.log,/work/kernel-sec/logs/f43_rep2.log"
).split(",")

ok = 0
bad = 0
fails = []


def check(cond, what, detail=""):
    global ok, bad
    if cond:
        ok += 1
    else:
        bad += 1
        fails.append("%s%s" % (what, (": " + detail) if detail else ""))
    return cond


def eq(got, want, what):
    return check(got == want, what, "got %r want %r" % (got, want))


def read(path):
    with open(path, "rb") as f:
        return f.read()


def text(path):
    return read(path).decode("utf-8", "replace").replace("\r\n", "\n")


# ---------------------------------------------------------------- frame model

def hx(s):
    if not s or s == "-":
        return b""
    return bytes.fromhex(s)


def be16(b, o):
    return (b[o] << 8) | b[o + 1]


def be32(b, o):
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


class Frame(object):
    """Everything the hook can see, derived from the bytes alone."""

    def __init__(self, tag, raw):
        self.tag = tag
        self.wire = raw
        self.ethtype = be16(raw, 12)
        n = 0
        off = 12
        # count 802.1Q / 802.1AD tags in the bytes
        while be16(raw, off) in (0x8100, 0x88A8, 0x9100) and off + 6 <= len(raw):
            n += 1
            off += 4
        self.ntags = n
        self.inner_type = be16(raw, off)
        payload = off + 2
        self.pppoe = (self.ntags == 0 and self.ethtype == 0x8864)
        if self.pppoe:
            self.pppproto = be16(raw, 20)
            self.ip_off = 22
        else:
            self.pppproto = None
            self.ip_off = payload
        self.ipver = raw[self.ip_off] >> 4
        if self.ipver == 4:
            self.ihl = (raw[self.ip_off] & 0x0f) * 4
            self.ipproto = raw[self.ip_off + 9]
            self.totlen = be16(raw, self.ip_off + 2)
        elif self.ipver == 6:
            self.ihl = 40
            self.ipproto = raw[self.ip_off + 6]
            self.totlen = 40 + be16(raw, self.ip_off + 4)
        else:
            self.ihl = 0
            self.ipproto = None
            self.totlen = 0
        self.l4_off = self.ip_off + self.ihl
        # the frame as the bridge hook sees it: the outermost tag was moved to
        # skb->vlan_tci by skb_vlan_untag() before any hook runs (F38)
        self.hook = raw[4:] if self.ntags >= 1 else raw
        if self.ntags >= 1:
            self.hook_ip = self.ip_off - 4
            self.hook_l4 = self.l4_off - 4
        else:
            self.hook_ip = self.ip_off
            self.hook_l4 = self.l4_off
        self.h_proto = be16(self.hook, 12)

    def skb_protocol(self):
        """skb->protocol after eth_type_trans()/skb_vlan_untag():
        vlan_set_encap_proto() replaces the outer TPID by the encapsulated
        ethertype, so a single-tagged IPv4 frame becomes 0x0800 and a Q-in-Q
        frame becomes 0x8100 (the inner TPID)."""
        if self.ntags >= 1:
            return self.inner_type if self.ntags == 1 else 0x8100
        return self.ethtype


def pktinfo(fr, gate):
    """(valid, nhoff, thoff) as nft_do_chain_bridge/nft_meta build it.

    thoff is in skb->data coordinates, and skb_network_offset() is 0 in the
    bridge hook (F41: the @nh store on a bare frame wrote frame byte 22 = 14+8),
    so the frame byte a transport write lands on is 14 + thoff + off.
    """
    valid = False
    nhoff = 0
    if fr.h_proto == 0x0800 and fr.ipver == 4:
        valid = True
    elif fr.h_proto == 0x86DD and fr.ipver == 6:
        valid = True
    if not valid and gate:
        sp = fr.skb_protocol()
        if sp == 0x8100:
            # nft_meta_pktinfo_may_update(): nhoff = VLAN_HLEN, ethertype read
            # at mac+16 -- the encapsulated proto of the tag still in bytes
            inner = be16(fr.hook, 16)
            if inner == 0x0800 and fr.hook_ip == 18:
                valid, nhoff = True, 4
        elif sp == 0x8864:
            # nhoff = PPPOE_SES_HLEN + skb_network_offset(); the proto byte
            # decides whether the inner frame is IP at all
            if fr.pppproto == 0x0021:
                valid, nhoff = True, 8
            elif fr.pppproto == 0x0057:
                valid, nhoff = True, 8
    thoff = nhoff + fr.ihl
    return valid, nhoff, thoff


def ll_write_ok(fr, off, ln):
    """nft_ll_write_ok(): off+len <= network_header - mac_header + vlan_hlen.
    network_header - mac_header is 14 in the hook frame; the tag in metadata
    adds VLAN_HLEN back (the payload view is adjusted by nft_payload_copy_vlan)."""
    vlan_hlen = 4 if fr.ntags >= 1 else 0
    return off + ln <= 14 + vlan_hlen


def th_write_ok(fr, off, ln):
    """nft_th_write_ok(): only TCP restricts, and only the ack_seq window."""
    if fr.ipproto != 6:
        return True
    doff = 12          # offsetof(struct tcphdr, ack_seq) + sizeof(__be32)
    return off > doff or off + ln <= doff


def nh_write_ok(fr, off, ln, imm):
    """nft_nh_write_ok() through the ip4 white list, as F41/F42 measured it:
    cells 0..3/4..7 are allowed when the value's first byte keeps the version
    nibble (case 0 compares imm[0] with data[0]), 8..19 unconditional, and
    everything from 20 is refused.  The value-comparing cells are modelled
    from the hook frame itself."""
    if fr.ipver != 4:
        return False
    if off in (0, 2):
        return imm[0] == fr.hook[14]        # data[0] == the first hook byte
    if off in (4, 6):
        return True
    if off == 8 and ln >= 2 and off + ln == 10:
        return imm[1] == fr.hook[22]        # data[9]: the low byte of id+1
    if 8 <= off <= 19 and off + ln <= 20:
        return True
    return False


# ---------------------------------------------------------------- the log

def parse_log(path):
    frames = {}
    rows = []
    meta = {"kernel": None, "sha": None, "initrd": None, "initrd_sha": None,
            "version": None}
    splat = []
    for ln in text(path).split("\n"):
        if ln.startswith("F565 FRAME|"):
            f = dict(x.split("=", 1) for x in ln.strip().split("|")[2:] if "=" in x)
            tag = ln.split("|")[1]
            frames[tag] = hx(f["wire"])
        elif ln.startswith("F565 R|"):
            rows.append(dict(x.split("=", 1)
                             for x in ln.strip().split("|")[1:] if "=" in x))
        elif ln.startswith("### kernel: "):
            meta["kernel"] = ln.split(": ", 1)[1].strip()
        elif ln.startswith("### sha256: "):
            meta["sha"] = ln.split(": ", 1)[1].strip()
        elif ln.startswith("### initrd: "):
            meta["initrd"] = ln.split(": ", 1)[1].strip()
        elif ln.startswith("### initrd sha256: "):
            meta["initrd_sha"] = ln.split(": ", 1)[1].strip()
        elif "Linux version 7.3.4" in ln and meta["version"] is None:
            meta["version"] = "7.3.4"
        for pat in ("KASAN", "BUG:", "Oops", "WARNING:", "general protection"):
            if pat in ln and not ln.startswith("F565"):
                splat.append(ln.strip()[:120])
    return frames, rows, meta, splat


# ---------------------------------------------------------------- checksums

def ones_sum(data, acc=0):
    if len(data) % 2:
        data = data + b"\x00"
    for i in range(0, len(data), 2):
        acc += (data[i] << 8) | data[i + 1]
    while acc >> 16:
        acc = (acc & 0xffff) + (acc >> 16)
    return acc


def udp_csum_ok(fr, cap):
    """Validate the UDP checksum of the captured frame, from its own bytes."""
    ip = fr.ip_off
    l4 = fr.l4_off
    ulen = len(cap) - l4 if fr.ipver == 4 else (fr.totlen - fr.ihl)
    if fr.ipver == 4:
        ulen = fr.totlen - fr.ihl
    seg = cap[l4:l4 + ulen]
    if len(seg) < 8 or len(seg) != ulen:
        return None, ulen
    field = (seg[6] << 8) | seg[7]
    if fr.ipver == 4 and field == 0:
        return "none", ulen        # legal "not computed"
    body = seg
    if fr.ipver == 4:
        pseudo = cap[ip + 12:ip + 20] + bytes([0, fr.ipproto]) + \
            struct.pack(">H", ulen)
    else:
        pseudo = cap[ip + 8:ip + 40] + struct.pack(">I", ulen) + \
            bytes([0, 0, 0, fr.ipproto])
    acc = ones_sum(pseudo + body)
    return ("ok" if acc == 0xffff else "bad"), ulen


def rebuild_with_csum(fr, ctl, at, imm):
    """The control frame with `imm` stored at `at`, and the UDP checksum
    recomputed from the bytes -- the model the kernel must match when
    NFTA_PAYLOAD_CSUM_TYPE is NFT_PAYLOAD_CSUM_INET."""
    b = bytearray(ctl)
    for i, x in enumerate(imm):
        if at + i < len(b):
            b[at + i] = x
    ip, l4 = fr.ip_off, fr.l4_off
    ulen = fr.totlen - fr.ihl
    # a store into the checksum field itself cannot be saved by CSUM_INET:
    # nft_payload_csum_inet() runs first and skb_store_bits() overwrites its
    # result, so the field ends up holding exactly the immediate
    if at <= l4 + 7 and at + len(imm) > l4 + 6:
        return bytes(b)
    b[l4 + 6] = 0
    b[l4 + 7] = 0
    seg = bytes(b[l4:l4 + ulen])
    if fr.ipver == 4:
        pseudo = bytes(b[ip + 12:ip + 20]) + bytes([0, fr.ipproto]) + \
            struct.pack(">H", ulen)
    else:
        pseudo = bytes(b[ip + 8:ip + 40]) + struct.pack(">I", ulen) + \
            bytes([0, 0, 0, fr.ipproto])
    c = (~ones_sum(pseudo + seg)) & 0xffff
    if c == 0:
        c = 0xffff
    b[l4 + 6] = (c >> 8) & 0xff
    b[l4 + 7] = c & 0xff
    return bytes(b)


# ---------------------------------------------------------------- main

def main():
    L = [parse_log(p) for p in LOGS]
    frames, rows, meta, splat = L[0]
    F = {t: Frame(t, raw) for t, raw in frames.items()}

    # ---- provenance -------------------------------------------------------
    eq(len(L), 2, "two boots")
    want_sha = hashlib.sha256(read(IMG)).hexdigest()
    for i, (_, _, m, _) in enumerate(L):
        eq(m["sha"], want_sha, "boot %d: kernel sha in the log == the file on disk" % i)
        check(m["kernel"] and m["kernel"].endswith("arch/x86/boot/bzImage"),
              "boot %d: the log names the kernel it booted" % i, str(m["kernel"]))
        eq(m["version"], "7.3.4", "boot %d: /proc/version says 7.3.4" % i)
        eq(hashlib.sha256(read(m["initrd"])).hexdigest(), m["initrd_sha"],
           "boot %d: initrd sha in the log == the file on disk" % i)
        hashes = dict(ln.split() for ln in
                      text(ROOT + "/logs/f43_initrd_hashes.txt").split("\n") if ln)
        eq(hashes["full"], m["initrd_sha"],
           "boot %d: the initrd is the one f43_run.sh recorded" % i)

    # the differ inside the initrd is the binary we built
    raw = gzip.decompress(read(meta["initrd"]))
    pos, found = 0, None
    while pos + 110 <= len(raw):
        hdr = raw[pos:pos + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            break
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = raw[pos + 110:pos + 110 + namesize - 1].decode()
        data_at = pos + 110 + namesize
        data_at = (data_at + 3) & ~3
        if name == "root/repro":
            found = raw[data_at:data_at + filesize]
            break
        pos = (data_at + filesize + 3) & ~3
    check(found is not None, "the differ is inside the initrd as root/repro")
    if found:
        eq(hashlib.sha256(found).hexdigest(),
           hashlib.sha256(read(BIN)).hexdigest(),
           "the binary the VM ran is the binary on disk")

    eq(splat, [], "no KASAN/BUG/Oops/WARNING lines in the log")

    # ---- source anchors: the model's constants must still be in the tree ---
    def src(rel):
        return text(SRC + "/" + rel)

    payload = src("net/netfilter/nft_payload.c")
    check("offset = nft_thoff(pkt);" in payload,
          "@th read and store both use nft_thoff(pkt)")
    eq(payload.count("offset = nft_thoff(pkt);"), 2,
       "@th read and store use it exactly twice (no asymmetry like @nh)")
    check("csum_offset = offset + priv->csum_offset;" in payload,
          "the inet csum update is aimed at base + csum_offset")
    check("offset += priv->offset;" in payload,
          "the store is aimed at base + priv->offset (a different byte)")
    check("unsigned int doff = offsetof(struct tcphdr, ack_seq) +\n\t\tsizeof(__be32);"
          in payload or "offsetof(struct tcphdr, ack_seq) + sizeof(__be32)" in payload,
          "nft_th_write_ok()'s doff is ack_seq+4 = 12")
    ipv4 = src("include/net/netfilter/nf_tables_ipv4.h")
    check("pkt->thoff = skb_network_offset(pkt->skb) + nhoff + thoff;" in ipv4,
          "thoff = network offset + nhoff + ihl*4 in the validate path")
    meta_c = src("net/netfilter/nft_meta.c")
    check("nhoff = PPPOE_SES_HLEN;" in meta_c, "meta uses PPPOE_SES_HLEN")
    check("nhoff = VLAN_HLEN;" in meta_c, "meta uses VLAN_HLEN")
    check("nhoff += skb_network_offset(skb);" in meta_c,
          "meta adds skb_network_offset to nhoff")
    check("__nft_set_pktinfo_ipv4_validate(pkt, nhoff)" in meta_c,
          "meta rebuilds pktinfo through the same validate path")
    skb_c = src("net/core/skbuff.c")
    check("__vlan_hwaccel_put_tag(skb, skb->protocol, vlan_tci);" in skb_c,
          "skb_vlan_untag moves the tag to metadata")
    check("vlan_set_encap_proto(skb, vhdr);" in skb_c,
          "skb_vlan_untag rewrites skb->protocol to the encapsulated proto")
    check("eth_type_vlan" in src("include/linux/if_vlan.h"), "eth_type_vlan exists")
    pppoe = src("drivers/net/ppp/pppoe.c")
    check("__get_item(pn, ph->sid, eth_hdr(skb)->h_source, dev->ifindex)"
          in pppoe,
          "pppoe_rcv() finds the session by (sid, source MAC, ifindex)")
    check("if (skb->len < len)" in pppoe and "ph = pppoe_hdr(skb);" in pppoe,
          "pppoe_rcv() gates on the length field, never on ver/type or code")
    core = src("net/netfilter/nft_chain_filter.c")
    check("switch (eth_hdr(skb)->h_proto)" in core,
          "nft_do_chain_bridge builds pktinfo from eth_hdr()->h_proto")

    # ---- the frame model itself -------------------------------------------
    for tag in ("p", "w", "q", "ps", "pt", "pst", "pu", "psu", "ps6"):
        check(tag in F, "the log contains the frame %s" % tag)
    if not all(t in F for t in ("p", "w", "q", "ps")):
        print("checks: %d ok, %d failed" % (ok, bad))
        for f in fails:
            print("FAIL: " + f)
        return 1
    eq(F["p"].hook_l4, 34, "bare: the transport header is at frame byte 34")
    eq(F["w"].hook_l4, 34, "802.1Q: the tag is not in the hook frame (byte 34)")
    eq(F["q"].hook_l4, 38, "Q-in-Q: one tag stays in the bytes (byte 38)")
    eq(F["ps"].hook_l4, 42, "PPPoE: 14+8+20 (byte 42)")
    eq(F["ps6"].hook_l4, 62, "IPv6 in PPPoE: 14+8+40 (byte 62)")
    eq(F["ps"].h_proto, 0x8864, "PPPoE: eth_hdr()->h_proto is 0x8864")
    eq(F["w"].h_proto, 0x0800, "802.1Q: eth_hdr()->h_proto is the inner 0x0800")
    eq(F["q"].h_proto, 0x8100, "Q-in-Q: eth_hdr()->h_proto is the inner TPID")
    eq(F["w"].skb_protocol(), 0x0800, "802.1Q: skb->protocol after untag is 0x0800")
    eq(F["q"].skb_protocol(), 0x8100, "Q-in-Q: skb->protocol after untag is 0x8100")
    eq(F["ps"].skb_protocol(), 0x8864, "PPPoE: skb->protocol is 0x8864")

    # ---- pktinfo per envelope and gate ------------------------------------
    WANT = {("p", 0): (True, 34), ("p", 1): (True, 34),
            ("w", 0): (True, 34), ("w", 1): (True, 34),
            ("q", 0): (False, 0), ("q", 1): (True, 38),
            ("ps", 0): (False, 0), ("ps", 1): (True, 42),
            ("pt", 0): (True, 34), ("pst", 0): (False, 0),
            ("pst", 1): (True, 42), ("ps6", 0): (False, 0),
            ("ps6", 1): (True, 62)}
    for (tag, gate), (wvalid, wl4) in WANT.items():
        fr = F[tag]
        valid, nhoff, thoff = pktinfo(fr, gate)
        eq(valid, wvalid, "%s gate %d: pktinfo valid" % (tag, gate))
        if wvalid:
            eq(14 + thoff, wl4,
               "%s gate %d: the transport base lands on byte 14+thoff"
               % (tag, gate))

    # ---- every arm, both boots -------------------------------------------
    def arm_index(rows):
        idx = {}
        for r in rows:
            idx.setdefault((r["sec"], r["env"], r["gate"], r["arm"]), []).append(r)
        return idx

    A = arm_index(rows)
    check(len(rows) >= 120, "the battery has at least 120 rows", str(len(rows)))

    # control captures: one per envelope, from the first ctl arm
    ctl = {}
    for (sec, env, gate, arm), rs in A.items():
        if arm == "ctl" and env not in ctl:
            ctl[env] = hx(rs[0]["rhex"])
    for env in ("p", "w", "q", "ps", "pt", "pst", "pu", "psu", "ps6"):
        check(env in ctl, "a control capture exists for %s" % env)
        if env in ctl and env in F:
            eq(len(ctl[env]), len(F[env].hook),
               "%s: the control capture is the hook frame" % env)

    def imm_of(r):
        return hx(r["imm"])

    counted = 0
    for (sec, env, gate, arm), rs in sorted(A.items()):
        r = rs[0]
        fr = F[env]
        gi = int(gate)
        eq(r["rc"], "0", "%s/%s/%s: the rule installed" % (sec, env, arm))
        eq(r["acks"], "1", "%s/%s/%s: one ack" % (sec, env, arm))
        eq(r["snd"], "0", "%s/%s/%s: the frame was sent" % (sec, env, arm))
        if arm == "ctl":
            eq(r["live"], "1", "%s/%s: the control counter counts the frame" % (sec, env))
            continue
        off, ln = int(r["off"]), int(r["len"])
        base = int(r["base"])
        imm = imm_of(r)
        valid, nhoff, thoff = pktinfo(fr, gi)
        want_live = valid
        if valid and base == 2:
            want_live = th_write_ok(fr, off, ln)
        elif valid and base == 1:
            want_live = nh_write_ok(fr, off, ln, imm)
        elif base == 0:
            want_live = ll_write_ok(fr, off, ln)
        eq(r["live"], "1" if want_live else "0",
           "%s/%s/g%d/%s: the guard's verdict" % (sec, env, gi, arm))
        cap = hx(r["rhex"])
        base_l4 = fr.hook_l4 if base in (1, 2) else 0
        if base == 2:
            at = fr.hook_l4 + off
        elif base == 1:
            at = 14 + off                  # store ignores nhoff (F40/F42)
        else:
            at = off
        if want_live:
            check(len(cap) > 0, "%s/%s/g%d/%s: an accepted write leaves a frame"
                  % (sec, env, gi, arm))
            if int(r["csum"]):
                want = rebuild_with_csum(fr, ctl[env], at, imm)
                eq(cap, want,
                   "%s/%s/g%d/%s: the frame equals the store + a recomputed "
                   "checksum" % (sec, env, gi, arm))
            else:
                exp = {}
                for i, b in enumerate(imm):
                    if at + i < len(ctl[env]) and ctl[env][at + i] != b:
                        exp[at + i] = b
                got = {i: cap[i] for i in range(min(len(cap), len(ctl[env])))
                       if cap[i] != ctl[env][i]}
                eq(got, exp, "%s/%s/g%d/%s: exactly the bytes at %d..%d changed"
                   % (sec, env, gi, arm, at, at + ln - 1))
            counted += 1
        else:
            eq(cap, ctl[env], "%s/%s/g%d/%s: a refused cell changes nothing"
               % (sec, env, gi, arm))

    check(counted >= 60, "at least 60 accepted writes were byte-checked",
          str(counted))

    # ---- the grid shape, cell by cell ------------------------------------
    def live(sec, env, gate, arm):
        rs = A.get((sec, env, gate, arm))
        return None if not rs else int(rs[0]["live"])

    grid_arms = ["t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4", "t12_4", "t16_2"]
    for env, g0, g1 in (("p", 8, 8), ("w", 8, 8), ("q", 0, 8), ("ps", 0, 8)):
        eq(sum(live("thg", env, "0", a) for a in grid_arms), g0,
           "grid %s gate 0: live cells" % env)
        eq(sum(live("thg", env, "1", a) for a in grid_arms), g1,
           "grid %s gate 1: live cells" % env)
    # 802.1Q with and without meta: the same table, cell for cell
    eq([live("thg", "w", "0", a) for a in grid_arms],
       [live("thg", "w", "1", a) for a in grid_arms],
       "802.1Q: meta protocol changes nothing, cell for cell")
    # the bare and the single-tag envelopes are the same table too
    eq([live("thg", "p", "0", a) for a in grid_arms],
       [live("thg", "w", "0", a) for a in grid_arms],
       "bare and 802.1Q are the same table, cell for cell")

    # ---- the TCP doff guard ----------------------------------------------
    tcp_dead = ["t10_4", "t12_1", "t12_2", "t12_4"]
    for env, gate in (("pt", "0"), ("pst", "0"), ("pst", "1")):
        for a in tcp_dead:
            v = live("tht", env, gate, a)
            if env == "pst" and gate == "0":
                eq(v, 0, "tcp %s g%s: %s dead (no pktinfo at all)" % (env, gate, a))
            else:
                eq(v, 0, "tcp %s g%s: %s dead (ack_seq window)" % (env, gate, a))
        for a in ("t0_2", "t16_2"):
            v = live("tht", env, gate, a)
            want = 0 if (env == "pst" and gate == "0") else 1
            eq(v, want, "tcp %s g%s: %s live=%d" % (env, gate, a, want))

    # ---- three bases, one packet, one cell shape -------------------------
    reach = {}
    at_of = {"ll0": 0, "nh0": 14, "th0": 42}
    for a in ("ll0", "nh0", "th0"):
        r = A[("thr", "ps", "1", a)][0]
        eq(r["live"], "1", "reach %s: accepted" % a)
        cap = hx(r["rhex"])
        ch = [i for i in range(min(len(cap), len(ctl["ps"])))
              if cap[i] != ctl["ps"][i]]
        reach[a] = ch
        imm = hx(r["imm"])
        want = [at_of[a] + i for i, x in enumerate(imm)
                if ctl["ps"][at_of[a] + i] != x]
        eq(ch, want, "reach %s: the store lands on frame bytes %s"
           % (a, want))
        check(ch and max(ch) < 44 and min(ch) >= at_of[a],
              "reach %s: nothing outside its own field moved" % a, str(ch))
    eq(len({tuple(v) for v in reach.values()}), 3,
       "three bases give three different coordinate systems")

    # @th can never reach the header that shifted it
    for env in ("ps", "q"):
        if env not in F:
            continue
        for a in grid_arms:
            for g in ("0", "1"):
                r = A.get(("thg", env, g, a))
                if not r or r[0]["live"] != "1":
                    continue
                cap = hx(r[0]["rhex"])
                ch = [i for i in range(min(len(cap), len(ctl[env])))
                      if cap[i] != ctl[env][i]]
                if not ch:
                    check(False, "@th on %s: an accepted write must change a byte"
                          % env, "%s g%s" % (a, g))
                    continue
                check(min(ch) >= F[env].hook_l4,
                      "@th on %s can never write before the transport header" % env,
                      "%s g%s changed %s" % (a, g, ch))
    th_ps = []
    for a in grid_arms:
        r = A.get(("thg", "ps", "1", a))
        if r and r[0]["live"] == "1":
            cap = hx(r[0]["rhex"])
            th_ps += [i for i in range(min(len(cap), len(ctl["ps"])))
                      if cap[i] != ctl["ps"][i]]
    check(th_ps and min(th_ps) == 42,
          "@th on PPPoE: the smallest byte it can touch is 42", str(min(th_ps)))
    check(min(th_ps) > 21,
          "the PPP protocol field (20..21) is unreachable from @th", str(min(th_ps)))

    # ---- the checksum section: validated from the captured bytes ---------
    for env, gate in (("pu", "0"), ("psu", "1")):
        for arm in ("ctl", "dp_nc", "dp_cs", "sp_cs", "ck_nc", "ck_cs",
                    "pay_cs", "pay_nc"):
            key = ("cs", env, "0" if arm == "ctl" else gate, arm)
            if key not in A:
                check(False, "missing arm %s" % (key,))
                continue
            r = A[key][0]
            cap = hx(r["rhex"])
            if not cap:
                eq(r["live"], "0", "cs %s/%s: no frames only when the rule is dead"
                   % (env, arm))
                continue
            status, ulen = udp_csum_ok(F[env], cap)
            dport = be16(cap, F[env].l4_off + 2)
            u5000, u5001 = int(r["u5000"]), int(r["u5001"])
            err = int(r["udperr"])
            if status in ("ok", "none"):
                eq(err, 0, "cs %s/%s: a valid datagram raises no UdpInErrors"
                   % (env, arm))
                if dport == 5000:
                    eq(u5000, 18, "cs %s/%s: delivered to 5000" % (env, arm))
                    eq(u5001, -1, "cs %s/%s: not to 5001" % (env, arm))
                else:
                    eq(dport, 5001, "cs %s/%s: the dport on the wire" % (env, arm))
                    eq(u5001, 18, "cs %s/%s: delivered to the WRITTEN port"
                       % (env, arm))
                    eq(u5000, -1, "cs %s/%s: not to the old port" % (env, arm))
            else:
                check(err >= 1, "cs %s/%s: a broken checksum is counted"
                      % (env, arm), "udperr=%d" % err)
                eq(u5000, -1, "cs %s/%s: nothing at 5000" % (env, arm))
                eq(u5001, -1, "cs %s/%s: nothing at 5001" % (env, arm))
            # the checksum field itself: updated only where CSUM_INET ran
            if arm in ("dp_cs", "sp_cs", "pay_cs"):
                eq(status, "ok", "cs %s/%s: CSUM_INET leaves a valid checksum"
                   % (env, arm))
            if arm in ("dp_nc", "pay_nc"):
                eq(status, "bad", "cs %s/%s: without it the checksum is stale"
                   % (env, arm))

    # ---- IPv6 in PPPoE ---------------------------------------------------
    for gate in ("0", "1"):
        live_v6 = sum(live("v6", "ps6", gate, a) for a in
                      ("t0_2", "t2_2", "t6_2", "t8_2"))
        eq(live_v6, 0 if gate == "0" else 4,
           "IPv6 in PPPoE gate %s: live cells" % gate)
    for gate in ("0", "1"):
        for arm in ("dp_nc", "dp_cs"):
            r = A[("v6", "ps6", "0" if arm == "ctl" else gate, arm)][0]
            cap = hx(r["rhex"])
            status, _ = udp_csum_ok(F["ps6"], cap)
            u5000, u5001 = int(r["u6_5000"]), int(r["u6_5001"])
            u6err = int(r["u6err"])
            if r["live"] == "0":
                eq(u5000, 18, "v6 g%s %s: the rule did not run, 5000 gets it"
                   % (gate, arm))
            elif status == "ok":
                eq(u5001, 18, "v6 g%s %s: CSUM_INET delivers to the written port"
                   % (gate, arm))
                eq(u5000, -1, "v6 g%s %s: not to the old port" % (gate, arm))
            else:
                check(u6err >= 1, "v6 g%s %s: a stale udp6 checksum is counted"
                      % (gate, arm), "u6err=%d" % u6err)
                eq((u5000, u5001), (-1, -1),
                   "v6 g%s %s: nothing delivered" % (gate, arm))

    # ---- determinism ------------------------------------------------------
    f1 = [ln for ln in text(LOGS[0]).split("\n") if ln.startswith("F565 ")]
    f2 = [ln for ln in text(LOGS[1]).split("\n") if ln.startswith("F565 ")]
    eq(len(f1), len(f2), "both boots produced the same number of F565 lines")
    diff = [(a, b) for a, b in zip(f1, f2) if a != b]
    check(not diff, "the two boots agree byte for byte",
          "%d lines differ, first %r" % (len(diff), diff[0] if diff else ""))

    print("checks: %d ok, %d failed" % (ok, bad))
    for f in fails[:80]:
        print("FAIL: " + f)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
