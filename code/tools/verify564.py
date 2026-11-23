#!/usr/bin/env python3
"""verify564.py -- independent check of turn 564 / F42.

Three debts F41 named, measured on one image (7.3.4-T563, the F41 build):
  A. PPPoE in PPPOX_BOUND: the frame becomes a real packet on ppp0
  B. IPv6 inside PPPoE: one cell of the ip6 white list lands on the PPP
     protocol byte
  C. ARP behind a real VLAN device: the same frame, with and without v1

What this script does NOT do: it does not read the C instrument's intent.
It reads the LOG, rebuilds every frame from the logged bytes, and recomputes
the verdict of the guard and of the receive path from a Python model of the
source (pppoe.c, ppp_generic.c, ip_input.c, ip6_input.c, nft_payload.c,
nft_meta.c, nf_flow_table.h, dev.c).  Where two mechanisms are plausible the
model is run BOTH ways and the measurement is required to pick one.

Exit 0 = every check passed, 1 = a discrepancy (printed).
"""
import hashlib
import os
import re
import sys

ROOT = "/work/kernel-sec"
IMG = ROOT + "/src/linux-7.3.4-T563/arch/x86/boot/bzImage"
SRC = ROOT + "/src/linux-7.3.4-T563"
BIN = ROOT + "/vm/build/differ564"
LOGS = os.environ.get(
    "F42_LOGS",
    "/work/kernel-sec/logs/f42_rep1.log,/work/kernel-sec/logs/f42_rep2.log"
).split(",")
LOGDIR = os.environ.get("F42_LOGDIR", "/work/kernel-sec/logs")

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


def lines_of(t):
    return t.split("\n")


def kv(line):
    """F564 B|sec=bound|arm=ctl|... -> dict of key=value fields."""
    d = {}
    for part in line.split("|")[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v
    return d


def num(d, k, default=None):
    v = d.get(k)
    if v is None:
        return default
    try:
        return int(v, 0)
    except ValueError:
        return default


def hx(s):
    if s in ("-", "", None):
        return b""
    return bytes.fromhex(s)


# ---------------------------------------------------------------- checksums
def ones_sum(b):
    s = 0
    for i in range(0, len(b) - 1, 2):
        s += (b[i] << 8) | b[i + 1]
    if len(b) & 1:
        s += b[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def ip4_csum_ok(hdr):
    return ones_sum(hdr) == 0xFFFF


def udp6_csum_ok(ip6):
    paylen = (ip6[4] << 8) | ip6[5]
    body = ip6[40:40 + paylen]
    if body[6] == 0 and body[7] == 0:
        return False
    pseudo = ip6[8:40] + bytes([paylen >> 8, paylen & 0xFF, 0, 0, 0, 17])
    s = ones_sum(pseudo + body)
    return s == 0xFFFF


# ---------------------------------------------------------------- the model
MAC_SRC = bytes.fromhex("aabbcc000066")
SID = 99
PPP_IP = 0x0021
PPP_IPV6 = 0x0057


def guard_ip4(wire, off, ln, imm):
    """nft_nh_write_ok_ip4() -- offset 8 alone is checked against the packet."""
    if off == 0:
        return ln == 2 and imm[0] == wire[14]
    if off == 1:
        return ln == 1
    if off == 4:
        return ln == 2
    if off == 8:
        if ln == 1:
            return True
        if ln != 2:
            return False
        return imm[1] == wire[23]
    if off == 10:
        return ln <= 10
    if off == 12:
        return ln <= 8
    if off == 16:
        return ln <= 4
    return False


def guard_ip6(wire, off, ln, imm):
    """nft_nh_write_ok_ip6(): cells 0,2,7,8,24."""
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


def guard_arp(off, ln):
    """nft_nh_write_ok_arp(): ar_op exactly, else anything post-fixed-header."""
    eth_ip = 2 * (6 + 4)
    if off == 6:
        return ln == 2
    return off >= 8 and ln <= eth_ip


def guard_ll(off, ln, network_offset=14):
    """nft_ll_write_ok(): offset + len <= skb_network_offset()."""
    return off + ln <= network_offset


def pppoe_receive(wire, dispatch_proto, trim=True):
    """Model pppoe_rcv() + pppoe_rcv_core() + ppp_input() + ppp_receive_nonmp_frame().

    Returns dict:
      dropped_at   : None | 'ptype' | 'sid' | 'compressed' | 'length'
      prx          : bytes added to /proc/net/dev of pppN (skb->len - 2)
      chan         : bytes queued on the channel file (proto >= 0xc000)
      unit         : bytes queued on the unit file (unknown protocol)
      ip           : the byte string handed to ip_rcv()/ipv6_rcv(), or None
    """
    res = {"dropped_at": None, "prx": 0, "chan": 0, "unit": 0, "ip": None}
    if dispatch_proto != 0x8864:
        res["dropped_at"] = "ptype"
        return res
    if len(wire) < 20:
        res["dropped_at"] = "ptype"
        return res
    sid = (wire[16] << 8) | wire[17]
    src = bytes(wire[6:12])
    if sid != SID or src != MAC_SRC:
        res["dropped_at"] = "sid"
        return res
    plen = (wire[18] << 8) | wire[19]
    body = wire[20:]
    if trim:
        if len(body) < plen:
            res["dropped_at"] = "length"
            return res
        body = body[:plen]
    if len(body) < 2:
        res["dropped_at"] = "length"
        return res
    if body[0] & 1:			# ppp_skb_is_compressed_proto()
        res["dropped_at"] = "compressed"
        return res
    proto = (body[0] << 8) | body[1]
    if proto >= 0xC000:
        res["chan"] = len(body)
        return res
    res["prx"] = len(body) - 2		# dev_sw_netstats_rx_add, before npi
    if proto not in (PPP_IP, PPP_IPV6):
        res["unit"] = len(body)
        return res
    res["ip"] = body[2:]
    return res


def ip4_receive(ip, local=bytes([10, 9, 0, 7])):
    """ip_rcv_core(): returns (inrecv, inhdrerr, indeliv, udp_payload)."""
    inrecv, inhdr, ind = 1, 0, 0
    if len(ip) < 20:
        return inrecv, 1, 0, None
    ihl = ip[0] & 0x0F
    if (ip[0] >> 4) != 4 or ihl < 5:
        return inrecv, 1, 0, None
    if len(ip) < ihl * 4:
        return inrecv, 1, 0, None
    if not ip4_csum_ok(ip[:ihl * 4]):
        return inrecv, 1, 0, None
    tot = (ip[2] << 8) | ip[3]
    if len(ip) < tot:
        return inrecv, 0, 0, None	# InTruncatedPkts, not InHdrErrors
    if tot < ihl * 4:
        return inrecv, 1, 0, None
    if bytes(ip[16:20]) != local:
        return inrecv, 0, 0, None
    ind = 1
    udp = ip[ihl * 4:tot]
    if len(udp) >= 8 and ((udp[2] << 8) | udp[3]) == 5000:
        return inrecv, 0, 1, bytes(udp[8:])
    return inrecv, 0, 1, None


def ip6_receive(ip, local=bytes.fromhex("fd000000000000000000000000990009")):
    """ip6_rcv_core(): returns (inrecv, inhdrerr, indeliv, udp_payload)."""
    inrecv, inhdr, ind = 1, 0, 0
    if len(ip) < 40:
        return inrecv, 1, 0, None
    if (ip[0] >> 4) != 6:
        return inrecv, 1, 0, None
    paylen = (ip[4] << 8) | ip[5]
    if 40 + paylen > len(ip):
        return inrecv, 1, 0, None
    if bytes(ip[24:40]) != local:
        return inrecv, 0, 0, None
    ind = 1
    if ip[6] != 17:
        return inrecv, 0, 1, None
    udp = ip[40:40 + paylen]
    if len(udp) < 8 or ((udp[2] << 8) | udp[3]) != 5000:
        return inrecv, 0, 1, None
    if not udp6_csum_ok(ip[:40 + paylen]):
        return inrecv, 0, 1, None
    return inrecv, 0, 1, bytes(udp[8:])


# ---------------------------------------------------------------- provenance
def extract_from_initrd(initrd, member="root/repro"):
    """read one cpio member (newc), with 4-byte alignment of the ARCHIVE
    offset -- the mistake this project made four times."""
    data = read(initrd)
    import gzip
    data = gzip.decompress(data)
    off = 0
    while off + 110 <= len(data):
        hdr = data[off:off + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            return None
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = data[off + 110:off + 110 + namesize - 1].decode()
        body_at = off + 110 + namesize
        body_at += (-body_at) % 4
        body = data[body_at:body_at + filesize]
        if name == member:
            return body
        off = body_at + filesize
        off += (-off) % 4
    return None


def main():
    if len(LOGS) != 2 or not all(os.path.exists(p) for p in LOGS):
        print("missing logs")
        return 1
    T = [text(p) for p in LOGS]
    L = [lines_of(t) for t in T]

    # ---- 1. provenance -------------------------------------------------
    bz = hashlib.sha256(read(IMG)).hexdigest()
    for i, t in enumerate(T):
        m = re.search(r"^### sha256: ([0-9a-f]{64})$", t, re.M)
        check(m is not None and m.group(1) == bz,
              "rep%d: kernel sha in the log == the file on disk" % (i + 1))
        m = re.search(r"^### initrd: (\S+)$", t, re.M)
        check(m is not None and m.group(1).endswith("/full.cpio.gz"),
              "rep%d: initrd path" % (i + 1))
        m = re.search(r"^### initrd sha256: ([0-9a-f]{64})$", t, re.M)
        hashes = text(LOGDIR + "/f42_initrd_hashes.txt").split("\n")
        full = [ln.split()[1] for ln in hashes if ln.startswith("full ")]
        full = full[-1:]
        check(m is not None and len(full) == 1 and m.group(1) == full[0],
              "rep%d: initrd sha == the recorded build hash" % (i + 1))
        check("VM_BOOT_OK" in t, "rep%d: boot marker" % (i + 1))
        check("=== MODE_EXIT f564=0 ===" in t, "rep%d: mode exit 0" % (i + 1))
        check("F564 DONE" in t, "rep%d: instrument reached DONE" % (i + 1))
        check("7.3.4" in (re.search(r"^Linux version (\S+)", t, re.M) or
                          type("x", (), {"group": lambda s, n: ""})()).group(1),
              "rep%d: the guest runs 7.3.4" % (i + 1))
        check("F564 KERNEL|7.3.4-T563" in t, "rep%d: image label" % (i + 1))
        for pat in ("KASAN", "BUG:", "WARNING:", "Oops", "general protection"):
            check(pat not in t, "rep%d: no %s" % (i + 1, pat))
        # the differ inside the initrd is the binary we built
        m = re.search(r"^### initrd: (\S+)$", t, re.M)
        inbin = extract_from_initrd(m.group(1))
        check(inbin is not None and hashlib.sha256(inbin).hexdigest() ==
              hashlib.sha256(read(BIN)).hexdigest(),
              "rep%d: differ extracted from the initrd == the built binary" % (i + 1))

    # ---- 2. source anchors ---------------------------------------------
    def src(rel, pat, what):
        body = text(os.path.join(SRC, rel))
        check(pat in body, "anchor: " + what, pat)

    src("drivers/net/ppp/pppoe.c",
        "skb_pull_rcsum(skb, sizeof(*ph));", "pppoe_rcv pulls the 6-byte session header")
    src("drivers/net/ppp/pppoe.c",
        "if (!skb_is_gso(skb) && pskb_trim_rcsum(skb, len))",
        "pppoe_rcv trims to the length field")
    src("drivers/net/ppp/pppoe.c",
        "if (sk->sk_state & PPPOX_BOUND) {\n\t\tppp_input(&po->chan, skb);",
        "PPPOX_BOUND hands the frame to ppp_input")
    src("drivers/net/ppp/pppoe.c",
        "po = __get_item(pn, ph->sid, eth_hdr(skb)->h_source, dev->ifindex);",
        "the session lookup key is (sid, h_source, ifindex)")
    src("drivers/net/ppp/ppp_generic.c",
        "dev_sw_netstats_rx_add(dev, skb->len - PPP_PROTO_LEN);",
        "pppN counts rx bytes before the protocol decision")
    src("drivers/net/ppp/ppp_generic.c",
        "npi = proto_to_npindex(proto);",
        "proto_to_npindex decides stack vs unit queue")
    src("drivers/net/ppp/ppp_generic.c",
        "skb->protocol = htons(npindex_to_ethertype[npi]);",
        "the PPP layer hands the frame to netif_rx as ETH_P_IP/IPV6")
    src("drivers/net/ppp/ppp_generic.c",
        "if ((dev->flags & IFF_UP) == 0 ||", "a down pppN frees the frame")
    src("net/ipv4/ip_input.c",
        "if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))",
        "ip_rcv verifies the IP checksum")
    src("net/ipv4/ip_input.c",
        "if (!pskb_may_pull(skb, sizeof(struct iphdr)))",
        "ip_rcv needs 20 bytes")
    src("net/ipv6/ip6_input.c", "if (hdr->version != 6) {",
        "ip6_rcv verifies the version")
    src("net/netfilter/nft_payload.c",
        "\tcase NFT_PAYLOAD_NETWORK_HEADER:\n\t\tif (!nft_nh_write_ok(pkt, priv, src))\n\t\t\tgoto err;\n\t\toffset = skb_network_offset(skb);",
        "the @nh store is at skb_network_offset(), not at the true header")
    src("net/netfilter/nft_payload.c",
        "return offset <= skb_network_offset(pkt->skb);",
        "nft_ll_write_ok: the write must end inside the link header")
    src("net/netfilter/nft_payload.c", "case offsetof(struct iphdr, daddr):",
        "the ip4 list is written in iphdr offsets")
    src("net/netfilter/nft_payload.c", "case offsetof(struct ipv6hdr, hop_limit):",
        "the ip6 list has a hop_limit cell")
    src("net/netfilter/nft_payload.c",
        "return offset >= sizeof(struct arphdr) && priv->len <= eth_ip;",
        "the ARP list is a catch-all above the fixed header")
    src("net/netfilter/nft_meta.c", "nhoff = PPPOE_SES_HLEN;",
        "meta protocol sets nhoff = 8 for PPPoE")
    src("include/net/netfilter/nf_flow_table.h",
        "\tcase htons(PPP_IPV6):\n\t\treturn htons(ETH_P_IPV6);",
        "nf_flow_pppoe_proto knows PPP_IPV6")
    src("net/8021q/vlan_core.c", "vlan_dev = vlan_find_dev(skb->dev, vlan_proto, vlan_id);",
        "vlan_do_receive looks the vlan device up on the receiving device")

    PPPOE_SES_HLEN = 6
    ETH_HLEN = 14

    for rep in (0, 1):
        tag = "rep%d" % (rep + 1)
        ln = L[rep]

        # ---- 3. the frames, rebuilt from the logged bytes --------------
        frame_line = [x for x in ln if x.startswith("F564 FRAME|ps|")]
        check(len(frame_line) == 1, tag + ": one FRAME line")
        fd = kv(frame_line[0])
        wire = hx(fd.get("wire"))
        eq(num(fd, "len"), len(wire), tag + ": the logged frame length matches its bytes")
        eq(len(wire), ETH_HLEN + PPPOE_SES_HLEN + 2 + 46, tag + ": 68 = 14+6+2+46")
        eq((wire[12] << 8) | wire[13], 0x8864, tag + ": ethertype PPP_SES")
        eq((wire[16] << 8) | wire[17], SID, tag + ": session id 99")
        eq((wire[18] << 8) | wire[19], 48, tag + ": pppoe length = 2 + 46")
        eq((wire[20] << 8) | wire[21], PPP_IP, tag + ": PPP protocol = ipv4")
        ip = wire[22:]
        eq(len(ip), 46, tag + ": the IPv4 datagram is 46 bytes")
        eq((ip[2] << 8) | ip[3], 46, tag + ": tot_len 46")
        eq(ip[8], 0x40, tag + ": ttl 64")
        eq(ip[9], 17, tag + ": proto UDP")
        eq(bytes(ip[12:16]), bytes([10, 1, 0, 1]), tag + ": saddr 10.1.0.1")
        eq(bytes(ip[16:20]), bytes([10, 9, 0, 7]), tag + ": daddr 10.9.0.7")
        check(ip4_csum_ok(ip[:20]), tag + ": the IPv4 header checksum is valid")
        eq(bytes(ip[28:36]), b"\x77" * 8, tag + ": the payload magic")

        # ---- 4. the environment --------------------------------------
        ppp = [kv(x) for x in ln if x.startswith("F564 PPP|unit=")]
        check(len(ppp) == 1, tag + ": one unit line")
        if ppp:
            eq(num(ppp[0], "unit"), 0, tag + ": unit 0")
            eq(ppp[0].get("dev"), "ppp0", tag + ": device name ppp0")
            eq(num(ppp[0], "up"), 0, tag + ": ppp0 came up (set_up rc=0)")
            check(num(ppp[0], "ifindex") > 0, tag + ": ppp0 has an ifindex")
        check(any(x.startswith("F564 PPP|addr4|rc=0") for x in ln),
              tag + ": 10.9.0.7/32 peer 10.1.0.1 was accepted")
        check(any(x.startswith("F564 PPP6|u6=") and "u6=-" not in x for x in ln),
              tag + ": the UDPv6 socket bound")

        # ---- 5. section B: the model against every arm ----------------
        B = [kv(x) for x in ln if x.startswith("F564 B|")]
        eq(len(B), 19, tag + ": 19 bound arms (18 + the pre88ff control)")
        byarm = {d["arm"]: d for d in B}
        ctl = byarm.get("ctl")
        check(ctl is not None, tag + ": a control arm exists")
        ctl_rhex = ctl.get("rhex") if ctl else "-"

        for d in B:
            arm = d["arm"]
            if arm == "pre88ff":
                # the same bytes from outside, no rule: not a PPPoE frame
                eq(num(d, "live"), 0, tag + "/pre88ff: no rule ran")
                eq(num(d, "udp4"), -1, tag + "/pre88ff: not delivered")
                eq(num(d, "ipin"), 0, tag + "/pre88ff: ip_rcv never saw it")
                eq(num(d, "prx"), 0, tag + "/pre88ff: ppp0 never saw it")
                continue
            gate = num(d, "gate")
            base = num(d, "base")
            off = num(d, "off")
            length = num(d, "len")
            imm = hx(d.get("imm"))
            w = bytearray(wire)
            if base == 1:		# NFT_PAYLOAD_NETWORK_HEADER
                if gate:
                    okguard = guard_ip4(w, off, length, imm) if length else False
                else:
                    okguard = False	# ethertype 0x8864: no branch
            else:			# NFT_PAYLOAD_LL_HEADER
                okguard = guard_ll(off, length) if length else False
            if length:
                eq(num(d, "live"), 1 if okguard else 0,
                   tag + "/%s: the guard's verdict" % arm)
                if okguard:
                    # @ll stores at skb_mac_header - skb->data + off (= off,
                    # mac_header == data in the bridge family); @nh stores at
                    # skb_network_offset() + off (= 14 + off on PPPoE).
                    at = off if base == 0 else ETH_HLEN + off
                    w[at:at + length] = imm
            else:
                eq(num(d, "live"), 1, tag + "/%s: a rule with no store runs" % arm)
            # receive path: the dispatch key is the protocol eth_type_trans()
            # cached BEFORE the hook -- bytes 12..13 of the frame as sent
            rec = pppoe_receive(bytes(w), 0x8864)
            if rec["dropped_at"] is None:
                eq(num(d, "prx"), rec["prx"], tag + "/%s: pppN rx bytes (skb->len-2)" % arm)
                eq(num(d, "urn"), rec["unit"], tag + "/%s: unit file queue" % arm)
                eq(num(d, "crn"), rec["chan"], tag + "/%s: channel file queue" % arm)
                if rec["ip"] is None:
                    eq(num(d, "ipin"), 0, tag + "/%s: no ip_rcv" % arm)
                    eq(num(d, "ideliv"), 0, tag + "/%s: no delivery" % arm)
                else:
                    inrecv, inhdr, indeliv, payload = ip4_receive(rec["ip"])
                    eq(num(d, "ipin"), inrecv, tag + "/%s: IpInReceives" % arm)
                    eq(num(d, "ihdr"), inhdr, tag + "/%s: IpInHdrErrors" % arm)
                    eq(num(d, "ideliv"), indeliv, tag + "/%s: IpInDelivers" % arm)
                    if payload is None:
                        eq(num(d, "udp4"), -1, tag + "/%s: no socket delivery" % arm)
                    else:
                        eq(num(d, "udp4"), len(payload),
                           tag + "/%s: the socket got %d bytes" % (arm, len(payload)))
                        eq(hx(d.get("uhex")), payload,
                           tag + "/%s: the socket got the written bytes" % arm)
            else:
                eq(num(d, "prx"), 0, tag + "/%s: dropped in pppoe_rcv: no pppN rx" % arm)
                eq(num(d, "ipin"), 0, tag + "/%s: dropped in pppoe_rcv: no ip_rcv" % arm)
                eq(num(d, "udp4"), -1, tag + "/%s: dropped in pppoe_rcv" % arm)
            # every arm forwards: the bridge copy still leaves on the far side
            eq(num(d, "rn"), len(wire), tag + "/%s: the frame left the bridge" % arm)
            eq(hx(d.get("rhex")), bytes(w[:48]),
               tag + "/%s: the far side sees exactly the stored bytes" % arm)

        # ---- 6. the discriminating facts of section B ------------------
        def val(arm, key):
            return num(byarm.get(arm, {}), key, None)

        # (a) refused is not dropped
        for arm in ("bare", "trsaddr", "trdaddr", "nh6", "ll14"):
            eq(val(arm, "live"), 0, tag + "/%s: the store was refused" % arm)
            eq(val(arm, "ipin"), 1, tag + "/%s: the frame still reached ip_rcv" % arm)
            eq(val(arm, "udp4"), 18, tag + "/%s: the datagram still arrived" % arm)
            eq(byarm[arm].get("rhex"), ctl_rhex,
               tag + "/%s: the frame left unchanged" % arm)
        # (b) the store lands at skb_network_offset(), not at the header:
        #     (4,2) rewrites the PPPoE length, and the stack gets 2 bytes
        eq(val("id4", "prx"), 2, tag + "/id4: pppN was handed 2 bytes")
        eq(val("id4", "ipin"), 1, tag + "/id4: ip_rcv ran on 2 bytes")
        eq(val("id4", "ihdr"), 1, tag + "/id4: too short for a header")
        # (c) the length field is a trim: too large and the frame dies in pppoe_rcv
        eq(val("idbig", "prx"), 0, tag + "/idbig: trimmed away before the stack")
        eq(val("idbig", "live"), 1, tag + "/idbig: the rule did run")
        # (d) the IP checksum: every write that changes a header byte dies
        for arm in ("ttl", "ttl2", "csum", "saddr", "daddr"):
            eq(val(arm, "ihdr"), 1, tag + "/%s: InHdrErrors" % arm)
            eq(val(arm, "udp4"), -1, tag + "/%s: not delivered" % arm)
        # ... but the cell NAMED tos lands on the PPPoE code byte, eight bytes
        # before the IPv4 tos, so the checksum never sees it
        eq(val("tos", "ihdr"), 0, tag + "/tos: the checksum never saw the write")
        eq(val("tos", "udp4"), 18, tag + "/tos: the datagram still arrived")
        eq(bytes.fromhex(byarm["tos"]["rhex"])[15:16], b"\x91",
           tag + "/tos: the write landed on the PPPoE code byte")
        # (e) the same cell, same value, changes nothing
        eq(val("ttlsame", "udp4"), 18, tag + "/ttlsame: the write was harmless")
        # (f) @ll can reach the source MAC but not the PPPoE header
        eq(val("ll6", "live"), 1, tag + "/ll6: allowed by the 14-boundary")
        eq(val("ll6", "prx"), 0, tag + "/ll6: the session lookup failed")
        eq(bytes.fromhex(byarm["ll6"]["rhex"])[6:8], b"\xff\xff",
           tag + "/ll6: the source MAC carries the write")
        eq(val("ll14", "live"), 0, tag + "/ll14: 16 > 14, refused")
        # (g) the ethertype byte changes on the wire, the dispatch does not
        eq(val("ll13", "ipin"), 1, tag + "/ll13: still dispatched")
        eq(val("ll13", "udp4"), 18, tag + "/ll13: still delivered")
        eq(bytes.fromhex(byarm["ll13"]["rhex"])[12:14], b"\x88\xff",
           tag + "/ll13: the wire byte changed")
        eq(val("pre88ff", "udp4"), -1, tag + "/pre88ff: the same byte from outside is not PPPoE")
        # (h) no arm can move the PPP protocol byte through @nh
        eq(val("nh6", "live"), 0, tag + "/nh6: the protocol field has no cell")

        # ---- 7. section V: IPv6 inside PPPoE --------------------------
        v6line = [x for x in ln if x.startswith("F564 V6|frame|")]
        check(len(v6line) == 1, tag + ": one V6 frame line")
        v6d = kv(v6line[0])
        w6 = hx(v6d.get("wire"))
        eq(num(v6d, "len"), 88, tag + ": the ip6 frame is 88 bytes")
        eq((w6[16] << 8) | w6[17], SID, tag + ": ip6 frame sid 99")
        eq((w6[20] << 8) | w6[21], PPP_IPV6, tag + ": PPP protocol = ipv6")
        ip6 = w6[22:22 + 66]
        eq((ip6[0] >> 4), 6, tag + ": ip6 version")
        eq((ip6[4] << 8) | ip6[5], 26, tag + ": payload length 26")
        eq(ip6[6], 17, tag + ": next header UDP")
        eq(ip6[7], 64, tag + ": hop limit 64")
        check(udp6_csum_ok(ip6), tag + ": the UDPv6 checksum is valid")
        eq(bytes(ip6[48:56]), b"\x77" * 8, tag + ": the ip6 payload magic")

        V = [kv(x) for x in ln if x.startswith("F564 V|")]
        eq(len(V), 11, tag + ": 11 v6p arms")
        vby = {d["arm"]: d for d in V}
        for d in V:
            arm = d["arm"]
            off = num(d, "off")
            length = num(d, "len")
            imm = hx(d.get("imm"))
            w = bytearray(w6)
            if length:
                okguard = guard_ip6(w, off, length, imm)
                eq(num(d, "live"), 1 if okguard else 0,
                   tag + "/v6:%s: the ip6 guard" % arm)
                if okguard:
                    w[ETH_HLEN + off:ETH_HLEN + off + length] = imm
            else:
                eq(num(d, "live"), 1, tag + "/v6:%s: control" % arm)
            rec = pppoe_receive(bytes(w), 0x8864)
            if rec["dropped_at"] is None:
                eq(num(d, "prx"), rec["prx"], tag + "/v6:%s: pppN rx bytes" % arm)
                eq(num(d, "urn"), rec["unit"], tag + "/v6:%s: unit queue" % arm)
                if rec["ip"] is None:
                    eq(num(d, "i6in"), 0, tag + "/v6:%s: no ipv6 input" % arm)
                else:
                    inrecv, inhdr, indeliv, payload = ip6_receive(rec["ip"])
                    eq(num(d, "i6in"), inrecv, tag + "/v6:%s: Ip6InReceives" % arm)
                    eq(num(d, "i6hdr"), inhdr, tag + "/v6:%s: Ip6InHdrErrors" % arm)
                    eq(num(d, "i6deliv"), indeliv, tag + "/v6:%s: Ip6InDelivers" % arm)
                    if payload is None:
                        eq(num(d, "udp6"), -1, tag + "/v6:%s: no socket delivery" % arm)
                    else:
                        eq(num(d, "udp6"), len(payload), tag + "/v6:%s: udp6 bytes" % arm)
                        eq(hx(d.get("uhex")), payload, tag + "/v6:%s: udp6 payload" % arm)
            else:
                eq(num(d, "prx"), 0, tag + "/v6:%s: dropped: no pppN rx" % arm)
                eq(num(d, "i6in"), 0, tag + "/v6:%s: dropped before the stack" % arm)
            eq(num(d, "rn"), len(w6), tag + "/v6:%s: the frame left the bridge" % arm)
            eq(hx(d.get("rhex")), bytes(w[:48]),
               tag + "/v6:%s: the far side sees the stored bytes" % arm)

        # the headline: one ip6 cell rewrites the PPP protocol byte
        hop = vby.get("hop", {})
        eq(num(hop, "urn"), 68, tag + "/v6:hop: the unit queue got 68 bytes")
        eq(hx(hop.get("urhex"))[:2], b"\x00\x90",
           tag + "/v6:hop: the PPP protocol became 0x0090")
        eq(num(hop, "prx"), 66, tag + "/v6:hop: pppN counted the frame the stack never saw")
        eq(num(hop, "i6in"), 0, tag + "/v6:hop: ipv6 never saw it")
        eq(num(vby.get("hopsame", {}), "udp6"), 18,
           tag + "/v6:hopsame: the same cell, the same byte, delivered")
        eq(num(vby.get("hdr_bad", {}), "i6hdr"), 1,
           tag + "/v6:hdr_bad: version 9")
        eq(num(vby.get("hdr_same", {}), "udp6"), 18,
           tag + "/v6:hdr_same: writing the true first 16 bytes changes nothing")

        # ---- 8. section L: ARP behind a real VLAN device --------------
        Ll = [kv(x) for x in ln if x.startswith("F564 L|")]
        lnov = [d for d in Ll if d.get("pass") == "novlan"]
        lvlan = [d for d in Ll if d.get("pass") == "vlan"]
        eq(len(lnov), 2, tag + ": 2 arms without the vlan device")
        eq(len(lvlan), 4, tag + ": 4 arms with it")
        for d in lnov:
            eq(num(d, "live"), 1, tag + "/L:%s: the rule ran" % d["arm"])
            eq(num(d, "arc"), 0, tag + "/L:%s: no ARP at NF_ARP_IN" % d["arm"])
            eq(num(d, "repn"), -1, tag + "/L:%s: no reply" % d["arm"])
        for d in lvlan:
            arm = d["arm"]
            if arm == "hln_vlan":
                eq(num(d, "live"), 0, tag + "/L:hln_vlan: offset 4 is refused")
            else:
                eq(num(d, "live"), 1, tag + "/L:%s: the rule ran" % arm)
            eq(num(d, "arc"), 1, tag + "/L:%s: the frame reached arp_rcv" % arm)
            if arm in ("ctl_vlan",):
                eq(num(d, "repn"), 42, tag + "/L:ctl_vlan: the kernel replied")
                check(d.get("ent", "").endswith(";v1"),
                      tag + "/L:ctl_vlan: /proc/net/arp names v1", d.get("ent"))
            if arm == "sha_vlan":
                eq(bytes.fromhex(d["rephex"])[0:6], b"\x90\x91\xcc\x00\x00\x66",
                   tag + "/L:sha_vlan: the reply went to the written MAC")
            if arm == "op_vlan":
                eq(num(d, "repn"), -1, tag + "/L:op_vlan: an unknown ar_op is not answered")
            if arm == "hln_vlan":
                eq(num(d, "repn"), 42, tag + "/L:hln_vlan: refused store, frame unchanged")
        # the guard's own verdict on the two write arms
        check(guard_arp(8, 2), "model: the ARP list allows offset 8")
        check(not guard_arp(4, 2), "model: the ARP list refuses offset 4")

        # ---- 9. the frame model: counters must add up ----------------
        for d in B:
            live = num(d, "live")
            eq(num(d, "cnt") - num(d, "cnt0"), live,
               tag + "/%s: the chain counter equals the verdict" % d["arm"])
        for d in V:
            eq(num(d, "cnt") - num(d, "cnt0"), num(d, "live"),
               tag + "/v6:%s: the chain counter equals the verdict" % d["arm"])

    # ---- 10. determinism between the two boots ------------------------
    def norm(lines):
        out = []
        macs = set()
        for x in lines:
            if x.startswith("F564 L|brmac="):
                macs.add(x.split("brmac=")[1].split("|")[0])
        for x in lines:
            if not x.startswith("F564 "):
                continue
            for m in macs:
                x = x.replace(m, "BRMAC")
            out.append(x)
        return out

    f1 = norm(L[0])
    f2 = norm(L[1])
    eq(len(f1), len(f2), "both boots produced the same number of F564 lines")
    diff = [(a, b) for a, b in zip(f1, f2) if a != b]
    check(not diff, "the two boots agree byte for byte",
          "%d lines differ, first: %r vs %r" % (len(diff),
                                                diff[0][0] if diff else "",
                                                diff[0][1] if diff else ""))

    print("checks: %d ok, %d failed" % (ok, bad))
    for f in fails[:60]:
        print("FAIL: " + f)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
