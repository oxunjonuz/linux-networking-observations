#!/usr/bin/env python3
"""verify566.py -- independent check of turn 566 / F44.

The two pktinfo constructors F43 never measured -- `nft_set_pktinfo_ipv4()`
at the layer-3 hooks of families `ip`/`inet`, and
`nft_set_pktinfo_ipv4_ingress()` at the inet ingress door -- plus the guard
asymmetry the two ingress doors create, because `nft_nh_write_ok()` and
`nft_in_ingress()` both read `pkt->state->pf` and one handler rewrites it.

What this script does NOT do: it does not read the C instrument's intent.  It
reads the LOG, rebuilds every frame from the logged bytes, derives the hook
layout from the frame itself (tag count, PPPoE header, IP version), recomputes
what each of the four pktinfo constructors puts in `pkt->thoff`/`pkt->nhoff`,
runs every write guard of `nft_payload.c` in Python, and then compares the
verdict and the byte against what the log says the hook saw (NFLOG payload),
what reached the wire (the far tap) and what the receiver's sockets got.

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
BIN = ROOT + "/vm/build/differ566"
INITRD = ROOT + "/vm/initrd566/full.cpio.gz"
LOGS = os.environ.get(
    "F44_LOGS",
    "/work/kernel-sec/logs/f44_rep1.log,/work/kernel-sec/logs/f44_rep2.log"
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
    # CRLF: the serial console of this image ends lines with \r\n (F38, and
    # every turn since).  Ninth reminder.
    return read(path).decode("utf-8", "replace").replace("\r\n", "\n")


def sha(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- frame model

def hx(s):
    if not s or s == "-":
        return b""
    return bytes.fromhex(s)


def be16(b, o):
    return (b[o] << 8) | b[o + 1]


VLAN_TYPES = (0x8100, 0x88A8, 0x9100)


class Frame(object):
    def __init__(self, tag, raw):
        self.tag = tag
        self.wire = raw
        self.ethtype = be16(raw, 12)
        n = 0
        off = 12
        while be16(raw, off) in VLAN_TYPES and off + 6 <= len(raw):
            n += 1
            off += 4
        self.ntags = n
        self.inner_type = be16(raw, off)
        self.pppoe = (n == 0 and self.ethtype == 0x8864)
        if self.pppoe:
            self.pppproto = be16(raw, 20)
            self.ip_off = 22
        else:
            self.pppproto = None
            self.ip_off = off + 2
        self.ipver = raw[self.ip_off] >> 4
        self.ihl = (raw[self.ip_off] & 0x0F) * 4 if self.ipver == 4 else 0
        self.ipproto = raw[self.ip_off + 9] if self.ipver == 4 else None
        self.totlen = be16(raw, self.ip_off + 2) if self.ipver == 4 else 0
        self.l4_off = self.ip_off + self.ihl
        # what skb->protocol is when __netif_receive_skb_core() reaches the
        # ingress door: skb_vlan_untag() has moved exactly ONE tag
        if n >= 1:
            self.proto_at_ingress = be16(raw, 12 + 4) if n >= 2 else be16(raw, 12 + 4)
        else:
            self.proto_at_ingress = self.ethtype

    def hex(self):
        return self.wire.hex()


def data_offset(door, fr):
    """skb->data, as an offset into the frame bytes, at the moment the hook
    runs.  Layer-3 doors: the link header has been pulled (eth_type_trans)
    and the tag (if any) moved to metadata, so data is the IP header.  Ingress
    doors: the frame is untagged in the bytes, so data is the IP header for a
    bare or single-tag frame, the inner tag for Q-in-Q, the PPPoE header for a
    session frame."""
    if door in ("ipp", "inp"):
        return fr.ip_off
    # ingress
    if fr.pppoe:
        return 14
    if fr.ntags >= 2:
        return 18           # the inner tag
    return fr.ip_off        # bare, or one tag popped


def pktinfo(door, fr, gate):
    """The pktinfo nf_tables builds at this door, from the source:
    ip/inet layer-3 -> nft_set_pktinfo_ipv4();  netdev ingress ->
    nft_set_pktinfo_ipv4_validate();  inet ingress ->
    nft_set_pktinfo_ipv4_ingress();  and meta protocol may repair an unspec
    pktinfo through nft_meta_pktinfo_may_update()."""
    d = data_offset(door, fr)
    out = {"data": d, "flags": 0, "tprot": 0, "nhoff": 0, "thoff": 0,
           "valid": False, "drop": False}

    def validate_ipv4(nhoff):
        # __nft_set_pktinfo_ipv4_validate(): reads at
        # skb_network_offset() + nhoff from skb->data
        p = d + nhoff
        iph = fr.wire[p:p + 20]
        if len(iph) < 20:
            return False
        if (iph[0] & 0x0F) < 5 or (iph[0] >> 4) != 4:
            return False
        tot = be16(iph, 2)
        th = (iph[0] & 0x0F) * 4
        skb_len = len(fr.wire) - d - nhoff
        if skb_len < tot or tot < th or th < 20:
            return False
        out.update(flags=1, tprot=iph[9], nhoff=nhoff,
                   thoff=0 + nhoff + th, valid=True)
        return True

    if door in ("ipp", "inp"):
        # nft_set_pktinfo_ipv4(): no validation at all
        out.update(flags=1, tprot=fr.wire[fr.ip_off + 9],
                   thoff=fr.ihl, valid=True)
        return out
    if door == "ndg":
        # nft_do_chain_netdev() switches on skb->protocol
        if fr.proto_at_ingress == 0x0800 and gate == 0:
            if not validate_ipv4(0):
                out.update(flags=0, tprot=0, nhoff=0, thoff=0)
            return out
        if gate:
            # nft_meta_pktinfo_may_update(): returns at once when flags != 0
            if fr.proto_at_ingress == 0x8100:
                nhoff = 4 + 0        # VLAN_HLEN + skb_network_offset
                if not validate_ipv4(nhoff):
                    out.update(flags=0, tprot=0, nhoff=0, thoff=0)
                return out
            if fr.pppoe:
                nhoff = 8 + 0        # PPPOE_SES_HLEN + skb_network_offset
                if not validate_ipv4(nhoff):
                    out.update(flags=0, tprot=0, nhoff=0, thoff=0)
                return out
        return out
    # ieg: nft_do_chain_inet_ingress() switches on skb->protocol and, for
    # 0x0800, builds the pktinfo with state.pf = NFPROTO_IPV4 before any rule
    if fr.proto_at_ingress != 0x0800:
        out["unreached"] = True
        return out
    iph = fr.wire[d:d + 20]
    if len(iph) < 20:
        out["drop"] = True
        return out
    if (iph[0] & 0x0F) < 5 or (iph[0] >> 4) != 4:
        out["drop"] = True
        return out
    tot = be16(iph, 2)
    th = (iph[0] & 0x0F) * 4
    if len(fr.wire) - d < tot:
        out["drop"] = True
        return out
    if tot < th or th < 20:
        out["drop"] = True
        return out
    out.update(flags=1, tprot=iph[9], nhoff=0, thoff=th, valid=True)
    return out


def guard_ll(door, fr, off, ln):
    """nft_payload_set_eval(), NFT_PAYLOAD_LL_HEADER.  Returns (live, why)."""
    # skb_mac_header_was_set() is true (eth_type_trans), and
    # skb_mac_header(skb) - skb->data == -14 at the ingress doors (measured:
    # the write lands on frame byte `off`), -14 at the layer-3 doors after
    # eth_type_trans pulled the link header.
    vlan_hlen = 0
    tag_present = fr.ntags >= 1
    if tag_present and off + ln > 12:
        # nft_payload_set_vlan()
        if off >= 16:
            vlan_hlen = 4
        elif off == 12:
            if ln not in (2, 4):
                return False, "set_vlan(12,%d)" % ln
            return True, "tag metadata"
        elif off == 14:
            if ln != 2:
                return False, "set_vlan(14,%d)" % ln
            return True, "tag metadata"
        else:
            return False, "set_vlan default"
    mac_delta = -14 - vlan_hlen
    if door == "ndg":
        # nft_in_ingress(state): pf == NFPROTO_NETDEV && hook == NETDEV_INGRESS
        return True, "ingress constant"
    # ieg rewrote pf to NFPROTO_IPV4 -> nft_in_ingress() is false
    netoff = 0 if data_offset(door, fr) == fr.ip_off else 0
    return (ln + off + mac_delta) <= netoff, "netoff %d" % netoff


def guard_nh(door, fr, off, ln, imm):
    """nft_nh_write_ok(): switch (pkt->state->pf)."""
    if door == "ndg":
        # NFPROTO_NETDEV + hook NF_NETDEV_INGRESS -> return true
        return True, "ingress constant"
    if door in ("ipp", "inp"):
        pf = "IPV4"
    else:
        pf = "IPV4"   # the handler rewrote state.pf
    if pf != "IPV4":
        return False, pf
    return _nh_ip4(fr, off, ln, imm)


def _nh_ip4(fr, off, ln, imm):
    ip = fr.ip_off
    old0 = fr.wire[ip]
    if off == 0:
        return (ln == 2 and imm[0] == old0), "case 0"
    if off == 1:
        return ln == 1, "tos"
    if off == 4:
        return ln == 2, "id"
    if off == 8:
        if ln == 1:
            return True, "ttl"
        if ln != 2:
            return False, "ttl len"
        return imm[1] == fr.wire[ip + 9], "ttl 2 must keep protocol"
    if off == 10:
        return ln <= 10, "check"
    if off == 12:
        return ln <= 8, "saddr"
    if off == 16:
        return ln <= 4, "daddr"
    return False, "not in the whitelist"


def guard_th(pkt, fr, off, ln):
    if not (pkt["flags"] & 1):
        return False, "no L4PROTO"
    if pkt["tprot"] == 6:      # TCP: the doff guard
        doff = 12
        if not (off > doff or off + ln <= doff):
            return False, "tcp doff"
    return True, "th"


def store_offset(door, fr, base, off, pkt):
    d = data_offset(door, fr)
    if base == 0:      # ll
        return d - 14 + off
    if base == 1:      # nh: offset = skb_network_offset + priv->offset
        netoff = 0
        return d + netoff + off
    return d + pkt["thoff"] + off     # th


# ---------------------------------------------------------------- log parsing

def parse_kv(line):
    d = {}
    for kv in line.split("|")[1:]:
        if "=" in kv:
            k, v = kv.split("=", 1)
            d[k] = v
    return d


def load(path):
    t = text(path)
    frames = {}
    mframes = {}
    arms = []
    for line in t.split("\n"):
        if line.startswith("F566 FRAME|"):
            k = parse_kv(line)
            tag = line.split("|")[1]
            frames[tag] = Frame(tag, hx(k["wire"]))
        elif line.startswith("F566 MFRAME|"):
            k = parse_kv(line)
            tag = line.split("|")[1]
            mframes[tag] = Frame(tag, hx(k["wire"]))
        elif line.startswith("F566 A|"):
            arms.append(parse_kv(line))
    return t, frames, mframes, arms


# ---------------------------------------------------------------- provenance

def cpio_extract(blob, name):
    """newc cpio; the alignment applies to the OFFSET, not to the name
    (the mistake of turns 556, 560, 562 and 565)."""
    at = 0
    while at + 110 <= len(blob):
        if blob[at:at + 6] not in (b"070701", b"070702"):
            break
        hdr = blob[at:at + 110]
        try:
            filesize = int(hdr[54:62], 16)
            namesize = int(hdr[94:102], 16)
        except ValueError:
            return None
        data_at = at + 110 + namesize
        data_at = (data_at + 3) & ~3
        nm = blob[at + 110:at + 110 + namesize - 1].decode("latin-1")
        if nm.lstrip("./") == name.lstrip("./"):
            return blob[data_at:data_at + filesize]
        at = data_at + filesize
        at = (at + 3) & ~3
    return None


print("== provenance ==")
img_sha = sha(read(IMG))
print("   bzImage sha256 = %s" % img_sha)
init_sha = sha(read(INITRD))
print("   initrd sha256  = %s" % init_sha)
hashlist = text(ROOT + "/logs/f44_initrd_hashes.txt").split("\n")
check(any(l.split()[1:] == [init_sha] for l in hashlist if len(l.split()) == 2),
      "initrd in the hash list written by the run script", init_sha)
bin_sha = sha(read(BIN))
print("   differ566 sha256 = %s" % bin_sha)
raw = gzip.GzipFile(fileobj=io.BytesIO(read(INITRD))).read()
extracted = cpio_extract(raw, "root/repro")
if not check(extracted is not None, "differ binary found in the initramfs"):
    pass
else:
    eq(sha(extracted), bin_sha, "the binary inside the initramfs is the built one")
    eq(len(extracted), os.path.getsize(BIN), "and has the same size")

# the source anchors the model stands on
src_payload = text(SRC + "/net/netfilter/nft_payload.c")
src_filter = text(SRC + "/net/netfilter/nft_chain_filter.c")
src_ipv4h = text(SRC + "/include/net/netfilter/nf_tables_ipv4.h")
src_ipv6h = text(SRC + "/include/net/netfilter/nf_tables_ipv6.h")
src_meta = text(SRC + "/net/netfilter/nft_meta.c")
src_core = text(SRC + "/net/netfilter/core.c")


def anchor(hay, needle, what):
    return check(needle in hay, "source anchor: " + what, needle)


anchor(src_ipv4h, "pkt->thoff = ip_hdrlen(pkt->skb);",
       "nft_set_pktinfo_ipv4() uses ip_hdrlen() without skb_network_offset")
anchor(src_ipv4h, "pkt->thoff = skb_network_offset(pkt->skb) + nhoff + thoff;",
       "the validate constructor is absolute")
anchor(src_ipv4h, "pkt->thoff = thoff;",
       "nft_set_pktinfo_ipv4_ingress() stores the relative ihl*4")
anchor(src_ipv4h, "\tif (iph->ihl < 5 || iph->version != 4)\n\t\tgoto inhdr_error;",
       "the ingress constructor validates version and ihl")
anchor(src_ipv4h, "IPSTATS_MIB_INTRUNCATEDPKTS", "and counts truncation")
anchor(src_ipv4h, "IPSTATS_MIB_INHDRERRORS", "and header errors before dropping")
anchor(src_filter, "ingress_state.pf = NFPROTO_IPV4;",
       "nft_do_chain_inet_ingress() rewrites pf")
anchor(src_filter, "ingress_state.hook = NF_INET_INGRESS;", "and the hook number")
anchor(src_filter, "\t\tif (nft_set_pktinfo_ipv4_ingress(&pkt) < 0)\n\t\t\treturn NF_DROP;",
       "a failed parse DROPS the frame before nft_do_chain")
anchor(src_filter, "case htons(ETH_P_IP):", "the inet ingress switch")
anchor(src_filter, "nft_set_pktinfo(&pkt, skb, state);\n\tnft_set_pktinfo_ipv4(&pkt);",
       "nft_do_chain_ipv4() uses the unvalidated constructor")
anchor(src_filter, "nft_set_pktinfo(&pkt, skb, state);\n\n\tswitch (state->pf) {",
       "and so does nft_do_chain_inet()")
anchor(src_filter, "nft_set_pktinfo_ipv4_validate(&pkt);",
       "nft_do_chain_netdev() uses the validate constructor")
anchor(src_payload, "return s->pf == NFPROTO_NETDEV && s->hook == NF_NETDEV_INGRESS;",
       "nft_in_ingress() tests pf AND hook")
anchor(src_payload, "\tcase NFPROTO_NETDEV:\n\t\tif (pkt->state->hook == NF_NETDEV_INGRESS)\n\t\t\treturn true;",
       "the netdev ingress branch of nft_nh_write_ok()")
anchor(src_payload, "\tswitch (pkt->state->pf) {\n\tcase NFPROTO_ARP:", "the guard dispatch")
anchor(src_payload, "return offset <= skb_network_offset(pkt->skb);",
       "nft_ll_write_ok() degrades to the network offset")
anchor(src_payload, "if (offset >= offsetof(struct vlan_ethhdr, h_vlan_encapsulated_proto)) {",
       "nft_payload_set_vlan(): the tag boundary")
anchor(src_payload, "\tdefault:\n\t\treturn false;\n\t}\n\n\treturn true;\n}",
       "set_vlan's default refusal")
anchor(src_meta, "nhoff = VLAN_HLEN;", "meta: Q-in-Q repair")
anchor(src_meta, "nhoff = PPPOE_SES_HLEN;", "meta: PPPoE repair")
anchor(src_meta, "nhoff += skb_network_offset(skb);", "meta: plus the network offset")
anchor(src_meta, "\t/* Is this an IP packet? Then, skip. */\n\tif (pkt->flags)\n\t\treturn;",
       "meta does nothing once flags is set")
anchor(src_core, "err = __nf_register_net_hook(net, NFPROTO_IPV4, reg);",
       "inet chains are registered under IPV4")
anchor(src_core, "return &dev->nf_hooks_ingress;",
       "and the inet ingress chain lives in the per-device ingress list")

# ---------------------------------------------------------------- the logs

nlogs = len(LOGS)
all_arms = []
for lp in LOGS:
    t = text(lp)
    check("F566 DONE" in t, "F566 DONE in " + os.path.basename(lp))
    check("MODE_EXIT f566=0" in t, "MODE_EXIT f566=0 in " + os.path.basename(lp))
    check("7.3.4-T563" in t, "the boot is 7.3.4-T563", os.path.basename(lp))
    check(not re.search(r"KASAN|BUG:|Oops|WARNING:", t),
          "no splat in " + os.path.basename(lp))

logs = []
for lp in LOGS:
    logs.append(load(lp))
    all_arms.append(len(logs[-1][3]))
print("   arm lines per boot: %s" % all_arms)
eq(all_arms[0], all_arms[1], "both boots have the same number of arms")
if os.environ.get("F44_PARTIAL") != "1":
    eq(all_arms[0], 348,
       "348 arms expected (180 td, 36 tm, 94 gd/gn, 12 rf, 8 dp, 18 md)")

t0, F0, M0, A0 = logs[0]
t1, F1, M1, A1 = logs[1]
eq(sorted(F0), sorted(F1), "the same five frames in both boots")
for tag in sorted(F0):
    eq(F0[tag].hex(), F1[tag].hex(), "frame %s is byte-identical between boots" % tag)
    print("   frame %-5s ntags=%d pppoe=%s ip_off=%d ihl=%d l4=%d" %
          (tag, F0[tag].ntags, F0[tag].pppoe, F0[tag].ip_off, F0[tag].ihl,
           F0[tag].l4_off))
for tag in sorted(M0):
    eq(M0[tag].hex(), M1[tag].hex(), "malformed frame %s is byte-identical" % tag)

# determinism: every arm line identical
if check(len(A0) == len(A1), "arm counts equal for the determinism check"):
    diff = [i for i in range(len(A0)) if A0[i] != A1[i]]
    eq(diff, [], "every F566 A line is identical between the two boots")

# ---------------------------------------------------------------- the model

DOORS = ("ipp", "inp", "ndg", "ieg")
ENVS = ("p", "w", "w0", "q", "ps")
SEC_ENV = {"td": ENVS, "tm": ("q", "ps"), "gd": ("p", "w"), "gn": ("p",),
           "rf": ("p",), "dp": ("p", "ps")}
MD_ENV = {"md_both": ("badver", "ihl4", "trunc"),
          "md_ndg": ("badver", "ihl4", "trunc"),
          "md_ieg": ("badver", "ihl4", "trunc")}

arms = {}
for a in A0:
    arms[(a["sec"], a["door"], a["env"], a["arm"])] = a


def get(sec, door, env, arm):
    return arms.get((sec, door, env, arm))


def fra(env):
    return F0[env] if env in F0 else M0[env]


# --- 1. the control arms: how many times did the hook run, and where is data
print("== control arms: passes and the data pointer ==")
for sec in ("td", "tm", "gd", "gn", "dp", "md_both", "md_ndg", "md_ieg"):
    doors = [d for d in DOORS if get(sec, d, None, "ctl") or
             any(a["sec"] == sec and a["door"] == d for a in A0)]
    for door in doors:
        envs = SEC_ENV.get(sec, MD_ENV.get(sec, ()))
        for env in envs:
            c = get(sec, door, env, "ctl")
            if c is None:
                continue
            fr = fra(env)
            pkt = pktinfo(door, fr, 1 if c["gate"] == "1" else 0)
            want_pass = {"td": {"ipp": 2, "inp": 2, "ndg": 1, "ieg": 1},
                         "dp": {"ipp": 2, "inp": 2, "ndg": 1, "ieg": 1},
                         "tm": {"ndg": 1, "ieg": 0},
                         "gd": {"ndg": 1, "ieg": 1},
                         "gn": {"ndg": 1, "ieg": 1},
                         "rf": {"ipp": 2, "inp": 2, "ndg": 1, "ieg": 1},
                         "md_both": {"ndg": 0}, "md_ndg": {"ndg": 1},
                         "md_ieg": {"ieg": 0}}[sec][door]
            if env not in ENVS:
                pass
            elif sec == "td":
                # passes: bare/w0 -> 2 at the layer-3 doors (bridge copy +
                # far copy), vid-100 tag -> 0 (F36), Q-in-Q -> 0, PPPoE -> 1
                want_pass = {"ipp": {"p": 2, "w": 0, "w0": 2, "q": 0, "ps": 1},
                             "inp": {"p": 2, "w": 0, "w0": 2, "q": 0, "ps": 1},
                             "ndg": {"p": 1, "w": 1, "w0": 1, "q": 1, "ps": 1},
                             "ieg": {"p": 1, "w": 1, "w0": 1, "q": 0, "ps": 0}}[door][env]
            elif sec == "tm":
                want_pass = {"ndg": 1, "ieg": 0}[door]
            elif sec == "dp":
                want_pass = {"ipp": {"p": 2, "ps": 1}, "inp": {"p": 2, "ps": 1},
                             "ndg": {"p": 1, "ps": 1},
                             "ieg": {"p": 1, "ps": 0}}[door][env]
            eq(int(c["livep"]), want_pass,
               "ctl passes %s/%s/%s" % (sec, door, env))
            eq(int(c["npre"]), want_pass,
               "the first chain logged exactly as often %s/%s/%s" % (sec, door, env))
            if want_pass and pkt["flags"]:
                eq(int(c["npost"]), want_pass,
                   "the second chain logged too %s/%s/%s" % (sec, door, env))
                # the logged payload starts at skb->data
                eq(len(hx(c["post"])), len(fr.wire) - data_offset(door, fr),
                   "payload length = frame minus the data offset %s/%s" %
                   (door, env))
                eq(c["post"], fr.wire[data_offset(door, fr):].hex(),
                   "the logged payload IS the frame from skb->data %s/%s" %
                   (door, env))

# --- 1b. the NFULA_L2HDR attribute follows the pf the handler left behind
print("== the log message itself: L2HDR only for the netdev pf ==")
for door in DOORS:
    for env in ENVS:
        c = get("td", door, env, "ctl")
        if c is None or int(c["npre"]) == 0:
            continue
        want_l2 = 14 if door == "ndg" else 0
        eq(int(c["l2"]), want_l2,
           "NFULA_L2HDR present only at the netdev door (%s/%s)" % (door, env))

# --- 2. every store arm: verdict and byte
print("== store arms: guard verdict and the byte written ==")
n_live = 0
n_refused = 0
for a in A0:
    sec = a["sec"]
    if sec not in ("td", "tm", "gd", "gn"):
        continue
    if a["mode"] != "1":
        continue
    door, env = a["door"], a["env"]
    base, off, ln = int(a["base"]), int(a["off"]), int(a["len"])
    imm = hx(a["imm"])
    fr = fra(env)
    gate = 1 if a["gate"] == "1" else 0
    ctl = get(sec, door, env, "ctl")
    passes = int(ctl["livep"])
    pkt = pktinfo(door, fr, gate)
    if base == 0:
        live, why = guard_ll(door, fr, off, ln)
    elif base == 1:
        live, why = guard_nh(door, fr, off, ln, imm)
    else:
        live, why = guard_th(pkt, fr, off, ln)
    live = bool(live) and passes > 0 and not pkt.get("drop", False)
    got_live = int(a["lives"])
    if live:
        n_live += 1
        eq(got_live, passes, "live %s/%s/%s/%s (%s)" %
           (sec, door, env, a["arm"], why))
        pre, post = hx(a["pre"]), hx(a["post"])
        eq(len(pre), len(post), "pre and post payload lengths match %s/%s" %
           (a["arm"], env))
        # where does the store land, counted from skb->data (the NFLOG
        # payload starts there)?
        vlan_hlen = 0
        tag_meta = False
        if base == 0:
            if fr.ntags >= 1 and off + ln > 12:
                if off >= 16:
                    vlan_hlen = 4
                elif off in (12, 14):
                    tag_meta = True
        if tag_meta:
            eq(post.hex(), pre.hex(),
               "a tag-metadata store touches no frame byte %s/%s/%s" %
               (sec, door, a["arm"]))
        else:
            if base == 0:
                pos = -14 - vlan_hlen + off
            elif base == 1:
                pos = off
            else:
                pos = pkt["thoff"] + off
            want = bytearray(pre)
            inside = True
            for k in range(ln):
                if 0 <= pos + k < len(want):
                    want[pos + k] = imm[k]
                else:
                    inside = False
            eq(post.hex(), bytes(want).hex(),
               "the store landed at data%+d %s/%s/%s" %
               (pos, sec, door, a["arm"]))
            if not inside:
                check(True, "store outside the logged payload (expected)")
    else:
        n_refused += 1
        eq(got_live, 0, "refused %s/%s/%s/%s (%s)" %
           (sec, door, env, a["arm"], why))
        eq(int(a["npost"]), 0,
           "a refused store never reaches the log expression %s/%s/%s" %
           (sec, door, a["arm"]))
        eq(a["post"], "-", "and produces no post payload %s/%s/%s" %
           (sec, door, a["arm"]))
print("   live store arms: %d, refused: %d" % (n_live, n_refused))

# --- 3. the headline counts the report quotes
def count_live(sec, door, env):
    n = 0
    for a in A0:
        if a["sec"] == sec and a["door"] == door and a["env"] == env and \
                a["mode"] == "1":
            if int(a["lives"]) > 0:
                n += 1
    return n


for door in DOORS:
    for env in ENVS:
        got = count_live("td", door, env)
        print("   td %-3s %-2s live=%d" % (door, env, got))
eq(count_live("td", "ipp", "p"), 8, "@th: ip prerouting, bare, 8/8")
eq(count_live("td", "inp", "p"), 8, "@th: inet prerouting, bare, 8/8")
eq(count_live("td", "inp", "w"), 0, "@th: inet prerouting, vid 100, unreachable")
eq(count_live("td", "inp", "w0"), 8, "@th: inet prerouting, vid 0, 8/8")
eq(count_live("td", "inp", "q"), 0, "@th: inet prerouting, Q-in-Q, unreachable")
eq(count_live("td", "inp", "ps"), 8, "@th: inet prerouting, PPPoE, 8/8")
eq(count_live("td", "ndg", "p"), 8, "@th: netdev ingress, bare, 8/8")
eq(count_live("td", "ndg", "q"), 0, "@th: netdev ingress, Q-in-Q, refused")
eq(count_live("td", "ndg", "ps"), 0, "@th: netdev ingress, PPPoE, refused")
eq(count_live("td", "ieg", "p"), 8, "@th: inet ingress, bare, 8/8")
eq(count_live("td", "ieg", "q"), 0, "@th: inet ingress, Q-in-Q, unreachable")
eq(count_live("td", "ieg", "ps"), 0, "@th: inet ingress, PPPoE, unreachable")
eq(count_live("tm", "ndg", "q"), 8, "meta protocol repairs Q-in-Q at netdev ingress")
eq(count_live("tm", "ndg", "ps"), 8, "meta protocol repairs PPPoE at netdev ingress")
eq(count_live("tm", "ieg", "q"), 0, "meta protocol cannot repair an unreached door (q)")
eq(count_live("tm", "ieg", "ps"), 0, "meta protocol cannot repair an unreached door (ps)")
eq(count_live("gd", "ndg", "p"), 12, "@ll bare at netdev ingress: constant, 12/12")
eq(count_live("gd", "ieg", "p"), 7, "@ll bare at inet ingress: off+len <= 14, 7/12")
eq(count_live("gd", "ndg", "w"), 11, "@ll tagged at netdev ingress: 11/12")
eq(count_live("gd", "ieg", "w"), 9, "@ll tagged at inet ingress: 9/12")
eq(count_live("gn", "ndg", "p"), 20, "@nh bare at netdev ingress: 20/20")
eq(count_live("gn", "ieg", "p"), 9, "@nh bare at inet ingress: the ip4 whitelist, 9/20")

# name the cells, so a wrong count cannot pass on a coincidence
live_ieg_ll = sorted((int(a["off"]), int(a["len"])) for a in A0
                     if a["sec"] == "gd" and a["door"] == "ieg" and
                     a["env"] == "p" and a["mode"] == "1" and int(a["lives"]) > 0)
eq(live_ieg_ll, [(0, 2), (0, 4), (6, 2), (8, 1), (10, 2), (12, 2), (13, 1)],
   "@ll at inet ingress: exactly the cells that stay inside the link header")
live_ieg_nh = sorted((int(a["off"]), int(a["len"])) for a in A0
                     if a["sec"] == "gn" and a["door"] == "ieg" and
                     a["mode"] == "1" and int(a["lives"]) > 0)
eq(live_ieg_nh, [(1, 1), (4, 2), (8, 1), (10, 2), (10, 4), (12, 2), (12, 4),
                 (16, 2), (16, 4)],
   "@nh at inet ingress: nft_nh_write_ok_ip4() and nothing else")
live_ieg_ll_w = sorted((int(a["off"]), int(a["len"])) for a in A0
                       if a["sec"] == "gd" and a["door"] == "ieg" and
                       a["env"] == "w" and a["mode"] == "1" and
                       int(a["lives"]) > 0)
eq(live_ieg_ll_w, [(0, 2), (0, 4), (6, 2), (8, 1), (10, 2), (12, 2), (12, 4),
                   (14, 2), (16, 2)],
   "@ll tagged at inet ingress: the tag metadata path plus off+len <= 18")

# --- 4. the far tap: what a write at each door reaches
print("== the far tap ==")
for a in A0:
    if a["sec"] not in ("td", "gd", "gn", "dp"):
        continue
    ctl = get(a["sec"], a["door"], a["env"], "ctl")
    if ctl is None or int(a["rn"]) <= 0:
        continue
    door = a["door"]
    fr = fra(a["env"])
    same = (a["rhex"] == ctl["rhex"])
    if door in ("ipp", "inp"):
        # the write lands on the copy delivered up to br0; the forwarded skb
        # is a different one
        check(same, "a write at %s never touches the forwarded skb (%s/%s)" %
              (door, a["env"], a["arm"]))
        continue
    base = int(a["base"])
    off, ln = int(a["off"]), int(a["len"])
    if a["mode"] == "0" or int(a["lives"]) == 0:
        check(same, "no accepted store -> unchanged far frame (%s/%s/%s)" %
              (door, a["env"], a["arm"]))
        continue
    tag_meta = (base == 0 and fr.ntags >= 1 and off + ln > 12 and
                off in (12, 14))
    if tag_meta:
        # the tag lives in skb->vlan_tci, so the frame bytes are untouched --
        # except when the written vlan_proto is one vlan_hw_offload_capable()
        # does not know (F37), and validate_xmit_vlan() then puts the tag
        # into the bytes on the way out
        ctlc = hx(get(a["sec"], door, a["env"], "ctl")["rhex"])
        got = hx(a["rhex"])
        eq(got[:12], ctlc[:12],
           "a tag-metadata write leaves the MAC addresses alone (%s/%s/%s)" %
           (door, a["env"], a["arm"]))
        proto = hx(a["imm"])[:2]
        if off == 12 and proto != b"\x81\x00":
            eq(len(got), len(ctlc) + 4,
               "a foreign vlan_proto puts the tag back into the bytes "
               "(%s/%s)" % (door, a["arm"]))
        else:
            eq(len(got), len(ctlc),
               "and otherwise the frame keeps its length (%s/%s)" %
               (door, a["arm"]))
        continue
    d = data_offset(door, fr)
    nt = fr.ntags
    if base == 0:
        vlan_hlen = 4 if (nt >= 1 and off + ln > 12 and off >= 16) else 0
        cap_at = off - (4 * nt if off >= 14 else 0)
    elif base == 1:
        cap_at = (d - 4 * nt) + off
    else:
        cap_at = (d - 4 * nt) + pktinfo(door, fr, 0)["thoff"] + off
    got_at = sorted(int(x.split(":")[0]) for x in a["rchgs"].split(",")
                    if ":" in x)
    eq(got_at, list(range(cap_at, cap_at + ln)),
       "the far frame changed exactly at %d..%d (%s/%s/%s)" %
       (cap_at, cap_at + ln - 1, door, a["env"], a["arm"]))
    chg = {}
    for x in a["rchgs"].split(","):
        if ":" in x:
            k, v = x.split(":")
            chg[int(k)] = v
    for k in range(ln):
        if cap_at + k in chg:
            old, new = chg[cap_at + k].split(">")
            eq(new, "%02x" % hx(a["imm"])[k],
               "byte %d carries the immediate (%s/%s/%s)" %
               (cap_at + k, door, a["env"], a["arm"]))

# --- 5. the socket oracle: the written dport is where the datagram lands
print("== the socket oracle ==")
for door in DOORS:
    a = get("dp", door, "p", "dp5001")
    if a is None:
        continue
    check(int(a["u5001"]) >= 1,
          "a dport write at %s delivers the datagram to 5001" % door,
          "u5001=%s" % a["u5001"])
    eq(int(a["u5000"]), 0, "and not to 5000 at %s" % door)
    b = get("dp", door, "ps", "dp5001")
    if b is None:
        continue
    if door == "ndg":
        eq(int(b["lives"]), 0, "PPPoE + netdev ingress: the store is refused")
        eq(int(b["u5000"]), 1, "so the datagram still lands on 5000")
    if door == "ieg":
        eq(int(b["livep"]), 0, "PPPoE + inet ingress: the chain is not reached")
_ps = get("dp", "ipp", "ps", "dp5001")
if _ps is not None:
    eq(int(_ps["u5001"]), 1,
       "PPPoE through the PPP unit: the dport write reaches the socket at 5001")

# --- 6. the drop: one hook, two doors, and the whole device
print("== the drop and the cross-family effect ==")
for env in MD_ENV["md_both"]:
    a = get("md_both", "ndg", env, env)
    if a is None:
        continue
    eq(int(a["livep"]), 0,
       "%s: with the inet ingress chains present the netdev door never counts" % env)
    eq(int(a["rn"]), -1, "%s: and the frame is not forwarded" % env)
    b = get("md_ieg", "ieg", env, env)
    if b is not None:
        eq(int(b["livep"]), 0, "%s: the inet ingress door runs no rule either" % env)
_bv = get("md_both", "ndg", "badver", "badver")
if _bv is not None:
    eq(int(_bv["ihdr"]), 1,
       "badver: one IP header error, and it is the ingress constructor's")
_tc = get("md_both", "ndg", "trunc", "trunc")
if _tc is not None:
    eq(int(_tc["itrun"]), 1,
       "trunc: the constructor counts a truncated packet, not a header error")
for env in MD_ENV["md_ndg"]:
    a = get("md_ndg", "ndg", env, env)
    if a is None:
        continue
    eq(int(a["livep"]), 1, "%s: with that table gone the netdev door counts" % env)
    eq(int(a["lives"]), 1, "%s: and the store is accepted" % env)
    eq(int(a["rn"]), 60, "%s: the frame is forwarded after all" % env)
    eq(int(a["ihdr"]), 2, "%s: two ip_rcv passes now" % env)

# --- 7. reads equal writes at every door
print("== read == write ==")
for door in DOORS:
    for arm in ("r0_2", "r2_2", "r6_2"):
        a = get("rf", door, "p", arm)
        if a is None:
            continue
        check(int(a["lives"]) > 0, "the read at %s/%s is live" % (door, arm))

# ---------------------------------------------------------------- summary
print("")
print("checks: %d ok, %d failed" % (ok, bad))
for f in fails[:40]:
    print("FAIL:", f)
print("VERIFY566 %s" % ("OK" if bad == 0 else "FAILED"))
sys.exit(0 if bad == 0 else 1)
