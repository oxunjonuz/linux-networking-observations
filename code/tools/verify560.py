#!/usr/bin/env python3
"""verify560.py -- turn 560 / F38: the receiving side of the 802.1Q tag.

Nothing here trusts the differ, the summary script or the document.  Every
number is re-derived:

  provenance   the kernel's sha256 from the log header against the file on
               disk; the initrd's sha256 against logs/f38_initrd_hashes.txt and
               against the file; the differ EXTRACTED FROM THE INITRD against
               the built binary; /proc/config.gz against .config.
  sources      the five guard functions and the receive-path order, read as
               bytes from src/linux-7.3.4-T558 (CRLF-proof).
  model        a Python transcription of nft_ll_write_ok / nft_nh_write_ok_ip4
               / nft_nh_write_ok_arp / the netdev switch / the vlan adjust,
               applied to every one of the 504 arms and compared with the
               rule's own counter delta.
  bytes        every claim about a byte index is recomputed from the hex in the
               log, including what it is NOT (the ttl on a 0x9100 frame).
  identity     the three sets that must be equal.
  determinism  rep1's F560 lines against rep2's.

usage: verify560.py [--quiet]
"""
import gzip
import hashlib
import re
import sys

ROOT = "/work/kernel-sec"
LOG1 = ROOT + "/logs/f38_rep1.log"
LOG2 = ROOT + "/logs/f38_rep2.log"
KERNEL = ROOT + "/src/linux-7.3.4-T558/arch/x86/boot/bzImage"
INITRD = ROOT + "/vm/initrd560/full.cpio.gz"
INITRD_HASHES = ROOT + "/logs/f38_initrd_hashes.txt"
DIFFER = ROOT + "/vm/build/differ560"
SRCDIR = ROOT + "/src/linux-7.3.4-T558"
SUMMARY = ROOT + "/findings/F38-recv-side-of-the-tag/summary.json"

N = 0
FAILS = []


def check(name, cond, detail=""):
    global N
    N += 1
    if not cond:
        FAILS.append("%s: %s" % (name, detail))
    return bool(cond)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def read_text(path):
    with open(path, "rb") as f:
        return f.read().replace(b"\r\n", b"\n").decode("utf-8", "replace")


def lines(path):
    out = []
    with open(path, "rb") as f:
        for raw in f:
            out.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
    return out


def rows(path):
    out = []
    for line in lines(path):
        if not line.startswith("F560 R|"):
            continue
        d = {}
        for kv in line.split("|")[1:]:
            k, _, v = kv.partition("=")
            d[k] = v
        for k in ("off", "len", "store", "rc", "live", "wn", "rn", "wchg",
                  "rchg"):
            d[k] = int(d[k])
        out.append(d)
    return out


def metas(path):
    out = {}
    for line in lines(path):
        for pre, kind in (("F560 REP|", "REP"), ("F560 SECTION|", "SECTION"),
                          ("F560 TAGSTORE|", "TAGSTORE"),
                          ("F560 KERNEL|", "KERNEL"), ("F560 NFL|", "NFL")):
            if line.startswith(pre):
                d = {}
                for kv in line.split("|")[1:]:
                    k, _, v = kv.partition("=")
                    d[k] = v
                out.setdefault(kind, []).append(d)
    return out


# ---------------------------------------------------------------- cpio ----
def cpio_extract(path, want_suffix):
    """names in this archive may or may not start with './' (F25/F32 lesson)"""
    data = gzip.open(path, "rb").read()
    at = 0
    while at + 110 <= len(data):
        hdr = data[at:at + 110]
        if hdr[:6] != b"070701":
            break
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = data[at + 110:at + 110 + namesize - 1].decode()
        # the DATA starts at a 4-byte boundary of the ARCHIVE, not of the
        # name: 110 + namesize is padded up to a multiple of 4 (F25/F32)
        body_at = at + 110 + namesize
        body_at += (-body_at) % 4
        body = data[body_at:body_at + filesize]
        if name.endswith(want_suffix) and filesize:
            return name, body
        at = body_at + filesize
        at = (at + 3) & ~3
    return None, None


# ------------------------------------------------------- guard models ----
def ll_ok(off, ln, vlan, ingress):
    """nft_payload_set_eval() LL branch + nft_ll_write_ok()."""
    if ingress:				# nft_in_ingress(): return true
        return True
    vh = 0
    if vlan and off + ln > 12:		# nft_payload_need_vlan_adjust()
        if off >= 16:			# h_vlan_encapsulated_proto and up
            vh = 4
        elif off == 12:			# h_vlan_proto
            if ln == 2:
                return True		# skb->vlan_proto, no boundary test
            if ln == 4:
                vh = 4			# __vlan_hwaccel_put_tag
            else:
                return False
        elif off == 14:			# h_vlan_TCI
            return ln == 2
        else:
            return False
    return off + ln <= 14 + vh


def ip4_ok(off, ln):
    """nft_nh_write_ok_ip4(), value tests already satisfied by f556_imm()."""
    if off == 0:
        return ln == 2			# + new_octets[0] == old_octet, checked below
    if off == 1:
        return ln == 1			# offsetof(struct iphdr, tos)
    if off == 4:
        return ln == 2
    if off == 8:
        return ln in (1, 2)		# len 2: new_octets[1] == old proto
    if off == 10:
        return ln <= 10
    if off == 12:
        return ln <= 8
    if off == 16:
        return ln <= 4
    return False


def ip6_ok(off, ln):
    if off == 0:
        return ln <= 4
    if off == 2:
        return ln <= 2
    if off == 7:
        return ln == 1
    if off == 8:
        return ln <= 32
    if off == 24:
        return ln <= 16
    return False


def arp_ok(off, ln):
    if off == 6:
        return ln == 2
    return off >= 8 and ln <= 20


ENVS = {
    "recv.p": dict(base="ll", vlan=False, etype=0x0800, ingress=False),
    "recv.w100": dict(base="ll", vlan=True, etype=0x0800, ingress=False),
    "recv.m100": dict(base="ll", vlan=False, etype=0x0800, ingress=False),
    "recv.v0": dict(base="ll", vlan=True, etype=0x0800, ingress=False),
    "recv.x91": dict(base="ll", vlan=False, etype=0x9100, ingress=False),
    "ndin.p": dict(base="nh", ingress=True, proto=0x0800),
    "ndin.w100": dict(base="nh", ingress=True, proto=0x0800),
    "ndin.x91": dict(base="nh", ingress=True, proto=0x9100),
    "ndeg.s0800": dict(base="nh", ingress=False, proto=0x0800),
    "ndeg.s8100": dict(base="nh", ingress=False, proto=0x8100),
    "ndeg.s9100": dict(base="nh", ingress=False, proto=0x9100),
    "arp.a": dict(base="nh", etype=0x0806, ingress=False),
    "arp.aw100": dict(base="nh", etype=0x0806, ingress=False),
    "arp.ax91": dict(base="nh", etype=0x9100, ingress=False),
}


def nh_verdict(etype_or_proto, off, ln):
    if etype_or_proto == 0x0800:
        return ip4_ok(off, ln)
    if etype_or_proto == 0x0806:
        return arp_ok(off, ln)
    if etype_or_proto == 0x86dd:
        return ip6_ok(off, ln)
    return False				# default: return false


def verdict(env, off, ln, arm=""):
    if env.startswith("drop."):
        # bridge, base ll; the w- arms carry a tag, the p- arms do not
        return ll_ok(off, ln, arm.startswith("w"), False)
    e = ENVS[env]
    if e["base"] == "ll":
        return ll_ok(off, ln, e["vlan"], e["ingress"])
    if e["ingress"]:
        return True			# before the switch on skb->protocol
    if e["proto"] is not None if "proto" in e else False:
        return nh_verdict(e["proto"], off, ln)
    return nh_verdict(e["etype"], off, ln)


def imm_bytes(off, ln):
    b = [(0x90 + i) & 0xff for i in range(16)]
    if off == 0:
        b[0] = 0x45			# the frame's ihl/version
    if off == 8 and ln >= 2:
        b[1] = 0x11			# the frame's protocol
    return b


def hexbytes(s):
    return bytes.fromhex(s) if s and s != "-" else b""


def main():
    global LOG1, LOG2
    quiet = "--quiet" in sys.argv
    if "--logdir" in sys.argv:
        d = sys.argv[sys.argv.index("--logdir") + 1]
        LOG1 = d + "/f38_rep1.log"
        LOG2 = d + "/f38_rep2.log"
    l1, l2 = lines(LOG1), lines(LOG2)
    r1, r2 = rows(LOG1), rows(LOG2)
    m1 = metas(LOG1)

    # ---- provenance -----------------------------------------------------
    kh = [x for x in l1 if x.startswith("### sha256: ")]
    check("prov.kernel.sha.in.log", len(kh) == 1, str(kh))
    if kh:
        check("prov.kernel.sha.matches.file", kh[0].split()[-1] == sha(KERNEL),
              kh[0])
    ih = [x for x in l1 if x.startswith("### initrd sha256: ")]
    check("prov.initrd.sha.in.log", len(ih) == 1, str(ih))
    ih2 = [x for x in l2 if x.startswith("### initrd sha256: ")]
    check("prov.initrd.same.in.both.boots", ih and ih2 and ih[0] == ih2[0])
    if ih:
        check("prov.initrd.sha.matches.file", ih[0].split()[-1] == sha(INITRD))
    with open(INITRD_HASHES) as f:
        taghash = dict(x.split() for x in f.read().split("\n") if x.strip())
    if ih:
        check("prov.initrd.in.hash.list",
              taghash.get("full") == ih[0].split()[-1], str(taghash.get("full")))
    name, body = cpio_extract(INITRD, "root/repro")
    check("prov.differ.in.initrd", body is not None, str(name))
    if body is not None:
        check("prov.differ.initrd.equals.build",
              hashlib.sha256(body).hexdigest() == sha(DIFFER),
              hashlib.sha256(body).hexdigest())

    # ---- boot and termination ------------------------------------------
    for tag, l in (("rep1", l1), ("rep2", l2)):
        check("boot.%s.VM_BOOT_OK" % tag, "=== VM_BOOT_OK ===" in l)
        check("boot.%s.version.7.3.4" % tag,
              any(x.startswith("Linux version 7.3.4") for x in l))
        check("boot.%s.MODE_EXIT=0" % tag,
              any(x.startswith("=== MODE_EXIT f560=0") for x in l))
        check("boot.%s.F560.DONE" % tag, "F560 DONE" in l)
        splat = [x for x in l if re.search(r"KASAN|BUG:|Oops|WARNING:|"
                                           r"general protection|double free",
                                           x) and "WARN" not in x[:4]]
        check("boot.%s.no.splat" % tag, not splat, str(splat[:2]))

    # ---- config ---------------------------------------------------------
    # T558 has no CONFIG_IKCONFIG_PROC: the boot prints NO_CONFIG_GZ (F36's
    # finding), so the config is checked where it is true -- the tree's .config
    # -- and the RUNTIME evidence of it is the family probe.
    check("config.no.config.gz.in.guest",
          any(x.strip() == "NO_CONFIG_GZ" for x in l1))
    kcfg = {}
    for x in read_text(SRCDIR + "/.config").split("\n"):
        if re.match(r"^CONFIG_(VLAN_8021Q|BRIDGE|NF_TABLES_BRIDGE|"
                    r"NF_TABLES_NETDEV|NF_TABLES_ARP|NET_EGRESS)=", x):
            k, _, v = x.partition("=")
            kcfg[k] = v
    for k in ("CONFIG_VLAN_8021Q", "CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE",
              "CONFIG_NF_TABLES_NETDEV", "CONFIG_NET_EGRESS"):
        check("config.%s=y" % k, kcfg.get(k) == "y", str(kcfg.get(k)))
    fam = {}
    for x in l1:
        m = re.match(r"^F556 FAM\|(\w+)\|(-?\d+)$", x)
        if m:
            fam[m.group(1)] = int(m.group(2))
    check("config.families.probed", len(fam) == 5, str(fam))
    for k, v in fam.items():
        check("config.family.%s.exists" % k, v == 0, str(v))

    # ---- sources --------------------------------------------------------
    pay = read_text(SRCDIR + "/net/netfilter/nft_payload.c")
    dev = read_text(SRCDIR + "/net/core/dev.c")
    skb = read_text(SRCDIR + "/net/core/skbuff.c")
    vlan = read_text(SRCDIR + "/include/linux/if_vlan.h")

    check("src.in_ingress.def",
          re.search(r"static bool nft_in_ingress\(const struct nf_hook_state \*s\)"
                    r"\s*\{\s*return s->pf == NFPROTO_NETDEV &&\s*"
                    r"s->hook == NF_NETDEV_INGRESS;", pay) is not None)
    check("src.netdev.ingress.true.first",
          re.search(r"case NFPROTO_NETDEV:\s*if \(pkt->state->hook == "
                    r"NF_NETDEV_INGRESS\)\s*return true;\s*return "
                    r"nft_nh_write_ok_netdev", pay) is not None)
    check("src.ll.ingress.true",
          re.search(r"static bool nft_ll_write_ok\(const struct nft_pktinfo "
                    r"\*pkt, int offset\)\s*\{\s*if \(nft_in_ingress\(pkt->state\)\)"
                    r"\s*return true;", pay) is not None)
    check("src.ll.boundary",
          re.search(r"return offset <= skb_network_offset\(pkt->skb\);",
                    pay) is not None)
    check("src.vlan_adjust.boundary",
          re.search(r"unsigned int boundary = offset \+ len;.*?"
                    r"if \(boundary > offsetof\(struct ethhdr, h_proto\)\)"
                    r"\s*return true;", pay, re.S) is not None)
    check("src.set_vlan.cases",
          re.search(r"case offsetof\(struct vlan_ethhdr, h_vlan_proto\):"
                    r".*?case offsetof\(struct vlan_ethhdr, h_vlan_TCI\):",
                    pay, re.S) is not None)
    check("src.set_vlan.gated.by.tag_present",
          re.search(r"if \(skb_vlan_tag_present\(skb\) &&\s*"
                    r"nft_payload_need_vlan_adjust", pay) is not None)
    check("src.arp.hole",
          re.search(r"return offset >= sizeof\(struct arphdr\) && priv->len "
                    r"<= eth_ip;", pay) is not None)
    check("src.netdev.default.false",
          re.search(r"default to false for now, relax later", pay) is not None)
    check("src.eth_type_vlan.two.types",
          re.search(r"static inline bool eth_type_vlan\(__be16 ethertype\)"
                    r"\s*\{\s*switch \(ethertype\) \{\s*"
                    r"case htons\(ETH_P_8021Q\):\s*"
                    r"case htons\(ETH_P_8021AD\):", vlan) is not None)
    m_pop = re.search(r"if \(eth_type_vlan\(skb->protocol\)\) \{\s*\n\s*"
                      r"skb = skb_vlan_untag\(skb\);", dev)
    i_pop = m_pop.start() if m_pop else -1
    i_tap = dev.find("list_for_each_entry_rcu(ptype, &dev_net_rcu(skb->dev)->ptype_all")
    i_ing = dev.find("if (nf_ingress(skb, &pt_prev, &ret, orig_dev) < 0)")
    check("src.order.pop.before.taps", -1 < i_pop < i_tap, "%d %d" % (i_pop, i_tap))
    check("src.order.pop.before.ingress", -1 < i_pop < i_ing, "%d %d" % (i_pop, i_ing))
    check("src.untag.puts.tag",
          "__vlan_hwaccel_put_tag(skb, skb->protocol, vlan_tci);" in skb)
    check("src.untag.resets.network.header",
          re.search(r"skb = skb_reorder_vlan_header\(skb\);.*?"
                    r"skb_reset_network_header\(skb\);", skb, re.S) is not None)
    # the egress hook runs in __dev_queue_xmit, before the queue calls
    # dev_hard_start_xmit: compare the two CALL SITES inside that function
    body_at = dev.find("int __dev_queue_xmit(struct sk_buff *skb")
    body = dev[body_at:dev.find("\n}\n", body_at)] if body_at >= 0 else ""
    i_eg = body.find("nf_hook_egress(")
    i_dhs = body.find("dev_hard_start_xmit(")
    check("src.egress.in.queue_xmit", body_at >= 0 and i_eg >= 0)
    check("src.egress.before.hard_start_xmit", -1 < i_eg < i_dhs,
          "%d %d" % (i_eg, i_dhs))

    # ---- the model against every arm -----------------------------------
    per_env = {}
    for r in r1:
        per_env.setdefault(r["env"], []).append(r)
    total_arms = 0
    for env, rs in per_env.items():
        check("env.known.%s" % env, env in ENVS or env.startswith("drop."), env)
        for r in rs:
            total_arms += 1
            if r["arm"] == "ctl":
                check("model.%s.ctl" % env, r["live"] == 1,
                      "control did not count")
                continue
            if r["store"] == 0:
                continue
            m = verdict(env, r["off"], r["len"], r["arm"])
            got = r["live"] > 0
            if r["rc"] != 0:
                check("model.%s.%s.installed" % (env, r["arm"]), False,
                      "rule refused rc=%d" % r["rc"])
                continue
            check("model.%s.%s" % (env, r["arm"]), m == got,
                  "model=%s measured=%s (%d,%d)" % (m, got, r["off"], r["len"]))
    check("model.arms.count", total_arms == 504, str(total_arms))

    # the value-dependent cells of the ip4 branch really do pass
    for env in ("ndeg.s0800",):
        for r in per_env[env]:
            if r["arm"] == "ctl" or not r["live"]:
                continue
            if r["off"] == 0:
                b = hexbytes(r["whex"])
                check("value.%s.off0.ihl.equals" % r["arm"],
                      b and b[14] == imm_bytes(0, r["len"])[0], str(b[14:16]))
            if r["off"] == 8 and r["len"] == 2:
                b = hexbytes(r["whex"])
                check("value.%s.off8.proto.equals" % r["arm"],
                      b and b[23] == imm_bytes(8, 2)[1], str(b[23]))

    # ---- the three identities ------------------------------------------
    def livemap(env):
        return {r["arm"]: (r["live"] > 0) for r in per_env[env]
                if r["arm"] != "ctl"}

    eight = {"g10_4", "g12_1", "g12_2", "g12_4", "g14_2", "g16_1", "g16_2",
             "g16_4"}
    p = livemap("recv.p")
    x = livemap("recv.x91")
    check("ident.plain.vs.9100.on.8.cells",
          all(p[k] == x[k] for k in eight),
          str({k: (p[k], x[k]) for k in eight if p[k] != x[k]}))
    w = livemap("recv.w100")
    v = livemap("recv.v0")
    check("ident.wire100.vs.vid0.on.8.cells",
          all(w[k] == v[k] for k in eight),
          str({k: (w[k], v[k]) for k in eight if w[k] != v[k]}))
    mm = livemap("recv.m100")
    check("ident.probe.m100.equals.plain.all.36", mm == p,
          str({k: (p[k], mm[k]) for k in p if p[k] != mm[k]}))
    a = livemap("arp.a")
    aw = livemap("arp.aw100")
    check("ident.arp.plain.vs.vlan.all.40",
          a == aw, str({k: (a[k], aw[k]) for k in a if a[k] != aw[k]}))

    # ---- counts that the document quotes -------------------------------
    want = {"recv.p": 23, "recv.w100": 25, "recv.m100": 23, "recv.v0": 5,
            "recv.x91": 3, "ndin.p": 40, "ndin.w100": 40, "ndin.x91": 40,
            "ndeg.s0800": 14, "ndeg.s8100": 0, "ndeg.s9100": 0,
            "arp.a": 25, "arp.aw100": 25, "arp.ax91": 0}
    for env, n in want.items():
        got = sum(1 for r in per_env[env] if r["arm"] != "ctl" and r["live"])
        check("count.%s" % env, got == n, "measured %d expected %d" % (got, n))

    # ---- bytes ---------------------------------------------------------
    def ctl(env):
        for r in per_env[env]:
            if r["arm"] == "ctl":
                return r
        return None

    cp, cw, cx, cm = ctl("recv.p"), ctl("recv.w100"), ctl("recv.x91"), ctl("recv.m100")
    check("bytes.far.p.equals.far.w100", cp["rhex"] == cw["rhex"])
    check("bytes.far.len.60", len(cp["rhex"]) == 120, str(len(cp["rhex"])))
    check("bytes.x91.wire.64", len(cx["whex"]) == 128, str(len(cx["whex"])))
    check("bytes.x91.wire.12_16", cx["whex"][24:32] == "91000064",
          cx["whex"][24:32])
    check("bytes.x91.not.popped.at.far", len(cx["rhex"]) == 128 and
          cx["rhex"][24:32] == "91000064", cx["rhex"][24:32])
    check("probe.m100.ctl.wire.equals.plain", cm["whex"] == cp["whex"])
    ts = m1.get("TAGSTORE", [])
    check("probe.tagstore.installed", len(ts) == 1 and ts[0]["rc"] == "0"
          and ts[0]["acks"] == "1", str(ts))
    check("probe.tagstore.is.12.4.8100.0064",
          ts and ts[0]["off"] == "12" and ts[0]["len"] == "4"
          and ts[0]["imm"] == "81000064", str(ts))

    def arm(env, name):
        for r in per_env[env]:
            if r["arm"] == name:
                return r
        return None

    g = {e: arm(e, "g8_1") for e in ("ndin.p", "ndin.w100", "ndin.x91")}
    check("bytes.ttl.plain.at.22", g["ndin.p"]["wchgs"] == "22:40>90",
          g["ndin.p"]["wchgs"])
    check("bytes.ttl.tagged.at.26", g["ndin.w100"]["wchgs"] == "26:40>90",
          g["ndin.w100"]["wchgs"])
    check("bytes.same.store.on.9100.at.22.is.id.not.ttl",
          g["ndin.x91"]["wchgs"] == "22:12>90", g["ndin.x91"]["wchgs"])
    bx = hexbytes(g["ndin.x91"]["whex"])
    check("bytes.9100.ttl.untouched.at.26", len(bx) > 26 and bx[26] == 0x40,
          hex(bx[26]) if len(bx) > 26 else "-")
    check("bytes.9100.ip.starts.at.18", len(bx) > 18 and bx[18] == 0x45,
          hex(bx[18]) if len(bx) > 18 else "-")

    for env, first, last, msglast in (("arp.a", 34, 49, 41),
                                      ("arp.aw100", 38, 53, 45)):
        r = arm(env, "x20_16")
        ch = [int(s.split(":")[0]) for s in r["wchgs"].split(",") if ":" in s]
        check("bytes.%s.span" % env, ch and min(ch) == first and max(ch) == last,
              "%s..%s" % (min(ch) if ch else "-", max(ch) if ch else "-"))
        check("bytes.%s.past.message" % env,
              sum(1 for i in ch if i > msglast) == 8,
              str([i for i in ch if i > msglast]))
        bw = hexbytes(r["whex"])
        check("bytes.%s.nl.bytes.in.order" % env,
              bw[first:last + 1] == bytes((0x90 + i) & 0xff for i in range(16)),
              bw[first:last + 1].hex())

    # ---- drop: the verdict, not just the counter -----------------------
    d = {r["arm"]: r for r in per_env["drop.drop"]}
    for k in ("ctl_p", "ctl_w"):
        check("drop.%s.delivered" % k, d[k]["live"] == 1 and d[k]["rn"] > 0,
              "%d %d" % (d[k]["live"], d[k]["rn"]))
    for k in ("p16_2", "p14_2"):
        check("drop.%s.refused.and.no.frame" % k,
              d[k]["live"] == 0 and d[k]["wn"] < 0 and d[k]["rn"] < 0,
              "%d %d %d" % (d[k]["live"], d[k]["wn"], d[k]["rn"]))
    for k in ("w16_2", "w14_2"):
        check("drop.%s.accepted.and.delivered" % k,
              d[k]["live"] == 1 and d[k]["rn"] > 0,
              "%d %d" % (d[k]["live"], d[k]["rn"]))
    check("drop.w16_2.rewrites.inner.ethertype",
          d["w16_2"]["rhex"][24:28] == "9091", d["w16_2"]["rhex"][24:28])

    # ---- determinism ---------------------------------------------------
    f1 = [x for x in l1 if x.startswith("F560")]
    f2 = [x for x in l2 if x.startswith("F560")]
    check("det.same.line.count", len(f1) == len(f2) and len(f1) == 528,
          "%d %d" % (len(f1), len(f2)))
    check("det.identical.lines", f1 == f2,
          "first diff: %s" % next((("%r != %r" % (a, b))
                                  for a, b in zip(f1, f2) if a != b), "-"))

    # ---- the summary JSON must agree with the logs ---------------------
    try:
        import json
        j = json.load(open(SUMMARY))
        for env, n in want.items():
            check("summary.%s.live" % env, j["envs"][env]["live"] == n,
                  str(j["envs"][env]["live"]))
        check("summary.rep_identical", j["rep_identical"] is True)
        check("summary.arms", j["arms"] == 504, str(j["arms"]))
    except FileNotFoundError:
        check("summary.exists", False, SUMMARY)

    if not quiet:
        print("verify560: %d checks, %d failed" % (N, len(FAILS)))
    for f in FAILS[:40]:
        print("FAIL %s" % f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
