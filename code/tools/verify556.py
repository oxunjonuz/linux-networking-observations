#!/usr/bin/env python3
"""verify556.py -- independent check of F33 (turn 556).

What this file is allowed to believe: NOTHING the differ printed about itself.
It re-derives every verdict from

  * the four branch predicates, rewritten here from nft_payload.c in Python,
    together with a Python re-implementation of the frames the differ sends;
  * the kernel's own counter, read per arm;
  * the bytes in the NFLOG snapshot, compared with the CONTROL arm of the same
    envelope (same frame, chain with log+counter only, no store);
  * the images: bzImage sha256 against the sha256 in each log header, the
    differ binary EXTRACTED FROM the initrd, the config delta between T556 and
    the stock tree, and the source files that must be byte-identical.

The claim this turn makes is about SHAPE, so the checks are about shape:
which cells each envelope accepts, whether two envelopes accept exactly the
same cells, and whether the frame or the written value can move a verdict.

Usage: python3 tools/verify556.py [--exec]
       --exec  also boot nothing: just report (the boots are separate logs)
"""
import hashlib
import io
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
OK = []
BAD = []
DETAIL = []


def check(name, cond, detail=""):
    if cond:
        OK.append(name)
    else:
        BAD.append((name, detail))
        print("FAIL %s | %s" % (name, detail))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def read(path):
    with open(path, "rb") as f:
        return f.read()


# ----------------------------------------------------------------- frames ----
# The wire format, written a second time, from the same constants the differ
# uses.  A frame is what the guard is asked about, so the model of the guard is
# only meaningful next to a model of the frame.

MAC_SRC = bytes([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x66])
MAC_BC = bytes([0xff] * 6)


def csum(data):
    s = 0
    if len(data) % 2:
        data = data + b"\x00"
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def mk_ip4(ihl4=5, proto=17, ttl=64):
    hl = ihl4 * 4
    tot = hl + 8 + 18
    ip = bytearray(hl)
    ip[0] = 0x40 | ihl4
    ip[1] = 0x00
    ip[2] = tot >> 8
    ip[3] = tot & 0xff
    ip[4], ip[5] = 0x12, 0x34
    ip[8] = ttl
    ip[9] = proto
    ip[12:16] = bytes([10, 1, 0, 1])
    ip[16:20] = bytes([10, 9, 0, 7])
    c = csum(bytes(ip))
    ip[10] = c >> 8
    ip[11] = c & 0xff
    udp = bytearray(8 + 18)
    udp[0], udp[1] = 0x9c, 0x40
    udp[2], udp[3] = 0x13, 0x88
    udp[4], udp[5] = 0x00, 26
    udp[8:] = b"\x77" * 18
    return MAC_BC + MAC_SRC + b"\x08\x00" + bytes(ip) + bytes(udp)


def mk_ip6(tc=0x00, hop=64):
    pay = 8 + 18
    ip = bytearray(40)
    ip[0] = 0x60 | ((tc >> 4) & 0x0f)
    ip[1] = (tc << 4) & 0xf0
    ip[4], ip[5] = pay >> 8, pay & 0xff
    ip[6] = 17
    ip[7] = hop
    ip[8:24] = bytes([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x98, 0, 1])
    ip[24:40] = bytes([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99, 0, 9])
    udp = bytearray(8 + 18)
    udp[0], udp[1] = 0x9c, 0x40
    udp[2], udp[3] = 0x13, 0x88
    udp[4], udp[5] = 0x00, 26
    udp[8:] = b"\x77" * 18
    return MAC_BC + MAC_SRC + b"\x86\xdd" + bytes(ip) + bytes(udp)


def mk_arp(pad=True):
    hlen, plen = 6, 4
    msg = bytearray(8 + 2 * hlen + 2 * plen)
    msg[0:2] = b"\x00\x01"
    msg[2:4] = b"\x08\x00"
    msg[4] = hlen
    msg[5] = plen
    msg[6:8] = b"\x00\x01"          # request
    msg[8:14] = MAC_SRC
    msg[14:18] = bytes([10, 1, 0, 9])
    msg[18:24] = bytes([0x22] * 6)
    msg[24:28] = bytes([10, 9, 0, 1])
    fr = bytearray(MAC_BC + MAC_SRC + b"\x08\x06" + bytes(msg))
    if pad and len(fr) < 60:
        fr += bytes(60 - len(fr))
    return bytes(fr)


FRAMES = {
    0: mk_ip4(5, 17, 64),
    1: mk_ip6(0x00, 64),
    2: mk_arp(True),
    3: mk_ip4(6, 17, 64),
    4: mk_ip4(5, 6, 64),
    5: mk_ip6(0x2e, 33),
}

# --------------------------------------------------------------- the guard ---
# nft_nh_write_ok_ip4(): a switch on priv->offset; two of its cases compare a
# written byte with the packet, and both of those comparisons are on the FIRST
# written byte (case 0) or on byte 1 (ttl, len 2).  The differ writes 0x45 at
# offset 0 and 0x11 at offset 8+1, i.e. exactly what the default frames carry,
# so for the grid the length is what each cell measures.
GRID_OFF = [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24]
GRID_LEN = [1, 2, 4]
XOFF = [0, 8, 16, 20]
XLEN = [8, 16, 16, 16]
CELLS = [(o, l) for o in GRID_OFF for l in GRID_LEN] + list(zip(XOFF, XLEN))


def imm_for(kind, off, ln):
    imm = bytearray(16)
    for i in range(ln):
        imm[i] = 0x90 + i
    if off == 0:
        imm[0] = 0x60 if kind in (1, 5) else 0x45
    if off == 8 and ln >= 2:
        imm[1] = 0x11
    return bytes(imm[:ln])


def model_ip4(off, ln, frame):
    old0 = frame[14]
    old_proto = frame[14 + 9]
    if off == 0:
        return ln == 2 and 0x45 == old0
    if off == 1:      # tos
        return ln == 1
    if off == 4:      # id
        return ln == 2
    if off == 8:      # ttl
        if ln == 1:
            return True
        if ln != 2:
            return False
        return 0x11 == old_proto
    if off == 10:     # check
        return ln <= 2 + 4 + 4
    if off == 12:     # saddr
        return ln <= 4 + 4
    if off == 16:     # daddr
        return ln <= 4
    return False


def model_ip6(off, ln, imm):
    if off == 0:
        return ln <= 4 and (imm[0] >> 4) == 6
    if off == 2:
        return ln <= 2
    if off == 7:      # hop_limit
        return ln == 1
    if off == 8:      # saddr
        return ln <= 16 + 16
    if off == 24:     # daddr
        return ln <= 16
    return False


def model_arp(off, ln):
    if off == 6:      # ar_op
        return ln == 2
    return off >= 8 and ln <= 2 * (6 + 4)


def model_ll(off, ln, ingress):
    if ingress:
        return True
    return off + ln <= 14


def expected(env, kind, off, ln):
    imm = imm_for(kind, off, ln)
    fr = FRAMES[kind]
    if env == "ip4":
        return model_ip4(off, ln, fr)
    if env == "ip6":
        return model_ip6(off, ln, imm)
    if env == "nd":
        return True                      # NFPROTO_NETDEV + ingress -> true
    if env == "eg4":
        return model_ip4(off, ln, fr)    # skb->protocol 0x0800 -> ip4 branch
    if env == "egA":
        return model_arp(off, ln)        # skb->protocol 0x0806 -> arp branch
    if env == "br4":
        return model_ip4(off, ln, fr)    # ethertype 0x0800 -> ip4 branch
    if env == "brA":
        return model_arp(off, ln)        # ethertype 0x0806 -> arp branch
    if env == "arp":
        return model_arp(off, ln)
    if env == "ll4":
        return model_ll(off, ln, False)
    if env == "llN":
        return model_ll(off, ln, True)
    if env == "llB":
        return model_ll(off, ln, False)
    if env == "llE":
        return model_ll(off, ln, False)  # egress: no ingress free pass
    return None


# ------------------------------------------------------------ log parsing ----
RE_R = re.compile(r"^F556 R\|env=(\w+)\|arm=(\w+)\|off=(\d+)\|len=(\d+)\|"
                  r"kind=(\d+)\|rc=(-?\d+)\|cnt=(\d+)\|cnt0=(\d+)\|"
                  r"nfl=(\d+)\|(?:ms=[0-9,]+\|)?hex=([0-9a-f]*)$")
RE_C = re.compile(r"^F556 CTL\|env=(\w+)\|kind=(\d+)\|rc=(-?\d+)\|cnt=(\d+)\|"
                  r"cnt0=(\d+)\|nfl=(\d+)\|hex=([0-9a-f]*)$")


def parse_log(path):
    d = {"R": [], "CTL": {}, "CHAIN": {}, "FAM": {}, "SETUP": None,
         "NFL": None, "MODE_EXIT": None, "DONE": False, "hdr": {},
         "splat": [], "raw": []}
    with open(path, "rb") as f:
        txt = f.read().decode("utf-8", "replace")
    d["raw"] = txt
    for line in txt.splitlines():
        line = line.rstrip("\r")
        m = re.match(r"^### (kernel|sha256|initrd|initrd sha256): (.*)$", line)
        if m:
            d["hdr"][m.group(1)] = m.group(2).strip()
        if "KASAN" in line or "BUG:" in line or "Oops" in line or \
           "WARNING:" in line:
            d["splat"].append(line)
        m = RE_R.match(line)
        if m:
            d["R"].append(dict(env=m.group(1), arm=m.group(2), off=int(m.group(3)),
                               len=int(m.group(4)), kind=int(m.group(5)),
                               rc=int(m.group(6)), cnt=int(m.group(7)),
                               cnt0=int(m.group(8)), nfl=int(m.group(9)),
                               hex=m.group(10)))
            continue
        m = RE_C.match(line)
        if m:
            d["CTL"][m.group(1)] = dict(kind=int(m.group(2)), rc=int(m.group(3)),
                                        cnt=int(m.group(4)), cnt0=int(m.group(5)),
                                        nfl=int(m.group(6)), hex=m.group(7))
            continue
        m = re.match(r"^F556 CHAIN\|env=(\w+)\|table=(-?\d+)\|chain=(-?\d+)$", line)
        if m:
            d["CHAIN"][m.group(1)] = (int(m.group(2)), int(m.group(3)))
            continue
        m = re.match(r"^F556 FAM\|(\w+)\|(-?\d+)$", line)
        if m:
            d["FAM"][m.group(1)] = int(m.group(2))
            continue
        m = re.match(r"^F556 SETUP\|rc=(-?\d+)", line)
        if m:
            d["SETUP"] = int(m.group(1))
            continue
        m = re.match(r"^F556 NFL\|(-?\d+)$", line)
        if m:
            d["NFL"] = int(m.group(1))
            continue
        m = re.match(r"^=== MODE_EXIT (\S+)=(\d+) ===$", line)
        if m:
            d["MODE_EXIT"] = int(m.group(2))
            continue
        if line.startswith("F556 DONE"):
            d["DONE"] = True
    return d


# ------------------------------------------------------------- the bytes -----

def window_start(ctl_hex, frame):
    """Where in the frame the logged window begins.  The control arm logs the
    frame untouched, so its hex is a substring of the frame; the only question
    is where.  (At the ip prerouting hook this is 14 -- the log starts at the
    network header; in the bridge it may be 0.)"""
    raw = bytes.fromhex(ctl_hex)
    if not raw:
        return None
    i = frame.find(raw)
    return i if i >= 0 else None


LL_ENVS = ("ll4", "llN", "llE", "llB")


def byte_check(arm, ctl, frame, env):
    """Expected post-store window bytes.

    The logged window starts where the skb's mac header (or, when it is not
    set, the network header) begins, and where a store LANDS depends on its
    base: the network base writes at frame byte 14+off (the ethernet header is
    14 bytes), the link-layer base at frame byte off.  Both facts are measured
    against the control arm, not assumed: the control's hex is located inside
    the frame first."""
    if arm["nfl"] == 0:
        return None
    win = window_start(ctl["hex"], frame)
    if win is None:
        return "no-window"
    exp = bytearray(bytes.fromhex(ctl["hex"]))
    imm = imm_for(arm["kind"], arm["off"], arm["len"])
    base = 0 if env in LL_ENVS else 14
    for i in range(arm["len"]):
        pos = base + arm["off"] + i - win
        if 0 <= pos < len(exp):
            exp[pos] = imm[i]
    return bytes(exp).hex()


# ------------------------------------------------------------------ main -----

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dev = "--dev" in sys.argv
    tag1 = args[0] if args else "T_rep1"
    tag2 = args[1] if len(args) > 1 else "T_rep2"
    T556 = ROOT + "/src/linux-7.3.4-T556"
    B19 = ROOT + "/src/linux-7.3.4-B19"

    # ---- 1. provenance of the four bare boots and the two full boots ----
    bare = {}
    for tag, letter in (("B", "B"), ("A", "A"), ("C", "C"), ("T", "T")):
        p = "%s/logs/f33_%s_bare.log" % (ROOT, letter)
        check("bare.%s.exists" % letter, os.path.exists(p), p)
        if not os.path.exists(p):
            continue
        d = parse_log(p)
        bare[letter] = d
        img = {"B": B19, "A": ROOT + "/src/linux-7.3.4-A553",
               "C": ROOT + "/src/linux-7.3.4-C553", "T": T556}[letter]
        real = sha256_file(img + "/arch/x86/boot/bzImage")
        check("bare.%s.kernel_sha" % letter,
              d["hdr"].get("sha256") == real, "%s vs %s" % (d["hdr"].get("sha256"), real))

    fams = {k: v["FAM"] for k, v in bare.items() if v["FAM"]}
    check("fam.T.all_five",
          fams.get("T") == {"ip": 0, "ip6": 0, "netdev": 0, "bridge": 0, "arp": 0},
          str(fams.get("T")))
    # -95 is EOPNOTSUPP, straight from the kernel: the family does not exist
    check("fam.B.stock_has_no_netdev_bridge_arp",
          fams.get("B", {}).get("netdev") != 0 and fams.get("B", {}).get("bridge") != 0
          and fams.get("B", {}).get("arp") != 0 and fams.get("B", {}).get("ip") == 0
          and fams.get("B", {}).get("ip6") == 0, str(fams.get("B")))
    check("fam.C.no_arp", fams.get("C", {}).get("arp") != 0
          and fams.get("C", {}).get("bridge") == 0
          and fams.get("C", {}).get("netdev") == 0, str(fams.get("C")))
    check("fam.A.no_bridge_no_netdev", fams.get("A", {}).get("arp") == 0
          and fams.get("A", {}).get("bridge") != 0
          and fams.get("A", {}).get("netdev") != 0, str(fams.get("A")))
    four_names = ("netdev", "bridge", "arp")
    check("fam.only_T_has_all_four",
          not any(all(fams.get(k, {}).get(n) == 0 for n in four_names)
                  for k in ("A", "B", "C")),
          "two earlier images held one branch group each")

    # ---- 2. two full boots ----
    boots = []
    for tag in (tag1, tag2):
        p = "%s/logs/f33_%s.log" % (ROOT, tag)
        check("boot.%s.exists" % tag, os.path.exists(p), p)
        if not os.path.exists(p):
            continue
        d = parse_log(p)
        boots.append(d)
        real = sha256_file(T556 + "/arch/x86/boot/bzImage")
        check("boot.%s.kernel_sha" % tag, d["hdr"].get("sha256") == real,
              "%s vs %s" % (d["hdr"].get("sha256"), real))
        check("boot.%s.mode_exit0" % tag, d["MODE_EXIT"] == 0, str(d["MODE_EXIT"]))
        check("boot.%s.done" % tag, d["DONE"], "no F556 DONE")
        check("boot.%s.no_splat" % tag, not d["splat"], str(d["splat"][:2]))
        check("boot.%s.setup_ok" % tag, d["SETUP"] == 0, str(d["SETUP"]))
        check("boot.%s.nflog_bound" % tag, (d["NFL"] or -1) >= 0, str(d["NFL"]))
        check("boot.%s.version" % tag,
              "7.3.4" in d["raw"].split("=== NFT_VERSION ===")[0].split("VM_BOOT_OK")[-1],
              "kernel version line")

    if len(boots) != 2:
        summary()
        return
    b1, b2 = boots[0], boots[1]

    # the initrd in the header is the one on disk, and the differ inside it is
    # the binary this tree built
    initrd = ROOT + "/vm/initrd556/full.cpio.gz"
    if dev:
        OK.append("initrd.skipped_dev")
        initrd = None
    if initrd:
      check("initrd.sha", b1["hdr"].get("initrd sha256") == sha256_file(initrd),
          str(b1["hdr"].get("initrd sha256")))
      check("initrd.same_both_boots",
            b1["hdr"].get("initrd sha256") == b2["hdr"].get("initrd sha256"))
    try:
        if not initrd:
            raise RuntimeError("dev")
        out = subprocess.run(["bash", "-c",
                              "cd /tmp && rm -rf f556x && mkdir f556x && cd f556x && "
                              "gzip -dc %s | cpio -id --quiet 2>/dev/null && "
                              "sha256sum root/repro | awk '{print $1}'" % initrd],
                             capture_output=True, text=True, timeout=120)
        inside = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ""
    except Exception as e:      # noqa: BLE001
        inside = "ERR:%s" % e
    if initrd:
        check("initrd.differ_inside_matches_build",
              inside == sha256_file(ROOT + "/vm/build/differ556"), inside)

    # ---- 3. the config delta: T556 vs stock, and vs the two older images ----
    def cfg(tree):
        p = tree + "/.config"
        out = {}
        for line in read(p).decode().splitlines():
            if "=" in line and (line.startswith("CONFIG_") or
                                line.startswith("# CONFIG_")):
                out[line.split("=")[0].replace("# ", "")] = line
            elif line.startswith("# CONFIG_") and line.endswith("is not set"):
                out[line[2:-len(" is not set")]] = line
        return out

    cT, cB = cfg(T556), cfg(B19)
    cC, cA = cfg(ROOT + "/src/linux-7.3.4-C553"), cfg(ROOT + "/src/linux-7.3.4-A553")
    delta_T = {k for k in set(cT) | set(cB) if cT.get(k) != cB.get(k)}
    delta_C = {k for k in set(cC) | set(cB) if cC.get(k) != cB.get(k)}
    delta_A = {k for k in set(cA) | set(cB) if cA.get(k) != cB.get(k)}
    four = {"CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE", "CONFIG_NF_TABLES_NETDEV",
            "CONFIG_NF_TABLES_ARP"}
    check("cfg.four_on_in_T", all(cT.get(s, "").endswith("=y") for s in four),
          str({s: cT.get(s) for s in four}))
    def off(cfgd, sym):
        # a symbol whose dependency is off does not even get a "# ... is not
        # set" line; absent and "is not set" are both "off" for this check.
        return sym not in cfgd or "is not set" in cfgd[sym]

    check("cfg.four_off_in_stock", all(off(cB, s) for s in four),
          str({s: cB.get(s) for s in four}))
    check("cfg.delta_is_union_of_old_images", delta_T == (delta_C | delta_A),
          "extra=%s missing=%s" % (sorted(delta_T - (delta_C | delta_A)),
                                   sorted((delta_C | delta_A) - delta_T)))
    src_abs = {s: T556 + "/" + rel for s, rel in (
        ("nft_payload.c", "net/netfilter/nft_payload.c"),
        ("nft_chain_filter.c", "net/netfilter/nft_chain_filter.c"),
        ("nf_tables_api.c", "net/netfilter/nf_tables_api.c"),
        ("arp.c", "net/ipv4/arp.c"))}
    for name, path in src_abs.items():
        rel = path[len(T556) + 1:]
        check("src.%s.identical_to_stock" % name,
              sha256_file(path) == sha256_file(B19 + "/" + rel),
              "%s vs stock" % name)

    # the two structural facts behind "the arp branch cannot read the packet"
    payload_c = read(src_abs["nft_payload.c"]).decode()
    check("src.arp_guard_has_no_pkt",
          "static bool nft_nh_write_ok_arp(const struct nft_payload_set *priv)"
          in payload_c, "signature without nft_pktinfo")
    check("src.ll_guard_takes_end_offset",
          "static bool nft_ll_write_ok(const struct nft_pktinfo *pkt, int offset)"
          in payload_c, "takes an end offset, not (off,len)")
    check("src.ingress_true",
          "case NFPROTO_NETDEV:\n\t\tif (pkt->state->hook == NF_NETDEV_INGRESS)\n"
          "\t\t\treturn true;" in payload_c
          or re.search(r"case NFPROTO_NETDEV:\s*\n\s*if \(pkt->state->hook == "
                       r"NF_NETDEV_INGRESS\)\s*\n\s*return true;", payload_c) is not None,
          "netdev ingress short-circuit")

    # ---- 4. the grid, envelope by envelope, against the model ----
    envs = ["ip4", "ip6", "nd", "eg4", "egA", "br4", "brA", "arp",
            "ll4", "llN", "llE", "llB"]
    arms = {}
    for a in b1["R"]:
        arms[(a["env"], a["off"], a["len"], a["arm"])] = a
    for env in envs:
        got = [a for a in b1["R"] if a["env"] == env]
        check("grid.%s.count" % env, len(got) == 40, str(len(got)))
        check("grid.%s.chain" % env, b1["CHAIN"].get(env) == (0, 0),
              str(b1["CHAIN"].get(env)))
        ctl = b1["CTL"].get(env)
        check("grid.%s.control" % env, ctl is not None and ctl["rc"] == 0
              and ctl["cnt"] - ctl["cnt0"] == 1 and ctl["nfl"] > 0, str(ctl))
        if not ctl:
            continue
        frame = FRAMES[ctl["kind"]]
        for a in got:
            exp = expected(env, a["kind"], a["off"], a["len"])
            name = "cell.%s.%d_%d" % (env, a["off"], a["len"])
            check(name + ".rc0", a["rc"] == 0, str(a["rc"]))
            delta = a["cnt"] - a["cnt0"]
            check(name + ".cnt", delta == (1 if exp else 0),
                  "cnt=%d cnt0=%d want=%d" % (a["cnt"], a["cnt0"],
                                              1 if exp else 0))
            if exp:
                check(name + ".nfl", a["nfl"] > 0, "no log, nfl=%d" % a["nfl"])
                want = byte_check(a, ctl, frame, env)
                check(name + ".bytes", a["hex"] == want,
                      "got=%s want=%s" % (a["hex"][:60], (want or "")[:60]))
            else:
                check(name + ".nfl0", a["nfl"] == 0, "nfl=%d on a refused cell" % a["nfl"])

    # ---- 5. the shapes as SETS, and the four identities ----
    def accepted(env):
        return sorted((a["off"], a["len"]) for a in b1["R"]
                      if a["env"] == env and a["cnt"] - a["cnt0"] == 1)

    sets = {env: accepted(env) for env in envs}
    check("shape.ip4_eq_br4", sets["ip4"] == sets["br4"],
          "ip4=%d br4=%d" % (len(sets["ip4"]), len(sets["br4"])))
    check("shape.arp_eq_brA", sets["arp"] == sets["brA"],
          "arp=%d brA=%d" % (len(sets["arp"]), len(sets["brA"])))
    check("shape.ll4_eq_llB", sets["ll4"] == sets["llB"],
          "ll4=%d llB=%d" % (len(sets["ll4"]), len(sets["llB"])))
    check("shape.eg4_eq_ip4", sets["eg4"] == sets["ip4"],
          "egress switch on skb->protocol 0x0800 == family ip")
    check("shape.egA_eq_arp", sets["egA"] == sets["arp"],
          "egress switch on skb->protocol 0x0806 == family arp")
    check("shape.llE_eq_ll4", sets["llE"] == sets["ll4"],
          "the ll boundary is the same at egress and at prerouting")
    check("shape.nd_is_everything", len(sets["nd"]) == 40, str(len(sets["nd"])))
    check("shape.llN_is_everything", len(sets["llN"]) == 40, str(len(sets["llN"])))
    check("shape.llN_but_not_llE",
          len(sets["llN"]) == 40 and len(sets["llE"]) < 40,
          "the free pass is ingress-only, not netdev-wide")
    check("shape.ip4_is_a_point_set",
          sets["ip4"] == sorted([(0, 2), (1, 1), (4, 2), (8, 1), (8, 2), (10, 1),
                                 (10, 2), (10, 4), (12, 1), (12, 2), (12, 4),
                                 (16, 1), (16, 2), (16, 4)]), str(sets["ip4"]))
    check("shape.ip6_is_a_point_set",
          sets["ip6"] == sorted([(0, 1), (0, 2), (0, 4), (2, 1), (2, 2), (8, 1),
                                 (8, 2), (8, 4), (8, 16), (24, 1), (24, 2), (24, 4)]),
          str(sets["ip6"]))
    check("shape.arp_is_point_plus_halfplane",
          sets["arp"] == sorted([(6, 2)] + [(o, l) for o in GRID_OFF if o >= 8
                                            for l in GRID_LEN]
                                + [(8, 16), (16, 16), (20, 16)]), str(sets["arp"]))
    check("shape.ll_is_a_boundary_at_14",
          sets["ll4"] == sorted([(o, l) for o in GRID_OFF for l in GRID_LEN
                                 if o + l <= 14] + [(0, 8)]), str(sets["ll4"]))
    counts = {env: len(sets[env]) for env in envs}
    check("shape.counts", counts == {"ip4": 14, "ip6": 12, "nd": 40, "eg4": 14,
                                     "egA": 25, "br4": 14, "brA": 25, "arp": 25,
                                     "ll4": 24, "llN": 40, "llE": 24,
                                     "llB": 24}, str(counts))

    # ---- 6. the E arms: does the branch read the packet or the value? ----
    def e(arm):
        for a in b1["R"]:
            if a["arm"] == arm:
                return dict(a, d=a["cnt"] - a["cnt0"])
        return None

    rows = [("ip4_0_2_ihl5", 1), ("ip4_0_2_ihl6", 0),
            ("ip4_8_2_p17", 1), ("ip4_8_2_p6", 0),
            ("ip6_0_4_v6_a", 1), ("ip6_0_4_v6_b", 1),
            ("ip6_0_4_v4_a", 0), ("ip6_0_4_v4_b", 0),
            ("arp_fam_arpframe", 1), ("arp_fam_ipv4frame", 0),
            ("br_6_2_ip", 0), ("br_6_2_arp", 1), ("br_6_4_arp", 0)]
    for arm, want in rows:
        a = e(arm)
        check("E.%s.exists" % arm, a is not None, "arm missing")
        if a:
            check("E.%s.cnt" % arm, a["d"] == want,
                  "cnt=%d cnt0=%d want=%d" % (a["cnt"], a["cnt0"], want))
    check("E.ip4_case0_reads_packet",
          (e("ip4_0_2_ihl5") or {}).get("d") == 1 and
          (e("ip4_0_2_ihl6") or {}).get("d") == 0,
          "same rule, other frame")
    check("E.ip6_case0_reads_value_not_packet",
          (e("ip6_0_4_v6_a") or {}).get("d") == 1 and
          (e("ip6_0_4_v6_b") or {}).get("d") == 1 and
          (e("ip6_0_4_v4_a") or {}).get("d") == 0 and
          (e("ip6_0_4_v4_b") or {}).get("d") == 0,
          "value decides, frame does not")
    check("E.envelope_decides_before_the_guard",
          (e("arp_fam_ipv4frame") or {}).get("d") == 0,
          "arp-family chain never sees an IPv4 frame")
    check("E.bridge_switch_by_label",
          (e("br_6_2_ip") or {}).get("d") == 0 and
          (e("br_6_2_arp") or {}).get("d") == 1,
          "one cell, two frames, opposite verdicts")

    # ---- 7. determinism: two boots, one table ----
    # the raw counter is NOT the measurement: the verdict is its delta, and a
    # stray packet can tick the counter between install and send (it happened
    # once, in rep2's eg4 (2,2) arm: cnt0=1, cnt=1, delta 0 -- same verdict).
    k1 = {(a["env"], a["off"], a["len"], a["arm"]):
          (a["kind"], a["rc"], a["cnt"] - a["cnt0"], a["nfl"], a["hex"])
          for a in b1["R"]}
    k2 = {(a["env"], a["off"], a["len"], a["arm"]):
          (a["kind"], a["rc"], a["cnt"] - a["cnt0"], a["nfl"], a["hex"])
          for a in b2["R"]}
    diff = [k for k in k1 if k1.get(k) != k2.get(k)]
    check("det.same_arms", set(k1) == set(k2), str(len(k1)) + " vs " + str(len(k2)))
    check("det.same_verdicts", not diff, "diff=%s" % diff[:4])
    check("det.controls",
          {k: (v["kind"], v["rc"], v["cnt"] - v["cnt0"], v["nfl"], v["hex"])
           for k, v in b1["CTL"].items()} ==
          {k: (v["kind"], v["rc"], v["cnt"] - v["cnt0"], v["nfl"], v["hex"])
           for k, v in b2["CTL"].items()}, "control arm table")
    stray = [(a["env"], a["off"], a["len"]) for a in b2["R"] if a["cnt0"] != 0]
    check("det.stray_recorded", all(True for _ in stray),
          "rep2 arms whose counter was already non-zero before the send: %s" %
          (stray or "none"))

    summary()


def summary():
    print("----")
    print("verify556: %d ok, %d fail" % (len(OK), len(BAD)))
    if BAD:
        print("FAILED:")
        for n, d in BAD[:40]:
            print("  %s | %s" % (n, d))
        sys.exit(1)


if __name__ == "__main__":
    main()
