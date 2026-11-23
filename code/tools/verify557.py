#!/usr/bin/env python3
"""verify557.py -- turn 557 / F35: the ll boundary is a function of the ENVELOPE.

The claim under test: nft_ll_write_ok() keeps a link-layer store out of the
network header, and the number it compares against,
`skb_network_header - skb_mac_header + vlan_hlen`, is the length of THIS
envelope's link header -- 14 on ethernet, 18 on an 802.1Q frame whose tag the
receive path pulled into skb metadata (for stores at offset >= 16), 0 on a
packet that came out of an L3 tunnel.  Everything below is parsed out of the
console logs; the differ binary is extracted from the initramfs itself and the
kernel hashes are compared with the hashes their own logs recorded.
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
LOGS = ROOT + "/logs"
if "--logs" in sys.argv:
    LOGS = sys.argv[sys.argv.index("--logs") + 1]
OK = []
FAIL = []


def check(name, cond, detail=""):
    if cond:
        OK.append(name)
    else:
        FAIL.append((name, detail))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def read(path):
    """CRLF: the console logs carry \\r\\n, so every $ anchor in this file is
    written \\r?$ -- a lesson this project has now paid for eight times."""
    with open(path, "rb") as f:
        return f.read().decode("latin-1")


GRID_OFF = [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24]
GRID_LEN = [1, 2, 4]
TUN_OFF = [0, 6, 10, 12, 14, 16, 20]
CELLS = [(o, l) for o in GRID_OFF for l in GRID_LEN]
TCELLS = [(o, l) for o in TUN_OFF for l in GRID_LEN]

# ---------------------------------------------------------------- the model --
# every branch below is a reading of nft_payload_set_eval()/nft_ll_write_ok()
# in 7.3.4, stated as a predicate, and then compared cell-for-cell with the
# kernel's own counter.
def m_plain(off, ln):
    """ethernet: the link header is 14 bytes, tag absent"""
    return off + ln <= 14


def m_vlan(off, ln):
    """802.1Q frame with the tag in skb metadata:
       off+len <= 12           -> no vlan adjust, base = mac-data, limit 14
       12/14 with the exact lengths nft_payload_set_vlan() accepts -> the
                                  store lands in skb->vlan_proto / vlan_tci
       off >= 16               -> vlan_hlen = 4 is subtracted from the base,
                                  so the limit becomes 18 and the store lands
                                  at frame byte `off` (the tag is not in the
                                  frame: skb_reorder_vlan_header() moved the
                                  mac header by 4)"""
    if off + ln <= 12:
        return off + ln <= 14
    if off == 12:
        return ln in (2, 4)
    if off == 14:
        return ln == 2
    return off >= 16 and off + ln <= 18


def m_l3tun(off, ln):
    """ipip: mac_header == data (skb_reset_mac_header in ipip_tunnel_rcv),
       network header == data, so the limit is 0"""
    return off + ln <= 0


MODEL = {
    "p4": m_plain, "p4s": m_plain, "pB": m_plain,
    "vB": m_vlan,
    # 802.1Q frame in the IP family: MEASURED all-dead, and not because of the
    # guard -- T557 has CONFIG_VLAN_8021Q unset, so the receive path never
    # untags the frame and the IPv4 stack never sees it (ingress counter 1,
    # ip prerouting counter 0, IpInReceives unchanged; see DIAG9 in the log).
    "v4": lambda off, ln: False,
    "ipip": m_l3tun, "vxlan": m_plain,
}
ENVS = ["p4s", "p4", "v4", "pB", "vB", "ipip", "vxlan"]

# ------------------------------------------------------------------- logs ----
RE_R = re.compile(
    r"^F557 R\|env=(\w+)\|arm=(\w+)\|off=(\d+)\|len=(\d+)\|kind=(\d+)\|"
    r"fast=(\d+)\|rc=(-?\d+)\|acks=(-?\d+)\|cnt=(\d+)\|cnt0=(\d+)\|nfl=(\d+)\|"
    r"(?:ms=\d+\|)?hex=([0-9a-f]*)\r?$", re.M)
RE_C = re.compile(
    r"^F557 CTL\|env=(\w+)\|kind=(\d+)\|fast=(\d+)\|rc=(-?\d+)\|acks=(-?\d+)\|"
    r"cnt=(\d+)\|cnt0=(\d+)\|nfl=(\d+)\|hex=([0-9a-f]*)\r?$", re.M)


RE_R556 = re.compile(
    r"^F556 R\|env=(\w+)\|arm=(\w+)\|off=(\d+)\|len=(\d+)\|kind=(\d+)\|"
    r"rc=(-?\d+)\|cnt=(\d+)\|cnt0=(\d+)\|nfl=(\d+)\|(?:ms=[0-9,]+\|)?"
    r"hex=([0-9a-f]*)\r?$", re.M)
RE_C556 = re.compile(
    r"^F556 CTL\|env=(\w+)\|kind=(\d+)\|rc=(-?\d+)\|cnt=(\d+)\|"
    r"cnt0=(\d+)\|nfl=(\d+)\|hex=([0-9a-f]*)\r?$", re.M)


def parse(path):
    log = read(path)
    d = {"R": {}, "CTL": {}, "log": log}
    # the F33 instrument's own output, used for the p4s reference envelope
    for m in RE_R556.finditer(log):
        env, arm, off, ln, kind, rc, cnt, cnt0, nfl, hexs = m.groups()
        d["R"][(env, arm)] = dict(off=int(off), len=int(ln), kind=int(kind),
                                 fast=0, rc=int(rc), acks=1, cnt=int(cnt),
                                 cnt0=int(cnt0), nfl=int(nfl), hex=hexs)
    for m in RE_C556.finditer(log):
        env, kind, rc, cnt, cnt0, nfl, hexs = m.groups()
        d["CTL"][env] = dict(kind=int(kind), fast=0, rc=int(rc), acks=1,
                             cnt=int(cnt), nfl=int(nfl), hex=hexs)
    for m in RE_R.finditer(log):
        env, arm, off, ln, kind, fast, rc, acks, cnt, cnt0, nfl, hexs = m.groups()
        d["R"][(env, arm)] = dict(off=int(off), len=int(ln), kind=int(kind),
                                 fast=int(fast), rc=int(rc), acks=int(acks),
                                 cnt=int(cnt), cnt0=int(cnt0), nfl=int(nfl),
                                 hex=hexs)
    for m in RE_C.finditer(log):
        env, kind, fast, rc, acks, cnt, cnt0, nfl, hexs = m.groups()
        d["CTL"][env] = dict(kind=int(kind), fast=int(fast), rc=int(rc),
                             acks=int(acks), cnt=int(cnt), nfl=int(nfl),
                             hex=hexs)
    return d


FULL = ["T_rep1", "T_rep2"]
logs = {}
for tag in FULL + ["T_grid", "T_ver", "T_tun", "smoke_f557tun"]:
    p = "%s/f35_%s.log" % (LOGS, tag)
    if os.path.isfile(p):
        logs[tag] = parse(p)
check("log.full_rep1", "T_rep1" in logs)
check("log.full_rep2", "T_rep2" in logs)

# ------------------------------------------------------------ 1. provenance --
T557 = ROOT + "/src/linux-7.3.4-T557/arch/x86/boot/bzImage"
check("image.exists", os.path.isfile(T557), T557)
real_k = sha256(T557) if os.path.isfile(T557) else ""
for tag in logs:
    m = re.search(r"### sha256: ([0-9a-f]{64})", logs[tag]["log"])
    check("prov.%s.sha_recorded" % tag, m is not None)
    if m:
        check("prov.%s.sha_matches_file" % tag, m.group(1) == real_k,
              "%s != %s" % (m.group(1), real_k))
    v = re.search(r"Linux version (\S+)", logs[tag]["log"])
    check("prov.%s.version_is_7_3_4" % tag,
          v is not None and v.group(1).startswith("7.3.4"), v.group(1) if v else "?")

initrd_hashes = {}
if os.path.isfile(ROOT + "/logs/f35_initrd_hashes.txt"):
    for line in read(ROOT + "/logs/f35_initrd_hashes.txt").splitlines():
        parts = line.split()
        if len(parts) == 2:
            initrd_hashes[parts[0]] = parts[1]
check("prov.initrd_hashes_recorded", len(initrd_hashes) >= 3,
      str(sorted(initrd_hashes)))

# the differ inside the initramfs the full boot used
initrd = ROOT + "/vm/initrd557/full.cpio.gz"
check("initrd.full.exists", os.path.isfile(initrd))
if os.path.isfile(initrd):
    tmp = tempfile.mkdtemp(prefix="f35initrd")
    subprocess.run("gzip -dc %s | cpio -id --quiet 2>/dev/null" % initrd,
                   shell=True, cwd=tmp)
    got = os.path.join(tmp, "root/repro")
    check("initrd.repro_present", os.path.isfile(got), got)
    if os.path.isfile(got):
        check("initrd.repro_is_build_artifact",
              sha256(got) == sha256(ROOT + "/vm/build/differ557"))
    check("initrd.nft_present", os.path.isfile(os.path.join(tmp, "nft")))

# the config delta: exactly the tunnel symbols, and the guard's file untouched
cfgT556 = ROOT + "/src/linux-7.3.4-T556/.config"
cfgT557 = ROOT + "/src/linux-7.3.4-T557/.config"


def cfg(path):
    d = {}
    for line in read(path).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("# ") and line.endswith(" is not set"):
            d[line[2:-11]] = "n"
        elif "=" in line:
            k, _, v = line.partition("=")
            d[k] = v
    return d


c556, c557 = cfg(cfgT556), cfg(cfgT557)
delta = {k: (c556.get(k, "?"), c557.get(k, "?"))
         for k in set(c556) | set(c557) if c556.get(k) != c557.get(k)}
check("cfg.delta_is_the_tunnel_set",
      set(delta) <= {"CONFIG_NET_IPIP", "CONFIG_VXLAN", "CONFIG_NET_UDP_TUNNEL"},
      str(delta))
check("cfg.ipip_on", c557.get("CONFIG_NET_IPIP") == "y")
check("cfg.vxlan_on", c557.get("CONFIG_VXLAN") == "y")
check("cfg.vlan_8021q_off", c557.get("CONFIG_VLAN_8021Q") == "n",
      c557.get("CONFIG_VLAN_8021Q"))
for f in ["net/netfilter/nft_payload.c", "net/netfilter/nft_cmp.c",
          "net/netfilter/nft_meta.c", "net/ipv4/ipip.c",
          "drivers/net/vxlan/vxlan_core.c"]:
    a, b = ROOT + "/src/linux-7.3.4-T556/" + f, ROOT + "/src/linux-7.3.4-T557/" + f
    if os.path.isfile(a) and os.path.isfile(b):
        check("cfg.identical.%s" % os.path.basename(f), sha256(a) == sha256(b))

# ------------------------------------------------------- 2. the grid cells --
def cells_of(tag, env):
    d = logs[tag]["R"]
    return {c: d[(env, "g%d_%d" % c)] for c in CELLS if (env, "g%d_%d" % c) in d}


def tcells_of(tag, env):
    d = logs[tag]["R"]
    return {c: d[(env, "g%d_%d" % c)] for c in TCELLS if (env, "g%d_%d" % c) in d}


if "T_rep1" in logs:
    for env in ENVS:
        cs = cells_of("T_rep1", env) if env not in ("ipip", "vxlan") \
            else tcells_of("T_rep1", env)
        if not cs:
            check("grid.%s.present" % env, False, "no cells")
            continue
        check("grid.%s.cell_count" % env,
              len(cs) == (len(CELLS) if env not in ("ipip", "vxlan") else len(TCELLS)),
              "%d cells" % len(cs))
        bad = []
        for (o, l), row in cs.items():
            want = 1 if MODEL[env](o, l) else 0
            if row["cnt"] != want:
                bad.append((o, l, row["cnt"], want))
        check("grid.%s.cells_match_model" % env, not bad, str(bad[:6]))
        # every arm must have installed (rc=0) and been acknowledged
        check("grid.%s.all_rc0" % env, all(r["rc"] == 0 for r in cs.values()),
              [k for k, r in cs.items() if r["rc"]])
        check("grid.%s.all_acked" % env, all(r["acks"] >= 1 for r in cs.values()))
        # a refused cell must leave no log message; a live one must be logged.
        # Not for p4s: that envelope is driven by the F33 helper, whose NFLOG
        # socket is opened by f556_main(), which this instrument never calls.
        if env != "p4s":
            check("grid.%s.nfl_follows_cnt" % env,
                  all((r["nfl"] > 0) == (r["cnt"] > 0) for r in cs.values()),
                  [(k, r["cnt"], r["nfl"]) for k, r in cs.items()
                   if (r["nfl"] > 0) != (r["cnt"] > 0)][:4])
        # the control arm: the frame (or the decapsulated packet) arrives
        ctl = logs["T_rep1"]["CTL"].get(env)
        want_ctl = 0 if env == "v4" else 1
        check("grid.%s.control" % env,
              ctl is not None and ctl["cnt"] == want_ctl, ctl)

# ------------------------------------ 3. the identities the claim rests on --
if "T_rep1" in logs:
    def live(env):
        cs = cells_of("T_rep1", env) if env not in ("ipip", "vxlan") \
            else tcells_of("T_rep1", env)
        return {c for c, r in cs.items() if r["cnt"] == 1}

    p4, pB, vB = live("p4"), live("pB"), live("vB")
    check("id.plain_ip_equals_plain_bridge", p4 == pB, str(p4 ^ pB))
    check("id.vlan_differs_from_plain", vB != pB)
    check("id.vlan_loses_the_ethertype_straddle", (10, 4) in pB and (10, 4) not in vB)
    check("id.vlan_loses_12_1", (12, 1) in pB and (12, 1) not in vB)
    check("id.vlan_gains_12_4", (12, 4) not in pB and (12, 4) in vB)
    check("id.vlan_gains_14_2", (14, 2) not in pB and (14, 2) in vB)
    check("id.vlan_gains_16_1", (16, 1) not in pB and (16, 1) in vB)
    check("id.vlan_gains_16_2", (16, 2) not in pB and (16, 2) in vB)
    check("id.vlan_16_4_still_dead", (16, 4) not in vB)
    check("id.vlan_20_dead", not any(c[0] == 20 for c in vB))
    # the two tunnels: same grid, opposite answers
    ipip, vx = live("ipip"), live("vxlan")
    check("id.ipip_all_dead", ipip == set(), str(sorted(ipip)))
    check("id.vxlan_is_plain_ethernet",
          vx == {c for c in TCELLS if m_plain(*c)}, str(sorted(vx)))
    check("id.tunnel_answers_differ", ipip != vx)

# ------------------------------------------- 4. the verdict under policy drop
VERDICT = {
    "bp": {"ctl": 1, "b12_1": 1, "b14_2": 0, "b16_2": 0},
    "bv": {"ctl": 1, "b12_1": 0, "b14_2": 1, "b16_2": 1},
}
if "T_rep1" in logs:
    d = logs["T_rep1"]
    for env, want in VERDICT.items():
        ctl = d["CTL"].get(env)
        check("verdict.%s.control" % env, ctl is not None and ctl["cnt"] == want["ctl"],
              ctl)
        for arm in ("b12_1", "b14_2", "b16_2"):
            row = d["R"].get((env, arm))
            check("verdict.%s.%s" % (env, arm),
                  row is not None and row["cnt"] == want[arm],
                  row["cnt"] if row else "missing")
    # the sentence the whole finding is about: same rule, opposite verdicts
    check("verdict.same_rule_opposite_outcome",
          d["R"][("bp", "b12_1")]["cnt"] == 1 and d["R"][("bv", "b12_1")]["cnt"] == 0
          and d["R"][("bp", "b16_2")]["cnt"] == 0 and d["R"][("bv", "b16_2")]["cnt"] == 1)
    # and the honest limit: in the IP family the tagged frame never arrives
    for env in ("vv",):
        ctl = d["CTL"].get(env)
        check("limit.%s.control_is_zero" % env, ctl is not None and ctl["cnt"] == 0,
              ctl)
    check("limit.v4_all_dead",
          all(r["cnt"] == 0 for r in cells_of("T_rep1", "v4").values()))
    check("limit.reason_is_config", c557.get("CONFIG_VLAN_8021Q") == "n")

# ------------------------------------------------------------ 5. determinism
if "T_rep1" in logs and "T_rep2" in logs:
    a, b = logs["T_rep1"]["R"], logs["T_rep2"]["R"]
    check("det.same_arm_set", set(a) == set(b),
          str(sorted(set(a) ^ set(b))[:6]))
    diff = [(k, a[k]["cnt"], b[k]["cnt"]) for k in a
            if k in b and a[k]["cnt"] != b[k]["cnt"]]
    check("det.same_counters", not diff, str(diff[:6]))
    check("det.same_controls",
          {k: v["cnt"] for k, v in logs["T_rep1"]["CTL"].items()} ==
          {k: v["cnt"] for k, v in logs["T_rep2"]["CTL"].items()})
if "T_rep1" in logs and "T_grid" in logs:
    for env in ("p4", "v4", "pB", "vB"):
        check("det.cross_boot.%s" % env,
              {c: r["cnt"] for c, r in cells_of("T_rep1", env).items()} ==
              {c: r["cnt"] for c, r in cells_of("T_grid", env).items()})
if "T_rep1" in logs and "T_tun" in logs:
    for env in ("ipip", "vxlan"):
        check("det.cross_boot.%s" % env,
              {c: r["cnt"] for c, r in tcells_of("T_rep1", env).items()} ==
              {c: r["cnt"] for c, r in tcells_of("T_tun", env).items()})

# --------------------------------------- 6. regression against F33 (turn 556)
F33 = "%s/f33_T_rep1.log" % LOGS
if os.path.isfile(F33) and "T_rep1" in logs:
    flog = read(F33)
    ref = {}
    for m in RE_R556.finditer(flog):
        if m.group(1) != "ll4":
            continue
        om = re.match(r"g(\d+)_(\d+)$", m.group(2))
        if om:
            ref[(int(om.group(1)), int(om.group(2)))] = int(m.group(7))
    check("regress.f33_ll4_present", len(ref) == len(CELLS), "%d cells" % len(ref))
    mine = {c: r["cnt"] for c, r in cells_of("T_rep1", "p4s").items()}
    check("regress.p4s_equals_f33_ll4", mine == ref,
          str([k for k in mine if mine.get(k) != ref.get(k)][:6]))
    # and the fast helper agrees with the slow one in the same boot
    fast = {c: r["cnt"] for c, r in cells_of("T_rep1", "p4").items()}
    check("regress.p4_fast_equals_p4s_slow", fast == mine,
          str([k for k in fast if fast.get(k) != mine.get(k)][:6]))

# ------------------------------------------------------------------ 7. splat
SPLAT = re.compile(r"KASAN:|BUG:|WARNING:|Oops|general protection|"
                   r"double free|use-after-free")
for tag in FULL:
    if tag in logs:
        n = len(SPLAT.findall(logs[tag]["log"]))
        check("splat.%s.none" % tag, n == 0, "%d lines" % n)

# ------------------------------------------------------------------ report --
print("verify557: %d ok, %d fail" % (len(OK), len(FAIL)))
for name, detail in FAIL:
    print("FAIL %s %s" % (name, detail))
sys.exit(1 if FAIL else 0)
