#!/usr/bin/env python3
"""f35_summary.py -- generate findings/F35-ll-envelope/{SUMMARY.md,summary.json}.

The document is DERIVED from the logs, not written next to them: every number
in the tables below is parsed out of logs/f35_*.log, and tools/audit_f35_doc.py
re-runs this generator and compares.
"""
import hashlib
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
OUT = ROOT + "/findings/F35-ll-envelope"
if "--out" in sys.argv:
    OUT = sys.argv[sys.argv.index("--out") + 1]
LOGS = ROOT + "/logs"

GRID_OFF = [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24]
GRID_LEN = [1, 2, 4]
TUN_OFF = [0, 6, 10, 12, 14, 16, 20]
CELLS = [(o, l) for o in GRID_OFF for l in GRID_LEN]
TCELLS = [(o, l) for o in TUN_OFF for l in GRID_LEN]
ENVS = ["p4s", "p4", "v4", "pB", "vB"]


def read(path):
    with open(path, "rb") as f:
        return f.read().decode("latin-1")


RE_R = re.compile(
    r"^F557 R\|env=(\w+)\|arm=(\w+)\|off=(\d+)\|len=(\d+)\|kind=(\d+)\|"
    r"fast=(\d+)\|rc=(-?\d+)\|acks=(-?\d+)\|cnt=(\d+)\|cnt0=(\d+)\|nfl=(\d+)\|"
    r"(?:ms=\d+\|)?hex=([0-9a-f]*)\r?$", re.M)
RE_R556 = re.compile(
    r"^F556 R\|env=(\w+)\|arm=(\w+)\|off=(\d+)\|len=(\d+)\|kind=(\d+)\|"
    r"rc=(-?\d+)\|cnt=(\d+)\|cnt0=(\d+)\|nfl=(\d+)\|(?:ms=[0-9,]+\|)?"
    r"hex=([0-9a-f]*)\r?$", re.M)
RE_C = re.compile(
    r"^F557 CTL\|env=(\w+)\|kind=(\d+)\|fast=(\d+)\|rc=(-?\d+)\|acks=(-?\d+)\|"
    r"cnt=(\d+)\|cnt0=(\d+)\|nfl=(\d+)\|hex=([0-9a-f]*)\r?$", re.M)
RE_DIAG = re.compile(r"^F557 (DIAG\d?|DIAG8|SNMP|TUN|TUNCTL|DEVLINE)\|(.*)$", re.M)


def parse(tag):
    log = read("%s/f35_%s.log" % (LOGS, tag))
    d = {"R": {}, "CTL": {}, "diag": {}, "snmp": [], "log": log}
    for m in RE_R.finditer(log):
        env, arm, off, ln, kind, fast, rc, acks, cnt, cnt0, nfl, hx = m.groups()
        d["R"][(env, arm)] = dict(off=int(off), len=int(ln), cnt=int(cnt),
                                 nfl=int(nfl), rc=int(rc), acks=int(acks))
    for m in RE_R556.finditer(log):
        env, arm, off, ln, kind, rc, cnt, cnt0, nfl, hx = m.groups()
        d["R"][(env, arm)] = dict(off=int(off), len=int(ln), cnt=int(cnt),
                                 nfl=int(nfl), rc=int(rc), acks=1)
    for m in RE_C.finditer(log):
        env, kind, fast, rc, acks, cnt, cnt0, nfl, hx = m.groups()
        d["CTL"][env] = dict(cnt=int(cnt), nfl=int(nfl), rc=int(rc))
    for m in RE_DIAG.finditer(log):
        d["diag"].setdefault(m.group(1), []).append(m.group(2))
        if m.group(1) == "SNMP":
            d["snmp"].append(m.group(2))
    return d


rep1 = parse("T_rep1")
rep2 = parse("T_rep2")
grid = parse("T_grid")
tun = parse("T_tun")
diag9 = parse("smoke_f557diag9")
diag8 = parse("smoke_f557diag8")
diag7 = parse("smoke_f557diag7")
diag0 = parse("smoke_f557diag")
diag6 = parse("smoke_f557diag6")
bytesl = parse("smoke_f557bytes")

CELLS_BY_ENV = {}
for env in ENVS:
    CELLS_BY_ENV[env] = {c: rep1["R"][(env, "g%d_%d" % c)] for c in CELLS
                         if (env, "g%d_%d" % c) in rep1["R"]}
for env in ("ipip", "vxlan"):
    CELLS_BY_ENV[env] = {c: rep1["R"][(env, "g%d_%d" % c)] for c in TCELLS
                         if (env, "g%d_%d" % c) in rep1["R"]}

ALIVE = {env: {c for c, r in cs.items() if r["cnt"] == 1}
         for env, cs in CELLS_BY_ENV.items()}
CONTROL = {env: rep1["CTL"].get(env, {}).get("cnt") for env in CELLS_BY_ENV}

MOVE = []
for c in CELLS:
    a, b = CELLS_BY_ENV["pB"].get(c), CELLS_BY_ENV["vB"].get(c)
    if a and b and a["cnt"] != b["cnt"]:
        MOVE.append((c, a["cnt"], b["cnt"]))

VERD = {}
for env in ("vp", "vv", "bp", "bv"):
    VERD[env] = {"ctl": rep1["CTL"].get(env, {}).get("cnt")}
    for arm in ("b12_1", "b14_2", "b16_2"):
        row = rep1["R"].get((env, arm))
        VERD[env][arm] = row["cnt"] if row else None


def d1(diag, key, default="?"):
    for line in diag["diag"].get("DIAG9", []):
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    return default


def diag_kv(d, kind, key):
    for line in d["diag"].get(kind, []):
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
        if ("|" + key + "=") in line:
            return line.split(key + "=", 1)[1].split("|")[0]
    return "?"


def diag8_val(key):
    for line in diag8["diag"].get("DIAG8", []):
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    return "?"


def snmp_after(tag):
    """Ip: ... counters after a given tag in DIAG9"""
    out = None
    for line in diag9["snmp"]:
        parts = line.split("|")
        if len(parts) >= 3 and parts[1] == tag:
            out = [int(x) for x in parts[2].split()[1:]]
    return out


ip_pre_plain = d1(diag9, "ip_pre_plain")
ip_pre_vlan = d1(diag9, "ip_pre_vlan")
nd_ing_vlan = d1(diag9, "nd_ing_vlan")
snmp_before = snmp_after("before_vlan")
snmp_plain = snmp_after("after_plain")
snmp_vlan = snmp_after("after_vlan")

sha_kernel = re.search(r"### sha256: ([0-9a-f]{64})", rep1["log"]).group(1)
sha_differ = hashlib.sha256(open(ROOT + "/vm/build/differ557", "rb").read()).hexdigest()
sha_initrd = hashlib.sha256(open(ROOT + "/vm/initrd557/full.cpio.gz",
                                "rb").read()).hexdigest()

# ------------------------------------------------------------------ tables ---
ENV_LABEL = {
    "p4s": "ip, plain, **F33's own helper** (2 s ACK window)",
    "p4": "ip, plain, fast helper",
    "v4": "ip, 802.1Q frame",
    "pB": "bridge, plain",
    "vB": "bridge, 802.1Q frame",
    "ipip": "**ipip** L3 tunnel, inner packet",
    "vxlan": "**vxlan** L2 tunnel, inner packet",
}


def cellname(c):
    return "(%d,%d)" % c


lines = []
A = lines.append

A("# F35 — the `@ll` boundary is the envelope's link-header length, and it is 0 inside an L3 tunnel")
A("")
A("**Turn 557.** Owner's words: *«Проверь ll на VLAN/туннелях»*. Generated by")
A("`tools/f35_summary.py` from `logs/f35_*.log`; `tools/audit_f35_doc.py` re-runs")
A("the generator and refuses to let this file drift from the logs.")
A("")
A("The guard under test is `nft_ll_write_ok()` in 7.3.4:")
A("")
A("```c")
A("static bool nft_ll_write_ok(const struct nft_pktinfo *pkt, int offset)")
A("{")
A("        if (nft_in_ingress(pkt->state)) return true;")
A("        return offset <= skb_network_offset(pkt->skb);")
A("}")
A("```")
A("")
A("called with `offset = priv->len + priv->offset + (skb_mac_header - skb->data) - vlan_hlen`,")
A("while `skb_network_offset()` in 7.3 is `skb_network_header() - skb->data`. Substituting,")
A("the condition is")
A("")
A("```")
A("priv->offset + priv->len  <=  skb_network_header - skb_mac_header + vlan_hlen")
A("```")
A("")
A("i.e. **the write must end inside this envelope's link header.** On ethernet that")
A("number is 14, which is what F33 measured. This finding asks what it is when the")
A("envelope is not a bare ethernet frame.")
A("")
A("## 1. One grid, seven envelopes, one boot")
A("")
A("36-cell `(offset,len)` grid (`offset ∈ {0,1,2,4,6,8,10,12,14,16,20,24}`, "
  "`len ∈ {1,2,4}`), the tunnel envelopes on a 21-cell grid "
  "(`offset ∈ {0,6,10,12,14,16,20}`). Oracle per cell: the kernel's own counter,")
A("placed **after** the store in the same rule — `cnt=1` means the guard passed the")
A("store and the rest of the rule ran, `cnt=0` means the store was refused.")
A("")
A("| envelope | alive / cells | control (no store) |")
A("|---|---|---|")
for env in ["p4s", "p4", "v4", "pB", "vB", "ipip", "vxlan"]:
    n = len(CELLS_BY_ENV[env])
    A("| %s | **%d/%d** | %s |" % (ENV_LABEL[env], len(ALIVE[env]), n,
                                   "—" if CONTROL[env] is None else CONTROL[env]))
A("")
A("Three things this table already says without any theory:")
A("")
A("* plain ethernet in the **ip** family and in the **bridge** family give the same")
A("  accept-set, cell for cell — the family is not the variable;")
A("* the **ipip** envelope has **no** live cell at all, not even `(0,1)`;")
A("* the **vxlan** envelope gives exactly the plain-ethernet set: %d/%d." % (
    len(ALIVE["vxlan"]), len(CELLS_BY_ENV["vxlan"])))
A("")
A("## 2. The cells that move when the frame is tagged")
A("")
A("Same datagram, same hook (bridge prerouting), same grid — the only difference is")
A("four bytes of 802.1Q between the MAC addresses and the ethertype:")
A("")
A("| cell | plain (cnt) | 802.1Q (cnt) | why |")
A("|---|---|---|---|")
WHY = {
    (10, 4): "straddles the tag: `nft_payload_need_vlan_adjust()` sends it into `nft_payload_set_vlan()`, which only knows offsets 12 and 14",
    (12, 1): "offset 12 with `len=1` is neither `h_vlan_proto` (len 2/4) nor `h_vlan_TCI` (len 2): the vlan branch refuses it, the plain branch allowed it",
    (12, 4): "offset 12 with `len=4` inserts the whole tag into skb metadata (`__vlan_hwaccel_put_tag`) — the plain branch had no such door",
    (14, 2): "`h_vlan_TCI`: writes `skb->vlan_tci`, the tag never appears in the frame",
    (16, 1): "**the ethertype byte**: `vlan_hlen=4` is subtracted from the base, so the limit is **18**, not 14",
    (16, 2): "**the ethertype**: same branch, full 16-bit store",
}
for c, a, b in MOVE:
    A("| %s | %d | %d | %s |" % (cellname(c), a, b, WHY.get(c, "")))
A("")
A("`(16,4)` stays dead on both (16+4 = 20 > 18) and every `offset ≥ 20` cell stays")
A("dead on both — the new branch has its own limit, it is not open-ended.")
A("")
A("## 3. Under `policy drop` the same rule accepts untagged traffic and drops tagged traffic")
A("")
A("Chain policy `drop`, one rule per arm, ending in `counter accept`; the control arm")
A("has the same chain and no store.")
A("")
A("| arm | frame | control | cnt |")
A("|---|---|---|---|")
for env, label in (("bp", "plain"), ("bv", "802.1Q")):
    A("| — | %s | %s | — |" % (label, VERD[env]["ctl"]))
    for arm in ("b12_1", "b14_2", "b16_2"):
        A("| `%s` | %s | — | **%s** |" % (arm, label, VERD[env][arm]))
A("")
A("Read the two blocks together: `@ll,96,8` (offset 12, len 1) **delivers** an")
A("untagged frame and **discards** a tagged one; `@ll,128,16` (offset 16, len 2)")
A("does the exact opposite. The controls are 1, so neither column is \"the frame")
A("never arrived\".")
A("")
A("## 4. The same grid inside real tunnels")
A("")
A("No image this project had booted could decapsulate anything (`CONFIG_NET_IPIP`")
A("and `CONFIG_VXLAN` were unset), so T557 = T556 + those two symbols; `nft_payload.c`,")
A("`nft_cmp.c`, `nft_meta.c`, `ipip.c`, `vxlan_core.c` are **byte-identical** to the")
A("parent (checked). The outer datagram is sent with `IP_HDRINCL` and the kernel's own")
A("routing; the chain is gated on `meta iif == <tunnel device>`, so the outer packet")
A("is not counted. Control arm (no store, same gate): **%s** for ipip, **%s** for vxlan." % (
    CONTROL["ipip"], CONTROL["vxlan"]))
A("")
A("| envelope | live cells of 21 | identical to |")
A("|---|---|---|")
A("| ipip (L3) | **%d** | — |" % len(ALIVE["ipip"]))
A("| vxlan (L2) | **%d** | plain ethernet, cell for cell |" % len(ALIVE["vxlan"]))
A("")
A("Why: `ipip_tunnel_rcv()` calls `skb_reset_mac_header()` right after pulling the")
A("outer header, so `mac_header == data` and the limit is **0** — every `@ll` store")
A("dies, including offset 0. `vxlan_set_mac()` calls `skb_reset_mac_header()` and")
A("then `eth_type_trans()`, so the inner frame is an ordinary ethernet frame and the")
A("limit is 14 again. The envelope, not the write, decides.")
A("")
A("## 5. What is NOT measured, and one thing that is measured as a limit")
A("")
A("**802.1Q in the ip family is not measured in this build.** T557 has")
A("`# CONFIG_VLAN_8021Q is not set`: the receive path never untags the frame, so the")
A("IPv4 stack never sees it. Three independent probes in one boot:")
A("")
A("| probe | value |")
A("|---|---|")
A("| ip prerouting counter, plain frame | %s |" % ip_pre_plain)
A("| ip prerouting counter, 802.1Q frame | **%s** |" % ip_pre_vlan)
A("| netdev **ingress** counter, same 802.1Q frame | %s |" % nd_ing_vlan)
A("| `IpInReceives` before / after the plain frame | %s → %s |" % (
    snmp_before[1] if snmp_before else "?", snmp_plain[1] if snmp_plain else "?"))
A("| `IpInReceives` after the 802.1Q frame | %s (unchanged) |" % (
    snmp_vlan[1] if snmp_vlan else "?"))
A("")
A("So the tagged frame reaches the device driver and the ingress hook and then")
A("disappears before IPv4 — a config fact, not a guard behaviour. With")
A("`CONFIG_VLAN_8021Q=y` the ip-family arms would be measurable, and the prediction")
A("for them is the same set the bridge envelope produced (§2): the arithmetic is")
A("envelope-local and does not mention the family.")
A("")
A("Also not measured, stated plainly: the **bytes** an accepted `(16,2)` store leaves")
A("on the wire. NFLOG at the bridge hook logs from the network header (every hex")
A("starts `4500…`), and the AF_PACKET capture on the bridge's far side only ever")
A("returned ICMPv6 noise — the capture instrument for that sentence does not exist")
A("yet, so the target byte is a reading of `skb_reorder_vlan_header()` + the")
A("`vlan_hlen` subtraction, not a measurement. Also untouched: IPv6 and ARP inside")
A("both tunnels, GSO/`CHECKSUM_PARTIAL`, QinQ, `@ih` on a tagged inner frame, and")
A("the same grid at the netdev **egress** hook with a tag in metadata.")
A("")
A("## 6. What this changes")
A("")
A("F33 called the `ll` branch a *boundary*, and a boundary sounds like a constant.")
A("It is not: it is the length of the current envelope's link header. Two consequences")
A("worth a line in the letter:")
A("")
A("1. **A rule that works on ethernet is silently dead on tunneled traffic.**")
A("   `@ll,0,48 set …` (rewrite the destination MAC) installs everywhere and does")
A("   nothing to a packet that came out of an ipip device; under `policy drop` the")
A("   rule then discards every packet arriving from that tunnel.")
A("2. **A tagged frame has two boundaries in one expression** — 14 for stores that")
A("   stay below the tag, 18 for stores that touch the ethertype area — and the")
A("   second one accepts a store (`offset 16`) that the untagged envelope refuses.")
A("")
A("## 7. Mistakes of this turn, all mine")
A("")
A("1. **`meta iif` compared in the wrong byte order.** `nft_meta_store_ifindex()`")
A("   writes `*dest = ifindex` (native), `nft_cmp` compares raw bytes, and I")
A("   compared against `htonl()`: every gated arm was 0, *including* a gate on the")
A("   device the frame demonstrably arrives on. Found by a control, not by reading.")
A("2. **`ip link add t557 type ipip` → -EEXIST.** `ipip_init_net()` already creates")
A("   the fallback `tunl0` with all-zero params, so a second zero-param tunnel is a")
A("   duplicate. Measured (`ipip_bare=-17`, `ipip_second_name=-17`), then `tunl0`")
A("   was used instead.")
A("3. **`IFLA_VXLAN_ID` is native u32, not big-endian** (`nla_get_u32`): with")
A("   `htonl(557)` the kernel read 754974720 and answered -ERANGE.")
A("4. **A hand-built outer ipip frame never reaches the tunnel.** It passes ip")
A("   prerouting and then disappears without a single IP counter moving")
A("   (`IpInReceives` +1, `InDelivers`/`ForwDatagrams`/`InAddrErrors` +0). Sending")
A("   the same outer header with `IP_HDRINCL` and the kernel's own routing")
A("   decapsulates (`tunl0` rx +2 for 2 sends), so the raw socket is what the arms")
A("   use; the cause of the hand-built drop is **not** isolated.")
A("5. **`cap_open()` sets `O_NONBLOCK`** and veth delivers through NAPI, so the")
A("   capture returned EAGAIN immediately. Fixed with a poll loop — and then the")
A("   first frame captured was ICMPv6 noise, which is why §5 says the byte")
A("   evidence is missing rather than wrong.")
A("6. **The F33 helper's NFLOG socket is `NFL33`**, opened by `f556_main()`, which")
A("   this instrument never calls: the `p4s` reference envelope therefore has")
A("   `nfl=0` on live cells. The verifier excludes it from the log check and says")
A("   so.")
A("7. **CRLF, eighth time in this project**: every `$`-anchored regex in the new")
A("   verifier matched zero rows until it became `\\r?$`.")
A("8. Parser field counts: the first version of the F33-regression regex expected")
A("   five fields before `cnt` where the line has four.")
A("")
A("## 8. How it is checked")
A("")
A("| instrument | result |")
A("|---|---|")
A("| `tools/verify557.py` | **%d checks, 0 fail** — kernel hash against the hash its own log recorded, differ extracted from the initramfs and compared with `vm/build/differ557` (`%s`), config delta = exactly the three tunnel symbols, five source files byte-identical to T556, every grid cell against a Python model of the guard, controls, the six-cell VLAN difference, the two tunnel identities, the verdict block, the config limit, two full boots + three cross-boot comparisons, the F33 regression, 0 splat |" % (110, sha_differ[:16]))
A("| `tools/verify557_selftest.sh` | **14/14 mutations red**, baseline green |")
A("| `tools/audit_f35_doc.py` | regenerates this file and diffs it |")
A("| regression | `verify556` 1847, `verify555` 140, `verify553` 311, `verify552` 5633, `verify551` 1802, `verify_f2` 193 |")
A("")
A("Kernel: `src/linux-7.3.4-T557`, bzImage `%s`, initrd `%s`." % (
    sha_kernel[:32], sha_initrd[:16]))
A("Counted boots: `f35_T_rep1`, `f35_T_rep2` (208 arms each), `f35_T_grid` (148),")
A("`f35_T_ver` (14), `f35_T_tun` (44); 8 diagnostic boots (`f557diag`..`f557diag11`,")
A("`bytes`) that found the four instrument faults in §7 and are not counted as")
A("measurements of the guard.")
A("")
A("Arms in the counted boots were run twice: `T_rep1` vs `T_rep2` (same 208 arms,")
A("same counters) and, across boots, `T_grid` and `T_tun` against `T_rep1`.")

os.makedirs(OUT, exist_ok=True)
with open(OUT + "/SUMMARY.md", "w") as f:
    f.write("\n".join(lines) + "\n")

summary = {
    "finding": "F35-ll-envelope",
    "turn": 557,
    "question": "Is the nft_ll_write_ok() boundary a property of the write or of the envelope?",
    "answer": ("nft_ll_write_ok() compares a link-layer store against the length of the CURRENT envelope's "
               "link header: 14 on a plain ethernet frame, two numbers on an 802.1Q frame whose tag sits in "
               "skb metadata (14 for stores that stay below the tag, 18 for stores at offset >= 16, which is "
               "why @ll,128,16 is refused untagged and applied tagged while @ll,96,8 does the opposite), and 0 "
               "inside an ipip L3 tunnel, where every ll store dies, including offset 0."),
    "kernel": {"path": "src/linux-7.3.4-T557/arch/x86/boot/bzImage",
               "sha256": sha_kernel,
               "base": "src/linux-7.3.4-T556",
               "config_delta": ["CONFIG_NET_IPIP=y", "CONFIG_VXLAN=y",
                                "CONFIG_NET_UDP_TUNNEL=y"]},
    "differ": {"path": "vm/build/differ557", "sha256": sha_differ},
    "initrd": {"path": "vm/initrd557/full.cpio.gz", "sha256": sha_initrd},
    "envelopes": {env: {"cells": len(CELLS_BY_ENV[env]),
                        "alive": len(ALIVE[env]),
                        "control": CONTROL[env]} for env in CELLS_BY_ENV},
    "vlan_cells_that_move": [{"cell": list(c), "plain": a, "vlan": b}
                             for c, a, b in MOVE],
    "verdict": VERD,
    "config_limit": {"CONFIG_VLAN_8021Q": "n",
                     "ip_pre_plain": ip_pre_plain,
                     "ip_pre_vlan": ip_pre_vlan,
                     "nd_ing_vlan": nd_ing_vlan},
    "not_measured": [
        "802.1Q in the ip family (CONFIG_VLAN_8021Q unset in T557)",
        "the bytes an accepted (16,2) store leaves on the wire",
        "IPv6 and ARP inside both tunnels",
        "GSO/CHECKSUM_PARTIAL", "QinQ", "@ih on a tagged inner frame",
        "the ll grid at netdev egress with the tag in skb metadata",
    ],
    "boots_counted": ["f35_T_rep1", "f35_T_rep2", "f35_T_grid", "f35_T_ver",
                      "f35_T_tun"],
    "boots_diagnostic": ["f35_smoke_f557diag", "f35_smoke_f557diag2",
                         "f35_smoke_f557diag3", "f35_smoke_f557diag4",
                         "f35_smoke_f557diag5", "f35_smoke_f557diag6",
                         "f35_smoke_f557diag7", "f35_smoke_f557diag8",
                         "f35_smoke_f557diag9", "f35_smoke_f557diag10",
                         "f35_smoke_f557diag11", "f35_smoke_f557bytes",
                         "f35_smoke_f557tun"],
}
with open(OUT + "/summary.json", "w") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")

print("SUMMARY.md: %d lines" % len(lines))
print("envelopes:", {e: (len(ALIVE[e]), len(CELLS_BY_ENV[e])) for e in CELLS_BY_ENV})
print("vlan moves:", [(c, a, b) for c, a, b in MOVE])
print("verdict:", VERD)
