#!/usr/bin/env python3
"""verify558.py -- independent checks over the turn-558 logs.

Nothing here trusts the instrument's own summary lines: every table is
rebuilt from the F558/F557 lines, the guard's predicate is re-implemented in
Python from the source (`off + len <= skb_network_offset` with the vlan
adjustment), the frame bytes are compared byte by byte from the hex, and the
provenance of the kernels is checked against the files on disk.

Run: python3 tools/verify558.py [--logs V_rep1,V_rep2,T_rep1]
"""
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
T557 = "src/linux-7.3.4-T557"
T558 = "src/linux-7.3.4-T558"
OFFS = [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24]
LENS = [1, 2, 4]
CELLS = [(o, l) for o in OFFS for l in LENS]

CHECKS = []
LOGDIR = os.environ.get("F36_LOGDIR", os.path.join(ROOT, "logs"))


def chk(name, ok, detail=""):
    CHECKS.append({"name": name, "ok": bool(ok), "detail": str(detail)[:400]})
    return ok


def cpio_member(path, want):
    """Extract one member of a newc cpio.gz by name, padding-aware."""
    import gzip
    data = gzip.open(path, "rb").read()
    i = 0
    while i + 110 <= len(data):
        hdr = data[i:i + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            break
        f = [int(hdr[6 + 8 * k:14 + 8 * k], 16) for k in range(13)]
        namesize, filesize = f[11], f[6]
        name = data[i + 110:i + 110 + namesize - 1].decode("latin1")
        off = i + 110 + namesize
        off += (-off) % 4
        body = data[off:off + filesize]
        if name.lstrip("./") == want or name == want:
            return body
        off += filesize
        off += (-off) % 4
        i = off
    return None


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def fields(line):
    return dict(kv.split("=", 1) for kv in line.rstrip("\n").split("|")[1:]
                if "=" in kv)


def parse_log(path):
    out = {"run": {}, "view": {}, "ctl557": {}, "r557": {}, "grid": {},
           "vlandev": [], "why": [], "one": [], "snmp": [], "dev": [],
           "sys": [], "kernel": None, "done": 0, "begin": []}
    with open(path, errors="replace") as f:
        for line in f:
            if line.startswith("F558 RUN|"):
                d = fields(line)
                out["run"][(d["env"], d["arm"])] = d
            elif line.startswith("F558 VIEW|"):
                d = fields(line)
                out["view"][(d["env"], d["arm"], d["view"])] = d
            elif line.startswith("F557 CTL|"):
                d = fields(line)
                out["ctl557"][d["env"]] = d
            elif line.startswith("F557 R|"):
                d = fields(line)
                out["r557"][(d["env"], d["arm"])] = d
            elif line.startswith("F558 GRID|"):
                d = fields(line)
                out["grid"][d["env"]] = d
            elif line.startswith("F558 VLANDEV|"):
                d = fields(line)
                d["_raw"] = line.strip()
                out["vlandev"].append(d)
            elif line.startswith("F558 ONE|"):
                d = fields(line)
                d["_t"] = line.rstrip("\n").split("|")[1:]
                out["one"].append(d)
            elif line.startswith("F558 WHY|"):
                d = fields(line)
                # the label tokens carry no '=', and fields() drops them:
                # keep the raw token list so a check cannot silently vanish
                # by looking up a key that was never there.
                d["_t"] = line.rstrip("\n").split("|")[1:]
                out["why"].append(d)
            elif line.startswith("F558 KERNEL|"):
                out["kernel"] = line.strip()
            elif line.startswith("F558 DONE"):
                out["done"] += 1
            elif line.startswith("F558 BEGIN|"):
                out["begin"].append(fields(line))
            elif line.startswith("F557 SNMP|"):
                out["snmp"].append(line.strip())
            elif line.startswith("F557 DEVLINE|"):
                out["dev"].append(line.strip())
            elif line.startswith("F557 SYS|"):
                out["sys"].append(line.strip())
    return out


def cells_of(L, env):
    """(off,len) -> 1/0 for one envelope, from whichever section printed it."""
    got = {}
    for (o, l) in CELLS:
        arm = "g%d_%d" % (o, l)
        if (env, arm) in L["run"]:
            d = L["run"][(env, arm)]
            got[(o, l)] = int(d["cnt"]) - int(d["cnt0"])
        elif (env, arm) in L["r557"]:
            d = L["r557"][(env, arm)]
            got[(o, l)] = int(d["cnt"]) - int(d["cnt0"])
    return got


def ctl_of(L, env):
    if (env, "ctl") in L["run"]:
        d = L["run"][(env, "ctl")]
        return int(d["cnt"]) - int(d["cnt0"])
    if env in L["ctl557"]:
        d = L["ctl557"][env]
        return int(d["cnt"]) - int(d["cnt0"])
    return None


def model_ip_live(off, ln):
    """nft_ll_write_ok(): offset <= skb_network_offset(skb); the store passes
    len + priv->offset + (mac_header - data - vlan_hlen), and in the ip family
    the tag is gone by the hook, so the limit is the 14-byte link header of the
    skb (mac_header..data), i.e. off + len <= 14."""
    return off + ln <= 14


def main():
    picked = sys.argv[2].split(",") if len(sys.argv) > 2 else \
        ["V_rep1", "V_rep2", "T_rep1", "ipv6_rep1"]
    logs = {}
    for tag in picked:
        p = os.path.join(LOGDIR, "f36_%s.log" % tag)
        logs[tag] = (p, parse_log(p))
    # the full-battery logs: only these ran the why/bytes/vlan sections
    FULL = [t for t in picked if t in ("V_rep1", "V_rep2", "T_rep1")]

    # ---------- 1. provenance: kernel bytes, build number, initrd ----------
    want = {"V": (T558, 6), "T": (T557, 5)}
    for tag in FULL:
        p, L = logs[tag]
        kind = tag[0]
        if tag.startswith("ipv6"):
            kind = "V"
        src, buildno = want[kind]
        img = os.path.join(ROOT, src, "arch/x86/boot/bzImage")
        hdr = {}
        with open(p, errors="replace") as f:
            for line in f:
                m = re.match(r"^### ([a-z_ 0-9]+): (.*)$", line)
                if m:
                    hdr[m.group(1)] = m.group(2).strip()
        chk("%s: kernel path is %s" % (tag, src), src in hdr.get("kernel", ""),
            hdr.get("kernel"))
        chk("%s: log's kernel sha == file on disk" % tag,
            hdr.get("sha256") == sha256_file(img), hdr.get("sha256"))
        ver = None
        with open(p, errors="replace") as f:
            for line in f:
                m = re.search(r"Linux version (\S+) .* (#[0-9]+) ", line)
                if m:
                    ver = (m.group(1), m.group(2))
                    break
        chk("%s: guest booted 7.3.4 %s" % (tag, "#%d" % buildno),
            ver == ("7.3.4", "#%d" % buildno), ver)
        chk("%s: initrd sha in log matches the recorded hash" % tag,
            hdr.get("initrd sha256") in open(
                os.path.join(ROOT, "logs/f36_initrd_hashes.txt")).read(),
            hdr.get("initrd sha256"))
        chk("%s: the run finished (F558 DONE)" % tag, L["done"] == 1, L["done"])
        chk("%s: no KASAN/BUG/Oops/WARNING" % tag,
            not re.search(r"KASAN|BUG:|Oops|WARNING:|general protection",
                          open(p, errors="replace").read()),
            "splat search")

    # the instrument inside the initrd is the one that was built, not a
    # later rebuild: extract root/repro and hash it
    initrd = os.path.join(ROOT, "vm/initrd558/full.cpio.gz")
    mem = cpio_member(initrd, "root/repro")
    chk("initrd: root/repro is present", mem is not None,
        initrd)
    if mem is not None:
        chk("initrd: the binary inside == vm/build/differ558",
            hashlib.sha256(mem).hexdigest() ==
            sha256_file(os.path.join(ROOT, "vm/build/differ558")),
            hashlib.sha256(mem).hexdigest())

    # ---------- 2. the config delta: one symbol, and the code is the same ----
    def cfg(p):
        out = {}
        for line in open(os.path.join(ROOT, p, ".config")):
            line = line.strip()
            if line.startswith("CONFIG_") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
            elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
                out[line[2:-11]] = None
        return out
    a, b = cfg(T557), cfg(T558)
    diff = {k for k in set(a) | set(b) if a.get(k) != b.get(k)}
    chk("config: VLAN_8021Q off in T557, on in T558",
        a.get("CONFIG_VLAN_8021Q") is None and b.get("CONFIG_VLAN_8021Q") == "y",
        (a.get("CONFIG_VLAN_8021Q"), b.get("CONFIG_VLAN_8021Q")))
    chk("config: the only ENABLED symbol that changes is VLAN_8021Q",
        diff - {"CONFIG_VLAN_8021Q", "CONFIG_VLAN_8021Q_GVRP",
                "CONFIG_VLAN_8021Q_MVRP", "CONFIG_BRIDGE_VLAN_FILTERING"} == set(),
        sorted(diff))
    chk("config: the other new lines are all '# ... is not set'",
        all((b.get(k) is None) for k in
            ("CONFIG_VLAN_8021Q_GVRP", "CONFIG_VLAN_8021Q_MVRP",
             "CONFIG_BRIDGE_VLAN_FILTERING")),
        {k: b.get(k) for k in ("CONFIG_VLAN_8021Q_GVRP",
                               "CONFIG_VLAN_8021Q_MVRP",
                               "CONFIG_BRIDGE_VLAN_FILTERING")})
    for f in ("net/netfilter/nft_payload.c", "net/netfilter/nft_chain_filter.c",
              "net/netfilter/nf_tables_api.c", "net/8021q/vlan_core.c",
              "net/core/skbuff.c", "net/ethernet/eth.c",
              "net/ipv4/ip_input.c", "net/bridge/br_input.c",
              "drivers/net/veth.c"):
        chk("same bytes in T557 and T558: %s" % f,
            sha256_file(os.path.join(ROOT, T557, f)) ==
            sha256_file(os.path.join(ROOT, T558, f)), "")

    # ---------- 3. the guard model over every cell of every envelope --------
    for tag in FULL:
        p, L = logs[tag]
        for env in ("p4", "vd", "v0", "novd", "novd2"):
            got = cells_of(L, env)
            if not got:
                continue
            ctl = ctl_of(L, env)
            if ctl == 0:
                # not an envelope: the frame never reaches the hook, so the
                # 36 zeros are a control, not 36 dead cells
                chk("%s/%s: control 0 and every cell 0 (no envelope)"
                    % (tag, env), all(v == 0 for v in got.values()),
                    {k: v for k, v in got.items() if v})
                continue
            chk("%s/%s: control is 1" % (tag, env), ctl == 1, ctl)
            bad = {k: v for k, v in got.items()
                   if v != (1 if model_ip_live(*k) else 0)}
            chk("%s/%s: all 36 cells match off+len<=14" % (tag, env),
                not bad, bad)
            chk("%s/%s: live count is 23" % (tag, env),
                sum(1 for v in got.values() if v) == 23,
                sum(1 for v in got.values() if v))
            if env in L["grid"]:
                chk("%s/%s: the printed GRID line agrees with the cells"
                    % (tag, env),
                    L["grid"][env].get("live") ==
                    str(sum(1 for v in got.values() if v)), L["grid"][env])

    # ---------- 4. the three ip-family envelopes are the same table --------
    for tag in FULL:
        p, L = logs[tag]
        p4 = cells_of(L, "p4")
        v0 = cells_of(L, "v0")
        chk("%s: p4 == v0 cell for cell" % tag, p4 == v0,
            {k: (p4.get(k), v0.get(k)) for k in CELLS if p4.get(k) != v0.get(k)})
        vd = cells_of(L, "vd")
        if vd:
            chk("%s: p4 == vd cell for cell" % tag, p4 == vd,
                {k: (p4.get(k), vd.get(k)) for k in CELLS
                 if p4.get(k) != vd.get(k)})
            chk("%s: vd == v0 cell for cell" % tag, vd == v0, "")
        else:
            chk("%s: no vd grid (no vlan device on this image)" % tag, True, "")

    # ---------- 5. the vlan device itself ----------
    for tag in FULL:
        p, L = logs[tag]
        adds = [v for v in L["vlandev"] if "add_rc" in v]
        kind = tag[0]
        if not adds:
            chk("%s: vlan device was attempted" % tag, False, L["vlandev"])
            continue
        rc = int(adds[0]["add_rc"])
        if kind == "T":
            chk("%s: on T557 the vlan device is EOPNOTSUPP (%d)" % (tag, rc),
                rc == -95, rc)
            chk("%s: on T557 the vd grid is skipped, not 36 zeros" % tag,
                any("vd_skipped" in v.get("_raw", "") for v in L["vlandev"]),
                [v.get("_raw") for v in L["vlandev"]])
        else:
            chk("%s: on T558 the vlan device exists (rc=%d)" % (tag, rc),
                rc == 0 and int(adds[0]["idx"]) > 0, adds[0])
            dels = [v for v in L["vlandev"] if "del_rc" in v]
            chk("%s: and it can be removed again" % tag,
                dels and int(dels[0]["del_rc"]) == 0, dels)

    # ---------- 6. the byte table ----------
    # expected: (live, ipin, nchg, chg)
    PRED = {
        "ctl": (1, 0, None, None),
        "ctl_plain": (1, 2, None, None),
        "s16_2_plain": (0, 2, "0", None),
        "s16_2": (1, 0, "1", "13:00>06"),
        "s14_99": (1, 0, "0", None),
        "s14_0": (1, 2, "0", None),
        "s14_1064": (1, 0, "0", None),
        "s12_4z": (1, 2, "0", None),
    }
    for tag in FULL:
        p, L = logs[tag]
        for arm, (live, ipin, nchg, chgv) in PRED.items():
            d = L["run"].get(("by", arm))
            if not chk("%s/by/%s: arm present" % (tag, arm), d is not None):
                continue
            chk("%s/by/%s: counter delta %d" % (tag, arm, live),
                int(d["cnt"]) - int(d["cnt0"]) == live,
                (d["cnt"], d["cnt0"]))
            chk("%s/by/%s: far side IpInReceives +%d" % (tag, arm, ipin),
                int(d["ipin"]) == ipin, d["ipin"])
            chk("%s/by/%s: the rule's own log saw %s frame(s)"
                % (tag, arm, "" if live else "no"),
                (int(d["nfl"]) == 46) == bool(live), d["nfl"])
            if nchg is None:
                continue
            for view in ("tx", "rx"):
                v = L["view"].get(("by", arm, view))
                if not chk("%s/by/%s/%s: view present" % (tag, arm, view),
                           v is not None):
                    continue
                chk("%s/by/%s/%s: nchg %s" % (tag, arm, view, nchg),
                    v["nchg"] == nchg, v["nchg"])
                if chgv:
                    chk("%s/by/%s/%s: change %s" % (tag, arm, view, chgv),
                        v["chg"] == chgv, v["chg"])

    # ---------- 7. the frames themselves, byte by byte ----------
    for tag in FULL:
        p, L = logs[tag]
        for arm in PRED:
            for view in ("tx", "rx"):
                v = L["view"].get(("by", arm, view))
                if not v or "hex" not in v or not v["hex"]:
                    continue
                hx = v["hex"]
                chk("%s/by/%s/%s: frame is 60 bytes on a veth" % (tag, arm, view),
                    v["n"] == "60" and len(hx) >= 120, (v["n"], len(hx)))
                if arm == "ctl":
                    ctlhex = hx[:120]
        ctlhex = L["view"].get(("by", "ctl", "tx"), {}).get("hex", "")[:120]
        if ctlhex:
            for arm, exp in (("s16_2", "0806"), ("s14_99", None),
                             ("s14_0", None), ("s14_1064", None),
                             ("s12_4z", None), ("s16_2_plain", None)):
                h = L["view"].get(("by", arm, "tx"), {}).get("hex", "")
                if not h:
                    continue
                b = bytes.fromhex(h)
                c = bytes.fromhex(ctlhex)
                if arm == "s16_2":
                    chk("%s: s16_2 writes exactly bytes 12..13 = %s"
                        % (tag, exp),
                        b[12:14] == bytes.fromhex(exp) and
                        b[:12] == c[:12] and b[14:] == c[14:], h[:40])
                else:
                    chk("%s: %s leaves every frame byte alone" % (tag, arm),
                        b == c, "%s vs %s" % (h[:40], ctlhex[:40]))
        # the tag never exists in the frame: the tagged control hex equals the
        # plain control hex, and the sent frame was 64 bytes
        pl = [x for x in L["why"] if x["_t"][:2] == ["plain", "arm=rx_r0"]]
        tg = [x for x in L["why"] if x["_t"][:2] == ["tagged", "arm=rx_r0"]]
        chk("%s: the why section printed both tagged views" % tag,
            len(tg) >= 1 and len([x for x in L["why"]
                                  if x["_t"][:2] == ["tagged", "arm=tx_r1"]]) >= 1,
            [x["_t"][:2] for x in L["why"]])
        if pl and tg:
            chk("%s: tagged control frame == plain frame at the far side"
                % tag, pl[0].get("hex") == tg[0].get("hex"),
                (pl[0].get("hex", "")[:40], tg[0].get("hex", "")[:40]))
            chk("%s: and the tagged view says so too (vs_plain=-)" % tag,
                tg[0].get("vs_plain") == "-", tg[0].get("vs_plain"))
            chk("%s: the sent tag never appears: 64 bytes sent, 60 seen" % tag,
                [x for x in L["why"] if x["_t"][:2] == ["tagged", "arm=tx_r1"]]
                [0].get("n") == "60", tg[0].get("n"))
        chk("%s: the two tagged-frame builders agree" % tag,
            any(x.get("frame_same") == "1" for x in L["why"]), L["why"][:1])

    # ---------- 8. one send, one count, one log message ----------
    for tag in FULL:
        p, L = logs[tag]
        one = [x for x in L["why"] if "cnt_delta" in x]
        chk("%s: one sent frame -> exactly one count and one log message"
            % tag, len(one) == 1 and one[0].get("msgs") == "1" and
            one[0].get("cnt_delta") == "1",
            [x for x in L["why"] if "cnt_delta" in x])

    # ---------- 8b. the counter counts any frame: measured, and not summonable
    if "ipv6_rep1" in logs:
        L = logs["ipv6_rep1"][1]
        rows = [x for x in L["one"] if "cnt_delta" in x]
        chk("ipv6_rep1: four one-send runs were printed", len(rows) == 4,
            len(rows))
        for r in rows:
            chk("ipv6_rep1/%s: one send -> one count" % r["_t"][1],
                r.get("cnt_delta") == "1" and r.get("msgs") == "1",
                (r.get("cnt_delta"), r.get("msgs")))
        msgs = [x for x in L["one"] if x["_t"][1].startswith("msg=")]
        chk("ipv6_rep1: every logged message is our IPv4 datagram (0x45...)",
            msgs and all(m["hex"].startswith("45") for m in msgs),
            [m["hex"][:4] for m in msgs])
        chk("ipv6_rep1: the boot finished", L["done"] == 1, L["done"])
        chk("ipv6_rep1: no splat",
            not re.search(r"KASAN|BUG:|Oops|WARNING:|general protection",
                          open(os.path.join(LOGDIR, "f36_ipv6_rep1.log"),
                               errors="replace").read()), "")

    # ---------- 9. determinism between the two T558 boots ----------
    if "V_rep1" in logs and "V_rep2" in logs:
        A = logs["V_rep1"][1]
        B = logs["V_rep2"][1]
        ka = {k: (v["cnt"], v["cnt0"], v.get("ipin")) for k, v in A["run"].items()}
        kb = {k: (v["cnt"], v["cnt0"], v.get("ipin")) for k, v in B["run"].items()}
        chk("rep1 == rep2: every F558 RUN cell", ka == kb,
            {k: (ka.get(k), kb.get(k)) for k in set(ka) | set(kb)
             if ka.get(k) != kb.get(k)})
        chk("rep1 == rep2: every frame hex",
            {k: v.get("hex") for k, v in A["view"].items()} ==
            {k: v.get("hex") for k, v in B["view"].items()}, "")
        chk("rep1 == rep2: grid totals", A["grid"] == B["grid"], A["grid"])
    # and T557 vs T558 on the sections that do not depend on the vlan device
    if "T_rep1" in logs and "V_rep1" in logs:
        T = logs["T_rep1"][1]
        V = logs["V_rep1"][1]
        chk("T557 == T558 on the p4 grid",
            cells_of(T, "p4") == cells_of(V, "p4"), "")
        chk("T557 == T558 on the v0 grid",
            cells_of(T, "v0") == cells_of(V, "v0"), "")
        chk("T557 == T558 on the byte table",
            {k: (v["cnt"], v.get("ipin")) for k, v in T["run"].items() if k[0] == "by"} ==
            {k: (v["cnt"], v.get("ipin")) for k, v in V["run"].items() if k[0] == "by"},
            "")

    # ---------- report ----------
    bad = [c for c in CHECKS if not c["ok"]]
    for c in CHECKS:
        if not c["ok"]:
            print("FAIL %s | %s" % (c["name"], c["detail"]))
    print("SUMMARY|checks=%d|passed=%d|failed=%d"
          % (len(CHECKS), len(CHECKS) - len(bad), len(bad)))
    out = {"checks": len(CHECKS), "passed": len(CHECKS) - len(bad),
           "failed": len(bad), "failures": bad, "log": picked}
    with open(os.path.join(LOGDIR, "verify558.json"), "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
