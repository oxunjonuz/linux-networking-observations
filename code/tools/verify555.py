#!/usr/bin/env python3
"""verify555.py -- independent check of turn 555 / F32 (the native `arp` envelope).

Nothing here trusts the differ's own summary: every cell is recomputed from the
console log of a boot, and every log is tied to a kernel by the sha256 that
run_qemu.sh printed and to the initrd by the sha256 in logs/f32_initrd_hashes.txt.

usage:  python3 tools/verify555.py [--logs DIR] [--src DIR] [--quiet]
"""
import hashlib
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
LOGS = os.path.join(ROOT, "logs")
SRC = os.path.join(ROOT, "src")

CHECKS = []


def ck(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))
    return bool(ok)


def read(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- log parsing

PATTERN = bytes([0xa5, 0x5a, 0x3c, 0xc3, 0x0f, 0xf0, 0x96, 0x69,
                 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])

FIELD_GEOM = {
    "htype": (0, 2, bytes([0x00, 0xab])),
    "ptype": (2, 2, bytes([0x86, 0xdd])),
    "hlen": (4, 1, bytes([0x08])),
    "plen": (5, 1, bytes([0x10])),
    "operation": (6, 2, bytes([0x00, 0x02])),
    "saddr_ether": (8, 6, bytes([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x99])),
    "saddr_ip": (14, 4, bytes([0x0a, 0x01, 0x00, 0x42])),
    "daddr_ether": (18, 6, bytes([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x88])),
    "daddr_ip": (24, 4, bytes([0x0a, 0x09, 0x00, 0x01])),
}
DEAD_FIELDS = ["htype", "ptype", "hlen", "plen"]
ALIVE_FIELDS = ["operation", "saddr_ether", "saddr_ip", "daddr_ether", "daddr_ip"]


class Log:
    def __init__(self, path):
        self.path = path
        self.text = read(path)
        self.lines = self.text.splitlines()
        self.mac = None
        self.setup = None
        self.symbols = {}
        self.bz_sha = None

    def parse(self):
        for ln in self.lines:
            if ln.startswith("F555 SETUP|"):
                self.setup = ln
                m = re.search(r"mac_i0=(([0-9a-f]{2}:){5}[0-9a-f]{2})", ln)
                if m:
                    self.mac = m.group(1)
            elif ln.startswith("### sha256: "):
                self.bz_sha = ln.split()[-1]
            elif re.match(r"^CONFIG_[A-Z0-9_]+=", ln):
                k, v = ln.split("=", 1)
                self.symbols[k] = v
        return self

    def mac_hex(self):
        return self.mac.replace(":", "") if self.mac else "?"

    def rows(self, prefix):
        out = {}
        for ln in self.lines:
            if not ln.startswith(prefix):
                continue
            parts = ln.split("|")
            tag = parts[1] if len(parts) > 1 else ""
            d = {}
            for p in parts[2:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    d[k] = v
            out.setdefault(tag, []).append(d)
        return out

    def arow(self, tag):
        r = self.rows("F555 A|").get(tag)
        return r[0] if r else None

    def norm(self):
        """measurement rows with everything per-boot (the random i0 MAC) removed.

        `chg` is dropped rather than patched: it prints byte pairs such as
        `22:ee>a5`, and the source byte there IS a MAC byte, so no textual
        substitution can normalise it.  Its correctness is checked separately
        from nhex in C3/E3/F3."""
        mac = self.mac_hex()
        out = []
        for ln in self.lines:
            if not ln.startswith(("F555 A|", "F555 F|", "F555 ARP|", "F555 G|")):
                continue
            parts = [p for p in ln.split("|") if not p.startswith("chg=")]
            ln = "|".join(parts).replace(mac, "MAC")
            out.append(ln)
        return out


def pred_in(off, ln):
    return (off == 6 and ln == 2) or (off >= 8 and ln <= 20)


def pred_out(off, ln):
    return pred_in(off, ln) and off + ln <= 28


def apply_store(ctl_hex, off, ln, imm):
    """the control payload with `imm` written at `off`"""
    b = bytearray(bytes.fromhex(ctl_hex))
    if off + ln > len(b):
        return None
    b[off:off + ln] = imm[:ln]
    return b.hex()


# ---------------------------------------------------------------- A: provenance

def check_provenance(a1, a2, m1, b_bare, q_bare):
    img_a = os.path.join(SRC, "linux-7.3.4-A553/arch/x86/boot/bzImage")
    img_m = os.path.join(SRC, "dl72/linux-7.2.15-A553/arch/x86/boot/bzImage")
    sha_a = sha256(img_a)
    sha_m = sha256(img_m)
    for tagname, log, want in (("A_rep1", a1, sha_a), ("A_rep2", a2, sha_a),
                               ("M_rep1", m1, sha_m)):
        ck("A1.%s.bzsha" % tagname, log.bz_sha == want,
           "log=%s disk=%s" % (log.bz_sha, want))
    # the kernel that actually ran: zcat /proc/config.gz in the guest
    # CONFIG_IKCONFIG_PROC is not set in these images, so /proc/config.gz does
    # not exist and the boot cannot print its own config.  The runtime proof of
    # *which* kernel ran is therefore (a) the sha256 run_qemu.sh printed from the
    # file it was given and (b) the answer the kernel gives about the family --
    # which is what B1/B2 measure.  This check only records that the section is
    # absent rather than silently skipping it.
    for tagname, log in (("A_rep1", a1), ("A_rep2", a2), ("M_rep1", m1)):
        ck("A2.%s.no_proc_config" % tagname, "NO_CONFIG_GZ" in log.text,
           "expected NO_CONFIG_GZ marker")

    # config delta is exactly the ARP symbol (+ what it selects), sources identical
    for parent, child, tag in (
            ("linux-7.3.4-B19", "linux-7.3.4-A553", "73"),
            ("dl72/linux-7.2.15", "dl72/linux-7.2.15-A553", "72")):
        def cfg(t):
            p = os.path.join(SRC, t, ".config")
            return [l for l in read(p).splitlines() if l and not l.startswith("#")]

        p = cfg(parent)
        c = cfg(child)
        added = [l for l in c if l not in p]
        removed = [l for l in p if l not in c]
        ck("A3.%s.config_delta" % tag,
           sorted(added) == ["CONFIG_NETFILTER_FAMILY_ARP=y", "CONFIG_NF_TABLES_ARP=y"]
           and not removed, "added=%r removed=%r" % (added, removed))
        for f in ("net/netfilter/nft_payload.c", "net/netfilter/nft_chain_filter.c",
                  "net/netfilter/nf_tables_api.c", "net/ipv4/arp.c"):
            ck("A3.%s.same.%s" % (tag, os.path.basename(f)),
               sha256(os.path.join(SRC, parent, f)) == sha256(os.path.join(SRC, child, f)),
               "")

    # initrd: the differ binary INSIDE the archive (cpio header name is padded to
    # 4 bytes after the 110-byte header -- F25 and F31 both lost a check to this)
    want_diff = sha256(os.path.join(ROOT, "vm/build/differ555"))
    want_nft = sha256(os.path.join(ROOT, "src/dl23/nftables-1.1.7/src/nft.static"))
    hashes = {}
    hp = os.path.join(LOGS, "f32_initrd_hashes.txt")
    if os.path.exists(hp):
        for ln in read(hp).splitlines():
            f = ln.split()
            if len(f) == 2:
                hashes[f[0]] = f[1]
    for tag, log in (("f555", a1), ("f555", a2), ("f555", m1),
                     ("bareB", b_bare), ("bareQ", q_bare)):
        p = os.path.join(ROOT, "vm/initrd555/%s.cpio.gz" % tag)
        ck("A4.%s.exists" % tag, os.path.exists(p), p)
    for tagname, log in (("A_rep1", a1), ("A_rep2", a2), ("M_rep1", m1)):
        m = re.search(r"### initrd sha256: ([0-9a-f]{64})", log.text)
        ck("A4.%s.log_initrd_sha" % tagname, bool(m), "no initrd sha in log")
        if m:
            ck("A4.%s.initrd_sha_known" % tagname, m.group(1) in hashes.values(),
               m.group(1))
    for tag in ("f555", "bareB", "bareQ"):
        p = os.path.join(ROOT, "vm/initrd555/%s.cpio.gz" % tag)
        if not os.path.exists(p):
            continue
        got = members_of(p)
        ck("A4.%s.differ_in_archive" % tag, got.get("root/repro") == want_diff,
           "archive=%s disk=%s" % (got.get("root/repro"), want_diff))
        ck("A4.%s.nft_in_archive" % tag, got.get("nft") == want_nft,
           "archive=%s disk=%s" % (got.get("nft"), want_nft))


def members_of(path):
    """sha256 of each regular file in a .cpio.gz, one at a time"""
    out = {}
    try:
        data = subprocess.run(["gzip", "-dc", path], capture_output=True).stdout
    except Exception:
        return out
    i = 0
    n = len(data)
    while i + 110 <= n:
        hdr = data[i:i + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            break
        try:
            fsize = int(hdr[54:62], 16)
            namesize = int(hdr[94:102], 16)
        except ValueError:
            break
        name = data[i + 110:i + 110 + namesize].split(b"\0")[0].decode("utf-8", "replace")
        if name.startswith("./"):
            name = name[2:]
        off = i + 110 + namesize
        off = (off + 3) & ~3           # name padded to a 4-byte boundary
        body = data[off:off + fsize]
        if name and not name.startswith("TRAILER") and fsize >= 0:
            out[name] = hashlib.sha256(body).hexdigest()
        i = (off + fsize + 3) & ~3
    return out


# ---------------------------------------------------------------- B: family/hooks

def check_family(a1, b_bare, q_bare):
    for tag in ("B_bare", "Q_bare"):
        log = b_bare if tag == "B_bare" else q_bare
        rc = re.search(r"F555 FAM\|arp\|(\d+)", log.text)
        ck("B1.%s.arp_rc" % tag, rc and int(rc.group(1)) != 0,
           "rc=%s" % (rc.group(1) if rc else None))
        rc2 = re.search(r"F555 FAM\|ip\|(\d+)", log.text)
        ck("B1.%s.ip_present" % tag, rc2 and int(rc2.group(1)) == 0,
           "ip family must still be there: rc=%s" % (rc2.group(1) if rc2 else None))
        ck("B1.%s.have" % tag, "F555 HAVE|arp=0" in log.text, "")
    rc = re.search(r"F555 FAM\|arp\|(\d+)", a1.text)
    ck("B2.A.arp_present", rc and int(rc.group(1)) == 0, "rc=%s" % (rc.group(1) if rc else None))
    ck("B2.A.have", "F555 HAVE|arp=1" in a1.text, "")
    want = {"input": True, "output": True, "forward": False, "prerouting": False,
            "postrouting": False, "ingress": False}
    for h, ok in want.items():
        m = re.search(r"F555 HOOK\|%s\|(\d+)" % h, a1.text)
        got = int(m.group(1)) == 0 if m else None
        ck("B3.hook.%s" % h, got is ok, "rc=%s want_ok=%s" % (m.group(1) if m else None, ok))
    # who refused: the kernel's EOPNOTSUPP or nft's own parser
    fwd = " ".join(l for l in a1.lines if re.match(r"F555X b\.forward\|", l))
    pre = " ".join(l for l in a1.lines if re.match(r"F555X b\.prerouting\|", l))
    ck("B4.forward_kernel_refusal",
       "not supported" in fwd and "does not support this hook" not in fwd, fwd[:120])
    ck("B4.prerouting_userspace_refusal",
       "does not support this hook" in pre, pre[:120])


# ---------------------------------------------------------------- C: nft fields

def check_fields(a1):
    arows = a1.rows("F555 A|")
    ctl = arows.get("c.ctl", [None])[0]
    ck("C0.control", ctl is not None and int(ctl["cnt"]) > 0 and ctl["nfl"] == "46",
       "ctl=%r" % ((ctl and (ctl["cnt"], ctl["nfl"])),))
    if not ctl:
        return
    ctl_hex = ctl["nhex"]
    dbg = {}
    for ln in a1.lines:
        m = re.match(r"F555X c\.([a-z2_.]+)\|\s*\[ payload write reg 1 => (\d+)b @ "
                     r"network header \+ (\d+)", ln)
        if m:
            dbg[m.group(1)] = (int(m.group(2)), int(m.group(3)))
    for name, (off, ln, imm) in FIELD_GEOM.items():
        r = arows.get("c." + name, [None])[0]
        ck("C1.%s.declared" % name, dbg.get(name) == (ln, off),
           "nft declared %r, source table says (%d,%d)" % (dbg.get(name), off, ln))
        if not r:
            ck("C2.%s.row" % name, False, "no row")
            continue
        if name in DEAD_FIELDS:
            ck("C2.%s.dead" % name,
               int(r["cnt"]) == 0 and r["nfl"] == "0" and r["chg"] == "-",
               "cnt=%s nfl=%s chg=%s" % (r["cnt"], r["nfl"], r["chg"]))
        else:
            want = apply_store(ctl_hex, off, ln, imm)
            ck("C3.%s.alive" % name, int(r["cnt"]) > 0 and r["nfl"] == "46",
               "cnt=%s nfl=%s" % (r["cnt"], r["nfl"]))
            ck("C3.%s.bytes" % name, r["nhex"] == want,
               "got=%s want=%s" % (r["nhex"], want))
    # the reply carries the rewritten values back out
    r = arows.get("c.saddr_ether", [None])[0]
    ck("C4.saddr_ether_echo", r and r["ihex"].startswith("aabbcc000099"),
       r["ihex"][:24] if r else "")
    r = arows.get("c.saddr_ip", [None])[0]
    ck("C4.saddr_ip_echo", r and r["ihex"].endswith("0a010042"),
       r["ihex"][-24:] if r else "")


# ---------------------------------------------------------------- D: @nh forms

def check_nh(a1):
    arows = a1.rows("F555 A|")
    ctl = arows.get("c.ctl", [None])[0]
    if not ctl:
        return
    spec = {
        "c2.spill2016": (20, 16, bytes.fromhex("00112233445566778899aabbccddeeff"), True),
        "c2.pad288": (28, 8, bytes.fromhex("0102030405060708"), True),
        "c2.op71": (7, 1, bytes([0xab]), False),
    }
    for tag, (off, ln, imm, alive) in spec.items():
        r = arows.get(tag, [None])[0]
        ck("D1.%s.installed" % tag, r is not None and r["rc"] == "0",
           "rc=%s" % (r and r["rc"]))
        if not r:
            continue
        ck("D1.%s.alive" % tag, (int(r["cnt"]) > 0) is alive,
           "cnt=%s want_alive=%s" % (r["cnt"], alive))
        if alive:
            want = apply_store(ctl["nhex"], off, ln, imm)
            ck("D2.%s.bytes" % tag, r["nhex"] == want,
               "got=%s want=%s" % (r["nhex"], want))


# ---------------------------------------------------------------- E/F: the grid

def check_grid_in(a1):
    arows = a1.rows("F555 A|")
    ctl = arows.get("d.ctl", [None])[0]
    ck("E0.control", ctl is not None and int(ctl["cnt"]) > 0, "")
    arms = {t: v[0] for t, v in arows.items() if re.match(r"^d\.\d+\.\d+$", t)}
    ck("E1.count", len(arms) == 96, "arms=%d want 96" % len(arms))
    alive = 0
    bad_pred, bad_bytes, bad_dead, bad_cnt2 = [], [], [], []
    for tag, r in arms.items():
        off, ln = map(int, r["g"].split(","))
        live = int(r["cnt"]) > 0
        if live != pred_in(off, ln):
            bad_pred.append((tag, r["cnt"]))
        if live:
            alive += 1
            if ctl and r["nhex"] != apply_store(ctl["nhex"], off, ln, PATTERN[:ln]):
                bad_bytes.append((tag, r["nhex"][:40]))
            # the kernel's own reply to the rewritten request: its destination is
            # the sender hardware address from the message.  A store that covers
            # offset 8 with an odd low bit makes that address MULTICAST, and the
            # reply then arrives on the peer too -- so the rule counts twice.
            mcast = off <= 8 < off + ln and (PATTERN[8 - off] & 1) == 1
            want_cnt = 2 if mcast else 1
            if int(r["cnt"]) != want_cnt:
                bad_cnt2.append((tag, r["cnt"], want_cnt))
            if mcast and not r["ihex"].startswith("a5"):
                bad_cnt2.append((tag, "reply_dst=%s" % r["ihex"][:2]))
        else:
            if r["nfl"] != "0":
                bad_dead.append((tag, r["nfl"]))
    ck("E2.predicate", not bad_pred, "mismatch=%r" % bad_pred[:4])
    ck("E3.bytes", not bad_bytes, "mismatch=%r" % bad_bytes[:4])
    ck("E4.dead_no_log", not bad_dead, "mismatch=%r" % bad_dead[:4])
    want_alive = sum(1 for r in arms.values()
                     if pred_in(*map(int, r["g"].split(","))))
    ck("E5.alive_count", alive == want_alive,
       "alive=%d predicate says %d" % (alive, want_alive))
    ck("E6.multicast_reply", not bad_cnt2, "mismatch=%r" % bad_cnt2[:4])


def check_grid_out(a1):
    arows = a1.rows("F555 A|")
    ctl = arows.get("e.ctl", [None])[0]
    ck("F0.control", ctl is not None and int(ctl["cnt"]) > 0 and ctl["nfl"] == "42",
       "ctl=%s nfl=%s" % ((ctl or {}).get("cnt"), (ctl or {}).get("nfl")))
    arms = {t: v[0] for t, v in arows.items() if re.match(r"^e\.\d+\.\d+$", t)}
    ck("F1.count", len(arms) == 12, "arms=%d want 12" % len(arms))
    alive = 0
    bad_pred, bad_bytes = [], []
    for tag, r in arms.items():
        off, ln = map(int, r["g"].split(","))
        live = int(r["cnt"]) > 0
        if live != pred_out(off, ln):
            bad_pred.append((tag, r["cnt"]))
        if live:
            alive += 1
            if ctl and r["nhex"] != apply_store(ctl["nhex"], off + 14, ln,
                                                PATTERN[:ln]):
                bad_bytes.append((tag, r["nhex"][:40]))
    ck("F2.predicate", not bad_pred, "mismatch=%r" % bad_pred[:4])
    ck("F3.bytes", not bad_bytes, "mismatch=%r" % bad_bytes[:4])
    want_alive = sum(1 for r in arms.values()
                     if pred_out(*map(int, r["g"].split(","))))
    ck("F4.alive_count", alive == want_alive,
       "alive=%d predicate says %d" % (alive, want_alive))


# ---------------------------------------------------------------- G: consequences

def check_consequences(a1):
    f = a1.rows("F555 F|")
    arp = a1.rows("F555 ARP|")
    exp = {
        # tag: (cnt>0, reply_i, spa flags, moved flags)
        "f.norule": (False, 0, None, None),
        "f.alive": (True, 1, None, 0x2),
        "f.dead": (False, 0, None, None),
        "f.op": (True, 0, None, None),
    }
    spa_of = {"f.norule": "10.1.0.91", "f.alive": "10.1.0.92",
              "f.dead": "10.1.0.93", "f.op": "10.1.0.94"}
    moved_of = {"f.norule": "10.5.5.5", "f.alive": "10.5.5.5",
                "f.dead": "10.5.5.6", "f.op": "10.5.5.7"}

    def flags(tag, ip):
        for ln in a1.lines:
            m = re.match(r"F555 ARP\|%s\|([0-9.]+)\|flags=(\S+)\|mac=(\S+)" % re.escape(tag), ln)
            if m and m.group(1) == ip:
                return None if m.group(2) == "none" else int(m.group(2), 16), m.group(3)
        return "missing", ""

    for tag, (live, rep, spafl, movfl) in exp.items():
        r = f.get(tag, [None])[0]
        ck("G1.%s.row" % tag, r is not None, "")
        if not r:
            continue
        ck("G1.%s.cnt" % tag, (int(r["cnt"]) > 0) is live,
           "cnt=%s want_live=%s" % (r["cnt"], live))
        ck("G1.%s.reply" % tag, int(r["reply_i"]) == rep,
           "reply_i=%s want=%s" % (r["reply_i"], rep))
        got = flags(tag, spa_of[tag])
        ck("G2.%s.spa" % tag, got[0] is spafl, "flags=%r want=%r" % (got[0], spafl))
        got = flags(tag, moved_of[tag])
        ck("G2.%s.moved" % tag, got[0] is movfl, "flags=%r want=%r" % (got[0], movfl))
        if movfl == 0x2:
            ck("G2.%s.moved_mac" % tag, got[1].lower() == "aa:bb:cc:00:00:66", got[1])
    # the sentence the table is for: two causes, one silence
    dead = f.get("f.dead", [{}])[0]
    op = f.get("f.op", [{}])[0]
    ck("G3.two_causes",
       dead.get("reply_i") == "0" and op.get("reply_i") == "0"
       and int(dead.get("cnt", 0)) == 0 and int(op.get("cnt", 1)) > 0, "")


def check_prefilter(a1):
    g = a1.rows("F555 G|")
    exp = {"g.h6p4": (True, True), "g.h8p16": (False, False), "g.h6p8": (False, False)}
    for tag, (live, logs) in exp.items():
        r = g.get(tag, [None])[0]
        ck("H1.%s.row" % tag, r is not None, "")
        if not r:
            continue
        ck("H1.%s.received" % tag, r["rx_i0"] == "1", "rx_i0=%s" % r["rx_i0"])
        ck("H2.%s.counter" % tag, (int(r["cnt"]) > 0) is live, "cnt=%s" % r["cnt"])
        ck("H2.%s.log" % tag, (r["nfl"] != "0") is logs, "nfl=%s" % r["nfl"])


# ---------------------------------------------------------------- I: determinism

def check_determinism(a1, a2, m1):
    ck("I1.rep_equal", a1.norm() == a2.norm(),
       "first diff: %r" % (next((x for x, y in zip(a1.norm(), a2.norm()) if x != y), ""),))
    ck("I2.version_equal", a1.norm() == m1.norm(),
       "first diff: %r" % (next((x for x, y in zip(a1.norm(), m1.norm()) if x != y), ""),))


# ---------------------------------------------------------------- J: hygiene

def check_hygiene(a1, a2, m1):
    for tag, log in (("A_rep1", a1), ("A_rep2", a2), ("M_rep1", m1)):
        ck("J1.%s.done" % tag, "F555 DONE" in log.text, "")
        ck("J1.%s.splat" % tag,
           not re.search(r"KASAN|BUG:|Oops|general protection|WARNING:", log.text),
           "splat lines present")
        ck("J1.%s.exit" % tag,
           re.search(r"=== MODE_EXIT f555=0 ===", log.text) is not None, "")


def main():
    global LOGS
    args = sys.argv[1:]
    quiet = "--quiet" in args
    if "--logs" in args:
        LOGS = args[args.index("--logs") + 1]
    a1 = Log(os.path.join(LOGS, "f32_A_rep1.log")).parse()
    a2 = Log(os.path.join(LOGS, "f32_A_rep2.log")).parse()
    m1 = Log(os.path.join(LOGS, "f32_M_rep1.log")).parse()
    b_bare = Log(os.path.join(LOGS, "f32_B_bare.log")).parse()
    q_bare = Log(os.path.join(LOGS, "f32_Q_bare.log")).parse()

    check_provenance(a1, a2, m1, b_bare, q_bare)
    check_family(a1, b_bare, q_bare)
    check_fields(a1)
    check_nh(a1)
    check_grid_in(a1)
    check_grid_out(a1)
    check_consequences(a1)
    check_prefilter(a1)
    check_determinism(a1, a2, m1)
    check_hygiene(a1, a2, m1)

    bad = [c for c in CHECKS if not c[1]]
    if not quiet:
        for name, ok, detail in CHECKS:
            if not ok:
                print("FAIL %-34s %s" % (name, detail))
    print("verify555: %d/%d ok%s" % (len(CHECKS) - len(bad), len(CHECKS),
                                     "" if not bad else "  FAILED=%d" % len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
