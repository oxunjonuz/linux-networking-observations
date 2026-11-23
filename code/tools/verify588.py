#!/usr/bin/env python3
"""verify588.py -- independent check of turn 588 (F66), both boots.

Nothing here trusts the instrument.  The arm table is read out of
vm/differ588_add.c; the two models under test are recomputed from the kernel
source and from the log's own numbers, and every printed field is compared
against them:

  A. THE BYTE CAP, per GRO shape.
       skb_gro_receive():      merge k refuses when  H + k*P      >= 65536
       skb_gro_receive_list(): merge k refuses when 2H + k*P      >= 65536
     with H = 48 (IPv6 40 + UDP 8) and the tail arm's last merge charged
     H (linear) or 2H (fraglist).  Predicted: 64 x 1022 merges on the
     fraglist door, 64 x 1023 merges on the linear door, and the tail flips
     between 990/991 (fraglist) and 975/976 (linear).

  B. THE RECEIVE BUDGET.  s (per-datagram truesize) and A (the aggregate's
     truesize, charged to its first segment) are DERIVED FROM THE LOG, from
     the two arms that keep 39 and 64 of 64; then every other arm is checked
     against kept = min(N, 1 + floor((rcvbuf - A) / s)), and the three arms
     q49152/q57344/q73728 are checked against numbers the derivation never
     saw (13, 26, 52).

  C. WHAT THE WIRE CARRIED.  Each tap frame: flen = 54 + uh->len, the ip6
     payload length, hop 63, sport/dport, and the checksum FIELD:
       fraglist aggregate -> the first datagram's own PARTIAL seed
       linear aggregate and every device segment -> seed(uh->len)
     Frames on y1 (parent, egress) must be byte-identical to frames on y3
     (receiver): the two independent witnesses of the same store.

  D. THE GSO CEILING.  A merged aggregate leaves the router as ONE frame iff
     14 + 40 + uh->len < 65536 (gso_features_check: skb->len >= gso_max_size
     strips the GSO features and the device segments in software); otherwise
     it leaves as N frames of payload P.  Predicted and checked per arm:
     tu961 (65535 bytes) one frame, tu962 (65536) sixty-four.
"""
import hashlib
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
LOGS = [f"{ROOT}/logs/f66_rep1.log", f"{ROOT}/logs/f66_rep2.log"]
if len(sys.argv) > 1:		# the selftest hands in mutated copies
    LOGS = [sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else sys.argv[1]]
KERNEL = f"{ROOT}/src/linux-7.3.4-T563/arch/x86/boot/bzImage"
SRC = f"{ROOT}/src/linux-7.3.4-T563"
DIFFER = f"{ROOT}/vm/build/differ588"
ADD = f"{ROOT}/vm/differ588_add.c"
INITRD = f"{ROOT}/vm/initrd588/full.cpio.gz"
KERNEL_SHA = "1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033"

H = 48				# IPv6 40 + UDP 8, the header GRO counts
NLMSG_MAX = 65531		# the longest NFLOG payload this kernel emits
GRO_CAP = 65536
GSO_CAP = 65536
SPORT = 43580
DPORT = 5000
SA = bytes([0xfd, 0x02] + [0] * 13 + [0x11])
DA = bytes([0xfd, 0x03] + [0] * 13 + [0x92])
DB = bytes([0xfd, 0x04] + [0] * 13 + [0x92])

ok = 0
bad = []


def chk(cond, what):
    global ok
    if cond:
        ok += 1
    else:
        bad.append(what)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------- checksum arithmetic ------------------------------------------
def fold(s):
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s & 0xFFFF


def csum16(b):
    if len(b) & 1:
        b = b + b"\0"
    return fold(sum((b[i] << 8) | b[i + 1] for i in range(0, len(b), 2)))


def seed(dst, ulen, src=SA):
    """The value udp6_hwcsum_outgoing() writes: fold of the pseudo-header."""
    return fold(csum16(src + dst + ulen.to_bytes(4, "big") +
                       b"\0\0\0" + bytes([17])))


# ---------- provenance ----------------------------------------------------
chk(os.path.exists(KERNEL), "kernel image present")
chk(sha(KERNEL) == KERNEL_SHA, "kernel sha256 == 7.3.4-T563")
dsha = sha(DIFFER)
tmp = "/tmp/f66_initrd"
subprocess.run(["rm", "-rf", tmp], check=True)
os.makedirs(tmp, exist_ok=True)
subprocess.run(["bash", "-c",
                "cd %s && gzip -dc %s | cpio -idm --quiet" %
                (tmp, INITRD)], check=True)
chk(sha(tmp + "/root/repro") == dsha,
    "differ extracted from the initramfs == vm/build/differ588")
chk(sha(INITRD) == sha(f"{ROOT}/vm/initrd588/full.cpio.gz"),
    "initramfs on disk == the one hashed in the log header")


def anchor(rel, needle, what, count=1):
    path = os.path.join(SRC, rel)
    txt = open(path, errors="replace").read()
    chk(txt.count(needle) == count,
        f"anchor {what}: {rel}: {needle!r} count {txt.count(needle)} != {count}")


anchor("net/core/gro.c",
       "if (unlikely(p->len + len >= netif_get_gro_max_size(p->dev, p) ||",
       "skb_gro_receive cap (linear: payload only)")
anchor("net/core/gro.c", "\t\treturn -E2BIG;", "skb_gro_receive -E2BIG", 4)
anchor("net/core/gro.c",
       "if (unlikely(p->len + skb->len >= 65536 ||",
       "skb_gro_receive_list cap (fraglist: whole skb)")
anchor("net/core/gro.c", "\tp->len += len;", "p->len grows by the payload")
anchor("net/core/gro.c", "\tNAPI_GRO_CB(p)->count += segs;",
       "count grows by the arriving segments")
anchor("include/linux/netdevice.h", "#define GRO_LEGACY_MAX_SIZE\t65536u",
       "GRO_LEGACY_MAX_SIZE")
anchor("net/core/dev.c", "\tdev->gso_max_size = GSO_LEGACY_MAX_SIZE;",
       "gso_max_size is the same 65536")
anchor("net/core/dev.c",
       "\tif (unlikely(skb->len >= netif_get_gso_max_size(dev, skb)))",
       "gso_features_check strips GSO at 65536 bytes of skb")
anchor("net/ipv4/udp.c", "\tif (rmem + size > rcvbuf) {", "the budget check")
anchor("net/ipv4/udp.c", "\t\t/* Accept the packet if queue is empty. */\n"
                         "\t\tif (rmem)\n\t\t\tgoto drop;",
       "the accept-when-empty clause")
anchor("net/ipv4/udp.c", "\t\tskb_condense(skb);", "condense above half")
anchor("include/net/udp.h",
       "static inline struct sk_buff *udp_rcv_segment(struct sock *sk,",
       "udp_rcv_segment")
anchor("net/ipv6/udp.c", "\tsegs = udp_rcv_segment(sk, skb, false);",
       "the IPv6 receive side segments an aggregate")
anchor("include/net/udp.h",
       "\t\tdrop_count = skb_shinfo(skb)->gso_segs;",
       "a refused segmentation charges gso_segs")
anchor("net/ipv4/udp.c",
       "\t\tif (rc == -ENOMEM) {\n\t\t\tUDP_INC_STATS(net, UDP_MIB_RCVBUFERRORS);",
       "a full queue is RCVBUFERRORS + INERRORS")

# ---------- the arm table, read out of the instrument ---------------------
ADDSRC = open(ADD, errors="replace").read()
ARMRE = re.compile(
    r'\{\s*"([a-z0-9_]+)",\s*\'(\w)\',\s*\'(\w)\',\s*\'(\w)\',\s*'
    r'(\d+),\s*(\d+),\s*(-?\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*'
    r'(NULL|"[0-9a-f]*"),\s*(\d+),\s*(\d+),\s*(\d+)\s*\}')


def arm_table(name):
    i = ADDSRC.index(f"AF588_{name}[] = {{")
    j = ADDSRC.index("};", i)
    out = []
    for m in ARMRE.finditer(ADDSRC[i:j]):
        (nm, src, dst, xg, n, pl, sh, sl, store, off, ln, hx, exp, rb,
         lazy) = m.groups()
        out.append(dict(name=nm, src=src, dst=dst, xg=xg, n=int(n),
                        pl=int(pl), sh=int(sh), sl=int(sl),
                        store=int(store), off=int(off), len=int(ln),
                        hex="-" if hx == "NULL" else hx[1:-1],
                        exp=int(exp), rcvbuf=int(rb), lazy=int(lazy)))
    return out


SPLIT = arm_table("SPLIT")
CAP = arm_table("CAP")
chk(len(SPLIT) == 20, f"split arm table has 20 arms, found {len(SPLIT)}")
chk(len(CAP) == 22, f"cap arm table has 22 arms, found {len(CAP)}")

# ---------- parsing the log ----------------------------------------------
def kv(line):
    out = {}
    for part in line.split("|")[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def mode_block(text, mode):
    a = text.index(f"=== MODE_BEGIN {mode} ===")
    b = text.index(f"=== MODE_EXIT {mode}=")
    return text[a:b].splitlines()


def collect(lines):
    """arm idx -> every line carrying that index (RCV/RXQ/TAP), plus its row.

    The parent prints its egress tap AFTER the ARM row, so the per-index
    bucket must survive the row rather than reset on it."""
    arms = {}
    rbuf = None
    for ln in lines:
        if ln.startswith("F587 RBUF|"):
            rbuf = int(kv(ln)["eff"])
        elif ln.startswith("F587 RCV|"):
            d = kv(ln)
            arms.setdefault(int(d["i"]), {}).setdefault("rcv", []).append(d)
        elif ln.startswith("F587 RXQ|"):
            d = kv(ln)
            arms.setdefault(int(d["i"]), {}).setdefault("rxq", []).append(d)
        elif ln.startswith("F587 TAP|"):
            d = kv(ln)
            arms.setdefault(int(d["i"]), {}).setdefault("tap", []).append(d)
        elif ln.startswith("F587 TAPX|"):
            d = kv(ln)
            arms.setdefault(int(d["i"]), {}).setdefault("tapx", {})[d["dev"]] = \
                int(d["n"])
        elif ln.startswith("F588 ARM|"):
            d = kv(ln)
            slot = arms.setdefault(int(d["i"]), {})
            slot["arm"] = d
            slot["rbuf"] = rbuf
    return arms


def parse_drops(line):
    """the socket's own drop counter: the last column of /proc/net/udp6"""
    f = line.split()
    return int(f[-1])


def parse_rxq(line):
    """rx_queue, in bytes: the 5th field, 'tx:rx' in hex"""
    f = line.split()
    for x in f:
        if re.fullmatch(r"[0-9A-F]{8}:[0-9A-F]{8}", x):
            return int(x.split(":")[1], 16)
    return -1


# ---------- model A: the byte cap ----------------------------------------
def merges(shape, k, P):
    """does the merge of the k-th datagram of payload P happen?"""
    need = (2 * H + k * P) if shape == "f" else (H + k * P)
    return need < GRO_CAP


def cap_shape(a):
    """(packets, [uh->len, ...]) for a cap arm"""
    N, P, shape = a["n"], a["pl"], a["xg"]
    if a["sh"] < 0:
        if all(merges(shape, k, P) for k in range(2, N + 1)):
            return 1, [8 + N * P]
        k = max(k for k in range(2, N + 1) if merges(shape, k, P))
        return 2, [8 + k * P, 8 + P]
    assert a["sh"] == N - 1, "this verifier only models a tail as the last one"
    assert all(merges(shape, k, P) for k in range(2, N)), a["name"]
    tot = (N - 1) * P + a["sl"]
    need = (2 * H + tot) if shape == "f" else (H + tot)
    if need < GRO_CAP:
        return 1, [8 + tot]
    return 2, [8 + (N - 1) * P, 8 + a["sl"]]


# ---------- model B: the receive budget ----------------------------------
def kept_model(eff, A, s, N):
    if eff < A:
        return 1
    return min(N, 1 + (eff - A) // s)


# ---------- model D: frames on the wire ----------------------------------
def frames_model(a, pkts):
    """how many frames y1 carries for this arm"""
    if len(pkts) > 1:
        # the aggregate (or the first datagram) plus the refused tail
        n = 0
        for u in pkts[:-1]:
            n += 1 if (a["dst"] and 54 + u < GSO_CAP) else \
                 -(-(u - 8) // a["pl"])
        u = pkts[-1]
        n += 1 if 54 + u < GSO_CAP else -(-(u - 8) // a["pl"])
        return n
    u = pkts[0]
    if 54 + u < GSO_CAP:
        return 1
    return -(-(u - 8) // a["pl"])


# ---------- the per-log checks -------------------------------------------
def check_log(path, tag):
    text = open(path, errors="replace").read()
    lines = text.splitlines()
    chk(f"### sha256: {KERNEL_SHA}" in text, f"{tag}: kernel sha in the header")
    chk("Linux version 7.3.4" in text, f"{tag}: the guest kernel version")
    chk("=== MODE_EXIT split=0 ===" in text, f"{tag}: split mode exited 0")
    chk("=== MODE_EXIT cap=0 ===" in text, f"{tag}: cap mode exited 0")
    isha = None
    for ln in lines[:8]:
        if ln.startswith("### initrd sha256:"):
            isha = ln.split(":")[1].strip()
    chk(isha == sha(INITRD), f"{tag}: initrd sha in the header")

    split = collect(mode_block(text, "split"))
    cap = collect(mode_block(text, "cap"))

    # ---- the arm table against the printed row ---------------------------
    for tbl, arms, nm in ((SPLIT, split, "split"), (CAP, cap, "cap")):
        chk(len(arms) == len(tbl),
            f"{tag}/{nm}: {len(tbl)} arms printed, {len(arms)} found")
        for a in tbl:
            i = tbl.index(a)
            row = arms.get(i, {}).get("arm")
            chk(row is not None, f"{tag}/{nm}/{a['name']}: ARM row missing")
            if not row:
                continue
            chk(row["name"] == a["name"], f"{tag}/{nm}/{i}: name")
            for k in ("src", "dst", "xg"):
                chk(row[k] == a[k], f"{tag}/{nm}/{a['name']}: {k}")
            for k in ("n", "pl", "sh", "sl", "store", "off", "len", "exp",
                      "lazy"):
                chk(int(row[k]) == a[k],
                    f"{tag}/{nm}/{a['name']}: printed {k}={row[k]} != source "
                    f"{a[k]}")
            chk(row["hex"] == a["hex"], f"{tag}/{nm}/{a['name']}: hex")
            chk(int(row["rbq"]) == a["rcvbuf"],
                f"{tag}/{nm}/{a['name']}: rcvbuf request")
            chk(int(row["rc"]) == 0, f"{tag}/{nm}/{a['name']}: rule rc")
            chk(int(row["cmdrc"]) == 0, f"{tag}/{nm}/{a['name']}: command rc")

    # ---- A: the byte cap, arm by arm -------------------------------------
    for i, a in enumerate(CAP):
        slot = cap.get(i, {})
        row = slot.get("arm")
        if not row:
            continue
        n_pkt, lens = cap_shape(a)
        chk(int(row["lgn"]) == n_pkt,
            f"{tag}/cap/{a['name']}: {n_pkt} packets predicted, "
            f"log says {row['lgn']}")
        chk(int(row["ch"]) == n_pkt,
            f"{tag}/cap/{a['name']}: counter {row['ch']} != {n_pkt}")
        chk(int(row["lgplen"]) == min(40 + lens[0], NLMSG_MAX),
            f"{tag}/cap/{a['name']}: first message {row['lgplen']} != "
            f"{min(40 + lens[0], NLMSG_MAX)}")
        udp = bytes.fromhex(row["lgudp"])
        chk(len(udp) == 8, f"{tag}/cap/{a['name']}: lgudp is 8 bytes")
        chk(int.from_bytes(udp[4:6], "big") == lens[0],
            f"{tag}/cap/{a['name']}: UDP length field {udp[4:6].hex()} != "
            f"{lens[0]:04x}")
        chk(int.from_bytes(udp[0:2], "big") == SPORT,
            f"{tag}/cap/{a['name']}: sport")
        chk(int.from_bytes(udp[2:4], "big") == DPORT,
            f"{tag}/cap/{a['name']}: dport")
        chk(int.from_bytes(udp[6:8], "big") ==
            seed(DA if a["dst"] == "a" else DB,
                 8 + a["pl"] if a["xg"] == "f" else lens[0]),
            f"{tag}/cap/{a['name']}: checksum field is the fraglist first-"
            f"datagram seed (or seed of the whole length on the linear path)")
        chk(int.from_bytes(bytes.fromhex(row["lg6"]), "big") == lens[0],
            f"{tag}/cap/{a['name']}: ip6 payload length in the message")
        if n_pkt == 2:
            chk(int(row["lg2"]) == min(40 + lens[1], NLMSG_MAX),
                f"{tag}/cap/{a['name']}: second message {row['lg2']} != "
                f"{min(40 + lens[1], NLMSG_MAX)}")
            chk(int.from_bytes(bytes.fromhex(row["lg2_udp"])[4:6], "big") ==
                lens[1], f"{tag}/cap/{a['name']}: second UDP length")
        else:
            chk(int(row["lg2"]) == -1,
                f"{tag}/cap/{a['name']}: no second message expected")

        # ---- D: the frames on the wire ----------------------------------
        want = frames_model(a, lens)
        chk(int(row["an"]) == want,
            f"{tag}/cap/{a['name']}: {want} frames on y1 predicted, log "
            f"says {row['an']}")
        taps = slot.get("tap", [])
        y1 = [t for t in taps if t["dev"] == "y1"]
        chk(len(y1) <= 4, f"{tag}/cap/{a['name']}: at most TAPN frames")
        for t in y1:
            u = int(t["uhlen"])
            chk(int(t["flen"]) == 54 + u,
                f"{tag}/cap/{a['name']}: frame {t['flen']} != 54+{u}")
            chk(int(t["iplen"]) == u,
                f"{tag}/cap/{a['name']}: ip6 payload length {t['iplen']} != "
                f"{u}")
            chk(int(t["hop"]) == 63,
                f"{tag}/cap/{a['name']}: hop {t['hop']} after the router")
            hx = bytes.fromhex(t["hex"])
            chk(int.from_bytes(hx[54:56], "big") == SPORT,
                f"{tag}/cap/{a['name']}: tap sport")
            chk(int.from_bytes(hx[56:58], "big") == DPORT,
                f"{tag}/cap/{a['name']}: tap dport")
            chk(int.from_bytes(hx[18:20], "big") == u,
                f"{tag}/cap/{a['name']}: tap ip6 payload length bytes")
            # the checksum field: flist aggregate keeps the first seed
            agg = (a["xg"] == "f" and u > 8 + a["pl"])
            want_ck = seed(DA if a["dst"] == "a" else DB,
                           8 + a["pl"] if agg else u)
            chk(int.from_bytes(hx[60:62], "big") == want_ck,
                f"{tag}/cap/{a['name']}: tap checksum {hx[60:62].hex()} != "
                f"{want_ck:04x}")
            chk(int(t["stat"]) == 9,
                f"{tag}/cap/{a['name']}: tap tp_status {t['stat']} "
                f"(CHECKSUM_PARTIAL)")

    # ---- the RBUF read-back must equal what the attempt reports ----------
    for nm, arms in (("split", split), ("cap", cap)):
        for i, slot in arms.items():
            row = slot.get("arm")
            rcv = slot.get("rcv", [])
            if not row or not rcv:
                continue
            if slot.get("rbuf") is not None:
                chk(slot["rbuf"] == int(rcv[0]["rb"]),
                    f"{tag}/{nm}/{row['name']}: RBUF read-back "
                    f"{slot['rbuf']} != the attempt's {rcv[0]['rb']}")

    # ---- every tap line, in both modes, is self-consistent ---------------
    for nm in ("split", "cap"):
        for ln in mode_block(text, nm):
            if not ln.startswith("F587 TAP|"):
                continue
            d = kv(ln)
            hx = bytes.fromhex(d["hex"])
            u = int(d["uhlen"])
            chk(int(d["flen"]) == 54 + u,
                f"{tag}/{nm}/tap {d['i']} {d['dev']}: flen")
            chk(int(d["iplen"]) == u,
                f"{tag}/{nm}/tap {d['i']} {d['dev']}: iplen == uhlen")
            chk(int(d["uhck"], 16) == int.from_bytes(hx[60:62], "big"),
                f"{tag}/{nm}/tap {d['i']} {d['dev']}: uhck field == the bytes "
                f"in the frame")
            chk(int.from_bytes(hx[58:60], "big") == u,
                f"{tag}/{nm}/tap {d['i']} {d['dev']}: UDP length field")
            chk(int.from_bytes(hx[56:58], "big") == DPORT,
                f"{tag}/{nm}/tap {d['i']} {d['dev']}: dport")
            chk(int(d["stat"]) == 9,
                f"{tag}/{nm}/tap {d['i']} {d['dev']}: tp_status "
                f"{d['stat']} != CHECKSUM_PARTIAL|USER")
            chk(int(d["hop"]) == 63,
                f"{tag}/{nm}/tap {d['i']} {d['dev']}: hop {d['hop']}")

    # ---- B: the receive budget -------------------------------------------
    def kept_of(i):
        slot = split.get(i, {})
        out = []
        for r in slot.get("rcv", []):
            out.append(int(r["n"]))
        return out

    def rxq_of(i):
        slot = split.get(i, {})
        for r in slot.get("rxq", []):
            return parse_rxq(r["line"])
        return -1

    # the two witness arms: 39 kept at 131072, 64 kept at 262144
    e39 = int(split[7]["rcv"][0]["rb"])
    e64 = int(split[8]["rcv"][0]["rb"])
    chk(e39 == 131072 and e64 == 262144,
        f"{tag}/split: the two witness arms read back 131072 and 262144")
    r39, r64 = rxq_of(7), rxq_of(8)
    chk(kept_of(7) == [39, 39], f"{tag}/split/q65536_lazy keeps 39 twice")
    chk(kept_of(8) == [64, 64], f"{tag}/split/q131072_lazy keeps 64 twice")
    s_seg = (r64 - r39) // (63 - 38)
    A_agg = r39 - 38 * s_seg
    chk((r64 - r39) % (63 - 38) == 0,
        f"{tag}/split: the two queue readings differ by a whole multiple")
    chk(s_seg == 1280, f"{tag}/split: per-datagram truesize {s_seg}")
    chk(A_agg == 81920, f"{tag}/split: aggregate truesize {A_agg}")
    chk(A_agg == 64 * s_seg,
        f"{tag}/split: the aggregate's truesize is 64 datagrams' worth")

    drops_seen = 0
    for i, a in enumerate(SPLIT):
        slot = split.get(i, {})
        row = slot.get("arm")
        if not row:
            continue
        rcv = slot.get("rcv", [])
        chk(len(rcv) == 2, f"{tag}/split/{a['name']}: two attempts")
        if a["n"] == 3:
            continue		# the witness arm: no budget pressure
        eff = int(rcv[0]["rb"])
        chk(all(int(r["rb"]) == eff for r in rcv),
            f"{tag}/split/{a['name']}: one buffer across attempts")
        kept = [int(r["n"]) for r in rcv]
        errs = [int(r["udperr"]) for r in rcv]
        deliv = [int(r["udp"]) for r in rcv]
        for k in range(2):
            chk(deliv[k] + errs[k] == a["n"],
                f"{tag}/split/{a['name']}: delivered + errors "
                f"({deliv[k]}+{errs[k]}) != {a['n']}")
            chk(deliv[k] == kept[k],
                f"{tag}/split/{a['name']}: Udp6InDatagrams {deliv[k]} != "
                f"what the socket read {kept[k]}")
        if a["pl"] == 512:
            want = kept_model(eff, A_agg, s_seg, a["n"])
            if a["lazy"]:
                chk(kept == [want, want],
                    f"{tag}/split/{a['name']}: kept {kept} != model "
                    f"[{want}, {want}] at buffer {eff}")
                chk(errs == [a["n"] - want] * 2,
                    f"{tag}/split/{a['name']}: errors {errs} != "
                    f"{a['n'] - want}")
                rx = [parse_rxq(r["line"]) for r in slot.get("rxq", [])]
                one_shape = (int(row["ch"]) == 1 and int(row["ch0"]) == 1)
                if one_shape:
                    chk(rx == [A_agg + (want - 1) * s_seg] * 2,
                        f"{tag}/split/{a['name']}: queue bytes {rx} != "
                        f"{A_agg + (want - 1) * s_seg}")
                dr = [parse_drops(r["line"]) for r in slot.get("rxq", [])]
                chk(len(dr) == 2, f"{tag}/split/{a['name']}: two queue rows")
                if len(dr) == 2:
                    chk(dr[1] - dr[0] == a["n"] - want,
                        f"{tag}/split/{a['name']}: socket drops "
                        f"{dr[1] - dr[0]} != {a['n'] - want}")
                    chk(dr[0] >= a["n"] - want,
                        f"{tag}/split/{a['name']}: cumulative drops "
                        f"{dr[0]} < this arm's {a['n'] - want}")
            else:
                # an eager reader can only ADD datagrams, and it may differ
                # between attempts: that is the measured difference
                chk(all(k >= want for k in kept),
                    f"{tag}/split/{a['name']}: eager kept {kept} < budget "
                    f"{want}")
                chk(all(k <= a["n"] for k in kept),
                    f"{tag}/split/{a['name']}: kept more than sent")
        else:
            # 54 x 1200 on the same default buffer
            chk(kept == [a["n"], a["n"]],
                f"{tag}/split/{a['name']}: all {a['n']} kept, got {kept}")
            chk(errs == [0, 0], f"{tag}/split/{a['name']}: no errors")
            if "rxq" in slot:
                rx = parse_rxq(slot["rxq"][0]["line"])
                unit = rx // (2 * a["n"] - 1)
                chk(rx == (2 * a["n"] - 1) * unit and unit % 256 == 0,
                    f"{tag}/split/{a['name']}: queue {rx} is a whole number "
                    f"of 256-byte units per datagram")

    # ---- C: two independent witnesses ------------------------------------
    taps_y1 = []
    taps_y3 = []
    txt_split = "\n".join(mode_block(text, "split"))
    for ln in txt_split.splitlines():
        if not ln.startswith("F587 TAP|"):
            continue
        d = kv(ln)
        if d["dev"] == "y1":
            taps_y1.append((d["hex"][:200], int(d["flen"])))
        elif d["dev"].startswith("y3"):
            taps_y3.append((d["hex"][:200], int(d["flen"])))
    chk(len(taps_y1) > 0, f"{tag}: the parent's egress tap saw frames at all")
    chk(set(taps_y1) <= set(taps_y3),
        f"{tag}: every frame y1 put on the wire was seen by the receiver")

    # ---- the store, in three places --------------------------------------
    i = 19
    slot = split[i]
    hx1 = [bytes.fromhex(t["hex"]) for t in slot["tap"] if t["dev"] == "y1"]
    hx3 = [bytes.fromhex(t["hex"]) for t in slot["tap"]
           if t["dev"].startswith("y3")]
    chk(len(hx1) == 1 and len(hx3) == 2,
        f"{tag}: the store arm has one frame on y1 (last attempt) and two "
        f"on y3 (both attempts)")
    if hx1 and hx3:
        chk(hx1[0][:760] == hx3[-1][:760],
            f"{tag}: the frame on y1 is byte-identical to the one on y3")
        chk(hx1[0][62:66] == bytes.fromhex("a0a1a2a3"),
            f"{tag}: the store sits at frame offset 62 (14+40+8)")
        chk(hx1[0][54:58] == bytes.fromhex("aa3c1388"),
            f"{tag}: and the UDP header is in front of it")
        chk(bytes.fromhex(slot["arm"]["lgp0"][0:8]) ==
            bytes.fromhex("a0a1a2a3"),
            f"{tag}: the log's first payload bytes are the store")
    return ok


# ---------- determinism across the two boots -----------------------------
def cross_check(p1, p2):
    t1 = open(p1, errors="replace").read()
    t2 = open(p2, errors="replace").read()
    for mode in ("split", "cap"):
        a1 = collect(mode_block(t1, mode))
        a2 = collect(mode_block(t2, mode))
        for i in sorted(a1):
            r1 = a1[i].get("arm")
            r2 = a2.get(i, {}).get("arm")
            chk(r1 is not None and r2 is not None,
                f"cross/{mode}/{i}: arm row in both boots")
            if not r1 or not r2:
                continue
            for k in ("ch", "lgn", "lgplen", "lg2", "lgudp", "lg2_udp"):
                # q_def_* may change SHAPE between boots (the poll boundary
                # splits the first datagram off); that is measured, not a
                # defect, and those two arms are excluded by name.
                shapek = k in ("ch", "lgn", "lgplen", "lg2",
                               "lg2_udp")
                if shapek and (mode == "split" and int(r1["lazy"]) == 0 or
                               r1["name"].startswith("q_def")):
                    continue
                chk(r1[k] == r2[k],
                    f"cross/{mode}/{r1['name']}: {k} {r1[k]} != {r2[k]}")
            if mode == "split":
                n1 = [int(r["n"]) for r in a1[i].get("rcv", [])]
                n2 = [int(r["n"]) for r in a2.get(i, {}).get("rcv", [])]
                if int(r1["lazy"]):
                    chk(n1 == n2,
                        f"cross/split/{r1['name']}: lazy count {n1} != {n2}")
    return ok


for n, p in enumerate(LOGS):
    check_log(p, f"rep{n + 1}")
if len(LOGS) == 2:
    cross_check(LOGS[0], LOGS[1])

print(f"checks={ok} failures={len(bad)}")
for b in bad[:40]:
    print("FAIL:", b)
sys.exit(1 if bad else 0)
