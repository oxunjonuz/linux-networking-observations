#!/usr/bin/env python3
"""verify589.py -- independent check of turn 589 (F67), both boots.

Nothing here trusts the instrument.  The arm table is read out of
vm/differ589_add.c; the two constants of the model are derived from two arms
of the log itself, and every other arm is then predicted and compared:

  A. THE DEFAULT BUFFER.  `sock_init_data()` sets sk_rcvbuf =
     sysctl_rmem_default = SK_RMEM_DEFAULT = SKB_TRUESIZE(256) * 256, and
     SO_RCVBUF(v) sets max(v*2, SOCK_MIN_RCVBUF).  The instrument prints the
     buffer the socket was BORN with (F67 DEFRB) and asks for the default with
     rb = -1; both must be 212992, the value derived from the two truesizes
     the same log measures (1280 - 704 and 2304 - 1728 both leave the 576 of
     shared_info + sk_buff).

  B. THE BUDGET, and the head's charge.  Two constants are derived here, from
     two arms only:
        s(512)  = rmem / (N + kept - 1) from c_only_test   -> 1280
        s(1200) = rmem / (N + kept - 1) from d1200_133120  -> 2304
     and the filler's cost per received frame, c = rmem / 64 from
     c_only_fill -> 2540.  That the filler is NOT one aggregate is decided by
     c_fill_s512_212 of the log: a head of 64*c would leave room for 39 bodies
     and the socket kept all 64.
     Then, for the test aggregate of N datagrams of payload P at buffer R with
     rmem already in the queue:
        h = s        if rmem > R >> 1        (the head's charge collapses)
        h = N * s    otherwise
        refused iff rmem != 0 and rmem + h > R
        kept = min(N, 1 + (R - rmem - h) // s)
     Every arm, both attempts, both boots is checked against that, including
     the two-aggregate arm where the byte cap splits one send 54 + 10.

  C. THE WITNESSES.  Per attempt: the rule's counter equals the number of
     aggregates, the NFLOG message count equals the counter, each message's
     length is 48 + the aggregate's payload, its IPv6 length field is
     8 + payload, its destination is the door that was asked for, and its
     first payload bytes are the sender's pattern (0x00.. for the test,
     0xE0.. for the filler).  The receiver's nf + nt == n and they match the
     two patterns; arrived + errors == N; the read-back buffer is 2v.

  D. THE FROZEN PREDICTIONS.  research/predictions_589.md was frozen before
     the first run (sha in logs/f67_predictions_sha.txt).  This verifier keeps
     their scoreboard honestly: which came true, which were refuted.  The
     refuted set is asserted to be exactly the four the document reports.
"""
import hashlib
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
LOGS = [f"{ROOT}/logs/f67_rep1.log", f"{ROOT}/logs/f67_rep2.log"]
if len(sys.argv) > 1:		# the selftest hands in mutated copies
    LOGS = [sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else sys.argv[1]]
KERNEL = f"{ROOT}/src/linux-7.3.4-T563/arch/x86/boot/bzImage"
SRC = f"{ROOT}/src/linux-7.3.4-T563"
DIFFER = f"{ROOT}/vm/build/differ589"
ADD = f"{ROOT}/vm/differ589_add.c"
INITRD = f"{ROOT}/vm/initrd589/full.cpio.gz"
KERNEL_SHA = "1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033"
PRED_SHA = "761ed3f85a5e852c942483509a5c57dab54a07a36f04fc19a01f7d7f37c14549"

DEFRB = 212992			# SK_RMEM_DEFAULT: SKB_TRUESIZE(256) * 256
FILL_N = 64			# the filler: datagrams, and payload
FILL_P = 512
CHUNK = 54			# 64 x 1200 splits 54 + 10 at the fraglist byte cap

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


# ---------- provenance ---------------------------------------------------
chk(os.path.exists(KERNEL), "kernel image present")
chk(sha(KERNEL) == KERNEL_SHA, "kernel sha256 == 7.3.4-T563")
dsha = sha(DIFFER)
tmp = "/tmp/f67_initrd"
subprocess.run(["rm", "-rf", tmp], check=True)
os.makedirs(tmp, exist_ok=True)
subprocess.run(["bash", "-c",
                "cd %s && gzip -dc %s | cpio -idm --quiet" %
                (tmp, INITRD)], check=True)
chk(sha(tmp + "/root/repro") == dsha,
    "differ extracted from the initramfs == vm/build/differ589")
chk(sha(INITRD) == "084ca450ae209d5889660a4aaee44750e244867c7aaa1ed875d969c8e9ca9000",
    "initramfs on disk == the one hashed in the log header")
chk(sha(f"{ROOT}/research/predictions_589.md") == PRED_SHA,
    "predictions_589.md unchanged since it was frozen")


def anchor(rel, needle, what):
    path = os.path.join(SRC, rel)
    chk(os.path.exists(path), f"source present: {rel}")
    txt = open(path, errors="replace").read()
    chk(needle in txt, f"anchor: {what} ({rel})")


anchor("net/core/sock.c",
       "sk->sk_rcvbuf\t\t=\tREAD_ONCE(sysctl_rmem_default);",
       "a socket is born with sysctl_rmem_default")
anchor("include/net/sock.h",
       "#define _SK_MEM_OVERHEAD\tSKB_TRUESIZE(256)",
       "SK_RMEM_DEFAULT's unit is SKB_TRUESIZE(256)")
anchor("include/net/sock.h",
       "#define SK_RMEM_DEFAULT\t\t(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)",
       "SK_RMEM_DEFAULT = overhead * 256 packets")
anchor("net/core/sock.c",
       "WRITE_ONCE(sk->sk_rcvbuf, max_t(int, val * 2, SOCK_MIN_RCVBUF));",
       "SO_RCVBUF(v) is doubled")
anchor("net/ipv4/udp.c",
       "\tif (rmem + size > rcvbuf) {",
       "the refusal test is rmem + size > rcvbuf")
anchor("net/ipv4/udp.c",
       "\t\t/* Accept the packet if queue is empty. */",
       "an empty queue accepts anything")
anchor("net/ipv4/udp.c",
       "\tif (rmem > (rcvbuf >> 1)) {\n\t\tskb_condense(skb);\n"
       "\t\tsize = skb->truesize;\n\t}",
       "the condense branch is below the refusal test, above half")
anchor("net/core/skbuff.c",
       "if (skb->data_len > skb->end - skb->tail ||",
       "skb_condense's first way to be inert")
anchor("net/core/skbuff.c",
       "\tskb->truesize = SKB_TRUESIZE(skb_end_offset(skb));",
       "skb_condense keeps the head's own size")
anchor("net/core/gro.c",
       "\tp->truesize += skb->truesize;",
       "a fraglist aggregate SUMS the incoming truesizes")
anchor("net/core/gro.c",
       "delta_truesize = skb->truesize - new_truesize;",
       "the linear merge adds only the payload share")
anchor("net/core/skbuff.c",
       "\t\tskb_condense(skb);",
       "___pskb_trim condenses a received skb")
anchor("net/core/gro.c" if False else "net/core/skbuff.c",
       "if (!skb->sk || skb->destructor == sock_edemux)",
       "the trim's condense (skbuff.c)")
anchor("net/ipv6/ip6_offload.c",
       "!ipv6_addr_equal(&iph->daddr, &iph2->daddr)",
       "a different destination is a different flow")
anchor("net/ipv4/udp_offload.c",
       "\t\tif (ulen > udp_get_len_short(uh2) || flush) {",
       "a longer datagram completes the aggregate")
anchor("net/core/gro.c",
       "if (unlikely(p->len + skb->len >= 65536 ||",
       "the fraglist merge refuses on flush and on the byte cap")

# ---------- the arm table, read out of the instrument --------------------
ADDSRC = open(ADD, errors="replace").read()
ARMRE = re.compile(
    r'\{\s*"([a-z0-9_]+)",\s*\'(\w)\',\s*(?:\'(\w)\'|(\d+)),\s*(\d+),\s*(\d+),\s*'
    r'(\d+),\s*(\d+),\s*(-?\d+),\s*(\d+),\s*(\d+)\s*\}')


def arm_table(name):
    i = ADDSRC.index(f"AF589_{name}[] = {{")
    j = ADDSRC.index("};", i)
    out = []
    for m in ARMRE.finditer(ADDSRC[i:j]):
        (nm, dst, fdst, fzero, fn, fpl, n, pl, rb, lazy, exp) = m.groups()
        out.append(dict(name=nm, dst=dst,
                        fdst=fdst if fdst else "-", fn=int(fn), fpl=int(fpl),
                        n=int(n), pl=int(pl), rcvbuf=int(rb),
                        lazy=int(lazy), exp=int(exp)))
        if fzero is not None and int(fzero) != 0:
            raise AssertionError(f"{nm}: filler door {fzero}?")
    return out


DFLT = arm_table("DFLT")
COND = arm_table("COND")
chk(len(DFLT) == 10, f"dflt arm table has 10 arms, found {len(DFLT)}")
chk(len(COND) == 7, f"cond arm table has 7 arms, found {len(COND)}")
TABLE = {"dflt": DFLT, "cond": COND}
# the two arms whose shape (and so whose count) is decided by where the
# poll boundary fell, not by the budget: named, never modelled.
RACY = {"d54_lazy", "d54_eag"}

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


def parse_rxq(line):
    f = line.split()
    for x in f:
        if re.fullmatch(r"[0-9A-F]{8}:[0-9A-F]{8}", x):
            return int(x.split(":")[1], 16)
    return -1


def collect(lines):
    """(mode, idx) -> {arm, rcv[], rxq[], msg[], tapx{}}"""
    arms = {}
    mode = None
    rbuf = None
    for ln in lines:
        m = re.match(r"=== MODE_BEGIN (\w+) ===", ln)
        if m:
            mode = m.group(1)
            rbuf = None
            continue
        if ln.startswith("F587 RBUF|"):
            rbuf = int(kv(ln)["eff"])
        elif ln.startswith("F589 ARM|"):
            d = kv(ln)
            slot = arms.setdefault((mode, int(d["i"])), {})
            slot["arm"] = d
            slot["rbuf"] = rbuf
        elif ln.startswith("F587 RCV|"):
            d = kv(ln)
            arms.setdefault((mode, int(d["i"])), {}) \
                .setdefault("rcv", []).append(d)
        elif ln.startswith("F587 RXQ|"):
            d = kv(ln)
            arms.setdefault((mode, int(d["i"])), {}) \
                .setdefault("rxq", []).append(parse_rxq(d["line"]))
        elif ln.startswith("F589 MSG|"):
            d = kv(ln)
            arms.setdefault((mode, int(d["i"])), {}) \
                .setdefault("msg", []).append(d)
        elif ln.startswith("F587 TAPX|"):
            d = kv(ln)
            arms.setdefault((mode, int(d["i"])), {}) \
                .setdefault("tapx", {})[d["dev"]] = int(d["n"])
    return arms


TEXTS = []
for p in LOGS:
    TEXTS.append(open(p, errors="replace").read())
    hdr = TEXTS[-1][:600]
    chk(KERNEL_SHA in hdr, f"{os.path.basename(p)}: header names the kernel")
    chk(sha(INITRD) in hdr, f"{os.path.basename(p)}: header names the initrd")

BOOTS = []
for t in TEXTS:
    boot = {}
    for m in ("dflt", "cond"):
        try:
            boot[m] = collect(mode_block(t, m))
        except ValueError:
            chk(False, f"the {m} block is missing from the log")
            boot[m] = {}
    BOOTS.append(boot)
    BOOTS[-1]["defrb"] = re.findall(r"F67 DEFRB\|def=(\d+)\|half=(\d+)", t)

# ---------- 1. the default buffer ----------------------------------------
for bi, b in enumerate(BOOTS):
    chk(len(b["defrb"]) >= 1, f"boot{bi}: DEFRB printed")
    for d, h in b["defrb"]:
        chk(int(d) == DEFRB, f"boot{bi}: the socket is born with {d}, want 212992")
        chk(int(h) == DEFRB // 2, f"boot{bi}: half printed as {h}")

# ---------- 2. every arm, its printed parameters, and the model ----------
def model(n, pl, R, rmem_before, s, chunk=None):
    """(kept, rmem_after, refused) for one aggregate"""
    h = s if rmem_before > (R >> 1) else n * s
    if rmem_before != 0 and rmem_before + h > R:
        return 0, rmem_before, True
    kept = min(n, 1 + (R - rmem_before - h) // s)
    kept = max(kept, 1)
    return kept, rmem_before + h + (kept - 1) * s, False


def model_arm(a, R, s512, s1200, cfill):
    """(kept_test, kept_fill, rmem_after) for a whole arm"""
    if a["fn"]:
        rmem = a["fn"] * cfill		# the filler: plain frames, no head
        kf = a["fn"]
    else:
        rmem = 0
        kf = 0
    if a["n"] == 0:
        return 0, kf, rmem
    s = s512 if a["pl"] == 512 else s1200
    n = a["n"]
    if a["pl"] == 1200 and n == 64:	# the byte cap splits one send 54 + 10
        k1, rmem, _ = model(CHUNK, a["pl"], R, rmem, s)
        k2, rmem, _ = model(n - CHUNK, a["pl"], R, rmem, s)
        return k1 + k2, kf, rmem
    k, rmem, _ = model(n, a["pl"], R, rmem, s)
    return k, kf, rmem


def attempts(slot):
    return sorted(slot.get("rcv", []), key=lambda d: int(d["att"]))


# --- the two constants, derived from the log, one boot at a time ---------
def find(b, mode, name):
    for (m, i), slot in b[mode].items():
        if "arm" in slot and slot["arm"]["name"] == name:
            return slot
    return None


for bi, b in enumerate(BOOTS):
    only_test = find(b, "cond", "c_only_test")
    if only_test is None or not attempts(only_test):
        chk(False, f"boot{bi}: c_only_test is missing, constants cannot be "
                   f"derived")
        globals().setdefault("CONST", {})[bi] = (1280, 2304, 2540)
        continue
    a = attempts(only_test)[0]
    rmem = only_test["rxq"][0]
    s512 = rmem // (int(a["n"]) + int(a["n"]) - 1)		# N + kept - 1
    chk(s512 * (64 + 64 - 1) == rmem, f"boot{bi}: s(512) divides 162560")
    only_1200 = find(b, "dflt", "d1200_133120")
    if only_1200 is None or not attempts(only_1200):
        chk(False, f"boot{bi}: d1200_133120 is missing")
        globals().setdefault("CONST", {})[bi] = (1280, 2304, 2540)
        continue
    a2 = attempts(only_1200)[0]
    rmem2 = only_1200["rxq"][0]
    s1200 = rmem2 // (54 + int(a2["n"]) - 1)
    chk(s1200 * (54 + 4 - 1) == rmem2, f"boot{bi}: s(1200) divides 131328")
    fill = find(b, "cond", "c_only_fill")
    if fill is None or not fill.get("rxq"):
        chk(False, f"boot{bi}: c_only_fill is missing")
        globals().setdefault("CONST", {})[bi] = (1280, 2304, 2540)
        continue
    rmemf = fill["rxq"][0]
    cfill = rmemf // FILL_N
    chk(cfill * FILL_N == rmemf, f"boot{bi}: the filler's cost divides evenly")
    chk(cfill > s512, f"boot{bi}: a received frame costs more than a segment")
    # the filler always gets through, and its cost is a constant of the arm
    for mode in ("dflt", "cond"):
        for sl in b[mode].values():
            if "arm" in sl and int(sl["arm"]["fn"]) > 0:
                for att in sl.get("rcv", []):
                    chk(int(att["nf"]) == FILL_N and int(att["nt"]) >= 0,
                        f"boot{bi}: the filler's 64 datagrams all arrive")
    globals().setdefault("CONST", {})[bi] = (s512, s1200, cfill)

    for mode in ("dflt", "cond"):
        for idx, a in enumerate(TABLE[mode]):
            slot = b[mode].get((mode, idx))
            chk(slot is not None, f"boot{bi}/{mode}/{a['name']}: arm present")
            if slot is None:
                continue
            if "arm" not in slot:
                chk(False, f"boot{bi}/{mode}/{a['name']}: no ARM row")
                continue
            row = slot["arm"]
            # --- printed parameters must match the source table
            for f, key in (("dst", "dst"), ("fdst", "fdst"), ("fn", "fn"),
                           ("fpl", "fpl"), ("n", "n"), ("pl", "pl"),
                           ("rcvbuf", "rcvbuf"), ("lazy", "lazy"),
                           ("exp", "exp")):
                chk(row[f] == str(a[key]),
                    f"boot{bi}/{a['name']}: printed {f}={row[f]} != source {a[key]}")
            R = slot["rbuf"]
            want = DEFRB if a["rcvbuf"] < 0 else 2 * a["rcvbuf"]
            chk(R == want, f"boot{bi}/{a['name']}: read-back {R} != {want}")
            chk(int(row["ch"]) == a["exp"],
                f"boot{bi}/{a['name']}: rule counted {row['ch']} packets, "
                f"expected {a['exp']}")
            chk(int(row["mn"]) == int(row["ch"]),
                f"boot{bi}/{a['name']}: {row['mn']} messages for {row['ch']} packets")
            kt, kf, rmem_want = model_arm(a, R, s512, s1200, cfill)
            # --- messages: length, length field, destination, payload
            msgs = [m for m in slot.get("msg", []) if m["att"] == "0"][:4]
            if a["name"] not in RACY:
                chk(len(msgs) == int(row["mn"]),
                    f"boot{bi}/{a['name']}: {len(msgs)} message lines for "
                    f"{row['mn']}")
            dt = "fd03" if a["dst"] == "a" else "fd04"
            aggs = []
            if a["fn"]:
                aggs.append(("f", FILL_N, FILL_P, "fd04", 0))
            if a["n"] == 64 and a["pl"] == 1200:
                aggs += [("s", CHUNK, 1200, dt, 0),
                         ("s", 10, 1200, dt, CHUNK)]
            elif a["n"]:
                aggs.append(("s", a["n"], a["pl"], dt, 0))
            if a["name"] not in RACY:
                chk(len(msgs) == len(aggs),
                    f"boot{bi}/{a['name']}: {len(msgs)} aggregates, model "
                    f"{len(aggs)}")
            for m, (kind, n, pl, dst, first) in zip(msgs, aggs):
                ulen = 8 + n * pl
                if a["name"] in RACY:
                    continue
                chk(int(m["plen"]) == 40 + ulen,
                    f"boot{bi}/{a['name']}/k{m['k']}: plen {m['plen']} != {40 + ulen}")
                chk(int(m["u6"], 16) == ulen,
                    f"boot{bi}/{a['name']}/k{m['k']}: ip6 len {m['u6']} != {ulen:04x}")
                chk(m["dst"][:4] == dst,
                    f"boot{bi}/{a['name']}/k{m['k']}: dst {m['dst']} != {dst}")
                if kind == "f":
                    p0 = "e041424344454647"
                else:
                    p0 = "%02x81828384858687" % first
                if a["name"] not in RACY:
                    chk(m["p0"] == p0,
                        f"boot{bi}/{a['name']}/k{m['k']}: payload p0 "
                        f"{m['p0']} != {p0}")
            # --- the receiver
            for att in attempts(slot):
                tag = f"boot{bi}/{a['name']}/att{att['att']}"
                n = int(att["n"])
                nf, nt = int(att["nf"]), int(att["nt"])
                chk(n == nf + nt, f"{tag}: n={n} != nf+n t={nf}+{nt}")
                chk(nf == kf, f"{tag}: filler delivered {nf}, model {kf}")
                if a["name"] in RACY:
                    chk(39 <= nt <= a["n"],
                        f"{tag}: the racy arm kept {nt}, outside [39, N]")
                else:
                    chk(nt == kt, f"{tag}: test delivered {nt}, model {kt}")
                chk(int(att["udp"]) == n, f"{tag}: Udp6InDatagrams +{att['udp']} != {n}")
                chk(int(att["udperr"]) == a["n"] + a["fn"] - n,
                    f"{tag}: Udp6InErrors +{att['udperr']} != "
                    f"{a['n'] + a['fn'] - n}")
                chk(int(att["hdr"]) == 0, f"{tag}: Ip6InHdrErrors {att['hdr']}")
                chk(int(att["rb"]) == R, f"{tag}: rb {att['rb']} != {R}")
                chk(int(att["lazy"]) == a["lazy"], f"{tag}: lazy {att['lazy']}")
                chk(n + int(att["udperr"]) == a["n"] + a["fn"],
                    f"{tag}: delivered + errors != N")
                T = [int(x) for x in att["T"].split(",") if x not in ("0", "")]
                chk(bool(T), f"{tag}: no arrival times")
                if a["lazy"]:
                    chk(390 <= T[0] <= 520,
                        f"{tag}: first arrival {T[0]} ms, lazy reader ~400")
                else:
                    chk(150 <= T[0] <= 320,
                        f"{tag}: first arrival {T[0]} ms, eager")
            # --- the queue's own byte account
            if a["lazy"]:
                chk(len(slot.get("rxq", [])) == 2,
                    f"boot{bi}/{a['name']}: two RXQ reads")
                for r in slot.get("rxq", []):
                    chk(r == rmem_want,
                        f"boot{bi}/{a['name']}: rmem {r} != model {rmem_want}")
            # --- frames on the two doors: y1 keeps the aggregate whole (one
            # frame per aggregate), y2 has no GSO_UDP_L4 and segments the filler
            aggs_n = (1 if a["fn"] else 0) + (0 if not a["n"] else
                                             (2 if (a["n"] == 64 and
                                                    a["pl"] == 1200) else 1))
            if a["fn"]:
                chk(int(row["bn"]) == FILL_N,
                    f"boot{bi}/{a['name']}: y2 carried {row['bn']} frames for "
                    f"{FILL_N} filler datagrams")
            if a["dst"] == "a" and a["n"]:
                chk(int(row["an"]) == aggs_n - (1 if a["fn"] else 0),
                    f"boot{bi}/{a['name']}: y1 carried {row['an']} frames for "
                    f"{aggs_n - (1 if a['fn'] else 0)} aggregates")
            elif a["dst"] == "b":
                chk(int(row["an"]) == 0,
                    f"boot{bi}/{a['name']}: nothing crosses y1")
                chk(1 <= int(row["bn"]) <= a["n"],
                    f"boot{bi}/{a['name']}: y2 carried {row['bn']} frames for "
                    f"{a['n']} datagrams")

# ---------- 3. the racy arms, named --------------------------------------
for bi, b in enumerate(BOOTS):
    for mode in ("dflt", "cond"):
        for idx, a in enumerate(TABLE[mode]):
            slot = b[mode].get((mode, idx))
            if slot is None or "arm" not in slot:
                chk(False, f"boot{bi}/{mode}/{a['name']}: no ARM row")
                continue
            row = slot["arm"]
            if a["name"] in RACY:
                continue
            chk(int(row["agr"]) == 1,
                f"boot{bi}/{a['name']}: the two attempts disagree")

# ---------- 4. determinism between the boots -----------------------------
for mode in ("dflt", "cond"):
    for idx, a in enumerate(TABLE[mode]):
        s1 = BOOTS[0][mode].get((mode, idx), {})
        s2 = BOOTS[1][mode].get((mode, idx), {})
        if "arm" not in s1 or "arm" not in s2:
            chk(False, f"{a['name']}: an ARM row is missing, cannot compare")
            continue
        f1 = [(int(d["n"]), int(d["nf"]), int(d["nt"]), int(d["udperr"]))
              for d in attempts(s1)]
        f2 = [(int(d["n"]), int(d["nf"]), int(d["nt"]), int(d["udperr"]))
              for d in attempts(s2)]
        if a["name"] in RACY:
            chk(set(x[2] for x in f1 + f2) and
                min(x[2] for x in f1 + f2) >= 39,
                f"{a['name']}: racy arm never keeps fewer than the budget")
        else:
            chk(f1 == f2, f"{a['name']}: boots disagree {f1} vs {f2}")
        if a["lazy"] and s1.get("rxq") and s2.get("rxq"):
            chk(s1["rxq"] == s2["rxq"],
                f"{a['name']}: rmem differs between boots")

# ---------- 5. the frozen predictions, honestly scored -------------------
# (arm, kind, predicted, measured-extractor)
def kept_of(b, mode, name, att=0):
    slot = find(b, mode, name)
    return int(attempts(slot)[att]["nt"])


def ue_of(b, mode, name, att=0):
    slot = find(b, mode, name)
    return int(attempts(slot)[att]["udperr"])


def rx_of(b, mode, name):
    return find(b, mode, name)["rxq"][0]


FROZEN = [
    ("P2", "d54_lazy", 39, 15, 211968),
    ("P4", "d64_lazy", 64, 0, 162560),
    ("P5", "d54_lazy_b", 39, 15, 211968),
    ("P6", "d64x1200_lazy", 39, 25, 211968),
    ("P7a", "d1200_133120", 4, 50, 131328),
    ("P7b", "d1200_143360", 9, 45, 142848),
    ("P7c", "d1200_153600", 13, 41, 152064),
    ("P7d", "d1200_163840", 18, 36, 163584),
    ("P7e", "d1200_184320", 27, 27, 184320),
    ("P8", "c_only_fill", 64, 0, 162560),
    ("P9", "c_only_test", 64, 0, 162560),
    ("P10", "c_fill_test", 14, 50, 261120),
    ("P11", "c_fill_test1200_262", 0, 54, 162560),
    ("P12", "c_fill_test1200_311", 11, 43, 310016),
    ("P13", "c_fill_test1200_344", 25, 29, 342272),
    ("P14", "c_fill_s512_212", 0, 64, 162560),
]
refuted = []
for p, name, k, ue, rx in FROZEN:
    b = BOOTS[0]
    mode = "dflt" if name.startswith("d") else "cond"
    sl = find(b, mode, name)
    if sl is None:
        refuted.append(p)
        print(f"  REF {p} {name}: the arm is not in the log")
        continue
    if p == "P8":			# the filler's own count, not the test's
        kk = int(attempts(find(b, mode, name))[0]["nf"])
    elif p == "P2":			# scored on the attempt the poll did not split
        kk = kept_of(b, mode, name, att=1)
    else:
        kk = kept_of(b, mode, name)
    uu = ue_of(b, mode, name, att=1 if p == "P2" else 0)
    rr = rx_of(b, mode, name)
    hit = (kk == k and uu == ue and rr == rx)
    print(("  ok  " if hit else "  REF ") + f"{p} {name}: "
          f"{kk}/{uu}/{rr} vs frozen {k}/{ue}/{rx}")
    if not hit:
        refuted.append(p)
# P2 has one racy attempt in rep1: the send split into two aggregates there
d54 = find(BOOTS[0], "dflt", "d54_lazy")
chk(d54 is not None and int(attempts(d54)[1]["nt"]) == 39,
    "P2: the non-racy attempt keeps 39")
chk(rx_of(BOOTS[0], "dflt", "d54_lazy") == 211968, "P2: rmem 211968")
# any attempt that departs from 39 must be the one whose send the poll split
# into two aggregates: the departure is a shape fact, not a budget fact
chk(d54 is not None and all(
    (int(d["nt"]) == 39) or int(d["n"]) > 39
    for d in attempts(d54)),
    "P2: a departing attempt keeps more, never fewer")
chk(d54 is not None and int(d54["arm"]["ch0"]) >= 1 and
    int(d54["arm"]["ch"]) >= 1, "P2: the rule counted packets in both attempts")
chk(set(refuted) == {"P10", "P11", "P12", "P14"},
    f"the refuted predictions are exactly the four the document reports, "
    f"got {sorted(refuted)}")
# P3: the eager reader never keeps fewer than the lazy one
for b in BOOTS:
    sl = find(b, "dflt", "d54_eag")
    chk(sl is not None and attempts(sl), "P3: the eager arm is present")
    if sl is not None and attempts(sl):
        eag = min(int(d["nt"]) for d in attempts(sl))
        chk(eag >= 39, f"P3: the eager reader kept {eag}, below the budget 39")

# ---------- report -------------------------------------------------------
print(f"checks={ok} failures={len(bad)}")
print("frozen: %d of %d satisfied, refuted %s" %
      (len(FROZEN) + 1 - len(refuted), len(FROZEN) + 1, sorted(refuted)))
print("constants: " + ", ".join(
    f"boot{bi}: s512={v[0]} s1200={v[1]} cfill={v[2]}"
    for bi, v in sorted(CONST.items())))
for what in bad:
    print("FAIL " + what)
sys.exit(1 if bad else 0)
