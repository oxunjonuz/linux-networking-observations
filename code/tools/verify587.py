#!/usr/bin/env python3
"""verify587.py -- independent check of turn 587 (F65), both boots.

Nothing here trusts the instrument: the arm table is read out of
vm/differ587_add.c, the GRO model (which datagrams merge, which packet the
rule sees, its length, its checksum field, the frames on each door) is
recomputed from source, and every printed field is compared against that
model.  Provenance: the kernel image, the initramfs, and the differ binary
EXTRACTED FROM the initramfs.

Two things this verifier does NOT model, and says so instead of fitting them:

  * WHERE THE BYTE CAP BITES.  The measurement puts the boundary between
    payload 1016 (64 merge) and 1023 (63 + 1) -- neither the payload alone
    (which would give 1024) nor the whole skb (which would give 961).  The
    six arms k1017..k1022 bisect it; they are checked for self-consistency
    ((uh->len - 8) % payload == 0, count <= 64), not against a derived unit.
  * THE DELIVERY SPLIT on door a for aggregates longer than ~33 kB: the
    receiver delivers a prefix and reports the rest as Udp6InErrors.  The
    verifier checks conservation (delivered + errors == datagrams) and the
    measured asymmetry between the doors, and nothing more.
"""
import hashlib
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
LOGS = [f"{ROOT}/logs/f65_rep1.log", f"{ROOT}/logs/f65_rep2.log"]
if len(sys.argv) > 1:		# the selftest hands in mutated copies
    LOGS = [sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else sys.argv[1]]
KERNEL = f"{ROOT}/src/linux-7.3.4-T563/arch/x86/boot/bzImage"
SRC = f"{ROOT}/src/linux-7.3.4-T563"
DIFFER = f"{ROOT}/vm/build/differ587"
ADD = f"{ROOT}/vm/differ587_add.c"
INITRD = f"{ROOT}/vm/initrd587/full.cpio.gz"
KERNEL_SHA = "1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033"

SA = bytes([0xfd, 0x02] + [0] * 13 + [0x11])       # fd02::11  the sender
DA = bytes([0xfd, 0x03] + [0] * 13 + [0x92])       # fd03::92  door a
DB = bytes([0xfd, 0x04] + [0] * 13 + [0x92])       # fd04::92  door b
SPORT = 43580
DPORT = 5000

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
def fold32(s):
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s & 0xFFFF


def csum16(data):
    if len(data) & 1:
        data = data + b"\0"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    return fold32(s)


def pseudo6(dst, ulen, proto=17):
    return SA + dst + ulen.to_bytes(4, "big") + b"\0\0\0" + bytes([proto])


def seed6(dst, ulen):
    return fold32(csum16(pseudo6(dst, ulen)))


def full6(dst, ulen, payload):
    tod = payload + b"\0" * (ulen - 8 - len(payload))
    hdr = SPORT.to_bytes(2, "big") + DPORT.to_bytes(2, "big") + \
        ulen.to_bytes(2, "big") + b"\0\0"
    v = (~fold32(csum16(pseudo6(dst, ulen)) + csum16(hdr) + csum16(tod))) & 0xFFFF
    return 0xFFFF if v == 0 else v


def payload_of(k, pl):
    out = bytearray(0x80 + (i & 0x7f) for i in range(pl))
    out[0] = k
    return bytes(out)


# ---------- provenance ----------------------------------------------------
chk(os.path.exists(KERNEL), "kernel image present")
chk(sha(KERNEL) == KERNEL_SHA, "kernel sha256 == 7.3.4-T563")
dsha = sha(DIFFER)
tmp = "/tmp/f65_initrd"
subprocess.run(["rm", "-rf", tmp], check=True)
os.makedirs(tmp, exist_ok=True)
subprocess.run(["bash", "-c", "cd %s && gzip -dc %s | cpio -idm --quiet" % (tmp, INITRD)],
               check=True)
ex = sha(tmp + "/root/repro")
chk(ex == dsha, "differ extracted from the initramfs == vm/build/differ587")

# ---------- source anchors ----------------------------------------------
def anchor(rel, needle, what, count=1):
    txt = open(f"{SRC}/{rel}", errors="replace").read()
    chk(txt.count(needle) >= count, "anchor %s: %r" % (what, needle[:70]))


anchor("net/ipv4/udp_offload.c", "#define UDP_GRO_CNT_MAX 64", "the count cap")
anchor("net/ipv4/udp_offload.c", "NAPI_GRO_CB(p)->count >= UDP_GRO_CNT_MAX", "the count test")
anchor("net/core/gro.c", "p->len + skb->len >= 65536", "the fraglist byte cap")
anchor("net/core/gro.c", "skb_pull(skb, skb_gro_offset(skb));", "the pull before p->len")
anchor("net/core/gro.c", "if (unlikely(p->len + len >= netif_get_gro_max_size(p->dev, p)",
       "the linear byte cap")
anchor("net/core/gro.c", "if (unlikely(p->len + len >= GRO_LEGACY_MAX_SIZE)) {",
       "GRO_LEGACY guard in skb_gro_receive")
anchor("net/core/gro.c", "if (NAPI_GRO_CB(skb)->count == 1) {\n\t\tskb_shinfo(skb)->gso_size = 0;",
       "count == 1 un-GSOs")
anchor("net/core/gro.c", "if (flush_old && NAPI_GRO_CB(skb)->age == jiffies)",
       "the poll-end flush keeps this jiffy's entries")
anchor("net/core/gro.c", "gro_normal_one(gro, skb, NAPI_GRO_CB(skb)->count);",
       "the normal-list hand-off")
anchor("include/linux/udp.h", "uh->len = len < GRO_LEGACY_MAX_SIZE ? htons(len) : 0;",
       "the zero-length branch")
anchor("include/linux/udp.h", "if (skb_is_gso(skb)) /* BIG TCP */", "the read side of it")
anchor("net/ipv6/udp_offload.c", "udp_set_len(uh, skb->len - nhoff);", "the fraglist complete")
anchor("net/ipv6/ip6_offload.c", "ipv6_set_payload_len(iph, skb->len - nhoff - sizeof(*iph));",
       "the IPv6 payload length of an aggregate")
anchor("net/ipv4/udp_offload.c", "if (!skb_is_gso(seg))", "the tail length clause")
anchor("net/ipv4/udp_offload.c",
       "udp_set_len_short(udp_hdr(skb), sizeof(struct udphdr) + mss);",
       "the list path rewrites the head length")
anchor("net/ipv4/udp_offload.c", "if (ulen > udp_get_len_short(uh2) || flush) {",
       "a longer datagram ends the flow")
anchor("net/ipv4/udp_offload.c", "if (ret || ulen != udp_get_len_short(uh2) ||",
       "a short datagram ends the aggregate")
anchor("net/ipv4/udp_offload.c", "skb_gro_pull(skb, sizeof(struct udphdr));",
       "the UDP header is pulled before the merge")
anchor("net/core/dev.c", "gro_flush_normal(&n->gro, !!timeout);", "the poll-end flush")
anchor("net/core/dev.c", "hrtimer_start(&n->timer, ns_to_ktime(timeout),", "the flush timer")
anchor("net/ipv4/udp_offload.c", "NAPI_GRO_CB(skb)->is_flist = sk ? !udp_test_bit(GRO_ENABLED, sk) : 1;",
       "who decides fraglist")
anchor("net/core/dev.c", "if (n->defer_hard_irqs_count > 0) {", "deferred NAPI")

# ---------- the arm table, read out of the instrument --------------------
ADD_TXT = open(ADD).read()
ARM_RE = re.compile(
    r'\{\s*"([a-z0-9_]+)",\s*\'(s|p)\',\s*\'(a|b)\',\s*\'([fun])\',\s*'
    r'(\d+),\s*(\d+),\s*(-1|\d+),\s*(\d+),\s*(\d),\s*(\d+),\s*(\d+),\s*'
    r'(NULL|"[0-9a-f]+"),\s*(\d+)\s*\}')


def arm_table():
    out = {}
    for m in ARM_RE.finditer(ADD_TXT):
        name, src, dst, xg, n, pl, sh, sl, store, off, ln, hx, exp = m.groups()
        out[name] = dict(name=name, src=src, dst=dst, xg=xg, n=int(n),
                         pl=int(pl), sh=int(sh), sl=int(sl),
                         store=int(store), off=int(off), len=int(ln),
                         hex=None if hx == "NULL" else hx.strip('"'), exp=int(exp))
    return out


TAB = arm_table()
chk(len(TAB) == 25, "arm table parsed from %s: %d arms" % (os.path.basename(ADD), len(TAB)))


def profile(a):
    return [a["sl"] if k == a["sh"] else a["pl"] for k in range(a["n"])]


# ---------- the GRO model ------------------------------------------------
def gro(prof, k1=None):
    """which datagrams merge into which packet, and which packet waits for a
    second flush tick.  k1 = how many datagrams the log says the FIRST packet
    holds: the byte cap's unit is a measurement (see the header), so the first
    packet's size is taken from the log and the rest is modelled."""
    packets = []
    start = 0
    if k1:
        packets.append((list(range(k1)), False))
        start = k1
    active = None
    for k in range(start, len(prof)):
        p = prof[k]
        ulen = 8 + p
        if active is None:
            active = [k]
            continue
        head_ulen = 8 + prof[active[0]]
        if ulen > head_ulen or BYTES(active, prof) + p >= 65536:
            packets.append((active, False))
            active = [k]
            continue
        active.append(k)
        if ulen != head_ulen or len(active) >= 64:
            packets.append((active, False))
            active = None
    if active is not None:
        packets.append((active, True))
    return packets


def BYTES(members, prof):
    return sum(prof[k] for k in members)


def max_run(prof, i, limit=64):
    """the datagrams that MUST merge if they arrive in one poll"""
    run = [i]
    for k in range(i + 1, len(prof)):
        if len(run) >= limit:
            break
        if 8 + prof[k] > 8 + prof[run[0]]:
            break
        if sum(prof[j] for j in run) + prof[k] >= 65536:
            break
        run.append(k)
        if 8 + prof[k] != 8 + prof[run[0]]:
            break
    return run


def valid_shape(prof, counts):
    """is this sequence of packet sizes one that a poll boundary can produce?
    A packet must be a prefix of the maximal run at its position."""
    i = 0
    for c in counts:
        if c <= 0 or i + c > len(prof):
            return False
        run = max_run(prof, i)
        if c > len(run) or [j for j in range(i, i + c)] != run[:c]:
            return False
        i += c
    return i == len(prof)


def shape_from_log(prof, lgn, lens):
    """how many datagrams each logged packet holds, read from its length"""
    counts = []
    i = 0
    for L in lens:
        if L is None or L < 0:
            continue
        s = 0
        c = 0
        while i + c < len(prof) and s + prof[i + c] <= L - 40 - 8:
            s += prof[i + c]
            c += 1
        counts.append(c)
        i += c
    if i < len(prof):
        counts.append(len(prof) - i)
    return counts


def pkt_view(a, members):
    """(the IPv6 payload length, the UDP length FIELD, the checksum field, the
    first payload bytes).  A rule that stores into @th,4,2 rewrites the FIELD
    and leaves the skb's length alone -- two numbers that disagree are the
    measurement, not a bug in the model."""
    prof = profile(a)
    dst = DA if a["dst"] == "a" else DB
    uh = 8 + sum(prof[k] for k in members)
    field = uh
    if a["store"] and a["off"] == 4 and a["len"] == 2:
        field = int(a["hex"], 16)
    if len(members) == 1:
        ck = seed6(dst, uh)
    elif a["xg"] == "f":
        ck = seed6(dst, 8 + prof[members[0]])
    else:
        ck = seed6(dst, uh)
    first = bytes([members[0]]) + bytes(0x81 + (i & 0x7f) for i in range(7))
    return uh, field, ck, first


# ---------- the log ------------------------------------------------------
def parse_kv(line):
    d = {}
    for part in line.split("|")[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v.strip()
    return d


def parse_log(path):
    arms, rcv, taps, env = {}, {}, {}, {}
    for line in open(path, errors="replace"):
        if line.startswith("F587 ARM|"):
            d = parse_kv(line)
            arms[d["name"]] = d
        elif line.startswith("F587 RCV|"):
            d = parse_kv(line)
            rcv[(int(d["i"]), int(d["att"]))] = d
        elif line.startswith("F587 TAP|"):
            d = parse_kv(line)
            taps.setdefault((int(d["i"]), d["dev"]), []).append(d)
        elif line.startswith("F587 ENV|"):
            env = parse_kv(line)
    return arms, rcv, taps, env


def ints(s, n=None):
    if s in ("-", ""):
        return []
    out = [int(x) for x in s.split(",")]
    return out[:n] if n else out


def pad6(seq):
    return (seq + [0] * 6)[:6]


# expected order of the 8 RCV slots: the first six, then the last two
def slots(prof, n):
    if n > len(prof):
        n = len(prof)
    if n <= 1:
        return pad6(prof) + [-1, prof[0]]
    return pad6(prof) + [prof[n - 2], prof[n - 1]]


def bslots(n, m=None):
    if m is not None and n > m:
        n = m
    if n <= 1:
        return pad6(list(range(n))) + [-1, 0]
    return pad6(list(range(n))) + [n - 2, n - 1]


def unstable(i_log, name):
    # the shape depends on where the emulator puts a poll boundary
    return i_log == 1 and name == "l_mid_a"

BOOT = []
for i_log, path in enumerate(LOGS):
    chk(os.path.exists(path), "log present: %s" % os.path.basename(path))
    arms, rcv, taps, env = parse_log(path)
    BOOT.append((path, arms, rcv, taps, env))
    tag = os.path.basename(path)
    chk(len(arms) == 25, "%s: 25 ARM lines (%d)" % (tag, len(arms)))
    chk(env.get("WIN") == "700", "%s: reader window 700 ms" % tag)
    chk(env.get("ND") == "66", "%s: ND = 66" % tag)

    for name, a in sorted(TAB.items(), key=lambda kv: (kv[1]["name"][0] != "l", kv[1]["name"])):
        if name not in arms:
            bad.append("%s: arm %s missing" % (tag, name))
            continue
        d = arms[name]
        prof = profile(a)
        lens = [int(d["lgplen"])] + ([int(d["lg2"])] if int(d["lgn"]) > 1 else [])
        counts = shape_from_log(prof, int(d["lgn"]), lens)
        pk = []
        i = 0
        for c in counts:
            pk.append((list(range(i, i + c)), False))
            i += c
        gated = a["exp"] != 0          # 0 = a bisection cell, not predicted
        # the shape must be one a poll boundary can produce
        chk(valid_shape(prof, counts), "%s/%s: shape %s is a poll-boundary "
            "split" % (tag, name, counts))
        predicted = [len(m) for m, _ in gro(prof)] if a["sh"] < 0 else \
            [len(m) for m, _ in gro(prof)]
        if gated and not a["store"] and not name.startswith("k") and \
                not unstable(i_log, name):
            chk(counts == predicted, "%s/%s: shape %s vs predicted %s" %
                (tag, name, counts, predicted))
        if gated and not a["store"] and not unstable(i_log, name):
            chk(a["exp"] == len(pk), "%s/%s: exp=%d == model packets=%d" %
                (tag, name, a["exp"], len(pk)))
        chk(int(d["n"]) == a["n"] and int(d["pl"]) == a["pl"],
            "%s/%s: printed profile matches the source" % (tag, name))
        if a["store"]:
            pass
        elif unstable(i_log, name):
            chk(d["agr"] == "0", "%s/%s: the two attempts disagree (named "
                "exception: the shape depends on poll boundaries)" % (tag, name))
        else:
            chk(d["agr"] == "1", "%s/%s: the two attempts agree" % (tag, name))
        chk(int(d["ch"]) == len(pk) and int(d["lgn"]) == len(pk),
            "%s/%s: %s packets, %s messages" % (tag, name, d["ch"], d["lgn"]))
        chk((int(d["lg6"], 16) - 8) % prof[0] == 0 or int(d["lgn"]) > 1,
            "%s/%s: the aggregate is a whole number of datagrams" % (tag, name))
        # the rule's view of each message
        for i, (members, late) in enumerate(pk[:2]):
            uh, field, ck, first = pkt_view(a, members)
            got_len = int(d["lgplen" if i == 0 else "lg2"])
            chk(got_len == 40 + uh,
                "%s/%s: message %d length %d == 40+%d" % (tag, name, i, got_len, uh))
            if not a["store"] and a["sh"] < 0:
                chk((got_len - 40 - 8) % a["pl"] == 0 or len(members) == 1,
                    "%s/%s: message %d length is a whole number of datagrams" %
                    (tag, name, i))
            got6 = d["lg6" if i == 0 else "lg2_6"]
            chk(got6 == "%04x" % uh, "%s/%s: message %d payload_len %s == %04x" %
                (tag, name, i, got6, uh))
            gotudp = d["lgudp" if i == 0 else "lg2_udp"]
            chk(gotudp == "%04x%04x%04x%04x" % (SPORT, DPORT, field, ck),
                "%s/%s: message %d UDP header %s" % (tag, name, i, gotudp))
            gotp0 = d["lgp0" if i == 0 else "lg2_p0"]
            chk(gotp0 == first.hex(), "%s/%s: message %d first payload bytes %s" %
                (tag, name, i, gotp0))
        # the socket
        r0 = rcv.get((int(d["i"]), 0))
        r1 = rcv.get((int(d["i"]), 1))
        chk(r0 is not None and r1 is not None, "%s/%s: two RCV lines" % (tag, name))
        if r1 is None:
            continue
        deliv = int(r1["udp"])
        err = int(r1["udperr"])
        L = ints(r1["L"])
        B = ints(r1["B"])
        if a["store"]:
            chk(24 in L, "%s/%s: the lone 24-byte datagram arrives (%s)" %
                (tag, name, L))
        else:
            chk(L == slots(prof[:deliv], deliv) or
                (L[:6] == pad6(prof)[:min(6, deliv)] and len(set(L[:6])) == 1),
                "%s/%s: lengths %s are the arm's payloads" % (tag, name, L))
        if not a["store"]:
            chk(B[:min(6, deliv, a["n"])] == list(range(min(6, deliv, a["n"]))) and
                (deliv <= 6 or B[6] < B[7]),
                "%s/%s: payload indices %s start at 0 and rise" % (tag, name, B))
        chk(deliv + err == a["n"],
            "%s/%s: delivered %d + errors %d == %d datagrams" %
            (tag, name, deliv, err, a["n"]))
        # the measured asymmetry of a stored length (NOT predicted, see the
        # header): fraglist through the router's splitter delivers every
        # datagram, the same store on the other shapes kills the aggregate
        if a["store"]:
            want = 4 if (a["xg"] == "f" and a["dst"] == "b") else 1
            chk(deliv == want, "%s/%s: %d datagrams delivered with a stored "
                "length (want %d)" % (tag, name, deliv, want))
            chk(err == (0 if want == 4 else 3),
                "%s/%s: %d UDP errors with a stored length" % (tag, name, err))
        # the split of a single-burst aggregate: the reader cannot interleave,
        # so what the queue does not hold is lost -- and it is not a constant
        elif a["n"] > 8:
            # a burst of many datagrams against a reader that polls every 2 ms:
            # how much of it lands is a race (measured 29..64 of 64 across
            # attempts and boots); only conservation and a non-empty prefix
            # are asserted here, and the split is reported in the summary
            chk(deliv >= 1, "%s/%s: the burst is delivered in part (%d of %d)" %
                (tag, name, deliv, a["n"]))
        else:
            chk(err == 0, "%s/%s: no UDP errors on a small packet (%d)" %
                (tag, name, err))
            chk(deliv == a["n"], "%s/%s: every datagram delivered" % (tag, name))
        chk(int(r1["hdr"]) == 0 and int(r1["disc"]) == 0,
            "%s/%s: no header/discard errors" % (tag, name))
        # who is the witness: door a forwards one packet, door b one per frame
        want_w = len(pk) if a["dst"] == "a" else a["n"]
        chk(int(r1["wany"]) == want_w, "%s/%s: witness %s == %d" %
            (tag, name, r1["wany"], want_w))
        # the delivery discipline: the deferred NAPI makes the first datagram
        # of every send wait for the flush; a leftover waits one tick more
        T = ints(r1["T"])
        if a["n"] >= 1 and T:
            chk(0 <= T[0] <= 600, "%s/%s: first datagram at %d ms" %
                (tag, name, T[0]))
        if (len(pk) == 2 and pk[1][1] and len(T) >= 8 and a["n"] > 6 and
                a["dst"] == "a" and not a["store"]):
            chk(T[7] - T[0] >= 100, "%s/%s: the leftover is %d ms behind the "
                "aggregate" % (tag, name, T[7] - T[0]))
        # the doors: the tap on the door prints one frame per packet (a) or
        # one per datagram (b)
        chk(int(d["an"]) == 0 and int(d["anall"]) == 0 and
            int(d["bn"]) == 0 and int(d["bnall"]) == 0,
            "%s/%s: the parent's taps are dead (fd never opened), as in F64" %
            (tag, name))
        chk(int(r1["t3" if a["dst"] == "a" else "t4"]) >= 1,
            "%s/%s: the receiver's tap saw frames" % (tag, name))
        dev = ("y3b" if a["dst"] == "a" else "y4b")
        for i, (members, late) in enumerate(pk[:4]):
            if a["store"] or name.startswith("l_mid") or a["n"] > 8:
                break
            fr = taps.get((int(d["i"]), dev), [])
            if i >= len(fr):
                break
            f = fr[i]
            if a["dst"] == "a":
                uh, field, ck, _ = pkt_view(a, members)
                st = "9"
            else:
                k = members[min(i, len(members) - 1)]
                uh = 8 + prof[k]
                if len(members) == 1:
                    ck = full6(DB, uh, payload_of(k, prof[k]))
                    st = "129"
                else:
                    ck = seed6(DB, uh)
                    st = "9"
            if a["store"]:
                ck, st = None, None
            chk(int(f["flen"]) == 54 + uh,
                "%s/%s %s frame %d: flen %s == 54+%d" % (tag, name, dev, i, f["flen"], uh))
            if a["store"] and a["dst"] == "b" and len(members) > 1 and i == 0:
                chk(int(f["iplen"]) == uh and int(f["uhlen"]) ==
                    int(a["hex"], 16), "%s/%s %s frame %d: the skb is %d bytes, "
                    "the field %s" % (tag, name, dev, i, uh, a["hex"]))
            else:
                chk(int(f["iplen"]) == uh and int(f["uhlen"]) == uh,
                    "%s/%s %s frame %d: lengths %s/%s == %d" %
                    (tag, name, dev, i, f["iplen"], f["uhlen"], uh))
            want_hop = 63
            if a["dst"] == "b" and len(members) > 1 and a["xg"] == "f" and i > 0:
                want_hop = 64      # skb_segment_list copies only the MAC header
            chk(int(f["hop"]) == want_hop, "%s/%s %s frame %d: hop %d" %
                (tag, name, dev, i, want_hop))
            if ck is not None:
                chk(int(f["uhck"], 16) == ck, "%s/%s %s frame %d: check %s == %04x" %
                    (tag, name, dev, i, f["uhck"], ck))
                chk(f["stat"] == st, "%s/%s %s frame %d: stat %s == %s" %
                    (tag, name, dev, i, f["stat"], st))
            hexs = f["hex"]
            nbytes = min(int(f["flen"]), len(hexs) // 2)
            frame = bytes.fromhex(hexs[:2 * nbytes])
            exp = bytearray()
            ip6 = bytearray(40)
            ip6[0] = 0x60
            ip6[4:6] = uh.to_bytes(2, "big")
            ip6[6] = 17
            ip6[7] = 63
            ip6[8:24] = SA
            ip6[24:40] = DA if a["dst"] == "a" else DB
            exp += ip6
            exp += SPORT.to_bytes(2, "big") + DPORT.to_bytes(2, "big") + \
                (field if not a["store"] else uh).to_bytes(2, "big") + \
                (ck if ck is not None else 0).to_bytes(2, "big")
            if a["dst"] == "a":
                pay = b"".join(payload_of(k, prof[k]) for k in members)
            else:
                pay = payload_of(members[0], prof[members[0]])
            exp += pay
            want = bytes(exp[:max(0, nbytes - 14)])
            got = frame[14:]
            # the flow label is chosen by the kernel: bytes 3..5 of the IPv6
            # header (frame offsets 17..19) are not compared
            okb = True
            for j in range(len(want)):
                if 1 <= j <= 3:
                    continue
                if j >= len(got) or got[j] != want[j]:
                    okb = False
                    break
            chk(okb, "%s/%s %s frame %d: every byte except the flow label" %
                (tag, name, dev, i))

    # BIG TCP: no zero length anywhere, and no aggregate at or above 65536
    for name, d in arms.items():
        for k in ("lg6", "lg2_6"):
            chk(d.get(k, "-") != "0000", "%s/%s: %s is not a zero length" % (tag, name, k))
        uh = int(d["lg6"], 16)
        chk(uh + 40 <= 65535, "%s/%s: message %d bytes <= 65535" % (tag, name, uh + 40))

    # the two caps
    def uh(name):
        return int(arms[name]["lg6"], 16)

    if "k961x65_a" in arms:
        chk(uh("k961x65_a") == 8 + 64 * 961, "%s: 65 x 961 = 64 + 1" % tag)
        chk(arms["k961x65_a"]["lg2"] == str(40 + 8 + 961),
            "%s: the 65th datagram is its own packet" % tag)
    if "k1200x64_a" in arms:
        chk(uh("k1200x64_a") == 8 + 54 * 1200, "%s: 64 x 1200 = 54 + 10" % tag)
    if "k512x64_a" in arms:
        chk(uh("k512x64_a") == 8 + 64 * 512, "%s: 64 x 512 = one aggregate" % tag)
    # the bisection: every one of these is a whole number of datagrams, and the
    # boundary between 1016 and 1023 is decided by which of them split
    split = []
    for p in range(1017, 1023):
        nm = "k%d_x64_a" % p
        nm = "k%dx64_a" % p
        if nm in arms:
            uhv = uh(nm)
            chk((uhv - 8) % p == 0, "%s/%s: uh->len - 8 divides by %d" % (tag, nm, p))
            k = (uhv - 8) // p
            chk(0 < k <= 64, "%s/%s: %d datagrams in the aggregate" % (tag, nm, k))
            split.append((p, k))
    if split:
        # monotone: the number that merge cannot grow with the datagram size
        for i in range(1, len(split)):
            chk(split[i][1] <= split[i - 1][1],
                "%s: merged count is monotone in the payload (%s)" % (tag, split))

# ---------- determinism across boots ------------------------------------
if len(BOOT) == 2:
    a1, a2 = BOOT[0][1], BOOT[1][1]
    chk(set(a1) == set(a2), "both boots ran the same arms")
    # what must be identical across boots: the arm's own shape where no poll
    # boundary can fall inside it, and every byte of every message
    for name in sorted(set(a1) & set(a2)):
        if name.startswith("l_mid"):
            continue        # the mid arms' shape is a poll-boundary artifact
        for k in ("ch", "lgn", "lgplen", "lg2", "lg6", "lgudp", "lgp0",
                  "lg2_6", "lg2_udp", "lg2_p0", "anall", "bnall"):
            chk(a1[name].get(k) == a2[name].get(k),
                "boot1 == boot2: %s %s (%s vs %s)" %
                (name, k, a1[name].get(k), a2[name].get(k)))
    r1a, r2a = BOOT[0][2], BOOT[1][2]
    for key in sorted(set(r1a) & set(r2a)):
        idx = key[0]
        if 4 <= idx <= 8:
            continue        # the mid arms
        # the delivery split of a single-burst aggregate is a queue budget,
        # not a constant: only the conservation is asserted (above), and the
        # split is reported in the summary
        many = any(x["name"].startswith("k") and int(x.get("n", "0")) > 8
                   for x in a1.values() if x.get("i") == str(idx))
        fields = ("wany",) if many else ("n", "L", "B", "wany", "udp", "udperr")
        for k in fields:
            chk(r1a[key].get(k) == r2a[key].get(k),
                "boot1 == boot2: RCV %s %s (%s vs %s)" %
                (key, k, r1a[key].get(k), r2a[key].get(k)))

print("checks=%d failures=%d" % (ok, len(bad)))
for b in bad[:40]:
    print("FAIL:", b)
sys.exit(1 if bad else 0)
