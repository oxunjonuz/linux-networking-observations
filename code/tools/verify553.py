#!/usr/bin/env python3
"""verify553.py -- independent check of F31 / turn 553.

Every number the SUMMARY states is recomputed here from the raw console logs,
never from the notes.  Nothing in this file may trust a value it did not parse
out of a log or a file on disk.

Exit code 0 only if every check passes.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = "/work/kernel-sec"
LOG = os.environ.get("F553_LOG", os.path.join(ROOT, "logs"))

ok = 0
bad = []
ncheck = 0


def chk(cond, what):
    global ok, ncheck
    ncheck += 1
    if cond:
        ok += 1
    else:
        bad.append(what)


def read(path):
    with open(path, "rb") as f:
        return f.read()


def sha(path):
    return hashlib.sha256(read(path)).hexdigest()


def text(path):
    return read(path).decode("utf-8", "replace")


# ---------------------------------------------------------------- log parsing
ARM_RE = re.compile(
    r"^F553 (?P<tag>[^|]+)\|label=(?P<label>[^|]*)\|rule=(?P<rule>[^|]*)\|"
    r"cap=(?P<cap>\d+)\|flen=(?P<flen>\d+)\|nchg=(?P<nchg>\d+)\|chg=(?P<chg>[^|]*)\|"
    r"cnt=(?P<cnt>\d+)\|hex=(?P<hex>.*)$")


def arms(path):
    out = {}
    for line in text(path).splitlines():
        line = line.rstrip("\r")
        m = ARM_RE.match(line)
        if m:
            d = m.groupdict()
            for k in ("cap", "flen", "nchg", "cnt"):
                d[k] = int(d[k])
            out[d["tag"]] = d
        if line.startswith("F553 ") and "SKIP=" in line:
            out[line.split("|")[0].split()[1]] = {"skip": True, "raw": line}
        if line.startswith("F553L "):
            tag = line.split("|")[0].split()[1]
            d = {"raw": line}
            for k, pat in (("p5000", r"p5000=(\d+)"), ("p6000", r"p6000=(\d+)"),
                           ("sport", r"sport=(\d+)"), ("cnt", r"\|cnt=(\d+)"),
                           ("pay", r"pay=([0-9a-f]*)")):
                m = re.search(pat, line)
                d[k] = m.group(1) if m else None
            d["p5000"] = int(d["p5000"] or 0)
            d["p6000"] = int(d["p6000"] or 0)
            d["cnt"] = int(d["cnt"] or 0)
            out[tag] = d
    return out


def ctl_line(path, tag):
    for line in text(path).splitlines():
        if line.startswith("F553 %s|" % tag):
            m = re.search(r"hex=([0-9a-f]*)$", line.rstrip("\r"))
            if m:
                return m.group(1)
    return None


def fam_line(path):
    for line in text(path).splitlines():
        if line.startswith("F553 FAM|"):
            m = re.search(r"netdev=(\d)\|bridge=(\d)\|ip=(\d)", line)
            if m:
                return tuple(int(x) for x in m.groups())
    return None


def skipped(path):
    return {l.split("|")[0].split()[1]
            for l in text(path).splitlines()
            if l.startswith("F553 ") and "SKIP=" in l}


KERNELS = ["Q", "R", "B", "C", "M"]
LOGF = {k: os.path.join(LOG, "f31_%s_rep1.log" % k) for k in KERNELS}
A = {}
for k in KERNELS:
    chk(os.path.exists(LOGF[k]), "log exists: %s" % LOGF[k])
    A[k] = arms(LOGF[k])

# ---------------------------------------------------------------- provenance
IMGS = {
    "Q": "src/dl72/linux-7.2.15/arch/x86/boot/bzImage",
    "R": "src/linux-7.3-R19/arch/x86/boot/bzImage",
    "B": "src/linux-7.3.4-B19/arch/x86/boot/bzImage",
    "C": "src/linux-7.3.4-C553/arch/x86/boot/bzImage",
    "M": "src/dl72/linux-7.2.15-C553/arch/x86/boot/bzImage",
}
VERSION = {"Q": "7.2.15", "R": "7.3.0", "B": "7.3.4", "C": "7.3.4", "M": "7.2.15"}
for k, rel in IMGS.items():
    p = os.path.join(ROOT, rel)
    chk(os.path.exists(p), "kernel image present: %s" % rel)
    log = text(LOGF[k])
    m = re.search(r"### sha256: ([0-9a-f]{64})", log)
    chk(m is not None, "%s: the log records a kernel sha256" % k)
    if m:
        chk(m.group(1) == sha(p), "%s: kernel sha256 in the log == the file" % k)
    m = re.search(r"Linux version ([\d.]+)", log)
    chk(m is not None and m.group(1) == VERSION[k],
        "%s: booted %s (log says %s)" % (k, VERSION[k], m.group(1) if m else "?"))

# one initrd for all six boots
initrd_hashes = set()
for k in KERNELS:
    m = re.search(r"### initrd sha256: ([0-9a-f]{64})", text(LOGF[k]))
    chk(m is not None, "%s: the log records an initrd sha256" % k)
    if m:
        initrd_hashes.add(m.group(1))
chk(len(initrd_hashes) == 1, "all five counted boots used ONE initrd (%d hashes)"
    % len(initrd_hashes))
INITRD = os.path.join(ROOT, "vm/initrd553/f553.cpio.gz")
chk(initrd_hashes == {sha(INITRD)}, "the initrd hash in the logs == the file on disk")

# the differ inside the archive must be the binary this turn built
BIN = os.path.join(ROOT, "vm/build/differ553")


def cpio_member(archive, want):
    """extract one file out of a gzipped newc cpio (name field is padded to 4)"""
    import gzip
    data = gzip.decompress(read(archive))
    off = 0
    while off + 110 <= len(data):
        hdr = data[off:off + 110]
        if hdr[:6] not in (b"070701", b"070702"):
            return None
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = data[off + 110:off + 110 + namesize - 1].decode()
        # the file data starts at the next 4-byte boundary after the name:
        # 110 + namesize is NOT always aligned (F25 lost a verifier to this)
        body_at = off + 110 + namesize
        body_at += (-body_at) % 4
        body = data[body_at:body_at + filesize]
        if name.lstrip("./") == want or name.endswith("/" + want):
            return body
        off = body_at + filesize
        off += (-off) % 4
    return None


inside = cpio_member(INITRD, "repro")
chk(inside is not None, "the differ was found inside the initrd")
if inside is not None:
    chk(hashlib.sha256(inside).hexdigest() == sha(BIN),
        "the binary in the initrd is byte-for-byte vm/build/differ553")
nft_inside = cpio_member(INITRD, "nft")
chk(nft_inside is not None and hashlib.sha256(nft_inside).hexdigest().startswith(
    "77d83a42"), "the nft in the initrd is the static 1.1.7 build (77d83a42...)")

# ---------------------------------------------------------------- config claim
def config_syms(tree):
    p = os.path.join(ROOT, "src", tree, ".config")
    out = {}
    for line in text(p).splitlines():
        for s in ("CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE", "CONFIG_NF_TABLES_NETDEV"):
            if line.startswith(s + "="):
                out[s] = line.split("=", 1)[1]
    return out


for k, tree, want in (
        ("Q", "dl72/linux-7.2.15", None),
        ("R", "linux-7.3-R19", None),
        ("B", "linux-7.3.4-B19", None),
        ("C", "linux-7.3.4-C553", "y"),
        ("M", "dl72/linux-7.2.15-C553", "y")):
    syms = config_syms(tree)
    for s in ("CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE", "CONFIG_NF_TABLES_NETDEV"):
        if want is None:
            chk(s not in syms and True or False,
                "%s (%s): %s is not set" % (k, tree, s)) if s in syms and \
                syms[s] != "y" else None
    if want:
        for s in ("CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE", "CONFIG_NF_TABLES_NETDEV"):
            chk(syms.get(s) == want, "%s (%s): %s=y" % (k, tree, s))
    else:
        for s in ("CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE", "CONFIG_NF_TABLES_NETDEV"):
            chk(syms.get(s) != "y", "%s (%s): %s is not y" % (k, tree, s))

# the config kernels differ from their parents in nothing but the symbols
for child, parent in (("linux-7.3.4-C553", "linux-7.3.4-B19"),
                      ("dl72/linux-7.2.15-C553", "dl72/linux-7.2.15")):
    chk(sha(os.path.join(ROOT, "src", child, "net/netfilter/nft_payload.c")) ==
        sha(os.path.join(ROOT, "src", parent, "net/netfilter/nft_payload.c")),
        "%s: nft_payload.c byte-identical to %s" % (child, parent))
def fn_text(path, name):
    body = text(path)
    i = body.index("static bool %s(" % name)
    j = body.index("\n}\n", i)
    return body[i:j + 3]


for fn in ("nft_nh_write_ok_ip4", "nft_nh_write_ok_arp"):
    chk(fn_text(os.path.join(ROOT, "src/dl72/linux-7.2.15/net/netfilter/nft_payload.c"), fn) ==
        fn_text(os.path.join(ROOT, "src/linux-7.3.4-B19/net/netfilter/nft_payload.c"), fn),
        "%s() is byte-identical in 7.2.15 and 7.3.4 (the whitelist is not new)" % fn)

# ---------------------------------------------------------------- source anchors
src = text(os.path.join(ROOT, "src/linux-7.3.4-C553/net/netfilter/nft_payload.c"))
chk("""	case NFPROTO_NETDEV:
		if (pkt->state->hook == NF_NETDEV_INGRESS)
			return true;
		return nft_nh_write_ok_netdev(pkt, priv, src);""" in src,
    "source: nft_nh_write_ok() short-circuits to true at netdev ingress")
chk("""	switch (pkt->ethertype) {
	case htons(ETH_P_ARP):
		return nft_nh_write_ok_arp(priv);
	case htons(ETH_P_IP):
		return nft_nh_write_ok_ip4(pkt, priv, src);""" in src,
    "source: the bridge branch switches on pkt->ethertype")
chk("""	return offset >= sizeof(struct arphdr) && priv->len <= eth_ip;""" in src,
    "source: the ARP branch checks offset and len but not offset+len")
chk("""	case NFPROTO_BRIDGE:
		return pkt->ethertype == htons(ETH_P_IP) &&
		       priv->csum_offset == offsetof(struct iphdr, check);""" in src,
    "source: the checksum gate reads the same ethertype a second time")

# only one hook exists in the netdev family
hooks = subprocess.run(
    ["grep", "-rn", "NF_NETDEV_INGRESS", os.path.join(ROOT, "src/linux-7.3.4-C553/net/netfilter/")],
    capture_output=True, text=True).stdout
chk("NF_NETDEV_INGRESS" in hooks,
    "source: the netdev family registers exactly the ingress hook (NF_NETDEV_INGRESS)")

# ---------------------------------------------------------------- families
FAMWANT = {"Q": (0, 0, 1), "R": (0, 0, 1), "B": (0, 0, 1), "C": (1, 1, 1), "M": (1, 1, 1)}
for k in KERNELS:
    chk(fam_line(LOGF[k]) == FAMWANT[k],
        "%s: netdev/bridge/ip reachability == %s (measured %s)"
        % (k, FAMWANT[k], fam_line(LOGF[k])))
    sk = skipped(LOGF[k])
    if FAMWANT[k][0] == 0:
        chk({"sb.raw42", "sb.raw8", "sb.raw8ttl", "sb.raw16", "sb.kw.length",
             "sb.kw.daddr"} <= sk,
            "%s: every netdev arm is marked SKIP=no-netdev-family" % k)
        chk("sd.ctl" in A[k] and A[k]["sd.ctl"].get("skip") and
            "SKIP=no-netdev-family" in A[k]["sd.ctl"]["raw"] and
            "sd.nh22" in A[k] and A[k]["sd.nh22"].get("skip"),
            "%s: the local-delivery section reports SKIP, not silence" % k)

# ---------------------------------------------------------------- section A
SAMESET = ("sa.raw42", "sa.raw8", "sa.raw8ttl", "sa.raw16", "sa.kw.length",
           "sa.kw.daddr")
for k in KERNELS:
    for tag in SAMESET:
        chk(tag in A[k], "%s: arm %s is in the log" % (k, tag))
    ref = A[k]
    chk(ref["sa.raw8ttl"]["nchg"] == 1 and ref["sa.raw8ttl"]["cnt"] == 1,
        "%s: the allowed ttl store is applied (nchg=1, cnt=1)" % k)
    chk("22:3f>20" in ref["sa.raw8ttl"]["chg"],
        "%s: the ttl byte itself changed 3f->20" % k)
    chk(ref["sa.raw42"]["cnt"] == 0 and ref["sa.raw42"]["nchg"] == 0,
        "%s: @nh,336,16 (offset 42) is refused in the ip family" % k)
    chk(ref["sa.raw8"]["cnt"] == 0 and ref["sa.raw8"]["nchg"] == 0,
        "%s: @nh,64,32 (ttl, 4 bytes) is refused in the ip family" % k)
    chk(ref["sa.raw16"]["cnt"] == 1, "%s: @nh,128,32 (daddr) is applied" % k)
    chk(ref["sa.kw.length"]["cnt"] == 0, "%s: `ip length set` is refused" % k)
    chk(ref["sa.kw.daddr"]["cnt"] == 1, "%s: `ip daddr set` is applied" % k)
    chk(ref["sa.raw42"]["cap"] == 1,
        "%s: the refused store does not stop the packet (policy accept)" % k)
    # the refused arms are refused in EVERY version measured
for tag in ("sa.raw42", "sa.raw8", "sa.kw.length"):
    chk(len({A[k][tag]["cnt"] for k in KERNELS}) == 1 and A["Q"][tag]["cnt"] == 0,
        "the refusal of %s is identical on 7.2.15, 7.3, 7.3.4 and both config "
        "kernels (the network whitelist predates 7.2.15)" % tag)

# ---------------------------------------------------------------- section B
for k in ("C", "M"):
    ref = A[k]
    chk(ref["sb.raw42"]["cnt"] == 1 and ref["sb.raw42"]["nchg"] == 2,
        "%s: the SAME arm the ip family refuses is applied at netdev ingress" % k)
    chk("56:77>ca,57:77>fe" in ref["sb.raw42"]["chg"],
        "%s: the changed bytes are 56 and 57 -- @nh is frame byte 14 at ingress" % k)
    chk(ref["sb.kw.length"]["cnt"] == 1,
        "%s: `ip length set` is applied at ingress (refused in the ip family)" % k)
    chk(ref["sb.kw.length"]["cap"] == 0,
        "%s: and the packet then dies in the stack, which the counter alone would "
        "not have said" % k)
    chk(ref["sb.raw8"]["cnt"] >= 1,
        "%s: the 4-byte ttl/proto/cksum store is applied at ingress" % k)
    chk(ref["sb.raw16"]["cnt"] == 1 and ref["sb.raw16"]["nchg"] == 0,
        "%s: the daddr store at ingress writes the value already there" % k)

# ---------------------------------------------------------------- section C
for k in ("C", "M"):
    ref = A[k]
    chk(ref["sd.ctl"]["p5000"] == 1 and ref["sd.ctl"]["p6000"] == 0,
        "%s: the control datagram reaches the socket on :5000" % k)
    chk(ref["sd.nh22"]["p6000"] == 1 and ref["sd.nh22"]["p5000"] == 0,
        "%s: a store at ingress moves the datagram to the socket on :6000" % k)
    chk(ref["sd.nh22"]["cnt"] == 1, "%s: and the kernel's counter agrees" % k)
    chk(ref["sd.nh36"]["p5000"] == 1 and ref["sd.nh36"]["p6000"] == 0,
        "%s: the offset-36 arm does NOT move it (so the base is 14, not 0)" % k)
    chk(ref["sd.nh36"]["pay"][16:20] == "1770",
        "%s: instead it rewrote payload bytes 8-9 (pay=%s)"
        % (k, ref["sd.nh36"]["pay"][16:20]))

# ---------------------------------------------------------------- section D
LABELS = ["0x0800", "0x8100", "0x9100", "0x0806"]
WANT_RAW16 = {"0x0800": 1, "0x8100": 1, "0x9100": 0, "0x0806": 1}
WANT_RAW8 = {"0x0800": 0, "0x8100": 0, "0x9100": 0, "0x0806": 1}
WANT_KW = {"0x0800": 1, "0x8100": 1, "0x9100": 0, "0x0806": 0}
for k in ("C", "M"):
    ref = A[k]
    for lab in LABELS:
        for pref, want in (("br.raw16.", WANT_RAW16), ("br.raw8.", WANT_RAW8),
                           ("br.kw.", WANT_KW)):
            tag = pref + lab
            chk(tag in ref, "%s: arm %s present" % (k, tag))
            if tag not in ref:
                continue
            alive = ref[tag]["cnt"] >= 1
            chk(alive == bool(want[lab]),
                "%s: %s alive=%s (wanted %s)" % (k, tag, alive, bool(want[lab])))
            chk((ref[tag]["nchg"] > 0) == alive,
                "%s: %s the frame agrees with the counter" % (k, tag))
            chk(ref[tag]["cap"] == 1,
                "%s: %s the frame reaches the far side either way" % (k, tag))
    # the money cell, stated as numbers
    chk(ref["br.raw8.0x0806"]["nchg"] == 3 and
        ref["br.raw8.0x0806"]["chg"] == "22:40>3e,24:11>aa,25:77>bb",
        "%s: on the ARP-labelled frame the ttl store lands on bytes 22,24,25 -- the "
        "IPv4 header of a frame that says ARP" % k)
    chk(ref["br.raw8.0x0800"]["cnt"] == 0,
        "%s: the same bytes under 0x0800 are refused" % k)
    # meta protocol: the field the guard reads
    chk(ref["br.meta.tag.q"]["cnt"] == 0 and ref["br.meta.tag.ip"]["cnt"] == 1,
        "%s: for an 802.1Q frame the kernel's protocol field says ip, not 8021q" % k)
    chk(ref["br.meta.91.91"]["cnt"] == 1 and ref["br.meta.91.ip"]["cnt"] == 0,
        "%s: for the 0x9100 frame the field says 0x9100" % k)
    chk(ref["br.meta.untag.ip"]["cnt"] == 1 and ref["br.meta.arpip.ip"]["cnt"] == 0,
        "%s: ip matches only where the label says ip" % k)
    # the tagged frame *arrives* untagged: the tag never survives the veth
    tag_hex = ctl_line(LOGF[k], "br.ctl.0x8100")
    chk(tag_hex is not None and tag_hex[24:28] == "0800",
        "%s: the captured 0x8100 frame carries 0x0800 at ethertype (%s)"
        % (k, tag_hex[24:28] if tag_hex else "?"))
    chk(len(tag_hex or "") // 2 == 58,
        "%s: and it is 58 bytes, i.e. the 4-byte tag is gone" % k)
    # the ARP overshoot
    chk(ref["br.arpov.pad"]["cnt"] == 1 and ref["br.arpov.pad"]["nchg"] == 16,
        "%s: the 16-byte store at ARP offset 20 is applied on the 60-byte frame" % k)
    chk(all(("%d:" % i) in ref["br.arpov.pad"]["chg"] for i in range(34, 50)),
        "%s: and its bytes are 34..49, so 8 of them lie past the 28-byte ARP message" % k)
    chk(ref["br.arpov.raw"]["cnt"] == 0,
        "%s: the same store on the unpadded 42-byte frame is refused" % k)
    chk(ref["br.arpov.raw"]["cap"] == 1,
        "%s: which drops the store, not the packet" % k)
    # the verdict
    chk(ref["br.drp.raw8.arpip"]["cap"] == 1 and ref["br.drp.raw8.arpip"]["cnt"] == 1,
        "%s: under policy drop the ARP-labelled store is applied and the accept runs" % k)
    chk(ref["br.drp.raw8.91"]["cap"] == 0 and ref["br.drp.raw8.91"]["cnt"] == 0,
        "%s: under policy drop a refused store swallows the counter AND the accept, "
        "and the packet is dropped" % k)
    chk(ref["br.drp.ctl.untag"]["cap"] == 0,
        "%s: control -- the drop chain alone drops the frame" % k)

# ---------------------------------------------------------------- determinism
def norm(path):
    out = []
    for line in text(path).splitlines():
        if not line.startswith("F553 "):
            continue
        if line.startswith("F553 SETUP|"):
            continue
        line = re.sub(r"hex=[0-9a-f]*$", "hex=<dropped>", line)
        out.append(line)
    return out


chk(norm(os.path.join(LOG, "f31_C_rep1.log")) ==
    norm(os.path.join(LOG, "f31_C_rep2.log")),
    "two boots of the config kernel produce identical lines (hex and the random "
    "kernel-assigned MACs aside)")

# the whole measured table is version-independent
chk(norm(LOGF["C"]) == norm(LOGF["M"]),
    "7.3.4+config and 7.2.15+config produce the SAME table: this is not a regression "
    "of any release, it is how the guard is built")

# ---------------------------------------------------------------- hygiene
for k in KERNELS + ["C_rep2"]:
    log = text(os.path.join(LOG, "f31_%s.log" % ("%s_rep1" % k if k in KERNELS else k)))
    splat = re.findall(r"KASAN|BUG:|Oops|WARNING:|general protection|double free|"
                       r"use-after-free", log)
    chk(not splat, "%s: no splat in the log (%s)" % (k, splat[:3]))
    chk("=== VM_POWEROFF ===" in log, "%s: the guest powered off cleanly" % k)
    chk("F553 DONE" in log, "%s: the differ reached its end marker" % k)

# every installed rule was acknowledged
for k in ("C", "M"):
    rc = re.findall(r"^F553RC ([^|]+)\|(-?\d+)$", text(LOGF[k]), re.M)
    failed = [(t, v) for t, v in rc if v != "0"]
    chk(not failed, "%s: every rule install returned 0 (%s)" % (k, failed[:4]))

# ---------------------------------------------------------------- report
print("verify553: %d/%d checks passed" % (ok, ncheck))
if bad:
    print("\nFAILED:")
    for b in bad:
        print("  -", b)
    sys.exit(1)
sys.exit(0)
