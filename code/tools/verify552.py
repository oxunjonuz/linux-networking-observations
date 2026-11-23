#!/usr/bin/env python3
"""verify552.py -- independent checks for turn 552 (F30).

Nothing here trusts the instrument's own verdict lines.  Every claim is
recomputed from a second source:

  * the kernel images and initrds are hashed, and the differ binary and the
    nft binary are read *out of* the initrd and hashed;
  * every declared store geometry is recomputed from nft's own
    --debug=netlink message and checked against the field table in
    src/dl23/nftables-1.1.7/src/proto.c (bit offset / bit length), with the
    offsets themselves coming from the compiler (tools/f30_offsets.c), not
    from my reading;
  * for every frame nft itself declares the mask and the xor, and the captured
    frame is recomputed from the control frame with that mask -- so "the store
    happened" is a byte-level identity, not an inference;
  * for the raw sweep the guard's verdict is recomputed in Python from the
    whitelist whose constants come from the offsets probe and whose membership
    is asserted against the case labels in nft_payload.c, and compared with the
    counter the kernel actually incremented.

Usage: python3 tools/verify552.py [--logs DIR]
"""
import gzip
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, 'logs')

OK = 0
FAIL = 0
FAILED = []


def check(name, cond, detail=''):
    global OK, FAIL
    if cond:
        OK += 1
    else:
        FAIL += 1
        FAILED.append(name + (' :: ' + str(detail) if detail else ''))
        print('  FAIL %s %s' % (name, detail))


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def read(p):
    with open(p, 'r', errors='replace') as f:
        return f.read()


def cpio_members(path):
    """newc archive -> {name: bytes}, with the 4-byte alignment of both the
    header name field and the file body."""
    raw = gzip.open(path, 'rb').read()
    out = {}
    i = 0
    while i + 110 <= len(raw):
        hdr = raw[i:i + 110]
        if hdr[:6] not in (b'070701', b'070702'):
            break

        def fld(o):
            return int(hdr[o:o + 8], 16)

        filesize = fld(54)
        namesize = fld(94)
        name = raw[i + 110:i + 110 + namesize - 1].decode('utf-8', 'replace')
        off = i + 110 + namesize
        off += (4 - off % 4) % 4
        body = raw[off:off + filesize]
        i = off + filesize
        i += (4 - i % 4) % 4
        name = name.lstrip('./')
        out[name] = body
        if name == 'TRAILER!!!':
            break
    return out


# ---------------------------------------------------------------- provenance

KERNELS = {
    'Q': ('src/dl72/linux-7.2.15/arch/x86/boot/bzImage', '7.2.15'),
    'R': ('src/linux-7.3-R19/arch/x86/boot/bzImage', '7.3.'),
    'B': ('src/linux-7.3.4-B19/arch/x86/boot/bzImage', '7.3.4'),
    'G': ('src/linux-7.3.4-P549/arch/x86/boot/bzImage', '7.3.4'),
    'P': ('src/linux-7.3.4-P548/arch/x86/boot/bzImage', '7.3.4'),
}

RUNS = ['B_rep1', 'B_rep2', 'Q_rep1', 'R_rep1', 'G_rep1', 'P_rep1']
NFT_SHA = '77d83a42'


LOGSDIR = [LOGS]


def logtext(tag):
    return read(os.path.join(LOGSDIR[0], 'f30_%s.log' % tag))


def provenance(runs):
    print('== provenance ==')
    differ = os.path.join(ROOT, 'vm/build/differ552')
    dsha = sha256_file(differ)
    for tag in runs:
        t = logtext(tag)
        m = re.search(r'^### kernel: (\S+)$', t, re.M)
        m2 = re.search(r'^### sha256: ([0-9a-f]{64})$', t, re.M)
        m3 = re.search(r'^### initrd: (\S+)$', t, re.M)
        m4 = re.search(r'^### initrd sha256: ([0-9a-f]{64})$', t, re.M)
        check('%s.header' % tag, bool(m and m2 and m3 and m4))
        if not (m and m2 and m3 and m4):
            continue
        img = m.group(1)
        check('%s.kernel_hash' % tag, sha256_file(img) == m2.group(1), img)
        check('%s.initrd_hash' % tag,
              sha256_file(m3.group(1)) == m4.group(1), m3.group(1))
        ver = KERNELS[tag[0]][1]
        mv = re.search(r'^Linux version (\S+)', t, re.M)
        check('%s.kernel_version' % tag, bool(mv) and mv.group(1).startswith(ver),
              mv.group(1) if mv else 'none')
        check('%s.boot_ok' % tag, 'VM_BOOT_OK' in t)
        check('%s.done' % tag, 'F552 DONE' in t)
        # the two binaries, read out of the archive the guest actually ran
        mem = cpio_members(m3.group(1))
        check('%s.differ_in_initrd' % tag,
              'root/repro' in mem and hashlib.sha256(mem['root/repro']).hexdigest() == dsha)
        check('%s.nft_in_initrd' % tag,
              'nft' in mem and hashlib.sha256(mem['nft']).hexdigest().startswith(NFT_SHA))
        check('%s.nft_version' % tag, 'nftables v1.1.7' in t)
        # no splat
        check('%s.no_splat' % tag,
              not re.search(r'KASAN|BUG:|Oops|WARNING:', t))


# ------------------------------------------------------------------- parsing

def parse_lines(t, prefix):
    return [l for l in t.splitlines() if l.startswith(prefix)]


def parse_f552(t):
    """F552 <tag>|k=v|...|hex=...  ->  {tag: {k: v, 'hex': bytes}}"""
    out = {}
    for l in t.splitlines():
        if not l.startswith('F552 ') or '|hex=' not in l:
            continue
        body = l[5:]
        tag, _, rest = body.partition('|')
        kv = {}
        hexs = ''
        for part in rest.split('|'):
            if '=' in part:
                k, _, v = part.partition('=')
                kv[k] = v
        if 'hex=' in rest:
            hexs = rest.split('hex=', 1)[1].strip()
        d = {}
        for k, v in kv.items():
            if k == 'hex':
                continue
            d[k] = int(v) if re.fullmatch(r'-?\d+', v) else v
        d['hex'] = bytes.fromhex(hexs) if re.fullmatch(r'[0-9a-fA-F]*', hexs) else b''
        out[tag] = d
    return out


def parse_kv(t, prefix, tagfield=True):
    """F552XXX <tag>|k=v|... -> {tag: {k:v}}"""
    out = {}
    for l in t.splitlines():
        if not l.startswith(prefix + ' '):
            continue
        body = l[len(prefix) + 1:]
        if tagfield:
            tag, _, rest = body.partition('|')
        else:
            tag, _, rest = body.partition(' ')
        d = {}
        for part in rest.split('|') if tagfield else [rest]:
            if '=' in part:
                k, _, v = part.partition('=')
                d[k] = int(v) if re.fullmatch(r'-?\d+', v) else v
        out[tag] = d
    return out


def parse_b(t):
    out = {}
    for l in t.splitlines():
        m = re.match(r'F552 B(\d)\.(\S+)\|off=(\d+)\|len=(\d+)\|keep=(\d+)\|'
                     r'csum=(\d+)\|bad=(\d+)\|sent=(\d+)\|cap=(\d+)\|deliv=(\d)', l)
        if m:
            out[(int(m.group(1)), m.group(2))] = {
                'off': int(m.group(3)), 'len': int(m.group(4)),
                'keep': int(m.group(5)), 'csum': int(m.group(6)),
                'bad': int(m.group(7)), 'deliv': int(m.group(10)),
                'cap': int(m.group(9))}
        m = re.match(r'F552 B(\d)\.(\S+)\|setup=ERR\|errno=(-?\d+)', l)
        if m:
            out[(int(m.group(1)), m.group(2))] = {'err': int(m.group(3))}
    return out


def parse_cnt(t):
    out = {}
    for l in t.splitlines():
        m = re.match(r'F552CNT (\d)\.(\S+)\|pkts=(\d+)', l)
        if m:
            out[(int(m.group(1)), m.group(2))] = int(m.group(3))
    return out


def parse_ca_counter(t):
    """the counter nft prints for an A-section arm: 'F552CA <fam>.<tag> ... counter packets N'"""
    out = {}
    for l in t.splitlines():
        if not l.startswith('F552CA '):
            continue
        m = re.match(r'F552CA (\S+) .*counter packets (\d+)', l)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def parse_nl(t):
    out = {}
    for l in t.splitlines():
        if not l.startswith('F552NL '):
            continue
        body = l[len('F552NL '):]
        tag, _, nl = body.partition(' ')
        out.setdefault(tag, []).append(nl)
    return out


def parse_rc(t):
    out = {}
    for l in t.splitlines():
        m = re.match(r'F552RC (\S+) (\d+)', l)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


# --------------------------------------------------------- geometry vs proto.c

PROTO_C = os.path.join(ROOT, 'src/dl23/nftables-1.1.7/src/proto.c')

BLOCK = {
    'ip': 'const struct proto_desc proto_ip = {',
    'ip6': 'const struct proto_desc proto_ip6 = {',
}

# byte sizes of the whole fields the network guard names, by kernel member
MEMBER_SIZE = {
    'tot_len': 16, 'id': 16, 'frag_off': 16, 'check': 16,
    'ttl': 8, 'protocol': 8, 'payload_len': 16, 'nexthdr': 8, 'hop_limit': 8,
}


def proto_field(fam, name, offsets):
    """(bit offset, bit length) of a payload template, from proto.c, scoped to
    the family's own protocol table (proto_ip and proto_ip6 both have a
    `dscp`, at different offsets)."""
    src = read(PROTO_C)
    start = src.index(BLOCK[fam])
    end = src.find('const struct proto_desc ', start + 10)
    block = src[start:end if end > 0 else len(src)]
    m = re.search(r'(HDR_BITFIELD|HDR_HEX_FIELD|IPHDR_FIELD|IP6HDR_FIELD|'
                  r'IPHDR_ADDR|IP6HDR_ADDR|INET_PROTOCOL|HDR_FIELD)\("%s"' % re.escape(name), block)
    if not m:
        return None, 'no template for %s in proto_%s' % (name, fam)
    line = block[m.start():block.find('\n', m.start())]
    if m.group(1) == 'HDR_BITFIELD':
        nums = re.findall(r'\b(\d+)\b', line.split('(', 1)[1])
        if len(nums) < 2:
            return None, 'cannot read the bitfield ' + line
        return (int(nums[-2]), int(nums[-1])), ''
    member = line.rstrip(',').rsplit(',', 1)[1].strip().rstrip(')')
    key = ('ip4.' if fam == 'ip' else 'ip6.') + member
    if key not in offsets:
        return None, 'no offset probe for ' + member
    size = MEMBER_SIZE.get(member)
    if size is None:
        size = 32 if member in ('saddr', 'daddr') and fam == 'ip' else 128
    return (offsets[key] * 8, size), ''


def load_offsets():
    out = {}
    for l in read(os.path.join(ROOT, 'research/f30_offsets.txt')).splitlines():
        k, _, v = l.partition(' ')
        out[k] = int(v)
    return out


def check_geometry(fam, field, off_bytes, len_bytes, offsets):
    """the declared store must cover the field, on a byte boundary consistent
    with the family's alignment: nft rounds a store up to an even width at an
    even offset only when the protocol carries a checksum."""
    bf, why = proto_field(fam, field, offsets)
    if bf is None:
        return None, why
    bitoff, bitlen = bf
    lo = off_bytes * 8
    hi = lo + len_bytes * 8
    if not (lo <= bitoff and hi >= bitoff + bitlen):
        return False, 'does not cover the field: %d..%d vs %d..%d' % (
            lo, hi, bitoff, bitoff + bitlen)
    if fam == 'ip':
        # the csum fixup forbids odd widths at odd offsets
        if off_bytes % 2 or len_bytes % 2:
            return False, 'ip store not even-aligned'
        return True, ''
    # ip6: no csum key, so the store starts at the byte that holds the field
    if lo != (bitoff // 8) * 8:
        return False, 'ip6 store does not start on the field byte'
    if hi < bitoff + bitlen:
        return False, 'ip6 store too short'
    return True, ''


# ---------------------------------------------------- the guard, in Python

def guard_ip4(off, length, byte0_same, proto_same):
    if off == 0:
        return length == 2 and byte0_same
    if off == 1:
        return length == 1
    if off == 4:
        return length == 2
    if off == 8:
        return length == 1 or (length == 2 and proto_same)
    if off == 10:
        return length <= 10
    if off == 12:
        return length <= 8
    if off == 16:
        return length <= 4
    return False


def guard_ip6(off, length, version6=True):
    if off == 0:
        return length <= 4 and version6
    if off == 2:
        return length <= 2
    if off == 7:
        return length == 1
    if off == 8:
        return length <= 32
    if off == 24:
        return length <= 16
    return False


def source_has_cases():
    """the whitelist is asserted against the source: every field the Python
    guard knows must appear as a case label in the right function."""
    src = read(os.path.join(ROOT, 'src/linux-7.3.4-B19/net/netfilter/nft_payload.c'))
    i4 = src[src.index('static bool nft_nh_write_ok_ip4'):]
    i4 = i4[:i4.index('\n}\n')]
    i6 = src[src.index('static bool nft_nh_write_ok_ip6'):]
    i6 = i6[:i6.index('\n}\n')]
    ll = src[src.index('static bool nft_ll_write_ok'):]
    ll = ll[:ll.index('\n}\n')]
    want4 = ['version', 'tos', 'id', 'ttl', 'check', 'saddr', 'daddr']
    want6 = ['hop_limit', 'saddr', 'daddr']
    res = {}
    for f in want4:
        if f == 'version':
            res['ip4.version'] = 'case 0:' in i4
        else:
            res['ip4.' + f] = ('case offsetof(struct iphdr, %s):' % f) in i4
    for f in want6:
        res['ip6.' + f] = ('case offsetof(struct ipv6hdr, %s):' % f) in i6
    res['ip6.flow'] = 'case 2:' in i6
    res['ll.boundary'] = 'offset <= skb_network_offset(pkt->skb)' in ll
    return res


# ---------------------------------------------------------------- the checks

A4_TAGS = ['ip.ctl.none', 'ip.ip.dscp', 'ip.ip.ecn', 'ip.ip.id', 'ip.ip.ttl',
           'ip.ip.checksum', 'ip.ip.saddr', 'ip.ip.version4', 'ip.ip.version6',
           'ip.ip.hdrlength5', 'ip.ip.hdrlength6', 'ip.ip.length',
           'ip.ip.fragoff', 'ip.ip.protocol']
A6_TAGS = ['ip6.ctl.none', 'ip6.ip6.dscp', 'ip6.ip6.ecn', 'ip6.ip6.flowlabel',
           'ip6.ip6.hoplimit', 'ip6.ip6.saddr', 'ip6.ip6.daddr',
           'ip6.ip6.version6', 'ip6.ip6.version5', 'ip6.ip6.length',
           'ip6.ip6.nexthdr']
LL_TAGS = ['ll.ctl.none', 'll.ll.saddr', 'll.ll.daddr', 'll.ll.type',
           'll.ll.raw0', 'll.ll.raw96', 'll.ll.raw112', 'll.ll.raw0_128']

FIELD = {
    'ip.ip.dscp': 'dscp', 'ip.ip.ecn': 'ecn', 'ip.ip.id': 'id',
    'ip.ip.ttl': 'ttl', 'ip.ip.checksum': 'checksum', 'ip.ip.saddr': 'saddr',
    'ip.ip.version4': 'version', 'ip.ip.version6': 'version',
    'ip.ip.hdrlength5': 'hdrlength', 'ip.ip.hdrlength6': 'hdrlength',
    'ip.ip.length': 'length', 'ip.ip.fragoff': 'frag-off',
    'ip.ip.protocol': 'protocol',
    'ip6.ip6.dscp': 'dscp', 'ip6.ip6.ecn': 'ecn',
    'ip6.ip6.flowlabel': 'flowlabel', 'ip6.ip6.hoplimit': 'hoplimit',
    'ip6.ip6.saddr': 'saddr', 'ip6.ip6.daddr': 'daddr',
    'ip6.ip6.version6': 'version', 'ip6.ip6.version5': 'version',
    'ip6.ip6.length': 'length', 'ip6.ip6.nexthdr': 'nexthdr',
}


def nl_geometry(nl_lines):
    """(offset, len, mask, xor, csum_type, csum_flags) from nft's own message"""
    off = ln = None
    mask = xor = None
    csum_type = csum_flags = 0
    for l in nl_lines:
        m = re.search(r'payload write reg \d+ => (\d+)b @ network header \+ (\d+)'
                      r' csum_type (\d+) csum_off \d+ csum_flags (0x[0-9a-f]+)', l)
        if m:
            ln, off = int(m.group(1)), int(m.group(2))
            csum_type = int(m.group(3))
            csum_flags = int(m.group(4), 16)
        m = re.search(r'bitwise reg \d+ = \( reg \d+ & (0x[0-9a-f]+) \) \^ (0x[0-9a-f]+)', l)
        if m:
            mask = int(m.group(1), 16)
            xor = int(m.group(2), 16)
        m = re.search(r'immediate reg \d+((?: 0x[0-9a-f]+)+)', l)
        if m and mask is None:
            words = re.findall(r'0x([0-9a-f]+)', m.group(1))
            mask = 0
            xor = int(''.join(w.zfill(8) for w in words), 16)
    return off, ln, mask, xor, csum_type, csum_flags


def sections_a(t, fam, tags, offsets):
    print('== A: %s spellings ==' % fam)
    f = parse_f552(t)
    nl = parse_nl(t)
    ca = parse_ca_counter(t)
    rc = parse_rc(t)
    ctl = f.get('%s.ctl.none' % fam, {}).get('hex', b'')
    check('%s.control_frame' % fam, len(ctl) > 40, len(ctl))
    for tag in tags:
        d = f.get(tag)
        check('%s.present' % tag, d is not None)
        if not d:
            continue
        check('%s.nft_rc0' % tag, rc.get(tag) == 0, rc.get(tag))
        if tag.endswith('ctl.none'):
            check('%s.ctl_nochg' % tag, d['nchg'] == 0 and d['hex'] == ctl)
            continue
        off, ln, mask, xor, ctype, cflags = nl_geometry(nl.get(tag, []))
        check('%s.geometry_found' % tag, off is not None and ln is not None)
        if off is None:
            continue
        field = FIELD.get(tag)
        good, why = check_geometry('ip' if fam == 'ip' else 'ip6', field, off, ln, offsets)
        check('%s.geometry_covers_field' % tag, good is True, '%s %s' % ((off, ln), why))
        cnt = ca.get(tag)
        if cnt is None:
            # no counter text: nft cannot print the rule (see F23) -- the frame decides
            cnt = 1 if d['nchg'] else 0
        if cnt == 1:
            # the frame must be the control with nft's own mask applied
            # the write offset nft declares is relative to the *network
            # header*.  The IPv4 probe returns the datagram (L2 already
            # stripped), the IPv6 probe returns the frame (14-byte Ethernet
            # header in front), so the frame position differs by that much.
            base2 = 0 if fam == 'ip' else 14
            pred = bytearray(ctl)
            width = ln
            mb = mask.to_bytes(width, 'big')
            xb = xor.to_bytes(width, 'big')
            for i in range(width):
                pred[base2 + off + i] = (ctl[base2 + off + i] & mb[i]) ^ xb[i]
            # bytes the kernel is allowed to update on its own: the checksum
            # fields the message declared
            # checksum fields the kernel updates by itself, in the
            # coordinates of what the probe captured: the IPv4 datagram
            # (L2 stripped) or the whole frame (L2 in front)
            allow = set()
            if fam == 'ip':
                allow |= {10, 11}            # IPv4 header checksum
                if cflags:
                    allow |= {36, 37}        # TCP checksum, pseudo-header
            elif cflags:
                allow |= {14 + 40 + 16, 14 + 40 + 17}   # TCP checksum
            bad = []
            for i in range(min(len(pred), len(d['hex']))):
                if i in allow:
                    continue
                if d['hex'][i] != pred[i]:
                    bad.append((i, '%02x' % ctl[i], '%02x' % d['hex'][i],
                                '%02x' % pred[i]))
            check('%s.frame_is_mask_applied' % tag, not bad, bad[:4])
            check('%s.store_visible' % tag, d['nchg'] > 0 or pred == ctl)
        else:
            check('%s.refused_frame_identical' % tag, d['nchg'] == 0 and d['hex'] == ctl,
                  d['nchg'])


def parse_ll(t):
    out = {}
    for l in t.splitlines():
        m = re.match(r'F552 (ll\.\S+)\|rule=(.*?)\|sent=(\d+)\|cap=(\d+)\|'
                     r'flen=(\d+)\|deliv=(\d)', l)
        if m:
            out[m.group(1)] = {'rule': m.group(2), 'sent': int(m.group(3)),
                               'cap': int(m.group(4)), 'deliv': int(m.group(6))}
    return out


def section_ll(t):
    print('== A0: link base ==')
    f = parse_ll(t)
    v = parse_kv(t, 'F552V', tagfield=False)
    for tag in LL_TAGS:
        d = f.get(tag)
        check('%s.present' % tag, d is not None)
        if not d:
            continue
        if tag.endswith('ctl.none'):
            check('%s.ctl_dropped' % tag, d['cap'] == 0)
            continue
        rule = d['rule']
        m = re.search(r'@ll,(\d+),(\d+)', rule)
        if m:
            end = (int(m.group(1)) + int(m.group(2))) // 8
        else:
            end = {'ll.ll.saddr': 6, 'll.ll.daddr': 6, 'll.ll.type': 14}[tag]
        want = 1 if end <= 14 else 0
        cnt = None
        for line in t.splitlines():
            if line.startswith('F552V %s ' % tag) and 'counter packets' in line:
                cnt = int(re.search(r'counter packets (\d+)', line).group(1))
        check('%s.counter_read' % tag, cnt is not None)
        check('%s.boundary_predicate' % tag, cnt == want, 'end=%d cnt=%s want=%d' % (end, cnt, want))
        check('%s.deliv_matches' % tag, d['deliv'] == want, (d['deliv'], want))


def section_raw(t, offsets, src_cases):
    print('== B: the predicate as a function ==')
    b = parse_b(t)
    cnt = parse_cnt(t)
    verdicts = {}
    for fam, maxoff in ((4, 20), (6, 40)):
        for off in range(maxoff):
            for ln in (1, 2):
                verdicts[(fam, '%d.%d' % (off, ln))] = True
        for (f2, tag) in b:
            if f2 == fam:
                verdicts[(fam, tag)] = True
    for (fam, tag) in sorted(verdicts):
        a = b.get((fam, tag))
        check('B%d.%s.present' % (fam, tag), a is not None)
        if not a:
            continue
        if 'err' in a:
            check('B%d.%s.init_refused' % (fam, tag), True, a['err'])
            continue
        if a['len'] == 0:
            # the control arm: a rule with only a verdict, no store and no counter
            check('B%d.%s.control_delivers' % (fam, tag), a['deliv'] == 1)
            continue
        if fam == 4:
            want = guard_ip4(a['off'], a['len'], not (a['bad'] == 1), not (a['bad'] == 2))
        else:
            want = guard_ip6(a['off'], a['len'], version6=not (a['bad'] == 1))
        check('B%d.%s.counter_read' % (fam, tag), (fam, tag) in cnt)
        if (fam, tag) not in cnt:
            continue
        check('B%d.%s.predicate' % (fam, tag), (cnt[(fam, tag)] > 0) == want,
              'off=%d len=%d cnt=%d want=%d' % (a['off'], a['len'], cnt[(fam, tag)], want))
        # the instrument's own deliv flag is a weaker oracle; it may only say
        # "delivered" when the guard allowed the store
        check('B%d.%s.deliv_implies_allowed' % (fam, tag),
              not a['deliv'] or want or a['off'] + a['len'] > (16 if fam == 4 else 24),
              'off=%d len=%d deliv=%d' % (a['off'], a['len'], a['deliv']))
    check('offsets.ip4.tos', offsets['ip4.tos'] == 1)
    check('offsets.ip4.id', offsets['ip4.id'] == 4)
    check('offsets.ip4.ttl', offsets['ip4.ttl'] == 8)
    check('offsets.ip4.check', offsets['ip4.check'] == 10)
    check('offsets.ip4.saddr', offsets['ip4.saddr'] == 12)
    check('offsets.ip4.daddr', offsets['ip4.daddr'] == 16)
    check('offsets.ip6.hop_limit', offsets['ip6.hop_limit'] == 7)
    check('offsets.ip6.saddr', offsets['ip6.saddr'] == 8)
    check('offsets.ip6.daddr', offsets['ip6.daddr'] == 24)
    for k, v in src_cases.items():
        check('source.case.%s' % k, v)


def parse_c(t):
    out = {}
    for l in t.splitlines():
        m = re.match(r'F552 (C\.\S+)\|rule=(.*?)\|nftrc=(-?\d+)\|sent=(\d+)\|'
                     r'cap=(\d+)\|deliv=(\d)', l)
        if m:
            out[m.group(1)] = {'rule': m.group(2), 'nftrc': int(m.group(3)),
                               'sent': int(m.group(4)), 'cap': int(m.group(5)),
                               'deliv': int(m.group(6))}
    return out


def section_c(t):
    print('== C: the consequence ==')
    f = parse_c(t)
    tags = (['C.ip.' + x for x in ['ctl.none'] + [a.split('.', 1)[1] for a in A4_TAGS[1:]]] +
            ['C.ip6.' + x for x in ['ctl.none'] + [a.split('.', 1)[1] for a in A6_TAGS[1:]]])
    for tag in tags:
        d = f.get(tag)
        check('%s.present' % tag, d is not None)
        if not d:
            continue
        check('%s.nftrc0' % tag, d['nftrc'] == 0, d['nftrc'])
        if tag.endswith('ctl.none'):
            check('%s.ctl_dropped' % tag, d['cap'] == 0)
            continue
        cnt = None
        for line in t.splitlines():
            if line.startswith('F552V %s ' % tag) and 'counter packets' in line:
                cnt = int(re.search(r'counter packets (\d+)', line).group(1))
        check('%s.counter_read' % tag, cnt is not None)
        check('%s.verdict_follows_store' % tag, (cnt == 1) == (d['deliv'] == 1),
              'cnt=%s deliv=%s' % (cnt, d['deliv']))


def normalise(t):
    """only the instrument's own lines (kernel boot chatter carries
    timestamps), and the pid that is part of the raw table name stripped"""
    keep = [l for l in t.splitlines() if l.startswith('F552')]
    return re.sub(r'p552_(\d)_\d+', r'p552_\1_PID', '\n'.join(keep))


def cross_kernel(texts):
    print('== the same on every kernel ==')
    base = texts['B_rep1']
    btags = parse_b(base)
    bcnt = parse_cnt(base)
    for tag in RUNS:
        if tag == 'B_rep1':
            continue
        o = parse_b(texts[tag])
        oc = parse_cnt(texts[tag])
        check('%s.same_arm_set' % tag, set(o) == set(btags))
        diff = [k for k in btags if k in o and bcnt.get(k) != oc.get(k)]
        check('%s.same_predicate' % tag, not diff, diff[:4])
        fa = parse_f552(texts[tag])
        fb = parse_f552(base)
        d2 = [k for k in A4_TAGS + A6_TAGS + LL_TAGS
              if k in fa and k in fb and fa[k].get('deliv') != fb[k].get('deliv')]
        check('%s.same_spelling_verdicts' % tag, not d2, d2[:4])


def determinism(texts):
    print('== determinism ==')
    a = parse_b(texts['B_rep1'])
    b = parse_b(texts['B_rep2'])
    check('det.same_arms', set(a) == set(b))
    check('det.same_counters', parse_cnt(texts['B_rep1']) == parse_cnt(texts['B_rep2']))
    fa = parse_f552(texts['B_rep1'])
    fb = parse_f552(texts['B_rep2'])
    bad = [k for k in fa if k in fb and fa[k].get('hex') != fb[k].get('hex')]
    check('det.same_frames', not bad, bad[:3])
    check('det.same_nl', normalise(texts['B_rep1']) == normalise(texts['B_rep2']))


def frozen():
    print('== frozen inputs ==')
    p = os.path.join(ROOT, 'logs/f30_frozen.txt')
    t = read(p)
    for line in t.splitlines():
        if ' ' not in line:
            continue
        sha, name = line.split(None, 1)
        f = os.path.join(ROOT, name.strip())
        if os.path.exists(f) and len(sha) == 64:
            check('frozen.%s' % os.path.basename(name.strip()),
                  sha256_file(f) == sha)


def main():
    logs = LOGS
    if '--logs' in sys.argv:
        logs = sys.argv[sys.argv.index('--logs') + 1]
        LOGSDIR[0] = logs
    runs = [r for r in RUNS
            if os.path.exists(os.path.join(logs, 'f30_%s.log' % r))]
    print('logs: %d runs' % len(runs))
    offsets = load_offsets()
    src_cases = source_has_cases()
    provenance(runs)
    texts = {r: read(os.path.join(logs, 'f30_%s.log' % r)) for r in runs}
    for r in runs:
        print('---- %s ----' % r)
        sections_a(texts[r], 'ip', A4_TAGS, offsets)
        section_ll(texts[r])
        sections_a(texts[r], 'ip6', A6_TAGS, offsets)
        section_raw(texts[r], offsets, src_cases)
        section_c(texts[r])
    if len(runs) > 1:
        determinism(texts)
        cross_kernel(texts)
    frozen()
    print('\n%d ok, %d failed' % (OK, FAIL))
    if FAILED:
        print('failures:')
        for f in FAILED:
            print('  ' + f)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
