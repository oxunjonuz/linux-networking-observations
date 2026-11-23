#!/usr/bin/env python3
"""verify584.py -- independent verification of the F62 (turn 584) instrument.

Reads the two boot logs of mode `gso` and re-derives every number the
instrument printed from a model written here, not there:

  P(L)      pseudo-header sum with the 32-bit length L
  seed(L)   = fold16(P(L))          the field of a CHECKSUM_PARTIAL datagram
  C(L, pay) = ~fold16(P(L) + H0(L) + sum(pay))

  the exit device segments (y2, no GSO_UDP_L4): for each segment
      check_i = csum16_sub(csum16_add(uh->check, ~uh->len), htons(len_i))
      field_i = ~fold16(H_i(len_i, check_i) + sum(pay_i))       (gso_make_checksum)
  the receiver segments (y1, GSO survives the wire): the same delta, but the
  segments stay CHECKSUM_PARTIAL, so skb_csum_unnecessary() says "do not check";

  a datagram is delivered iff (a) it is PARTIAL at the socket, or (b) its
  CHECKSUM_NONE field satisfies fold16(P + H + G) == 0xffff.

Usage: python3 tools/verify584.py [--quiet]
"""
import sys
import os
import re
import hashlib
import subprocess
import struct

ROOT = '/work/kernel-sec'
BOOTS = os.environ.get('F584_BOOTS',
                      'logs/f62_rep1.log,logs/f62_rep2.log').split(',')
SRC = 'vm/differ584_add.c'
KERNEL = 'src/linux-7.3.4-T563'

N = 0
FAIL = []
QUIET = '--quiet' in sys.argv


def eq(got, want, what):
    global N
    N += 1
    if got != want:
        FAIL.append((what, got, want))


def ok(cond, what):
    eq(bool(cond), True, what)


def sha(path):
    h = hashlib.sha256()
    with open(os.path.join(ROOT, path), 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- arithmetic

def fold32(w):
    while w >> 16:
        w = (w & 0xffff) + (w >> 16)
    return w & 0xffff


def fold16(b):
    if len(b) % 2:
        b = b + b'\x00'
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    return fold32(s)


def csum16(b):
    return (~fold16(b)) & 0xffff


def c16add(a, b):
    r = (a + b) & 0xffff
    return (r + 1) & 0xffff if r < b else r


def c16sub(a, b):
    return c16add(a, (~b) & 0xffff)


def hexb(s):
    return bytes.fromhex(s)


S6 = hexb('fd020000000000000000000000000011')
R6 = hexb('fd020000000000000000000000000091')
DA = hexb('fd030000000000000000000000000092')
DB = hexb('fd040000000000000000000000000092')
RA = hexb('fd030000000000000000000000000091')
RB = hexb('fd040000000000000000000000000091')

D = 1200
MSS = 512
SPORT = 43580
DPORT = 5000
DPORT_GRO = 5001
PAY = bytes(0x80 + (i & 0x7f) for i in range(D))
SEGS = [512, 512, 176]
L_TOTAL = 8 + D
FRAME = 14 + 40 + L_TOTAL             # 1262
SKB_L3 = 40 + L_TOTAL                 # 1248  (what udpv6_rcv() sees)


def pseudo(saddr, daddr, ln, proto=17):
    return saddr + daddr + struct.pack('!I', ln) + b'\x00\x00\x00' + bytes([proto])


def Psum(saddr, daddr, ln):
    return fold16(pseudo(saddr, daddr, ln))


def udp_hdr(sport, dport, ln, field):
    return struct.pack('!HHHH', sport, dport, ln, field)


def C_of(saddr, daddr, sport, dport, pay):
    ln = 8 + len(pay)
    return (~fold32(Psum(saddr, daddr, ln) +
                    fold16(udp_hdr(sport, dport, ln, 0) + pay))) & 0xffff


def valid_of(saddr, daddr, sport, dport, ln, field, pay):
    return fold32(Psum(saddr, daddr, ln) +
                  fold16(udp_hdr(sport, dport, ln, field) + pay)) == 0xffff


def frame(saddr, daddr, hop, sport, dport, ulen, field, pay):
    eth = b'\x00' * 12 + b'\x86\xdd'
    ip6 = bytes([0x60, 0, 0, 0]) + struct.pack('!H', 8 + len(pay)) + \
        bytes([17, hop]) + saddr + daddr
    return eth + ip6 + udp_hdr(sport, dport, ulen, field) + pay


def norm(fr):
    """zero the two MACs (the kernel picks them per boot) and the IPv6 flow
    label (also per boot) so two boots can be compared"""
    if fr is None:
        return None
    b = bytearray(fr)
    b[0:12] = b'\x00' * 12
    b[15] &= 0xf0
    b[16] = 0
    b[17] = 0
    return bytes(b)


# ---------------------------------------------------------------- the source

BASES = {'B584_NH': 1, 'B584_TH': 2, '0': 0}


def parse_arms():
    """the arm table, read out of the instrument's own source"""
    src = open(os.path.join(ROOT, SRC)).read()
    body = src.split('static const struct f584_arm AF584[] = {')[1]
    body = body.split('};')[0]
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    arms = []
    pat = (r'\{\s*"([a-z0-9_]+)"\s*,\s*\'([sp])\'\s*,\s*\'([ab])\'\s*,'
           r'\s*\'([pg])\'\s*,([^}]*)\}')
    for m in re.finditer(pat, body):
        name, prov, dst, skt, rest = m.groups()
        toks = [t.strip() for t in rest.split(',') if t.strip()]
        base = BASES[toks[1]]
        store, off, ln = int(toks[0]), int(toks[2]), int(toks[3])
        hexs = toks[4].strip('"')
        hexs = None if hexs == 'NULL' else hexs
        ct = 1 if toks[5] == 'NFT_PAYLOAD_CSUM_INET' else int(toks[5])
        co, cf = int(toks[6]), int(toks[7])
        arms.append(dict(i=len(arms), name=name, prov=prov, dst=dst,
                         skt=skt, store=store, base=base, off=off, len=ln,
                         hex=hexs, ct=ct, co=co, cf=cf))
    return arms


def imm_of(a):
    if not a['store']:
        return b''
    return bytes.fromhex(a['hex'])


# ---------------------------------------------------------------- the logs

def parse_boot(path):
    txt = open(os.path.join(ROOT, path), errors='replace').read()
    head = {}
    for k, pat in (('kernel', r'^### kernel: (.*)$'),
                   ('ksha', r'^### sha256: ([0-9a-f]{64})$'),
                   ('initrd', r'^### initrd: (.*)$'),
                   ('isha', r'^### initrd sha256: ([0-9a-f]{64})$'),
                   ('exit', r'^### qemu exit=(\d+)$')):
        m = re.search(pat, txt, re.M)
        head[k] = m.group(1) if m else None
    kv = {}
    for m in re.finditer(r'^F584 ([A-Z]+)\|(.*)$', txt, re.M):
        tag, rest = m.group(1), m.group(2)
        d = dict(x.split('=', 1) for x in rest.split('|') if '=' in x)
        kv.setdefault(tag, []).append(d)
    arms, rcvs, taps, rtaps = [], [], {}, {}
    for m in re.finditer(r'^F584 ARM\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        arms.append(d)
    for m in re.finditer(r'^F584 RCV\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        rcvs.append(d)
    for m in re.finditer(r'^F584 TAP\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        taps.setdefault((d['dev'], int(d['i'])), []).append(d)
    for m in re.finditer(r'^F584 RTAP\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        rtaps.setdefault((d['dev'], int(d['i'])), []).append(d)
    return dict(txt=txt, head=head, kv=kv, arms=arms, rcvs=rcvs, taps=taps,
                rtaps=rtaps, bootok='VM_BOOT_OK' in txt)


# ---------------------------------------------------------------- the model

def expect(a):
    """everything the model says about one arm"""
    dst = DA if a['dst'] == 'a' else DB
    dport = DPORT if a['skt'] == 'p' else DPORT_GRO
    if a['prov'] == 'p':
        dport = DPORT          # the hand-built frame is addressed to 5000
    gso = a['prov'] == 's'
    # the frame the sender emits
    if gso:
        field0 = Psum(S6, dst, L_TOTAL)
        sender = frame(S6, dst, 0x40, SPORT, dport, L_TOTAL, field0, PAY)
    else:
        field0 = C_of(S6, dst, SPORT, dport, PAY)
        sender = frame(S6, dst, 0x40, SPORT, dport, L_TOTAL, field0, PAY)
    # the forward door: the hop limit is already 0x3f, then the store
    post = bytearray(sender)
    post[21] = 0x3f
    if a['store']:
        o = 14 + 40 + a['off'] if a['base'] == 2 else 14 + a['off']
        imm = imm_of(a)
        # on a PARTIAL skb the csum fixup block is skipped entirely (F60/F61)
        post[o:o + len(imm)] = imm
    post = bytes(post)
    if a['prov'] == 'p' and a['cf']:
        # CHECKSUM_NONE world: nft_payload_set_eval() is not skipped, and
        # csum flags=1 makes the rule write the true checksum of the datagram
        # as it stands after the store (measured in F60/F61 as 3a36).
        pay_now = bytes(post[14 + 48:])
        fld = C_of(S6, dst, SPORT, dport, pay_now)
        post = post[:14 + 46] + struct.pack('!H', fld) + post[14 + 48:]
    l3p = post[14:]
    uh_len = struct.unpack('!H', l3p[44:46])[0]
    uh_chk = struct.unpack('!H', l3p[46:48])[0]
    pay = l3p[48:]
    # ---- the wire -------------------------------------------------------
    frames = []
    if a['dst'] == 'a':
        # y1 keeps GSO_UDP_L4: one frame, and it is still CHECKSUM_PARTIAL
        # whatever the rule wrote (the rule cannot change ip_summed).
        frames = [post]
        stat = 9 if gso else 1
    elif not gso:
        # y2 but nothing to segment: a plain 1262-byte datagram is one frame
        frames = [post]
        stat = 1
    else:
        # y2: validate_xmit_skb -> skb_gso_segment -> __udp_gso_segment.
        # Each segment is a fresh copy of the post-store header, so the delta
        # is computed from the SAME uh->len / uh->check for all three.
        off = 0
        for k, sl in enumerate(SEGS):
            seg_pay = pay[off:off + sl]
            if k < len(SEGS) - 1:
                newlen = 8 + MSS
            else:
                newlen = 8 + len(seg_pay)
            check = c16add(c16sub(uh_chk, uh_len), newlen)
            fld = (~fold32(fold16(udp_hdr(SPORT, dport, newlen, check) +
                                  seg_pay))) & 0xffff
            fr = frame(S6, dst, 0x3f, SPORT, dport, newlen, fld, seg_pay)
            frames.append(fr)
            off += sl
        stat = 1
    # ---- the receiver ---------------------------------------------------
    delivered = []      # the payloads that reach the socket, in order
    errors = 0
    if a['dst'] == 'a':
        ln = uh_len
        rx = SKB_L3
        if ln > rx:
            errors += 1                       # short_packet
        elif ln < 8:
            errors += 1
        else:
            if ln < rx:
                rx = ln                       # pskb_trim_rcsum()
            body = pay[:rx - 8]
            if a['skt'] == 'g' and gso:
                delivered.append(body)        # ACCEPT_L4: no segmentation
            elif a['skt'] == 'g' and not gso:
                if valid_of(S6, dst, SPORT, dport, uh_len, uh_chk, pay):
                    delivered.append(body)
                else:
                    errors += 1
            elif not gso:
                if valid_of(S6, dst, SPORT, dport, uh_len, uh_chk, pay):
                    delivered.append(body)    # a plain datagram, checked
                else:
                    errors += 1
            elif rx <= 8 + MSS:
                errors += len(SEGS)           # udp_rcv_segment: -EINVAL
            else:
                rest = body
                while rest:
                    delivered.append(rest[:MSS])
                    rest = rest[MSS:]
    elif not gso:
        if valid_of(S6, dst, SPORT, dport, uh_len, uh_chk, pay):
            delivered.append(pay)
        else:
            errors += 1
    else:
        off = 0
        for k, sl in enumerate(SEGS):
            seg_pay = pay[off:off + sl]
            newlen = 8 + sl
            fld = struct.unpack('!H', frames[k][14 + 40 + 6:14 + 40 + 8])[0]
            if valid_of(S6, dst, SPORT, dport, newlen, fld, seg_pay):
                delivered.append(seg_pay)
            else:
                errors += 1
            off += sl
    return dict(dst=dst, dport=dport, gso=gso, log=l3p, frames=frames,
                stat=stat, uh_len=uh_len, uh_chk=uh_chk, pay=pay,
                delivered=delivered, errors=errors, sender=sender,
                field0=field0)


# ---------------------------------------------------------------- per arm

def fz(v, off=0):
    if v is None or v == '-':
        return None
    return norm(bytes.fromhex(v))


def rcv_slot(R, key, k):
    v = R.get('%s%d' % (key, k), '0:0:')
    p = v.split(':')
    return int(p[0]), int(p[1]), p[2]


def tap_frames(B, dev, i):
    return [fz(t['hex']) for t in B['taps'].get((dev, i), [])]


def rcv_frames(B, dev, i):
    return [fz(t['hex']) for t in B['taps'].get((dev, i), [])]


def check_boot(path, arms):
    B = parse_boot(path)
    tag = os.path.basename(path)
    ok(B['bootok'], '%s: VM_BOOT_OK present' % tag)
    eq(B['head']['exit'], '0', '%s: qemu exit 0' % tag)
    eq(B['head']['ksha'], sha('src/linux-7.3.4-T563/arch/x86/boot/bzImage'),
       '%s: kernel sha256 matches the file' % tag)
    initrd = B['head']['initrd']
    ok(initrd and initrd.startswith(ROOT + '/'),
       '%s: the initrd path is inside the tree' % tag)
    rel = initrd[len(ROOT) + 1:] if initrd else ''
    eq(B['head']['isha'], sha(rel),
       '%s: initrd sha256 matches the file the log names' % tag)
    ex = subprocess.run(
        'cd %s && zcat %s | cpio -i --to-stdout '
        'root/repro 2>/dev/null | sha256sum' % (ROOT, rel), shell=True,
        capture_output=True, text=True).stdout.split()[0]
    eq(ex, sha('vm/build/differ584'),
       '%s: differ extracted from the initramfs == the built one' % tag)

    env = B['kv']['ENV'][0]
    eq(env['D'], str(D), '%s: payload 1200' % tag)
    eq(env['mss'], str(MSS), '%s: UDP_SEGMENT 512' % tag)
    eq(B['kv']['CHAINS'][0]['rc'], '0', '%s: chain created' % tag)
    y1 = [f for f in B['kv']['FEAT'] if f.get('dev') == 'y1'][0]
    y2 = [f for f in B['kv']['FEAT'] if f.get('dev') == 'y2'][0]
    ok(int(y1['ac0'], 16) & 0x8, '%s: y1 has NETIF_F_HW_CSUM' % tag)
    ok(not (int(y2['ac0'], 16) & 0x8), '%s: y2 lost NETIF_F_HW_CSUM' % tag)
    ok(int(y1['ac1'], 16) & 0x2, '%s: y1 keeps NETIF_F_GSO_UDP_L4 (bit 33)' % tag)
    ok(not (int(y2['ac1'], 16) & 0x2),
       '%s: y2 lost NETIF_F_GSO_UDP_L4 with the same write' % tag)
    eq(B['kv']['FEAT'][0].get('gsoudpbit'), '33',
       '%s: the instrument names bit 33' % tag)

    snd = [d for d in B['kv']['CHILDS'] if d.get('cmd', '').startswith('s')]
    eq(len(snd), len([a for a in arms if a['prov'] == 's']),
       '%s: every socket arm was sent' % tag)
    for d in snd:
        eq(d['rc'], str(D), '%s: sendto returned 1200 (%s)' % (tag, d['cmd']))
    for d in B['kv']['CHILDS']:
        if 'gso_rc' in d:
            eq(d['gso_rc'], '0', '%s: UDP_SEGMENT accepted' % tag)

    eq(len(B['arms']), len(arms), '%s: every arm printed' % tag)
    eq(len(B['rcvs']), len(arms), '%s: every arm has a receiver line' % tag)

    for a, A, R in zip(arms, B['arms'], B['rcvs']):
        e = expect(a)
        w = '%s: arm %02d %s' % (tag, a['i'], a['name'])
        eq(int(A['i']), a['i'], '%s: arm index' % w)
        eq(A['name'], a['name'], '%s: name printed' % w)
        eq(A['prov'], a['prov'], '%s: prov printed' % w)
        eq(A['dst'], a['dst'], '%s: dst printed' % w)
        eq(A['skt'], a['skt'], '%s: socket printed' % w)
        eq(int(A['store']), a['store'], '%s: store printed' % w)
        eq(int(A['base']), a['base'], '%s: base printed' % w)
        eq(int(A['off']), a['off'], '%s: off printed' % w)
        eq(int(A['len']), a['len'], '%s: len printed' % w)
        eq(int(A['cf']), a['cf'], '%s: csum flags printed' % w)
        eq(A['hex'], imm_of(a).hex() if a['store'] else '-', '%s: imm printed' % w)
        eq(int(A['rc']), 0, '%s: rule installed' % w)
        eq(int(A['ch']), 1, '%s: the rule counted one packet' % w)
        eq(int(A['nl']), 1, '%s: the rule logged once' % w)
        eq(int(A['lgplen']), SKB_L3, '%s: the log carries the whole GSO packet' % w)
        lgf = A['lgfirst']
        eq(lgf[0:2], '60', '%s: the logged packet is IPv6' % w)
        eq(lgf[8:12], e['log'][4:6].hex(),
           '%s: the logged IPv6 payload length' % w)
        eq(lgf[12:14], '11', '%s: the logged next header is UDP' % w)
        eq(lgf[14:16], '3f', '%s: hop limit 0x3f at FORWARD' % w)
        eq(A['lgudp'], e['log'][40:48].hex(),
           '%s: the UDP header in the log is the post-store header' % w)
        eq(A['lgtail'], e['log'][-16:].hex(),
           '%s: the last 16 logged bytes' % w)
        # ---- the exit taps, frame by frame
        good, bad = ('a', 'b') if a['dst'] == 'a' else ('b', 'a')
        eq(int(A['%sn' % bad]), 0, '%s: nothing on the other exit' % w)
        eq(int(A['%sn' % good]), len(e['frames']),
           '%s: %d frame(s) on the exit device' % (w, len(e['frames'])))
        got = tap_frames(B, good, a['i'])
        eq(len(got), len(e['frames']), '%s: tap frames parsed' % w)
        for k, (g, want) in enumerate(zip(got, e['frames'])):
            eq(g, norm(want), '%s: exit frame %d bytes' % (w, k))
            eq(len(g), len(want), '%s: exit frame %d length' % (w, k))
        stats = [int(t['stat']) for t in B['taps'].get((good, a['i']), [])]
        for k, st in enumerate(stats):
            eq(st, e['stat'], '%s: exit frame %d tap status' % (w, k))
        # the receiver's tap: same bytes, same status
        rdev = 'y3' if a['dst'] == 'a' else 'y4'
        rgot = rcv_frames(B, rdev, a['i'])
        eq(len(rgot), len(e['frames']), '%s: receiver tap frames' % w)
        for k, (g, want) in enumerate(zip(rgot, e['frames'])):
            eq(g, norm(want), '%s: receiver tap frame %d bytes' % (w, k))
        rstats = [int(t['stat']) for t in B['taps'].get((rdev, a['i']), [])]
        for k, st in enumerate(rstats):
            eq(st, e['stat'], '%s: receiver tap frame %d status' % (w, k))
        # ---- the socket
        key = 'a' if a['skt'] == 'p' else 'b'
        other = 'b' if key == 'a' else 'a'
        eq(int(R[key]), len(e['delivered']), '%s: datagram count' % w)
        eq(int(R[other]), 0, '%s: nothing on the other socket' % w)
        for k, body in enumerate(e['delivered'][:3]):
            ln, gsz, hx = rcv_slot(R, key, k)
            eq(ln, len(body), '%s: datagram %d length' % (w, k))
            eq(hx, body[:8].hex(), '%s: datagram %d first bytes' % (w, k))
            want_gso = -1
            if a['skt'] == 'g' and e['gso'] and len(e['frames']) == 1:
                want_gso = MSS      # the skb is still GSO at the socket
            eq(gsz, want_gso, '%s: datagram %d UDP_GRO cmsg' % (w, k))
        eq(int(R['du6in']), len(e['delivered']),
           '%s: Udp6InDatagrams == delivered' % w)
        eq(int(R['du6err']), e['errors'], '%s: Udp6InErrors == dropped' % w)
        eq(int(R['dhdr']), 0, '%s: no IPv6 header error at the receiver' % w)
        eq(int(R['noroute']), 0, '%s: no route error at the receiver' % w)
        nframes = len(e['frames'])
        eq(int(R['t3']) + int(R['t4']), nframes,
           '%s: the receiver taps saw every frame' % w)
        eq(int(A['hdr']), 0, '%s: no header error on the router' % w)
        eq(int(A['noroute']), 0, '%s: no route error on the router' % w)
    return B


def lgnorm(h):
    if not h or h == '-':
        return h
    return h[0:2] + h[2:3] + '0' + '0000' + h[8:]


def derived(B, arms, tag):
    """the claims the document will make, each one measured here"""
    A = B['arms']
    by = {a['name']: (a, A[i], B['rcvs'][i]) for i, a in enumerate(arms)}
    fr = lambda n: tap_frames(B, 'a' if by[n][0]['dst'] == 'a' else 'b',
                              by[n][0]['i'])
    dg = lambda n, k: rcv_slot(by[n][2], 'a' if by[n][0]['skt'] == 'p' else 'b', k)

    def diffs(x, y):
        return [i for i in range(min(len(x), len(y))) if x[i] != y[i]]

    def uh(f):
        return struct.unpack('!H', f[58:60])[0], struct.unpack('!H', f[60:62])[0]

    # 1. the census: one frame on y1, three on y2, the same datagrams
    ca, cb = fr('c_a'), fr('c_b')
    eq(len(ca), 1, '%s: c_a is one frame' % tag)
    eq(len(cb), 3, '%s: c_b is three frames' % tag)
    eq([len(f) for f in cb], [574, 574, 238], '%s: c_b frame sizes' % tag)
    eq(uh(ca[0]), (1208, Psum(S6, DA, 1208)),
       '%s: c_a carries the seed, not a checksum' % tag)
    for k, f in enumerate(cb):
        ln, fld = uh(f)
        eq(ln, 8 + SEGS[k], '%s: c_b frame %d length field' % (tag, k))
        ok(valid_of(S6, DB, SPORT, DPORT, ln, fld, f[62:]),
           '%s: c_b frame %d checksum is valid' % (tag, k))
    eq([dg('c_a', k) for k in range(3)], [dg('c_b', k) for k in range(3)],
       '%s: the same three datagrams on both doors' % tag)

    # 2. the store in the big frame: exactly its own bytes, no payment
    wa, ca0 = fr('w_a')[0], ca[0]
    eq(diffs(wa, ca0), [62, 63, 64, 65],
       '%s: w_a differs from c_a at the four payload bytes only' % tag)
    eq(uh(wa)[1], uh(ca0)[1], '%s: w_a checksum field untouched' % tag)
    eq(dg('w_a', 0)[2], 'a0a1a2a384858687', '%s: the first datagram carries the store' % tag)
    eq(dg('w_a', 1), dg('c_a', 1), '%s: the second datagram is untouched' % tag)

    # 3. the same store on the segmenting door: paid, and only where it falls
    wb, cb0 = fr('w_b'), cb
    eq(diffs(wb[0], cb0[0]), [60, 61, 62, 63, 64, 65],
       '%s: w_b frame 0 differs in the checksum and the four payload bytes' % tag)
    eq(wb[1], cb0[1], '%s: w_b frame 1 is byte-identical to c_b' % tag)
    eq(wb[2], cb0[2], '%s: w_b frame 2 is byte-identical to c_b' % tag)
    ok(valid_of(S6, DB, SPORT, DPORT, 520, uh(wb[0])[1], wb[0][62:]),
       '%s: w_b frame 0 checksum is valid for the modified payload' % tag)
    ok(not valid_of(S6, DB, SPORT, DPORT, 520, uh(cb0[0])[1], wb[0][62:]),
       '%s: and the unmodified field would not have been' % tag)

    # 4. middle and last segment
    for nm, k, o in (('wm_b', 1, 62), ('wl_b', 2, 234)):
        x = fr(nm)
        eq(diffs(x[k], cb0[k]), [60, 61, o, o + 1, o + 2, o + 3],
           '%s: %s stores into frame %d only, at byte %d' % (tag, nm, k, o))
        for j in range(3):
            if j != k:
                eq(x[j], cb0[j], '%s: %s leaves frame %d alone' % (tag, nm, j))
    eq(dg('wm_b', 1)[2], 'b0b1b2b384858687', '%s: wm lands in datagram 1' % tag)

    # 5. csum flags on a PARTIAL skb is dead code
    eq(fr('wfl_a'), fr('w_a'), '%s: wfl_a == w_a byte for byte' % tag)
    eq(fr('wfl_b'), fr('w_b'), '%s: wfl_b == w_b byte for byte' % tag)

    # 6. a store of the value already there changes nothing
    eq(fr('lens_a'), fr('c_a'), '%s: lens_a == c_a byte for byte' % tag)
    eq([dg('lens_a', k) for k in range(3)], [dg('c_a', k) for k in range(3)],
       '%s: lens_a delivers what c_a delivers' % tag)

    # 7-9. the length field: trimmed refusal, short packet, and the erasure
    eq(uh(fr('len_a')[0])[0], 0x20, '%s: len_a carries 0x0020' % tag)
    eq(uh(fr('len_a')[0])[1], Psum(S6, DA, 1208),
       '%s: len_a leaves the checksum field alone' % tag)
    eq(int(by['len_a'][2]['du6in']), 0, '%s: len_a delivers nothing' % tag)
    eq(int(by['len_a'][2]['du6err']), 3, '%s: len_a costs three errors' % tag)
    eq(uh(fr('lenbig_a')[0])[0], 0xffff, '%s: lenbig_a carries 0xffff' % tag)
    eq(int(by['lenbig_a'][2]['du6err']), 1,
       '%s: lenbig_a costs one error (short_packet)' % tag)
    for k, f in enumerate(fr('len_b')):
        eq(struct.unpack('!H', f[58:60])[0], struct.unpack('!H', cb0[k][58:60])[0],
           '%s: len_b frame %d has the rewritten length' % (tag, k))
        eq(struct.unpack('!H', f[60:62])[0],
           c16sub(struct.unpack('!H', cb0[k][60:62])[0], 1208 - 0x20),
           '%s: len_b frame %d checksum is short by 1208-0x20' % (tag, k))
    eq(int(by['len_b'][2]['du6in']), 0, '%s: len_b delivers nothing' % tag)
    eq(int(by['len_b'][2]['du6err']), 3, '%s: len_b costs three errors' % tag)

    # 10-11. the checksum field: unseen on y1, fatal on y2
    eq(uh(fr('chk_a')[0])[1], 0xdead, '%s: chk_a carries 0xdead' % tag)
    eq(int(by['chk_a'][2]['du6in']), 3, '%s: chk_a still delivers three' % tag)
    for k, f in enumerate(fr('chk_b')):
        eq(struct.unpack('!H', f[60:62])[0],
           c16sub(struct.unpack('!H', cb0[k][60:62])[0],
                  c16sub(0xdead, Psum(S6, DB, 1208))),
           '%s: chk_b frame %d checksum is off by the seed change' % (tag, k))
    eq(int(by['chk_b'][2]['du6err']), 3, '%s: chk_b costs three errors' % tag)

    # 12. the packet provenance: same bytes, different flag, opposite fate
    cpa, wpa = fr('c_p_a')[0], fr('w_p_a')[0]
    eq(diffs(cpa, wpa), [62, 63, 64, 65],
       '%s: w_p_a differs from c_p_a at the store only' % tag)
    eq(int(by['c_p_a'][2]['du6in']), 1, '%s: c_p_a delivers one datagram' % tag)
    eq(dg('c_p_a', 0)[0], 1200, '%s: c_p_a is a 1200-byte datagram' % tag)
    eq(int(by['c_p_b'][2]['du6in']), 1, '%s: c_p_b delivers one too' % tag)
    eq(int(by['w_p_a'][2]['du6in']), 0, '%s: w_p_a is dropped' % tag)
    eq(int(by['w_p_a'][2]['du6err']), 1, '%s: w_p_a costs one error' % tag)

    # 13. the one flag that pays in the CHECKSUM_NONE world
    g = A[by['wb_p_a'][0]['i']]
    mod = PAY[:0] + bytes.fromhex('a0a1a2a3') + PAY[4:]
    eq(int(g['lgudp'][12:16], 16), C_of(S6, DA, SPORT, DPORT, mod),
       '%s: wb_p_a makes the rule write the true checksum' % tag)
    eq(int(by['wb_p_a'][2]['du6in']), 1, '%s: wb_p_a is delivered' % tag)
    eq(dg('wb_p_a', 0)[2], 'a0a1a2a384858687', '%s: with the store' % tag)

    # 14. the UDP_GRO socket decides how many datagrams the application sees
    eq(int(by['g_a'][2]['b']), 1, '%s: g_a gets one datagram' % tag)
    eq(dg('g_a', 0)[:2], (1200, MSS), '%s: g_a is 1200 bytes with gso 512' % tag)
    eq(int(by['g_b'][2]['b']), 3, '%s: g_b gets three' % tag)
    eq([dg('g_b', k)[0] for k in range(3)], [512, 512, 176],
       '%s: g_b sizes' % tag)
    eq(dg('gw_a', 0)[:2], (1200, MSS), '%s: gw_a one datagram with the store' % tag)
    eq(dg('glen_a', 0)[:2], (24, MSS), '%s: glen_a is trimmed to 24 bytes' % tag)
    # the seed does not depend on the port, so only the low byte of the
    # destination port is different: 0x1388 -> 0x1389
    eq(diffs(fr('g_a')[0], ca[0]), [57],
       '%s: the GRO socket changes one byte (the destination port)' % tag)


def determinism(B1, B2, arms):
    for a in arms:
        e = expect(a)
        w = 'boots agree: arm %02d %s' % (a['i'], a['name'])
        for dev in ('a', 'b'):
            eq(tap_frames(B1, dev, a['i']), tap_frames(B2, dev, a['i']),
               '%s: exit tap %s' % (w, dev))
            eq(rcv_frames(B1, 'y3' if dev == 'a' else 'y4', a['i']),
               rcv_frames(B2, 'y3' if dev == 'a' else 'y4', a['i']),
               '%s: receiver tap %s' % (w, dev))
        for key in ('a', 'b'):
            for k in range(3):
                kk = '%s%d' % (key, k)
                eq(B1['rcvs'][a['i']][kk], B2['rcvs'][a['i']][kk],
                   '%s: socket %s' % (w, kk))
        for k in ('du6in', 'du6err', 'u6err', 'dhdr', 'ddisc'):
            eq(B1['rcvs'][a['i']][k], B2['rcvs'][a['i']][k],
               '%s: counter %s' % (w, k))
        A1, A2 = B1['arms'][a['i']], B2['arms'][a['i']]
        # lgfirst carries the IPv6 flow label, which the kernel picks per
        # boot (F61 normalised it the same way: byte 1 high nibble kept).
        eq(lgnorm(A1['lgfirst']), lgnorm(A2['lgfirst']),
           '%s: lgfirst (flow label normalised)' % w)
        for k in ('ch', 'nl', 'lgplen', 'lgudp', 'lgtail'):
            eq(A1[k], A2[k], '%s: %s' % (w, k))


def source_anchors():
    def rd(p):
        return open(os.path.join(ROOT, KERNEL, p), errors='replace').read()

    udph = rd('include/linux/udp.h')
    ok('static inline bool udp_unexpected_gso(struct sock *sk, struct sk_buff *skb)'
       in udph, 'udp.h: udp_unexpected_gso exists')
    body = udph.split('static inline bool udp_unexpected_gso')[1].split('\n}')[0]
    ok('SKB_GSO_UDP_L4' in body and 'ACCEPT_L4' in body,
       'udp.h: a GSO_UDP_L4 skb is "unexpected" unless the socket asked for GRO')
    netudp = rd('include/net/udp.h')
    ok('static inline void udp_post_segment_fix_csum' in netudp,
       'net/udp.h: udp_post_segment_fix_csum exists')
    v6 = rd('net/ipv6/udp.c')
    ok('segs = udp_rcv_segment(sk, skb, false);' in v6,
       'udp.c: the receiver segments a GSO datagram for a plain socket')
    ok('if (likely(!udp_unexpected_gso(sk, skb)))' in v6,
       'udp.c: and only when it is unexpected')
    ok('ulen = udp_get_len(skb, uh, 0);' in v6 and
       'if (ulen > skb->len)' in v6, 'udp.c: a length field above the skb is short_packet')
    ok('pskb_trim_rcsum(skb, ulen)' in v6,
       'udp.c: a length field below the skb trims the datagram')
    off = rd('net/ipv4/udp_offload.c')
    ok('if (gso_skb->len <= sizeof(*uh) + mss)' in off,
       'udp_offload.c: a trimmed skb can no longer be segmented')
    ok('check = csum16_add(csum16_sub(uh->check, uh->len), htons(newlen));' in off,
       'udp_offload.c: the per-segment seed is a delta on the length')
    ok('uh->check = gso_make_checksum(seg, ~check) ? :' in off,
       'udp_offload.c: a CHECKSUM_NONE segment is summed in software')
    ok('if (seg->ip_summed == CHECKSUM_PARTIAL)' in off,
       'udp_offload.c: a PARTIAL segment is handed a seed, not a sum')
    gso = rd('include/net/gso.h')
    ok('return csum_fold(csum_partial(csum_start, plen, partial));' in gso,
       'gso.h: gso_make_checksum sums the transport header and payload')
    dev = rd('net/core/dev.c')
    ok('if (netif_needs_gso(skb, features)) {' in dev,
       'dev.c: validate_xmit_skb segments when the device cannot')
    nd = rd('include/linux/netdevice.h')
    ok('static inline bool netif_needs_gso(struct sk_buff *skb,' in nd,
       'netdevice.h: netif_needs_gso exists')
    ok('return skb_is_gso(skb) && (!skb_gso_ok(skb, features) ||' in nd,
       'netdevice.h: and it is a feature test')
    skb = rd('include/linux/skbuff.h')
    ok('static inline int skb_csum_unnecessary(const struct sk_buff *skb)'
       in skb, 'skbuff.h: skb_csum_unnecessary exists')
    body = skb.split('static inline int skb_csum_unnecessary')[1].split('\n}')[0]
    ok('CHECKSUM_PARTIAL' in body,
       'skbuff.h: PARTIAL counts as "unnecessary" -> nobody checks it')
    ip6o = rd('net/ipv6/ip6_offload.c')
    ok('payload_len = skb->len - nhoff - sizeof(*ipv6h);' in ip6o,
       'ip6_offload.c: each segment gets its own payload length')
    nf = rd('include/linux/netdev_features.h')
    order = nf.split('enum {')[1].split('};')[0]
    names = [x.strip().split()[0].strip(',') for x in order.splitlines()
             if x.strip().startswith('NETIF_F_') or
             x.strip().startswith('__UNUSED_NETIF_F')]
    ok('NETIF_F_GSO_UDP_L4_BIT' in names,
       'netdev_features.h: GSO_UDP_L4_BIT is in the enum')
    ok(names.index('NETIF_F_GSO_UDP_L4_BIT') == 33,
       'netdev_features.h: GSO_UDP_L4_BIT is bit 33 (ac1 bit 1)')


def main():
    need = BOOTS + ['vm/initrd584/full.cpio.gz', 'vm/build/differ584',
                    'vm/differ584.c', 'vm/differ584_add.c',
                    'vm/initramfs584.cpio.gz',
                    'src/linux-7.3.4-T563/arch/x86/boot/bzImage']
    for p in need:
        if not os.path.exists(os.path.join(ROOT, p)):
            print('MISSING %s' % p)
            return 1
    arms = parse_arms()
    eq(len(arms), 25, 'the arm table has 25 entries')
    source_anchors()
    boots = [check_boot(p, arms) for p in BOOTS]
    for p, B in zip(BOOTS, boots):
        derived(B, arms, os.path.basename(p))
    determinism(boots[0], boots[1], arms)
    print('checks=%d failures=%d' % (N, len(FAIL)))
    for what, got, want in FAIL[:40]:
        print('FAIL %s: got %r want %r' % (what, got, want))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
