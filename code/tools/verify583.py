#!/usr/bin/env python3
"""verify583.py -- independent verification of the F61 (turn 583) instrument.

Reads the two boot logs of mode `fwd` and re-derives every number the
instrument printed, from a model of the kernel that is written here, not
there:

  P       = fold16(pseudo header)                     udp6_hwcsum_outgoing()
  S0      = fold16(UDP region with a zero field)
  C       = ~fold32(P + S0)                           the true checksum
  help(f) = ~fold32(S0 + f)                            skb_checksum_help()
  valid   = fold32(P + S0 + f) == 0xffff               a CHECKSUM_NONE receiver

and the rule from nft_payload_set_eval():

  the fixup block (csum type inet / csum flags) is SKIPPED when the base is
  TRANSPORT_HEADER and skb->ip_summed == CHECKSUM_PARTIAL;

  skb_checksum_help() is called for PARTIAL packets only, and only when the
  egress device features lack HW_CSUM | IP_CSUM | IPV6_CSUM.

Usage: python3 tools/verify583.py [--quiet]
"""
import sys
import os
import re
import gzip
import hashlib
import subprocess
import struct

ROOT = '/work/kernel-sec'
BOOTS = ['logs/f61_rep1.log', 'logs/f61_rep2.log']
SRC = 'vm/differ583_add.c'
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


# ---------------------------------------------------------------- checksums

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


def hexb(s):
    return bytes.fromhex(s)


def fl_zero(b):
    return fl_zero_(b)


def fz(v, off=0):
    """bytes from a log field with the IPv6 flow label zeroed (the kernel
    picks it per boot).  off = where the IPv6 header starts: 0 for an L3
    buffer, 14 for a frame with an Ethernet header.  None for '-'."""
    if v is None or v == '-':
        return None
    b = bytearray(v if isinstance(v, (bytes, bytearray)) else bytes.fromhex(v))
    b[off + 1] &= 0xf0
    b[off + 2] = 0
    b[off + 3] = 0
    return bytes(b)


def fld(v):
    """the checksum field (hex chars 120..123 of a frame), -1 when '-'"""
    if v is None or v == '-':
        return -1
    return int(v[120:124], 16)


S6 = hexb('fd020000000000000000000000000011')
R6 = hexb('fd020000000000000000000000000091')
DA = hexb('fd030000000000000000000000000092')
DB = hexb('fd040000000000000000000000000092')
RA = hexb('fd030000000000000000000000000091')
RB = hexb('fd040000000000000000000000000091')
NEW = hexb('fd020000000000000000000000000077')
PAY = bytes(range(0x80, 0x92))
ULEN = 8 + len(PAY)


def pseudo(saddr, daddr, ln=ULEN, proto=17):
    return saddr + daddr + struct.pack('!I', ln) + b'\x00\x00\x00' + bytes([proto])


def udp_region(sport, dport, field, pay):
    return struct.pack('!HHHH', sport, dport, 8 + len(pay), field) + pay


def l3(saddr, daddr, hop, fl, sport, dport, field, pay):
    """the 66-byte L3 buffer: IPv6 header + UDP + payload"""
    h = bytearray()
    h += bytes([0x60 | ((fl >> 16) & 0x0f), (fl >> 8) & 0xff, fl & 0xff,
                fl & 0xff])
    h += struct.pack('!H', 8 + len(pay)) + bytes([17, hop])
    h += saddr + daddr
    return bytes(h) + udp_region(sport, dport, field, pay)


def P_of(dst, saddr=S6):
    return fold16(pseudo(saddr, dst))


def S0_of(sport, dport, pay):
    return fold16(udp_region(sport, dport, 0, pay))


def C_of(dst, sport, dport, pay, saddr=S6):
    return (~fold32(P_of(dst, saddr) + S0_of(sport, dport, pay))) & 0xffff


def help_of(sport, dport, pay, field_in):
    return (~fold32(S0_of(sport, dport, pay) + field_in)) & 0xffff


def valid_of(dst, sport, dport, pay, field, saddr=S6):
    return fold32(P_of(dst, saddr) + S0_of(sport, dport, pay) + field) == 0xffff


# ---------------------------------------------------------------- the source

def parse_arms():
    """the arm table, read out of the instrument's own source"""
    src = open(os.path.join(ROOT, SRC)).read()
    body = src.split('static const struct f583_arm AF583[] = {')[1]
    body = body.split('};')[0]
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    arms = []
    for m in re.finditer(r'\{\s*"([a-z0-9_]+)"\s*,\s*\'([sp])\'\s*,\s*\'([ab])\'([^}]*)\}', body):
        name, prov, dst, rest = m.group(1), m.group(2), m.group(3), m.group(4)
        toks = [t.strip() for t in rest.split(',') if t.strip()]
        base = {'B583_NH': 1, 'B583_TH': 2, '0': 0}[toks[0]]
        store, off, ln = (int(toks[1]), int(toks[2]), int(toks[3]))
        hexs = toks[4].strip('"')
        hexs = None if hexs == 'NULL' else hexs
        ct = 1 if toks[5] == 'NFT_PAYLOAD_CSUM_INET' else int(toks[5])
        co, cf = int(toks[6]), int(toks[7])
        arms.append(dict(i=len(arms), name=name, prov=prov, dst=dst, base=base,
                         store=store, off=off, len=ln, hex=hexs, ct=ct, co=co,
                         cf=cf))
    return arms


def imm_of(a):
    if not a['store']:
        return b''
    if a['hex']:
        return bytes.fromhex(a['hex'])
    return NEW[:a['len']]


def abs_off(a):
    """absolute offset inside the L3 buffer (IPv6 header starts at 0)"""
    return a['off'] + (0 if a['base'] == 1 else 40)


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
    for m in re.finditer(r'^F583 ([A-Z]+)\|(.*)$', txt, re.M):
        tag, rest = m.group(1), m.group(2)
        d = dict(x.split('=', 1) for x in rest.split('|') if '=' in x)
        kv.setdefault(tag, []).append(d)
    arms = []
    for m in re.finditer(r'^F583 ARM\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        arms.append(d)
    rcvs = []
    for m in re.finditer(r'^F583 RCV\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        rcvs.append(d)
    return dict(txt=txt, head=head, kv=kv, arms=arms, rcvs=rcvs,
                bootok='VM_BOOT_OK' in txt)


def fl_zero_(b):
    """zero the IPv6 flow label (bytes 1..3) -- the kernel picks it"""
    b = bytearray(b)
    b[1] = b[1] & 0xf0
    b[2] = 0
    b[3] = 0
    return bytes(b)


def l3_of_frame(fr):
    return fr[14:]


# ---------------------------------------------------------------- per arm

def expect(arm):
    """everything the model says about one arm"""
    dst = DA if arm['dst'] == 'a' else DB
    dport = 5000
    sport0 = 43580
    pay0 = PAY
    field0 = P_of(dst) if arm['prov'] == 's' else C_of(dst, sport0, dport, pay0)
    post = bytearray(l3(S6, dst, 0x40, 0, sport0, dport, field0, pay0))
    if arm['store']:
        o = abs_off(arm)
        imm = imm_of(arm)
        post[o:o + len(imm)] = imm
    post = bytes(post)
    hop = 0x3f
    post = post[:7] + bytes([hop]) + post[8:]
    sport = (post[40] << 8) | post[41]
    dprt = (post[42] << 8) | post[43]
    field_in = (post[46] << 8) | post[47]
    # in the CHECKSUM_NONE world the rule's own csum option is NOT skipped and
    # writes the true sum of the post-store datagram (F60); for base
    # NETWORK_HEADER on IPv6 nft_payload_csum_write_ok() refuses, so no fixup
    if arm['prov'] == 'p' and arm['base'] == 2 and (arm['ct'] or arm['cf']):
        field_in = C_of(dst, sport, 5000, post[48:])
        post = post[:46] + struct.pack('!H', field_in) + post[48:]
    pay = post[48:]
    saddr = post[8:24]
    dstn = post[24:40]
    # who pays
    pays = (arm['prov'] == 's' and arm['dst'] == 'b')
    field_out = help_of(sport, dprt, pay, field_in) if pays else field_in
    wire = post[:46] + struct.pack('!H', field_out) + post[48:]
    valid = valid_of(dstn, sport, dprt, pay, field_out, saddr=saddr)
    partial_at_rx = (arm['prov'] == 's' and not pays)
    delivered = partial_at_rx or valid
    stat = 9 if partial_at_rx else 1
    return dict(dst=dst, log=post, wire=wire, field_in=field_in,
                field_out=field_out, valid=valid, delivered=delivered,
                stat=stat, pay=pay, sport=sport, pays=pays,
                partial_at_rx=partial_at_rx, hop=hop)


def check_boot(path, arms):
    B = parse_boot(path)
    tag = os.path.basename(path)
    ok(B['bootok'], '%s: VM_BOOT_OK present' % tag)
    eq(B['head']['exit'], '0', '%s: qemu exit 0' % tag)
    # provenance
    eq(B['head']['ksha'], sha('src/linux-7.3.4-T563/arch/x86/boot/bzImage'),
       '%s: kernel sha256 matches the file' % tag)
    eq(B['head']['isha'], sha('vm/initrd583/full.cpio.gz'),
       '%s: initrd sha256 matches the file' % tag)
    eq(sha('vm/initrd583/full.cpio.gz'), sha('vm/initramfs583.cpio.gz'),
       '%s: the initrd is the one in the tree' % tag)
    # the differ inside the initramfs is the differ that was built
    ex = subprocess.run(
        'cd %s && zcat vm/initrd583/full.cpio.gz | cpio -i --to-stdout '
        'root/repro 2>/dev/null | sha256sum' % ROOT, shell=True,
        capture_output=True, text=True).stdout.split()[0]
    eq(ex, sha('vm/build/differ583'),
       '%s: differ extracted from the initramfs == the built one' % tag)
    eq(sha('vm/differ583.c'), sha('vm/differ583.c'),
       '%s: differ583.c present' % tag)

    # environment
    env = B['kv']['ENV'][0]
    eq(env['hwcsumbit'], '3', '%s: NETIF_F_HW_CSUM_BIT is 3' % tag)
    eq(B['kv']['CHAINS'][0]['rc'], '0', '%s: chain created' % tag)
    feats = B['kv']['FEAT']
    y1 = [f for f in feats if f.get('dev') == 'y1'][0]
    y2 = [f for f in feats if f.get('dev') == 'y2'][0]
    a1, a2 = int(y1['ac0'], 16), int(y2['ac0'], 16)
    ok(a1 & 0x8, '%s: y1 has NETIF_F_HW_CSUM' % tag)
    ok(not (a2 & 0x8), '%s: y2 lost NETIF_F_HW_CSUM' % tag)
    for bit, nm in ((1, 'IP_CSUM'), (2, 'unused'), (4, 'IPV6_CSUM')):
        ok(not (a2 & (1 << bit)),
           '%s: y2 has no %s either -> the help must run' % (tag, nm))
    # the same ioctl that removed HW_CSUM also removed GSO_UDP_L4
    ok(int(y1['ac1'], 16) & 0x2, '%s: y1 keeps NETIF_F_GSO_UDP_L4' % tag)
    ok(not (int(y2['ac1'], 16) & 0x2),
       '%s: y2 lost NETIF_F_GSO_UDP_L4 with the same write' % tag)

    # the frames the sender built, against the model
    frm = {f['id']: f for f in B['kv']['FRMPY']}
    for did, dst in (('a', DA), ('b', DB)):
        want = l3(S6, dst, 0x40, 0, 43580, 5000, C_of(dst, 43580, 5000, PAY),
                  PAY)
        got = l3_of_frame(hexb(frm[did]['hex']))
        eq(fl_zero(got), fl_zero(want),
           '%s: FRMPY %s is the model frame' % (tag, did))

    eq(len(B['arms']), len(arms), '%s: every arm printed' % tag)
    eq(len(B['rcvs']), len(arms), '%s: every arm has a receiver line' % tag)

    prev_u6in = 0
    prev_u6err = 0
    for a, A, R in zip(arms, B['arms'], B['rcvs']):
        e = expect(a)
        w = '%s: arm %02d %s' % (tag, a['i'], a['name'])
        # printed parameters == the source table
        eq(A['prov'], a['prov'], '%s: prov printed' % w)
        eq(A['dst'], a['dst'], '%s: dst printed' % w)
        eq(int(A['base']), a['base'], '%s: base printed' % w)
        eq(int(A['store']), a['store'], '%s: store printed' % w)
        eq(int(A['off']), a['off'], '%s: off printed' % w)
        eq(int(A['len']), a['len'], '%s: len printed' % w)
        eq(int(A['ct']), a['ct'], '%s: csum type printed' % w)
        eq(int(A['cf']), a['cf'], '%s: csum flags printed' % w)
        eq(A['hex'], imm_of(a).hex() if a['store'] else '-',
           '%s: imm printed' % w)
        eq(int(A['rc']), 0, '%s: the rule was installed' % w)
        eq(int(A['ch']), 1, '%s: the rule counted one datagram' % w)
        eq(int(A['nl']), 1, '%s: the rule logged' % w)
        eq(int(A['lglen']), 66, '%s: the logged L3 length' % w)
        # the log at the forward door: the post-store buffer, hop already 0x3f
        lg = fz(A['lg'])
        eq(lg, fz(e['log']),
           '%s: the forward-door bytes are the model bytes' % w)
        ok(lg is not None and lg[7] == 0x3f,
           '%s: hop limit already 0x3f at FORWARD' % w)
        # the egress tap on the right device
        good, bad = ('a', 'b') if a['dst'] == 'a' else ('b', 'a')
        eq(int(A['%sn' % bad]), 0,
           '%s: no frame on the other exit device' % w)
        eq(int(A['%sn' % good]), 1, '%s: one frame on the exit device' % w)
        eq(int(A['%slen' % good]), 80, '%s: the exit frame is 80 bytes' % w)
        eq(int(A['%sstat' % good]), e['stat'],
           '%s: the exit tap status (PARTIAL iff nobody paid)' % w)
        fr = fz(A[good], 14)
        ok(fr is not None, '%s: an exit frame was captured' % w)
        if fr is not None:
            eq(fr[14:], fz(e['wire']),
               '%s: the wire bytes are the model bytes' % w)
        eq(fld(A[good]), e['field_out'],
           '%s: the checksum field on the wire' % w)
        # the receiver
        eq(int(R['n']), 1 if e['delivered'] else 0,
           '%s: delivered iff PARTIAL or valid' % w)
        if e['delivered']:
            eq(int(R['ifidx']), 4 if a['dst'] == 'a' else 5,
               '%s: the datagram arrived on y3 for a, y4 for b' % w)
        if e['delivered']:
            eq(int(R['sport']), e['sport'], '%s: the source port at the socket' % w)
            eq(R['pay'], e['pay'][:64].hex(), '%s: the payload at the socket' % w)
        else:
            eq(R['pay'], '-', '%s: no datagram reached the socket' % w)
        # the receiver's own tap: the same bytes, the same status
        rg, rb = ('t3', 't4') if a['dst'] == 'a' else ('t4', 't3')
        eq(int(R['%sn' % rb]), 0, '%s: nothing on the other receiver tap' % w)
        eq(int(R['%sn' % rg]), 1, '%s: the receiver tap saw the frame' % w)
        eq(int(R['%sstat' % rg]), e['stat'],
           '%s: the flag survived the hop' % w)
        eq(fz(R[rg], 14), fr,
           '%s: the receiver tap bytes == the exit tap bytes' % w)
        # fate counters (absolute; differenced against the previous arm)
        u6in, u6err = int(R['u6in']), int(R['u6err'])
        eq(u6in - prev_u6in, 1 if e['delivered'] else 0,
           '%s: Udp6InDatagrams +1 iff delivered' % w)
        eq(u6err - prev_u6err, 0 if e['delivered'] else 1,
           '%s: Udp6InErrors +1 iff dropped' % w)
        prev_u6in, prev_u6err = u6in, u6err
        eq(int(R['hdr']), 0, '%s: no header error at the receiver' % w)
        eq(int(R['noroute']), 0, '%s: no routing error at the receiver' % w)
        # the forwarder
        eq(int(A['hdr']), 0, '%s: no header error on the router' % w)
        eq(int(A['noroute']), 0, '%s: no route error on the router' % w)
    return B


def derived(B, arms, tag):
    """the claims the document will make, each one measured here"""
    A = B['arms']
    by = {a['name']: (a, A[i], B['rcvs'][i]) for i, a in enumerate(arms)}
    D = lambda n: by[n]

    # 1. census: the seed on y1, the true sum on y2, both delivered
    a, x, r = D('c_s_a')
    eq((fz(x['a'], 14) or b'\x00' * 80)[14:][46:48],
       struct.pack('!H', P_of(DA)),
       '%s: census y1 carries the pseudo-header seed' % tag)
    ok(not valid_of(DA, 43580, 5000, PAY, P_of(DA)),
       '%s: the seed is NOT a checksum (NONE arithmetic)' % tag)
    a, x, r = D('c_s_b')
    eq((fz(x['b'], 14) or b'\x00' * 80)[14:][46:48],
       struct.pack('!H', C_of(DB, 43580, 5000, PAY)),
       '%s: census y2 carries the true checksum' % tag)
    ok(valid_of(DB, 43580, 5000, PAY, C_of(DB, 43580, 5000, PAY)),
       '%s: and it is valid' % tag)
    eq(fld(D('c_p_a')[1]['a']),
       C_of(DA, 43580, 5000, PAY),
       '%s: the AF_PACKET census frame carries the checksum it was built with'
       % tag)

    # 2. the payload store: free on y1, paid by y2
    eq(fld(D('w_s_a')[1]['a']), P_of(DA),
       '%s: w_s_a leaves the seed untouched' % tag)
    eq(fld(D('w_s_b')[1]['b']),
       C_of(DB, 43580, 5000, bytes([0xa0, 0xa1, 0xa2, 0xa3]) + PAY[4:]),
       '%s: w_s_b carries the checksum of the modified datagram' % tag)
    ok(not valid_of(DA, 43580, 5000, b'\xa0\xa1\xa2\xa3' + PAY[4:],
                    P_of(DA)),
       '%s: the y1 frame would be rejected by a verifier' % tag)
    ok(valid_of(DB, 43580, 5000, b'\xa0\xa1\xa2\xa3' + PAY[4:],
                C_of(DB, 43580, 5000, b'\xa0\xa1\xa2\xa3' + PAY[4:])),
       '%s: the y2 frame is valid' % tag)

    # 3. csum type inet / csum flags are dead code on CHECKSUM_PARTIAL
    for pair, nm in ((('w_s_a', 'wcs_s_a', 'wfl_s_a'), 'y1'),
                     (('w_s_b', 'wcs_s_b', 'wfl_s_b'), 'y2')):
        base = D(pair[0])[1]['a' if nm == 'y1' else 'b']
        for other in pair[1:]:
            got = D(other)[1]['a' if nm == 'y1' else 'b']
            eq(got, base,
               '%s: %s == %s byte for byte on %s' % (tag, other, pair[0], nm))

    # 4. the store in the checksum field itself
    eq(fld(D('d_s_a')[1]['a']), 0xdead,
       '%s: d_s_a ships the rule bytes in the field' % tag)
    eq(fld(D('d_s_b')[1]['b']),
       help_of(43580, 5000, PAY, 0xdead),
       '%s: d_s_b ships the payer value, computed from dead' % tag)
    ok(not valid_of(DB, 43580, 5000, PAY, help_of(43580, 5000, PAY, 0xdead)),
       '%s: and that value is not a checksum' % tag)
    eq(int(D('d_s_a')[2]['n']), 1, '%s: d_s_a is delivered anyway' % tag)
    eq(int(D('d_s_b')[2]['n']), 0, '%s: d_s_b is dropped' % tag)

    # 5. CHECKSUM_NONE: nobody pays anywhere
    for nm, dev in (('d_p_a', 'a'), ('d_p_b', 'b')):
        eq(fld(D(nm)[1][dev]), 0xdead,
           '%s: %s ships dead (no payer in the NONE world)' % (tag, nm))
        eq(int(D(nm)[2]['n']), 0, '%s: %s dropped' % (tag, nm))
    for nm, dev in (('w_p_a', 'a'), ('w_p_b', 'b')):
        eq(fld(D(nm)[1][dev]),
           C_of(DA if dev == 'a' else DB, 43580, 5000, PAY),
           '%s: %s ships the stale checkum' % (tag, nm))
        eq(int(D(nm)[2]['n']), 0, '%s: %s dropped' % (tag, nm))
    eq(fld(D('wcs_p_a')[1]['a']),
       C_of(DA, 43580, 5000, b'\xa0\xa1\xa2\xa3' + PAY[4:]),
       '%s: csum type inet repairs it in the NONE world' % tag)
    eq(int(D('wcs_p_a')[2]['n']), 1, '%s: and it is delivered' % tag)
    eq(D('wfl_p_a')[1]['a'], D('wcs_p_a')[1]['a'],
       '%s: csum flags reach the same bytes as csum type inet' % tag)

    # 6. the source port: the same store, two fates
    sp = PAY
    eq(fld(D('sp_s_b')[1]['b']),
       C_of(DB, 0xbeef, 5000, sp), '%s: sp_s_b carries the sum for the new port' % tag)
    eq(int(D('sp_s_b')[2]['n']), 1, '%s: sp_s_b delivered' % tag)
    eq(fld(D('sp_p_a')[1]['a']), C_of(DA, 43580, 5000, sp),
       '%s: sp_p_a carries the sum for the old port' % tag)
    eq(int(D('sp_p_a')[2]['n']), 0, '%s: sp_p_a dropped' % tag)

    # 7. the source address: the payer pays with the old pseudo header
    eq(fld(D('n_s_a')[1]['a']), P_of(DA),
       '%s: n_s_a leaves the seed' % tag)
    eq(fld(D('n_s_b')[1]['b']), C_of(DB, 43580, 5000, PAY),
       '%s: n_s_b carries the sum for the OLD source address' % tag)
    ok(not valid_of(DB, 43580, 5000, PAY, C_of(DB, 43580, 5000, PAY),
                    saddr=NEW),
       '%s: and it is invalid for the new one' % tag)
    eq(int(D('n_s_b')[2]['n']), 0, '%s: n_s_b dropped' % tag)
    eq(int(D('n_s_a')[2]['n']), 1, '%s: n_s_a delivered (nobody checks)' % tag)
    eq(D('ncs_s_b')[1]['b'], D('n_s_b')[1]['b'],
       '%s: csum type inet changes nothing for IPv6 @nh' % tag)
    eq(int(D('ncs_s_b')[2]['n']), 0, '%s: ncs_s_b dropped' % tag)

    # 8. writing the seed: the payer produces the untouched checksum
    eq(fld(D('dz_s_b')[1]['b']), C_of(DB, 43580, 5000, PAY),
       '%s: dz_s_b ends up with the census checksum' % tag)
    eq(D('dz_s_b')[1]['b'], D('c_s_b')[1]['b'],
       '%s: dz_s_b is byte-identical to the census on the wire' % tag)
    eq(int(D('dz_s_b')[2]['n']), 1, '%s: dz_s_b delivered' % tag)


def determinism(b1, b2, arms):
    def proj(B):
        out = []
        for A, R in zip(B['arms'], B['rcvs']):
            xs = []
            for k in sorted(A):
                if k in ('anall', 'bnall', 'rcv', 'deliv'):
                    continue        # neighbour-discovery noise, timing dependent
                v = A[k]
                if k in ('a', 'b', 't3', 't4'):
                    if v != '-':
                        v = fl_zero(hexb(v)).hex()
                        v = 'ETH' + v[48:]          # 48 hex = 24 eth bytes
                elif k == 'lg':
                    v = fl_zero(hexb(v)).hex()
                xs.append((k, v))
            ys = []
            for k in sorted(R):
                if k in ('rcv', 'deliv'):
                    continue
                v = R[k]
                if k in ('t3', 't4') and v != '-':
                    v = fl_zero(hexb(v)).hex()
                    v = 'ETH' + v[48:]
                ys.append((k, v))
            out.append((tuple(xs), tuple(ys)))
        return out
    p1, p2 = proj(b1), proj(b2)
    eq(len(p1), len(p2), 'determinism: same arm count')
    for i, (x, y) in enumerate(zip(p1, p2)):
        eq(x, y, 'determinism: arm %02d %s identical across boots'
           % (i, arms[i]['name']))


def source_anchors():
    """the kernel code this turn leans on, read from the tree"""
    def rd(p):
        return open(os.path.join(ROOT, KERNEL, p), errors='replace').read()

    dev = rd('net/core/dev.c')
    ok('skb->ip_summed = CHECKSUM_NONE;' in dev,
       'dev.c: skb_checksum_help ends by setting CHECKSUM_NONE')
    ok('*(__sum16 *)(skb->data + offset) = csum_fold(csum) ?: CSUM_MANGLED_0;'
       in dev, 'dev.c: the payer writes ~fold(sum of the region as it stands)')
    ok('if (skb_csum_hwoffload_help(skb, features))' in dev,
       'dev.c: validate_xmit_skb asks for help only under PARTIAL')
    ok('if (skb->ip_summed == CHECKSUM_PARTIAL) {' in dev,
       'dev.c: and only inside that branch')
    ok('if (features & NETIF_F_HW_CSUM)\n\t\treturn 0;' in dev,
       'dev.c: skb_csum_hwoffload_help returns 0 when HW_CSUM is present')
    skb = rd('net/core/skbuff.c')
    ok('void skb_scrub_packet(struct sk_buff *skb, bool xnet)' in skb,
       'skbuff.c: skb_scrub_packet exists')
    body = skb.split('void skb_scrub_packet(struct sk_buff *skb, bool xnet)')[1]
    body = body.split('\n}')[0]
    ok('ip_summed' not in body,
       'skbuff.c: skb_scrub_packet does NOT touch ip_summed')
    udp = rd('net/ipv6/udp.c')
    ok('uh->check = ~csum_ipv6_magic(saddr, daddr, len, IPPROTO_UDP, 0);' in udp,
       'udp.c: the sender writes the pseudo-header seed')
    nft = rd('net/netfilter/nft_payload.c')
    ok('skb->ip_summed != CHECKSUM_PARTIAL)) {' in nft,
       'nft_payload.c: the fixup block is guarded on PARTIAL')
    out = rd('net/ipv6/ip6_output.c')
    ip6f = out.split('int ip6_forward(struct sk_buff *skb)')[1]
    ok('hdr->hop_limit--;' in ip6f.split('NF_HOOK(NFPROTO_IPV6, NF_INET_FORWARD')[0],
       'ip6_output.c: the hop limit is decremented BEFORE the FORWARD hook')
    veth = rd('drivers/net/veth.c')
    ok('#define VETH_FEATURES (NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HW_CSUM |'
       in veth, 'veth.c: veth advertises HW_CSUM')


def main():
    need = BOOTS + ['vm/initrd583/full.cpio.gz', 'vm/build/differ583',
                    'vm/differ583.c', 'vm/differ583_add.c',
                    'vm/initramfs583.cpio.gz',
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
