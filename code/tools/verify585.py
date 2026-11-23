#!/usr/bin/env python3
"""verify585.py -- independent verification of the F63 (turn 585) instrument.

Reads the two boot logs of mode `aggr` and re-derives every number the
instrument printed from a model written here, not there.

The model, in full:

  three datagrams of 512 payload bytes, same 5-tuple, payload
      pay_k[0] = 0x10 + k, pay_k[i] = 0x80 + (i & 0x7f)
  pseudo(saddr, daddr, L) = saddr || daddr || (u32)L || 0 0 0 || 17
  seed(L) = fold16(pseudo(...))                    -- the PARTIAL field
  C(pay)  = ~fold16(pseudo(8 + len) + H(8+len, 0) + pay)   -- the real one

GRO (measured, not assumed):
  * veth is born with NETIF_F_GRO off (veth_disable_gro in veth_newlink), so
    before `gro on` there is no NAPI at all;
  * a UDP_GRO socket calls udp_tunnel_encap_enable(), which switches on the
    global udpv6_encap_needed_key -- and only then does udp6_gro_receive()
    look up a socket.  With a socket in hand the merge needs the SOCKET's
    GRO_ENABLED bit (linear, is_flist = 0) unless rx-gro-list is on, in which
    case is_flist = 1 and the aggregate is a fraglist;
  * with no socket (forwarded traffic) rx-udp-gro-forwarding decides;
  * completion: linear rewrites uh->check to seed(UDP length of the whole
    aggregate) and uh->len to the total; fraglist rewrites only uh->len.

Splitting:
  * a fraglist aggregate always leaves the kernel through
    __udp_gso_segment() (its gso_type bit has no device counterpart), and
    when skb_pagelen(skb) - 8 == gso_size it goes through
    __udp_gso_segment_list() -> skb_segment_list(), which copies nothing and
    computes no checksum; skb_segment() in the other branch does compute one
    when the device has no csum bit;
  * a linear aggregate leaves a device with GSO_UDP_L4 whole.

Usage: python3 tools/verify585.py [--quiet]
"""
import sys
import os
import re
import hashlib
import subprocess
import struct

ROOT = '/work/kernel-sec'
BOOTS = os.environ.get('F585_BOOTS',
                       'logs/f63_rep1.log,logs/f63_rep2.log').split(',')
SRC = 'vm/differ585_add.c'
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
    try:
        with open(os.path.join(ROOT, path), 'rb') as f:
            for b in iter(lambda: f.read(1 << 20), b''):
                h.update(b)
    except OSError:
        return None
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
DA = hexb('fd030000000000000000000000000092')
DB = hexb('fd040000000000000000000000000092')
RA = hexb('fd030000000000000000000000000091')
RB = hexb('fd040000000000000000000000000091')

P = 512
ND = 3
SPORT = 43580
DPORT = 5000
DPORT_G = 5001
ULEN = 8 + P                       # 520
AGGR_UDP = ND * P + 8              # 1544
FRAME = 14 + 40 + ULEN             # 574
AGGR = 40 + ND * P + 8             # 1584
PAY = []
for k in range(ND):
    b = bytearray(0x80 + (i & 0x7f) for i in range(P))
    b[0] = 0x10 + k
    PAY.append(bytes(b))


def pseudo(saddr, daddr, ln, proto=17):
    return saddr + daddr + struct.pack('!I', ln) + b'\x00\x00\x00' + bytes([proto])


def Psum(saddr, daddr, ln):
    return fold16(pseudo(saddr, daddr, ln))


def seed(saddr, daddr, ln):
    return Psum(saddr, daddr, ln)


def udp_hdr(sport, dport, ln, field):
    return struct.pack('!HHHH', sport, dport, ln, field)


def C_of(saddr, daddr, sport, dport, pay):
    ln = 8 + len(pay)
    return (~fold32(Psum(saddr, daddr, ln) +
                    fold16(udp_hdr(sport, dport, ln, 0) + pay))) & 0xffff


def valid_of(saddr, daddr, sport, dport, ln, field, pay):
    return fold32(Psum(saddr, daddr, ln) +
                  fold16(udp_hdr(sport, dport, ln, field) + pay)) == 0xffff


def frame(saddr, daddr, hop, ulen, field, pay):
    eth = b'\x00' * 12 + b'\x86\xdd'
    ip6 = bytes([0x60, 0, 0, 0]) + struct.pack('!H', 8 + len(pay)) + \
        bytes([17, hop]) + saddr + daddr
    return eth + ip6 + udp_hdr(SPORT, DPORT, ulen, field) + pay


def norm(fr):
    """zero the two MACs and the IPv6 flow label (chosen by the kernel)"""
    if fr is None:
        return None
    b = bytearray(fr)
    b[0:12] = b'\x00' * 12
    b[15] &= 0xf0
    b[16] = 0
    b[17] = 0
    return bytes(b)


# ---------------------------------------------------------------- the source

def parse_arms():
    """the arm table, read out of the instrument's own source"""
    src = open(os.path.join(ROOT, SRC)).read()
    body = src.split('static const struct f585_arm AF585[] = {')[1]
    body = body.split('};')[0]
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    arms = []
    pat = (r'\{\s*"([A-Za-z0-9_]+)"\s*,\s*\'([LFP])\'\s*,\s*\'([ab])\'\s*,'
           r'\s*\'([nuf])\'\s*,\s*\'([nuf])\'\s*,\s*\'([pg])\'\s*,([^}]*)\}')
    for m in re.finditer(pat, body):
        name, src_, dst, xg, dg, skt, rest = m.groups()
        toks = [t.strip() for t in rest.split(',') if t.strip()]
        store, off, ln = int(toks[0]), int(toks[1]), int(toks[2])
        hexs = toks[3].strip('"')
        hexs = None if hexs == 'NULL' else hexs
        arms.append(dict(i=len(arms), name=name, src=src_, dst=dst, xg=xg,
                         dg=dg, skt=skt, store=store, off=off, len=ln,
                         hex=hexs))
    return arms


# ---------------------------------------------------------------- the logs

def parse_boot(path):
    try:
        txt = open(os.path.join(ROOT, path), errors='replace').read()
    except OSError:
        # a missing log must be a red check, never a traceback
        txt = ''
    head = {}
    for k, pat in (('kernel', r'^### kernel: (.*)$'),
                   ('ksha', r'^### sha256: ([0-9a-f]{64})$'),
                   ('initrd', r'^### initrd: (.*)$'),
                   ('isha', r'^### initrd sha256: ([0-9a-f]{64})$'),
                   ('exit', r'^### qemu exit=(\d+)$')):
        m = re.search(pat, txt, re.M)
        head[k] = m.group(1) if m else None
    arms, rcvs, taps = [], [], {}
    defeats = []
    for m in re.finditer(r'^F585 ARM\|(.*)$', txt, re.M):
        arms.append(dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x))
    for m in re.finditer(r'^F585 RCV\|(.*)$', txt, re.M):
        rcvs.append(dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x))
    for m in re.finditer(r'^F585 TAP\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        taps.setdefault((d['dev'], int(d['i'])), []).append(d)
    for m in re.finditer(r'^F585 DFEAT\|(.*)$', txt, re.M):
        defeats.append(dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x))
    kv = {}
    for m in re.finditer(r'^F585 ([A-Z0-9]+)\|(.*)$', txt, re.M):
        kv.setdefault(m.group(1), []).append(m.group(2))
    return dict(txt=txt, head=head, arms=arms, rcvs=rcvs, taps=taps,
                defeats=defeats, kv=kv, bootok='VM_BOOT_OK' in txt,
                initrd=head['initrd'] or '')


# ---------------------------------------------------------------- the model

def store_payloads(a, pay):
    """apply the rule's store to the datagram payloads it can reach.

    Returns (paylist, neffect) where paylist is the list of payloads after the
    store and neffect is how many datagrams the store touched."""
    imm = bytes.fromhex(a['hex']) if a['store'] else b''
    out = [bytearray(x) for x in pay]
    if not a['store'] or a['off'] < 8:
        return [bytes(x) for x in out], (len(out) if a['store'] else 0)
    at = a['off'] - 8                       # payload offset inside the datagram
    k, o = divmod(at, P)
    if k < ND and o + len(imm) <= P:
        out[k][o:o + len(imm)] = imm
        return [bytes(x) for x in out], 1
    return [bytes(x) for x in out], 0       # past every payload: the header


def expect(a):
    """the model's answer for one arm"""
    src = S6 if a['src'] in 'FP' else (RA if a['dst'] == 'a' else RB)
    dst = DA if a['dst'] == 'a' else DB
    dport = DPORT_G if a['skt'] == 'g' else DPORT
    partial_src = (a['dst'] == 'a' and a['src'] != 'P')
    pays = list(PAY)
    e = dict(src=src, dst=dst, dport=dport, partial=partial_src)

    # ---- how many packets the rule sees --------------------------------
    agg = a['src'] == 'F' and a['xg'] != 'n'
    e['agg'] = agg
    e['ch'] = 1 if agg else ND
    e['lgplen'] = AGGR if agg else 40 + ULEN
    e['shape'] = a['xg'] if agg else None

    # ---- the field of each datagram as the sender writes it ------------
    # a socket writes the seed when the FIRST device it hands the skb to can
    # checksum; src L's first device is the arm's door, src F's is x1 (which
    # keeps HW_CSUM), and src P builds its own frames with real checksums
    sender_partial = (a['src'] == 'F' or
                      (a['src'] == 'L' and a['dst'] == 'a'))
    fields = []
    for k in range(ND):
        if sender_partial:
            fields.append(seed(src, dst, ULEN))
        else:
            fields.append(C_of(src, dst, SPORT, dport, PAY[k]))
    e['field0'] = fields[0]

    # ---- the aggregate's own header (what the rule reads) --------------
    e['uhl'] = [ULEN] * ND
    if agg:
        nh = 63 if a['src'] in 'FP' else 64
        e['nh'] = nh
        e['uhlen'] = AGGR_UDP
        if a['xg'] == 'u':
            e['uhck'] = seed(src, dst, AGGR_UDP)     # rewritten by completion
        else:
            e['uhck'] = fields[0]                    # untouched by completion
        if a['store'] and a['off'] == 4:
            e['uhlen'] = int(a['hex'], 16)           # the rule writes the length
        if a['store'] and a['off'] == 6:
            e['uhck'] = int(a['hex'], 16)            # ... and the checksum field
        # the store on the aggregate
        imm = bytes.fromhex(a['hex']) if a['store'] else b''
        pay_after, touched = store_payloads(a, PAY)
        e['imm'] = imm
        e['touched'] = touched
        # which bytes of the aggregate's payloads the store landed in
        off = a['off'] - 8 if a['store'] and a['off'] >= 8 else -1
        e['store_at'] = off
    else:
        # the store hits every datagram separately
        pay_k = []
        for k in range(ND):
            b = bytearray(PAY[k])
            if a['store'] and a['off'] >= 8:
                o = a['off'] - 8
                imm = bytes.fromhex(a['hex'])
                if o + len(imm) <= P:
                    b[o:o + len(imm)] = imm
            if a['store'] and a['off'] == 4:
                e['uhl'][k] = int(a['hex'], 16)
            if a['store'] and a['off'] == 6:
                fields[k] = int(a['hex'], 16)
            pay_k.append(bytes(b))
        e['pays'] = pay_k
    e['fields'] = fields
    # was the checksum computed by anyone before the socket sees it?  Only a
    # frame that some device hashed is CHECKSUM_NONE at the receiver, and only
    # then is it validated; skb_segment_list() leaves the fragments PARTIAL.
    if a['src'] == 'P':
        e['validated'] = True
    elif a['src'] == 'L':
        e['validated'] = a['dst'] == 'b'
    elif agg and a['dst'] == 'b':
        pull = a['store'] and (a['off'] - 8) >= P
        e['validated'] = not (a['xg'] == 'f' and not pull)
    else:
        e['validated'] = False
    return e


def help_csum(field, pay, ln=ULEN):
    """skb_checksum_help(): sum from the UDP header with the field as it
    stands, then write its complement -- valid only when field == seed(ln)"""
    return (~fold16(udp_hdr(SPORT, DPORT, ln, field) + pay)) & 0xffff


def agg_payload(a):
    """the aggregate's payload after the rule's store, in aggregate coords"""
    flat = bytearray(b''.join(PAY))
    if a['store']:
        imm = bytes.fromhex(a['hex'])
        o = a['off'] - 8
        if o >= 0 and o + len(imm) <= len(flat):
            flat[o:o + len(imm)] = imm
    return bytes(flat)


def agg_frame(e, uhlen, uhck, pay):
    eth = b'\x00' * 12 + b'\x86\xdd'
    ip6 = bytes([0x60, 0, 0, 0]) + struct.pack('!H', len(pay) + 8) + \
        bytes([17, e['nh']]) + e['src'] + e['dst']
    return eth + ip6 + udp_hdr(SPORT, DPORT, uhlen, uhck) + pay


def wire_frames(a, e):
    """the frames the LAST router device puts on the wire, as
    (iplen, hop, uhlen, uhck, bytes)"""
    dst = e['dst']
    out = []
    if a['src'] == 'F' and e['agg']:
        flat = agg_payload(a)
        if a['dst'] == 'a':
            out.append((AGGR_UDP, e['nh'], e['uhlen'], e['uhck'],
                        agg_frame(e, e['uhlen'], e['uhck'], flat)))
            return out
        pull = a['store'] and (a['off'] - 8) >= P
        if a['xg'] == 'f' and not pull:
            # __udp_gso_segment_list: every fragment keeps its own header
            for k in range(ND):
                pay = flat[k * P:(k + 1) * P]
                hop = e['nh'] if k == 0 else 64
                fld = e['uhck'] if k == 0 else e['fields'][k]
                out.append((ULEN, hop, ULEN, fld,
                            frame(e['src'], dst, hop, ULEN, fld, pay)))
            return out
        # skb_segment: headers from the head, the device computes.  Reached
        # from a fraglist only after __skb_linearize(), which first writes
        # uh->check = ~udp_v6_check(gso_skb->len, ...)
        base = seed(e['src'], dst, AGGR_UDP) if a['xg'] == 'f' else e['uhck']
        ck = c16add(c16sub(base, e['uhlen']), ULEN)
        for k in range(ND):
            pay = flat[k * P:(k + 1) * P]
            fld = help_csum(ck, pay)
            out.append((ULEN, e['nh'], ULEN, fld,
                        frame(e['src'], dst, e['nh'], ULEN, fld, pay)))
        return out
    for k in range(ND):
        pay = e['pays'][k]
        fld = e['fields'][k]
        uhl = e['uhl'][k]
        hop = 63 if a['src'] in 'FP' else 64
        out.append((ULEN, hop, uhl, fld,
                    frame(e['src'], dst, hop, uhl, fld, pay)))
    return out


def d_packets(a, e, wire):
    """the same frames after the receiving device's GRO: what the tap at the
    receiver, and the stack, actually see"""
    if len(wire) != ND:
        return wire
    if a['dg'] == 'n':
        return wire
    if a['skt'] != 'g' and a['dg'] != 'f':
        return wire                     # rx-udp-gro-forwarding is for no-socket flows
    if any(f[2] != ULEN for f in wire):
        return wire                     # GRO refuses a length that lies
    if e['validated']:
        # CHECKSUM_NONE provenance: GRO validates, and a rule that broke a
        # checksum is not aggregated
        for (iplen, hop, uhlen, uhck, fr) in wire:
            if not valid_of(e['src'], e['dst'], SPORT, e['dport'], uhlen,
                            uhck, fr[14 + 48:]):
                return wire
    flat = b''.join(f[4][14 + 48:] for f in wire)
    eth = b'\x00' * 12 + b'\x86\xdd'
    ip6 = bytes([0x60, 0, 0, 0]) + struct.pack('!H', AGGR_UDP) + \
        bytes([17, wire[0][1]]) + e['src'] + e['dst']
    if a['skt'] == 'g':
        uhck = seed(e['src'], e['dst'], AGGR_UDP)      # linear completion
    else:
        uhck = wire[0][3]                              # fraglist: untouched
    return [(AGGR_UDP, wire[0][1], AGGR_UDP, uhck,
             eth + ip6 + udp_hdr(SPORT, DPORT, AGGR_UDP, uhck) + flat)]


def delivery(a, e, wire, dp):
    """(delivered datagrams, Udp6InErrors, read lengths)"""
    one_agg = len(dp) == 1 and dp[0][0] == AGGR_UDP
    if one_agg:
        iplen, hop, uhlen, uhck, fr = dp[0]
        if a['store'] and a['off'] == 4:
            return 0, 3, []            # trimmed to 32: <= 8 + mss -> EINVAL, 3
        if a['skt'] == 'g':
            return 1, 0, [ND * P]      # one aggregate read, cmsg 512
        pay = fr[14 + 48:]
        if a['store'] and a['off'] == 6 and uhck == 0:
            # the head's segment carries the zero field, the others their own
            return 2, 1, [P, P]
        return 3, 0, [P, P, P]
    n = 0
    err = 0
    lens = []
    for (iplen, hop, uhlen, uhck, fr) in dp:
        pay = fr[14 + 48:]
        if a['store'] and a['off'] == 4:
            n += 1
            lens.append(uhlen - 8)     # the receiver trims to uh->len
            continue
        if uhck == 0:
            err += 1          # a zero checksum is illegal over IPv6
            continue
        if e['validated'] and not valid_of(e['src'], e['dst'], SPORT,
                                            e['dport'], uhlen, uhck, pay):
            err += 1
            continue
        if uhlen != ULEN:
            n += 1
            lens.append(uhlen - 8)
            continue
        n += 1
        lens.append(P)
    return n, err, lens


def check_boot(arms, boot, tag):
    txt = boot['txt']
    # ---- provenance ----------------------------------------------------
    ok(boot['bootok'], '%s: VM_BOOT_OK' % tag)
    ok(boot['head']['exit'] == '0', '%s: qemu exit 0' % tag)
    eq(boot['head']['ksha'], sha('src/linux-7.3.4-T563/arch/x86/boot/bzImage'),
       '%s: kernel sha in the header == the image' % tag)
    # the differ really is the one inside the initramfs: extract it and hash
    out = subprocess.run(
        'cd %s && zcat %s | cpio -i --to-stdout root/repro 2>/dev/null | '
        'sha256sum' % (ROOT, boot['initrd']), shell=True,
        capture_output=True, text=True).stdout.split()
    eq(out[0] if out else None, sha('vm/build/differ585'),
       '%s: differ extracted from the initramfs == the built one' % tag)
    eq(boot['head']['isha'], sha(boot['initrd']),
       '%s: initrd sha in the header == the file' % tag)
    ok('MODE_EXIT aggr=0' in txt, '%s: mode aggr exited 0' % tag)
    ok(len(arms) == 26, '%s: 26 ARM lines' % tag)
    ok(len(boot['rcvs']) == 26, '%s: 26 RCV lines' % tag)

    # ---- the source anchors the model leans on -------------------------
    def has(rel, needle, what):
        p = os.path.join(ROOT, KERNEL, rel)
        ok(needle in open(p, errors='replace').read(), '%s: %s' % (tag, what))

    has('drivers/net/veth.c', 'veth_disable_gro(dev);',
        'veth_newlink turns GRO off')
    has('drivers/net/veth.c', 'if (skb_shared(skb) || skb_unclone(skb, GFP_ATOMIC))',
        'a shared skb skips GRO in veth')
    has('net/ipv4/udp.c', 'udp_tunnel_encap_enable(sk);',
        'UDP_GRO enables the encap lookup')
    has('net/ipv4/udp_offload.c', 'NAPI_GRO_CB(skb)->is_flist = sk ? !udp_test_bit(GRO_ENABLED, sk) : 1;',
        'is_flist needs the socket bit off')
    has('net/ipv4/udp_offload.c', '(sk && udp_test_bit(GRO_ENABLED, sk)) || NAPI_GRO_CB(skb)->is_flist',
        'the merge gate')
    has('net/ipv6/udp_offload.c', 'udp_set_len(uh, skb->len - nhoff);',
        'fraglist completion rewrites the length')
    has('net/ipv4/udp_offload.c', 'return __udp_gso_segment_list(gso_skb, features, is_ipv6);',
        'the list branch exists')
    has('net/ipv4/udp_offload.c', 'if ((skb_pagelen(gso_skb) - sizeof(*uh) == skb_shinfo(gso_skb)->gso_size)',
        'the geometry test that picks it')
    has('net/core/skbuff.c', 'struct sk_buff *skb_segment_list(struct sk_buff *skb,',
        'skb_segment_list')
    has('include/net/udp.h', 'features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;',
        'udp_rcv_segment buys the csum bits')
    has('net/core/skbuff.c', 'Eaten partially.',
        '__pskb_pull_tail and the frag_list')
    has('include/net/gro.h', 'return !!((first_word & htonl(0x0FF00000)) |',
        'ipv6_gro_flush compares TC and hop limit')
    has('include/linux/skbuff.h', 'SKB_GSO_FRAGLIST = 1 << 18,',
        'SKB_GSO_FRAGLIST is bit 18')
    has('drivers/net/veth.c', 'rcu_access_pointer(rq->napi) &&',
        'veth only GROs when the peer NAPI exists')

    # ---- per arm -------------------------------------------------------
    prev = None
    for a, r in zip(arms, boot['rcvs']):
        i = a['i']
        e = expect(a)
        frames = d_packets(a, e, wire_frames(a, e))
        eq(int(r['i']), i, '%s arm %d: index' % (tag, i))
        eq(int(r['mode']), {'n': 0, 'u': 1, 'f': 2}[a['dg']],
           '%s arm %d (%s): GRO mode at the receiver' % (tag, i, a['name']))
        arm = boot['arms'][i]
        eq(int(arm['ch']), e['ch'],
           '%s arm %d (%s): rule counter' % (tag, i, a['name']))
        eq(int(arm['nl']), 1, '%s arm %d: one NFLOG message' % (tag, i))
        eq(int(arm['lgplen']), e['lgplen'],
           '%s arm %d (%s): NFLOG length' % (tag, i, a['name']))
        if e['agg']:
            # what the rule reads: the aggregate's own header
            lg = hexb(arm['lgudp'])
            eq(int.from_bytes(lg[4:6], 'big'), e['uhlen'],
               '%s arm %d: aggregate UDP length seen by the rule' % (tag, i))
            eq(int.from_bytes(lg[6:8], 'big'), e['uhck'],
               '%s arm %d (%s): aggregate checksum field seen by the rule'
               % (tag, i, a['name']))
            eq(hexb(arm['lgfirst'])[4:6], struct.pack('!H', AGGR_UDP),
               '%s arm %d: IPv6 payload length of the aggregate' % (tag, i))
            eq(hexb(arm['lgfirst'])[7], e['nh'],
               '%s arm %d: hop limit at the door' % (tag, i))
            # the aggregate's payloads sit back to back, headers stripped
            afl = agg_payload(a)
            eq(hexb(arm['lgf1']), afl[512:528],
               '%s arm %d: aggregate offset 560 is datagram 2 payload' % (tag, i))
            eq(hexb(arm['lgf2']), afl[1072:1088],
               '%s arm %d: aggregate offset 1120 is datagram 3 payload' % (tag, i))
        else:
            lg = hexb(arm['lgudp'])
            eq(int.from_bytes(lg[4:6], 'big'), e['uhl'][0],
               '%s arm %d: datagram UDP length' % (tag, i))
            eq(int.from_bytes(lg[6:8], 'big'), e['field0'],
               '%s arm %d (%s): datagram checksum field' % (tag, i, a['name']))
        # ---- the wire ---------------------------------------------------
        dev = 'y3' if a['dst'] == 'a' else 'y4'
        t = boot['taps'].get((dev, i), [])
        eq(len(t), len(frames),
           '%s arm %d (%s): frames on the %s tap' % (tag, i, a['name'], dev))
        for k, (fr, exp) in enumerate(zip(t, frames)):
            iplen, hop, uhlen, uhck, raw = exp
            eq(int(fr['flen']), len(raw),
               '%s arm %d frame %d: wire length' % (tag, i, k))
            eq(int(fr['iplen']), iplen,
               '%s arm %d frame %d: IPv6 payload length' % (tag, i, k))
            eq(int(fr['hop']), hop,
               '%s arm %d frame %d: hop limit' % (tag, i, k))
            eq(int(fr['uhlen']), uhlen,
               '%s arm %d frame %d: UDP length' % (tag, i, k))
            eq(int(fr['uhck'], 16), uhck,
               '%s arm %d frame %d (%s): checksum field on the wire'
               % (tag, i, k, a['name']))
            if fr['trunc'] == '0':
                eq(norm(hexb(fr['hex'])), norm(raw),
                   '%s arm %d frame %d: every wire byte' % (tag, i, k))
        # ---- the receiver ----------------------------------------------
        nd, nerr, lens = delivery(a, e, wire_frames(a, e), frames)
        eq(int(r['udp']), nd, '%s arm %d (%s): datagrams delivered'
           % (tag, i, a['name']))
        eq(int(r['udperr']), nerr, '%s arm %d (%s): Udp6InErrors'
           % (tag, i, a['name']))
        got = ([int(r['a%d' % k]) for k in range(4)] if a['skt'] == 'p'
               else [int(r['b0'])] + [0, 0, 0])
        want = (lens + [0, 0, 0, 0])[:4]
        eq(got, want, '%s arm %d (%s): socket read lengths'
           % (tag, i, a['name']))
        # the witness counters are cumulative
        cur = (int(r['w1544']), int(r['w520']))
        if prev is None:
            d1544, d520 = cur
        else:
            d1544, d520 = cur[0] - prev[0], cur[1] - prev[1]
        n1544 = sum(1 for (iplen, _, _, _, _) in frames if iplen == AGGR_UDP)
        n520 = sum(1 for (iplen, _, _, _, _) in frames if iplen == ULEN)
        eq(d1544, n1544, '%s arm %d (%s): packets with IPv6 length 1544 at D'
           % (tag, i, a['name']))
        eq(d520, n520, '%s arm %d (%s): packets with IPv6 length 520 at D'
           % (tag, i, a['name']))
        prev = cur
        # ---- the shape bit really was on ---------------------------------
        if a['dg'] != 'n':
            eq(boot['defeats'][i]['mode'], str({'n': 0, 'u': 1, 'f': 2}[a['dg']]),
               '%s arm %d: the receiver set the shape bit before the traffic'
               % (tag, i))


def main():
    arms = parse_arms()
    boots = [parse_boot(p) for p in BOOTS]
    for tag, b in zip([os.path.basename(p) for p in BOOTS], boots):
        check_boot(arms, b, tag)
    # ---- determinism between the two boots -----------------------------
    if len(boots) == 2 and all(len(b['rcvs']) == len(arms) for b in boots):
        for i, a in enumerate(arms):
            e = expect(a)
            f0 = wire_frames(a, e)
            t1 = boots[0]['taps'].get(('y3' if a['dst'] == 'a' else 'y4', i), [])
            t2 = boots[1]['taps'].get(('y3' if a['dst'] == 'a' else 'y4', i), [])
            eq(len(t1), len(t2), 'arm %d: same number of frames in both boots' % i)
            for k in range(min(len(t1), len(t2))):
                eq(norm(hexb(t1[k]['hex'])), norm(hexb(t2[k]['hex'])),
                   'arm %d frame %d: byte-identical in both boots' % (i, k))
                eq(t1[k]['flen'], t2[k]['flen'],
                   'arm %d frame %d: same length in both boots' % (i, k))
            r1, r2 = boots[0]['rcvs'][i], boots[1]['rcvs'][i]
            for fld in ('n', 'n2', 'udp', 'udperr', 'w1544', 'w520', 'woth'):
                eq(r1[fld], r2[fld], 'arm %d: %s identical in both boots' % (i, fld))
    print('%d checks, %d failures' % (N, len(FAIL)))
    for (what, got, want) in FAIL[:60]:
        print('  FAIL %s: got %r want %r' % (what, got, want))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
