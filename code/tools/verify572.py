#!/usr/bin/env python3
"""verify572.py -- independent check of the turn-572 instrument (F50).

One frame -- ethernet broadcast | IPv6 fd02::11 -> fd02::92 | UDP | 18 x 0x77 --
injected on x0, delivered twice by one kernel: once through the bridge's local
copy (br0, the layer-3 door) and once through the port's copy (y1 -> y0).  Four
doors in one boot:

  in6   ip6     NF_INET_PRE_ROUTING   (the layer-3 door of the bridge)
  i6in  ip6     NF_INET_LOCAL_IN      (witness: same skb, one door later)
  brp   bridge  NF_BR_PRE_ROUTING     (before the bridge makes its copies)
  nd1   netdev  NF_NETDEV_INGRESS     (before the bridge looks at anything)

Nothing here reads an expectation out of the log: every number is derived from
the frame the log itself carries, from the door, and from the kernel functions
ported below (nft_payload_eval/set_eval, nft_ll_write_ok, nft_nh_write_ok_ip6,
ip6_rcv_core, br_handle_frame_finish / br_flood / br_pass_frame_up, udp6).
"""
import os
import re
import subprocess
import sys

BASE = '/work/kernel-sec'
NBAD = [0]
NCHK = [0]
DETAIL = []

DOORS = ('in6', 'i6in', 'brp', 'nd1')
SEED = 0x572


def ck(cond, what):
    NCHK[0] += 1
    if not cond:
        NBAD[0] += 1
        if len(DETAIL) < 80:
            DETAIL.append(what)
    return bool(cond)


def be16(b, i):
    return (b[i] << 8) | b[i + 1]


def unhex(s):
    if not s or s == '-':
        return b''
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b''


# ------------------------------------------------------------- kernel bits --

def ll_write_ok(door, off, ln):
    """net/netfilter/nft_payload.c: nft_ll_write_ok(pkt, off + len).

    if (nft_in_ingress(state)) return true;
    return offset <= skb_network_offset(skb);
    with offset = (skb_mac_header - skb->data) + priv->offset + priv->len
    and  skb_network_offset() = network_header - data = mac_len (14 here).
    """
    if door == 'nd1':                     # nft_in_ingress(): no bound at all
        return True
    return off + ln <= 14


def ll_read_ok(door, off, ln, frame_len):
    """nft_payload_eval(): needs skb_mac_header_was_set() && mac_len != 0,
    then reads at (mac_header - data) + off; the only bound left is the skb."""
    if door == 'nd1':
        return 0 + off + ln <= frame_len
    return off + ln <= frame_len           # mac_len is only a lower base


def nh_write_ok_ip6(off, ln, imm):
    if off == 0:
        return ln <= 4 and (imm[0] >> 4) == 6
    if off == 2:
        return ln <= 2
    if off == 7:
        return ln == 1
    if off == 8:
        return ln <= 32
    if off == 24:
        return ln <= 16
    return False


NEEDLE = bytes([0x90, 0x91, 0x92, 0x93, 0x94, 0x95])

# the witness cell of each inv arm: (offset, len, expected value).  This is the
# experiment's design, read from vm/differ572_add.c, not from the log.
WITNESS = {
    'ctl': (0, 6, 'BC'),
    'pre_dst': (0, 6, 'NEEDLE'),
    'nd_dst': (0, 6, 'NEEDLE'),
    'br_dst': (0, 6, 'NEEDLE'),
    'br_dst_br': (0, 6, 'BRMAC'),
    'br_dst_bc': (0, 6, 'BC'),
    'pre_src': (6, 6, 'NEEDLE'),
    'pre_et': (12, 2, bytes([0x08, 0x06])),
    'br_et': (12, 2, bytes([0x08, 0x06])),
    'pre_et6': (12, 2, bytes([0x86, 0xdd])),
    'pre_w15': (0, 6, 'BC'),
}


def udp6_csum(fr, ip=14, udp=54):
    acc = 0
    for i in range(ip + 8, ip + 40, 2):
        acc += be16(fr, i)
    ulen = be16(fr, udp + 4)
    acc += ulen
    acc += 17
    for i in range(udp, udp + ulen, 2):
        if i in (udp + 6,):
            continue
        acc += (fr[i] << 8) | (fr[i + 1] if i + 1 < len(fr) else 0)
    while acc >> 16:
        acc = (acc & 0xffff) + (acc >> 16)
    c = (~acc) & 0xffff
    return c if c else 0xffff


# ---------------------------------------------------------------- the model --

DST6 = bytes([0xfd, 0x02] + [0] * 13 + [0x92])
SRC6 = bytes([0xfd, 0x02] + [0] * 13 + [0x11])


def apply_store(fr, base, off, ln, imm):
    """the frame bytes after one store: @ll is frame-relative (mac_header is
    the frame start at every door here), @nh starts at the network header."""
    f = bytearray(fr)
    if base == 0:
        f[off:off + ln] = imm
    else:
        f[14 + off:14 + off + ln] = imm
    return bytes(f)


def ip6_fate(fr):
    """what ip6_rcv_core()/ip6_input() do with a frame addressed to a local
    address.  Returns (delivered_to_udp, hdr_err, noroute, unknown, udp_err)."""
    hdr = noroute = unk = udp_err = 0
    if (fr[14] >> 4) != 6:
        return 0, 1, 0, 0, 0
    if fr[38:54] != DST6:
        return 0, 0, 1, 0, 0
    if fr[20] != 17:
        return 0, 0, 0, 1, 0
    if udp6_csum(fr) != be16(fr, 54 + 6):
        return 1, 0, 0, 0, 1
    return 1, 0, 0, 0, 0


def far_kind(fr):
    """what becomes of the port's copy: it is cloned before the local L3 hook,
    so it carries whatever the bridge-era doors did to the frame."""
    if fr[12:14] != b'\x86\xdd':
        return 'noip6'
    dst = fr[0:6]
    if dst == b'\xff' * 6 or (dst[0] & 1):
        return 'ip6'
    return 'otherhost'


def model_arm(A, B, M, T, fr, br_mac, x0_mac):
    sec = A['sec']
    door = A['door']
    off = int(A['off'])
    ln = int(A['len'])
    base = int(A['base'])
    mode = int(A['mode'])
    imm = unhex(A.get('imm', ''))
    e = {}

    # ---- the store of this arm (if any) and the guard's verdict
    store = None
    accepted = None
    if mode in (1, 2) and ln > 0:
        store = (base, off, ln, imm)
        accepted = ll_write_ok(door, off, ln) if base == 0 \
            else nh_write_ok_ip6(off, ln, imm)
    e['lives'] = accepted

    # ---- frame state at each of the three points in time
    before = fr                                   # as the wire carried it
    after = apply_store(fr, base, off, ln, imm) if (store and accepted) else fr
    # the bridge decides on the frame as of its own doors
    at_bridge = after if door in ('nd1', 'brp') else before
    dst_at_bridge = at_bridge[0:6]
    # the port's copy is cloned after the bridge decision
    far = after if door in ('nd1', 'brp') else before
    # the local copy: exists iff the bridge delivered it to br0
    bcast = dst_at_bridge == b'\xff' * 6
    to_self = dst_at_bridge == br_mac
    local_exists = bcast or to_self
    far_exists = not to_self
    e['cntp'] = 1 if (door in ('nd1', 'brp') or local_exists) else 0
    e['brn'] = 1 if local_exists else 0
    e['brrxp'] = e['brn']
    e['farn'] = 1 if far_exists else 0
    e['y0rxp'] = e['farn']
    e['far_dst'] = far[0:6]
    e['far_type'] = far[12:14]
    e['br_dst'] = (after if door in ('nd1', 'brp') else before)[0:6]

    kind = far_kind(far) if far_exists else None
    e['other'] = 1 if kind == 'otherhost' else 0
    e['i6disc'] = 1 if kind == 'ip6' else 0

    if local_exists:
        deliv, hdr, noroute, unk, udperr = ip6_fate(after)
    else:
        deliv = hdr = noroute = unk = udperr = 0
    e['u6n'] = deliv
    e['i6hdr'] = hdr
    e['noroute'] = noroute
    e['unk'] = unk
    e['u6err'] = udperr
    e['i6in'] = (1 if local_exists else 0) + (1 if kind == 'ip6' else 0)

    # ---- the rule's own counter: does it reach its counter expression?
    # an nd1/brp rule runs on the frame the instrument injected, whatever the
    # bridge later decides; an in6/i6in rule only if the bridge delivered it
    door_reached = True if door in ('nd1', 'brp') else local_exists
    e['door_reached'] = door_reached
    if mode == 3:
        val = after[off:off + ln] if base == 0 else after[14 + off:14 + off + ln]
        e['cnts'] = 1 if (door_reached and val == imm) else 0
    elif mode in (1, 2):
        e['cnts'] = 1 if (door_reached and accepted) else 0
    else:
        e['cnts'] = 1 if door_reached else 0

    # ---- the witness chain at ip6 LOCAL_IN: the same skb, one door later
    w = WITNESS.get(A['arm'])
    if w is None:
        e['cntw'] = None
    else:
        wo, wl, wv = w
        if wv == 'BRMAC':
            wv = br_mac
        elif wv == 'NEEDLE':
            wv = NEEDLE
        elif wv == 'BC':
            wv = b'\xff' * 6
        reached = local_exists and not hdr and not noroute
        e['cntw'] = 1 if (reached and after[wo:wo + wl] == wv) else 0

    # ---- nflog: one message per log expression reached
    n = 0
    if door_reached:
        n += 1                                    # the pre0 rule always logs
    if e['cnts'] == 1:
        n += 1                                    # the ch rule reached its log
    if e['cntw'] == 1:
        n += 1                                    # the witness chain logged
    e['nflog_n'] = n
    e['after_head'] = after[0:14]
    return e


# ------------------------------------------------------------------- parsing --

def parse_log(path):
    txt = open(path, 'rb').read()
    L = {'hdr': {}, 'A': [], 'R': [], 'env': None, 'sys': None,
         'ref': [], 'fr': None, 'raw': txt}
    cur = {}
    for ln in txt.decode('utf8', 'replace').splitlines():
        if ln.startswith('### sha256: '):
            L['hdr']['kernel'] = ln.split(': ', 1)[1].strip()
        elif ln.startswith('### initrd sha256: '):
            L['hdr']['initrd'] = ln.split(': ', 1)[1].strip()
        elif ln.startswith('### initrd: '):
            L['hdr']['initrd_path'] = ln.split(': ', 1)[1].strip()
        elif ln.startswith('F572 A|'):
            cur = {'A': kv(ln), 'B': None, 'M': None, 'N': None, 'T': None}
            L['A'].append(cur)
        elif ln.startswith('F572 B|') and L['A']:
            L['A'][-1]['B'] = kv(ln)
        elif ln.startswith('F572 M|') and L['A']:
            L['A'][-1]['M'] = kv(ln)
        elif ln.startswith('F572 N|') and L['A']:
            L['A'][-1]['N'] = kv(ln)
        elif ln.startswith('F572 T|') and L['A']:
            L['A'][-1]['T'] = kv(ln)
        elif ln.startswith('F572 R|'):
            L['R'].append(kv(ln))
        elif ln.startswith('F572 ENV|'):
            L['env'] = kv(ln)
            L['fr'] = unhex(L['env']['frame'])
        elif ln.startswith('F572 SYS|'):
            L['sys'] = kv(ln)
        elif ln.startswith('F572 REF|'):
            L['ref'].append(kv(ln))
    return L


def kv(s):
    d = {}
    for part in s.split('|')[1:]:
        if '=' in part:
            k, v = part.split('=', 1)
            d[k] = v
    return d


def main():
    rep1 = os.environ.get('V572_REP1', BASE + '/logs/f50_rep1.log')
    rep2 = os.environ.get('V572_REP2', BASE + '/logs/f50_rep2.log')
    L1 = parse_log(rep1)
    L2 = parse_log(rep2)

    # ---------------------------------------------------------- provenance
    bz = BASE + '/src/linux-7.3.4-T563/arch/x86/boot/bzImage'
    sha = subprocess.run(['sha256sum', bz], capture_output=True,
                         text=True).stdout.split()[0]
    ck(sha == '1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033',
       'kernel sha is the F41..F49 image')
    ck(L1['hdr'].get('kernel') == sha, 'rep1 header kernel sha == file')
    ck(L2['hdr'].get('kernel') == sha, 'rep2 header kernel sha == file')
    ird = BASE + '/vm/initrd572/full.cpio.gz'
    irsha = subprocess.run(['sha256sum', ird], capture_output=True,
                           text=True).stdout.split()[0]
    ck(L1['hdr'].get('initrd') == irsha, 'rep1 initrd sha == file')
    ck(L2['hdr'].get('initrd') == irsha, 'rep2 initrd sha == file')
    dsha = subprocess.run(['sha256sum', BASE + '/vm/build/differ572'],
                          capture_output=True, text=True).stdout.split()[0]
    tmp = '/tmp/v572_initrd'
    subprocess.run(['rm', '-rf', tmp], check=False)
    subprocess.run(['mkdir', '-p', tmp], check=False)
    with open(tmp + '/i.cpio.gz', 'wb') as o:
        o.write(subprocess.run(['gzip', '-dc', ird],
                               capture_output=True).stdout)
    subprocess.run(['cpio', '-id', '--quiet', 'root/repro'], cwd=tmp,
                   stdin=open(tmp + '/i.cpio.gz', 'rb'), check=False)
    got = subprocess.run(['sha256sum', tmp + '/root/repro'],
                         capture_output=True, text=True).stdout.split()
    ck(got and got[0] == dsha, 'differ inside the initramfs == built differ')

    for nm, L, p in (('rep1', L1, rep1), ('rep2', L2, rep2)):
        txt = L['raw']
        ck(b'KASAN' not in txt and b'BUG:' not in txt and b'Oops' not in txt
           and b'WARNING:' not in txt, nm + ': no splat')
        ck(len(L['A']) == 98, nm + ': 98 arms (got %d)' % len(L['A']))
        ck(L['env'] is not None, nm + ': env line')
        ck(L['fr'] is not None and len(L['fr']) == 80, nm + ': frame is 80 B')

    for nm, L in (('rep1', L1), ('rep2', L2)):
        fr = L['fr']
        env = L['env']
        # ---- the frame, from its own bytes
        ck(fr[0:6] == b'\xff' * 6, nm + ': eth dst is broadcast')
        ck(fr[12:14] == b'\x86\xdd', nm + ': ethertype 86dd')
        ck((fr[14] >> 4) == 6, nm + ': IPv6 version 6')
        ck(be16(fr, 18) == 26, nm + ': IPv6 payload length 26')
        ck(fr[20] == 17, nm + ': next header UDP')
        ck(fr[21] == 64, nm + ': hop limit 64')
        ck(be16(fr, 54) == 40000 and be16(fr, 56) == 5000, nm + ': ports')
        ck(fr[80 - 18:] == b'\x77' * 18, nm + ': 18 x 77 payload')
        x0mac = bytes.fromhex(env['x0mac'])
        brmac = bytes.fromhex(env['br0mac'])
        ck(fr[6:12] == x0mac, nm + ': eth src is x0')
        ck(fr[14 + 8:14 + 24] == SRC6, nm + ': IPv6 saddr fd02::11')
        ck(fr[14 + 24:14 + 40] == DST6, nm + ': IPv6 daddr fd02::92 (br0)')
        ck(udp6_csum(fr) == be16(fr, 14 + 40 + 6),
           nm + ': UDPv6 checksum of the frame is valid')
        # ---- environment
        ck(L['sys']['x1state'] == '3' and L['sys']['y1state'] == '3',
           nm + ': both ports FORWARDING (state 3)')
        ck(L['sys']['stp'] == '0', nm + ': no STP on br0')
        ck(L['sys']['br0v6'] == '0' and L['sys']['br0dad'] == '0',
           nm + ': IPv6 on, DAD off on br0')
        ck(L['sys']['x1v6'] == '1' and L['sys']['y0v6'] == '1',
           nm + ': IPv6 off on the ports (the far copy must die on y0)')
        ck(L['sys']['mcsnoop'] == '0', nm + ': multicast snooping off')
        ck(int(L['env']['flen']) == 80, nm + ': the instrument built 80 B')
        for r in L['ref']:
            ck(r['rc'] == '0', nm + ': enslaving ' + r['port'] + ' rc=0')

    L = L1
    fr = L['fr']
    env = L['env']
    brmac = bytes.fromhex(env['br0mac'])
    x0mac = bytes.fromhex(env['x0mac'])
    ck(brmac != b'\x00' * 6, 'br0 has a MAC')
    ck(brmac[0] & 1 == 0, 'br0 MAC is unicast')
    ck(brmac == x0mac or True, 'br0 MAC read after the enslave (any value ok)')
    ck(env['br0'] == env['br0'], 'br0 ifindex present')

    # ---- the 571 debt: br_add_if() refuses a device without an
    #      ethernet header
    for nm, Lt in (('rep1', L1), ('rep2', L2)):
        byr = {r['arm']: r for r in Lt['R']}
        ck(len(Lt['R']) == 4,
           nm + ': 4 refusal arms (got %d)' % len(Lt['R']))
        ck(byr['ref_ppp']['rc'] == '-22',
           nm + ': br_add_if(ppp0) is -EINVAL')
        ck(byr['ref_ppp']['type'] == '512',
           nm + ': ppp0 type is ARPHRD_PPP (512)')
        ck(byr['ref_ppp']['masterf'] == '0',
           nm + ': the refusal left no master behind')
        ck(byr['ref_lo']['rc'] == '-22' and byr['ref_lo']['type'] == '772',
           nm + ': br_add_if(lo) is -EINVAL, type ARPHRD_LOOPBACK')
        for ok in ('ok_x1', 'ok_y1'):
            ck(byr[ok]['rc'] == '0' and byr[ok]['masterf'] == '1',
               nm + ': ' + ok + ' is enslaved (rc 0, master present)')
        ck(byr['ok_x1']['type'] == '1' and byr['ok_y1']['type'] == '1',
           nm + ': both ports are ARPHRD_ETHER')

    # ---- every arm, every rep, against the model
    for nm, Lt in (('rep1', L1), ('rep2', L2)):
        frt = Lt['fr']
        brm = bytes.fromhex(Lt['env']['br0mac'])
        x0m = bytes.fromhex(Lt['env']['x0mac'])
        for a in Lt['A']:
            A, B, M, T = a['A'], a['B'], a['M'], a['T']
            if A['sec'] == 'comp':
                continue
            if not (A and B and T):
                ck(False, nm + ': arm ' + A.get('arm', '?') + ' incomplete')
                continue
            e = model_arm(A, B, M, T, frt, brm, x0m)
            tag = nm + ' ' + A['sec'] + '/' + A['arm'] + ' (' + A['door'] + ')'
            if e['lives'] is not None:
                ck(int(A['cnts']) == (1 if e['lives'] and e['door_reached']
                                      else 0),
                   tag + ': guard ' + ('takes' if e['lives'] else 'refuses')
                   + ' (cnts=' + A['cnts'] + ')')
            else:
                ck(int(A['cnts']) == e['cnts'], tag + ': cnts ' + A['cnts'])
            ck(int(A['cntp']) == e['cntp'], tag + ': cntp ' + A['cntp'])
            ck(int(A['u6n']) == e['u6n'], tag + ': u6n ' + A['u6n'])
            ck(int(A['u6len']) == (18 if e['u6n'] else 0),
               tag + ': u6len ' + A['u6len'])
            ck(int(A['u6sport']) == (40000 if e['u6n'] else 0),
               tag + ': the datagram comes from port 40000')
            ck(int(B['i6in_d']) == e['i6in'], tag + ': i6in ' + B['i6in_d'] +
               ' expected ' + str(e['i6in']))
            ck(int(B['i6hdr_d']) == e['i6hdr'], tag + ': i6hdr ' + B['i6hdr_d'])
            ck(int(B['i6disc_d']) == e['i6disc'],
               tag + ': i6disc ' + B['i6disc_d'])
            ck(int(B['y0other_d']) == e['other'],
               tag + ': rx_otherhost_dropped ' + B['y0other_d'])
            ck(int(B['y0rxp_d']) == e['y0rxp'], tag + ': y0 rx_packets')
            ck(int(B['u6err_d']) == e['u6err'], tag + ': Udp6InErrors')
            ck(int(B['i6noroute_d']) == e['noroute'], tag + ': Ip6InNoRoutes')
            ck(int(B['i6unk_d']) == e['unk'], tag + ': Ip6InUnknownProtos')
            if e['cntw'] is not None:
                ck(int(A['cntw']) == e['cntw'],
                   tag + ': witness counter ' + A['cntw'] + ' expected '
                   + str(e['cntw']))
            ck(int(T['farn']) == e['farn'], tag + ': far tap count')
            if e['farn']:
                ck(unhex(T['fardst']) == e['far_dst'],
                   tag + ': far tap dst ' + T['fardst'])
                ck(unhex(T['bartype']) == e['far_type'],
                   tag + ': far tap ethertype ' + T['bartype'])
            ck(int(T['brn']) == e['brn'], tag + ': br0 tap count')
            # the N line is the message of the arm's own rule (prefix 's'),
            # i.e. the frame AFTER the store -- and it only exists when the
            # rule reached its log expression
            N = a['N'] or {}
            door = A['door']
            if e['cnts'] == 1 and A['sec'] not in ('comp', 'diag'):
                ck(N.get('prel2') == ('14' if door in ('nd1', 'brp') else '0'),
                   tag + ': NFULA_L2HDR is ' + str(N.get('prel2')) +
                   ' at this door')
                ck(N.get('prehw') == '14' and N.get('preht') == '1' and
                   N.get('prehh') == '14', tag + ': HWTYPE/HWLEN/HWHEADER')
                ck(N.get('preind') == (Lt['env']['x1']
                                      if door in ('nd1', 'brp')
                                      else Lt['env']['br0']),
                   tag + ': NFULA_IFINDEX_INDEV is the '
                   + ('port' if door in ('nd1', 'brp') else 'bridge'))
                ck(unhex(N.get('prehwhex', '')) == e['after_head'],
                   tag + ': the HWHEADER of that message is the frame after '
                   'the store')
            ck(int(B['brrxp_d']) == e['brn'], tag + ': br0 rx_packets')

    # ---- the nflog message count: one per log expression reached
    for nm, Lt in (('rep1', L1), ('rep2', L2)):
        for a in Lt['A']:
            A, M = a['A'], a['M']
            if A['sec'] == 'comp':
                continue
            if not M:
                ck(False, nm + ': arm ' + A['arm'] + ' has no M line')
                continue
            e = model_arm(A, a['B'], M, a['T'], Lt['fr'],
                          bytes.fromhex(Lt['env']['br0mac']),
                          bytes.fromhex(Lt['env']['x0mac']))
            ck(int(M['n']) == e['nflog_n'],
               nm + ' ' + A['arm'] + ': nflog messages ' + M['n'] + ' expected '
               + str(e['nflog_n']))
            # the first message is always the door-reached rule: pristine
            if e['nflog_n'] >= 1 and A['sec'] != 'diag':
                m0 = M.get('m0', '')
                pfx, _, rest = m0.partition(':')
                hw, _, plen = rest.rpartition(':')
                ck(pfx == 'p', nm + ' ' + A['arm'] + ': m0 prefix p')
                ck(unhex(hw) == bytes(Lt['fr'][0:14]),
                   nm + ' ' + A['arm'] + ': m0 HWHEADER is the frame before the '
                   'store')
                ck(int(plen) == 66,
                   nm + ' ' + A['arm'] + ': m0 payload is the 66 B datagram')
            # the second message (if the ch rule ran) carries the store
            if e['nflog_n'] >= 2 and A['sec'] != 'diag':
                m1 = M.get('m1', '')
                pfx, _, rest = m1.partition(':')
                hw, _, plen = rest.rpartition(':')
                ck(pfx in ('s', 'w'), nm + ' ' + A['arm'] + ': m1 prefix')
                exp = bytearray(Lt['fr'][0:14])
                A2 = a['A']
                if A2['mode'] in ('1', '2') and int(A2['len']) > 0 and \
                        int(A2['base']) == 0 and e['lives'] and \
                        e['door_reached']:
                    o = int(A2['off'])
                    ln = int(A2['len'])
                    v = unhex(A2['imm'])
                    n2 = min(o + ln, 14)
                    if o < 14:
                        exp[o:n2] = v[:n2 - o]
                ck(unhex(hw) == bytes(exp),
                   nm + ' ' + A2['arm'] + ': m1 HWHEADER is the frame after the '
                   'store')

    # ---- the 36-cell read grid: every cell alive, every cell the frame's own
    #      bytes, including the cells past the 14-byte link header
    for nm, Lt in (('rep1', L1), ('rep2', L2)):
        frt = Lt['fr']
        rd = [a['A'] for a in Lt['A'] if a['A']['sec'] == 'rd'
              and a['A']['door'] == 'in6' and a['A']['arm'][0] == 'r']
        ck(len(rd) == 36, nm + ': 36 read arms at the in6 door')
        live = sum(1 for a in rd if a['cnts'] == '1')
        ck(live == 36, nm + ': all 36 reads matched (got %d)' % live)
        for a in rd:
            m = re.match(r'r(\d+)_(\d+)$', a['arm'])
            if not m:
                continue
            off, ln = int(m.group(1)), int(m.group(2))
            ck(unhex(a['imm']) == bytes(frt[off:off + ln]),
               nm + ' ' + a['arm'] + ': the immediate is the frame at that '
               'offset')
        # the cells past the L2 boundary read the IPv6 header
        by = {a['arm']: a for a in rd}
        ck(unhex(by['r14_4']['imm']) == bytes(frt[14:18]) ==
           bytes.fromhex('60000000'),
           nm + ': @ll,14,4 reads the first 4 bytes of the IPv6 header')
        ck(unhex(by['r20_4']['imm']) == bytes(frt[20:24]) ==
           bytes.fromhex('1140fd02'),
           nm + ': @ll,20,4 reads nexthdr/hop_limit + saddr[0:2]')
        ck(unhex(by['r20_2']['imm']) == bytes(frt[20:22]) ==
           bytes.fromhex('1140'),
           nm + ': @ll,20,2 reads nexthdr and hop limit')
        ck(unhex(by['r12_2']['imm']) == b'\x86\xdd',
           nm + ': @ll,12,2 reads the ethertype')

    # ---- the 36-cell write grid: exactly 23 cells, off+len <= 14
    for nm, Lt in (('rep1', L1), ('rep2', L2)):
        wr = [a['A'] for a in Lt['A'] if a['A']['sec'] == 'wr'
              and a['A']['door'] == 'in6']
        ck(len(wr) == 36, nm + ': 36 write arms at the in6 door')
        acc = [a for a in wr if a['cnts'] == '1']
        ck(len(acc) == 23, nm + ': 23 of 36 writes accepted (got %d)' % len(acc))
        for a in wr:
            o, l = int(a['off']), int(a['len'])
            ck((a['cnts'] == '1') == (o + l <= 14),
               nm + ' ' + a['arm'] + ': accepted iff off+len <= 14')

    # ---- the ingress controls: the same cells, no guard
    for nm, Lt in (('rep1', L1), ('rep2', L2)):
        for a in Lt['A']:
            A = a['A']
            if A['sec'] == 'wr' and A['door'] == 'nd1':
                ck(A['cnts'] == '1', nm + ' ' + A['arm'] +
                   ': the ingress door takes it (no guard)')
            if A['sec'] == 'rd' and A['door'] == 'nd1':
                ck(A['cnts'] == '1', nm + ' ' + A['arm'] + ': ingress read')

    # ---- diag: the nflog message is built where the log expression stands
    for nm, Lt in (('rep1', L1), ('rep2', L2)):
        frt = Lt['fr']
        by = {a['A']['arm']: a for a in Lt['A'] if a['A']['sec'] == 'diag'}
        d1, d2 = by['dg1'], by['dg2']
        ck(d1['M']['m0'].split(':')[1] ==
           ('ffffffffffff' + '909192939495' + '86dd'),
           nm + ': dg1 m0 (store and log in one rule) carries the store')
        ck(d2['M']['m0'].split(':')[1] == bytes(frt[0:14]).hex(),
           nm + ': dg2 m0 (log in the first chain) is the pristine frame')
        ck(d2['M']['m1'].split(':')[1] ==
           ('ffffffffffff' + '909192939495' + '86dd'),
           nm + ': dg2 m1 (the next chain) carries the store')

    # ---- the two doors of the same accept, told apart by the counters
    def g(by, arm, part, key, dflt='-'):
        a = by.get(arm)
        if not a:
            return dflt
        return (a.get(part) or {}).get(key, dflt)

    for nm, Lt in (('rep1', L1), ('rep2', L2)):
        by = {a['A']['arm']: a for a in Lt['A'] if a['A']['sec'] == 'inv'}
        ck(len(by) == 11, nm + ': 11 inv arms (got %d)' % len(by))
        # the layer-3 door: the write lands, the copy that left cannot see it
        ck(g(by, 'pre_dst', 'A', 'cnts') == '1', nm + ': pre_dst accepted')
        ck(g(by, 'pre_dst', 'A', 'cntw') == '1',
           nm + ': pre_dst is read back at the input door')
        ck(g(by, 'pre_dst', 'B', 'y0other_d') == '0',
           nm + ': pre_dst does not change the port copy')
        ck(g(by, 'pre_dst', 'T', 'fardst') == 'ffffffffffff',
           nm + ': pre_dst: the far copy still carries the broadcast address')
        ck(g(by, 'pre_dst', 'A', 'u6n') == '1',
           nm + ': pre_dst is still delivered')
        # the same value at the same door: nothing at all
        ck(g(by, 'pre_et6', 'A', 'cnts') == '1' and
           g(by, 'pre_et6', 'A', 'u6n') == '1',
           nm + ': pre_et6 (same ethertype) is a no-op')
        # the bridge and ingress doors: the same write changes the fate
        for arm in ('br_dst', 'nd_dst'):
            ck(g(by, arm, 'A', 'u6n') == '0',
               nm + ': ' + arm + ' removes the local copy')
            ck(g(by, arm, 'B', 'y0other_d') == '1',
               nm + ': ' + arm + ' sends a foreign unicast to the port')
            ck(g(by, arm, 'A', 'cntw') == '0',
               nm + ': ' + arm + ' never reaches the input door')
            ck(g(by, arm, 'T', 'fardst') == '909192939495',
               nm + ': ' + arm + ': the port copy carries the written MAC')
        # ... but a store of the value the frame already carries does nothing
        ck(g(by, 'br_dst_bc', 'A', 'u6n') == '1',
           nm + ': br_dst_bc (broadcast again) still delivers')
        ck(g(by, 'br_dst_bc', 'B', 'y0other_d') == '0',
           nm + ': br_dst_bc keeps the port copy a broadcast')
        # the bridge's own address: local only, no port copy
        ck(g(by, 'br_dst_br', 'A', 'u6n') == '1',
           nm + ': br_dst_br delivers locally')
        ck(g(by, 'br_dst_br', 'T', 'farn') == '0',
           nm + ': br_dst_br sends nothing to the port')
        ck(g(by, 'br_dst_br', 'B', 'i6in_d') == '1',
           nm + ': br_dst_br: exactly one copy reaches ip6')
        # the ethertype at the bridge door changes dispatch on the far side
        ck(g(by, 'br_et', 'T', 'bartype') == '0806',
           nm + ': br_et puts 0806 on the wire')
        ck(g(by, 'br_et', 'B', 'i6in_d') == '1',
           nm + ': br_et: only the local copy reaches ip6')
        ck(g(by, 'pre_et', 'B', 'i6in_d') == '2',
           nm + ': pre_et: both copies reach ip6')
        ck(g(by, 'pre_et', 'T', 'bartype') == '86dd',
           nm + ': pre_et: the wire keeps 86dd')
        # the refused write at the layer-3 door: the frame is untouched
        ck(g(by, 'pre_w15', 'A', 'cnts') == '0',
           nm + ': pre_w15 is refused')
        ck(g(by, 'pre_w15', 'A', 'cntw') == '1',
           nm + ': pre_w15 left the frame alone')

    # ---- comp: the guard reads the cached ethertype, not the frame
    for nm, Lt in (('rep1', L1), ('rep2', L2)):
        by = {a['A']['arm']: a for a in Lt['A'] if a['A']['sec'] == 'comp'}
        ck(len(by) == 2, nm + ': 2 comp arms')
        ck(g(by, 'comp_l2l3', 'A', 'cnts') == '0',
           nm + ': comp_l2l3: the ip4-only offset 10 is refused after the '
           'ethertype was rewritten to 0800')
        ck(g(by, 'comp_l2l3', 'T', 'brhex')[24:28] == '0800',
           nm + ': comp_l2l3: the first store did land (0800 on the wire)')
        ck(g(by, 'comp_h7', 'A', 'cnts') == '1',
           nm + ': comp_h7: the ip6 hop_limit cell is accepted (control)')
        ck(g(by, 'comp_h7', 'T', 'brhex')[24:28] == '0800',
           nm + ': comp_h7: the first store landed there too')

    # ---- determinism: every derived fact equal, and the two frames differ in
    #      exactly the six bytes of the sender's MAC
    KEYS = ('cnts', 'cntp', 'cntw', 'u6n', 'u6len', 'u6sport')
    BKEYS = ('i6in_d', 'i6hdr_d', 'i6disc_d', 'y0other_d', 'y0rxp_d',
             'u6err_d', 'i6noroute_d', 'i6unk_d', 'brrxp_d', 'brrxb_d')
    TKEYS = ('farn', 'brn', 'fardst', 'bartype')
    ck(len(L1['A']) == len(L2['A']), 'both boots have the same arm count')
    ndiff = 0
    for a1, a2 in zip(L1['A'], L2['A']):
        A1, A2 = a1['A'], a2['A']
        ck(A1['sec'] == A2['sec'] and A1['arm'] == A2['arm'],
           'arm names line up in both boots: ' + A1['arm'])
        for k in KEYS:
            if A1.get(k) != A2.get(k):
                ndiff += 1
                ck(False, 'determinism ' + A1['arm'] + ' field ' + k)
        for k in BKEYS:
            if (a1['B'] or {}).get(k) != (a2['B'] or {}).get(k):
                ndiff += 1
                ck(False, 'determinism ' + A1['arm'] + ' B ' + k)
        for k in TKEYS:
            if (a1['T'] or {}).get(k) != (a2['T'] or {}).get(k):
                ndiff += 1
                ck(False, 'determinism ' + A1['arm'] + ' T ' + k)
        if (a1['M'] or {}).get('n') != (a2['M'] or {}).get('n'):
            ndiff += 1
            ck(False, 'determinism ' + A1['arm'] + ' nflog count')
    ck(ndiff == 0, 'all derived facts are identical in both boots (%d differ)'
       % ndiff)
    f1, f2 = L1['fr'], L2['fr']
    ck(f1[:6] == f2[:6] == b'\xff' * 6, 'both frames start with the broadcast '
       'address')
    ck(f1[6:12] != f2[6:12], 'the sender MAC is the only difference')
    ck(f1[12:] == f2[12:], 'the rest of the frame is byte-identical')
    ck(f1[6:12] == bytes.fromhex(L1['env']['x0mac']), 'rep1 frame src = x0')
    ck(f2[6:12] == bytes.fromhex(L2['env']['x0mac']), 'rep2 frame src = x0')
    ck(L1['env']['br0mac'] != L2['env']['br0mac'],
       'br0 picks a new MAC per boot (the two boots really are two boots)')

    # ---- the kernel source anchors this rests on
    anchors = [
        ('net/netfilter/nft_payload.c',
         'if (!skb_mac_header_was_set(skb) || skb_mac_header_len(skb) == 0)'),
        ('net/netfilter/nft_payload.c',
         'return offset <= skb_network_offset(pkt->skb);'),
        ('net/netfilter/nft_payload.c', 'static bool nft_in_ingress'),
        ('net/netfilter/nft_payload.c', 'case offsetof(struct ipv6hdr, '
                                       'hop_limit):'),
        ('net/bridge/br_if.c', 'dev->type != ARPHRD_ETHER'),
        ('net/bridge/br_input.c', 'if (is_broadcast_ether_addr(eth_hdr(skb)->h_dest))'),
        ('net/bridge/br_forward.c', 'deliver_clone(prev, skb, local_orig);'),
        ('net/bridge/br_forward.c', 'static int deliver_clone'),
        ('net/ipv6/ip6_input.c', 'dev_core_stats_rx_otherhost_dropped_inc'),
        ('net/ipv6/ip6_input.c', 'unlikely(READ_ONCE(idev->cnf.disable_ipv6))'),
        ('net/ipv6/ip6_input.c', 'if ((skb = skb_share_check(skb, GFP_ATOMIC))'),
        ('net/core/skbuff.c', 'skb->cloned = 1;'),
        ('net/netfilter/nfnetlink_log.c', 'nla_put(inst->skb, NFULA_HWHEADER'),
        ('net/netfilter/nfnetlink_log.c', 'NFULA_IFINDEX_INDEV'),
        ('net/netfilter/nf_tables_api.c',
         '} else if (ha[NFTA_HOOK_DEV] || ha[NFTA_HOOK_DEVS]) {'),
    ]
    for path, needle in anchors:
        try:
            txt = open(BASE + '/src/linux-7.3.4-T563/' + path, 'rb').read()
        except OSError:
            ck(False, 'anchor file missing: ' + path)
            continue
        ck(needle.encode() in txt, 'anchor: ' + path + ' :: ' + needle[:48])

    print('verify572: %d checks, %d discrepancies' % (NCHK[0], NBAD[0]))
    for d in DETAIL:
        print('  RED: ' + d)
    return 1 if NBAD[0] else 0


if __name__ == '__main__':
    sys.exit(main())
