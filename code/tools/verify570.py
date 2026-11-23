#!/usr/bin/env python3
"""verify570.py -- independent check of the turn-570 instrument (F48).

Two modes in one boot:
  ppp6e -- IPv6 inside PPPoE at the netdev egress door of x0, with the plain
           IPv6 datagram out the same device and the netdev ingress door of the
           same device as controls.
  th6   -- @th on the F46/F47 v6 doors, five frame shapes.

Nothing here reads a number out of the log to decide what the number should be:
every expectation is computed from the frame the log itself carries, the door,
the envelope, and the kernel functions ported below.
"""
import json
import os
import re
import subprocess
import sys

BASE = '/work/kernel-sec'
NBAD = [0]
NCHK = [0]
DETAIL = []


def ck(cond, what):
    NCHK[0] += 1
    if not cond:
        NBAD[0] += 1
        if len(DETAIL) < 40:
            DETAIL.append(what)
    return bool(cond)


def hx(b):
    return b.hex()


def be16(b, i):
    return (b[i] << 8) | b[i + 1]


# ---------------------------------------------------------------- frames ----

def ipv6_walk(fr, base, ip6off):
    """net/ipv6/exthdrs_core.c: ipv6_find_hdr(), target=-1, flags=AUTH.

    ip6off is the data-relative offset of the IPv6 header; the returned thoff
    is the data-relative offset of the transport header.
    """
    hdr = ip6off + 40
    if base + ip6off + 40 > len(fr):
        return None, None
    nx = fr[base + ip6off + 6]
    cnt = 0
    while True:
        if nx in (0, 43, 44, 51, 60):
            cnt += 1
            if cnt > 8 or base + hdr + 2 > len(fr):
                return None, None
            if nx == 51:                 # IP6_FH_F_AUTH stops on the AH header
                return 51, hdr
            hl = 8 if nx == 44 else (fr[base + hdr + 1] + 1) * 8
            nxt = fr[base + hdr]
            hdr += hl
            nx = nxt
            continue
        return nx, hdr


def validate6(fr, base, noff, nhoff):
    """__nft_set_pktinfo_ipv6_validate(pkt, nhoff) in Python.

    Returns (ok, tprot, thoff) where thoff is data-relative.
    """
    idx = base + noff + nhoff
    if idx + 40 > len(fr):
        return False, None, None
    if (fr[idx] >> 4) != 6:
        return False, None, None
    plen = be16(fr, idx + 4)
    skb_len = len(fr) - base - noff - nhoff
    if plen + 40 > skb_len:
        return False, None, None
    # ipv6_find_hdr(): *offset == 0 means "start at skb_network_offset"
    tprot, thoff = ipv6_walk(fr, base, nhoff if nhoff else noff)
    if tprot is None:
        return False, None, None
    return True, tprot, thoff


def validate4(fr, base, noff, nhoff):
    idx = base + noff + nhoff
    if idx + 20 > len(fr):
        return False, None
    if (fr[idx] >> 4) != 4:
        return False, None
    ihl = (fr[idx] & 0xf) * 4
    if ihl < 20:
        return False, None
    return True, noff + nhoff + ihl


# ----------------------------------------------------------------- parse ----

def hexok(v):
    if v in ('', '-'):
        return True
    if len(v) % 2 or any(c not in '0123456789abcdefABCDEF' for c in v):
        return False
    return True


def parse_log(path):
    out = {'A': [], 'T': [], 'frame': {}, 'frame6': [], 'hdr': {},
           'bad_hex': []}
    with open(path, 'r', errors='replace') as f:
        for ln in f:
            ln = ln.rstrip('\n')
            if ln.startswith('### sha256: '):
                out['hdr']['kernel'] = ln.split(': ', 1)[1].strip()
            elif ln.startswith('### initrd sha256: '):
                out['hdr']['initrd'] = ln.split(': ', 1)[1].strip()
            elif ln.startswith('### initrd: '):
                out['hdr']['initrd_path'] = ln.split(': ', 1)[1].strip()
            elif ln.startswith('F570 FRAME|'):
                parts = ln.split('|')
                f = dict(p.split('=', 1) for p in parts if '=' in p)
                out['frame'][parts[1]] = bytes.fromhex(f['hex'])
            elif ln.startswith('F570 FRAME6|'):
                f = dict(p.split('=', 1) for p in ln.split('|') if '=' in p)
                out['frame6'].append((f['shape'], bytes.fromhex(f['hex'])))
            elif ln.startswith('F570 A|'):
                d = dict(p.split('=', 1) for p in ln.split('|') if '=' in p)
                for k in ('tap', 'p', 's'):
                    if k not in d:
                        continue
                    if d.get(k) == '-':
                        d[k] = ''
                    elif not hexok(d[k]):
                        out['bad_hex'].append(('A', d.get('arm', '?'), k, d[k][:12]))
                        d[k] = ''
                out['A'].append(d)
            elif ln.startswith('F570 T|'):
                d = dict(p.split('=', 1) for p in ln.split('|') if '=' in p)
                for k in ('tap', 'p', 's'):
                    if k not in d:
                        continue
                    if d.get(k) == '-':
                        d[k] = ''
                    elif not hexok(d[k]):
                        out['bad_hex'].append(('T', d.get('arm', '?'), k, d[k][:12]))
                        d[k] = ''
                out['T'].append(d)
    return out


# --------------------------------------------------------------- ppp6e ------

def model_ppp6e(arm, fr_pre, door):
    """Predict what the rule did, from the frame the log carries.

    Returns dict with: cnts, wr_off (index in fr of the written byte or None),
    ipv6_at (frame index of the IPv6 header).
    """
    base = 0 if door == 'egr' else 14          # skb->data in the frame
    noff = 14 if door == 'egr' else 0          # skb_network_offset
    proto = 'ppp' if arm.get('sk') in ('1', '2') else 'plain'
    meta = arm['mp'] == '1'
    l4 = arm['ml'] == '1'
    # the pktinfo the door builds before any expression
    flags, tprot, thoff, nhoff = False, None, None, 0
    if proto == 'plain':
        ok, tprot, thoff = validate6(fr_pre, base, noff, 0)
        flags = ok
        if proto == 'plain' and not ok:
            ok4, th4 = validate4(fr_pre, base, noff, 0)
            flags = ok4
    # `meta protocol` / `meta l4proto` re-run nft_meta_pktinfo_may_update()
    if (meta or l4) and not flags and proto == 'ppp':
        # ETH_P_PPP_SES branch: ethertype from the PPP field, nhoff = 8 + noff
        ppp = be16(fr_pre, 20)
        eth = 0x0800 if ppp == 0x0021 else (0x86dd if ppp == 0x0057 else None)
        n2 = 8 + noff
        if eth == 0x86dd:
            ok, tprot, thoff = validate6(fr_pre, base, noff, n2)
            if ok:
                flags, nhoff = True, n2
            else:
                flags, nhoff, tprot, thoff = False, 0, None, None
        else:
            flags, nhoff, tprot, thoff = False, 0, None, None
    res = {'flags': flags, 'tprot': tprot, 'thoff': thoff, 'nhoff': nhoff,
           'base': base, 'proto': proto, 'eth': None}
    ppp = be16(fr_pre, 20) if proto == 'ppp' else None
    res['eth'] = 0x86dd if (proto == 'plain') else (0x86dd if ppp == 0x0057 else None)
    # the guard
    ok_write = True
    if arm['wr'] == '1':
        b = int(arm['base'])
        if b == 1:                              # @nh
            if door == 'egr':
                ok_write = (proto == 'plain')        # nft_nh_write_ok_netdev
                # switches on skb->protocol: ETH_P_PPP_SES has no case
            else:
                ok_write = True                      # constant at ingress
        else:                                   # @th
            ok_write = flags and tprot != 6
    ok_read = True
    if arm['rd'] == '1':
        ok_read = (int(arm['base']) != 2) or flags
    res['cnts'] = 1 if (ok_write and ok_read) else 0
    if l4 and not flags:
        res['cnts'] = 0                   # meta l4proto: NFT_BREAK
    # where the write lands
    res['wr'] = None
    if arm['wr'] == '1' and res['cnts']:
        b = int(arm['base'])
        off = int(arm['off'])
        if b == 1:
            res['wr'] = noff + off              # the write never adds nhoff
        else:
            res['wr'] = thoff + off
    # where a read looks (for the read arms)
    res['rd'] = None
    if arm['rd'] == '1' or arm['nh'] == '1':
        b = int(arm['base']) if arm['rd'] == '1' else 1
        off = int(arm['off'])
        if arm['nh'] == '1':
            res['rd'] = noff + nhoff + int(arm['off'])
        elif b == 1:
            res['rd'] = noff + nhoff + off
        elif thoff is not None:
            res['rd'] = thoff + off
    return res


NHREAD = {('egr', 'nh0_ppp'): '11000063', ('egr', 'nh_m_ppp'): '06070809',
          ('egr', 'fak_nh'): '60000008', ('ing', 'in_rdnh'): '60000000'}


def check_ppp6e(rep, L):
    arms = L['A']
    ck(len(arms) >= 25, 'ppp6e: at least 25 arms, got %d' % len(arms))
    fr_norm = None
    fr_fake = None
    for a in arms:
        shape = a['shape']
        # the frame as the rule saw it
        p = bytes.fromhex(a['p']) if a['p'] else b''
        ck(len(p) > 0, 'ppp6e %s: the door log carries a payload' % a['arm'])
        door = a['door']
        base = 0 if door == 'egr' else 14
        fr = bytes(base) + p if door == 'ing' else p
        if shape == '1' and fr_fake is None:
            fr_fake = fr
        if shape == '0' and a['arm'] == 'ctl_ppp':
            fr_norm = fr
        m = model_ppp6e(a, fr, door)
        key = (door, a['arm'])
        if key in NHREAD and m['rd'] is not None:
            want = bytes.fromhex(NHREAD[key])
            got = fr[m['base'] + m['rd']:m['base'] + m['rd'] + len(want)]
            m['cnts'] = 1 if got == want else 0
        ck(int(a['cnts']) == m['cnts'],
           'ppp6e %s/%s: cnts %s, model %d' % (door, a['arm'], a['cnts'], m['cnts']))
        ck(int(a['cntp']) == 1,
           'ppp6e %s/%s: the door counter is 1, got %s' % (door, a['arm'], a['cntp']))
        # the post-write payload, measured at the rule itself
        s = bytes.fromhex(a['s']) if a['s'] else b''
        if not a['p']:
            ck(False, 'ppp6e %s/%s: the p column does not parse' % (door, a['arm']))
        if m['cnts'] == 0:
            ck(a['sn'] == '0', 'ppp6e %s/%s: no ch log when the rule broke'
               % (door, a['arm']))
        else:
            ck(len(s) == len(p), 'ppp6e %s/%s: s and p are the same length'
               % (door, a['arm']))
            if m['wr'] is not None:
                imm = bytes.fromhex(a['imm'])
                got = s[m['wr']:m['wr'] + len(imm)]
                ck(got == imm, 'ppp6e %s/%s: byte at %d is %s, written %s'
                   % (door, a['arm'], m['wr'], got.hex(), imm.hex()))
                # every other byte is untouched
                rest_s = s[:m['wr']] + s[m['wr'] + len(imm):]
                rest_p = p[:m['wr']] + p[m['wr'] + len(imm):]
                ck(rest_s == rest_p,
                   'ppp6e %s/%s: the write moved exactly one cell' % (door, a['arm']))
        # the wire
        tap = bytes.fromhex(a['tap']) if a['tap'] else b''
        if m['cnts'] == 1 and m['wr'] is not None:
            if door == 'egr':
                ck(len(tap) == len(fr),
                   'ppp6e egr/%s: the tap frame has the door frame length' % a['arm'])
                if len(tap) == len(fr):
                    exp = bytearray(fr)
                    imm = bytes.fromhex(a['imm'])
                    exp[m['wr']:m['wr'] + len(imm)] = imm
                    ck(bytes(exp) == tap,
                       'ppp6e egr/%s: the wire is the frame with one cell rewritten'
                       % a['arm'])
            else:
                # measured: on the receive path the packet-socket copy is the
                # frame before the rule wrote it
                ck(tap[14:] == p,
                   'ppp6e ing/%s: the rx tap copy is the pre-write frame'
                   % a['arm'])
    # the printed frame must be the frame the door actually saw
    if fr_norm and 'ppp' in L['frame']:
        pr = L['frame']['ppp']
        ck(len(pr) == len(fr_norm) and pr[12:] == fr_norm[12:],
           'the printed ppp frame is the frame at the door, past the MACs')
    if fr_fake and 'fake' in L['frame']:
        ck(len(L['frame']['fake']) == len(fr_fake), 'the printed crafted frame travels')
    # the frames the log printed, checked against their own bytes
    if fr_norm:
        ck(fr_norm[12:14] == b'\x88\x64', 'the ppp frame is PPPoE on the wire')
        ck(be16(fr_norm, 20) == 0x0057, 'the PPP protocol field says IPv6')
        ck((fr_norm[22] >> 4) == 6, 'the inner header at 22 is IPv6')
        ck(be16(fr_norm, 18) == len(fr_norm) - 20, 'the PPPoE length covers the rest')
        ck(be16(fr_norm, 26) == 26, 'the inner payload_len is 26')
    if fr_fake:
        ck((fr_fake[36] >> 4) == 6,
           'the crafted frame carries a version-6 nibble at 36')
        ck(fr_fake[36] != fr_norm[36],
           'the crafted frame differs from the normal one at 36')
        ck((fr_fake[22] >> 4) == 6, 'and a real IPv6 header at 22')
    # the facts the section is about, stated as checks
    by = {}
    for a in arms:
        by.setdefault((a['door'], a['arm']), a)

    def A_(door, arm):
        if (door, arm) not in by:
            ck(False, 'ppp6e: the arm %s/%s is missing from the log' % (door, arm))
            return {k: '0' for k in ('cnts', 's', 'tap', 'sn', 'p', 'imm')}
        return by[(door, arm)]

    ck(A_('egr', 'proto_ppp')['cnts'] == '1',
       'egress ppp: meta protocol reports the inner ethertype')
    ck(A_('egr', 'l4_ppp')['cnts'] == '0',
       'egress ppp: meta l4proto does not see the inner transport')
    ck(A_('egr', 'nh0_ppp')['cnts'] == '1',
       'egress ppp without meta: the @nh base is skb_network_offset = 14')
    ck(A_('egr', 'nh_m_ppp')['cnts'] == '0',
       'egress ppp with meta: the failed validation resets the base to 0')
    ck(A_('egr', 'nhw_ppp')['cnts'] == '0',
       'egress ppp: @nh write refused (no ETH_P_PPP_SES case in the guard)')
    ck(A_('egr', 'thw_ppp')['cnts'] == '0',
       'egress ppp: @th write refused (no L4 flags)')
    ck(A_('egr', 'thw_ppp_m')['cnts'] == '0',
       'egress ppp with meta: still refused, the version byte at 36 is not 6')
    ck(A_('egr', 'fak_l4')['cnts'] == '1',
       'crafted frame: meta l4proto = 17, the walk starts at 22')
    ck(A_('egr', 'fak_nh')['cnts'] == '1',
       'crafted frame: the @nh read lands at 36 (the attacker bytes)')
    ck(A_('egr', 'fak_thw')['cnts'] == '1',
       'crafted frame: @th write accepted')
    fk = A_('egr', 'fak_thw')
    st = bytes.fromhex(fk['s'])
    ck(st[62:64] == b'\x90\x91',
       'crafted frame: the write landed at 62, the real transport header')
    ck(A_('ing', 'in_nhw')['cnts'] == '1',
       'ingress ppp: @nh write accepted (the guard is a constant there)')
    it = bytes.fromhex(A_('ing', 'in_nhw')['s'])
    ck(it[7] == 0x90, 'ingress ppp: the write landed at data+7, the PPP field')
    ck(A_('ing', 'in_thw')['cnts'] == '0',
       'ingress ppp without meta: @th refused')
    ck(A_('ing', 'in_thw_m')['cnts'] == '1',
       'ingress ppp with meta: @th accepted')
    im_ = bytes.fromhex(A_('ing', 'in_thw_m')['s'])
    ck(im_[48:50] == b'\x90\x91',
       'ingress ppp with meta: the write landed at data+48, the real sport')
    ck(A_('egr', 'nhw_plain')['cnts'] == '1',
       'plain: @nh write accepted at the egress door')
    ck(A_('egr', 'thw_plain')['cnts'] == '1',
       'plain: @th write accepted at the egress door')
    pt = bytes.fromhex(A_('egr', 'thw_plain')['tap'])
    ck(pt[54:56] == b'\x90\x91', 'plain: the write landed at 54, the sport')
    hp = bytes.fromhex(A_('egr', 'nhw_plain')['tap'])
    ck(hp[21] == 0x90, 'plain: the @nh write landed at 21, the hop limit')
    # determinism inside one boot: the repeat of ctl_ppp
    reps = [a for a in arms if a['arm'] == 'ctl_ppp']
    if len(reps) >= 2:
        ck(reps[0]['tap'][24:] == reps[-1]['tap'][24:],
           'ppp6e: the repeated control arm is byte-identical past the MACs')
    return len(arms)


# ----------------------------------------------------------------- th6 ------

def check_th6(rep, L):
    arms = L['T']
    ck(len(arms) >= 30, 'th6: at least 30 arms, got %d' % len(arms))
    for a in arms:
        # the frame the arm sent (rebuilt by the differ for every fwd arm)
        shape = {'bare': 0, 'hbh': 8, 'hbd': 16, 'ah': 24, 'rh': 8}[a['shape']]
        if a['cls'] == 'fwd':
            fr = [x for x in L['frame6'] if x[0] == a['shape']]
            if not fr:
                ck(False, 'th6 %s: no frame printed for the shape' % a['arm'])
                continue
            fr = fr[0][1]
            base, noff = 0, 0
        else:
            fr = None
            base, noff = 14, 14
        if fr is not None:
            ck((fr[14] >> 4) == 6, 'th6 %s: the frame starts with IPv6' % a['shape'])
            ck(be16(fr, 18) == 26 + shape,
               'th6 %s: payload_len covers ext + udp' % a['shape'])
            if a['shape'] == 'ah':
                ck(fr[54] == 17 and fr[55] == 4, 'th6 ah: the AH header is 24 bytes')
        # the base the walk produces, as an offset in the frame
        tot = 40 + shape
        if a['arm'] in ('thw', 'thr', 'cs'):
            # for the loc class the datagram is always bare
            ext = 0 if a['cls'] == 'loc' else shape
            want = 14 + 40 + (0 if a['shape'] == 'ah' else ext)
            if a['arm'] in ('thr',):
                ck(a['lives'] == '1', 'th6 %s/%s/%s: the read was allowed'
                   % (a['door'], a['cls'], a['arm']))
            elif a['l4cmp'] == '-1':
                ck(a['lives'] == '1', 'th6 %s/%s/%s: the write was allowed'
                   % (a['door'], a['cls'], a['arm']))
                tap = bytes.fromhex(a['tap']) if a['tap'] else b''
                if a['cls'] == 'loc' or a['shape'] == 'bare':  # the two the tap keeps
                    ck(len(tap) > want + 2, 'th6 %s: a wire frame long enough' % a['arm'])
                    if len(tap) > want + 2:
                        imm = b'\x90\x91'
                        ck(tap[want:want + 2] == imm,
                           'th6 %s/%s/%s: the wire carries the write at %d'
                           % (a['door'], a['cls'], a['shape'], want))
                        if a['arm'] == 'thr':
                            ck(tap[want:want + 2] == b'\x9c\x40',
                               'th6 thr: the read arm wrote nothing')
                # the cost, measured at the receiver
                if a['cls'] == 'loc':
                    ck(int(a['u6n']) == 1, 'th6 loc %s/%s: delivered'
                       % (a['door'], a['shape']))
                    if a['arm'] == 'thw':
                        ck(int(a['u6sport']) == 0x9091,
                           'th6 loc %s/%s: the receiver saw the written sport'
                           % (a['door'], a['shape']))
                    ck(int(a['u6err_d']) == 0, 'th6 loc %s/%s: no udp error'
                       % (a['door'], a['shape']))
                elif a['shape'] == 'ah':
                    # the walk stops at the AH header and nothing after it runs:
                    # the frame dies before the UDP layer either way
                    ck(int(a['u6n']) == 0,
                       'th6 fwd ah/%s: no udp delivery' % a['arm'])
                    ck(int(a['u6err_d']) == 0,
                       'th6 fwd ah/%s: and no udp error either' % a['arm'])
                else:
                    if a['arm'] == 'thw':
                        ck(int(a['u6n']) == 0, 'th6 fwd %s/%s: not delivered'
                           % (a['door'], a['shape']))
                        ck(int(a['u6err_d']) >= 1, 'th6 fwd %s/%s: udp in error'
                           % (a['door'], a['shape']))
                    else:
                        ck(int(a['u6n']) == 1, 'th6 fwd %s/%s cs: delivered'
                           % (a['door'], a['shape']))
                        ck(int(a['u6err_d']) == 0, 'th6 fwd %s/%s cs: no udp error'
                           % (a['door'], a['shape']))
                        ck(int(a['u6sport']) == 0x9091,
                           'th6 fwd %s/%s cs: the receiver saw the written sport'
                           % (a['door'], a['shape']))
        # the walk's exceptions
        if a['arm'] in ('l4_17', 'l4_51'):
            want = 51 if a['shape'] == 'ah' else 17
            ck(a['l4cmp'] == str(want) and a['lives'] == '1' or
               a['l4cmp'] != str(want) and a['lives'] == '0',
               'th6 %s: meta l4proto reports %d on this shape' % (a['shape'], want))
    # the named facts
    def get(door, shape, arm):
        for a in arms:
            if a['door'] == door and a['shape'] == shape and a['arm'] == arm:
                return a
        return None

    a = get('out', 'bare', 'thw')
    ck(a and a['tap'][108:112] == '9091', 'bare loc: the write is the sport')
    a = get('pre', 'bare', 'thw')
    ck(a and a['u6err_d'] == '1', 'bare fwd at prerouting: the write breaks the sum')
    a = get('pre', 'bare', 'cs')
    ck(a and a['u6n'] == '1' and a['u6sport'] == str(0x9091),
       'bare fwd with csum inet: delivered to the written sport')
    a = get('pre', 'ah', 'l4_51')
    ck(a and a['lives'] == '1', 'AH: the walk stops on the auth header')
    a = get('pre', 'ah', 'l4_17')
    ck(a and a['lives'] == '0', 'AH: the transport protocol is not reported')
    for sh in ('hbh', 'hbd', 'rh'):
        a = get('pre', sh, 'cs')
        ck(a and a['u6sport'] == str(0x9091),
           'walk + toll %s: the written sport reached the receiver' % sh)
    return len(arms)


def F570_PAY_OF(shape):
    return 18


# ---------------------------------------------------------------- main ------

def extract_differ(initrd_path):
    """The bytes of root/repro inside the initramfs, read without cpio."""
    import gzip
    import hashlib
    raw = gzip.decompress(open(initrd_path, 'rb').read())
    i, n = 0, len(raw)
    while i + 110 <= n:
        hdr = raw[i:i + 110]
        if hdr[:6] not in (b'070701', b'070702'):
            break
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        name = raw[i + 110:i + 110 + namesize - 1].decode(errors='replace')
        data_at = i + 110 + namesize
        data_at += (-data_at) % 4
        if name in ('root/repro', './root/repro'):
            return hashlib.sha256(raw[data_at:data_at + filesize]).hexdigest()
        i = data_at + filesize
        i += (-i) % 4
    return None


def main():
    reps = sys.argv[1:] or ['rep1', 'rep2']
    kernel = '1efbc957'          # the F41..F47 image, full sha below
    kfull = subprocess.run(['sha256sum',
                            BASE + '/src/linux-7.3.4-T563/arch/x86/boot/bzImage'],
                           capture_output=True, text=True).stdout.split()[0]
    built = subprocess.run(['sha256sum', BASE + '/vm/build/differ570'],
                           capture_output=True, text=True).stdout.split()[0]
    facts = {}
    for rep in reps:
        path = rep if '/' in rep else '%s/logs/f48_%s.log' % (BASE, rep)
        if not os.path.exists(path):
            print('MISSING LOG', path)
            return 2
        L = parse_log(path)
        ck(L['hdr'].get('kernel') == kfull,
           '%s: the kernel sha in the log header is the image on disk' % rep)
        ck(L['hdr'].get('kernel', '').startswith(kernel),
           '%s: the kernel is 7.3.4-T563' % rep)
        got = extract_differ(L['hdr']['initrd_path'])
        ck(got == built,
           '%s: the differ extracted from the initramfs is the built binary' % rep)
        ck(not L['bad_hex'], '%s: every hex column in the log parses (%d bad: %s)'
           % (rep, len(L['bad_hex']), L['bad_hex'][:3]))
        n1 = check_ppp6e(rep, L)
        n2 = check_th6(rep, L)
        # the derived facts, for the cross-boot comparison
        f = []
        for a in L['A']:
            f.append((a['door'], a['arm'], a['cnts'], a['pn'], a['sn'],
                      len(a['p']), len(a['s']), len(a['tap'])))
        for a in L['T']:
            f.append((a['door'], a['cls'], a['shape'], a['arm'], a['lives'],
                      a['u6n'], a['u6err_d'], a['u6sport'], a['taplen']))
        facts[rep] = f
        print('%s: ppp6e arms=%d th6 arms=%d' % (rep, n1, n2))
    if len(reps) == 2:
        ck(facts[reps[0]] == facts[reps[1]],
           'the two boots produce the same derived facts')
    print('checks=%d bad=%d' % (NCHK[0], NBAD[0]))
    for d in DETAIL:
        print('  BAD:', d)
    return 0 if NBAD[0] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
