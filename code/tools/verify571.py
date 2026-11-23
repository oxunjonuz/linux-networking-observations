#!/usr/bin/env python3
"""verify571.py -- independent check of the turn-571 instrument (F49).

One frame -- ethernet | PPPoE session (sid 99) | PPP proto 00 57 | IPv6/UDP --
presented to four doors of one boot:

  in3   inet  family, NF_INET_PRE_ROUTING on ppp0   (layer 3, after decap)
  ip63  ipv6  family, NF_INET_PRE_ROUTING on ppp0
  nd1   netdev family, NF_NETDEV_INGRESS on x1      (before decap)
  ip43  ipv4  family, NF_INET_PRE_ROUTING           (a door this frame is not for)

Nothing here reads an expectation out of the log: every number is derived from
the frame the log itself carries, from the door, and from the kernel functions
ported below (nft_payload_eval/set_eval, nft_nh_write_ok_ip6, nft_ll_write_ok,
nft_meta_pktinfo_may_update, pppoe_rcv, ppp_receive_nonmp_frame, ip6_rcv_core,
ip6_input_finish, udp6 checksum).
"""
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
        if len(DETAIL) < 60:
            DETAIL.append(what)
    return bool(cond)


def be16(b, i):
    return (b[i] << 8) | b[i + 1]


def be32(b, i):
    return (b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]


# ------------------------------------------------------------- kernel bits --

def udp6_csum(fr, ip=22, udp=62):
    """UDPv6 checksum of the datagram as it stands (csum field zeroed)."""
    acc = 0
    for i in range(ip + 8, ip + 40, 2):          # saddr + daddr
        acc += be16(fr, i)
    ulen = be16(fr, udp + 4)
    acc += ulen
    acc += 17
    for i in range(udp, udp + ulen, 2):
        if i == udp + 6:
            continue
        w = (fr[i] << 8) | (fr[i + 1] if i + 1 < len(fr) else 0)
        acc += w
    while acc >> 16:
        acc = (acc & 0xffff) + (acc >> 16)
    c = (~acc) & 0xffff
    return c if c else 0xffff


def csum_ok(fr):
    return udp6_csum(fr) == be16(fr, 68)


def nh_write_ok_ip6(off, ln, imm):
    """net/netfilter/nft_payload.c: nft_nh_write_ok_ip6(), case by case."""
    if off == 0:
        return ln <= 4 and (imm[0] >> 4) == 6
    if off == 2:
        return ln <= 2
    if off == 7:                                  # hop_limit
        return ln == 1
    if off == 8:                                  # saddr: <= 16 + 16
        return ln <= 32
    if off == 24:                                 # daddr: <= 16
        return ln <= 16
    return False


def ipv6_walk(fr, ip):
    """ipv6_find_hdr(target=-1, IP6_FH_F_AUTH): returns (nexthdr, thoff)."""
    hdr = ip + 40
    if ip + 40 > len(fr):
        return None, None
    nx = fr[ip + 6]
    for _ in range(8):
        if nx in (0, 43, 44, 51, 60):
            if hdr + 2 > len(fr):
                return None, None
            if nx == 51:
                return 51, hdr
            hl = 8 if nx == 44 else (fr[hdr + 1] + 1) * 8
            nx2 = fr[hdr]
            hdr += hl
            nx = nx2
            continue
        return nx, hdr
    return None, None


def validate6(fr, idx, data_base):
    """__nft_set_pktinfo_ipv6_validate() at data_base + idx (data-relative)."""
    i = data_base + idx
    if i + 40 > len(fr):
        return None
    if (fr[i] >> 4) != 6:
        return None
    plen = be16(fr, i + 4)
    skb_len = len(fr) - data_base - idx
    if plen + 40 > skb_len:
        return None
    tprot, thoff = ipv6_walk(fr, i)
    if tprot is None:
        return None
    return dict(tprot=tprot, thoff=thoff - data_base, nhoff=idx)


# ------------------------------------------------------------------ parse ---

DOORS = {
    'in3':  dict(data=22, mac=22, maclen=0, pf=10),
    'ip63': dict(data=22, mac=22, maclen=0, pf=10),
    'nd1':  dict(data=14, mac=0, maclen=14, pf=5),
    'ip43': None,
}


def parse_log(path):
    out = {'A': [], 'T': [], 'fr': b'', 'env': {}, 'hdr': {}, 'bad': []}
    with open(path, 'r', errors='replace') as f:
        for ln in f:
            ln = ln.rstrip('\n')
            if ln.startswith('### sha256: '):
                out['hdr']['kernel'] = ln.split(': ', 1)[1].strip()
            elif ln.startswith('### initrd sha256: '):
                out['hdr']['initrd'] = ln.split(': ', 1)[1].strip()
            elif ln.startswith('### initrd: '):
                out['hdr']['initrd_path'] = ln.split(': ', 1)[1].strip()
            elif ln.startswith('F571 ENV|'):
                d = dict(p.split('=', 1) for p in ln.split('|') if '=' in p)
                out['env'] = d
            elif ln.startswith('F571 FRAME|'):
                parts = ln.split('|')
                out['fr'] = bytes.fromhex(parts[-1].strip())
            elif ln.startswith('F571 A|'):
                d = dict(p.split('=', 1) for p in ln.split('|') if '=' in p)
                for k in ('pre', 'post', 'postl2hex'):
                    v = d.get(k, '-')
                    if v == '-':
                        d[k] = ''
                    elif len(v) % 2 or any(c not in '0123456789abcdef'
                                           for c in v):
                        out['bad'].append((d.get('arm', '?'), k, v[:16]))
                        d[k] = ''
                out['A'].append(d)
            elif ln.startswith('F571 T|'):
                d = dict(p.split('=', 1) for p in ln.split('|') if '=' in p)
                for k in ('first', 'frame'):
                    if d.get(k) == '-':
                        d[k] = ''
                out['T'].append(d)
    return out


# ------------------------------------------------------------------ model ---

def _fate(out, ip, f, f0):
    """ip6_rcv_core() -> ip6_input_finish() -> udp6_rcv() on the frame after
    the door.  f0 is the frame as ip6_rcv_core saw it (before the door write at
    a layer-3 door, after it at the ingress door)."""
    if not out.get('pkt', False):
        return out
    if (f0[ip] >> 4) != 6:
        out['hdr'] = 1
        return out
    out['i6in'] = 1
    if be16(f0, ip + 4) + 40 > len(f0) - ip:
        out['trunc'] = 1
        return out
    nx, th = ipv6_walk(f, ip)
    if nx != 17:
        out['unk'] = 1
        return out
    if f[ip + 24:ip + 40] != dst6_of(f):
        out['noroute'] = 1
        return out
    out['deliv'] = 1
    if not csum_ok(f):
        out['u6err'] = 1
        return out
    out['u6in'] = 1
    out['u6d'] = 1
    out['sport'] = be16(f, 62)
    return out


def dst6_of(fr):
    """the address that is local on ppp0: the daddr of the control frame"""
    return LOCAL6[0]


LOCAL6 = [None]


def expect(A, fr, srcmac, sid, dst6):
    """What the log line must say, computed from the frame and the door."""
    door = A['door']
    mode = int(A['mode'])
    base = int(A['base'])
    off = int(A['off'])
    ln = int(A['len'])
    imm = bytes.fromhex(A['imm']) if A['imm'] else b''
    mv = bytes.fromhex(A['mv']) if A['mv'] not in ('', '-') else b''
    meta = int(A['meta'])
    csum = int(A.get('csum', '0') or 0)
    cso = int(A.get('cso', '0') or 0)
    LOCAL6[0] = dst6

    if A.get('snt') == '0':
        # the arm never sent a frame
        return dict(cntp=0, lives=0, pre=None, post=None, u6d=0, sport=0,
                    i6in=0, hdr=0, trunc=0, unk=0, noroute=0, deliv=0,
                    u6err=0, u6in=0, prx=0, pby=0, l2=None), False, None, fr
    if door == 'ip43':
        # the chain is not on this frame's path; the frame is delivered
        out = dict(i6in=0, hdr=0, trunc=0, unk=0, noroute=0, deliv=0,
                   u6err=0, u6in=0, u6d=0, sport=0, prx=1, pby=66,
                   pkt=True, cntp=0, lives=0, l2=None)
        out = _fate(out, 22, fr, fr)
        return out, False, None, fr

    D = DOORS[door]
    data = D['data']

    # ---- pktinfo the door builds before any expression
    if door == 'nd1':
        flags, tprot, thoff, nhoff = False, None, None, 0
        eth = 0x8864                     # skb->protocol at netdev ingress
        if meta in (1, 16):              # meta protocol / l4proto: may_update
            eth = 0x86dd                 # nf_flow_pppoe_proto(PPP_IPV6)
            v = validate6(fr, 8, data)   # nhoff = PPPOE_SES_HLEN (8) + 0
            if v:
                flags, tprot = True, v['tprot']
                thoff, nhoff = v['thoff'], 8
    else:
        v = validate6(fr, 0, data)
        flags = bool(v)
        tprot = v['tprot'] if v else None
        thoff = v['thoff'] if v else None
        nhoff = 0
        eth = 0x86dd
    pf = D['pf']

    # ---- meta head (the immediate is C->mv, printed as mv/mlen)
    ok = True
    if meta == 1:
        ok = eth == be16(mv, 0)
    elif meta == 15:
        ok = pf == mv[0]
    elif meta == 16:
        ok = flags and tprot is not None and tprot == mv[0]

    wr_at = None
    fr1 = bytearray(fr)
    if ok and mode in (1, 2):
        if base == 1:                       # @nh
            if door == 'nd1':
                g = True                    # constant: NF_NETDEV_INGRESS
            else:
                g = nh_write_ok_ip6(off, ln, imm)
            at = data + nhoff + off
        elif base == 0:                     # @ll
            if D['maclen'] == 0:
                g = False                   # skb_mac_header_len() == 0
                at = None
            else:
                g = True                    # nft_in_ingress(): constant
                at = D['mac'] + off
        else:                               # @th
            g = flags and tprot != 6
            at = data + (thoff if thoff is not None else 0) + off
        if not g:
            ok = False
        elif at is not None and at + ln <= len(fr1):
            fr1[at:at + ln] = imm
            wr_at = at
        else:
            ok = False
    if ok and mode in (1, 2) and csum == 1 and base == 2 and flags and \
       tprot == 17 and cso == 6:
        # nft_payload_csum_inet(): the transport checksum is recomputed over
        # the packet as it now stands, at thoff + csum_offset
        at = data + (thoff if thoff is not None else 0) + 6
        if at + 2 <= len(fr1):
            c = udp6_csum(bytes(fr1))
            fr1[at:at + 2] = bytes([c >> 8, c & 0xff])
    if ok and mode in (2, 3):
        if base == 0:
            ok = D['maclen'] != 0
            at = D['mac'] + off
        elif base == 1:
            at = data + nhoff + off
        else:
            ok = bool(flags)
            at = data + (thoff if thoff is not None else 0) + off
        if ok:
            ok = bytes(fr1[at:at + ln]) == imm

    # ---- the packet the receiving side gets
    f = bytes(fr1)
    f0 = bytes(fr)
    out = dict(i6in=0, hdr=0, trunc=0, unk=0, noroute=0, deliv=0, u6err=0,
               u6in=0, u6d=0, sport=0, prx=0, pby=0, l2=D['maclen'],
               pf=pf, eth=eth, cntp=1, lives=1 if ok else 0)

    if door == 'nd1':
        # pppoe_rcv() on x1, then ppp_input()/ppp_receive_nonmp_frame()
        out['pkt'] = False
        if be16(f, 12) == 0x8864 and f[14] == 0x11 and \
           be16(f, 18) <= len(f) - 20 and not (f[20] & 1) and \
           be16(f, 16) == sid and f[6:12] == srcmac:
            out['prx'] = 1
            out['pby'] = 66
            out['pkt'] = (be16(f, 20) == 0x0057)
        out = _fate(out, 22, f, f)
    else:
        out['prx'] = 1
        out['pby'] = 66
        out['pkt'] = True
        out = _fate(out, 22, f, f0)
    return out, ok, wr_at, f

def post_bytes(A, fr, fr1):
    return bytes(fr1[DOORS[A['door']]['data']:])


# ------------------------------------------------------------------ checks --

def main():
    rep1 = os.environ.get('V571_REP1', BASE + '/logs/f49_rep1.log')
    rep2 = os.environ.get('V571_REP2', BASE + '/logs/f49_rep2.log')
    L1TXT = rep1
    L2TXT = rep2
    L1 = parse_log(rep1)
    L2 = parse_log(rep2)

    # ---- provenance
    bz = BASE + '/src/linux-7.3.4-T563/arch/x86/boot/bzImage'
    sha = subprocess.run(['sha256sum', bz], capture_output=True,
                         text=True).stdout.split()[0]
    ck(sha == '1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033',
       'kernel sha is the F41..F48 image')
    ck(L1['hdr'].get('kernel') == sha, 'rep1 header sha == file')
    ck(L2['hdr'].get('kernel') == sha, 'rep2 header sha == file')
    ird = BASE + '/vm/initrd571/full.cpio.gz'
    irsha = subprocess.run(['sha256sum', ird], capture_output=True,
                           text=True).stdout.split()[0]
    ck(L1['hdr'].get('initrd') == irsha, 'rep1 initrd sha == file')
    ck(L2['hdr'].get('initrd') == irsha, 'rep2 initrd sha == file')
    # the differ inside the initramfs is the one that was built
    dsha = subprocess.run(['sha256sum', BASE + '/vm/build/differ571'],
                          capture_output=True, text=True).stdout.split()[0]
    tmp = '/tmp/v571_initrd'
    subprocess.run(['rm', '-rf', tmp], check=False)
    subprocess.run(['mkdir', '-p', tmp], check=False)
    with open(tmp + '/i.cpio.gz', 'wb') as o:
        o.write(subprocess.run(['gzip', '-dc', ird], capture_output=True
                               ).stdout)
    subprocess.run(['cpio', '-id', '--quiet', 'root/repro'], cwd=tmp,
                   stdin=open(tmp + '/i.cpio.gz', 'rb'), check=False)
    got = subprocess.run(['sha256sum', tmp + '/root/repro'],
                         capture_output=True, text=True).stdout.split()
    ck(got and got[0] == dsha, 'differ inside the initramfs == built differ')

    for name, L, lp in (('rep1', L1, L1TXT), ('rep2', L2, L2TXT)):
        txt = open(lp, 'rb').read()
        ck(b'KASAN' not in txt and b'BUG:' not in txt and b'Oops' not in txt,
           name + ': no splat')
        ck(len(L['A']) == 71, name + ': 71 arms')
        ck(len(L['T']) == 2, name + ': 2 tap arms')

    fr = L1['fr']
    ck(len(fr) == 88, 'frame is 88 bytes')
    ck(fr[12:14] == b'\x88\x64', 'frame ethertype is PPPoE session')
    ck(fr[14] == 0x11 and be16(fr, 16) == 99, 'PPPoE ver/type and sid 99')
    ck(be16(fr, 18) == 68, 'PPPoE length = 2 + 66 (the IPv6 packet)')
    ck(fr[20:22] == b'\x00\x57', 'PPP protocol 00 57 = IPv6')
    ck((fr[22] >> 4) == 6, 'IPv6 version 6 at frame offset 22')
    ck(be16(fr, 26) == 26, 'IPv6 payload length 26 (UDP 8 + 18)')
    ck(csum_ok(fr), 'the frame as built has a valid UDPv6 checksum')
    srcmac = fr[6:12]
    sid = be16(fr, 16)
    dst6 = fr[46:62]

    # ---- every arm of both boots against the model
    for name, L in (('rep1', L1), ('rep2', L2)):
        fr = L['fr']
        srcmac = fr[6:12]
        sid = be16(fr, 16)
        dst6 = fr[46:62]
        for A in L['A']:
            tag = '%s/%s/%s/%s' % (name, A['door'], A['sec'], A['arm'])
            E, ok, wr_at, want = expect(A, fr, srcmac, sid, dst6)
            ck(int(A['cntp']) == E['cntp'], tag + ': cntp')
            ck(int(A['lives']) == (1 if ok else 0), tag + ': lives')
            ck((A['pre'] != '') == (E['cntp'] == 1), tag + ': pre iff counted')
            ck((A['post'] != '') == (ok and E['cntp'] == 1),
               tag + ': post iff the rule reached its tail')
            if E['cntp'] == 1:
                ck(A['pre'] == fr[DOORS[A['door']]['data']:].hex(),
                   tag + ': pre payload is skb->data')
                ck(int(A['preind']) == (6 if A['door'] in ('in3', 'ip63')
                                        else 4), tag + ': indev')
                ck(int(A['prel2']) == E['l2'], tag + ': NFULA_L2HDR length')
                # ARPHRD_PPP = 512, ARPHRD_ETHER = 1; hard_header_len 22 on
                # ppp0 (PPP_HDRLEN - 2 + 2?) and 14 on a veth
                ck(int(A['preht']) == (512 if A['door'] in ('in3', 'ip63')
                                       else 1), tag + ': NFULA_HWTYPE')
                ck(int(A['prehw']) == (22 if A['door'] in ('in3', 'ip63')
                                       else 14), tag + ': NFULA_HWLEN')
                ck(int(A['prehh']) == (22 if A['door'] in ('in3', 'ip63')
                                       else 14), tag + ': NFULA_HWHEADER len')
                # NFULA_HWHEADER is dev->hard_header_len bytes from
                # skb_mac_header(): on ppp0 that pointer is the IPv6 header
                if A['door'] in ('in3', 'ip63'):
                    ck(A['prehwhex'] == fr[22:44].hex(),
                       tag + ': the "hardware header" of ppp0 is IPv6 bytes')
                else:
                    ck(A['prehwhex'] == fr[0:14].hex(),
                       tag + ': the hardware header of x1 is ethernet')
            if ok and E['cntp'] == 1:
                ck(int(A['postlen']) == len(fr) - DOORS[A['door']]['data'],
                   tag + ': post length')
                if A['door'] == 'nd1':
                    ck(A['postl2hex'] == want[0:14].hex(),
                       tag + ': NFULA_L2HDR is the ethernet header')
                else:
                    ck(A['postl2hex'] == '',
                       tag + ': no NFULA_L2HDR on a layer-3 door')
                # the post payload is the frame with the write applied at the
                # cell the model says, not at the cell the column claims
                ck(A['post'] == want[DOORS[A['door']]['data']:].hex(),
                   tag + ': post payload == frame written at ' + str(wr_at))
            for k, ek in (('i6in_d', 'i6in'), ('i6hdr_d', 'hdr'),
                          ('i6trunc_d', 'trunc'), ('i6unk_d', 'unk'),
                          ('i6noroute_d', 'noroute'), ('deliv_d', 'deliv'),
                          ('u6err_d', 'u6err'), ('u6in_d', 'u6in'),
                          ('u6d', 'u6d'), ('prx_d', 'prx'), ('pby_d', 'pby')):
                ck(int(A[k]) == E[ek], tag + ': ' + k)
            if E['u6d']:
                ck(int(A['u6sport']) == E['sport'], tag + ': delivered sport')

    # ---- the three facts this turn is about, stated as such
    A1 = {a['arm']: a for a in L1['A'] if a['door'] == 'in3'}
    N1 = {a['arm']: a for a in L1['A'] if a['door'] == 'nd1'}
    I1 = {a['arm']: a for a in L1['A'] if a['door'] == 'ip63'}
    # 1. the layer-3 base is the real IPv6 header
    ck(A1['nh0']['imm'] == '60000000', '@nh,0 at layer 3 is 60 00 00 00')
    ck(A1['nh4']['imm'] == '001a', '@nh,4 is the payload length')
    ck(A1['nh7']['imm'] == '40', '@nh,7 is the hop limit')
    ck(int(A1['nh7_ppp']['lives']) == 0, 'and it is not the PPP proto byte')
    # 2. @ll on ppp0 does not exist as a base
    for a in ('ll0', 'll4', 'll8'):
        ck(int(A1[a]['lives']) == 0, '@ll read refused on ppp0: ' + a)
    for a in ('ll0_1', 'll0_2', 'll7_1'):
        ck(int(A1[a]['lives']) == 0, '@ll write refused on ppp0: ' + a)
    ck(int(N1['ll0']['lives']) == 1, '@ll on x1 reads the dst MAC')
    # 3. one expression, two doors
    ck(int(N1['nh7_90']['prx_d']) == 1 and int(N1['nh7_90']['pby_d']) == 66
       and int(N1['nh7_90']['i6in_d']) == 0 and int(N1['nh7_90']['u6d']) == 0,
       'the accepted write at the netdev door: device counted, stack blind')
    ck(N1['nh7_90']['post'][14:16] == '90', 'it wrote the PPP protocol byte')
    ck(int(A1['nh7_90']['u6d']) == 1 and A1['nh7_90']['post'][14:16] == '90',
       'the same write at layer 3 lands on the hop limit and is delivered')
    ck(int(I1['nh7_90']['u6d']) == 1, 'the ip6 family door does the same')
    # 4. @th: two formulas, one byte
    ck(int(A1['th0']['lives']) == 1 and A1['th0']['imm'] == '9c40',
       '@th,0 at layer 3 is the real source port')
    ck(int(N1['th0_m']['lives']) == 1 and N1['th0_m']['imm'] == '9c40',
       '@th,0 at the netdev door needs meta protocol and reads the same port')
    ck(int(N1['th0_nm']['lives']) == 0, 'and without it the base is refused')
    ck(int(N1['th0_2_m_cs']['u6d']) == 1 and
       int(N1['th0_2_m_cs']['u6sport']) == 0x9091,
       'written source port delivered from the pre-decap door')
    ck(int(A1['th0_2_cs']['u6d']) == 1 and
       int(A1['th0_2_cs']['u6sport']) == 0x9091,
       'written source port delivered from layer 3')
    # 5. the guard is the ip6 whitelist, not the netdev constant
    ck(int(A1['nh4_2']['lives']) == 0 and int(A1['nh6_1']['lives']) == 0,
       'layer 3 refuses payload length and next header')
    ck(int(N1['nh4_2_len']['lives']) == 1 and int(N1['nh6_1_proto']['lives']) == 1,
       'the netdev door accepts the same two cells')
    ck(int(A1['nh0_bad']['lives']) == 0 and int(A1['nh0_ok']['lives']) == 1,
       'the version check of case 0 is the value, not the length')
    ck(int(A1['nh8_cs']['lives']) == 1 and int(A1['nh8_cs']['u6d']) == 1,
       'a checksum request on @nh is ignored for IPv6, not refused')
    ck(int(A1['nh8_alt']['u6err_d']) == 1 and int(A1['nh8_same']['u6d']) == 1,
       'saddr: the same value is delivered, another value dies at Udp6InErrors')
    ck(int(A1['nh24_alt']['i6noroute_d']) == 1 and int(A1['nh24_alt']['deliv_d']) == 0,
       'daddr: lost at the route lookup with InNoRoutes')
    # 6. the ip family door does not see this frame
    F1 = {a['arm']: a for a in L1['A'] if a['door'] == 'ip43'}
    ck(int(F1['ctl_ip43']['cntp']) == 0 and int(F1['ctl_ip43']['lives']) == 0
       and F1['ctl_ip43']['pre'] == '',
       'the ipv4 prerouting chain counts nothing for this frame')
    ck(int(F1['ctl_ip43']['i6in_d']) == 1 and int(F1['ctl_ip43']['u6d']) == 1,
       'and the frame is delivered with no rule at all')
    # 7. the tap debt: the filter, not the wire
    T = {t['shape']: t for t in L1['T']}
    ck(int(T['bare']['old']) == 1 and int(T['bare']['new']) == 1,
       'bare shape: both filters see it')
    ck(int(T['hbh']['total']) == 1 and int(T['hbh']['old']) == 0 and
       int(T['hbh']['new']) == 1,
       'hbh shape: the wire carried it, the old filter did not count it')
    ck(T['hbh']['first'] == T['hbh']['frame'], 'the tap bytes are the frame')

    # ---- determinism between the two boots (MACs are assigned per boot)
    def norm(line, macs):
        for m in macs:
            line = line.replace(m, 'MAC')
        return line

    macs1 = [L1['env'].get('x0', ''), L1['env'].get('x1', '')]
    macs2 = [L2['env'].get('x0', ''), L2['env'].get('x1', '')]
    keys = ('door', 'sec', 'arm', 'mode', 'meta', 'base', 'off', 'len', 'imm',
            'cntp', 'lives', 'u6d', 'u6len', 'u6sport', 'i6in_d', 'i6hdr_d',
            'i6addr_d', 'i6unk_d', 'i6trunc_d', 'i6noroute_d', 'deliv_d',
            'u6in_d', 'u6err_d', 'u6noport_d', 'prx_d', 'pby_d', 'prelen',
            'pre', 'prel2', 'preind', 'postlen', 'post', 'postl2', 'postind')
    ck(len(L1['A']) == len(L2['A']), 'both boots ran the same arms')
    for x, y in zip(L1['A'], L2['A']):
        for k in keys:
            vx = norm(x.get(k, ''), macs1)
            vy = norm(y.get(k, ''), macs2)
            ck(vx == vy,
               'determinism %s %s %s: %r != %r' % (x['door'], x['arm'], k,
                                                   vx, vy))
    for x, y in zip(L1['T'], L2['T']):
        for k in ('shape', 'len', 'total', 'old', 'new'):
            ck(x.get(k) == y.get(k), 'tap determinism %s %s' % (x['shape'], k))

    print('checks=%d bad=%d' % (NCHK[0], NBAD[0]))
    for d in DETAIL:
        print('BAD: ' + d)
    return 1 if NBAD[0] else 0


if __name__ == '__main__':
    sys.exit(main())
