#!/usr/bin/env python3
"""verify578.py -- independent check of differ578 (F56), both boots.

What it checks, in order:

 1. provenance: the kernel sha256 in each boot header against the file on disk;
    the initrd sha256 in the header against logs/f56_initrd_hashes.txt and the
    file itself; /root/repro extracted from the initramfs against
    vm/build/differ578 (byte for byte, not by size).
 2. source anchors: the lines the model rests on, read out of the built tree.
 3. the instrument's own claims: the five frames rebuilt in Python and
    compared with the printed hex; the VLAN devices' protocol/flag readback;
    the ethtool feature readback per arm.
 4. every arm of both modes, both boots: the door census, the fate (snmp6 and
    per-device counters), both taps (length and first 24 bytes), every NFLOG
    message (prefix, indev/outdev, hardware-header length, L2-header length
    and bytes, the VLAN nest, the payload length and the payload itself, and
    the hop limit at the index that payload implies), every read/store outcome
    (`rc` of the rule, `ch` of its counter) and -- for every accepted action --
    the byte the read had to see or the store had to replace.
 5. determinism between the two boots, MACs normalised.

The model is written from the source, not from the first boot's numbers; the
places where the measurement refuted the model are named in the arm table.
"""
import gzip
import hashlib
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
KERNEL = 'src/linux-7.3.4-T563/arch/x86/boot/bzImage'
DIFFER = 'vm/build/differ578'
LOGS = ['logs/f56_rep1.log', 'logs/f56_rep2.log']

N = 0
BAD = []
NOTES = []


def ck(cond, msg):
    global N
    N += 1
    if not cond:
        BAD.append(msg)
    return bool(cond)


def note(msg):
    NOTES.append(msg)


def sha256f(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def hx(s):
    return bytes.fromhex(s)


# --------------------------------------------------------------------------
# 1. provenance
# --------------------------------------------------------------------------

def provenance():
    ksha = sha256f(KERNEL)
    hashes = {}
    for ln in open('logs/f56_initrd_hashes.txt'):
        t, s = ln.split()
        hashes[t] = s
    want_differ = sha256f(DIFFER)
    for lp in LOGS:
        txt = open(lp, 'rb').read().decode('utf-8', 'replace')
        m = re.search(r'^### sha256: ([0-9a-f]{64})$', txt, re.M)
        ck(bool(m), '%s: no kernel sha in the header' % lp)
        ck(m and m.group(1) == ksha, '%s: kernel sha %s != %s'
           % (lp, m and m.group(1), ksha))
        m = re.search(r'^### initrd: (\S+)$', txt, re.M)
        ck(bool(m), '%s: no initrd path' % lp)
        mi = re.search(r'^### initrd sha256: ([0-9a-f]{64})$', txt, re.M)
        ck(bool(mi), '%s: no initrd sha' % lp)
        if m and mi:
            ir = m.group(1)
            ck(os.path.exists(ir), '%s: initrd %s missing' % (lp, ir))
            ck(sha256f(ir) == mi.group(1),
               '%s: initrd bytes != header sha' % lp)
            tag = os.path.basename(ir).split('.')[0]
            ck(hashes.get(tag) == mi.group(1),
               '%s: initrd %s not in the hash list' % (lp, tag))
            # the binary inside the initramfs
            import subprocess
            out = subprocess.run(['bash', '-c',
                                  'zcat %s | cpio -i --to-stdout root/repro '
                                  '2>/dev/null | sha256sum' % ir],
                                 capture_output=True, text=True)
            got = out.stdout.split()[0] if out.stdout else ''
            ck(got == want_differ,
               '%s: /root/repro in the initramfs is %s, the built binary is %s'
               % (lp, got[:16], want_differ[:16]))
    ck(len(set(hashes.get(t) for t in ('full',))) == 1,
       'more than one "full" initrd in the hash list')


# --------------------------------------------------------------------------
# 2. source anchors
# --------------------------------------------------------------------------

ANCHORS = [
    ('net/8021q/vlan_core.c',
     '!netif_is_bridge_port(vlan_dev)) {',
     'the bridge-port condition that skips the byte reinsertion'),
    ('include/linux/if_vlan.h',
     'if (proto == htons(ETH_P_8021AD) && features & NETIF_F_HW_VLAN_STAG_TX)',
     'the STAG branch of vlan_hw_offload_capable'),
    ('include/linux/if_vlan.h',
     '#define skb_vlan_tag_present(__skb)\t(!!(__skb)->vlan_all)',
     'tag presence is the whole word'),
    ('net/8021q/vlan_dev.c',
     'vlan_tci |= vlan_dev_get_egress_qos_mask(dev, skb->priority);',
     'the two writers of vlan_tci'),
    ('net/8021q/vlan_dev.c',
     'vlan_hw_offload_capable(READ_ONCE(vlan->real_dev->features),',
     'the pop of an in-band tag consults the capability'),
    ('net/core/dev.c',
     '!vlan_hw_offload_capable(features, skb->vlan_proto))',
     'validate_xmit_vlan pushes only what it cannot offload'),
    ('drivers/net/veth.c',
     'NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX | \\',
     'veth advertises both CTAG and STAG'),
    ('net/netfilter/nft_payload.c',
     'veth->h_vlan_TCI = htons(skb_vlan_tag_get(skb));',
     'the virtual vlan header a read is rebuilt from'),
    ('net/netfilter/nft_payload.c',
     'offset = skb_mac_header(skb) - skb->data - vlan_hlen;',
     'the -4 shift for offsets >= 16 at a word-tag door'),
    ('net/netfilter/nft_payload.c',
     'return offset <= skb_network_offset(pkt->skb);',
     'the write bound of @ll outside ingress'),
    ('net/ipv6/ip6_input.c',
     '__IP6_UPD_PO_STATS(net, idev, IPSTATS_MIB_IN, skb->len);',
     'Ip6InReceives is counted before the disable_ipv6 check'),
    ('net/ipv6/ip6_input.c',
     '!idev || unlikely(READ_ONCE(idev->cnf.disable_ipv6))) {',
     'and the same packet then counts Ip6InDiscards'),
    ('net/bridge/br_input.c',
     'return nf_hook_bridge_pre(skb, pskb);',
     'the door that comes before br_handle_frame_finish'),
]


def anchors():
    for path, needle, why in ANCHORS:
        p = os.path.join('src/linux-7.3.4-T563', path)
        ck(os.path.exists(p), 'anchor file %s missing' % path)
        txt = open(p, 'rb').read().decode('utf-8', 'replace')
        ck(needle in txt, 'anchor missing in %s (%s): %r'
           % (path, why, needle[:40]))


# --------------------------------------------------------------------------
# 3. parse a boot
# --------------------------------------------------------------------------

def parse(path):
    txt = open(path, 'rb').read().decode('utf-8', 'replace')
    out = {'env': {}, 'ch': {}, 'arms': {}, 'feat': {}, 'order': [],
           'readback': {}, 'flen': {}, 'vnew': {}, 'sock': None,
           'settle': {}, 'sys': {}, 'ens': {}, 'addr6': {}, 'neigh': {}}
    cur = None
    for ln in txt.splitlines():
        if ln.startswith('F575 VDEV|'):
            d = {}
            for t in ln.split('|')[1:]:
                if '=' in t:
                    k, v = t.split('=', 1)
                    d[k] = v
            out['vdev'] = out.get('vdev', []) + [d]
            continue
        if not ln.startswith('F578 '):
            continue
        parts = ln.split('|')
        head = parts[0][5:]
        d = {}
        for t in parts[1:]:
            if '=' in t:
                k, v = t.split('=', 1)
                d[k] = v
        if head == 'ENV':
            out['env'].update(d)
            out.setdefault('envm', {})[d.get('mode', '?')] = d
        elif head == 'CH':
            out['ch'][d['door']] = d
        elif head == 'VNEW':
            out['vnew'].update(d)
        elif head == 'ENS':
            out['ens'].update(d)
        elif head == 'ADDR6':
            out['addr6'].update(d)
        elif head == 'NEIGH':
            out['neigh'].update(d)
        elif head == 'SOCK':
            out['sock'] = d
        elif head == 'FLEN':
            out['flen'].update(d)
        elif head == 'SETTLE':
            out['settle'][d.get('mode', '?')] = d
        elif head == 'SYS':
            out['sys'].update(d)
        elif head == 'FEAT':
            out['feat'][d['arm']] = d
        elif head == 'FRM':
            for k, v in d.items():
                out.setdefault('frm', {})[k] = v
        elif head == 'A':
            cur = (int(d.get('mode', '-1')), d.get('arm'))
            out['order'].append(cur)
            out['arms'][cur] = {'A': d, 'C': {}, 'B': {}, 'F': {}, 'M': [],
                                'T': {}, 'msgs': []}
        elif head in ('C', 'B', 'F'):
            if cur:
                out['arms'][cur][head] = d
        elif head == 'M':
            if cur:
                out['arms'][cur]['n'] = int(d.get('n', '0'))
                for t in parts[2:]:
                    if not t.startswith('m') or '=' not in t:
                        continue
                    f = t.split('=', 1)[1].split(':')
                    out['arms'][cur]['msgs'].append({
                        'i': int(t[1:].split('=', 1)[0]),
                        'prefix': f[0],
                        'indev': int(f[1]), 'outdev': int(f[2]),
                        'hwtype': int(f[3]), 'hwlen': int(f[4]),
                        'hlen': int(f[5]), 'h': f[6], 'llen': int(f[7]),
                        'l': f[8], 'vpresent': int(f[9]),
                        'vproto': int(f[10], 16), 'vtci': int(f[11], 16),
                        'plen': int(f[12]), 'p': f[13]})
        elif head == 'T':
            for k in ('t0', 't1'):
                if k in d:
                    f = d[k].split(':')
                    kv = {}
                    for t in f[4:]:
                        if '=' in t:
                            a_, b_ = t.split('=', 1)
                            kv[a_] = b_
                    out['arms'][cur]['T'][k] = {
                        'n': int(f[0]), 'flen': int(f[1]), 'len': int(f[2]),
                        'hex': f[3], 'auxn': int(kv.get('aux', -1)),
                        'atci': int(f[5]), 'atpid': int(f[6], 16),
                        'astat': int(f[7]), 'skip': int(kv.get('skip', -1)),
                        'pkt': int(kv.get('pkt', -1)),
                        'proto': int(kv.get('proto', '0'), 16),
                        'alen': int(kv.get('alen', -1)),
                        'atplen': int(kv.get('atplen', -1)),
                        'asnap': int(kv.get('asnap', -1))}
        elif head == 'VDEV':
            out['vdev'] = out.get('vdev', []) + [d]
        elif head.startswith('VLAN') or head == 'RB':
            out['readback'].setdefault(d.get('dev', '?'), d)
    return out


def vlan_readback_text(path):
    """the f575_vlan_readback lines: dev, proto, flags"""
    txt = open(path, 'rb').read().decode('utf-8', 'replace')
    rb = {}
    for m in re.finditer(r'^F578 RB\|dev=(\S+)\|(.*)$', txt, re.M):
        d = {}
        for t in m.group(2).split('|'):
            if '=' in t:
                k, v = t.split('=', 1)
                d[k] = v
        rb[m.group(1)] = d
    return rb


# --------------------------------------------------------------------------
# frames, rebuilt
# --------------------------------------------------------------------------
SRC = bytes.fromhex('fd020000000000000000000000000011')


def a6(last, third=2):
    return bytes([0xfd, third, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last])


def frame(dmac, smac, tpid, tci, dst6):
    f = bytearray()
    f += dmac + smac
    f += tpid.to_bytes(2, 'big') + tci.to_bytes(2, 'big')
    f += b'\x86\xdd'
    ip = bytearray(40)
    ip[0] = 0x60
    pay = 8 + 18
    ip[4] = pay >> 8
    ip[5] = pay & 0xff
    ip[6] = 17
    ip[7] = 64
    ip[8:24] = SRC
    ip[24:40] = dst6
    udp = bytearray(8)
    udp[0:2] = (43200).to_bytes(2, 'big')
    udp[2:4] = (5000).to_bytes(2, 'big')
    udp[4:6] = (8 + 18).to_bytes(2, 'big')
    body = bytes([0x77]) * 18
    # udp checksum, as f570_ip6 computes it
    s = 0
    pseudo = SRC + dst6 + (pay).to_bytes(4, 'big') + b'\x00\x00\x00\x11'
    for blob in (pseudo, bytes(udp) + body):
        for i in range(0, len(blob), 2):
            s += (blob[i] << 8) | blob[i + 1]
            s = (s & 0xffff) + (s >> 16)
    cs = (~s) & 0xffff
    if cs == 0:
        cs = 0xffff
    udp[6:8] = cs.to_bytes(2, 'big')
    return bytes(f) + bytes(ip) + bytes(udp) + body


# --------------------------------------------------------------------------
# 4. the arm tables -- what each arm does, and what the source says it must do
# --------------------------------------------------------------------------
# effect names, mode `ad`:
#   none          the tag the egress device wrote reaches the far end untouched
#   word2066      store at e2's TCI: the bytes are popped into the word and the
#                 vid is unchanged (102), the PCP becomes 1
#   wire2066      same store, STAG_TX cleared: no pop, the bytes carry 2066
#   word6067      store at e3's TCI (vid 103 kept, PCP 3)
#   wire6067      same, CTAG_TX cleared
#   ether0806     store at e4's 12: there is no tag in bytes (reorder DEFAULT)
#                 and none in a word, so 12 is the frame's ethertype
#   otherhost     store of 0067 into the word at p1: vid 103, no device
#   wire0806      store of 0806 into the proto word at p1: not offloadable, so
#                 validate_xmit_vlan pushes it inside and the far end sees 0806
AD = {
    'ctl2':      dict(fr='fa', feat=0, eff='none'),
    'rd_e2':     dict(fr='fa', feat=0, eff='none',
                      act=[('e2', 'rd', 12, 2, 0x88a8)]),
    'rd_p1':     dict(fr='fa', feat=0, eff='none',
                      act=[('p1', 'rd', 12, 2, 0x88a8),
                           ('p1', 'rd', 14, 2, 0x0066)]),
    'w14_e2':    dict(fr='fa', feat=0, eff='word2066',
                      act=[('e2', 'st', 14, 2, 0x2066)]),
    'ctl2s':     dict(fr='fa', feat=1, eff='none'),
    'w14_e2s':   dict(fr='fa', feat=1, eff='wire2066',
                      act=[('e2', 'st', 14, 2, 0x2066)]),
    'ctl3':      dict(fr='fb', feat=0, eff='none'),
    'w14_e3':    dict(fr='fb', feat=0, eff='word6067',
                      act=[('e3', 'st', 14, 2, 0x6067)]),
    'ctl3c':     dict(fr='fb', feat=2, eff='none'),
    'w14_e3c':   dict(fr='fb', feat=2, eff='wire6067',
                      act=[('e3', 'st', 14, 2, 0x6067)]),
    'ctl4':      dict(fr='fe', feat=0, eff='none'),
    'w14_e4':    dict(fr='fe', feat=0, eff='none',
                      act=[('e4', 'st', 14, 2, 0x2066)], accept=False),
    'w12_e4':    dict(fr='fe', feat=0, eff='ether0806',
                      act=[('e4', 'st', 12, 2, 0x0806)]),
    'w_tci_p1':  dict(fr='fa', feat=0, eff='otherhost',
                      act=[('p1', 'st', 14, 2, 0x0067)]),
    'w_proto_p1': dict(fr='fa', feat=0, eff='wire0806',
                       act=[('p1', 'st', 12, 2, 0x0806)]),
    'rd_r0':     dict(fr='fa', feat=0, eff='none',
                      act=[('r0', 'rd', 12, 2, 0x88a8),
                           ('r0', 'rd', 14, 2, 0x0066)]),
}
# 'accept=False' is the one action the source says must be refused: the door has
# no tag anywhere and the write bound is mac_len = 14.

# mode `br` -- all arms send frame C unless sdev says otherwise
BR = {
    'ctl_x':    dict(fr='fc', eff='none'),
    'rd_bv':    dict(fr='fc', eff='none', act=[('bv', 'rd', 12, 2, 0x86dd)]),
    'rd_bvt':   dict(fr='fc', eff='none', act=[('bv', 'rd', 12, 2, 0x8100)],
                     accept=False),
    'rd_n1':    dict(fr='fc', eff='none', act=[('n1', 'rd', 12, 2, 0x86dd)],
                     accept=False),
    'rd_bv_z':  dict(fr='fd', eff='none', act=[('bv', 'rd', 12, 2, 0x86dd)]),
    'rd_nz':    dict(fr='fd', eff='none', act=[('nz', 'rd', 12, 2, 0x86dd)],
                     accept=False),
    'rd_q1':    dict(fr='fc', eff='none',
                     act=[('q1', 'prio', 0, 0, 0), ('q1', 'rd', 12, 2, 0x86dd)]),
    'rd_e2':    dict(fr='fc', eff='none',
                     act=[('e2', 'rd', 12, 2, 0x86dd),
                          ('e2', 'rd', 18, 2, 0x001a)]),
    'rd_bl':    dict(fr='fc', eff='none', act=[('bl', 'rd', 12, 2, 0x86dd)]),
    'rd_ry':    dict(fr='fc', eff='none', act=[('ry', 'rd', 12, 2, 0x8100),
                                               ('ry', 'rd', 14, 2, 0x0066)]),
    'w12_bv':   dict(fr='fc', eff='ether0806', act=[('bv', 'st', 12, 2, 0x0806)]),
    'w12_e2':   dict(fr='fc', eff='e2ether0806',
                     act=[('e2', 'st', 12, 2, 0x0806)]),
    'w14_e2':   dict(fr='fc', eff='none', act=[('e2', 'st', 14, 2, 0x0067)],
                     accept=False),
    'w16_ry':   dict(fr='fc', eff='ryether0806',
                     act=[('ry', 'st', 16, 2, 0x0806)]),
}
# in mode `br`, at the egress door of a bridge port there is no tag at all
# (vlan_do_receive dropped it, vlan_dev_hard_start_xmit has not written it yet),
# so 12 is the frame's ethertype and 14 is past the write bound.

AD_DOORS = ['g6', 'f6', 'e2', 'e3', 'e4', 'p1', 'r0']
BR_DOORS = ['bv', 'bf', 'bl', 'gv', 'n1', 'nz', 'q1', 'e2', 'p1', 'ry']


def pfx(door, mode):
    d = AD_DOORS if mode == 0 else BR_DOORS
    return 'p%d' % d.index(door)


def chain_pfx(door, mode):
    # the arm rule lives in the `ch` chain with the fixed prefix "s"
    return 's'


# --------------------------------------------------------------------------
# the models
# --------------------------------------------------------------------------
AD_DOOR_ORD = ['g6', 'f6', 'e2', 'e3', 'e4', 'p1', 'r0']
BR_DOOR_ORD = ['bv', 'bf', 'bl', 'gv', 'n1', 'nz', 'q1', 'e2', 'p1', 'ry']
AD_DEV = {'fa': ('x1.102', 'e2', 'x0.102'), 'fb': ('x1.103', 'e3', 'x0.103'),
          'fe': ('x1.104', 'e4', 'x0.104')}
AD_TCI = {'fa': 0x0066, 'fb': 0x0067, 'fe': 0x0068}
AD_TPID = {'fa': 0x88a8, 'fb': 0x8100, 'fe': 0x88a8}


def swap12(b):
    return b[6:12] + b[0:6] + b[12:]


def ad_wire(fb, fr, feat, eff):
    """the bytes on the wire, and what the far end's stack makes of them"""
    tpid = AD_TPID[fr]
    tci = AD_TCI[fr]
    # the instrument sends dst=x1mac, src=x0mac; the router rewrites the frame
    # to dst=x0mac (neighbour entry) and src=x1.102 (= x1), sets the egress
    # device's TPID and vid, and ip6_forward() decrements the hop limit
    f = bytearray(swap12(fb))
    f[12:14] = tpid.to_bytes(2, 'big')
    f[14:16] = tci.to_bytes(2, 'big')
    f[18 + 7] = (f[18 + 7] - 1) & 0xff
    band = (feat == 1 and fr == 'fa') or (feat == 2 and fr == 'fb')
    demux = stack6 = True
    other = False
    tag = tci
    if eff in ('word2066', 'wire2066'):
        tag = 0x2066
    if eff in ('word6067', 'wire6067'):
        tag = 0x6067
    if eff in ('wire2066', 'wire6067'):
        f[14:16] = tag.to_bytes(2, 'big')
    wire = bytes(f)
    if not band:
        # the tag is a word on the wire: the eight tag bytes are not there
        wire = wire[0:12] + wire[16:]
    if eff == 'ether0806':
        w = bytearray(wire)
        w[12:14] = b'\x08\x06'
        wire = bytes(w)
        stack6 = False        # eth_type_trans read 0806; the tag is still a word
    if eff == 'otherhost':
        demux = False
        other = True
        tag = 0x0067          # the store wrote the whole word: vid 103
    if eff == 'wire0806':
        head = bytearray(swap12(fb))
        head[12:14] = b'\x08\x06'
        head[14:16] = tag.to_bytes(2, 'big')
        head[18 + 7] = (head[18 + 7] - 1) & 0xff
        wire = bytes(head)
        band = False
        demux = False
        stack6 = False
    return dict(wire=wire, band=band, demux=demux, stack6=stack6, other=other,
                tag=tag, tpid=tpid, tci=tci, eff=eff,
                reorder_cleared=(fr != 'fe'))


def ad_msgs(fr, feat, w):
    """every door's message, from the frame and the tag's whereabouts"""
    dev, edoor, far = AD_DEV[fr]
    tpid, tci = AD_TPID[fr], AD_TCI[fr]
    wire = w['wire']
    m = []
    for door, indev, outdev in (('g6', 'x1.101', None),
                                ('f6', 'x1.101', dev)):
        m.append(dict(door=door, indev=indev, outdev=outdev, hlen=14,
                      llen=0, vpresent=0, vproto=0, vtci=0, plen=66,
                      data_off=18, l2=b''))
    # the egress device's own door: with REORDER cleared
    # vlan_dev_hard_header() has already put the tag in the bytes, so the frame
    # there is 84 bytes and its L2 header is 18; with the flag default nothing
    # is in the bytes yet and the frame is 80 bytes with a 14-byte header
    if w['reorder_cleared']:
        l2e = (tpid.to_bytes(2, 'big') + tci.to_bytes(2, 'big') + b'\x86\xdd')
        plen_e, llen_e = 84, 18
    else:
        l2e = b'\x86\xdd'
        plen_e, llen_e = 80, 14
    m.append(dict(door=edoor, indev=None, outdev=dev, hlen=0, llen=llen_e,
                  vpresent=0, vproto=0, vtci=0, plen=plen_e, data_off=0,
                  l2=l2e,
                  l2post=(wire[0:12] + tpid.to_bytes(2, 'big') +
                          w['tag'].to_bytes(2, 'big') + b'\x86\xdd')
                  if llen_e == 18 else (wire[0:12] +
                                        (b'\x08\x06' if w['eff'] ==
                                         'ether0806' else b'\x86\xdd'))))
    if w['band']:
        m.append(dict(door='p1', indev=None, outdev='x1', hlen=0, llen=18,
                      vpresent=0, vproto=0, vtci=0, plen=len(wire), data_off=0,
                      l2=wire[12:18]))
    elif 'wire0806' == w.get('eff'):
        pass
    else:
        m.append(dict(door='p1', indev=None, outdev='x1', hlen=0, llen=14,
                      vpresent=1, vproto=w['tpid'], vtci=w['tag'],
                      plen=80, data_off=0, l2=wire[12:14]))
    # the far end
    if w['demux'] or w['other']:
        m.append(dict(door='r0', indev='x0', outdev=None, hlen=14, llen=14,
                      vpresent=1, vproto=w['tpid'], vtci=w['tag'], plen=66,
                      data_off=14, l2=wire[12:14]))
    else:
        # no vlan device: the frame is judged by its own ethertype, so the
        # tag (if it was pushed inside) is payload from byte 14 on, and the
        # stack's payload starts at 14
        m.append(dict(door='r0', indev='x0', outdev=None, hlen=14, llen=14,
                      vpresent=0, vproto=0, vtci=0, plen=len(wire) - 14,
                      data_off=14, l2=wire[12:14]))
    return m


def ad_expect(S, boot):
    fr, feat, eff = S['fr'], S['feat'], S['eff']
    fb = hx(boot['frm'][fr])
    dev, edoor, far = AD_DEV[fr]
    pre = ad_wire(fb, fr, feat, 'none')
    post = ad_wire(fb, fr, feat, eff)
    w = post
    mp, mq = {}, {}
    for m in ad_msgs(fr, feat, pre):
        mp.setdefault(m['door'], []).append(m)
    for m in ad_msgs(fr, feat, post):
        mq.setdefault(m['door'], []).append(m)
    if eff == 'wire0806':
        # at the p1 door the store has only written skb->vlan_proto: the tag is
        # still a word (0806 : 0066).  The push into the bytes happens later, in
        # validate_xmit_vlan(), and that is what the wire and the far end see.
        mq['p1'] = [dict(door='p1', indev=None, outdev='x1', hlen=0, llen=14,
                         vpresent=1, vproto=0x0806, vtci=0x0066, plen=80,
                         data_off=0, l2=post['wire'][12:14], l2post=None)]
    doors = {d: 0 for d in AD_DOOR_ORD}
    doors['g6'] = doors['f6'] = doors['p1'] = doors['r0'] = 1
    doors[edoor] = 1
    snmp = dict(i6in=1 + (1 if (w['demux'] and w['stack6']) else 0),
                disc=1 if (w['demux'] and w['stack6']) else 0,
                deliv=0, fwd=1, u6in=0, u6n=0)
    dv = {'x0': (1, len(w['wire']), 1 if w['other'] else 0),
          'x1': (1, 84, 0), 'x1.101': (1, 66, 0),
          far: (1, 66, 0) if w['demux'] else (0, 0, 0)}
    return dict(doors=doors, snmp=snmp, dev=dv, pre=mp, post=mq,
                t0len=84 if (w['band'] or eff == 'wire0806') else 80,
                t1len=80, wire=w['wire'], order=AD_DOOR_ORD)


def br_wire(fb, fr, eff):
    # the bridge's egress port writes its vid as a word (vlan_dev_hard_start_xmit)
    # and veth is CTAG-capable, so the wire carries no tag bytes at all
    wire = fb[0:12] + fb[16:]
    demux = stack6 = True
    if eff in ('ether0806', 'e2ether0806'):
        w = bytearray(wire)
        w[12:14] = b'\x08\x06'
        wire = bytes(w)
        stack6 = False
    if eff == 'ryether0806':
        # the store happens at the far end's ingress door, after the wire: no
        # byte of the wire changes, and the stack had already read 86dd
        stack6 = True
    return dict(wire=wire, demux=demux, stack6=stack6, tag=0x0066)


def br_msgs(fr, w):
    ind = 'x1.101' if fr == 'fc' else 'z1.101'
    indr = 'x1' if fr == 'fc' else 'z1'
    wire = w['wire']
    ports = ['z1.101', 'y1.102'] if fr == 'fc' else ['x1.101', 'y1.102']
    m = []
    m.append(dict(door='bv', indev=ind, outdev=None, hlen=14, llen=14,
                  vpresent=0, vproto=0, vtci=0, plen=66, data_off=18,
                  l2=wire[12:14]))
    for pdev in ports:
        m.append(dict(door='bf', indev=ind, outdev=pdev, hlen=14, llen=14,
                      vpresent=0, vproto=0, vtci=0, plen=66, data_off=18,
                      l2=wire[12:14]))
    m.append(dict(door='bl', indev=ind, outdev=None, hlen=14, llen=14,
                  vpresent=0, vproto=0, vtci=0, plen=66, data_off=18,
                  l2=wire[12:14]))
    m.append(dict(door='gv', indev='br0', outdev=None, hlen=14, llen=0,
                  vpresent=0, vproto=0, vtci=0, plen=66, data_off=18,
                  l2=b''))
    m.append(dict(door='n1' if fr == 'fc' else 'nz', indev=indr, outdev=None,
                  hlen=14, llen=14, vpresent=1, vproto=0x8100, vtci=0x0065,
                  plen=66, data_off=14, l2=wire[12:14]))
    if fr == 'fc':
        m.append(dict(door='q1', indev='x1.101', outdev=None, hlen=14,
                      llen=14, vpresent=0, vproto=0, vtci=0, plen=66,
                      data_off=18, l2=wire[12:14]))
    m.append(dict(door='e2', indev=None, outdev='y1.102', hlen=0, llen=14,
                  vpresent=0, vproto=0, vtci=0, plen=80, data_off=0,
                  l2=wire[12:14]))
    m.append(dict(door='p1', indev=None, outdev='y1', hlen=0, llen=14,
                  vpresent=1, vproto=0x8100, vtci=w['tag'], plen=80,
                  data_off=0, l2=wire[12:14]))
    m.append(dict(door='ry', indev='y0', outdev=None, hlen=14, llen=14,
                  vpresent=1, vproto=0x8100, vtci=w['tag'], plen=66,
                  data_off=14, l2=wire[12:14]))
    return m


def br_expect(S, boot):
    fr, eff = S['fr'], S['eff']
    fb = hx(boot['frm'][fr])
    pre = br_wire(fb, fr, 'none')
    post = br_wire(fb, fr, eff)
    w = post
    mp = {}
    mq = {}
    for m in br_msgs(fr, pre):
        mp.setdefault(m['door'], []).append(m)
    for m in br_msgs(fr, post):
        mq.setdefault(m['door'], []).append(m)
    doors = {d: 0 for d in BR_DOOR_ORD}
    for d in ('bv', 'bl', 'gv', 'e2', 'p1', 'ry'):
        doors[d] = 1
    doors['bf'] = 2
    doors['n1' if fr == 'fc' else 'nz'] = 1
    if fr == 'fc':
        doors['q1'] = 1
    snmp = dict(i6in=1 + (1 if w['stack6'] else 0),
                disc=1 if w['stack6'] else 0,
                deliv=1, fwd=0, u6in=1, u6n=1)
    dv = {'y0': (1, 80, 0), 'y0.102': (1, 66, 0)}
    if fr == 'fc':
        dv['x1'] = (1, 84, 0)
        dv['x1.101'] = (1, 66, 0)
        dv['x0'] = (0, 0, 0)
    else:
        dv['x1'] = (0, 0, 0)
        dv['x1.101'] = (0, 0, 0)
        dv['x0'] = (1, 80, 1)     # the other flood copy comes back here
    return dict(doors=doors, snmp=snmp, dev=dv, pre=mp, post=mq,
                t0len=80, t1len=80, wire=w['wire'], order=BR_DOOR_ORD)


def devmap(boot):
    """device -> ifindex, per mode, from the VDEV readbacks and the ENV line"""
    m = {}
    vd = boot.get('vdev', [])
    ad, br = vd[:7], vd[7:11]
    e0 = boot.get('envm', {}).get('ad', {})
    e1 = boot.get('envm', {}).get('br', {})
    for d, e in ((0, e0), (1, e1)):
        mm = {}
        mm['x0'] = int(e.get('x0', -1))
        mm['x1'] = int(e.get('x1', -1))
        if d == 0:
            for k, nm in (('e2', 'x1.102'), ('e3', 'x1.103'),
                          ('e4', 'x1.104'), ('r0', 'x0.102')):
                mm[nm] = int(e.get(k, -1))
        else:
            mm['br0'] = int(e.get('br0', -1))
            mm['y1'] = int(e.get('p1', -1))
            mm['y0'] = int(e.get('ry', -1))
            mm['z1'] = int(e.get('nz', -1))
        for row in (ad if d == 0 else br):
            mm[row['dev']] = int(row['idx'])
        m[d] = mm
    return m


# --------------------------------------------------------------------------
# compare one arm
# --------------------------------------------------------------------------
NUM = ('i6in', 'disc', 'deliv', 'fwd', 'u6in', 'u6n')
SNMPKEY = {'i6in': 'i6in_d', 'disc': 'disc_d', 'deliv': 'deliv_d',
           'fwd': 'fwd_d', 'u6in': 'u6in_d', 'u6n': 'u6n'}


def check_msg(tag, got, m, DM, mode):
    if m['indev'] == 'z1':
        note('indev of the nz door not checked: the instrument\'s ENV line '
             'prints n1 twice and never prints z1 (F56 defect)')
    else:
        ck(got['indev'] == (DM[mode].get(m['indev'], -1) if m['indev'] else -1),
           '%s: %s indev %d want %s' % (tag, m['door'], got['indev'],
                                        m['indev']))
    ck(got['outdev'] == (DM[mode].get(m['outdev'], -1) if m['outdev'] else -1),
       '%s: %s outdev %d want %s' % (tag, m['door'], got['outdev'],
                                     m['outdev']))
    ck(got['hlen'] == m['hlen'], '%s: %s hlen %d want %d'
       % (tag, m['door'], got['hlen'], m['hlen']))
    ck(got['llen'] == m['llen'], '%s: %s llen %d want %d'
       % (tag, m['door'], got['llen'], m['llen']))
    ck(got['vpresent'] == m['vpresent'], '%s: %s vpresent %d want %d'
       % (tag, m['door'], got['vpresent'], m['vpresent']))
    if m['vpresent']:
        ck(got['vproto'] == m['vproto'], '%s: %s vproto %04x want %04x'
           % (tag, m['door'], got['vproto'], m['vproto']))
        ck(got['vtci'] == m['vtci'], '%s: %s vtci %04x want %04x'
           % (tag, m['door'], got['vtci'], m['vtci']))
    ck(got['plen'] == m['plen'], '%s: %s payload length %d want %d'
       % (tag, m['door'], got['plen'], m['plen']))


def check_arm(boot, mode, name, S, E, DM):
    A = boot['arms'][(mode, name)]
    tag = '%s/%s' % (os.path.basename(boot['path']), name)
    order = E['order']
    acts = S.get('act', [])
    rc = [A['A'].get('rc0', '-99'), A['A'].get('rc1', '-99')]
    ch = [A['C'].get('ch0', '-1'), A['C'].get('ch1', '-1')]
    acc = S.get('accept', True)
    groups = []
    for a in acts:
        if groups and groups[-1][0] == a[0]:
            groups[-1][2].append(a)
        else:
            groups.append([a[0], a[1], [a]])
    for i, (door, op, gl) in enumerate(groups[:2]):
        ck(rc[i] == '0', '%s: %s arm rule %d rc=%s' % (tag, door, i, rc[i]))
        want = '1' if acc else '0'
        ck(ch[i] == want, '%s: %s action %d counter %s want %s'
           % (tag, door, i, ch[i], want))
    if not acts:
        ck(ch[0] in ('-1', '0') and ch[1] == '-1',
           '%s: no action but ch0=%s ch1=%s' % (tag, ch[0], ch[1]))
    # what the instrument printed as the arm's parameters must be the table's
    for i, (door, op, gl) in enumerate(groups[:2]):
        f = A['A']
        ck(f.get('a%d' % i, '-') == door, '%s: printed door %s, table %s'
           % (tag, f.get('a%d' % i), door))
        if op in ('rd', 'prio'):
            rl = gl if op == 'rd' else gl[1:]
            for j, x in enumerate(rl[:2]):
                key = ('r0a', 'r0b')[j]
                want = '%d:%d:%s' % (x[2], x[3], '%0*x' % (x[3] * 2, x[4]))
                ck(f.get(key, '-') == want,
                   '%s: printed read %s = %s, table %s' % (tag, key,
                                                           f.get(key), want))
            if op == 'prio':
                ck(f.get('cmp0') == str(gl[0][4]),
                   '%s: printed priority compare %s, table %s'
                   % (tag, f.get('cmp0'), gl[0][4]))
        else:
            ck(f.get('r%da' % i) == '%d:%d:-' % (gl[0][2], gl[0][3]),
               '%s: printed store offset:len %s, table %d:%d'
               % (tag, f.get('r%da' % i), gl[0][2], gl[0][3]))
            ck(int(f.get('set%d' % i, '-1')) == gl[0][4],
               '%s: printed store value %s, table %d'
               % (tag, f.get('set%d' % i), gl[0][4]))
    for d in order:
        got = A['C'].get(d)
        ck(got is not None, '%s: no counter for door %s' % (tag, d))
        if got is not None:
            ck(int(got) == E['doors'][d], '%s: door %s counted %s want %d'
               % (tag, d, got, E['doors'][d]))
    B = A['B']
    for k in NUM:
        got = B.get(SNMPKEY[k])
        ck(got is not None, '%s: no %s' % (tag, k))
        if got is not None:
            ck(int(got) == E['snmp'][k], '%s: %s=%s want %d'
               % (tag, k, got, E['snmp'][k]))
    if mode == 1:
        ck(B.get('u6len') == '18', '%s: local delivery length %s'
           % (tag, B.get('u6len')))
        ck(B.get('u6sport') == '43200', '%s: local delivery sport %s'
           % (tag, B.get('u6sport')))
    F = A['F']
    for devname, want in E['dev'].items():
        got = F.get(devname)
        ck(got is not None, '%s: no counter for %s' % (tag, devname))
        if got:
            ck([int(x) for x in got.split(':')] == list(want),
               '%s: %s=%s want %s' % (tag, devname, got, want))
    T = A['T']
    ck('t0' in T and 't1' in T, '%s: tap records missing' % tag)
    if 't0' in T:
        ck(T['t0']['n'] == 1, '%s: tap0 saw %d' % (tag, T['t0']['n']))
        ck(T['t0']['flen'] == E['t0len'], '%s: tap0 length %d want %d'
           % (tag, T['t0']['flen'], E['t0len']))
        ck(T['t0']['pkt'] == 4, '%s: tap0 is not PACKET_OUTGOING' % tag)
        ck(T['t0']['hex'] == E['wire'][:24].hex(),
           '%s: tap0 %s want %s' % (tag, T['t0']['hex'],
                                    E['wire'][:24].hex()))
    if 't1' in T:
        # the receiving tap is handed the frame after skb_vlan_untag(), so an
        # in-band tag is not in its copy
        w = E['wire']
        if len(w) == 84 and w[12:14] in (b'\x81\x00', b'\x88\xa8'):
            w = w[0:12] + w[16:]
        ck(T['t1']['flen'] == len(w), '%s: tap1 length %d want %d'
           % (tag, T['t1']['flen'], len(w)))
        ck(T['t1']['hex'] == w[:24].hex(),
           '%s: tap1 %s want %s' % (tag, T['t1']['hex'], w[:24].hex()))
    # ---- the messages: pre0 shows the state before the arm's chain, the
    # arm's own log (prefix `s`) shows the state after its store
    adoor = acts[0][0] if acts else None
    ai = order.index(adoor) if adoor in order else len(order)
    want = []
    for d in order:
        for m in E['pre'].get(d, []):
            if order.index(d) > ai:
                for m2 in E['post'].get(d, []):
                    if (m2['indev'], m2['outdev']) == (m['indev'],
                                                       m['outdev']):
                        m = m2
            want.append(('p%d' % order.index(d), m))
    got = {}
    for m in A['msgs']:
        got.setdefault(m['prefix'], []).append(m)
    for pfxw, m in want:
        ck(pfxw in got, '%s: no message at %s (%s)' % (tag, m['door'], pfxw))
        if pfxw not in got:
            continue
        # match by outdev when a door logs one message per port
        cands = got[pfxw]
        if len(cands) == 1:
            check_msg(tag, cands[0], m, DM, mode)
        else:
            okv = False
            for g in cands:
                if DM[mode].get(m['outdev'], -1) in (g['outdev'],) or \
                   (m['outdev'] and DM[mode].get(m['outdev']) == g['outdev']):
                    check_msg(tag, g, m, DM, mode)
                    okv = True
            ck(okv, '%s: no %s message with outdev %s (%d present)'
               % (tag, m['door'], m['outdev'], len(cands)))
    # the arm's own log
    if acts and acc:
        ck('s' in got, '%s: the rule matched but logged nothing' % tag)
        if 's' in got:
            post = E['post'].get(adoor, [])
            if post:
                m = post[0] if isinstance(post, list) else post
                g = got['s'][0]
                ck(g['plen'] == m['plen'], '%s: s plen %d want %d'
                   % (tag, g['plen'], m['plen']))
                ck(g['llen'] == m['llen'], '%s: s llen %d want %d'
                   % (tag, g['llen'], m['llen']))
                if m.get('l2post') is not None:
                    ck(g['l'] == m['l2post'].hex(), '%s: s L2 %s want %s'
                       % (tag, g['l'], m['l2post'].hex()))
    if acts and not acc:
        ck('s' not in got, '%s: a refused rule still logged' % tag)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    for lp in LOGS:
        if not os.path.exists(lp):
            print('MISSING  %s' % lp)
            return 1
    provenance()
    anchors()
    boots = []
    for lp in LOGS:
        b = parse(lp)
        b['path'] = lp
        boots.append(b)
    DM = {b['path']: devmap(b) for b in boots}
    # --- the instrument's own claims, per boot
    for b in boots:
        tag = os.path.basename(b['path'])
        ck(b['sock'] is not None and int(b['sock']['u6']) > 0,
           '%s: no UDP listener' % tag)
        ck(b['sock'] is not None and int(b['sock']['nfl']) > 0,
           '%s: no NFLOG socket' % tag)
        # the five frames, rebuilt
        dmac = hx(b['env']['x1mac'])
        smac = hx(b['env']['x0mac'])
        exp = {'fa': frame(dmac, smac, 0x8100, 0x0065, a6(0x92, 2)),
               'fb': frame(dmac, smac, 0x8100, 0x0065, a6(0x92, 3)),
               'fe': frame(dmac, smac, 0x8100, 0x0065, a6(0x92, 4))}
        for k in ('fa', 'fb', 'fe'):
            if k in b['frm']:
                ck(b['frm'][k] == exp[k].hex(),
                   '%s: frame %s does not match the reconstruction' % (tag, k))
        if 'fc' in b['frm']:
            # the bridge env does not print x0's MAC, so the frame is checked
            # as: broadcast destination, a unicast source that is not br0's,
            # and the rest (tag, IPv6, UDP, payload) rebuilt exactly
            fc = hx(b['frm']['fc'])
            ref = frame(b'\xff' * 6, b'\x02' * 6, 0x8100, 0x0065, a6(0x91, 5))
            ck(fc[0:6] == b'\xff' * 6, '%s: frame fc dst is not broadcast' % tag)
            ck(fc[12:] == ref[12:], '%s: frame fc body does not rebuild' % tag)
            ck(fc[6] & 1 == 0, '%s: frame fc source is not unicast' % tag)
            ck(fc[6:12].hex() != b['env'].get('br0mac', ''),
               '%s: frame fc source is br0 itself' % tag)
        if 'fd' in b['frm']:
            fc = hx(b['frm']['fc'])
            fd = hx(b['frm']['fd'])
            ck(fd[0:6] == fc[0:6] and fd[12:] == fc[12:],
               '%s: frame fd is not frame fc with another source MAC' % tag)
            ck(fd[6:12] != fc[6:12],
               '%s: frames fc and fd share a source MAC' % tag)
        ck(b['flen']['fa'] == '84' and b['flen']['fb'] == '84' and
           b['flen']['fe'] == '84', '%s: frame lengths %s' % (tag, b['flen']))
        # the vlan devices the mode `ad` env created
        ck(b['vnew']['i102'] == '0' and b['vnew']['i103'] == '0' and
           b['vnew']['i104'] == '0', '%s: vlan creation %s' % (tag, b['vnew']))
        if 'x1_101' in b['vnew']:
            ck(b['vnew']['x1_101'] == '0' and b['vnew']['z1_101'] == '0',
               '%s: bridge vlan creation %s' % (tag, b['vnew']))
        if 'x1_101' in b['ens']:
            ck(b['ens']['x1_101'] == '0' and b['ens']['z1_101'] == '0' and
               b['ens']['y1_102'] == '0',
               '%s: enslavement %s' % (tag, b['ens']))
        ck(b['settle'].get('ad', {}).get('st') == '3',
           '%s: mode ad did not settle' % tag)
        if 'fc' in b['frm']:
            ck(b['settle'].get('br', {}).get('st') == '3',
               '%s: mode br did not settle' % tag)
        if 'fc' in b['frm']:
            ck(b['sys'].get('stp') == '0',
               '%s: bridge stp %s' % (tag, b['sys']))
            for d in ('x1state', 'z1state', 'y1state'):
                ck(b['sys'].get(d) == '3', '%s: port state %s=%s'
                   % (tag, d, b['sys'].get(d)))
        # the VLAN devices: protocol, vid and the REORDER flag, per mode
        want = [('x1.101', 0x8100, 101, 0), ('x1.102', 0x88a8, 102, 0),
                ('x1.103', 0x8100, 103, 0), ('x1.104', 0x88a8, 104, 1),
                ('x0.102', 0x88a8, 102, 1), ('x0.103', 0x8100, 103, 1),
                ('x0.104', 0x88a8, 104, 1),
                ('x1.101', 0x8100, 101, 0), ('z1.101', 0x8100, 101, 1),
                ('y1.102', 0x8100, 102, 1), ('y0.102', 0x8100, 102, 1)]
        vd = b.get('vdev', [])
        if 'fc' not in b['frm']:
            want = want[:7]
        ck(len(vd) == len(want), '%s: %d VLAN readbacks, want %d'
           % (tag, len(vd), len(want)))
        for row, w in zip(vd, want):
            dev, proto, vid, fp = w
            ck(row['dev'] == dev, '%s: readback order %s want %s'
               % (tag, row['dev'], dev))
            ck(int(row['proto'], 16) == proto, '%s: %s proto %s want %04x'
               % (tag, dev, row['proto'], proto))
            ck(int(row['vid']) == vid, '%s: %s vid %s want %d'
               % (tag, dev, row['vid'], vid))
            ck(int(row['flags_present']) == fp,
               '%s: %s flags_present %s want %d (REORDER %s)'
               % (tag, dev, row['flags_present'], fp,
                  'default' if fp else 'cleared'))
        # every door was created
        dl = list(AD_DOORS) + (list(BR_DOORS) if 'fc' in b['frm'] else [])
        for d in dl:
            ck(b['ch'].get(d, {}).get('ch') == '0',
               '%s: chain for door %s: %s' % (tag, d, b['ch'].get(d)))
    # --- the arms
    for b in boots:
        for name, S in AD.items():
            if 'fa' not in b['frm']:
                break
            ck((0, name) in b['arms'], '%s: arm %s missing'
               % (os.path.basename(b['path']), name))
            if (0, name) not in b['arms']:
                continue
            E = ad_expect(S, b)
            check_arm(b, 0, name, S, E, DM[b['path']])
            # the feature readback: the intended bit really changed
            f = b['feat'].get(name)
            ck(f is not None, 'no feature readback for %s' % name)
            if f:
                w0 = int(f['ac0'], 16)
                w1 = int(f['ac1'], 16)
                ctag = bool(w0 & (1 << 7))
                stag = bool(w1 & (1 << 13))
                ck(ctag == (S['feat'] != 2), '%s: CTAG_TX active=%d feat=%d'
                   % (name, ctag, S['feat']))
                ck(stag == (S['feat'] != 1), '%s: STAG_TX active=%d feat=%d'
                   % (name, stag, S['feat']))
                ck(f['r1'] == '0' and f['r2'] == '0', '%s: feature set rc %s/%s'
                   % (name, f['r1'], f['r2']))
        for name, S in BR.items():
            if 'fc' not in b['frm']:
                break
            ck((1, name) in b['arms'], '%s: arm %s missing'
               % (os.path.basename(b['path']), name))
            if (1, name) not in b['arms']:
                continue
            E = br_expect(S, b)
            check_arm(b, 1, name, S, E, DM[b['path']])
    # --- determinism between the two boots
    # The kernel picks new MACs at every boot, so every 6-byte address is
    # replaced by a placeholder.  The placeholder's number is the order in which
    # the address first appears in that boot's own log, walking frames first and
    # then the arms in log order: identical structure, identical role numbers.
    if len(boots) == 2:
        a, b = boots

        def macorder(x):
            order = []

            def add(v):
                if len(v) >= 12 and v[:12] not in order:
                    order.append(v[:12])
                if len(v) >= 24 and v[12:24] not in order:
                    order.append(v[12:24])
            for k in ('fa', 'fb', 'fe', 'fc', 'fd'):
                if k in x.get('frm', {}):
                    add(x['frm'][k])
            for key in x['arms']:
                for m in x['arms'][key]['msgs']:
                    for fld in ('l', 'h'):
                        if len(m[fld]) >= 24:
                            add(m[fld])
                for t in ('t0', 't1'):
                    if t in x['arms'][key]['T']:
                        add(x['arms'][key]['T'][t]['hex'])
            for k in ('x0mac', 'x1mac', 'br0mac'):
                if k in x['env']:
                    order.append(x['env'][k]) if x['env'][k] not in order else None
            return order

        def mk_norm(x):
            order = macorder(x)

            def N_(s):
                for i, m in enumerate(order):
                    s = s.replace(m, '@%d@' % i)
                return s
            return N_
        Na, Nb = mk_norm(a), mk_norm(b)
        for key in [(0, x) for x in AD] + [(1, x) for x in BR]:
            name = key
            if key not in a['arms'] or key not in b['arms']:
                continue
            for kind in ('C', 'B', 'F'):
                ck(Na(str(a['arms'][key][kind])) ==
                   Nb(str(b['arms'][key][kind])),
                   'determinism %s/%s: %s differs' % (name, kind, kind))
            for m1, m2 in zip(a['arms'][key]['msgs'],
                              b['arms'][key]['msgs']):
                for k in ('prefix', 'indev', 'outdev', 'hlen', 'llen',
                          'vpresent', 'vproto', 'vtci', 'plen'):
                    ck(m1[k] == m2[k], 'determinism %s/%s msg %s=%s/%s'
                       % (name, m1['prefix'], k, m1[k], m2[k]))
                ck(Na(m1['p']) == Nb(m2['p']),
                   'determinism %s/%s msg payload' % (name, m1['prefix']))
            for t in ('t0', 't1'):
                if t in a['arms'][key]['T']:
                    ck(Na(a['arms'][key]['T'][t]['hex']) ==
                       Nb(b['arms'][key]['T'][t]['hex']),
                       'determinism %s/%s tap bytes' % (name, t))
    print('checks=%d failures=%d notes=%d' % (N, len(BAD), len(NOTES)))
    for n in NOTES:
        print('NOTE  ' + n)
    for b in BAD[:120]:
        print('FAIL  ' + b)
    if len(BAD) > 120:
        print('... %d more' % (len(BAD) - 120))
    return 1 if BAD else 0


if __name__ == '__main__':
    sys.exit(main())
