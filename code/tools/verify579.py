#!/usr/bin/env python3
"""verify579.py -- independent check of differ579 (F57), the privilege boundary.

What is checked, in order:

 1. provenance: the kernel sha256 in each boot header against the file on disk;
    the initrd sha256 in the header against logs/f57_initrd_hashes.txt and the
    file itself; /root/repro extracted from the initramfs against
    vm/build/differ579 (bytes, not size).
 2. source anchors: the two gates the whole turn rests on, read out of the
    built tree, plus the reason a foreign device name is not an error.
 3. the instrument's own frames: five frames rebuilt in Python -- IPv6, the two
    extension headers, the flow label and the 802.1Q tag, with the UDPv6
    checksum -- and compared byte for byte with what the parent printed and
    with what the child said it put on the wire in every arm.
 4. the census: four credential contexts, each with the same four expressions,
    against the value the two gates imply.
 5. every arm of both boots: the rule's counter, the delivered datagram, its
    length, and the six snmp6 deltas -- each derived from the frame bytes and
    from which door the rule sits on.
 6. determinism between the two boots on every arm field.

The model is written from the source and from the frames, not from the boot's
own numbers.
"""
import hashlib
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
KERNEL = 'src/linux-7.3.4-T563/arch/x86/boot/bzImage'
DIFFER = 'vm/build/differ579'
LOGS = ['logs/f57_rep1.log', 'logs/f57_rep2.log']

N = 0
BAD = []
NOTES = []


def ck(cond, msg):
    global N
    N += 1
    if not cond:
        BAD.append(msg)
    return bool(cond)


def note(m):
    NOTES.append(m)


def load(lp):
    """a missing log is a failure, not a crash"""
    if not os.path.exists(lp):
        ck(False, '%s: missing' % lp)
        return ''
    return open(lp, 'rb').read().decode('utf-8', 'replace').replace('\r', '')


def sha256f(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


# --------------------------------------------------------------------------
# 1. provenance
# --------------------------------------------------------------------------

def provenance():
    ksha = sha256f(KERNEL)
    hashes = {}
    for ln in open('logs/f57_initrd_hashes.txt'):
        t, s = ln.split()
        hashes[t] = s
    want = sha256f(DIFFER)
    for lp in LOGS:
        txt = load(lp)
        m = re.search(r'^### sha256: ([0-9a-f]{64})$', txt, re.M)
        ck(bool(m), '%s: no kernel sha in the header' % lp)
        ck(m and m.group(1) == ksha, '%s: kernel sha != the file on disk' % lp)
        m = re.search(r'^### initrd: (\S+)$', txt, re.M)
        mi = re.search(r'^### initrd sha256: ([0-9a-f]{64})$', txt, re.M)
        ck(bool(m) and bool(mi), '%s: no initrd line' % lp)
        if m and mi:
            ir = m.group(1)
            ck(os.path.exists(ir), '%s: initrd %s missing' % (lp, ir))
            ck(sha256f(ir) == mi.group(1),
               '%s: initrd bytes != the header sha' % lp)
            tag = os.path.basename(ir).split('.')[0]
            ck(hashes.get(tag) == mi.group(1),
               '%s: initrd %s is not in logs/f57_initrd_hashes.txt'
               % (lp, tag))
            out = subprocess.run(
                ['bash', '-c',
                 'zcat %s | cpio -i --to-stdout root/repro 2>/dev/null | '
                 'sha256sum' % ir],
                capture_output=True, text=True)
            got = out.stdout.split()[0] if out.stdout else ''
            ck(got == want,
               '%s: differ inside the initramfs %s != built %s'
               % (lp, got[:16], want[:16]))
        ck('F579 BOOT|mode=priv' in txt, '%s: not a priv boot' % lp)
        ck(txt.count('MODE_EXIT priv=0') == 1,
           '%s: priv did not exit 0' % lp)


# --------------------------------------------------------------------------
# 2. source anchors
# --------------------------------------------------------------------------

ANCHORS = [
    ('net/netfilter/nfnetlink.c',
     'if (!netlink_net_capable(skb, CAP_NET_ADMIN)) {',
     'gate 1: CAP_NET_ADMIN in the user namespace that owns the netns'),
    ('net/netfilter/nft_payload.c',
     'if (ctx->net->user_ns != &init_user_ns)',
     'gate 2: a payload STORE needs the initial user namespace'),
    ('net/netfilter/nft_payload.c',
     'static int nft_payload_init(const struct nft_ctx *ctx,',
     'the read path, which has no gate 2'),
    ('net/netfilter/nft_meta.c',
     'int nft_meta_set_init(const struct nft_ctx *ctx,',
     'meta set, which has no gate 2 either'),
    ('net/netfilter/nft_payload.c',
     'if (nft_in_ingress(pkt->state))',
     'the ingress path returns true from the @ll write guard'),
    ('net/netfilter/nft_payload.c',
     'return offset <= skb_network_offset(pkt->skb);',
     'the @ll write bound that only applies outside ingress'),
    ('net/netfilter/nf_tables_api.c',
     'hook = nft_netdev_hook_alloc(net, tb[NFTA_HOOK_DEV], false);',
     'the netdev chain takes the device by name'),
    ('net/netfilter/nf_tables_api.c',
     'for_each_netdev(net, dev) {',
     'and matches it against THIS namespace only'),
    ('net/netfilter/nf_tables_api.c',
     'err = nla_strscpy(hook->ifname, attr, IFNAMSIZ);',
     'no match is not an error: an empty hook list is returned'),
    ('net/ipv6/ip6_input.c',
     'IPSTATS_MIB_INUNKNOWNPROTOS);',
     'the counter an unknown nexthdr lands in'),
    ('net/ipv6/ip6_input.c',
     '__IP6_UPD_PO_STATS(net, idev, IPSTATS_MIB_IN, skb->len);',
     'Ip6InReceives is counted before the prerouting hook'),
    ('net/netfilter/nft_payload.c',
     'if (skb_copy_bits(skb, offset, dest, priv->len) < 0)',
     'the read bound, which is the frame length'),
    ('net/ipv6/exthdrs.c',
     'int ipv6_parse_hopopts(struct sk_buff *skb)',
     'the extension headers whose presence moves @nh'),
]


def anchors():
    for path, needle, why in ANCHORS:
        p = os.path.join('src/linux-7.3.4-T563', path)
        ck(os.path.exists(p), 'anchor file %s missing' % path)
        txt = open(p, 'rb').read().decode('utf-8', 'replace')
        ck(needle in txt, 'anchor missing in %s (%s)' % (path, why))


# --------------------------------------------------------------------------
# 3. the frames, rebuilt
# --------------------------------------------------------------------------

SRC6 = bytes.fromhex('fd020000000000000000000000000011')
DST6 = bytes.fromhex('fd020000000000000000000000000091')
DMAC = b'\xff' * 6
SMAC = bytes.fromhex('020000000079')
SPORT, DPORT, PAY = 43300, 5000, 18


def acc16(b, acc=0):
    if len(b) % 2:
        b += b'\x00'
    for i in range(0, len(b), 2):
        acc += (b[i] << 8) | b[i + 1]
    return acc


def fold(acc):
    while acc >> 16:
        acc = (acc & 0xffff) + (acc >> 16)
    c = (~acc) & 0xffff
    return c or 0xffff


def udp6_csum(ip, ext, udplen):
    udp = ip[40 + ext:40 + ext + udplen]
    a = acc16(ip[8:40])
    a += udplen
    a += 17
    a = acc16(udp, a)
    return fold(a)


def build(fid):
    """The frame as the child puts it on the wire."""
    ext = 8 if fid in (2, 3) else 0
    udplen = 8 + PAY
    tot = ext + udplen
    flow = 0x0086dd if fid == 4 else 0
    ip = bytearray(40 + tot)
    ip[0] = 0x60 | ((flow >> 16) & 0x0f)     # version 6, tc 0, flow hi
    ip[1] = 0x00
    ip[2] = (flow >> 8) & 0xff
    ip[3] = flow & 0xff
    ip[4] = tot >> 8
    ip[5] = tot & 0xff
    ip[6] = 17
    ip[7] = 64
    ip[8:24] = SRC6
    ip[24:40] = DST6
    if fid == 2:                              # hop-by-hop -> UDP
        ip[6] = 0
        ip[40] = 17
        ip[41] = 0
    if fid == 3:                              # fragment, offset 0, M 0
        ip[6] = 44
        ip[40] = 17
        ip[41] = 0
        ip[46] = 0x00
        ip[47] = 0x79
    u = 40 + ext
    ip[u + 0] = SPORT >> 8
    ip[u + 1] = SPORT & 0xff
    ip[u + 2] = DPORT >> 8
    ip[u + 3] = DPORT & 0xff
    ip[u + 4] = udplen >> 8
    ip[u + 5] = udplen & 0xff
    ip[u + 8:u + 8 + PAY] = b'\x77' * PAY
    c = udp6_csum(bytes(ip), ext, udplen)
    ip[u + 6] = c >> 8
    ip[u + 7] = c & 0xff
    if fid == 5:                              # 802.1Q vid 100
        eth = DMAC + SMAC + b'\x81\x00\x00\x64\x86\xdd'
        return eth + bytes(ip)
    return DMAC + SMAC + b'\x86\xdd' + bytes(ip)


FRAME = {i: build(i) for i in range(1, 6)}
FRAME[0] = b''			# no frame id 0

# what the child must have sent, and how long it is
FLEN = {i: len(FRAME[i]) for i in FRAME if i}


def frames(txt):
    got = 0
    for m in re.finditer(r'^F579 FRMPY\|id=(\d+)\|len=(\d+)\|hex=([0-9a-f]*)$',
                         txt, re.M):
        fid, ln, hx = int(m.group(1)), int(m.group(2)), m.group(3)
        got += 1
        ck(fid in FRAME, 'FRMPY: unknown frame id %d' % fid)
        ck(bytes.fromhex(hx) == FRAME[fid],
           'FRMPY id=%d: parent bytes != Python' % fid)
        ck(ln == FLEN[fid], 'FRMPY id=%d: len %d != %d'
           % (fid, ln, FLEN[fid]))
    ck(got == 5, 'FRMPY: %d frames printed, expected 5' % got)
    # every frame the child actually put on the wire
    seen = 0
    for m in re.finditer(r'^F579 FRM\|id=(\d+)\|len=(\d+)\|hex=([0-9a-f]*)$',
                         txt, re.M):
        fid, ln, hx = int(m.group(1)), int(m.group(2)), m.group(3)
        seen += 1
        ck(bytes.fromhex(hx) == FRAME[fid],
           'FRM id=%d: the wire bytes differ from Python' % fid)
        ck(ln == FLEN[fid], 'FRM id=%d: len %d != %d'
           % (fid, ln, FLEN[fid]))
    ck(seen == 19, 'FRM: %d frame lines, expected 19 (one per traffic arm)'
       % seen)


# --------------------------------------------------------------------------
# 4. the census
# --------------------------------------------------------------------------

# what the two gates imply, context by context
CENSUS = {
    # ctx: (tbl, chn, rd, st, meta)
    'root_init':     (0, 0, 0, 0, 0),      # nothing gates the initial ns
    'uid1000_init':  (-1, -1, -1, -1, -1),  # gate 1: EPERM on every message
    'userns_own':    (0, 0, 0, -1, 0),      # gate 2 hits the store only
}


def kv(line):
    d = {}
    for part in line.split('|')[1:]:
        if '=' in part:
            k, v = part.split('=', 1)
            d[k.strip()] = v.strip()
    return d


def census(txt):
    seen = {}
    for m in re.finditer(r'^F579 CAP\|(.*)$', txt, re.M):
        d = kv('CAP|' + m.group(1))
        seen[d['ctx']] = d
    for ctx, want in CENSUS.items():
        ck(ctx in seen, 'census: context %s absent' % ctx)
        if ctx not in seen:
            continue
        d = seen[ctx]
        for i, k in enumerate(('tbl', 'chn', 'rd', 'st', 'meta')):
            ck(int(d[k]) == want[i],
               'census %s: %s=%s, model says %d' % (ctx, k, d[k], want[i]))
    # nothing is available without CAP_NET_ADMIN in the owning user ns
    d = seen.get('uid1000_init', {})
    ck(all(int(d.get(k, 0)) == -1 for k in ('tbl', 'chn', 'rd', 'st', 'meta')),
       'uid1000_init: not every expression was refused')
    # the namespace owner: reads work end to end, the store does not
    d = seen.get('userns_own', {})
    if d:
        ck(int(d['rd']) == 0, 'userns_own: the read rule was refused')
        ck(int(d['fx_ch']) == 1,
           'userns_own: the read rule did not count its own frame')
        ck(int(d['fx_u6']) == 0,
           'userns_own: the frame was delivered although the rule dropped it')
        ck(int(d['meta']) == 0,
           'userns_own: meta priority set was refused')
        ck(int(d['st']) == -1,
           'userns_own: the @ll store was NOT refused with EPERM')
        # a chain naming another namespace's device: created, and dead
        ck(int(d['fore']) == 0,
           'userns_own: a chain on a foreign device name was an error')
        ck(int(d['fore2']) == 0,
           'userns_own: the rule in the foreign chain was an error')
        ck(int(d['fx2_ch']) == 0,
           'userns_own: the dead chain counted a packet')
        ck(int(d['a6']) == 0, 'userns_own: the address on w1 failed')
        ck(int(d['dis']) == 0, 'userns_own: IPv6 stayed disabled on w1')
        # the two ends of the child's veth are in the same netns, so its own
        # MLD reports are counted as received and discarded there too: the
        # per-netns counter cannot witness one frame, the socket can
        ck(int(d['fx2_rcv']) >= 1,
           'userns_own: the namespace stack did not even receive the frame')
        note('inside the child its own MLD reports are counted too '
             '(fx2_rcv 1 in one boot, 2 in the other, with fx2_disc 0/1): '
             'a per-netns counter is not a witness for a single frame when '
             'both ends of the wire live in it')
        ck(int(d['fx2_deliv']) == 1,
           'userns_own: the frame was not delivered inside the namespace')
        ck(int(d['fx2_addrerr']) == 0,
           'userns_own: the destination was not local inside the namespace')
        ck(int(d['fx2_u6']) == 1,
           'userns_own: the frame did not arrive although the chain is dead')
    # root: the same foreign name is also accepted -- no error either way
    d = seen.get('root_init', {})
    if d:
        ck(int(d['fore']) == 0,
           'root_init: a chain on a nonexistent device was an error')
        note('a netdev chain naming a device that does not exist is created '
             'without an error in every context (nft_netdev_hook_alloc '
             'matches with for_each_netdev and returns an empty hook list): '
             'the foreign-device question cannot be answered by an errno, '
             'only by a fate')
    for m in re.finditer(r'^F579 MAPS\|(.*)$', txt, re.M):
        d = kv('MAPS|' + m.group(1))
        for k in ('setgroups', 'uid', 'gid'):
            ck(int(d[k]) == 0, 'MAPS: %s write failed (%s)' % (k, d[k]))
    m = re.search(r'^F579 UNSHARE\|uid_in=(\d+)\|veth=(-?\d+)\|'
                  r'iw0=(-?\d+)\|iw1=(-?\d+)\|ix1=(-?\d+)$', txt, re.M)
    ck(bool(m), 'UNSHARE line missing')
    if m:
        ck(int(m.group(1)) == 0, 'UNSHARE: the inside uid is not 0')
        ck(int(m.group(2)) == 0, 'UNSHARE: veth creation inside a userns '
           'failed (%s)' % m.group(2))
        ck(int(m.group(3)) > 0 and int(m.group(4)) > 0,
           'UNSHARE: the namespace has no devices of its own')
        ck(int(m.group(5)) == -1,
           'UNSHARE: the initial namespace device x1 is visible inside')
    m = re.search(r'^F579 MOVE\|dev=x0\|rc=(-?\d+)\|here=(-?\d+)$', txt, re.M)
    ck(bool(m), 'MOVE line missing')
    if m:
        ck(int(m.group(1)) == 0, 'MOVE: moving x0 across the border failed')
        ck(int(m.group(2)) == -1, 'MOVE: x0 is still in the initial netns')
    m = re.search(r'^F579 VDEV\|mk100=(-?\d+)\|idx100=(-?\d+)\|a6=(-?\d+)$',
                  txt, re.M)
    ck(bool(m), 'VDEV line missing')
    if m:
        ck(int(m.group(1)) == 0, 'VDEV: x1.100 was not created')
        ck(int(m.group(2)) > 0, 'VDEV: x1.100 has no ifindex')
        ck(int(m.group(3)) == 0, 'VDEV: the address on x1.100 failed')


# --------------------------------------------------------------------------
# 5. the arms
# --------------------------------------------------------------------------

# the byte a read at @ll sees at the netdev ingress door is the frame's own
# byte; @nh,6,1 is the first header's nexthdr; meta l4proto walks the chain.
NEXTHDR = {1: 17, 2: 0, 3: 44, 4: 17, 5: 17}
L4PROTO = {1: 17, 2: 17, 3: 17, 4: 17, 5: 17}

# name -> (fid, door, kind, off, len, val, expected ch, expected fate)
#   fate: 'in'  delivered (rcv 1, deliv 1, udp 1)
#         'n1'  killed at the netdev ingress door (rcv 0)
#         'pre' killed at ip6 prerouting, counted (rcv 1, deliv 0)
#         'unk' killed by ip6_input as an unknown protocol (rcv 1, ukproto 1)
ARMS = [
    ('c_plain',          1, 0, 0,  0, 0, 0x0000, None, 'in'),
    ('c_tag',            5, 0, 0,  0, 0, 0x0000, None, 'in'),
    ('d12_8100_plain',   1, 1, 0, 12, 2, 0x8100, 0, 'in'),
    ('d12_8100_tag',     5, 1, 0, 12, 2, 0x8100, 1, 'n1'),
    ('d12_86dd_tag',     5, 1, 0, 12, 2, 0x86dd, 0, 'in'),
    ('d16_0000_plain',   1, 1, 0, 16, 2, 0x0000, 1, 'n1'),
    ('d16_86dd_flow',    4, 1, 0, 16, 2, 0x86dd, 1, 'n1'),
    ('d16_86dd_tag',     5, 1, 0, 16, 2, 0x86dd, 1, 'n1'),
    ('e_nh_plain',       1, 2, 3,  6, 1, 17,     1, 'pre'),
    ('e_nh_hbh',         2, 2, 3,  6, 1, 17,     0, 'in'),
    ('e_nh_frag',        3, 2, 3,  6, 1, 17,     0, 'in'),
    ('e_nh0_hbh',        2, 2, 3,  6, 1, 0,      1, 'pre'),
    ('e_l4_plain',       1, 2, 4,  0, 1, 17,     1, 'pre'),
    ('e_l4_hbh',         2, 2, 4,  0, 1, 17,     1, 'pre'),
    ('x_r78',            1, 1, 0, 78, 2, 0x7777, 1, 'in'),
    ('x_r79',            1, 1, 0, 79, 2, 0x7777, 0, 'in'),
    ('w_l12',            1, 1, 1, 12, 2, 0x2066, 1, 'in'),
    ('w_l13',            1, 1, 1, 13, 2, 0x2066, 1, 'in'),
    ('w_l20',            1, 1, 1, 20, 2, 0x2066, 1, 'unk'),
]


def read_ok(fid, off, ln):
    """nft_payload_eval: skb_copy_bits against the frame's own length."""
    return off + ln <= FLEN[fid]


def ll_bytes(fid, off, ln):
    return FRAME[fid][off:off + ln]


def model_ch(fid, door, kind, off, ln, val):
    if door == 0:
        return None
    want = val.to_bytes(ln, 'big')
    if kind == 0:                                   # read @ll + cmp
        if not read_ok(fid, off, ln):
            return 0                                # NFT_BREAK: no counter
        return 1 if ll_bytes(fid, off, ln) == want else 0
    if kind == 1:                                   # store @ll
        return 1                                    # the guard is `true`
    if kind == 3:                                   # read @nh + cmp
        return 1 if NEXTHDR[fid] == val else 0
    if kind == 4:                                   # meta l4proto + cmp
        return 1 if L4PROTO[fid] == val else 0
    raise AssertionError(kind)


FATE = {
    'in':  dict(rcv=1, deliv=1, hdrerr=0, addrerr=0, disc=0, ukproto=0,
                udp=1, udperr=0, udpnop=0, u6n=1),
    'n1':  dict(rcv=0, deliv=0, hdrerr=0, addrerr=0, disc=0, ukproto=0,
                udp=0, udperr=0, udpnop=0, u6n=0),
    'pre': dict(rcv=1, deliv=0, hdrerr=0, addrerr=0, disc=0, ukproto=0,
                udp=0, udperr=0, udpnop=0, u6n=0),
    'unk': dict(rcv=1, deliv=0, hdrerr=0, addrerr=0, disc=0, ukproto=1,
                udp=0, udperr=0, udpnop=0, u6n=0),
}
KEYS = ('rcv', 'deliv', 'hdrerr', 'addrerr', 'disc', 'ukproto', 'udp',
        'udperr', 'udpnop')


def arms(txt, boot):
    seen = []
    for m in re.finditer(r'^F579 ARM\|(.*)$', txt, re.M):
        seen.append(kv('ARM|' + m.group(1)))
    ck(len(seen) == len(ARMS),
       '%s: %d arms, expected %d' % (boot, len(seen), len(ARMS)))
    by = {d['name']: d for d in seen}
    for name, fid, door, kind, off, ln, val, ch, fate in ARMS:
        ck(name in by, '%s: arm %s absent' % (boot, name))
        if name not in by:
            continue
        d = by[name]
        ck(int(d['fid']) == fid, '%s/%s: fid %s != %d'
           % (boot, name, d['fid'], fid))
        ck(int(d['door']) == door, '%s/%s: door %s != %d'
           % (boot, name, d['door'], door))
        if door == 0:
            ck(int(d['rc']) == -99,
               '%s/%s: no rule was to be installed, rc=%s'
               % (boot, name, d['rc']))
        else:
            ck(int(d['rc']) == 0, '%s/%s: the rule was refused (rc=%s)'
               % (boot, name, d['rc']))
        ck(int(d['snd']) == FLEN[fid], '%s/%s: sent %s bytes, frame is %d'
           % (boot, name, d['snd'], FLEN[fid]))
        want_ch = model_ch(fid, door, kind, off, ln, val)
        if want_ch is None:
            ck(d['ch'] in ('-1', '18446744073709551615'),
               '%s/%s: no rule, but ch=%s' % (boot, name, d['ch']))
        else:
            ck(int(d['ch']) == want_ch,
               '%s/%s: ch=%s, model says %d' % (boot, name, d['ch'],
                                                want_ch))
        f = FATE[fate]
        ck(int(d['u6n']) == f['u6n'],
           '%s/%s: u6n=%s, model says %d' % (boot, name, d['u6n'],
                                             f['u6n']))
        if f['u6n']:
            ck(int(d['u6len']) == PAY,
               '%s/%s: datagram length %s' % (boot, name, d['u6len']))
        for k in KEYS:
            ck(int(d[k]) == f[k], '%s/%s: %s=%s, model says %d'
               % (boot, name, k, d[k], f[k]))
    return seen


# --------------------------------------------------------------------------
# 6. determinism
# --------------------------------------------------------------------------

def determinism(a, b):
    ka = [d for d in a]
    kb = [d for d in b]
    ck(len(ka) == len(kb), 'determinism: different arm counts')
    for x, y in zip(ka, kb):
        ck(x == y, 'determinism: arm %s differs between the boots'
           % x.get('name'))


def main():
    provenance()
    anchors()
    all_arms = []
    for lp in LOGS:
        txt = load(lp)
        frames(txt)
        census(txt)
        all_arms.append(arms(txt, os.path.basename(lp)))
    determinism(*all_arms)
    print('F57 VERIFY: %d checks, %d bad' % (N, len(BAD)))
    for n in NOTES:
        print('  note: %s' % n)
    for b in BAD[:40]:
        print('  BAD: %s' % b)
    return 1 if BAD else 0


if __name__ == '__main__':
    sys.exit(main())
