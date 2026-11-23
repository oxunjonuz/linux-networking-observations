#!/usr/bin/env python3
"""verify573.py -- independent check of the turn-573 instrument (F51).

One bridge br0 with three ports (x1, y1, z1), IPv6 on br0 only, three frames:

  A  ethernet broadcast | IPv6 fd02::11 -> fd02::92 | UDP 40000->5000 | 18 x 77
  B  the same with br0's MAC as the ethernet destination (no flood)
  C  A with an 802.1Q tag (vid 100) in front of the IPv6 header

Four doors in one boot:

  brp  bridge  NF_BR_PRE_ROUTING   before br_flood() splits the skb
  brf  bridge  NF_BR_FORWARD       once per port copy
  brl  bridge  NF_BR_LOCAL_IN      the local copy only
  in6  ip6     NF_INET_PRE_ROUTING the local copy, inside the IP stack

The model is derived from the kernel functions ported here and from the frame
the log itself carries, never from an expectation written into the instrument.
For every arm it decides which copies exist and what each copy carries:

  * br_flood() delivers to every port but the ingress (through deliver_clone(),
    i.e. skb_clone()) and, when local_rcv, it clones for the last port as well
    and returns the ORIGINAL skb to br_pass_frame_up() for the local copy;
  * a store lands on every copy made AFTER it -- clones share the head -- and on
    the copies made BEFORE it only if nothing cloned the skb before the store;
    but __skb_clone() marks the SOURCE too (net/core/skbuff.c:1637), so any
    clone before the store makes skb_ensure_writable() copy the head and the
    earlier copies keep the old bytes.

The learned-MAC set is carried across arms: the bridge learns the source of
every frame it decides, so an arm that stores a value into the *source* arms the
next arm that aims at those bytes with the *destination* -- that frame becomes a
known unicast back to the ingress port and is delivered nowhere.

The two frame-C arms are recorded as observations, not as a claim: see the
report's "not understood" section.
"""
import os
import subprocess
import sys

BASE = '/work/kernel-sec'
NBAD = [0]
NCHK = [0]
DETAIL = []

TAPS = ('x1', 'y0', 'z0', 'br0')
T_X1, T_Y0, T_Z0, T_BR0 = 1, 2, 4, 8
T_Y0Z0 = T_Y0 | T_Z0
T_ALL3 = T_Y0 | T_Z0 | T_BR0
T_ALL4 = T_X1 | T_ALL3

BC = b'\xff' * 6
N6 = bytes.fromhex('909192939495')
N7 = bytes.fromhex('909192939497')
ET_ARP = bytes.fromhex('0806')
SRC6_TAIL = b'\x00' * 7 + b'\x11'
DST6_TAIL = b'\x00' * 7 + b'\x92'


def ck(cond, what):
    NCHK[0] += 1
    if not cond:
        NBAD[0] += 1
        if len(DETAIL) < 90:
            DETAIL.append(what)
    return bool(cond)


def kv(s):
    d = {}
    for part in s.split('|')[1:]:
        if '=' in part:
            k, v = part.split('=', 1)
            d[k] = v
    return d


def unhex(s):
    if not s or s == '-':
        return b''
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b''


def be16(b, i):
    return (b[i] << 8) | b[i + 1]


def apply_store(state, base, off, ln, imm):
    """nft_payload_set_eval(): skb_store_bits() at (base + off)."""
    b = bytearray(state)
    o = off if base == 0 else 14 + off
    if o < 0 or o + ln > len(b):
        return bytes(b)
    b[o:o + ln] = imm[:ln]
    return bytes(b)


def udp6_csum(fr, iplen_off=14):
    src = fr[iplen_off + 8:iplen_off + 24]
    dst = fr[iplen_off + 24:iplen_off + 40]
    plen = be16(fr, iplen_off + 4)
    udp = fr[iplen_off + 40:iplen_off + 40 + plen]
    s = 0
    for i in range(0, len(src), 2):
        s += be16(src, i)
    for i in range(0, len(dst), 2):
        s += be16(dst, i)
    s += plen + 17
    for i in range(0, len(udp), 2):
        s += be16(udp, i) if i + 1 < len(udp) else (udp[i] << 8)
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


# ------------------------------------------------------------ arm catalogue --
# name: (frame, tapmask, door, mode, base, off, len, imm)
ARMS = {
    'topo':      ('-', 0, '-', -1, 0, -1, -1, b''),
    'ctlA':      ('A', T_Y0Z0 | T_BR0, '-', -1, 0, -1, -1, b''),
    'ctlX':      ('A', T_ALL4, '-', -1, 0, -1, -1, b''),
    'uniC':      ('B', T_Y0Z0 | T_BR0, '-', -1, 0, -1, -1, b''),
    'preS':      ('A', T_Y0Z0 | T_BR0, 'brp', 1, 0, 6, 6, N6),
    'preS_x1':   ('A', T_ALL4, 'brp', 1, 0, 6, 6, N6),
    'preD':      ('A', T_Y0Z0 | T_BR0, 'brp', 1, 0, 0, 6, N6),
    'preD7':     ('A', T_Y0Z0 | T_BR0, 'brp', 1, 0, 0, 6, N7),
    'preE':      ('A', T_Y0Z0 | T_BR0, 'brp', 1, 0, 12, 2, ET_ARP),
    'fwdS':      ('A', T_Y0Z0 | T_BR0, 'brf', 1, 0, 6, 6, N6),
    'fwdD':      ('A', T_Y0Z0 | T_BR0, 'brf', 1, 0, 0, 6, N6),
    'fwdE':      ('A', T_Y0Z0 | T_BR0, 'brf', 1, 0, 12, 2, ET_ARP),
    'in6D':      ('A', T_Y0Z0 | T_BR0, 'in6', 1, 0, 0, 6, N6),
    'in6D_noT':  ('A', T_Y0Z0, 'in6', 1, 0, 0, 6, N6),
    'in6E':      ('A', T_Y0Z0 | T_BR0, 'in6', 1, 0, 12, 2, ET_ARP),
    'brlH':      ('A', T_Y0Z0 | T_BR0, 'brl', 1, 1, 7, 1, b'\x90'),
    'uniD':      ('B', T_Y0Z0 | T_BR0, 'in6', 1, 0, 0, 6, N6),
    'uniD_noT':  ('B', 0, 'in6', 1, 0, 0, 6, N6),
    'rdA':       ('A', T_Y0Z0 | T_BR0, 'brp', 3, 0, 0, 6, BC),
    'rdAmiss':   ('A', T_Y0Z0 | T_BR0, 'brp', 3, 0, 0, 6, N7),
    'vlanC':     ('C', T_Y0Z0 | T_BR0, '-', -1, 0, -1, -1, b''),
    'vlanR':     ('C', T_Y0Z0 | T_BR0, 'brp', 3, 0, 12, 2, b'\x86\xdd'),
}
ORDER = list(ARMS.keys())
HOOKPR = {'p0': (0, 10), 'p1': (1, 30), 'p2': (2, 50), 'p3': (3, 70)}


# --------------------------------------------------------------- parsing ----

def parse_log(path):
    txt = open(path, 'rb').read()
    L = {'hdr': {}, 'A': [], 'env': None, 'sys': None, 'ref': [], 'fr': {},
         'ch': [], 'raw': txt}
    cur = None
    for ln in txt.decode('utf8', 'replace').splitlines():
        if ln.startswith('### sha256: '):
            L['hdr']['kernel'] = ln.split(': ', 1)[1].strip()
        elif ln.startswith('### initrd sha256: '):
            L['hdr']['initrd'] = ln.split(': ', 1)[1].strip()
        elif ln.startswith('F573 ENV|'):
            L['env'] = kv(ln)
        elif ln.startswith('F573 SYS|'):
            L['sys'] = kv(ln)
        elif ln.startswith('F573 REF|'):
            L['ref'].append(kv(ln))
        elif ln.startswith('F573 FRM|'):
            d = kv(ln)
            if 'a' in d:
                L['fr']['a'] = unhex(d['a'])
            if 'c' in d:
                L['fr']['c'] = unhex(d['c'])
        elif ln.startswith('F573 CH|'):
            L['ch'].append(kv(ln))
        elif ln.startswith('F573 A|'):
            cur = {'A': kv(ln), 'B': None, 'M': None, 'T': None}
            L['A'].append(cur)
        elif ln.startswith('F573 C|') and cur is not None:
            d = {}
            for part in ln.split('|')[1:]:
                if '=' in part:
                    k, v = part.split('=', 1)
                    d[k] = v
            cur['C'] = d
        elif ln.startswith('F573 B|') and cur is not None:
            cur['B'] = kv(ln)
        elif ln.startswith('F573 M|') and cur is not None:
            cur['M'] = kv(ln)
        elif ln.startswith('F573 T|') and cur is not None:
            cur['T'] = kv(ln)
    return L


def mlog(M):
    keys = sorted((k for k in M if k.startswith('m')), key=lambda x: int(x[1:]))
    return 'n=%s|' % M['n'] + '|'.join('m%s=%s' % (k[1:], M[k]) for k in keys)


def parse_mlog(s):
    if isinstance(s, dict):
        s = mlog(s)
    out = []
    n = 0
    for part in s.split('|'):
        if part.startswith('n='):
            n = int(part[2:])
        elif part.startswith('m'):
            f = part.split('=', 1)[1].split(':')
            out.append((f[0], int(f[1]), int(f[2]), int(f[3]),
                        f[4] if len(f) > 4 else ''))
    return n, out


def parse_taps(s):
    if isinstance(s, dict):
        s = '|'.join('%s=%s' % (k, v) for k, v in s.items())
    d = {}
    for part in s.split('|'):
        if '=' not in part:
            continue
        name, rest = part.split('=', 1)
        f = rest.split(':')
        if name.startswith('t') and name[1:].isdigit():
            name = TAPS[int(name[1:])] if int(name[1:]) < len(TAPS) else name
        d[name] = (int(f[1]), int(f[2]),
                   unhex(f[3]) if len(f) > 3 else b'')
    return d


# ------------------------------------------------------------------ model ---

def model_arm(name, env, learned):
    fk, tapmask, door, mode, base, off, ln, imm = ARMS[name]
    frA = env['frA']
    if fk == 'A':
        fr = frA
    elif fk == 'B':
        fr = bytes.fromhex(env['br0mac']) + frA[6:]
    elif fk == 'C':
        fr = env['frC']
    else:
        fr = b''

    e = {'fk': fk, 'taps': {}, 'msgs': [], 'nfl': 0,
         'cnt': {'brp': 0, 'brf': 0, 'brl': 0, 'in6': 0}, 'cnts': 0,
         'u6n': 0, 'u6len': 0, 'u6sport': 0, 'i6in': 0, 'disc': 0, 'oth': 0,
         'ports': 0, 'local': 0}
    for t in TAPS:
        e['taps'][t] = None
    if fk == '-':
        return e, learned

    store = mode in (1, 2)
    post = apply_store(fr, base, off, ln, imm) if store else fr
    if door == 'brp':
        st_bridge, st_port, st_local = post, post, post
    elif door == 'brf':
        st_bridge, st_port, st_local = fr, post, fr
    elif door in ('brl', 'in6'):
        st_bridge, st_port, st_local = fr, fr, post
    else:
        st_bridge = st_port = st_local = fr
    # the br0 tap is taken when the frame is delivered to netif_receive_skb():
    # after the brp hook and after the brl hook, but before the in6 hook
    st_br0tap = post if door in ('brp', 'brl') else st_local \
        if door == 'brf' else fr

    dst = st_bridge[0:6]
    if dst == BC:
        ports, local = 2, 1
    elif dst == bytes.fromhex(env['br0mac']):
        ports, local = 0, 1
    elif learned.get(dst) == 'x1':
        ports, local = 0, 0        # known unicast back to the ingress port
    else:
        ports, local = 2, 0        # unknown unicast: flooded
    e['ports'], e['local'] = ports, local
    learned = dict(learned)
    learned[st_bridge[6:12]] = 'x1'

    cnt = {'brp': 1, 'brf': ports, 'brl': 1 if local else 0,
           'in6': 1 if local else 0}
    e['cnt'] = cnt
    if mode == 3:
        val = st_bridge[off:off + ln] if base == 0 else \
            st_bridge[14 + off:14 + off + ln]
        e['cnts'] = cnt.get(door, 0) if val == imm[:ln] else 0
    else:
        e['cnts'] = cnt.get(door, 0)

    if tapmask & T_X1:
        e['taps']['x1'] = (1, len(fr), fr)
    if tapmask & T_Y0:
        e['taps']['y0'] = (1 if ports else 0, len(st_port), st_port)
    if tapmask & T_Z0:
        e['taps']['z0'] = (1 if ports else 0, len(st_port), st_port)
    if tapmask & T_BR0:
        e['taps']['br0'] = (1 if local else 0,
                            len(st_br0tap) if local else -1,
                            st_br0tap if local else b'')

    e['u6n'] = 1 if local else 0
    e['u6len'] = 18 if local else 0
    e['u6sport'] = 40000 if local else 0
    e['local_type'] = st_local[12:14]
    port_type = st_port[12:14]
    port_dst = st_port[0:6]
    i6in, disc, oth = (1 if local else 0), 0, 0
    if port_type == b'\x86\xdd' and ports:
        if port_dst[0] & 1:
            i6in += ports
            disc += ports
        else:
            oth += 1          # counted per port, not per pair
    e['i6in'], e['disc'], e['oth'] = i6in, disc, oth
    e['port_type'], e['port_dst'] = port_type, port_dst

    # NFLOG: one message per reached log expression, in hook order
    msgs = []
    pre = post if door == 'brp' else fr
    msgs.append(('p0', 'x1', -1, pre))
    if door == 'brp':
        msgs.append(('s', 'x1', -1, post))
    for p in range(ports):
        port = 'y1' if p == 0 else 'z1'
        msgs.append(('p1', 'x1', port, pre))
        if door == 'brf':
            msgs.append(('s', 'x1', port, post))
    if local:
        msgs.append(('p2', 'x1', -1, pre))
        if door == 'brl':
            msgs.append(('s', 'x1', -1, post))
        msgs.append(('p3', 'br0', -1, post if door == 'brl' else pre))
        if door == 'in6':
            msgs.append(('s', 'br0', -1, post))
    # the kernel runs the hooks in this order, and at the forward door it runs
    # them per copy: p1(y1) s(y1) p1(z1) s(z1)
    if mode == 3 and e['cnts'] == 0:
        msgs = [m for m in msgs if m[0] != 's']    # NFT_BREAK: no log
    e['msgs'] = msgs
    e['nfl'] = len(msgs)
    return e, learned


# ------------------------------------------------------------------- main ---

def main():
    rep1 = os.environ.get('V573_REP1', BASE + '/logs/f51_rep1.log')
    rep2 = os.environ.get('V573_REP2', BASE + '/logs/f51_rep2.log')
    L1 = parse_log(rep1)
    L2 = parse_log(rep2)

    # ---------------------------------------------------------- provenance
    bz = BASE + '/src/linux-7.3.4-T563/arch/x86/boot/bzImage'
    sha = subprocess.run(['sha256sum', bz], capture_output=True,
                         text=True).stdout.split()[0]
    ck(sha == '1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033',
       'kernel sha is the F41..F50 image')
    ck(L1['hdr'].get('kernel') == sha, 'rep1 header kernel sha == file')
    ck(L2['hdr'].get('kernel') == sha, 'rep2 header kernel sha == file')
    ird = BASE + '/vm/initrd573/full.cpio.gz'
    irsha = subprocess.run(['sha256sum', ird], capture_output=True,
                           text=True).stdout.split()[0]
    ck(L1['hdr'].get('initrd') == irsha, 'rep1 initrd sha == file')
    ck(L2['hdr'].get('initrd') == irsha, 'rep2 initrd sha == file')
    dsha = subprocess.run(['sha256sum', BASE + '/vm/build/differ573'],
                          capture_output=True, text=True).stdout.split()[0]
    tmp = '/tmp/v573_initrd'
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

    # ------------------------------------------------------- source anchors
    def anchor(path, needle, nm):
        t = open(BASE + '/src/linux-7.3.4-T563/' + path, 'r',
                 errors='replace').read()
        ck(needle in t, nm)

    anchor('net/core/skbuff.c',
           'atomic_inc(&(skb_shinfo(skb)->dataref));\n\tskb->cloned = 1;',
           'skbuff.c: __skb_clone() marks the SOURCE cloned')
    anchor('net/bridge/br_forward.c',
           'prev = maybe_deliver(prev, p, skb, local_orig);',
           'br_forward.c: br_flood() delivers per port through maybe_deliver()')
    anchor('net/bridge/br_forward.c',
           'if (local_rcv)\n\t\tdeliver_clone(prev, skb, local_orig);\n\telse\n\t\t__br_forward(prev, skb, local_orig);',
           'br_forward.c: br_flood() keeps the ORIGINAL for the local path')
    anchor('net/bridge/br_forward.c',
           'skb = skb_clone(skb, GFP_ATOMIC);\n\tif (!skb) {\n\t\tDEV_STATS_INC(dev, tx_dropped);',
           'br_forward.c: deliver_clone() clones (and so marks the source)')
    anchor('net/core/skbuff.c',
           'if (!skb_cloned(skb) || skb_clone_writable(skb, write_len))',
           'skbuff.c: skb_ensure_writable() copies the head of a clone')
    anchor('net/netfilter/nft_payload.c',
           'if (skb_ensure_writable(skb, max(offset + priv->len, 0)) ||',
           'nft_payload.c: the payload store goes through skb_ensure_writable()')
    anchor('net/netfilter/nft_payload.c',
           'return offset <= skb_network_offset(pkt->skb);',
           'nft_payload.c: nft_ll_write_ok() stops at the network header')
    anchor('net/bridge/br_private.h',
           'static inline struct sk_buff *br_handle_vlan(struct net_bridge *br,',
           'br_private.h: br_handle_vlan() stub exists for filtering off')
    anchor('.config', '# CONFIG_BRIDGE_VLAN_FILTERING is not set',
           '.config: CONFIG_BRIDGE_VLAN_FILTERING is not set')
    anchor('.config', '# CONFIG_BRIDGE_NETFILTER is not set',
           '.config: CONFIG_BRIDGE_NETFILTER is not set')

    # ----------------------------------------------------- per-rep structure
    for nm, L in (('rep1', L1), ('rep2', L2)):
        txt = L['raw']
        reg = b''
        if b'=== REPRO_OUTPUT_BEGIN ===' in txt and b'=== REPRO_OUTPUT_END ===' in txt:
            reg = txt.split(b'=== REPRO_OUTPUT_BEGIN ===', 1)[1].split(
                b'=== REPRO_OUTPUT_END ===', 1)[0]
        ck(reg != b'', nm + ': the arms ran inside the marker window')
        for bad in (b'KASAN', b'BUG:', b'Oops', b'general protection',
                    b'use-after-free', b'WARNING:'):
            ck(bad not in reg, nm + ': no ' + bad.decode() + ' while the arms ran')
        tail = txt.split(b'=== DMESG_TAIL ===', 1)[-1]
        if b'BUG: KASAN' in tail:
            # the image reports a wild-memory-access in rcu_is_watching from
            # cpuid_model on swapper/0 at 3.29 s under TCG: it is in the boot
            # log before any arm, and it is the only splat allowed here
            ck(b'rcu_is_watching' in tail and b'swapper/0' in tail,
               nm + ': the only dmesg splat is the boot-time cpuid KASAN')
        ck(len(L['A']) == len(ORDER),
           nm + ': %d arms (got %d)' % (len(ORDER), len(L['A'])))
        ck([a['A']['arm'] for a in L['A']] == ORDER,
           nm + ': the arms are the catalogue, in order')
        ck(L['env'] is not None and L['sys'] is not None, nm + ': env + sys')
        ck(len(L['ch']) == 4, nm + ': four base chains created')
        for c in L['ch']:
            ck(c['table'] == '0' and c['pre0'] == '0' and c['ch'] == '0',
               nm + ': chain created: ' + c['door'])
        ck(len(L['ref']) == 3, nm + ': three enslave results')
        for r in L['ref']:
            ck(r['rc'] == '0', nm + ': enslave ' + r['port'] + ' rc=0')

    # ---------------------------------------------------------- environment
    for nm, L in (('rep1', L1), ('rep2', L2)):
        env, sysd = L['env'], L['sys']
        ck(env['la'] == '80' and env['lc'] == '84',
           nm + ': frame A 80 B, frame C 84 B')
        ck(env['x0mac'] != env['br0mac'],
           nm + ': x0 and br0 have different MACs')
        ck(sysd['y0v6'] == '1' and sysd['z0v6'] == '1' and sysd['x1v6'] == '1',
           nm + ': IPv6 disabled on x1, y0, z0')
        ck(sysd['br0v6'] == '0', nm + ': IPv6 enabled on br0')
        ck(sysd['stp'] == '0', nm + ': no STP')
        ck(sysd['x1state'] == '3' and sysd['y1state'] == '3'
           and sysd['z1state'] == '3', nm + ': all three ports FORWARDING')
        ck(sysd['mcsnoop'] == '0', nm + ': multicast snooping off')
        ck(sysd['vfpath'] == '0' and sysd['vf'] == '-1',
           nm + ': no vlan_filtering attribute (feature compiled out)')
        fr = L['fr']['a']
        ck(fr[0:6] == BC and fr[6:12] == bytes.fromhex(env['x0mac']),
           nm + ': frame A dst broadcast, src x0')
        ck(fr[12:14] == b'\x86\xdd', nm + ': frame A ethertype 86dd')
        ck(be16(fr, 18) == 26 and fr[20] == 17 and fr[21] == 64,
           nm + ': frame A IPv6 plen 26, UDP, hop limit 64')
        ck(fr[30:38] == SRC6_TAIL, nm + ': frame A IPv6 saddr fd02::11')
        ck(fr[46:54] == DST6_TAIL, nm + ': frame A IPv6 daddr fd02::92')
        ck(be16(fr, 54) == 40000 and be16(fr, 56) == 5000, nm + ': UDP ports')
        ck(udp6_csum(fr) == 0 and be16(fr, 60) != 0,
           nm + ': frame A UDPv6 checksum valid')
        ck(fr[62:] == b'\x77' * 18, nm + ': 18 x 77 payload')
        fc = L['fr']['c']
        ck(fc[12:14] == b'\x81\x00' and fc[14:16] == b'\x00\x64'
           and fc[16:18] == b'\x86\xdd', nm + ': frame C 8100 vid 100, inner 86dd')
        ck(len(fc) == 84, nm + ': frame C is 84 B')

    # ------------------------------------------------------ every arm, twice
    for nm, L in (('rep1', L1), ('rep2', L2)):
        env = dict(L['env'])
        env['frA'] = L['fr']['a']
        env['frC'] = L['fr']['c']
        ck('y1' in env and 'z1' in env, nm + ': ENV names y1 and z1')
        ck(int(env['y1']) not in (int(env['x1']), int(env['y0']),
                                  int(env['z0']), int(env['br0'])),
           nm + ': y1 is its own interface')
        ck(int(env['z1']) not in (int(env['x1']), int(env['y0']),
                                  int(env['z0']), int(env['br0'])),
           nm + ': z1 is its own interface')
        learned = {bytes.fromhex(env['x0mac']): 'x1',
                   bytes.fromhex(env['br0mac']): 'local'}
        for a in L['A']:
            name = a['A']['arm']
            e, learned = model_arm(name, env, learned)
            A, Bb, M, Tt, Cc = a['A'], a['B'], a['M'], a['T'], a['C']
            tag = nm + ' ' + name
            fk, tapmask, door, mode, base, off, lnx, imm = ARMS[name]
            # the instrument prints its default frame name ("A") for the
            # no-injection arm; every other arm prints the frame it used
            ck(A['fk'] == fk or (fk == '-' and A['fk'] == 'A'),
               tag + ': frame ' + fk)
            ck(int(A['tapmask']) == tapmask, tag + ': tapmask')
            ck(A['door'] == door, tag + ': door ' + door)
            if mode >= 0:
                ck(int(A['mode']) == mode and int(A['base']) == base
                   and int(A['off']) == off and int(A['len']) == lnx,
                   tag + ': store/read parameters')
                ck(unhex(A['imm']) == imm[:lnx], tag + ': immediate')
            ck(int(A['snt']) == (1 if fk != '-' else 0), tag + ': injected')
            if fk != '-':
                ck(A['sendrc'] == '0', tag + ': sendto rc 0')
            ck(int(A['st']) >= 1, tag + ': counters settled before the arm')
            if fk != 'C':
                ck(int(A['nfl']) == e['nfl'],
                   '%s: nflog n=%d (model %d)' % (tag, int(A['nfl']),
                                                  e['nfl']))
            if fk == 'C':
                # recorded, not claimed: see the report's "not understood"
                ck(Cc['brp'] == '1,-1' or Cc['brp'] == '1,0' or Cc['brp'] == '1,1',
                   tag + ': the bridge prerouting door is reached once')
                ck(Cc['brf'] == '2,-1' and Cc['brl'] == '1,-1'
                   and Cc['in6'] == '0,-1',
                   tag + ': the door census of the tagged frame')
                ck(A['u6n'] == '0', tag + ': no datagram delivered')
                tp = parse_taps(Tt)
                for t in ('y0', 'z0', 'br0'):
                    if e['taps'][t] is None:
                        continue
                    ck(tp[t][0] == 1, tag + ': tap ' + t + ' saw the frame once')
                continue
            for d in ('brp', 'brf', 'brl', 'in6'):
                pre, ch = Cc[d].split(',')
                ck(int(pre) == e['cnt'][d],
                   '%s: cnt %s = %d (model %d)' % (tag, d, int(pre),
                                                   e['cnt'][d]))
                if d == door and mode >= 0:
                    ck(int(ch) == e['cnts'],
                       '%s: ch %s = %d (model %d)' % (tag, d, int(ch),
                                                      e['cnts']))
                elif d != door:
                    ck(ch == '-1', tag + ': ch at ' + d + ' has no rule')
            ck(int(A['u6n']) == e['u6n'], tag + ': u6n = %d' % e['u6n'])
            if e['u6n']:
                ck(int(A['u6len']) == e['u6len'], tag + ': payload length 18')
                ck(int(A['u6sport']) == e['u6sport'], tag + ': source port')
            ck(int(Bb['i6in_d']) == e['i6in'],
               '%s: Ip6InReceives +%d (model +%d)' % (tag, int(Bb['i6in_d']),
                                                      e['i6in']))
            ck(int(Bb['disc_d']) == e['disc'],
               '%s: Ip6InDiscards +%d (model +%d)' % (tag, int(Bb['disc_d']),
                                                      e['disc']))
            ck(int(Bb['deliv_d']) == e['u6n'], tag + ': Ip6InDelivers')
            ck(int(Bb['u6in_d']) == e['u6n'], tag + ': Udp6InDatagrams')
            ck(int(Bb['u6err_d']) == 0 and int(Bb['u6nop_d']) == 0,
               tag + ': no UDP errors')
            for k in ('i6hdr_d', 'i6addr_d', 'i6unk_d', 'i6trunc_d',
                      'i6nor_d', 'mcas_d'):
                ck(int(Bb[k]) == 0, tag + ': ' + k + ' stays 0')
            per = 1 if e['ports'] else 0
            ck(int(Bb['y0rxp_d']) == per, tag + ': y0 received its copy')
            ck(int(Bb['z0rxp_d']) == per, tag + ': z0 received its copy')
            ck(int(Bb['y0oth_d']) == e['oth'], tag + ': y0 otherhost')
            ck(int(Bb['z0oth_d']) == e['oth'], tag + ': z0 otherhost')
            ck(int(Bb['brrxp_d']) == e['local'], tag + ': br0 got the local copy')
            ck(int(Bb['x1rxp_d']) == (1 if fk != '-' else 0),
               tag + ': x1 received the frame once')
            # NFLOG: how many, and what each one saw
            n, msgs = parse_mlog(mlog(M))
            ck(n == len(e['msgs']), tag + ': nflog messages == model')
            for i, (pre, ind, outd, plen, hexs) in enumerate(msgs):
                if i >= len(e['msgs']):
                    break
                epre, eind, eout, estate = e['msgs'][i]
                ck(pre == epre,
                   '%s: m%d prefix %s (model %s)' % (tag, i, pre, epre))
                want_ind = int(env['x1']) if eind == 'x1' else int(env['br0'])
                ck(ind == want_ind,
                   '%s: m%d indev %d (want %d)' % (tag, i, ind, want_ind))
                if eout == -1:
                    ck(outd == -1, '%s: m%d outdev -1' % (tag, i))
                else:
                    ck(outd in (int(env['y1']), int(env['z1'])),
                       '%s: m%d outdev is a bridge port (%s)' % (tag, i, outd))
                ck(plen == 66, '%s: m%d payload 66 B' % (tag, i))
                ck(unhex(hexs) == estate[14:14 + 42],
                   '%s: m%d payload is the IPv6 header of the state at that door'
                   % (tag, i))
            # the two port messages must name the two ports, in either order
            p1out = sorted(outd for (pre, ind, outd, plen, h) in msgs
                           if pre == 'p1')
            ck(p1out == sorted([int(env['y1']), int(env['z1'])])[:len(p1out)],
               '%s: the forward door saw the two ports' % tag)
            # taps
            tp = parse_taps(Tt)
            for tname in TAPS:
                want = e['taps'][tname]
                got = tp.get(tname, (0, -1, b''))
                if want is None:
                    ck(got[0] == 0, tag + ': tap ' + tname + ' closed')
                    continue
                ck(got[0] == want[0],
                   '%s: tap %s n=%d (model %d)' % (tag, tname, got[0], want[0]))
                if want[0]:
                    ck(got[1] == want[1],
                       '%s: tap %s length %d (model %d)'
                       % (tag, tname, got[1], want[1]))
                    ck(got[2][:len(want[2])] == want[2],
                       '%s: tap %s bytes' % (tag, tname))

    # ------------------------------------------------------- the claims
    by1 = {a['A']['arm']: a for a in L1['A']}
    x0 = bytes.fromhex(L1['env']['x0mac'])
    # 1. a store before the split reaches every copy
    Tt = parse_taps(by1['preS']['T'])
    for t in ('y0', 'z0', 'br0'):
        ck(Tt[t][2][6:12] == N6,
           'preS: tap ' + t + ' carries the stored source')
    # 2. a store after the split, on the local copy, reaches no port
    for arm in ('in6D', 'in6D_noT'):
        Tt = parse_taps(by1[arm]['T'])
        for t in ('y0', 'z0'):
            ck(Tt[t][2][0:6] == BC,
               arm + ': port ' + t + ' still carries the broadcast destination')
        ck(by1[arm]['A']['u6n'] == '1', arm + ': the local copy is delivered')
        ck(by1[arm]['C']['in6'].split(',')[1] == '1',
           arm + ': the store at the ip6 door was accepted once')
        ck(by1[arm]['B']['i6in_d'] == '3',
           arm + ': one local receive + two port receives')
        ck(by1[arm]['B']['disc_d'] == '2',
           arm + ': both port copies are discarded, none carries the store')
    # 3. the per-copy door changes exactly the copies
    for arm in ('fwdS', 'fwdD', 'fwdE'):
        Tt = parse_taps(by1[arm]['T'])
        ck(by1[arm]['C']['brf'] == '2,2', arm + ': two copies, two stores')
        ck(Tt['br0'][2][6:12] == x0,
           arm + ': the local copy never passes the forward door')
        ck(by1[arm]['A']['u6n'] == '1', arm + ': the local copy is delivered')
    Tt = parse_taps(by1['fwdS']['T'])
    for t in ('y0', 'z0'):
        ck(Tt[t][2][6:12] == N6, 'fwdS: ' + t + ' carries the per-copy store')
    # 4. a clone before the store does not change what the copies carry
    ck(parse_taps(by1['preS_x1']['T'])['x1'][2][6:12] == x0,
       'preS_x1: the ingress tap is the pre-store frame')
    for t in ('y0', 'z0', 'br0'):
        ck(parse_taps(by1['preS_x1']['T'])[t][2][6:12] == N6,
           'preS_x1: ' + t + ' still carries the store')
    # 5. a source store teaches the bridge; the next destination store is
    #    swallowed -- same bytes, two outcomes
    ck(by1['preD']['C']['brf'] == '0,-1' and by1['preD']['C']['brl'] == '0,-1',
       'preD: a known unicast back to the ingress port is delivered nowhere')
    ck(by1['preD']['A']['nfl'] == '2',
       'preD: only the two messages of the bridge prerouting door')
    ck(by1['preD7']['C']['brf'] == '2,-1',
       'preD7: the same store with a MAC the bridge never learned is flooded')
    ck(by1['preD7']['B']['y0oth_d'] == '1'
       and by1['preD7']['B']['z0oth_d'] == '1',
       'preD7: both ports drop it as OTHERHOST')
    # 6. the read machinery works on a frame the instrument knows
    ck(by1['rdA']['C']['brp'] == '1,1', 'rdA: @ll,0,6 == broadcast reads back')
    ck(by1['rdAmiss']['C']['brp'] == '1,0',
       'rdAmiss: the same read with a wrong value does not fire')
    # 7. the VLAN-filtering debt: the attribute does not exist
    ck(L1['sys']['vfpath'] == '0', 'no vlan_filtering attribute on br0')
    # 8. the tagged frame, recorded: the local copy is not IPv6, and the LL read
    #    at 12 is not the inner ethertype
    ck(by1['vlanC']['C']['in6'] == '0,-1' and by1['vlanC']['A']['u6n'] == '0',
       'vlanC: the local copy of a tagged frame never reaches the ip6 door')
    ck(by1['vlanR']['C']['brp'] == '1,0',
       'vlanR: @ll,12,2 at the bridge door is not the inner ethertype')

    # --------------------------------------------------------- determinism
    def norm(L):
        env = L['env']
        x0m = env['x0mac']
        brm = env['br0mac']
        keep = []
        for a in L['A']:
            row = dict(a['A'])
            keep.append(('A', sorted(row.items())))
            keep.append(('C', sorted(a['C'].items())))
            keep.append(('B', sorted(a['B'].items())))
            n, msgs = parse_mlog(mlog(a['M']))
            nm = []
            for (pre, ind, outd, plen, hexs) in msgs:
                h = hexs.replace(x0m, 'X0').replace(brm, 'BR')
                nm.append((pre, 'x1' if ind == int(env['x1']) else
                           'br0' if ind == int(env['br0']) else ind,
                           outd if outd == -1 else
                           'y1' if outd == int(env['y0']) + 1 else
                           'z1' if outd == int(env['z0']) + 1 else outd,
                           plen, h))
            keep.append(('M', nm))
            tp = parse_taps(a['T'])
            keep.append(('T', sorted((k, v[0], v[1],
                                      v[2].hex().replace(x0m, 'X0').replace(brm, 'BR'))
                                     for k, v in tp.items())))
        return keep

    k1, k2 = norm(L1), norm(L2)
    ck(len(k1) == len(k2), 'determinism: same number of arm records')
    for i, (a, b) in enumerate(zip(k1, k2)):
        ck(a == b, 'determinism: record %d (%s) identical in both boots'
           % (i, L1['A'][i // 5]['A']['arm'] if i // 5 < len(L1['A']) else '?'))

    print('checks: %d, mismatches: %d' % (NCHK[0], NBAD[0]))
    for d in DETAIL:
        print('  MISMATCH:', d)
    return 1 if NBAD[0] else 0


if __name__ == '__main__':
    sys.exit(main())
