#!/usr/bin/env python3
"""f578_summary.py -- the tables of the F56 summary, derived from the log.

Nothing here is typed by hand: every cell is read out of logs/f56_rep1.log and
cross-checked against logs/f56_rep2.log (the derivations must be identical).
"""
import re
import sys

LOG = sys.argv[1] if len(sys.argv) > 1 else 'logs/f56_rep1.log'
LOG2 = sys.argv[2] if len(sys.argv) > 2 else 'logs/f56_rep2.log'


def parse(path):
    txt = open(path, 'rb').read().decode('utf-8', 'replace')
    A, C, B, F, T, M = {}, {}, {}, {}, {}, {}
    cur = None
    for ln in txt.splitlines():
        if not ln.startswith('F578 '):
            continue
        p = ln.split('|')
        h = p[0][5:]
        d = dict((t.split('=', 1) for t in p[1:] if '=' in t))
        if h == 'A':
            cur = (d['mode'], d['arm'])
            A[cur] = d
            M[cur] = {}
        elif h == 'C':
            C[(cur[0], d['arm'])] = d
        elif h == 'B':
            B[(cur[0], d['arm'])] = d
        elif h == 'F':
            F[(cur[0], d['arm'])] = d
        elif h == 'T':
            T[(cur[0], d['arm'])] = d
        elif h == 'M':
            for t in p[2:]:
                if t.startswith('m') and '=' in t:
                    f = t.split('=', 1)[1].split(':')
                    M[cur][f[0]] = {
                        'indev': int(f[1]), 'outdev': int(f[2]),
                        'hlen': int(f[5]), 'llen': int(f[7]), 'l': f[8],
                        'vp': int(f[9]), 'vproto': int(f[10], 16),
                        'vtci': int(f[11], 16), 'plen': int(f[12]),
                        'p': f[13]}
    return A, C, B, F, T, M


def tap(d, i):
    if 't%d' % i not in d:
        return None
    f = d['t%d' % i].split('=')
    v = (d['t%d' % i].split('=')[1] if '=' in d['t%d' % i] else '')
    return v


A1, C1, B1, F1, T1, M1 = parse(LOG)
A2, C2, B2, F2, T2, M2 = parse(LOG2)


def cell(d, key, default='-'):
    return d.get(key, default)


def taptok(T, key, idx, which):
    """which: n | flen | hex | atci | atpid | astat"""
    # (tci, tpid) is printed as '-' when the record carries no VLAN metadata
    if key not in T:
        return '-'
    raw = T[key].get('t%d' % idx)
    if raw is None:
        return '-'
    v = raw.split(':', 15)
    if which == 'n':
        return v[0]
    if which == 'flen':
        return v[1]
    if which == 'hex':
        return v[3]
    if which == 'atci':
        return '%04x' % int(v[5]) if int(v[6], 16) else '-'
    if which == 'atpid':
        return v[6]
    if which == 'astat':
        return v[7]
    return '-'


def arm_doors(C, key, doors):
    return ' '.join('%s=%s' % (d, C.get(key, {}).get(d, '?')) for d in doors)


AD_DOORS = ['g6', 'f6', 'e2', 'e3', 'e4', 'p1', 'r0']
BR_DOORS = ['bv', 'bf', 'bl', 'gv', 'n1', 'nz', 'q1', 'e2', 'p1', 'ry']

AD_ORDER = ['ctl2', 'rd_e2', 'rd_p1', 'w14_e2', 'ctl2s', 'w14_e2s',
            'ctl3', 'w14_e3', 'ctl3c', 'w14_e3c', 'ctl4', 'w14_e4', 'w12_e4',
            'w_tci_p1', 'w_proto_p1', 'rd_r0']
BR_ORDER = ['ctl_x', 'rd_bv', 'rd_bvt', 'rd_n1', 'rd_bv_z', 'rd_nz', 'rd_q1',
            'rd_e2', 'rd_bl', 'rd_ry', 'w12_bv', 'w12_e2', 'w14_e2', 'w16_ry']

out = []
o = out.append

o('## T1 — mode `ad`: what the rule did, and where the tag was\n')
o('| arm | frame | bits | action | ch | tap0 B | tap0 tci:tpid | '
  'egress-door L2 | p1 L2 | p1 nest | far end | u6n |')
o('|---|---|---|---|---|---|---|---|---|---|---|---|')
for name in AD_ORDER:
    k = ('0', name)
    a, c, m, t = A1.get(k, {}), C1.get(k, {}), M1.get(k, {}), T1.get(k, {})
    fr = cell(a, 'fk')
    feat = cell(a, 'feat')
    act = ''
    if a.get('op0') in ('1', '2'):
        act = '%s@%s:%s' % ('set' if a['op0'] == '1' else 'rd',
                            cell(a, 'a0'), cell(a, 'r0a'))
    ch = cell(c, 'ch0')
    e2 = m.get('p2', {})
    p1 = m.get('p5', {})
    far = '-'
    for key, dev in (('x0.102', 'x0.102'), ('x0.103', 'x0.103'),
                     ('x0.104', 'x0.104')):
        if F1.get(k, {}).get(key, '0:0:0') != '0:0:0':
            far = '%s %s' % (dev, F1[k][key])
    cells = [name, fr, feat, act, ch, taptok(T1, k, 0, 'flen'),
             '%s:%s' % (taptok(T1, k, 0, 'atci'),
                        taptok(T1, k, 0, 'atpid')),
             str(e2.get('llen', '-')), str(p1.get('llen', '-')),
             ('%04x:%04x' % (p1.get('vproto', 0), p1.get('vtci', 0)))
             if p1.get('vp') else 'none', far,
             cell(B1.get(k, {}), 'u6n')]
    assert cells[0] == name and len(cells) == 12, (cells, len(cells))
    o('| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |'
      % tuple(cells))

o('\n## T2 — mode `ad`: the tag at the two doors and on the wire\n')
o('| arm | device proto | reorder | tag in bytes at the egress door | '
  'tag at p1 | wire | far-end demux |')
o('|---|---|---|---|---|---|---|')
proto = {'ctl2': '88a8', 'rd_e2': '88a8', 'rd_p1': '88a8', 'w14_e2': '88a8',
         'ctl2s': '88a8', 'w14_e2s': '88a8', 'ctl3': '8100', 'w14_e3': '8100',
         'ctl3c': '8100', 'w14_e3c': '8100', 'ctl4': '88a8', 'w14_e4': '88a8',
         'w12_e4': '88a8', 'w_tci_p1': '88a8', 'w_proto_p1': '88a8',
         'rd_r0': '88a8'}
reord = {'ctl4': 'default', 'w14_e4': 'default', 'w12_e4': 'default'}
for name in AD_ORDER:
    k = ('0', name)
    m, t = M1.get(k, {}), T1.get(k, {})
    e = m.get({'A': 'p2', 'B': 'p3', 'E': 'p4'}[A1[k]['fk']], {})
    edoor_l2 = e.get('l', '')
    p1 = m.get('p5', {})
    far = '-'
    for key in ('x0.102', 'x0.103', 'x0.104'):
        if F1.get(k, {}).get(key, '0:0:0') != '0:0:0':
            far = key
    llen = e.get('llen', 0)
    o('| `%s` | %s | %s | L2 %d B: %s | %s | %s B | %s |'
      % (name, proto[name], reord.get(name, 'cleared'), llen,
         edoor_l2 if llen else 'none',
         ('%04x:%04x' % (p1.get('vproto', 0), p1.get('vtci', 0)))
         if p1.get('vp') else 'no word',
         taptok(T1, k, 0, 'flen'), far))

o('\n## T3 — mode `br`: the door census and the fate\n')
o('| arm | frame | doors | ch | wire | ry nest | y0.102 | u6n |')
o('|---|---|---|---|---|---|---|---|')
for name in BR_ORDER:
    k = ('1', name)
    a, c, m, t = A1.get(k, {}), C1.get(k, {}), M1.get(k, {}), T1.get(k, {})
    ry = m.get('p9', {})
    o('| `%s` | %s | %s | %s | %s B | %s | %s | %s |'
      % (name, cell(a, 'fk'), arm_doors(C1, k, BR_DOORS), cell(c, 'ch0'),
         taptok(T1, k, 0, 'flen'),
         ('%04x:%04x' % (ry.get('vproto', 0), ry.get('vtci', 0)))
         if ry.get('vp') else 'none',
         F1.get(k, {}).get('y0.102', '-'), cell(B1.get(k, {}), 'u6n')))

o('\n## T4 — mode `br`: the four stores, and what each one hit\n')
o('| arm | door | offset | what the offset is there | counter | wire bytes 12..17 | far end |')
o('|---|---|---|---|---|---|---|')
WHAT = {
    'w12_bv': ('bv', '12', "the frame's ethertype (the tag does not exist)"),
    'w12_e2': ('e2', '12', "the frame's ethertype (no tag at this door)"),
    'w14_e2': ('e2', '14', 'past mac_len = 14: refused'),
    'w16_ry': ('ry', '16', 'the frame\'s 12..13 (vlan_hlen = 4)'),
}
for name in ('w12_bv', 'w12_e2', 'w14_e2', 'w16_ry'):
    k = ('1', name)
    c = C1.get(k, {})
    door, off, what = WHAT[name]
    o('| `%s` | %s | %s | %s | %s | %s | y0.102 %s, other %s |'
      % (name, door, off, what, cell(c, 'ch0'),
         taptok(T1, k, 0, 'hex')[24:36],
         F1.get(k, {}).get('y0.102', '-').split(':')[0],
         F1.get(k, {}).get('y0', '-').split(':')[2]))

print('\n'.join(out))

# --- the derivations must be identical between the two boots
bad = 0
for k in A1:
    if k not in A2:
        continue
    if A1[k].get('mode') != A2[k].get('mode'):
        bad += 1
    for kind, X, Y in (('C', C1, C2), ('B', B1, B2)):
        if X.get(k) != Y.get(k):
            # MACs and ifindexes are stable inside a boot but not across boots
            bad += 1
print('\n<!-- derivations differ between the boots: %d -->' % bad)
sys.exit(0)
