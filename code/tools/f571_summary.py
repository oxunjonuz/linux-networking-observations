#!/usr/bin/env python3
"""f571_summary.py [log] -- the tables of F49, built from the log itself.

Nothing is typed twice: every cell below is read from the arm lines of the log.
"""
import re
import sys

BASE = '/work/kernel-sec'


def rows(path):
    out = []
    with open(path, 'r', errors='replace') as f:
        for ln in f:
            if ln.startswith('F571 A|'):
                out.append(dict(p.split('=', 1)
                                for p in ln.rstrip('\n').split('|') if '=' in p))
            elif ln.startswith('F571 T|'):
                d = dict(p.split('=', 1)
                         for p in ln.rstrip('\n').split('|') if '=' in p)
                d['kind'] = 'T'
                out.append(d)
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else BASE + '/logs/f49_rep1.log'
    A = rows(path)
    D = {}
    for a in A:
        if a.get('kind') == 'T':
            continue
        D[(a['door'], a['arm'])] = a

    def g(door, arm, key, dash='—'):
        a = D.get((door, arm))
        return dash if a is None else a[key]

    print('### T1  where each base lands (imm = the byte the frame carries)')
    print()
    print('| cell | `in3` on ppp0 | `nd1` on x1 |')
    print('|---|---|---|')
    for cell, a3, an, extra in (
            ('`@nh,0,4`', 'nh0', 'nh0', ''),
            ('`@nh,4,2`', 'nh4', 'nh4_len', ''),
            ('`@nh,6,1`', 'nh6', None, ''),
            ('`@nh,7,1`', 'nh7', 'nh7_ppp', ''),
            ('`@nh,7,1` = `40`', 'nh7_ppp', 'nh7_hop', ''),
            ('`@nh,8,16`', 'nh8', None, ''),
            ('`@nh,24,16`', 'nh24', None, ''),
            ('`@ll,0`', 'll0', 'll0', ''),
            ('`@ll,4,2`', 'll4', None, ''),
            ('`@ll,13,1`', None, 'll13', ''),
            ('`@th,0,2`', 'th0', 'th0_nm', ''),
            ('`@th,0,2` + `meta protocol`', None, 'th0_m', ''),
            ):
        def cellv(door, arm):
            if arm is None:
                return '—'
            a = D.get((door, arm))
            if a is None:
                return '—'
            if door == 'nd1' and arm == 'll0':
                return '`MAC` ✓' if a['lives'] == '1' else 'refused'
            if a['lives'] == '1':
                return '`%s` ✓' % a['imm']
            return 'refused / ≠`%s`' % a['imm']
        print('| %s | %s | %s |' % (cell, cellv('in3', a3), cellv('nd1', an)))

    print()
    print('### T2  the guard at the layer-3 door (`in3`, pf = NFPROTO_IPV6)')
    print()
    print('| arm | cell | imm | lives | delivered | Udp6InErrors | InNoRoutes |')
    print('|---|---|---|---|---|---|---|')
    order = ['nh7_90', 'nh7_00', 'nh4_2', 'nh6_1', 'nh0_ok', 'nh0_bad', 'nh2_2',
             'nh40_16', 'nh8_same', 'nh8_alt', 'nh8_cs', 'nh24_same',
             'nh24_alt', 'll0_1', 'll0_2', 'll7_1', 'th0_2', 'th0_2_cs', 'th6_2']
    for arm in order:
        a = D.get(('in3', arm))
        if a is None:
            continue
        base = {'0': '@ll', '1': '@nh', '2': '@th'}[a['base']]
        print('| `%s` | `%s,%s,%s` | `%s` | %s | %s | %s | %s |' % (
            arm, base, a['off'], a['len'], a['imm'], a['lives'],
            a['u6d'], a['u6err_d'], a['i6noroute_d']))

    print()
    print('### T3  one expression, three doors: `@nh,7,1 = 0x90` on the same frame')
    print()
    print('| door | cntp | lives | byte at the cell | ppp0 rx | Ip6InReceives | delivered |')
    print('|---|---|---|---|---|---|---|')
    for door, name in (('nd1', 'netdev ingress on x1'),
                       ('in3', 'inet prerouting on ppp0'),
                       ('ip63', 'ip6 prerouting on ppp0')):
        a = D.get((door, 'nh7_90'))
        print('| %s | %s | %s | `%s` | %s B | %s | %s |' % (
            name, a['cntp'], a['lives'],
            a['post'][14:16] if a['door'] == 'nd1' else a['post'][14:16],
            a['pby_d'], a['i6in_d'], a['u6d']))

    print()
    print('### T4  `@th` on the same frame: two formulas, one byte')
    print()
    print('| door | pktinfo | thoff | read `@th,0,2` | write, no csum | write + csum |')
    print('|---|---|---|---|---|---|')
    for door, pk, ra, wa, wb in (('in3', 'nhoff = 0', 'th0', 'th0_2',
                                  'th0_2_cs'),
                                 ('ip63', 'nhoff = 0', 'th0', 'th0_2', None),
                                 ('nd1', 'nhoff = 8', 'th0_m', None,
                                  'th0_2_m_cs')):
        r = D.get((door, ra))
        a = D.get((door, wa)) if wa else None
        b = D.get((door, wb)) if wb else None

        def w(v):
            if v is None:
                return '—'
            if v['u6d'] == '1':
                return 'sport %s, delivered' % v['u6sport']
            if v['u6err_d'] == '1':
                return 'Udp6InErrors'
            return 'delivered 0'
        print('| `%s` | %s | %s | `%s` | %s | %s |' % (
            door, pk, '40' if door != 'nd1' else '48',
            r['imm'] if r['lives'] == '1' else 'refused', w(a), w(b)))

    print()
    print('### T5  what an accepted write at the pre-decap door does')
    print()
    print('| arm | cell | wrote | ppp0 rx | Ip6InReceives | Udp6InErrors | delivered |')
    print('|---|---|---|---|---|---|---|')
    for arm in ('nh7_same', 'nh7_90', 'nh4_2_same', 'nh4_2_len', 'nh2_2_sid',
                'nh6_1_proto', 'll6_2', 'th0_2_m', 'th0_2_m_cs'):
        a = D.get(('nd1', arm))
        if a is None:
            continue
        base = {'0': '@ll', '1': '@nh', '2': '@th'}[a['base']]
        print('| `%s` | `%s,%s,%s` | `%s` | %s B | %s | %s | %s |' % (
            arm, base, a['off'], a['len'], a['imm'], a['pby_d'],
            a['i6in_d'], a['u6err_d'], a['u6d']))

    print()
    print('### T6  what the log carries about L2 at each door')
    print()
    print('| door | NFULA_L2HDR | NFULA_HWTYPE | NFULA_HWLEN | NFULA_HWHEADER |')
    print('|---|---|---|---|---|')
    for door, name in (('in3', '`in3` (ppp0)'), ('ip63', '`ip63` (ppp0)'),
                       ('nd1', '`nd1` (x1)')):
        a = D.get((door, 'ctl_' + door))
        if a is None:
            a = D.get((door, 'ctl_in3')) or D.get((door, 'ctl_nd1'))
        print('| %s | %s B | %d | %d | %s B: `%s` |' % (
            name, a['prel2'], int(a['preht']), int(a['prehw']),
            a['prehh'], a['prehwhex']))

    print()
    print('### T7  the tap debt: the same frames, two filters')
    print()
    print('| shape | frames on the tap | old filter | shape-aware filter |')
    print('|---|---|---|---|')
    for a in A:
        if a.get('kind') != 'T':
            continue
        print('| `%s` | %s | %s | %s |' % (a['shape'], a['total'], a['old'],
                                           a['new']))


if __name__ == '__main__':
    main()
