#!/usr/bin/env python3
"""f570_summary.py -- the tables of F48, derived from the frozen logs.

Every cell is read out of logs/f48_rep1.log and logs/f48_rep2.log; nothing is
typed by hand.  Writes findings/F48-pppoe-egress/summary.json and prints the
two markdown tables the SUMMARY quotes.
"""
import json
import os
import sys

BASE = '/work/kernel-sec'
OUT = BASE + '/findings/F48-pppoe-egress'


def parse(path):
    A, T, frames = [], [], {}
    for ln in open(path, errors='replace'):
        ln = ln.rstrip('\n')
        if ln.startswith('F570 FRAME|'):
            p = ln.split('|')
            frames[p[1]] = dict(x.split('=', 1) for x in p if '=' in x)
        elif ln.startswith('F570 A|'):
            A.append(dict(x.split('=', 1) for x in ln.split('|') if '=' in x))
        elif ln.startswith('F570 T|'):
            T.append(dict(x.split('=', 1) for x in ln.split('|') if '=' in x))
    return A, T, frames


def byte_at(a, field, off):
    h = a.get(field, '') or ''
    return h[2 * off:2 * off + 2]


def main():
    A1, T1, F1 = parse(BASE + '/logs/f48_rep1.log')
    A2, T2, F2 = parse(BASE + '/logs/f48_rep2.log')
    os.makedirs(OUT, exist_ok=True)
    sinfo = {}

    # ---------------- ppp6e: the door grid ----------------
    rows = []
    for a in A1:
        rows.append({
            'door': a['door'], 'arm': a['arm'], 'send': a['sk'],
            'shape': a['shape'], 'meta_proto': a['mp'] == '1',
            'meta_l4': a['ml'] == '1', 'nh_read': a['nh'] == '1',
            'write': a['wr'] == '1', 'read': a['rd'] == '1',
            'base': a['base'], 'off': a['off'], 'len': a['len'],
            'imm': a['imm'], 'cntp': a['cntp'], 'cnts': a['cnts'],
            'p_len': len(a['p']) // 2, 's_len': len(a['s']) // 2,
            'tap_len': len(a['tap']) // 2,
            's_sport': byte_at(a, 's', 54) + byte_at(a, 's', 55),
            's_ppp_proto': byte_at(a, 's', 6) + byte_at(a, 's', 7),
            's_62': byte_at(a, 's', 62) + byte_at(a, 's', 63),
            'tap_21': byte_at(a, 'tap', 21),
            'tap_54': byte_at(a, 'tap', 54) + byte_at(a, 'tap', 55),
            'tap_62': byte_at(a, 'tap', 62) + byte_at(a, 'tap', 63),
        })
    sinfo['ppp6e'] = rows
    sinfo['frames'] = {k: {'len': v['len'], 'hex': v['hex']} for k, v in F1.items()}

    # ---------------- th6: @th on the v6 doors ----------------
    trows = []
    for a in T1:
        trows.append({
            'door': a['door'], 'cls': a['cls'], 'shape': a['shape'],
            'arm': a['arm'], 'l4cmp': a['l4cmp'], 'base': a['base'],
            'rcs': a['rcs'], 'lives': a['lives'], 'nmsg': a['nmsg'],
            'tapn': a['tapn'], 'taplen': a['taplen'],
            'tap_54': byte_at(a, 'tap', 54) + byte_at(a, 'tap', 55),
            'tap_62': byte_at(a, 'tap', 62) + byte_at(a, 'tap', 63),
            'tap_40': byte_at(a, 'tap', 40) + byte_at(a, 'tap', 41),
            'u6n': a['u6n'], 'u6sport': a['u6sport'], 'u6len': a['u6len'],
            'u6err': a['u6err_d'], 'deliv': a['deliv_d'],
        })
    sinfo['th6'] = trows

    # cross-boot agreement of the derived facts
    same = 0
    tot = 0
    for x, y in zip(rows, [None] * 0 + rows):
        pass
    for a, b in zip(rows, [dict(zip(r.keys(), r.values())) for r in rows]):
        pass
    a_sig = [(r['door'], r['arm'], r['cnts'], r['p_len'], r['s_len'],
              r['tap_len']) for r in rows]
    b_sig = [(r['door'], r['arm'], r['cnts'], r['p_len'], r['s_len'],
              r['tap_len']) for r in
             [{'door': x['door'], 'arm': x['arm'], 'cnts': x['cnts'],
               'p_len': len(x['p']) // 2, 's_len': len(x['s']) // 2,
               'tap_len': len(x['tap']) // 2} for x in A2]]
    for x, y in zip(a_sig, b_sig):
        tot += 1
        same += (x == y)
    t_sig = [(r['door'], r['cls'], r['shape'], r['arm'], r['lives'], r['u6n'],
              r['u6err'], r['u6sport']) for r in trows]
    u_sig = [(x['door'], x['cls'], x['shape'], x['arm'], x['lives'], x['u6n'],
              x['u6err_d'], x['u6sport']) for x in T2]
    for x, y in zip(t_sig, u_sig):
        tot += 1
        same += (x == y)
    sinfo['determinism'] = {'fields': tot, 'same': same}
    sinfo['turn'] = 570
    sinfo['finding'] = 'F48-pppoe-egress'
    sinfo['kernel'] = '7.3.4-T563'
    sinfo['arms_per_boot'] = {'ppp6e': len(rows), 'th6': len(trows)}
    sinfo['boots'] = 2
    sinfo['id'] = 'F48'
    sinfo['question'] = ('at an egress door, does `meta protocol` put a PPPoE '
                         'frame into the same coordinate system for the read and '
                         'the write bases?')
    sinfo['answer_short'] = ('no: it computes nhoff = 8 + skb_network_offset and '
                             'the version check adds skb_network_offset a second '
                             'time, so the walk parses at 22 while the version '
                             'byte is read at 36; the failed validation resets '
                             'nhoff to 0, both writes are refused, and one byte '
                             'of the sender own address makes the same @th write '
                             'land in the real UDP source port')
    json.dump(sinfo, open(OUT + '/summary.json', 'w'), indent=1)

    # ---------------- the printed tables ----------------
    print('### ppp6e')
    print('| door | arm | send | meta | cell | cntp | cnts | s[6:8] | s[54:56] | s[62:64] | tap[21] | tap[54:56] | tap[62:64] |')
    print('|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    for r in rows:
        cell = '-'
        if r['base'] == '1':
            cell = '@nh,%d,%d' % (int(r['off']), int(r['len']))
        elif r['base'] == '2':
            cell = '@th,%d,%d' % (int(r['off']), int(r['len']))
        meta = ('proto ' if r['meta_proto'] else '') + ('l4 ' if r['meta_l4'] else '')
        meta = meta or '-'
        print('| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |' % (
            r['door'], r['arm'], {'0': 'plain', '1': 'pppoe', '2': 'inject'}[r['send']],
            meta, cell, r['cntp'], r['cnts'], r['s_ppp_proto'], r['s_sport'],
            r['s_62'], r['tap_21'] or '-', r['tap_54'] or '-', r['tap_62'] or '-'))
    print()
    print('### th6')
    print('| door | cls | shape | arm | l4cmp | rcs | lives | tapn | tap[40:42] | tap[54:56] | tap[62:64] | u6n | u6sport | u6err |')
    print('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    for r in trows:
        print('| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |' % (
            r['door'], r['cls'], r['shape'], r['arm'], r['l4cmp'], r['rcs'],
            r['lives'], r['tapn'], r['tap_40'] or '-', r['tap_54'] or '-',
            r['tap_62'] or '-', r['u6n'], r['u6sport'], r['u6err']))
    print()
    print('determinism: %d/%d derived fields identical across the two boots'
          % (sinfo['determinism']['same'], sinfo['determinism']['fields']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
