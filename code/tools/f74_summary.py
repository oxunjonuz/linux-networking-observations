#!/usr/bin/env python3
"""f74_summary.py -- build findings/F74-*/summary.json from the campaign logs.

Every number here is read from logs/f74_rep{1,2}.log or recomputed by the
verifier's own models; nothing is typed in.
"""
import hashlib
import json
import os
import sys

ROOT = '/work/kernel-sec'
sys.path.insert(0, ROOT + '/tools')
import verify596 as V   # noqa: E402


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def main():
    src = open(ROOT + '/vm/differ596_add.c', errors='replace').read()
    tq = V.parse_arm_table(src, 'AF596_Q')
    th = V.parse_arm_table(src, 'AF596_H')
    out = {'turn': 596, 'finding': 'F74-sender-sets-the-bill',
           'kernel_sha256': V.KERNEL_SHA,
           'differ_sha256': sha(ROOT + '/vm/build/differ596'),
           'predictions': {'a': V.sha(V.PRED_A), 'b': V.sha(V.PRED_B)},
           'logs': {}, 'q': [], 'h': [], 'slab': {}, 'queues': {}}
    for name in ('rep1', 'rep2'):
        path = '%s/logs/f74_%s.log' % (ROOT, name)
        out['logs'][name] = sha(path)
        D = V.parse_log(path)
        if not out['slab'] and D['slab']:
            out['slab'] = {'small_head': V.gint(D['slab'][0], 'obj'),
                           'classes': sorted(set(V.arr(
                               D['kmc'][0].get('sizes', ''))))}
        for i, A in enumerate(tq):
            for att in (0, 1):
                k = ('q', i, att)
                rcv = D['rcv'].get(k, {})
                if not rcv:
                    continue
                seq = [V.charge_at(A['pl'], A['align'], j)
                       for j in range(64)]
                R = V.gint(rcv, 'rb0')
                kept, rmem, drops = V.simulate_queue(R, seq, A['pl'])
                eq = D['eq'].get(k, {})
                pkt = D['pkt'].get(k, {})
                out['q'].append({
                    'boot': name, 'i': i, 'att': att, 'arm': A['name'],
                    'pl': A['pl'], 'align': A['align'],
                    'rcvbuf': A['rcvbuf'], 'R': R, 'rule': A['rule'],
                    'charge_first16': V.arr(eq.get('ts', '')),
                    'charge_model16': seq[:16],
                    'kept': V.gint(rcv, 'n0'), 'rmem': V.gint(rcv, 'rmem0'),
                    'inerrors': V.gint(rcv, 'udperr'),
                    'model_kept': kept, 'model_rmem': rmem,
                    'model_drops': drops,
                    'gate_enq': V.gint(D['cnt'].get(k, {}), 'enq'),
                    'gate_end': V.arr(eq.get('end', ''))[:1],
                    'gate_dlen': V.arr(eq.get('dlen', ''))[:1],
                    'logged_packets': V.gint(pkt, 'n'),
                    'logged_uhlen': V.arr(pkt.get('uhlen', ''))[:1],
                })
        for i, A in enumerate(th):
            for att in (0, 1):
                k = ('h', i, att)
                rcv = D['rcv'].get(k, {})
                if not rcv:
                    continue
                recs = D['rec'].get(('TX',) + k, [])
                mine = [(e, t, l) for (ts_, dl, ln, tl, en, fl) in recs
                        for j, e in enumerate(en) if ln[j] == A['pl'] + 42
                        for t in [ts_[j]] for l in [ln[j]]]
                out['h'].append({
                    'boot': name, 'i': i, 'att': att, 'arm': A['name'],
                    'pl': A['pl'], 'n_records': len(recs),
                    'tx_end': mine[0][0] if mine else None,
                    'tx_ts': mine[0][1] if mine else None,
                    'tx_len': mine[0][2] if mine else None,
                    'tx_copies': len(mine),
                    'rmem': V.gint(rcv, 'rmem0'), 'n0': V.gint(rcv, 'n0'),
                })
    # the two tables the document quotes, recomputed from the log
    out['queues'] = {
        'by_arm': {r['arm']: {'R': r['R'], 'kept': r['kept'],
                              'rmem': r['rmem'], 'kept_rep2':
                              [x['kept'] for x in out['q']
                               if x['arm'] == r['arm']]} for r in out['q']},
    }
    dst = ROOT + '/findings/F74-sender-sets-the-bill/summary.json'
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, 'w') as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print('wrote', dst, len(json.dumps(out)))
    print('q rows=%d h rows=%d' % (len(out['q']), len(out['h'])))


if __name__ == '__main__':
    main()
