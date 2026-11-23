#!/usr/bin/env python3
"""f73_summary.py -- build findings/F73-*/summary.json from the campaign logs.

Every number here is read from logs/f73_rep{1,2}.log; nothing is typed in.
"""
import json
import re
import sys

ROOT = '/work/kernel-sec'
sys.path.insert(0, ROOT + '/tools')
import verify595 as V   # noqa: E402  (the parser and the arm tables)


def main():
    tables = V.arm_tables()
    rows = []
    for name in ('rep1', 'rep2'):
        log, glob = V.parse_log('%s/logs/f73_%s.log' % (ROOT, name))
        for mode in ('chg', 'cln', 'spl'):
            for idx, A in enumerate(tables[mode]):
                A = dict(A)
                A['mode'] = mode
                for att in (0, 1):
                    R = log.get((mode, idx, att))
                    if not R:
                        continue
                    gates = V.recs(R, 'gate')
                    row = {
                        'boot': name, 'mode': mode, 'i': idx, 'att': att,
                        'arm': A['name'], 'door': A['xg'], 'n': A['n'],
                        'pl': A['pl'], 'align': A['al'], 'splice': A['sp'],
                        'zc': A['zc'], 'rule': A['rule'],
                        'gate_ts': [g['ts'][k] for g in gates
                                    for k in range(g['n'])],
                        'gate_end': [g['end'][k] for g in gates
                                     for k in range(g['n'])],
                        'gate_dlen': [g['dlen'][k] for g in gates
                                      for k in range(g['n'])],
                        'gate_cloned': [g['fl'][k] for g in gates
                                        for k in range(g['n'])],
                        'probes': {k: int(R.get('cnt', {}).get(k, -1))
                                   for k in ('enq', 'clone', 'ubuf', 'zc',
                                             'zf', 'sp', 'tx', 'fwd', 'loc',
                                             'udp', 'seg', 'segl', 'ap')},
                        'clone_callers': [c[6] for c in R.get('cln', [])],
                        'rmem_after': [int(w['rmem']) for w in
                                       V.recs(R, 'wait')],
                    }
                    tx = V.recs(R, 'tx')
                    if tx:
                        t = tx[0]
                        row['tx_ts'] = t['ts']
                        row['tx_len'] = t['len']
                        row['tx_dlen'] = t['dlen']
                        row['tx_end'] = t['end']
                    rows.append(row)
    out = {
        'turn': 595,
        'finding': 'F73-charge-and-clones',
        'kernel': '7.3.4-T563',
        'kernel_sha256':
            '1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033',
        'predictions_sha256': V.sha(ROOT + '/research/predictions_595.md'),
        'instrument': {
            'source': 'vm/differ595_add.c',
            'sha256_source': V.sha(ROOT + '/vm/differ595_add.c'),
            'sha256_binary': V.sha(ROOT + '/vm/build/differ595'),
            'initrd': 'vm/initrd595/full.cpio.gz',
            'sha256_initrd': V.sha(ROOT + '/vm/initrd595/full.cpio.gz'),
            'modes': {'chg': len(tables['chg']), 'cln': len(tables['cln']),
                      'spl': len(tables['spl'])},
            'attempts': len(rows),
        },
        'clone_call_site': {
            'symbol': 'skb_segment',
            'address': '0x%x' % (V.sym_addr('skb_segment') or 0),
            'returns_from_call': ['0x%x' % (x + 5)
                                  for x in V.segment_clone_sites()],
        },
        'rows': rows,
    }
    p = ROOT + '/findings/F73-charge-and-clones/summary.json'
    with open(p, 'w') as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write('\n')
    print('wrote', p, 'rows', len(rows))


if __name__ == '__main__':
    main()
