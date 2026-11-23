#!/usr/bin/env python3
"""f585_summary.py -- the numbers of F63, out of the two boot logs."""
import json
import re
import sys

ROOT = '/work/kernel-sec'


def parse(path):
    txt = open('%s/%s' % (ROOT, path), errors='replace').read()
    arms, rcvs, taps = {}, {}, {}
    for m in re.finditer(r'^F585 ARM\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        arms[int(d['i'])] = d
    for m in re.finditer(r'^F585 RCV\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        rcvs[int(d['i'])] = d
    for m in re.finditer(r'^F585 TAP\|(.*)$', txt, re.M):
        d = dict(x.split('=', 1) for x in m.group(1).split('|') if '=' in x)
        taps.setdefault(int(d['i']), []).append(d)
    return arms, rcvs, taps


out = {'turn': 585, 'finding': 'F63', 'kernel': '7.3.4-T563',
       'claim': 'GRO hands the rule a packet the sender never sent: the checksum '
                'field the rule reads, and who pays when the aggregate is split, '
                'are decided by a device bit and by the rule\'s own write offset.',
       'answer_short': 'A fraglist splitter copies nothing and pays nothing '
                       '(skb_segment_list ignores features); a linear one pays for '
                       'all three; four bytes of store offset switch the branch.',
       'kernel_sha': '1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033',
       'mode': 'aggr', 'arms': 26, 'boots': []}
for tag in ('rep1', 'rep2'):
    a, r, t = parse('logs/f63_%s.log' % tag)
    rows = []
    for i in sorted(a):
        rows.append({
            'i': i, 'name': a[i]['name'], 'ch': int(a[i]['ch']),
            'lgplen': int(a[i]['lgplen']), 'lgudp': a[i]['lgudp'],
            'uhlen': int(a[i]['lgudp'][8:12], 16) if a[i]['lgudp'] != '-' else None,
            'uhck': int(a[i]['lgudp'][12:16], 16) if a[i]['lgudp'] != '-' else None,
            'reads': [int(r[i]['a%d' % k]) for k in range(4)],
            'b0': int(r[i]['b0']), 'bg0': int(r[i]['bg0']),
            'udp': int(r[i]['udp']), 'udperr': int(r[i]['udperr']),
            'w1544': int(r[i]['w1544']), 'w520': int(r[i]['w520']),
            'frames': [{'flen': int(f['flen']), 'iplen': int(f['iplen']),
                        'hop': int(f['hop']), 'uhlen': int(f['uhlen']),
                        'uhck': int(f['uhck'], 16)} for f in t.get(i, [])],
        })
    out['boots'].append({'tag': 'logs/f63_%s.log' % tag, 'arms': rows})
json.dump(out, open('%s/findings/F63-gro-aggregate/summary.json' % ROOT, 'w'),
          indent=1, sort_keys=True)
print('arms parsed:', [len(b['arms']) for b in out['boots']])
