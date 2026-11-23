#!/usr/bin/env python3
"""f30_summary.py -- build findings/F30-network-base-guard/summary.json from
the logs, and print the markdown tables that SUMMARY.md quotes.

Every number in the JSON is read out of logs/f30_*.log; nothing is typed by
hand here.  tools/audit_f30_doc.py re-derives the SUMMARY.md cells from the
same logs and compares them with what is written there.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, 'logs')
RUNS = ['B_rep1', 'B_rep2', 'Q_rep1', 'R_rep1', 'G_rep1', 'P_rep1']
OUT = os.path.join(ROOT, 'findings/F30-network-base-guard/summary.json')


def read(tag):
    with open(os.path.join(LOGS, 'f30_%s.log' % tag), errors='replace') as f:
        return f.read()


def counters(t):
    out = {}
    for l in t.splitlines():
        if 'counter packets' in l and (l.startswith('F552CA ') or l.startswith('F552V ')):
            m = re.match(r'F552(?:CA|V) (\S+) .*counter packets (\d+)', l)
            if m:
                out[m.group(1)] = int(m.group(2))
    return out


def raw_counters(t):
    out = {}
    for l in t.splitlines():
        m = re.match(r'F552CNT (\d)\.(\S+)\|pkts=(\d+)', l)
        if m:
            out['%s.%s' % (m.group(1), m.group(2))] = int(m.group(3))
    return out


def spellings(t):
    """A sections: the counter after the store, and the frame delta."""
    cnt = counters(t)
    out = {'ip': [], 'ip6': [], 'll': []}
    for l in t.splitlines():
        m = re.match(r'F552 ((?:ip|ip6)\.(?:ip|ip6)\.\S+)\|rule=(.*?)\|sent=\d+\|'
                     r'cap=(\d+)\|flen=(\d+)\|nchg=(\d+)\|chg=(\S*)\|hex=', l)
        if m:
            tag = m.group(1)
            fam = 'ip' if tag.startswith('ip.') else 'ip6'
            out[fam].append({'tag': tag, 'rule': m.group(2), 'alive': cnt.get(tag),
                             'nchg': int(m.group(5)), 'chg': m.group(6), 'cap': int(m.group(3))})
            continue
        m = re.match(r'F552 (ll\.\S+)\|rule=(.*?)\|sent=\d+\|cap=(\d+)\|flen=(\d+)\|deliv=(\d)', l)
        if m:
            tag = m.group(1)
            out['ll'].append({'tag': tag, 'rule': m.group(2), 'deliv': int(m.group(5)),
                              'alive': cnt.get(tag)})
    return out


def consequence(t):
    out = []
    cnt = counters(t)
    for l in t.splitlines():
        m = re.match(r'F552 (C\.(?:ip|ip6)\.\S+)\|rule=(.*?)\|nftrc=(-?\d+)\|sent=\d+\|'
                     r'cap=(\d+)\|deliv=(\d)', l)
        if m:
            out.append({'tag': m.group(1), 'rule': m.group(2), 'nftrc': int(m.group(3)),
                        'cap': int(m.group(4)), 'deliv': int(m.group(5)),
                        'counter': cnt.get(m.group(1))})
    return out


def geometry(t):
    """the write geometry nft itself declared, per spelling"""
    out = {}
    maskseen = {}
    cur = None
    for l in t.splitlines():
        if l.startswith('F552NL '):
            body = l[len('F552NL '):]
            tag, _, nl = body.partition(' ')
            m = re.search(r'payload write reg \d+ => (\d+)b @ network header \+ (\d+)'
                          r' csum_type (\d+) csum_off (\d+) csum_flags (0x[0-9a-f]+)', nl)
            if m:
                out[tag] = {'len': int(m.group(1)), 'off': int(m.group(2)),
                            'csum_type': int(m.group(3)), 'csum_off': int(m.group(4)),
                            'csum_flags': int(m.group(5), 16)}
            m = re.search(r'bitwise reg \d+ = \( reg \d+ & (0x[0-9a-f]+) \) \^ (0x[0-9a-f]+)', nl)
            if m:
                maskseen.setdefault(tag, {})['mask'] = m.group(1)
                maskseen[tag]['xor'] = m.group(2)
    for tag, v in maskseen.items():
        if tag in out:
            out[tag].update(v)
    return out


def raw(t):
    b = {}
    for l in t.splitlines():
        m = re.match(r'F552 B(\d)\.(\S+)\|off=(\d+)\|len=(\d+)\|keep=\d+\|'
                     r'csum=(\d+)\|bad=(\d+)\|sent=\d+\|cap=(\d+)\|deliv=(\d)', l)
        if m:
            b['%s.%s' % (m.group(1), m.group(2))] = {
                'off': int(m.group(3)), 'len': int(m.group(4)),
                'csum': int(m.group(5)), 'bad': int(m.group(6)),
                'cap': int(m.group(7)), 'deliv': int(m.group(8))}
    cnt = raw_counters(t)
    for k, v in b.items():
        v['counter'] = cnt.get(k)
    return b


def main():
    data = {'turn': 552, 'finding': 'F30', 'runs': {}, 'kernels': {}}
    for tag in RUNS:
        if not os.path.exists(os.path.join(LOGS, 'f30_%s.log' % tag)):
            continue
        t = read(tag)
        data['runs'][tag] = {
            'lines_f552': sum(1 for l in t.splitlines() if l.startswith('F552 ')),
            'done': 'F552 DONE' in t,
            'spellings': spellings(t),
            'consequence': consequence(t),
            'geometry': geometry(t),
            'raw': raw(t),
        }
        m = re.search(r'^### sha256: ([0-9a-f]{64})$', t, re.M)
        v = re.search(r'^Linux version (\S+)', t, re.M)
        data['kernels'][tag] = {'kernel_sha': m.group(1) if m else None,
                                'version': v.group(1) if v else None}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w') as f:
        json.dump(data, f, indent=1, sort_keys=True)
    print('wrote', OUT)

    b = data['runs']['B_rep1']
    print('\nspellings (kernel B):')
    for fam in ('ip', 'ip6', 'll'):
        for s in b['spellings'][fam]:
            alive = s.get('alive')
            print('  %-22s %-12s %s' % (s['tag'], 'alive' if alive else 'DEAD', s['rule']))
    print('\nconsequence (kernel B):')
    for c in b['consequence']:
        print('  %-24s counter=%-4s deliv=%d  %s' % (c['tag'], c['counter'], c['deliv'], c['rule']))
    print('\nraw predicate:')
    for fam, maxoff in (('4', 20), ('6', 40)):
        for ln in (1, 2):
            row = ''
            for off in range(maxoff):
                v = b['raw'].get('%s.%d.%d' % (fam, off, ln))
                row += '.' if not v else ('+' if v['counter'] else '-')
            print('  %s len=%d  %s' % (fam, ln, row))


if __name__ == '__main__':
    sys.exit(main())
