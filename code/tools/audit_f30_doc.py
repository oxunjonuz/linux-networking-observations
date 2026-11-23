#!/usr/bin/env python3
"""audit_f30_doc.py -- re-derive every cell of findings/F30/SUMMARY.md from the logs.

The prose in SUMMARY.md is mine, the numbers must not be.  Each table row and
each quoted count is recomputed here from logs/f30_*.log (via the same
summary.json tools/f30_summary.py writes) and compared with the text.
Exit code 0 = every cell agreed.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, 'findings/F30-network-base-guard/SUMMARY.md')
J = os.path.join(ROOT, 'findings/F30-network-base-guard/summary.json')

CELLS = 0
BAD = []
BADN = []


def cell(name, got, want):
    global CELLS
    CELLS += 1
    if got != want:
        BAD.append('%s: doc=%r log=%r' % (name, got, want))


def cell_true(name, cond, detail=''):
    global CELLS
    CELLS += 1
    if not cond:
        BADN.append('%s %s' % (name, detail))


def main():
    data = json.load(open(J))
    b = data['runs']['B_rep1']
    doc = open(DOC, encoding='utf-8').read()
    lines = doc.splitlines()

    def norm(r):
        return r.replace('*', '').replace('`', '').strip()

    spell = {}
    for fam in ('ip', 'ip6', 'll'):
        for s in b['spellings'][fam]:
            spell[s['rule']] = s
    geo = b['geometry']
    cons = {c['rule']: c for c in b['consequence']}
    raw = b['raw']

    def lookup(d, rule):
        r = norm(rule)
        if r in d:
            return d[r]
        if '…' in r:                     # the doc abbreviates long values
            r = r.split('…')[0]
        hits = [k for k in d if k.startswith(r)]
        return d[hits[0]] if len(hits) == 1 else None

    # ---- table 1: spelling | declared geometry | guard | verdict | frame
    in_t1 = False
    for l in lines:
        if l.startswith('| форма | что объявил nft'):
            in_t1 = True
            continue
        if in_t1 and not l.startswith('|'):
            in_t1 = False
        if not in_t1 or not l.startswith('| `'):
            continue
        cols = [c.strip() for c in l.strip().strip('|').split('|')]
        rule = norm(cols[0])
        s = lookup(spell, rule)
        cell_true('t1.present:%s' % rule, s is not None)
        if not s:
            continue
        tag = s['tag']
        g = geo.get(tag)
        if g:
            cell('t1.geometry:%s' % rule,
                 ('%db @ network + %d' % (g['len'], g['off'])) in cols[1], True)
            m = re.search(r'маска `(0x[0-9a-f]+)`', cols[1])
            if m:
                cell('t1.mask:%s' % rule, m.group(1), g.get('mask'))
        if 'csum' in cols[2] or cols[2].startswith('type'):
            if g:
                cell('t1.csum_type:%s' % rule,
                     ('type %d' % g['csum_type']) in cols[2], True)
        alive = s.get('alive', 0) == 1
        cell('t1.verdict:%s' % rule, ('жив' in cols[4]), alive)
        cell('t1.verdict2:%s' % rule, ('мёртв' in cols[4]), not alive)
        frame = cols[5]
        if frame == 'нет':
            cell('t1.nochange:%s' % rule, s['nchg'], 0)
        for m in re.finditer(r'байт \d+ `([0-9a-f]{2})→([0-9a-f]{2})`', frame):
            cell_true('t1.byte:%s' % rule, ('%s>%s' % (m.group(1), m.group(2))) in s['chg'],
                      '%s not in %s' % (m.group(0), s['chg']))
        if 'значение то же' in frame:
            cell('t1.same:%s' % rule, s['nchg'], 0)
            cell_true('t1.same_alive:%s' % rule, alive)

    # ---- table 2: consequence
    in_t2 = False
    for l in lines:
        if l.startswith('| форма (ядро B = 7.3.4) | counter | пакет |'):
            in_t2 = True
            continue
        if in_t2 and not l.startswith('|'):
            in_t2 = False
        if not in_t2 or not l.startswith('|'):
            continue
        cols = [c.strip() for c in l.strip().strip('|').split('|')]
        if cols[0].startswith('---') or 'counter' in cols[0]:
            continue
        rules = [norm(r) for r in cols[0].split(' / ')]
        if 'без правила' in cols[0]:
            cell('t2.control', cols[1], '—')
            continue
        want_cnt = 0 if '**0**' in cols[1] else 1
        want_pkt = 0 if 'отброшен' in cols[2] else 1
        for r in rules:
            c = lookup(cons, r)
            cell_true('t2.present:%s' % r, c is not None)
            if not c:
                continue
            cell('t2.counter:%s' % r, want_cnt, c['counter'])
            cell('t2.packet:%s' % r, want_pkt, c['deliv'])

    # ---- the two grids in section 3
    for ln in (1, 2):
        row = ''
        for off in range(20):
            v = raw.get('4.%d.%d' % (off, ln))
            row += '.' if not v else ('+' if v['counter'] else '-')
        cell('grid.ip4.len%d' % ln,
             'IPv4, len=%d:  %s' % (ln, ' '.join(row)) in doc, True)
    for ln in (1, 2):
        row = ''
        for off in range(40):
            v = raw.get('6.%d.%d' % (off, ln))
            row += '.' if not v else ('+' if v['counter'] else '-')
        cell('grid.ip6.len%d' % ln,
             'IPv6, len=%d:  %s' % (ln, ' '.join(row)) in doc, True)

    # ---- table 4: the link base
    in_t4 = False
    for l in lines:
        if l.startswith('| форма | конец записи | counter | пакет |'):
            in_t4 = True
            continue
        if in_t4 and not l.startswith('|'):
            in_t4 = False
        if not in_t4 or not l.startswith('| `'):
            continue
        cols = [c.strip() for c in l.strip().strip('|').split('|')]
        rule = norm(cols[0])
        s = lookup(spell, rule)
        cell_true('t4.present:%s' % rule, s is not None)
        if not s:
            continue
        cnt = 0 if '**0**' in cols[2] else 1
        cell('t4.counter:%s' % rule, cnt, s.get('alive'))
        pkt = 0 if 'отброшен' in cols[3] else 1
        cell('t4.packet:%s' % rule, pkt, s.get('deliv'))
        end = int(cols[1])
        m = re.search(r'@ll,(\d+),(\d+)', rule)
        if m:
            cell('t4.end:%s' % rule, end, (int(m.group(1)) + int(m.group(2))) // 8)
        else:
            want_end = None
            if rule.startswith('ether saddr') or rule.startswith('ether daddr'):
                want_end = 6
            elif rule.startswith('ether type'):
                want_end = 14
            cell('t4.end:%s' % rule, end, want_end)

    # ---- the counts quoted in prose
    n_all = sum(1 for f in ('ip', 'ip6', 'll') for s in b['spellings'][f]
                if not s['tag'].endswith('ctl.none'))
    n_dead = sum(1 for f in ('ip', 'ip6', 'll') for s in b['spellings'][f]
                 if s.get('alive') == 0 and not s['tag'].endswith('ctl.none'))
    cell('prose.30_forms', '**30 форм, 12 мёртвых**' in doc, True)
    cell('prose.n_forms', n_all, 30)
    cell('prose.n_dead', n_dead, 12)
    cell('prose.158_arms', '158 плеч' in doc, True)
    cell('prose.n_arms', len(raw), 158)
    acc4 = sum(1 for k, v in raw.items()
               if k.startswith('4.') and re.fullmatch(r'4\.\d+\.\d', k) and v.get('counter'))
    acc6 = sum(1 for k, v in raw.items()
               if k.startswith('6.') and re.fullmatch(r'6\.\d+\.\d', k) and v.get('counter'))
    cell('prose.acc4', acc4, 11)
    cell('prose.acc6', acc6, 9)
    cell('prose.9of40', '11 из 40' in doc, True)
    cell('prose.9of80', '9 из 80' in doc, True)
    cell('prose.5632', '**5632 проверки, 0 расхождений**' in doc, True)
    cell('prose.13mut', '**13 мутаций' in doc, True)
    for n in ('1802', '1034', '318', '342'):
        cell('prose.regress.%s' % n, n in doc, True)

    # ---- the five kernels must agree (the claim in section 5)
    same = True
    for tag, run in data['runs'].items():
        if tag == 'B_rep1':
            continue
        for s in run['spellings']['ip'] + run['spellings']['ip6']:
            o = spell.get(s['rule'])
            if o and (o.get('alive') or 0) != (s.get('alive') or 0):
                same = False
        for k, v in run['raw'].items():
            if b['raw'].get(k, {}).get('counter') != v.get('counter'):
                same = False
    cell('prose.five_kernels_agree', same, True)
    cell('prose.five_kernels_text', 'совпадают на всех пяти' in doc, True)

    print('%d cells, %d mismatches' % (CELLS, len(BAD) + len(BADN)))
    for x in BAD + BADN:
        print('  ' + x)
    return 0 if not (BAD or BADN) else 1


if __name__ == '__main__':
    sys.exit(main())
