#!/usr/bin/env python3
"""audit_f51_doc.py -- regenerate the tables of F51's SUMMARY.md from the log
and compare them, cell by cell, plus the prose facts the document asserts.

Three single-cell substitutions in a copy of the document must each make exactly
one cell disagree (the -t mode).
"""
import re
import subprocess
import sys

BASE = '/work/kernel-sec'
DOC = BASE + '/findings/F51-flood-copies/SUMMARY.md'
LOG = BASE + '/logs/f51_rep1.log'
N = [0]
BAD = [0]
DET = []


def ck(cond, what):
    N[0] += 1
    if not cond:
        BAD[0] += 1
        DET.append(what)


def tables_from_log():
    out = subprocess.run(['python3', BASE + '/tools/f573_summary.py', LOG],
                         capture_output=True, text=True).stdout
    blocks, cur = {}, None
    for ln in out.splitlines():
        if ln.startswith('### T'):
            cur = ln.split()[1]
            blocks[cur] = []
        elif cur:
            blocks[cur].append(ln)
    for k in blocks:
        b = [l for l in blocks[k] if not l.startswith('###')]
        while b and not b[0].strip():
            b.pop(0)
        while b and not b[-1].strip():
            b.pop()
        blocks[k] = b
    return blocks


def cells(blocks):
    """Every table row of the document, as a list of lines, mapped to its block."""
    doc = open(DOC).read().splitlines()
    out = []
    for k, blk in blocks.items():
        for line in blk:
            if not line.startswith('|'):
                continue
            ck(line in doc, 'table %s row is in the document: %s' % (k, line[:60]))
            out.append((k, line))
    return out


def facts():
    txt = open(LOG, 'rb').read().decode('utf8', 'replace')
    doc = open(DOC).read()

    def has(s):
        return s in txt

    # the prose of the document, against the log's own lines
    ck(has('F573 SYS|') and 'vfpath=0' in txt and 'vf=-1' in txt,
       'log says the vlan_filtering attribute does not exist')
    ck('vfpath=0' in doc and 'vf=-1' in doc,
       'document says the vlan_filtering attribute does not exist')
    ck('| preS | A | 1 | 2 | 1 | 1 |' in doc, 'doc: the census row of preS')
    ck('| preD | A | 1 | 0 | 0 | 0 |' in doc, 'doc: the census row of preD')
    ck('brf=2,2' in txt, 'log: the forward door evaluates twice')
    ck('@ll,0,6' in doc, 'doc names the store it measured')
    ck('skb->cloned = 1;' in doc, 'doc quotes the line that marks the source')
    ck('pskb_expand_head' in doc, 'doc names the copy')
    ck('skb_ensure_writable' in doc, 'doc names the store path')
    ck('3186' in doc, 'doc carries the check count of verify573.py')

    def run(v):
        o = subprocess.run(['python3', BASE + '/tools/verify573.py'],
                           capture_output=True, text=True,
                           env={'V573_REP1': BASE + '/logs/f51_rep1.log',
                                'V573_REP2': BASE + '/logs/f51_rep2.log',
                                'PATH': '/usr/bin:/bin'}).stdout
        return o

    o = run(None)
    ck('checks: 3186, mismatches: 0' in o,
       'verify573.py still reports 3186 checks and 0 mismatches')


def substitutions():
    """Three single-cell edits: invert one table cell, swap two, drop one."""
    blocks = tables_from_log()
    doc = open(DOC).read()
    tests = []
    # 1. a census cell
    a = '| ctlA | A | 1 | 2 | 1 | 1 |'
    b = '| ctlA | A | 1 | 1 | 1 | 1 |'
    tests.append((a, b))
    # 2. an SNMP6 cell
    a2 = '| in6D | in6 | +3 | +2 | +1 | +1 |'
    b2 = '| in6D | in6 | +3 | +1 | +1 | +1 |'
    tests.append((a2, b2))
    # 3. a tap cell
    a3 = '| brp | preS | 1/2/1 | 909192939495 | ffffffffffff/909192939495/40 |'
    b3 = '| brp | preS | 1/2/1 | 909192939495 | ffffffffffff/909192939495/41 |'
    tests.append((a3, b3))
    for a, b in tests:
        if a not in doc:
            ck(False, 'substitution anchor missing: ' + a[:40])
            continue
        mut = doc.replace(a, b, 1)
        bad = 0
        for k, blk in blocks.items():
            for line in blk:
                if line.startswith('|') and line not in mut.splitlines():
                    bad += 1
        ck(bad == 1, 'a single substitution reddens exactly one cell (got %d)' % bad)


def main():
    if '-t' in sys.argv:
        substitutions()
    else:
        blocks = tables_from_log()
        cells(blocks)
        facts()
    print('checks: %d, mismatches: %d' % (N[0], BAD[0]))
    for d in DET:
        print('  MISMATCH:', d)
    return 1 if BAD[0] else 0


if __name__ == '__main__':
    sys.exit(main())
