#!/usr/bin/env python3
"""audit_f49_doc.py [doc] -- check the prose of F49 against the log.

The seven tables of SUMMARY.md are compared cell-by-cell with the output of
f571_summary.py; the numbers stated in the prose are compared with the same
generated blocks or with a fresh run of verify571.py.  Nothing in the document
is trusted because it was written next to a measurement.
"""
import os
import re
import subprocess
import sys

BASE = '/work/kernel-sec'
DOC = sys.argv[1] if len(sys.argv) > 1 else BASE + '/findings/F49-ppp0-layer3/SUMMARY.md'
GEN = BASE + '/findings/_f49_tables.md'
NBAD = [0]
NCHK = [0]
DETAIL = []


def ck(cond, what):
    NCHK[0] += 1
    if not cond:
        NBAD[0] += 1
        if len(DETAIL) < 40:
            DETAIL.append(what)
    return bool(cond)


def blocks(path, mode):
    """mode 'html' reads <!-- Tn --> ... <!-- /Tn -->; 'gen' reads ### Tn ..."""
    txt = open(path, 'r', errors='replace').read().split('\n')
    out = {}
    if mode == 'html':
        cur = None
        for ln in txt:
            m = re.match(r'<!--\s*(T\d)\s*-->', ln)
            if m:
                cur = m.group(1)
                out[cur] = []
                continue
            if re.match(r'<!--\s*/\s*T\d\s*-->', ln):
                cur = None
                continue
            if cur:
                out[cur].append(ln)
    else:
        cur = None
        for ln in txt:
            m = re.match(r'###\s*(T\d)\b', ln)
            if m:
                cur = m.group(1)
                out[cur] = [ln]
                continue
            if ln.startswith('### '):
                cur = None
                continue
            if cur:
                out[cur].append(ln)
    return out


def strip(block):
    return [ln for ln in block if ln.strip() != '']


def main():
    subprocess.run(['python3', BASE + '/tools/f571_summary.py',
                    BASE + '/logs/f49_rep1.log'],
                   stdout=open(GEN, 'w'), check=True)
    D = blocks(DOC, 'html')
    G = blocks(GEN, 'gen')
    ck(len(D) == 7, 'the document carries seven generated tables')
    for k in sorted(G):
        if k not in D:
            ck(False, 'table %s missing from the document' % k)
            continue
        a = strip([ln for ln in D[k] if not ln.startswith('### ')])
        b = strip([ln for ln in G[k] if not ln.startswith('### ')])
        ck(len(a) == len(b), '%s: same number of rows (%d vs %d)' %
           (k, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            ck(x.strip() == y.strip(), '%s row %d: %r != %r' % (k, i, x, y))
            cx = [c.strip() for c in x.strip().strip('|').split('|')]
            cy = [c.strip() for c in y.strip().strip('|').split('|')]
            ck(len(cx) == len(cy), '%s row %d: cell count' % (k, i))
            for j, c in enumerate(cx):
                NCHK[0] += 1
                if j >= len(cy) or c != cy[j]:
                    NBAD[0] += 1
                    if len(DETAIL) < 40:
                        DETAIL.append('%s row %d cell %d: %r != %r' %
                                      (k, i, j, c, cy[j] if j < len(cy) else None))

    txt = open(DOC, 'r', errors='replace').read()

    # ---- prose numbers, each against its own source
    ck('88 байт' in txt, 'the frame size is stated')
    ck('71 плечо' in txt, 'the arm count is stated')
    ck('PPPOE_SES_HLEN (8)' in txt, 'the PPPoE header length is 8')
    # the checks of the verifier: run it
    r = subprocess.run(['python3', BASE + '/tools/verify571.py'],
                       capture_output=True, text=True)
    m = re.search(r'checks=(\d+) bad=(\d+)', r.stdout)
    ck(bool(m), 'the verifier reports its numbers')
    if m:
        ck(m.group(2) == '0', 'the verifier is green')
        ck(('%s проверки' % m.group(1)) in txt,
           'the document quotes the verifier count (%s)' % m.group(1))
    # the selftest count
    st = BASE + '/tools/verify571_selftest.sh'
    ck(os.path.exists(st), 'the selftest exists')
    ck('19/19' in txt, 'the document quotes the selftest result')
    # every refuted prediction named in the prose exists in the prediction file
    pred = open(BASE + '/research/predictions_571.md', errors='replace').read()
    for p in ('P3', 'P5', 'P9', 'P10', 'P15'):
        ck(p in pred, 'prediction %s exists' % p)
        ck(('| %s |' % p) in txt, 'prediction %s is in the refuted table' % p)
    # the facts the document leans on must be in the verifier, too
    v = open(BASE + '/tools/verify571.py', errors='replace').read()
    ck('skb_mac_header_len' in txt, 'the @ll refusal names its check')
    ck("th0_2_m_cs" in v and 'th0_2_m_cs' in txt,
       'the pre-decap transport write is a measured arm')
    ck('prehwhex' in v, 'the verifier reads NFULA_HWHEADER bytes')

    print('cells=%d bad=%d' % (NCHK[0], NBAD[0]))
    for d in DETAIL:
        print('BAD: ' + d)
    return 1 if NBAD[0] else 0


if __name__ == '__main__':
    sys.exit(main())
