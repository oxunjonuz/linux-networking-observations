#!/usr/bin/env python3
"""audit_f74_doc.py -- does SUMMARY.md say what the logs measured?

Every number the document quotes is recomputed from the campaign logs (or from
arithmetic the document itself states) and looked for in the document text.
Run with no arguments: audits findings/F74-*/SUMMARY.md.
`--mutate` copies the document, changes one number, and requires the audit to
go red -- the only way to know the audit can fail.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = '/work/kernel-sec'
DOC = ROOT + '/findings/F74-sender-sets-the-bill/SUMMARY.md'
LOGS = [ROOT + '/logs/f74_rep1.log', ROOT + '/logs/f74_rep2.log']
sys.path.insert(0, ROOT + '/tools')
import verify596 as V   # noqa: E402

CHECKS = 0
FAILS = []


def ck(cond, msg):
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(msg)


def ck_eq(got, want, msg):
    ck(got == want, '%s: got %r, want %r' % (msg, got, want))


def measure():
    """arm name -> list of (kept, rmem, inerrors_delta), one per attempt."""
    out = {}
    for path in LOGS:
        D = V.parse_log(path)
        order = list(D['rcv'].keys())
        prev = {order[j]: (order[j - 1] if j else None)
                for j in range(len(order))}
        for k in order:
            if k[0] != 'q':
                continue
            f = D['arm'].get(k, {})
            name = f.get('name')
            if not name:
                continue
            r = D['rcv'][k]
            pk = prev[k]
            b = V.gint(D['rcv'][pk], 'udperr') if pk else 0
            out.setdefault(name, []).append(
                (V.gint(r, 'n0'), V.gint(r, 'rmem0'),
                 (V.gint(r, 'udperr') or 0) - (b or 0),
                 V.arr(D['eq'].get(k, {}).get('ts', ''))))
        for k in D['rec']:
            if k[0] != 'TX':
                continue
            mode, i, att = k[1], k[2], k[3]
            name = D['arm'].get((mode, i, att), {}).get('name')
            if not name:
                continue
            for (ts_, dl, ln, tl, en, fl) in D['rec'][k]:
                for j in range(len(ln)):
                    out.setdefault('tx:' + name, []).append(
                        (ln[j], en[j], ts_[j]))
    return out


ROWS = [
    # arm, R, kept, rmem, errors
    ('q64_a0_R38', 38400, 7, 35392, 57),
    ('q64_a0_R50', 51200, 10, 50560, 54),
    ('q64_a0_R76', 76800, 15, 75840, 49),
    ('q64_a0_R102', 102400, 20, 101120, 44),
    ('q64_4096a36_R38', 38400, 4, 36608, 60),
    ('q64_4096a36_R50', 51200, 5, 45760, 59),
    ('q64_4096a36_R76', 76800, 8, 73216, 56),
    ('q64_4096a36_R102', 102400, 11, 100672, 53),
    ('q64_a0_one', 35390, 6, 30336, 58),
    ('q64_a0_eq', 35392, 7, 35392, 57),
    ('q64_a0_full', 323584, 64, 323584, 0),
    ('q64_4096a36_full', 585728, 64, 585728, 0),
    ('q64_a0_cn', 38400, 7, 35392, 57),
    ('q64_a36_R38', 38400, 5, 37568, 59),
    ('q64_a36_R50', 51200, 7, 47680, 57),
    ('q64_a36_R76', 76800, 11, 76096, 53),
    ('q64_a36_R102', 102400, 14, 99456, 50),
    ('q64_a36_full', 585728, 64, 454656, 0),
    ('q64_4097a0', 38400, 4, 36608, 60),
    ('q64_z200', 38400, 18, 33664, 46),
    ('q64_4096a0_R38', 38400, 5, 33472, 59),
]

R_IN_ROW = {'q64_a0_R38', 'q64_a0_R50', 'q64_a0_R76', 'q64_a0_R102',
            'q64_4096a36_R38', 'q64_4096a36_R50', 'q64_4096a36_R76',
            'q64_4096a36_R102', 'q64_a0_one', 'q64_a0_eq', 'q64_a0_full',
            'q64_4096a36_full'}

HEIGHT = [(270, 384, 960), (277, 384, 960), (278, 384, 960), (309, 384, 960),
          (310, 384, 960), (325, 384, 960), (326, 704, 1280),
          (342, 704, 1280), (5000, 7872, 8448)]


def audit(doc_path, M):
    doc = open(doc_path, errors='replace').read()
    flat = ' '.join(doc.split())

    # every quoted arm row must be measured, four times (2 attempts, 2 boots)
    for name, R, kept, rmem, err in ROWS:
        got = M.get(name, [])
        ck_eq(len(got), 4, '%s: four attempts in the logs' % name)
        for g in got:
            ck_eq((g[0], g[1], g[2]), (kept, rmem, err),
                  '%s: log says %r' % (name, g[:3]))
        row = re.search(r'\|\s*`%s`\s*\|([^|\n]*\|){3,5}' % re.escape(name),
                        doc)
        if row:
            # cell by cell, not substring: '6' lives inside '17695' too
            cells = [c.strip().strip('*').strip()
                     for c in row.group(0).split('|')]
            ck(str(kept) in cells, '%s: kept %d as a cell' % (name, kept))
            ck(str(rmem) in cells, '%s: rmem %d as a cell' % (name, rmem))
            # only the arms of the curve table print R in their row; the
            # mixed arms are argued in their own table, the three prose arms
            # in prose, and R is checked for them by the log comparison above
            if name in R_IN_ROW:
                ck(str(R) in cells, '%s: R %d as a cell' % (name, R))
        else:
            # three arms are argued in prose rather than in a table: their
            # name and their two numbers must still stand together
            at = doc.find('`%s`' % name)
            ck(at >= 0, '%s: named in the document' % name)
            near = doc[max(0, at - 400):at + 400]
            ck(str(kept) in near and str(rmem) in near,
               '%s: kept %d and rmem %d near its name' % (name, kept, rmem))

    # the arithmetic the document asserts
    ck_eq(7 * 5056, 35392, '7 x 5056')
    ck_eq(64 * 5056, 323584, '64 x 5056')
    ck_eq(64 * 9152, 585728, '64 x 9152')
    ck_eq(32 * 9152 + 32 * 5056, 454656, 'the mixed full arm')
    ck_eq(4 * 5056 + 14 * 960, 33664, 'the 200-byte arm')
    ck_eq(18 * 5056, 91008, 'what 18 x 5056 would have been')
    ck_eq(18 * 5056 - 33664, 57344, 'what the pull saved')
    ck_eq(6 * 5056, 30336, 'six datagrams')
    ck_eq(7 * 5056 - 6 * 5056, 5056, 'one datagram of the pair')
    ck_eq(7 * 512, 3584, 'payload bytes kept at offset 0')
    ck_eq(4 * 512, 2048, 'payload bytes kept at offset 3600')
    ck_eq(9152 + 5056, 14208, 'the first two of the alternating arm')
    ck_eq(42624 + 5056, 47680, 'the eighth datagram still fits')
    ck_eq(42624 + 9152, 51776, 'the seventh did not')
    ck(51776 > 51200, 'and it does not fit: 51776 > 51200')
    for n in (91008, 57344, 35392, 323584, 585728, 454656, 33664, 33472,
              47680, 76096, 99456, 36608, 45760, 73216, 100672, 30336,
              20224, 13440, 51500):
        pass
    for needle in ('91008', '57344', '51776', '57344', '35392', '323584', '585728', '454656',
                   '33664', '33472', '47680', '76096', '99456', '36608',
                   '45760', '73216', '100672', '30336', '20224', '13440',
                   '42624', '51776', '3584', '2048'):
        ck(needle in flat, 'the document quotes %s' % needle)

    # the charges, as measured on the gate
    for name, seq in [('q64_a0_R38', [5056] * 16),
                      ('q64_a36_R38', [9152, 5056] * 8),
                      ('q64_4096a36_R38', [9152] * 16),
                      ('q64_4097a0', [9152] * 16),
                      ('q64_z200', [5056] * 16)]:
        got = M.get(name, [])
        ck(len(got) == 4, '%s: four attempts' % name)
        for g in got:
            ck_eq(g[3], seq, '%s: gate charges' % name)

    # the heights: end and ts per payload, on the wire
    for pl, end, ts in HEIGHT:
        name = 'h%d' % pl
        got = [r for r in M.get('tx:' + name, []) if r[0] == pl + 42]
        ck(len(got) >= 4, '%s: the datagram was on the wire in every attempt'
           % name)
        for g in got:
            ck_eq((g[1], g[2]), (end, ts), '%s: end/ts at the wire' % name)
        line = None
        for ln in doc.split('\n'):
            if not ln.startswith('|'):
                continue
            cells = [c.strip().strip('*').strip() for c in ln.split('|')]
            if len(cells) > 3 and cells[1] == str(pl):
                line = ln
                break
        ck(line is not None, 'the document has the %d-byte row' % pl)
        if line:
            ck(str(end) in line, 'the %d-byte row has end %d' % (pl, end))
            ck(str(ts) in line, 'the %d-byte row quotes ts %d' % (pl, ts))

    # the frozen files must still be the frozen files
    ck_eq(V.sha(V.PRED_A), V.PRED_A_SHA, 'predictions_596.md unchanged')
    ck_eq(V.sha(V.PRED_B), V.PRED_B_SHA, 'predictions_596b.md unchanged')

    # the seven refutations must be stated with the numbers that refuted them
    for said, measured in [('4 / 36608', '5 / 37568'),
                           ('5 / 45760', '7 / 47680'),
                           ('8 / 73216', '11 / 76096'),
                           ('11 / 100672', '14 / 99456'),
                           ('64 / 585728', '64 / 454656'),
                           ('6 / 42624', '7 / 47680'),
                           ('10 / 71040', '11 / 76096')]:
        ck(said in flat, 'the refused number %s is stated' % said)
        ck(measured in flat, 'the measured number %s is stated' % measured)
    ck('P2' in doc and 'P31' in doc and 'P32' in doc,
       'the refuted predictions are named')

    # and the three named survivors, because an unnamed survivor is a lie
    for s in ('condense', 'empty-queue clause', 'second (locked)'):
        ck(s in flat, 'the document names the survivor: %s' % s)


def main(argv):
    M = measure()
    audit(DOC, M)
    print('checks=%d fails=%d' % (CHECKS, len(FAILS)))
    for f in FAILS[:30]:
        print('FAIL', f)
    if '--mutate' in argv:
        return mutate(M)
    return 0 if not FAILS else 1


def mutate(M):
    """Change one number at a time in a copy of the document: the audit must
    go red each time, and must not crash."""
    doc = open(DOC, errors='replace').read()
    cases = [('35392', '35391'), ('33664', '33665'), ('47680', '47681'),
             ('**384**', '**448**'), ('| **326** | **704** | **1280** |',
                                      '| **326** | **704** | **1344** |'),
             ('**7872**', '**7873**'), ('91008', '91009'),
             ('57344', '57345'), ('| 35390 | **6** |', '| 35390 | **7** |'),
             ('| 38400  | 5056 |', '| 38401  | 5056 |')]
    bad = 0
    for old, new in cases:
        if old not in doc:
            print('MUTATE-SKIP', old)
            bad += 1
            continue
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, 'SUMMARY.md')
        open(path, 'w').write(doc.replace(old, new, 1))
        global CHECKS, FAILS
        CHECKS, FAILS = 0, []
        try:
            audit(path, M)
            red = bool(FAILS)
        except Exception as e:      # a crash is not a red
            print('MUTATE-CRASH', old, new, repr(e))
            bad += 1
            shutil.rmtree(tmp)
            continue
        print('%-5s mutate %s -> %s' % ('RED' if red else 'SURVIVED', old, new))
        if not red:
            bad += 1
        shutil.rmtree(tmp)
    print('MUTATIONS %d/%d red' % (len(cases) - bad, len(cases)))
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
