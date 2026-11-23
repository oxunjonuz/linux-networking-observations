#!/usr/bin/env python3
"""audit_f73_doc.py -- does SUMMARY.md say what the logs measured?

Every number quoted in the document is looked up in the campaign logs and
compared.  Run with no arguments: audits findings/F73-*/SUMMARY.md.
`--mutate` copies the document, changes one number, and requires the audit to
go red (that is the only way to know the audit can fail).
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = '/work/kernel-sec'
DOC = ROOT + '/findings/F73-charge-and-clones/SUMMARY.md'
LOG1 = ROOT + '/logs/f73_rep1.log'
LOG2 = ROOT + '/logs/f73_rep2.log'
SPL = ROOT + '/logs/f73_spl.log'
F72 = ROOT + '/logs/f72_rep1.log'

CHECKS = 0
FAILS = []


def ck(cond, msg):
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(msg)


def ck_eq(got, want, msg):
    ck(got == want, '%s: got %r, want %r' % (msg, got, want))


def gate_map(path):
    """arm name -> gate ts list, from ARM lines and GATE lines in order"""
    out, cur = {}, None
    for line in open(path, errors='replace'):
        m = re.match(r'F595 ARM\|i=(\d+)\|att=(\d+)\|name=([^|]+)\|', line)
        if m:
            cur = m.group(3)
            continue
        m = re.match(r'F595 GATE\|i=\d+\|att=\d+\|n=\d+\|ts=([\d,]+)\|'
                     r'dlen=([\d,]+)\|len=([\d,]+)\|end=([\d,]+)'
                     r'\|fl=([\d,]+)', line)
        if m and cur:
            out[cur] = ([int(x) for x in m.group(1).split(',')],
                        [int(x) for x in m.group(2).split(',')],
                        [int(x) for x in m.group(3).split(',')],
                        [int(x) for x in m.group(4).split(',')],
                        [int(x) for x in m.group(5).split(',')])
            cur = None
    return out


def clone_counts(path):
    """CNT is printed BEFORE the ARM line of the same attempt: buffer it"""
    out, pend = {}, None
    for line in open(path, errors='replace'):
        m = re.match(r'F595 CNT\|i=\d+\|att=\d+\|.*clone=(\d+)\|', line)
        if m:
            pend = int(m.group(1))
            continue
        m = re.match(r'F595 ARM\|i=(\d+)\|att=(\d+)\|name=([^|]+)\|', line)
        if m:
            if pend is not None:
                out.setdefault(m.group(3), []).append(pend)
            pend = None
    return out


def callers(path):
    out = []
    for line in open(path, errors='replace'):
        m = re.search(r'F595 CALLERS\|[^|]*\|[^|]*\|n=(\d+)\|a=([0-9a-f,]+)',
                      line)
        if m:
            out.append(m.group(2).split(','))
    return out


def main():
    doc = open(DOC, errors='replace').read() if not sys.argv[1:] else \
        open(sys.argv[-1], errors='replace').read()
    g1 = gate_map(LOG1)
    g2 = gate_map(LOG2)
    gs = gate_map(SPL)

    # ---- §1: the eight charge cells, as the document states them
    for arm, ts in (('g512_a0', 5056), ('g512_az', 5056), ('g512_a36', 9152),
                    ('g1200_a36', 9152), ('g4097_a0', 9152),
                    ('g5000_a0', 9152), ('g5000_a36', 13248)):
        ck(arm in g1, 'the log has arm ' + arm)
        if arm in g1:
            ck_eq(g1[arm][0], [ts], 'gate ts of ' + arm + ' (boot 1)')
        if arm in g2:
            ck_eq(g2[arm][0], [ts], 'gate ts of ' + arm + ' (boot 2)')
        ck(('`%s`' % arm) in doc, 'the document names arm ' + arm)
        ck(str(ts) in doc, 'the document quotes %d' % ts)

    # the identity: ts = 960 + page_up(pl + off)
    def page_up(x):
        return (x + 4095) & ~4095
    for arm, pl, off in (('g512_a0', 512, 0), ('g512_a36', 512, 3600),
                         ('g1200_a36', 1200, 3600), ('g4097_a0', 4097, 0),
                         ('g5000_a0', 5000, 0), ('g5000_a36', 5000, 3600)):
        ck_eq(g1[arm][0][0], 960 + page_up(pl + off),
              'the identity holds for ' + arm)
    ck('960 + `PAGE_ALIGN(payload + offset)`' in doc or
       'PAGE_ALIGN(payload + offset)' in doc,
       'the document states the identity')
    ck('net/core/datagram.c:662' in doc, 'the document cites the line')
    ck('lib/iov_iter.c:1080' in doc, 'the document cites the start offset')

    # ---- §2: the three-cell demonstration
    ck_eq(g1['g512_az'][0], g1['g512_a0'][0],
          'the raw buffer charges like offset 0')
    ck(g1['g512_a36'][0] != g1['g512_a0'][0], 'the offset changes the charge')
    allch = sum(1 for l in open(F72, errors='replace') if 'F594 CHILDS|' in l)
    n_al = sum(1 for l in open(F72, errors='replace')
               if 'F594 CHILDS|' in l and 'cmd=sa0' in l)
    ck_eq(allch, 181, 'F72 printed 181 CHILDS lines')
    ck_eq(n_al, 18, 'eighteen of them are test commands')
    bad = sum(1 for l in open(F72, errors='replace')
              if 'F594 CHILDS|' in l and 'al=' in l)
    ck_eq(bad, 0, 'not one of the 181 carries an alignment')
    ck('181' in doc, 'the document quotes 181')

    # ---- §3: the clones
    cl1 = clone_counts(LOG1)
    for arm, n in (('c6_log', 5), ('c6_cnt', 5), ('c1_log', 0),
                   ('c6_f', 0)):
        ck_eq(cl1.get(arm), [n, n], 'clone count of ' + arm)
        ck(arm in doc, 'the document names ' + arm)
    ca = callers(LOG1) + callers(LOG2)
    ck_eq(len(ca), 8, 'two boots times four attempts carry callers')
    for c in ca:
        ck_eq(len(set(c)), 1, 'one caller per attempt')
        ck_eq(len(c), 5, 'five clones per attempt')
        ck_eq(c[0], 'ffffffff829134c4', 'the caller address')
    ck('0xffffffff829134c4' in doc, 'the document quotes the caller')
    ck('net/core/skbuff.c:4933' in doc, 'the document cites the clone site')
    ck_eq(g1['c6_f'][0], [7680, 1280, 1280, 1280, 1280, 1280],
          'the fraglist door head carries the aggregate')
    ck_eq(g1['c6_log'][4], [0, 1, 1, 1, 1, 1],
          'the cloned bit marks the five clones')
    ck_eq(g1['c6_f'][4], [0, 0, 0, 0, 0, 0],
          'the fraglist door leaves the bit clear')

    # ---- §4: the splice arms and the diagnostic
    ck_eq(gs['s512'][0], [1280], 's512 charge')
    ck_eq(gs['s512'][3], [704], 's512 end')
    ck_eq(gs['s5000'][0], [8448], 's5000 charge')
    ck_eq(gs['s5000'][3], [7872], 's5000 end')
    ck_eq(gs['z512'][0], [9152], 'z512 charge')
    ck_eq(gs['z5000'][0], [13248], 'z5000 charge')
    for n in ('1280', '8448', '704', '7872', '9152', '13248'):
        ck(n in doc, 'the document quotes ' + n)
    api = [l for l in open(SPL, errors='replace') if 'F595 API|' in l]
    ck_eq(len(api), 16, 'the diagnostic printed sixteen API records')
    zeros = [l for l in api if 'flags=0|' in l]
    zeros = [l for l in zeros if 'len=520|' in l or 'len=5008|' in l]
    ck_eq(len(zeros), 4, 'both splice attempts saw flags = 0')
    zc = [l for l in api if 'flags=67108864|' in l]
    ck_eq(len(zc), 4, 'both zerocopy attempts saw MSG_ZEROCOPY')
    ck('net/socket.c:2277' in doc, 'the document cites the syscall filter')
    ck('MSG_INTERNAL_SENDMSG_FLAGS' in doc, 'the document names the mask')
    ck('include/linux/socket.h:358' in doc, 'the document cites the mask')

    # ---- §5: the prediction count
    conf = re.findall(r'\*\*P\d+\*\*', doc[doc.find('## 5.'):doc.find('## 6.')])
    ck(len(conf) >= 12, 'the document lists the confirmed predictions')
    ck('**Refuted: P9 and P10**' in doc, 'the document names the refutation')
    ck('12 confirmed, 2 refuted' in doc, 'the heading count')

    # ---- the sections a summary must have
    for sec in ('## 0.', '## 1.', '## 2.', '## 3.', '## 4.', '## 5.',
                '## 6.', '## 7.', '## 8.'):
        ck(sec in doc, 'section present: ' + sec)
    ck('Не уязвимость' in doc, 'the scope note')
    ck('predictions_595.md' in doc, 'the predictions file is named')

    # ---- the three tables, parsed cell by cell
    def cell_int(s):
        m = re.search(r'-?\d+', s.replace('*', ''))
        return int(m.group(0)) if m else None

    def table(sec_start, sec_end):
        i, j = doc.find(sec_start), doc.find(sec_end)
        out = []
        for line in doc[i:j].split('\n'):
            if line.startswith('|') and '`' in line:
                cells = [c.strip() for c in line.strip('|').split('|')]
                names = re.findall(r'`([^`]+)`', cells[0])
                if names:
                    out.append((names[-1], cells))
        return out

    for arm, cells in table('## 1.', '## 2.'):
        if arm in g1 and len(cells) >= 6:
            ck_eq(cell_int(cells[3]), g1[arm][0][0],
                  'table 1: ts of ' + arm)
            ck_eq(cell_int(cells[4]), g1[arm][3][0],
                  'table 1: end of ' + arm)
            ck_eq(cell_int(cells[5]), g1[arm][1][0],
                  'table 1: dlen of ' + arm)
    for arm, cells in table('## 2.', '## 3.'):
        if arm in g1 and len(cells) >= 4:
            ck_eq(cell_int(cells[3]), g1[arm][0][0], 'table 2: ts of ' + arm)
    seg_calls = {}
    for line in open(LOG1, errors='replace'):
        m = re.match(r'F595 CNT\|i=\d+\|att=\d+\|.*\|seg=(\d+)\|segl=(\d+)\|',
                     line)
        if m:
            seg_calls.setdefault('_', []).append((int(m.group(1)),
                                                  int(m.group(2))))
    for arm, cells in table('## 3.', '## 4.'):
        if arm in cl1 and len(cells) >= 8:
            ck_eq(cell_int(cells[3]), cl1[arm][0],
                  'table 3: clone count of ' + arm)
            ck_eq(cells[7], ','.join(str(x) for x in g1[arm][4]),
                  'table 3: cloned bits of ' + arm)
    for arm, cells in table('## 4.', '## 5.'):
        name = arm
        if name in gs and len(cells) >= 6:
            ck_eq(cell_int(cells[4]), gs[name][0][0], 'table 4: ts of ' + name)
            ck_eq(cells[5].replace(' ', ''),
                  '%d,%d' % (gs[name][3][0], gs[name][1][0]),
                  'table 4: end,dlen of ' + name)

    print('checks: %d, failures: %d' % (CHECKS, len(FAILS)))
    for f in FAILS[:40]:
        print('FAIL ' + f)
    return 1 if FAILS else 0


def mutate():
    """one number at a time in a copy of the document; each must be caught"""
    base = open(DOC, errors='replace').read()
    rc = subprocess.run([sys.executable, __file__],
                        capture_output=True).returncode
    print('baseline rc=%d' % rc)
    if rc != 0:
        return 1
    muts = [('section1', '| **5056** | 384 | 512 | 960 + 4096 |',
             '| **5057** | 384 | 512 | 960 + 4096 |'),
            ('caller', '0xffffffff829134c4', '0xffffffff829134c5'),
            ('clone_site', 'net/core/skbuff.c:4933', 'net/core/skbuff.c:4932'),
            ('f72_lines', '181', '182'),
            ('splice_end', '| **8448** | 7872, 0 |', '| **8448** | 7873, 0 |'),
            ('syscall', 'net/socket.c:2277', 'net/socket.c:2278'),
            ('predictions', '12 confirmed, 2 refuted', '11 confirmed, 3 refuted'),
            ('identity', 'net/core/datagram.c:662', 'net/core/datagram.c:663'),
            ('cloned_bit', '0,1,1,1,1,1', '0,1,1,1,1,0'),
            ('scope', 'Не уязвимость', 'Уязвимость')]
    bad = 0
    tmp = tempfile.mkdtemp(prefix='f73_doc_')
    for name, old, new in muts:
        if old not in base:
            print('%-12s SAMPLE NOT FOUND' % name)
            bad += 1
            continue
        p = os.path.join(tmp, name + '.md')
        open(p, 'w').write(base.replace(old, new, 1))
        r = subprocess.run([sys.executable, __file__, p],
                           capture_output=True, text=True)
        ok = r.returncode == 1 and 'Traceback' not in r.stdout + r.stderr
        print('%-12s %s' % (name, 'RED' if ok else 'NOT RED'))
        bad += 0 if ok else 1
    print('doc mutations: %d, not caught: %d' % (len(muts), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    if '--mutate' in sys.argv:
        sys.exit(mutate())
    sys.exit(main())
