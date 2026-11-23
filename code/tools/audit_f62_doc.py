#!/usr/bin/env python3
"""audit_f62_doc.py -- check the numbers in SUMMARY.md against the boot log.

Independent of tools/verify584.py: this script reads only the document and the
two logs, and never imports the verifier's model.  It answers one question:
does the document say what the instrument measured?

  A1  every row of the 25-arm table: name, frames, lengths, uh->len, fields,
      delivered, errors -- from the log's own hexdumps
  A2  the counts the document states (25 / 48 / 11 / 25 / 25 / 1248)
  A3  the checksum constants the document quotes appear in the log
  A4  the feature words quoted in the table (ac0/ac1 of y1 and y2)
  A5  "wfl_a = w_a", "wfl_b = w_b", "lens_a = c_a" and "w_b differs from
      c_b only in frame 0" -- compared on the log's own hexdumps
  A6  every forward-door message carries hop 0x3f and a 1248-byte payload
  A7  the deltas the document states (fb67, 20c6, 55d2, 426f, ff72, 82af)

Usage: python3 tools/audit_f62_doc.py [doc] [--mutate]
"""
import os
import re
import sys

ROOT = '/work/kernel-sec'
DOC = 'findings/F62-gso-two-segmenters/SUMMARY.md'
LOGS = ['logs/f62_rep1.log', 'logs/f62_rep2.log']

N = 0
FAIL = []


def eq(got, want, what):
    global N
    N += 1
    if got != want:
        FAIL.append((what, got, want))


def parse_log(path):
    arms, rcvs, taps = [], [], {}
    for line in open(os.path.join(ROOT, path), errors='replace'):
        if line.startswith('F584 ARM|'):
            arms.append(dict(x.split('=', 1)
                             for x in line[9:].rstrip().split('|')
                             if '=' in x))
        elif line.startswith('F584 RCV|'):
            rcvs.append(dict(x.split('=', 1)
                             for x in line[9:].rstrip().split('|')
                             if '=' in x))
        elif line.startswith('F584 TAP|'):
            d = dict(x.split('=', 1)
                     for x in line[9:].rstrip().split('|') if '=' in x)
            taps.setdefault((d['dev'], int(d['i'])), []).append(
                bytes.fromhex(d['hex']))
    return arms, rcvs, taps


def doc_rows(text):
    """the 25-arm table: | # | `name` | frames | uh->len | field | del | err |"""
    rows = {}
    pat = (r'^\| (\d+) \| `([a-z0-9_]+)` \| ([0-9/*]+) \| ([0-9/*]+) \| '
           r'([0-9a-f`/*]+) \| (\d+) \| (\d+) \|$')
    for m in re.finditer(pat, text, re.M):
        rows[m.group(2)] = dict(i=int(m.group(1)),
                                frames=m.group(3).replace('*', ''),
                                uhlens=m.group(4).replace('*', ''),
                                fields=m.group(5).replace('`', '').replace('*', ''),
                                delivered=int(m.group(6)),
                                errors=int(m.group(7)))
    return rows


def uh(fr):
    return ((fr[58] << 8) | fr[59], (fr[60] << 8) | fr[61])


def c16add(a, b):
    r = (a + b) & 0xffff
    return (r + 1) & 0xffff if r < b else r


def c16sub(a, b):
    return c16add(a, (~b) & 0xffff)


def audit(doc_path):
    text = open(doc_path).read()
    rows = doc_rows(text)
    eq(len(rows), 25, 'the document has 25 arm rows')
    for path in LOGS:
        tag = os.path.basename(path)
        A, R, T = parse_log(path)
        eq(len(A), 25, '%s: 25 arms' % tag)
        for a, r in zip(A, R):
            n = a['name']
            dev = 'a' if a['dst'] == 'a' else 'b'
            frames = T.get((dev, int(a['i'])), [])
            got = dict(
                i=int(a['i']),
                frames='/'.join(str(len(f)) for f in frames),
                uhlens='/'.join(str(uh(f)[0]) for f in frames),
                fields='/'.join('%04x' % uh(f)[1] for f in frames),
                delivered=int(r['a']) + int(r['b']),
                errors=int(r['du6err']))
            want = rows.get(n)
            eq(want is not None, True, '%s: row for %s' % (tag, n))
            if want is None:
                continue
            for k in ('i', 'frames', 'uhlens', 'fields', 'delivered',
                      'errors'):
                eq(want[k], got[k], '%s: %s row %s' % (tag, n, k))
        # A2: the counts the text states
        eq(sum(int(r['a']) + int(r['b']) for r in R), 48,
           '%s: 48 datagrams delivered' % tag)
        eq(sum(int(r['du6err']) for r in R), 11, '%s: 11 udp errors' % tag)
        eq(sum(1 for a in A if a['ch'] == '1'), 25, '%s: 25 counters' % tag)
        eq(sum(1 for a in A if a['nl'] == '1'), 25, '%s: 25 logs' % tag)
        eq({int(a['lgplen']) for a in A}, {1248},
           '%s: every log is 1248 bytes' % tag)
        # A3/A7: constants, from the frames themselves
        cb = T[('b', 1)]
        eq(['%04x' % uh(f)[1] for f in cb], ['82af', '82af', '1f91'],
           '%s: c_b fields' % tag)
        eq('%04x' % uh(T[('a', 0)][0])[1], 'ff72', '%s: c_a seed' % tag)
        eq('%04x' % uh(T[('a', 12)][0])[1], 'dead', '%s: chk_a field' % tag)
        eq('%04x' % uh(T[('a', 9)][0])[0], '0020', '%s: len_a length' % tag)
        eq(uh(T[('a', 11)][0])[0], 65535, '%s: lenbig_a length' % tag)
        dl = '%04x' % c16sub(uh(T[('b', 10)][0])[1], uh(cb[0])[1])
        eq(dl, 'fb67', '%s: len_b delta is -(1208-0x20)' % tag)
        eq(dl in text, True, 'the document quotes the derived len_b delta')
        dc = '%04x' % c16sub(uh(T[('b', 13)][0])[1], uh(cb[0])[1])
        eq(dc, '20c6', '%s: chk_b delta is the seed change' % tag)
        eq(dc in text, True, 'the document quotes the derived chk_b delta')
        eq('%04x' % uh(T[('a', 19)][0])[1], '55d2',
           '%s: wb_p_a carries the true sum' % tag)
        eq('%04x' % uh(T[('b', 3)][0])[1], '426f',
           '%s: w_b frame 0 field' % tag)
        # A5: the equalities the document claims, on the log's bytes
        for x, y in (('wfl_a', 'w_a'), ('wfl_b', 'w_b'), ('lens_a', 'c_a')):
            a1 = [a for a in A if a['name'] == x][0]
            a2 = [a for a in A if a['name'] == y][0]
            d1 = 'a' if a1['dst'] == 'a' else 'b'
            d2 = 'a' if a2['dst'] == 'a' else 'b'
            eq(T.get((d1, int(a1['i']))), T.get((d2, int(a2['i']))),
               '%s: %s == %s frame for frame' % (tag, x, y))
        wb = T[('b', 3)]
        eq(wb[1:], cb[1:], '%s: w_b leaves frames 1 and 2 alone' % tag)
        eq([i for i in range(len(wb[0])) if wb[0][i] != cb[0][i]],
           [60, 61, 62, 63, 64, 65],
           '%s: w_b frame 0 differs in the field and the store only' % tag)
        wa = T[('a', 2)][0]
        eq([i for i in range(len(wa)) if wa[i] != T[('a', 0)][0][i]],
           [62, 63, 64, 65], '%s: w_a differs in four payload bytes only' % tag)
        wl = T[('b', 7)]
        eq([i for i in range(len(wl[2])) if wl[2][i] != cb[2][i]],
           [60, 61, 234, 235, 236, 237],
           '%s: wl_b lands in the last segment' % tag)
        # A4: the feature words
        feats = {}
        for line in open(os.path.join(ROOT, path), errors='replace'):
            m = re.match(r'^F584 FEAT\|dev=(\w+)\|av0=(\w+)\|ac0=(\w+)\|'
                         r'av1=(\w+)\|ac1=(\w+)$', line.strip())
            if m:
                feats[m.group(1)] = (m.group(3), m.group(5))
        eq(feats['y1'], ('4fdd09e9', '0000612e'), '%s: y1 bits' % tag)
        eq(feats['y2'], ('4fc009e1', '0000612c'), '%s: y2 bits' % tag)
        # A6: hop limit in every logged message
        for a in A:
            eq(a['lgfirst'][14:16], '3f', '%s: %s hop at FORWARD' % (tag, a['name']))
    # every constant the document quotes must be in the log it claims to
    # describe (this is what makes a wrong digit in the text a failure)
    for c in ('ff72', '82af', '1f91', '426f', '224f', 'f768', '7e17', '1af9',
              'a375', '4057', '9612', '9611', '55d2', '82ae', '1f90', '426e',
              '4fdd09e9', '4fc009e1', '0000612e', '0000612c'):
        eq(c in text, True, 'the document quotes %s' % c)
        eq(c in open(os.path.join(ROOT, LOGS[0]), errors='replace').read(),
           True, '%s appears in rep1' % c)
    # the document's own count words
    eq(text.count('Доставлено 48 датаграмм, ошибок 11'), 1,
       'the document states 48 / 11')
    eq(text.count('17 из 17'), 1, 'the document states 17 of 17 predictions')


def main():
    doc = DOC
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if args:
        doc = args[0]
    audit(doc if os.path.isabs(doc) else os.path.join(ROOT, doc))
    print('checks=%d failures=%d' % (N, len(FAIL)))
    for what, got, want in FAIL[:20]:
        print('FAIL %s: got %r want %r' % (what, got, want))
    return 1 if FAIL else 0


MUT = [
    ('field_swap', ('| 1 | `c_b` | 574/574/238 | 520/520/184 | `82af`/`82af`/`1f91` |',
                    '| 1 | `c_b` | 574/574/238 | 520/520/184 | `82af`/`82af`/`1f92` |')),
    ('count_words', ('Доставлено 48 датаграмм, ошибок 11', 'Доставлено 47 датаграмм, ошибок 11')),
    ('pred_words', ('17 из 17', '16 из 17')),
    ('delta_words', ('`20c6 = ~c16sub(0xdead, ff73)`', '`20c7 = ~c16sub(0xdead, ff73)`')),
    ('y2bits', ('| `y2` | `4fc009e1` | **снят** | `0000612c` |', '| `y2` | `4fc009e1` | **снят** | `0000612a` |')),
]


def mutate():
    import subprocess
    import tempfile
    text = open(os.path.join(ROOT, DOC)).read()
    for name, (old, new) in MUT:
        if text.count(old) != 1:
            print('%s: NOT UNIQUE (%d)' % (name, text.count(old)))
            continue
        t = text.replace(old, new)
        fd, p = tempfile.mkstemp(suffix='.md')
        os.close(fd)
        open(p, 'w').write(t)
        r = subprocess.run([sys.executable, os.path.abspath(__file__), p],
                           capture_output=True, text=True)
        os.unlink(p)
        line = (r.stdout.strip().splitlines() or [''])[0]
        print('%-12s %s' % (name, 'caught: ' + line if r.returncode
                            else 'NOT CAUGHT (' + line + ')'))


if __name__ == '__main__':
    if '--mutate' in sys.argv:
        mutate()
    sys.exit(main())
