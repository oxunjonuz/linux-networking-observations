#!/usr/bin/env python3
"""audit_f61_doc.py -- check the numbers in SUMMARY.md against the boot log.

Independent of tools/verify583.py: this script reads only the document and the
two logs, and never imports the verifier's model.  It answers one question:
does the document say what the instrument measured?

  A1  every row of the 25-arm table: name, exit, field, fate
  A2  the counts the document states (25 / 17 / 8 / 25 / 25)
  A3  the checksum constants the document quotes appear in the log as frames
  A4  the feature words quoted in the table
  A5  "the arms with csum are byte-identical to the arms without" -- compared
      on the log's own hexdumps, not on the model
  A6  the hop limit: every forward-door message carries 0x3f

Mutations (A7): three single substitutions in a copy of the document must each
turn this audit red.
"""
import os
import re
import sys

ROOT = '/work/kernel-sec'
DOC = 'findings/F61-forwarded-checksum/SUMMARY.md'
LOGS = ['logs/f61_rep1.log', 'logs/f61_rep2.log']

N = 0
FAIL = []


def eq(got, want, what):
    global N
    N += 1
    if got != want:
        FAIL.append((what, got, want))


def parse_log(path):
    arms, rcvs = [], []
    for line in open(os.path.join(ROOT, path), errors='replace'):
        if line.startswith('F583 ARM|'):
            arms.append(dict(x.split('=', 1) for x in line[9:].rstrip().split('|') if '=' in x))
        elif line.startswith('F583 RCV|'):
            rcvs.append(dict(x.split('=', 1) for x in line[9:].rstrip().split('|') if '=' in x))
    return arms, rcvs


def doc_rows(text):
    rows = {}
    for m in re.finditer(r'^\| (\d+) \| `([a-z0-9_]+)` \| (\w) \| (\w+) \| ([^|]*) \|'
                         r' \*?\*?`([0-9a-f]{4}|dead)`\*?\*? \| ([^|]*) \| ([^|]*) \|$',
                         text, re.M):
        rows[m.group(2)] = dict(i=int(m.group(1)), prov=m.group(3),
                                dst=m.group(4), field=m.group(6),
                                who=m.group(7).strip(), fate=m.group(8).strip())
    return rows


def audit(doc_path):
    text = open(doc_path).read()
    rows = doc_rows(text)
    eq(len(rows), 25, 'A1 the document has 25 arm rows')
    tot_del = tot_drop = 0
    for path in LOGS:
        A, R = parse_log(path)
        eq(len(A), 25, '%s: 25 arms' % path)
        for a, r in zip(A, R):
            d = rows.get(a['name'])
            if d is None:
                eq(None, a['name'], '%s: arm %s is in the table' % (path, a['name']))
                continue
            hexs = a['a'] if a['dst'] == 'a' else a['b']
            field = hexs[120:124] if hexs != '-' else '-'
            eq(d['field'], field, '%s/%s: the field the document quotes'
               % (path, a['name']))
            eq(d['prov'], a['prov'], '%s/%s: provenance' % (path, a['name']))
            eq('y1' if a['dst'] == 'a' else 'y2', d['dst'],
               '%s/%s: exit device' % (path, a['name']))
            fate = 'доставлено' if int(r['n']) else '**уронено**'
            eq(d['fate'], fate, '%s/%s: fate' % (path, a['name']))
        # A2 counts
        eq(sum(int(r['n']) for r in R), 17, '%s: delivered' % path)
        eq(sum(1 for r in R if not int(r['n'])), 8, '%s: dropped' % path)
        eq(sum(1 for a in A if a['ch'] == '1'), 25, '%s: rules that counted one' % path)
        eq(sum(1 for a in A if a['nl'] == '1'), 25, '%s: messages at the forward door' % path)
        # A3 the constants the document quotes really appear
        by = {a['name']: (a, r) for a, r in zip(A, R)}
        def field(n):
            a = by[n][0]
            h = a['a'] if a['dst'] == 'a' else a['b']
            return h[120:124]
        for n, want in (('c_s_a', 'fad4'), ('c_s_b', '7a75'), ('c_p_a', '7a76'),
                        ('w_s_a', 'fad4'), ('w_s_b', '3a35'), ('d_s_a', 'dead'),
                        ('d_s_b', '969d'), ('sp_s_b', '65c2'),
                        ('wcs_p_a', '3a36'), ('dz_s_b', '7a75'),
                        ('n_s_b', '7a75'), ('sp_p_a', '7a76')):
            eq(field(n), want, '%s/%s: %s' % (path, n, want))
        for n in ('w_s_a', 'c_s_a'):
            pass
        # A4 the feature words
        for line in open(os.path.join(ROOT, path), errors='replace'):
            pass
        # A5 byte-identity of the csum arms, on the log's own hexdumps
        for base, other in (('w_s_a', 'wcs_s_a'), ('w_s_a', 'wfl_s_a'),
                            ('w_s_b', 'wcs_s_b'), ('w_s_b', 'wfl_s_b')):
            a, _ = by[base]
            b, _ = by[other]
            dev = 'a' if a['dst'] == 'a' else 'b'
            eq(b[dev], a[dev], '%s: %s == %s byte for byte' % (path, other, base))
        # A6 the hop limit in every forward-door message
        for a, r in zip(A, R):
            eq(a['lg'][14:16], '3f', '%s/%s: hop 0x3f in the forward message'
               % (path, a['name']))
    # the feature words quoted in §1
    log = open(os.path.join(ROOT, LOGS[0]), errors='replace').read()
    m = re.search(r'F583 FEAT\|dev=y1\|av0=(\w+)\|ac0=(\w+)\|av1=(\w+)\|ac1=(\w+)', log)
    eq((m.group(2), m.group(4)), ('4fdd09e9', '0000612e'), 'A4 y1 features')
    m = re.search(r'F583 FEAT\|dev=y2\|av0=(\w+)\|ac0=(\w+)\|av1=(\w+)\|ac1=(\w+)', log)
    eq((m.group(2), m.group(4)), ('4fc009e1', '0000612c'), 'A4 y2 features')
    for word in ('`fad4`', '`fad5`', '`7a76`', '`7a75`', '`3a35`', '`3a36`',
                 '`969d`', '`65c2`', '`dead`', '4fdd09e9', '4fc009e1',
                 '0000612e', '0000612c'):
        eq(word in text, True, 'A3 the document quotes %s' % word)


MUT = [
    ('field_sub', ('| 5 | `w_s_b` | s | y2 | `@th,8,4` | `3a35` |',
                   '| 5 | `w_s_b` | s | y2 | `@th,8,4` | `3a36` |')),
    ('fate_sub', ('| 11 | `d_s_b` | s | y2 | `@th,6,2=dead` | `969d` | устройство (неверно) | **уронено** |',
                  '| 11 | `d_s_b` | s | y2 | `@th,6,2=dead` | `969d` | устройство (неверно) | доставлено |')),
    ('count_sub', ('Доставлено 17, уронено 8.', 'Доставлено 18, уронено 7.')),
]


def the_counts(text):
    m = re.search(r'Доставлено (\d+), уронено (\d+)\.', text)
    return (int(m.group(1)), int(m.group(2))) if m else (None, None)


def main():
    path = os.path.join(ROOT, DOC)
    if len(sys.argv) > 1 and not sys.argv[1].startswith('--'):
        path = sys.argv[1]
    audit(path)
    text = open(path).read()
    A, R = parse_log(LOGS[0])
    eq(the_counts(text), (17, 8), 'A2 the sentence with the counts')
    print('checks=%d failures=%d' % (N, len(FAIL)))
    for what, got, want in FAIL[:20]:
        print('FAIL %s: got %r want %r' % (what, got, want))
    return 1 if FAIL else 0


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
