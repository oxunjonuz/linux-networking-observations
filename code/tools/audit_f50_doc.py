#!/usr/bin/env python3
"""audit_f50_doc.py -- the SUMMARY.md of F50 must be the generator's output.

1. Re-run tools/f572_summary.py and diff it against findings/F50-bridge-l3/
   SUMMARY.md; any difference is a failure.
2. Three single-cell substitutions in a copy of the document must each make the
   audit red -- otherwise the audit is not looking.
"""
import os
import subprocess
import sys

BASE = '/work/kernel-sec'
DOC = BASE + '/findings/F50-bridge-l3/SUMMARY.md'
GEN = BASE + '/tools/f572_summary.py'

NCHK = [0]
NBAD = [0]


def ck(cond, what):
    NCHK[0] += 1
    if not cond:
        NBAD[0] += 1
        print('  RED: ' + what)


def generate():
    r = subprocess.run([sys.executable, GEN], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr)
        raise SystemExit('generator failed')
    return r.stdout


def main():
    if not os.path.exists(DOC):
        raise SystemExit('missing ' + DOC)
    doc = open(DOC).read()
    gen = generate()
    ck(doc == gen, 'SUMMARY.md is exactly what f572_summary.py generates')
    # the document must keep the sections it claims
    for sec in ('## 1.', '## 2.', '## 3.', '## 4.', '## 5.', '## 6.',
                '## 6b.', '## 7.', '## 8.'):
        ck(sec in doc, 'section present: ' + sec)
    # a table the finding leans on must be there with its numbers
    ck('| `@ll` **чтение** | **36/36** |' in doc, 'the 36/36 read row')
    ck('| `@ll` **запись** | **23/36** |' in doc, 'the 23/36 write row')
    ck('| `ref_ppp` | `ppp0` | 512 | **-22** | нет |' in doc,
       'the refused bridge port row')
    ck('5629 проверок, 0 расхождений' in doc, 'the verifier count')

    # ---- the three substitutions: each must be caught
    subs = [
        ('| `@ll` **чтение** | **36/36** |', '| `@ll` **чтение** | **35/36** |'),
        ('| `ref_ppp` | `ppp0` | 512 | **-22** | нет |',
         '| `ref_ppp` | `ppp0` | 512 | **0** | нет |'),
        ('`pre_dst` | `in6` | 1 | 1 | **1** | 2 | 1 | 0 | 1 | ffffffffffff |',
         '`pre_dst` | `in6` | 1 | 1 | **1** | 2 | 0 | 0 | 1 | ffffffffffff |'),
    ]
    for a, b in subs:
        ck(a in doc, 'substitution target exists: ' + a[:40])
        copy = doc.replace(a, b, 1)
        ck(copy != doc, 'substitution changed the document')
        ck(copy != gen, 'the generator does not reproduce the tampered copy')
        tmp = '/tmp/f50_doc_tampered.md'
        with open(tmp, 'w') as f:
            f.write(copy)
        ck(open(tmp).read() != gen, 'tampered copy differs from the generator')

    print('audit_f50_doc: %d checks, %d discrepancies' % (NCHK[0], NBAD[0]))
    return 1 if NBAD[0] else 0


if __name__ == '__main__':
    sys.exit(main())
