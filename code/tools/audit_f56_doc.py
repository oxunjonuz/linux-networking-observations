#!/usr/bin/env python3
"""audit_f56_doc.py [--subst]

Reads findings/F56-tag-or-word/SUMMARY.md and re-derives, from
logs/f56_rep1.log + logs/f56_rep2.log, the cells of its four tables.  A number in
the document that the log does not carry is a defect of the document.

--subst performs three single-cell substitutions in a copy of the document and
requires the audit to notice each one.
"""
import re
import subprocess
import sys

DOC = 'findings/F56-tag-or-word/SUMMARY.md'
LOGS = ['logs/f56_rep1.log', 'logs/f56_rep2.log']
N = 0
BAD = []


def ck(cond, msg):
    global N
    N += 1
    if not cond:
        BAD.append(msg)


def parse(path):
    txt = open(path, 'rb').read().decode('utf-8', 'replace')
    A, C, B, F, T, M = {}, {}, {}, {}, {}, {}
    cur = None
    for ln in txt.splitlines():
        if not ln.startswith('F578 '):
            continue
        p = ln.split('|')
        h = p[0][5:]
        d = dict((t.split('=', 1) for t in p[1:] if '=' in t))
        if h == 'A':
            cur = (d['mode'], d['arm'])
            A[cur] = d
            M[cur] = {}
        elif h == 'C':
            C[(cur[0], d['arm'])] = d
        elif h == 'B':
            B[(cur[0], d['arm'])] = d
        elif h == 'F':
            F[(cur[0], d['arm'])] = d
        elif h == 'T':
            T[(cur[0], d['arm'])] = d
        elif h == 'M':
            for t in p[2:]:
                if t.startswith('m') and '=' in t:
                    f = t.split('=', 1)[1].split(':')
                    M[cur][f[0]] = {'indev': int(f[1]), 'outdev': int(f[2]),
                                    'llen': int(f[7]), 'l': f[8],
                                    'vp': int(f[9]), 'vproto': int(f[10], 16),
                                    'vtci': int(f[11], 16), 'plen': int(f[12])}
    return A, C, B, F, T, M


def tap_flen(T, key, i=0):
    raw = T.get(key, {}).get('t%d' % i)
    return None if raw is None else int(raw.split(':', 15)[1])


def tap_hex(T, key, i=0):
    raw = T.get(key, {}).get('t%d' % i)
    return None if raw is None else raw.split(':', 15)[3]


def rows(doc, title):
    """the markdown rows of the table that follows a given '## <title>' line"""
    out = []
    seen = False
    started = False
    for ln in doc.splitlines():
        if ln.startswith('## ') and title in ln:
            seen = True
            continue
        if seen:
            if ln.startswith('| `'):
                started = True
                out.append([c.strip() for c in ln.strip('|').split('|')])
            elif started and not ln.startswith('|'):
                break
    return out


def audit(doc, logs):
    data = [parse(p) for p in logs]
    A1, C1, B1, F1, T1, M1 = data[0]
    T3 = rows(doc, 'T3')
    T1r = rows(doc, 'T1')
    T2 = rows(doc, 'T2')
    T4 = rows(doc, 'T4')
    ck(len(T1r) == 16, 'T1 has %d rows, want 16' % len(T1r))
    ck(len(T2) == 16, 'T2 has %d rows, want 16' % len(T2))
    ck(len(T3) == 14, 'T3 has %d rows, want 14' % len(T3))
    ck(len(T4) == 4, 'T4 has %d rows, want 4' % len(T4))
    for r in T1r:
        name = r[0].strip('`')
        k = ('0', name)
        ck(k in A1, 'T1 arm %s is not in the log' % name)
        if k not in A1:
            continue
        ck(r[4] == C1[k].get('ch0', '?'),
           'T1 %s: ch %s, log %s' % (name, r[4], C1[k].get('ch0')))
        ck(r[5] == str(tap_flen(T1, k)), 'T1 %s: tap0 %s, log %s'
           % (name, r[5], tap_flen(T1, k)))
        far = '-'
        for key in ('x0.102', 'x0.103', 'x0.104'):
            if F1[k].get(key, '0:0:0') != '0:0:0':
                far = '%s %s' % (key, F1[k][key])
        ck(r[10] == far, 'T1 %s: far end %r, log %r' % (name, r[10], far))
        ck(r[11] == B1[k].get('u6n', '?'), 'T1 %s: u6n %s, log %s'
           % (name, r[11], B1[k].get('u6n')))
    for r in T2:
        name = r[0].strip('`')
        k = ('0', name)
        if k not in A1:
            continue
        pre = {'A': 'p2', 'B': 'p3', 'E': 'p4'}[A1[k]['fk']]
        e = M1[k].get(pre, {})
        llen = e.get('llen', 0)
        ck(r[3].startswith('L2 %d B' % llen), 'T2 %s: egress L2 %r, log %d'
           % (name, r[3], llen))
        # the last 12 hex characters of the L2 are the tag
        if llen >= 18:
            ck(r[3].endswith(e['l'][-12:]), 'T2 %s: L2 bytes %r, log ...%s'
               % (name, r[3][-12:], e['l'][-12:]))
        p1 = M1[k].get('p5', {})
        want = ('%04x:%04x' % (p1.get('vproto', 0), p1.get('vtci', 0))
                if p1.get('vp') else 'no word')
        ck(r[4] == want, 'T2 %s: p1 nest %s, log %s' % (name, r[4], want))
        ck(r[5] == '%d B' % tap_flen(T1, k), 'T2 %s: wire %s, log %d B'
           % (name, r[5], tap_flen(T1, k)))
    for r in T3:
        name = r[0].strip('`')
        k = ('1', name)
        ck(k in A1, 'T3 arm %s is not in the log' % name)
        if k not in A1:
            continue
        doors = ' '.join('%s=%s' % (d, C1[k].get(d, '?'))
                         for d in ('bv', 'bf', 'bl', 'gv', 'n1', 'nz', 'q1',
                                   'e2', 'p1', 'ry'))
        ck(r[2] == doors, 'T3 %s: doors %r, log %r' % (name, r[2], doors))
        ck(r[3] == C1[k].get('ch0', '?'), 'T3 %s: ch %s, log %s'
           % (name, r[3], C1[k].get('ch0')))
        ck(r[4] == '%d B' % tap_flen(T1, k), 'T3 %s: wire %s, log %d B'
           % (name, r[4], tap_flen(T1, k)))
        ck(r[6] == F1[k].get('y0.102', '?'), 'T3 %s: y0.102 %s, log %s'
           % (name, r[6], F1[k].get('y0.102')))
        ck(r[7] == B1[k].get('u6n', '?'), 'T3 %s: u6n %s, log %s'
           % (name, r[7], B1[k].get('u6n')))
    for r in T4:
        name = r[0].strip('`')
        k = ('1', name)
        ck(k in A1, 'T4 arm %s is not in the log' % name)
        if k not in A1:
            continue
        ck(r[4] == C1[k].get('ch0', '?'), 'T4 %s: counter %s, log %s'
           % (name, r[4], C1[k].get('ch0')))
        hx = tap_hex(T1, k)
        ck(r[5] == hx[24:36], 'T4 %s: wire 12..17 %s, log %s'
           % (name, r[5], hx[24:36]))
        far = 'y0.102 %s, other %s' % (F1[k].get('y0.102', '?').split(':')[0],
                                       F1[k].get('y0', '?').split(':')[2])
        ck(r[6] == far, 'T4 %s: far end %r, log %r' % (name, r[6], far))
    # both boots must agree on every derived cell
    A2, C2, B2, F2, T2d, M2 = data[1]
    for k in A1:
        if k not in A2:
            continue
        for d in ('ch0', 'bf', 'bv'):
            if d in C1[k]:
                ck(C1[k][d] == C2[k].get(d),
                   'boots disagree on %s/%s: %s vs %s'
                   % (k, d, C1[k][d], C2[k].get(d)))
        for d in ('i6in_d', 'disc_d', 'deliv_d', 'u6n'):
            ck(B1[k].get(d) == B2[k].get(d),
               'boots disagree on %s/%s' % (k, d))


def main():
    doc = open(DOC, encoding='utf-8').read()
    audit(doc, LOGS)
    print('audit: checks=%d failures=%d' % (N, len(BAD)))
    for b in BAD[:40]:
        print('FAIL  ' + b)
    if '--subst' in sys.argv:
        subs = [
            ('| `w14_e2s` | A | 1 | set@e2:14:2:- | 1 | 84 |',
             '| `w14_e2s` | A | 1 | set@e2:14:2:- | 1 | 80 |'),
            ('| `ctl_x` | C | bv=1 bf=2', '| `ctl_x` | C | bv=1 bf=1'),
            ('| `w16_ry` | ry | 16 | the frame\'s 12..13 (vlan_hlen = 4) | 1 | 86dd60000000 |',
             '| `w16_ry` | ry | 16 | the frame\'s 12..13 (vlan_hlen = 4) | 1 | 080660000000 |'),
        ]
        caught = 0
        for old, new in subs:
            if old not in doc:
                print('SUBST-MISS  pattern not in the document: %r' % old[:40])
                continue
            open('tmp/f56_doc_subst.md', 'w', encoding='utf-8').write(
                doc.replace(old, new, 1))
            out = subprocess.run([sys.executable, __file__,
                                  'tmp/f56_doc_subst.md'],
                                 capture_output=True, text=True)
            if out.returncode != 0:
                caught += 1
            else:
                print('SUBST-MISS  not caught: %r' % old[:40])
        print('substitutions caught: %d/%d' % (caught, len(subs)))
    return 1 if BAD else 0


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1].endswith('.md'):
        # a substituted copy: audit it and report
        d = open(sys.argv[1], encoding='utf-8').read()
        audit(d, LOGS)
        print('audit(copy): checks=%d failures=%d' % (N, len(BAD)))
        sys.exit(1 if BAD else 0)
    sys.exit(main())
