#!/usr/bin/env python3
"""audit_f58_doc.py [--file SUMMARY.md]

Checks that every measurement written into F58's SUMMARY.md still agrees with
the frozen logs, and that every sha256 written into VERIFY_REPORT.md still
agrees with the file it names.  Reading, not trusting: the tables are parsed out
of the markdown, and each row's verdict is compared with the arm's own log line.

Usage:
  python3 tools/audit_f58_doc.py                    # the real document
  python3 tools/audit_f58_doc.py --file COPY.md     # a copy (selftest)
  python3 tools/audit_f58_doc.py --mutate yes       # mutate one cell first

Exit 0 iff every row agrees.
"""
import hashlib
import os
import re
import sys

ROOT = '/work/kernel-sec'
DOC = os.path.join(ROOT, 'findings/F58-write-guards/SUMMARY.md')
REP = os.path.join(ROOT, 'findings/F58-write-guards/VERIFY_REPORT.md')
LOG = os.path.join(ROOT, 'logs/f58_rep1.log')
LOG2 = os.path.join(ROOT, 'logs/f58_rep2.log')

checks = 0
bad = 0


def ck(cond, label, extra=''):
    global checks, bad
    checks += 1
    if not cond:
        bad += 1
        print('BAD %s %s' % (label, extra))


def arms(path):
    out = {}
    for line in open(path, errors='replace'):
        if line.startswith('F580 ARM|'):
            d = dict(kv.split('=', 1) for kv in line.strip().split('|')[1:])
            out[d['name']] = d
    return out


def segment(text, start, end):
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


def rows(seg, first='| `'):
    out = []
    for ln in seg.splitlines():
        if ln.startswith(first):
            out.append([c.strip() for c in ln.strip().strip('|').split('|')])
    return out


def verdict(cell):
    v = cell.replace('*', '').strip()
    if 'yes by the guard' in v:
        return 'no'          # accepted, but the store never happened
    if v.startswith('yes'):
        return 'yes'
    if v == 'no':
        return 'no'
    if v == '-75':
        return 'enc'
    if v == '1':
        return 'yes'
    if v == '0':
        return 'no'
    if v.startswith('yes by the guard'):
        return 'yes'
    return '?'


def main():
    path = DOC
    mutate = None
    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == '--file':
            path = args.pop(0)
        elif a == '--mutate':
            mutate = args.pop(0)
    text = open(path, errors='replace').read()
    A = arms(LOG)
    A2 = arms(LOG2)
    ck(len(A) == 55, 'log|arms', str(len(A)))
    ck(len(A2) == 55, 'log2|arms', str(len(A2)))

    if mutate == 'yes':
        text = text.replace('| **yes** |', '| no |', 1)
    elif mutate == 'nl':
        text = text.replace('| 1 | **none** — `vlan_proto = 8100`', '| 0 | **none** — `vlan_proto = 8100`', 1)
    elif mutate == 'name':
        text = text.replace('`t_12_4v`', '`t_12_5v`', 1)

    # ---- 1. the layer-3 grid (§1)
    seg = segment(text, 'Nine\ncells at `g6`:', 'One accepted cell out of nine.')
    for r in rows(seg):
        name = r[0].strip('`')
        ck(name in A, 's1|arm_exists|%s' % name)
        if name not in A:
            continue
        ck(verdict(r[2]) == ('yes' if A[name]['nl'] == '1' else 'no'),
           's1|verdict|%s' % name, '%s vs nl=%s' % (r[2], A[name]['nl']))
    g6 = [n for n in A if n.startswith('g_')]
    ck(len(g6) == 9, 's1|count', str(len(g6)))
    ck(sum(1 for n in g6 if A[n]['nl'] == '1') == 1, 's1|one_of_nine')

    # ---- 2. the tag grid (§2)
    seg = segment(text, '15 cells at `n1`', 'Read the `nl` column as a set:')
    for r in rows(seg):
        name = r[0].strip('`')
        ck(name in A, 's2|arm_exists|%s' % name)
        if name not in A:
            continue
        ck(verdict(r[2]) == ('yes' if A[name]['nl'] == '1' else 'no'),
           's2|verdict|%s' % name, '%s vs nl=%s' % (r[2], A[name]['nl']))
        # the receiving device, where the table names one
        dev = r[4].replace('**', '').strip()
        if dev.startswith('`x1.'):
            ck(A[name]['pindev'].split(':')[-1] == dev.strip('`'),
               's2|dev|%s' % name, '%s vs %s' % (A[name]['pindev'], dev))
        elif dev.startswith('**none**'):
            ck(A[name]['pnl'] == '0' and A[name]['oth'] == '1',
               's2|dead|%s' % name, 'pnl=%s oth=%s' % (A[name]['pnl'], A[name]['oth']))
        elif dev.startswith('dead'):
            ck(A[name]['u6n'] == '0' and A[name]['rcv'] == '1',
               's2|dead_ip|%s' % name)
    tag = [n for n in A if n.startswith('t_')]
    ck(len(tag) == 15, 's2|count', str(len(tag)))

    # ---- 3. the @nh grid (§3)
    seg = segment(text, '16 cells at `g6` on the plain frame:', 'Two observations that only exist')
    for r in rows(seg):
        name = r[0].strip('`')
        ck(name in A, 's3|arm_exists|%s' % name)
        if name not in A:
            continue
        v = verdict(r[2])
        got = 'enc' if A[name]['rc'] == '-75' else ('yes' if A[name]['nl'] == '1' else 'no')
        ck(v == got, 's3|verdict|%s' % name, '%s vs %s (rc=%s nl=%s)'
           % (v, got, A[name]['rc'], A[name]['nl']))
    nh = [n for n in A if n.startswith('n_')]
    ck(len(nh) == 16, 's3|count', str(len(nh)))

    # ---- 4. the @th grid (§4)
    seg = segment(text, '| cell | frame | `@th,off,len`', 'The protected thing is not')
    for r in rows(seg):
        name = r[0].strip('`')
        ck(name in A, 's4|arm_exists|%s' % name)
        if name not in A:
            continue
        ck(verdict(r[3]) == ('yes' if A[name]['nl'] == '1' else 'no'),
           's4|verdict|%s' % name, '%s vs nl=%s' % (r[3], A[name]['nl']))
    th = [n for n in A if n.startswith('u_') or n.startswith('h_')]
    ck(len(th) == 10, 's4|count', str(len(th)))

    # ---- 5. the claims that name a counter
    ck(A['t_18_2']['hdrerr'] == '1' and A['t_18_2']['u6n'] == '0',
       'claim|t_18_2_hdrerr')
    ck(A['t_24_4']['ukproto'] == '1', 'claim|t_24_4_ukproto')
    ck(A['t_12_4']['oth'] == '1' and A['t_12_4']['u6n'] == '0',
       'claim|t_12_4_otherhost')
    ck(A['u_60_4']['nl'] == '0' and A['u_60_4']['ch'] == '1'
       and A['u_60_4']['u6n'] == '1', 'claim|u_60_4')
    ck(A['n_2_2']['u6n'] == '1', 'claim|n_2_2_delivered')
    ck(A['n_8_16']['udperr'] == '1', 'claim|n_8_16_udperr')
    ck(A['n_24_16']['noroutes'] == '1', 'claim|n_24_16_noroutes')
    ck(A['n_8_32r']['nl'] == '1' and A['n_8_32i']['rc'] == '-75',
       'claim|the_two_lanes')
    # the 32-byte store really writes 32 bytes ending on the header's last byte
    p = bytes.fromhex(A['n_8_32r']['p'])
    pre = bytes.fromhex(A['c_p_g6']['p'])
    ck(p[8:40] == pre[0:32] and p[0:8] == pre[0:8],
       'claim|n_8_32r_footprint', '%s' % p.hex()[:48])
    # the word cells change no frame byte
    hw = bytes.fromhex(A['c_t_n1']['hw'])
    for n in ('t_12_2', 't_12_4', 't_12_4v', 't_14_2'):
        ck(bytes.fromhex(A[n]['hw']) == hw and bytes.fromhex(A[n]['p'])
           == bytes.fromhex(A['c_t_n1']['p']), 'claim|word_no_byte|%s' % n)
    # two boots agree on these arms
    for n in ('t_12_4v', 't_14_2', 'n_8_32r', 'u_60_4'):
        ck(A[n]['p'] == A2[n]['p'] and A[n]['pindev'] == A2[n]['pindev'],
           'claim|det|%s' % n)

    # ---- 6. the sha256 lines of VERIFY_REPORT.md
    rep = open(REP, errors='replace').read()
    named = {
        'bzImage': os.path.join(ROOT, 'src/linux-7.3.4-T563/arch/x86/boot/bzImage'),
        'initrd': os.path.join(ROOT, 'vm/initrd580/full.cpio.gz'),
        'differ': os.path.join(ROOT, 'vm/build/differ580'),
    }
    for label, p in named.items():
        h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        ck(h in rep, 'report|sha|%s' % label, h[:16])

    # ---- 7. the arm counts stated in the report
    ck('55 arms' in text or '55 arms' in rep, 'report|arms55')
    ck('5703' in rep, 'report|5703')
    ck('30/30' in rep, 'report|selftest')
    ck('NOT SENT' in open(os.path.join(ROOT, 'findings/F58-write-guards/LETTER_SECTION_F58.txt')).read(),
       'letter|status')

    print('audit: checks=%d bad=%d' % (checks, bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
