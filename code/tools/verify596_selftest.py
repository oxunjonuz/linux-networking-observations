#!/usr/bin/env python3
"""verify596_selftest.py -- can verify596.py go red?  And does it crash instead?

Two families, both single-change:

  data  -- one value in a copy of a real log is altered (n0, rmem0, a gate
           charge, an end, a dlen, enq, a TX end, an arm parameter, a PKT
           length, udperr, a message, the slab size, mark, rb0, f0, a WAIT);
           the verifier must exit non-zero and must NOT print a traceback.
  model -- one line of a copy of the verifier itself is altered (the strict
           `>` of the queue check, the condense branch, its threshold, the
           960 base, the page granularity, the small-head size, the 320, the
           request's hh, the reader's buffer); same requirement.

A change that survives is printed as SURVIVED and must be explained in
findings/F74-*/SUMMARY.md as a limit of the arms, not hidden.
"""
import os
import re
import shutil
import subprocess
import sys

ROOT = '/work/kernel-sec'
WORK = ROOT + '/tmp/f74_mut'
VER = ROOT + '/tools/verify596.py'
LOGS = [ROOT + '/logs/f74_rep1.log', ROOT + '/logs/f74_rep2.log']

DATA = [
    ('n0', lambda s: s.replace('|n0=7|', '|n0=8|', 1)),
    ('rmem0', lambda s: s.replace('|rmem0=35392|', '|rmem0=35391|', 1)),
    ('gate_ts', lambda s: s.replace('|ts=5056,5056', '|ts=5056,5057', 1)),
    ('gate_end', lambda s: s.replace('|end=384,384', '|end=704,384', 1)),
    ('gate_dlen', lambda s: s.replace('|dlen=512,512', '|dlen=513,512', 1)),
    ('enq', lambda s: s.replace('|enq=64|', '|enq=63|', 1)),
    ('tx_end', lambda s: re.sub(r'(?m)^(F595 TX\|i=06\|att=0\|.*?)\|end=384,704,',
                                r'\1|end=384,768,', s, count=1)),
    ('arm_rcvbuf', lambda s: s.replace('|rcvbuf=19200|', '|rcvbuf=25600|', 1)),
    ('pkt_uhlen', lambda s: s.replace('|uhlen=520,520', '|uhlen=521,520', 1)),
    ('udperr', lambda s: s.replace('|udperr=57|', '|udperr=56|', 1)),
    ('arm_name', lambda s: s.replace('name=q64_a0_R38', 'name=q64_a0_R39', 1)),
    ('slab', lambda s: s.replace('|obj=704|', '|obj=768|', 1)),
    ('mark', lambda s: s.replace('|mark=1|', '|mark=0|', 1)),
    ('rb0', lambda s: re.sub(r'(?m)^(F595 RCV\|i=00\|att=0\|.*?)\|rb0=38400\|',
                             r'\1|rb0=38399|', s, count=1)),
    ('f0', lambda s: s.replace('|f0=16|', '|f0=17|', 1)),
    ('wait', lambda s: s.replace('|stable=100|ok=1', '|stable=100|ok=0', 1)),
    ('drop_rcv', lambda s: re.sub(r'(?m)^F595 RCV\|i=03\|att=1\|.*\n', '', s, 1)),
    ('drop_eq', lambda s: re.sub(r'(?m)^F595 EQ\|i=04\|att=0\|.*\n', '', s, 1)),
    ('truncate', lambda s: s[:len(s) // 2]),
    ('fail_line', lambda s: s + 'F596 FAIL|setup\n'),
]

MODEL = [
    ('strict_gt', "if rmem + pre > R:", "if rmem + pre >= R:"),
    ('no_condense', "if rmem > half and pl <= 340:",
     "if False and rmem > half and pl <= 340:"),
    ('condense_ge', "if rmem > half and pl <= 340:",
     "if rmem >= half and pl <= 340:"),
    ('base_576', "return end + SKB_DATA_ALIGN_SHINFO + SKB_DATA_ALIGN_SKB + "
     "page_align(pl + off)", "return end + page_align(pl + off)"),
    ('page_4096_off', "    off = (base + 2048 * k) % 4096",
     "    off = (base + 4096 * k) % 4096"),
    ('small_768', "SMALL_HEAD = 704", "SMALL_HEAD = 768"),
    ('shinfo_256', "SKB_DATA_ALIGN_SHINFO = 320", "SKB_DATA_ALIGN_SHINFO = 256"),
    ('hh_43', "    req = pl + 59", "    req = pl + 43"),
    ('reader_unbounded', "ck_eq(arr(rcv.get('dl0', ''))[:1], "
     "[min(A['pl'], 4096)],", "ck_eq(arr(rcv.get('dl0', ''))[:1], "
     "[A['pl']],"),
    ('empty_queue_clause', "            if rmem:\n", "            if True:\n"),
    ('no_second_check', "        if not (rmem + size <= R or rmem == 0):",
     "        if False:"),
]


# A mutation that survives is a place to read, not a verdict: these three
# change a clause that no arm of THIS turn can exercise, and each is named in
# findings/F74-*/SUMMARY.md as a limit of the arms, not hidden.
EXPECT_SURVIVE = {
    'model/condense_ge':
        'no arm brings the queue to exactly R/2 at a condense decision '
        '(F70 pinned that boundary with its own arms, not these)',
    'model/empty_queue_clause':
        'no arm sends a datagram larger than the whole buffer, so the '
        'empty-queue clause is never the reason a datagram is accepted '
        '(F66/F67 pinned it)',
    'model/no_second_check':
        'the second (locked) check never rejects in these arms: the shrunk '
        'charge is always smaller than the size the first check accepted',
}


def run(cmd, env=None):
    e = dict(os.environ)
    e['V596_DEV'] = '1'
    if env:
        e.update(env)
    p = subprocess.run(cmd, capture_output=True, text=True, env=e, timeout=1800)
    return p.returncode, p.stdout, p.stderr


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)
    real = open(LOGS[0], errors='replace').read()
    bad = 0
    total = 0
    survivors = []
    named = []
    for name, fn in DATA:
        total += 1
        body = fn(real)
        if body == real:
            print('MUTATION-NOT-APPLIED data/%s' % name)
            bad += 1
            continue
        path = '%s/data_%s.log' % (WORK, name)
        open(path, 'w').write(body)
        rc, out, err = run(['python3', VER, path])
        ok = rc != 0 and 'Traceback' not in err + out
        print('%-5s data/%-18s rc=%d %s' % ('RED' if ok else 'SURVIVED',
                                            name, rc, out.splitlines()[-1]
                                            if out else ''))
        if not ok:
            bad += 1
            survivors.append('data/' + name)
    src = open(VER, errors='replace').read()
    for name, old, new in MODEL:
        total += 1
        if old not in src:
            print('MUTATION-NOT-APPLIED model/%s' % name)
            bad += 1
            continue
        path = '%s/ver_%s.py' % (WORK, name)
        open(path, 'w').write(src.replace(old, new, 1))
        rc, out, err = run(['python3', path] + LOGS)
        ok = rc != 0 and 'Traceback' not in err + out
        print('%-5s model/%-17s rc=%d %s' % ('RED' if ok else 'SURVIVED',
                                             name, rc, out.splitlines()[-1]
                                             if out else ''))
        if not ok:
            if 'model/' + name in EXPECT_SURVIVE:
                print('NAMED model/%-17s survived: %s'
                      % (name, EXPECT_SURVIVE['model/' + name]))
                named.append('model/' + name)
            else:
                bad += 1
                survivors.append('model/' + name)
    # the noop control: the unmodified verifier on the unmodified logs
    rc, out, err = run(['python3', VER] + LOGS)
    print('noop  rc=%d %s' % (rc, out.splitlines()[-1] if out else ''))
    if rc != 0:
        bad += 1
    total += 1
    print('SELFTEST %d/%d red, %d named survivors, noop green, '
          'unexplained=%r' % (total - bad - len(named), total, len(named),
                              survivors))
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
