#!/usr/bin/env python3
"""verify595_selftest.py -- can verify595.py go red, and only when it should?

Two kinds of single faults:

  * data mutations: one textual change in a copy of a real log;
  * model mutations: one textual change in a copy of the verifier itself.

Every mutation must make the verifier exit 1 **without** a traceback (a crash
is not a red check).  A `noop` copy must stay green, otherwise the baseline
is wrong and nothing below means anything.
"""
import os
import subprocess
import sys
import tempfile

ROOT = '/work/kernel-sec'
LOG = ROOT + '/logs/f73_rep1.log'
VER = ROOT + '/tools/verify595.py'


def run(script, logs):
    r = subprocess.run([sys.executable, script] + logs,
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def one(name, text, old, new, count=1):
    if old not in text:
        return None
    return (name, text.replace(old, new, count))


def main():
    base_text = open(LOG, errors='replace').read()
    rc, out = run(VER, [LOG])
    print('baseline rc=%d %s' % (rc, out.strip().split('\n')[0]))
    if rc != 0:
        print('BASELINE RED -- nothing below is meaningful')
        return 1

    data = [
        one('gate_ts_5056', base_text, 'GATE|i=00|att=0|n=1|ts=5056',
            'GATE|i=00|att=0|n=1|ts=5057'),
        one('gate_ts_9152', base_text, 'GATE|i=02|att=0|n=1|ts=9152',
            'GATE|i=02|att=0|n=1|ts=5056'),
        one('gate_end', base_text, 'GATE|i=02|att=0|n=1|ts=9152|dlen=512|'
            'len=512|end=384', 'GATE|i=02|att=0|n=1|ts=9152|dlen=512|'
            'len=512|end=704'),
        one('gate_dlen', base_text, 'GATE|i=02|att=0|n=1|ts=9152|dlen=512',
            'GATE|i=02|att=0|n=1|ts=9152|dlen=0'),
        one('childs_align', base_text, 'pl=512|zc=1|al=2|sp=0|sent=1',
            'pl=512|zc=1|al=1|sp=0|sent=1'),
        one('childs_splice', base_text, 'pl=512|zc=0|al=2|sp=1|sent=1',
            'pl=512|zc=0|al=2|sp=0|sent=1'),
        one('probe_mask', base_text, 'PROBE|ok=1|mask=1fff',
            'PROBE|ok=1|mask=fff'),
        one('def_offset', base_text, 'len=+112(%di)', 'len=+108(%di)'),
        one('clone_count', base_text, 'enq=6|clone=5', 'enq=6|clone=4'),
        one('clone_caller', base_text, 'caller=0xffffffff829134c4',
            'caller=0xffffffff829134c5'),
        one('clone_ring', base_text, 'GATE|i=00|att=0|n=6|ts=1280,1280',
            'GATE|i=00|att=0|n=5|ts=1280,1280'),
        one('cloned_bit', base_text,
            'GATE|i=00|att=0|n=6|ts=1280,1280,1280,1280,1280,1280|dlen=0,0,0,0,0,0|'
            'len=512,512,512,512,512,512|end=704,704,704,704,704,704|'
            'fl=0,1,1,1,1,1',
            'GATE|i=00|att=0|n=6|ts=1280,1280,1280,1280,1280,1280|dlen=0,0,0,0,0,0|'
            'len=512,512,512,512,512,512|end=704,704,704,704,704,704|'
            'fl=0,0,0,0,0,0'),
        one('splice_probe', base_text, 'enq=1|clone=0|ubuf=0|zc=0|zf=0|sp=0',
            'enq=1|clone=0|ubuf=0|zc=0|zf=0|sp=1'),
        one('rmem', base_text, 'WAIT|port=5000|want=0|rmem=5056',
            'WAIT|port=5000|want=0|rmem=5057'),
        one('tx_ts', base_text, 'TX|i=02|att=0|n=4|ts=960,9152',
            'TX|i=02|att=0|n=4|ts=960,5056'),
        one('mark_lost', base_text, 'mark=1|ncl=5', 'mark=0|ncl=5'),
        one('rule_column', base_text, 'name=g512_a36n|sp=0|rule=1',
            'name=g512_a36n|sp=0|rule=0'),
        one('nfl_line', base_text, 'F595 NFL|i=03|att=0|skipped=1\n', '\n'),
        one('childf_sg', base_text, 'CHILDF|dev=x1|av0=4fdd49e9|ac0=4fdd09e9',
            'CHILDF|dev=x1|av0=4fdd49e9|ac0=4fdd09e8'),
        one('fwd_ts', base_text, 'FWD|i=02|att=0|n=2|ts=960,9152',
            'FWD|i=02|att=0|n=2|ts=960,960'),
    ]
    data = [m for m in data if m]

    models = []
    code = open(VER).read()
    for name, old, new in (
            ('page_up', 'return (x + 4095) & ~4095',
             'return (x + 4094) & ~4094'),
            ('offset_3600', 'return 960 + page_up(A[\'pl\'] + 3600)',
             'return 960 + page_up(A[\'pl\'])'),
            ('clone_five', "5 if (A['n'] == 6 and A['xg'] == 'u') else 0",
             "4 if (A['n'] == 6 and A['xg'] == 'u') else 0"),
            ('end_384', "ck_eq(g['end'][k], 384, tagn + ': gate end of a paged skb')",
             "ck_eq(g['end'][k], 704, tagn + ': gate end of a paged skb')"),
            ('mask', "ck_eq(p.get('mask'), '1fff'", "ck_eq(p.get('mask'), 'fff'"),
            ('caller_plus', "want = set('0x%x' % (x + 5) for x in clone_sites)",
             "want = set('0x%x' % (x + 6) for x in clone_sites)"),
            ('rmem_off', "ck_eq(int(last['rmem']), A['n'] * exp,",
             "ck_eq(int(last['rmem']), A['n'] * exp + 1,"),
            ('f72_al', "ck_eq(al, 0, 'F72: not one command carried an alignment')",
             "ck_eq(al, 1, 'F72: not one command carried an alignment')"),
            ('splice_probe_off', "ck_eq(int(cnt.get('sp', -1)), 0, tagn + ': splice NOT called')",
             "ck_eq(int(cnt.get('sp', -1)), 1, tagn + ': splice NOT called')"),
            ('plen', "ck_eq(g['len'][k], A['pl'], tagn + ': gate len == payload')",
             "ck_eq(g['len'][k], A['pl'] + 1, tagn + ': gate len == payload')"),
    ):
        if old in code:
            models.append((name, code.replace(old, new, 1)))

    bad = 0
    total = 0
    tmpdir = tempfile.mkdtemp(prefix='f73_self_')
    for name, text in data:
        total += 1
        p = os.path.join(tmpdir, name + '.log')
        open(p, 'w').write(text)
        rc, out = run(VER, [p])
        ok = rc == 1 and 'Traceback' not in out
        print('%-16s %s' % (name, 'RED' if ok else 'NOT RED rc=%d' % rc))
        bad += 0 if ok else 1
    for name, text in models:
        total += 1
        p = os.path.join(tmpdir, name + '.py')
        open(p, 'w').write(text)
        # the mutated verifier imports nothing from its own path, but it
        # resolves the tree by absolute path, so it runs from anywhere
        rc, out = run(p, [LOG])
        ok = rc == 1 and 'Traceback' not in out
        print('model:%-10s %s' % (name, 'RED' if ok else 'NOT RED rc=%d' % rc))
        bad += 0 if ok else 1

    # a noop copy must stay green: the mutations above are the only difference
    p = os.path.join(tmpdir, 'noop.log')
    open(p, 'w').write(base_text)
    rc, out = run(VER, [p])
    print('noop            %s' % ('GREEN' if rc == 0 else 'RED rc=%d' % rc))
    bad += 0 if rc == 0 else 1
    total += 1

    print('mutations: %d, not red: %d' % (total, bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
