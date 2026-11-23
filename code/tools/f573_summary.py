#!/usr/bin/env python3
"""f573_summary.py [log] -- the tables of the F51 report, printed from the log.

Every cell is read out of logs/f51_rep1.log; nothing here is typed by hand, so
audit_f51_doc.py can regenerate the document's tables and compare them.
"""
import sys

LOG = sys.argv[1] if len(sys.argv) > 1 else '/work/kernel-sec/logs/f51_rep1.log'


def kv(s):
    d = {}
    for part in s.split('|')[1:]:
        if '=' in part:
            k, v = part.split('=', 1)
            d[k] = v
    return d


def unhex(s):
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b''


def parse(path):
    A = []
    env = None
    for ln in open(path, 'rb').read().decode('utf8', 'replace').splitlines():
        if ln.startswith('F573 ENV|'):
            env = kv(ln)
        elif ln.startswith('F573 A|'):
            A.append({'A': kv(ln)})
        elif ln.startswith('F573 C|') and A:
            d = {}
            for part in ln.split('|')[1:]:
                if '=' in part:
                    k, v = part.split('=', 1)
                    d[k] = v
            A[-1]['C'] = d
        elif ln.startswith('F573 B|') and A:
            A[-1]['B'] = kv(ln)
        elif ln.startswith('F573 M|') and A:
            A[-1]['M'] = kv(ln)
        elif ln.startswith('F573 T|') and A:
            A[-1]['T'] = kv(ln)
    return A, env


TAPNAME = {'t0': 'x1', 't1': 'y0', 't2': 'z0', 't3': 'br0'}


def taps(a):
    d = {}
    for k, v in a['T'].items():
        f = v.split(':')
        d[TAPNAME.get(k, k)] = (int(f[1]), int(f[2]),
                                unhex(f[3]) if len(f) > 3 else b'')
    return d


def main():
    A, env = parse(LOG)
    by = {a['A']['arm']: a for a in A}
    x0 = bytes.fromhex(env['x0mac'])
    br = bytes.fromhex(env['br0mac'])

    print('### T1 door census (copies seen by each door, pre0 counter)')
    print()
    print('| arm | frame | brp | brf | brl | in6 |')
    print('|---|---|---|---|---|---|')
    for nm in ('ctlA', 'ctlX', 'uniC', 'preS', 'preD', 'preD7', 'fwdS',
               'in6D', 'vlanC'):
        if nm not in by:
            continue
        c = by[nm]['C']
        a = by[nm]['A']
        print('| %s | %s | %s | %s | %s | %s |' % (
            nm, a['fk'],
            c['brp'].split(',')[0], c['brf'].split(',')[0],
            c['brl'].split(',')[0], c['in6'].split(',')[0]))
    print()

    print('### T2 what each copy carries, by door')
    print()
    print('| door | arm | copies | stored | y0 dst/src/hl | z0 dst/src/hl | br0 dst/src/hl | u6n |')
    print('|---|---|---|---|---|---|---|---|')
    for nm in ('preS', 'preS_x1', 'preD7', 'fwdS', 'in6D', 'in6D_noT', 'brlH'):
        if nm not in by:
            continue
        a = by[nm]
        t = taps(a)
        def sd(k):
            n, fl, b = t.get(k, (0, -1, b''))
            if not n:
                return '-'
            hl = b[21] if len(b) > 21 else -1
            return '%s/%s/%02x' % (b[0:6].hex(), b[6:12].hex(), hl)
        a_ = a['A']
        print('| %s | %s | %s/%s/%s | %s | %s | %s | %s | %s |' % (
            a_['door'], nm, a_['door'] and a['C'][a_['door']].split(',')[0],
            a['C']['brf'].split(',')[0], a['C']['in6'].split(',')[0],
            (a_['imm'] if a_['mode'] in ('1', '3') else '-'),
            sd('y0'), sd('z0'), sd('br0'), a_['u6n']))
    print()

    print('### T3 the same eight bytes, two outcomes (frame A, bridge door)')
    print()
    print('| arm | dst store | brf | brl | taps y0/z0/br0 | Ip6InReceives | discards | otherhost y0/z0 | u6n |')
    print('|---|---|---|---|---|---|---|---|---|')
    for nm in ('preD', 'preD7'):
        if nm not in by:
            continue
        a = by[nm]
        t = taps(a)
        n = '/'.join(str(t.get(k, (0, -1, b''))[0]) for k in ('y0', 'z0', 'br0'))
        B = a['B']
        print('| %s | %s | %s | %s | %s | +%s | +%s | %s/%s | %s |' % (
            nm, a['A']['imm'], a['C']['brf'].split(',')[0],
            a['C']['brl'].split(',')[0], n, B['i6in_d'], B['disc_d'],
            B['y0oth_d'], B['z0oth_d'], a['A']['u6n']))
    print()

    print('### T4 NFLOG provenance: prefix, indev, outdev, and what it saw')
    print()
    print('| arm | messages (prefix:indev:outdev) |')
    print('|---|---|')
    for nm in ('ctlA', 'preS', 'fwdS', 'brlH', 'in6D', 'preD'):
        if nm not in by:
            continue
        M = by[nm]['M']
        ks = sorted((k for k in M if k.startswith('m')), key=lambda x: int(x[1:]))
        msgs = []
        for k in ks:
            f = M[k].split(':')
            msgs.append('%s:%s:%s' % (f[0], f[1], f[2]))
        print('| %s | %s |' % (nm, '  '.join(msgs)))
    print()

    print('### T5 the counters of the local copy, per door')
    print()
    print('| arm | door | Ip6InReceives | discards | Ip6InDelivers | Udp6InDatagrams |')
    print('|---|---|---|---|---|---|')
    for nm in ('ctlA', 'in6D', 'in6D_noT', 'uniD', 'uniD_noT', 'brlH'):
        if nm not in by:
            continue
        a = by[nm]
        B = a['B']
        print('| %s | %s | +%s | +%s | +%s | +%s |' % (
            nm, a['A']['door'], B['i6in_d'], B['disc_d'], B['deliv_d'],
            B['u6in_d']))
    print()
    print('frame A: %d bytes, br0 mac %s, x0 mac %s, y1 ifindex %s, z1 %s'
          % (int(env['la']), env['br0mac'], env['x0mac'], env['y1'],
             env['z1']))


if __name__ == '__main__':
    main()
