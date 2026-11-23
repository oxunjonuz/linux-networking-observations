#!/usr/bin/env python3
"""verify595.py -- independent checks for turn 595 (F73).

Reads the campaign logs, the instrument source, the kernel image and its
DWARF, the initramfs and F72's own logs.  Recomputes every number it can and
compares it with what the instrument printed.  Exit 0 only if every check
passes.

  python3 tools/verify595.py [log ...]        # default: rep1 + rep2
"""
import hashlib
import re
import subprocess
import sys

ROOT = '/work/kernel-sec'
SRC = ROOT + '/src/linux-7.3.4-T563'
BZ = SRC + '/arch/x86/boot/bzImage'
INITRD = ROOT + '/vm/initrd595/full.cpio.gz'
DIFFER = ROOT + '/vm/build/differ595'
PRED = ROOT + '/research/predictions_595.md'
PRED_SHA = 'c35903d62eec3882702d525565fa0b77b68b68b26ea530c0e0071f5760f1a026'
F72_LOG = ROOT + '/logs/f72_rep1.log'

CHECKS = 0
FAILS = []


def ck(cond, msg):
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(msg)


def ck_eq(got, want, msg):
    ck(got == want, '%s: got %r, want %r' % (msg, got, want))


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- parsing

def flds(rest):
    d = {}
    for part in rest.split('|'):
        if '=' in part:
            k, v = part.split('=', 1)
            d[k] = v
    return d


def arr(s):
    return [int(x) for x in s.split(',')] if s else []


TAG2KEY = {'GATE': 'gate', 'TX': 'tx', 'UB': 'ub', 'FWD': 'fwd', 'LOC': 'loc',
           'UDP': 'udp', 'ZIN': 'zin', 'ZFI': 'zfi', 'SPI': 'spi', 'EQ': 'eq'}
REC = ('gate', 'tx', 'ub', 'fwd', 'loc', 'udp', 'zin', 'zfi', 'spi')
CLN_RE = re.compile(r'len=(\d+) dlen=(\d+) tail=(\d+) end=(\d+) ts=(\d+) '
                    r'fl=(\d+) caller=(0x[0-9a-f]+)')


def parse_log(path):
    out, glob = {}, {'boot': [], 'probe': [], 'def': [], 'fail': [],
                     'run': []}
    mode = None
    pending = []      # lines that carry no i=/att= belong to the next one that does
    for line in open(path, errors='replace'):
        if not line.startswith('F595 '):
            continue
        body = line[5:].rstrip('\n')
        tag, _, rest = body.partition('|')
        if tag == 'BOOT':
            mode = flds(rest).get('mode')
            glob['boot'].append(flds(rest))
            continue
        if tag == 'RUN':
            # one boot runs both tables, and the printed i= restarts at 00
            mode = flds(rest).get('mode')
            glob['run'].append(flds(rest))
            continue
        if tag == 'CHILDF':
            glob.setdefault('childf', []).append(flds(rest))
            continue
        if tag in ('PROBE', 'DEF', 'ENV', 'CHAINS', 'FEAT', 'GROSW',
                   'FAIL', 'DEFRB'):
            if tag == 'DEF':
                glob['def'].append(rest)
            elif tag == 'PROBE':
                glob['probe'].append(flds(rest))
            elif tag == 'FAIL':
                glob['fail'].append(rest)
            continue
        if tag == 'CLN':
            d = flds(rest)
            key = (mode, int(d['i']), int(d['att']))
            rec = out.setdefault(key, {'mode': mode, 'i': int(d['i']),
                                       'att': int(d['att'])})
            m = CLN_RE.search(rest)
            ck(m is not None, 'clone record parses: ' + rest[:80])
            if m:
                rec.setdefault('cln', []).append(
                    tuple(int(m.group(k)) for k in range(1, 7)) +
                    (m.group(7),))
            continue
        d = flds(rest)
        if 'i' not in d or 'att' not in d:
            pending.append((tag, d))
            continue
        key = (mode, int(d['i']), int(d['att']))
        rec = out.setdefault(key, {'mode': mode, 'i': int(d['i']),
                                   'att': int(d['att'])})
        for ptag, pd in pending:
            if ptag in ('CHILDS', 'WAIT', 'PREP', 'DTAP', 'ZC', 'NFL'):
                rec.setdefault(ptag.lower(), []).append(pd)
        pending = []
        if tag == 'ARM':
            rec['arm'] = d
        elif tag == 'ARM2':
            rec['arm2'] = d
        elif tag == 'CNT':
            rec['cnt'] = d
        elif tag == 'CALLERS':
            rec['callers'] = d['a'].split(',') if d.get('a') else []
        elif tag == 'CHILDS':
            rec.setdefault('childs', []).append(d)
        elif tag == 'WAIT':
            rec.setdefault('wait', []).append(d)
        elif tag == 'RCV':
            rec.setdefault('rcv', []).append(d)
        elif tag == 'PKT':
            rec.setdefault('pkt', []).append(d)
        elif tag == 'ZC':
            rec.setdefault('zcdone', []).append(d)
        elif tag == 'NFL':
            rec.setdefault('nfl', []).append(d)
        elif tag in TAG2KEY:
            rec.setdefault(TAG2KEY[tag], []).append({
                'n': int(d['n']), 'ts': arr(d['ts']), 'dlen': arr(d['dlen']),
                'len': arr(d['len']), 'end': arr(d['end']),
                'fl': arr(d.get('fl', ''))})
    return out, glob


def recs(R, key):
    return R.get(key, [])


# ---------------------------------------------------------------- sources

def arm_tables():
    src = open(ROOT + '/vm/differ595_add.c').read()
    out = {}
    for name in ('AF595_CHG', 'AF595_CLN', 'AF595_SPL'):
        m = re.search(name + r'\[\] = \{(.*?)\n\};', src, re.S)
        ck(m is not None, 'table found in the source: ' + name)
        rows = []
        for line in m.group(1).split('\n'):
            s = line.strip()
            if not s.startswith('{'):
                continue
            f = [x.strip() for x in s.strip('{}').rstrip(',').split(',')]
            rows.append(dict(name=f[0].strip('"'), xg=f[1].strip("'"),
                             skt=f[2].strip("'"), j=int(f[3]), n=int(f[4]),
                             pl=int(f[5]), sh=int(f[6]), sl=int(f[7]),
                             rcvbuf=int(f[8]), tap=int(f[9]), zc=int(f[10]),
                             al=int(f[11]), sp=int(f[12]), dtap=int(f[13]),
                             rule=int(f[14])))
        out[name.rsplit('_', 1)[1].lower()] = rows
    return out


def pahole():
    o = subprocess.run(['pahole', '-C', 'sk_buff', 'vmlinux'], cwd=SRC,
                       capture_output=True, text=True).stdout
    want = {'len': 112, 'data_len': 116, 'tail': 188, 'end': 192,
            'truesize': 216, 'cloned': 126}
    got = {}
    for line in o.split('\n'):
        for name in want:
            m = re.search(r'\b' + name + r'\b[^;]*;\s*/\*\s*(\d+)', line)
            if m and name not in got:
                got[name] = int(m.group(1))
    return want, got


def sym_addr(name):
    o = subprocess.run(['nm', 'vmlinux'], cwd=SRC, capture_output=True,
                       text=True).stdout
    for line in o.split('\n'):
        p = line.split()
        if len(p) == 3 and p[2] == name:
            return int(p[0], 16)
    return None


def segment_clone_sites():
    """return addresses of `call ... <skb_clone>` inside skb_segment()"""
    a = sym_addr('skb_segment')
    if a is None:
        return []
    o = subprocess.run(['objdump', '-d', '--start-address=%d' % a,
                        '--stop-address=%d' % (a + 0x1800), 'vmlinux'],
                       cwd=SRC, capture_output=True, text=True).stdout
    rets, lines = [], o.split('\n')
    for k, line in enumerate(lines):
        if '<skb_clone>' in line and '\tcall' in line:
            m = re.match(r'\s*([0-9a-f]+):', line)
            if m:
                rets.append(int(m.group(1), 16))
    return rets


def initramfs_differ_sha():
    o = subprocess.run('gzip -dc %s | cpio -i --to-stdout root/repro 2>/dev/null'
                       % INITRD, shell=True, capture_output=True)
    return hashlib.sha256(o.stdout).hexdigest()


# ---------------------------------------------------------------- models

def page_up(x):
    return (x + 4095) & ~4095


def expected_charge(A):
    """the model of this turn, in bytes of the receive queue.

    A zerocopy datagram costs PAGE_ALIGN(payload + page offset).  A datagram
    sent with MSG_SPLICE_PAGES does not reach skb_splice_from_iter() on this
    stand: it arrives as a linear copy and costs exactly its own truesize,
    end + 576 -- measured, and the reason the prediction of F73 P9/P10 was
    refuted."""
    if A['sp']:
        return None
    if A['al'] == 2:
        return 960 + page_up(A['pl'] + 3600)
    return 960 + page_up(A['pl'])       # al 0 and 1 both land in one page


def expected_clone_segments(A):
    if A['n'] == 1:
        return [1280]
    if A['xg'] == 'u':
        return [1280] * 6               # one fresh head + five cloned members
    return [7680] + [1280] * 5          # skb_segment_list keeps the head whole


# ---------------------------------------------------------------- per arm

def check_arm(tagn, A, R, clone_sites):
    cnt = R.get('cnt', {})
    gates = recs(R, 'gate')
    n_gate = sum(g['n'] for g in gates)
    ck_eq(int(cnt.get('enq', -1)), n_gate, tagn + ': CNT enq == records')
    ck_eq(int(cnt.get('mark', -1)), 1, tagn + ': own marker window')
    ck_eq(n_gate, A['n'], tagn + ': one enqueue per datagram')
    exp = expected_charge(A) if A['mode'] in ('chg', 'spl') else None

    for g in gates:
        for k in range(g['n']):
            ck_eq(g['len'][k], A['pl'], tagn + ': gate len == payload')
            if A['mode'] == 'cln' and A['n'] == 6 and A['xg'] == 'u':
                # one fresh head and five clones of frag_list members
                ck_eq(g['fl'][k], 0 if k == 0 else 1,
                      tagn + ': the cloned bit marks the five clones')
            else:
                ck_eq(g['fl'][k], 0, tagn + ': gate cloned bit clear')
            if A['zc']:
                ck_eq(g['end'][k], 384, tagn + ': gate end of a paged skb')
                ck_eq(g['dlen'][k], A['pl'], tagn + ': payload in frags')
            elif A['sp']:
                ck_eq(g['dlen'][k], 0, tagn + ': splice arm is a linear copy')
                ck_eq(g['ts'][k], g['end'][k] + 576,
                      tagn + ': a copied datagram costs end + 576')
            else:
                ck_eq(g['end'][k], 704, tagn + ': gate end of a segment')
                ck_eq(g['dlen'][k], 0, tagn + ': segments are linear')
            if exp is not None:
                ck_eq(g['ts'][k], exp, tagn + ': the charge, from the model')

    # ---- who was called, and how often
    if A['zc']:
        ck_eq(int(cnt.get('zf', -1)), A['n'], tagn + ': fill per datagram')
        ck_eq(int(cnt.get('zc', -1)), A['n'], tagn + ': wrapper called too')
        ck_eq(int(cnt.get('sp', -1)), 0, tagn + ': splice absent')
        ck_eq(int(cnt.get('ubuf', -1)), A['n'], tagn + ': one ubuf copy each')
    elif A['sp']:
        # the refutation, as a fact: the splice entry point is never reached
        ck_eq(int(cnt.get('sp', -1)), 0, tagn + ': splice NOT called')
        ck_eq(int(cnt.get('zc', -1)), 0, tagn + ': zerocopy wrapper absent')
        ck_eq(int(cnt.get('zf', -1)), 0, tagn + ': fill absent')
        ck_eq(int(cnt.get('ubuf', -1)), 0, tagn + ': no ubuf copy')
        ck_eq(int(cnt.get('ap', -1)), 0,
              tagn + ': ip_append_data itself is not the entry either')
    else:
        ck_eq(int(cnt.get('zf', -1)), 0, tagn + ': no fill on a copy sender')
        ck_eq(int(cnt.get('ubuf', -1)), 0, tagn + ': no ubuf copy')

    if A['mode'] in ('chg', 'spl'):
        # the fill sees the header alone, before the payload is attached
        for z in recs(R, 'zin') + recs(R, 'zfi'):
            for k in range(z['n']):
                ck_eq(z['ts'][k], 960, tagn + ': fill entry truesize')
                ck_eq(z['len'][k], 28, tagn + ': fill entry length')
                ck_eq(z['dlen'][k], 0, tagn + ': fill entry data_len')
        # the test frame leaves X already charged, and nothing on the way
        # rewrites the number: X's xmit, the ubuf copy, the forward, the
        # local delivery and udp_rcv all carry the same truesize
        txr = recs(R, 'tx')[0] if recs(R, 'tx') else None
        if txr:
            if A['sp']:
                idx = [k for k in range(txr['n'])
                       if txr['len'][k] == A['pl'] + 42]
            else:
                idx = [k for k in range(txr['n'])
                       if txr['dlen'][k] == A['pl']]
            ck(len(idx) >= 1, tagn + ': the test frame is in the xmit log')
            if idx:
                k = idx[0]
                ck_eq(txr['len'][k], A['pl'] + 42,
                      tagn + ': frame length on the wire')
                want_ts = exp if exp is not None else txr['end'][k] + 576
                ck_eq(txr['ts'][k], want_ts,
                      tagn + ': the charge leaves X')
            prim = [k for k in range(txr['n']) if txr['len'][k] == 106]
            ck(len(prim) >= 1, tagn + ': the primer is on the wire too')
            for k in prim:
                ck_eq(txr['ts'][k], 960, tagn + ': primer truesize')
        for kind in ('ub', 'fwd', 'loc', 'udp'):
            for r in recs(R, kind):
                if A['sp']:
                    hit = [k for k in range(r['n'])
                           if r['len'][k] in (A['pl'], A['pl'] + 8,
                                              A['pl'] + 28)]
                else:
                    hit = [k for k in range(r['n'])
                           if r['dlen'][k] == A['pl']]
                ck(len(hit) >= 1, tagn + ': a test record in ' + kind)
                for k in hit:
                    want_ts = exp if exp is not None else r['end'][k] + 576
                    ck_eq(r['ts'][k], want_ts,
                          tagn + ': %s carries the charge' % kind)
        # the queue itself, read back before any read()
        if recs(R, 'wait') and exp is not None:
            last = recs(R, 'wait')[-1]
            ck_eq(int(last['rmem']), A['n'] * exp,
                  tagn + ': /proc rmem == the charge')
        if recs(R, 'wait') and exp is None:
            last = recs(R, 'wait')[-1]
            tot = sum(g['ts'][k] for g in gates for k in range(g['n']))
            ck_eq(int(last['rmem']), tot,
                  tagn + ': /proc rmem == end + 576 of the linear copy')
    else:
        exp_seg = expected_clone_segments(A)
        got = [g['ts'][k] for g in gates for k in range(g['n'])]
        ck_eq(got, exp_seg, tagn + ': every segment charged as modelled')
        ck_eq(int(cnt.get('clone', -1)),
              5 if (A['n'] == 6 and A['xg'] == 'u') else 0,
              tagn + ': clone count')
        ck_eq(int(cnt.get('seg', -1)),
              1 if A['xg'] == 'u' and A['n'] == 6 else 0,
              tagn + ': skb_segment calls')
        ck_eq(int(cnt.get('segl', -1)),
              1 if A['xg'] == 'f' else 0, tagn + ': skb_segment_list calls')
        cl = R.get('cln', [])
        ck_eq(len(cl), int(cnt.get('clone', -1)), tagn + ': clone records')
        for c in cl:
            ck_eq(c[0], 512, tagn + ': the cloned skb is a datagram')
            ck_eq(c[1], 0, tagn + ': cloned member is linear')
            ck_eq(c[4], 1280, tagn + ': cloned member truesize')
            ck_eq(c[5], 2, tagn + ': cloned bit set on the source')
        if cl and clone_sites:
            rets = set(c[6] for c in cl)
            ck_eq(len(rets), 1, tagn + ': one call site')
            want = set('0x%x' % (x + 5) for x in clone_sites)
            ck(rets <= want, tagn + ': caller is the skb_clone() call in '
               'skb_segment (%s)' % sorted(rets))


def check_log(name, path, tables, clone_sites):
    log, glob = parse_log(path)
    ck_eq(glob['fail'], [], name + ': no FAIL line')
    ck_eq(len(glob['boot']), 1, name + ': one mode per boot')
    ck_eq(glob['boot'][0].get('mode'), 'all', name + ': mode all')
    ck_eq([r.get('mode') for r in glob['run']], ['chg', 'cln', 'spl'],
          name + ': every table ran, in order')
    ck_eq(len(glob['probe']), 1, name + ': one probe registration')
    for p in glob['probe']:
        ck_eq(p.get('ok'), '1', name + ': probes ok')
        ck_eq(p.get('mask'), '1fff', name + ': all thirteen probes enabled')
        ck_eq(p.get('off'), '112,116,188,192,216,126', name + ': offsets')
    ck_eq(len(glob['def']), 13, name + ': thirteen definitions')
    cf = glob.get('childf', [])
    ck_eq(len(cf), 1, name + ': the sender reported x1 once')
    if cf:
        ac0 = int(cf[0]['ac0'], 16)
        ck_eq(cf[0]['dev'], 'x1', name + ': the sender device')
        ck_eq(ac0 & 1, 1, name + ': NETIF_F_SG is on for x1')
        ck(ac0 != 0, name + ': features were read, not defaulted')

    off = (112, 116, 188, 192, 216, 126)
    want_def = {
        'f595gate': ('__udp_enqueue_schedule_skb', 'si', 0),
        'f595zc': ('__zerocopy_sg_from_iter', 'dx', 0),
        'f595zf': ('zerocopy_fill_skb_from_iter', 'di', 0),
        'f595sp': ('skb_splice_from_iter', 'di', 0),
        'f595ub': ('skb_copy_ubufs', 'di', 0),
        'f595tx': ('__dev_queue_xmit', 'di', 0),
        'f595fwd': ('ip_forward', 'di', 0),
        'f595loc': ('ip_local_deliver', 'di', 0),
        'f595udp': ('udp_rcv', 'di', 0),
        'f595cln': ('skb_clone', 'di', 1),
    }
    seen = {}
    for d in glob['def']:
        m = re.match(r'p:kprobes/(\w+) (\S+)(.*)$', d)
        ck(m is not None, name + ': definition parses')
        if not m:
            continue
        ev, sym, f = m.group(1), m.group(2), m.group(3)
        if ev in want_def:
            seen[ev] = d
            w = want_def[ev]
            ck_eq(sym, w[0], name + ': ' + ev + ' symbol')
            body = (' len=+%d(%%%s):u32 dlen=+%d(%%%s):u32 '
                    'tail=+%d(%%%s):u32 end=+%d(%%%s):u32 '
                    'ts=+%d(%%%s):u32 fl=+%d(%%%s):u8') % (
                        off[0], w[1], off[1], w[1], off[2], w[1], off[3],
                        w[1], off[4], w[1], off[5], w[1])
            want_f = body + (' caller=$stack0:x64' if w[2] else '')
            ck_eq(f.strip(), want_f.strip(), name + ': ' + ev + ' fields')
        else:
            ck_eq(sym, {'f595seg': 'skb_segment',
                        'f595segl': 'skb_segment_list',
                        'f595ap': 'ip_append_data'}.get(ev, '?'),
                  name + ': ' + ev + ' symbol')
    for ev in want_def:
        ck(ev in seen, name + ': definition present: ' + ev)

    # ---- the arms
    for mode in ('chg', 'cln', 'spl'):
        for idx, A in enumerate(tables[mode]):
            A = dict(A)
            A['mode'] = mode
            for att in (0, 1):
                R = log.get((mode, idx, att))
                ck(R is not None, '%s: arm present %s[%d] att%d'
                   % (name, mode, idx, att))
                if not R:
                    continue
                tagn = '%s/%s/%d/%d' % (name, mode, idx, att)
                arm = R.get('arm', {})
                ck_eq(arm.get('name'), A['name'], tagn + ': name')
                ck_eq(arm.get('xg'), A['xg'], tagn + ': door')
                ck_eq(int(arm.get('n', -1)), A['n'], tagn + ': n')
                ck_eq(int(arm.get('pl', -1)), A['pl'], tagn + ': payload')
                ck_eq(int(arm.get('zc', -1)), A['zc'], tagn + ': zc column')
                ck_eq(int(arm.get('al', -1)), A['al'], tagn + ': align column')
                a2 = R.get('arm2', {})
                ck_eq(int(a2.get('sp', -1)), A['sp'], tagn + ': splice column')
                ck_eq(int(a2.get('rule', -1)), A['rule'], tagn + ': rule')
                ck_eq(int(a2.get('rrc', -1)), 0, tagn + ': rule installed')
                ch = [c for c in recs(R, 'childs')
                      if c.get('cmd', '').startswith('sa0')]
                ck_eq(len(ch), 1, tagn + ': one test command')
                if ch:
                    c = ch[0]
                    ck_eq(int(c['al']), A['al'], tagn + ': sender got align')
                    ck_eq(int(c['sp']), A['sp'], tagn + ': sender got splice')
                    ck_eq(int(c['n']), A['n'], tagn + ': sender got n')
                    ck_eq(int(c['pl']), A['pl'], tagn + ': sender got pl')
                    ck_eq(int(c['zc']), A['zc'], tagn + ': sender got zc')
                    ck_eq(int(c['sent']), A['n'], tagn + ': all datagrams sent')
                ck_eq(len(recs(R, 'nfl')), 1 if A['rule'] == 1 else 0,
                      tagn + ': NFLOG skipped iff counter-only')
                check_arm(tagn, A, R, clone_sites)
    return log


def check_f72_dead_parameter():
    """F72's own logs: the sender never reported an alignment, because the
    command byte that carried it was never written."""
    n = al = 0
    for line in open(F72_LOG, errors='replace'):
        if 'F594 CHILDS|' in line and 'cmd=sa0' in line:
            n += 1
            if 'al=' in line:
                al += 1
    ck(n >= 15, 'F72: the sender reported its commands (%d lines)' % n)
    ck_eq(al, 0, 'F72: not one command carried an alignment')


def main():
    args = sys.argv[1:]
    logs = args if args else [ROOT + '/logs/f73_rep1.log',
                              ROOT + '/logs/f73_rep2.log']

    ck_eq(sha(PRED), PRED_SHA, 'predictions_595.md unchanged since the freeze')
    bz = sha(BZ)
    ird = sha(INITRD)
    for p in logs:
        head = open(p, errors='replace').read(4000)
        ck(('### sha256: ' + bz) in head, p + ': kernel sha in the header')
        ck(('initrd sha256: ' + ird) in head, p + ': initrd sha in the header')
        ck('7.3.4-T563' in head, p + ': kernel release')
    ck_eq(initramfs_differ_sha(), sha(DIFFER),
          'the differ inside the initramfs is the built one')

    want, got = pahole()
    for k in want:
        ck_eq(got.get(k), want[k], 'pahole: offset of ' + k)
    sites = segment_clone_sites()
    ck(len(sites) >= 1, 'skb_segment contains a call to skb_clone')

    tables = arm_tables()
    ck_eq(len(tables['chg']), 10, 'ten charge arms in the source')
    ck_eq(len(tables['cln']), 4, 'four clone arms in the source')
    ck_eq(len(tables['spl']), 4, 'four diagnostic arms in the source')

    check_f72_dead_parameter()

    parsed = {}
    for p in logs:
        name = p.split('/')[-1].replace('f73_', '').replace('.log', '')
        parsed[name] = check_log(name, p, tables, sites)

    # ---- the three-cell demonstration of the dead parameter
    for name, log in parsed.items():
        def ts(mode, idx, att=0):
            R = log.get((mode, idx, att))
            g = recs(R, 'gate') if R else []
            return g[0]['ts'][0] if g else None
        a0, az, a36 = ts('chg', 0), ts('chg', 1), ts('chg', 2)
        ck_eq(az, a0, name + ': F72\'s raw buffer charges like offset 0')
        ck_eq(a0, 5056, name + ': offset 0 costs one page')
        ck_eq(a36, 9152, name + ': offset 3600 costs two')
        ck(a36 != a0, name + ': the offset is visible in the charge')

    # ---- determinism between boots
    names = sorted(parsed)
    if len(names) == 2:
        a, b = parsed[names[0]], parsed[names[1]]
        ck_eq(sorted(a), sorted(b), 'same attempt set in both boots')
        for key in sorted(a):
            if key not in b:
                continue
            for kind in REC:
                def norm(rec):
                    # a 70-byte frame on __dev_queue_xmit is an ARP request
                    # or reply from the neighbour cache, not part of the arm:
                    # how many of them land inside the window is a race.
                    out = []
                    for r in rec:
                        keep = [k for k in range(r['n'])
                                if not (kind == 'tx' and r['len'][k] == 70)]
                        if kind == 'tx':
                            # the primer's forward and the test's send are
                            # two processes: their order inside one window is
                            # a race, their content is not
                            keep = sorted(keep, key=lambda k: (r['len'][k],
                                                              r['ts'][k]))
                        out.append((len(keep), [r['ts'][k] for k in keep],
                                    [r['dlen'][k] for k in keep],
                                    [r['len'][k] for k in keep],
                                    [r['end'][k] for k in keep],
                                    [r['fl'][k] for k in keep]))
                    return out
                ck_eq(norm(recs(a[key], kind)), norm(recs(b[key], kind)),
                      'determinism %s %s' % (key, kind))
            ck_eq([c[6] for c in a[key].get('cln', [])],
                  [c[6] for c in b[key].get('cln', [])],
                  'determinism %s clone callers' % (key,))

    print('checks: %d, failures: %d' % (CHECKS, len(FAILS)))
    for f in FAILS[:60]:
        print('FAIL ' + f)
    return 1 if FAILS else 0


if __name__ == '__main__':
    sys.exit(main())
