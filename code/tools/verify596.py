#!/usr/bin/env python3
"""verify596.py -- independent checks for turn 596 (F74).

Reads the campaign logs, the instrument source, the kernel image and its
DWARF, the initramfs and the two frozen prediction files.  Recomputes every
number it can and compares it with what the instrument printed.  Exit 0 only
if every check passes; a missing or malformed line is a red count, never a
traceback.

  python3 tools/verify596.py [log ...]        # default: rep1 + rep2
  V596_DEV=1 python3 tools/verify596.py log   # skip provenance (instrument dev)
"""
import hashlib
import os
import re
import subprocess
import sys

ROOT = '/work/kernel-sec'
SRC = ROOT + '/src/linux-7.3.4-T563'
BZ = SRC + '/arch/x86/boot/bzImage'
INITRD = ROOT + '/vm/initrd596/full.cpio.gz'
INITRD_TAG = 'full'
DIFFER = ROOT + '/vm/build/differ596'
PRED_A = ROOT + '/research/predictions_596.md'
PRED_B = ROOT + '/research/predictions_596b.md'
PRED_A_SHA = '743c6360141fc542e217f93f9ede9229700822df1fb291f300981b38036b6f5e'
PRED_B_SHA = '878121a5f087a7fd58540aa537be714a8b2f4823bcfdef4f2b0fbd4ca3f83b68'
KERNEL_SHA = '1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033'
DEV = bool(os.environ.get('V596_DEV'))

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


def flds(rest):
    d = {}
    for part in rest.split('|'):
        if '=' in part:
            k, v = part.split('=', 1)
            d[k] = v
    return d


def arr(s):
    return [int(x) for x in s.split(',')] if s else []


def gint(d, k, default=None):
    try:
        return int(d.get(k, default))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------- parsing

MODE_TAGS = ('GATE', 'TX', 'UB', 'FWD', 'LOC', 'UDP', 'ZIN', 'ZFI', 'SPI')


def parse_log(path):
    D = {'boot': [], 'slab': [], 'kmc': [], 'probe': [], 'def': [], 'run': [],
         'fail': [], 'childs': [], 'zc': [], 'wf': [], 'arm': {}, 'arm2': {},
         'cnt': {}, 'eq': {}, 'rcv': {}, 'pkt': {}, 'nfl': {}, 'rec': {}}
    mode = None
    for line in open(path, errors='replace'):
        if line.startswith('F596 '):
            body = line[5:].rstrip('\n')
            tag, _, rest = body.partition('|')
            if tag == 'BOOT':
                D['boot'].append(flds(rest))
            elif tag == 'SLAB':
                D['slab'].append(flds(rest))
            elif tag == 'KMC':
                D['kmc'].append(flds(rest))
            elif tag == 'FAIL':
                D['fail'].append(body)
            continue
        if not line.startswith('F595 '):
            continue
        body = line[5:].rstrip('\n')
        tag, _, rest = body.partition('|')
        f = flds(rest)
        if tag in ('ARM', 'ARM2', 'CNT', 'EQ', 'RCV', 'PKT', 'NFL'):
            i, att = gint(f, 'i'), gint(f, 'att')
            key = (mode, i, att)
            D[{'ARM': 'arm', 'ARM2': 'arm2', 'CNT': 'cnt', 'EQ': 'eq',
               'RCV': 'rcv', 'PKT': 'pkt', 'NFL': 'nfl'}[tag]][key] = f
        elif tag in MODE_TAGS:
            key = (mode, gint(f, 'i'), gint(f, 'att'))
            D['rec'].setdefault((tag,) + key, []).append(
                (arr(f.get('ts', '')), arr(f.get('dlen', '')),
                 arr(f.get('len', '')), arr(f.get('tail', '')),
                 arr(f.get('end', '')), arr(f.get('fl', ''))))
        elif tag == 'RUN':
            mode = f.get('mode')
            D['run'].append(f)
        elif tag == 'PROBE':
            D['probe'].append(f)
        elif tag == 'DEF':
            D['def'].append(rest)
        elif tag == 'CHILDS':
            D['childs'].append(f)
        elif tag == 'ZC':
            D['zc'].append(f)
        elif tag in ('WAIT', 'PREP'):
            D['wf'].append(f)
    return D


# ---------------------------------------------------------------- models

def align_up(x, unit):
    return ((x + unit - 1) // unit) * unit


def page_align(x):
    return ((x + 4095) // 4096) * 4096


SKB_DATA_ALIGN_SHINFO = 320      # pahole, re-derived below from the vmlinux
SKB_DATA_ALIGN_SKB = 256
SMALL_HEAD = 704                 # from the booting kernel's own slab cache


def charge_at(pl, align, k):
    """The zerocopy charge of datagram k of an arm.

    The sender advances its payload pointer by F591_MAXPL = 2048 bytes
    (differ595_add.c, `pay + k * F591_MAXPL`), so the page offset of the k-th
    datagram is (base + 2048 k) mod 4096 with base 0 for `al=1` and 3600 for
    `al=2`.  The charge itself is F73's measured law.
    """
    base = 3600 if align == 2 else 0
    off = (base + 2048 * k) % 4096
    end = SMALL_HEAD - SKB_DATA_ALIGN_SHINFO              # 384
    return end + SKB_DATA_ALIGN_SHINFO + SKB_DATA_ALIGN_SKB + page_align(pl + off)


def simulate_queue(R, seq_pre, pl, n=64):
    """__udp_enqueue_schedule_skb() with the charges in the order sent.

    net/ipv4/udp.c:1701  accept iff rmem + size <= rcvbuf (`>` drops), and
    :1705 an empty queue accepts regardless;  :1716 condense only when
    rmem > rcvbuf >> 1, and only a skb whose data_len fits the head's free
    room is actually shrunk (F71/F73: 340 bytes for a zerocopy head);
    :1739 a second check with the (possibly shrunk) size.
    """
    rmem = 0
    kept = 0
    drops = 0
    half = R >> 1
    for k in range(n):
        pre = seq_pre[k]
        if rmem + pre > R:
            if rmem:
                drops += 1
                continue
        size = pre
        if rmem > half and pl <= 340:
            # SKB_TRUESIZE(end) = 384 + 320 + 256 = 960, not 576: the 384
            # is the head itself and it does not disappear when the frags do
            size = (SMALL_HEAD - SKB_DATA_ALIGN_SHINFO) + \
                SKB_DATA_ALIGN_SHINFO + SKB_DATA_ALIGN_SKB
        if not (rmem + size <= R or rmem == 0):
            drops += 1
            continue
        rmem += size
        kept += 1
    return kept, rmem, drops


def model_end(pl, classes):
    """net/core/skbuff.c:390-400 + :605-625, with the copy path's request.

    req = payload + 28 (IP+UDP) + hh_len + 15, hh_len = LL_RESERVED_SPACE =
    ((hard_header_len + needed_headroom) & ~15) + 16 = 16 for veth with a
    zero needed_headroom  ->  req = pl + 59.  obj = ALIGN(req,64) + 320; if
    obj <= SKB_SMALL_HEAD_CACHE_SIZE the small-head cache gives exactly 704,
    else kmalloc_size_roundup(obj) from the classes the boot itself printed.
    end = ksize - 320, ts = end + 576.
    """
    req = pl + 59
    obj = align_up(req, 64) + SKB_DATA_ALIGN_SHINFO
    if obj <= SMALL_HEAD:
        ksize = SMALL_HEAD
    else:
        bigger = [c for c in classes if c >= obj]
        ksize = min(bigger) if bigger else None
    if ksize is None:
        return None, None
    end = ksize - SKB_DATA_ALIGN_SHINFO
    return end, end + SKB_DATA_ALIGN_SHINFO + SKB_DATA_ALIGN_SKB


# ---------------------------------------------------------------- source

def grep_src(path, needle):
    # whitespace-insensitive: a rule may be wrapped across two lines
    try:
        with open(path, errors='replace') as f:
            body = ' '.join(f.read().split())
    except OSError:
        return False
    return ' '.join(needle.split()) in body


def parse_arm_table(src_text, name):
    m = re.search(r'static const struct f595_arm %s\[\] = \{(.*?)\n\};'
                  % name, src_text, re.S)
    if not m:
        return []
    out = []
    for line in m.group(1).split('\n'):
        line = line.split('/*')[0].strip()
        if not line.startswith('{'):
            continue
        body = line.strip().rstrip(',').strip('{}')
        vals = [v.strip() for v in body.split(',')]
        if len(vals) != 21:
            out.append({'BAD': len(vals), 'LINE': line})
            continue
        out.append({
            'name': vals[0].strip('"'), 'xg': vals[1].strip("'"),
            'skt': vals[2].strip("'"), 'j': int(vals[3]), 'n': int(vals[4]),
            'pl': int(vals[5]), 'sh': int(vals[6]), 'sl': int(vals[7]),
            'rcvbuf': int(vals[8]), 'tap': int(vals[9]), 'zc': int(vals[10]),
            'align': int(vals[11]), 'splice': int(vals[12]),
            'dtap': int(vals[13]), 'rule': int(vals[14]),
            'exp_enq': int(vals[15]), 'exp_cond': int(vals[16]),
            'exp_pull': int(vals[17]), 'exp_seg': int(vals[18]),
            'exp_dl': int(vals[19]), 'exp_charge': int(vals[20])})
    return out


def cpio_member(path, want):
    """Extract one member of a gzip'd newc cpio without trusting tar tools."""
    import gzip
    data = gzip.open(path, 'rb').read()
    i = 0
    while i + 110 <= len(data):
        hdr = data[i:i + 110]
        if hdr[:6] not in (b'070701', b'070702'):
            return None
        try:
            namesize = int(hdr[94:102], 16)
            filesize = int(hdr[54:62], 16)
        except ValueError:
            return None
        name = data[i + 110:i + 110 + namesize - 1].decode('utf-8', 'replace')
        off = i + 110 + namesize
        off = (off + 3) & ~3
        body = data[off:off + filesize]
        if name.lstrip('./') == want.lstrip('./'):
            return body
        i = (off + filesize + 3) & ~3
        if name == 'TRAILER!!!':
            break
    return None


# ---------------------------------------------------------------- checks

def main(argv):
    logs = argv or [ROOT + '/logs/f74_rep1.log', ROOT + '/logs/f74_rep2.log']
    src = open(ROOT + '/vm/differ596_add.c', errors='replace').read()
    table_q = parse_arm_table(src, 'AF596_Q')
    table_h = parse_arm_table(src, 'AF596_H')

    ck_eq(len(table_q), 21, 'AF596_Q must have 21 arms')
    ck_eq(len(table_h), 9, 'AF596_H must have 9 arms')
    ck(all('BAD' not in a for a in table_q + table_h),
       'every arm row must parse to 21 fields')

    if not DEV:
        ck_eq(sha(BZ), KERNEL_SHA, 'kernel bzImage sha256')
        ck_eq(sha(INITRD), _initrd_sha_from_log(logs[0]),
              'initrd file hash equals the log header')
        ck_eq(sha(PRED_A), PRED_A_SHA, 'predictions_596.md unchanged')
        ck_eq(sha(PRED_B), PRED_B_SHA, 'predictions_596b.md unchanged')
        body = cpio_member(INITRD, 'root/repro')
        ck(body is not None, 'differ596 found inside the initramfs')
        if body is not None:
            ck_eq(hashlib.sha256(body).hexdigest(), sha(DIFFER),
                  'differ596 extracted from the initramfs is the built one')
        tag = [l.split() for l in open(ROOT + '/logs/f74_initrd_hashes.txt')
               if l.startswith(INITRD_TAG + ' ')]
        ck(len(tag) >= 1, 'initrd hash recorded for tag %s' % INITRD_TAG)
        if tag:
            ck_eq(tag[-1][1], sha(INITRD), 'recorded initrd hash')

    # ---- source anchors: every rule the model uses must be in this tree
    u = SRC + '/net/ipv4/udp.c'
    s = SRC + '/net/core/skbuff.c'
    o = SRC + '/net/ipv4/ip_output.c'
    nd = SRC + '/include/linux/netdevice.h'
    sk = SRC + '/include/linux/skbuff.h'
    for path, needle in [
            (u, 'if (rmem + size > rcvbuf) {'),
            (u, 'if (rmem) goto drop;'),
            (u, 'if (rmem > (rcvbuf >> 1)) {'),
            (u, 'skb_condense(skb);'),
            (u, 'err = udp_rmem_schedule(sk, size);'),
            (s, 'size -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));'),
            (s, 'obj_size = SKB_HEAD_ALIGN(*size);'),
            (s, 'if (obj_size <= SKB_SMALL_HEAD_CACHE_SIZE &&'),
            (s, '*size = SKB_SMALL_HEAD_CACHE_SIZE;'),
            (s, '#define SKB_SMALL_HEAD_CACHE_SIZE'),
            (s, 'if (skb->data_len > skb->end - skb->tail ||'),
            (o, 'alloc_extra = hh_len + 15;'),
            (o, 'skb = sock_alloc_send_skb(sk, alloclen,'),
            (nd, '#define LL_RESERVED_SPACE_EX(dev, hlen)'),
            (nd, '#define HH_DATA_MOD\t16'),
            (sk, '#define SKB_HEAD_ALIGN(X) (SKB_DATA_ALIGN(X) + \\'),
            (sk, '#define SKB_TRUESIZE(X) ((X) +')]:
        ck(grep_src(path, needle), 'source anchor missing: %s in %s'
           % (needle[:40], os.path.basename(path)))

    # ---- DWARF: the two constants the truesize identity is made of
    if not DEV:
        try:
            out = subprocess.run(['pahole', '-C', 'skb_shared_info',
                                  SRC + '/vmlinux'], capture_output=True,
                                 text=True, timeout=600).stdout
            m = re.search(r'/\* size: (\d+), cachelines', out)
            ck_eq(int(m.group(1)) if m else None, SKB_DATA_ALIGN_SHINFO,
                  'pahole: sizeof(struct skb_shared_info)')
            out = subprocess.run(['pahole', '-C', 'sk_buff',
                                  SRC + '/vmlinux'], capture_output=True,
                                 text=True, timeout=600).stdout
            m = re.search(r'/\* size: (\d+), cachelines', out)
            ck_eq(align_up(int(m.group(1)), 64) if m else None,
                  SKB_DATA_ALIGN_SKB, 'pahole: ALIGN(sizeof(struct sk_buff),64)')
        except (OSError, subprocess.SubprocessError) as e:
            ck(False, 'pahole failed: %r' % (e,))

    # ---- the small-head size, derived from the source's own constants
    ck_eq(704, SMALL_HEAD, 'SKB_SMALL_HEAD_CACHE_SIZE is 704 (source)')

    for path in logs:
        one(path, table_q, table_h)
    if len(logs) >= 2:
        two(logs)
    return report()


def _initrd_sha_from_log(path):
    for line in open(path, errors='replace'):
        if line.startswith('### initrd sha256:'):
            return line.split(':', 1)[1].strip()
        if not line.startswith('###'):
            break
    return None


def one(path, table_q, table_h):
    tag = os.path.basename(path)
    D = parse_log(path)
    # the image runs one process per mode (`repro q`, `repro h`), so a boot
    # has as many BOOT/PROBE/DEF blocks as it has modes
    nproc = len(D['boot'])
    ck(nproc >= 1, tag + ': at least one BOOT line')
    ck(sorted(b.get('mode') for b in D['boot']) in (['q'], ['h'], ['h', 'q']),
       tag + ': one process per mode: %r' % ([b.get('mode')
                                             for b in D['boot']],))
    ck(not D['fail'], tag + ': no FAIL lines: %r' % (D['fail'],))
    ck_eq(len(D['probe']), nproc, tag + ': a PROBE line per process')
    for pr in D['probe']:
        ck_eq(pr.get('ok'), '1', tag + ': all probes registered')
        ck_eq(pr.get('off'), '112,116,188,192,216,126',
              tag + ': sk_buff offsets from pahole')
    ck_eq(len(D['def']), 13 * nproc, tag + ': thirteen definitions per process')
    byname = {}
    for d in D['def']:
        m = re.match(r'p:kprobes/(\w+) (\w+) (.*)', d)
        if m:
            byname[m.group(1)] = (m.group(2), m.group(3))
    for ev, sym, reg in [('f595gate', '__udp_enqueue_schedule_skb', 'si'),
                         ('f595zc', '__zerocopy_sg_from_iter', 'dx'),
                         ('f595ub', 'skb_copy_ubufs', 'di'),
                         ('f595tx', '__dev_queue_xmit', 'di')]:
        got = byname.get(ev)
        ck(got is not None, '%s: probe %s defined' % (tag, ev))
        if got:
            ck_eq(got[0], sym, '%s: %s probes %s' % (tag, ev, sym))
            ck(('len=+112(%%%s)' % reg) in got[1],
               '%s: %s reads skb through %%%s' % (tag, ev, reg))

    # ---- the slab witness: the small-head cache and the kmalloc classes
    slab = [x for x in D['slab'] if x.get('src') == 'sysfs']
    ck(len(slab) >= 1, tag + ': a SLAB line')
    for x in slab:
        ck_eq(gint(x, 'obj'), SMALL_HEAD,
              tag + ': the booting kernel\'s skbuff_small_head object size')
    kmc = D['kmc'][0] if D['kmc'] else {}
    classes = sorted(set(arr(kmc.get('sizes', ''))))
    ck(len(classes) >= 5, tag + ': kmalloc classes printed')
    ck(768 not in classes, tag + ': 768 is not a kmalloc class (320-step)')
    ck(1024 in classes, tag + ': 1024 is a kmalloc class')

    # ---- both modes ran, in order, with the right arm counts
    modes = [r.get('mode') for r in D['run']]
    if DEV:
        ck(modes in ([], ['q'], ['h'], ['q', 'h']),
           tag + ': modes are a prefix of q,h')
    else:
        ck_eq(modes, ['q', 'h'], tag + ': both modes ran, q then h')

    wok = [x.get('ok') for x in D['wf'] if 'want' in x]
    ck(len(wok) >= 18, tag + ': WAIT lines for every arm')
    ck(all(w == '1' for w in wok), tag + ': every queue wait succeeded')

    # attempts in log order, so the cumulative InErrors can be differenced
    order = list(D['rcv'].keys())
    prev_of = {order[j]: (order[j - 1] if j else None)
               for j in range(len(order))}

    # ---- mode q: the arm table, the charges, and the queue
    for i, A in enumerate(table_q if 'q' in modes else []):
        for att in (0, 1):
            k = ('q', i, att)
            arm = D['arm'].get(k)
            ck(arm is not None, '%s q%s/%d: ARM line' % (tag, i, att))
            if arm is None:
                continue
            idn = '%s q%02d %s att%d' % (tag, i, A['name'], att)
            ck_eq(arm.get('name'), A['name'], idn + ': name')
            for fld, key in [('xg', 'xg'), ('skt', 'skt'), ('n', 'n'),
                             ('pl', 'pl'), ('rcvbuf', 'rcvbuf'),
                             ('tap', 'tap'), ('zc', 'zc'), ('al', 'align'),
                             ('dtap', 'dtap'), ('exp_enq', 'exp_enq'),
                             ('exp_charge', 'exp_charge')]:
                if fld == 'xg' or fld == 'skt':
                    ck_eq(arm.get(fld), A[key], idn + ': ' + fld)
                else:
                    ck_eq(gint(arm, fld), A[key], idn + ': ' + fld)
            ck_eq(gint(arm, 'j'), A['j'], idn + ': j')
            ck_eq(gint(arm, 'cmdrc'), 0, idn + ': no command errors')
            ck_eq(gint(arm, 'rc'), 0, idn + ': sender rc')
            pass
            ck_eq(gint(D['arm2'].get(k, {}), 'rrc'), 0, idn + ': rule installed')
            ck_eq(gint(D['arm2'].get(k, {}), 'rule'), A['rule'],
                  idn + ': the rule the arm asked for')

            cnt = D['cnt'].get(k, {})
            ck_eq(gint(cnt, 'enq'), 64, idn + ': 64 datagrams reached the gate')
            ck_eq(gint(cnt, 'ubuf'), 64, idn + ': 64 ubuf copies at the receiver')
            ck_eq(gint(cnt, 'zc'), 64, idn + ': 64 zerocopy fillers')
            ck_eq(gint(cnt, 'zf'), 64, idn + ': 64 zf')
            ck_eq(gint(cnt, 'segl'), 0, idn + ': no fraglist aggregate')
            ck_eq(gint(cnt, 'clone'), 0, idn + ': nothing cloned')
            ck_eq(gint(cnt, 'mark'), 1, idn + ': the window is in this arm')

            seq = [charge_at(A['pl'], A['align'], j) for j in range(64)]
            eq = D['eq'].get(k, {})
            ts = arr(eq.get('ts', ''))
            ck_eq(len(ts), 16, idn + ': sixteen gate records printed')
            ck_eq(ts, seq[:16], idn + ': gate charges in the measured order')
            ck_eq(arr(eq.get('len', '')), [A['pl']] * 16, idn + ': gate len')
            ck_eq(arr(eq.get('dlen', '')), [A['pl']] * 16,
                  idn + ': every datagram is paged')
            ck_eq(arr(eq.get('end', '')), [384] * 16, idn + ': gate end')
            ck_eq(arr(eq.get('tail', '')), [44] * 16, idn + ': gate tail')
            ck_eq(arr(eq.get('fl', '')), [0] * 16, idn + ': gate fl')

            rcv = D['rcv'].get(k, {})
            ck(bool(rcv), idn + ': RCV line present')
            if not rcv:
                continue
            R = gint(rcv, 'rb0')
            ck_eq(R, 2 * A['rcvbuf'], idn + ': sk_rcvbuf is twice SO_RCVBUF')
            kept, rmem, drops = simulate_queue(R or 0, seq, A['pl'])
            ck_eq(gint(rcv, 'n0'), kept, idn + ': datagrams kept')
            ck_eq(gint(rcv, 'n1'), 0, idn + ': nothing on the GRO socket')
            ck_eq(gint(rcv, 'rmem0'), rmem, idn + ': the queue\'s own bill')
            # the reader's own buffer is 4096 bytes, so a 4097-byte
            # datagram is READ as 4096: a limit of the witness, named
            ck_eq(arr(rcv.get('dl0', ''))[:1], [min(A['pl'], 4096)],
                  idn + ': delivered length (reader buffer 4096)')
            ck_eq(gint(rcv, 'f0'), 16 if A['align'] == 1 else 0,
                  idn + ': first payload byte')
            pk = prev_of.get(k)
            prev = D['rcv'].get(pk) if pk else None
            base_err = gint(prev, 'udperr') if prev else 0
            ck(rcv.get('udperr') is not None,
               idn + ': InErrors is printed')
            ck_eq((gint(rcv, 'udperr') or 0) - (base_err or 0), drops,
                  idn + ': InErrors delta equals the drops')

            pkt = D['pkt'].get(k)
            nfl = D['nfl'].get(k, {})
            if A['rule'] == 0:
                ck(pkt is not None, idn + ': the rule logged (PKT line)')
                if pkt:
                    ck_eq(gint(pkt, 'n'), 64, idn + ': the rule saw 64 packets')
                    ck_eq(arr(pkt.get('uhlen', '')), [A['pl'] + 8] * 32,
                          idn + ': uh->len of every logged packet')
                    ck_eq(arr(pkt.get('tot', '')), [A['pl'] + 28] * 32,
                          idn + ': IPv4 total length of every logged packet')
            else:
                ck_eq(nfl.get('skipped'), '1',
                      idn + ': counter-only rule has no log witness')
                ck(pkt is None, idn + ': no PKT line without a log rule')

    # ---- mode h: where `end` comes from
    for i, A in enumerate(table_h if 'h' in modes else []):
        for att in (0, 1):
            k = ('h', i, att)
            arm = D['arm'].get(k)
            ck(arm is not None, '%s h%s/%d: ARM line' % (tag, i, att))
            if arm is None:
                continue
            idn = '%s h%02d %s att%d' % (tag, i, A['name'], att)
            ck_eq(arm.get('name'), A['name'], idn + ': name')
            ck_eq(gint(arm, 'n'), A['n'], idn + ': n')
            ck_eq(gint(arm, 'pl'), A['pl'], idn + ': pl')
            ck_eq(gint(arm, 'zc'), A['zc'], idn + ': zc')
            ck_eq(gint(arm, 'cmdrc'), 0, idn + ': no command errors')
            cnt = D['cnt'].get(k, {})
            ck_eq(gint(cnt, 'enq'), 1, idn + ': one enqueue')
            ck_eq(gint(cnt, 'mark'), 1, idn + ': the window is in this arm')
            end, ts = model_end(A['pl'], classes)
            recs = D['rec'].get(('TX',) + k, [])
            ck(len(recs) >= 1, idn + ': TX records')
            mine = 0
            for (tsa, dla, lna, tla, ena, fla) in recs:
                for j in range(len(lna)):
                    if lna[j] == A['pl'] + 42:
                        mine += 1
                        ck_eq(ena[j], end, idn + ': end at __dev_queue_xmit')
                        ck_eq(tsa[j], ts, idn + ': truesize at the wire')
                        ck_eq(dla[j], 0, idn + ': a copy has no page frags')
                    ck_eq(tsa[j] - ena[j], SKB_DATA_ALIGN_SHINFO +
                          SKB_DATA_ALIGN_SKB,
                          idn + ': ts = end + 576 on every record')
            ck(mine >= 1, idn + ': the datagram itself is on the wire')
            rcv = D['rcv'].get(k, {})
            ck(bool(rcv), idn + ': RCV line present')
            if not rcv:
                continue
            ck_eq(gint(rcv, 'n0'), 1, idn + ': delivered once')
            ck_eq(gint(rcv, 'rmem0'), ts, idn + ': the queue paid that number')
            ck_eq(gint(rcv, 'rb0'), 2 * A['rcvbuf'], idn + ': buffer')


def two(logs):
    """Determinism: the same arm in two boots must print the same numbers."""
    a, b = parse_log(logs[0]), parse_log(logs[1])
    for tag, key, flds_ in [('n0', 'rcv', 'n0'), ('rmem0', 'rcv', 'rmem0'),
                            ('udperr', 'rcv', 'udperr'),
                            ('enq', 'cnt', 'enq'), ('ubuf', 'cnt', 'ubuf')]:
        for k in sorted(set(a[key]) & set(b[key])):
            ck_eq(gint(a[key][k], flds_), gint(b[key][k], flds_),
                  'determinism %s %s: %r' % (tag, k, a[key][k].get(flds_)))
    for k in sorted(set(a['eq']) & set(b['eq'])):
        ck_eq(a['eq'][k].get('ts'), b['eq'][k].get('ts'),
              'determinism EQ %r' % (k,))
    ck_eq(len(a['arm']), len(b['arm']), 'both boots ran the same arms')


def report():
    print('checks=%d fails=%d' % (CHECKS, len(FAILS)))
    for f in FAILS[:40]:
        print('FAIL', f)
    if len(FAILS) > 40:
        print('... and %d more' % (len(FAILS) - 40))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
