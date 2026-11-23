#!/usr/bin/env python3
"""verify580.py -- the F58 verifier.

Checks, for both boots of differ580 mode `bounds`:

  * provenance: the kernel sha of each boot header against the image on disk,
    the initrd sha against the file and between boots, and the differ
    EXTRACTED FROM THE INITRAMFS against the binary that was built;
  * the arm table parsed out of the instrument's own source against what the
    instrument printed;
  * the three frames rebuilt in Python (UDPv6/TCPv6 checksums included) against
    the FRMPY lines;
  * every arm, from the arms' own bytes:
      - the counter (the rule saw the frame) and the arm's log message
        (the store expression passed the guard AND the store was written);
      - the logged NFULA_HWHEADER and NFULA_PAYLOAD against the same frame's
        census bytes with the predicted store applied at the predicted byte --
        the write footprint is checked byte for byte;
      - the probe message at the ip6 prerouting hook: whether the frame got
        there at all and WHICH device delivered it (the VLAN device the written
        tag selected);
      - the nine snmp6 deltas and the socket count, predicted from the frame's
        bytes at the ip6 door and from the door (the version/length checks run
        before the prerouting hook, not after it);
      - rx_otherhost_dropped on x1;
  * determinism: every field of every arm equal between the two boots.

The four guards are modelled from the source, not from the output:
  nft_ll_write_ok      ingress -> true; else len+off+(mac-data) <= network_offset
  nft_nh_write_ok_ip6  a closed whitelist: 0(len<=4,version 6) 2(len<=2)
                       7(len==1) 8(len<=32) 24(len<=16)
  nft_th_write_ok      tprot != TCP -> true; else off > 12 || off+len <= 12
  nft_payload_set_vlan off+len > 12 -> off>=16 ? frame at off-4 :
                       off==12,len in {2,4} ? word : off==14,len==2 ? word :
                       refuse
"""
import hashlib
import os
import re
import subprocess
import sys

ROOT = '/work/kernel-sec'
LOGNAMES = ['rep1', 'rep2']
IMG = os.path.join(ROOT, 'src/linux-7.3.4-T563/arch/x86/boot/bzImage')
SRC = os.path.join(ROOT, 'src/linux-7.3.4-T563')
BIN = os.path.join(ROOT, 'vm/build/differ580')
SRCC = os.path.join(ROOT, 'vm/differ580_add.c')
INITRD = os.path.join(ROOT, 'vm/initrd580/full.cpio.gz')
LOGDIR = os.environ.get('F58_LOGDIR', 'logs')

bad = 0
checks = 0
nbad_by = {}


def ck(cond, label, extra=''):
    global checks, bad
    checks += 1
    if not cond:
        bad += 1
        key = label.split('|')[0]
        nbad_by[key] = nbad_by.get(key, 0) + 1
        if bad <= 40:
            print('BAD %s %s' % (label, extra))


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- frames

ADDR = bytes.fromhex('fd02' + '00' * 13 + '91')
SRC6 = bytes.fromhex('fd02' + '00' * 13 + '11')
SPORT = 43580
DPORT = 5000


def csum16(data):
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def csum6(ip, l4off, l4len, proto):
    ph = ip[8:24] + ip[24:40] + l4len.to_bytes(4, 'big') + b'\x00\x00\x00' + bytes([proto])
    body = bytearray(ip[l4off:l4off + l4len])
    return csum16(ph + bytes(body))


def mk_udp(tagged):
    if tagged:
        l2 = bytes.fromhex('ffffffffffff' '020000000080' '81000064' '86dd')
    else:
        l2 = bytes.fromhex('ffffffffffff' '020000000080' '86dd')
    tot = 8 + 18
    ip = bytearray(40)
    ip[0] = 0x60
    ip[4:6] = tot.to_bytes(2, 'big')
    ip[6] = 17
    ip[7] = 64
    ip[8:24] = SRC6
    ip[24:40] = ADDR
    udp = bytearray()
    udp += SPORT.to_bytes(2, 'big') + DPORT.to_bytes(2, 'big')
    udp += tot.to_bytes(2, 'big') + b'\x00\x00'
    udp += b'\x77' * 18
    c = csum6(bytes(ip), 0, 0, 0) if False else None
    # checksum over ip + udp: build the concatenation first
    ip = bytes(ip)
    pseudo = ip[8:24] + ip[24:40] + tot.to_bytes(4, 'big') + b'\x00\x00\x00' + bytes([17])
    c = csum16(pseudo + bytes(udp))
    if c == 0:
        c = 0xffff
    udp[6:8] = c.to_bytes(2, 'big')
    return l2 + ip + bytes(udp)


def mk_tcp():
    l2 = bytes.fromhex('ffffffffffff' '020000000080' '86dd')
    tot = 20
    ip = bytearray(40)
    ip[0] = 0x60
    ip[4:6] = tot.to_bytes(2, 'big')
    ip[6] = 6
    ip[7] = 64
    ip[8:24] = SRC6
    ip[24:40] = ADDR
    tcp = bytearray(20)
    tcp[0:2] = SPORT.to_bytes(2, 'big')
    tcp[2:4] = DPORT.to_bytes(2, 'big')
    tcp[7] = 1
    tcp[12] = 0x50
    tcp[13] = 0x02
    tcp[14:16] = (8192).to_bytes(2, 'big')
    pseudo = bytes(ip[8:24]) + bytes(ip[24:40]) + tot.to_bytes(4, 'big')
    pseudo += b'\x00\x00\x00' + bytes([6])
    c = csum16(pseudo + bytes(tcp))
    if c == 0:
        c = 0xffff
    tcp[16:18] = c.to_bytes(2, 'big')
    return l2 + bytes(ip) + bytes(tcp)


FRAMES = {1: mk_udp(False), 5: mk_udp(True), 6: mk_tcp()}


def view_of(fid):
    """the bytes as the L3 stack sees them: the tag is metadata, so the
    14-byte L2 view of a tagged frame is dst|src|inner-ethertype."""
    f = FRAMES[fid]
    if fid == 5:
        return f[0:12] + f[16:]
    return f


def udp_valid(ip, udp):
    """the kernel validates over the datagram it has, not over the header's
    payload_len (measured: n_2_2 is delivered)."""
    pseudo = ip[8:24] + ip[24:40] + len(udp).to_bytes(4, 'big')
    pseudo += b'\x00\x00\x00' + bytes([17])
    return csum16(pseudo + udp) == 0


def ip_fate(view, door):
    """the fate of the frame at the ip6 door.  door='n1' means the store ran at
    the ingress hook, i.e. BEFORE ip6_rcv_core's version and length checks;
    door='g6' means the store ran at prerouting, AFTER them."""
    r = dict(rcv=0, deliv=0, hdrerr=0, addrerr=0, disc=0, ukproto=0,
             trunc=0, noroutes=0, udp=0, udperr=0, udpnop=0, u6n=0)
    ip = view[14:]
    r['rcv'] = 1
    if door == 'n1':
        if ip[0] >> 4 != 6:
            r['hdrerr'] = 1
            return r
        if 40 + int.from_bytes(ip[4:6], 'big') > len(ip):
            r['trunc'] = 1
            return r
    nh = ip[6]
    if nh not in (6, 17):
        r['ukproto'] = 1
        return r
    if ip[24:40] != ADDR:
        r['noroutes'] = 1
        return r
    if nh == 6:
        r['deliv'] = 1
        return r
    udp = ip[40:]
    r['deliv'] = 1
    ulen = int.from_bytes(udp[4:6], 'big')
    if ulen < 8 or ulen > len(udp) or not udp_valid(ip, udp):
        r['udperr'] = 1
        return r
    if int.from_bytes(udp[2:4], 'big') != DPORT:
        r['udpnop'] = 1
        return r
    r['udp'] = 1
    r['u6n'] = 1
    return r


# ---------------------------------------------------------------- guards

IP6_LANES = {
    0: lambda ln, imm: ln <= 4 and (imm[0] >> 4) == 6,
    2: lambda ln, imm: ln <= 2,
    7: lambda ln, imm: ln == 1,
    8: lambda ln, imm: ln <= 32,
    24: lambda ln, imm: ln <= 16,
}


def ll_outcome(door, off, ln, word):
    """('refuse',None) | ('word',None) | ('bytes', position in the view)"""
    if word:
        if off + ln > 12:
            if off >= 16:
                return ('bytes', off - 4)
            if off == 12 and ln in (2, 4):
                return ('word', None)
            if off == 14 and ln == 2:
                return ('word', None)
            return ('refuse', None)
        return ('bytes', off)
    if off + ln <= 14:          # len+off-14 <= skb_network_offset()(=0)
        return ('bytes', off)
    return ('refuse', None)


def nh_ok(off, ln, imm):
    fn = IP6_LANES.get(off)
    return bool(fn and fn(ln, imm))


def th_ok(tprot, off, ln):
    if tprot != 6:
        return True
    return off > 12 or off + ln <= 12


# ---------------------------------------------------------------- arms

ARM_RE = re.compile(
    r'\{ "([a-z0-9_]+)",\s*(\d+), (\d+), ([A-Za-z0-9_]+), (\d+), (\d+), '
    r'(\d+), (NULL|"([0-9a-f]+)")\s*\}')
BASE_MAP = {'F580_B_LL': 0, 'F580_B_NH': 1, 'F580_B_TH': 2}


def parse_arm_table():
    txt = open(SRCC).read()
    body = txt[txt.index('static const struct f580_arm A580[] = {'):]
    body = body[:body.index('};')]
    arms = []
    for m in ARM_RE.finditer(body):
        name, fid, door, base_tok, store, off, ln = m.group(1, 2, 3, 4, 5, 6, 7)
        hexs = m.group(9)
        base = BASE_MAP.get(base_tok)
        if base is None:
            base = int(base_tok)
        hexs = m.group(9)
        arms.append(dict(name=name, fid=int(fid), door=int(door),
                         base=int(base), store=int(store), off=int(off),
                         len=int(ln), hex=hexs))
    return arms


def pattern(n):
    return bytes((0xa0 + i) & 0xff for i in range(n))


def imm_of(a):
    if a['store'] != 1:
        return b''
    if a['hex'] is None:
        return pattern(a['len'])
    return bytes.fromhex(a['hex'])


# ---------------------------------------------------------------- parse

def be16(b):
    return (b[0] << 8) | b[1]


def parse_arms(logtxt):
    out = []
    for line in logtxt.splitlines():
        if not line.startswith('F580 ARM|'):
            continue
        d = {}
        for kv in line[len('F580 ARM|'):].split('|'):
            k, _, v = kv.partition('=')
            d[k] = v
        out.append(d)
    return out


def parse_pylog(logtxt, tag):
    out = {}
    for line in logtxt.splitlines():
        if line.startswith('F580 %s|' % tag):
            d = {}
            for kv in line[len('F580 %s|' % tag):].split('|'):
                k, _, v = kv.partition('=')
                d[k] = v
            out.setdefault('_', []).append(d)
    return out


# ---------------------------------------------------------------- main

def main():
    text = {}
    for n in LOGNAMES:
        p = os.path.join(ROOT, LOGDIR, 'f58_%s.log' % n)
        if not os.path.exists(p):
            print('MISSING %s' % p)
            return 2
        text[n] = open(p, 'r', errors='replace').read()

    # ---- provenance
    img_sha = sha256_file(IMG)
    initrd_sha = sha256_file(INITRD)
    bin_sha = sha256_file(BIN)
    got = subprocess.run('zcat %s | cpio -i --to-stdout root/repro 2>/dev/null | sha256sum'
                         % INITRD, shell=True, capture_output=True)
    in_initrd = got.stdout.decode().split()[0] if got.stdout else '-'
    ck(in_initrd == bin_sha, 'prov|initrd_binary', '%s vs %s' % (in_initrd, bin_sha))
    for n in LOGNAMES:
        m = re.search(r'^### sha256: ([0-9a-f]{64})$', text[n], re.M)
        ck(bool(m) and m.group(1) == img_sha, 'prov|kernel_sha|%s' % n)
        m = re.search(r'^### initrd sha256: ([0-9a-f]{64})$', text[n], re.M)
        ck(bool(m) and m.group(1) == initrd_sha, 'prov|initrd_sha|%s' % n)
        ck('VM_BOOT_OK' in text[n], 'prov|boot|%s' % n)
        ck(re.search(r'WARNING:|BUG:|Oops|general protection|KASAN', text[n]) is None,
           'prov|no_splat|%s' % n)

    # ---- source anchors
    anchors = [
        ('net/netfilter/nft_payload.c', 'static bool nft_ll_write_ok(const struct nft_pktinfo *pkt, int offset)'),
        ('net/netfilter/nft_payload.c', '\tif (nft_in_ingress(pkt->state))\n\t\treturn true;'),
        ('net/netfilter/nft_payload.c', '\treturn offset <= skb_network_offset(pkt->skb);'),
        ('net/netfilter/nft_payload.c', 'static bool nft_nh_write_ok_ip6(const struct nft_pktinfo *pkt,'),
        ('net/netfilter/nft_payload.c', '\t\treturn priv->len <= 4 && ih->version == 6;'),
        ('net/netfilter/nft_payload.c', '\tcase offsetof(struct ipv6hdr, hop_limit):\n\t\treturn priv->len == 1;'),
        ('net/netfilter/nft_payload.c', '\t\treturn priv->len <= 16 + 16;'),
        ('net/netfilter/nft_payload.c', 'static bool nft_th_write_ok(const struct nft_pktinfo *pkt,'),
        ('net/netfilter/nft_payload.c', '\tunsigned int doff = offsetof(struct tcphdr, ack_seq) + sizeof(__be32);'),
        ('net/netfilter/nft_payload.c', '\tif (pkt->tprot != IPPROTO_TCP)\n\t\treturn true;'),
        ('net/netfilter/nft_payload.c', 'nft_payload_set_vlan(const u32 *src, struct sk_buff *skb, u16 offset, u8 len,'),
        ('net/netfilter/nft_payload.c', '\tif (offset >= offsetof(struct vlan_ethhdr, h_vlan_encapsulated_proto)) {'),
        ('net/netfilter/nft_payload.c', 'static bool nft_payload_need_vlan_adjust(u32 offset, u32 len)'),
        ('net/netfilter/nft_payload.c', '\tif (boundary > offsetof(struct ethhdr, h_proto))'),
        ('net/netfilter/nft_payload.c', '\t\tvlan_tci = ntohs(nft_reg_load_be16(src));'),
        ('net/netfilter/nft_payload.c', '\t\t\t\t\t       ntohs(vlanh->h_vlan_TCI));'),
        ('net/netfilter/nft_payload.c', '\t\tif (!nft_th_write_ok(pkt, priv))\n\t\t\tgoto err;'),
        ('net/netfilter/nft_payload.c', '\t\tif (!(pkt->flags & NFT_PKTINFO_L4PROTO) || pkt->fragoff)\n\t\t\tgoto err;\n\t\tif (!nft_th_write_ok(pkt, priv))'),
        ('net/netfilter/nft_payload.c', '\tif (skb_ensure_writable(skb, max(offset + priv->len, 0)) ||'),
        ('net/netfilter/nft_immediate.c', 'priv->dlen = desc.len;'),
        ('net/netfilter/nf_tables_api.c', '\tif (len > desc->size)\n\t\treturn -EOVERFLOW;'),
    ]
    for path, needle in anchors:
        try:
            txt = open(os.path.join(SRC, path), errors='replace').read()
        except OSError:
            ck(False, 'anchor|missing|%s' % path)
            continue
        ck(needle in txt, 'anchor|%s|%s' % (path, needle.splitlines()[0][:60]))

    # ---- the instrument's own table
    table = parse_arm_table()
    ck(len(table) > 40, 'table|count', str(len(table)))

    # ---- frames
    for n in LOGNAMES:
        seen = {}
        for line in text[n].splitlines():
            if line.startswith('F580 FRMPY|'):
                d = dict(kv.split('=', 1) for kv in line.split('|')[1:])
                seen[int(d['id'])] = (int(d['len']), d['hex'])
        for fid, fr in FRAMES.items():
            got = seen.get(fid)
            ck(got is not None and got[0] == len(fr) and got[1] == fr.hex(),
               'frame|%s|%d' % (n, fid))

    # ---- per boot
    per_boot = {}
    for n in LOGNAMES:
        arms = parse_arms(text[n])
        ck(len(arms) == len(table), 'arms|count|%s' % n,
           '%d vs %d' % (len(arms), len(table)))
        rows = {}
        cached = {}
        for rep, a in enumerate(arms):
            idx = int(a['i'])
            A = table[idx] if idx < len(table) else None
            ck(A is not None and a['name'] == A['name'], 'arms|name|%s|%d' % (n, idx))
            if A is None:
                continue
            for fld, key in (('fid', 'fid'), ('door', 'door'), ('base', 'base'),
                             ('store', 'store'), ('off', 'off'), ('len', 'len')):
                ck(int(a[fld]) == A[key], 'arms|%s|%s|%d' % (fld, n, idx),
                   '%s vs %s' % (a[fld], A[key]))
            imm = imm_of(A)
            ck(a['hex'] == (imm.hex() if A['store'] == 1 else '-'),
               'arms|imm|%s|%d' % (n, idx))
            rows[idx] = a
        per_boot[n] = (rows, table)

    # ---- the model, applied to both boots
    for n in LOGNAMES:
        rows, table = per_boot[n]
        census = {}
        for idx, a in rows.items():
            if table[idx]['store'] == 0:
                census[(int(a['fid']), int(a['door']))] = a
        for idx, a in rows.items():
            A = table[idx]
            fid, door = A['fid'], A['door']
            door_s = 'n1' if door == 1 else 'g6'
            base_view = view_of(fid)
            imm = imm_of(A)
            rc = int(a['rc'])
            encodable = not (A['store'] == 1 and A['len'] > 16)
            ck(encodable == (rc == 0), 'enc|%s|%s' % (n, A['name']),
               'rc=%s len=%s' % (rc, A['len']))
            if not encodable:
                # the rule was never installed: the frame is untouched
                accepted = False
                view = bytearray(base_view)
                for key in ('rcv', 'deliv', 'hdrerr', 'addrerr', 'disc',
                            'ukproto', 'trunc', 'noroutes', 'udp', 'udperr',
                            'udpnop'):
                    ck(int(a[key]) == ip_fate(bytes(base_view), door_s)[key],
                       'enc_fate|%s|%s|%s' % (key, n, A['name']))
                ck(int(a['ch']) == 0 and int(a['nl']) == 0,
                   'enc|no_rule|%s|%s' % (n, A['name']))
                ck(a['pindev'].split(':')[-1] == ('x1.100' if fid == 5 else 'x1'),
                   'enc|pindev|%s|%s' % (n, A['name']), a['pindev'])
                ck(a['pp'] == bytes(base_view[14:]).hex(),
                   'enc|pp|%s|%s' % (n, A['name']))
                continue
            view = bytearray(base_view)
            word = (fid == 5 and door == 1)
            accepted = True
            want_word = None
            if A['store'] == 0:
                accepted = True
            elif A['store'] == 3:
                # read @ll,14,16 -> REG32_08, @ll,30,16 -> REG32_12, store
                # 32 bytes of the frame at @nh,8: the source is the frame's
                # own IPv6 bytes 0..31
                src32 = base_view[14:46]
                accepted = nh_ok(8, 32, src32)
                if accepted:
                    view[14 + 8:14 + 40] = src32
            elif A['base'] == 0:
                kind, pos = ll_outcome(door_s, A['off'], A['len'], word)
                accepted = kind != 'refuse'
                if kind == 'bytes':
                    view[pos:pos + A['len']] = imm
                elif kind == 'word':
                    want_word = imm
            elif A['base'] == 1:
                accepted = nh_ok(A['off'], A['len'], imm)
                if accepted:
                    view[14 + A['off']:14 + A['off'] + A['len']] = imm
            else:
                tprot = FRAMES[fid][14 + 6]
                accepted = th_ok(tprot, A['off'], A['len'])
                if accepted and (A['off'] + A['len']) <= (len(base_view) - 54):
                    view[54 + A['off']:54 + A['off'] + A['len']] = imm
                elif accepted:
                    accepted = 'guard_yes_store_no'
            # ---- the counter
            rc = int(a['rc'])
            ck(int(a['ch']) == (1 if rc == 0 else 0), 'ch|%s|%d' % (n, idx),
               'rc=%s ch=%s' % (rc, a['ch']))
            # ---- the arm's own log message
            logged = int(a['nl']) == 1
            ck(logged == (accepted is True), 'log|%s|%s' % (n, A['name']),
               'accepted=%s nl=%s' % (accepted, a['nl']))
            # ---- the demux (only a tagged frame at the ingress door has one)
            dev = None
            oth = 0
            if word:
                proto, tci = 0x8100, 0x0064
                if want_word is not None:
                    if A['off'] == 12 and A['len'] == 2:
                        proto = be16(want_word)
                    elif A['off'] == 12 and A['len'] == 4:
                        proto = be16(want_word[0:2])
                        tci = be16(want_word[2:4])
                    elif A['off'] == 14 and A['len'] == 2:
                        tci = be16(want_word)
                vid = tci & 0xfff
                if proto != 0x8100:
                    dev = None
                else:
                    dev = {100: 'x1.100', 1024: 'x1.1024'}.get(vid)
                if dev is None:
                    oth = 1
            else:
                dev = 'x1.100' if fid == 5 else 'x1'
            # ---- the probe
            pnl = int(a['pnl'])
            fate_pre = ip_fate(bytes(view), door_s) if dev is not None else None
            reached = (dev is not None and fate_pre['hdrerr'] == 0
                       and fate_pre['trunc'] == 0)
            ck(pnl == (1 if reached else 0), 'probe|%s|%s' % (n, A['name']),
               'dev=%s reached=%s pnl=%s' % (dev, reached, a['pnl']))
            if reached:
                ck(a['pindev'].split(':')[-1] == dev, 'pindev|%s|%s' % (n, A['name']),
                   '%s vs %s' % (a['pindev'], dev))
                ck(int(a['pplen']) == len(view) - 14, 'pplen|%s|%s' % (n, A['name']),
                   '%s' % a['pplen'])
                ck(a['pp'] == bytes(view[14:]).hex(), 'pp|%s|%s' % (n, A['name']))
            # ---- the logged bytes at the arm's door
            if logged:
                ck(int(a['hwlen']) == 14, 'hwlen|%s|%s' % (n, A['name']),
                   a['hwlen'])
                ck(a['hw'] == bytes(view[0:14]).hex(), 'hw|%s|%s' % (n, A['name']),
                   '%s vs %s' % (a['hw'], bytes(view[0:14]).hex()))
                ck(a['p'] == bytes(view[14:]).hex(), 'p|%s|%s' % (n, A['name']))
                ck(a['pre'].startswith('58:'), 'pre|%s|%s' % (n, A['name']))
                if int(a['door']) == 1:
                    if fid == 5:
                        pr, tc = 0x8100, 0x0064
                        if want_word is not None:
                            if A['off'] == 12 and A['len'] == 2:
                                pr = be16(want_word)
                            elif A['off'] == 12 and A['len'] == 4:
                                pr, tc = be16(want_word[0:2]), be16(want_word[2:4])
                            elif A['off'] == 14 and A['len'] == 2:
                                tc = be16(want_word)
                        ck(a['vlan'] == '%04x:%04x' % (pr, tc),
                           'vlan|%s|%s' % (n, A['name']),
                           '%s vs %04x:%04x' % (a['vlan'], pr, tc))
                    else:
                        ck(a['vlan'] == 'none', 'vlan|%s|%s' % (n, A['name']),
                           a['vlan'])
                if int(a['door']) == 1:
                    ck(int(a['l2len']) == 14 and a['l2'] == bytes(view[0:14]).hex(),
                       'l2|%s|%s' % (n, A['name']))
            # ---- the fate
            if dev is None:
                want = dict(rcv=0, deliv=0, hdrerr=0, addrerr=0, disc=0,
                            ukproto=0, trunc=0, noroutes=0, udp=0, udperr=0,
                            udpnop=0, u6n=0)
            else:
                want = ip_fate(bytes(view), door_s)
            for key in ('rcv', 'deliv', 'hdrerr', 'addrerr', 'disc', 'ukproto',
                        'trunc', 'noroutes', 'udp', 'udperr', 'udpnop'):
                ck(int(a[key]) == want[key], 'fate|%s|%s|%s' % (key, n, A['name']),
                   '%s vs %s' % (a[key], want[key]))
            ck(int(a['u6n']) == want['u6n'], 'fate|u6n|%s|%s' % (n, A['name']),
               '%s vs %s' % (a['u6n'], want['u6n']))
            ck(int(a['oth']) == oth, 'fate|oth|%s|%s' % (n, A['name']),
               '%s vs %s' % (a['oth'], oth))
            # ---- the census arms must reproduce the door's own bytes
            if A['store'] == 0:
                ck(a['hw'] == base_view[0:14].hex(), 'census|hw|%d' % idx)
                ck(a['p'] == base_view[14:].hex(), 'census|p|%d' % idx)

    # ---- determinism between the boots
    if not ('rep1' in per_boot and 'rep2' in per_boot):
        print('checks=%d bad=%d (single boot)' % (checks, bad))
        return 1 if bad else 0
    rows1, table = per_boot['rep1']
    rows2, _ = per_boot['rep2']
    for idx in sorted(rows1):
        if idx not in rows2:
            ck(False, 'det|missing|%d' % idx)
            continue
        for k, v in rows1[idx].items():
            ck(rows2[idx].get(k) == v, 'det|%s|%s' % (k, table[idx]['name']),
               '%s vs %s' % (v, rows2[idx].get(k)))

    print('checks=%d bad=%d' % (checks, bad))
    if nbad_by:
        print('bad groups:', ', '.join('%s=%d' % kv for kv in sorted(nbad_by.items())))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
