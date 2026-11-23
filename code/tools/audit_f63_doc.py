#!/usr/bin/env python3
"""audit_f63_doc.py [doc] -- does the F63 document say what the logs say?

Every number the SUMMARY quotes about a specific arm is looked up in
summary.json (which is generated from the two boot logs) and compared.  A
copy of the document with one number swapped must fail.
"""
import json
import re
import sys

ROOT = '/work/kernel-sec'
DOC = sys.argv[1] if len(sys.argv) > 1 else \
    'findings/F63-gro-aggregate/SUMMARY.md'
N = 0
FAIL = []


def eq(got, want, what):
    global N
    N += 1
    if got != want:
        FAIL.append((what, got, want))


def ok(cond, what):
    eq(bool(cond), True, what)


doc = open('%s/%s' % (ROOT, DOC)).read()
summ = json.load(open('%s/findings/F63-gro-aggregate/summary.json' % ROOT))
arms = {r['name']: r for r in summ['boots'][0]['arms']}
arms2 = {r['name']: r for r in summ['boots'][1]['arms']}


def frame(name, k):
    return arms[name]['frames'][k]


def wire(name):
    return ' '.join('%04x' % f['uhck'] for f in arms[name]['frames'])


# ---- the census table of §2 ------------------------------------------------
eq(arms['A_none_a']['w520'] - 0, 3, 'A_none_a: three packets at D')
eq(len(arms['A_none_a']['frames']), 3, 'A_none_a: three frames')
eq(arms['C_UFWD_local']['frames'][0]['uhck'], 0xfd43,
   'C_UFWD_local: the seed, and three packets')
eq(len(arms['C_UFWD_local']['frames']), 3, 'C_UFWD_local: still three frames')
eq(len(arms['C_FLIST']['frames']), 1, 'C_FLIST: one aggregate frame')
eq(frame('C_FLIST', 0)['flen'], 1598, 'C_FLIST: 1598 bytes')
eq(frame('C_FLIST', 0)['iplen'], 1544, 'C_FLIST: IPv6 payload 1544')
eq(arms['C_GRO_SOCK']['b0'], 1536, 'C_GRO_SOCK: one 1536-byte read')
eq(arms['C_GRO_SOCK']['bg0'], 512, 'C_GRO_SOCK: cmsg segment size 512')
eq(arms['C_FG_SOCK']['b0'], 1536, 'C_FG_SOCK: the socket bit wins')
eq(frame('C_FG_SOCK', 0)['uhck'], 0x0144,
   'C_FG_SOCK: linear completion rewrote the field')
eq(arms['B_UFWD_x0']['ch'], 1, 'B_UFWD_x0: the rule saw ONE packet')
eq(arms['B_UFWD_x0']['lgplen'], 1584, 'B_UFWD_x0: 1584 bytes of log')
eq(arms['B_FLIST_x0']['ch'], 1, 'B_FLIST_x0: one packet at the rule')
eq(arms['B_UFWD_x0']['uhlen'], 1544, 'B_UFWD_x0: uh->len 1544')
eq(arms['B_FLIST_x0']['uhlen'], 1544, 'B_FLIST_x0: uh->len 1544')
eq(arms['B_UFWD_x0']['uhck'], 0x00c3, 'B_UFWD_x0: uh->check = seed(1544)')
eq(arms['B_FLIST_x0']['uhck'], 0xfcc2, 'B_FLIST_x0: uh->check = seed(520)')

# ---- who pays (§4) ---------------------------------------------------------
eq(wire('B_UFWD_w_b'), '426f f1af f0af', 'B_UFWD_w_b: the device paid')
eq(wire('B_FLIST_w_b'), 'fcc3 fcc3 fcc3', 'B_FLIST_w_b: nobody paid')
eq([f['hop'] for f in arms['B_UFWD_w_b']['frames']], [63, 63, 63],
   'B_UFWD_w_b: hop limit copied to every segment')
eq([f['hop'] for f in arms['B_FLIST_w_b']['frames']], [63, 64, 64],
   'B_FLIST_w_b: only the head carries the router hop limit')
eq(arms['B_UFWD_w_b']['udp'], 3, 'B_UFWD_w_b: three delivered')
eq(arms['B_FLIST_w_b']['udp'], 3, 'B_FLIST_w_b: three delivered')

# ---- the length store (§5) -------------------------------------------------
eq(arms['B_FLIST_len_a']['udp'], 0, 'B_FLIST_len_a: nothing delivered')
eq(arms['B_FLIST_len_a']['udperr'], 3, 'B_FLIST_len_a: three errors')
eq(arms['B_FLIST_len_b']['udp'], 3, 'B_FLIST_len_b: three delivered')
eq([f['uhlen'] for f in arms['B_FLIST_len_b']['frames']], [520, 520, 520],
   'B_FLIST_len_b: the splitter rewrote the length back to 520')

# ---- the checksum store (§6) ----------------------------------------------
eq(wire('B_FLIST_chk_b'), 'dead fcc3 fcc3', 'B_FLIST_chk_b: dead ships')
eq(arms['B_FLIST_chk_b']['udp'], 3, 'B_FLIST_chk_b: three delivered')
eq(arms['B_FLIST_chk_b']['udperr'], 0, 'B_FLIST_chk_b: no error')
eq(wire('B_UFWD_chk_b'), '14c6 13c6 12c6', 'B_UFWD_chk_b: hashed from dead')
eq(arms['B_UFWD_chk_b']['udp'], 0, 'B_UFWD_chk_b: nothing delivered')
eq(arms['B_UFWD_chk_b']['udperr'], 3, 'B_UFWD_chk_b: three errors')
eq(wire('B_FLIST_chk0_b'), '0000 fcc3 fcc3', 'B_FLIST_chk0_b: zero ships')
eq(arms['B_FLIST_chk0_b']['udp'], 2, 'B_FLIST_chk0_b: two delivered')
eq(arms['B_FLIST_chk0_b']['udperr'], 1, 'B_FLIST_chk0_b: one error')

# ---- the pull (§7) ---------------------------------------------------------
eq(wire('B_FLIST_w_b'), 'fcc3 fcc3 fcc3', 'the 8-offset arm pays nothing')
eq(wire('B_FLIST_pull_b'), 'f2af a1ce f0af', 'the 520-offset arm pays for all')
eq(len(arms['B_FLIST_pull_b']['frames']), 3, 'pull: three frames on door b')
eq(frame('B_FLIST_pull_a', 0)['uhck'], 0xfcc2,
   'pull via door a: the aggregate seed after linearisation')
eq(arms['B_FLIST_pull_a']['udp'], 3, 'pull via door a: three delivered')

# ---- provenance (§8) -------------------------------------------------------
eq(len(arms['P_FLIST_none']['frames']), 1, 'P_FLIST_none: one aggregate')
eq(arms['P_FLIST_none']['udp'], 3, 'P_FLIST_none: three delivered')
eq(len(arms['P_FLIST_w']['frames']), 3, 'P_FLIST_w: GRO refused to merge')
eq(arms['P_FLIST_w']['udp'], 0, 'P_FLIST_w: nothing delivered')
eq(arms['P_FLIST_w']['udperr'], 3, 'P_FLIST_w: three errors')

# ---- the length store on single datagrams ---------------------------------
eq(arms['A_len']['reads'][0], 24, 'A_len: the receiver trims to 24 bytes')
eq(arms['C_FLIST_len']['reads'][0], 24, 'C_FLIST_len: the store kills the merge')
eq(len(arms['C_FLIST_len']['frames']), 3, 'C_FLIST_len: three packets at D')

# ---- the two boots say the same -------------------------------------------
for name, r in arms.items():
    eq(r['frames'], arms2[name]['frames'], 'both boots: %s frames' % name)
    eq(r['udp'], arms2[name]['udp'], 'both boots: %s delivered' % name)

# ---- the document's own claims --------------------------------------------
ok('26 плеч' in doc, 'the document says 26 arms')
ok('1818 проверок' in doc or '1818' in doc, 'the document quotes the verifier')
ok('veth_disable_gro' in doc, 'the document names veth_disable_gro')
ok('__pskb_pull_tail' in doc, 'the document names the pull')
ok('skb_segment_list' in doc, 'the document names the splitter')
ok('не замораживал' in doc, 'the document admits no frozen predictions')

print('%d checks, %d failures' % (N, len(FAIL)))
for f in FAIL:
    print('  FAIL %s: got %r want %r' % f)
sys.exit(1 if FAIL else 0)
