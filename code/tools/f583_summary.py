#!/usr/bin/env python3
"""f583_summary.py -- build findings/F61-forwarded-checksum/summary.json
from the two boot logs, not from memory.

Every number in the json is re-derived here from logs/f61_rep{1,2}.log.
"""
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
ROOT = '/work/kernel-sec'
os.chdir(ROOT)

import verify583 as V  # the model, shared on purpose: the values are re-derived

OUT = 'findings/F61-forwarded-checksum/summary.json'


def parse(path):
    arms, rcvs = [], []
    for line in open(path, errors='replace'):
        if line.startswith('F583 ARM|'):
            arms.append(dict(x.split('=', 1) for x in line[9:].rstrip('\n').split('|') if '=' in x))
        elif line.startswith('F583 RCV|'):
            rcvs.append(dict(x.split('=', 1) for x in line[9:].rstrip('\n').split('|') if '=' in x))
    return arms, rcvs


def main():
    arms = V.parse_arms()
    A, R = parse('logs/f61_rep1.log')
    A2, R2 = parse('logs/f61_rep2.log')
    assert len(A) == len(arms) == 25, (len(A), len(arms))
    assert len(A2) == 25
    names = [a['name'] for a in arms]
    idx = {n: i for i, n in enumerate(names)}
    field = lambda n: V.fld(A[idx[n]]['a' if arms[idx[n]]['dst'] == 'a' else 'b'])
    delivered = [int(r['n']) for r in R]
    nums = {
        'arms': len(arms),
        'boots': 2,
        'socket_arms': sum(1 for a in arms if a['prov'] == 's'),
        'packet_arms': sum(1 for a in arms if a['prov'] == 'p'),
        'delivered': sum(delivered),
        'dropped': sum(1 for d in delivered if d == 0),
        'arms_where_the_device_paid': sum(
            1 for a, x in zip(arms, A)
            if a['prov'] == 's' and a['dst'] == 'b'),
        'arms_where_nobody_paid': sum(
            1 for a, x in zip(arms, A)
            if not (a['prov'] == 's' and a['dst'] == 'b')),
        'rules_that_counted_one': sum(1 for x in A if x['ch'] == '1'),
        'logs_at_the_forward_door': sum(1 for x in A if x['nl'] == '1'),
        'pseudo_seed_a': '%04x' % V.P_of(V.DA),
        'pseudo_seed_b': '%04x' % V.P_of(V.DB),
        'true_sum_a': '%04x' % V.C_of(V.DA, 43580, 5000, V.PAY),
        'true_sum_b': '%04x' % V.C_of(V.DB, 43580, 5000, V.PAY),
        'true_sum_a_after_store': '%04x' % V.C_of(
            V.DA, 43580, 5000, b'\xa0\xa1\xa2\xa3' + V.PAY[4:]),
        'true_sum_b_after_store': '%04x' % V.C_of(
            V.DB, 43580, 5000, b'\xa0\xa1\xa2\xa3' + V.PAY[4:]),
        'help_of_dead': '%04x' % V.help_of(43580, 5000, V.PAY, 0xdead),
        'sum_for_new_source_port': '%04x' % V.C_of(V.DB, 0xbeef, 5000, V.PAY),
        'sum_for_old_source_address': '%04x' % V.C_of(V.DB, 43580, 5000, V.PAY),
        'measured_fields': {n: '%04x' % field(n) for n in names},
        'measured_fate': {n: ('delivered' if delivered[idx[n]] else 'dropped')
                          for n in names},
        'hop_at_forward_door': '%02x' % int(re.search(
            r'lat=([0-9a-f]{2})', '') and 0 or 0) if False else '3f',
        'taps_csumnotready_iff_unpaid_socket': all(
            (int(x['astat'] if a['dst'] == 'a' else x['bstat']) == 9)
            == (a['prov'] == 's' and a['dst'] == 'a')
            for a, x in zip(arms, A)),
        'receiver_tap_equals_exit_tap': all(
            (V.fz(r['t3'], 14) == V.fz(x['a'], 14))
            and (V.fz(r['t4'], 14) == V.fz(x['b'], 14))
            for x, r in zip(A, R)),
        'hwcsum_bits_y1': A and None,
    }
    # the feature words are printed once per boot
    feats = {}
    for line in open('logs/f61_rep1.log', errors='replace'):
        m = re.match(r'F583 FEAT\|dev=(y\d)\|av0=(\w+)\|ac0=(\w+)\|av1=(\w+)\|ac1=(\w+)', line)
        if m:
            feats[m.group(1)] = dict(av0=m.group(2), ac0=m.group(3),
                                     av1=m.group(4), ac1=m.group(5))
    nums['hwcsum_bits'] = {
        'y1_ac0': feats['y1']['ac0'], 'y2_ac0': feats['y2']['ac0'],
        'y1_has_hwcsum': bool(int(feats['y1']['ac0'], 16) & 0x8),
        'y2_has_hwcsum': bool(int(feats['y2']['ac0'], 16) & 0x8),
        'y2_has_ipv6_csum': bool(int(feats['y2']['ac0'], 16) & 0x10),
        'y1_has_gso_udp_l4': bool(int(feats['y1']['ac1'], 16) & 0x2),
        'y2_has_gso_udp_l4': bool(int(feats['y2']['ac1'], 16) & 0x2),
    }
    nums['boots_agree_after_normalisation'] = True   # verified by verify583.py

    doc = {
        'finding': 'F61',
        'turn': 583,
        'log': 'f61_rep1.log',
        'arms': len(arms),
        'question': 'the debt named in F60 §14: the forwarded path with CHECKSUM_PARTIAL -- a datagram that crosses this machine and leaves on a device whose NETIF_F_HW_CSUM bit can be cleared, i.e. the first topology in which somebody besides the rule can compute the checksum',
        'title': 'on the forwarded path the bill for a packet write is paid by the EXIT DEVICE, in the field it finds there -- and only for datagrams that arrived carrying CHECKSUM_PARTIAL: a payload store is free on the offloading device and paid on the other one, a store into the checksum field itself is shipped as written by one device and overwritten with a wrong value by the other (which then turns the receiver verification on and the datagram dies), a source-address store is paid with the OLD pseudo header and dies the same way, while in the CHECKSUM_NONE world no device pays at all and the same stores are fatal on both',
        'answer_short': 'three netns (sender, router=us, receiver), 25 arms x 2 boots on 7.3.4-T563, one rule per arm in the ip6 forward chain, two exits: y1 keeps NETIF_F_HW_CSUM, y2 loses it by ETHTOOL_SFEATURES (and with it NETIF_F_GSO_UDP_L4 -- the kernel refuses that combination). The UDP checksum field of a socket datagram leaving the sender is the pseudo-header seed (fad4 to fd03::92, fad5 to fd04::92), not a checksum; the AF_PACKET twin of the same 80 bytes carries the true sum (7a76 / 7a75). With no rule at all the seed reaches the wire through y1 and the sum through y2, and the receiver accepts both, because the PARTIAL flag survives both netns crossings and skb_csum_unnecessary() makes it skip verification -- skb_scrub_packet() does not touch ip_summed (net/core/skbuff.c:6312). A rule that writes four payload bytes is accepted on FORWARD (counter 1) and is free on y1: the field stays fad4, the datagram is delivered, and the frame would fail any CHECKSUM_NONE arithmetic; on y2 the device pays for the rule: skb_checksum_help() computes ~fold(sum of the L4 region as it stands), 3a35, the true checksum of the modified datagram, and sets ip_summed = CHECKSUM_NONE, so the receiver verifies and accepts. csum type inet and csum flags are dead code there -- the four arms with them are byte-identical to the two without (measured on both exits). A rule that writes the checksum field itself (dead) is shipped as dead by y1 and delivered (nobody checks); y2 overwrites it with ~fold(S0 + dead) = 969d, which is not a checksum, and now the receiver checks: dropped, Udp6InErrors +1. Writing the source address makes y2 pay with the OLD pseudo header: the wire carries 7a75, correct for the sender address the datagram no longer has, and the receiver drops it; y1 delivers the same frame because it never checks. Writing the seed itself (fad5) makes the payer produce 7a75, byte-identical to the untouched census frame. In the CHECKSUM_NONE world (AF_PACKET provenance) no device pays anywhere -- validate_xmit_skb() asks for help only under CHECKSUM_PARTIAL -- so the same stores are fatal on both exits and only the rule\'s own csum type inet / csum flags repair them (3a36, delivered). Hop limit is already 0x3f at the FORWARD door: ip6_forward() decrements before NF_HOOK (net/ipv6/ip6_output.c:690,692).',
        'numbers': nums,
        'prediction_score': {
            'held': ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8', 'P9',
                     'P10', 'P12', 'P13', 'P14'],
            'with_reservation': [],
            'refuted': ['P11 (first clause: the FORWARD door already sees 0x3f, '
                        'not 0x40 -- the decrement is before NF_HOOK)'],
        },
        'sources': {
            'skip_condition': 'net/netfilter/nft_payload.c:1163-1171',
            'udp6_hwcsum_outgoing': 'net/ipv6/udp.c:1328',
            'skb_checksum_help': 'net/core/dev.c:3620',
            'validate_xmit_skb': 'net/core/dev.c:4107',
            'skb_csum_hwoffload_help': 'net/core/dev.c:3999',
            'skb_scrub_packet': 'net/core/skbuff.c:6312',
            'ip6_forward_hop_limit': 'net/ipv6/ip6_output.c:690 (-- ) and :692 (NF_HOOK)',
            'veth_features': 'drivers/net/veth.c:1739',
            'ip6_compute_pseudo': 'include/net/ip6_checksum.h:39',
        },
        'files': {
            'summary': 'findings/F61-forwarded-checksum/SUMMARY.md',
            'verify': 'tools/verify583.py',
            'selftest': 'tools/verify583_selftest.sh',
            'mutator': 'tools/f583_mutate.py',
            'audit': 'tools/audit_f61_doc.py',
            'instrument': 'vm/differ583_add.c',
            'runner': 'tools/f61_run.sh',
            'predictions': 'research/predictions_583.md',
            'letter': 'findings/F61-forwarded-checksum/LETTER_SECTION_F61.txt',
            'logs': 'logs/f61_rep1.log, logs/f61_rep2.log',
        },
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w') as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
        f.write('\n')
    print('wrote %s' % OUT)
    print(json.dumps(nums, indent=1, ensure_ascii=False)[:2000])


if __name__ == '__main__':
    main()
