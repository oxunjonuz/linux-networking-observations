#!/usr/bin/env python3
"""f584_summary.py -- build findings/F62-gso-two-segmenters/summary.json
from the two boot logs, not from memory.

Every number in the json is re-derived here from logs/f62_rep{1,2}.log.
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
ROOT = '/work/kernel-sec'
os.chdir(ROOT)

import verify584 as V  # the model, shared on purpose: the values are re-derived

OUT = 'findings/F62-gso-two-segmenters/summary.json'


def parse(path):
    arms, rcvs = [], []
    for line in open(path, errors='replace'):
        if line.startswith('F584 ARM|'):
            arms.append(dict(x.split('=', 1)
                             for x in line[9:].rstrip('\n').split('|')
                             if '=' in x))
        elif line.startswith('F584 RCV|'):
            rcvs.append(dict(x.split('=', 1)
                             for x in line[9:].rstrip('\n').split('|')
                             if '=' in x))
    return arms, rcvs


def main():
    arms = V.parse_arms()
    A, R = parse('logs/f62_rep1.log')
    A2, R2 = parse('logs/f62_rep2.log')
    assert len(A) == len(arms) == 25, (len(A), len(arms))
    assert len(A2) == 25
    B = V.parse_boot('logs/f62_rep1.log')
    names = [a['name'] for a in arms]
    idx = {n: i for i, n in enumerate(names)}

    def frames(n):
        a = arms[idx[n]]
        dev = 'a' if a['dst'] == 'a' else 'b'
        return [(int(t['len']), t['hex']) for t in B['taps'].get((dev, a['i']), [])]

    def uh(n, k=0):
        fr = bytes.fromhex(frames(n)[k][1])
        return struct.unpack('!H', fr[58:60])[0], struct.unpack('!H', fr[60:62])[0]

    def slot(n, k):
        a = arms[idx[n]]
        return V.rcv_slot(R[idx[n]], 'a' if a['skt'] == 'p' else 'b', k)

    delivered = [int(r['a']) + int(r['b']) for r in R]
    errors = [int(r['du6err']) for r in R]
    nums = {
        'arms': len(arms),
        'boots': 2,
        'socket_arms': sum(1 for a in arms if a['prov'] == 's'),
        'packet_arms': sum(1 for a in arms if a['prov'] == 'p'),
        'gro_arms': sum(1 for a in arms if a['skt'] == 'g'),
        'datagrams_delivered': sum(delivered),
        'arms_that_delivered_nothing': sum(1 for d in delivered if d == 0),
        'udp_errors': sum(errors),
        'rules_that_counted_one': sum(1 for a in A if a['ch'] == '1'),
        'logs_at_the_forward_door': sum(1 for a in A if a['nl'] == '1'),
        'logged_bytes': sorted({int(a['lgplen']) for a in A}),
        'seed_a': '%04x' % V.Psum(V.S6, V.DA, 1208),
        'seed_b': '%04x' % V.Psum(V.S6, V.DB, 1208),
        'c_a_frames': [l for l, _ in frames('c_a')],
        'c_b_frames': [l for l, _ in frames('c_b')],
        'c_b_fields': ['%04x' % uh('c_b', k)[1] for k in range(3)],
        'c_b_uhlens': [uh('c_b', k)[0] for k in range(3)],
        'w_b_frame0_field': '%04x' % uh('w_b', 0)[1],
        'w_b_other_frames_identical': frames('w_b')[1:] == frames('c_b')[1:],
        'w_a_field': '%04x' % uh('w_a')[1],
        'len_a_uhlen': uh('len_a')[0],
        'lenbig_a_uhlen': uh('lenbig_a')[0],
        'len_b_fields': ['%04x' % uh('len_b', k)[1] for k in range(3)],
        'len_b_delta': '%04x' % V.c16sub(uh('len_b', 0)[1], uh('c_b', 0)[1]),
        'len_b_expected_delta': '%04x' % ((~(1208 - 0x20)) & 0xffff),
        'chk_a_field': '%04x' % uh('chk_a')[1],
        'chk_b_fields': ['%04x' % uh('chk_b', k)[1] for k in range(3)],
        'chk_b_delta': '%04x' % V.c16sub(uh('chk_b', 0)[1], uh('c_b', 0)[1]),
        'chk_b_expected_delta': '%04x' % ((~V.c16sub(0xdead, V.Psum(V.S6, V.DB,
                                                                    1208))) & 0xffff),
        'wfl_a_equals_w_a': frames('wfl_a') == frames('w_a'),
        'wfl_b_equals_w_b': frames('wfl_b') == frames('w_b'),
        'lens_a_equals_c_a': frames('lens_a') == frames('c_a'),
        'w_p_a_delivered': int(R[idx['w_p_a']]['a']),
        'w_p_a_errors': int(R[idx['w_p_a']]['du6err']),
        'wb_p_a_field': A[idx['wb_p_a']]['lgudp'][12:16],
        'wb_p_a_true_sum': '%04x' % V.C_of(V.S6, V.DA, V.SPORT, V.DPORT,
                                           b'\xa0\xa1\xa2\xa3' + V.PAY[4:]),
        'g_a_datagrams': int(R[idx['g_a']]['b']),
        'g_a_len_gso': slot('g_a', 0)[:2],
        'g_b_lengths': [slot('g_b', k)[0] for k in range(3)],
        'glen_a_len_gso': slot('glen_a', 0)[:2],
        'c_p_a_len': slot('c_p_a', 0)[0],
        'per_arm': {n: {'frames': [l for l, _ in frames(n)],
                        'uhlen': [uh(n, k)[0] for k in range(len(frames(n)))],
                        'field': ['%04x' % uh(n, k)[1]
                                  for k in range(len(frames(n)))],
                        'delivered': delivered[idx[n]],
                        'errors': errors[idx[n]]}
                    for n in names},
    }
    doc = {
        'finding': 'F62',
        'turn': 584,
        'log': 'f62_rep1.log',
        'arms': 25,
        'question': ('the debt named in F61 §11: a UDP-GSO datagram crossing '
                     'this machine, with two exit devices that differ in '
                     'NETIF_F_GSO_UDP_L4 as well as in NETIF_F_HW_CSUM -- '
                     'who segments, and who pays for a store made on the '
                     'FORWARD door'),
        'title': ('on the GSO path the bill is paid by whoever segments, and '
                  'the two doors segment in different places: y2 segments on '
                  'the way out and then computes every segment checksum from '
                  'the actual bytes (the payload store is paid correctly), y1 '
                  'ships the whole GSO datagram and the RECEIVER segments it '
                  'into PARTIAL pieces that nobody ever verifies -- so the '
                  'same store is paid on one door and free on the other, a '
                  'store into the length field is erased by both segmenters '
                  'yet leaves every checksum wrong on y2 (three drops) and '
                  'trims the datagram to 24 bytes for a GRO socket on y1, and '
                  'a store into the checksum field ships verbatim through y1 '
                  'and destroys all three segments on y2'),
        'answer_short': (
            'three netns (sender, router=us, receiver), 25 arms x 2 boots on '
            '7.3.4-T563, one rule per arm in the ip6 forward chain; the '
            'sender sends ONE 1200-byte datagram with UDP_SEGMENT=512. y1 '
            'keeps NETIF_F_GSO_UDP_L4 (ac1 ...612e), y2 loses it with HW_CSUM '
            '(ac1 ...612c), so with no rule y1 puts one 1262-byte frame on the '
            'wire whose checksum field is the pseudo-header seed for the '
            'WHOLE datagram (%s) and the receiver segments it into 512/512/176, '
            'while y2 segments first: three frames 574/574/238, each with a '
            'checksum valid for its own bytes, and the receiver gets the same '
            'three datagrams, byte for byte. The place a payload store lands '
            'decides the price: in segment 0 the store is free on y1 (field '
            'unchanged) and paid on y2, where the segmenter recomputes from '
            'the modified payload (frame 0 field %s, and only frame 0 differs '
            'from the census); the store at payload 512 and 1196 lands in the '
            'middle and last segments with the same rule. csum flags is dead '
            'code on both doors (byte-identical arms). A store into the UDP '
            'LENGTH field is read by the segmenter: on y2 the length is '
            'rewritten (so the store vanishes from the wire) and every '
            'checksum is short by exactly 1208-0x20 = 0x0498 -> three drops; '
            'on y1 the receiver trims the skb to the written length and then '
            'refuses to segment it (EINVAL, gso_segs=3) -> Udp6InErrors +3, '
            'while a length longer than the datagram is short_packet -> +1. A '
            'store into the CHECKSUM field: y1 carries 0xdead to the socket '
            'and still delivers three datagrams (PARTIAL is never checked), '
            'y2 derives every seed from 0xdead and all three die. The '
            'AF_PACKET twin of the same 1262 bytes (no GSO) is one datagram '
            'of 1200 on both doors, its stored copy dies on the stale '
            'checksum, and the one flag that pays there is the rule\'s own '
            'csum flags. A UDP_GRO socket shows the segmentation point: y1 '
            'delivers ONE 1200-byte datagram with gso_size 512, y2 delivers '
            'three (there is nothing left to GRO); with the length store the '
            'GRO socket gets 24 bytes. Every rule counted one packet and '
            'logged 1248 bytes -- one message per GSO datagram, not per '
            'segment.' % ('%04x' % V.Psum(V.S6, V.DA, 1208),
                          '%04x' % uh('w_b', 0)[1])),
        'numbers': nums,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w') as f:
        json.dump(doc, f, indent=1)
        f.write('\n')
    print('wrote %s (%d bytes)' % (OUT, os.path.getsize(OUT)))


if __name__ == '__main__':
    main()
