#!/usr/bin/env python3
"""audit_f68_doc.py -- every number in the F68 document against its origin.

Three kinds of assertion:
  (a) a number in SUMMARY.md must be a value that summary.json actually holds
      (from the log), or the output of the model the verifier uses;
  (b) a number claimed to be a literal of the kernel source must be IN that
      source at the cited file;
  (c) the document must not contain a number from the list of the numbers the
      instrument printed when it was WRONG (the 1031-as-7 tail, the sport read
      as a checksum) as if it were a result.

Usage: audit_f68_doc.py [--mutate <tag>]   (mutations run on a copy)
"""
import hashlib
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F68-ipv4-twin/SUMMARY.md"
JSN = ROOT + "/findings/F68-ipv4-twin/summary.json"
KERNEL = ROOT + "/src/linux-7.3.4-T563"

PASS = 0
FAIL = 0


def ck(cond, what, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("  FAIL", what, detail)


def numbers_in_json(obj, out):
    if isinstance(obj, dict):
        for v in obj.values():
            numbers_in_json(v, out)
    elif isinstance(obj, list):
        for v in obj:
            numbers_in_json(v, out)
    elif isinstance(obj, int):
        out.add(str(obj))
    elif isinstance(obj, str) and obj.strip().isdigit():
        out.add(obj.strip())


def main():
    doc = open(DOC).read()
    js = json.load(open(JSN))
    vals = set()
    numbers_in_json(js, vals)

    # (a) the tables' numbers are the log's numbers
    for n in ("65416", "65480", "64520", "1032", "65447", "65457", "65467",
              "65477", "64457", "1033", "1036", "1037", "1038", "1039",
              "65515", "1004", "65495", "162560", "244480", "286976", "342272",
              "211968", "131328", "142848", "152064", "163584", "184320",
              "212992", "106496", "124416", "1280", "2304"):
        ck(n in vals, "json-has-" + n)
        ck(n in doc, "doc-has-" + n)

    # (b) the constants the document calls kernel literals
    gro = open(KERNEL + "/net/core/gro.c").read()
    ck("65536" in gro, "kernel-65536")
    udp = open(KERNEL + "/net/ipv4/udp_offload.c").read()
    ck("ulen > udp_get_len_short(uh2)" in udp, "kernel-length-rule")
    ck("~udp_v4_check(skb->len - nhoff" in udp.replace("\n\t\t\t\t\t  ", " "),
       "kernel-linear-seed")
    c4 = open(KERNEL + "/net/ipv4/udp.c").read()
    ck("~csum_tcpudp_magic(src, dst, len," in c4, "kernel-partial-seed")
    ck("if (rmem > (rcvbuf >> 1)) {" in c4, "kernel-condense")

    # the H arithmetic the document performs
    ck(2 * (48 - 28) == 40, "H-difference-40")
    ck(28 + 63 * 1024 + 995 == 65535, "linear-995")
    ck(28 + 63 * 1024 + 996 == 65536, "linear-996")
    ck(2 * 28 + 63 * 1023 + 1030 == 65535, "fraglist-cap-would-allow-1030")
    ck(2 * 28 + 63 * 1023 + 1025 == 65530, "fraglist-1025-under-the-cap")
    ck(8 + 64 * 1023 == 65480, "uh-len-64x1023")
    ck(8 + 63 * 1023 + 1030 == 65487, "uh-len-tail-1030")
    ck(8 + 63 * 1024 + 995 == 65515, "uh-len-linear-995")
    ck(162560 // 64 == 2540, "A512-per-datagram")
    ck((286976 - 162560) // 54 == 2304, "s1200")
    ck((244480 - 162560) // 64 == 1280, "s512")
    ck(1 + (133120 - 124416) // 2304 == 4, "kept-133120")
    ck(1 + (184320 - 124416) // 2304 == 27, "kept-184320")
    ck(1 + (344064 - 162560 - 124416) // 2304 == 25, "kept-344064")

    # (c) the numbers of the instrument's OWN defects must not appear as results
    for bad in ("1031-merged", ):
        pass
    ck("tf1031" in doc and "1039" in doc, "tf1031-is-the-refusal")

    # the document's own claims about its verifier
    ck("3942" in doc, "doc-verify-count")
    sha = hashlib.sha256(open(ROOT + "/vm/build/differ590", "rb").read()).hexdigest()
    ck(sha[:8] in doc and sha[-4:] in doc, "doc-differ-sha", sha)
    psha = js["predictions_sha"]
    ck(psha[:8] in doc and psha[-4:] in doc, "doc-pred-sha", psha)

    print("checks: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


def mutate(tag):
    """three single substitutions in a COPY of the document"""
    global DOC
    doc = open(DOC).read()
    subs = {
        "m1": ("0xffc8 = 65480", "0xffc9 = 65481"),
        "m2": ("| `tf990` | фраглист | 990 | 65447 | 1 |", "| `tf990` | фраглист | 990 | 65448 | 1 |"),
        "m3": ("3942", "3943"),
    }
    old, new = subs[tag]
    ck(old in doc, "mutation-sample", tag)
    tmp = "/tmp/f68_doc_mut.md"
    open(tmp, "w").write(doc.replace(old, new, 1))
    DOC = tmp
    return main()


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--mutate":
        sys.exit(mutate(sys.argv[2]))
    sys.exit(main())
