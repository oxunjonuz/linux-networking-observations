#!/usr/bin/env python3
"""f39_mutate.py <rep1-in> <rep2-in> <outdir> <mutation>

One deliberate fault at a time in a COPY of the two logs.  The harness
verify561_selftest.sh then requires verify561.py to go red on exactly the
check that fault belongs to.
"""
import os
import sys

MUT = {}


def reg(name):
    def deco(fn):
        MUT[name] = fn
        return fn
    return deco


def lines(txt):
    return txt.splitlines(keepends=True)


def find(txt, needle):
    for i, l in enumerate(txt.splitlines()):
        if needle in l:
            return i
    raise SystemExit("no line with %r" % needle)


def setfield(line, key, val):
    parts = line.rstrip("\n").split("|")
    out = []
    for p in parts:
        if p.startswith(key + "="):
            p = key + "=" + val
        out.append(p)
    return "|".join(out) + "\n"


@reg("ll_p_live")
def _(txt):
    ls = lines(txt)
    i = find(txt, "F561 R|env=ll.p|arm=g8_1|")
    ls[i] = ls[i].replace("|live=1|", "|live=0|", 1)
    return "".join(ls)


@reg("ll_p_wire")
def _(txt):
    """One byte of the wire hex of a live cell."""
    ls = lines(txt)
    i = find(txt, "F561 R|env=ll.p|arm=g8_1|")
    line = ls[i]
    k = line.index("|whex=") + len("|whex=")
    end = line.find("|", k)
    h = line[k:end]
    ls[i] = line[:k] + h[:22] + "91" + h[24:] + line[end:]
    return "".join(ls)


@reg("ll_q_16_2")
def _(txt):
    ls = lines(txt)
    i = find(txt, "F561 R|env=ll.q|arm=g16_2|")
    ls[i] = ls[i].replace("|live=1|", "|live=0|", 1)
    return "".join(ls)


@reg("meta_q")
def _(txt):
    ls = lines(txt)
    i = find(txt, "F561 M|env=meta|rep=q|want=0800|")
    j = find(txt, "F561 M|env=meta|rep=q|want=8100|")
    ls[i] = setfield(ls[i], "live", "0")
    ls[j] = setfield(ls[j], "live", "1")
    return "".join(ls)


@reg("unlock_qmeta")
def _(txt):
    ls = lines(txt)
    i = find(txt, "F561 R|env=unlock.q.meta|arm=g8_1|")
    ls[i] = ls[i].replace("|live=1|", "|live=0|", 1)
    return "".join(ls)


@reg("xmit_b88")
def _(txt):
    ls = lines(txt)
    i = find(txt, "F561 R|env=xmit.B_01.p88a8|")
    ls[i] = setfield(ls[i], "whex", "ffffffffffffaabbcc00006688a80064" + "00" * 0)
    return "".join(ls)


@reg("far_q")
def _(txt):
    ls = lines(txt)
    i = find(txt, "F561 FAR|rep=q|")
    line = ls[i]
    hexf = "rhex="
    k = line.index(hexf) + len(hexf)
    end = line.find("|", k)
    if end < 0:
        end = line.find("\n", k)
    h = line[k:end]
    ls[i] = line[:k] + h[8:] + line[end:]
    return "".join(ls)


@reg("far_wire")
def _(txt):
    """The far tap of the one-tag frame loses its last four bytes."""
    ls = lines(txt)
    i = find(txt, "F561 FAR|rep=w|")
    line = ls[i]
    k = line.index("rhex=") + len("rhex=")
    end = line.find("\n", k)
    h = line[k:end]
    ls[i] = line[:k] + h[8:] + line[end:]
    return "".join(ls)


@reg("ll_ipin")
def _(txt):
    ls = lines(txt)
    i = find(txt, "F561 R|env=ll.p|arm=ctl|")
    ls[i] = setfield(ls[i], "ipin", "7")
    return "".join(ls)


@reg("ndin_ctl_ipin")
def _(txt):
    ls = lines(txt)
    i = find(txt, "F561 R|env=ndin.q|arm=ctl|")
    ls[i] = setfield(ls[i], "ipin", "3")
    return "".join(ls)


@reg("ndin_double")
def _(txt):
    ls = lines(txt)
    i = find(txt, "F561 R|env=ndin.q|arm=g0_2|")
    ls[i] = setfield(ls[i], "live", "2")
    return "".join(ls)


@reg("ksha")
def _(txt):
    ls = lines(txt)
    for i, l in enumerate(ls):
        if l.startswith("### sha256:"):
            ls[i] = "### sha256: " + "0" * 64 + "\n"
            break
    return "".join(ls)


@reg("isha")
def _(txt):
    ls = lines(txt)
    for i, l in enumerate(ls):
        if l.startswith("### initrd sha256:"):
            ls[i] = "### initrd sha256: " + "0" * 64 + "\n"
            break
    return "".join(ls)


@reg("done")
def _(txt):
    return "".join(l for l in lines(txt) if "F561 DONE" not in l)


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    a, b, outdir, mut = sys.argv[1:]
    if mut not in MUT:
        raise SystemExit("unknown mutation %r" % mut)
    os.makedirs(outdir, exist_ok=True)
    ta = open(a, errors="replace").read()
    tb = open(b, errors="replace").read()
    open(os.path.join(outdir, "rep1.log"), "w").write(MUT[mut](ta))
    open(os.path.join(outdir, "rep2.log"), "w").write(MUT[mut](tb))


if __name__ == "__main__":
    main()
