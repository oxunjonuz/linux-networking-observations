#!/usr/bin/env python3
"""f40_mutate.py <rep1-in> <rep2-in> <outdir> <mutation>

One deliberate fault at a time in a COPY of the two logs.  The harness
verify562_selftest.sh then requires verify562.py to go red on exactly the
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


def setfield(line, key, val):
    parts = line.rstrip("\n").split("|")
    out = []
    for p in parts:
        if p.startswith(key + "="):
            p = key + "=" + val
        out.append(p)
    return "|".join(out) + "\n"


def getfield(line, key):
    for p in line.rstrip("\n").split("|"):
        if p.startswith(key + "="):
            return p.split("=", 1)[1]
    return None


def match(line, **kw):
    if not line.startswith("F562 R|"):
        return False
    for k, v in kw.items():
        if getfield(line, k) != str(v):
            return False
    return True


def mutate(txt, **kw):
    """Apply fn to the first line matching kw; return the new text."""
    def deco(fn):
        lines = txt.splitlines(keepends=True)
        for idx, l in enumerate(lines):
            if match(l, **kw):
                lines[idx] = fn(l)
                return "".join(lines)
        raise SystemExit("no line matching %r" % (kw,))
    return deco


def both(fn):
    def run(t1, t2):
        return fn(t1), fn(t2)
    return run


# ---- read grid -------------------------------------------------------------

@reg("rd_p_live")
def _(t1, t2):
    f = lambda l: setfield(l, "live", "0")
    kw = dict(env="rd.p.bare", off=8, len=1, cand="A")
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


@reg("rd_q_nhoff")
def _(t1, t2):
    f = lambda l: setfield(l, "live", "0")
    return (mutate(t1, env="rd.q.meta", off=8, len=1, cand="B")(f),
            mutate(t2, env="rd.q.meta", off=8, len=1, cand="B")(f))


@reg("rd_cv")
def _(t1, t2):
    f = lambda l: setfield(l, "cv", "0000")
    return (mutate(t1, env="rd.q.meta", off=16, len=4, cand="B")(f),
            mutate(t2, env="rd.q.meta", off=16, len=4, cand="B")(f))


@reg("rd_wire")
def _(t1, t2):
    def f(l):
        h = getfield(l, "whex")
        return setfield(l, "whex", "00" + h[2:])
    return (mutate(t1, env="rd.p.bare", off=8, len=1, cand="A")(f),
            mutate(t2, env="rd.p.bare", off=8, len=1, cand="A")(f))


# ---- pair ------------------------------------------------------------------

@reg("pair_guard")
def _(t1, t2):
    f = lambda l: setfield(l, "live", "0")
    kw = dict(env="pair.q.meta", off=8, len=1, rd=0, wr=1)
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


@reg("pair_wrrd")
def _(t1, t2):
    f = lambda l: setfield(l, "live", "0")
    kw = dict(env="pair.q.meta", off=8, len=1, rd=1, wr=1, first=1)
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


@reg("pair_bytes")
def _(t1, t2):
    def f(l):
        h = getfield(l, "whex")
        assert h[60:62] == "90", h[60:62]
        return setfield(l, "whex", h[:60] + "00" + h[62:])
    kw = dict(env="pair.q.meta", off=16, len=4, rd=1, wr=1, first=0)
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


# ---- transport base --------------------------------------------------------

@reg("ih_read")
def _(t1, t2):
    f = lambda l: setfield(l, "live", "0")
    kw = dict(env="ih.q.meta", off=2, len=2, cand="T")
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


@reg("ih_dead")
def _(t1, t2):
    f = lambda l: setfield(l, "live", "1")
    kw = dict(env="ih.q.bare", off=0, len=2, cand="T")
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


@reg("ih_bytes")
def _(t1, t2):
    def f(l):
        h = getfield(l, "whex")
        return setfield(l, "whex", h[:78] + "00" + h[80:])
    kw = dict(env="ih.q.meta", off=0, len=2, rd=0, wr=1)
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


# ---- ARP in Q-in-Q ---------------------------------------------------------

@reg("arp_guard")
def _(t1, t2):
    f = lambda l: setfield(l, "live", "0")
    kw = dict(env="qarp.qa.meta", off=6, len=2, rd=0, wr=1)
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


@reg("arp_bytes")
def _(t1, t2):
    def f(l):
        h = getfield(l, "whex")
        return setfield(l, "whex", h[:40] + "0800" + h[44:])
    kw = dict(env="qarp.qa.meta", off=6, len=2, rd=0, wr=1)
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


@reg("arp_read")
def _(t1, t2):
    f = lambda l: setfield(l, "live", "0")
    kw = dict(env="qarp.qa.meta", off=10, len=2, cand="A")
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


# ---- provenance / determinism ---------------------------------------------

@reg("ksha")
def _(t1, t2):
    def f(t):
        out = []
        for l in t.splitlines(keepends=True):
            if l.startswith("### sha256:"):
                l = "### sha256: " + "0" * 64 + "\n"
            out.append(l)
        return "".join(out)
    return f(t1), f(t2)


@reg("isha")
def _(t1, t2):
    def f(t):
        out = []
        for l in t.splitlines(keepends=True):
            if l.startswith("### initrd sha256:"):
                l = "### initrd sha256: " + "0" * 64 + "\n"
            out.append(l)
        return "".join(out)
    return f(t1), f(t2)


@reg("done")
def _(t1, t2):
    return t1.replace("F562 DONE", "F562 DNOE"), t2.replace("F562 DONE",
                                                             "F562 DNOE")


@reg("ctl_ipin")
def _(t1, t2):
    f = lambda l: setfield(l, "ipin", "0")
    kw = dict(env="ctl.p")
    return mutate(t1, **kw)(f), mutate(t2, **kw)(f)


@reg("det")
def _(t1, t2):
    f = lambda l: setfield(l, "live", "0")
    kw = dict(env="rd.w.meta", off=4, len=2, cand="A")
    return t1, mutate(t2, **kw)(f)


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: f40_mutate.py r1 r2 outdir mutation")
    r1, r2, out, name = sys.argv[1:]
    t1 = open(r1, "r", errors="replace").read()
    t2 = open(r2, "r", errors="replace").read()
    if name not in MUT:
        raise SystemExit("unknown mutation %r (have %s)" %
                         (name, ",".join(sorted(MUT))))
    a, b = MUT[name](t1, t2)
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "rep1.log"), "w").write(a)
    open(os.path.join(out, "rep2.log"), "w").write(b)
    return 0


if __name__ == "__main__":
    sys.exit(main())
