#!/usr/bin/env python3
"""f37_mutate.py <log> <rule> -- one surgical edit, for verify559_selftest.sh.

Every rule names the line it edits by its own `|key=value|` fields and states
the change; a rule that cannot find exactly one line is an error, not a silent
no-op (the F35 lesson: three mutations "survived" because they hit nothing).
"""
import sys

RULES = {}


def rule(name, prefix="F559 R"):
    def deco(fn):
        RULES[name] = (prefix, fn)
        return fn
    return deco


def find(lines, prefix, which=0, **kw):
    hits = []
    for i, ln in enumerate(lines):
        if not ln.startswith(prefix):
            continue
        toks = set(ln.split("|"))
        if all(("%s=%s" % (k, v)) in toks for k, v in kw.items()):
            hits.append(i)
    if len(hits) < 1:
        raise SystemExit("rule found no line for %r" % (kw,))
    return hits[which]


def sub1(line, old, new):
    if line.count(old) != 1:
        raise SystemExit("substring %r appears %d times" % (old, line.count(old)))
    return line.replace(old, new, 1)


def hexfield(line, name, fn):
    j = line.index("|%s=" % name) + len(name) + 2
    k = line.find("|", j)
    if k < 0:
        k = len(line)
    return line[:j] + fn(line[j:k]) + line[k:]


@rule("wire_byte")
def _(lines, i):
    lines[i] = hexfield(lines[i], "whex", lambda h: h[:-2] + "07")


@rule("wire_far_byte")
def _(lines, i):
    lines[i] = hexfield(lines[i], "rhex",
                        lambda h: h[:-1] + ("0" if h[-1] != "0" else "1"))


@rule("wire_truncated")
def _(lines, i):
    lines[i] = hexfield(lines[i], "whex", lambda h: h[:-8])


@rule("grid_live_to_dead")
def _(lines, i):
    lines[i] = sub1(lines[i], "|live=1|", "|live=0|")


@rule("grid_dead_to_live")
def _(lines, i):
    lines[i] = sub1(lines[i], "|live=0|", "|live=1|")


@rule("grid_doff_lost")
def _(lines, i):
    lines[i] = sub1(lines[i], "|live=0|", "|live=1|")


@rule("grid_wrong_offset")
def _(lines, i):
    lines[i] = hexfield(lines[i], "whex", lambda h: h[:40] + "90" + h[42:])


@rule("set_rc", prefix="F559 SET")
def _(lines, i):
    lines[i] = sub1(lines[i], "|rc=0|", "|rc=-95|")


@rule("set_bit_stayed", prefix="F559 FEAT")
def _(lines, i):
    lines[i] = sub1(lines[i], "|act_tx=0|", "|act_tx=1|")


@rule("nwords", prefix="F559 FEAT")
def _(lines, i):
    lines[i] = sub1(lines[i], "|nwords=2|", "|nwords=3|")


@rule("chain_b_et_alive", prefix="F559 C")
def _(lines, i):
    lines[i] = sub1(lines[i], "|live=0|", "|live=1|")


@rule("chain_a_none_bytes", prefix="F559 C")
def _(lines, i):
    lines[i] = hexfield(lines[i], "whex", lambda h: h.replace("1f90", "1f91"))


@rule("mode_exit")
def _(lines, i=None):
    for k, ln in enumerate(lines):
        if ln.startswith("=== MODE_EXIT"):
            lines[k] = ln.replace("=0 ===", "=139 ===")
            return
    raise SystemExit("no MODE_EXIT line")


@rule("kernel_sha")
def _(lines, i=None):
    for k, ln in enumerate(lines):
        if ln.startswith("### sha256: "):
            lines[k] = "### sha256: " + "0" * 64
            return
    raise SystemExit("no kernel sha line")


@rule("splat")
def _(lines, i=None):
    lines.append("[    1.000000] WARNING: injected splat for the selftest")


# (rule, prefix, how to find the line)
WHERE = {
    "wire_byte": dict(state="clear", arm="s16_2", env="wire"),
    "wire_far_byte": dict(state="clear", arm="s14_99", env="wire"),
    "wire_truncated": dict(state="clear", arm="ctl", env="wire"),
    "grid_live_to_dead": dict(state="clear", arm="g0_1", env="p6T"),
    "grid_dead_to_live": dict(state="clear", arm="g24_4", env="uT"),
    "grid_doff_lost": dict(state="clear", arm="g12_2", env="p6P"),
    "grid_wrong_offset": dict(state="clear", arm="g0_1", env="uP"),
    "set_rc": dict(stage="clear", valid="00000080"),
    "set_bit_stayed": dict(stage="clear", dev="r1"),
    "nwords": dict(stage="init", dev="s0"),
    "chain_b_et_alive": dict(arm="b_et"),
    "chain_a_none_bytes": dict(arm="a_none"),
    "mode_exit": dict(),
    "kernel_sha": dict(),
    "splat": dict(),
}


WHICH = {"set_rc": -1, "set_bit_stayed": 0}


def main():
    path, name = sys.argv[1], sys.argv[2]
    if name not in RULES:
        raise SystemExit("unknown rule %r" % name)
    prefix, fn = RULES[name]
    txt = open(path, "rb").read().decode("latin-1").split("\n")
    kw = WHERE[name]
    if kw:
        fn(txt, find(txt, prefix, which=WHICH.get(name, 0), **kw))
    else:
        fn(txt)
    open(path, "wb").write("\n".join(txt).encode("latin-1"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
