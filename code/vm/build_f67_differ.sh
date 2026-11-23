#!/bin/bash
# build_f67_differ.sh -- assemble and compile the turn-589 instrument (F67).
#
# differ589.c is GENERATED: differ588.c (the F66 instrument) with its main()
# renamed to f588_entry, seven surgical patches, plus vm/differ589_add.c, which
# supplies the new main(), modes `dflt` and `cond`.
#
# The patches:
#   1. F589_FPAY: the filler's own payload buffer (first byte >= 0x80), so the
#      receiver can count the two flows apart.
#   2. the child's 'f' command: send the filler from the same socket.
#   3. F67 DEFRB: the receive buffer this socket is BORN with, read back once,
#      instead of assuming it.
#   4. 'v' with rb = -1 asks for the true default (SO_RCVBUF(default/2) gives
#      max(2v, ...) = the default; F66's rb = 0 meant "leave the previous one",
#      which silently carried three arms over from the arm before).
#   5. nf / nt: datagrams the receiver got with payload byte 0 >= 0x80 (the
#      filler) or < 0x80 (the test), counted in the receive loop.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f588_entry(int argc, char **argv)/' \
	vm/differ588.c > vm/differ589.c
grep -q '^int f588_entry' vm/differ589.c || { echo "RENAME_FAIL"; exit 1; }
python3 - <<'PY'
p = "/work/kernel-sec/vm/differ589.c"
s = open(p).read()

def sub1(old, new, tag):
    global s
    n = s.count(old)
    assert n == 1, "%s: count=%d" % (tag, n)
    s = s.replace(old, new)

def subfn(fn, old, new, tag):
    """replace inside one function body only"""
    global s
    i0 = s.index(fn)
    i1 = s.index("\n/* ---------- ", i0)
    body = s[i0:i1]
    n = body.count(old)
    assert n == 1, "%s: count=%d" % (tag, n)
    s = s[:i0] + body.replace(old, new) + s[i1:]

sub1("static unsigned char F587_PAY[F587_ND][F587_MAXPL];",
     "static unsigned char F587_PAY[F587_ND][F587_MAXPL];\n"
     "/* F67: the filler's payload -- byte 0 in [0xE0,0xFF], so the receiver can\n"
     " * tell a filler datagram from a test datagram by its first byte alone. */\n"
     "static unsigned char F589_FPAY[F587_ND][F587_MAXPL];\n"
     "static int f589_def;\t\t/* SO_RCVBUF this socket was born with */",
     "fpay")

sub1("\t\tF587_PAY[i][0] = (unsigned char)i;\n\t}\n",
     "\t\tF587_PAY[i][0] = (unsigned char)i;\n\t}\n"
     "\tfor (i = 0; i < F587_ND; i++) {\n\t\tint k;\n\n"
     "\t\tfor (k = 0; k < F587_MAXPL; k++)\n"
     "\t\t\tF589_FPAY[i][k] = (unsigned char)(0x40 + (k & 0x3f));\n"
     "\t\tF589_FPAY[i][0] = (unsigned char)(0xE0 | (i & 0x1f));\n\t}\n",
     "fpay_init")

subfn("static void f587_child_s(void)",
      "\t\t\tif (c[0] == 's') {\n"
      "\t\t\t\trc = (int)sendto(s6, F587_PAY[k], (size_t)pl, 0,\n"
      "\t\t\t\t\t\t (struct sockaddr *)&d6,\n"
      "\t\t\t\t\t\t sizeof(d6));\n"
      "\t\t\t} else {",
      "\t\t\tif (c[0] == 's') {\n"
      "\t\t\t\trc = (int)sendto(s6, F587_PAY[k], (size_t)pl, 0,\n"
      "\t\t\t\t\t\t (struct sockaddr *)&d6,\n"
      "\t\t\t\t\t\t sizeof(d6));\n"
      "\t\t\t} else if (c[0] == 'f') {\n"
      "\t\t\t\t/* F67: the filler.  Same socket, the caller's own\n"
      "\t\t\t\t * destination, a payload that starts >= 0x80. */\n"
      "\t\t\t\trc = (int)sendto(s6, F589_FPAY[k], (size_t)pl, 0,\n"
      "\t\t\t\t\t\t (struct sockaddr *)&d6,\n"
      "\t\t\t\t\t\t sizeof(d6));\n"
      "\t\t\t} else {", "filler")

subfn("static void f587_child_d(void)",
     "\t\t\t\t\t (socklen_t)sizeof(gro));\n\t\t}\n\t}\n",
     "\t\t\t\t\t (socklen_t)sizeof(gro));\n\t\t}\n"
     "\t\t/* F67: the buffer this socket is born with, measured, not\n"
     "\t\t * assumed -- F66 wrote 212992 into its document without a\n"
     "\t\t * read-back behind it. */\n"
     "\t\t{\n\t\t\tunsigned int dv = 0;\n"
     "\t\t\tsocklen_t dvl = (socklen_t)sizeof(dv);\n\n"
     "\t\t\tif (s >= 0)\n"
     "\t\t\t\tgetsockopt(s, SOL_SOCKET, SO_RCVBUF, &dv, &dvl);\n"
     "\t\t\tf589_def = (int)dv;\n"
     "\t\t\tprintf(\"F67 DEFRB|def=%d|half=%d\\n\", f589_def,\n"
     "\t\t\t       f589_def >> 1);\n\t\t\tfflush(stdout);\n\t\t}\n\t}\n",
     "defrb")

sub1("\t\tif (c[0] == 'v') {\n\t\t\tint rb = (c[1] << 24) | (c[2] << 16) | (c[3] << 8) | c[4];",
     "\t\tif (c[0] == 'v') {\n\t\t\tint rb = (c[1] << 24) | (c[2] << 16) | (c[3] << 8) | c[4];",
     "vhead")

sub1("\t\t\tif (rb > 0) {\n\t\t\t\tif (s >= 0)\n",
     "\t\t\t/* F67: rb < 0 means the true default */\n"
     "\t\t\tif (rb < 0)\n\t\t\t\trb = f589_def / 2;\n"
     "\t\t\tif (rb > 0) {\n\t\t\t\tif (s >= 0)\n", "vdefault")

subfn("static void f587_child_d(void)",
      "\t\tint idx, att, win, pass, nd[2] = { 0, 0 }, psel, ncnt;",
      "\t\tint idx, att, win, pass, nd[2] = { 0, 0 }, psel, ncnt;\n"
      "\t\tint nfl = 0, nts = 0;\t/* F67: filler and test datagrams */",
      "nfl_decl")

subfn("static void f587_child_d(void)",
      "\t\tmemset(ta, 0, sizeof(ta));\n\t\tt0 = f587_ms();",
      "\t\tmemset(ta, 0, sizeof(ta));\n\t\tnfl = 0;\n\t\tnts = 0;\n"
      "\t\tt0 = f587_ms();", "nfl_reset")

subfn("static void f587_child_d(void)",
      "\t\t\t\t\tgot++;\n",
      "\t\t\t\t\tgot++;\n"
      "\t\t\t\t\tif ((unsigned char)buf[0] >= 0x80)\n"
      "\t\t\t\t\t\tnfl++;\n\t\t\t\t\telse\n"
      "\t\t\t\t\t\tnts++;\n", "nfl_count")

sub1('"rb=%d|lazy=%d\\n",', '"rb=%d|lazy=%d|nf=%d|nt=%d\\n",', "rcvfmt")
sub1("\t\t       t3.n, t4.n, f588_rb, (int)c[6]);",
     "\t\t       t3.n, t4.n, f588_rb, (int)c[6], nfl, nts);", "rcvargs")
open(p, "w").write(s)
print("patches=9")
PY
cat vm/differ589_add.c >> vm/differ589.c
grep -c '^int main(int argc, char \*\*argv)$' vm/differ589.c | grep -qx 1 || { echo "MAIN_COUNT"; exit 1; }
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ589 vm/differ589.c \
	2> logs/f67_gcc.log || { echo "GCC_FAIL"; grep "error:" logs/f67_gcc.log | head -40; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f67_gcc.log || true)"
grep "error:" logs/f67_gcc.log | head -20 || true
ls -la vm/build/differ589
sha256sum vm/build/differ589 vm/differ589.c vm/differ589_add.c
