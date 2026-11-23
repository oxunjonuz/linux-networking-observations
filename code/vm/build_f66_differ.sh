#!/bin/bash
# build_f66_differ.sh -- assemble and compile the turn-588 instrument (F66).
#
# differ588.c is GENERATED: differ587.c (the F65 instrument) with its main()
# renamed to f587_entry, seven surgical patches (the receive-buffer command
# `v`, the lazy reader, the /proc/net/udp6 witness, the egress taps), plus
# vm/differ588_add.c, which supplies the new main(), modes `split` and `cap`.
# Patches inside the F65 receiver are scoped to that function's own body:
# earlier turns carry near-identical blocks (that is how this instrument is
# built), so a file-wide replace is not allowed to guess.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f587_entry(int argc, char **argv)/' \
	vm/differ587.c > vm/differ588.c
grep -q '^int f587_entry' vm/differ588.c || { echo "RENAME_FAIL"; exit 1; }
python3 - <<'PY'
p = "/work/kernel-sec/vm/differ588.c"
s = open(p).read()

def sub1(old, new, tag):
    global s
    n = s.count(old)
    assert n == 1, "%s: count=%d" % (tag, n)
    s = s.replace(old, new)

WHERE = {}

def subreg(old, new, tag):
    global s
    fn = WHERE.get(tag, "static void f587_child_d(void)")
    i0 = s.index(fn)
    i1 = s.index("\n/* ---------- ", i0)
    assert i0 < i1
    body = s[i0:i1]
    n = body.count(old)
    assert n == 1, "%s: count=%d" % (tag, n)
    s = s[:i0] + body.replace(old, new) + s[i1:]

RXQ = '''/* ---------- F66: the effective receive buffer, and what it holds -------- */

static int f588_rb;\t\t/* last effective SO_RCVBUF, read back */

/* /proc/net/udp6 in THIS netns: the queue's own byte account.  Printed as a
 * whole line, so the verifier parses the kernel's number, not mine. */
static void f588_rxq(int idx)
{
\tchar b[8192];
\tchar line[360];
\tint fd, r, i, n = 0, hit = 0;

\tfd = open("/proc/net/udp6", O_RDONLY);
\tif (fd < 0) {
\t\tprintf("F587 RXQ|i=%02d|fd=%d\\n", idx, fd);
\t\treturn;
\t}
\tr = (int)read(fd, b, sizeof(b) - 1);
\tclose(fd);
\tif (r <= 0) {
\t\tprintf("F587 RXQ|i=%02d|r=%d\\n", idx, r);
\t\treturn;
\t}
\tb[r] = 0;
\tfor (i = 0; i <= r; i++) {
\t\tif (i < r && b[i] != '\\n') {
\t\t\tif (n < (int)sizeof(line) - 1)
\t\t\t\tline[n++] = (char)b[i];
\t\t\tcontinue;
\t\t}
\t\tline[n] = 0;
\t\tif (strstr(line, ":1388")) {\t/* port 5000, hex */
\t\t\tprintf("F587 RXQ|i=%02d|line=%s\\n", idx, line);
\t\t\thit = 1;
\t\t}
\t\tn = 0;
\t}
\tif (!hit)
\t\tprintf("F587 RXQ|i=%02d|line=NONE\\n", idx);
\tfflush(stdout);
}

'''

sub1('/* ---------- D: the receiver, with arrival times ------------------------ */',
     RXQ + '/* ---------- D: the receiver, with arrival times ------------------------ */',
     'rxq')

subreg('\t\tmemset(any, 0, sizeof(any));\n\t\ts = f564_udp_bind(AF_INET6, 0, any, F587_DPORT);',
       '\t\t/* F66: the receive buffer is the subject, raise its ceiling first */\n'
       '\t\tf555_sysctl("/proc/sys/net/core/rmem_max", "16777216");\n'
       '\t\tmemset(any, 0, sizeof(any));\n\t\ts = f564_udp_bind(AF_INET6, 0, any, F587_DPORT);',
       'rmem_max')

VBUF = '''\t\tif (c[0] == 'v') {
\t\t\tint rb = (c[1] << 24) | (c[2] << 16) | (c[3] << 8) | c[4];
\t\t\tunsigned int got = 0;
\t\t\tsocklen_t gl = (socklen_t)sizeof(got);

\t\t\tif (rb > 0) {
\t\t\t\tif (s >= 0)
\t\t\t\t\tsetsockopt(s, SOL_SOCKET, SO_RCVBUF,
\t\t\t\t\t\t   &rb, (socklen_t)sizeof(rb));
\t\t\t\tif (sg >= 0)
\t\t\t\t\tsetsockopt(sg, SOL_SOCKET, SO_RCVBUF,
\t\t\t\t\t\t   &rb, (socklen_t)sizeof(rb));
\t\t\t}
\t\t\tif (s >= 0)
\t\t\t\tgetsockopt(s, SOL_SOCKET, SO_RCVBUF, &got, &gl);
\t\t\tf588_rb = (int)got;
\t\t\tprintf("F587 RBUF|rb=%d|eff=%u\\n", rb, got);
\t\t\tfflush(stdout);
\t\t\tc[0] = 'D';
\t\t\tif (write(F585_C.up[1], c, 1) != 1)
\t\t\t\t_exit(8);
\t\t\tcontinue;
\t\t}
'''
subreg("\t\tif (c[0] != 'r')\n\t\t\tcontinue;",
       VBUF + "\t\tif (c[0] != 'r')\n\t\t\tcontinue;", 'vbuf')

subreg('\t\tt0 = f587_ms();',
       '\t\tt0 = f587_ms();\n'
       '\t\t/* F66: a lazy reader lets the burst finish first, so what it\n'
       '\t\t * reads is the queue own budget and not the reader pace */\n'
       '\t\tif (c[6]) {\n'
       '\t\t\tusleep((useconds_t)c[6] * 10000);\n'
       '\t\t\tf588_rxq(idx);\n'
       '\t\t}', 'lazy')

subreg('"hdr=%lld|disc=%lld|nop=%lld|t3=%d|t4=%d\\n",',
       '"hdr=%lld|disc=%lld|nop=%lld|t3=%d|t4=%d|"\n\t\t       "rb=%d|lazy=%d\\n",',
       'rcvfmt')

subreg('\t\t       t3.n, t4.n);\n\t\tcwp[0] = cw[0];',
       '\t\t       t3.n, t4.n, f588_rb, (int)c[6]);\n\t\tcwp[0] = cw[0];',
       'rcvargs')

i0 = s.index("static int f587_setup(void)")
i1 = s.index("\nstatic void f587_shutdown", i0)
assert s[i0:i1].count('\tF585_TA.fd = -1;\n\tF585_TB.fd = -1;') == 1
sb = s[i0:i1]
s = s[:i0] + sb.replace(
     '\tF585_TA.fd = -1;\n\tF585_TB.fd = -1;',
     '\t/* F65 fixed the fd and the taps were still empty, for a second reason:\n'
     '\t * these two taps sit on the EGRESS devices y1/y2, where every frame\n'
     '\t * arrives with sll_pkttype == PACKET_OUTGOING, and f585_tap_drain()\n'
     '\t * with only_out == 0 throws exactly those away.  Both causes, fixed. */\n'
     '\tF585_TA.fd = -1;\n\tF585_TB.fd = -1;\n'
     '\tF585_TA.fd = -1;\n\tF585_TB.fd = -1;\n'
     '\tF585_TA.only_out = 1;\n\tF585_TB.only_out = 1;') + s[i1:]

WHERE["sl16"] = "static void f587_child_s(void)"
subreg('\t\tpsel = c[2] & 3;\n\t\tn = c[3];\n\t\tsh = c[4] == 0xff ? -1 : c[4];\n\t\tsl = c[5];',
       '\t\tpsel = c[2] & 3;\n\t\tn = c[3];\n\t\tsh = c[4] == 0xff ? -1 : c[4];\n'
       '\t\t/* F66: the tail length is 16 bits; the high bits ride in c[2] > 1,\n'
       '\t\t * because F65 sent c[5] alone and every tail above 255 arrived as\n'
       '\t\t * (sl & 0xff) bytes -- measured, then fixed. */\n'
       '\t\tsl = ((c[2] >> 2) << 8) | c[5];', 'sl16')
open(p, "w").write(s)
print("patches=8")
PY
cat vm/differ588_add.c >> vm/differ588.c
grep -c '^int main(int argc, char \*\*argv)$' vm/differ588.c | grep -qx 1 || { echo "MAIN_COUNT"; exit 1; }
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ588 vm/differ588.c \
	2> logs/f66_gcc.log || { echo "GCC_FAIL"; grep "error:" logs/f66_gcc.log | head -40; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f66_gcc.log || true)"
grep "error:" logs/f66_gcc.log | head -20 || true
ls -la vm/build/differ588
sha256sum vm/build/differ588 vm/differ588.c vm/differ588_add.c
