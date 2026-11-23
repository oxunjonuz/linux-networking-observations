/* ================= turn 593 (F71) =======================================
 *
 * The debt of F70, in its own words: clause 1 of skb_condense()
 *
 *     if (skb->data_len) {
 *             if (skb->data_len > skb->end - skb->tail ||
 *                 skb_cloned(skb) || !skb_frags_readable(skb))
 *                     return;
 *             __pskb_pull_tail(skb, skb->data_len);
 *     }
 *     skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
 *
 * never fired: 36 attempts, __pskb_pull_tail 0 calls, because no skb with
 * data_len > 0 ever reached the enqueue gate.  This instrument builds one.
 *
 * Three source readings decide the arms (research/predictions_593.md §1):
 *
 *  (a) include/linux/udp.h:214, udp_unexpected_gso(): a packet whose gso_type
 *      has SKB_GSO_FRAGLIST is "unexpected" unless the socket has
 *      ACCEPT_FRAGLIST, and UDP_GRO (net/ipv4/udp.c:3019) sets only
 *      ACCEPT_L4.  ACCEPT_FRAGLIST is set by udp_allow_gso(), which only
 *      tunnel sockets (vxlan/geneve/bareudp) call.  So the fraglist aggregate
 *      CANNOT be delivered whole to a user UDP_GRO socket -- it is segmented
 *      exactly as on a plain one.  That is P1, a claim that can lose.
 *
 *  (b) net/core/gro.c, skb_gro_receive(): when the head is head_frag (the veth
 *      RX skb is), the incoming data is parked in page frags and
 *      p->data_len += skb_gro_len() -- the PAYLOAD only.  The linear
 *      rx-udp-gro-forwarding door therefore yields an aggregate with
 *      data_len > 0 and gso_type SKB_GSO_UDP_L4, which the UDP_GRO socket
 *      accepts whole.  That is the skb clause 1 needs.
 *
 *  (c) net/core/skbuff.c:7131: the comparison is with the HEAD's tailroom,
 *      end - tail, and __pskb_pull_tail(skb, data_len) with data_len ==
 *      end - tail needs no expansion (eat = tail + delta - end = 0).
 *
 * So the boundary is a byte: a head of 512 (end 704, tail 556, tailroom 148)
 * pulls a 148-byte tail and returns on 149; a head of 200 (384/244/140) pulls
 * 140 and returns on 141; a head of 1200 (1728/1244/484, predicted) pulls 484
 * and returns on 485.
 *
 * Probes (5), all with fetchargs at the offsets pahole reads out of the
 * booting vmlinux's DWARF, plus the kernel's own echo of each definition:
 *
 *   f593cond  skb_condense            len dlen tail end ts fl
 *   f593enq   __udp_enqueue_schedule_skb   same six -- THE GATE, so the whole
 *             aggregate's geometry is measured even when condense is not
 *             called (below half a buffer)
 *   f593pull  __pskb_pull_tail        eat=%si  -- how many bytes it moved
 *   f593seg   skb_segment_list
 *   f593trim  ___pskb_trim
 *
 * The queue is put at an exact position by a filler sent ONE DATAGRAM AT A
 * TIME, 250 ms apart, to the SAME port as the test, so it never aggregates
 * and rmem == j * 1280 exactly.
 *
 * Topology, veths, netns and the sender are F68/F69/F70's unchanged
 * (f591_setup).  The receiver is new (f593_child_d): two sockets, 5000 plain
 * and 5001 with UDP_GRO, both drained and measured per port.
 */

#include <sys/mount.h>

#define F593_TRC	"/sys/kernel/tracing"
#define F593_TRCD	"/sys/kernel/debug/tracing"
#define F593_GAP	250000		/* us between filler datagrams */

/* field offsets of struct sk_buff in THIS kernel, from
 *   pahole -C sk_buff vmlinux   (DWARF5, the bytes that boot).
 * sizeof(struct sk_buff) = 232, so SKB_DATA_ALIGN() = 256: the truesize a
 * merged datagram gives up in skb_gro_receive(). */
#define F593_O_LEN	112
#define F593_O_DLEN	116
#define F593_O_TAIL	188
#define F593_O_END	192
#define F593_O_TS	216
#define F593_O_FL	126

struct f593_arm {
	const char *name;
	char xg;	/* GRO at x0: 'u' linear (udp_fwd), 'f' fraglist */
	char skt;	/* the test's socket at D: 'g' UDP_GRO 5001, 'p' plain 5000 */
	int j;		/* filler datagrams, one at a time, F593_GAP apart */
	int n;		/* test datagrams, back to back */
	int pl;		/* test payload length */
	int sh;		/* short-tail index, -1 none */
	int sl;		/* its payload length */
	int rcvbuf;	/* SO_RCVBUF request (sk_rcvbuf becomes 2x this) */
	int tap;	/* 1: keep the parent's y1/y2 taps open during the arm */
	int exp_enq;	/* expected enqueues */
	int exp_cond;	/* expected calls of skb_condense */
	int exp_pull;	/* expected calls of __pskb_pull_tail */
	int exp_seg;	/* expected calls of skb_segment_list */
	int exp_dl;	/* expected data_len at the first enqueue, -1 any */
	int exp_charge;	/* expected queue growth, -1 any */
};

/* rcvbuf 19200 -> sk_rcvbuf 38400 -> half 19200; 16 filler datagrams = 20480,
 * one more than the half; 13 would be 16640.  The paged aggregate of six 512s
 * costs 1280 + 5*(1280-256) = 6400, so 20480 + 6400 fits in 38400. */
static const struct f593_arm AF593[] = {
	/* name        xg skt   j   n    pl sh   sl rcvbuf tap enq cond pull seg dl charge */
	{ "g_pg6_lo",  'u', 'g',  0,  6,  512, -1,   0, 19200, 0,  1,   0,   0,  0, 2560,  7680 },
	{ "g_pg6_gt",  'u', 'g', 16,  6,  512, -1,   0, 19200, 0,  1,   1,   0,  0, 2560,  7680 },
	{ "g_t512_147",'u', 'g', 16,  2,  512,  1, 147, 19200, 0,  1,   1,   1,  0,  147,  1280 },
	{ "g_t512_148",'u', 'g', 16,  2,  512,  1, 148, 19200, 0,  1,   1,   1,  0,  148,  1280 },
	{ "g_t512_149",'u', 'g', 16,  2,  512,  1, 149, 19200, 0,  1,   1,   0,  0,  149,  2240 },
	{ "g_t512_147t",'u','g', 16,  2,  512,  1, 147, 19200, 1,  1,   1,   0,  0,  147,  2240 },
	{ "g_t512_lo", 'u', 'g',  0,  2,  512,  1, 148, 19200, 0,  1,   0,   0,  0,  148,  2240 },
	{ "g_t200_139",'u', 'g', 16,  2,  200,  1, 139, 19200, 0,  1,   1,   1,  0,  139,   960 },
	{ "g_t200_140",'u', 'g', 16,  2,  200,  1, 140, 19200, 0,  1,   1,   1,  0,  140,   960 },
	{ "g_t200_141",'u', 'g', 16,  2,  200,  1, 141, 19200, 0,  1,   1,   0,  0,  141,  1920 },
	{ "g_t1200_483",'u','g', 16,  2, 1200,  1, 483, 19200, 0,  1,   1,   1,  0,  483,  2304 },
	{ "g_t1200_484",'u','g', 16,  2, 1200,  1, 484, 19200, 0,  1,   1,   1,  0,  484,  2304 },
	{ "g_t1200_485",'u','g', 16,  2, 1200,  1, 485, 19200, 0,  1,   1,   0,  0,  485,  3584 },
	{ "g_fl_gro",  'f', 'g', 16,  6,  512, -1,   0, 19200, 0,  6,   6,   0,  1,   0,  7680 },
	{ "g_fl_pl",   'f', 'p', 16,  6,  512, -1,   0, 19200, 0,  6,   6,   0,  1,   0,  7680 },
	{ "g_pg_pl",   'u', 'p', 16,  6,  512, -1,   0, 19200, 0,  6,   6,   0,  0,   0,  7680 },
	{ "g_pg1_gro", 'u', 'g', 16,  1,  512, -1,   0, 19200, 0,  1,   1,   0,  0,   0,  1280 },
	{ "g_pg6_eq2", 'u', 'g', 16,  6,  512, -1,   0, 19200, 0,  1,   1,   0,  0, 2560,  7680 },
};

static int F593_T_ok;
static const char *F593_T = F593_TRC;

static const char *f593_p(const char *suffix)
{
	static char b[4][192];
	static int r;
	char *p = b[r++ & 3];

	snprintf(p, sizeof(b[0]), "%s%s", F593_T, suffix);
	return p;
}

static int f593_wf(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);
	int r;

	if (fd < 0)
		return -1;
	r = (int)write(fd, s, strlen(s));
	close(fd);
	return r < 0 ? -1 : 0;
}

static int f593_rf(const char *path, char *buf, int cap)
{
	int fd = open(path, O_RDONLY);
	int got = 0;

	if (fd < 0)
		return -1;
	for (;;) {
		int r = (int)read(fd, buf + got, (size_t)(cap - 1 - got));

		if (r <= 0)
			break;
		got += r;
		if (got >= cap - 1)
			break;
	}
	close(fd);
	buf[got] = 0;
	return got;
}

/* every probe this turn needs; the kernel echoes each definition back and the
 * echo is printed verbatim (the provenance of the offsets is the kernel's,
 * not mine) */
static int f593_probe_up(void)
{
	char b[512];
	int i;

	mkdir(F593_TRC, 0755);
	if (mount("none", F593_TRC, "tracefs", 0, NULL) && errno != EBUSY) {
		mkdir("/sys/kernel/debug", 0755);
		(void)mount("none", "/sys/kernel/debug", "debugfs", 0, NULL);
		if (access(F593_TRCD "/kprobe_events", W_OK) == 0)
			F593_T = F593_TRCD;
	}
	if (access(f593_p("/kprobe_events"), W_OK)) {
		printf("F593 PROBE|ok=0|errno=%d|path=%s\n", errno, F593_T);
		return -1;
	}
	(void)f593_wf(f593_p("/tracing_on"), "0");
	(void)f593_wf(f593_p("/kprobe_events"), "\n");
	snprintf(b, sizeof(b),
		 "p:f593cond skb_condense len=+%d(%%di):u32 dlen=+%d(%%di):u32 "
		 "tail=+%d(%%di):u32 end=+%d(%%di):u32 ts=+%d(%%di):u32 "
		 "fl=+%d(%%di):u8\n",
		 F593_O_LEN, F593_O_DLEN, F593_O_TAIL, F593_O_END, F593_O_TS,
		 F593_O_FL);
	if (f593_wf(f593_p("/kprobe_events"), b)) {
		printf("F593 PROBE|ok=0|why=cond\n");
		return -1;
	}
	snprintf(b, sizeof(b),
		 "p:f593enq __udp_enqueue_schedule_skb len=+%d(%%si):u32 "
		 "dlen=+%d(%%si):u32 tail=+%d(%%si):u32 end=+%d(%%si):u32 "
		 "ts=+%d(%%si):u32 fl=+%d(%%si):u8\n",
		 F593_O_LEN, F593_O_DLEN, F593_O_TAIL, F593_O_END, F593_O_TS,
		 F593_O_FL);
	if (f593_wf(f593_p("/kprobe_events"), b)) {
		printf("F593 PROBE|ok=0|why=enq\n");
		return -1;
	}
	(void)f593_wf(f593_p("/kprobe_events"),
		      "p:f593pull __pskb_pull_tail eat=%si:s32\n");
	(void)f593_wf(f593_p("/kprobe_events"), "p:f593seg skb_segment_list\n");
	(void)f593_wf(f593_p("/kprobe_events"), "p:f593trim ___pskb_trim\n");
	(void)f593_wf(f593_p("/kprobe_events"), "p:f593clone skb_clone\n");
	(void)f593_wf(f593_p("/kprobe_events"), "p:f593exp pskb_expand_head\n");
	{
		static const char *ev[] = { "f593cond", "f593enq", "f593pull",
					    "f593seg", "f593trim", "f593clone",
					    "f593exp" };
		int ok = 0;

		for (i = 0; i < 7; i++) {
			char p[128];

			snprintf(p, sizeof(p), "%s/events/kprobes/%s/enable",
				 F593_T, ev[i]);
			if (f593_wf(p, "1") == 0)
				ok |= 1 << i;
		}
		printf("F593 PROBE|ok=%d|mask=%02x|path=%s|"
		       "off=%d,%d,%d,%d,%d,%d\n",
		       ok == 0x7f ? 1 : 0, ok, F593_T, F593_O_LEN, F593_O_DLEN,
		       F593_O_TAIL, F593_O_END, F593_O_TS, F593_O_FL);
		if (ok != 0x7f)
			return -1;
	}
	{
		/* 4 KiB: five definitions do not fit in 256 bytes, and a
		 * truncated echo is a witness that lies about its own size
		 * (F40 #2, F50 #5, F70 #3) */
		static char kb[4096];
		char *nl = kb;
		int k = 0;

		kb[0] = 0;
		if (f593_rf(f593_p("/kprobe_events"), kb, (int)sizeof(kb)) > 0) {
			while (*nl && k < 10) {
				char *e = strchr(nl, '\n');
				char line[300];

				if (e)
					*e = 0;
				snprintf(line, sizeof(line), "%s", nl);
				if (line[0])
					printf("F593 DEF|%s\n", line);
				k++;
				if (!e)
					break;
				nl = e + 1;
			}
		}
	}
	(void)f593_wf(f593_p("/trace"), "\n");
	(void)f593_wf(f593_p("/tracing_on"), "1");
	F593_T_ok = 1;
	return 0;
}

static void f593_mark(const char *what)
{
	if (F593_T_ok)
		(void)f593_wf(f593_p("/trace_marker"), what);
}

static int f593_field(const char *line, const char *key, int *out)
{
	const char *p = strstr(line, key);

	if (!p)
		return -1;
	*out = atoi(p + strlen(key));
	return 0;
}

/* ---------- D: two sockets, one command stream -------------------------- */

static void f593_child_d(void)
{
	static unsigned char buf[4096];
	static unsigned char cb[256];
	unsigned char msg[16], c[8], b[13];
	int s = -1, sg = -1, i, rc;

	close(F585_C.up[0]);
	close(F585_C.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F593 CHILDD|unshare=%d\n", errno);
		_exit(1);
	}
	c[0] = 'U';
	if (write(F585_C.up[1], c, 1) != 1)
		_exit(2);
	if (read(F585_C.dn[0], msg, 1) != 1)
		_exit(3);
	set_up("lo");
	for (i = 0; i < 400 && f555_ifindex("y3") < 0; i++)
		usleep(20000);
	set_up("y3");
	set_up("y4");
	/* the receiver must not aggregate: all three GRO bits off */
	rc = f578_feat_set("y3", F585_GRO_BIT, 0);
	rc |= f578_feat_set("y3", F585_GROFL_BIT, 0);
	rc |= f578_feat_set("y3", F585_GROFWD_BIT, 0);
	rc |= f578_feat_set("y4", F585_GRO_BIT, 0);
	rc |= f578_feat_set("y4", F585_GROFL_BIT, 0);
	rc |= f578_feat_set("y4", F585_GROFWD_BIT, 0);
	printf("F593 GROSW|y3=%d|y4=%d\n", f555_ifindex("y3"),
	       f555_ifindex("y4"));
	i = f555_addr_add("y3", htonl(A90_DA), 24);
	i |= f555_addr_add("y4", htonl(A90_DB), 24);
	f585_mtu("y3", "65000");
	f585_mtu("y4", "65000");
	rc |= mac_get("y3", F591_Y3M);
	rc |= mac_get("y4", F591_Y4M);
	s = f564_udp_bind(AF_INET, 0, NULL, F591_DPORT);
	sg = f564_udp_bind(AF_INET, 0, NULL, F591_DPORT_G);
	if (sg >= 0) {
		int gro = 1;

		(void)setsockopt(sg, IPPROTO_UDP, UDP_GRO, &gro,
				 (socklen_t)sizeof(gro));
	}
	{
		unsigned int dv = 0;
		socklen_t dvl = (socklen_t)sizeof(dv);

		if (s >= 0)
			getsockopt(s, SOL_SOCKET, SO_RCVBUF, &dv, &dvl);
		F591_DEF = (int)dv;
	}
	printf("F593 DEFRB|def=%d|half=%d\n", F591_DEF, F591_DEF >> 1);
	b[0] = 'M';
	memcpy(b + 1, F591_Y3M, 6);
	memcpy(b + 7, F591_Y4M, 6);
	if (write(F585_C.up[1], b, 13) != 13)
		_exit(4);
	printf("F593 CHILDD|rc=%d|y3=%d|y4=%d|s=%d|sg=%d|addr=%d|"
	       "m3=%02x%02x%02x%02x%02x%02x|m4=%02x%02x%02x%02x%02x%02x\n",
	       rc, f555_ifindex("y3"), f555_ifindex("y4"), s, sg, i,
	       F591_Y3M[0], F591_Y3M[1], F591_Y3M[2], F591_Y3M[3],
	       F591_Y3M[4], F591_Y3M[5], F591_Y4M[0], F591_Y4M[1],
	       F591_Y4M[2], F591_Y4M[3], F591_Y4M[4], F591_Y4M[5]);
	fflush(stdout);
	for (;;) {
		if (f586_read8(F585_C.dn[0], c) != 8)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		if (c[0] == 'p') {
			int req = (int)(((unsigned int)c[1] << 24) |
					((unsigned int)c[2] << 16) |
					((unsigned int)c[3] << 8) |
					(unsigned int)c[4]);
			unsigned int rb0 = 0, rb1 = 0;
			socklen_t rbl = (socklen_t)sizeof(rb0);
			int got0 = 0, got1 = 0;

			if (req < 0)
				req = F591_DEF / 2;
			if (req > 0) {
				if (s >= 0)
					(void)setsockopt(s, SOL_SOCKET,
							 SO_RCVBUF, &req,
							 (socklen_t)sizeof(req));
				if (sg >= 0)
					(void)setsockopt(sg, SOL_SOCKET,
							 SO_RCVBUF, &req,
							 (socklen_t)sizeof(req));
			}
			if (s >= 0)
				getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rb0, &rbl);
			rbl = (socklen_t)sizeof(rb1);
			if (sg >= 0)
				getsockopt(sg, SOL_SOCKET, SO_RCVBUF, &rb1, &rbl);
			for (;;) {
				int r = s < 0 ? -1 :
					(int)recv(s, buf, sizeof(buf),
						  MSG_DONTWAIT);

				if (r < 0)
					break;
				got0++;
			}
			for (;;) {
				int r = sg < 0 ? -1 :
					(int)recv(sg, buf, sizeof(buf),
						  MSG_DONTWAIT);

				if (r < 0)
					break;
				got1++;
			}
			printf("F593 PREP|req=%d|rb0=%u|rb1=%u|d0=%d|d1=%d|"
			       "rmem0=%d|rmem1=%d\n",
			       req, rb0, rb1, got0, got1,
			       f591_proc_rmem(F591_DPORT),
			       f591_proc_rmem(F591_DPORT_G));
		} else if (c[0] == 'w') {
			int want = (int)(((unsigned int)c[1] << 24) |
					 ((unsigned int)c[2] << 16) |
					 ((unsigned int)c[3] << 8) |
					 (unsigned int)c[4]);
			int port = c[5] ? F591_DPORT_G : F591_DPORT;
			long long t0 = f587_ms();
			int last = -2, stable = 0, ok = 0;

			while (f587_ms() - t0 < 6000) {
				int r = f591_proc_rmem(port);

				if (r != last) {
					last = r;
					stable = 0;
				} else {
					stable++;
				}
				/* want < 0: the queue must be EMPTY (the j = 0
				 * arms); want > 0: it must reach this many
				 * bytes; want == 0: any non-empty queue */
				if ((want < 0 ? (last == 0) :
				     want > 0 ? (last >= want) : (last > 0)) &&
				    stable >= 100) {
					ok = 1;
					break;
				}
				usleep(5000);
			}
			printf("F593 WAIT|port=%d|want=%d|rmem=%d|ms=%lld|"
			       "stable=%d|ok=%d\n",
			       port, want, last, f587_ms() - t0, stable, ok);
		} else if (c[0] == 'r') {
			int idx = c[1], att = c[2];
			int win = (c[3] << 8) | c[4];
			int lazy = c[6];
			int nd0 = 0, nd1 = 0, empt = 0, pass = 0;
			int dl0[8], dl1[8], f0 = -1, f1 = -1, g1 = -1;
			int la0 = -1, lb0 = -1, la1 = -1, lb1 = -1;
			int dv0, dv1;
			unsigned int rb0 = 0, rb1 = 0;
			socklen_t rbl;
			long long t0, in, err;

			for (i = 0; i < 8; i++) {
				dl0[i] = -1;
				dl1[i] = -1;
			}
			if (lazy)
				usleep((useconds_t)lazy * 1000);
			rbl = (socklen_t)sizeof(rb0);
			if (s >= 0)
				getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rb0, &rbl);
			rbl = (socklen_t)sizeof(rb1);
			if (sg >= 0)
				getsockopt(sg, SOL_SOCKET, SO_RCVBUF, &rb1, &rbl);
			/* the queues AS THEY WERE BUILT, before a single read */
			dv0 = f591_proc_rmem(F591_DPORT);
			dv1 = f591_proc_rmem(F591_DPORT_G);
			t0 = f587_ms();
			while (f587_ms() - t0 < win && pass < 4000) {
				int got = 0;

				pass++;
				for (;;) {
					struct msghdr m;
					struct iovec iov;
					struct cmsghdr *cm;
					int r;

					iov.iov_base = buf;
					iov.iov_len = sizeof(buf);
					memset(&m, 0, sizeof(m));
					m.msg_iov = &iov;
					m.msg_iovlen = 1;
					m.msg_control = cb;
					m.msg_controllen = sizeof(cb);
					r = s < 0 ? -1 :
						(int)recvmsg(s, &m,
							     MSG_DONTWAIT);
					if (r < 0)
						break;
					if (nd0 == 0)
						f0 = (int)buf[0];
					if (nd0 < 8)
						dl0[nd0] = r;
					la0 = lb0;
					lb0 = r;
					nd0++;
					got++;
				}
				for (;;) {
					struct msghdr m;
					struct iovec iov;
					struct cmsghdr *cm;
					int r;

					iov.iov_base = buf;
					iov.iov_len = sizeof(buf);
					memset(&m, 0, sizeof(m));
					m.msg_iov = &iov;
					m.msg_iovlen = 1;
					m.msg_control = cb;
					m.msg_controllen = sizeof(cb);
					r = sg < 0 ? -1 :
						(int)recvmsg(sg, &m,
							     MSG_DONTWAIT);
					if (r < 0)
						break;
					if (nd1 == 0)
						f1 = (int)buf[0];
					if (nd1 < 8)
						dl1[nd1] = r;
					la1 = lb1;
					lb1 = r;
					for (cm = CMSG_FIRSTHDR(&m); cm;
					     cm = CMSG_NXTHDR(&m, cm)) {
						int v;

						if (cm->cmsg_level != IPPROTO_UDP ||
						    cm->cmsg_type != UDP_GRO)
							continue;
						memcpy(&v, CMSG_DATA(cm), 4);
						g1 = v;
					}
					nd1++;
					got++;
				}
				if (!got)
					empt++;
				else
					empt = 0;
				usleep(2000);
			}
			f591_snmp4(&in, &err);
			printf("F593 RCV|i=%02d|att=%d|n0=%d|n1=%d|rmem0=%d|"
			       "rmem1=%d|rb0=%u|rb1=%u|lazy=%d|win=%d|pass=%d|"
			       "empt=%d|f0=%d|f1=%d|dl0=%d,%d,%d,%d|"
			       "dl1=%d,%d,%d,%d|g1=%d|hl0=%d,%d|hl1=%d,%d|"
			       "udpin=%lld|udperr=%lld|ms=%lld\n",
			       idx, att, nd0, nd1, dv0, dv1, rb0, rb1, lazy,
			       win, pass, empt, f0, f1, dl0[0], dl0[1],
			       dl0[2], dl0[3], dl1[0], dl1[1], dl1[2],
			       dl1[3], g1, la0, lb0, la1, lb1, in, err,
			       f587_ms() - t0);
		}
		fflush(stdout);
		c[0] = 'D';
		if (write(F585_C.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* ---------- the parent side --------------------------------------------- */

/* f591_setup() with one line changed: the receiver is f593_child_d. */
static int f593_setup(void)
{
	static const char *old[] = { "x0", "x1", "y1", "y2", "y3", "y4" };
	struct f578_gf g;
	unsigned char msg[16];
	int i, rc, r1, r2;

	f585_tap_zero(&F585_TA);
	f585_tap_zero(&F585_TB);
	F585_TA.fd = -1;
	F585_TB.fd = -1;
	F585_TA.only_out = 1;
	F585_TB.only_out = 1;
	for (i = 0; i < F591_ND; i++) {
		int k;

		for (k = 0; k < F591_MAXPL; k++)
			F591_PAY[i][k] = (unsigned char)(0x40 + (k & 0x3f));
		F591_PAY[i][0] = (unsigned char)(0x10 + (i & 0x0f));
		F591_PAY[i][1] = (unsigned char)i;
	}
	for (i = 0; i < F591_ND; i++) {
		int k;

		for (k = 0; k < F591_MAXPL; k++)
			F591_FPAY[i][k] = (unsigned char)(0x40 + (k & 0x3f));
		F591_FPAY[i][0] = (unsigned char)(0xE0 | (i & 0x1f));
		F591_FPAY[i][1] = (unsigned char)i;
	}
	f555_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
	f555_sysctl("/proc/sys/net/ipv4/conf/all/forwarding", "1");
	f555_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
	f555_sysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0");
	for (i = 0; i < 6; i++)
		f558_link_del(old[i]);
	{
		int acks = 0;

		(void)f557_flush(NFPROTO_IPV4, "f90p", "fwd", &acks);
		(void)f584_deltable(NFPROTO_IPV4, "f90p");
	}
	if (pipe(F585_S.up) || pipe(F585_S.dn) || pipe(F585_C.up) ||
	    pipe(F585_C.dn)) {
		printf("F593 FAIL|pipe\n");
		return -1;
	}
	F585_S.pid = fork();
	if (F585_S.pid < 0) {
		printf("F593 FAIL|fork\n");
		return -1;
	}
	if (F585_S.pid == 0)
		f591_child_s();
	F585_C.pid = fork();
	if (F585_C.pid < 0) {
		printf("F593 FAIL|fork2\n");
		return -1;
	}
	if (F585_C.pid == 0)
		f593_child_d();
	close(F585_S.up[1]);
	close(F585_S.dn[0]);
	close(F585_C.up[1]);
	close(F585_C.dn[0]);
	if (f585_wait_byte(F585_S.up[0], 5000) != 'U') {
		printf("F593 FAIL|senderns\n");
		return -1;
	}
	if (f585_wait_byte(F585_C.up[0], 5000) != 'U') {
		printf("F593 FAIL|recvns\n");
		return -1;
	}
	rc = f585_veth_ns("x0", "x1", (int)F585_S.pid);
	rc |= f585_veth_ns("y1", "y3", (int)F585_C.pid);
	rc |= f585_veth_ns("y2", "y4", (int)F585_C.pid);
	if (rc) {
		printf("F593 FAIL|veth|rc=%d\n", rc);
		return -1;
	}
	set_up("x0");
	set_up("y1");
	set_up("y2");
	printf("F593 GROSW|x0=%d\n", f578_feat_set("x0", F585_GRO_BIT, 1));
	rc = f555_addr_add("x0", htonl(A90_X0), 24);
	rc |= f555_addr_add("y1", htonl(A90_RA), 24);
	rc |= f555_addr_add("y2", htonl(A90_RB), 24);
	f555_sysctl("/proc/sys/net/ipv4/conf/x0/rp_filter", "0");
	f555_sysctl("/proc/sys/net/ipv4/conf/y1/rp_filter", "0");
	f555_sysctl("/proc/sys/net/ipv4/conf/y2/rp_filter", "0");
	f585_mtu("x0", "65000");
	f585_mtu("y1", "65000");
	f585_mtu("y2", "65000");
	f585_groto("x0", "200000000");
	mac_get("x0", F591_X0M);
	msg[0] = 'M';
	memcpy(msg + 1, F591_X0M, 6);
	if (write(F585_S.dn[1], msg, 7) != 7) {
		printf("F593 FAIL|mactx\n");
		return -1;
	}
	{
		unsigned char c = 'R';

		if (write(F585_C.dn[1], &c, 1) != 1) {
			printf("F593 FAIL|dsync\n");
			return -1;
		}
	}
	if (f585_wait_byte(F585_S.up[0], 8000) != 'R') {
		printf("F593 FAIL|senderready\n");
		return -1;
	}
	{
		unsigned char b[13];
		int got = 0;

		for (i = 0; i < 300 && got < 13; i++) {
			int r = (int)read(F585_C.up[0], b + got,
					  (size_t)(13 - got));

			if (r > 0)
				got += r;
			else
				usleep(10000);
		}
		if (got == 13 && b[0] == 'M') {
			memcpy(F591_Y3M, b + 1, 6);
			memcpy(F591_Y4M, b + 7, 6);
		} else {
			printf("F593 FAIL|dmac|got=%d\n", got);
			return -1;
		}
	}
	rc |= f591_neigh4("y1", htonl(A90_DA), F591_Y3M);
	rc |= f591_neigh4("y2", htonl(A90_DB), F591_Y4M);
	r1 = 0;
	r1 |= f578_feat_set("y1", F585_TSO_BIT, 0);
	r1 |= f578_feat_set("y1", F585_TSOECN_BIT, 0);
	r1 |= f578_feat_set("y1", F585_TSOMID_BIT, 0);
	r1 |= f578_feat_set("y1", F585_TSO6_BIT, 0);
	r2 = f578_feat_set("y2", F585_HWCSUM_BIT, 0);
	r2 |= f578_feat_set("y2", F585_TSO_BIT, 0);
	r2 |= f578_feat_set("y2", F585_TSOECN_BIT, 0);
	r2 |= f578_feat_set("y2", F585_TSOMID_BIT, 0);
	r2 |= f578_feat_set("y2", F585_TSO6_BIT, 0);
	r2 |= f578_feat_set("y2", F585_GSOUDP_BIT, 0);
	r2 |= f578_feat_set("y2", F585_GSOFL_BIT, 0);
	printf("F593 FEAT|r1=%d|r2=%d\n", r1, r2);
	f578_feat_get("x0", &g);
	printf("F593 FEAT|dev=x0|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y1", &g);
	printf("F593 FEAT|dev=y1|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y2", &g);
	printf("F593 FEAT|dev=y2|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	{
		int k = 0;

		k |= f579_tbl(NFPROTO_IPV4, "f90p");
		k |= f580_chn(NFPROTO_IPV4, "f90p", "fwd", NULL, 2, 0);
		printf("F593 CHAINS|rc=%d\n", k);
	}
	F573_NFL = nfl_open(F591_GROUP);
	F585_NFL = F573_NFL;
	f586_taps(1);
	printf("F593 ENV|x0=%d|y1=%d|y2=%d|nfl=%d|addr=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|m3=%02x%02x%02x%02x%02x%02x|"
	       "m4=%02x%02x%02x%02x%02x%02x|ND=%d\n",
	       f555_ifindex("x0"), f555_ifindex("y1"), f555_ifindex("y2"),
	       F573_NFL, rc, F591_X0M[0], F591_X0M[1], F591_X0M[2],
	       F591_X0M[3], F591_X0M[4], F591_X0M[5],
	       F591_Y3M[0], F591_Y3M[1], F591_Y3M[2], F591_Y3M[3],
	       F591_Y3M[4], F591_Y3M[5],
	       F591_Y4M[0], F591_Y4M[1], F591_Y4M[2], F591_Y4M[3],
	       F591_Y4M[4], F591_Y4M[5], F591_ND);
	return 0;
}

/* ---------- the trace, per attempt -------------------------------------- */

struct f593_rec {
	int len, dlen, tail, end, ts, fl;
};

struct f593_cnt {
	int cond, enq, pull, seg, trim, clone, exp;
	int mark_ok;
	int n_cond, n_enq;
	struct f593_rec cnd[16];
	struct f593_rec eq[16];
	int eat[16];
	int n_eat;
};

/* Count ONLY the records of this attempt: those between its BEGIN marker and
 * its END marker.  A write to `trace` does not reset the buffer in this kernel
 * (measured in F70), so attribution is by marker. */
static void f593_dump(int idx, int att, struct f593_cnt *C)
{
	static char big[1 << 20];
	int n = f593_rf(f593_p("/trace"), big, (int)sizeof(big));
	char *p = big;
	char b1[48], b2[48];
	int inside = 0, seen = -1;

	memset(C, 0, sizeof(*C));
	snprintf(b1, sizeof(b1), "BEGIN i=%02d att=%d", idx, att);
	snprintf(b2, sizeof(b2), "END i=%02d att=%d", idx, att);
	if (n <= 0)
		return;
	while (*p) {
		char *e = strchr(p, '\n');
		char *line = p;

		if (e)
			*e = 0;
		if (strstr(line, "tracing_mark_write:")) {
			if (strstr(line, b1)) {
				inside = 1;
				seen = idx;
				printf("F593 TRC|i=%02d|att=%d|%s\n", idx,
				       att, line);
			} else if (strstr(line, b2)) {
				inside = 0;
				printf("F593 TRC|i=%02d|att=%d|%s\n", idx,
				       att, line);
			}
		} else if (inside && strstr(line, "f593cond:")) {
			struct f593_rec *R = NULL;
			int v;

			C->cond++;
			if (C->n_cond < 16) {
				R = &C->cnd[C->n_cond++];
				memset(R, 0, sizeof(*R));
				if (f593_field(line, " len=", &v) == 0)
					R->len = v;
				(void)f593_field(line, "dlen=", &R->dlen);
				(void)f593_field(line, "tail=", &R->tail);
				(void)f593_field(line, "end=", &R->end);
				(void)f593_field(line, "ts=", &R->ts);
				(void)f593_field(line, "fl=", &R->fl);
			}
			printf("F593 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		} else if (inside && strstr(line, "f593enq:")) {
			struct f593_rec *R = NULL;
			int v;

			C->enq++;
			if (C->n_enq < 16) {
				R = &C->eq[C->n_enq++];
				memset(R, 0, sizeof(*R));
				if (f593_field(line, " len=", &v) == 0)
					R->len = v;
				(void)f593_field(line, "dlen=", &R->dlen);
				(void)f593_field(line, "tail=", &R->tail);
				(void)f593_field(line, "end=", &R->end);
				(void)f593_field(line, "ts=", &R->ts);
				(void)f593_field(line, "fl=", &R->fl);
			}
			printf("F593 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		} else if (inside && strstr(line, "f593pull:")) {
			int v;

			C->pull++;
			if (f593_field(line, "eat=", &v) == 0 &&
			    C->n_eat < 16)
				C->eat[C->n_eat++] = v;
			printf("F593 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		} else if (inside && strstr(line, "f593seg:")) {
			C->seg++;
		} else if (inside && strstr(line, "f593clone:")) {
			C->clone++;
		} else if (inside && strstr(line, "f593exp:")) {
			C->exp++;
		} else if (inside && strstr(line, "f593trim:")) {
			C->trim++;
			printf("F593 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		}
		if (!e)
			break;
		p = e + 1;
	}
	C->mark_ok = (seen == idx) ? 1 : 0;
}

static void f593_arm(const struct f593_arm *A, int idx)
{
	struct f593_cnt C;
	char mk[96];
	int att, i, rc = -99, cmdrc = 0, wrc = 0, wrc2 = 0;
	int psel = A->skt == 'g' ? 1 : 0;

	for (att = 0; att < 2; att++) {
		/* 0. the parent's y1/y2 taps: F63 measured that
		 * dev_queue_xmit_nit() clones the skb and veth then takes the
		 * shared path.  A per-arm bit, because the tap is the prime
		 * suspect for skb_cloned() at the enqueue gate. */
		if (A->tap) {
			if (F585_TA.fd < 0)
				F585_TA.fd = f578_tap_open_aux("y1");
			if (F585_TB.fd < 0)
				F585_TB.fd = f578_tap_open_aux("y2");
		} else {
			f586_taps(0);
		}
		/* 1. the shape of x0's GRO: a device bit no socket can see */
		(void)f578_feat_set("x0", F585_GRO_BIT, 1);
		(void)f578_feat_set("x0", F585_GROFL_BIT, A->xg == 'f');
		(void)f578_feat_set("x0", F585_GROFWD_BIT, A->xg == 'u');
		/* 2. clean slate: the two buffers, both queues */
		cmdrc |= f586_cmd(&F585_C, 'p',
				  (A->rcvbuf >> 24) & 0xff,
				  (A->rcvbuf >> 16) & 0xff,
				  (A->rcvbuf >> 8) & 0xff,
				  A->rcvbuf & 0xff, 0, 0, 0) ? 1 : 0;
		usleep(300000);
		/* 3. the filler: one datagram at a time, so it NEVER aggregates,
		 *    each one costing exactly one 1280-byte unit */
		rc = 0;
		for (i = 0; i < A->j; i++) {
			if (f591_send_s(&F585_S, 'f', 'a', psel, 1, 0xff, 0,
					512, 0)) {
				rc = -1;
				break;
			}
			usleep(F593_GAP);
		}
		cmdrc |= rc ? 8 : 0;
		/* 4. the queue must be exactly where the model says it is */
		{
			int want = A->j ? A->j * 1280 : -1;

			wrc = f586_cmd(&F585_C, 'w',
				       (want >> 24) & 0xff, (want >> 16) & 0xff,
				       (want >> 8) & 0xff, want & 0xff,
				       psel, 0, 0) ? 256 : 0;
		}
		cmdrc |= wrc;
		usleep(150000);
		/* 5. from here on, every record belongs to this arm */
		(void)f593_wf(f593_p("/trace"), "\n");
		snprintf(mk, sizeof(mk), "BEGIN i=%02d att=%d %s", idx, att,
			 A->name);
		f593_mark(mk);
		/* 6a. the primer: one 64-byte datagram to a port nobody listens
		 *     on, so x0's NAPI is already inside a poll when the
		 *     measured burst starts (F69 measured that without it the
		 *     first datagram is sometimes processed alone).  It never
		 *     reaches a socket and is never enqueued. */
		cmdrc |= f591_send_s(&F585_S, 's', 'a', 2, 1, 0xff, 0, 64, 0)
			 ? 512 : 0;
		/* 6. the test: one back-to-back burst through the router */
		rc = f591_send_s(&F585_S, 's', 'a', psel, A->n, A->sh, A->sl,
				 A->pl, 0);
		cmdrc |= rc ? 16 : 0;
		/* 7. the queue must be BUILT before it is read */
		wrc2 = f586_cmd(&F585_C, 'w', 0, 0, 0, 0, psel, 0, 0) ? 128 : 0;
		cmdrc |= wrc2;
		snprintf(mk, sizeof(mk), "END i=%02d att=%d", idx, att);
		f593_mark(mk);
		/* 8. reals: the queues before a single read, then the drain */
		cmdrc |= f586_cmd(&F585_C, 'r', idx, att, 0x01, 0x90, psel, 0, 0)
			 ? 32 : 0;
		f593_dump(idx, att, &C);
		printf("F593 CNT|i=%02d|att=%d|enq=%d|cond=%d|pull=%d|seg=%d|"
		       "trim=%d|clone=%d|exp=%d|eat=%d|mark=%d\n", idx, att,
		       C.enq, C.cond, C.pull, C.seg, C.trim, C.clone, C.exp,
		       C.n_eat ? C.eat[0] : -1, C.mark_ok);
		printf("F593 ARM|i=%02d|att=%d|name=%s|xg=%c|skt=%c|j=%d|n=%d|"
		       "pl=%d|sh=%d|sl=%d|rcvbuf=%d|tap=%d|exp_enq=%d|exp_cond=%d|"
		       "exp_pull=%d|exp_seg=%d|exp_dl=%d|exp_charge=%d|"
		       "rc=%d|cmdrc=%d|wrc=%d|wrc2=%d\n",
		       idx, att, A->name, A->xg, A->skt, A->j, A->n, A->pl,
		       A->sh, A->sl, A->rcvbuf, A->tap, A->exp_enq, A->exp_cond,
		       A->exp_pull, A->exp_seg, A->exp_dl, A->exp_charge, rc,
		       cmdrc, wrc > 0, wrc2 > 0);
		if (C.n_enq) {
			int k;

			printf("F593 EQ|i=%02d|att=%d|n=%d|ts=", idx, att,
			       C.n_enq);
			for (k = 0; k < C.n_enq && k < 16; k++)
				printf("%s%d", k ? "," : "", C.eq[k].ts);
			printf("|dlen=");
			for (k = 0; k < C.n_enq && k < 16; k++)
				printf("%s%d", k ? "," : "", C.eq[k].dlen);
			printf("|len=");
			for (k = 0; k < C.n_enq && k < 16; k++)
				printf("%s%d", k ? "," : "", C.eq[k].len);
			printf("|tail=");
			for (k = 0; k < C.n_enq && k < 16; k++)
				printf("%s%d", k ? "," : "", C.eq[k].tail);
			printf("|end=");
			for (k = 0; k < C.n_enq && k < 16; k++)
				printf("%s%d", k ? "," : "", C.eq[k].end);
			printf("|fl=");
			for (k = 0; k < C.n_enq && k < 16; k++)
				printf("%s%d", k ? "," : "", C.eq[k].fl);
			printf("\n");
		}
		if (C.n_cond) {
			int k;

			printf("F593 CQ|i=%02d|att=%d|n=%d|ts=", idx, att,
			       C.n_cond);
			for (k = 0; k < C.n_cond && k < 16; k++)
				printf("%s%d", k ? "," : "", C.cnd[k].ts);
			printf("|dlen=");
			for (k = 0; k < C.n_cond && k < 16; k++)
				printf("%s%d", k ? "," : "", C.cnd[k].dlen);
			printf("|len=");
			for (k = 0; k < C.n_cond && k < 16; k++)
				printf("%s%d", k ? "," : "", C.cnd[k].len);
			printf("|tail=");
			for (k = 0; k < C.n_cond && k < 16; k++)
				printf("%s%d", k ? "," : "", C.cnd[k].tail);
			printf("|end=");
			for (k = 0; k < C.n_cond && k < 16; k++)
				printf("%s%d", k ? "," : "", C.cnd[k].end);
			printf("|fl=");
			for (k = 0; k < C.n_cond && k < 16; k++)
				printf("%s%d", k ? "," : "", C.cnd[k].fl);
			printf("\n");
		}
		fflush(stdout);
	}
}

static int f593_run(const struct f593_arm *T, int n, int limit, const char *nm)
{
	int i, upto = limit > 0 && limit < n ? limit : n;

	printf("F593 RUN|mode=%s|arms=%d|run=%d\n", nm, n, upto);
	for (i = 0; i < upto; i++) {
		f593_arm(&T[i], i);
		fflush(stdout);
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "gro";
	int limit = argc > 2 ? atoi(argv[2]) : 0;
	static char mbuf[32];

	if (strchr(mode, ':')) {
		const char *c = strchr(mode, ':');
		int n = (int)(c - mode);

		if (n > 0 && n < (int)sizeof(mbuf)) {
			memcpy(mbuf, mode, (size_t)n);
			mbuf[n] = 0;
			mode = mbuf;
			limit = atoi(c + 1);
		}
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("F593 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "gro")) {
		if (f593_setup()) {
			printf("F593 FAIL|setup\n");
			return 1;
		}
		f593_probe_up();
		f593_run(AF593, (int)(sizeof(AF593) / sizeof(AF593[0])), limit,
			 "gro");
		f591_shutdown();
		return 0;
	}
	return f592_entry(argc, argv);
}
