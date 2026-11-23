/* ================= turn 594 (F72) =======================================
 *
 * Two debts, both from F71 section 8, and both in the same function:
 *
 *   clause 3 of skb_condense()  (!skb_frags_readable) never fired, because no
 *   skb with SKBFL_PURE_ZEROCOPY existed in that topology;
 *
 *   "who else on the receive path sets skb_cloned, and is clause 2 reachable
 *   without an observer" -- F71 fired it with the parent's own AF_PACKET tap.
 *
 * The instrument is F71's three-netns IPv4 path (x0 <- S -> y1/y2 -> D),
 * unchanged except for two additions:
 *
 *   (a) the SENDER can use SO_ZEROCOPY + MSG_ZEROCOPY, so the payload of a
 *       datagram lives in user pages (SKBFL_ZEROCOPY_ENABLE) and the skb has
 *       data_len > 0 with no aggregation at all;
 *
 *   (b) the RECEIVER D can open a packet socket on y3 -- one that keeps its
 *       frames, and one whose classic BPF filter returns 0 so it keeps
 *       nothing -- i.e. a second packet_type that never holds a frame.
 *
 * Four source readings decide the arms (research/predictions_594.md section 1):
 *
 *  (1) net/core/gro.c:112  skb_gro_receive()  refuses skb_zcopy() outright:
 *      the LINEAR door cannot merge a zerocopy datagram.
 *      net/core/gro.c:234  skb_gro_receive_list() has no such check: the
 *      FRAGLIST door merges it.
 *  (2) SKBFL_PURE_ZEROCOPY is set only in net/ipv4/tcp.c:1331 -> a UDP skb can
 *      never make skb_frags_readable() false, so clause 3 is a TCP flag on a
 *      UDP-only queue.
 *  (3) ip_local_deliver_finish() (net/ipv4/ip_input.c:231) calls
 *      skb_orphan_frags_rx() -> skb_copy_ubufs(): the RECEIVER copies every
 *      zerocopy payload into kernel pages before udp_rcv().
 *  (4) skb_gro_receive_list() ORs only SKBFL_SHARED_FRAG into the aggregate,
 *      and skb_segment_list() never orphans frags -- so a fraglist aggregate
 *      carries the members' user pages to the queue untouched.
 *
 * Probes (8), offsets from pahole of the booting vmlinux (F71's six, plus
 * skb_copy_ubufs):
 *
 *   f594cond  skb_condense                 len dlen tail end ts fl
 *   f594enq   __udp_enqueue_schedule_skb   same six -- THE GATE
 *   f594pull  __pskb_pull_tail             eat=%si
 *   f594seg   skb_segment_list
 *   f594trim  ___pskb_trim
 *   f594clone skb_clone
 *   f594exp   pskb_expand_head
 *   f594ubuf  skb_copy_ubufs               <- new: the payload copy
 */

#include <sys/mount.h>

#define F594_TRC	"/sys/kernel/tracing"
#define F594_TRCD	"/sys/kernel/debug/tracing"
#define F594_GAP	250000		/* us between filler datagrams */

/* field offsets of struct sk_buff in THIS kernel, from
 *   pahole -C sk_buff vmlinux   (DWARF5, the bytes that boot).
 * sizeof(struct sk_buff) = 232, so SKB_DATA_ALIGN() = 256: the truesize a
 * merged datagram gives up in skb_gro_receive(). */
#define F594_O_LEN	112
#define F594_O_DLEN	116
#define F594_O_TAIL	188
#define F594_O_END	192
#define F594_O_TS	216
#define F594_O_FL	126

struct f594_arm {
	const char *name;
	char xg;	/* GRO at x0: 'u' linear (udp_fwd), 'f' fraglist */
	char skt;	/* the test's socket at D: 'g' UDP_GRO 5001, 'p' plain 5000 */
	int j;		/* filler datagrams, one at a time, F594_GAP apart */
	int n;		/* test datagrams, back to back */
	int pl;		/* test payload length */
	int sh;		/* short-tail index, -1 none */
	int sl;		/* its payload length */
	int rcvbuf;	/* SO_RCVBUF request (sk_rcvbuf becomes 2x this) */
	int tap;	/* 1: keep the parent's y1/y2 taps open during the arm */
	int zc;		/* 1: sender uses SO_ZEROCOPY + MSG_ZEROCOPY */
	int align;	/* 1: payload buffer page aligned (zc page accounting) */
	int dtap;	/* D's packet socket on y3: 0 none, 1 keep, 2 ret-0 filter */
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
static const struct f594_arm AF594[] = {
	/* name        xg skt   j   n    pl sh   sl rcvbuf tap zc al dtap enq cond pull seg dl charge */
	{ "z_ctl6",    'u', 'p',  0,  6,  512, -1,   0,     0, 0, 0, 0, 0,  1,   0,   0,  0, 2560,  7680 },
	{ "z_lin6",    'u', 'p',  0,  6,  512, -1,   0,     0, 0, 1, 0, 0,  6,   6,   0,  0,  512,    -1 },
	{ "z_lin6a",   'u', 'p',  0,  6,  512, -1,   0,     0, 0, 1, 1, 0,  6,   6,   0,  0,  512,    -1 },
	{ "z_lin6x",   'u', 'p',  0,  6,  512, -1,   0,     0, 0, 1, 2, 0,  6,   6,   0,  0,  512,    -1 },
	{ "z_fl6",     'f', 'p',  0,  6,  512, -1,   0,     0, 0, 1, 0, 0,  6,   6,   0,  0,  512,    -1 },
	{ "z_lin1",    'u', 'p',  0,  1,  512, -1,   0,     0, 0, 1, 0, 0,  1,   1,   0,  0,  512,    -1 },
	{ "z_lin1q",   'u', 'p',  0,  1, 1200, -1,   0,     0, 0, 1, 0, 0,  1,   1,   0,  0, 1200,    -1 },
	{ "z_lin1w",   'u', 'p',  0,  1, 5000, -1,   0,     0, 0, 1, 0, 0,  1,   1,   0,  0, 5000,    -1 },
	{ "z_lin64",   'u', 'p',  0, 64,  512, -1,   0, 19200, 0, 1, 0, 0, -1,  -1,  -1, -1,  512,    -1 },
	{ "c_none",    'u', 'g', 16,  2,  512,  1, 148, 19200, 0, 0, 0, 0,  1,   1,   1,  0,  148,  1280 },
	{ "c_egr",     'u', 'g', 16,  2,  512,  1, 148, 19200, 1, 0, 0, 0,  1,   1,   0,  0,  148,  2240 },
	{ "c_ing_k",   'u', 'g', 16,  2,  512,  1, 148, 19200, 0, 0, 0, 1,  1,   1,   0,  0,  148,  2240 },
	{ "c_ing_d",   'u', 'g', 16,  2,  512,  1, 148, 19200, 0, 0, 0, 2,  1,   1,   1,  0,  148,  1280 },
};

/* z_lin6a: the same six zerocopy datagrams, payload in a page-aligned buffer.
 * Added after the first smoke, which showed the gate charging a zerocopy
 * datagram 5056 or 9152 bytes alternately -- one page or two.  Not a
 * prediction (predictions_594.md was hashed before any smoke). */
/* c_*: the socket is the UDP_GRO one (5001).  With a plain socket the
 * aggregate is segmented by skb_segment_list() before the queue and the gate
 * never sees data_len > 0 -- the smoke showed exactly that (two enqueues with
 * dlen 0).  predictions_594.md's P11..P14 describe the GRO-socket cell, which
 * is F71's own. */

/* The plain-socket port in D (5000) is what every arm here uses: an
 * aggregate that arrives as a fraglist and is not accepted whole is segmented
 * by skb_segment_list(), which is what P6/P7 are about. */

static int F594_T_ok;
static const char *F594_T = F594_TRC;

static const char *f594_p(const char *suffix)
{
	static char b[4][192];
	static int r;
	char *p = b[r++ & 3];

	snprintf(p, sizeof(b[0]), "%s%s", F594_T, suffix);
	return p;
}

static int f594_wf(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);
	int r;

	if (fd < 0)
		return -1;
	r = (int)write(fd, s, strlen(s));
	close(fd);
	return r < 0 ? -1 : 0;
}

static int f594_rf(const char *path, char *buf, int cap)
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
static int f594_probe_up(void)
{
	char b[512];
	int i;

	mkdir(F594_TRC, 0755);
	if (mount("none", F594_TRC, "tracefs", 0, NULL) && errno != EBUSY) {
		mkdir("/sys/kernel/debug", 0755);
		(void)mount("none", "/sys/kernel/debug", "debugfs", 0, NULL);
		if (access(F594_TRCD "/kprobe_events", W_OK) == 0)
			F594_T = F594_TRCD;
	}
	if (access(f594_p("/kprobe_events"), W_OK)) {
		printf("F594 PROBE|ok=0|errno=%d|path=%s\n", errno, F594_T);
		return -1;
	}
	(void)f594_wf(f594_p("/tracing_on"), "0");
	(void)f594_wf(f594_p("/kprobe_events"), "\n");
	snprintf(b, sizeof(b),
		 "p:f594cond skb_condense len=+%d(%%di):u32 dlen=+%d(%%di):u32 "
		 "tail=+%d(%%di):u32 end=+%d(%%di):u32 ts=+%d(%%di):u32 "
		 "fl=+%d(%%di):u8\n",
		 F594_O_LEN, F594_O_DLEN, F594_O_TAIL, F594_O_END, F594_O_TS,
		 F594_O_FL);
	if (f594_wf(f594_p("/kprobe_events"), b)) {
		printf("F594 PROBE|ok=0|why=cond\n");
		return -1;
	}
	snprintf(b, sizeof(b),
		 "p:f594enq __udp_enqueue_schedule_skb len=+%d(%%si):u32 "
		 "dlen=+%d(%%si):u32 tail=+%d(%%si):u32 end=+%d(%%si):u32 "
		 "ts=+%d(%%si):u32 fl=+%d(%%si):u8\n",
		 F594_O_LEN, F594_O_DLEN, F594_O_TAIL, F594_O_END, F594_O_TS,
		 F594_O_FL);
	if (f594_wf(f594_p("/kprobe_events"), b)) {
		printf("F594 PROBE|ok=0|why=enq\n");
		return -1;
	}
	(void)f594_wf(f594_p("/kprobe_events"),
		      "p:f594pull __pskb_pull_tail eat=%si:s32\n");
	(void)f594_wf(f594_p("/kprobe_events"), "p:f594seg skb_segment_list\n");
	(void)f594_wf(f594_p("/kprobe_events"), "p:f594trim ___pskb_trim\n");
	(void)f594_wf(f594_p("/kprobe_events"), "p:f594clone skb_clone\n");
	(void)f594_wf(f594_p("/kprobe_events"), "p:f594exp pskb_expand_head\n");
	(void)f594_wf(f594_p("/kprobe_events"), "p:f594ubuf skb_copy_ubufs\n");
	{
		static const char *ev[] = { "f594cond", "f594enq", "f594pull",
					    "f594seg", "f594trim", "f594clone",
					    "f594exp", "f594ubuf" };
		int ok = 0;

		for (i = 0; i < 8; i++) {
			char p[128];

			snprintf(p, sizeof(p), "%s/events/kprobes/%s/enable",
				 F594_T, ev[i]);
			if (f594_wf(p, "1") == 0)
				ok |= 1 << i;
		}
		printf("F594 PROBE|ok=%d|mask=%02x|path=%s|"
		       "off=%d,%d,%d,%d,%d,%d\n",
		       ok == 0xff ? 1 : 0, ok, F594_T, F594_O_LEN, F594_O_DLEN,
		       F594_O_TAIL, F594_O_END, F594_O_TS, F594_O_FL);
		if (ok != 0xff)
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
		if (f594_rf(f594_p("/kprobe_events"), kb, (int)sizeof(kb)) > 0) {
			while (*nl && k < 10) {
				char *e = strchr(nl, '\n');
				char line[300];

				if (e)
					*e = 0;
				snprintf(line, sizeof(line), "%s", nl);
				if (line[0])
					printf("F594 DEF|%s\n", line);
				k++;
				if (!e)
					break;
				nl = e + 1;
			}
		}
	}
	(void)f594_wf(f594_p("/trace"), "\n");
	(void)f594_wf(f594_p("/tracing_on"), "1");
	F594_T_ok = 1;
	return 0;
}

static void f594_mark(const char *what)
{
	if (F594_T_ok)
		(void)f594_wf(f594_p("/trace_marker"), what);
}

static int f594_field(const char *line, const char *key, int *out)
{
	const char *p = strstr(line, key);

	if (!p)
		return -1;
	*out = atoi(p + strlen(key));
	return 0;
}

/* ---------- D: two sockets, one command stream -------------------------- */

/* A packet socket inside D on y3.  mode 1: keep every frame (never read);
 * mode 2: a classic BPF filter whose single instruction is `ret 0`, so the
 * socket holds a packet_type but never keeps a frame. */
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 26
#endif
struct f594_bpf_insn {
	unsigned short code;
	unsigned char jt;
	unsigned char jf;
	unsigned int k;
};
struct f594_fprog {
	unsigned short len;
	struct f594_bpf_insn *filter;
};

static int f594_tap_y3(int mode)
{
	struct sockaddr_ll sll;
	int fd, idx = f555_ifindex("y3");

	if (idx < 0)
		return -1;
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return -2;
	if (mode == 2) {
		struct f594_bpf_insn ins[1];
		struct f594_fprog pr;

		ins[0].code = 0x06;	/* BPF_RET | BPF_K */
		ins[0].jt = 0;
		ins[0].jf = 0;
		ins[0].k = 0;		/* keep nothing */
		pr.len = 1;
		pr.filter = ins;
		if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &pr,
			       (socklen_t)sizeof(pr)) < 0) {
			int e = errno;

			close(fd);
			return -1000 - e;
		}
	}
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = idx;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		int e = errno;

		close(fd);
		return -2000 - e;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	return fd;
}

static void f594_child_d(void)
{
	static unsigned char buf[4096];
	static unsigned char cb[256];
	unsigned char msg[16], c[8], b[13];
	int s = -1, sg = -1, i, rc, dtap = -1;

	close(F585_C.up[0]);
	close(F585_C.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F594 CHILDD|unshare=%d\n", errno);
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
	printf("F594 GROSW|y3=%d|y4=%d\n", f555_ifindex("y3"),
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
	printf("F594 DEFRB|def=%d|half=%d\n", F591_DEF, F591_DEF >> 1);
	b[0] = 'M';
	memcpy(b + 1, F591_Y3M, 6);
	memcpy(b + 7, F591_Y4M, 6);
	if (write(F585_C.up[1], b, 13) != 13)
		_exit(4);
	printf("F594 CHILDD|rc=%d|y3=%d|y4=%d|s=%d|sg=%d|addr=%d|"
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
			printf("F594 PREP|req=%d|rb0=%u|rb1=%u|d0=%d|d1=%d|"
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
			printf("F594 WAIT|port=%d|want=%d|rmem=%d|ms=%lld|"
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
			printf("F594 RCV|i=%02d|att=%d|n0=%d|n1=%d|rmem0=%d|"
			       "rmem1=%d|rb0=%u|rb1=%u|lazy=%d|win=%d|pass=%d|"
			       "empt=%d|f0=%d|f1=%d|dl0=%d,%d,%d,%d|"
			       "dl1=%d,%d,%d,%d|g1=%d|hl0=%d,%d|hl1=%d,%d|"
			       "udpin=%lld|udperr=%lld|ms=%lld\n",
			       idx, att, nd0, nd1, dv0, dv1, rb0, rb1, lazy,
			       win, pass, empt, f0, f1, dl0[0], dl0[1],
			       dl0[2], dl0[3], dl1[0], dl1[1], dl1[2],
			       dl1[3], g1, la0, lb0, la1, lb1, in, err,
			       f587_ms() - t0);
		} else if (c[0] == 't') {
			int want = (int)(((unsigned int)c[1] << 24) |
					 ((unsigned int)c[2] << 16) |
					 ((unsigned int)c[3] << 8) |
					 (unsigned int)c[4]);

			if (dtap >= 0) {
				close(dtap);
				dtap = -1;
			}
			if (want) {
				dtap = f594_tap_y3(want);
				printf("F594 DTAP|want=%d|fd=%d|if=%d\n",
				       want, dtap, f555_ifindex("y3"));
			} else {
				printf("F594 DTAP|want=0|fd=-1\n");
			}
		}
		fflush(stdout);
		c[0] = 'D';
		if (write(F585_C.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* What the RULE saw: every packet that passed the nft `log` in the forward
 * chain produces one NFLOG message.  Read them for `ms` after the burst and
 * print, per packet, the UDP length field and the IP total length; filter on
 * the destination port, so the primer (5002) and the filler (also the test
 * port, but drained before the burst) do not leak in. */
static int f594_nfl_count(int fd, int want_port, int ms, int idx, int att)
{
	int n = 0, uh[32], tot[32], dport[32];
	const int max = 32;
	int quiet = 0, total_ms = 0;
	char pre[64];
	unsigned char p[128];

	while (total_ms < ms && quiet < 25) {
		struct timeval tv;
		fd_set rfds;
		unsigned char b[65536];
		int r;

		tv.tv_sec = 0;
		tv.tv_usec = 10000;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
			total_ms += 10;
			quiet += 10;
			continue;
		}
		r = (int)recv(fd, b, sizeof(b), 0);
		if (r <= 0) {
			total_ms += 10;
			quiet += 10;
			continue;
		}
		{
			int pl = 0;

			if (!nfl_one(b, r, pre, (int)sizeof(pre), p, &pl))
				continue;
			if (pl < 28)
				continue;
			{
				int ihl = (p[0] & 0x0f) * 4;

				if (p[9] != 17 || pl < ihl + 8)
					continue;
				dport[n < max ? n : max - 1] =
					(p[ihl + 2] << 8) | p[ihl + 3];
				uh[n < max ? n : max - 1] =
					(p[ihl + 4] << 8) | p[ihl + 5];
				tot[n < max ? n : max - 1] =
					(p[2] << 8) | p[3];
				if (dport[n < max ? n : max - 1] == want_port)
					n++;
				quiet = 0;
			}
		}
	}
	printf("F594 PKT|i=%02d|att=%d|n=%d|uhlen=", idx, att, n);
	{
		int k;

		for (k = 0; k < n && k < max; k++)
			printf("%s%d", k ? "," : "", uh[k]);
		printf("|tot=");
		for (k = 0; k < n && k < max; k++)
			printf("%s%d", k ? "," : "", tot[k]);
		printf("\n");
	}
	return n;
}

/* ---------- S: the sender, with SO_ZEROCOPY ------------------------------ */

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif
#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0x4000000
#endif
#include <linux/errqueue.h>

#define F594_SO_EE_ORIGIN_ZEROCOPY 2
#define F594_SO_EE_CODE_ZEROCOPY_COPIED 1

/* command: c0 's' test / 'f' filler, c1 'a'|'b', c2 port selector, c3 n,
 * c4 sh (0xff none), c5..c6 sl, c7..c8 pl, c9..c10 head length,
 * c11 zc (1: SO_ZEROCOPY + MSG_ZEROCOPY).  c0 'd' drains the error queue and
 * prints the completion counters of the previous command. */
static int f594_send_s(struct f585_conn *C, int c0, int dst, int psel, int n,
		       int sh, int sl, int pl, int head, int zc, int align)
{
	unsigned char m[16];

	memset(m, 0, sizeof(m));
	m[0] = (unsigned char)c0;
	m[1] = (unsigned char)dst;
	m[2] = (unsigned char)psel;
	m[3] = (unsigned char)n;
	m[4] = (unsigned char)sh;
	m[5] = (unsigned char)((sl >> 8) & 0xff);
	m[6] = (unsigned char)(sl & 0xff);
	m[7] = (unsigned char)((pl >> 8) & 0xff);
	m[8] = (unsigned char)(pl & 0xff);
	m[9] = (unsigned char)((head >> 8) & 0xff);
	m[10] = (unsigned char)(head & 0xff);
	m[11] = (unsigned char)(zc ? 1 : 0);
	if (write(C->dn[1], m, sizeof(m)) != (ssize_t)sizeof(m))
		return -1;
	return f585_wait_byte(C->up[0], 20000) == 'D' ? 0 : -1;
}

/* page-aligned copy of the test payloads: same bytes, base 0 mod 4096 */
static unsigned char F594_ABUF[F591_ND][F591_MAXPL + 4096]
	__attribute__((aligned(4096)));

static void f594_child_s(void)
{
	unsigned char msg[8], c[16];
	int s = -1, i, rc, k;
	int last_sent = 0, last_zc = 0, abuf_filled = 0;

	close(F585_S.up[0]);
	close(F585_S.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F594 CHILDS|unshare=%d\n", errno);
		_exit(1);
	}
	c[0] = 'U';
	if (write(F585_S.up[1], c, 1) != 1)
		_exit(2);
	if (read(F585_S.dn[0], msg, 7) != 7 || msg[0] != 'M')
		_exit(3);
	memcpy(F591_X0M, msg + 1, 6);
	set_up("lo");
	for (i = 0; i < 200 && f555_ifindex("x1") < 0; i++)
		usleep(20000);
	set_up("x1");
	rc = f555_addr_add("x1", htonl(A90_S), 24);
	rc |= f591_route4_default(htonl(A90_X0), "x1");
	rc |= f591_neigh4("x1", htonl(A90_X0), F591_X0M);
	f585_mtu("x1", "65000");
	f555_sysctl("/proc/sys/net/ipv4/conf/all/forwarding", "0");
	i = mac_get("x1", F591_X1M);
	for (k = 0; k < 60; k++) {
		s = f564_udp_bind(AF_INET, A90_S, NULL, F591_SPORT);
		if (s >= 0)
			break;
		usleep(50000);
	}
	printf("F594 CHILDS|rc=%d|x1=%d|s=%d|errno=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|m1=%02x%02x%02x%02x%02x%02x\n",
	       rc, f555_ifindex("x1"), s, s < 0 ? errno : 0,
	       F591_X0M[0], F591_X0M[1], F591_X0M[2], F591_X0M[3],
	       F591_X0M[4], F591_X0M[5], F591_X1M[0], F591_X1M[1],
	       F591_X1M[2], F591_X1M[3], F591_X1M[4], F591_X1M[5]);
	c[0] = 'R';
	if (write(F585_S.up[1], c, 1) != 1)
		_exit(4);
	for (;;) {
		struct sockaddr_in d4;
		int n, sh, sl, psel, pl, hl, zc, sent = 0, last = -9;
		int rzc = -1;

		if (f591_readn(F585_S.dn[0], c, 16) != 16)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		if (c[0] == 'd') {
			int cplt = 0, copied = 0, other = 0, tries;

			for (tries = 0; tries < 400; tries++) {
				struct sockaddr_in from;
				struct iovec iov;
				struct msghdr m;
				union {
					struct cmsghdr h;
					unsigned char b[256];
				} ctl;
				unsigned char pay[64];
				struct sock_extended_err *ee;
				struct cmsghdr *cm;
				int r;

				iov.iov_base = pay;
				iov.iov_len = sizeof(pay);
				memset(&m, 0, sizeof(m));
				m.msg_name = &from;
				m.msg_namelen = sizeof(from);
				m.msg_iov = &iov;
				m.msg_iovlen = 1;
				m.msg_control = &ctl;
				m.msg_controllen = sizeof(ctl);
				r = (int)recvmsg(s, &m, MSG_ERRQUEUE | MSG_DONTWAIT);
				if (r < 0) {
					if (errno != EAGAIN && errno != EWOULDBLOCK) {
						other = errno;
						break;
					}
					if (cplt + other > 0)
						break;
					usleep(1000);
					continue;
				}
				rzc = 0;
				for (cm = CMSG_FIRSTHDR(&m); cm;
				     cm = CMSG_NXTHDR(&m, cm)) {
					if (cm->cmsg_level != SOL_IP ||
					    cm->cmsg_type != IP_RECVERR)
						continue;
					ee = (struct sock_extended_err *)CMSG_DATA(cm);
					if (ee->ee_origin ==
					    F594_SO_EE_ORIGIN_ZEROCOPY) {
						cplt++;
						if (ee->ee_code &
						    F594_SO_EE_CODE_ZEROCOPY_COPIED)
							copied++;
					} else {
						other++;
					}
				}
			}
			printf("F594 ZC|sent=%d|zc=%d|cplt=%d|copied=%d|"
			       "other=%d|sozc=%d\n",
			       last_sent, last_zc, cplt, copied, other, rzc);
			last_sent = 0;
			last_zc = 0;
		} else if (c[0] == 's' || c[0] == 'f') {
			const unsigned char *pay;
			int sndflags;

			psel = c[2] & 3;
			n = c[3];
			sh = c[4] == 0xff ? -1 : c[4];
			sl = (c[5] << 8) | c[6];
			pl = (c[7] << 8) | c[8];
			hl = (c[9] << 8) | c[10];
			zc = c[11] ? 1 : 0;
			if (zc) {
				int one = 1;

				if (setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &one,
					       (socklen_t)sizeof(one)) < 0)
					printf("F594 ZCERR|so=%d\n", errno);
			}
			pay = c[0] == 's' ? &F591_PAY[0][0] : &F591_FPAY[0][0];
			if (c[12]) {
				/* 1: page aligned base, 2: base + 3600 so that
				 * every other payload straddles a page. */
				pay = &F594_ABUF[0][0] + (c[12] == 2 ? 3600 : 0);
				if (!abuf_filled) {
					int z;

					for (z = 0; z < F591_ND; z++)
						memcpy(&F594_ABUF[z][0],
						       &F591_PAY[z][0],
						       F591_MAXPL);
					abuf_filled = 1;
				}
			}
			memset(&d4, 0, sizeof(d4));
			d4.sin_family = AF_INET;
			d4.sin_addr.s_addr = htonl(c[1] == 'a' ? A90_DA : A90_DB);
			d4.sin_port = htons(psel == 0 ? F591_DPORT :
					    psel == 1 ? F591_DPORT_G : F591_DPORT_W);
			sndflags = zc ? MSG_ZEROCOPY : 0;
			for (k = 0; k < n; k++) {
				int l = (k == sh) ? sl : (k == 0 && hl) ? hl : pl;

				rc = (int)sendto(s, pay + (size_t)k * F591_MAXPL,
						 (size_t)l, sndflags,
						 (struct sockaddr *)&d4,
						 sizeof(d4));
				last = rc;
				if (rc == l)
					sent++;
			}
			last_sent = sent;
			last_zc = zc;
			printf("F594 CHILDS|cmd=%c%c%d|n=%d|sh=%d|sl=%d|pl=%d|"
			       "zc=%d|sent=%d|rc=%d|errno=%d\n",
			       c[0], c[1], psel, n, sh, sl, pl, zc, sent, last,
			       last < 0 ? errno : 0);
		}
		c[0] = 'D';
		if (write(F585_S.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* ---------- the parent side --------------------------------------------- */

/* f591_setup() with one line changed: the receiver is f594_child_d. */
static int f594_setup(void)
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
		printf("F594 FAIL|pipe\n");
		return -1;
	}
	F585_S.pid = fork();
	if (F585_S.pid < 0) {
		printf("F594 FAIL|fork\n");
		return -1;
	}
	if (F585_S.pid == 0)
		f594_child_s();
	F585_C.pid = fork();
	if (F585_C.pid < 0) {
		printf("F594 FAIL|fork2\n");
		return -1;
	}
	if (F585_C.pid == 0)
		f594_child_d();
	close(F585_S.up[1]);
	close(F585_S.dn[0]);
	close(F585_C.up[1]);
	close(F585_C.dn[0]);
	if (f585_wait_byte(F585_S.up[0], 5000) != 'U') {
		printf("F594 FAIL|senderns\n");
		return -1;
	}
	if (f585_wait_byte(F585_C.up[0], 5000) != 'U') {
		printf("F594 FAIL|recvns\n");
		return -1;
	}
	rc = f585_veth_ns("x0", "x1", (int)F585_S.pid);
	rc |= f585_veth_ns("y1", "y3", (int)F585_C.pid);
	rc |= f585_veth_ns("y2", "y4", (int)F585_C.pid);
	if (rc) {
		printf("F594 FAIL|veth|rc=%d\n", rc);
		return -1;
	}
	set_up("x0");
	set_up("y1");
	set_up("y2");
	printf("F594 GROSW|x0=%d\n", f578_feat_set("x0", F585_GRO_BIT, 1));
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
		printf("F594 FAIL|mactx\n");
		return -1;
	}
	{
		unsigned char c = 'R';

		if (write(F585_C.dn[1], &c, 1) != 1) {
			printf("F594 FAIL|dsync\n");
			return -1;
		}
	}
	if (f585_wait_byte(F585_S.up[0], 8000) != 'R') {
		printf("F594 FAIL|senderready\n");
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
			printf("F594 FAIL|dmac|got=%d\n", got);
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
	printf("F594 FEAT|r1=%d|r2=%d\n", r1, r2);
	f578_feat_get("x0", &g);
	printf("F594 FEAT|dev=x0|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y1", &g);
	printf("F594 FEAT|dev=y1|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y2", &g);
	printf("F594 FEAT|dev=y2|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	{
		int k = 0, r;

		k |= f579_tbl(NFPROTO_IPV4, "f90p");
		k |= f580_chn(NFPROTO_IPV4, "f90p", "fwd", NULL, 2, 0);
		/* a rule that only logs, counts and accepts: the NFLOG window
		 * is how "what the rule saw" becomes a number.  F68..F71 ran
		 * with an EMPTY chain, so their instruments could not see the
		 * aggregation at all -- the socket is the only witness there. */
		r = install_ctl(NFPROTO_IPV4, "f90p", "fwd", F591_GROUP,
				"f72");
		printf("F594 CHAINS|rc=%d|rule=%d\n", k, r);
	}
	F573_NFL = nfl_open(F591_GROUP);
	F585_NFL = F573_NFL;
	f586_taps(1);
	printf("F594 ENV|x0=%d|y1=%d|y2=%d|nfl=%d|addr=%d|"
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

struct f594_rec {
	int len, dlen, tail, end, ts, fl;
};

struct f594_cnt {
	int cond, enq, pull, seg, trim, clone, exp, ubuf;
	int mark_ok;
	int n_cond, n_enq;
	struct f594_rec cnd[16];
	struct f594_rec eq[16];
	int eat[16];
	int n_eat;
};

/* Count ONLY the records of this attempt: those between its BEGIN marker and
 * its END marker.  A write to `trace` does not reset the buffer in this kernel
 * (measured in F70), so attribution is by marker. */
static void f594_dump(int idx, int att, struct f594_cnt *C)
{
	static char big[1 << 20];
	int n = f594_rf(f594_p("/trace"), big, (int)sizeof(big));
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
				printf("F594 TRC|i=%02d|att=%d|%s\n", idx,
				       att, line);
			} else if (strstr(line, b2)) {
				inside = 0;
				printf("F594 TRC|i=%02d|att=%d|%s\n", idx,
				       att, line);
			}
		} else if (inside && strstr(line, "f594cond:")) {
			struct f594_rec *R = NULL;
			int v;

			C->cond++;
			if (C->n_cond < 16) {
				R = &C->cnd[C->n_cond++];
				memset(R, 0, sizeof(*R));
				if (f594_field(line, " len=", &v) == 0)
					R->len = v;
				(void)f594_field(line, "dlen=", &R->dlen);
				(void)f594_field(line, "tail=", &R->tail);
				(void)f594_field(line, "end=", &R->end);
				(void)f594_field(line, "ts=", &R->ts);
				(void)f594_field(line, "fl=", &R->fl);
			}
			printf("F594 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		} else if (inside && strstr(line, "f594enq:")) {
			struct f594_rec *R = NULL;
			int v;

			C->enq++;
			if (C->n_enq < 16) {
				R = &C->eq[C->n_enq++];
				memset(R, 0, sizeof(*R));
				if (f594_field(line, " len=", &v) == 0)
					R->len = v;
				(void)f594_field(line, "dlen=", &R->dlen);
				(void)f594_field(line, "tail=", &R->tail);
				(void)f594_field(line, "end=", &R->end);
				(void)f594_field(line, "ts=", &R->ts);
				(void)f594_field(line, "fl=", &R->fl);
			}
			printf("F594 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		} else if (inside && strstr(line, "f594pull:")) {
			int v;

			C->pull++;
			if (f594_field(line, "eat=", &v) == 0 &&
			    C->n_eat < 16)
				C->eat[C->n_eat++] = v;
			printf("F594 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		} else if (inside && strstr(line, "f594seg:")) {
			C->seg++;
		} else if (inside && strstr(line, "f594clone:")) {
			C->clone++;
		} else if (inside && strstr(line, "f594exp:")) {
			C->exp++;
		} else if (inside && strstr(line, "f594ubuf:")) {
			C->ubuf++;
			printf("F594 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		} else if (inside && strstr(line, "f594trim:")) {
			C->trim++;
			printf("F594 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		}
		if (!e)
			break;
		p = e + 1;
	}
	C->mark_ok = (seen == idx) ? 1 : 0;
}

static void f594_arm(const struct f594_arm *A, int idx)
{
	struct f594_cnt C;
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
		/* 2b. D's packet socket on y3, per arm: 0 none, 1 keep every
		 * frame, 2 a `ret 0` filter so it keeps nothing.  Opened here,
		 * before any measured datagram, and never read. */
		cmdrc |= f586_cmd(&F585_C, 't',
				  (A->dtap >> 24) & 0xff, (A->dtap >> 16) & 0xff,
				  (A->dtap >> 8) & 0xff, A->dtap & 0xff, 0, 0, 0) ?
			1024 : 0;
		/* 3. the filler: one datagram at a time, so it NEVER aggregates,
		 *    each one costing exactly one 1280-byte unit */
		rc = 0;
		for (i = 0; i < A->j; i++) {
			if (f594_send_s(&F585_S, 'f', 'a', psel, 1, 0xff, 0,
					512, 0, 0, 0)) {
				rc = -1;
				break;
			}
			usleep(F594_GAP);
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
		/* 4b. the NFLOG window starts clean: everything logged so far
		 * (the filler) is dropped, so the count below is the burst. */
		nfl_drain(F585_NFL);
		/* 5. from here on, every record belongs to this arm */
		(void)f594_wf(f594_p("/trace"), "\n");
		snprintf(mk, sizeof(mk), "BEGIN i=%02d att=%d %s", idx, att,
			 A->name);
		f594_mark(mk);
		/* 6a. the primer: one 64-byte datagram to a port nobody listens
		 *     on, so x0's NAPI is already inside a poll when the
		 *     measured burst starts (F69 measured that without it the
		 *     first datagram is sometimes processed alone).  It never
		 *     reaches a socket and is never enqueued. */
		cmdrc |= f594_send_s(&F585_S, 's', 'a', 2, 1, 0xff, 0, 64, 0, 0, 0)
			 ? 512 : 0;
		/* 6. the test: one back-to-back burst through the router */
		rc = f594_send_s(&F585_S, 's', 'a', psel, A->n, A->sh, A->sl,
				 A->pl, 0, A->zc, A->align);
		cmdrc |= rc ? 16 : 0;
		/* 7. the queue must be BUILT before it is read */
		wrc2 = f586_cmd(&F585_C, 'w', 0, 0, 0, 0, psel, 0, 0) ? 128 : 0;
		cmdrc |= wrc2;
		/* 7b. what the rule saw, before the socket is drained */
		(void)f594_nfl_count(F585_NFL, psel == 0 ? F591_DPORT :
				     F591_DPORT_G, 400, idx, att);
		snprintf(mk, sizeof(mk), "END i=%02d att=%d", idx, att);
		f594_mark(mk);
		/* 8. reals: the queues before a single read, then the drain */
		cmdrc |= f586_cmd(&F585_C, 'r', idx, att, 0x01, 0x90, psel, 0, 0)
			 ? 32 : 0;
		/* 8b. the zerocopy completions: the ubufs are released when the
		 * receiver's skbs are freed, i.e. by step 8. */
		cmdrc |= f594_send_s(&F585_S, 'd', 0, 0, 0, 0, 0, 0, 0, 0, 0) ?
			64 : 0;
		f594_dump(idx, att, &C);
		printf("F594 CNT|i=%02d|att=%d|enq=%d|cond=%d|pull=%d|seg=%d|"
		       "trim=%d|clone=%d|exp=%d|ubuf=%d|eat=%d|mark=%d\n", idx,
		       att, C.enq, C.cond, C.pull, C.seg, C.trim, C.clone,
		       C.exp, C.ubuf, C.n_eat ? C.eat[0] : -1, C.mark_ok);
		printf("F594 ARM|i=%02d|att=%d|name=%s|xg=%c|skt=%c|j=%d|n=%d|"
		       "pl=%d|sh=%d|sl=%d|rcvbuf=%d|tap=%d|zc=%d|al=%d|dtap=%d|exp_enq=%d|exp_cond=%d|"
		       "exp_pull=%d|exp_seg=%d|exp_dl=%d|exp_charge=%d|"
		       "rc=%d|cmdrc=%d|wrc=%d|wrc2=%d\n",
		       idx, att, A->name, A->xg, A->skt, A->j, A->n, A->pl,
		       A->sh, A->sl, A->rcvbuf, A->tap, A->zc, A->align, A->dtap,
		       A->exp_enq, A->exp_cond,
		       A->exp_pull, A->exp_seg, A->exp_dl, A->exp_charge, rc,
		       cmdrc, wrc > 0, wrc2 > 0);
		if (C.n_enq) {
			int k;

			printf("F594 EQ|i=%02d|att=%d|n=%d|ts=", idx, att,
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

			printf("F594 CQ|i=%02d|att=%d|n=%d|ts=", idx, att,
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

static int f594_run(const struct f594_arm *T, int n, int limit, const char *nm)
{
	int i, upto = limit > 0 && limit < n ? limit : n;

	printf("F594 RUN|mode=%s|arms=%d|run=%d\n", nm, n, upto);
	for (i = 0; i < upto; i++) {
		f594_arm(&T[i], i);
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
	printf("F594 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "zc") || !strcmp(mode, "cl")) {
		if (f594_setup()) {
			printf("F594 FAIL|setup\n");
			return 1;
		}
		f594_probe_up();
		f594_run(AF594, (int)(sizeof(AF594) / sizeof(AF594[0])), limit,
			 mode);
		f591_shutdown();
		return 0;
	}
	return f592_entry(argc, argv);
}
