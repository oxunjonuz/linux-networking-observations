/* ================= turn 592 (F70) =======================================
 *
 * The debt of F67 §6 and F68 §9, in their own words: "какая функция теряет
 * N·s" and "строгость > в сравнении с половиной буфера не проверена".
 *
 * F67/F69 INFERRED the branch from the queue arithmetic:
 *
 *     net/ipv4/udp.c, __udp_enqueue_schedule_skb():
 *         if (rmem + size > rcvbuf) { ... goto drop; }
 *         if (rmem > (rcvbuf >> 1)) {
 *                 skb_condense(skb);
 *                 size = skb->truesize;
 *         }
 *
 *     net/core/skbuff.c, skb_condense():
 *         if (skb->data_len) {
 *                 if (skb->data_len > skb->end - skb->tail ||
 *                     skb_cloned(skb) || !skb_frags_readable(skb))
 *                         return;                       // early return
 *                 __pskb_pull_tail(skb, skb->data_len);
 *         }
 *         skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
 *
 * and concluded that on the fraglist door the FIRST segment -- built by
 * skb_segment_list(), which subtracts len and data_len from the head and never
 * touches truesize -- arrives at the enqueue path already linear (data_len ==
 * 0) carrying the WHOLE aggregate's truesize, and that the last line above
 * therefore rewrites n*s into one datagram's worth.
 *
 * This instrument measures the branch instead of inferring it: a kprobe on
 * skb_condense() with fetchargs at the field offsets pahole reads out of
 * vmlinux's DWARF (len 112, dlen 116, tail 188, end 192, truesize 216,
 * flags 126), plus counters on __pskb_pull_tail (did it linearise?),
 * __udp_enqueue_schedule_skb (how many enqueues), ___pskb_trim (the other
 * caller of skb_condense) and skb_segment_list (which segmenter ran).
 *
 * The queue is put at an exact position by a filler sent ONE DATAGRAM AT A
 * TIME, 250 ms apart, so it never aggregates: F = j * 1280 exactly.  Every
 * arm then sends one back-to-back burst through the router's GRO door.
 *
 * Nothing here touches nft: the arm needs the queue and the trace, nothing
 * else.  Topology, veths, netns and the sender/receiver children are F68/F69's
 * unchanged (f591_setup()).
 */

#include <sys/mount.h>

#define F592_TRC	"/sys/kernel/tracing"
#define F592_TRCD	"/sys/kernel/debug/tracing"
#define F592_S		1280		/* truesize of one 512-byte datagram */
#define F592_GAP	250000		/* us between filler datagrams */

/* field offsets of struct sk_buff in THIS kernel, from
 *   pahole -C sk_buff vmlinux   (DWARF5, the bytes that boot) */
#define F592_O_LEN	112
#define F592_O_DLEN	116
#define F592_O_TAIL	188
#define F592_O_END	192
#define F592_O_TS	216
#define F592_O_FL	126

struct f592_arm {
	const char *name;
	char xg;	/* GRO at x0: 'f' fraglist, 'u' linear (udp_fwd) */
	int j;		/* filler datagrams, one at a time, F592_GAP apart */
	int n;		/* test datagrams, back to back */
	int pl;		/* test payload length */
	int sh;		/* short-tail datagram index, -1 none */
	int sl;		/* its payload length */
	int rcvbuf;	/* SO_RCVBUF request (sk_rcvbuf becomes 2x this) */
	int exp_f;	/* expected rmem after the filler */
	int exp_delta;	/* expected rmem after the test minus exp_f */
	int exp_calls;	/* expected calls of skb_condense in the arm */
	int exp_t0;	/* expected truesize of the first call, -1 any */
	int exp_pull;	/* expected calls of __pskb_pull_tail */
	int exp_seg;	/* expected skb_segment_list calls, -1 any */
};

/* s = 1280, rcvbuf request 19200 -> sk_rcvbuf 38400 -> half = 19200.
 * test n = 6 -> head truesize 6*1280 = 7680; fraglist charge (2n-1)*s = 14080;
 * linear charge n*s = 7680. */
static const struct f592_arm AF592_COND[] = {
	/* name      xg   j   n   pl   sh  sl rcvbuf exp_f exp_delta calls t0 pull seg */
	{ "c_zero", 'f',  0,  6, 512, -1,  0, 19200,     0,    14080,   0,   -1,  0, 1 },
	{ "c_lt",   'f', 13,  6, 512, -1,  0, 19200, 16640,    14080,   5, 1280,  0, 1 },
	{ "c_eq",   'f', 15,  6, 512, -1,  0, 19200, 19200,    14080,   5, 1280,  0, 1 },
	{ "c_gt",   'f', 16,  6, 512, -1,  0, 19200, 20480,     7680,   6, 7680,  0, 1 },
	{ "c_eq2",  'f', 15,  6, 512, -1,  0, 19200, 19200,    14080,   5, 1280,  0, 1 },
	{ "c_gt2",  'f', 16,  6, 512, -1,  0, 19200, 20480,     7680,   6, 7680,  0, 1 },
	{ "c_one",  'f', 16,  1, 512, -1,  0, 19200, 20480,     1280,   1, 1280,  0, 0 },
	{ "c_lin",  'u', 16,  6, 512, -1,  0, 19200, 20480,     7680,   6, 1280,  0, 0 },
	{ "c_tail", 'f', 16,  6, 512,  5, 200, 19200, 20480,       -1,  -1,   -1, -1, 1 },
};

static int F592_T_ok;			/* tracefs is up */
static const char *F592_T = F592_TRC;

/* build a tracefs path; four rotating buffers so one statement can use two */
static const char *f592_p(const char *suffix)
{
	static char b[4][192];
	static int r;
	char *p = b[r++ & 3];

	snprintf(p, sizeof(b[0]), "%s%s", F592_T, suffix);
	return p;
}

static int f592_wf(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);
	int r;

	if (fd < 0)
		return -1;
	r = (int)write(fd, s, strlen(s));
	close(fd);
	return r < 0 ? -1 : 0;
}

/* read a whole file into buf, NUL-terminated; returns bytes or -1 */
static int f592_rf(const char *path, char *buf, int cap)
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

static int f592_probe_up(void)
{
	char b[256];
	int i;

	mkdir(F592_TRC, 0755);
	if (mount("none", F592_TRC, "tracefs", 0, NULL) && errno != EBUSY) {
		mkdir("/sys/kernel/debug", 0755);
		(void)mount("none", "/sys/kernel/debug", "debugfs", 0, NULL);
		if (access(F592_TRCD "/kprobe_events", W_OK) == 0)
			F592_T = F592_TRCD;
	}
	if (access(f592_p("/kprobe_events"), W_OK)) {
		printf("F592 PROBE|ok=0|errno=%d|path=%s\n", errno, F592_T);
		return -1;
	}
	(void)f592_wf(f592_p("/tracing_on"), "0");
	(void)f592_wf(f592_p("/kprobe_events"), "\n");	/* clear any old */
	snprintf(b, sizeof(b),
		 "p:f592cond skb_condense len=+%d(%%di):u32 dlen=+%d(%%di):u32 "
		 "tail=+%d(%%di):u32 end=+%d(%%di):u32 ts=+%d(%%di):u32 "
		 "fl=+%d(%%di):u8\n",
		 F592_O_LEN, F592_O_DLEN, F592_O_TAIL, F592_O_END, F592_O_TS,
		 F592_O_FL);
	if (f592_wf(f592_p("/kprobe_events"), b)) {
		printf("F592 PROBE|ok=0|why=cond\n");
		return -1;
	}
	(void)f592_wf(f592_p("/kprobe_events"), "p:f592pull __pskb_pull_tail\n");
	(void)f592_wf(f592_p("/kprobe_events"),
		      "p:f592enq __udp_enqueue_schedule_skb\n");
	(void)f592_wf(f592_p("/kprobe_events"), "p:f592trim ___pskb_trim\n");
	(void)f592_wf(f592_p("/kprobe_events"), "p:f592seg skb_segment_list\n");
	{
		static const char *ev[] = { "f592cond", "f592pull", "f592enq",
					    "f592trim", "f592seg" };
		int ok = 0;

		for (i = 0; i < 5; i++) {
			char p[128];

			snprintf(p, sizeof(p), "%s/events/kprobes/%s/enable",
				 F592_T, ev[i]);
			if (f592_wf(p, "1") == 0)
				ok |= 1 << i;
		}
		printf("F592 PROBE|ok=%d|mask=%02x|path=%s|"
		       "off=%d,%d,%d,%d,%d,%d\n",
		       ok == 0x1f ? 1 : 0, ok, F592_T, F592_O_LEN, F592_O_DLEN,
		       F592_O_TAIL, F592_O_END, F592_O_TS, F592_O_FL);
		if (ok != 0x1f)
			return -1;
	}
	/* the kernel's own echo of the definition: the provenance of the
	 * offsets, printed by the kernel, not by me */
	{
		/* the buffer must hold ALL five definitions: 255 bytes was not
		 * enough and silently printed "p:k" -- a witness that lies about
		 * its own size, the class of F40 #2 and F50 #5, found here by
		 * verify592.py's check that the kernel's echo is complete. */
		static char kb[4096];
		char *nl = kb;
		int k = 0;

		kb[0] = 0;
		if (f592_rf(f592_p("/kprobe_events"), kb, (int)sizeof(kb)) > 0) {
			while (*nl && k < 8) {
				char *e = strchr(nl, '\n');
				char line[300];

				if (e)
					*e = 0;
				snprintf(line, sizeof(line), "%s", nl);
				if (line[0])
					printf("F592 DEF|%s\n", line);
				k++;
				if (!e)
					break;
				nl = e + 1;
			}
		}
	}
	(void)f592_wf(f592_p("/trace"), "\n");
	(void)f592_wf(f592_p("/tracing_on"), "1");
	F592_T_ok = 1;
	return 0;
}

static void f592_mark(const char *what)
{
	if (F592_T_ok)
		(void)f592_wf(f592_p("/trace_marker"), what);
}

/* find "key=" after the event name and return the first int, or -1 */
static int f592_field(const char *line, const char *key, int *out)
{
	const char *p = strstr(line, key);

	if (!p)
		return -1;
	*out = atoi(p + strlen(key));
	return 0;
}

struct f592_cnt {
	int cond, pull, enq, trim, seg;
	int mark_ok;
	int ts_n;
	int ts[128];
	int dl[128];
	int ln[128];
	int tail[128], end[128], fl[128];
};

/* Read the trace buffer and count ONLY the records of this attempt: those
 * between its BEGIN marker and its END marker.  The buffer cannot be relied
 * on to be cleared (measured: a write to `trace` did not reset it in this
 * kernel), so attribution is by marker, and a record outside the markers
 * belongs to the filler or to the previous arm. */
static void f592_dump(int idx, int att, struct f592_cnt *C)
{
	static char big[1 << 20];
	int n = f592_rf(f592_p("/trace"), big, (int)sizeof(big));
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
				printf("F592 TRC|i=%02d|att=%d|%s\n", idx,
				       att, line);
			} else if (strstr(line, b2)) {
				inside = 0;
				printf("F592 TRC|i=%02d|att=%d|%s\n", idx,
				       att, line);
			}
		} else if (!inside) {
			/* outside this attempt: counted nowhere */
		} else if (strstr(line, "f592cond:")) {
			int v;

			C->cond++;
			if (f592_field(line, " len=", &v) == 0 &&
			    C->ts_n < 128) {
				C->ln[C->ts_n] = v;
				(void)f592_field(line, "dlen=",
						 &C->dl[C->ts_n]);
				(void)f592_field(line, "tail=",
						 &C->tail[C->ts_n]);
				(void)f592_field(line, "end=",
						 &C->end[C->ts_n]);
				(void)f592_field(line, "ts=",
						 &C->ts[C->ts_n]);
				(void)f592_field(line, "fl=",
						 &C->fl[C->ts_n]);
				C->ts_n++;
			}
			printf("F592 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		} else if (strstr(line, "f592pull:")) {
			C->pull++;
		} else if (strstr(line, "f592enq:")) {
			C->enq++;
		} else if (strstr(line, "f592trim:")) {
			C->trim++;
			printf("F592 TRC|i=%02d|att=%d|%s\n", idx, att, line);
		} else if (strstr(line, "f592seg:")) {
			C->seg++;
		}
		if (!e)
			break;
		p = e + 1;
	}
	C->mark_ok = (seen == idx) ? 1 : 0;
}

static void f592_arm(const struct f592_arm *A, int idx)
{
	struct f592_cnt C;
	char mk[96];
	int att, i, rc = -99, cmdrc = 0, wrc = 0, wrc2 = 0;

	for (att = 0; att < 2; att++) {
		/* 1. the shape of x0's GRO: a device bit the socket cannot see */
		(void)f578_feat_set("x0", F585_GRO_BIT, 1);
		(void)f578_feat_set("x0", F585_GROFL_BIT, A->xg == 'f');
		(void)f578_feat_set("x0", F585_GROFWD_BIT, A->xg == 'u');
		/* 2. clean slate: the buffer, the queue */
		cmdrc |= f586_cmd(&F585_C, 'p',
				  (A->rcvbuf >> 24) & 0xff,
				  (A->rcvbuf >> 16) & 0xff,
				  (A->rcvbuf >> 8) & 0xff,
				  A->rcvbuf & 0xff, 0, 0, 0) ? 1 : 0;
		usleep(300000);
		/* 3. the filler: one datagram at a time, so it NEVER aggregates
		 *    and each one costs exactly one s */
		rc = 0;
		for (i = 0; i < A->j; i++) {
			if (f591_send_s(&F585_S, 'f', 'b', 0, 1, 0xff, 0, 512, 0)) {
				rc = -1;
				break;
			}
			usleep(F592_GAP);
		}
		cmdrc |= rc ? 8 : 0;
		/* 4. the queue must be exactly where the model says it is */
		wrc = f586_cmd(&F585_C, 'w',
			       (A->exp_f >> 24) & 0xff, (A->exp_f >> 16) & 0xff,
			       (A->exp_f >> 8) & 0xff, A->exp_f & 0xff,
			       0, 0, 0) ? 256 : 0;
		cmdrc |= wrc;
		usleep(150000);
		/* 5. from here on, every record belongs to this arm */
		(void)f592_wf(f592_p("/trace"), "\n");
		snprintf(mk, sizeof(mk), "BEGIN i=%02d att=%d %s", idx, att,
			 A->name);
		f592_mark(mk);
		/* 6a. the primer: one 64-byte datagram to a port nobody listens
		 *     on, so that x0's NAPI is already inside a poll when the
		 *     measured burst starts (F69: without it the first
		 *     datagram of a burst is sometimes processed alone and the
		 *     aggregate splits, which changes the charge).  It never
		 *     reaches the socket and is never enqueued. */
		cmdrc |= f591_send_s(&F585_S, 's', 'a', 2, 1, 0xff, 0, 64, 0)
			 ? 512 : 0;
		/* 6. the test: one back-to-back burst through the router */
		rc = f591_send_s(&F585_S, 's', 'a', 0, A->n, A->sh, A->sl, A->pl,
				 0);
		cmdrc |= rc ? 16 : 0;
		/* 7. the queue must be BUILT before it is read */
		wrc2 = f586_cmd(&F585_C, 'w', 0, 0, 0, 0, 0, 0, 0) ? 128 : 0;
		cmdrc |= wrc2;
		snprintf(mk, sizeof(mk), "END i=%02d att=%d", idx, att);
		f592_mark(mk);
		/* 8. reals: the queue before a single read, then the drain */
		cmdrc |= f586_cmd(&F585_C, 'r', idx, att, 0x01, 0x90, 0, 0, 0)
			 ? 32 : 0;
		f592_dump(idx, att, &C);
		printf("F592 CNT|i=%02d|att=%d|cond=%d|pull=%d|enq=%d|trim=%d|"
		       "seg=%d|mark=%d\n", idx, att, C.cond, C.pull, C.enq,
		       C.trim, C.seg, C.mark_ok);
		printf("F592 ARM|i=%02d|att=%d|name=%s|xg=%c|j=%d|n=%d|pl=%d|"
		       "sh=%d|sl=%d|rcvbuf=%d|exp_f=%d|exp_delta=%d|exp_calls=%d|"
		       "exp_t0=%d|exp_pull=%d|exp_seg=%d|rc=%d|cmdrc=%d|"
		       "wrc=%d|wrc2=%d\n",
		       idx, att, A->name, A->xg, A->j, A->n, A->pl, A->sh, A->sl,
		       A->rcvbuf, A->exp_f, A->exp_delta, A->exp_calls,
		       A->exp_t0, A->exp_pull, A->exp_seg, rc, cmdrc, wrc > 0,
		       wrc2 > 0);
		if (C.ts_n) {
			int k;

			printf("F592 SEQ|i=%02d|att=%d|n=%d|ts=", idx, att,
			       C.ts_n);
			for (k = 0; k < C.ts_n && k < 16; k++)
				printf("%s%d", k ? "," : "", C.ts[k]);
			printf("|dlen=");
			for (k = 0; k < C.ts_n && k < 16; k++)
				printf("%s%d", k ? "," : "", C.dl[k]);
			printf("|len=");
			for (k = 0; k < C.ts_n && k < 16; k++)
				printf("%s%d", k ? "," : "", C.ln[k]);
			printf("|tail=");
			for (k = 0; k < C.ts_n && k < 16; k++)
				printf("%s%d", k ? "," : "", C.tail[k]);
			printf("|end=");
			for (k = 0; k < C.ts_n && k < 16; k++)
				printf("%s%d", k ? "," : "", C.end[k]);
			printf("|fl=");
			for (k = 0; k < C.ts_n && k < 16; k++)
				printf("%s%d", k ? "," : "", C.fl[k]);
			printf("\n");
		}
		fflush(stdout);
	}
}

static int f592_run(const struct f592_arm *T, int n, int limit, const char *nm)
{
	int i, upto = limit > 0 && limit < n ? limit : n;

	printf("F592 RUN|mode=%s|arms=%d|run=%d\n", nm, n, upto);
	for (i = 0; i < upto; i++) {
		f592_arm(&T[i], i);
		fflush(stdout);
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "cond";
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
	printf("F592 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "cond")) {
		if (f591_setup()) {
			printf("F592 FAIL|setup\n");
			return 1;
		}
		f592_probe_up();
		f592_run(AF592_COND,
			 (int)(sizeof(AF592_COND) / sizeof(AF592_COND[0])),
			 limit, "cond");
		f591_shutdown();
		return 0;
	}
	return f591_entry(argc, argv);
}
