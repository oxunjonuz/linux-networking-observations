/* ================= turn 596 (F74) =======================================
 *
 * Two debts, both named in F73 section 7:
 *
 *   "what the offset charge does to the receive queue" -- the standing plan
 *   of turn 595: 64 zerocopy datagrams from a page-aligned iov against the
 *   same 64 from an iov starting at 3600, at sk_rcvbuf 38400;
 *
 *   "where `end` comes from (the allocation's bucket, not the payload) is
 *   read, not measured".
 *
 * Mode `q` answers the first with eight curve cells, two one-byte-apart
 * cells, two exact-fit cells and one cell where skb_condense() erases the
 * page charge.  Mode `h` answers the second with nine payloads that bracket
 * the small-head boundary -- one byte decides between three readings.
 *
 * Nothing here is a new kernel: the run uses 7.3.4-T563 as F71..F73 did.
 *
 * The arm table is f595_arm (F73's), unchanged: `q` only uses `n`, `pl`,
 * `rcvbuf`, `zc` and `align`; `h` only `pl`.  The one new number printed is
 * the slab cache size: the model says every skb whose ALIGN(size,64)+320 is
 * at most SKB_SMALL_HEAD_CACHE_SIZE gets a head of exactly that size, and
 * 704 is a number to be read out of the booting kernel, not remembered.
 */

/* the small-head cache of THIS kernel: 704 (source: net/core/skbuff.c:113).
 * sysfs is tried first because it needs no SLUB debug; /proc/slabinfo is the
 * fallback, and both are printed with the byte count that was read, so a
 * truncated read is visible instead of silent (F40 #2, F50 #5, F70 #3). */
static void f596_slab(void)
{
	static char b[1 << 16];
	int n, cap = (int)sizeof(b);

	n = f595_rf("/sys/kernel/slab/skbuff_small_head/object_size", b, cap);
	if (n > 0) {
		printf("F596 SLAB|src=sysfs|obj=%d|n=%d|cap=%d\n", atoi(b), n,
		       cap);
	} else {
		char *p;

		n = f595_rf("/proc/slabinfo", b, cap);
		printf("F596 SLAB|src=slabinfo|n=%d|cap=%d|errno=%d\n", n, cap,
		       errno);
		if (n > 0) {
			for (p = b; p && *p; ) {
				char *e = strchr(p, '\n');
				char *sp = strchr(p, ' ');

				if (!strncmp(p, "skbuff_small_head", 17) && sp) {
					char nm[64];
					long a = 0, o = 0, ns = 0;
					int l = (int)(sp - p);

					if (l > 63)
						l = 63;
					memcpy(nm, p, (size_t)l);
					nm[l] = 0;
					if (sscanf(sp + 1, "%ld %ld %ld",
						   &a, &o, &ns) >= 3)
						printf("F596 SLAB|src=slabinfo"
						       "|name=%s|obj=%ld|"
						       "objects=%ld\n",
						       nm, ns, o);
				}
				if (!e)
					break;
				p = e + 1;
			}
		}
	}
	/* the kmalloc classes, because 768 -- the object size one step above
	 * the small head -- must round up to 1024 for the model to predict a
	 * step of 320 rather than of 64 */
	{
		char *p;
		int k = 0;

		n = f595_rf("/proc/slabinfo", b, cap);
		printf("F596 KMC|n=%d|cap=%d|sizes=", n, cap);
		if (n > 0) {
			for (p = b; p && *p; ) {
				char *e = strchr(p, '\n');
				char *sp = strchr(p, ' ');

				if (!strncmp(p, "kmalloc-", 8) && sp &&
				    strncmp(p, "kmalloc-rcl", 11) &&
				    strncmp(p, "kmalloc-cg", 10)) {
					long a = 0, o = 0, ns = 0;

					if (sscanf(sp + 1, "%ld %ld %ld",
						   &a, &o, &ns) >= 3) {
						printf("%s%ld",
						       k++ ? "," : "", ns);
					}
				}
				if (!e || k > 24)
					break;
				p = e + 1;
			}
		}
		printf("\n");
	}
}

/* F73's own lesson, in a second dress: writing "\n" to `trace` does NOT clear
 * this kernel's ring buffer (F73 error #2), so records accumulate for the
 * whole boot.  F73 lived with it because one armed parsed a small window; here
 * a boot runs 21 arms of 64 datagrams and the accumulation crossed the 2 MB
 * read window of f595_dump by arm 13 -- measured in the first smoke of this
 * turn: from arm 13 on, `mark=0` and every counter zero, while the receiver
 * still reported the right queue (n0=18, rmem=33664).  A witness that has
 * silently stopped watching is the worst kind; the cure is to truncate the
 * file, not to append a newline to it.
 *
 * O_TRUNC is what `echo > trace` does in the shell, and f595_wf (open
 * O_WRONLY) never did.  The clear is done before every arm, never inside one,
 * so a window never straddles two clears. */
static void f596_clear(void)
{
	int fd = open(f595_p("/trace"), O_WRONLY | O_TRUNC);

	if (fd >= 0)
		close(fd);
}

static int f596_run(const struct f595_arm *T, int n, int limit, const char *nm)
{
	int i, upto = limit > 0 && limit < n ? limit : n;

	F595_RUN = nm;
	printf("F595 RUN|mode=%s|arms=%d|run=%d\n", nm, n, upto);
	for (i = 0; i < upto; i++) {
		f596_clear();
		f595_arm(&T[i], i);
		fflush(stdout);
	}
	return 0;
}

/* Mode `q`: the queue's bill for 64 zerocopy datagrams, and who sets it.
 *
 * Every arm: linear GRO door, plain socket 5000, one back-to-back burst of
 * 64, no filler, taps closed; the only thing that changes is the payload's
 * page offset (`align`), the payload, the receive buffer, or the rule. */
static const struct f595_arm AF596_Q[] = {
	/* name          xg skt  j  n   pl sh sl rcvbuf tap zc al sp dtap rule enq cond pull seg  dl  charge */
	{ "q64_a0_R38",   'u', 'p', 0, 64, 512, -1, 0,  19200, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 512, 35392 },
	{ "q64_a36_R38",  'u', 'p', 0, 64, 512, -1, 0,  19200, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 512, 36608 },
	{ "q64_a0_R50",   'u', 'p', 0, 64, 512, -1, 0,  25600, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 512, 50560 },
	{ "q64_a36_R50",  'u', 'p', 0, 64, 512, -1, 0,  25600, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 512, 45760 },
	{ "q64_a0_R76",   'u', 'p', 0, 64, 512, -1, 0,  38400, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 512, 75840 },
	{ "q64_a36_R76",  'u', 'p', 0, 64, 512, -1, 0,  38400, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 512, 73216 },
	{ "q64_a0_R102",  'u', 'p', 0, 64, 512, -1, 0,  51200, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 512, 101120 },
	{ "q64_a36_R102", 'u', 'p', 0, 64, 512, -1, 0,  51200, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 512, 100672 },
	{ "q64_a0_one",   'u', 'p', 0, 64, 512, -1, 0,  17695, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 512, 30336 },
	{ "q64_a0_eq",    'u', 'p', 0, 64, 512, -1, 0,  17696, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 512, 35392 },
	{ "q64_a0_full",  'u', 'p', 0, 64, 512, -1, 0, 161792, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 512, 323584 },
	{ "q64_a36_full", 'u', 'p', 0, 64, 512, -1, 0, 292864, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 512, 585728 },
	{ "q64_a0_cn",    'u', 'p', 0, 64, 512, -1, 0,  19200, 0, 1, 1, 0, 0, 1, 64, -1, -1, -1, 512, 35392 },
	{ "q64_4097a0",   'u', 'p', 0, 64, 4097, -1, 0, 19200, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 4097, 36608 },
	{ "q64_z200",     'u', 'p', 0, 64, 200, -1, 0,  19200, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 200, 33664 },
	/* The five arms below were added AFTER the first smoke, and the reason is
	 * the smoke's own finding: the sender advances its payload pointer by
	 * F591_MAXPL = 2048 bytes, so an `al=2` burst is not at one page offset
	 * -- it alternates 3600 and 1552 (3600 + 2048 - 4096), and therefore
	 * alternates 9152 and 5056.  Those arms stay (they measure the mixed
	 * sequence); these five give the SAME sequence a constant charge without
	 * touching the sender: a 4096-byte payload at either of the two offsets
	 * spans the same two pages, so PAGE_ALIGN(payload + offset) = 8192 for
	 * both, i.e. 9152 per datagram -- the number the alternating arms were
	 * meant to produce.  `q64_4096a0_*` is the matching constant-5056 cell. */
	{ "q64_4096a36_R38",  'u', 'p', 0, 64, 4096, -1, 0, 19200, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 4096, 36608 },
	{ "q64_4096a36_R50",  'u', 'p', 0, 64, 4096, -1, 0, 25600, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 4096, 45760 },
	{ "q64_4096a36_R76",  'u', 'p', 0, 64, 4096, -1, 0, 38400, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 4096, 73216 },
	{ "q64_4096a36_R102", 'u', 'p', 0, 64, 4096, -1, 0, 51200, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 4096, 100672 },
	{ "q64_4096a36_full", 'u', 'p', 0, 64, 4096, -1, 0, 292864, 0, 1, 2, 0, 0, 0, 64, -1, -1, -1, 4096, 585728 },
	{ "q64_4096a0_R38",   'u', 'p', 0, 64, 4096, -1, 0, 19200, 0, 1, 1, 0, 0, 0, 64, -1, -1, -1, 4096, 35392 },
};

/* Mode `h`: one COPIED datagram per arm; the payload is the only variable.
 * 325/326 is the primary boundary (hypothesis A of predictions_596.md §0d);
 * 309/310 and 277/278 are the two named alternatives, so that a refutation
 * is a measurement rather than a reinterpretation. */
static const struct f595_arm AF596_H[] = {
	/* name    xg skt  j n   pl  sh sl rcvbuf tap zc al sp dtap rule enq cond pull seg dl charge */
	{ "h270",  'u', 'p', 0, 1,  270, -1, 0, 19200, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0,  960 },
	{ "h277",  'u', 'p', 0, 1,  277, -1, 0, 19200, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0,  960 },
	{ "h278",  'u', 'p', 0, 1,  278, -1, 0, 19200, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0,  960 },
	{ "h309",  'u', 'p', 0, 1,  309, -1, 0, 19200, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0,  960 },
	{ "h310",  'u', 'p', 0, 1,  310, -1, 0, 19200, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0,  960 },
	{ "h325",  'u', 'p', 0, 1,  325, -1, 0, 19200, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0,  960 },
	{ "h326",  'u', 'p', 0, 1,  326, -1, 0, 19200, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0, 1280 },
	{ "h342",  'u', 'p', 0, 1,  342, -1, 0, 19200, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0, 1280 },
	{ "h5000", 'u', 'p', 0, 1, 5000, -1, 0, 19200, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0, 8448 },
};

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "q";
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
	printf("F596 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "q") || !strcmp(mode, "h") || !strcmp(mode, "all")) {
		int nq = (int)(sizeof(AF596_Q) / sizeof(AF596_Q[0]));
		int nh = (int)(sizeof(AF596_H) / sizeof(AF596_H[0]));

		if (f595_setup()) {
			printf("F596 FAIL|setup\n");
			return 1;
		}
		if (f595_probe_up()) {
			printf("F596 FAIL|probe\n");
			return 1;
		}
		f596_slab();
		if (!strcmp(mode, "q") || !strcmp(mode, "all"))
			f596_run(AF596_Q, nq, !strcmp(mode, "q") ? limit : 0,
				 "q");
		if (!strcmp(mode, "h") || !strcmp(mode, "all"))
			f596_run(AF596_H, nh, !strcmp(mode, "h") ? limit : 0,
				 "h");
		f591_shutdown();
		return 0;
	}
	return f595_entry(argc, argv);
}
