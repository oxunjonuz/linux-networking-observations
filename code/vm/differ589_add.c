/* ================= turn 589 (F67) ========================================
 *
 * Two debts named in F66 §8:
 *
 * (a) "Для 1200 байт измерено только одно плечо (s = 2304), и его буфер был
 *     425984, а не дефолтный" -- the 1200-byte budget at the buffer the socket
 *     is actually born with, plus a 1200-byte sweep of the same formula.
 *
 * (b) "skb_condense() ... заметно не срабатывал" -- the branch is reached only
 *     when rmem > rcvbuf/2 at the enqueue of an skb, and the one skb whose
 *     truesize is NOT SKB_TRUESIZE(end_offset) is the head segment of an
 *     aggregate (it is charged the whole aggregate).  To reach the branch at a
 *     head, the queue must already be above half when a NEW aggregate arrives:
 *     a filler aggregate to the other door does exactly that.  The filler and
 *     the test differ by destination address, which ipv6_gro_receive() makes a
 *     different flow, so they never merge.
 *
 * Also: rb = -1 now means "the socket's own default", and the default is read
 * back once at setup (F67 DEFRB) instead of being assumed.
 */

struct f589_arm {
	const char *name;
	char dst;	/* the test's door: 'a' fd03::92 (y1), 'b' fd04::92 (y2) */
	char fdst;	/* the filler's door, 0 = no filler */
	int fn;		/* filler datagrams */
	int fpl;	/* filler payload length */
	int n;		/* test datagrams */
	int pl;		/* test payload length */
	int rcvbuf;	/* SO_RCVBUF request; -1 = the socket's own default */
	int lazy;	/* 10 ms units the reader waits before reading, 0 eager */
	int exp;	/* packets the rule is expected to count */
};

/* mode `dflt`: the true default buffer, and the 1200-byte budget curve */
static const struct f589_arm AF589_DFLT[] = {
	{ "d54_lazy",	  'a', 0,   0,   0, 54, 1200, -1, 40, 1 },
	{ "d54_eag",	  'a', 0,   0,   0, 54, 1200, -1,  0, 1 },
	{ "d54_lazy_b",	  'b', 0,   0,   0, 54, 1200, -1, 40, 1 },
	{ "d64_lazy",	  'a', 0,   0,   0, 64,  512, -1, 40, 1 },
	{ "d64x1200_lazy",'a', 0,   0,   0, 64, 1200, -1, 40, 2 },
	/* kept = 1 + floor((R - 124416) / 2304); R = 2v */
	{ "d1200_133120", 'a', 0,   0,   0, 54, 1200,  66560, 40, 1 },
	{ "d1200_143360", 'a', 0,   0,   0, 54, 1200,  71680, 40, 1 },
	{ "d1200_153600", 'a', 0,   0,   0, 54, 1200,  76800, 40, 1 },
	{ "d1200_163840", 'a', 0,   0,   0, 54, 1200,  81920, 40, 1 },
	{ "d1200_184320", 'a', 0,   0,   0, 54, 1200,  92160, 40, 1 },
};

/* mode `cond`: a filler aggregate first, then the test aggregate, so that the
 * test's head segment meets the queue above half a buffer */
static const struct f589_arm AF589_COND[] = {
	{ "c_only_fill",	 'a', 'b', 64, 512,  0, 512, 131072, 40, 1 },
	{ "c_only_test",	 'a', 0,    0,   0, 64, 512, 131072, 40, 1 },
	{ "c_fill_test",	 'a', 'b', 64, 512, 64, 512, 131072, 40, 2 },
	{ "c_fill_test1200_262", 'a', 'b', 64, 512, 54, 1200, 131072, 40, 2 },
	{ "c_fill_test1200_311", 'a', 'b', 64, 512, 54, 1200, 155648, 40, 2 },
	{ "c_fill_test1200_344", 'a', 'b', 64, 512, 54, 1200, 172032, 40, 2 },
	{ "c_fill_s512_212",	 'a', 'b', 64, 512, 64,  512, 106496, 40, 2 },
};

static int f589_send(char cmd, int dst, int n, int pl)
{
	return f586_cmd(&F585_S, cmd, dst, 0, n, 0xff, 0,
			(pl >> 8) & 0xff, pl & 0xff);
}

/* every message the drain kept, one line each: length, UDP length field, the
 * destination's own bytes, and the first payload byte */
static int f589_msgs(const struct f575_pl *pl, int idx, int att)
{
	int n = 0, i;

	for (i = 0; i < pl->n && i < F575_NPL; i++) {
		const struct f575_msg *M = &pl->m[i];
		int st = 1680;
		char u6[24] = "-", ud[16] = "-", p0[24] = "-", dd[16] = "-";

		if (strncmp(M->prefix, "86:", 3))
			continue;
		f587_sl(u6, sizeof(u6), M->p, st, 4, 6);
		f587_sl(dd, sizeof(dd), M->p, st, 24, 28);
		f587_sl(ud, sizeof(ud), M->p, st, 40, 48);
		f587_sl(p0, sizeof(p0), M->p, st, 48, 56);
		printf("F589 MSG|i=%02d|att=%d|k=%d|plen=%d|u6=%s|dst=%s|"
		       "udp=%s|p0=%s\n", idx, att, n, M->plen, u6, dd, ud, p0);
		n++;
	}
	return n;
}

static void f589_arm(const struct f589_arm *A, int idx)
{
	struct f575_pl pl;
	struct f585_arm B;
	int rc = -99, cmdrc = 0, att, acks = 0, mn = 0, mn0 = 0;
	int ch0 = -1, ch1 = -1, agr = -1;
	int win = A->lazy * 10 + 400;

	memset(&B, 0, sizeof(B));
	B.name = A->name;
	B.src = 'F';
	B.dst = A->dst;
	B.xg = 'f';		/* the fraglist shape: F66's rx-gro-list */
	B.skt = 'p';
	B.store = 0;
	f578_feat_set("x0", F585_GRO_BIT, 1);
	f578_feat_set("x0", F585_GROFL_BIT, 1);
	f578_feat_set("x0", F585_GROFWD_BIT, 0);
	(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
	(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
	f575_nfl_drain(&pl);
	cmdrc |= f586_cmd(&F585_C, 'p', 0, 0, 0, 0, 0, 0, 0) ? 1 : 0;
	cmdrc |= f586_cmd(&F585_C, 'v', (A->rcvbuf >> 24) & 0xff,
			  (A->rcvbuf >> 16) & 0xff, (A->rcvbuf >> 8) & 0xff,
			  A->rcvbuf & 0xff, 0, 0, 0) ? 2 : 0;
	cmdrc |= f586_cmd(&F585_C, 'b', 0, 0, 0, 0, 0, 0, 0) ? 4 : 0;
	for (att = 0; att < 2; att++) {
		(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
		(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
		f575_nfl_drain(&pl);
		rc = f585_rule(&B, idx, NULL, 0);
		if (A->fn > 0)	/* the filler: F589_FPAY, first byte >= 0x80 */
			cmdrc |= f589_send('f', A->fdst, A->fn, A->fpl) ? 8 : 0;
		cmdrc |= f589_send('s', A->dst, A->n, A->pl) ? 16 : 0;
		cmdrc |= f586_cmd(&F585_C, 'r', idx, 0, att,
				  (win >> 8) & 0xff, win & 0xff,
				  A->lazy, 0) ? 32 : 0;
		f585_tap_drain(&F585_TA);
		f585_tap_drain(&F585_TB);
		f575_nfl_drain(&pl);
		ch1 = (int)f555_count(NFPROTO_IPV6, "f85p", "fwd");
		mn = f589_msgs(&pl, idx, att);
		if (att == 0) {
			ch0 = ch1;
			mn0 = mn;
		} else {
			agr = (ch1 == ch0 && mn == mn0) ? 1 : 0;
		}
	}
	printf("F589 ARM|i=%02d|name=%s|dst=%c|fdst=%c|fn=%d|fpl=%d|n=%d|"
	       "pl=%d|rcvbuf=%d|lazy=%d|exp=%d|rc=%d|cmdrc=%d|ch=%d|ch0=%d|"
	       "agr=%d|mn=%d|mn0=%d|an=%d|anall=%d|bn=%d|bnall=%d\n",
	       idx, A->name, A->dst, A->fdst ? A->fdst : '-', A->fn, A->fpl,
	       A->n, A->pl, A->rcvbuf, A->lazy, A->exp, rc, cmdrc, ch1, ch0,
	       agr, mn, mn0, F585_TA.n, F585_TA.nall, F585_TB.n, F585_TB.nall);
	fflush(stdout);
	f585_tap_print(&F585_TA, idx, "y1");
	f585_tap_print(&F585_TB, idx, "y2");
	fflush(stdout);
}

static int f589_run(const struct f589_arm *T, int n, int limit, const char *nm)
{
	int i;

	printf("F587 GROTO_PLAN|timeout=200000000|defer=1|F67=1\n");
	if (f587_setup())
		return -1;
	for (i = 0; i < n; i++) {
		if (limit > 0 && i >= limit) {
			printf("F587 SKIP|from=%d|limit=%d\n", i, limit);
			break;
		}
		f589_arm(&T[i], i);
	}
	f587_shutdown();
	printf("F587 END|mode=%s|arms=%d\n", nm, i);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "dflt";
	int limit = argc > 2 ? atoi(argv[2]) : 0;
	char mbuf[32];

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
	printf("F589 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "dflt"))
		return f589_run(AF589_DFLT,
				(int)(sizeof(AF589_DFLT) / sizeof(AF589_DFLT[0])),
				limit, "dflt");
	if (!strcmp(mode, "cond"))
		return f589_run(AF589_COND,
				(int)(sizeof(AF589_COND) / sizeof(AF589_COND[0])),
				limit, "cond");
	return f588_entry(argc, argv);
}
