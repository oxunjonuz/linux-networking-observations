/* ================= turn 588 (F66) =======================================
 *
 * Two debts named in F65 §9 and one defect named there too.
 *
 * (a) "the delivery split's mechanism".  F65 saw a socket receive 29..64 of
 *     64 segmented datagrams and called the split a race.  The candidate is
 *     the receive buffer, not the reader: __udp_enqueue_schedule_skb()
 *     drops as soon as `rmem + size > rcvbuf`, with one exception -- a packet
 *     is accepted when the queue is EMPTY whatever its size.  Hold the
 *     reader back (lazy) and sweep SO_RCVBUF, and the count becomes a
 *     function of the budget alone.
 *
 * (b) "what the extra byte in the byte cap is".  The two GRO shapes check
 *     different lengths:
 *       skb_gro_receive():      p->len + skb_gro_len(skb)   -- payload only
 *       skb_gro_receive_list(): p->len + skb->len           -- L3 + payload
 *     while p->len grows by the payload in both.  So with H = L3+L4 header:
 *       linear : H + N*P < 65536
 *       fraglist: 2H + N*P < 65536
 *     and the 64-datagram ceiling differs by one payload byte at N=64.  A
 *     shorter tail on 63 equal datagrams walks the same check to the byte.
 *
 * (c) the parent's y1/y2 taps: fd 0 fixed in F65, still empty because an
 *     egress tap sees PACKET_OUTGOING only.  only_out = 1 now.
 */

struct f588_arm {
	const char *name;
	char src;	/* 's' socket (CHECKSUM_PARTIAL), 'p' hand-built frame */
	char dst;	/* 'a' y1 fd03::92, 'b' y2 fd04::92 */
	char xg;	/* GRO at x0: 'n' none, 'u' udp_fwd (linear), 'f' fraglist */
	int n;		/* datagrams */
	int pl;		/* default payload length */
	int sh;		/* index of the short one, -1 none */
	int sl;		/* its payload length */
	int store;
	unsigned int off, len;
	const char *hex;
	int exp;	/* packets the rule is expected to count */
	int rcvbuf;	/* SO_RCVBUF requested, 0 = leave the default */
	int lazy;	/* 10 ms units the reader waits before reading, 0 eager */
};

static const struct f588_arm AF588_SPLIT[] = {
	/* 64 datagrams of 512 leave S as 64 packets and reach D as one
	 * aggregate; the socket's budget decides how many of the 64 survive */
	{ "q_def_lazy",	   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 212992, 40 },
	{ "q_def_eager",   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 212992, 0 },
	{ "q1024_lazy",	   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 1024, 40 },
	{ "q4096_lazy",	   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 4096, 40 },
	{ "q8192_lazy",	   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 8192, 40 },
	{ "q16384_lazy",   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 16384, 40 },
	{ "q32768_lazy",   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 32768, 40 },
	{ "q65536_lazy",   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 65536, 40 },
	{ "q131072_lazy",  's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 131072, 40 },
	{ "q262144_lazy",  's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 262144, 40 },
	{ "q1048576_lazy", 's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 1048576, 40 },
	{ "q1048576_eag",  's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 1048576, 0 },
	/* where the budget binds: the same 64 datagrams, the same reader, only
	 * the pace differs */
	{ "q65536_eag",	   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 65536, 0 },
	{ "q131072_eag",   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 131072, 0 },
	/* F65's own regime: one aggregate of 54 x 1200 on the default buffer,
	 * where F65 saw the socket keep 29..64 datagrams */
	{ "q54x1200_lazy", 's', 'a', 'f', 54, 1200, -1, 0, 0, 0, 0, NULL, 0, 212992, 40 },
	{ "q54x1200_eag",  's', 'a', 'f', 54, 1200, -1, 0, 0, 0, 0, NULL, 0, 212992, 0 },
	/* The budget model fitted on rcvbuf 131072 (39 kept) and refitted from the
 * queue bytes: the first segment carries the whole aggregate's truesize
 * (64 x 1280 = 81920), each further one 1280, so
 *   kept = min(64, 1 + floor((rcvbuf_eff - 81920) / 1280)).
 * SO_RCVBUF(v) gives rcvbuf_eff = 2v, so these three requests predict
 * 13, 26 and 52 kept -- points the model was NOT fitted on. */
	{ "q49152_lazy",   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 49152, 40 },
	{ "q57344_lazy",   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 57344, 40 },
	{ "q73728_lazy",   's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 0, 73728, 40 },
/* the witness arm: three datagrams, one store, three places to see it */
	{ "t3_store_a",	   's', 'a', 'f', 3, 512, -1, 0, 1, 8, 4, "a0a1a2a3", 1, 0, 0 },
};

static const struct f588_arm AF588_CAP[] = {
	/* the same 64 datagrams through the two GRO shapes */
	{ "ku1022_f", 's', 'a', 'f', 64, 1022, -1, 0, 0, 0, 0, NULL, 1, 1048576, 0 },
	{ "ku1023_f", 's', 'a', 'f', 64, 1023, -1, 0, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "ku1023_u", 's', 'a', 'u', 64, 1023, -1, 0, 0, 0, 0, NULL, 1, 1048576, 0 },
	{ "ku1024_u", 's', 'a', 'u', 64, 1024, -1, 0, 0, 0, 0, NULL, 2, 1048576, 0 },
	/* fraglist: 63 x 1023 + one shorter tail; merged iff
	 * 2H + 63*1023 + sl < 65536, i.e. sl < 1150 - 2H */
	{ "tf960", 's', 'a', 'f', 64, 1023, 63, 960, 0, 0, 0, NULL, 1, 1048576, 0 },
	{ "tf962", 's', 'a', 'f', 64, 1023, 63, 962, 0, 0, 0, NULL, 1, 1048576, 0 },
	{ "tf963", 's', 'a', 'f', 64, 1023, 63, 963, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tf965", 's', 'a', 'f', 64, 1023, 63, 965, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tf980", 's', 'a', 'f', 64, 1023, 63, 980, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tf988", 's', 'a', 'f', 64, 1023, 63, 988, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tf989", 's', 'a', 'f', 64, 1023, 63, 989, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tf990", 's', 'a', 'f', 64, 1023, 63, 990, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tf991", 's', 'a', 'f', 64, 1023, 63, 991, 0, 0, 0, NULL, 2, 1048576, 0 },
	/* linear: 63 x 1024 + one shorter tail; merged iff
	 * H + 63*1024 + sl < 65536, i.e. sl < 976 - H */
	{ "tu960", 's', 'a', 'u', 64, 1024, 63, 960, 0, 0, 0, NULL, 1, 1048576, 0 },
	{ "tu961", 's', 'a', 'u', 64, 1024, 63, 961, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tu962", 's', 'a', 'u', 64, 1024, 63, 962, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tu970", 's', 'a', 'u', 64, 1024, 63, 970, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tu973", 's', 'a', 'u', 64, 1024, 63, 973, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tu974", 's', 'a', 'u', 64, 1024, 63, 974, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tu975", 's', 'a', 'u', 64, 1024, 63, 975, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tu976", 's', 'a', 'u', 64, 1024, 63, 976, 0, 0, 0, NULL, 2, 1048576, 0 },
	{ "tu980", 's', 'a', 'u', 64, 1024, 63, 980, 0, 0, 0, NULL, 2, 1048576, 0 },
};

/* the messages this attempt left in the drain buffer (F65's helper) */
static void f588_arm(const struct f588_arm *A, int idx)
{
	struct f575_pl pl;
	struct f585_arm B;
	unsigned char imm[64];
	char hxi[128] = "-";
	char m1_6[16] = "-", m1_udp[40] = "-", m1_p0[40] = "-";
	char m2_6[16] = "-", m2_udp[40] = "-", m2_p0[40] = "-";
	int rc = -99, ilen = -1, cmdrc = 0, att, acks = 0;
	int ch0 = -1, ch1 = -1, lgn0 = -1, l10 = -1, l20 = -1, agr = -1;
	int lgn = 0, l1 = -1, l2 = -1;
	int win = A->lazy ? A->lazy * 10 + 400 : 700;

	memset(&B, 0, sizeof(B));
	B.name = A->name;
	B.src = 'F';
	B.dst = A->dst;
	B.xg = A->xg;
	B.skt = 'p';
	B.store = A->store;
	B.off = A->off;
	B.len = A->len;
	B.hex = A->hex;
	if (A->store) {
		ilen = f586_imm(&B, imm);
		if (ilen > 0)
			f559_hexs(hxi, sizeof(hxi), imm, ilen);
	}
	f578_feat_set("x0", F585_GRO_BIT, A->xg == 'n' ? 0 : 1);
	f578_feat_set("x0", F585_GROFL_BIT, A->xg == 'f');
	f578_feat_set("x0", F585_GROFWD_BIT, A->xg == 'u');
	(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
	(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
	f575_nfl_drain(&pl);
	cmdrc |= f586_cmd(&F585_C, 'p', 0, 0, 0, 0, 0, 0, 0) ? 1 : 0;
	cmdrc |= f586_cmd(&F585_C, 'v', (A->rcvbuf >> 24) & 0xff,
			  (A->rcvbuf >> 16) & 0xff, (A->rcvbuf >> 8) & 0xff,
			  A->rcvbuf & 0xff, 0, 0, 0) ? 2 : 0;
	cmdrc |= f586_cmd(&F585_C, 'b', 0, 0, 0, 0, 0, 0, 0) ? 4 : 0;
	f586_taps(1);
	for (att = 0; att < 2; att++) {
		(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
		(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
		f575_nfl_drain(&pl);
		rc = ilen < 0 ? f585_rule(&B, idx, NULL, 0) :
				f585_rule(&B, idx, imm, ilen);
		cmdrc |= f586_cmd(&F585_S, A->src, A->dst == 'a' ? 'a' : 'b',
				  ((A->sl >> 8) << 2) & 0xfc, A->n,
				  A->sh < 0 ? 0xff : A->sh, A->sl & 0xff,
				  (A->pl >> 8) & 0xff, A->pl & 0xff) ? 8 : 0;
		cmdrc |= f586_cmd(&F585_C, 'r', idx, 0, att,
				  (win >> 8) & 0xff, win & 0xff,
				  A->lazy, 0) ? 16 : 0;
		f585_tap_drain(&F585_TA);
		f585_tap_drain(&F585_TB);
		f575_nfl_drain(&pl);
		ch1 = (int)f555_count(NFPROTO_IPV6, "f85p", "fwd");
		lgn = f587_msgs(&pl, &l1, &l2, m1_6, m1_udp, m1_p0,
				m2_6, m2_udp, m2_p0);
		if (att == 0) {
			ch0 = ch1;
			lgn0 = lgn;
			l10 = l1;
			l20 = l2;
		} else {
			agr = (ch1 == ch0 && lgn == lgn0 && l1 == l10 &&
			       l2 == l20) ? 1 : 0;
		}
	}
	printf("F588 ARM|i=%02d|name=%s|src=%c|dst=%c|xg=%c|n=%d|pl=%d|sh=%d|"
	       "sl=%d|store=%d|off=%u|len=%u|hex=%s|rc=%d|cmdrc=%d|exp=%d|"
	       "ch=%d|ch0=%d|agr=%d|lgn=%d|lgplen=%d|lg2=%d|lg6=%s|"
	       "lgudp=%s|lgp0=%s|lg2_6=%s|lg2_udp=%s|lg2_p0=%s|win=%d|"
	       "rbq=%d|lazy=%d|an=%d|anall=%d|bn=%d|bnall=%d\n",
	       idx, A->name, A->src, A->dst, A->xg, A->n, A->pl, A->sh,
	       A->sl, A->store, A->off, A->len, hxi, rc, cmdrc, A->exp,
	       ch1, ch0, agr, lgn, l1, l2,
	       m1_6, m1_udp, m1_p0, m2_6, m2_udp, m2_p0, win,
	       A->rcvbuf, A->lazy,
	       F585_TA.n, F585_TA.nall, F585_TB.n, F585_TB.nall);
	fflush(stdout);
	f585_tap_print(&F585_TA, idx, "y1");
	f585_tap_print(&F585_TB, idx, "y2");
	fflush(stdout);
}

static int f588_run(const struct f588_arm *T, int n, int limit, const char *nm)
{
	int i;

	printf("F587 GROTO_PLAN|timeout=200000000|defer=1|F66=1\n");
	if (f587_setup())
		return -1;
	for (i = 0; i < n; i++) {
		if (limit > 0 && i >= limit) {
			printf("F587 SKIP|from=%d|limit=%d\n", i, limit);
			break;
		}
		f588_arm(&T[i], i);
	}
	f587_shutdown();
	printf("F587 END|mode=%s|arms=%d\n", nm, i);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "split";
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
	printf("F588 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "split"))
		return f588_run(AF588_SPLIT,
				(int)(sizeof(AF588_SPLIT) / sizeof(AF588_SPLIT[0])),
				limit, "split");
	if (!strcmp(mode, "cap"))
		return f588_run(AF588_CAP,
				(int)(sizeof(AF588_CAP) / sizeof(AF588_CAP[0])),
				limit, "cap");
	return f587_entry(argc, argv);
}
