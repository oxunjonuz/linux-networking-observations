/* differ561_add.c -- turn 561 / F39: 802.1AD and Q-in-Q.
 *
 * F38 ended with "на veth метку в байтах кадра не показать" and with a promise:
 * eth_type_vlan() knows two constants and only one of them was measured.
 *
 * This instrument measures the second one -- 0x88a8 -- and the two-tag frame.
 * Same kernel as F36..F38 (7.3.4-T558), no new build: every file that matters
 * (nft_payload.c, nft_chain_filter.c, nft_meta.c, skbuff.c, dev.c, vlan_core.c)
 * is byte-for-byte the one those findings measured.
 *
 *   meta   what the packet IS, per representation: `meta protocol` compared
 *          against eight candidate ethertypes.  The counter is the oracle, so
 *          the value is read out of a match, never out of a print.
 *   ll     bridge prerouting, base ll, the 36-cell grid, six representations.
 *   unlock the same 40-cell network grid with and without a `meta protocol`
 *          expression in front of the store: the guard switches on pkt->ethertype,
 *          and pkt->ethertype is a field another expression may rewrite.
 *   xmit   the way out.  F37's one feature bit (NETIF_F_HW_VLAN_CTAG_TX) plus
 *          the one it never touched (NETIF_F_HW_VLAN_STAG_TX, bit 46): whether
 *          a stored skb->vlan_proto survives to the wire depends on both.
 *   far    the receiving side of a two-tag frame, no bridge: one pop or two?
 *   ndin   netdev ingress on the bridge port, the 40-cell network grid on a
 *          plain and on a QinQ frame: both are 40/40, and the bytes tell where
 *          "accepted" ends and "landed in the field" begins.
 *
 * Views: w = AF_PACKET on r1 (or i0), after validate_xmit_skb; r = AF_PACKET on
 * r0 (or i1), after skb_vlan_untag.  Oracle for every store: the rule's own
 * counter, read before and after one send.
 */

/* ---------- frames ---------- */

struct f561_rep {
	const char *tag;
	int ntag;
	unsigned int tp1, tc1, tp2, tc2;
};

static const struct f561_rep R561[] = {
	{ "p",   0, 0x0000, 0x0000, 0x0000, 0x0000 },
	{ "w",   1, 0x8100, 0x0064, 0x0000, 0x0000 },
	{ "s88", 1, 0x88a8, 0x0064, 0x0000, 0x0000 },
	{ "q",   2, 0x88a8, 0x0064, 0x8100, 0x00c8 },
	{ "q81", 2, 0x8100, 0x0064, 0x8100, 0x00c8 },
	{ "x91", 1, 0x9100, 0x0064, 0x0000, 0x0000 },
};
#define N561 ((int)(sizeof(R561) / sizeof(R561[0])))

/* the plain frame with ntag tags inserted in front of its ethertype */
static int f561_mkframe(const struct f561_rep *r, unsigned char *out)
{
	unsigned char tmp[512];
	unsigned int tp[2], tc[2];
	int n = f556_frame(FK33_IP4, tmp), i;

	tp[0] = r->tp1; tc[0] = r->tc1;
	tp[1] = r->tp2; tc[1] = r->tc2;
	memset(out, 0, 512);
	memcpy(out, tmp, 12);
	for (i = 0; i < r->ntag; i++) {
		out[12 + 4 * i] = (unsigned char)(tp[i] >> 8);
		out[13 + 4 * i] = (unsigned char)tp[i];
		out[14 + 4 * i] = (unsigned char)(tc[i] >> 8);
		out[15 + 4 * i] = (unsigned char)tc[i];
	}
	memcpy(out + 12 + 4 * r->ntag, tmp + 12, (size_t)(n - 12));
	return n + 4 * r->ntag;
}

/* the ethertype the frame announces (what eth_type_trans() will copy) */
static unsigned short f561_proto(const struct f561_rep *r)
{
	return r->ntag ? (unsigned short)r->tp1 : 0x0800;
}

static const unsigned char M561_77[8] = { 0x77, 0x77, 0x77, 0x77,
					  0x77, 0x77, 0x77, 0x77 };

/* ---------- rules: up to one gate in front of one store ---------- */

#define F561_GATE_NONE		0
#define F561_GATE_META_NE	1	/* meta protocol != 0xffff  */
#define F561_GATE_META_EQ	2	/* meta protocol == want    */
#define F561_REG_META		NFT_REG32_08

static int f561_rule(uint8_t fam, const char *table, const char *chain,
		     int gate, unsigned int want, uint32_t base, uint32_t off,
		     uint32_t len, const unsigned char *imm, int immlen,
		     int do_store, int loggroup, const char *prefix, int *acks)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs, *e, *d, *cd;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			fam);
	put_str(nlh, NFTA_RULE_TABLE, table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	if (gate != F561_GATE_NONE) {
		uint16_t v = htons((uint16_t)(gate == F561_GATE_META_EQ ? want
								       : 0xffff));

		e = nest_start(nlh, NFTA_LIST_ELEM);
		put_str(nlh, NFTA_EXPR_NAME, "meta");
		d = nest_start(nlh, NFTA_EXPR_DATA);
		put_be32(nlh, NFTA_META_KEY, NFT_META_PROTOCOL);
		put_be32(nlh, NFTA_META_DREG, F561_REG_META);
		nest_end(nlh, d);
		nest_end(nlh, e);

		e = nest_start(nlh, NFTA_LIST_ELEM);
		put_str(nlh, NFTA_EXPR_NAME, "cmp");
		d = nest_start(nlh, NFTA_EXPR_DATA);
		put_be32(nlh, NFTA_CMP_SREG, F561_REG_META);
		put_be32(nlh, NFTA_CMP_OP,
			 gate == F561_GATE_META_EQ ? NFT_CMP_EQ : NFT_CMP_NEQ);
		cd = nest_start(nlh, NFTA_CMP_DATA);
		attr_put(nlh, NFTA_DATA_VALUE, &v, 2);
		nest_end(nlh, cd);
		nest_end(nlh, d);
		nest_end(nlh, e);
	}
	if (do_store) {
		imm_value(nlh, NFT_REG32_00, imm, immlen);
		e = nest_start(nlh, NFTA_LIST_ELEM);
		put_str(nlh, NFTA_EXPR_NAME, "payload");
		d = nest_start(nlh, NFTA_EXPR_DATA);
		put_be32(nlh, NFTA_PAYLOAD_SREG, NFT_REG32_00);
		put_be32(nlh, NFTA_PAYLOAD_BASE, base);
		put_be32(nlh, NFTA_PAYLOAD_OFFSET, off);
		put_be32(nlh, NFTA_PAYLOAD_LEN, len);
		put_be32(nlh, NFTA_PAYLOAD_CSUM_TYPE, NFT_PAYLOAD_CSUM_NONE);
		put_be32(nlh, NFTA_PAYLOAD_CSUM_OFFSET, 0);
		nest_end(nlh, d);
		nest_end(nlh, e);
	}
	log_expr(nlh, loggroup, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

/* ---------- one arm ---------- */

static const char *F561_SEC = "-";

static void f561_arm(const char *env, const char *arm, int gate,
		     unsigned int want, uint8_t fam, const char *table,
		     const char *chain, uint32_t base, int off, int len,
		     const unsigned char *imm, int do_store,
		     const unsigned char *fr, int flen, const char *sdev,
		     unsigned short sproto, const unsigned char *magic, int mlen,
		     int wfd, int rfd, const struct f559_out *base_out,
		     struct f559_out *out)
{
	struct f559_out o;
	char cw[1024], cr[1024], hw[512], hr[512];
	int kw = 0, kr = 0;

	/* F39: without this, an arm with no baseline printed the PREVIOUS arm's
	 * diff string (uninitialised stack) under wchg=0.  Found by reading the
	 * ll.q control of the smoke, fixed before any number was quoted. */
	cw[0] = 0;
	cr[0] = 0;

	memset(&o, 0, sizeof(o));
	snprintf(PRE57, sizeof(PRE57), "f61.%s.%s", env, arm);
	f557_flush(fam, table, chain, &o.acks);
	o.rc = f561_rule(fam, table, chain, gate, want, base, (uint32_t)off,
			 (uint32_t)len, imm, do_store ? len : 0, do_store, 5,
			 PRE57, &o.acks);
	nfl_drain(NFL59);
	o.cnt0 = f555_count(fam, table, chain);
	{
		unsigned long long ip0 = f558_ipin();

		f560_send2(sdev, sproto, fr, flen, magic, mlen, wfd, rfd, &o);
		usleep(20000);
		o.ipin = f558_ipin() - ip0;
	}
	o.cnt = f555_count(fam, table, chain);
	if (base_out && o.wn > 0 && base_out->wn > 0)
		kw = f558_chg(cw, sizeof(cw), base_out->w, base_out->wn, o.w,
			      o.wn);
	if (base_out && o.rn > 0 && base_out->rn > 0)
		kr = f558_chg(cr, sizeof(cr), base_out->r, base_out->rn, o.r,
			      o.rn);
	printf("F561 R|env=%s.%s|arm=%s|gate=%d|want=%04x|fam=%u|base=%u|"
	       "off=%d|len=%d|store=%d|"
	       "rc=%d|acks=%d|snd=%d|cnt0=%llu|cnt=%llu|live=%llu|ipin=%llu|"
	       "wn=%d|wpt=%d|wchg=%d|wchgs=%s|whex=%s|"
	       "rn=%d|rpt=%d|rchg=%d|rchgs=%s|rhex=%s\n",
	       F561_SEC, env, arm, gate, want, (unsigned)fam, (unsigned)base,
	       off, len, do_store,
	       o.rc, o.acks, o.snd, o.cnt0, o.cnt, o.cnt - o.cnt0, o.ipin,
	       o.wn, o.wpt, kw, cw[0] ? cw : "-",
	       o.wn > 0 ? f559_hexs(hw, sizeof(hw), o.w, o.wn) : "-",
	       o.rn, o.rpt, kr, cr[0] ? cr : "-",
	       o.rn > 0 ? f559_hexs(hr, sizeof(hr), o.r, o.rn) : "-");
	if (out)
		memcpy(out, &o, sizeof(o));
}

/* the 36-cell grid */
static void f561_grid36(const char *env, uint8_t fam, const char *table,
			const char *chain, uint32_t base, int gate,
			const unsigned char *fr, int flen, const char *sdev,
			unsigned short sproto, const unsigned char *magic,
			int mlen, int wfd, int rfd, const struct f559_out *ctl)
{
	unsigned char imm[16];
	char arm[32];
	int i, j;

	for (i = 0; i < G33_NOFF; i++) {
		for (j = 0; j < G33_NLEN; j++) {
			f556_imm(FK33_IP4, G33_OFF[i], G33_LEN[j], imm);
			snprintf(arm, sizeof(arm), "g%d_%d", G33_OFF[i],
				 G33_LEN[j]);
			f561_arm(env, arm, gate, 0, fam, table, chain, base,
				 G33_OFF[i], G33_LEN[j], imm, G33_LEN[j], fr,
				 flen, sdev, sproto, magic, mlen, wfd, rfd, ctl,
				 NULL);
		}
	}
}

/* the 36 cells plus the four wide arms = the 40-cell grid */
static void f561_grid40(const char *env, uint8_t fam, const char *table,
			const char *chain, uint32_t base, int gate,
			const unsigned char *fr, int flen, const char *sdev,
			unsigned short sproto, const unsigned char *magic,
			int mlen, int wfd, int rfd, const struct f559_out *ctl)
{
	unsigned char imm[16];
	char arm[32];
	int i;

	f561_grid36(env, fam, table, chain, base, gate, fr, flen, sdev, sproto,
		    magic, mlen, wfd, rfd, ctl);
	for (i = 0; i < G33_NEXT; i++) {
		f556_imm(FK33_IP4, G33_XOFF[i], G33_XLEN[i], imm);
		snprintf(arm, sizeof(arm), "x%d_%d", G33_XOFF[i], G33_XLEN[i]);
		f561_arm(env, arm, gate, 0, fam, table, chain, base, G33_XOFF[i],
			 G33_XLEN[i], imm, G33_XLEN[i], fr, flen, sdev, sproto,
			 magic, mlen, wfd, rfd, ctl, NULL);
	}
}

/* ---------- feature bits ---------- */

#define F561_CTAG_TX_BIT	7	/* NETIF_F_HW_VLAN_CTAG_TX_BIT */
#define F561_STAG_TX_BIT	45	/* NETIF_F_HW_VLAN_STAG_TX_BIT */
#define F561_STAG_SHIFT		(F561_STAG_TX_BIT - 32)

static void f561_feat(const char *stage, const char *dev)
{
	struct f559_fblk b[F559_FWORDS];
	int n = 0, i, rc = f559_gfeat(dev, b, F559_FWORDS, &n);

	printf("F561 FEAT|stage=%s|dev=%s|rc=%d|nwords=%d", stage, dev, rc, n);
	if (rc == 0) {
		for (i = 0; i < n && i < F559_FWORDS; i++)
			printf("|avail%d=%08x|want%d=%08x|act%d=%08x", i,
			       b[i].avail, i, b[i].want, i, b[i].act);
		printf("|ctag_tx=%d|stag_tx=%d|stag_rx=%d",
		       (int)((b[0].act >> F561_CTAG_TX_BIT) & 1),
		       n > 1 ? (int)((b[1].act >> F561_STAG_SHIFT) & 1) : -1,
		       n > 1 ? (int)((b[1].act >> (F561_STAG_SHIFT + 1)) & 1)
			     : -1);
	}
	printf("\n");
}

static int f561_sfeat2(const char *dev, int nblk, unsigned int v0,
		       unsigned int r0, unsigned int v1, unsigned int r1)
{
	struct {
		unsigned int cmd, size;
		struct {
			unsigned int valid, req;
		} b[F559_FWORDS];
	} c;
	struct ifreq ifr;
	int fd, rc;

	memset(&c, 0, sizeof(c));
	c.cmd = F559_SFEATURES;
	c.size = (unsigned int)nblk;
	c.b[0].valid = v0;
	c.b[0].req = r0;
	c.b[1].valid = v1;
	c.b[1].req = r1;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
	ifr.ifr_data = (char *)&c;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	return rc < 0 ? -errno : rc;
}

/* ctag/stag: 1 = ask for the bit, 0 = ask it away.  Returns the raw ioctl. */
static int f561_setbits(const char *stage, const char *dev, int ctag, int stag)
{
	struct f559_fblk b[F559_FWORDS];
	unsigned int v0 = 1u << F561_CTAG_TX_BIT, r0 = 0;
	unsigned int v1 = 0, r1 = 0;
	int n = 0, rc;

	if (f559_gfeat(dev, b, F559_FWORDS, &n) < 0 || n <= 0) {
		printf("F561 SET|stage=%s|dev=%s|no_gfeat\n", stage, dev);
		return -1;
	}
	if (ctag)
		r0 = v0;
	if (n > 1) {
		v1 = 1u << F561_STAG_SHIFT;
		if (stag)
			r1 = v1;
	}
	rc = f561_sfeat2(dev, n, v0, r0, v1, r1);
	printf("F561 SET|stage=%s|dev=%s|nwords=%d|valid0=%08x|req0=%08x|"
	       "valid1=%08x|req1=%08x|rc=%d|f_unsup=%d|f_wish=%d\n",
	       stage, dev, n, v0, r0, v1, r1, rc, rc >= 0 ? (rc & 1) : -1,
	       rc >= 0 ? (rc & 2) : -1);
	f561_feat(stage, dev);
	return rc;
}

/* ---------- meta: what the packet is ---------- */

static const unsigned int V561[8] = { 0x0800, 0x0806, 0x8100, 0x88a8,
				      0x9100, 0x4500, 0x86dd, 0x0002 };

static void f561_sec_meta(void)
{
	unsigned char fr[512];
	int r, v, acks = 0, flen;
	struct f559_out o;

	F561_SEC = "meta";
	f561_feat("meta.in", "r1");
	if (add_table(NFPROTO_BRIDGE, "p61a") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p61a", "g", 0, 0, 1, NULL)) {
		printf("F561 FAIL|meta|chain\n");
		return;
	}
	for (r = 0; r < N561; r++) {
		flen = f561_mkframe(&R561[r], fr);
		memset(&o, 0, sizeof(o));
		snprintf(PRE57, sizeof(PRE57), "f61.meta.%s.ctl", R561[r].tag);
		f557_flush(NFPROTO_BRIDGE, "p61a", "g", &acks);
		o.rc = f561_rule(NFPROTO_BRIDGE, "p61a", "g", F561_GATE_NONE, 0,
				 0, 0, 0, NULL, 0, 0, 5, PRE57, &acks);
		o.cnt0 = f555_count(NFPROTO_BRIDGE, "p61a", "g");
		o.snd = pkt_send_p("s0", fr, flen, f561_proto(&R561[r]));
		usleep(20000);
		o.cnt = f555_count(NFPROTO_BRIDGE, "p61a", "g");
		printf("F561 M|env=meta|rep=%s|want=-|ctl=1|rc=%d|acks=%d|"
		       "snd=%d|cnt0=%llu|cnt=%llu|live=%llu\n",
		       R561[r].tag, o.rc, o.acks, o.snd, o.cnt0, o.cnt,
		       o.cnt - o.cnt0);
		for (v = 0; v < 8; v++) {
			f557_flush(NFPROTO_BRIDGE, "p61a", "g", &acks);
			snprintf(PRE57, sizeof(PRE57), "f61.meta.%s.%04x",
				 R561[r].tag, V561[v]);
			o.rc = f561_rule(NFPROTO_BRIDGE, "p61a", "g",
					 F561_GATE_META_EQ, V561[v], 0, 0, 0,
					 NULL, 0, 0, 5, PRE57, &acks);
			o.cnt0 = f555_count(NFPROTO_BRIDGE, "p61a", "g");
			o.snd = pkt_send_p("s0", fr, flen,
					   f561_proto(&R561[r]));
			usleep(20000);
			o.cnt = f555_count(NFPROTO_BRIDGE, "p61a", "g");
			printf("F561 M|env=meta|rep=%s|want=%04x|ctl=0|rc=%d|"
			       "acks=%d|snd=%d|cnt0=%llu|cnt=%llu|live=%llu\n",
			       R561[r].tag, V561[v], o.rc, o.acks, o.snd,
			       o.cnt0, o.cnt, o.cnt - o.cnt0);
		}
	}
	sh("/nft flush ruleset");
}

/* ---------- ll: the 36-cell grid over six representations ---------- */

static void f561_sec_ll(void)
{
	unsigned char fr[512];
	struct f559_out ctl;
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int r, flen;

	F561_SEC = "ll";
	f561_feat("ll.in", "r1");
	printf("F561 SECTION|ll|wfd=%d|rfd=%d|reps=%d\n", wfd, rfd, N561);
	if (add_table(NFPROTO_BRIDGE, "p61b") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p61b", "g", 0, 0, 1, NULL)) {
		printf("F561 FAIL|ll|chain\n");
		return;
	}
	for (r = 0; r < N561; r++) {
		flen = f561_mkframe(&R561[r], fr);
		printf("F561 REP|env=ll|rep=%s|flen=%d|ntag=%d|tp1=%04x|"
		       "tp2=%04x|sproto=%04x\n",
		       R561[r].tag, flen, R561[r].ntag, R561[r].tp1,
		       R561[r].tp2, f561_proto(&R561[r]));
		memset(&ctl, 0, sizeof(ctl));
		f561_arm(R561[r].tag, "ctl", F561_GATE_NONE, 0, NFPROTO_BRIDGE,
			 "p61b", "g", NFT_PAYLOAD_LL_HEADER, 0, 0, NULL, 0, fr,
			 flen, "s0", f561_proto(&R561[r]), M561_77, 8, wfd,
			 rfd, NULL, &ctl);
		f561_grid36(R561[r].tag, NFPROTO_BRIDGE, "p61b", "g",
			    NFT_PAYLOAD_LL_HEADER, F561_GATE_NONE, fr, flen, "s0",
			    f561_proto(&R561[r]), M561_77, 8, wfd, rfd, &ctl);
	}
	sh("/nft flush ruleset");
}

/* ---------- unlock: the guard reads a field another expression rewrites ---- */

static void f561_sec_unlock(void)
{
	static const int reps[2] = { 1, 3 };	/* w, q */
	unsigned char fr[512];
	struct f559_out ctl;
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int k, r, flen, gate;

	F561_SEC = "unlock";
	f561_feat("unlock.in", "r1");
	printf("F561 SECTION|unlock|wfd=%d|rfd=%d\n", wfd, rfd);
	if (add_table(NFPROTO_BRIDGE, "p61c") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p61c", "g", 0, 0, 1, NULL)) {
		printf("F561 FAIL|unlock|chain\n");
		return;
	}
	for (k = 0; k < 2; k++) {
		r = reps[k];
		flen = f561_mkframe(&R561[r], fr);
		for (gate = 0; gate < 2; gate++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", R561[r].tag,
				 gate ? "meta" : "bare");
			printf("F561 REP|env=unlock|rep=%s|flen=%d|gate=%d\n",
			       env, flen, gate);
			memset(&ctl, 0, sizeof(ctl));
			f561_arm(env, "ctl", F561_GATE_NONE, 0,
				 NFPROTO_BRIDGE, "p61c", "g",
				 NFT_PAYLOAD_NETWORK_HEADER, 0, 0, NULL, 0, fr,
				 flen, "s0", f561_proto(&R561[r]), M561_77, 8,
				 wfd, rfd, NULL, &ctl);
			f561_grid40(env, NFPROTO_BRIDGE, "p61c", "g",
				    NFT_PAYLOAD_NETWORK_HEADER,
				    gate ? F561_GATE_META_NE : F561_GATE_NONE,
				    fr, flen, "s0", f561_proto(&R561[r]),
				    M561_77, 8, wfd, rfd, &ctl);
		}
	}
	sh("/nft flush ruleset");
}

/* ---------- xmit: does a stored vlan_proto survive the wire? ---------- */

static void f561_sec_xmit(void)
{
	static const struct {
		const char *tag;
		int off, len;
		unsigned int v1, v2;
	} A[] = {
		{ "ctl",   0,  0, 0x0000, 0x0000 },
		{ "p8100", 12, 2, 0x8100, 0x0000 },
		{ "p88a8", 12, 2, 0x88a8, 0x0000 },
		{ "p0000", 12, 2, 0x0000, 0x0000 },
		{ "t88a8", 12, 4, 0x88a8, 0x0064 },
	};
	static const struct {
		const char *tag;
		int ctag, stag;
	} S[] = {
		{ "A_11", 1, 1 },
		{ "B_01", 0, 1 },
		{ "C_00", 0, 0 },
	};
	unsigned char fr[512], imm[16];
	struct f559_out ctl;
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int s, a, flen;

	F561_SEC = "xmit";
	printf("F561 SECTION|xmit|wfd=%d|rfd=%d\n", wfd, rfd);
	if (add_table(NFPROTO_BRIDGE, "p61d") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p61d", "g", 0, 0, 1, NULL)) {
		printf("F561 FAIL|xmit|chain\n");
		return;
	}
	flen = f561_mkframe(&R561[1], fr);	/* the single 0x8100 tag frame */
	printf("F561 REP|env=xmit|rep=w|flen=%d|sproto=%04x\n", flen,
	       f561_proto(&R561[1]));
	for (s = 0; s < 3; s++) {
		f561_setbits(S[s].tag, "r1", S[s].ctag, S[s].stag);
		for (a = 0; a < (int)(sizeof(A) / sizeof(A[0])); a++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", S[s].tag,
				 A[a].tag);
			memset(imm, 0, sizeof(imm));
			imm[0] = (unsigned char)(A[a].v1 >> 8);
			imm[1] = (unsigned char)A[a].v1;
			imm[2] = (unsigned char)(A[a].v2 >> 8);
			imm[3] = (unsigned char)A[a].v2;
			memset(&ctl, 0, sizeof(ctl));
			if (a == 0)
				f561_arm(env, "ctl", F561_GATE_NONE, 0,
					 NFPROTO_BRIDGE, "p61d", "g",
					 NFT_PAYLOAD_LL_HEADER, 0, 0, NULL, 0,
					 fr, flen, "s0", f561_proto(&R561[1]),
					 M561_77, 8, wfd, rfd, NULL, &ctl);
			else
				f561_arm(env, A[a].tag, F561_GATE_NONE, 0,
					 NFPROTO_BRIDGE, "p61d", "g",
					 NFT_PAYLOAD_LL_HEADER, A[a].off,
					 A[a].len, imm, 1, fr, flen, "s0",
					 f561_proto(&R561[1]), M561_77, 8, wfd,
					 rfd, &ctl, NULL);
		}
	}
	f561_setbits("restore", "r1", 1, 1);
	sh("/nft flush ruleset");
}

/* ---------- far: the receiving side of a two-tag frame ---------- */

static void f561_sec_far(void)
{
	unsigned char fr[512];
	int r, flen;
	int wfd = cap_open("i0"), rfd = cap_open("i1");

	F561_SEC = "far";
	printf("F561 SECTION|far|wfd=%d|rfd=%d|dev=i0->i1\n", wfd, rfd);
	for (r = 0; r < N561; r++) {
		struct f559_out o;

		flen = f561_mkframe(&R561[r], fr);
		memset(&o, 0, sizeof(o));
		{
			unsigned long long ip0 = f558_ipin();

			f560_send2("i0", f561_proto(&R561[r]), fr, flen, M561_77,
				   8, wfd, rfd, &o);
			usleep(20000);
			o.ipin = f558_ipin() - ip0;
		}
		{
			char hw[512], hr[512];

			printf("F561 FAR|rep=%s|flen=%d|snd=%d|ipin=%llu|"
			       "wn=%d|wpt=%d|whex=%s|rn=%d|rpt=%d|rhex=%s\n",
			       R561[r].tag, flen, o.snd, o.ipin, o.wn, o.wpt,
			       o.wn > 0 ? f559_hexs(hw, sizeof(hw), o.w, o.wn)
					: "-",
			       o.rn, o.rpt,
			       o.rn > 0 ? f559_hexs(hr, sizeof(hr), o.r, o.rn)
					: "-");
		}
	}
}

/* ---------- ndin: netdev ingress, plain vs QinQ ---------- */

static void f561_sec_ndin(void)
{
	static const int reps[2] = { 0, 3 };	/* p, q */
	unsigned char fr[512];
	struct f559_out ctl;
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int k, r, flen;

	F561_SEC = "ndin";
	f561_feat("ndin.in", "s1");
	printf("F561 SECTION|ndin|wfd=%d|rfd=%d|dev=s1\n", wfd, rfd);
	if (add_table(NFPROTO_NETDEV, "p61e") ||
	    f556_add_chain(NFPROTO_NETDEV, "p61e", "ing", 0, 0, 1, "s1")) {
		printf("F561 FAIL|ndin|chain\n");
		return;
	}
	for (k = 0; k < 2; k++) {
		r = reps[k];
		flen = f561_mkframe(&R561[r], fr);
		printf("F561 REP|env=ndin|rep=%s|flen=%d|sproto=%04x\n",
		       R561[r].tag, flen, f561_proto(&R561[r]));
		memset(&ctl, 0, sizeof(ctl));
		f561_arm(R561[r].tag, "ctl", F561_GATE_NONE, 0, NFPROTO_NETDEV,
			 "p61e", "ing", NFT_PAYLOAD_NETWORK_HEADER, 0, 0, NULL,
			 0, fr, flen, "s0", f561_proto(&R561[r]), M561_77, 8,
			 wfd, rfd, NULL, &ctl);
		f561_grid40(R561[r].tag, NFPROTO_NETDEV, "p61e", "ing",
			    NFT_PAYLOAD_NETWORK_HEADER, F561_GATE_NONE, fr, flen,
			    "s0", f561_proto(&R561[r]), M561_77, 8, wfd, rfd,
			    &ctl);
	}
	sh("/nft flush ruleset");
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "f561";

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F561 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F561 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F561 KERNEL|%s\n", "7.3.4-T558");
	f556_env_setup();
	{
		static const char *dv[] = { "all", "default", "lo", "i0", "i1",
					    "s0", "s1", "r0", "r1", "br0" };
		char path[96];
		int i;

		for (i = 0; i < (int)(sizeof(dv) / sizeof(dv[0])); i++) {
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", dv[i]);
			f555_sysctl(path, "1");
		}
	}
	NFL59 = nfl_open(5);
	printf("F561 NFL|%d\n", NFL59);
	if (!strcmp(mode, "f561meta")) {
		f561_sec_meta();
	} else if (!strcmp(mode, "f561ll")) {
		f561_sec_ll();
	} else if (!strcmp(mode, "f561unlock")) {
		f561_sec_unlock();
	} else if (!strcmp(mode, "f561xmit")) {
		f561_sec_xmit();
	} else if (!strcmp(mode, "f561far")) {
		f561_sec_far();
	} else if (!strcmp(mode, "f561ndin")) {
		f561_sec_ndin();
	} else {
		f561_sec_far();
		f561_sec_meta();
		f561_sec_ll();
		f561_sec_unlock();
		f561_sec_xmit();
		f561_sec_ndin();
	}
	printf("F561 DONE\n");
	return 0;
}
