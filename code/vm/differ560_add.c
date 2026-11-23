/* differ560_add.c -- turn 560 / F38: the RECEIVING side of the tag.
 *
 * F37 ended with the tag measured as bytes on the wire: a veth whose
 * NETIF_F_HW_VLAN_CTAG_TX bit was taken away makes validate_xmit_vlan() insert
 * the tag into the frame itself, so the wire shows `8100 0064 0800 ...`.
 *
 * This turn sends that frame back IN, from an AF_PACKET socket, and asks what
 * the receiving kernel and the four guards make of it:
 *
 *   recv  family bridge, base ll, the 36-cell grid, five representations of one
 *         tagged frame: plain, wire-tagged (0x8100 vid 100), the SAME tag put
 *         into skb metadata by a `pre`-chain rule, a priority tag (vid 0), and
 *         a 0x9100 frame with the same four tag-shaped bytes.  Two of them are
 *         the same object seen from two sides; the grid must not be able to
 *         tell them apart, and neither must the wire.
 *   ndin  family netdev, INGRESS hook on s1, base nh, 40 cells: the guard
 *         returns true before it looks at skb->protocol -- but the receive path
 *         has already popped the tag, so the store's coordinates are skb
 *         coordinates, not wire coordinates.
 *   ndeg  family netdev, EGRESS hook on i0, base nh, 40 cells, three sends with
 *         sll_protocol = 0x0800 / 0x8100 / 0x9100: the only hook where a human
 *         chooses what the guard's switch reads.
 *   arp   family bridge, base nh, an 0x8100 + 0x0806 frame: F32's ARP branch
 *         (offset >= 8 && len <= 20, no test of the message length) through the
 *         new envelope.
 *   drop  policy drop at the bridge: the same rule refuses one representation
 *         and accepts the other.
 *
 * Views: w = AF_PACKET on r1 (xmit side, AFTER validate_xmit_skb: the tag the
 *        port actually put there), r = AF_PACKET on r0 (receive side, AFTER
 *        skb_vlan_untag: the frame as the far stack gets it).
 * Oracle for the guard: the rule's own counter, read before and after one send.
 */

/* ---------- frames ---------- */

/* the plain frame of `kind` with a 4-byte tag inserted in front of its
 * ethertype; tpid is the outer ethertype, tci the tag control word */
static int f560_tag(unsigned char *out, int kind, unsigned int tpid,
		    unsigned int tci)
{
	unsigned char tmp[512];
	int n = f556_frame(kind, tmp);

	memset(out, 0, 512);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = (unsigned char)((tpid >> 8) & 0xff);
	out[13] = (unsigned char)(tpid & 0xff);
	out[14] = (unsigned char)((tci >> 8) & 0xff);
	out[15] = (unsigned char)(tci & 0xff);
	memcpy(out + 16, tmp + 12, 2);		/* inner ethertype */
	memcpy(out + 18, tmp + 14, (size_t)(n - 14));	/* the datagram */
	return n + 4;
}

static const unsigned char MAGIC77[8] = { 0x77, 0x77, 0x77, 0x77,
					  0x77, 0x77, 0x77, 0x77 };

/* ---------- one send, two taps ---------- */

static void f560_send2(const char *dev, unsigned short proto,
		       const unsigned char *fr, int flen,
		       const unsigned char *magic, int mlen,
		       int wfd, int rfd, struct f559_out *o)
{
	int sk = 0;

	o->wpt = -1;
	o->rpt = -1;
	if (wfd >= 0)
		cap_drain(wfd);
	if (rfd >= 0)
		cap_drain(rfd);
	usleep(15000);
	if (wfd >= 0)
		cap_drain(wfd);
	if (rfd >= 0)
		cap_drain(rfd);
	memset(o->w, 0, sizeof(o->w));
	memset(o->r, 0, sizeof(o->r));
	o->snd = pkt_send_p(dev, fr, flen, proto);
	o->wn = f558_cap_match(wfd, o->w, (int)sizeof(o->w), 700, magic, mlen,
			       &sk, &o->wpt);
	sk = 0;
	o->rn = f558_cap_match(rfd, o->r, (int)sizeof(o->r), 400, magic, mlen,
			       &sk, &o->rpt);
}

/* ---------- one arm: one rule, one frame, two taps, one counter delta ---------- */

/* the section name, so that "p" in recv and "p" in ndin are two different
 * environments in every line of the log (the smoke run proved they collide) */
static const char *F560_SEC = "-";

static void f560_arm(const char *env, const char *arm, uint8_t fam,
		     const char *table, const char *chain, uint32_t base,
		     int off, int len, const unsigned char *imm, int do_store,
		     const unsigned char *fr, int flen, const char *sdev,
		     unsigned short sproto, const unsigned char *magic, int mlen,
		     int wfd, int rfd, const struct f559_out *base_out,
		     struct f559_out *out)
{
	struct f559_out o;
	char cw[1024], cr[1024], hw[256], hr[256];
	int kw = 0, kr = 0;

	memset(&o, 0, sizeof(o));
	snprintf(PRE57, sizeof(PRE57), "f60.%s.%s", env, arm);
	f557_flush(fam, table, chain, &o.acks);
	o.rc = f557_install(fam, table, chain, 0, base, (uint32_t)off,
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
	printf("F560 R|env=%s.%s|arm=%s|fam=%u|base=%u|off=%d|len=%d|store=%d|"
	       "rc=%d|acks=%d|snd=%d|cnt0=%llu|cnt=%llu|live=%llu|ipin=%llu|"
	       "wn=%d|wpt=%d|wchg=%d|wchgs=%s|whex=%s|"
	       "rn=%d|rpt=%d|rchg=%d|rchgs=%s|rhex=%s\n",
	       F560_SEC, env, arm, (unsigned)fam, (unsigned)base, off, len,
	       do_store,
	       o.rc, o.acks, o.snd, o.cnt0, o.cnt, o.cnt - o.cnt0, o.ipin,
	       o.wn, o.wpt, kw, cw[0] ? cw : "-",
	       o.wn > 0 ? f559_hexs(hw, sizeof(hw), o.w, o.wn) : "-",
	       o.rn, o.rpt, kr, cr[0] ? cr : "-",
	       o.rn > 0 ? f559_hexs(hr, sizeof(hr), o.r, o.rn) : "-");
	if (out)
		memcpy(out, &o, sizeof(o));
}

/* the 12x3 grid (36 cells), every (off,len) of it */
static void f560_grid36(const char *env, uint8_t fam, const char *table,
			const char *chain, uint32_t base,
			const unsigned char *fr, int flen, int kind,
			const char *sdev, unsigned short sproto,
			const unsigned char *magic, int mlen, int wfd, int rfd,
			const struct f559_out *ctl)
{
	unsigned char imm[16];
	char arm[32];
	int i, j;

	for (i = 0; i < G33_NOFF; i++) {
		for (j = 0; j < G33_NLEN; j++) {
			f556_imm(kind, G33_OFF[i], G33_LEN[j], imm);
			snprintf(arm, sizeof(arm), "g%d_%d", G33_OFF[i],
				 G33_LEN[j]);
			f560_arm(env, arm, fam, table, chain, base, G33_OFF[i],
				 G33_LEN[j], imm, G33_LEN[j], fr, flen, sdev,
				 sproto, magic, mlen, wfd, rfd, ctl, NULL);
		}
	}
}

/* the same 36 cells plus the four wide arms = F33's 40-cell grid */
static void f560_grid40(const char *env, uint8_t fam, const char *table,
			const char *chain, uint32_t base,
			const unsigned char *fr, int flen, int kind,
			const char *sdev, unsigned short sproto,
			const unsigned char *magic, int mlen, int wfd, int rfd,
			const struct f559_out *ctl)
{
	unsigned char imm[16];
	char arm[32];
	int i;

	f560_grid36(env, fam, table, chain, base, fr, flen, kind, sdev, sproto,
		    magic, mlen, wfd, rfd, ctl);
	for (i = 0; i < G33_NEXT; i++) {
		f556_imm(kind, G33_XOFF[i], G33_XLEN[i], imm);
		snprintf(arm, sizeof(arm), "x%d_%d", G33_XOFF[i], G33_XLEN[i]);
		f560_arm(env, arm, fam, table, chain, base, G33_XOFF[i],
			 G33_XLEN[i], imm, G33_XLEN[i], fr, flen, sdev, sproto,
			 magic, mlen, wfd, rfd, ctl, NULL);
	}
}

/* ---------- recv: five representations of one tagged frame ---------- */

struct f560_rep {
	const char *tag;
	int kind;
	unsigned int tpid;	/* 0 = no tag in the frame bytes */
	unsigned int tci;
	const unsigned char *mtag;	/* four bytes for the `pre` chain, or NULL */
	unsigned short sproto;	/* sll_protocol of the send */
	int only_x;		/* 1 = only the eight informative cells */
};

/* the eight cells that a tag moves: (10,4) (12,1) (12,2) (12,4) (14,2)
 * (16,1) (16,2) (16,4) */
static const int X560_OFF[8] = { 10, 12, 12, 12, 14, 16, 16, 16 };
static const int X560_LEN[8] = { 4, 1, 2, 4, 2, 1, 2, 4 };

static int X560_IS(int off, int len)
{
	int k;

	for (k = 0; k < 8; k++)
		if (X560_OFF[k] == off && X560_LEN[k] == len)
			return 1;
	return 0;
}

static void f560_sec_recv(void)
{
	static const struct f560_rep reps[] = {
		{ "p",    FK33_IP4, 0,      0,      NULL, 0x0800, 0 },
		{ "w100", FK33_IP4, 0x8100, 0x0064, NULL, 0x8100, 0 },
		{ "m100", FK33_IP4, 0,      0,
		  (const unsigned char *)"\x81\x00\x00\x64", 0x0800, 0 },
		{ "v0",   FK33_IP4, 0x8100, 0x0000, NULL, 0x8100, 1 },
		{ "x91",  FK33_IP4, 0x9100, 0x0064, NULL, 0x9100, 1 },
	};
	struct f559_out ctl;
	unsigned char fr[512], imm[16];
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int acks = 0, r, i, j, flen;

	F560_SEC = "recv";
	printf("F560 SECTION|recv|wfd=%d|rfd=%d|reps=%d\n", wfd, rfd,
	       (int)(sizeof(reps) / sizeof(reps[0])));
	if (add_table(NFPROTO_BRIDGE, "p60a") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p60a", "pre", 0, 0, 1, NULL) ||
	    f556_add_chain(NFPROTO_BRIDGE, "p60a", "g", 0, 10, 1, NULL)) {
		printf("F560 FAIL|recv|chain\n");
		return;
	}
	for (r = 0; r < (int)(sizeof(reps) / sizeof(reps[0])); r++) {
		if (reps[r].tpid)
			flen = f560_tag(fr, reps[r].kind, reps[r].tpid,
					reps[r].tci);
		else
			flen = f556_frame(reps[r].kind, fr);
		/* the `pre` chain holds the tag store, or nothing at all */
		f557_flush(NFPROTO_BRIDGE, "p60a", "pre", &acks);
		if (reps[r].mtag) {
			int prerc;

			snprintf(PRE57, sizeof(PRE57), "f60.tag.%s",
				 reps[r].tag);
			prerc = f557_install(NFPROTO_BRIDGE, "p60a", "pre", 0,
					     NFT_PAYLOAD_LL_HEADER, 12, 4,
					     reps[r].mtag, 4, 1, 5, PRE57,
					     &acks);
			printf("F560 TAGSTORE|rep=%s|rc=%d|acks=%d|off=12|len=4|"
			       "imm=%02x%02x%02x%02x\n", reps[r].tag, prerc,
			       acks, reps[r].mtag[0], reps[r].mtag[1],
			       reps[r].mtag[2], reps[r].mtag[3]);
		}
		printf("F560 REP|env=recv|rep=%s|flen=%d|tpid=%04x|tci=%04x|"
		       "meta=%d|sproto=%04x|only_x=%d\n", reps[r].tag, flen,
		       reps[r].tpid, reps[r].tci, reps[r].mtag != NULL,
		       reps[r].sproto, reps[r].only_x);
		memset(&ctl, 0, sizeof(ctl));
		f560_arm(reps[r].tag, "ctl", NFPROTO_BRIDGE, "p60a", "g", 0, 0, 0,
			 NULL, 0, fr, flen, "s0", reps[r].sproto, MAGIC77, 8,
			 wfd, rfd, NULL, &ctl);
		for (i = 0; i < G33_NOFF; i++) {
			for (j = 0; j < G33_NLEN; j++) {
				char arm[32];

				if (reps[r].only_x &&
				    !X560_IS(G33_OFF[i], G33_LEN[j]))
					continue;
				f556_imm(reps[r].kind, G33_OFF[i], G33_LEN[j],
					 imm);
				snprintf(arm, sizeof(arm), "g%d_%d",
					 G33_OFF[i], G33_LEN[j]);
				f560_arm(reps[r].tag, arm, NFPROTO_BRIDGE,
					 "p60a", "g", NFT_PAYLOAD_LL_HEADER,
					 G33_OFF[i], G33_LEN[j], imm,
					 G33_LEN[j], fr, flen, "s0",
					 reps[r].sproto, MAGIC77, 8, wfd, rfd,
					 &ctl, NULL);
			}
		}
	}
	sh("/nft flush ruleset");
}

/* ---------- ndin: the ingress hook, three ethertypes ---------- */

static void f560_sec_ndin(void)
{
	struct f559_out ctl;
	unsigned char fr[512];
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int flen, i;
	static const struct {
		const char *tag;
		unsigned int tpid;
		unsigned short sproto;
	} reps[] = {
		{ "p",    0,      0x0800 },
		{ "w100", 0x8100, 0x8100 },
		{ "x91",  0x9100, 0x9100 },
	};

	F560_SEC = "ndin";
	printf("F560 SECTION|ndin|wfd=%d|rfd=%d\n", wfd, rfd);
	if (add_table(NFPROTO_NETDEV, "p60b") ||
	    f556_add_chain(NFPROTO_NETDEV, "p60b", "ing", 0, 0, 1, "s1")) {
		printf("F560 FAIL|ndin|chain\n");
		return;
	}
	for (i = 0; i < 3; i++) {
		if (reps[i].tpid)
			flen = f560_tag(fr, FK33_IP4, reps[i].tpid, 0x0064);
		else
			flen = f556_frame(FK33_IP4, fr);
		printf("F560 REP|env=ndin|rep=%s|flen=%d|sproto=%04x|dev=s1\n",
		       reps[i].tag, flen, reps[i].sproto);
		memset(&ctl, 0, sizeof(ctl));
		f560_arm(reps[i].tag, "ctl", NFPROTO_NETDEV, "p60b", "ing", 0, 0,
			 0, NULL, 0, fr, flen, "s0", reps[i].sproto, MAGIC77,
			 8, wfd, rfd, NULL, &ctl);
		f560_grid40(reps[i].tag, NFPROTO_NETDEV, "p60b", "ing",
			    NFT_PAYLOAD_NETWORK_HEADER, fr, flen, FK33_IP4, "s0",
			    reps[i].sproto, MAGIC77, 8, wfd, rfd, &ctl);
	}
	sh("/nft flush ruleset");
}

/* ---------- ndeg: the egress hook, three sll_protocol values ---------- */

static void f560_sec_ndeg(void)
{
	struct f559_out ctl;
	unsigned char fr[512];
	int wfd = cap_open("i0"), rfd = cap_open("i1");
	int flen, i;
	static const struct {
		const char *tag;
		unsigned int tpid;
		unsigned short sproto;
	} reps[] = {
		{ "s0800", 0,      0x0800 },
		{ "s8100", 0x8100, 0x8100 },
		{ "s9100", 0x9100, 0x9100 },
	};

	F560_SEC = "ndeg";
	printf("F560 SECTION|ndeg|wfd=%d|rfd=%d\n", wfd, rfd);
	if (add_table(NFPROTO_NETDEV, "p60c") ||
	    f556_add_chain(NFPROTO_NETDEV, "p60c", "egr", 1, 0, 1, "i0")) {
		printf("F560 FAIL|ndeg|chain\n");
		return;
	}
	for (i = 0; i < 3; i++) {
		if (reps[i].tpid)
			flen = f560_tag(fr, FK33_IP4, reps[i].tpid, 0x0064);
		else
			flen = f556_frame(FK33_IP4, fr);
		printf("F560 REP|env=ndeg|rep=%s|flen=%d|sproto=%04x|dev=i0\n",
		       reps[i].tag, flen, reps[i].sproto);
		memset(&ctl, 0, sizeof(ctl));
		f560_arm(reps[i].tag, "ctl", NFPROTO_NETDEV, "p60c", "egr", 0, 0,
			 0, NULL, 0, fr, flen, "i0", reps[i].sproto, MAGIC77,
			 8, wfd, rfd, NULL, &ctl);
		f560_grid40(reps[i].tag, NFPROTO_NETDEV, "p60c", "egr",
			    NFT_PAYLOAD_NETWORK_HEADER, fr, flen, FK33_IP4, "i0",
			    reps[i].sproto, MAGIC77, 8, wfd, rfd, &ctl);
	}
	sh("/nft flush ruleset");
}

/* ---------- arp: F32's branch through the new envelope ---------- */

static void f560_sec_arp(void)
{
	struct f559_out ctl;
	unsigned char fr[512];
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int flen, i;
	static const struct {
		const char *tag;
		unsigned int tpid;
		unsigned short sproto;
	} reps[] = {
		{ "a",    0,      0x0806 },
		{ "aw100", 0x8100, 0x8100 },
		{ "ax91", 0x9100, 0x9100 },
	};

	F560_SEC = "arp";
	printf("F560 SECTION|arp|wfd=%d|rfd=%d\n", wfd, rfd);
	if (add_table(NFPROTO_BRIDGE, "p60d") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p60d", "g", 0, 0, 1, NULL)) {
		printf("F560 FAIL|arp|chain\n");
		return;
	}
	for (i = 0; i < 3; i++) {
		if (reps[i].tpid)
			flen = f560_tag(fr, FK33_ARP, reps[i].tpid, 0x0064);
		else
			flen = f556_frame(FK33_ARP, fr);
		printf("F560 REP|env=arp|rep=%s|flen=%d|sproto=%04x|dev=s0\n",
		       reps[i].tag, flen, reps[i].sproto);
		memset(&ctl, 0, sizeof(ctl));
		f560_arm(reps[i].tag, "ctl", NFPROTO_BRIDGE, "p60d", "g", 0, 0, 0,
			 NULL, 0, fr, flen, "s0", reps[i].sproto, MAC_SRC, 6,
			 wfd, rfd, NULL, &ctl);
		f560_grid40(reps[i].tag, NFPROTO_BRIDGE, "p60d", "g",
			    NFT_PAYLOAD_NETWORK_HEADER, fr, flen, FK33_ARP, "s0",
			    reps[i].sproto, MAC_SRC, 6, wfd, rfd, &ctl);
	}
	sh("/nft flush ruleset");
}

/* ---------- drop: one rule, two representations, two verdicts ---------- */

static void f560_sec_drop(void)
{
	static const struct {
		const char *tag;
		int off, len;
		unsigned int tpid;
		unsigned short sproto;
	} arms[] = {
		{ "ctl_p", 0, 0, 0, 0x0800 },
		{ "ctl_w", 0, 0, 0x8100, 0x8100 },
		{ "p16_2", 16, 2, 0, 0x0800 },
		{ "w16_2", 16, 2, 0x8100, 0x8100 },
		{ "p14_2", 14, 2, 0, 0x0800 },
		{ "w14_2", 14, 2, 0x8100, 0x8100 },
	};
	struct f559_out o;
	unsigned char fr[512], imm[16];
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int i, flen;

	F560_SEC = "drop";
	printf("F560 SECTION|drop|wfd=%d|rfd=%d\n", wfd, rfd);
	if (add_table(NFPROTO_BRIDGE, "p60e") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p60e", "g", 0, 0, 0, NULL)) {
		printf("F560 FAIL|drop|chain\n");
		return;
	}
	for (i = 0; i < (int)(sizeof(arms) / sizeof(arms[0])); i++) {
		if (arms[i].tpid)
			flen = f560_tag(fr, FK33_IP4, arms[i].tpid, 0x0064);
		else
			flen = f556_frame(FK33_IP4, fr);
		f556_imm(FK33_IP4, arms[i].off, arms[i].len, imm);
		f560_arm("drop", arms[i].tag, NFPROTO_BRIDGE, "p60e", "g",
			 NFT_PAYLOAD_LL_HEADER, arms[i].off, arms[i].len, imm,
			 arms[i].len, fr, flen, "s0", arms[i].sproto, MAGIC77,
			 8, wfd, rfd, NULL, &o);
	}
	sh("/nft flush ruleset");
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "f560";

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F560 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F560 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F560 KERNEL|%s\n", "7.3.4-T558");
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
	printf("F560 NFL|%d\n", NFL59);
	/* the tag must survive the egress port, or the wire view is 60 bytes
	 * of nothing -- F37's one feature bit, cleared here once */
	if (!strcmp(mode, "f560recv")) {
		f559_setoff("clear", "r1", 0);
		f560_sec_recv();
	} else if (!strcmp(mode, "f560ndin")) {
		f559_setoff("clear", "r1", 0);
		f560_sec_ndin();
	} else if (!strcmp(mode, "f560ndeg")) {
		f560_sec_ndeg();
	} else if (!strcmp(mode, "f560arp")) {
		f559_setoff("clear", "r1", 0);
		f560_sec_arp();
	} else if (!strcmp(mode, "f560drop")) {
		f559_setoff("clear", "r1", 0);
		f560_sec_drop();
	} else {
		f559_setoff("clear", "r1", 0);
		f560_sec_recv();
		f560_sec_ndin();
		f560_sec_ndeg();
		f560_sec_arp();
		f560_sec_drop();
	}
	printf("F560 DONE\n");
	return 0;
}
