/* differ559_add.c -- turn 559 / F37: the 802.1Q tag as BYTES.
 *
 * F36 ended with an honest instrument limit: on a veth the tag lives in skb
 * metadata, AF_PACKET taps the frame after skb_vlan_untag() on the way in and
 * after validate_xmit_vlan() on the way out, and veth advertises
 * NETIF_F_HW_VLAN_CTAG_TX so the core never puts the tag back -- so "the bytes
 * of the tag on the wire" could not be measured at all.
 *
 * The way out is not a new driver.  net/ethtool/ioctl.c:ethtool_set_features()
 * writes dev->wanted_features and calls __netdev_update_features(); it does not
 * need an ndo_set_features op.  So ONE BIT can be taken away from a veth from
 * userspace (ETHTOOL_SFEATURES, NETIF_F_HW_VLAN_CTAG_TX), and then
 * net/core/dev.c:validate_xmit_vlan() has to insert the tag into the frame
 * itself.  That single bit is the difference this turn measures.
 *
 * Two views per arm, and they are different instruments:
 *   wire -- AF_PACKET on r1, the port the bridge transmits on.  The tap runs in
 *           xmit_one(), i.e. AFTER validate_xmit_skb(): with the offload it is
 *           60 bytes and tagless, without it the tag is at 12..15.
 *   far  -- AF_PACKET on r0, the peer of r1.  That tap runs in
 *           __netif_receive_skb_core() AFTER skb_vlan_untag(), so it is
 *           untagged in BOTH cases -- but a frame whose ethertype byte was
 *           zeroed reaches it as bytes, and then it is not "the far side's
 *           verdict" any more, it is the frame.
 *
 * Sections
 *   feat   GFEATURES/SFEATURES on every device of the netns; the bit, and the
 *          two frames it decides.
 *   wire   the same eight arms in three feature states (on -> cleared ->
 *          restored), so the causal link is bit -> bytes -> bit.
 *   ih     F36's own debt: the transport-base store at the bridge, on a tagged
 *          and on a plain frame, proto 6 and proto 17, 36 cells each.
 *   chain  two chains at one hook: what `pre` writes into the frame decides
 *          whether `post`'s transport store is alive at all.
 */

#include <linux/sockios.h>	/* SIOCETHTOOL */

/* ---------- frames ---------- */

/* the tagged frame for ANY of the base kinds: the datagram is moved 4 bytes
 * down and the tag is written in front of it, so "tagged" and "plain" differ in
 * exactly those 4 bytes. */
static int f559_frame(int kind, int tagged, unsigned char *out)
{
	unsigned char tmp[512];
	int n = f556_frame(kind, tmp);

	if (!tagged) {
		memcpy(out, tmp, (size_t)n);
		return n;
	}
	memset(out, 0, 512);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = 0x81; out[13] = 0x00;	/* 802.1Q */
	out[14] = 0x00; out[15] = 0x64;	/* prio 0, vid 100 */
	out[16] = 0x08; out[17] = 0x00;	/* inner ethertype */
	memcpy(out + 18, tmp + 14, (size_t)(n - 14));
	return n + 4;
}

/* ---------- ethtool: one bit ---------- */

#define F559_GFEATURES		0x0000003a	/* not 0x3b: that is SFEATURES here */
#define F559_SFEATURES		0x0000003b
#define F559_FWORDS		8
#define F559_TX_BIT		7	/* NETIF_F_HW_VLAN_CTAG_TX_BIT */
#define F559_RX_BIT		8	/* NETIF_F_HW_VLAN_CTAG_RX_BIT */

struct f559_fblk {
	unsigned int avail, want, act, never;
};

static int f559_gfeat(const char *dev, struct f559_fblk *blk, int max, int *nblk)
{
	struct {
		unsigned int cmd, size;
		struct f559_fblk b[F559_FWORDS];
	} c;
	struct ifreq ifr;
	int fd, rc, i;

	memset(&c, 0, sizeof(c));
	c.cmd = F559_GFEATURES;
	c.size = (unsigned int)max;	/* the kernel clamps and reports back */
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
	ifr.ifr_data = (char *)&c;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	if (rc < 0)
		return -errno;
	*nblk = (int)c.size;
	for (i = 0; i < *nblk && i < max; i++)
		blk[i] = c.b[i];
	return 0;
}

static int f559_sfeat(const char *dev, int nblk, unsigned int valid0,
		      unsigned int req0)
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
	c.b[0].valid = valid0;
	c.b[0].req = req0;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
	ifr.ifr_data = (char *)&c;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	return rc < 0 ? -errno : rc;	/* >= 0: an ETHTOOL_F_* mask, not errno */
}

static void f559_featline(const char *stage, const char *dev)
{
	struct f559_fblk b[F559_FWORDS];
	int n = 0, i, rc = f559_gfeat(dev, b, F559_FWORDS, &n);

	printf("F559 FEAT|stage=%s|dev=%s|rc=%d|nwords=%d", stage, dev, rc, n);
	if (rc == 0) {
		for (i = 0; i < n && i < F559_FWORDS; i++)
			printf("|avail%d=%08x|want%d=%08x|act%d=%08x", i,
			       b[i].avail, i, b[i].want, i, b[i].act);
		printf("|avail_tx=%d|act_tx=%d|act_rx=%d",
		       (int)((b[0].avail >> F559_TX_BIT) & 1),
		       (int)((b[0].act >> F559_TX_BIT) & 1),
		       (int)((b[0].act >> F559_RX_BIT) & 1));
	}
	printf("\n");
}

/* on: 1 = ask for the bit, 0 = ask it away.  Returns the raw ioctl result. */
static int f559_setoff(const char *stage, const char *dev, int on)
{
	struct f559_fblk b[F559_FWORDS];
	unsigned int bit = 1u << F559_TX_BIT;
	int n = 0, rc;

	if (f559_gfeat(dev, b, F559_FWORDS, &n) < 0 || n <= 0) {
		printf("F559 SET|stage=%s|dev=%s|no_gfeat\n", stage, dev);
		return -1;
	}
	rc = f559_sfeat(dev, n, bit, on ? bit : 0u);
	printf("F559 SET|stage=%s|dev=%s|valid=%08x|req=%08x|nwords=%d|rc=%d|"
	       "f_unsup=%d|f_wish=%d\n", stage, dev, bit, on ? bit : 0u, n, rc,
	       rc >= 0 ? (rc & 1) : -1, rc >= 0 ? (rc & 2) : -1);
	f559_featline(stage, dev);
	return rc;
}

/* ---------- one arm ---------- */

struct f559_env {
	const char *tag;
	const char *table;
	const char *chain;
	uint32_t base;
	int kind;
	int tagged;
};

struct f559_out {
	int rc, snd, acks;
	int wn, wpt, rn, rpt;
	unsigned long long cnt0, cnt, ipin;
	unsigned char w[2048], r[2048];
};

static int NFL59 = -1;
static const char *F559_STATE = "-";

static const char *f559_hexs(char *out, size_t osz, const unsigned char *b, int n)
{
	size_t at = 0;
	int i;

	out[0] = 0;
	for (i = 0; i < n && i < 96 && at + 3 < osz; i++)
		at += (size_t)snprintf(out + at, osz - at, "%02x", b[i]);
	return out;
}

static int f559_chain(const struct f559_env *e)
{
	int rc = add_table(NFPROTO_BRIDGE, e->table);
	int rc2 = f556_add_chain(NFPROTO_BRIDGE, e->table, e->chain, 0, 0, 1,
				 NULL);

	printf("F559 CHAIN|env=%s|table=%d|chain=%d\n", e->tag, rc, rc2);
	return rc || rc2;
}

/* the frame goes in from s0 (outside the bridge), the bridge floods it to r1
 * and up to br0; the two taps below are the two views. */
static void f559_send(const unsigned char *fr, int flen, int proto, int wfd,
		      int rfd, struct f559_out *o)
{
	static const unsigned char magic[8] = { 0x77, 0x77, 0x77, 0x77,
						0x77, 0x77, 0x77, 0x77 };
	int sk = 0;

	o->wpt = -1; o->rpt = -1;
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
	o->snd = pkt_send_p("s0", fr, flen, (unsigned short)proto);
	o->wn = f558_cap_match(wfd, o->w, (int)sizeof(o->w), 700, magic, 8, &sk,
			       &o->wpt);
	sk = 0;
	o->rn = f558_cap_match(rfd, o->r, (int)sizeof(o->r), 400, magic, 8, &sk,
			       &o->rpt);
}

/* install one rule, send one frame, read both taps, print one line.
 * `base` (may be NULL) is the arm whose bytes are the diff baseline; *out, if
 * not NULL, receives this arm's capture so that a control arm can become the
 * next arm's baseline. */
static void f559_arm(const struct f559_env *e, const char *arm, int off, int len,
		     const unsigned char *imm, int do_store,
		     const struct f559_out *base, int wfd, int rfd,
		     struct f559_out *out)
{
	struct f559_out o;
	unsigned char fr[512];
	char cw[1024], cr[1024], hw[256], hr[256];
	int flen = f559_frame(e->kind, e->tagged, fr);
	int kw = 0, kr = 0;

	memset(&o, 0, sizeof(o));
	snprintf(PRE57, sizeof(PRE57), "f59.%s.%s", e->tag, arm);
	f557_flush(NFPROTO_BRIDGE, e->table, e->chain, &o.acks);
	o.rc = f557_install(NFPROTO_BRIDGE, e->table, e->chain, 0, e->base,
			    (uint32_t)off, (uint32_t)len, imm,
			    do_store ? len : 0, do_store, 5, PRE57, &o.acks);
	nfl_drain(NFL59);
	o.cnt0 = f555_count(NFPROTO_BRIDGE, e->table, e->chain);
	{
		unsigned long long ip0 = f558_ipin();

		f559_send(fr, flen, e->tagged ? 0x8100 : 0x0800, wfd, rfd, &o);
		usleep(20000);
		o.ipin = f558_ipin() - ip0;
	}
	o.cnt = f555_count(NFPROTO_BRIDGE, e->table, e->chain);
	if (base && o.wn > 0 && base->wn > 0)
		kw = f558_chg(cw, sizeof(cw), base->w, base->wn, o.w, o.wn);
	if (base && o.rn > 0 && base->rn > 0)
		kr = f558_chg(cr, sizeof(cr), base->r, base->rn, o.r, o.rn);
	printf("F559 R|state=%s|env=%s|arm=%s|tagged=%d|base=%u|off=%d|len=%d|"
	       "store=%d|rc=%d|acks=%d|snd=%d|cnt0=%llu|cnt=%llu|live=%llu|"
	       "ipin=%llu|wn=%d|wpt=%d|wchg=%d|wchgs=%s|whex=%s|"
	       "rn=%d|rpt=%d|rchg=%d|rchgs=%s|rhex=%s\n",
	       F559_STATE, e->tag, arm, e->tagged, e->base, off, len, do_store,
	       o.rc, o.acks, o.snd, o.cnt0, o.cnt, o.cnt - o.cnt0, o.ipin,
	       o.wn, o.wpt, kw, cw[0] ? cw : "-",
	       o.wn > 0 ? f559_hexs(hw, sizeof(hw), o.w, o.wn) : "-",
	       o.rn, o.rpt, kr, cr[0] ? cr : "-",
	       o.rn > 0 ? f559_hexs(hr, sizeof(hr), o.r, o.rn) : "-");
	if (out)
		memcpy(out, &o, sizeof(o));
}

/* ---------- probe: is the ioctl transport itself alive? ---------- */

static int f559_ioctl_raw(const char *dev, void *data)
{
	struct ifreq ifr;
	int fd, rc, e;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
	ifr.ifr_data = (char *)data;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1000;
	errno = 0;
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	e = errno;
	close(fd);
	return rc < 0 ? -e : rc;
}

static void f559_sec_probe(void)
{
	struct {
		unsigned int cmd, size;
		unsigned int b[8 * 4];
	} c;
	int rc;

	printf("F559 PROBE|sioc_ethtool=%08x|sizeof_ifreq=%d|sizeof_gfeat=%d|"
	       "sizeof_sfeat=%d\n", (unsigned int)SIOCETHTOOL,
	       (int)sizeof(struct ifreq), 8 + 16 * 3, 8 + 8 * 3);
	/* ETHTOOL_GSET = 0x1, GDRVINFO = 0x3, GLINK = 0xa */
	memset(&c, 0, sizeof(c));
	c.cmd = 0x00000001; c.size = 0;
	rc = f559_ioctl_raw("r1", &c);
	printf("F559 PROBE|gset=%d\n", rc);
	memset(&c, 0, sizeof(c));
	c.cmd = 0x0000000a;
	rc = f559_ioctl_raw("r1", &c);
	printf("F559 PROBE|glink=%d|link=%u\n", rc, c.size);
	memset(&c, 0, sizeof(c));
	c.cmd = F559_GFEATURES; c.size = 3;
	rc = f559_ioctl_raw("r1", &c);
	printf("F559 PROBE|gfeat3=%d|size=%u|avail0=%08x|act0=%08x\n", rc, c.size,
	       c.b[0], c.b[2]);
	memset(&c, 0, sizeof(c));
	c.cmd = F559_GFEATURES; c.size = 8;
	rc = f559_ioctl_raw("r1", &c);
	printf("F559 PROBE|gfeat8=%d|size=%u|avail0=%08x|act0=%08x\n", rc, c.size,
	       c.b[0], c.b[2]);
	memset(&c, 0, sizeof(c));
	c.cmd = F559_SFEATURES; c.size = 3;
	rc = f559_ioctl_raw("r1", &c);
	printf("F559 PROBE|sfeat_nop=%d\n", rc);
}

/* ---------- feat ---------- */

static void f559_sec_feat(void)
{
	static const char *dv[] = { "lo", "i0", "i1", "s0", "s1", "r0", "r1",
				    "br0" };
	int i;

	for (i = 0; i < (int)(sizeof(dv) / sizeof(dv[0])); i++)
		f559_featline("init", dv[i]);
	/* the causal chain, on the port the bridge transmits on */
	f559_setoff("clear", "r1", 0);
	f559_setoff("restore", "r1", 1);
}

/* ---------- wire: eight arms, three feature states ---------- */

static void f559_sec_wire(const char *state)
{
	static const struct {
		const char *tag;
		int off, len;
		unsigned char v[4];
	} arms[] = {
		{ "s16_2", 16, 2, { 0x08, 0x06 } },
		{ "s14_99", 14, 2, { 0x00, 0x99 } },
		{ "s14_0", 14, 2, { 0x00, 0x00 } },
		{ "s12_2z", 12, 2, { 0x00, 0x00 } },
		{ "s12_4z", 12, 4, { 0x81, 0x00, 0x00, 0x00 } },
	};
	struct f559_env et, ep;
	struct f559_out ct, cp, o;
	unsigned char imm[16];
	unsigned char fr[512];
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int k;

	F559_STATE = state;
	memset(&et, 0, sizeof(et));
	et.tag = "wire"; et.table = "p59a"; et.chain = "pre";
	et.base = NFT_PAYLOAD_LL_HEADER; et.kind = FK33_IP4; et.tagged = 1;
	ep = et; ep.tagged = 0;
	if (f559_chain(&et))
		return;
	printf("F559 SECTION|wire|state=%s|wfd=%d|rfd=%d|flen_t=%d|flen_p=%d\n",
	       state, wfd, rfd, f559_frame(FK33_IP4, 1, fr),
	       f559_frame(FK33_IP4, 0, fr));
	memset(&ct, 0, sizeof(ct));
	f559_arm(&et, "ctl", 0, 0, NULL, 0, NULL, wfd, rfd, &ct);
	for (k = 0; k < (int)(sizeof(arms) / sizeof(arms[0])); k++) {
		memset(imm, 0, sizeof(imm));
		memcpy(imm, arms[k].v, (size_t)arms[k].len);
		f559_arm(&et, arms[k].tag, arms[k].off, arms[k].len, imm,
			 arms[k].len, &ct, wfd, rfd, &o);
	}
	/* the same store on a plain frame: 16+2 > 14, so it must be dead */
	memset(&cp, 0, sizeof(cp));
	f559_arm(&ep, "ctl_plain", 0, 0, NULL, 0, NULL, wfd, rfd, &cp);
	f559_arm(&ep, "s16_2_plain", 16, 2, (const unsigned char *)"\x08\x06",
		 2, &cp, wfd, rfd, &o);
	sh("/nft flush ruleset");
}

/* ---------- ih: transport base at the bridge, tagged and plain ---------- */

static void f559_sec_ih(void)
{
	static const int offs[12] = { 0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24 };
	static const int lens[3] = { 1, 2, 4 };
	static const struct {
		const char *tag;
		const char *table;
		int kind;
		int tagged;
	} combos[] = {
		{ "p6T", "p59b1", FK33_IP4_P6, 1 },
		{ "p6P", "p59b2", FK33_IP4_P6, 0 },
		{ "uT", "p59b3", FK33_IP4, 1 },
		{ "uP", "p59b4", FK33_IP4, 0 },
	};
	struct f559_env e;
	struct f559_out ctl, o;
	unsigned char imm[16], fr[512];
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int c, i, j;

	F559_STATE = "clear";
	for (c = 0; c < (int)(sizeof(combos) / sizeof(combos[0])); c++) {
		memset(&e, 0, sizeof(e));
		e.tag = combos[c].tag;
		e.table = combos[c].table;
		e.chain = "pre";
		e.base = NFT_PAYLOAD_TRANSPORT_HEADER;
		e.kind = combos[c].kind;
		e.tagged = combos[c].tagged;
		if (f559_chain(&e))
			continue;
		printf("F559 SECTION|ih|combo=%s|wfd=%d|rfd=%d|flen=%d\n",
		       e.tag, wfd, rfd, f559_frame(e.kind, e.tagged, fr));
		memset(&ctl, 0, sizeof(ctl));
		f559_arm(&e, "ctl", 0, 0, NULL, 0, NULL, wfd, rfd, &ctl);
		for (i = 0; i < 12; i++) {
			for (j = 0; j < 3; j++) {
				char arm[32];

				f557_imm(offs[i], lens[j], imm);
				snprintf(arm, sizeof(arm), "g%d_%d", offs[i],
					 lens[j]);
				f559_arm(&e, arm, offs[i], lens[j], imm,
					 lens[j], &ctl, wfd, rfd, &o);
			}
		}
	}
	sh("/nft flush ruleset");
}

/* ---------- chain: the envelope is a property of the moment ---------- */

static void f559_two(const unsigned char *fr, int flen, const char *arm,
		     int pre_do, uint32_t pre_base, int pre_off, int pre_len,
		     const unsigned char *pre_imm, int wfd, int rfd,
		     const struct f559_out *base)
{
	unsigned char pimm[4] = { 0x1f, 0x90 };	/* the transport store */
	struct f559_out o;
	char cw[1024], cr[1024], hw[256], hr[256];
	int kw = 0, kr = 0;
	int acks = 0;	/* f557_nft_one() writes *acks unconditionally */

	memset(&o, 0, sizeof(o));
	f557_flush(NFPROTO_BRIDGE, "p59c", "pre", &acks);
	f557_flush(NFPROTO_BRIDGE, "p59c", "post", &acks);
	if (pre_do) {
		snprintf(PRE57, sizeof(PRE57), "f59.pre.%s", arm);
		f557_install(NFPROTO_BRIDGE, "p59c", "pre", 0, pre_base,
			     (uint32_t)pre_off, (uint32_t)pre_len, pre_imm,
			     pre_len, 1, 5, PRE57, &o.acks);
	}
	snprintf(PRE57, sizeof(PRE57), "f59.post.%s", arm);
	o.rc = f557_install(NFPROTO_BRIDGE, "p59c", "post", 0,
			    NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, pimm, 2, 1, 5,
			    PRE57, &o.acks);
	nfl_drain(NFL59);
	o.cnt0 = f555_count(NFPROTO_BRIDGE, "p59c", "post");
	{
		unsigned long long ip0 = f558_ipin();

		f559_send(fr, flen, 0x8100, wfd, rfd, &o);
		usleep(20000);
		o.ipin = f558_ipin() - ip0;
	}
	o.cnt = f555_count(NFPROTO_BRIDGE, "p59c", "post");
	if (base && o.wn > 0 && base->wn > 0)
		kw = f558_chg(cw, sizeof(cw), base->w, base->wn, o.w, o.wn);
	if (base && o.rn > 0 && base->rn > 0)
		kr = f558_chg(cr, sizeof(cr), base->r, base->rn, o.r, o.rn);
	printf("F559 C|state=%s|arm=%s|pre=%d|prebase=%u|preoff=%d|prelen=%d|"
	       "rc=%d|cnt0=%llu|cnt=%llu|live=%llu|ipin=%llu|"
	       "wn=%d|wchg=%d|wchgs=%s|whex=%s|rn=%d|rchg=%d|rchgs=%s|rhex=%s\n",
	       F559_STATE, arm, pre_do, pre_base, pre_off, pre_len, o.rc,
	       o.cnt0, o.cnt, o.cnt - o.cnt0, o.ipin, o.wn, kw,
	       cw[0] ? cw : "-",
	       o.wn > 0 ? f559_hexs(hw, sizeof(hw), o.w, o.wn) : "-", o.rn,
	       kr, cr[0] ? cr : "-",
	       o.rn > 0 ? f559_hexs(hr, sizeof(hr), o.r, o.rn) : "-");
}

static void f559_sec_chain(void)
{
	struct f559_out ctl;
	unsigned char fr[512];
	int wfd = cap_open("r1"), rfd = cap_open("r0");
	int flen = f559_frame(FK33_IP4_P6, 1, fr);
	int rc, rc1, rc2;
	int acks = 0;

	F559_STATE = "clear";
	rc = add_table(NFPROTO_BRIDGE, "p59c");
	rc1 = f556_add_chain(NFPROTO_BRIDGE, "p59c", "pre", 0, 0, 1, NULL);
	rc2 = f556_add_chain(NFPROTO_BRIDGE, "p59c", "post", 0, 10, 1, NULL);
	printf("F559 SECTION|chain|table=%d|pre=%d|post=%d|flen=%d\n", rc, rc1,
	       rc2, flen);
	if (rc || rc1 || rc2)
		return;
	/* baseline: both chains empty, so the diffs below are the stores' own */
	memset(&ctl, 0, sizeof(ctl));
	f557_flush(NFPROTO_BRIDGE, "p59c", "pre", &acks);
	f557_flush(NFPROTO_BRIDGE, "p59c", "post", &acks);
	f559_send(fr, flen, 0x8100, wfd, rfd, &ctl);
	f559_two(fr, flen, "a_none", 0, 0, 0, 0, NULL, wfd, rfd, &ctl);
	f559_two(fr, flen, "b_et", 1, NFT_PAYLOAD_LL_HEADER, 16, 2,
		 (const unsigned char *)"\x08\x06", wfd, rfd, &ctl);
	f559_two(fr, flen, "c_tci", 1, NFT_PAYLOAD_LL_HEADER, 14, 2,
		 (const unsigned char *)"\x00\x99", wfd, rfd, &ctl);
	sh("/nft flush ruleset");
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "f559";

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F559 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F559 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F559 KERNEL|%s\n", "7.3.4-T558");
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
	printf("F559 NFL|%d\n", NFL59);
	if (!strcmp(mode, "f559probe")) {
		f559_sec_probe();
	} else if (!strcmp(mode, "f559feat")) {
		f559_sec_feat();
	} else if (!strcmp(mode, "f559wire")) {
		f559_sec_wire("on");
	} else if (!strcmp(mode, "f559wiron")) {
		f559_sec_wire("on");
	} else if (!strcmp(mode, "f559wiroff")) {
		f559_setoff("clear", "r1", 0);
		f559_sec_wire("clear");
	} else if (!strcmp(mode, "f559ih")) {
		f559_setoff("clear", "r1", 0);
		f559_sec_ih();
	} else if (!strcmp(mode, "f559chain")) {
		f559_setoff("clear", "r1", 0);
		f559_sec_chain();
	} else if (!strcmp(mode, "f559smoke")) {
		f559_sec_feat();
		f559_sec_wire("on");
		f559_setoff("clear", "r1", 0);
		f559_sec_wire("clear");
	} else {
		f559_sec_feat();
		f559_sec_wire("on");
		f559_setoff("clear", "r1", 0);
		f559_sec_wire("clear");
		f559_setoff("restore", "r1", 1);
		f559_sec_wire("restored");
		f559_setoff("clear2", "r1", 0);
		f559_sec_ih();
		f559_sec_chain();
	}
	printf("F559 DONE\n");
	return 0;
}
