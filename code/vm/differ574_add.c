/* differ574_add.c -- turn 574 (F52).
 *
 *  THE DEBT (named at the end of 573, §8): a tagged frame on the bridge --
 *  the local copy never reaches the ip6 door although `brl` counts it, and
 *  `@ll,12,2` at the bridge door is not the inner ethertype although the taps
 *  show 86dd at 12..13.  Two questions: what IS the `@ll` domain of a tagged
 *  frame, and what kills the local copy between LOCAL_IN and PRE_ROUTING.
 *
 *  Mode `tag`: the same three-port bridge as F51 (x1/y1/z1 on br0, IPv6 only
 *  on br0).  Five doors of one frame:
 *
 *    brp  bridge prerouting   (NF_BR_PRE_ROUTING)   before br_flood()
 *    brf  bridge forward      (NF_BR_FORWARD)       once per port copy
 *    brl  bridge local-in     (NF_BR_LOCAL_IN)      the local copy
 *    in6  ip6 prerouting      (br0, or br0.100 in group D)
 *    ndy  netdev ingress on y0 (the far end of one port copy)
 *
 *  Frames, all broadcast, IPv6 fd02::11 -> fd02::92, UDP 40000->5000:
 *    A  plain, 86dd at 12..13                                (74+6 bytes)
 *    B  802.1Q TCI 0x0064  (vid 100)                         (78+6 bytes)
 *    C  802.1Q TCI 0x0000  (priority tag, vid 0)             (78+6 bytes)
 *
 *  Groups: S = B with no VLAN device, V = C, D = B with br0.100 up, F = store
 *  at the forward door.  Every arm carries the census (counter+log+accept at
 *  prio 0 in all five doors) and at most one counter+store/read+log+accept at
 *  prio 10 in one door.
 */

#define F574_SPORT	40000
#define F574_DPORT	5000
#define ND74		5

static const unsigned char A74_SRC[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x11 };
static const unsigned char A74_DST[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x92 };
static const unsigned char A74_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const unsigned char A74_N6[6] = { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95 };

/* ---------- the five doors ---------- */

static struct f571_door D574[] = {
	{ "brp", NFPROTO_BRIDGE, "e74a", NULL, 0, 10, 20 },	/* PRE_ROUTING */
	{ "brf", NFPROTO_BRIDGE, "e74b", NULL, 2, 30, 40 },	/* FORWARD     */
	{ "brl", NFPROTO_BRIDGE, "e74c", NULL, 1, 50, 60 },	/* LOCAL_IN    */
	{ "in6", NFPROTO_IPV6,   "e74d", NULL, 0, 70, 80 },	/* PRE_ROUTING */
	{ "ndy", NFPROTO_NETDEV, "e74e", "y0", 0, 90, 100 },	/* INGRESS     */
};
enum { E74_BRP = 0, E74_BRF, E74_BRL, E74_IN6, E74_NDY };

#define T_A4	((1 << T_X1) | (1 << T_Y0) | (1 << T_Z0) | (1 << T_BR0))

static unsigned char F574_FA[128], F574_FB[128], F574_FC[128];
static int F574_LA = -1, F574_LB = -1, F574_LC = -1;

/* ---------- a 802.1Q frame: 14 + 4 + IPv6/UDP ---------- */

static int f574_frame_tag(unsigned char *out, const unsigned char *dmac,
			  const unsigned char *smac, unsigned int tci)
{
	memset(out, 0, 128);
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x81;
	out[13] = 0x00;			/* TPID 802.1Q */
	out[14] = (unsigned char)((tci >> 8) & 0xff);
	out[15] = (unsigned char)(tci & 0xff);
	out[16] = 0x86;			/* inner ethertype */
	out[17] = 0xdd;
	return 18 + f570_ip6(out + 18, A74_SRC, A74_DST, 0, F574_SPORT,
			     F574_DPORT);
}

/* ---------- the VLAN device (group D) ---------- */

#define F574_IFLA_VLAN_ID	1

static int f574_link_add_vlan(const char *name, const char *link,
			      unsigned short vid)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[256];
	} req;
	struct nlattr *li, *data;
	uint32_t lidx = (uint32_t)f555_ifindex(link);
	int fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	attr_put(&req.nlh, IFLA_IFNAME, name, (int)strlen(name) + 1);
	attr_put(&req.nlh, IFLA_LINK, &lidx, 4);
	li = nest_start(&req.nlh, IFLA_LINKINFO);
	attr_put(&req.nlh, IFLA_INFO_KIND, "vlan", 5);
	data = nest_start(&req.nlh, IFLA_INFO_DATA);
	attr_put(&req.nlh, F574_IFLA_VLAN_ID, &vid, 2);
	nest_end(&req.nlh, data);
	nest_end(&req.nlh, li);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* ---------- environment: F51's bridge plus the three frames ---------- */

static int f574_env(void)
{
	int rc = f573_env();
	char ha[256], hb[256], hc[256];

	printf("F574 ENVRC|f573=%d\n", rc);
	if (rc)
		return rc;
	F574_LA = f570_frame_plain(F574_FA, A74_BC, F573_X0M, A74_SRC,
				   A74_DST, 0);
	F574_LB = f574_frame_tag(F574_FB, A74_BC, F573_X0M, 0x0064);
	F574_LC = f574_frame_tag(F574_FC, A74_BC, F573_X0M, 0x0000);
	printf("F574 FRM|a=%s\n", f559_hexs(ha, sizeof(ha), F574_FA, F574_LA));
	printf("F574 FRM|b=%s\n", f559_hexs(hb, sizeof(hb), F574_FB, F574_LB));
	printf("F574 FRM|c=%s\n", f559_hexs(hc, sizeof(hc), F574_FC, F574_LC));
	printf("F574 ENV|la=%d|lb=%d|lc=%d|x0mac=%s|br0mac=%s|br0=%d|x1=%d|"
	       "y0=%d|z0=%d|u6=%d|nfl=%d\n",
	       F574_LA, F574_LB, F574_LC,
	       f559_hexs(ha, sizeof(ha), F573_X0M, 6),
	       f559_hexs(hb, sizeof(hb), F573_BRM, 6),
	       f555_ifindex("br0"), f555_ifindex("x1"), f555_ifindex("y0"),
	       f555_ifindex("z0"), F573_U6, F573_NFL);
	return 0;
}

static int f574_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND74; i++) {
		struct f571_door *D = &D574[i];
		int a, b, c;

		a = add_table(D->fam, D->table);
		b = f556_add_chain(D->fam, D->table, "pre0", D->hook,
				   (uint32_t)D->prio0, 1, D->dev);
		c = f556_add_chain(D->fam, D->table, "ch", D->hook,
				   (uint32_t)D->prio1, 1, D->dev);
		printf("F574 CH|door=%s|fam=%d|hook=%u|dev=%s|table=%d|"
		       "pre0=%d|ch=%d\n", D->tag, (int)D->fam, D->hook,
		       D->dev ? D->dev : "-", a, b, c);
		rc |= a | b | c;
	}
	return rc;
}

static void f574_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND74; i++) {
		f557_flush(D574[i].fam, D574[i].table, "pre0", &acks);
		f557_flush(D574[i].fam, D574[i].table, "ch", &acks);
	}
}

/* ---------- the snapshot: F51's plus br0's OTHERHOST counter ---------- */

struct f574_rep {
	struct f573_rep b;
	unsigned long long broth, brrxd;
};

static void f574_snap(struct f574_rep *R)
{
	struct f573_lst s;

	f573_snap(&R->b);
	f573_stats("br0", &s);
	R->broth = s.other;
	R->brrxd = s.rxd;
}

/* ---------- one arm ---------- */

static void f574_arm2(const char *arm, int fk, int tapmask, int door,
		      const struct f571_cfg *C, int door2,
		      const struct f571_cfg *C2);

static void f574_arm(const char *arm, int fk, int tapmask, int door,
		     const struct f571_cfg *C)
{
	f574_arm2(arm, fk, tapmask, door, C, -1, NULL);
}

static void f574_arm2(const char *arm, int fk, int tapmask, int door,
		      const struct f571_cfg *C, int door2,
		      const struct f571_cfg *C2)
{
	struct f571_cfg N, Z;
	struct f574_rep r0, r;
	struct f573_pl pl;
	const unsigned char *fr = NULL;
	int flen = 0, proto = 0x8100;
	unsigned long long c0[ND74], c1[ND74], s0 = 0, s1 = 0, s2 = 0, s20 = 0;
	int i, acks = 0, snd = 0, polls = 0, k, maxp = 12, st = -9, rcs = -99;
	int rcs2 = -99;
	char hx[64];
	const char *fkn = "A";

	memset(&r0, 0, sizeof(r0));
	memset(&r, 0, sizeof(r));
	f571_zero(&N, "p");
	if (fk == 0) {
		fr = F574_FA;
		flen = F574_LA;
		proto = 0x86dd;
		fkn = "A";
	} else if (fk == 1) {
		fr = F574_FB;
		flen = F574_LB;
		fkn = "B";
	} else if (fk == 2) {
		fr = F574_FC;
		flen = F574_LC;
		fkn = "C";
	}
	f574_flush_all();
	f573_nfl_drain(NULL);
	st = f573_settle();
	f573_tap_close_all();
	f573_tap_open_mask(tapmask);
	for (i = 0; i < F573_TAPN; i++)
		if (F573_TAP[i].fd >= 0)
			f573_tap_drain(i);
	for (i = 0; i < ND74; i++) {
		char nm[8];

		snprintf(nm, sizeof(nm), "p%d", i);
		if (f571_rule(&D574[i], "pre0", nm, &N, &acks))
			printf("F574 RUFAIL|arm=%s|door=%s|chain=pre0\n", arm,
			       D574[i].tag);
	}
	if (door >= 0) {
		f571_zero(&Z, "s");
		rcs = f571_rule(&D574[door], "ch", "s", C ? C : &Z, &acks);
	}
	if (door2 >= 0) {
		f571_zero(&Z, "q");
		rcs2 = f571_rule(&D574[door2], "ch", "q",
				 C2 ? C2 : &Z, &acks);
	}
	for (i = 0; i < ND74; i++)
		c0[i] = f555_count(D574[i].fam, D574[i].table, "pre0");
	s0 = door >= 0 ? f555_count(D574[door].fam, D574[door].table, "ch") : 0;
	s20 = door2 >= 0 ? f555_count(D574[door2].fam, D574[door2].table, "ch")
			 : 0;
	f574_snap(&r0);
	f573_u6_drain(&r0.b);
	if (fk >= 0) {
		snd = pkt_send_p("x0", fr, flen, (unsigned short)proto);
		for (k = 0; k < maxp; k++) {
			usleep(120000);
			f574_snap(&r);
			polls++;
			if (r.b.u6n > r0.b.u6n || r.b.i6in > r0.b.i6in ||
			    r.b.i6disc > r0.b.i6disc || r.b.yrxp > r0.b.yrxp ||
			    r.b.zrxp > r0.b.zrxp || r.b.brrxp > r0.b.brrxp ||
			    r.broth > r0.broth)
				break;
		}
	} else {
		usleep(300000);
		polls = 1;
	}
	f574_snap(&r);
	usleep(150000);
	f574_snap(&r);
	for (i = 0; i < ND74; i++)
		c1[i] = f555_count(D574[i].fam, D574[i].table, "pre0");
	s1 = door >= 0 ? f555_count(D574[door].fam, D574[door].table, "ch") : 0;
	s2 = door2 >= 0 ? f555_count(D574[door2].fam, D574[door2].table, "ch")
		       : 0;
	memset(&pl, 0, sizeof(pl));
	f573_nfl_drain(&pl);
	for (i = 0; i < F573_TAPN; i++)
		f573_tap_drain(i);

	printf("F574 A|arm=%s|fk=%s|door=%s|d2=%s|mode=%d|base=%u|off=%d|"
	       "len=%d|imm=%s|rcs=%d|rcs2=%d|snt=%d|sendrc=%d|polls=%d|"
	       "tapmask=%d|u6n=%d|u6len=%d|u6sport=%d|nfl=%d|st=%d\n",
	       arm, fkn, door >= 0 ? D574[door].tag : "-",
	       door2 >= 0 ? D574[door2].tag : "-",
	       C ? C->mode : (door >= 0 ? 0 : -1), C ? C->base : 0,
	       C ? C->off : -1, C ? C->len : -1,
	       C ? f559_hexs(hx, sizeof(hx), C->imm, C->len) : "-", rcs, rcs2,
	       fk >= 0, snd, polls, tapmask, r.b.u6n - r0.b.u6n, r.b.u6len,
	       r.b.u6sport, pl.n, st);
	printf("F574 C|brp=%llu,%lld|brf=%llu,%lld|brl=%llu,%lld|"
	       "in6=%llu,%lld|ndy=%llu,%lld|c2=%lld\n",
	       c1[E74_BRP] - c0[E74_BRP],
	       door == E74_BRP ? (long long)(s1 - s0) : -1LL,
	       c1[E74_BRF] - c0[E74_BRF],
	       door == E74_BRF ? (long long)(s1 - s0) : -1LL,
	       c1[E74_BRL] - c0[E74_BRL],
	       door == E74_BRL ? (long long)(s1 - s0) : -1LL,
	       c1[E74_IN6] - c0[E74_IN6],
	       door == E74_IN6 ? (long long)(s1 - s0) : -1LL,
	       c1[E74_NDY] - c0[E74_NDY],
	       door == E74_NDY ? (long long)(s1 - s0) : -1LL,
	       door2 >= 0 ? (long long)(s2 - s20) : -1LL);
	printf("F574 B|i6in_d=%llu|i6hdr_d=%llu|i6addr_d=%llu|i6unk_d=%llu|"
	       "i6trunc_d=%llu|i6nor_d=%llu|deliv_d=%llu|disc_d=%llu|"
	       "mcas_d=%llu|u6in_d=%llu|u6err_d=%llu|u6nop_d=%llu|"
	       "y0rxp_d=%llu|y0oth_d=%llu|z0rxp_d=%llu|z0oth_d=%llu|"
	       "brrxp_d=%llu|brrxb_d=%llu|broth_d=%llu|brrxd_d=%llu|"
	       "x1rxp_d=%llu\n",
	       r.b.i6in - r0.b.i6in, r.b.i6hdr - r0.b.i6hdr,
	       r.b.i6addr - r0.b.i6addr, r.b.i6unk - r0.b.i6unk,
	       r.b.i6trunc - r0.b.i6trunc, r.b.i6nor - r0.b.i6nor,
	       r.b.i6deliv - r0.b.i6deliv, r.b.i6disc - r0.b.i6disc,
	       r.b.i6mcast - r0.b.i6mcast, r.b.u6in - r0.b.u6in,
	       r.b.u6err - r0.b.u6err, r.b.u6nop - r0.b.u6nop,
	       r.b.yrxp - r0.b.yrxp, r.b.yoth - r0.b.yoth,
	       r.b.zrxp - r0.b.zrxp, r.b.zoth - r0.b.zoth,
	       r.b.brrxp - r0.b.brrxp, r.b.brrxb - r0.b.brrxb,
	       r.broth - r0.broth, r.brrxd - r0.brrxd,
	       r.b.x1rxp - r0.b.x1rxp);
	{
		char mb[1400];
		int o2 = 0;

		mb[0] = 0;
		for (i = 0; i < pl.n && i < F573_NPL; i++) {
			char hh[220];
			int w = snprintf(mb + o2, sizeof(mb) - (size_t)o2,
					 "|m%d=%s:%d:%d:%d:%s", i,
					 pl.m[i].prefix, pl.m[i].indev,
					 pl.m[i].outdev, pl.m[i].plen,
					 f559_hexs(hh, sizeof(hh), pl.m[i].p,
						   pl.m[i].plen > 42 ? 42
								     : pl.m[i].plen));

			if (w < 0 || w >= (int)sizeof(mb) - o2)
				break;
			o2 += w;
		}
		printf("F574 M|n=%d%s\n", pl.n, mb);
	}
	{
		char tb[1400];
		int o2 = 0;

		tb[0] = 0;
		for (i = 0; i < F573_TAPN; i++) {
			char hh[260];
			int w;

			if (F573_TAP[i].len > 0) {
				w = snprintf(tb + o2, sizeof(tb) - (size_t)o2,
					     "|t%d=%s:%d:%d:%s", i,
					     F573_TAPDEV[i], F573_TAP[i].n,
					     F573_TAP[i].flen,
					     f559_hexs(hh, sizeof(hh),
						       F573_TAP[i].b,
						       F573_TAP[i].len));
			} else {
				w = snprintf(tb + o2, sizeof(tb) - (size_t)o2,
					     "|t%d=%s:%d:%d:-", i,
					     F573_TAPDEV[i], F573_TAP[i].n,
					     F573_TAP[i].flen);
			}
			if (w < 0 || w >= (int)sizeof(tb) - o2)
				break;
			o2 += w;
		}
		printf("F574 T|%s\n", tb[0] ? tb + 1 : tb);
	}
}

/* ---------- config builders ---------- */

static void f574_wr(struct f571_cfg *C, uint32_t base, int off, int len,
		    const unsigned char *imm)
{
	f571_wr(C, "s", base, off, len, imm, 0, 0);
}

static void f574_rdv(struct f571_cfg *C, uint32_t base, int off, int len,
		     const unsigned char *imm)
{
	f571_zero(C, "s");
	C->mode = 3;
	C->base = base;
	C->off = off;
	C->len = len;
	memcpy(C->imm, imm, (size_t)len);
}

/* ---------- sections ---------- */

static void f574_sec_topo(void)
{
	f574_arm("topo", -1, 0, -1, NULL);
}

/* S: the tagged frame with vid 100 and no VLAN device */
static void f574_sec_s(void)
{
	struct f571_cfg C;
	unsigned char b12[2] = { 0x81, 0x00 };
	unsigned char i12[2] = { 0x86, 0xdd };
	unsigned char t14[2] = { 0x00, 0x64 };
	unsigned char i16[2] = { 0x86, 0xdd };
	unsigned char v18[2] = { 0x60, 0x00 };
	unsigned char p4[4] = { 0x60, 0x00, 0x00, 0x00 };
	unsigned char hl[1] = { 0x40 };
	unsigned char z14[2] = { 0x00, 0x00 };
	unsigned char z4[4] = { 0x00, 0x00, 0x00, 0x00 };
	unsigned char et[2] = { 0x08, 0x06 };
	unsigned char v4[2] = { 0x08, 0x00 };

	f574_arm("c100", 1, T_A4, -1, NULL);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A74_BC);
	f574_arm("r0", 1, T_A4, E74_BRP, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 6, 6, F573_X0M);
	f574_arm("r6", 1, T_A4, E74_BRP, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, b12);
	f574_arm("r12t", 1, T_A4, E74_BRP, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, i12);
	f574_arm("r12i", 1, T_A4, E74_BRP, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, t14);
	f574_arm("r14", 1, T_A4, E74_BRP, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, i16);
	f574_arm("r16", 1, T_A4, E74_BRP, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 18, 2, v18);
	f574_arm("r18", 1, T_A4, E74_BRP, &C);
	f574_rdv(&C, NFT_PAYLOAD_NETWORK_HEADER, 7, 1, hl);
	f574_arm("nh7", 1, T_A4, E74_BRP, &C);
	f574_rdv(&C, NFT_PAYLOAD_NETWORK_HEADER, 0, 4, p4);
	f574_arm("nh0", 1, T_A4, E74_BRP, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, i16);
	f574_arm("brl16", 1, T_A4, E74_BRL, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, t14);
	f574_arm("ndy14", 1, T_A4, E74_NDY, &C);
	f574_wr(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, t14);
	f574_arm("w14_same", 1, T_A4, E74_BRP, &C);
	f574_wr(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, z14);
	f574_arm("w14_0", 1, T_A4, E74_BRP, &C);
	f574_wr(&C, NFT_PAYLOAD_LL_HEADER, 14, 4, z4);
	f574_arm("w14_len4", 1, T_A4, E74_BRP, &C);
	f574_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, et);
	f574_arm("w12_p", 1, T_A4, E74_BRP, &C);
	f574_wr(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, v4);
	f574_arm("w16", 1, T_A4, E74_BRP, &C);
	f574_wr(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A74_N6);
	f574_arm("w0d", 1, T_A4, E74_BRP, &C);
	/* offset 12 with len 4: `struct vlan_ethhdr` has h_vlan_proto at 12 and
	 * h_vlan_TCI at 14, so this one expression can set both at once */
	f574_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 4, z4);
	f574_arm("w12_4", 1, T_A4, E74_BRP, &C);
}

/* F: the same store at the forward door -- once per port copy */
static void f574_sec_f(void)
{
	struct f571_cfg C;
	unsigned char z14[2] = { 0x00, 0x00 };

	f574_wr(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, z14);
	f574_arm("wf14", 1, T_A4, E74_BRF, &C);
	/* the same store at the forward door, with the far end asked what TCI it
	 * received: the store on a clone must reach that clone and no other */
	f574_arm2("wf14_ndy", 1, T_A4, E74_BRF, &C, E74_NDY, &C);
}

/* V: the priority tag (vid 0) -- same bytes, different vid */
static void f574_sec_v(void)
{
	struct f571_cfg C;
	unsigned char t100[2] = { 0x00, 0x64 };

	f574_arm("c0", 2, T_A4, -1, NULL);
	f574_wr(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, t100);
	f574_arm("w14_100", 2, T_A4, E74_BRP, &C);
}

/* D: the same frame with a VLAN device on br0 -- mechanism, not correlation */
static void f574_sec_d(void)
{
	struct f571_cfg C;
	unsigned char i16[2] = { 0x86, 0xdd };
	unsigned char b12[2] = { 0x81, 0x00 };
	unsigned char i12[2] = { 0x86, 0xdd };
	unsigned char v14[2] = { 0x60, 0x00 };
	unsigned char l16[2] = { 0x00, 0x00 };
	unsigned char l16o[2] = { 0x00, 0x1a };
	unsigned char n18[2] = { 0x00, 0x1a };
	int rc;

	rc = f574_link_add_vlan("br0.100", "br0", 100);
	printf("F574 VLANDEV|name=br0.100|link=br0|vid=100|rc=%d\n", rc);
	set_up("br0.100");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0.100/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0.100/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0.100/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0.100/accept_ra", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0.100/autoconf", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0.100/forwarding", "0");
	printf("F574 VDSYS|idx=%d|v6=%d\n", f555_ifindex("br0.100"),
	       f573_sysint("/proc/sys/net/ipv6/conf/br0.100/disable_ipv6"));
	usleep(2000000);
	f573_settle();
	f574_arm("vd_c", 1, T_A4, -1, NULL);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, i16);
	f574_arm("vd_r16i", 1, T_A4, E74_IN6, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, b12);
	f574_arm("vd_r12", 1, T_A4, E74_IN6, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, i12);
	f574_arm("vd_r12i", 1, T_A4, E74_IN6, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, v14);
	f574_arm("vd_r14", 1, T_A4, E74_IN6, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, l16);
	f574_arm("vd_r16", 1, T_A4, E74_IN6, &C);
	/* the same offset with the value the TAGGED layout puts there */
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, l16o);
	f574_arm("vd_r16old", 1, T_A4, E74_IN6, &C);
	f574_rdv(&C, NFT_PAYLOAD_LL_HEADER, 18, 2, n18);
	f574_arm("vd_r18", 1, T_A4, E74_IN6, &C);
	/* and the vid-0 frame through the same device: the tag is gone for every
	 * vid, so the LL domain does not depend on the vid here */
	f574_arm("vd_c0", 2, T_A4, -1, NULL);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "tag";
	int rc;

	printf("F574 BEGIN|mode=%s\n", mode);
	rc = f574_env();
	if (rc)
		return 3;
	rc = f574_chains();
	printf("F574 CHAINS|rc=%d\n", rc);
	if (rc)
		return 4;
	printf("F574 START\n");
	fflush(stdout);

	f574_sec_topo();
	f574_sec_s();
	f574_sec_f();
	f574_sec_v();
	f574_sec_d();

	printf("F574 END\n");
	return 0;
}
