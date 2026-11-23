/* differ571_add.c -- turn 571 (F49).
 *
 *  THE DEBT (named at the end of 570): "the same PPPoE frame at a layer-3
 *  door, pf = NFPROTO_IPV6, nhoff = 22, the guard nft_nh_write_ok_ip6()
 *  instead of the netdev branch".
 *
 *  Mode `pp6l3`: one frame, made by f570_frame_ppp() (the F48 builder) and
 *  injected on x0:  ethernet (14) | PPPoE session hdr (6, sid 99) | PPP proto
 *  00 57 (2) | IPv6 + UDP 40000->5000 + 18x77.  The PPPoX session socket is
 *  bound on x1 with remote = x0's MAC, the unit is attached exactly as pppd
 *  does it, and ppp0 carries an IPv6 address -- so the 8 bytes the netdev door
 *  still sees are removed by the kernel, not by the instrument, and the same
 *  frame is presented to *four* doors:
 *
 *    in3   inet  family, prerouting (layer 3, on ppp0)  <- the door in question
 *    ip63  ipv6  family, prerouting (layer 3, on ppp0)  <- control for the family
 *    nd1   netdev family, ingress on x1                 <- the door of F44/F48
 *    ip43  ipv4  family, prerouting                     <- a door this frame is not for
 *
 *  Mode `tap6f` closes the other named debt: the three extension shapes that
 *  came out of F48 with tapn = 0.  Same veth, the old filter (byte 20 must be
 *  17) and a shape-aware filter on the same frames, counted on the same tap.
 *
 *  Every helper below the new code is the one that produced F31..F48.
 */

#define F571_SID	99
#define F571_SPORT	40000
#define F571_DPORT	5000

/* the IPv6 datagram the frame carries: fd02::11 -> fd02::91 */
static const unsigned char A6_L_SRC[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x11 };
static const unsigned char A6_L_DST[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x91 };
static const unsigned char A6_L_ALT[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x92 };

/* ---------- the four doors ---------- */

struct f571_door {
	const char *tag;
	uint8_t fam;
	const char *table;
	const char *dev;
	uint32_t hook;
	int prio0, prio1;
};

static struct f571_door D571[] = {
	{ "in3",  NFPROTO_INET,   "e71a", NULL, 0, 10, 20 },
	{ "ip63", NFPROTO_IPV6,   "e71b", NULL, 0, 30, 40 },
	{ "nd1",  NFPROTO_NETDEV, "e71c", "x1", 0, 50, 60 },
	{ "ip43", NFPROTO_IPV4,   "e71d", NULL, 0, 70, 80 },
};
#define ND71	4
enum { D_IN3 = 0, D_IP63, D_ND1, D_IP43 };

static unsigned char F571_X0M[6], F571_X1M[6];
static char F571_PPP[16];
static int F571_SOCK = -1, F571_FDU = -1, F571_FDC = -1;
static int F571_U6 = -1, F571_TAP = -1, F571_NFL = -1;
static unsigned char F571_FR[256];
static int F571_FRLEN = -1;

/* ---------- environment ---------- */

static int f571_ppp_unit(void)
{
	int u = -1, idx = -1, up;
	char path[96];

	F571_SOCK = f563_pppoe_sock("x1", htons(F571_SID), F571_X0M);
	if (F571_SOCK < 0) {
		printf("F571 PPP|fail|sock|%d\n", F571_SOCK);
		return -1;
	}
	if (ioctl(F571_SOCK, PPPIOCGCHAN, &idx) < 0) {
		printf("F571 PPP|fail|gchan|%d\n", errno);
		return -1;
	}
	F571_FDU = open("/dev/ppp", O_RDWR);
	if (F571_FDU < 0) {
		printf("F571 PPP|fail|unit|%d\n", errno);
		return -1;
	}
	if (ioctl(F571_FDU, PPPIOCNEWUNIT, &u) < 0) {
		printf("F571 PPP|fail|newunit|%d\n", errno);
		return -1;
	}
	F571_FDC = open("/dev/ppp", O_RDWR);
	if (F571_FDC < 0) {
		printf("F571 PPP|fail|chan|%d\n", errno);
		return -1;
	}
	if (ioctl(F571_FDC, PPPIOCATTCHAN, &idx) < 0) {
		printf("F571 PPP|fail|attchan|%d\n", errno);
		return -1;
	}
	if (ioctl(F571_FDC, PPPIOCCONNECT, &u) < 0) {
		printf("F571 PPP|fail|connect|%d\n", errno);
		return -1;
	}
	snprintf(F571_PPP, sizeof(F571_PPP), "ppp%d", u);
	up = set_up(F571_PPP);
	/* ppp_receive_nonmp_frame() frees the frame when the device is down */
	printf("F571 PPP|unit=%d|chan=%d|dev=%s|ifindex=%d|up=%d\n", u, idx,
	       F571_PPP, f555_ifindex(F571_PPP), up);
	return 0;
}

static int f571_env(void)
{
	char path[96];

	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	if (link_add_veth("x0", "x1")) {
		printf("F571 FAIL|veth\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	if (mac_get("x0", F571_X0M) || mac_get("x1", F571_X1M)) {
		printf("F571 FAIL|mac\n");
		return -1;
	}
	if (f571_ppp_unit())
		return -2;

	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6",
		 F571_PPP);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/accept_dad",
		 F571_PPP);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/dad_transmits",
		 F571_PPP);
	f555_sysctl(path, "0");
	printf("F571 ADDR6|rc=%d\n", f564_addr6(F571_PPP, A6_L_DST, 128));
	F571_U6 = f564_udp_bind(AF_INET6, 0, A6_L_DST, F571_DPORT);

	F571_FRLEN = f570_frame_ppp(F571_FR, F571_X1M, F571_X0M, F571_SID,
				    A6_L_SRC, A6_L_DST, 0);
	{
		char hx[64], hy[64];

		printf("F571 ENV|u6=%d|flen=%d|ppp=%d|x0=%s|x1=%s\n", F571_U6,
		       F571_FRLEN, f555_ifindex(F571_PPP),
		       f559_hexs(hx, sizeof(hx), F571_X0M, 6),
		       f559_hexs(hy, sizeof(hy), F571_X1M, 6));
	}
	return 0;
}

static int f571_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND71; i++) {
		struct f571_door *D = &D571[i];

		rc |= add_table(D->fam, D->table);
		rc |= f556_add_chain(D->fam, D->table, "pre0", D->hook,
				     (uint32_t)D->prio0, 1, D->dev);
		rc |= f556_add_chain(D->fam, D->table, "ch", D->hook,
				     (uint32_t)D->prio1, 1, D->dev);
	}
	return rc;
}

static void f571_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND71; i++) {
		f557_flush(D571[i].fam, D571[i].table, "pre0", &acks);
		f557_flush(D571[i].fam, D571[i].table, "ch", &acks);
	}
}

/* ---------- the snapshot ---------- */

struct f571_rep {
	int u6n, u6len, u6sport;
	char u6pay[64];
	unsigned long long i6in, i6hdr, i6addr, i6unk, i6trunc, i6noroute,
			   i6deliv, u6in, u6err, u6noport, i6out, i6disc,
			   i6mcast, icmp6in;
	unsigned long long prx, pby;
	int tapn;
};

static void f571_u6_drain(struct f571_rep *R)
{
	unsigned char b[1024];
	struct sockaddr_in6 sa;
	socklen_t sl;
	int r, k;

	if (F571_U6 < 0)
		return;
	for (;;) {
		memset(&sa, 0, sizeof(sa));
		sl = sizeof(sa);
		r = (int)recvfrom(F571_U6, b, sizeof(b), MSG_DONTWAIT,
				  (struct sockaddr *)&sa, &sl);
		if (r < 0)
			break;
		if (!f568_needle(b, r))
			continue;
		R->u6n++;
		R->u6len = r;
		R->u6sport = ntohs(sa.sin6_port);
		k = r < (int)sizeof(R->u6pay) - 1 ? r
						 : (int)sizeof(R->u6pay) - 1;
		memcpy(R->u6pay, b, (size_t)k);
		R->u6pay[k] = 0;
	}
}

static void f571_snap(struct f571_rep *R)
{
	char p[96];

	f571_u6_drain(R);
	R->i6in = f564_snmp6("Ip6InReceives");
	R->i6hdr = f564_snmp6("Ip6InHdrErrors");
	R->i6addr = f564_snmp6("Ip6InAddrErrors");
	R->i6unk = f564_snmp6("Ip6InUnknownProtos");
	R->i6trunc = f564_snmp6("Ip6InTruncatedPkts");
	R->i6noroute = f564_snmp6("Ip6InNoRoutes");
	R->i6deliv = f564_snmp6("Ip6InDelivers");
	R->i6disc = f564_snmp6("Ip6InDiscards");
	R->i6mcast = f564_snmp6("Ip6InMcastPkts");
	R->u6in = f564_snmp6("Udp6InDatagrams");
	R->u6err = f564_snmp6("Udp6InErrors");
	R->u6noport = f564_snmp6("Udp6NoPorts");
	R->i6out = f564_snmp6("Ip6OutRequests");
	R->icmp6in = f564_snmp6("Icmp6InMsgs");
	f564_devrx(F571_PPP, &R->pby, &R->prx);	/* bytes, packets */
}

/* ---------- NFLOG: payload, L2 header, device ---------- */

#define F571_NPL	6
#define F571_PLLEN	96
struct f571_msg {
	int plen;
	unsigned char p[F571_PLLEN];
	int l2len;
	unsigned char l2[32];
	int hwlen2;
	unsigned char hw[32];
	int hwlen, hwtype, hwhdr, indev, outdev;
	char prefix[8];
};
struct f571_pl {
	int n;
	struct f571_msg m[F571_NPL];
};

#define NFULA_IFINDEX_INDEV_	4
#define NFULA_IFINDEX_OUTDEV_	5
#define NFULA_HWTYPE_		15	/* value: ARPHRD_*      */
#define NFULA_HWHEADER_		16	/* bytes of the L2 hdr  */
#define NFULA_HWLEN_		17	/* declared hard_header_len */
#define NFULA_L2HDR_571 	21

static void f571_nfl_drain(struct f571_pl *v)
{
	unsigned char b[16384];
	int guard = 0, rl;

	if (v)
		memset(v, 0, sizeof(*v));
	if (F571_NFL < 0)
		return;
	while (guard++ < 64) {
		struct nlmsghdr *h;
		int len;

		rl = (int)recv(F571_NFL, b, sizeof(b), MSG_DONTWAIT);
		if (rl <= 0)
			break;
		len = rl;
		for (h = (struct nlmsghdr *)b; NLMSG_OK(h, len);
		     h = NLMSG_NEXT(h, len)) {
			const char *p, *end, *prefix = NULL;
			const unsigned char *pl = NULL, *l2 = NULL;
			int pll = 0, l2l = 0, hwl = -1, hwt = -1, hwh = -1;
			int ind = -1, outd = -1, hwhl = 0;
			unsigned char hwb[32];

			if (h->nlmsg_type == NLMSG_DONE ||
			    h->nlmsg_type == NLMSG_ERROR)
				continue;
			p = (const char *)h + NLMSG_HDRLEN +
			    sizeof(struct nfgenmsg);
			end = (const char *)h + h->nlmsg_len;
			for (; p + (int)sizeof(struct nlattr) <= end; ) {
				const struct nlattr *a = (const struct nlattr *)p;
				int al = (int)a->nla_len;
				int t;

				if (al < (int)sizeof(*a) || p + al > end)
					break;
				t = a->nla_type & 0x3fff;
				if (t == NFULA_PREFIX_) {
					prefix = (const char *)a + NLA_HDRLEN;
				} else if (t == NFULA_PAYLOAD_) {
					pl = (const unsigned char *)a +
					     NLA_HDRLEN;
					pll = al - NLA_HDRLEN;
				} else if (t == NFULA_L2HDR_571) {
					l2 = (const unsigned char *)a +
					     NLA_HDRLEN;
					l2l = al - NLA_HDRLEN;
				} else if (t == NFULA_HWLEN_) {
					__be16 v;

					memcpy(&v, (const char *)a + NLA_HDRLEN,
					       2);
					hwl = ntohs(v);
				} else if (t == NFULA_HWHEADER_) {
					const unsigned char *hp =
						(const unsigned char *)a +
						NLA_HDRLEN;
					int kk = al - NLA_HDRLEN;

					hwh = kk;
					if (kk > (int)sizeof(hwb))
						kk = (int)sizeof(hwb);
					memcpy(hwb, hp, (size_t)kk);
					hwhl = kk;
				} else if (t == NFULA_HWTYPE_) {
					__be16 v;

					memcpy(&v, (const char *)a + NLA_HDRLEN,
					       2);
					hwt = ntohs(v);
				} else if (t == NFULA_IFINDEX_INDEV_) {
					__be32 v;

					memcpy(&v, (const char *)a + NLA_HDRLEN,
					       4);
					ind = (int)ntohl(v);
				} else if (t == NFULA_IFINDEX_OUTDEV_) {
					__be32 v;

					memcpy(&v, (const char *)a + NLA_HDRLEN,
					       4);
					outd = (int)ntohl(v);
				}
				p += NLA_ALIGN_(al);
			}
			if (!v || !prefix || prefix[0] == 0)
				continue;
			if (v->n < F571_NPL) {
				struct f571_msg *M = &v->m[v->n];
				int k;

				snprintf(M->prefix, sizeof(M->prefix), "%s",
					 prefix);
				if (pl) {
					k = pll < F571_PLLEN ? pll : F571_PLLEN;
					memcpy(M->p, pl, (size_t)k);
					M->plen = k;
				}
				if (l2) {
					k = l2l < (int)sizeof(M->l2) ? l2l
							    : (int)sizeof(M->l2);
					memcpy(M->l2, l2, (size_t)k);
					M->l2len = k;
				}
				M->hwlen = hwl;
				M->hwhdr = hwh;
				M->hwlen2 = hwhl;
				memcpy(M->hw, hwb, (size_t)hwhl);
				M->hwtype = hwt;
				M->indev = ind;
				M->outdev = outd;
			}
			v->n++;
		}
	}
}

/* ---------- the rule ---------- */

struct f571_cfg {
	const char *arm;
	int mode;			/* 0 none, 1 store, 2 store+read, 3 read */
	int meta;			/* -1 or NFT_META_* */
	unsigned char mv[2];
	int mlen;
	uint32_t base;
	int off, len;
	unsigned char imm[16];
	int csum, cso;
};

static void f571_zero(struct f571_cfg *C, const char *arm)
{
	memset(C, 0, sizeof(*C));
	C->arm = arm;
	C->meta = -1;
}

static int f571_rule(const struct f571_door *D, const char *chain,
		     const char *prefix, const struct f571_cfg *C, int *acks)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			D->fam);
	put_str(nlh, NFTA_RULE_TABLE, D->table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	if (C->meta >= 0) {
		f570_put_meta(nlh, C->meta);
		f562_cmp(nlh, F562_RD_DREG, C->mv, C->mlen);
	}
	if (C->mode == 1 || C->mode == 2)
		f565_store(nlh, C->base, (uint32_t)C->off, (uint32_t)C->len,
			   C->imm, C->csum, (unsigned int)C->cso);
	if (C->mode == 2 || C->mode == 3) {
		f562_read(nlh, C->base, (uint32_t)C->off, (uint32_t)C->len);
		f562_cmp(nlh, F562_RD_DREG, C->imm, C->len);
	}
	log_expr(nlh, 5, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

/* ---------- one arm ---------- */

static int f571_send(void)
{
	return pkt_send_p("x0", F571_FR, F571_FRLEN, 0x8864);
}

static void f571_arm(int door, const char *sec, const struct f571_cfg *C,
		     int send, int maxp)
{
	struct f571_door *D = &D571[door];
	struct f571_cfg N;
	struct f571_rep r0, r;
	struct f571_pl pl;
	unsigned long long c0p, c0s, c1p, c1s;
	int rcp = -1, rcs = -1, acks = 0, snd = 0, polls = 0, k;
	const struct f571_msg *mp = NULL, *ms = NULL;
	char hx[300], hy[300], hz[300], hw[80], hm[40], hq[80], hr2[80];

	memset(&r0, 0, sizeof(r0));
	memset(&r, 0, sizeof(r));
	f571_zero(&N, "pre");
	f571_flush_all();
	f571_nfl_drain(NULL);
	f571_snap(&r0);
	rcp = f571_rule(D, "pre0", "p", &N, &acks);
	rcs = f571_rule(D, "ch", "s", C, &acks);
	c0p = f555_count(D->fam, D->table, "pre0");
	c0s = f555_count(D->fam, D->table, "ch");
	/* the socket was drained by f571_snap(&r0) -- clear what arrived
	 * between the drain and the rule install */
	f571_u6_drain(&r0);
	if (send)
		snd = f571_send();
	if (send) {
		for (k = 0; k < maxp; k++) {
			usleep(120000);
			f571_snap(&r);
			polls++;
			if (r.u6n > r0.u6n || r.i6in > r0.i6in ||
			    r.i6hdr > r0.i6hdr || r.i6addr > r0.i6addr ||
			    r.i6trunc > r0.i6trunc || r.i6unk > r0.i6unk ||
			    r.i6noroute > r0.i6noroute || r.u6err > r0.u6err ||
			    r.prx > r0.prx || r.i6deliv > r0.i6deliv)
				break;
		}
	} else {
		usleep(400000);
		f571_snap(&r);
		polls = 1;
	}
	f571_snap(&r);
	c1p = f555_count(D->fam, D->table, "pre0");
	c1s = f555_count(D->fam, D->table, "ch");
	memset(&pl, 0, sizeof(pl));
	f571_nfl_drain(&pl);
	for (k = 0; k < pl.n; k++) {
		if (pl.m[k].prefix[0] == 'p' && !mp)
			mp = &pl.m[k];
		if (pl.m[k].prefix[0] == 's' && !ms)
			ms = &pl.m[k];
	}
	printf("F571 A|sec=%s|door=%s|arm=%s|mode=%d|meta=%d|base=%u|off=%d|"
	       "len=%d|imm=%s|mv=%s|mlen=%d|csum=%d|cso=%d|rcp=%d|rcs=%d|"
	       "sendrc=%d|snt=%d|"
	       "cntp=%llu|lives=%llu|"
	       "polls=%d|u6d=%d|u6len=%d|u6sport=%d|u6pay=%s|",
	       sec, D->tag, C->arm, C->mode, C->meta, C->base, C->off, C->len,
	       f559_hexs(hx, sizeof(hx), C->imm, C->len),
	       C->meta >= 0 ? f559_hexs(hm, sizeof(hm), C->mv, C->mlen) : "-",
	       C->meta >= 0 ? C->mlen : 0, C->csum, C->cso, rcp, rcs, snd, send,
	       c1p - c0p, c1s - c0s, polls, r.u6n - r0.u6n, r.u6len,
	       r.u6sport, r.u6pay[0] ? r.u6pay : "-");
	printf("i6in_d=%llu|i6hdr_d=%llu|i6addr_d=%llu|i6unk_d=%llu|"
	       "i6trunc_d=%llu|i6noroute_d=%llu|deliv_d=%llu|u6in_d=%llu|"
	       "u6err_d=%llu|u6noport_d=%llu|i6out_d=%llu|i6disc_d=%llu|"
	       "icmp6_d=%llu|prx_d=%llu|pby_d=%llu|",
	       r.i6in - r0.i6in, r.i6hdr - r0.i6hdr, r.i6addr - r0.i6addr,
	       r.i6unk - r0.i6unk, r.i6trunc - r0.i6trunc,
	       r.i6noroute - r0.i6noroute, r.i6deliv - r0.i6deliv,
	       r.u6in - r0.u6in, r.u6err - r0.u6err,
	       r.u6noport - r0.u6noport, r.i6out - r0.i6out,
	       r.i6disc - r0.i6disc, r.icmp6in - r0.icmp6in,
	       r.prx - r0.prx, r.pby - r0.pby);
	printf("prelen=%d|pre=%s|prel2=%d|preind=%d|prehw=%d|preht=%d|prehh=%d|"
	       "prehwhex=%s|",
	       mp ? mp->plen : -1,
	       mp ? f559_hexs(hy, sizeof(hy), mp->p, mp->plen) : "-",
	       mp ? mp->l2len : -1, mp ? mp->indev : -1, mp ? mp->hwlen : -1,
	       mp ? mp->hwtype : -1, mp ? mp->hwhdr : -1,
	       mp && mp->hwlen2 > 0 ? f559_hexs(hq, sizeof(hq), mp->hw,
						mp->hwlen2) : "-");
	printf("postlen=%d|post=%s|postl2=%d|postind=%d|posthw=%d|postht=%d|"
	       "posthh=%d|postl2hex=%s|posthwhex=%s\n",
	       ms ? ms->plen : -1,
	       ms ? f559_hexs(hz, sizeof(hz), ms->p, ms->plen) : "-",
	       ms ? ms->l2len : -1, ms ? ms->indev : -1, ms ? ms->hwlen : -1,
	       ms ? ms->hwtype : -1, ms ? ms->hwhdr : -1,
	       ms && ms->l2len > 0
		       ? f559_hexs(hw, sizeof(hw), ms->l2, ms->l2len) : "-",
	       ms && ms->hwlen2 > 0
		       ? f559_hexs(hr2, sizeof(hr2), ms->hw, ms->hwlen2) : "-");
}

/* ---------- read cells: the immediate is what the frame carries ---------- */

static void f571_rd(struct f571_cfg *C, const char *arm, uint32_t base, int off,
		    int len, const unsigned char *src)
{
	f571_zero(C, arm);
	C->mode = 3;
	C->base = base;
	C->off = off;
	C->len = len;
	memcpy(C->imm, src + off, (size_t)len);
}

static void f571_wr(struct f571_cfg *C, const char *arm, uint32_t base, int off,
		    int len, const unsigned char *imm, int csum, int cso)
{
	f571_zero(C, arm);
	C->mode = 1;
	C->base = base;
	C->off = off;
	C->len = len;
	memcpy(C->imm, imm, (size_t)len);
	C->csum = csum;
	C->cso = cso;
}

/* ---------- section `ctl` ---------- */

static void f571_sec_ctl(void)
{
	struct f571_cfg C;

	f571_zero(&C, "ctl_in3");
	f571_arm(D_IN3, "ctl", &C, 1, 14);
	f571_zero(&C, "ctl_ip63");
	f571_arm(D_IP63, "ctl", &C, 1, 14);
	f571_zero(&C, "ctl_nd1");
	f571_arm(D_ND1, "ctl", &C, 1, 14);
	f571_zero(&C, "ctl_ip43");
	f571_arm(D_IP43, "ctl", &C, 1, 6);
	f571_zero(&C, "quiet_in3");
	f571_arm(D_IN3, "ctl", &C, 0, 1);
	f571_zero(&C, "quiet_ip63");
	f571_arm(D_IP63, "ctl", &C, 0, 1);
}

/* ---------- section `rd`: where each base lands ---------- */

static void f571_sec_rd(void)
{
	struct f571_cfg C;
	const unsigned char *ip = F571_FR + 22;	/* IPv6 header = data on ppp0 */
	const unsigned char *fr = F571_FR;	/* frame start = data on x1   */
	const unsigned char *nd = F571_FR + 14;	/* PPPoE header = data on x1  */

	/* layer 3, door in3 */
	f571_rd(&C, "nh0", NFT_PAYLOAD_NETWORK_HEADER, 0, 4, ip);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_rd(&C, "nh4", NFT_PAYLOAD_NETWORK_HEADER, 4, 2, ip);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_rd(&C, "nh6", NFT_PAYLOAD_NETWORK_HEADER, 6, 1, ip);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_rd(&C, "nh7", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, ip);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	/* ... and the twin: the byte the netdev door sees at the same cell */
	f571_rd(&C, "nh7_ppp", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, nd);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_rd(&C, "nh8", NFT_PAYLOAD_NETWORK_HEADER, 8, 16, ip);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_rd(&C, "nh24", NFT_PAYLOAD_NETWORK_HEADER, 24, 16, ip);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	/* @ll on ppp0: mac_header == data */
	f571_rd(&C, "ll0", NFT_PAYLOAD_LL_HEADER, 0, 1, ip);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_rd(&C, "ll4", NFT_PAYLOAD_LL_HEADER, 4, 2, ip);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_rd(&C, "ll8", NFT_PAYLOAD_LL_HEADER, 8, 16, ip);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	/* @th on ppp0: data + thoff */
	f571_rd(&C, "th0", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, F571_FR + 62);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_rd(&C, "th2", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, F571_FR + 62);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_rd(&C, "th6", NFT_PAYLOAD_TRANSPORT_HEADER, 6, 2, F571_FR + 62);
	f571_arm(D_IN3, "rd", &C, 1, 10);
	/* meta */
	f571_zero(&C, "meta_proto");
	C.meta = NFT_META_PROTOCOL;
	C.mv[0] = 0x86;
	C.mv[1] = 0xdd;
	C.mlen = 2;
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_zero(&C, "meta_l4");
	C.meta = NFT_META_L4PROTO;
	C.mv[0] = 17;
	C.mlen = 1;
	f571_arm(D_IN3, "rd", &C, 1, 10);
	f571_zero(&C, "meta_pf");
	C.meta = NFT_META_NFPROTO;
	C.mv[0] = 10;			/* NFPROTO_IPV6 */
	C.mlen = 1;
	f571_arm(D_IN3, "rd", &C, 1, 10);

	/* layer 3, door ip63 -- the same cells in the other family */
	f571_rd(&C, "nh7", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, ip);
	f571_arm(D_IP63, "rd", &C, 1, 10);
	f571_rd(&C, "ll0", NFT_PAYLOAD_LL_HEADER, 0, 1, ip);
	f571_arm(D_IP63, "rd", &C, 1, 10);
	f571_rd(&C, "th0", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, F571_FR + 62);
	f571_arm(D_IP63, "rd", &C, 1, 10);
	f571_zero(&C, "meta_pf");
	C.meta = NFT_META_NFPROTO;
	C.mv[0] = 10;
	C.mlen = 1;
	f571_arm(D_IP63, "rd", &C, 1, 10);

	/* the netdev ingress door on x1: data = the PPPoE header */
	f571_rd(&C, "nh0", NFT_PAYLOAD_NETWORK_HEADER, 0, 4, nd);
	f571_arm(D_ND1, "rd", &C, 1, 10);
	f571_rd(&C, "nh4_len", NFT_PAYLOAD_NETWORK_HEADER, 4, 2, nd);
	f571_arm(D_ND1, "rd", &C, 1, 10);
	f571_rd(&C, "nh7_ppp", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, nd);
	f571_arm(D_ND1, "rd", &C, 1, 10);
	f571_rd(&C, "nh7_hop", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, ip);
	f571_arm(D_ND1, "rd", &C, 1, 10);
	f571_rd(&C, "ll0", NFT_PAYLOAD_LL_HEADER, 0, 6, fr);
	f571_arm(D_ND1, "rd", &C, 1, 10);
	f571_rd(&C, "ll13", NFT_PAYLOAD_LL_HEADER, 13, 1, fr);
	f571_arm(D_ND1, "rd", &C, 1, 10);
	f571_rd(&C, "th0_nm", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2,
		F571_FR + 62);
	f571_arm(D_ND1, "rd", &C, 1, 10);
	f571_zero(&C, "meta_proto");
	C.meta = NFT_META_PROTOCOL;
	C.mv[0] = 0x88;
	C.mv[1] = 0x64;
	C.mlen = 2;
	f571_arm(D_ND1, "rd", &C, 1, 10);
	f571_zero(&C, "meta_pf");
	C.meta = NFT_META_NFPROTO;
	C.mv[0] = 5;			/* NFPROTO_NETDEV */
	C.mlen = 1;
	f571_arm(D_ND1, "rd", &C, 1, 10);
	/* `meta protocol` at this door asks nf_flow_pppoe_proto(): the answer is
	 * the *inner* ethertype, and asking it also rebuilds pktinfo with
	 * nhoff = PPPOE_SES_HLEN (8) + skb_network_offset. */
	f571_zero(&C, "meta_proto86");
	C.meta = NFT_META_PROTOCOL;
	C.mv[0] = 0x86;
	C.mv[1] = 0xdd;
	C.mlen = 2;
	f571_arm(D_ND1, "rd", &C, 1, 10);
	f571_rd(&C, "th0_m", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2,
		F571_FR + 62);
	C.meta = NFT_META_PROTOCOL;
	C.mv[0] = 0x86;
	C.mv[1] = 0xdd;
	C.mlen = 2;
	f571_arm(D_ND1, "rd", &C, 1, 10);
}

/* ---------- section `wr`: what the guards let through ---------- */

static void f571_sec_wr(void)
{
	struct f571_cfg C;
	static const unsigned char hop90[1] = { 0x90 };
	static const unsigned char hop00[1] = { 0x00 };
	static const unsigned char big[2] = { 0x90, 0x91 };
	static const unsigned char v6f[4] = { 0x60, 0x00, 0x00, 0x08 };
	static const unsigned char v9f[4] = { 0x90, 0x00, 0x00, 0x08 };
	static const unsigned char nh3b[1] = { 0x3b };
	const unsigned char *nd = F571_FR + 14;	/* PPPoE header = data on x1 */
	static const unsigned char ff[2] = { 0xff, 0xff };

	/* --- the guard of nft_nh_write_ok_ip6(), one cell at a time --- */
	f571_wr(&C, "nh7_90", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, hop90, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	f571_wr(&C, "nh7_00", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, hop00, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	f571_wr(&C, "nh4_2", NFT_PAYLOAD_NETWORK_HEADER, 4, 2, big, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 10);
	f571_wr(&C, "nh6_1", NFT_PAYLOAD_NETWORK_HEADER, 6, 1, nh3b, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 10);
	f571_wr(&C, "nh0_ok", NFT_PAYLOAD_NETWORK_HEADER, 0, 4, v6f, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	f571_wr(&C, "nh0_bad", NFT_PAYLOAD_NETWORK_HEADER, 0, 4, v9f, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 10);
	f571_wr(&C, "nh2_2", NFT_PAYLOAD_NETWORK_HEADER, 2, 2, big, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	f571_wr(&C, "nh40_16", NFT_PAYLOAD_NETWORK_HEADER, 40, 16, A6_L_ALT,
		0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 10);
	/* saddr: same value (checksum stays valid) and another value */
	f571_wr(&C, "nh8_same", NFT_PAYLOAD_NETWORK_HEADER, 8, 16, A6_L_SRC,
		0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	f571_wr(&C, "nh8_alt", NFT_PAYLOAD_NETWORK_HEADER, 8, 16, A6_L_ALT,
		0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	f571_wr(&C, "nh8_cs", NFT_PAYLOAD_NETWORK_HEADER, 8, 16, A6_L_SRC, 1,
		10);
	f571_arm(D_IN3, "wr", &C, 1, 10);
	/* daddr */
	f571_wr(&C, "nh24_same", NFT_PAYLOAD_NETWORK_HEADER, 24, 16, A6_L_DST,
		0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	f571_wr(&C, "nh24_alt", NFT_PAYLOAD_NETWORK_HEADER, 24, 16, A6_L_ALT,
		0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	/* @ll on ppp0: every write is outside the link header */
	f571_wr(&C, "ll0_1", NFT_PAYLOAD_LL_HEADER, 0, 1, hop90, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 10);
	f571_wr(&C, "ll0_2", NFT_PAYLOAD_LL_HEADER, 0, 2, big, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 10);
	f571_wr(&C, "ll7_1", NFT_PAYLOAD_LL_HEADER, 7, 1, hop90, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 10);
	/* @th on ppp0: the real transport header */
	f571_wr(&C, "th0_2", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, big, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	f571_wr(&C, "th0_2_cs", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, big, 1, 6);
	f571_arm(D_IN3, "wr", &C, 1, 14);
	f571_wr(&C, "th6_2", NFT_PAYLOAD_TRANSPORT_HEADER, 6, 2, big, 0, 0);
	f571_arm(D_IN3, "wr", &C, 1, 14);

	/* --- the same two cells at the ip6 family door --- */
	f571_wr(&C, "nh7_90", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, hop90, 0, 0);
	f571_arm(D_IP63, "wr", &C, 1, 14);
	f571_wr(&C, "nh4_2", NFT_PAYLOAD_NETWORK_HEADER, 4, 2, big, 0, 0);
	f571_arm(D_IP63, "wr", &C, 1, 10);
	f571_wr(&C, "ll0_1", NFT_PAYLOAD_LL_HEADER, 0, 1, hop90, 0, 0);
	f571_arm(D_IP63, "wr", &C, 1, 10);
	f571_wr(&C, "th0_2", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, big, 0, 0);
	f571_arm(D_IP63, "wr", &C, 1, 14);

	/* --- the same frame at the netdev ingress door: guard = constant --- */
	f571_wr(&C, "nh7_90", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, hop90, 0, 0);
	f571_arm(D_ND1, "wr", &C, 1, 14);
	/* the same cell, the value the frame already carries: the write happens
	 * and the packet is delivered -- the death is the value, not the act */
	f571_wr(&C, "nh7_same", NFT_PAYLOAD_NETWORK_HEADER, 7, 1, nd + 7, 0, 0);
	f571_arm(D_ND1, "wr", &C, 1, 14);
	f571_wr(&C, "nh4_2_len", NFT_PAYLOAD_NETWORK_HEADER, 4, 2, big, 0, 0);
	f571_arm(D_ND1, "wr", &C, 1, 14);
	f571_wr(&C, "nh4_2_same", NFT_PAYLOAD_NETWORK_HEADER, 4, 2, nd + 4, 0,
		0);
	f571_arm(D_ND1, "wr", &C, 1, 14);
	f571_arm(D_ND1, "wr", &C, 1, 14);
	f571_wr(&C, "nh2_2_sid", NFT_PAYLOAD_NETWORK_HEADER, 2, 2, big, 0, 0);
	f571_arm(D_ND1, "wr", &C, 1, 14);
	f571_wr(&C, "nh6_1_proto", NFT_PAYLOAD_NETWORK_HEADER, 6, 1, nh3b, 0,
		0);
	f571_arm(D_ND1, "wr", &C, 1, 14);
	f571_wr(&C, "ll6_2", NFT_PAYLOAD_LL_HEADER, 6, 2, ff, 0, 0);
	f571_arm(D_ND1, "wr", &C, 1, 14);
	/* @th at ingress needs meta protocol; without it the base is refused */
	f571_wr(&C, "th0_2_nm", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, big, 0, 0);
	f571_arm(D_ND1, "wr", &C, 1, 10);
	f571_wr(&C, "th0_2_m", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, big, 0, 0);
	C.meta = NFT_META_PROTOCOL;
	C.mv[0] = 0x86;
	C.mv[1] = 0xdd;
	C.mlen = 2;
	f571_arm(D_ND1, "wr", &C, 1, 14);
	f571_wr(&C, "th0_2_m_cs", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, big, 1, 6);
	C.meta = NFT_META_PROTOCOL;
	C.mv[0] = 0x86;
	C.mv[1] = 0xdd;
	C.mlen = 2;
	f571_arm(D_ND1, "wr", &C, 1, 14);
}

/* ---------- section `tapf`: the filter that ate three shapes ---------- */

struct f571_tap {
	int total, old, new;
	unsigned char first[256];
	int firstlen;
};

/* the filter of F48 (f569_tap6): byte 20 of the frame must be 17 */
static int f571_tap_old(const unsigned char *b, int n)
{
	if (n < 14 + 40 + 8)
		return 0;
	if (b[12] != 0x86 || b[13] != 0xdd)
		return 0;
	if (b[20] != 17)
		return 0;
	return f568_needle(b, n);
}

/* the same question asked by walking the next-header chain: the frame is
 * ethernet (14) + IPv6 (40) + extension headers + UDP.  `hdr` is the frame
 * offset of the extension header that `nh` announces. */
static int f571_tap_new(const unsigned char *b, int n)
{
	int hdr = 14 + 40, nh, guard = 0;

	if (n < 14 + 40 + 8)
		return 0;
	if (b[12] != 0x86 || b[13] != 0xdd)
		return 0;
	nh = b[14 + 6];
	while (guard++ < 8) {
		if (nh == 17)
			return f568_needle(b, n);
		if (hdr + 2 > n)
			return 0;
		if (nh == 0 || nh == 60 || nh == 43) {
			nh = b[hdr];
			hdr += (b[hdr + 1] + 1) * 8;
			continue;
		}
		if (nh == 51) {
			nh = b[hdr];
			hdr += (b[hdr + 1] + 2) * 4;
			continue;
		}
		return 0;
	}
	return 0;
}

static int f571_tap_open(const char *dev)
{
	struct sockaddr_ll sll;
	int s, idx = f555_ifindex(dev);

	if (idx < 0)
		return -1;
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
		return -2;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = idx;
	if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		close(s);
		return -3;
	}
	return s;
}

static void f571_tap_drain(struct f571_tap *T)
{
	unsigned char b[2048];
	int r;

	memset(T, 0, sizeof(*T));
	T->firstlen = -1;
	if (F571_TAP < 0)
		return;
	while ((r = (int)recv(F571_TAP, b, sizeof(b), MSG_DONTWAIT)) > 0) {
		T->total++;
		if (f571_tap_old(b, r))
			T->old++;
		if (f571_tap_new(b, r)) {
			T->new++;
			if (T->firstlen < 0) {
				T->firstlen = r < (int)sizeof(T->first) ? r
									: (int)sizeof(T->first);
				memcpy(T->first, b, (size_t)T->firstlen);
			}
		}
	}
}

static void f571_sec_tapf(void)
{
	static const char *NM[2] = { "bare", "hbh" };
	unsigned char fr[256];
	int shape, n;

	F571_TAP = f571_tap_open("x1");
	printf("F571 TAP|fd=%d\n", F571_TAP);
	for (shape = 0; shape < 2; shape++) {
		struct f571_tap T;
		char hx[600];

		f571_flush_all();
		f571_tap_drain(&T);
		n = f570_frame_plain(fr, F571_X1M, F571_X0M, A6_L_SRC, A6_L_DST,
				     shape);
		pkt_send_p("x0", fr, n, 0x86dd);
		usleep(300000);
		f571_tap_drain(&T);
		printf("F571 T|shape=%s|len=%d|total=%d|old=%d|new=%d|"
		       "firstlen=%d|first=%s|frame=%s\n",
		       NM[shape], n, T.total, T.old, T.new, T.firstlen,
		       T.firstlen > 0 ? f559_hexs(hx, sizeof(hx), T.first,
						  T.firstlen) : "-",
		       f559_hexs(hx, sizeof(hx), fr, n));
	}
}

/* ---------- mode entry ---------- */

int f571_main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "pp6l3";

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F571 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F571 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F571 KERNEL|7.3.4-T563\n");
	if (f571_env())
		return 0;
	printf("F571 DOORS|rc=%d\n", f571_chains());
	F571_NFL = nfl_open(5);
	printf("F571 NFL|%d\n", F571_NFL);
	{
		char hx[400];

		printf("F571 FRAME|len=%d|%s\n", F571_FRLEN,
		       f559_hexs(hx, sizeof(hx), F571_FR, F571_FRLEN));
	}
	if (!strcmp(mode, "ctl"))
		f571_sec_ctl();
	else if (!strcmp(mode, "rd"))
		f571_sec_rd();
	else if (!strcmp(mode, "wr"))
		f571_sec_wr();
	else if (!strcmp(mode, "tapf"))
		f571_sec_tapf();
	else {
		f571_sec_ctl();
		f571_sec_rd();
		f571_sec_wr();
		f571_sec_tapf();
	}
	printf("F571 END|mode=%s\n", mode);
	return 0;
}

int main(int argc, char **argv)
{
	return f571_main(argc, argv);
}
