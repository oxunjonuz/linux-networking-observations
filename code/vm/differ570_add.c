/* differ570_add.c -- turn 570 (F48).
 *
 *  DEBT 1 (mode `ppp6e`): IPv6 inside PPPoE at an EGRESS door.  The frame is
 *  built by the kernel itself -- a PF_PPPOX/PX_PROTO_OE session socket bound to
 *  x0 with sid 99 -- so the egress door of x0 sees a real PPPoE frame whose
 *  skb_network_offset is 14 and whose IPv6 header sits at frame offset 22.
 *  A plain IPv6 datagram out the same device is the control on the same door;
 *  the ingress door of x0 with the same bytes is the second control.
 *
 *  DEBT 2 (mode `th6`): @th in the v6 mode.  Six door/class pairs and five frame
 *  shapes (bare, hop-by-hop, hop-by-hop + dest-opts, AH, routing header), all on
 *  the F46/F47 harness (f569_setup_v6, the child netns, the door table D568).
 *
 *  Every helper below the new code is the one that produced F31..F47.
 */

#include <linux/if_pppox.h>

#define F570_PAY	18
#define F570_META	0x51
#define F570_SID	99

/* ---------- the IPv6 datagram, with optional extension headers ---------- */

/* shape: 0 bare, 1 hop-by-hop, 2 hop-by-hop+dest, 3 AH, 4 routing header */
static int f570_extlen(int shape)
{
	switch (shape) {
	case 1: return 8;
	case 2: return 16;
	case 3: return 24;
	case 4: return 8;
	}
	return 0;
}

static void f570_udp6_csum(unsigned char *ip6, int extlen, int udplen)
{
	unsigned char *udp = ip6 + 40 + extlen;
	unsigned int acc;
	unsigned short c;

	acc = f564_sum(ip6 + 8, 32, 0);		/* saddr + daddr */
	acc += (unsigned int)udplen;
	acc += 17;				/* next header: UDP */
	udp[6] = 0;
	udp[7] = 0;
	acc = f564_sum(udp, udplen, acc);
	c = f564_fold(acc);
	if (!c)
		c = 0xffff;
	udp[6] = (unsigned char)(c >> 8);
	udp[7] = (unsigned char)c;
}

/* the IPv6 datagram alone: 40 + ext + 8 + F570_PAY bytes */
static int f570_ip6(unsigned char *ip, const unsigned char *s16,
		    const unsigned char *d16, int shape, int sport, int dport)
{
	int ext = f570_extlen(shape);
	int udplen = 8 + F570_PAY;
	int tot = ext + udplen;
	unsigned char *p, *udp;
	int i;

	memset(ip, 0, (size_t)(40 + tot));
	ip[0] = 0x60;
	ip[4] = (unsigned char)(tot >> 8);
	ip[5] = (unsigned char)(tot & 0xff);
	ip[7] = 64;
	memcpy(ip + 8, s16, 16);
	memcpy(ip + 24, d16, 16);

	switch (shape) {
	case 0:
		ip[6] = 17;
		break;
	case 1:
		ip[6] = 0;
		p = ip + 40;
		p[0] = 17;
		p[1] = 0;
		break;
	case 2:
		ip[6] = 0;
		p = ip + 40;
		p[0] = 60;
		p[1] = 0;
		p = ip + 48;
		p[0] = 17;
		p[1] = 0;
		break;
	case 3:
		ip[6] = 51;
		p = ip + 40;
		p[0] = 17;
		p[1] = 4;			/* (4 + 2) * 4 = 24 bytes */
		p[4] = 0x11;
		p[5] = 0x22;
		p[6] = 0x33;
		p[7] = 0x44;
		p[11] = 1;
		for (i = 0; i < 12; i++)
			p[12 + i] = 0x5a;
		break;
	case 4:
		ip[6] = 43;
		p = ip + 40;
		p[0] = 17;
		p[1] = 0;
		p[2] = 0;
		p[3] = 0;			/* segments left */
		break;
	}

	udp = ip + 40 + ext;
	udp[0] = (unsigned char)(sport >> 8);
	udp[1] = (unsigned char)(sport & 0xff);
	udp[2] = (unsigned char)(dport >> 8);
	udp[3] = (unsigned char)(dport & 0xff);
	udp[4] = (unsigned char)(udplen >> 8);
	udp[5] = (unsigned char)(udplen & 0xff);
	memcpy(udp + 8, F568_PAY, F570_PAY);
	f570_udp6_csum(ip, ext, udplen);
	return 40 + tot;
}

/* ethernet + PPPoE session + PPP protocol + IPv6 */
static int f570_frame_ppp(unsigned char *out, const unsigned char *dmac,
			  const unsigned char *smac, unsigned short sid,
			  const unsigned char *s16, const unsigned char *d16,
			  int shape)
{
	int n;

	memset(out, 0, 14 + 8 + 40 + 64);
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x88;
	out[13] = 0x64;
	out[14] = 0x11;
	out[15] = 0x00;
	out[16] = (unsigned char)(sid >> 8);
	out[17] = (unsigned char)(sid & 0xff);
	out[20] = 0x00;
	out[21] = 0x57;			/* PPP_IPV6 */
	n = f570_ip6(out + 22, s16, d16, shape, 40000, 5000);
	out[18] = (unsigned char)((2 + n) >> 8);
	out[19] = (unsigned char)((2 + n) & 0xff);
	return 22 + n;
}

/* ethernet + IPv6 (the plain control frame) */
static int f570_frame_plain(unsigned char *out, const unsigned char *dmac,
			    const unsigned char *smac, const unsigned char *s16,
			    const unsigned char *d16, int shape)
{
	memset(out, 0, 14 + 40 + 64);
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	return 14 + f570_ip6(out + 14, s16, d16, shape, 40000, 5000);
}

/* the payload handed to send() on the PPPoX session socket */
static int f570_ppp_payload(unsigned char *out, const unsigned char *s16,
			    const unsigned char *d16, int shape)
{
	int n;

	out[0] = 0x00;
	out[1] = 0x57;
	n = f570_ip6(out + 2, s16, d16, shape, 40000, 5000);
	return 2 + n;
}

/* ---------- addresses of mode `ppp6e` ---------- */

static const unsigned char A6_P_SRC[16] = { 0xfd, 0x01, 0x02, 0x03, 0x04, 0x05,
					    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
					    0x0c, 0x0d, 0x0e, 0x0f };
static const unsigned char A6_P_DST[16] = { 0xfd, 0x11, 0x12, 0x13, 0x14, 0x15,
					    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
					    0x1c, 0x1d, 0x1e, 0x1f };
/* crafted: byte 36 (saddr[6]) reads 0x60, daddr[0..1] give a payload length */
static const unsigned char A6_P_FS[16] = { 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
					   0x60, 0x00, 0x00, 0x08, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00 };
static const unsigned char A6_P_FD[16] = { 0x00, 0x08, 0x11, 0x12, 0x13, 0x14,
					   0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
					   0x1b, 0x1c, 0x1d, 0x1e };

struct f570_door {
	const char *tag;
	const char *table;
	const char *dev;
	uint32_t hook;
	int prio0, prio1;
};

static struct f570_door DB[] = {
	{ "egr", "e70a", "x0", 1, 10, 20 },
	{ "ing", "e70b", "x0", 0, 10, 20 },
};
#define NDB	(int)(sizeof(DB) / sizeof(DB[0]))

struct f570_cfg {
	const char *arm;
	int send_kind;			/* 0 plain egress, 1 pppoe egress, 2 injected */
	int shape;			/* 0 normal, 1 crafted */
	int meta_proto;
	unsigned char pv[2];
	int meta_l4;
	int l4;
	int nh_rd;
	int nh_off, nh_len;
	unsigned char nhi[4];
	int wr, rd;
	uint32_t base;
	int off, len;
	unsigned char imm[16];
	int csum, cso;
};

/* ---------- rule builder for mode `ppp6e` ---------- */

static void f570_put_meta(struct nlmsghdr *nlh, int key)
{
	struct nlattr *e, *d;

	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "meta");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_META_KEY, key);
	put_be32(nlh, NFTA_META_DREG, F562_RD_DREG);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

static int f570_rule_b(const struct f570_door *D, const char *chain,
		       const char *prefix, const struct f570_cfg *C, int *acks)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			NFPROTO_NETDEV);
	put_str(nlh, NFTA_RULE_TABLE, D->table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	if (C->meta_proto) {
		f570_put_meta(nlh, NFT_META_PROTOCOL);
		f562_cmp(nlh, F562_RD_DREG, C->pv, 2);
	}
	if (C->meta_l4) {
		unsigned char v = (unsigned char)C->l4;

		f570_put_meta(nlh, NFT_META_L4PROTO);
		f562_cmp(nlh, F562_RD_DREG, &v, 1);
	}
	if (C->nh_rd) {
		f562_read(nlh, NFT_PAYLOAD_NETWORK_HEADER, (uint32_t)C->nh_off,
			  (uint32_t)C->nh_len);
		f562_cmp(nlh, F562_RD_DREG, C->nhi, C->nh_len);
	}
	if (C->wr)
		f565_store(nlh, C->base, (uint32_t)C->off, (uint32_t)C->len,
			   C->imm, C->csum, (unsigned int)C->cso);
	if (C->rd) {
		f562_read(nlh, C->base, (uint32_t)C->off, (uint32_t)C->len);
		f562_cmp(nlh, F562_RD_DREG, C->imm, C->len);
	}
	log_expr(nlh, 5, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

/* ---------- capture ---------- */

static int f570_needle(const unsigned char *b, int n)
{
	return f568_needle(b, n);
}

static int f570_tap(int fd, unsigned char *out, int max, int *count)
{
	unsigned char b[2048];
	int r, n = -1, seen = 0;

	if (count)
		*count = 0;
	if (fd < 0)
		return -1;
	while ((r = (int)recv(fd, b, sizeof(b), MSG_DONTWAIT)) > 0) {
		if (!f570_needle(b, r))
			continue;
		seen++;
		if (n < 0) {
			n = r < max ? r : max;
			memcpy(out, b, (size_t)n);
		}
	}
	if (count)
		*count = seen;
	return n;
}

/* ---------- mode `ppp6e`: the environment ---------- */

static unsigned char F570_PLAIN_PAY[F569_PAY] = { 0x77, 0x77, 0x77, 0x77,
	0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
	0x77, 0x77, 0x77 };
static unsigned char F570_PAYLOAD[256];
static int F570_PAYLOAD_LEN = -1;
static unsigned char F570_INJ[256];
static int F570_INJ_LEN = -1;
static int F570_PPPFD = -1;
static int F570_LOC6 = -1;
static unsigned char F570_X0MAC[6];

static int f570_env_b(void)
{
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	if (link_add_veth("x0", "x1"))
		return -1;
	set_up("x0");
	set_up("x1");
	if (mac_get("x1", X1_MAC))
		return -2;
	if (mac_get("x0", F570_X0MAC))
		return -3;
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/disable_ipv6", "0");
	usleep(300000);
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/accept_ra", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/rtr_solicitations", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	f564_addr6("x0", A6_X0, 64);
	f569_neigh6_add("x0", A6_X1, X1_MAC);
	F570_LOC6 = f564_udp_bind(AF_INET6, 0, A6_X0, 40000);
	F570_PPPFD = f563_pppoe_sock("x0", htons(F570_SID), X1_MAC);
	printf("F570 ENV|loc6=%d|pppoe=%d|errno=%d\n", F570_LOC6, F570_PPPFD,
	       errno);
	return 0;
}

static int f570_send(const struct f570_cfg *C)
{
	if (C->send_kind == 0) {
		struct sockaddr_in6 sa;

		memset(&sa, 0, sizeof(sa));
		sa.sin6_family = AF_INET6;
		memcpy(&sa.sin6_addr, A6_X1, 16);
		sa.sin6_port = htons(5000);
		return (int)sendto(F570_LOC6, F570_PLAIN_PAY, F569_PAY, 0,
				   (struct sockaddr *)&sa, sizeof(sa));
	}
	if (C->send_kind == 1) {
		F570_PAYLOAD_LEN = f570_ppp_payload(F570_PAYLOAD,
						    C->shape ? A6_P_FS : A6_P_SRC,
						    C->shape ? A6_P_FD : A6_P_DST,
						    0);
		return (int)send(F570_PPPFD, F570_PAYLOAD, F570_PAYLOAD_LEN, 0);
	}
	F570_INJ_LEN = f570_frame_ppp(F570_INJ, F570_X0MAC, X1_MAC, F570_SID,
				      C->shape ? A6_P_FS : A6_P_SRC,
				      C->shape ? A6_P_FD : A6_P_DST, 0);
	return pkt_send_p("x1", F570_INJ, F570_INJ_LEN, 0x8864);
}

static void f570_arm_b(const struct f570_door *D, const struct f570_cfg *C,
		       int rfd, int tapfd)
{
	struct f570_cfg P;
	struct f568_log pre, post;
	unsigned long long c0p, c0s, c1p, c1s;
	unsigned char tap[1024];
	char hp[1200], hs[1200], ht[1800], hi[40];
	int taplen, tapn = 0, rcp = -1, rcs = -1, acks = 0, snd = -99, try;

	memset(&P, 0, sizeof(P));
	memset(&pre, 0, sizeof(pre));
	memset(&post, 0, sizeof(post));
	memset(tap, 0, sizeof(tap));
	for (try = 0; try < 4; try++) {
		int np, ns;

		acks = 0;
		f557_flush(NFPROTO_NETDEV, D->table, "pre0", &acks);
		acks = 0;
		f557_flush(NFPROTO_NETDEV, D->table, "ch", &acks);
		np = f568_rule_count(NFPROTO_NETDEV, D->table, "pre0");
		ns = f568_rule_count(NFPROTO_NETDEV, D->table, "ch");
		if (!np && !ns)
			break;
		printf("F570 RETRY|arm=%s|try=%d|np=%d|ns=%d\n", C->arm, try,
		       np, ns);
	}
	acks = 0;
	rcp = f570_rule_b(D, "pre0", "p", &P, &acks);
	acks = 0;
	rcs = f570_rule_b(D, "ch", "s", C, &acks);
	c0p = f555_count(NFPROTO_NETDEV, D->table, "pre0");
	c0s = f555_count(NFPROTO_NETDEV, D->table, "ch");
	nfl_drain(rfd);
	cap_drain(tapfd);
	snd = f570_send(C);
	usleep(250000);
	c1p = f555_count(NFPROTO_NETDEV, D->table, "pre0");
	c1s = f555_count(NFPROTO_NETDEV, D->table, "ch");
	f568_logs(rfd, &pre, &post);
	taplen = f570_tap(tapfd, tap, (int)sizeof(tap), &tapn);
	hp[0] = 0;
	hs[0] = 0;
	ht[0] = 0;
	if (pre.seen)
		f559_hexs(hp, sizeof(hp), pre.p, pre.plen);
	if (post.seen)
		f559_hexs(hs, sizeof(hs), post.p, post.plen);
	if (taplen > 0)
		f559_hexs(ht, sizeof(ht), tap, taplen);
	printf("F570 A|sec=ppp6e|door=%s|arm=%s|sk=%d|shape=%d|mp=%d|ml=%d|nh=%d|"
	       "wr=%d|rd=%d|base=%u|off=%d|len=%d|imm=%s|rcp=%d|rcs=%d|sendrc=%d|"
	       "cntp=%llu|cnts=%llu|pn=%d|plen=%d|p=%s|sn=%d|slen=%d|s=%s|"
	       "tn=%d|tlen=%d|tap=%s\n",
	       D->tag, C->arm, C->send_kind, C->shape, C->meta_proto, C->meta_l4,
	       C->nh_rd, C->wr, C->rd, C->base, C->off, C->len,
	       C->wr || C->rd ? f559_hexs(hi, sizeof(hi), C->imm,
					  C->len > 0 ? C->len : 1) : "-",
	       rcp, rcs, snd, c1p - c0p, c1s - c0s, pre.seen, pre.plen, hp,
	       post.seen, post.plen, hs, tapn, taplen, ht);
}

static void f570_sec_ppp6e(void)
{
	static const struct f570_cfg A[] = {
		{ "ctl_plain", 0, 0, 0, { 0 }, 0, 0, 0, 0, 0, { 0 }, 0, 0, 0, 0, 0,
		  { 0 }, 0, 0 },
		{ "ctl_ppp", 1, 0, 0, { 0 }, 0, 0, 0, 0, 0, { 0 }, 0, 0, 0, 0, 0,
		  { 0 }, 0, 0 },
		{ "proto_plain", 0, 0, 1, { 0x86, 0xdd }, 0, 0, 0, 0, 0, { 0 }, 0,
		  0, 0, 0, 0, { 0 }, 0, 0 },
		{ "proto_ppp", 1, 0, 1, { 0x86, 0xdd }, 0, 0, 0, 0, 0, { 0 }, 0, 0,
		  0, 0, 0, { 0 }, 0, 0 },
		{ "l4_plain", 0, 0, 0, { 0 }, 1, 17, 0, 0, 0, { 0 }, 0, 0, 0, 0,
		  0, { 0 }, 0, 0 },
		{ "l4_ppp", 1, 0, 0, { 0 }, 1, 17, 0, 0, 0, { 0 }, 0, 0, 0, 0, 0,
		  { 0 }, 0, 0 },
	};
	static const unsigned char NH_PLAIN[4] = { 0x60, 0x00, 0x00, 0x00 };
	static const unsigned char NH_PPP[4] = { 0x11, 0x00, 0x00, 0x63 };
	static const unsigned char NH_OFF36[4] = { 0x06, 0x07, 0x08, 0x09 };
	static const unsigned char NH_FAKE[4] = { 0x60, 0x00, 0x00, 0x08 };
	static const unsigned char IMM_HOP[1] = { 0x90 };
	static const unsigned char IMM_SP[2] = { 0x90, 0x91 };
	static const unsigned char IMM_SP_OR[2] = { 0x9c, 0x40 };
	struct f570_cfg C;
	int i, rfd, tapfd;

	if (f570_env_b()) {
		printf("F570 FAIL|env ppp6e\n");
		return;
	}
	for (i = 0; i < NDB; i++)
		if (add_table(NFPROTO_NETDEV, DB[i].table) ||
		    f556_add_chain(NFPROTO_NETDEV, DB[i].table, "pre0", DB[i].hook,
				   (uint32_t)DB[i].prio0, 1, DB[i].dev) ||
		    f556_add_chain(NFPROTO_NETDEV, DB[i].table, "ch", DB[i].hook,
				   (uint32_t)DB[i].prio1, 1, DB[i].dev)) {
			printf("F570 FAIL|chains %s\n", DB[i].tag);
			return;
		}
	rfd = nfl_open(5);
	tapfd = cap_open("x0");
	printf("F570 NFL|%d|tap=%d\n", rfd, tapfd);
	{
		unsigned char fr[256];
		char hx[1200];
		int n = f570_frame_ppp(fr, F570_X0MAC, X1_MAC, F570_SID, A6_P_SRC,
				       A6_P_DST, 0);

		printf("F570 FRAME|ppp|len=%d|hex=%s\n", n,
		       f559_hexs(hx, sizeof(hx), fr, n));
		n = f570_frame_ppp(fr, F570_X0MAC, X1_MAC, F570_SID, A6_P_FS,
				   A6_P_FD, 0);
		printf("F570 FRAME|fake|len=%d|hex=%s\n", n,
		       f559_hexs(hx, sizeof(hx), fr, n));
	}

	for (i = 0; i < (int)(sizeof(A) / sizeof(A[0])); i++)
		f570_arm_b(&DB[0], &A[i], rfd, tapfd);

	/* @nh read without any meta: the base is skb_network_offset alone */
	memset(&C, 0, sizeof(C));
	C.arm = "nh0_ppp";
	C.send_kind = 1;
	C.nh_rd = 1;
	C.nh_off = 0;
	C.nh_len = 4;
	memcpy(C.nhi, NH_PPP, 4);
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	/* @nh read through `meta protocol`: the coordinate the write never sees */
	memset(&C, 0, sizeof(C));
	C.arm = "nh_m_ppp";
	C.send_kind = 1;
	C.meta_proto = 1;
	C.pv[0] = 0x86;
	C.pv[1] = 0xdd;
	C.nh_rd = 1;
	C.nh_off = 0;
	C.nh_len = 4;
	memcpy(C.nhi, NH_OFF36, 4);
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	/* the writes: @nh and @th, on the plain datagram and on the PPPoE frame */
	memset(&C, 0, sizeof(C));
	C.arm = "nhw_plain";
	C.send_kind = 0;
	C.wr = 1;
	C.base = NFT_PAYLOAD_NETWORK_HEADER;
	C.off = 7;
	C.len = 1;
	memcpy(C.imm, IMM_HOP, 1);
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	C.arm = "nhw_ppp";
	C.send_kind = 1;
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	memset(&C, 0, sizeof(C));
	C.arm = "thw_plain";
	C.send_kind = 0;
	C.wr = 1;
	C.base = NFT_PAYLOAD_TRANSPORT_HEADER;
	C.off = 0;
	C.len = 2;
	memcpy(C.imm, IMM_SP, 2);
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	C.arm = "thw_ppp";
	C.send_kind = 1;
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	/* the read side of @th: the coordinate the walk builds from nhoff */
	memset(&C, 0, sizeof(C));
	C.arm = "thr_plain";
	C.send_kind = 0;
	C.rd = 1;
	C.base = NFT_PAYLOAD_TRANSPORT_HEADER;
	C.off = 0;
	C.len = 2;
	memcpy(C.imm, IMM_SP_OR, 2);
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	/* the same write on the *normal* frame: refused because validation
	 * never gets past the version byte at 36 */
	memset(&C, 0, sizeof(C));
	C.arm = "thw_ppp_m";
	C.send_kind = 1;
	C.meta_proto = 1;
	C.pv[0] = 0x86;
	C.pv[1] = 0xdd;
	C.wr = 1;
	C.base = NFT_PAYLOAD_TRANSPORT_HEADER;
	C.off = 0;
	C.len = 2;
	memcpy(C.imm, IMM_SP, 2);
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	/* the crafted frame: the version check at 36 passes, the walk still
	 * starts at 22, and the two bases disagree inside one expression */
	memset(&C, 0, sizeof(C));
	C.arm = "fak_l4";
	C.send_kind = 1;
	C.shape = 1;
	C.meta_proto = 1;
	C.pv[0] = 0x86;
	C.pv[1] = 0xdd;
	C.meta_l4 = 1;
	C.l4 = 17;
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	C.arm = "fak_nh";
	C.meta_l4 = 0;
	C.nh_rd = 1;
	C.nh_off = 0;
	C.nh_len = 4;
	memcpy(C.nhi, NH_FAKE, 4);
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	C.arm = "fak_thw";
	C.nh_rd = 0;
	C.wr = 1;
	C.base = NFT_PAYLOAD_TRANSPORT_HEADER;
	C.off = 0;
	C.len = 2;
	memcpy(C.imm, IMM_SP, 2);
	f570_arm_b(&DB[0], &C, rfd, tapfd);

	/* the same cells at the ingress door: same bytes, the other hook */
	memset(&C, 0, sizeof(C));
	C.arm = "in_ctl";
	C.send_kind = 2;
	f570_arm_b(&DB[1], &C, rfd, tapfd);

	C.arm = "in_nhw";
	C.wr = 1;
	C.base = NFT_PAYLOAD_NETWORK_HEADER;
	C.off = 7;
	C.len = 1;
	memcpy(C.imm, IMM_HOP, 1);
	f570_arm_b(&DB[1], &C, rfd, tapfd);

	memset(&C, 0, sizeof(C));
	C.arm = "in_rdnh";
	C.send_kind = 2;
	C.meta_proto = 1;
	C.pv[0] = 0x86;
	C.pv[1] = 0xdd;
	C.nh_rd = 1;
	C.nh_off = 0;
	C.nh_len = 4;
	memcpy(C.nhi, NH_PLAIN, 4);
	f570_arm_b(&DB[1], &C, rfd, tapfd);

	C.arm = "in_thw";
	C.meta_proto = 0;
	C.nh_rd = 0;
	C.wr = 1;
	C.base = NFT_PAYLOAD_TRANSPORT_HEADER;
	C.off = 0;
	C.len = 2;
	memcpy(C.imm, IMM_SP, 2);
	f570_arm_b(&DB[1], &C, rfd, tapfd);

	C.arm = "in_thw_m";
	C.meta_proto = 1;
	C.pv[0] = 0x86;
	C.pv[1] = 0xdd;
	C.wr = 1;
	f570_arm_b(&DB[1], &C, rfd, tapfd);

	C.arm = "in_rdth_m";
	C.wr = 0;
	C.rd = 1;
	memcpy(C.imm, IMM_SP_OR, 2);
	f570_arm_b(&DB[1], &C, rfd, tapfd);

	C.arm = "in_rdth";
	C.meta_proto = 0;
	C.wr = 0;
	C.rd = 1;
	memcpy(C.imm, IMM_SP_OR, 2);
	f570_arm_b(&DB[1], &C, rfd, tapfd);

	/* repeat of the first arm: determinism */
	{
		char hx[1200];

		printf("F570 PAYLOAD|len=%d|hex=%s\n", F570_PAYLOAD_LEN,
		       f559_hexs(hx, sizeof(hx), F570_PAYLOAD,
				 F570_PAYLOAD_LEN > 0 ? F570_PAYLOAD_LEN : 0));
		printf("F570 INJ|len=%d|hex=%s\n", F570_INJ_LEN,
		       f559_hexs(hx, sizeof(hx), F570_INJ,
				 F570_INJ_LEN > 0 ? F570_INJ_LEN : 0));
	}
	f570_arm_b(&DB[0], &A[1], rfd, tapfd);
	close(tapfd);
}

/* ---------- part 2: mode `th6` — @th at the v6 doors ---------- */

static int F570_SHAPE = 0;
static unsigned char F570_FWD[200];
static int F570_FWD_LEN = -1;
static unsigned char F570_O0MAC[6];
static const char *F570_SN[5] = { "bare", "hbh", "hbd", "ah", "rh" };

static void f570_emit6(int cls)
{
	if (cls == C_LOC) {
		struct sockaddr_in6 sa;

		memset(&sa, 0, sizeof(sa));
		sa.sin6_family = AF_INET6;
		memcpy(&sa.sin6_addr, A6_X1, 16);
		sa.sin6_port = htons(5000);
		sendto(LOC6_SOCK, F568_PAY, F569_PAY, 0,
		       (struct sockaddr *)&sa, sizeof(sa));
	} else {
		F570_FWD_LEN = f570_frame_plain(F570_FWD, F570_O0MAC,
						(const unsigned char *)"\x02\x00\x00\x00\x00\x71",
						A6_FS, A6_X1, F570_SHAPE);
		pkt_send_p("o1", F570_FWD, F570_FWD_LEN, 0x86dd);
	}
}

static int f570_rule6(const struct f568_door *D, const char *chain,
		      const char *prefix, uint32_t base, int off, int len,
		      const unsigned char *imm, int mode, int csum, int cso,
		      int l4cmp, int *acks)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	unsigned char v;

	if (l4cmp < 0)
		return f568_rule(D, chain, prefix, base, off, len, imm, mode, csum,
				 cso, acks);
	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			D->fam);
	put_str(nlh, NFTA_RULE_TABLE, D->table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	f570_put_meta(nlh, NFT_META_L4PROTO);
	v = (unsigned char)l4cmp;
	f562_cmp(nlh, F562_RD_DREG, &v, 1);
	if (mode == 1 || mode == 2)
		f565_store(nlh, base, (uint32_t)off, (uint32_t)len, imm, csum,
			   (unsigned int)cso);
	if (mode == 2 || mode == 3) {
		f562_read(nlh, base, (uint32_t)off, (uint32_t)len);
		f562_cmp(nlh, F562_RD_DREG, imm, len);
	}
	log_expr(nlh, 5, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

static void f570_arm6(const char *sec, const struct f568_pair *P,
		      const char *arm, uint32_t base, int off, int len,
		      const unsigned char *imm, int mode, int csum, int cso,
		      int l4cmp, int rfd)
{
	struct f568_door *D = &D568[P->door];
	const char *cn = CLSN[P->cls];
	unsigned long long c0p, c0s, c1p, c1s;
	struct f569_rep6 r, r0;
	struct f569_pl pl;
	int rcp = -1, rcs = -1, acks = 0, snd = 0, rc0 = -9, rc1 = -9, npolls = 0;
	unsigned long long p0in, p0hdr, p0out, p0disc, q0rx, q0tx, p0addr, p0idisc;
	char hx[600], hx2[600], hi[40];
	int i;

	memset(&r, 0, sizeof(r));
	memset(&r0, 0, sizeof(r0));
	p0addr = f564_snmp6("Ip6InAddrErrors");
	p0idisc = f564_snmp6("Ip6InDiscards");
	q0rx = f567_read_ll("/sys/class/net/o0/statistics/rx_packets");
	q0tx = f567_read_ll("/sys/class/net/x0/statistics/tx_packets");
	p0in = f564_snmp6("Ip6InReceives");
	p0hdr = f564_snmp6("Ip6InHdrErrors");
	p0out = f564_snmp6("Ip6OutRequests");
	p0disc = f564_snmp6("Ip6OutDiscards");
	if (P->cls == C_FWD) {
		F570_FWD_LEN = f570_frame_plain(F570_FWD, F570_O0MAC,
						(const unsigned char *)"\x02\x00\x00\x00\x00\x71",
						A6_FS, A6_X1, F570_SHAPE);
		printf("F570 FRAME6|shape=%s|len=%d|hex=%s\n", F570_SN[F570_SHAPE],
		       F570_FWD_LEN, f559_hexs(hx, sizeof(hx), F570_FWD,
					       F570_FWD_LEN));
	}
	f568_flush_all();
	f569_drain(rfd, &pl);
	acks = 0;
	rcp = f568_rule(D, "pre0", "p", 0, 0, 0, NULL, 0, 0, 0, &acks);
	acks = 0;
	rcs = f570_rule6(D, "ch", "s", base, off, len, imm, mode, csum, cso,
			 l4cmp, &acks);
	c0p = f555_count(D->fam, D->table, "pre0");
	c0s = f555_count(D->fam, D->table, "ch");
	rc0 = f569_snapshot6(&r0);
	f570_emit6(P->cls);
	snd = P->cls == C_LOC ? F569_PAY : F570_FWD_LEN;
	{
		int k, polls = 0;
		unsigned long long o0rx0 = f567_read_ll("/sys/class/net/o0/statistics/rx_packets");

		rc1 = -1;
		for (k = 0; k < 20; k++) {
			unsigned long long o0rx;

			usleep(250000);
			rc1 = f569_snapshot6(&r);
			polls++;
			if (rc1)
				break;
			o0rx = f567_read_ll("/sys/class/net/o0/statistics/rx_packets");
			if (r.u6tot > r0.u6tot || r.alltot > r0.alltot ||
			    r.i6in > r0.i6in || r.i6hdr > r0.i6hdr ||
			    r.i6addr > r0.i6addr || r.i6trunc > r0.i6trunc ||
			    r.i6unk > r0.i6unk || r.i6noroute > r0.i6noroute ||
			    o0rx > o0rx0)
				break;
		}
		npolls = polls;
	}
	f569_drain(rfd, &pl);
	c1p = f555_count(D->fam, D->table, "pre0");
	c1s = f555_count(D->fam, D->table, "ch");

	printf("F570 T|sec=%s|door=%s|cls=%s|shape=%s|arm=%s|l4cmp=%d|base=%u|mode=%d|"
	       "off=%d|len=%d|imm=%s|rcp=%d|rcs=%d|sendrc=%d|cntp=%llu|lives=%llu|"
	       "nmsg=%d|rc0=%d|rc1=%d|polls=%d|tapd=%d|u6d=%d|all_d=%d|"
	       "deliv_d=%llu|u6in_d=%llu|u6err_d=%llu|",
	       sec, D->tag, cn, F570_SN[F570_SHAPE], arm, l4cmp, base, mode, off, len,
	       f559_hexs(hi, sizeof(hi), imm, len > 0 ? len : 1), rcp, rcs, snd,
	       c1p - c0p, c1s - c0s, pl.n, rc0, rc1, npolls, r.taptot - r0.taptot,
	       r.u6tot - r0.u6tot, r.alltot - r0.alltot, r.i6deliv - r0.i6deliv,
	       r.u6in - r0.u6in, r.u6err - r0.u6err);
	for (i = 0; i < pl.n && i < F569_NMSG; i++)
		printf("m%d=%s|", i,
		       f559_hexs(hx2, sizeof(hx2), pl.p[i], pl.plen[i]));
	printf("paddr_d=%llu|pidisc_d=%llu|", f564_snmp6("Ip6InAddrErrors") - p0addr,
	       f564_snmp6("Ip6InDiscards") - p0idisc);
	printf("o0rx_d=%llu|x0tx_d=%llu|pin_d=%llu|phdr_d=%llu|pout_d=%llu|pdisc_d=%llu|",
	       f567_read_ll("/sys/class/net/o0/statistics/rx_packets") - q0rx,
	       f567_read_ll("/sys/class/net/x0/statistics/tx_packets") - q0tx,
	       f564_snmp6("Ip6InReceives") - p0in,
	       f564_snmp6("Ip6InHdrErrors") - p0hdr,
	       f564_snmp6("Ip6OutRequests") - p0out,
	       f564_snmp6("Ip6OutDiscards") - p0disc);
	printf("tapn=%d|taplen=%d|tap=%s|u6n=%d|u6len=%d|u6sport=%d|u6pay=%s|",
	       r.tapn, r.taplen, r.taphex, r.u6n, r.u6len0, r.u6sport0, r.u6pay);
	printf("i6in=%llu|i6hdr=%llu|i6addr=%llu|i6unk=%llu|i6trunc=%llu|"
	       "i6noroute=%llu|i6deliv=%llu|u6in=%llu|u6err=%llu|u6noport=%llu|"
	       "i6out=%llu|i6outnoroute=%llu|icmp6in=%llu\n",
	       r.i6in, r.i6hdr, r.i6addr, r.i6unk, r.i6trunc, r.i6noroute,
	       r.i6deliv, r.u6in, r.u6err, r.u6noport, r.i6out,
	       r.i6outnoroute, r.icmp6in);
}

static void f570_sec_th6(int rfd)
{
	static const struct f568_pair P[] = {
		{ 0, C_LOC }, { 1, C_LOC }, { 5, C_LOC },
		{ 3, C_FWD }, { 2, C_FWD }, { 5, C_FWD },
	};
	const int NP = (int)(sizeof(P) / sizeof(P[0]));
	unsigned char imm[2] = { 0x90, 0x91 };
	int i, j;

	for (i = 0; i < 3; i++) {
		F570_SHAPE = i;
		for (j = 0; j < NP; j++)
			f570_arm6("th6", &P[j], "thw", NFT_PAYLOAD_TRANSPORT_HEADER,
				  0, 2, imm, 1, 0, 0, -1, rfd);
	}
	/* AH and routing header: the walk's two named exceptions */
	for (i = 3; i < 5; i++) {
		F570_SHAPE = i;
		for (j = 3; j < 5; j++)
			f570_arm6("th6", &P[j], "thw", NFT_PAYLOAD_TRANSPORT_HEADER,
				  0, 2, imm, 1, 0, 0, -1, rfd);
	}
	/* the read side on the bare shape */
	F570_SHAPE = 0;
	for (j = 0; j < NP; j++) {
		unsigned char im2[2] = { 0x9c, 0x40 };

		f570_arm6("th6", &P[j], "thr", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2,
			  im2, 3, 0, 0, -1, rfd);
	}
	/* `meta l4proto` where the walk has an exception */
	for (i = 1; i < 5; i++) {
		F570_SHAPE = i;
		f570_arm6("th6", &P[3], "l4_17", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2,
			  imm, 1, 0, 0, 17, rfd);
		f570_arm6("th6", &P[3], "l4_51", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2,
			  imm, 1, 0, 0, 51, rfd);
	}
	/* the toll: the forwarded class with a recomputed transport checksum */
	F570_SHAPE = 0;
	{
		unsigned char im3[2] = { 0x90, 0x91 };

		f570_arm6("th6", &P[3], "cs", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2,
			  im3, 1, 1, 6, -1, rfd);
		f570_arm6("th6", &P[4], "cs", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2,
			  im3, 1, 1, 6, -1, rfd);
		f570_arm6("th6", &P[5], "cs", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2,
			  im3, 1, 1, 6, -1, rfd);
		/* the walk and the toll together: the receiver reports the source
		 * port the rule wrote, which names the base the walk produced */
		for (i = 1; i < 5; i++) {
			F570_SHAPE = i;
			f570_arm6("th6", &P[3], "cs", NFT_PAYLOAD_TRANSPORT_HEADER,
				  0, 2, im3, 1, 1, 6, -1, rfd);
		}
	}
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "ppp6e";
	char line[1024];

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F570 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F570 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F570 KERNEL|7.3.4-T563\n");

	if (!strcmp(mode, "ppp6e")) {
		f570_sec_ppp6e();
		printf("F570 DONE\n");
		return 0;
	}
	if (strcmp(mode, "th6")) {
		printf("F570 FAIL|mode|%s\n", mode);
		return 0;
	}

	/* mode th6: the F47 environment, verbatim */
	f569_setup_v6();
	printf("F570 FORK|rc=%d\n", f569_start_child());
	if (f568_read_line(line, (int)sizeof(line), 20000) < 0 || line[0] != 'U')
		printf("F570 FAIL|child unshare|%s\n", line);
	printf("F570 MOVE|rc=%d\n", f568_move_link("x1", (int)CHILD));
	f568_ask("C");
	for (;;) {
		int n;

		if (f568_read_line(line, (int)sizeof(line), 20000) < 0) {
			printf("F570 FAIL|child cfg\n");
			break;
		}
		printf("F570 CHILDR|%s\n", line);
		n = (int)strlen(line);
		if (!strncmp(line, "READY", 5) || (n && line[0] == 'E'))
			break;
	}
	{
		int rfdt;
		char hx[600];

		if (mac_get("o0", F570_O0MAC))
			printf("F570 FAIL|mac o0\n");
		F570_FWD_LEN = f570_frame_plain(F570_FWD, F570_O0MAC,
						(const unsigned char *)"\x02\x00\x00\x00\x00\x71",
						A6_FS, A6_X1, 0);
		printf("F570 FRAME6|shape=bare|len=%d|hex=%s\n", F570_FWD_LEN,
		       f559_hexs(hx, sizeof(hx), F570_FWD, F570_FWD_LEN));
		LOC6_SOCK = f564_udp_bind(AF_INET6, 0, A6_X0, 40000);
		printf("F570 SOCK|loc6=%d\n", LOC6_SOCK);
		printf("F570 NEIGH6|rc=%d\n", f569_neigh6_add("x0", A6_X1, X1_MAC));
		rfdt = nfl_open(5);
		printf("F570 NFL|%d\n", rfdt);
		if (f568_chains()) {
			printf("F570 FAIL|chains\n");
			return 0;
		}
		{
			struct f569_rep6 r;
			int k, got = 0;

			memset(&r, 0, sizeof(r));
			f568_flush_all();
			for (k = 0; k < 6; k++) {
				struct sockaddr_in6 sa;

				memset(&sa, 0, sizeof(sa));
				sa.sin6_family = AF_INET6;
				memcpy(&sa.sin6_addr, A6_X1, 16);
				sa.sin6_port = htons(5000);
				sendto(LOC6_SOCK, F568_PAY, F569_PAY, 0,
				       (struct sockaddr *)&sa, sizeof(sa));
				usleep(150000);
				if (f569_snapshot6(&r) == 0 && r.u6n > 0) {
					got = 1;
					break;
				}
			}
			printf("F570 WARM|got=%d|tapn=%d|u6n=%d|i6deliv=%llu\n", got,
			       r.tapn, r.u6n, r.i6deliv);
		}
		f570_sec_th6(rfdt);
	}
	f568_ask("Q");
	printf("F570 DONE\n");
	return 0;
}
