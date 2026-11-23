/* differ580_add.c -- turn 580 (F58): THE THREE WRITE GUARDS.
 *
 *  F57 ended with three named debts: the @th store bound (nft_th_write_ok),
 *  the @nh store bound (nft_nh_write_ok) and nft_payload_set_vlan()'s bounds
 *  where the tag is a word.  Reading the source before writing the instrument
 *  put the three in one sentence:
 *
 *    nft_ll_write_ok()   arithmetic: len+off+(mac_header-data) <= network_offset,
 *                        and `true` on the netdev ingress path;
 *    nft_nh_write_ok_*() a closed whitelist of (offset,len) keyed by the CHAIN's
 *                        family (pkt->state->pf), never by the packet;
 *    nft_th_write_ok()   TCP only: off > 12 || off+len <= 12;
 *    nft_payload_set_vlan()  a switch on (offset,len) gated by off+len > 12,
 *                        choosing between "word", "frame byte at off-4" and
 *                        "refuse".
 *
 *  None of the four asks how long the packet is.  The only bound that does is
 *  skb_ensure_writable()/skb_store_bits(), i.e. skb->len -- which is why
 *  "accepted by the guard" and "written into the frame" are two events that
 *  the counter cannot tell apart and the log can.
 *
 *  Mode `bounds`, 52 arms, two doors:
 *    n1  netdev ingress on x1   (the tag is a word here -- F55/F57)
 *    g6  ip6 prerouting         (layer-3 door)
 *
 *  Every arm is ONE rule on ONE door:
 *      counter, [payload store], log(group 80, prefix "58:<i>"), accept
 *  so the counter says the rule saw the frame, and the log message carries
 *  NFULA_HWHEADER (from mac_header) and NFULA_PAYLOAD (from skb->data) AFTER
 *  the store -- the write footprint is the byte diff against the same frame's
 *  census arm.
 *
 *  Frames (fd02::11 -> fd02::91, sport 43580, dport 5000):
 *    1  IPv6/UDP plain            80 bytes
 *    5  802.1Q vid 100 + IPv6/UDP 84 bytes
 *    6  IPv6/TCP SYN              74 bytes
 */

#define F580_SPORT	43580
#define F580_DPORT	5000
#define F580_PAY	18
#define F580_B_LL	0
#define F580_B_NH	1
#define F580_B_TH	2
#define F580_GROUP	80
#define F580_TN		"f80n"
#define F580_TG		"f80g"

static const unsigned char A80_S[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x11 };
static const unsigned char A80_D[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x91 };
static const unsigned char F580_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const unsigned char F580_SM[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x80 };

static int F580_U6 = -1;
static char F580_HX[512];

/* ---------- snmp6: the set of counters this turn needs ----------------- */

struct f580_sn {
	unsigned long long rcv, deliv, hdrerr, addrerr, disc, ukproto, trunc,
			   noroutes, udp, udperr, udpnop;
};

static void f580_snmp(struct f580_sn *s)
{
	static char buf[8192];
	int fd = open("/proc/net/snmp6", O_RDONLY);
	int n;

	memset(s, 0, sizeof(*s));
	if (fd < 0)
		return;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = 0;
	s->rcv = f579_snmp_one(buf, "Ip6InReceives");
	s->deliv = f579_snmp_one(buf, "Ip6InDelivers");
	s->hdrerr = f579_snmp_one(buf, "Ip6InHdrErrors");
	s->addrerr = f579_snmp_one(buf, "Ip6InAddrErrors");
	s->disc = f579_snmp_one(buf, "Ip6InDiscards");
	s->ukproto = f579_snmp_one(buf, "Ip6InUnknownProtos");
	s->trunc = f579_snmp_one(buf, "Ip6InTruncatedPkts");
	s->noroutes = f579_snmp_one(buf, "Ip6InNoRoutes");
	s->udp = f579_snmp_one(buf, "Udp6InDatagrams");
	s->udperr = f579_snmp_one(buf, "Udp6InErrors");
	s->udpnop = f579_snmp_one(buf, "Udp6NoPorts");
}

/* ---------- frames ------------------------------------------------------ */

static unsigned short f580_csum6(const unsigned char *ip6, int l4off, int l4len,
				 unsigned char proto)
{
	unsigned int sum = 0;
	int i;

	for (i = 0; i < 16; i += 2)
		sum += (unsigned int)((ip6[8 + i] << 8) | ip6[9 + i]);
	for (i = 0; i < 16; i += 2)
		sum += (unsigned int)((ip6[24 + i] << 8) | ip6[25 + i]);
	sum += (unsigned int)l4len;
	sum += (unsigned int)proto;
	for (i = 0; i < l4len; i += 2) {
		unsigned int hi = ip6[l4off + i];

		sum += (hi << 8) | (i + 1 < l4len ? ip6[l4off + i + 1] : 0);
	}
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = ~sum & 0xffff;
	return (unsigned short)(sum ? sum : 0xffff);
}

static int f580_mk_udp(unsigned char *out, int tagged)
{
	int off = tagged ? 18 : 14, i, tot = 8 + F580_PAY;
	unsigned char *ip, *udp;
	unsigned short c;

	memset(out, 0, 192);
	memcpy(out, F580_BC, 6);
	memcpy(out + 6, F580_SM, 6);
	if (tagged) {
		out[12] = 0x81;
		out[13] = 0x00;
		out[14] = 0x00;			/* prio 0, dei 0 */
		out[15] = 0x64;			/* vid 100 */
		out[16] = 0x86;
		out[17] = 0xdd;
	} else {
		out[12] = 0x86;
		out[13] = 0xdd;
	}
	ip = out + off;
	udp = ip + 40;
	ip[0] = 0x60;
	ip[4] = (unsigned char)(tot >> 8);
	ip[5] = (unsigned char)(tot & 0xff);
	ip[6] = 17;
	ip[7] = 64;
	memcpy(ip + 8, A80_S, 16);
	memcpy(ip + 24, A80_D, 16);
	udp[0] = (unsigned char)(F580_SPORT >> 8);
	udp[1] = (unsigned char)(F580_SPORT & 0xff);
	udp[2] = (unsigned char)(F580_DPORT >> 8);
	udp[3] = (unsigned char)(F580_DPORT & 0xff);
	udp[4] = (unsigned char)(tot >> 8);
	udp[5] = (unsigned char)(tot & 0xff);
	for (i = 0; i < F580_PAY; i++)
		udp[8 + i] = 0x77;
	udp[6] = 0;
	udp[7] = 0;
	c = f580_csum6(ip, 40, tot, 17);
	udp[6] = (unsigned char)(c >> 8);
	udp[7] = (unsigned char)(c & 0xff);
	return off + 40 + tot;
}

static int f580_mk_tcp(unsigned char *out)
{
	int off = 14, tot = 20;
	unsigned char *ip, *tcp;
	unsigned short c;

	memset(out, 0, 192);
	memcpy(out, F580_BC, 6);
	memcpy(out + 6, F580_SM, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	ip = out + off;
	tcp = ip + 40;
	ip[0] = 0x60;
	ip[4] = 0;
	ip[5] = (unsigned char)tot;
	ip[6] = 6;
	ip[7] = 64;
	memcpy(ip + 8, A80_S, 16);
	memcpy(ip + 24, A80_D, 16);
	tcp[0] = (unsigned char)(F580_SPORT >> 8);
	tcp[1] = (unsigned char)(F580_SPORT & 0xff);
	tcp[2] = (unsigned char)(F580_DPORT >> 8);
	tcp[3] = (unsigned char)(F580_DPORT & 0xff);
	tcp[6] = 0x00;
	tcp[7] = 0x01;				/* seq 1 */
	tcp[12] = 0x50;				/* doff 5 */
	tcp[13] = 0x02;				/* SYN */
	tcp[14] = 0x20;				/* window 8192 */
	tcp[15] = 0x00;
	c = f580_csum6(ip, 40, tot, 6);
	tcp[16] = (unsigned char)(c >> 8);
	tcp[17] = (unsigned char)(c & 0xff);
	return off + 40 + tot;
}

static int f580_frame(unsigned char *out, int id)
{
	switch (id) {
	case 1:
		return f580_mk_udp(out, 0);
	case 5:
		return f580_mk_udp(out, 1);
	case 6:
		return f580_mk_tcp(out);
	}
	return -1;
}

/* ---------- one raw send ------------------------------------------------ */

static int f580_send(const unsigned char *f, int flen)
{
	struct sockaddr_ll sa;
	int s, rc, ifi = f555_ifindex("x0");

	if (ifi < 0)
		return -10;
	s = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
	if (s < 0)
		return -errno;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = ifi;
	sa.sll_halen = 6;
	memcpy(sa.sll_addr, F580_BC, 6);
	rc = (int)sendto(s, f, (size_t)flen, 0, (struct sockaddr *)&sa,
			 sizeof(sa));
	close(s);
	return rc == flen ? flen : -errno;
}

/* ---------- the arms ---------------------------------------------------- */

struct f580_arm {
	const char *name;
	int fid;		/* 1 plain udp, 5 tagged udp, 6 tcp */
	int door;		/* 0 = g6 ip6 prerouting, 1 = n1 netdev ingress */
	int base;		/* 0 @ll, 1 @nh, 2 @th */
	int store;		/* 0 = census only */
	unsigned int off, len;
	const char *hex;	/* immediate; NULL = pattern 0xa0+i */
};

static const struct f580_arm A580[] = {
	/* --- census: the same frame at each door, no store --- */
	{ "c_p_g6",	1, 0, 0, 0, 0, 0, NULL },
	{ "c_p_n1",	1, 1, 0, 0, 0, 0, NULL },
	{ "c_t_g6",	5, 0, 0, 0, 0, 0, NULL },
	{ "c_t_n1",	5, 1, 0, 0, 0, 0, NULL },
	{ "c_tcp_g6",	6, 0, 0, 0, 0, 0, NULL },
	/* --- S1: @ll where the tag is a word (ingress, tagged frame) --- */
	{ "t_10_2",	5, 1, F580_B_LL, 1, 10, 2, "a0a1" },
	{ "t_10_4",	5, 1, F580_B_LL, 1, 10, 4, "a0a1a2a3" },
	{ "t_11_2",	5, 1, F580_B_LL, 1, 11, 2, "a0a1" },
	{ "t_12_1",	5, 1, F580_B_LL, 1, 12, 1, "a0" },
	{ "t_12_2",	5, 1, F580_B_LL, 1, 12, 2, "8100" },
	{ "t_12_4",	5, 1, F580_B_LL, 1, 12, 4, "81000fff" },
	{ "t_12_4v",	5, 1, F580_B_LL, 1, 12, 4, "81000400" },
	{ "t_13_2",	5, 1, F580_B_LL, 1, 13, 2, "a0a1" },
	{ "t_14_2",	5, 1, F580_B_LL, 1, 14, 2, "0400" },
	{ "t_14_4",	5, 1, F580_B_LL, 1, 14, 4, "a0a1a2a3" },
	{ "t_15_2",	5, 1, F580_B_LL, 1, 15, 2, "a0a1" },
	{ "t_16_2",	5, 1, F580_B_LL, 1, 16, 2, "0806" },
	{ "t_18_2",	5, 1, F580_B_LL, 1, 18, 2, "a0a1" },
	{ "t_20_2",	5, 1, F580_B_LL, 1, 20, 2, "a0a1" },
	{ "t_24_4",	5, 1, F580_B_LL, 1, 24, 4, "dea0a1a2" },
	/* --- S2: @ll at the layer-3 door (no tag at all) --- */
	{ "g_12_2",	1, 0, F580_B_LL, 1, 12, 2, "a0a1" },
	{ "g_13_2",	1, 0, F580_B_LL, 1, 13, 2, "a0a1" },
	{ "g_14_2",	1, 0, F580_B_LL, 1, 14, 2, "a0a1" },
	{ "g_16_2",	1, 0, F580_B_LL, 1, 16, 2, "a0a1" },
	{ "g_20_2",	1, 0, F580_B_LL, 1, 20, 2, "dea1" },
	{ "g_24_2",	1, 0, F580_B_LL, 1, 24, 2, "a0a1" },
	{ "g_30_2",	1, 0, F580_B_LL, 1, 30, 2, "a0a1" },
	{ "g_40_2",	1, 0, F580_B_LL, 1, 40, 2, "a0a1" },
	{ "g_50_2",	1, 0, F580_B_LL, 1, 50, 2, "a0a1" },
	/* --- S3: @nh, the closed whitelist of the ip6 family --- */
	{ "n_0_4v6",	1, 0, F580_B_NH, 1, 0, 4, "60a1a2a3" },
	{ "n_0_4v4",	1, 0, F580_B_NH, 1, 0, 4, "40a1a2a3" },
	{ "n_0_2",	1, 0, F580_B_NH, 1, 0, 2, "60a1" },
	{ "n_2_2",	1, 0, F580_B_NH, 1, 2, 2, "0066" },
	{ "n_4_2",	1, 0, F580_B_NH, 1, 4, 2, "a0a1" },
	{ "n_6_1",	1, 0, F580_B_NH, 1, 6, 1, "99" },
	{ "n_7_1",	1, 0, F580_B_NH, 1, 7, 1, "3f" },
	{ "n_7_2",	1, 0, F580_B_NH, 1, 7, 2, "3f40" },
	{ "n_8_32i",	1, 0, F580_B_NH, 1, 8, 32, NULL },
	{ "n_8_32r",	1, 0, F580_B_NH, 3, 8, 32, NULL },
	{ "n_8_16",	1, 0, F580_B_NH, 1, 8, 16, NULL },
	{ "n_9_16",	1, 0, F580_B_NH, 1, 9, 16, NULL },
	{ "n_24_16",	1, 0, F580_B_NH, 1, 24, 16, NULL },
	{ "n_24_15",	1, 0, F580_B_NH, 1, 24, 15, NULL },
	{ "n_36_4",	1, 0, F580_B_NH, 1, 36, 4, NULL },
	{ "n_40_4",	1, 0, F580_B_NH, 1, 40, 4, NULL },
	/* --- S4: @th, UDP against TCP --- */
	{ "u_0_2",	1, 0, F580_B_TH, 1, 0, 2, "a0a1" },
	{ "u_8_4",	1, 0, F580_B_TH, 1, 8, 4, "a0a1a2a3" },
	{ "u_0_16",	1, 0, F580_B_TH, 1, 0, 16, NULL },
	{ "u_60_4",	1, 0, F580_B_TH, 1, 60, 4, "a0a1a2a3" },
	{ "h_0_2",	6, 0, F580_B_TH, 1, 0, 2, "a0a1" },
	{ "h_8_4",	6, 0, F580_B_TH, 1, 8, 4, "a0a1a2a3" },
	{ "h_10_4",	6, 0, F580_B_TH, 1, 10, 4, "a0a1a2a3" },
	{ "h_12_1",	6, 0, F580_B_TH, 1, 12, 1, "a0" },
	{ "h_13_1",	6, 0, F580_B_TH, 1, 13, 1, "a0" },
	{ "h_0_16",	6, 0, F580_B_TH, 1, 0, 16, NULL },
};
#define NA580 ((int)(sizeof(A580) / sizeof(A580[0])))

static int f580_imm(const struct f580_arm *A, unsigned char *imm)
{
	int n = (int)A->len, i;

	if (n <= 0 || n > 64)
		return -1;
	if (A->hex) {
		if ((int)strlen(A->hex) != 2 * n)
			return -1;
		for (i = 0; i < n; i++) {
			unsigned int v = 0;
			char two[3];

			two[0] = A->hex[2 * i];
			two[1] = A->hex[2 * i + 1];
			two[2] = 0;
			if (sscanf(two, "%x", &v) != 1)
				return -1;
			imm[i] = (unsigned char)v;
		}
		return n;
	}
	for (i = 0; i < n; i++)
		imm[i] = (unsigned char)(0xa0 + i);
	return n;
}

/* A payload read into a chosen register and a payload store from a chosen
 * register: needed because a 32-byte value cannot travel in an immediate
 * (struct nft_data is 16 bytes -- measured, -EOVERFLOW), while a 32-byte
 * register store is legal (8*4 + 32 = 64 = the register file). */
static void f580_read_into(struct nlmsghdr *nlh, uint32_t dreg, uint32_t base,
			   uint32_t off, uint32_t len)
{
	struct nlattr *e, *d;

	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "payload");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_PAYLOAD_DREG, dreg);
	put_be32(nlh, NFTA_PAYLOAD_BASE, base);
	put_be32(nlh, NFTA_PAYLOAD_OFFSET, off);
	put_be32(nlh, NFTA_PAYLOAD_LEN, len);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

static void f580_store_from(struct nlmsghdr *nlh, uint32_t sreg, uint32_t base,
			    uint32_t off, uint32_t len)
{
	struct nlattr *e, *d;

	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "payload");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_PAYLOAD_SREG, sreg);
	put_be32(nlh, NFTA_PAYLOAD_BASE, base);
	put_be32(nlh, NFTA_PAYLOAD_OFFSET, off);
	put_be32(nlh, NFTA_PAYLOAD_LEN, len);
	put_be32(nlh, NFTA_PAYLOAD_CSUM_TYPE, NFT_PAYLOAD_CSUM_NONE);
	put_be32(nlh, NFTA_PAYLOAD_CSUM_OFFSET, 0);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

static int f580_chn(uint8_t fam, const char *table, const char *chain,
		    const char *dev, uint32_t hook, int prio)
{
	struct nlmsghdr *nlh;
	struct nlattr *h;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, fam);
	put_str(nlh, NFTA_CHAIN_TABLE, table);
	put_str(nlh, NFTA_CHAIN_NAME, chain);
	h = nest_start(nlh, NFTA_CHAIN_HOOK);
	put_be32(nlh, NFTA_HOOK_HOOKNUM, hook);
	put_be32(nlh, NFTA_HOOK_PRIORITY, (uint32_t)prio);
	if (dev)
		put_str(nlh, NFTA_HOOK_DEV, dev);
	nest_end(nlh, h);
	put_be32(nlh, NFTA_CHAIN_POLICY, 1);
	put_str(nlh, NFTA_CHAIN_TYPE, "filter");
	{
		int acks = 0;

		return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
	}
}

/* the probe: a log every frame that reaches the ip6 prerouting hook, with the
 * device that delivered it -- the witness of which VLAN device the written tag
 * selected.  One chain, installed once, never flushed with the arms. */
static int f580_probe_rule(void)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	int acks = 0;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			NFPROTO_IPV6);
	put_str(nlh, NFTA_RULE_TABLE, F580_TG);
	put_str(nlh, NFTA_RULE_CHAIN, "cp");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	counter_expr(nlh);
	log_expr(nlh, F580_GROUP, "PR");
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

/* counter, [store], log, accept -- the counter first, so that it counts the
 * frame even when the store expression refuses and stops the rule. */
static int f580_rule(const struct f580_arm *A, int idx,
		     const unsigned char *imm, int immlen)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	char pre[16];
	int acks = 0;

	snprintf(pre, sizeof(pre), "58:%02d", idx);
	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			A->door ? NFPROTO_NETDEV : NFPROTO_IPV6);
	put_str(nlh, NFTA_RULE_TABLE, A->door ? F580_TN : F580_TG);
	put_str(nlh, NFTA_RULE_CHAIN, "c0");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	counter_expr(nlh);
	if (A->store == 1) {
		f562_store(nlh, (uint32_t)A->base, A->off, A->len, imm);
	} else if (A->store == 3) {
		f580_read_into(nlh, NFT_REG32_08, F580_B_LL, 14, 16);
		f580_read_into(nlh, NFT_REG32_12, F580_B_LL, 30, 16);
		f580_store_from(nlh, NFT_REG32_08, F580_B_NH, A->off, A->len);
	}
	log_expr(nlh, F580_GROUP, pre);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

static void f580_flush(void)
{
	int acks = 0;

	f557_flush(NFPROTO_NETDEV, F580_TN, "c0", &acks);
	f557_flush(NFPROTO_IPV6, F580_TG, "c0", &acks);
}

static const char *f580_ifname(int idx)
{
	static char b[IFNAMSIZ + 1];

	if (idx < 0)
		return "-";
	if (!if_indextoname((unsigned int)idx, b))
		return "-";
	return b;
}

static void f580_arm(const struct f580_arm *A, int idx)
{
	struct f580_sn a, b;
	struct f575_pl pl;
	struct f573_lst st0, st1;
	unsigned char imm[64], fr[192];
	char hx[512], hwh[128], plh[256], l2h[64];
	int rc = -99, u6n = -1, u6len = -1, snd, flen, ilen = -1;
	int nl = 0, ch = -1;
	char vtxt[32] = "-", pretx[16] = "-", indev[20] = "-";
	char hwx[128] = "-", plx[256] = "-", l2x[64] = "-";
	int hwlen = -1, plen = -1, llen = -1;
	int pnl = 0, pplen = -1;
	char pindev[20] = "-", pph[256] = "-", ppx[256] = "-";
	unsigned long long oth0 = 0, oth1 = 0;
	int oth_ok = 0;

	flen = f580_frame(fr, A->fid);
	f580_flush();
	(void)f579_drain(NULL);
	(void)f575_nfl_drain(&pl);		/* drop stragglers */
	if (A->store) {
		ilen = f580_imm(A, imm);
		rc = ilen < 0 ? -99 : f580_rule(A, idx, imm, ilen);
	} else {
		rc = f580_rule(A, idx, NULL, 0);
	}
	f573_stats("x1", &st0);
	f580_snmp(&a);
	snd = f580_send(fr, flen);
	usleep(300000);
	u6n = f579_drain(&u6len);
	f580_snmp(&b);
	f573_stats("x1", &st1);
	oth_ok = st0.ok && st1.ok;
	oth0 = st0.other;
	oth1 = st1.other;
	(void)f575_nfl_drain(&pl);
	{
		int j, ia = -1, ip = -1;

		for (j = 0; j < pl.n && j < F575_NPL; j++) {
			if (!strncmp(pl.m[j].prefix, "58:", 3) && ia < 0)
				ia = j;
			else if (!strcmp(pl.m[j].prefix, "PR") && ip < 0)
				ip = j;
		}
		nl = ia >= 0 ? 1 : 0;
		pnl = ip >= 0 ? 1 : 0;
		if (ip >= 0) {
			struct f575_msg *Q = &pl.m[ip];

			snprintf(pindev, sizeof(pindev), "%d:%s", Q->indev,
				 f580_ifname(Q->indev));
			pplen = Q->plen;
			f559_hexs(pph, sizeof(pph), Q->p, Q->plen);
			snprintf(ppx, sizeof(ppx), "%s", pph);
		}
		if (ia >= 0)
			pl.m[0] = pl.m[ia];
	}
	if (nl > 0) {
		struct f575_msg *M = &pl.m[0];

		snprintf(pretx, sizeof(pretx), "%s", M->prefix);
		snprintf(indev, sizeof(indev), "%d:%s", M->indev,
			 f580_ifname(M->indev));
		hwlen = M->hlen;
		plen = M->plen;
		llen = M->llen;
		f559_hexs(hwh, sizeof(hwh), M->h, M->hlen);
		snprintf(hwx, sizeof(hwx), "%s", hwh);
		f559_hexs(plh, sizeof(plh), M->p, M->plen);
		snprintf(plx, sizeof(plx), "%s", plh);
		f559_hexs(l2h, sizeof(l2h), M->l, M->llen);
		snprintf(l2x, sizeof(l2x), "%s", l2h);
		if (M->vpresent)
			snprintf(vtxt, sizeof(vtxt), "%04x:%04x", M->vproto,
				 M->vtci);
		else
			snprintf(vtxt, sizeof(vtxt), "none");
	}
	if (A->store)
		ch = (int)f555_count(A->door ? NFPROTO_NETDEV : NFPROTO_IPV6,
				     A->door ? F580_TN : F580_TG, "c0");
	else
		ch = (int)f555_count(A->door ? NFPROTO_NETDEV : NFPROTO_IPV6,
				     A->door ? F580_TN : F580_TG, "c0");
	f559_hexs(hx, sizeof(hx), imm, ilen > 0 ? ilen : 0);
	printf("F580 ARM|i=%02d|name=%s|fid=%d|door=%d|base=%d|store=%d|"
	       "off=%u|len=%u|hex=%s|flen=%d|rc=%d|snd=%d|ch=%d|nl=%d|pre=%s|"
	       "indev=%s|hwlen=%d|hw=%s|l2len=%d|l2=%s|vlan=%s|plen=%d|p=%s|"
	       "u6n=%d|u6len=%d|rcv=%llu|deliv=%llu|hdrerr=%llu|addrerr=%llu|"
	       "disc=%llu|ukproto=%llu|trunc=%llu|noroutes=%llu|udp=%llu|"
	       "udperr=%llu|udpnop=%llu|oth_ok=%d|oth=%llu|pnl=%d|pindev=%s|"
	       "pplen=%d|pp=%s\n",
	       idx, A->name, A->fid, A->door, A->base, A->store, A->off,
	       A->len, A->store == 1 ? hx : "-", flen, rc, snd, ch, nl, pretx,
	       indev, hwlen, hwx, llen, l2x, vtxt, plen, plx, u6n, u6len,
	       b.rcv - a.rcv, b.deliv - a.deliv, b.hdrerr - a.hdrerr,
	       b.addrerr - a.addrerr, b.disc - a.disc, b.ukproto - a.ukproto,
	       b.trunc - a.trunc, b.noroutes - a.noroutes, b.udp - a.udp,
	       b.udperr - a.udperr, b.udpnop - a.udpnop, oth_ok,
	       oth1 - oth0, pnl, pindev, pplen, ppx);
	fflush(stdout);
}

/* ---------- the mode ---------------------------------------------------- */

static int f580_bounds(void)
{
	static const char *old[] = { "x1.1024", "x1.100", "x0", "x1" };
	unsigned char fr[192];
	char hx[512];
	int i, k, rc = 0;

	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	for (i = 0; i < 4; i++)
		f558_link_del(old[i]);
	if (link_add_veth("x0", "x1")) {
		printf("F580 FAIL|veth\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/autoconf", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/accept_ra", "0");
	k = f564_addr6("x1", A80_D, 64);
	k |= f575_link_add_vlan("x1.100", "x1", 100, 0x0000, 0);
	set_up("x1.100");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1.100/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1.100/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1.100/dad_transmits", "0");
	k |= f564_addr6("x1.100", A80_D, 64);
	/* the second device exists to turn "the frame died" into "the frame
	 * went to device N": the 4-byte tag write installs a byte-swapped vid
	 * (see the summary), and only a device at that vid can witness it. */
	k |= f575_link_add_vlan("x1.1024", "x1", 1024, 0x0000, 0);
	set_up("x1.1024");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1.1024/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1.1024/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1.1024/dad_transmits", "0");
	k |= f564_addr6("x1.1024", A80_D, 64);
	printf("F580 VDEV|rc=%d|idx100=%d|idx1024=%d|if6=%s\n", k,
	       f555_ifindex("x1.100"), f555_ifindex("x1.1024"),
	       f579_if6(A80_D));
	F580_U6 = f564_udp_bind(AF_INET6, 0, A80_D, F580_DPORT);
	F579_U6 = F580_U6;		/* f579_drain() reads F579_U6 */
	F573_NFL = nfl_open(F580_GROUP);
	printf("F580 ENV|u6=%d|nfl=%d|x0=%d|x1=%d|mac0=%d|mac1=%d|uid=%d|"
	       "euid=%d\n", F580_U6, F573_NFL, f555_ifindex("x0"),
	       f555_ifindex("x1"), mac_get("x0", fr), mac_get("x1", fr),
	       (int)getuid(), (int)geteuid());
	k = f579_tbl(NFPROTO_NETDEV, F580_TN);
	k |= f579_chn(NFPROTO_NETDEV, F580_TN, "c0", "x1", 0);
	k |= f579_tbl(NFPROTO_IPV6, F580_TG);
	k |= f579_chn(NFPROTO_IPV6, F580_TG, "c0", NULL, 0);
	k |= f580_chn(NFPROTO_IPV6, F580_TG, "cp", NULL, 0, 20);
	k |= f580_probe_rule();
	printf("F580 CHAINS|rc=%d\n", k);
	for (i = 1; i <= 6; i++) {
		int n = f580_frame(fr, i);

		if (n < 0)
			continue;
		printf("F580 FRMPY|id=%d|len=%d|hex=%s\n", i, n,
		       f559_hexs(hx, sizeof(hx), fr, n));
	}
	for (i = 0; i < NA580; i++)
		f580_arm(&A580[i], i);
	f580_flush();
	for (i = 0; i < 4; i++)
		f558_link_del(old[i]);
	printf("F580 END|arms=%d\n", NA580);
	fflush(stdout);
	(void)rc;
	return 0;
}

/* ---------- entry ------------------------------------------------------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "bounds";

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("F580 BOOT|mode=%s|argc=%d\n", mode, argc);
	if (!strcmp(mode, "bounds"))
		return f580_bounds();
	return f579_entry(argc, argv);
}
