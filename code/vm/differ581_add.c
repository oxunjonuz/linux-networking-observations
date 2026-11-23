/* differ581_add.c -- turn 581 (F59): THE GUARD IS THE CHAIN'S, THE FIX IS THE
 * PACKET'S.
 *
 *  Debts named at the end of F58: the @nh whitelists for IPv4 and ARP, the
 *  @th store with a checksum recompute (csum_type/csum_flags -- every F58 arm
 *  was CSUM_NONE), and the `inet` family on both doors.
 *
 *  Reading the source first put three findings in one sentence:
 *
 *   1. nft_nh_write_ok() switches on pkt->state->pf.  For an `inet` chain at
 *      prerouting nf_register_net_hook() registers the SAME ops in the ipv4
 *      and ipv6 hook lists, so state->pf is the PACKET's family; at INGRESS
 *      nft_do_chain_inet_ingress() rewrites state->pf from NFPROTO_NETDEV to
 *      NFPROTO_IPV4/IPV6 and sets hook = NF_INET_INGRESS.  Therefore the two
 *      chains that share one ingress hook point on one device get DIFFERENT
 *      guards: netdev gets nft_ll_write_ok()==true and nft_nh_write_ok()==true
 *      (the NF_NETDEV_INGRESS shortcut), inet gets the arithmetic @ll bound
 *      and the per-family @nh whitelist -- because nft_in_ingress() tests
 *      (pf == NFPROTO_NETDEV && hook == NF_NETDEV_INGRESS).
 *
 *   2. nft_nh_write_ok_arp() compares `len <= 20` with the constant
 *      eth_ip = 2*(ETH_ALEN+4) and `offset >= sizeof(struct arphdr)`, but
 *      never offset+len against the 28-byte ARP body: the real bound is the
 *      frame length via skb_ensure_writable().
 *
 *   3. csum_type=INET on base @nh has its own guard, keyed by the family
 *      (nft_payload_csum_nh_write_ok: IPv4 only), and a false guard there is
 *      NOT a refusal -- the fixup is silently skipped.  On base @th the same
 *      attribute writes at the csum_offset the rule names, and csum_flags
 *      (pseudo-header) finds the L4 checksum by itself and SKIPS a UDP
 *      datagram whose checksum field is 0.
 *
 *  Mode `guard`, 60 arms, six doors, one rule per arm:
 *      counter, [payload store], log(group 81, "59:NN"), accept
 *
 *  doors: 0 netdev ingress x1 prio 0 | 1 inet ingress x1 prio 10
 *         2 ipv6 prerouting        | 3 ipv4 prerouting
 *         4 arp IN                 | 5 inet prerouting
 *  a probe chain on ipv6 prerouting (prio 20) logs every frame that reaches
 *  layer 3 with prefix "PR".
 *
 *  Frames: F1 IPv6/UDP 80B, F2 IPv4/UDP (csums correct) 60B,
 *          F3 IPv4/UDP with UDP checksum 0, F4 ARP request 60B,
 *          F5 IPv6 with a broken hop-by-hop chain 62B.
 */

#define F581_GROUP	81
#define F581_SPORT	43580
#define F581_DPORT	5000
#define F581_PAY	18
#define B581_LL		0
#define B581_NH		1
#define B581_TH		2

#define A81_IP4_S	0x0a3b000bU	/* 10.59.0.11 the sender    */
#define A81_IP4_D	0x0a3b0001U	/* 10.59.0.1  us            */
#define A81_IP4_X	0x0a3b0063U	/* 10.59.0.99 written saddr */
#define A81_IP4_Y	0x0a3b004dU	/* 10.59.0.77 written spa   */

static const unsigned char A81_S[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x11 };
static const unsigned char A81_D[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x91 };
static const unsigned char A81_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const unsigned char A81_SM[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x80 };

static int F581_U6 = -1, F581_U4 = -1;

/* ---------- the doors --------------------------------------------------- */

struct f581_door {
	uint8_t fam;
	const char *tbl;
	const char *chn;
	const char *dev;
	uint32_t hook;
	int prio;
	const char *name;
};

static const struct f581_door D581[6] = {
	{ NFPROTO_NETDEV, "f81n", "c0", "x1", 0,  0, "n1" },
	{ NFPROTO_INET,   "f81i", "c0", "x1", 5, 10, "i1" },
	{ NFPROTO_IPV6,   "f81g", "c0", NULL, 0,  0, "g6" },
	{ NFPROTO_IPV4,   "f81p", "c0", NULL, 0,  0, "g4" },
	{ NFPROTO_ARP,    "f81a", "c0", NULL, 0,  0, "a0" },
	{ NFPROTO_INET,   "f81t", "c0", NULL, 0,  0, "t4" },
};

/* ---------- frames ------------------------------------------------------ */

static unsigned short f581_csum(const unsigned char *b, int n)
{
	unsigned int sum = 0;
	int i;

	for (i = 0; i + 1 < n; i += 2)
		sum += (unsigned int)((b[i] << 8) | b[i + 1]);
	if (n & 1)
		sum += (unsigned int)(b[n - 1] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = ~sum & 0xffff;
	return (unsigned short)sum;
}

/* F1: plain IPv6/UDP.  F5/F6: the same frame whose extension-header chain is
 * broken: next header 0 (hop-by-hop, walked in ip6_rcv_core) or 60
 * (destination options, walked only later), then hdrlen 255. */
static int f581_mk_udp6(unsigned char *out, int broken)
{
	int off = 14, tot = 8 + F581_PAY, elen = broken ? 8 : 0;
	unsigned char *ip, *udp, tmp[256];
	unsigned short c;
	int i;

	memset(out, 0, 192);
	memcpy(out, A81_BC, 6);
	memcpy(out + 6, A81_SM, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	ip = out + off;
	udp = ip + 40;
	ip[0] = 0x60;
	ip[4] = (unsigned char)((broken ? elen : tot) >> 8);
	ip[5] = (unsigned char)((broken ? elen : tot) & 0xff);
	ip[6] = broken == 1 ? 0x00 : broken == 2 ? 60 : 17;	/* next header */
	ip[7] = 64;
	memcpy(ip + 8, A81_S, 16);
	memcpy(ip + 24, A81_D, 16);
	if (broken) {
		ip[40] = 0x00;			/* hop-by-hop: next header */
		ip[41] = 0xff;			/* hdrlen 255 -> walk runs off */
		return off + 40 + elen;
	}
	udp[0] = (unsigned char)(F581_SPORT >> 8);
	udp[1] = (unsigned char)(F581_SPORT & 0xff);
	udp[2] = (unsigned char)(F581_DPORT >> 8);
	udp[3] = (unsigned char)(F581_DPORT & 0xff);
	udp[4] = (unsigned char)(tot >> 8);
	udp[5] = (unsigned char)(tot & 0xff);
	for (i = 0; i < F581_PAY; i++)
		udp[8 + i] = 0x77;
	/* pseudo header + UDP datagram in one buffer, checksum field 0 */
	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, ip + 8, 32);
	tmp[32] = 0;
	tmp[33] = 17;
	tmp[34] = (unsigned char)(tot >> 8);
	tmp[35] = (unsigned char)(tot & 0xff);
	memcpy(tmp + 36, udp, (size_t)tot);
	c = f581_csum(tmp, 36 + tot);
	if (!c)
		c = 0xffff;
	udp[6] = (unsigned char)(c >> 8);
	udp[7] = (unsigned char)(c & 0xff);
	return off + 40 + tot;
}

/* F2 (udp_csum_on) / F3 (off): IPv4/UDP, header checksum always correct. */
static int f581_mk_udp4(unsigned char *out, int udp_csum_on)
{
	int off = 14, tot = 8 + F581_PAY;
	unsigned char *ip, *udp, tmp[128];
	unsigned short c;
	int i;

	memset(out, 0, 192);
	memcpy(out, A81_BC, 6);
	memcpy(out + 6, A81_SM, 6);
	out[12] = 0x08;
	out[13] = 0x00;
	ip = out + off;
	udp = ip + 20;
	ip[0] = 0x45;
	ip[1] = 0x00;
	ip[2] = (unsigned char)((20 + tot) >> 8);
	ip[3] = (unsigned char)(20 + tot);
	ip[4] = 0x12;
	ip[5] = 0x34;
	ip[6] = 0x00;
	ip[7] = 0x00;
	ip[8] = 64;			/* ttl */
	ip[9] = 17;			/* udp */
	ip[10] = 0;
	ip[11] = 0;
	be32_out(ip + 12, A81_IP4_S);
	be32_out(ip + 16, A81_IP4_D);
	c = f581_csum(ip, 20);
	ip[10] = (unsigned char)(c >> 8);
	ip[11] = (unsigned char)c;
	udp[0] = (unsigned char)(F581_SPORT >> 8);
	udp[1] = (unsigned char)(F581_SPORT & 0xff);
	udp[2] = (unsigned char)(F581_DPORT >> 8);
	udp[3] = (unsigned char)(F581_DPORT & 0xff);
	udp[4] = (unsigned char)(tot >> 8);
	udp[5] = (unsigned char)(tot & 0xff);
	udp[6] = 0;
	udp[7] = 0;
	for (i = 0; i < F581_PAY; i++)
		udp[8 + i] = 0x77;
	if (udp_csum_on) {
		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, ip + 12, 8);
		tmp[8] = 0;
		tmp[9] = 17;
		tmp[10] = (unsigned char)(tot >> 8);
		tmp[11] = (unsigned char)(tot & 0xff);
		memcpy(tmp + 12, udp, (size_t)tot);
		c = f581_csum(tmp, 12 + tot);
		if (!c)
			c = 0xffff;
		udp[6] = (unsigned char)(c >> 8);
		udp[7] = (unsigned char)(c & 0xff);
	}
	return off + 20 + tot;
}

/* F4: ARP request "who has 10.59.0.1? tell 10.59.0.11", padded to 60. */
static int f581_mk_arp(unsigned char *out)
{
	return build_arp(out, 1, A81_IP4_S, A81_IP4_D, A81_SM, 6, 4, 1);
}

static int f581_frame(unsigned char *out, int fid)
{
	switch (fid) {
	case 1:
		return f581_mk_udp6(out, 0);
	case 2:
		return f581_mk_udp4(out, 1);
	case 3:
		return f581_mk_udp4(out, 0);
	case 4:
		return f581_mk_arp(out);
	case 5:
		return f581_mk_udp6(out, 1);
	case 6:
		return f581_mk_udp6(out, 2);
	}
	return -1;
}

/* ---------- sockets ----------------------------------------------------- */

static int f581_drain6(int *firstlen)
{
	unsigned char b[512];
	int n = 0, r;

	if (firstlen)
		*firstlen = -1;
	if (F581_U6 < 0)
		return -1;
	for (;;) {
		r = (int)recv(F581_U6, b, sizeof(b), MSG_DONTWAIT);
		if (r < 0)
			break;
		if (n == 0 && firstlen)
			*firstlen = r;
		n++;
	}
	return n;
}

static int f581_drain4(int *firstlen)
{
	unsigned char b[512];
	int n = 0, r;

	if (firstlen)
		*firstlen = -1;
	if (F581_U4 < 0)
		return -1;
	for (;;) {
		r = (int)recv(F581_U4, b, sizeof(b), MSG_DONTWAIT);
		if (r < 0)
			break;
		if (n == 0 && firstlen)
			*firstlen = r;
		n++;
	}
	return n;
}

/* ---------- IPv4 snmp --------------------------------------------------- */

struct f581_s4 {
	unsigned long long in, hdr, addr, uk, disc, deliv;
	unsigned long long udp, udperr, udpnop;
};

static void f581_snmp4(struct f581_s4 *s)
{
	memset(s, 0, sizeof(*s));
	s->in = f564_snmp("Ip", "InReceives");
	s->hdr = f564_snmp("Ip", "InHdrErrors");
	s->addr = f564_snmp("Ip", "InAddrErrors");
	s->uk = f564_snmp("Ip", "InUnknownProtos");
	s->disc = f564_snmp("Ip", "InDiscards");
	s->deliv = f564_snmp("Ip", "InDelivers");
	s->udp = f564_snmp("Udp", "InDatagrams");
	s->udperr = f564_snmp("Udp", "InErrors");
	s->udpnop = f564_snmp("Udp", "NoPorts");
}

/* ---------- the arms ---------------------------------------------------- */

struct f581_arm {
	const char *name;
	int fid;
	int door;
	int base;
	int store;
	unsigned int off, len;
	const char *hex;
	int ct;			/* NFTA_PAYLOAD_CSUM_TYPE */
	unsigned int co;	/* csum offset */
	unsigned int cf;	/* csum flags */
};

static const struct f581_arm A581[] = {
	/* --- census: one arm per door, no store --- */
	{ "c_n1",	1, 0, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_i1",	1, 1, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_g6",	1, 2, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_g4",	2, 3, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_a0",	4, 4, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_t4",	2, 5, 0, 0, 0, 0, NULL, 0, 0, 0 },
	/* --- A: one ingress hook point, two families (F1) --- */
	{ "n1_ll12",	1, 0, B581_LL, 1, 12, 2, "0800", 0, 0, 0 },
	{ "i1_ll12",	1, 1, B581_LL, 1, 12, 2, "0800", 0, 0, 0 },
	{ "n1_ll14",	1, 0, B581_LL, 1, 14, 2, "4000", 0, 0, 0 },
	{ "i1_ll14",	1, 1, B581_LL, 1, 14, 2, "4000", 0, 0, 0 },
	{ "n1_ll16",	1, 0, B581_LL, 1, 16, 2, "aaaa", 0, 0, 0 },
	{ "i1_ll16",	1, 1, B581_LL, 1, 16, 2, "aaaa", 0, 0, 0 },
	{ "n1_nh06",	1, 0, B581_NH, 1, 6, 1, "99", 0, 0, 0 },
	{ "i1_nh06",	1, 1, B581_NH, 1, 6, 1, "99", 0, 0, 0 },
	{ "n1_nh07",	1, 0, B581_NH, 1, 7, 1, "3f", 0, 0, 0 },
	{ "i1_nh07",	1, 1, B581_NH, 1, 7, 1, "3f", 0, 0, 0 },
	{ "n1_nh08",	1, 0, B581_NH, 1, 8, 16, NULL, 0, 0, 0 },
	{ "i1_nh08",	1, 1, B581_NH, 1, 8, 16, NULL, 0, 0, 0 },
	{ "i1_ttl_no",	2, 1, B581_NH, 1, 8, 1, "3f", 0, 0, 0 },
	{ "i1_ttl_cs",	2, 1, B581_NH, 1, 8, 1, "3f",
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	/* --- B: the IPv4 whitelist (F2, ipv4 prerouting) --- */
	{ "v4_0_2s",	2, 3, B581_NH, 1, 0, 2, "45a0", 0, 0, 0 },
	{ "v4_0_2c",	2, 3, B581_NH, 1, 0, 2, "55a0", 0, 0, 0 },
	{ "v4_1_1",	2, 3, B581_NH, 1, 1, 1, "a0", 0, 0, 0 },
	{ "v4_1_2",	2, 3, B581_NH, 1, 1, 2, "a0a1", 0, 0, 0 },
	{ "v4_4_2",	2, 3, B581_NH, 1, 4, 2, "beef", 0, 0, 0 },
	{ "v4_4_1",	2, 3, B581_NH, 1, 4, 1, "a0", 0, 0, 0 },
	{ "v4_8_1",	2, 3, B581_NH, 1, 8, 1, "3f", 0, 0, 0 },
	{ "v4_8_2s",	2, 3, B581_NH, 1, 8, 2, "3f11", 0, 0, 0 },
	{ "v4_8_2c",	2, 3, B581_NH, 1, 8, 2, "3f06", 0, 0, 0 },
	{ "v4_10_10",	2, 3, B581_NH, 1, 10, 10, NULL, 0, 0, 0 },
	{ "v4_10_11",	2, 3, B581_NH, 1, 10, 11, NULL, 0, 0, 0 },
	{ "v4_12_8",	2, 3, B581_NH, 1, 12, 8, "0a3b00630a3b0001", 0, 0, 0 },
	{ "v4_12_9",	2, 3, B581_NH, 1, 12, 9, NULL, 0, 0, 0 },
	{ "v4_16_4",	2, 3, B581_NH, 1, 16, 4, "0a3b0001", 0, 0, 0 },
	{ "v4_16_5",	2, 3, B581_NH, 1, 16, 5, NULL, 0, 0, 0 },
	{ "v4_20_2",	2, 3, B581_NH, 1, 20, 2, "a0a1", 0, 0, 0 },
	/* --- C: the checksum fixup --- */
	{ "v4_sr_no",	2, 3, B581_NH, 1, 12, 4, "0a3b0063", 0, 0, 0 },
	{ "v4_sr_cs",	2, 3, B581_NH, 1, 12, 4, "0a3b0063",
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	{ "v4_ttl_cs",	2, 3, B581_NH, 1, 8, 1, "3f",
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	{ "v4_cs_o11",	2, 3, B581_NH, 1, 12, 4, "0a3b0063",
	  NFT_PAYLOAD_CSUM_INET, 11, 0 },
	{ "v4_u0_no",	3, 3, B581_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "v4_u0_cs",	3, 3, B581_TH, 1, 8, 4, "a0a1a2a3",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	{ "v4_u0_fl",	3, 3, B581_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 1 },
	{ "v6_p_no",	1, 2, B581_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "v6_p_cs",	1, 2, B581_TH, 1, 8, 4, "a0a1a2a3",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	{ "v6_p_fl",	1, 2, B581_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 1 },
	{ "v6_s_fl",	1, 2, B581_NH, 1, 8, 16, NULL, 0, 0, 1 },
	{ "v6_s_cs",	1, 2, B581_NH, 1, 8, 16, NULL,
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	{ "ll_cs",	1, 2, B581_LL, 1, 12, 2, "0800",
	  NFT_PAYLOAD_CSUM_INET, 0, 0 },
	{ "th_cs_fl",	1, 2, B581_TH, 1, 8, 4, "a0a1a2a3",
	  NFT_PAYLOAD_CSUM_INET, 6, 1 },
	{ "t4_s_cs",	2, 5, B581_NH, 1, 12, 4, "0a3b0063",
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	{ "t4_s_no",	2, 5, B581_NH, 1, 12, 4, "0a3b0063", 0, 0, 0 },
	/* --- D: the ARP whitelist and what the kernel learns (F4) --- */
	{ "a_6_2",	4, 4, B581_NH, 1, 6, 2, "0002", 0, 0, 0 },
	{ "a_6_1",	4, 4, B581_NH, 1, 6, 1, "00", 0, 0, 0 },
	{ "a_7_2",	4, 4, B581_NH, 1, 7, 2, "0002", 0, 0, 0 },
	{ "a_8_6",	4, 4, B581_NH, 1, 8, 6, "a0a1a2a3a4a5", 0, 0, 0 },
	{ "a_8_20",	4, 4, B581_NH, 1, 8, 20, NULL, 0, 0, 0 },
	{ "a_8_21",	4, 4, B581_NH, 1, 8, 21, NULL, 0, 0, 0 },
	{ "a_14_4",	4, 4, B581_NH, 1, 14, 4, "0a3b004d", 0, 0, 0 },
	{ "a_24_4",	4, 4, B581_NH, 1, 24, 4, "0a3b0063", 0, 0, 0 },
	{ "a_27_2",	4, 4, B581_NH, 1, 27, 2, "beef", 0, 0, 0 },
	{ "a_27_14",	4, 4, B581_NH, 1, 27, 14, NULL, 0, 0, 0 },
	{ "a_27_20",	4, 4, B581_NH, 1, 27, 20, NULL, 0, 0, 0 },
};
#define NA581 ((int)(sizeof(A581) / sizeof(A581[0])))

static int f581_imm(const struct f581_arm *A, unsigned char *imm)
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

/* counter, [store], log, accept -- the counter first, so it counts the frame
 * even when the store refuses and the rule stops (NFT_BREAK). */
static int f581_rule(const struct f581_arm *A, int idx,
		     const unsigned char *imm, int immlen)
{
	const struct f581_door *D = &D581[A->door];
	struct nlmsghdr *nlh;
	struct nlattr *exprs, *e, *d;
	char pre[16];
	int acks = 0;

	snprintf(pre, sizeof(pre), "59:%02d", idx);
	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			D->fam);
	put_str(nlh, NFTA_RULE_TABLE, D->tbl);
	put_str(nlh, NFTA_RULE_CHAIN, D->chn);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	counter_expr(nlh);
	if (A->store) {
		if (immlen <= 16) {
			imm_value(nlh, NFT_REG32_00, imm, immlen);
		} else {
			imm_value(nlh, NFT_REG32_00, imm, 16);
			imm_value(nlh, NFT_REG32_04, imm + 16, immlen - 16);
		}
		e = nest_start(nlh, NFTA_LIST_ELEM);
		put_str(nlh, NFTA_EXPR_NAME, "payload");
		d = nest_start(nlh, NFTA_EXPR_DATA);
		put_be32(nlh, NFTA_PAYLOAD_SREG, NFT_REG32_00);
		put_be32(nlh, NFTA_PAYLOAD_BASE, (uint32_t)A->base);
		put_be32(nlh, NFTA_PAYLOAD_OFFSET, A->off);
		put_be32(nlh, NFTA_PAYLOAD_LEN, A->len);
		put_be32(nlh, NFTA_PAYLOAD_CSUM_TYPE, (uint32_t)A->ct);
		if (A->ct == NFT_PAYLOAD_CSUM_INET)
			put_be32(nlh, NFTA_PAYLOAD_CSUM_OFFSET, A->co);
		if (A->cf)
			put_be32(nlh, NFTA_PAYLOAD_CSUM_FLAGS, A->cf);
		nest_end(nlh, d);
		nest_end(nlh, e);
	}
	log_expr(nlh, F581_GROUP, pre);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

static void f581_flush(void)
{
	int acks = 0, i;

	for (i = 0; i < 6; i++)
		f557_flush(D581[i].fam, D581[i].tbl, D581[i].chn, &acks);
}

static int f581_deltable(uint8_t fam, const char *table)
{
	struct nlmsghdr *nlh;
	int acks = 0;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
			NLM_F_REQUEST | NLM_F_ACK, fam);
	put_str(nlh, NFTA_TABLE_NAME, table);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

/* ---------- one arm ----------------------------------------------------- */

static void f581_arm(const struct f581_arm *A, int idx)
{
	struct f580_sn a, b;
	struct f581_s4 c, d;
	struct f575_pl pl;
	struct f573_lst st0, st1;
	unsigned char imm[64], fr[192];
	char hx[512], hwh[128], plh[512], l2h[64];
	char m11[32] = "-", m77[32] = "-", m99[32] = "-";
	int rc = -99, u6n = -1, u6len = -1, u4n = -1, u4len = -1;
	int snd, flen, ilen = -1, nl = 0, ch = -1;
	int pnl = 0, pplen = -1;
	char vtxt[32] = "-", pretx[16] = "-", indev[20] = "-";
	char hwx[128] = "-", plx[512] = "-", l2x[64] = "-";
	char pindev[20] = "-", pph[512] = "-";
	int hwlen = -1, plen = -1, llen = -1;
	unsigned long long oth0 = 0, oth1 = 0;
	int oth_ok = 0;

	flen = f581_frame(fr, A->fid);
	f581_flush();
	(void)f581_drain6(NULL);
	(void)f581_drain4(NULL);
	(void)f575_nfl_drain(&pl);
	if (A->fid == 4) {
		f555_neigh_del("x1", htonl(A81_IP4_S));
		f555_neigh_del("x1", htonl(A81_IP4_Y));
		f555_neigh_del("x1", htonl(A81_IP4_X));
	}
	if (A->store) {
		ilen = f581_imm(A, imm);
		rc = ilen < 0 ? -99 : f581_rule(A, idx, imm, ilen);
	} else {
		rc = f581_rule(A, idx, NULL, 0);
	}
	f573_stats("x1", &st0);
	f580_snmp(&a);
	f581_snmp4(&c);
	snd = f580_send(fr, flen);
	usleep(300000);
	u6n = f581_drain6(&u6len);
	u4n = f581_drain4(&u4len);
	f580_snmp(&b);
	f581_snmp4(&d);
	f573_stats("x1", &st1);
	oth_ok = st0.ok && st1.ok;
	oth0 = st0.other;
	oth1 = st1.other;
	(void)f575_nfl_drain(&pl);
	{
		int j, ia = -1, ip = -1;

		for (j = 0; j < pl.n && j < F575_NPL; j++) {
			if (!strncmp(pl.m[j].prefix, "59:", 3) && ia < 0)
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
	ch = (int)f555_count(D581[A->door].fam, D581[A->door].tbl,
			     D581[A->door].chn);
	if (A->fid == 4) {
		if (arp_flags("10.59.0.11", m11, sizeof(m11)) < 0)
			snprintf(m11, sizeof(m11), "-");
		if (arp_flags("10.59.0.77", m77, sizeof(m77)) < 0)
			snprintf(m77, sizeof(m77), "-");
		if (arp_flags("10.59.0.99", m99, sizeof(m99)) < 0)
			snprintf(m99, sizeof(m99), "-");
	}
	f559_hexs(hx, sizeof(hx), imm, ilen > 0 ? ilen : 0);
	printf("F581 ARM|i=%02d|name=%s|fid=%d|door=%d|base=%d|store=%d|"
	       "off=%u|len=%u|hex=%s|ct=%d|co=%u|cf=%u|flen=%d|rc=%d|snd=%d|"
	       "ch=%d|nl=%d|pre=%s|indev=%s|hwlen=%d|hw=%s|l2len=%d|l2=%s|"
	       "vlan=%s|plen=%d|p=%s|u6n=%d|u6l=%d|u4n=%d|u4l=%d|"
	       "rcv=%llu|deliv=%llu|hdrerr=%llu|addrerr=%llu|disc=%llu|"
	       "ukproto=%llu|trunc=%llu|noroutes=%llu|udp6=%llu|udperr6=%llu|"
	       "udpnop6=%llu|ipin=%llu|iphdr=%llu|ipaddr=%llu|ipuk=%llu|"
	       "ipdisc=%llu|ipdeliv=%llu|u4=%llu|u4err=%llu|u4nop=%llu|"
	       "arp11=%s|arp77=%s|arp99=%s|oth_ok=%d|oth=%llu|pnl=%d|"
	       "pindev=%s|pplen=%d|pp=%s\n",
	       idx, A->name, A->fid, A->door, A->base, A->store, A->off,
	       A->len, A->store ? hx : "-", A->ct, A->co, A->cf, flen, rc,
	       snd, ch, nl, pretx, indev, hwlen, hwx, llen, l2x, vtxt, plen,
	       plx, u6n, u6len, u4n, u4len,
	       b.rcv - a.rcv, b.deliv - a.deliv, b.hdrerr - a.hdrerr,
	       b.addrerr - a.addrerr, b.disc - a.disc, b.ukproto - a.ukproto,
	       b.trunc - a.trunc, b.noroutes - a.noroutes, b.udp - a.udp,
	       b.udperr - a.udperr, b.udpnop - a.udpnop,
	       d.in - c.in, d.hdr - c.hdr, d.addr - c.addr, d.uk - c.uk,
	       d.disc - c.disc, d.deliv - c.deliv, d.udp - c.udp,
	       d.udperr - c.udperr, d.udpnop - c.udpnop,
	       m11, m77, m99, oth_ok, oth1 - oth0, pnl, pindev, pplen, pph);
	fflush(stdout);
}

/* ---------- the validating ingress door --------------------------------- */

/* An EMPTY inet ingress chain parses the packet before any layer-3 hook:
 * nft_set_pktinfo_ipv6_ingress() runs ipv6_find_hdr() and drops what it cannot
 * walk.  F5 is such a frame.  Row 1: with the inet table.  Row 2: after
 * deleting it. */
static void f581_badnh(void)
{
	static const struct f581_arm C = { "bad", 5, 0, 0, 0, 0, 0, NULL, 0, 0, 0 };
	struct f580_sn a, b;
	struct f575_pl pl;
	unsigned char fr[192];
	char pph[512];
	int k, fi, flen, snd, nl, ch, pnl, pplen;
	char pindev[20];

	for (fi = 5; fi <= 6; fi++) {
	flen = f581_frame(fr, fi);
	for (k = 0; k < 2; k++) {
		f581_flush();
		(void)f575_nfl_drain(&pl);
		f581_rule(&C, 90, NULL, 0);
		f580_snmp(&a);
		snd = f580_send(fr, flen);
		usleep(300000);
		f580_snmp(&b);
		(void)f575_nfl_drain(&pl);
		nl = 0;
		pnl = 0;
		pplen = -1;
		snprintf(pindev, sizeof(pindev), "-");
		pph[0] = 0;
		{
			int j;

			for (j = 0; j < pl.n && j < F575_NPL; j++) {
				if (!strncmp(pl.m[j].prefix, "59:", 3))
					nl = 1;
				else if (!strcmp(pl.m[j].prefix, "PR")) {
					struct f575_msg *Q = &pl.m[j];

					pnl = 1;
					snprintf(pindev, sizeof(pindev),
						 "%d:%s", Q->indev,
						 f580_ifname(Q->indev));
					pplen = Q->plen;
					f559_hexs(pph, sizeof(pph), Q->p,
						  Q->plen);
				}
			}
		}
		ch = (int)f555_count(NFPROTO_NETDEV, D581[0].tbl,
				     D581[0].chn);
		printf("F581 BAD|fid=%d|stage=%s|snd=%d|ch=%d|nl=%d|pnl=%d|"
		       "pindev=%s|pplen=%d|pp=%s|rcv=%llu|deliv=%llu|"
		       "hdrerr=%llu|ukproto=%llu|disc=%llu|trunc=%llu\n",
		       fi, k == 0 ? "inet_present" : "inet_removed", snd, ch, nl,
		       pnl, pindev, pplen, pph, b.rcv - a.rcv, b.deliv - a.deliv,
		       b.hdrerr - a.hdrerr, b.ukproto - a.ukproto,
		       b.disc - a.disc, b.trunc - a.trunc);
		fflush(stdout);
		if (k == 0) {
			f581_deltable(NFPROTO_INET, D581[1].tbl);
			usleep(100000);
		} else {
			f579_tbl(NFPROTO_INET, D581[1].tbl);
			f580_chn(NFPROTO_INET, D581[1].tbl, "c0", "x1", 5, 10);
		}
	}
	}
}

/* ---------- the mode ---------------------------------------------------- */

static int f581_guard(void)
{
	static const char *old[] = { "x1", "x0" };
	unsigned char fr[192];
	char hx[1024];
	int i, k, rc = 0;

	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	f555_sysctl("/proc/sys/net/ipv4/ip_forward", "0");
	for (i = 0; i < 2; i++)
		f558_link_del(old[i]);
	if (link_add_veth("x0", "x1")) {
		printf("F581 FAIL|veth\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/autoconf", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/accept_ra", "0");
	k = f564_addr6("x1", A81_D, 64);
	k |= f555_addr_add("x1", htonl(A81_IP4_D), 24);
	printf("F581 VDEV|rc=%d|if6=%s|mac1=%d\n", k, f579_if6(A81_D),
	       mac_get("x1", fr));
	F581_U6 = f564_udp_bind(AF_INET6, 0, A81_D, F581_DPORT);
	F581_U4 = f564_udp_bind(AF_INET, A81_IP4_D, NULL, F581_DPORT);
	F579_U6 = F581_U6;
	F573_NFL = nfl_open(F581_GROUP);
	printf("F581 ENV|u6=%d|u4=%d|nfl=%d|x0=%d|x1=%d|uid=%d|euid=%d\n",
	       F581_U6, F581_U4, F573_NFL, f555_ifindex("x0"),
	       f555_ifindex("x1"), (int)getuid(), (int)geteuid());
	k = 0;
	for (i = 0; i < 6; i++) {
		k |= f579_tbl(D581[i].fam, D581[i].tbl);
		k |= f580_chn(D581[i].fam, D581[i].tbl, D581[i].chn,
			      D581[i].dev, D581[i].hook, D581[i].prio);
	}
	k |= f580_chn(NFPROTO_IPV6, "f81g", "cp", NULL, 0, 20);
	{
		struct nlmsghdr *nlh;
		struct nlattr *exprs;
		int acks = 0;

		nlh = msg_start(opbuf, (int)sizeof(opbuf),
				(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
				NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
				NLM_F_APPEND, NFPROTO_IPV6);
		put_str(nlh, NFTA_RULE_TABLE, "f81g");
		put_str(nlh, NFTA_RULE_CHAIN, "cp");
		exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
		log_expr(nlh, F581_GROUP, "PR");
		accept_expr(nlh);
		nest_end(nlh, exprs);
		k |= f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
	}
	printf("F581 CHAINS|rc=%d|arp=%d|inet=%d\n", k, D581[4].fam,
	       D581[1].fam);
	for (i = 1; i <= 6; i++) {
		int n = f581_frame(fr, i);

		if (n < 0)
			continue;
		printf("F581 FRMPY|id=%d|len=%d|hex=%s\n", i, n,
		       f559_hexs(hx, sizeof(hx), fr, n));
	}
	for (i = 0; i < NA581; i++)
		f581_arm(&A581[i], i);
	f581_badnh();
	f581_flush();
	for (i = 0; i < 2; i++)
		f558_link_del(old[i]);
	printf("F581 END|arms=%d\n", NA581);
	fflush(stdout);
	(void)rc;
	return 0;
}

/* ---------- entry ------------------------------------------------------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "guard";

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("F581 BOOT|mode=%s|argc=%d\n", mode, argc);
	if (!strcmp(mode, "guard"))
		return f581_guard();
	return f580_entry(argc, argv);
}
