/* differ556_add.c -- turn 556 / F33: one guard, four types, one grid.
 *
 * F30/F31/F32 measured the four branches of nft_nh_write_ok() one at a time,
 * on three DIFFERENT images:
 *
 *   ip4/ip6     stock 7.3.4-B19           (F30)
 *   bridge      src/linux-7.3.4-C553      (F31, ethertype 0x0800 / 0x0806)
 *   netdev      src/linux-7.3.4-C553      (F31, dead code at ingress)
 *   arp         src/linux-7.3.4-A553      (F32)
 *
 * F33 asks a different question: not "does branch X guard byte Y", but "what
 * KIND of function is each branch".  The answer is the SHAPE of the set of
 * (offset,len) pairs it accepts, and a shape measured in three different boots
 * on three different images is not a shape.  So: one kernel (T556) with all
 * four branches live, one boot, and ONE identical 40-cell grid shipped through
 * every envelope:
 *
 *   ip4   family ip,     base nh, chain prerouting   (nft_nh_write_ok_ip4)
 *   ip6   family ip6,    base nh, chain prerouting   (nft_nh_write_ok_ip6)
 *   nd    family netdev, base nh, chain ingress i1   (nft_nh_write_ok -> true)
 *   br4   family bridge, base nh, chain prerouting, ethertype 0x0800
 *   brA   family bridge, base nh, chain prerouting, ethertype 0x0806
 *   arp   family arp,    base nh, chain input        (nft_nh_write_ok_arp)
 *   ll4   family ip,     base ll, chain prerouting   (nft_ll_write_ok)
 *   llN   family netdev, base ll, chain ingress i1
 *   llB   family bridge, base ll, chain prerouting
 *
 * Oracle per arm: the kernel's own counter, placed AFTER the store in the same
 * rule -- cnt=1 means "the guard let the store through and the rest of the
 * rule ran", cnt=0 means the store was refused and the remaining expressions
 * (log, counter, verdict) never ran.  The NFLOG message carries the frame as
 * it looks at the log point, i.e. after the store, so every alive cell also
 * gets its bytes checked against the control arm of the same envelope.
 *
 * This file is appended to a renamed copy of differ555.c (see
 * vm/build_f33_differ.sh); all helpers above it -- netlink toolkit, veth,
 * rtnetlink, NFLOG, build_arp, f555_count -- are the F32 ones, unchanged.
 */

/* ---------- bridge device helpers (same code as differ553.c) ---------- */

static int f556_link_add_kind(const char *name, const char *kind)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[256];
	} req;
	struct nlattr *li;
	int fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	attr_put(&req.nlh, IFLA_IFNAME, name, (int)strlen(name) + 1);
	li = nest_start(&req.nlh, IFLA_LINKINFO);
	attr_put(&req.nlh, IFLA_INFO_KIND, kind, (int)strlen(kind) + 1);
	nest_end(&req.nlh, li);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

static int f556_link_enslave(const char *port, const char *master)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[128];
	} req;
	uint32_t midx = (uint32_t)f555_ifindex(master);
	int fd, rc;

	if ((int)midx < 0)
		return -10;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = f555_ifindex(port);
	attr_put(&req.nlh, IFLA_MASTER, &midx, 4);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* ---------- one chain, with a device when the hook needs one ---------- */

/* base chain: family, hook number, priority, policy; dev != NULL only for the
 * netdev ingress hook, whose NFTA_HOOK_DEV is a STRING (nf_tables_api.c reads
 * it with nla_get_string()). */
static int f556_add_chain(uint8_t family, const char *table, const char *chain,
			  uint32_t hook, uint32_t prio, uint32_t policy,
			  const char *dev)
{
	struct nlmsghdr *nlh;
	struct nlattr *h;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, family);
	put_str(nlh, NFTA_CHAIN_TABLE, table);
	put_str(nlh, NFTA_CHAIN_NAME, chain);
	h = nest_start(nlh, NFTA_CHAIN_HOOK);
	put_be32(nlh, NFTA_HOOK_HOOKNUM, hook);
	put_be32(nlh, NFTA_HOOK_PRIORITY, prio);
	if (dev)
		put_str(nlh, NFTA_HOOK_DEV, dev);
	nest_end(nlh, h);
	put_be32(nlh, NFTA_CHAIN_POLICY, policy);
	put_str(nlh, NFTA_CHAIN_TYPE, "filter");
	return nft_one(opbuf, (int)nlh->nlmsg_len);
}

/* ---------- the store, with an explicit payload BASE ---------- */

/* one rule: [store <base>+off = imm][log][counter][accept] */
static int f556_install_store(uint8_t family, const char *table, const char *chain,
			      uint32_t base, uint32_t off, uint32_t len,
			      const unsigned char *imm, int immlen,
			      int loggroup, const char *prefix)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs, *e, *d;
	int rc;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			family);
	put_str(nlh, NFTA_RULE_TABLE, table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
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
	log_expr(nlh, loggroup, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	rc = nft_one(opbuf, (int)nlh->nlmsg_len);
	return rc;
}

/* ---------- frames ---------- */

static const unsigned char M33_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static unsigned short f556_csum(const void *data, int len)
{
	const unsigned char *p = data;
	unsigned int sum = 0;

	while (len > 1) {
		sum += (unsigned int)((p[0] << 8) | p[1]);
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (unsigned int)(p[0] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (unsigned short)~sum;
}

/* frame kinds */
#define FK33_IP4	0	/* ethernet + IPv4 (ihl 5, proto 17) + UDP */
#define FK33_IP6	1	/* ethernet + IPv6 + UDP                     */
#define FK33_ARP	2	/* ethernet + ARP request, padded to 60      */
#define FK33_IP4_IHL6	3	/* the same datagram with ihl 6 -> byte 14 = 0x46 */
#define FK33_IP4_P6	4	/* the same datagram with proto 6 (byte 23 = 0x06) */
#define FK33_IP6_B	5	/* a different IPv6 frame (tc/hop differ)    */

/* Ethernet + IPv4 + UDP.  ihl4 is the header length in 32-bit words; the
 * checksum is computed over exactly ihl4*4 bytes, so an ihl-6 frame is a
 * VALID datagram -- ip_rcv must not drop it before the hook, or the guard
 * would never be asked. */
static int f556_mk_ip4(unsigned char *out, int ihl4, int proto, int ttl)
{
	int hl = ihl4 * 4, tot = hl + 8 + 18;
	unsigned char *ip = out + 14;
	unsigned char *u = out + 14 + hl;
	unsigned short c;

	memset(out, 0, 200);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = 0x08;
	out[13] = 0x00;
	ip[0] = (unsigned char)(0x40 | ihl4);
	ip[1] = 0x00;
	ip[2] = (unsigned char)(tot >> 8);
	ip[3] = (unsigned char)tot;
	ip[4] = 0x12;
	ip[5] = 0x34;
	ip[6] = 0x00;
	ip[7] = 0x00;
	ip[8] = (unsigned char)ttl;
	ip[9] = (unsigned char)proto;
	ip[10] = 0x00;
	ip[11] = 0x00;
	ip[12] = 0x0a; ip[13] = 0x01; ip[14] = 0x00; ip[15] = 0x01;	/* 10.1.0.1 */
	ip[16] = 0x0a; ip[17] = 0x09; ip[18] = 0x00; ip[19] = 0x07;	/* 10.9.0.7 */
	c = f556_csum(ip, hl);
	ip[10] = (unsigned char)(c >> 8);
	ip[11] = (unsigned char)c;
	u[0] = 0x9c; u[1] = 0x40;	/* sport 40000 */
	u[2] = 0x13; u[3] = 0x88;	/* dport 5000  */
	u[4] = 0x00; u[5] = 26;		/* 8 + 18      */
	u[6] = 0x00; u[7] = 0x00;	/* checksum 0 (legal for IPv4) */
	memset(u + 8, 0x77, 18);
	return 14 + tot;
}

/* Ethernet + IPv6 + UDP.  `tc` goes into the traffic-class nibbles of bytes
 * 14..15, `hop` into byte 21 -- the two bytes FK33_IP6_B changes, so the same
 * rule over two IPv6 frames tests whether that branch reads the packet. */
static int f556_mk_ip6(unsigned char *out, int tc, int hop)
{
	int pay = 8 + 18;
	unsigned char *ip = out + 14;
	unsigned char *u = out + 14 + 40;
	static const unsigned char src[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
					       0, 0, 0, 0, 0, 0x98, 0, 1 };
	static const unsigned char dst[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
					       0, 0, 0, 0, 0, 0x99, 0, 9 };

	memset(out, 0, 200);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	ip[0] = 0x60 | (unsigned char)((tc >> 4) & 0x0f);
	ip[1] = (unsigned char)((tc << 4) & 0xf0);
	ip[4] = (unsigned char)(pay >> 8);
	ip[5] = (unsigned char)pay;
	ip[6] = 17;
	ip[7] = (unsigned char)hop;
	memcpy(ip + 8, src, 16);
	memcpy(ip + 24, dst, 16);
	u[0] = 0x9c; u[1] = 0x40;
	u[2] = 0x13; u[3] = 0x88;
	u[4] = 0x00; u[5] = 26;
	u[6] = 0x00; u[7] = 0x00;
	memset(u + 8, 0x77, 18);
	return 14 + 40 + pay;
}

static int f556_frame(int kind, unsigned char *out)
{
	switch (kind) {
	case FK33_IP4:
		return f556_mk_ip4(out, 5, 17, 64);
	case FK33_IP4_IHL6:
		return f556_mk_ip4(out, 6, 17, 64);
	case FK33_IP4_P6:
		return f556_mk_ip4(out, 5, 6, 64);
	case FK33_IP6:
		return f556_mk_ip6(out, 0x00, 64);
	case FK33_IP6_B:
		return f556_mk_ip6(out, 0x2e, 33);
	case FK33_ARP:
		return build_arp(out, 1, 0x0a010009, 0x0a090001, MAC_SRC, 6, 4, 1);
	}
	return f556_mk_ip4(out, 5, 17, 64);
}

/* pkt_send() above sets sll_protocol = ETH_P_ALL.  That is what
 * packet_snd() copies into skb->protocol, and at the netdev EGRESS hook the
 * guard switches on exactly that field -- so an egress arm sent with
 * ETH_P_ALL would be judged as "unknown protocol" and every cell would look
 * refused.  This variant sends the frame's own ethertype. */
static int pkt_send_p(const char *dev, const unsigned char *fr, int len,
		      unsigned short proto)
{
	struct sockaddr_ll sll;
	int s, rc, idx = f555_ifindex(dev);

	if (idx < 0)
		return -1;
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
		return -2;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(proto);
	sll.sll_ifindex = idx;
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, fr, 6);
	rc = (int)sendto(s, fr, (size_t)len, 0, (struct sockaddr *)&sll, sizeof(sll));
	close(s);
	return rc < 0 ? -errno : 0;
}

static unsigned short f556_proto(int kind)
{
	if (kind == FK33_ARP)
		return 0x0806;
	if (kind == FK33_IP6 || kind == FK33_IP6_B)
		return 0x86dd;
	return 0x0800;
}

/* ---------- the shared grid ---------- */

#define G33_NOFF 12
#define G33_NLEN 3
#define G33_NEXT 4
#define G33_N (G33_NOFF * G33_NLEN + G33_NEXT)

static const int G33_OFF[G33_NOFF] = { 0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24 };
static const int G33_LEN[G33_NLEN] = { 1, 2, 4 };
static const int G33_XOFF[G33_NEXT] = { 0, 8, 16, 20 };
static const int G33_XLEN[G33_NEXT] = { 8, 16, 16, 16 };

/* The value a cell writes.  Where a branch compares a written byte with the
 * frame (ip4 offset 0 and offset 8 + len 2), the value is chosen equal to what
 * the frame carries, so that the LENGTH is what the cell measures and not the
 * value.  The value-dependence itself is measured separately, by the E arms. */
static void f556_imm(int kind, int off, int len, unsigned char *imm)
{
	int i;

	memset(imm, 0, 16);
	for (i = 0; i < len && i < 16; i++)
		imm[i] = (unsigned char)(0x90 + i);
	if (off == 0)
		imm[0] = (kind == FK33_IP6 || kind == FK33_IP6_B) ? 0x60 : 0x45;
	if (off == 8 && len >= 2)
		imm[1] = 0x11;	/* keep byte 9 (protocol) as the frame has it */
}

/* ---------- one envelope ---------- */

struct f556_env {
	const char *tag;
	uint8_t fam;
	const char *table;
	const char *chain;
	uint32_t hook;
	uint32_t base;
	const char *dev;	/* where the frame is injected */
	const char *rule_dev;	/* NFTA_HOOK_DEV, netdev only */
	int kind;		/* default frame kind */
};

static int NFL33 = -1;
static char PRE33[96];

static long f33_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000L + tv.tv_usec / 1000;
}

static unsigned long long f556_arm(const struct f556_env *e, const char *tag,
				   int off, int len, const unsigned char *imm,
				   int immlen, int kind)
{
	unsigned char fr[256], pay[192];
	unsigned long long cnt, cnt0;
	int flen, n = 0, rc, i;
	long t0, t1, t2, t3, t4;

	flen = f556_frame(kind, fr);
	snprintf(PRE33, sizeof(PRE33), "f33.%s.%s", e->tag, tag);
	t0 = f33_ms();
	flush_chain(e->fam, e->table, e->chain);
	t1 = f33_ms();
	rc = f556_install_store(e->fam, e->table, e->chain, e->base,
				(uint32_t)off, (uint32_t)len, imm, immlen,
				5, PRE33);
	t2 = f33_ms();
	nfl_drain(NFL33);
	cnt0 = (rc == 0) ? f555_count(e->fam, e->table, e->chain) : 0;
	if (rc == 0) {
		usleep(15000);
		pkt_send_p(e->dev, fr, flen, f556_proto(kind));
		n = nfl_wait(NFL33, PRE33, pay, (int)sizeof(pay), 200);
	}
	t3 = f33_ms();
	cnt = f555_count(e->fam, e->table, e->chain);
	t4 = f33_ms();
	printf("F556 R|env=%s|arm=%s|off=%d|len=%d|kind=%d|rc=%d|cnt=%llu|cnt0=%llu|"
	       "nfl=%d|ms=%ld,%ld,%ld,%ld|hex=",
	       e->tag, tag, off, len, kind, rc, cnt, cnt0, n, t1 - t0, t2 - t1,
	       t3 - t2, t4 - t3);
	for (i = 0; i < n && i < 96; i++)
		printf("%02x", pay[i]);
	printf("\n");
	return cnt;
}

static void f556_ctl(const struct f556_env *e, int kind)
{
	unsigned char fr[256], pay[192];
	unsigned long long cnt, cnt0;
	int flen, n, rc, i;

	flen = f556_frame(kind, fr);
	snprintf(PRE33, sizeof(PRE33), "f33.%s.ctl", e->tag);
	flush_chain(e->fam, e->table, e->chain);
	rc = install_ctl(e->fam, e->table, e->chain, 5, PRE33);
	nfl_drain(NFL33);
	n = 0;
	cnt0 = (rc == 0) ? f555_count(e->fam, e->table, e->chain) : 0;
	if (rc == 0) {
		usleep(15000);
		pkt_send_p(e->dev, fr, flen, f556_proto(kind));
		n = nfl_wait(NFL33, PRE33, pay, (int)sizeof(pay), 300);
	}
	cnt = f555_count(e->fam, e->table, e->chain);
	printf("F556 CTL|env=%s|kind=%d|rc=%d|cnt=%llu|cnt0=%llu|nfl=%d|hex=",
	       e->tag, kind, rc, cnt, cnt0, n);
	for (i = 0; i < n && i < 96; i++)
		printf("%02x", pay[i]);
	printf("\n");
}

/* create the table and the one chain this envelope owns */
static int f556_chain(const struct f556_env *e)
{
	int rc, rc2;

	rc = add_table(e->fam, e->table);
	rc2 = f556_add_chain(e->fam, e->table, e->chain, e->hook, 0, 1,
			     e->rule_dev);
	printf("F556 CHAIN|env=%s|table=%d|chain=%d\n", e->tag, rc, rc2);
	return rc || rc2;
}

static void f556_env_run(const struct f556_env *e)
{
	unsigned char imm[16];
	char tag[32];
	int i, j;

	f556_ctl(e, e->kind);
	for (i = 0; i < G33_NOFF; i++) {
		for (j = 0; j < G33_NLEN; j++) {
			f556_imm(e->kind, G33_OFF[i], G33_LEN[j], imm);
			snprintf(tag, sizeof(tag), "g%d_%d", G33_OFF[i], G33_LEN[j]);
			f556_arm(e, tag, G33_OFF[i], G33_LEN[j], imm, G33_LEN[j],
				 e->kind);
		}
	}
	for (i = 0; i < G33_NEXT; i++) {
		f556_imm(e->kind, G33_XOFF[i], G33_XLEN[i], imm);
		snprintf(tag, sizeof(tag), "x%d_%d", G33_XOFF[i], G33_XLEN[i]);
		f556_arm(e, tag, G33_XOFF[i], G33_XLEN[i], imm, G33_XLEN[i],
			 e->kind);
	}
	sh("/nft flush ruleset");
}

/* ---------- environment ---------- */

static int HAVE33_IP, HAVE33_IP6, HAVE33_NETDEV, HAVE33_BRIDGE, HAVE33_ARP;

static void f556_fams(void)
{
	struct { const char *n; uint8_t f; int *have; } fams[] = {
		{ "ip",     NFPROTO_IPV4,   &HAVE33_IP },
		{ "ip6",    NFPROTO_IPV6,   &HAVE33_IP6 },
		{ "netdev", NFPROTO_NETDEV, &HAVE33_NETDEV },
		{ "bridge", NFPROTO_BRIDGE, &HAVE33_BRIDGE },
		{ "arp",    NFPROTO_ARP,    &HAVE33_ARP },
	};
	char cmd[256];
	int i;

	sh("/nft flush ruleset");
	for (i = 0; i < (int)(sizeof(fams) / sizeof(fams[0])); i++) {
		int rc = add_table(fams[i].f, "p33probe");

		*fams[i].have = (rc == 0);
		printf("F556 FAM|%s|%d\n", fams[i].n, rc);
		if (rc == 0) {
			snprintf(cmd, sizeof(cmd), "/nft delete table %s p33probe",
				 fams[i].n);
			sh(cmd);
		}
	}
}

static int f556_env_setup(void)
{
	int rc = 0;

	if (link_add_veth("i0", "i1"))
		rc |= 1;
	if (link_add_veth("s0", "s1"))
		rc |= 2;
	if (link_add_veth("r0", "r1"))
		rc |= 4;
	set_up("i0"); set_up("i1");
	set_up("s0"); set_up("s1");
	set_up("r0"); set_up("r1");
	set_up("lo");
	if (f556_link_add_kind("br0", "bridge"))
		rc |= 8;
	set_up("br0");
	if (f556_link_enslave("s1", "br0") || f556_link_enslave("r1", "br0"))
		rc |= 16;
	printf("F556 SETUP|rc=%d|i1=%d|s1=%d|r1=%d|br0=%d\n", rc,
	       f555_ifindex("i1"), f555_ifindex("s1"), f555_ifindex("r1"),
	       f555_ifindex("br0"));
	return rc;
}

/* ---------- the nine envelopes ---------- */

static void f556_sec(const char *only)
{
	struct f556_env e;

	/* ---- 1. family ip, base nh: nft_nh_write_ok_ip4() ---- */
	if (!only || !strcmp(only, "ip4")) {
		memset(&e, 0, sizeof(e));
		e.tag = "ip4"; e.fam = NFPROTO_IPV4; e.table = "p33f";
		e.chain = "pre"; e.hook = 0;	/* NF_INET_PRE_ROUTING */
		e.base = NFT_PAYLOAD_NETWORK_HEADER; e.dev = "i0"; e.kind = FK33_IP4;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	/* ---- 2. family ip6, base nh: nft_nh_write_ok_ip6() ---- */
	if (!only || !strcmp(only, "ip6")) {
		memset(&e, 0, sizeof(e));
		e.tag = "ip6"; e.fam = NFPROTO_IPV6; e.table = "p33g";
		e.chain = "pre"; e.hook = 0;
		e.base = NFT_PAYLOAD_NETWORK_HEADER; e.dev = "i0"; e.kind = FK33_IP6;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	/* ---- 3. family netdev, ingress: NFPROTO_NETDEV + ingress -> true ---- */
	if (!only || !strcmp(only, "nd")) {
		memset(&e, 0, sizeof(e));
		e.tag = "nd"; e.fam = NFPROTO_NETDEV; e.table = "p33n";
		e.chain = "ing"; e.hook = 0;	/* NF_NETDEV_INGRESS */
		e.base = NFT_PAYLOAD_NETWORK_HEADER; e.dev = "i0";
		e.rule_dev = "i1"; e.kind = FK33_IP4;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	/* ---- 3b. family netdev, EGRESS: nft_nh_write_ok_netdev() ----
	 * F31 called this branch dead code because "netdev has only the
	 * ingress hook".  uapi/linux/netfilter.h has NF_NETDEV_INGRESS then
	 * NF_NETDEV_EGRESS, and nft_chain_filter_netdev's hook_mask has BOTH,
	 * so the branch is reachable -- and at egress the guard is the
	 * switch on skb->protocol, not the constant.  Two labels, two
	 * shapes, same chain. */
	if (!only || !strcmp(only, "eg4")) {
		memset(&e, 0, sizeof(e));
		e.tag = "eg4"; e.fam = NFPROTO_NETDEV; e.table = "p33q";
		e.chain = "egr"; e.hook = 1;	/* NF_NETDEV_EGRESS */
		e.base = NFT_PAYLOAD_NETWORK_HEADER; e.dev = "i0";
		e.rule_dev = "i0"; e.kind = FK33_IP4;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	if (!only || !strcmp(only, "egA")) {
		memset(&e, 0, sizeof(e));
		e.tag = "egA"; e.fam = NFPROTO_NETDEV; e.table = "p33r";
		e.chain = "egr"; e.hook = 1;
		e.base = NFT_PAYLOAD_NETWORK_HEADER; e.dev = "i0";
		e.rule_dev = "i0"; e.kind = FK33_ARP;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	/* ---- 4. family bridge, ethertype 0x0800 ---- */
	if (!only || !strcmp(only, "br4")) {
		memset(&e, 0, sizeof(e));
		e.tag = "br4"; e.fam = NFPROTO_BRIDGE; e.table = "p33b";
		e.chain = "pre"; e.hook = 0;	/* NF_BR_PRE_ROUTING */
		e.base = NFT_PAYLOAD_NETWORK_HEADER; e.dev = "s0"; e.kind = FK33_IP4;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	/* ---- 5. family bridge, ethertype 0x0806 ---- */
	if (!only || !strcmp(only, "brA")) {
		memset(&e, 0, sizeof(e));
		e.tag = "brA"; e.fam = NFPROTO_BRIDGE; e.table = "p33c";
		e.chain = "pre"; e.hook = 0;
		e.base = NFT_PAYLOAD_NETWORK_HEADER; e.dev = "s0"; e.kind = FK33_ARP;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	/* ---- 6. family arp, hook input: nft_nh_write_ok_arp() ---- */
	if (!only || !strcmp(only, "arp")) {
		memset(&e, 0, sizeof(e));
		e.tag = "arp"; e.fam = NFPROTO_ARP; e.table = "p33a";
		e.chain = "in"; e.hook = 0;	/* NF_ARP_IN */
		e.base = NFT_PAYLOAD_NETWORK_HEADER; e.dev = "i0"; e.kind = FK33_ARP;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	/* ---- 7..9. base ll in three envelopes: nft_ll_write_ok() ---- */
	if (!only || !strcmp(only, "ll4")) {
		memset(&e, 0, sizeof(e));
		e.tag = "ll4"; e.fam = NFPROTO_IPV4; e.table = "p33h";
		e.chain = "pre"; e.hook = 0;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0"; e.kind = FK33_IP4;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	if (!only || !strcmp(only, "llN")) {
		memset(&e, 0, sizeof(e));
		e.tag = "llN"; e.fam = NFPROTO_NETDEV; e.table = "p33i";
		e.chain = "ing"; e.hook = 0;	/* NF_NETDEV_INGRESS */
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0"; e.rule_dev = "i1";
		e.kind = FK33_IP4;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	if (!only || !strcmp(only, "llE")) {
		memset(&e, 0, sizeof(e));
		e.tag = "llE"; e.fam = NFPROTO_NETDEV; e.table = "p33s";
		e.chain = "egr"; e.hook = 1;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0"; e.rule_dev = "i0";
		e.kind = FK33_IP4;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
	if (!only || !strcmp(only, "llB")) {
		memset(&e, 0, sizeof(e));
		e.tag = "llB"; e.fam = NFPROTO_BRIDGE; e.table = "p33j";
		e.chain = "pre"; e.hook = 0;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "s0"; e.kind = FK33_IP4;
		if (!f556_chain(&e))
			f556_env_run(&e);
	}
}

/* ---------- E arms: does the branch read the PACKET, or the VALUE? ---------- */

static void f556_sec_e(void)
{
	struct f556_env e;
	unsigned char imm[16];

	/* ip4, offset 0, len 2: the guard compares the WRITTEN first byte with
	 * the one in the packet (nft_nh_write_ok_ip4 case 0, skb_copy_bits).
	 * Same rule, two valid datagrams: ihl 5 (0x45) and ihl 6 (0x46). */
	f556_imm(FK33_IP4, 0, 2, imm);
	imm[0] = 0x45;
	memset(&e, 0, sizeof(e));
	e.tag = "e4"; e.fam = NFPROTO_IPV4; e.table = "p33k";
	e.chain = "pre"; e.hook = 0; e.base = NFT_PAYLOAD_NETWORK_HEADER;
	e.dev = "i0"; e.kind = FK33_IP4;
	if (f556_chain(&e)) {
		printf("F556 E|SKIP=e4-chain\n");
		return;
	}
	f556_arm(&e, "ip4_0_2_ihl5", 0, 2, imm, 2, FK33_IP4);
	f556_arm(&e, "ip4_0_2_ihl6", 0, 2, imm, 2, FK33_IP4_IHL6);
	/* ip4, offset 8, len 2: the guard compares the written SECOND byte with
	 * the protocol byte of the packet.  imm[1] = 0x11, so a proto-17 frame
	 * passes and a proto-6 frame does not -- same rule, other frame. */
	f556_imm(FK33_IP4, 8, 2, imm);
	f556_arm(&e, "ip4_8_2_p17", 8, 2, imm, 2, FK33_IP4);
	f556_arm(&e, "ip4_8_2_p6", 8, 2, imm, 2, FK33_IP4_P6);
	sh("/nft flush ruleset");

	/* ip6, offset 0: nft_nh_write_ok_ip6 case 0 tests ih->version of the
	 * WRITTEN data, not of the packet.  So the VALUE must decide and the
	 * FRAME must not: 0x60 alive on both frames, 0x40 dead on both. */
	memset(&e, 0, sizeof(e));
	e.tag = "e6"; e.fam = NFPROTO_IPV6; e.table = "p33l";
	e.chain = "pre"; e.hook = 0; e.base = NFT_PAYLOAD_NETWORK_HEADER;
	e.dev = "i0"; e.kind = FK33_IP6;
	if (f556_chain(&e)) {
		printf("F556 E|SKIP=e6-chain\n");
		return;
	}
	memset(imm, 0, sizeof(imm));
	imm[0] = 0x60; imm[1] = 0x11; imm[2] = 0x22; imm[3] = 0x33;
	f556_arm(&e, "ip6_0_4_v6_a", 0, 4, imm, 4, FK33_IP6);
	f556_arm(&e, "ip6_0_4_v6_b", 0, 4, imm, 4, FK33_IP6_B);
	imm[0] = 0x40;
	f556_arm(&e, "ip6_0_4_v4_a", 0, 4, imm, 4, FK33_IP6);
	f556_arm(&e, "ip6_0_4_v4_b", 0, 4, imm, 4, FK33_IP6_B);
	sh("/nft flush ruleset");

	/* the envelope decides before the guard: an ARP-family chain never sees
	 * an IPv4 frame at all (arp_rcv is not on that path). */
	memset(&e, 0, sizeof(e));
	e.tag = "ea"; e.fam = NFPROTO_ARP; e.table = "p33m";
	e.chain = "in"; e.hook = 0; e.base = NFT_PAYLOAD_NETWORK_HEADER;
	e.dev = "i0"; e.kind = FK33_ARP;
	if (f556_chain(&e)) {
		printf("F556 E|SKIP=ea-chain\n");
		return;
	}
	f556_imm(FK33_ARP, 8, 2, imm);
	f556_arm(&e, "arp_fam_arpframe", 8, 2, imm, 2, FK33_ARP);
	f556_arm(&e, "arp_fam_ipv4frame", 8, 2, imm, 2, FK33_IP4);
	sh("/nft flush ruleset");

	/* the switch, measured by the same cell under two labels: (6,2) is in
	 * the ARP predicate and in none of the IPv4 case labels. */
	memset(&e, 0, sizeof(e));
	e.tag = "eb"; e.fam = NFPROTO_BRIDGE; e.table = "p33o";
	e.chain = "pre"; e.hook = 0; e.base = NFT_PAYLOAD_NETWORK_HEADER;
	e.dev = "s0"; e.kind = FK33_IP4;
	if (f556_chain(&e)) {
		printf("F556 E|SKIP=eb-chain\n");
		return;
	}
	f556_imm(FK33_IP4, 6, 2, imm);
	f556_arm(&e, "br_6_2_ip", 6, 2, imm, 2, FK33_IP4);
	f556_arm(&e, "br_6_2_arp", 6, 2, imm, 2, FK33_ARP);
	f556_arm(&e, "br_6_4_arp", 6, 4, imm, 4, FK33_ARP);
	sh("/nft flush ruleset");
}

/* ---------- diagnostic: why does the ingress chain not count ---------- */

static void f556_diag_nd(void)
{
	unsigned char fr[256];
	unsigned long long cnt;
	int flen, rc;

	flen = f556_frame(FK33_IP4, fr);
	sh("/nft flush ruleset");

	/* D1: ingress (NF_NETDEV_INGRESS = 0) on i1, frame sent from i0 */
	printf("F556 DN|table_i|%d\n", add_table(NFPROTO_NETDEV, "p33di"));
	rc = f556_add_chain(NFPROTO_NETDEV, "p33di", "ing", 0, 0, 1, "i1");
	printf("F556 DN|chain_ingress|%d\n", rc);
	nft("dn.list_ing", "/nft list chain netdev p33di ing");
	printf("F556 DN|ctl_ing|%d\n",
	       install_ctl(NFPROTO_NETDEV, "p33di", "ing", 5, "dn.ing"));
	nfl_drain(NFL33);
	usleep(20000);
	pkt_send_p("i0", fr, flen, 0x0800);
	cnt = f555_count(NFPROTO_NETDEV, "p33di", "ing");
	printf("F556 DN|ctl_ingress_cnt|%llu\n", cnt);

	/* D2: egress (NF_NETDEV_EGRESS = 1) on i0, frame sent from i0 */
	sh("/nft flush ruleset");
	printf("F556 DN|table_e|%d\n", add_table(NFPROTO_NETDEV, "p33de"));
	rc = f556_add_chain(NFPROTO_NETDEV, "p33de", "egr", 1, 0, 1, "i0");
	printf("F556 DN|chain_egress|%d\n", rc);
	nft("dn.list_egr", "/nft list chain netdev p33de egr");
	printf("F556 DN|ctl_egr|%d\n",
	       install_ctl(NFPROTO_NETDEV, "p33de", "egr", 5, "dn.egr"));
	nfl_drain(NFL33);
	usleep(20000);
	pkt_send_p("i0", fr, flen, 0x0800);
	cnt = f555_count(NFPROTO_NETDEV, "p33de", "egr");
	printf("F556 DN|ctl_egress_cnt|%llu\n", cnt);

	/* D3: the same egress chain written by nft itself, for comparison */
	sh("/nft flush ruleset");
	nft("dn.table_nft", "/nft add table netdev p33df");
	nft("dn.chain_nft", "/nft add chain netdev p33df egr '{ type filter hook egress device i0 priority 0; }'");
	nft("dn.rule_nft", "/nft add rule netdev p33df egr 'counter accept'");
	usleep(20000);
	pkt_send_p("i0", fr, flen, 0x0800);
	nft("dn.after_egr", "/nft list chain netdev p33df egr");

	/* D4: and the ingress chain written by nft, as F31 did */
	sh("/nft flush ruleset");
	nft("dn.table_nft2", "/nft add table netdev p33dg");
	nft("dn.chain_nft2", "/nft add chain netdev p33dg ing '{ type filter hook ingress device i1 priority 0; }'");
	nft("dn.rule_nft2", "/nft add rule netdev p33dg ing 'counter accept'");
	usleep(20000);
	pkt_send_p("i0", fr, flen, 0x0800);
	nft("dn.after_ing", "/nft list chain netdev p33dg ing");
	sh("/nft flush ruleset");
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "f556";
	const char *only = argc > 2 ? argv[2] : NULL;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F556 BEGIN|mode=%s|only=%s\n", mode, only ? only : "-");
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F556 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	if (!strcmp(mode, "f556bare")) {
		printf("F556 DONE\n");
		return 0;
	}
	if (!HAVE33_IP || !HAVE33_IP6 || !HAVE33_NETDEV || !HAVE33_BRIDGE ||
	    !HAVE33_ARP)
		printf("F556 WARN|missing_family|ip=%d|ip6=%d|nd=%d|br=%d|arp=%d\n",
		       HAVE33_IP, HAVE33_IP6, HAVE33_NETDEV, HAVE33_BRIDGE,
		       HAVE33_ARP);
	f556_env_setup();
	NFL33 = nfl_open(5);
	printf("F556 NFL|%d\n", NFL33);
	if (!strncmp(mode, "f556one:", 8)) {
		f556_sec(mode + 8);
		printf("F556 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f556nd")) {
		f556_diag_nd();
		printf("F556 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f556e")) {
		f556_sec("ip4");
		f556_sec_e();
		printf("F556 DONE\n");
		return 0;
	}
	f556_sec(only);
	if (!only)
		f556_sec_e();
	printf("F556 DONE\n");
	return 0;
}
