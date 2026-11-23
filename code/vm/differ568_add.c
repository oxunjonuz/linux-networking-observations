/* ==========================================================================
 * Turn 568 -- F46: the EGRESS doors.
 *
 * F44/F45 asked where `@th` lands and found one coordinate behind five doors.
 * Every door so far was an INGRESS door, and every frame arrived from the
 * wire.  This turn asks the mirror question on the way out:
 *
 *   where is the MAC header, and who pays for a write into the IP header?
 *
 * Source, read before any measurement:
 *   __ip_local_out():   ip_send_check(iph) BEFORE nf_hook(LOCAL_OUT)
 *   ip_forward():       ip_decrease_ttl()  BEFORE nf_hook(FORWARD)
 *   ip_rcv():           ip_rcv_core() (header csum) BEFORE nf_hook(PRE_ROUTING)
 *   __dev_queue_xmit(): skb_reset_mac_header() is its FIRST statement
 *   eth_header():       skb_push(ETH_HLEN) + writes all 14 bytes, no mac_reset
 *   eth_type_trans():   skb_reset_mac_header() on receive
 *   nft_payload_set_eval(): @ll offset = mac_header - data, guard len+off <= net_off
 *                           @nh offset = skb_network_offset (no nhoff)
 *   nft_payload_csum_inet(): incremental -- read the csum at csum_offset,
 *                            add the delta, store, THEN store the immediate
 *
 * Three traffic classes, one receiver in its own netns (pipe protocol):
 *   loc -- socket 10.10.0.1:40000 -> 10.10.0.2:5000, out x0
 *   fwd -- frame injected on o0, dst 10.10.0.2, received on o1, forwarded via x0
 *   in  -- frame injected on y0, dst 10.11.0.2 (local on y1), delivered here
 *
 * differ568.c is GENERATED: differ567.c with its main() renamed, plus this
 * file.  The netlink toolkit, veth/rtnetlink helpers, NFLOG reader, AF_PACKET
 * capture and counter read-back are the ones that produced F31..F45.
 * ========================================================================== */

#define NFULA_L2HDR_	21
#define F568_CSUM_INET	1

/* ---------- doors ---------- */

struct f568_door {
	const char *tag;
	uint8_t fam;
	const char *table;
	const char *dev;
	uint32_t hook;
	int prio0, prio1;
};

#define NF_INET_PRE_	0
#define NF_INET_IN_	1
#define NF_INET_FWD_	2
#define NF_INET_OUT_	3
#define NF_INET_POST_	4
#define NF_NETDEV_EGR_	1

static struct f568_door D568[] = {
	{ "out",  NFPROTO_INET,   "e68a", NULL, NF_INET_OUT_,   10,  20 },
	{ "post", NFPROTO_INET,   "e68b", NULL, NF_INET_POST_,  30,  40 },
	{ "fwd",  NFPROTO_INET,   "e68c", NULL, NF_INET_FWD_,   50,  60 },
	{ "pre",  NFPROTO_INET,   "e68d", NULL, NF_INET_PRE_,   70,  80 },
	{ "lin",  NFPROTO_INET,   "e68e", NULL, NF_INET_IN_,    90, 100 },
	{ "egr",  NFPROTO_NETDEV, "e68f", "x0", NF_NETDEV_EGR_, 110, 120 },
};
#define ND68 6

enum { C_LOC = 0, C_FWD, C_IN, C_NK };
static const char *CLSN[C_NK] = { "loc", "fwd", "in" };

struct f568_pair { int door, cls; };
static struct f568_pair P568[] = {
	{ 0, C_LOC }, { 1, C_LOC }, { 5, C_LOC },
	{ 1, C_FWD }, { 2, C_FWD }, { 5, C_FWD }, { 3, C_FWD },
	{ 3, C_IN },  { 4, C_IN },
};
#define NP68 ((int)(sizeof(P568) / sizeof(P568[0])))

/* ---------- addresses ---------- */

#define A_X0	0x0a0a0001u	/* 10.10.0.1  x0  (sender side)      */
#define A_X1	0x0a0a0002u	/* 10.10.0.2  x1  (receiver netns)   */
#define A_Y1	0x0b0b0002u	/* 10.11.0.2  y1  (local delivery)   */
#define A_FS	0x0a080002u	/* 10.8.0.2   src of the fwd frame   */
#define A_IS	0x0a080302u	/* 10.8.3.2   src of the in frame    */

static const unsigned char F568_PAY[18] = {
	0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
	0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77
};

static int LOC_SOCK = -1;	/* 10.10.0.1:40000 -> 10.10.0.2:5000 */
static int IN_SOCK = -1;	/* bound 10.11.0.2:5000               */
static int P_W = -1, P_R = -1;	/* parent -> child, child -> parent   */
static pid_t CHILD = -1;

/* the reference frame of every (door, class): from the control arm */
static unsigned char REF568[ND68][C_NK][256];
static int REFLEN568[ND68][C_NK];

/* ---------- the receiver in its own netns ---------- */

struct f568_rep {
	int tapn, taplen;
	char taphex[600];
	int udpn, ulen0, usport0;
	char pay[40];
	unsigned long long ipin, ihdr, iaddr, ideliv;
	unsigned long long udpin, udperr, udpnoport, ipout, icmpin;
};

static int f568_needle(const unsigned char *b, int n)
{
	int i;

	for (i = 0; i + 8 <= n; i++)
		if (!memcmp(b + i, F568_PAY, 8))
			return 1;
	return 0;
}

static void f568_child_snap(int tapfd, int ufd, int wfd)
{
	unsigned char b[2048], last[512];
	int r, tapn = 0, lastlen = -1;
	int udpn = 0, ulen0 = -1, usport0 = -1;
	char pay[40] = "-", hx[600] = "-";

	while ((r = (int)recv(tapfd, b, sizeof(b), MSG_DONTWAIT)) > 0) {
		if (!f568_needle(b, r))
			continue;
		tapn++;
		/* keep the FIRST matching frame: a later one may be an ICMP
		 * error that quotes our payload (F46 smoke, port arms) */
		if (lastlen >= 0)
			continue;
		lastlen = r < (int)sizeof(last) ? r : (int)sizeof(last);
		memcpy(last, b, (size_t)lastlen);
	}
	for (;;) {
		struct sockaddr_in from;
		socklen_t fl = sizeof(from);

		memset(&from, 0, sizeof(from));
		r = (int)recvfrom(ufd, b, sizeof(b), MSG_DONTWAIT,
				  (struct sockaddr *)&from, &fl);
		if (r < 0)
			break;
		if (udpn == 0) {
			int k, n = r < 8 ? r : 8;
			char *o = pay;

			ulen0 = r;
			usport0 = (int)ntohs(from.sin_port);
			for (k = 0; k < n; k++)
				o += sprintf(o, "%02x", b[k]);
		}
		udpn++;
		if (udpn > 32)
			break;
	}
	if (lastlen > 0) {
		int k, n = lastlen < 200 ? lastlen : 200;
		char *o = hx;

		for (k = 0; k < n; k++)
			o += sprintf(o, "%02x", last[k]);
	}
	dprintf(wfd, "R|%d|%d|%s|%d|%d|%d|%s|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu\n",
		tapn, lastlen, hx, udpn, ulen0, usport0, pay,
		f564_snmp("Ip", "InReceives"), f564_snmp("Ip", "InHdrErrors"),
		f564_snmp("Ip", "InAddrErrors"), f564_snmp("Ip", "InDelivers"),
		f564_snmp("Udp", "InDatagrams"), f564_snmp("Udp", "InErrors"),
		f564_snmp("Udp", "NoPorts"), f564_snmp("Ip", "OutRequests"),
		f564_snmp("Icmp", "InMsgs"));
}

/* The child: unshare, wait for the device to be moved in, configure, serve. */
static void f568_child_loop(int rfd, int wfd)
{
	char cmd[64];
	int tapfd, ufd;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (unshare(CLONE_NEWNET) < 0) {
		dprintf(wfd, "E|unshare|%d\n", errno);
		_exit(1);
	}
	dprintf(wfd, "U\n");
	for (;;) {
		int n = (int)read(rfd, cmd, sizeof(cmd) - 1);

		if (n <= 0)
			_exit(2);
		cmd[n] = 0;
		if (cmd[0] == 'C')
			break;
	}
	set_up("lo");
	set_up("x1");
	dprintf(wfd, "A|%d\n", f555_addr_add("x1", htonl(A_X1), 24));
	{
		char p[96];

		snprintf(p, sizeof(p), "/proc/sys/net/ipv4/conf/x1/rp_filter");
		f555_sysctl(p, "0");
		snprintf(p, sizeof(p), "/proc/sys/net/ipv4/conf/all/rp_filter");
		f555_sysctl(p, "0");
		snprintf(p, sizeof(p), "/proc/sys/net/ipv4/conf/default/rp_filter");
		f555_sysctl(p, "0");
	}
	{
		struct sockaddr_in sa;
		int one = 1;

		ufd = socket(AF_INET, SOCK_DGRAM, 0);
		setsockopt(ufd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(INADDR_ANY);
		sa.sin_port = htons(5000);
		if (bind(ufd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
			dprintf(wfd, "E|bind|%d\n", errno);
	}
	tapfd = cap_open("x1");
	dprintf(wfd, "READY|%d|%d\n", tapfd, f555_ifindex("x1"));
	for (;;) {
		int n = (int)read(rfd, cmd, sizeof(cmd) - 1);

		if (n <= 0)
			_exit(3);
		cmd[n] = 0;
		if (cmd[0] == 'Q')
			_exit(0);
		if (cmd[0] == 'S')
			f568_child_snap(tapfd, ufd, wfd);
	}
}

/* ---------- parent side of the pipe ---------- */

static int f568_ask(const char *what)
{
	char c = what[0];
	ssize_t w;

	w = write(P_W, &c, 1);
	(void)w;
	return 0;
}

static int f568_read_line(char *out, int osz, int ms)
{
	struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
	fd_set rfds;
	int n = 0;

	out[0] = 0;
	for (;;) {
		char ch;
		int r;

		FD_ZERO(&rfds);
		FD_SET(P_R, &rfds);
		if (select(P_R + 1, &rfds, NULL, NULL, &tv) <= 0)
			return -1;
		r = (int)read(P_R, &ch, 1);
		if (r <= 0)
			return -1;
		if (ch == '\n')
			return n;
		if (n < osz - 1)
			out[n++] = ch;
		out[n] = 0;
	}
}

static int f568_split(char *line, char **f, int max)
{
	int n = 0;
	char *p = line;

	while (n < max) {
		char *b = strchr(p, '|');

		f[n++] = p;
		if (!b)
			break;
		*b = 0;
		p = b + 1;
	}
	return n;
}

/* returns 0 on success; fills R with the child's answer */
static int f568_snapshot(struct f568_rep *R)
{
	char line[2048], *f[24];
	int n;

	memset(R, 0, sizeof(*R));
	R->taplen = -1;
	R->ulen0 = -1;
	R->usport0 = -1;
	snprintf(R->taphex, sizeof(R->taphex), "-");
	snprintf(R->pay, sizeof(R->pay), "-");
	f568_ask("S");
	if (f568_read_line(line, (int)sizeof(line), 8000) < 0)
		return -1;
	n = f568_split(line, f, 24);
	if (n < 17 || f[0][0] != 'R')
		return -2;
	R->tapn = atoi(f[1]);
	R->taplen = atoi(f[2]);
	snprintf(R->taphex, sizeof(R->taphex), "%s", f[3]);
	R->udpn = atoi(f[4]);
	R->ulen0 = atoi(f[5]);
	R->usport0 = atoi(f[6]);
	snprintf(R->pay, sizeof(R->pay), "%s", f[7]);
	R->ipin = strtoull(f[8], NULL, 10);
	R->ihdr = strtoull(f[9], NULL, 10);
	R->iaddr = strtoull(f[10], NULL, 10);
	R->ideliv = strtoull(f[11], NULL, 10);
	R->udpin = strtoull(f[12], NULL, 10);
	R->udperr = strtoull(f[13], NULL, 10);
	R->udpnoport = strtoull(f[14], NULL, 10);
	R->ipout = strtoull(f[15], NULL, 10);
	R->icmpin = strtoull(f[16], NULL, 10);
	return 0;
}

/* ---------- moving a device into the child's netns ---------- */

static int f568_move_link(const char *dev, int pid)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[64];
	} req;
	struct nlattr *a;
	int fd, rc, idx = f555_ifindex(dev);

	if (idx < 0)
		return -1;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = idx;
	a = (struct nlattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
	a->nla_type = IFLA_NET_NS_PID;
	a->nla_len = NLA_HDRLEN + 4;
	memcpy((char *)a + NLA_HDRLEN, &pid, 4);
	req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + NLA_ALIGN(a->nla_len);
	fd = rtnl_open();
	if (fd < 0)
		return -2;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* A permanent neighbour for the receiver: without it the entry goes STALE
 * after base_reachable_time (15..45 s) and the next packet is queued behind an
 * ARP probe -- the smoke run lost a whole block of egress arms that way, and
 * the loss looked exactly like a refused store. */
static int f568_neigh_add(const char *dev, uint32_t dst_be,
			  const unsigned char *mac)
{
	struct {
		struct nlmsghdr nlh;
		struct ndmsg ndm;
		char attrs[64];
	} req;
	int fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.nlh.nlmsg_type = RTM_NEWNEIGH;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
	req.nlh.nlmsg_seq = 1;
	req.ndm.ndm_family = AF_INET;
	req.ndm.ndm_ifindex = f555_ifindex(dev);
	req.ndm.ndm_state = NUD_PERMANENT;
	attr_put(&req.nlh, NDA_DST, &dst_be, 4);
	attr_put(&req.nlh, NDA_LLADDR, mac, 6);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* ---------- frames ---------- */

static int f568_mkframe(unsigned char *out, const unsigned char *dmac,
			uint32_t sip, uint32_t dip, unsigned short sport,
			unsigned short dport)
{
	struct {
		unsigned char dmac[6], smac[6];
		unsigned short proto;
	} __attribute__((packed)) eth;
	struct {
		unsigned char vihl, tos;
		unsigned short tot;
		unsigned short id;
		unsigned short frag;
		unsigned char ttl, proto;
		unsigned short csum;
		uint32_t src, dst;
	} __attribute__((packed)) ip;
	struct {
		unsigned short sport, dport, len, csum;
	} __attribute__((packed)) udp;
	int o = 0, iplen = 20 + 8 + (int)sizeof(F568_PAY);
	unsigned char pseudo[12];

	memcpy(eth.dmac, dmac, 6);
	{
		static const unsigned char sm[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x68 };

		memcpy(eth.smac, sm, 6);
	}
	eth.proto = htons(0x0800);

	memset(&ip, 0, sizeof(ip));
	ip.vihl = 0x45;
	ip.tos = 0;
	ip.tot = htons((unsigned short)iplen);
	ip.id = htons(0x1234);
	ip.frag = 0;
	ip.ttl = 64;
	ip.proto = 17;
	ip.src = htonl(sip);
	ip.dst = htonl(dip);
	ip.csum = 0;
	ip.csum = htons(f556_csum(&ip, sizeof(ip)));

	udp.sport = htons(sport);
	udp.dport = htons(dport);
	udp.len = htons((unsigned short)(8 + sizeof(F568_PAY)));
	udp.csum = 0;
	memcpy(pseudo, &ip.src, 4);
	memcpy(pseudo + 4, &ip.dst, 4);
	pseudo[8] = 0;
	pseudo[9] = 17;
	memcpy(pseudo + 10, &udp.len, 2);	/* already network order in memory */
	{
		unsigned char buf[12 + 8 + sizeof(F568_PAY)];
		unsigned short cs;

		memcpy(buf, pseudo, 12);
		memcpy(buf + 12, &udp, 8);
		memcpy(buf + 20, F568_PAY, sizeof(F568_PAY));
		cs = f556_csum(buf, (int)sizeof(buf));
		if (cs == 0)
			cs = 0xffff;
		udp.csum = htons(cs);
	}

	memcpy(out + o, &eth, sizeof(eth));
	o += (int)sizeof(eth);
	memcpy(out + o, &ip, sizeof(ip));
	o += (int)sizeof(ip);
	memcpy(out + o, &udp, sizeof(udp));
	o += (int)sizeof(udp);
	memcpy(out + o, F568_PAY, sizeof(F568_PAY));
	o += (int)sizeof(F568_PAY);
	return o;
}

static unsigned char X1_MAC[6];	/* read before x1 leaves this netns */
static int FWD_FRAME_LEN = -1, IN_FRAME_LEN = -1;
static unsigned char FWD_FRAME[128], IN_FRAME[128];

/* ---------- chains and rules ---------- */

static int f568_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND68; i++) {
		struct f568_door *D = &D568[i];

		rc |= add_table(D->fam, D->table);
		rc |= f556_add_chain(D->fam, D->table, "pre0", D->hook,
				     (uint32_t)D->prio0, 1, D->dev);
		rc |= f556_add_chain(D->fam, D->table, "ch", D->hook,
				     (uint32_t)D->prio1, 1, D->dev);
	}
	return rc;
}

static void f568_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND68; i++) {
		f557_flush(D568[i].fam, D568[i].table, "pre0", &acks);
		f557_flush(D568[i].fam, D568[i].table, "ch", &acks);
	}
}

/* mode 0: nothing; 1: store; 2: store, then read the same cell and compare
 * with the immediate ("did the write land?"); 3: read + compare. */
static int f568_rule(const struct f568_door *D, const char *chain,
		     const char *prefix, uint32_t base, int off, int len,
		     const unsigned char *imm, int mode, int csum, int cso,
		     int *acks)
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
	if (mode == 1 || mode == 2)
		f565_store(nlh, base, (uint32_t)off, (uint32_t)len, imm, csum, (unsigned int)cso);
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

/* ---------- NFLOG ---------- */

struct f568_log {
	int seen;
	int l2;
	int plen;
	unsigned char p[128];
};

static void f568_parse_log(unsigned char *buf, int len, struct f568_log *pre,
			   struct f568_log *post)
{
	struct nlmsghdr *h;

	for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
		const char *p, *end, *prefix = NULL;
		const unsigned char *pl = NULL;
		int pll = 0, l2 = 0;

		if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
			continue;
		p = (const char *)h + NLMSG_HDRLEN + sizeof(struct nfgenmsg);
		end = (const char *)h + h->nlmsg_len;
		for (; p + (int)sizeof(struct nlattr) <= end; ) {
			const struct nlattr *a = (const struct nlattr *)p;
			int al = (int)a->nla_len;
			int t;

			if (al < (int)sizeof(*a) || p + al > end)
				break;
			t = a->nla_type & 0x3fff;
			if (t == NFULA_PREFIX_)
				prefix = (const char *)a + NLA_HDRLEN;
			else if (t == NFULA_PAYLOAD_) {
				pl = (const unsigned char *)a + NLA_HDRLEN;
				pll = al - NLA_HDRLEN;
			} else if (t == NFULA_L2HDR_)
				l2 = al - NLA_HDRLEN;
			p += NLA_ALIGN_(al);
		}
		if (!prefix || !pl)
			continue;
		if (prefix[0] == 'p') {
			pre->seen++;
			pre->l2 = l2;
			pre->plen = pll < (int)sizeof(pre->p) ? pll : (int)sizeof(pre->p);
			memcpy(pre->p, pl, (size_t)pre->plen);
		} else {
			post->seen++;
			post->l2 = l2;
			post->plen = pll < (int)sizeof(post->p) ? pll : (int)sizeof(post->p);
			memcpy(post->p, pl, (size_t)post->plen);
		}
	}
}

static void f568_logs(int fd, struct f568_log *pre, struct f568_log *post)
{
	unsigned char b[16384];
	int guard = 0, rl;

	memset(pre, 0, sizeof(*pre));
	memset(post, 0, sizeof(*post));
	if (fd < 0)
		return;
	while (guard++ < 64) {
		rl = (int)recv(fd, b, sizeof(b), MSG_DONTWAIT);
		if (rl <= 0)
			break;
		f568_parse_log(b, rl, pre, post);
	}
}

/* how many rules are in the chain right now?  f555_count() sums counters and
 * cannot see a rule that has not counted anything yet -- a rule left behind by
 * a failed flush, whose counter is 0, doubled the door counter in one arm and
 * the sum looked clean. */
static int f568_rule_count(uint8_t family, const char *table, const char *chain)
{
	char buf[1024], rbuf[65536];
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;
	int fd, sent, n = 0;

	fd = nl_open();
	if (fd < 0)
		return -1;
	{
		struct timeval tv = { .tv_sec = 0, .tv_usec = 120000 };

		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_HDRLEN + sizeof(*nfg);
	nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = 1;
	nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(0);
	attr_put(nlh, NFTA_RULE_TABLE, table, (int)strlen(table) + 1);
	attr_put(nlh, NFTA_RULE_CHAIN, chain, (int)strlen(chain) + 1);
	sent = (int)nlh->nlmsg_len;
	if (send(fd, buf, (size_t)sent, 0) != sent) {
		close(fd);
		return -2;
	}
	for (;;) {
		int rl = (int)recv(fd, rbuf, sizeof(rbuf), 0);
		struct nlmsghdr *h;

		if (rl <= 0)
			break;
		for (h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, rl); h = NLMSG_NEXT(h, rl)) {
			if (h->nlmsg_type == NLMSG_DONE) {
				close(fd);
				return n;
			}
			if (h->nlmsg_type == NLMSG_ERROR) {
				close(fd);
				return -3;
			}
			if (h->nlmsg_type == (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) |
							NFT_MSG_NEWRULE))
				n++;
		}
	}
	close(fd);
	return n;
}

/* ---------- one arm ---------- */

static int f568_parent_udp_drain(int *firstlen, int *sport, char *pay, int paysz)
{
	unsigned char b[512];
	int n = 0, r;

	if (firstlen)
		*firstlen = -1;
	if (sport)
		*sport = -1;
	if (pay && paysz > 0)
		pay[0] = 0;
	if (IN_SOCK < 0)
		return -1;
	for (;;) {
		struct sockaddr_in from;
		socklen_t fl = sizeof(from);
		int k, m;

		memset(&from, 0, sizeof(from));
		r = (int)recvfrom(IN_SOCK, b, sizeof(b), MSG_DONTWAIT,
				  (struct sockaddr *)&from, &fl);
		if (r < 0)
			break;
		if (n == 0 && firstlen) {
			char *o = pay;

			*firstlen = r;
			if (sport)
				*sport = (int)ntohs(from.sin_port);
			if (pay && paysz > 0) {
				m = r < 8 ? r : 8;
				for (k = 0; k < m; k++)
					o += sprintf(o, "%02x", b[k]);
			}
		}
		n++;
	}
	return n;
}

static void f568_arm(const char *sec, const struct f568_pair *P,
		     const char *arm, uint32_t base, int off, int len,
		     const unsigned char *imm, int mode, int csum, int cso,
		     int rfd)
{
	const struct f568_door *D = &D568[P->door];
	struct f568_rep r0, r1;
	struct f568_log pre, post;
	unsigned char rf[1024], cf[1024];
	char hi[160], hpre[300], hpost[300], hr[600], cw[600];
	unsigned long long cntp0, cnts0, cntp1, cnts1;
	unsigned long long pin0, phdr0, pdel0, puerr0;
	unsigned long long pin1, phdr1, pdel1, puerr1;
	unsigned long long pnr0, pout0, picmp0, picmpo0;
	unsigned long long pnr1, pout1, picmp1, picmpo1;
	int rcp, rcs, acks, snd, rn = 0, rchg = 0;
	int pr = 0, prlen = -1, prsport = -1;
	char prpay[40] = "-";
	int plen = 0;
	const char *cn = CLSN[P->cls];

	{
		int try, np, ns;

		for (try = 0; try < 4; try++) {
			f568_flush_all();
			np = f568_rule_count(D->fam, D->table, "pre0");
			ns = f568_rule_count(D->fam, D->table, "ch");
			if (np == 0 && ns == 0)
				break;
			printf("F568 RETRY2|sec=%s|door=%s|cls=%s|arm=%s|try=%d|np=%d|ns=%d\n",
			       sec, D->tag, cn, arm, try, np, ns);
		}
	}
	acks = 0;
	rcp = f568_rule(D, "pre0", "p", 0, 0, 0, NULL, 0, 0, 0, &acks);
	acks = 0;
	rcs = f568_rule(D, "ch", "s", base, off, len, imm, mode, csum, cso, &acks);

	nfl_drain(NFL67);
	if (rfd >= 0)
		cap_drain(rfd);
	f568_parent_udp_drain(NULL, NULL, NULL, 0);
	f568_snapshot(&r0);
	cntp0 = f555_count(D->fam, D->table, "pre0");
	cnts0 = f555_count(D->fam, D->table, "ch");
	if (cntp0 || cnts0) {
		/* a rule that survived the flush would double the door counter for
		 * every packet (measured once: cntp=3 for a single datagram) */
		printf("F568 RETRY|sec=%s|door=%s|cls=%s|arm=%s|c0p=%llu|c0s=%llu\n",
		       sec, D->tag, cn, arm, cntp0, cnts0);
		f568_flush_all();
		acks = 0;
		rcp = f568_rule(D, "pre0", "p", 0, 0, 0, NULL, 0, 0, 0, &acks);
		acks = 0;
		rcs = f568_rule(D, "ch", "s", base, off, len, imm, mode, csum, cso, &acks);
		cntp0 = f555_count(D->fam, D->table, "pre0");
		cnts0 = f555_count(D->fam, D->table, "ch");
	}
	pin0 = f564_snmp("Ip", "InReceives");
	phdr0 = f564_snmp("Ip", "InHdrErrors");
	pdel0 = f564_snmp("Ip", "InDelivers");
	puerr0 = f564_snmp("Udp", "InErrors");
	pnr0 = f567_netstat("IpExt", "InNoRoutes");
	pout0 = f564_snmp("Ip", "OutRequests");
	picmp0 = f564_snmp("Icmp", "InMsgs");
	picmpo0 = f564_snmp("Icmp", "OutMsgs");
	memset(&r1, 0, sizeof(r1));

	if (P->cls == C_LOC) {
		struct sockaddr_in sin;

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(A_X1);
		sin.sin_port = htons(5000);
		snd = (int)sendto(LOC_SOCK, F568_PAY, sizeof(F568_PAY), 0,
				  (struct sockaddr *)&sin, sizeof(sin));
	} else if (P->cls == C_FWD) {
		snd = pkt_send_p("o0", FWD_FRAME, FWD_FRAME_LEN, 0x0800);
	} else {
		snd = pkt_send_p("y0", IN_FRAME, IN_FRAME_LEN, 0x0800);
	}
	usleep(150000);
	pr = f568_parent_udp_drain(&prlen, &prsport, prpay, (int)sizeof(prpay));
	cntp1 = f555_count(D->fam, D->table, "pre0");
	cnts1 = f555_count(D->fam, D->table, "ch");
	pin1 = f564_snmp("Ip", "InReceives");
	phdr1 = f564_snmp("Ip", "InHdrErrors");
	pdel1 = f564_snmp("Ip", "InDelivers");
	puerr1 = f564_snmp("Udp", "InErrors");
	pnr1 = f567_netstat("IpExt", "InNoRoutes");
	pout1 = f564_snmp("Ip", "OutRequests");
	picmp1 = f564_snmp("Icmp", "InMsgs");
	picmpo1 = f564_snmp("Icmp", "OutMsgs");
	f568_logs(NFL67, &pre, &post);
	if (f568_snapshot(&r1) < 0)
		memset(&r1, 0, sizeof(r1));
	if (rfd >= 0) {
		int skip = 0, pt = -1;

		rn = f558_cap_match(rfd, rf, (int)sizeof(rf), 60, F568_PAY, 8,
				    &skip, &pt);
	}
	if (P->cls == C_IN) {
		/* no second wire: the reference is the frame we injected */
		rn = IN_FRAME_LEN;
		memcpy(rf, IN_FRAME, (size_t)IN_FRAME_LEN);
	}
	if (r1.taplen > 0 && strcmp(r1.taphex, "-")) {
		int k, nb = (int)strlen(r1.taphex) / 2;

		if (nb > (int)sizeof(rf))
			nb = (int)sizeof(rf);
		for (k = 0; k < nb; k++) {
			unsigned v;
			char hh[3] = { r1.taphex[2 * k], r1.taphex[2 * k + 1], 0 };

			if (sscanf(hh, "%x", &v) != 1)
				break;
			rf[k] = (unsigned char)v;
		}
		rn = k;
	}
	if (REFLEN568[P->door][P->cls] > 0 && rn > 0) {
		int cl = REFLEN568[P->door][P->cls];

		memcpy(cf, REF568[P->door][P->cls], (size_t)cl);
		rchg = f558_chg(cw, sizeof(cw), cf, cl, rf, rn);
	}
	if (mode == 0 && rn > 0) {
		memcpy(REF568[P->door][P->cls], rf, (size_t)rn);
		REFLEN568[P->door][P->cls] = rn;
	}
	plen = post.plen > 64 ? 64 : post.plen;

	printf("F568 A|sec=%s|door=%s|cls=%s|arm=%s|mode=%d|base=%u|off=%d|len=%d|"
	       "csum=%d|cso=%d|imm=%s|",
	       sec, D->tag, cn, arm, mode, (unsigned)base, off, len, csum, cso,
	       (len > 0 && imm) ? f559_hexs(hi, sizeof(hi), imm, len) : "-");
	printf("rcp=%d|rcs=%d|sendrc=%d|c0p=%llu|c0s=%llu|cntp=%llu|lives=%llu|",
	       rcp, rcs, snd, cntp0, cnts0, cntp1 - cntp0, cnts1 - cnts0);
	printf("tapn=%d|taplen=%d|tap=%s|", r1.tapn, r1.taplen, r1.taphex);
	printf("udpn=%d|ulen=%d|usport=%d|pay=%s|", r1.udpn, r1.ulen0,
	       r1.usport0, r1.pay);
	printf("ripin=%llu|rihdr=%llu|riaddr=%llu|rideliv=%llu|rudpin=%llu|"
	       "rudperr=%llu|rudpnp=%llu|ripout=%llu|ricmp=%llu|",
	       r1.ipin - r0.ipin, r1.ihdr - r0.ihdr, r1.iaddr - r0.iaddr,
	       r1.ideliv - r0.ideliv, r1.udpin - r0.udpin,
	       r1.udperr - r0.udperr, r1.udpnoport - r0.udpnoport,
	       r1.ipout - r0.ipout, r1.icmpin - r0.icmpin);
	printf("pin=%llu|phdr=%llu|pdeliv=%llu|puerr=%llu|precv=%d|prlen=%d|"
	       "prsport=%d|prpay=%s|",
	       pin1 - pin0, phdr1 - phdr0, pdel1 - pdel0, puerr1 - puerr0,
	       pr, prlen, prsport, prpay);
	printf("pnr=%llu|pout=%llu|picmp=%llu|picmpo=%llu|",
	       pnr1 - pnr0, pout1 - pout0, picmp1 - picmp0, picmpo1 - picmpo0);
	printf("npre=%d|prel2=%d|pre=%s|npost=%d|postl2=%d|postlen=%d|post=%s|",
	       pre.seen, pre.l2,
	       pre.seen ? f559_hexs(hpre, sizeof(hpre), pre.p, pre.plen) : "-",
	       post.seen, post.l2, plen,
	       post.seen ? f559_hexs(hpost, sizeof(hpost), post.p, plen) : "-");
	if (rn > 0)
		f559_hexs(hr, sizeof(hr), rf, rn < 200 ? rn : 200);
	printf("rn=%d|rchg=%d|rchgs=%s|rhex=%s\n", rn, rchg,
	       rchg > 0 ? cw : "-", rn > 0 ? hr : "-");
}

/* ---------- cells ---------- */

struct f568_spec {
	const char *arm;
	uint32_t base;
	int off, len;
	unsigned char imm[32];
};

/* the link-layer base: twelve cells, four of them past the guard's boundary */
static struct f568_spec L568[] = {
	{ "cz",  0, 0, 0, { 0 } },
	{ "l0_2",  NFT_PAYLOAD_LL_HEADER, 0, 2, { 0x90, 0x91 } },
	{ "l0_6",  NFT_PAYLOAD_LL_HEADER, 0, 6, { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95 } },
	{ "l2_4",  NFT_PAYLOAD_LL_HEADER, 2, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "l4_2",  NFT_PAYLOAD_LL_HEADER, 4, 2, { 0x90, 0x91 } },
	{ "l6_2",  NFT_PAYLOAD_LL_HEADER, 6, 2, { 0x90, 0x91 } },
	{ "l8_6",  NFT_PAYLOAD_LL_HEADER, 8, 6, { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95 } },
	{ "l10_2", NFT_PAYLOAD_LL_HEADER, 10, 2, { 0x90, 0x91 } },
	{ "l11_1", NFT_PAYLOAD_LL_HEADER, 11, 1, { 0x90 } },
	{ "l12_2", NFT_PAYLOAD_LL_HEADER, 12, 2, { 0x90, 0x91 } },
	{ "l13_1", NFT_PAYLOAD_LL_HEADER, 13, 1, { 0x90 } },
	{ "l12_4", NFT_PAYLOAD_LL_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "l14_2", NFT_PAYLOAD_LL_HEADER, 14, 2, { 0x90, 0x91 } },
};
#define NL68 ((int)(sizeof(L568) / sizeof(L568[0])))

/* the network base: every branch of nft_nh_write_ok_ip4() and cells it
 * does not name; two cells whose verdict reads the VALUE (offset 0) */
static struct f568_spec N568[] = {
	{ "nz",   0, 0, 0, { 0 } },
	{ "n0_2s", NFT_PAYLOAD_NETWORK_HEADER, 0, 2, { 0x45, 0x00 } },
	{ "n0_2t", NFT_PAYLOAD_NETWORK_HEADER, 0, 2, { 0x45, 0x10 } },
	{ "n0_2x", NFT_PAYLOAD_NETWORK_HEADER, 0, 2, { 0x90, 0x91 } },
	{ "n0_1",  NFT_PAYLOAD_NETWORK_HEADER, 0, 1, { 0x45 } },
	{ "n1_1",  NFT_PAYLOAD_NETWORK_HEADER, 1, 1, { 0x90 } },
	{ "n2_2",  NFT_PAYLOAD_NETWORK_HEADER, 2, 2, { 0x90, 0x91 } },
	{ "n4_2",  NFT_PAYLOAD_NETWORK_HEADER, 4, 2, { 0x90, 0x91 } },
	{ "n6_2",  NFT_PAYLOAD_NETWORK_HEADER, 6, 2, { 0x90, 0x91 } },
	{ "n8_1",  NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x90 } },
	{ "n8_1s", NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x40 } },
	{ "n8_2p", NFT_PAYLOAD_NETWORK_HEADER, 8, 2, { 0x90, 0x11 } },
	{ "n8_2x", NFT_PAYLOAD_NETWORK_HEADER, 8, 2, { 0x90, 0x91 } },
	{ "n9_1",  NFT_PAYLOAD_NETWORK_HEADER, 9, 1, { 0x90 } },
	{ "n10_2", NFT_PAYLOAD_NETWORK_HEADER, 10, 2, { 0x90, 0x91 } },
	{ "n10_10", NFT_PAYLOAD_NETWORK_HEADER, 10, 10,
	  { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99 } },
	{ "n12_4", NFT_PAYLOAD_NETWORK_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n12_8", NFT_PAYLOAD_NETWORK_HEADER, 12, 8,
	  { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 } },
	{ "n14_2", NFT_PAYLOAD_NETWORK_HEADER, 14, 2, { 0x90, 0x91 } },
	{ "n16_4", NFT_PAYLOAD_NETWORK_HEADER, 16, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n16_8", NFT_PAYLOAD_NETWORK_HEADER, 16, 8,
	  { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 } },
	{ "n20_2", NFT_PAYLOAD_NETWORK_HEADER, 20, 2, { 0x90, 0x91 } },
};
#define NN68 ((int)(sizeof(N568) / sizeof(N568[0])))

/* the transport base: F43's eight cells */
static struct f568_spec T568[] = {
	{ "tz",  0, 0, 0, { 0 } },
	{ "t0_2",  NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x90, 0x91 } },
	{ "t2_2",  NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x90, 0x91 } },
	{ "t4_2",  NFT_PAYLOAD_TRANSPORT_HEADER, 4, 2, { 0x90, 0x91 } },
	{ "t6_2",  NFT_PAYLOAD_TRANSPORT_HEADER, 6, 2, { 0x90, 0x91 } },
	{ "t8_2",  NFT_PAYLOAD_TRANSPORT_HEADER, 8, 2, { 0x90, 0x91 } },
	{ "t0_4",  NFT_PAYLOAD_TRANSPORT_HEADER, 0, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "t12_4", NFT_PAYLOAD_TRANSPORT_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "t16_2", NFT_PAYLOAD_TRANSPORT_HEADER, 16, 2, { 0x90, 0x91 } },
};
#define NT68 ((int)(sizeof(T568) / sizeof(T568[0])))

/* the repair arms: one cell, one immediate, and the csum attribute */
struct f568_csum {
	const char *arm;
	uint32_t base;
	int off, len;
	unsigned char imm[8];
	int csum, cso;
};

static struct f568_csum C568[] = {
	{ "r_ttl0",  NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x90 }, 0, 0 },
	{ "r_ttl12", NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x90 }, F568_CSUM_INET, 12 },
	{ "r_ttl10", NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x90 }, F568_CSUM_INET, 10 },
	{ "r_ttl6",  NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x90 }, F568_CSUM_INET, 6 },
	{ "r_tos0",  NFT_PAYLOAD_NETWORK_HEADER, 1, 1, { 0x90 }, 0, 0 },
	{ "r_tos12", NFT_PAYLOAD_NETWORK_HEADER, 1, 1, { 0x90 }, F568_CSUM_INET, 12 },
	{ "r_tos10", NFT_PAYLOAD_NETWORK_HEADER, 1, 1, { 0x90 }, F568_CSUM_INET, 10 },
	{ "r_src0",  NFT_PAYLOAD_NETWORK_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 }, 0, 0 },
	{ "r_src12", NFT_PAYLOAD_NETWORK_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 }, F568_CSUM_INET, 12 },
	{ "r_src10", NFT_PAYLOAD_NETWORK_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 }, F568_CSUM_INET, 10 },
	{ "r_src6",  NFT_PAYLOAD_NETWORK_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 }, F568_CSUM_INET, 6 },
	{ "r_chk10", NFT_PAYLOAD_NETWORK_HEADER, 10, 2, { 0x90, 0x91 }, F568_CSUM_INET, 10 },
	{ "r_chk12", NFT_PAYLOAD_NETWORK_HEADER, 10, 2, { 0x90, 0x91 }, F568_CSUM_INET, 12 },
	{ "r_port6", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x90, 0x91 }, F568_CSUM_INET, 6 },
	{ "r_port0", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x90, 0x91 }, 0, 0 },
	{ "r_sport6", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x90, 0x91 }, F568_CSUM_INET, 6 },
	{ "r_sport0", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x90, 0x91 }, 0, 0 },
	{ "r_pay6",  NFT_PAYLOAD_TRANSPORT_HEADER, 8, 2, { 0x90, 0x91 }, F568_CSUM_INET, 6 },
	{ "r_pay0",  NFT_PAYLOAD_TRANSPORT_HEADER, 8, 2, { 0x90, 0x91 }, 0, 0 },
};
#define NC68 ((int)(sizeof(C568) / sizeof(C568[0])))

/* read-only cells at the egress door: does the read land on the same byte the
 * store writes when nhoff == 0? */
struct f568_rd {
	const char *arm;
	uint32_t base;
	int off, len;
	unsigned char imm[8];
};

static struct f568_rd R568[] = {
	{ "q_ttl", NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x40 } },
	{ "q_ver", NFT_PAYLOAD_NETWORK_HEADER, 0, 2, { 0x45, 0x00 } },
	{ "q_ttl_x", NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x99 } },
	{ "q_src", NFT_PAYLOAD_NETWORK_HEADER, 12, 4, { 0x0a, 0x0a, 0x00, 0x01 } },
	{ "q_dst", NFT_PAYLOAD_NETWORK_HEADER, 16, 4, { 0x0a, 0x0a, 0x00, 0x02 } },
	{ "q_sport", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x9c, 0x40 } },
};
#define NR68 ((int)(sizeof(R568) / sizeof(R568[0])))

/* ---------- sections ---------- */

/* A. the reference frame of every (door, class) */
static void f568_sec_ctl(int rfd)
{
	int i;

	for (i = 0; i < NP68; i++) {
		f568_arm("ctl", &P568[i], "ctl", 0, 0, 0, NULL, 0, 0, 0, rfd);
		f568_arm("ctl", &P568[i], "ctl2", 0, 0, 0, NULL, 0, 0, 0, rfd);
	}
}

/* B. the link-layer base on every door */
static void f568_sec_ll(int rfd)
{
	int i, k;

	for (i = 0; i < NP68; i++)
		for (k = 1; k < NL68; k++)
			f568_arm("ll", &P568[i], L568[k].arm, L568[k].base,
				 L568[k].off, L568[k].len, L568[k].imm, 1, 0, 0,
				 rfd);
}

/* C. the network base on six (door, class) pairs */
static void f568_sec_nh(int rfd)
{
	static const int pairs[] = { 0, 1, 2, 3, 4, 8, 7 };	/* out/loc post/loc egr/loc post/fwd fwd/fwd lin/in pre/in */
	int i, k;

	for (i = 0; i < (int)(sizeof(pairs) / sizeof(pairs[0])); i++)
		for (k = 1; k < NN68; k++)
			f568_arm("nh", &P568[pairs[i]], N568[k].arm, N568[k].base,
				 N568[k].off, N568[k].len, N568[k].imm, 1, 0, 0,
				 rfd);
}

/* D. the transport base: one egress door and one ingress door */
static void f568_sec_th(int rfd)
{
	int k;

	static const int pairs[] = { 0, 2, 3, 8, 7 };	/* out/loc egr/loc post/fwd lin/in pre/in */
	int i;

	for (i = 0; i < (int)(sizeof(pairs) / sizeof(pairs[0])); i++)
		for (k = 1; k < NT68; k++)
			f568_arm("th", &P568[pairs[i]], T568[k].arm, T568[k].base,
				 T568[k].off, T568[k].len, T568[k].imm, 1, 0, 0,
				 rfd);
}

/* E. the repair: one store, one csum attribute, four doors */
static void f568_sec_cs(int rfd)
{
	static const int pairs[] = { 0, 1, 3, 5, 8 };	/* out/loc post/loc post/fwd egr/fwd lin/in */
	int i, k;

	for (i = 0; i < (int)(sizeof(pairs) / sizeof(pairs[0])); i++)
		for (k = 0; k < NC68; k++)
			f568_arm("cs", &P568[pairs[i]], C568[k].arm, C568[k].base,
				 C568[k].off, C568[k].len, C568[k].imm, 1,
				 C568[k].csum, C568[k].cso, rfd);
}

/* F. read-only cells at the egress doors: read and write share a base */
static void f568_sec_rd(int rfd)
{
	int i, k;

	for (i = 0; i < 2; i++)		/* out/loc, pre/in */
		for (k = 0; k < NR68; k++)
			f568_arm("rd", &P568[i ? 8 : 0], R568[k].arm,
				 R568[k].base, R568[k].off, R568[k].len,
				 R568[k].imm, 3, 0, 0, rfd);
}

/* G. did the write land where nobody can see it?  store, read back, compare */
static void f568_sec_ld(int rfd)
{
	static const int pairs[] = { 8, 7 };	/* pre/in, pre/fwd */
	struct f568_spec cells[] = {
		{ "d_ttl",  NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x90 } },
		{ "d_src",  NFT_PAYLOAD_NETWORK_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 } },
		{ "d_port", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x90, 0x91 } },
		{ "d_ll",   NFT_PAYLOAD_LL_HEADER, 0, 2, { 0x90, 0x91 } },
	};
	int i, k;

	for (i = 0; i < 2; i++)
		for (k = 0; k < (int)(sizeof(cells) / sizeof(cells[0])); k++)
			f568_arm("ld", &P568[pairs[i]], cells[k].arm, cells[k].base,
				 cells[k].off, cells[k].len, cells[k].imm, 2, 0, 0,
				 rfd);
}

/* ---------- setup ---------- */

static void f568_setup_env(void)
{
	if (link_add_veth("x0", "x1"))
		printf("F568 FAIL|veth x\n");
	if (link_add_veth("o0", "o1"))
		printf("F568 FAIL|veth o\n");
	if (link_add_veth("y0", "y1"))
		printf("F568 FAIL|veth y\n");
	if (mac_get("x1", X1_MAC))
		printf("F568 FAIL|mac x1\n");
	set_up("x0"); set_up("x1");
	set_up("o0"); set_up("o1");
	set_up("y0"); set_up("y1");
	printf("F568 SETUP|x0=%d|x1=%d|o0=%d|o1=%d|y0=%d|y1=%d\n",
	       f555_ifindex("x0"), f555_ifindex("x1"), f555_ifindex("o0"),
	       f555_ifindex("o1"), f555_ifindex("y0"), f555_ifindex("y1"));
	printf("F568 ADDR|rc=%d\n", f555_addr_add("x0", htonl(A_X0), 24));
	printf("F568 ADDR2|rc=%d\n", f555_addr_add("y1", htonl(A_Y1), 24));
	{
		char p[96];
		static const char *devs[] = { "x0", "o0", "o1", "y0", "y1" };
		int i;

		for (i = 0; i < 5; i++) {
			snprintf(p, sizeof(p), "/proc/sys/net/ipv4/conf/%s/rp_filter", devs[i]);
			f555_sysctl(p, "0");
		}
		f555_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
		f555_sysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0");
		f555_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
		f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	}
}

static int f568_start_child(void)
{
	int to_ch[2], to_p[2];
	pid_t pid;

	if (pipe(to_ch) || pipe(to_p))
		return -1;
	pid = fork();
	if (pid < 0)
		return -2;
	if (pid == 0) {
		close(to_ch[1]);
		close(to_p[0]);
		f568_child_loop(to_ch[0], to_p[1]);
		_exit(0);
	}
	close(to_ch[0]);
	close(to_p[1]);
	P_W = to_ch[1];
	P_R = to_p[0];
	CHILD = pid;
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "f568";
	char line[512], hx[400];
	int rfd = -1, i, rc;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F568 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F568 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F568 KERNEL|7.3.4-T563\n");

	f568_setup_env();

	/* the receiver lives in its own netns; x1 is moved into it */
	rc = f568_start_child();
	printf("F568 FORK|rc=%d|pid=%d\n", rc, (int)CHILD);
	if (rc == 0) {
		if (f568_read_line(line, sizeof(line), 20000) < 0 || line[0] != 'U')
			printf("F568 FAIL|child unshare|%s\n", line);
		else
			printf("F568 CHILD|%s\n", line);
		printf("F568 MOVE|rc=%d\n", f568_move_link("x1", (int)CHILD));
		f568_ask("C");
		for (;;) {
			if (f568_read_line(line, sizeof(line), 20000) < 0) {
				printf("F568 FAIL|child cfg\n");
				break;
			}
			printf("F568 CHILDR|%s\n", line);
			if (!strncmp(line, "READY", 5) || line[0] == 'E')
				break;
		}
	}
	NFL67 = nfl_open(5);
	printf("F568 NFL|%d\n", NFL67);

	if (f568_chains()) {
		printf("F568 FAIL|chains\n");
		return 0;
	}

	/* the two frames we inject */
	{
		unsigned char mo[6], my[6];

		if (mac_get("o1", mo) || mac_get("y1", my)) {
			printf("F568 FAIL|mac\n");
			return 0;
		}
		FWD_FRAME_LEN = f568_mkframe(FWD_FRAME, mo, A_FS, A_X1, 40000, 5000);
		IN_FRAME_LEN = f568_mkframe(IN_FRAME, my, A_IS, A_Y1, 40000, 5000);
		printf("F568 FRAME|fwd|len=%d|wire=%s\n", FWD_FRAME_LEN,
		       f559_hexs(hx, sizeof(hx), FWD_FRAME, FWD_FRAME_LEN));
		printf("F568 FRAME|in|len=%d|wire=%s\n", IN_FRAME_LEN,
		       f559_hexs(hx, sizeof(hx), IN_FRAME, IN_FRAME_LEN));
	}
	LOC_SOCK = f564_udp_bind(AF_INET, A_X0, NULL, 40000);
	IN_SOCK = f564_udp_bind(AF_INET, A_Y1, NULL, 5000);
	printf("F568 SOCK|loc=%d|in=%d\n", LOC_SOCK, IN_SOCK);
	rfd = cap_open("y1");
	printf("F568 CAP|rfd=%d\n", rfd);

	/* pin the neighbour so that no arm is spent waiting for an ARP probe */
	{
		unsigned char mx1[6];

		memcpy(mx1, X1_MAC, 6);
		printf("F568 NEIGH|rc=%d|mac=%02x%02x%02x%02x%02x%02x\n",
		       f568_neigh_add("x0", htonl(A_X1), mx1),
		       mx1[0], mx1[1], mx1[2], mx1[3], mx1[4], mx1[5]);
	}

	/* warm-up: resolve the neighbour for 10.10.0.2 through the receiver */
	{
		struct f568_rep r;
		struct sockaddr_in sin;
		int k, got = 0;

		f568_flush_all();
		for (k = 0; k < 6; k++) {
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = htonl(A_X1);
			sin.sin_port = htons(5000);
			sendto(LOC_SOCK, F568_PAY, sizeof(F568_PAY), 0,
			       (struct sockaddr *)&sin, sizeof(sin));
			usleep(120000);
			if (f568_snapshot(&r) == 0 && r.udpn > 0) {
				got = 1;
				break;
			}
		}
		printf("F568 WARM|got=%d|tapn=%d|udpn=%d\n", got, r.tapn, r.udpn);
	}

	if (!strcmp(mode, "ctl"))
		f568_sec_ctl(rfd);
	else if (!strcmp(mode, "ll"))
		f568_sec_ll(rfd);
	else if (!strcmp(mode, "nh"))
		f568_sec_nh(rfd);
	else if (!strcmp(mode, "th"))
		f568_sec_th(rfd);
	else if (!strcmp(mode, "cs"))
		f568_sec_cs(rfd);
	else if (!strcmp(mode, "rd"))
		f568_sec_rd(rfd);
	else if (!strcmp(mode, "ld"))
		f568_sec_ld(rfd);
	else {
		f568_sec_ctl(rfd);
		f568_sec_ll(rfd);
		f568_sec_nh(rfd);
		f568_sec_th(rfd);
		f568_sec_cs(rfd);
		f568_sec_rd(rfd);
		f568_sec_ld(rfd);
	}
	(void)i;
	f568_ask("Q");
	printf("F568 DONE\n");
	return 0;
}
