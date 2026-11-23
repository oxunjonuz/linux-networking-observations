/* differ579_add.c -- turn 579 (F57): THE PRIVILEGE BOUNDARY.
 *
 *  The question is not about a door any more: it is about who is allowed to
 *  stand at it, and whose bytes reach it.
 *
 *    (1) which of the effects measured in F42..F56 need an administrator;
 *    (2) which of them arise from processing ordinary incoming traffic, i.e.
 *        from bytes an unprivileged party chooses;
 *    (3) would we know if one of them were a 0-day.
 *
 *  Two gates exist in the source and they are not the same gate:
 *
 *    net/netfilter/nfnetlink.c:659
 *        if (!netlink_net_capable(skb, CAP_NET_ADMIN)) -> -EPERM
 *        CAP_NET_ADMIN in the user namespace that OWNS the netns.  An
 *        unprivileged user who unshares CLONE_NEWUSER|CLONE_NEWNET passes it.
 *
 *    net/netfilter/nft_payload.c:1207  (nft_payload_set_init only)
 *        if (ctx->net->user_ns != &init_user_ns) -> -EPERM
 *        every STORE into the packet is refused unless the netns belongs to
 *        the initial user namespace.  The read path (nft_payload_init) has no
 *        such check, and nft_meta_set_init has none either.
 *
 *  Part A is the census: one context, one table, four expressions -- read @ll,
 *  store @ll, meta priority set, and a chain hooked on a device that is not in
 *  this namespace -- run in three credential contexts.
 *
 *  Part B asks the second question with real traffic.  A child that holds no
 *  capability in the initial user namespace owns one end of a veth pair (the
 *  parent moves that end into the child's netns); the far end, its IPv6
 *  address and every rule belong to root in the initial netns.  That child is
 *  the local stand-in for "the far end of the wire".
 *
 *  Frames (all fd02::11 -> fd02::91, UDP 43300 -> 5000, 18 payload bytes):
 *    1 plain   nexthdr 17, flow label 0
 *    2 hbh     nexthdr 0, hop-by-hop (8 bytes) -> 17
 *    3 frag    nexthdr 44, fragment (8 bytes, offset 0, M 0) -> 17
 *    4 flow    nexthdr 17, flow label 0x0086dd  (frame bytes 16..17 = 86dd)
 *    5 tag     802.1Q vid 100, inner ethertype 86dd, flow label 0
 */

#define F579_SPORT	43300
#define F579_DPORT	5000
#define F579_PAY	18
#define F579_IFLA_NET_NS_FD 28
#define F579_B_LL	0
#define F579_B_NH	1
#define F579_NFRM	5

static const unsigned char A79_S[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x11 };
static const unsigned char A79_D[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x91 };
static const unsigned char A79_W[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x00, 0x00, 0x00, 0x00, 0x00,
					 0x99 };
static const unsigned char F579_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const unsigned char F579_SM[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x79 };

#define F579_TN		"f79n"		/* netdev ingress table, device x1 */
#define F579_TG		"f79g"		/* ip6 prerouting table            */

static int F579_U6 = -1;
static unsigned char F579_FM0[6], F579_FM1[6], F579_FR[192];
static unsigned char F579_DST[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
				      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				      0x00, 0x00, 0x00, 0x91 };
static char F579_HX[512];

/* ---------- small helpers ---------------------------------------------- */

static const char *f579_sysctl_read(const char *path)
{
	static char b[128];
	int fd = open(path, O_RDONLY);
	int n;

	b[0] = 0;
	if (fd < 0)
		return "-";
	n = (int)read(fd, b, sizeof(b) - 1);
	close(fd);
	if (n <= 0)
		return "-";
	b[n] = 0;
	while (n > 0 && (b[n - 1] == '\n' || b[n - 1] == ' '))
		b[--n] = 0;
	return b;
}

static const char *f579_fdlink(int fd)
{
	static char b[160];
	char p[64];
	int n;

	snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
	n = (int)readlink(p, b, sizeof(b) - 1);
	if (n <= 0)
		return "-";
	b[n] = 0;
	return b;
}


/* what /proc/net/if_inet6 says: "<flags>:<dev>" for the address we added,
 * "-" if it never landed, and the number of lines in the whole table */
static const char *f579_if6(const unsigned char *a)
{
	static char out[64];
	char hex[33];
	int fd, n, i, lines = 0;
	static char buf[4096];

	for (i = 0; i < 16; i++)
		snprintf(hex + 2 * i, 3, "%02x", a[i]);
	snprintf(out, sizeof(out), "-:-");
	fd = open("/proc/net/if_inet6", O_RDONLY);
	if (fd < 0)
		return out;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return out;
	buf[n] = 0;
	{
		char *p = buf;

		while (p && *p) {
			char *e = strchr(p, '\n');
			char save;

			if (e)
				save = *e, *e = 0;
			lines++;
			if (!strncmp(p, hex, 32)) {
				/* addr ifidx plen scope flags name */
				char f4[8] = "?", nm[IFNAMSIZ] = "?";
				unsigned idx, plen, scope;
				unsigned fl = 0;

				if (sscanf(p + 32, "%x %x %x %x %15s %15s",
					   &idx, &plen, &scope, &fl, nm) == 5)
					snprintf(out, sizeof(out), "%x:%s",
						 fl, nm);
			}
			if (e)
				*e = save, p = e + 1;
			else
				break;
		}
	}
	(void)lines;
	return out;
}

/* ---------- frames ------------------------------------------------------ */

static int f579_ip6(unsigned char *ip, int id)
{
	int ext = (id == 2 || id == 3) ? 8 : 0;
	int udplen = 8 + F579_PAY;
	int tot = ext + udplen;
	unsigned int flow = (id == 4) ? 0x0086ddu : 0u;
	unsigned char *p, *udp;
	int i;

	memset(ip, 0, (size_t)(40 + tot));
	ip[0] = 0x60;				/* version 6, tc 0 */
	ip[1] = (unsigned char)((flow >> 16) & 0x0f);
	ip[2] = (unsigned char)((flow >> 8) & 0xff);
	ip[3] = (unsigned char)(flow & 0xff);
	ip[4] = (unsigned char)(tot >> 8);
	ip[5] = (unsigned char)(tot & 0xff);
	ip[6] = 17;
	ip[7] = 64;
	memcpy(ip + 8, A79_S, 16);
	memcpy(ip + 24, F579_DST, 16);

	switch (id) {
	case 2:					/* hop-by-hop */
		ip[6] = 0;
		p = ip + 40;
		p[0] = 17;
		p[1] = 0;
		break;
	case 3:					/* fragment: offset 0, M 0 */
		ip[6] = 44;
		p = ip + 40;
		p[0] = 17;
		p[1] = 0;
		p[2] = 0;
		p[3] = 0;
		p[6] = 0x00;
		p[7] = 0x79;
		break;
	}

	udp = ip + 40 + ext;
	udp[0] = (unsigned char)(F579_SPORT >> 8);
	udp[1] = (unsigned char)(F579_SPORT & 0xff);
	udp[2] = (unsigned char)(F579_DPORT >> 8);
	udp[3] = (unsigned char)(F579_DPORT & 0xff);
	udp[4] = (unsigned char)(udplen >> 8);
	udp[5] = (unsigned char)(udplen & 0xff);
	for (i = 0; i < F579_PAY; i++)
		udp[8 + i] = 0x77;
	f570_udp6_csum(ip, ext, udplen);
	return 40 + tot;
}

static int f579_frame(unsigned char *out, int id)
{
	int off, n;

	memset(out, 0, 192);
	memcpy(out, F579_BC, 6);
	memcpy(out + 6, F579_SM, 6);
	if (id == 5) {
		out[12] = 0x81;
		out[13] = 0x00;
		out[14] = 0x00;			/* prio 0 */
		out[15] = 0x64;			/* vid 100 */
		out[16] = 0x86;
		out[17] = 0xdd;
		off = 18;
	} else {
		out[12] = 0x86;
		out[13] = 0xdd;
		off = 14;
	}
	n = f579_ip6(out + off, id);
	return off + n;
}

/* ---------- nft ------------------------------------------------------- */

static int f579_one(void)
{
	int acks = 0;

	return f557_nft_one(opbuf,
			    (int)((struct nlmsghdr *)opbuf)->nlmsg_len, &acks);
}

static int f579_tbl(uint8_t fam, const char *table)
{
	struct nlmsghdr *nlh;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, fam);
	put_str(nlh, NFTA_TABLE_NAME, table);
	return f579_one();
}

static int f579_chn(uint8_t fam, const char *table, const char *chain,
		    const char *dev, uint32_t hook)
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
	put_be32(nlh, NFTA_HOOK_PRIORITY, 10);
	if (dev)
		put_str(nlh, NFTA_HOOK_DEV, dev);
	nest_end(nlh, h);
	put_be32(nlh, NFTA_CHAIN_POLICY, 1);
	put_str(nlh, NFTA_CHAIN_TYPE, "filter");
	return f579_one();
}

static void f579_verdict(struct nlmsghdr *nlh, int verdict)
{
	struct nlattr *e, *d;
	uint32_t code = htonl((uint32_t)verdict);

	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "immediate");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
	{
		struct nlattr *v = nest_start(nlh, NFTA_IMMEDIATE_DATA);
		struct nlattr *vd = nest_start(nlh, NFTA_DATA_VERDICT);

		attr_put(nlh, NFTA_VERDICT_CODE, &code, 4);
		nest_end(nlh, vd);
		nest_end(nlh, v);
	}
	nest_end(nlh, d);
	nest_end(nlh, e);
}

/* one rule.  kind: 0 read+cmp @ll, 1 store @ll, 2 meta priority set,
 *                  3 read+cmp @nh, 4 read+cmp meta l4proto                */
static int f579_rule(uint8_t fam, const char *table, const char *chain,
		     int kind, uint32_t off, uint32_t len, uint32_t val,
		     int drop)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	unsigned char b[4];
	int acks = 0;

	b[0] = (unsigned char)((val >> 24) & 0xff);
	b[1] = (unsigned char)((val >> 16) & 0xff);
	b[2] = (unsigned char)((val >> 8) & 0xff);
	b[3] = (unsigned char)(val & 0xff);
	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			fam);
	put_str(nlh, NFTA_RULE_TABLE, table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	switch (kind) {
	case 0:
		f562_read(nlh, F579_B_LL, off, len);
		f562_cmp(nlh, F562_RD_DREG, b + (4 - len), (int)len);
		break;
	case 1:
		f565_store(nlh, F579_B_LL, off, len, b + (4 - len), 0, 0);
		break;
	case 2:
		imm_value(nlh, F562_WR_SREG, b, 4);
		{
			struct nlattr *e, *d;

			e = nest_start(nlh, NFTA_LIST_ELEM);
			put_str(nlh, NFTA_EXPR_NAME, "meta");
			d = nest_start(nlh, NFTA_EXPR_DATA);
			put_be32(nlh, NFTA_META_KEY, NFT_META_PRIORITY);
			put_be32(nlh, NFTA_META_SREG, F562_WR_SREG);
			nest_end(nlh, d);
			nest_end(nlh, e);
		}
		break;
	case 3:
		f562_read(nlh, F579_B_NH, off, len);
		f562_cmp(nlh, F562_RD_DREG, b + (4 - len), (int)len);
		break;
	case 4:
		f570_put_meta(nlh, NFT_META_L4PROTO);
		f562_cmp(nlh, F562_RD_DREG, b + (4 - len), (int)len);
		break;
	}
	counter_expr(nlh);
	if (drop)
		f579_verdict(nlh, NF_DROP);
	else
		accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

static void f579_flush(void)
{
	int acks = 0;

	f557_flush(NFPROTO_NETDEV, F579_TN, "c0", &acks);
	f557_flush(NFPROTO_IPV6, F579_TG, "c0", &acks);
}

/* ---------- snmp6 ------------------------------------------------------ */

struct f579_sn {
	unsigned long long rcv, deliv, hdrerr, addrerr, disc, ukproto,
			   udp, udperr, udpnop;
};

static unsigned long long f579_snmp_one(const char *txt, const char *key)
{
	const char *p = txt;
	size_t kl = strlen(key);

	while (p && *p) {
		const char *e = strchr(p, '\n');

		if (!e)
			break;
		if (!strncmp(p, key, kl) && p[kl] == ' ') {
			const char *q = p + kl;

			while (*q == ' ' || *q == '\t')
				q++;
			return strtoull(q, NULL, 10);
		}
		p = e + 1;
	}
	return 0;
}

static void f579_snmp(struct f579_sn *s)
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
	s->udp = f579_snmp_one(buf, "Udp6InDatagrams");
	s->udperr = f579_snmp_one(buf, "Udp6InErrors");
	s->udpnop = f579_snmp_one(buf, "Udp6NoPorts");
}

static int f579_drain(int *firstlen)
{
	unsigned char b[512];
	int n = 0, r;

	if (firstlen)
		*firstlen = -1;
	if (F579_U6 < 0)
		return -1;
	for (;;) {
		r = (int)recv(F579_U6, b, sizeof(b), MSG_DONTWAIT);
		if (r < 0)
			break;
		if (n == 0 && firstlen)
			*firstlen = r;
		n++;
	}
	return n;
}

/* ---------- ipc ------------------------------------------------------- */

static int f579_wr(int fd, const void *p, int n)
{
	const char *c = p;
	int done = 0;

	while (done < n) {
		int r = (int)write(fd, c + done, (size_t)(n - done));

		if (r <= 0)
			return -1;
		done += r;
	}
	return 0;
}

static int f579_rd(int fd, void *p, int n)
{
	char *c = p;
	int done = 0;

	while (done < n) {
		int r = (int)read(fd, c + done, (size_t)(n - done));

		if (r <= 0)
			return -1;
		done += r;
	}
	return 0;
}

struct f579_cap {
	int un, umap, gmap, veth, iw0, iw1, ix1;
	int tbl, chn, rd, st, meta, fore, fore2;
	int fx_ch, fx_u6, fx_rcv, fx2_ch, fx2_u6;
	int a6, dis, fx2_rcv, fx2_deliv, fx2_addrerr, fx2_disc;
	char if6[64];
};

/* ---------- userns plumbing ------------------------------------------- */

static int f579_wrfile(const char *path, const char *val, int len)
{
	int fd = open(path, O_WRONLY);
	int rc;

	if (fd < 0)
		return -errno;
	rc = (int)write(fd, val, (size_t)len);
	close(fd);
	return rc == len ? 0 : -errno;
}

/* enter a user+net namespace of our own, starting as uid 1000 outside.
 * The uid map cannot be written from inside: /proc/self/uid_map belongs to
 * the initial user namespace and refuses an euid that is not 0 there
 * (measured: -EACCES).  The parent writes /proc/<pid>/uid_map instead. */
static int f579_userns(struct f579_cap *c)
{
	if (setgid(1000) || setuid(1000)) {
		c->un = -1000 - errno;
		return -1;
	}
	c->un = unshare(CLONE_NEWUSER | CLONE_NEWNET) ? -errno : 0;
	return c->un ? -1 : 0;
}

/* parent side of the map: uid 1000 outside, 0 inside */
static int f579_maps(int pid)
{
	char path[64], v[32];
	int r1, r2, r3;

	snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
	r1 = f579_wrfile(path, "deny\n", 5);
	snprintf(v, sizeof(v), "0 1000 1\n");
	snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
	r2 = f579_wrfile(path, v, (int)strlen(v));
	snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
	r3 = f579_wrfile(path, v, (int)strlen(v));
	printf("F579 MAPS|pid=%d|setgroups=%d|uid=%d|gid=%d\n", pid, r1, r2, r3);
	return r2 | r3;
}

/* ---------- the sender child ------------------------------------------ */

static int f579_send_frame(const char *dev, int id)
{
	unsigned char f[192];
	struct sockaddr_ll sa;
	int n, s, ifi, rc;

	ifi = f555_ifindex(dev);
	if (ifi < 0)
		return -10;
	n = f579_frame(f, id);
	s = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
	if (s < 0)
		return -errno;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = ifi;
	sa.sll_halen = 6;
	memcpy(sa.sll_addr, F579_BC, 6);
	rc = (int)sendto(s, f, (size_t)n, 0, (struct sockaddr *)&sa,
			 sizeof(sa));
	close(s);
	return rc == n ? n : -errno;
}

/* child B: the census inside its own namespace, then part B's sender */
static void f579_child_ns(int p2c, int c2p, int sp)
{
	struct f579_cap c;
	struct msghdr mh;
	struct cmsghdr *cm;
	struct iovec iov;
	char cc = 'n';
	char buf[CMSG_SPACE(sizeof(int))];
	unsigned char f[192];
	char hx[512];
	int nsfd, cmd, len;

	memset(&c, 0, sizeof(c));
	alarm(300);
	if (f579_userns(&c)) {
		int z = 0;

		f579_wr(c2p, &z, sizeof(z));
		f579_wr(c2p, &c, sizeof(c));
		_exit(1);
	}
	/* the uid map must be written from outside */
	{
		int me = (int)getpid();
		int ack = -1;

		f579_wr(c2p, &me, sizeof(me));
		if (f579_rd(p2c, &ack, sizeof(ack)) || ack) {
			c.un = -4000 - ack;
			f579_wr(c2p, &c, sizeof(c));
			_exit(1);
		}
	}
	if (setgid(0) || setuid(0)) {
		c.un = -2000 - errno;
		f579_wr(c2p, &c, sizeof(c));
		_exit(1);
	}
	c.un = (int)getuid();		/* 0 inside, 1000 outside */
	nsfd = open("/proc/self/ns/net", O_RDONLY);
	memset(&mh, 0, sizeof(mh));
	iov.iov_base = &cc;
	iov.iov_len = 1;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = buf;
	mh.msg_controllen = CMSG_SPACE(sizeof(int));
	cm = CMSG_FIRSTHDR(&mh);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &nsfd, sizeof(int));
	sendmsg(sp, &mh, 0);

	/* ---- census, on devices this namespace creates for itself ---- */
	c.veth = link_add_veth("w0", "w1");
	c.iw0 = f555_ifindex("w0");
	c.iw1 = f555_ifindex("w1");
	c.ix1 = f555_ifindex("x1");	/* lives in the initial netns */
	if (!c.veth) {
		f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
		f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");
		set_up("w0");
		set_up("w1");
		f555_sysctl("/proc/sys/net/ipv6/conf/w1/disable_ipv6", "0");
		f555_sysctl("/proc/sys/net/ipv6/conf/w1/accept_dad", "0");
		f555_sysctl("/proc/sys/net/ipv6/conf/w1/dad_transmits", "0");
		c.a6 = f564_addr6("w1", A79_W, 64);
		memcpy(F579_DST, A79_W, 16);	/* our own device, not the parent's */
		c.dis = atoi(f579_sysctl_read(
			"/proc/sys/net/ipv6/conf/w1/disable_ipv6"));
		snprintf(c.if6, sizeof(c.if6), "%s", f579_if6(A79_W));
		c.tbl = f579_tbl(NFPROTO_NETDEV, "f79c");
		c.chn = f579_chn(NFPROTO_NETDEV, "f79c", "c0", "w1", 0);
		c.rd = f579_rule(NFPROTO_NETDEV, "f79c", "c0", 0, 12, 2,
				 0x86dd, 1);
		c.st = f579_rule(NFPROTO_NETDEV, "f79c", "c0", 1, 12, 2,
				 0x2066, 0);
		c.meta = f579_rule(NFPROTO_NETDEV, "f79c", "c0", 2, 0, 4,
				   5, 0);
		c.fore = f579_chn(NFPROTO_NETDEV, "f79c", "c1", "x1", 0);
		c.fore2 = f579_rule(NFPROTO_NETDEV, "f79c", "c1", 0, 12, 2,
				    0x86dd, 1);
		if (!c.rd) {
			struct f579_sn t0, t1;

			F579_U6 = f564_udp_bind(AF_INET6, 0, A79_W,
						F579_DPORT);
			f579_snmp(&t0);
			f579_send_frame("w0", 1);
			usleep(200000);
			c.fx_rcv = (int)((f579_snmp(&t1), t1.rcv - t0.rcv));
			c.fx_u6 = f579_drain(&len);
			c.fx_ch = (int)f555_count(NFPROTO_NETDEV, "f79c",
						  "c0");
			if (F579_U6 >= 0) {
				close(F579_U6);
				F579_U6 = -1;
			}
		}
		/* the chain that names another namespace's device: created
		 * without an error -- does it ever fire? */
		if (!c.fore2) {
			/* c0 still holds the drop rule of the test above and it
			 * sits on the same hook: without this the fate would be
			 * decided by c0 and not by the foreign chain at all */
			int acks = 0;

			struct f579_sn s0, s1;

			f557_flush(NFPROTO_NETDEV, "f79c", "c0", &acks);
			F579_U6 = f564_udp_bind(AF_INET6, 0, A79_W,
						F579_DPORT);
			f579_snmp(&s0);
			f579_send_frame("w0", 1);
			usleep(200000);
			c.fx2_u6 = f579_drain(&len);
			f579_snmp(&s1);
			c.fx2_rcv = (int)(s1.rcv - s0.rcv);
			c.fx2_deliv = (int)(s1.deliv - s0.deliv);
			c.fx2_addrerr = (int)(s1.addrerr - s0.addrerr);
			c.fx2_disc = (int)(s1.disc - s0.disc);
			c.fx2_ch = (int)f555_count(NFPROTO_NETDEV, "f79c",
						   "c1");
			if (F579_U6 >= 0) {
				close(F579_U6);
				F579_U6 = -1;
			}
		}
	}
	memcpy(F579_DST, A79_D, 16);
	f579_wr(c2p, &c, sizeof(c));

	/* ---- part B: wait for commands from the parent ---- */
	for (;;) {
		int rc = 0;

		if (f579_rd(p2c, &cmd, sizeof(cmd)))
			_exit(0);
		if (cmd == 0)
			_exit(0);
		if (cmd == 1) {
			set_up("x0");
			rc = f555_ifindex("x0");
			printf("F579 CHILD|cmd=up|idx=%d|macret=%d\n", rc,
			       mac_get("x0", f));
		} else if (cmd >= 10 && cmd < 10 + F579_NFRM + 1) {
			int id = cmd - 10;

			rc = f579_send_frame("x0", id);
			printf("F579 FRM|id=%d|len=%d|hex=%s\n", id,
			       f579_frame(f, id),
			       f559_hexs(hx, sizeof(hx), f,
					 f579_frame(f, id)));
		}
		fflush(stdout);
		f579_wr(c2p, &rc, sizeof(rc));
	}
}

/* child A: uid 1000 in the initial netns, no capabilities at all */
static void f579_child_uid(int c2p)
{
	struct f579_cap c;

	memset(&c, 0, sizeof(c));
	if (setgid(1000) || setuid(1000)) {
		c.un = -3000 - errno;
		f579_wr(c2p, &c, sizeof(c));
		_exit(1);
	}
	c.un = 0;
	c.tbl = f579_tbl(NFPROTO_NETDEV, "f79x");		/* new table   */
	c.chn = f579_chn(NFPROTO_NETDEV, F579_TN, "c0un", "x1", 0);
	c.rd = f579_rule(NFPROTO_NETDEV, F579_TN, "c0", 0, 12, 2,
			 0x86dd, 1);
	c.st = f579_rule(NFPROTO_NETDEV, F579_TN, "c0", 1, 12, 2,
			 0x2066, 0);
	c.meta = f579_rule(NFPROTO_NETDEV, F579_TN, "c0", 2, 0, 4, 5, 0);
	f579_wr(c2p, &c, sizeof(c));
	_exit(0);
}

/* ---------- part A: the root context ---------------------------------- */

static void f579_census_root(void)
{
	struct f579_cap c;

	memset(&c, 0, sizeof(c));
	c.tbl = f579_tbl(NFPROTO_NETDEV, "f79r");
	c.chn = f579_chn(NFPROTO_NETDEV, "f79r", "c0", "x1", 0);
	c.rd = f579_rule(NFPROTO_NETDEV, "f79r", "c0", 0, 12, 2, 0x86dd, 1);
	c.st = f579_rule(NFPROTO_NETDEV, "f79r", "c0", 1, 12, 2,
			 0x2066, 0);
	c.meta = f579_rule(NFPROTO_NETDEV, "f79r", "c0", 2, 0, 4, 5, 0);
	c.fore = f579_chn(NFPROTO_NETDEV, "f79r", "c1", "nosuchdev", 0);
	printf("F579 CAP|ctx=root_init|tbl=%d|chn=%d|rd=%d|st=%d|meta=%d|"
	       "fore=%d\n", c.tbl, c.chn, c.rd, c.st, c.meta, c.fore);
	fflush(stdout);
	/* the census chain sits on the same hook as part B: empty it, or its
	 * store would rewrite the tag of every frame that follows */
	{
		int acks = 0;

		f557_flush(NFPROTO_NETDEV, "f79r", "c0", &acks);
		printf("F579 CAPFLUSH|acks=%d\n", acks);
	}
}

/* ---------- moving a device across the namespace border --------------- */

static int f579_move_ns(const char *dev, int nsfd)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[128];
	} req;
	uint32_t fdv = (uint32_t)nsfd;
	int fd, rc, idx = f555_ifindex(dev);

	if (idx < 0 || nsfd < 0)
		return -1;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = idx;
	attr_put(&req.nlh, F579_IFLA_NET_NS_FD, &fdv, 4);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* ---------- part B: one arm ------------------------------------------- */

static int F579_CMD = -1, F579_ACK = -1, F579_KID = -1;

static int f579_ask(int cmd)
{
	int rc = -99;

	if (f579_wr(F579_CMD, &cmd, sizeof(cmd)))
		return -1;
	if (f579_rd(F579_ACK, &rc, sizeof(rc)))
		return -2;
	return rc;
}

struct f579_arm {
	const char *name;
	int fid;
	int door;		/* 0 none, 1 netdev ingress, 2 ip6 prerouting */
	int kind;
	int drop;
	uint32_t off, len, val;
};

static void f579_armB(const struct f579_arm *A)
{
	struct f579_sn a, b;
	unsigned long long ch = (unsigned long long)-1;
	int rc = -99, u6n, u6len = -1, snd;

	f579_flush();
	if (A->door == 1)
		rc = f579_rule(NFPROTO_NETDEV, F579_TN, "c0", A->kind,
			       A->off, A->len, A->val, A->drop);
	else if (A->door == 2)
		rc = f579_rule(NFPROTO_IPV6, F579_TG, "c0", A->kind,
			       A->off, A->len, A->val, A->drop);
	(void)f579_drain(NULL);
	f579_snmp(&a);
	snd = f579_ask(10 + A->fid);
	usleep(300000);
	u6n = f579_drain(&u6len);
	f579_snmp(&b);
	if (A->door == 1)
		ch = f555_count(NFPROTO_NETDEV, F579_TN, "c0");
	else if (A->door == 2)
		ch = f555_count(NFPROTO_IPV6, F579_TG, "c0");
	printf("F579 ARM|name=%s|fid=%d|door=%d|kind=%d|rc=%d|snd=%d|"
	       "ch=%llu|u6n=%d|u6len=%d|rcv=%llu|deliv=%llu|hdrerr=%llu|"
	       "addrerr=%llu|disc=%llu|ukproto=%llu|udp=%llu|udperr=%llu|"
	       "udpnop=%llu\n",
	       A->name, A->fid, A->door, A->kind, rc, snd, ch, u6n, u6len,
	       b.rcv - a.rcv, b.deliv - a.deliv, b.hdrerr - a.hdrerr,
	       b.addrerr - a.addrerr, b.disc - a.disc,
	       b.ukproto - a.ukproto, b.udp - a.udp, b.udperr - a.udperr,
	       b.udpnop - a.udpnop);
	fflush(stdout);
}

static const struct f579_arm A579[] = {
	/* baselines: no rule at all */
	{ "c_plain",		1, 0, 0, 0, 0, 0, 0 },
	{ "c_tag",		5, 0, 0, 0, 0, 0, 0 },
	/* where the four tag bytes live at the netdev ingress door */
	{ "d12_8100_plain",	1, 1, 0, 1, 12, 2, 0x8100 },
	{ "d12_8100_tag",	5, 1, 0, 1, 12, 2, 0x8100 },
	{ "d12_86dd_tag",	5, 1, 0, 1, 12, 2, 0x86dd },
	/* one offset, two meanings: inner ethertype vs flow label */
	{ "d16_0000_plain",	1, 1, 0, 1, 16, 2, 0x0000 },
	{ "d16_86dd_flow",	4, 1, 0, 1, 16, 2, 0x86dd },
	{ "d16_86dd_tag",	5, 1, 0, 1, 16, 2, 0x86dd },
	/* @nh is the byte at 6; the sender builds the chain in front of it */
	{ "e_nh_plain",		1, 2, 3, 1, 6, 1, 17 },
	{ "e_nh_hbh",		2, 2, 3, 1, 6, 1, 17 },
	{ "e_nh_frag",		3, 2, 3, 1, 6, 1, 17 },
	{ "e_nh0_hbh",		2, 2, 3, 1, 6, 1, 0 },
	/* the same intent written with the walker instead of the byte */
	{ "e_l4_plain",		1, 2, 4, 1, 0, 1, 17 },
	{ "e_l4_hbh",		2, 2, 4, 1, 0, 1, 17 },
	/* the bound of a read at the exact end of the 80-byte frame */
	{ "x_r78",		1, 1, 0, 0, 78, 2, 0x7777 },
	{ "x_r79",		1, 1, 0, 0, 79, 2, 0x7777 },
	/* the bound of a write at mac_len = 14 */
	{ "w_l12",		1, 1, 1, 0, 12, 2, 0x2066 },
	{ "w_l13",		1, 1, 1, 0, 13, 2, 0x2066 },
	{ "w_l20",		1, 1, 1, 0, 20, 2, 0x2066 },
};
#define NA579 ((int)(sizeof(A579) / sizeof(A579[0])))

/* ---------- the mode -------------------------------------------------- */

static int f579_priv(void)
{
	int p2c[2], c2p[2], sp[2];
	struct f579_cap c;
	struct msghdr mh;
	struct cmsghdr *cm;
	struct iovec iov;
	char cc;
	char buf[CMSG_SPACE(sizeof(int))];
	int nsfd = -1, i, k;

	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");
	{
		static const char *old[] = { "x0", "w0", "x1", "w1" };

		for (i = 0; i < 4; i++)
			f558_link_del(old[i]);
	}
	if (link_add_veth("x0", "x1")) {
		printf("F579 FAIL|veth\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/accept_ra", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/autoconf", "0");
	f564_addr6("x1", A79_D, 64);
	/* vid 100 on the receiving side: without it a tagged frame dies as
	 * PACKET_OTHERHOST (F52 §1) and a rule that misses it cannot be shown
	 * to matter; with it the frame is demultiplexed and delivered. */
	k = f575_link_add_vlan("x1.100", "x1", 100, 0x0000, 0);
	set_up("x1.100");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1.100/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1.100/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1.100/dad_transmits", "0");
	printf("F579 VDEV|mk100=%d|idx100=%d|a6=%d\n", k,
	       f555_ifindex("x1.100"), f564_addr6("x1.100", A79_D, 64));
	printf("F579 PIF6|x1=%s|x1100=%s\n", f579_if6(A79_D), f579_if6(A79_D));
	F579_U6 = f564_udp_bind(AF_INET6, 0, A79_D, F579_DPORT);
	printf("F579 ENV|u6=%d|x0=%d|x1=%d|x0mac=%d|x1mac=%d|userns_max=%s|"
	       "uid=%d|euid=%d\n", F579_U6, f555_ifindex("x0"),
	       f555_ifindex("x1"), mac_get("x0", F579_FM0),
	       mac_get("x1", F579_FM1),
	       f579_sysctl_read("/proc/sys/user/max_user_namespaces"),
	       (int)getuid(), (int)geteuid());

	/* the two chains part B uses; they exist before the census so that the
	 * unprivileged child meets a cap check and not a missing table */
	k = f579_tbl(NFPROTO_NETDEV, F579_TN);
	k |= f579_chn(NFPROTO_NETDEV, F579_TN, "c0", "x1", 0);
	k |= f579_tbl(NFPROTO_IPV6, F579_TG);
	k |= f579_chn(NFPROTO_IPV6, F579_TG, "c0", NULL, 0);
	printf("F579 CHAINS|rc=%d\n", k);

	for (i = 1; i <= F579_NFRM; i++)
		printf("F579 FRMPY|id=%d|len=%d|hex=%s\n", i,
		       f579_frame(F579_FR, i),
		       f559_hexs(F579_HX, sizeof(F579_HX), F579_FR,
				 f579_frame(F579_FR, i)));

	/* ---- part A ---- */
	f579_census_root();

	if (pipe(c2p)) {
		printf("F579 FAIL|pipe\n");
		return -1;
	}
	k = fork();
	if (k == 0) {
		close(c2p[0]);
		f579_child_uid(c2p[1]);
		_exit(0);
	}
	close(c2p[1]);
	memset(&c, 0, sizeof(c));
	f579_rd(c2p[0], &c, sizeof(c));
	close(c2p[0]);
	printf("F579 CAP|ctx=uid1000_init|tbl=%d|chn=%d|rd=%d|st=%d|"
	       "meta=%d|fore=-1\n", c.tbl, c.chn, c.rd, c.st, c.meta);

	/* ---- child B ---- */
	if (pipe(p2c) || pipe(c2p) ||
	    socketpair(AF_UNIX, SOCK_DGRAM, 0, sp)) {
		printf("F579 FAIL|pipe2\n");
		return -1;
	}
	F579_KID = fork();
	if (F579_KID == 0) {
		close(p2c[1]);
		close(c2p[0]);
		close(sp[0]);
		f579_child_ns(p2c[0], c2p[1], sp[1]);
		_exit(0);
	}
	close(p2c[0]);
	close(c2p[1]);
	close(sp[1]);
	F579_CMD = p2c[1];
	F579_ACK = c2p[0];
	{
		int me = -1, ack = 0;

		if (f579_rd(F579_ACK, &me, sizeof(me))) {
			printf("F579 FAIL|nspid\n");
			return -1;
		}
		ack = f579_maps(me) ? -1 : 0;
		f579_wr(F579_CMD, &ack, sizeof(ack));
	}
	memset(&mh, 0, sizeof(mh));
	iov.iov_base = &cc;
	iov.iov_len = 1;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = buf;
	mh.msg_controllen = sizeof(buf);
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };

		setsockopt(sp[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	if (recvmsg(sp[0], &mh, 0) < 0) {
		printf("F579 FAIL|nsfd\n");
		return -1;
	}
	cm = CMSG_FIRSTHDR(&mh);
	if (cm)
		memcpy(&nsfd, CMSG_DATA(cm), sizeof(int));
	printf("F579 NSFD|fd=%d|link=%s\n", nsfd, f579_fdlink(nsfd));
	memset(&c, 0, sizeof(c));
	f579_rd(F579_ACK, &c, sizeof(c));
	printf("F579 UNSHARE|uid_in=%d|veth=%d|iw0=%d|iw1=%d|ix1=%d\n",
	       c.un, c.veth, c.iw0, c.iw1, c.ix1);
	printf("F579 CAP|ctx=userns_own|tbl=%d|chn=%d|rd=%d|st=%d|meta=%d|"
	       "fore=%d|fore2=%d|fx_ch=%d|fx_u6=%d|fx_rcv=%d|fx2_ch=%d|fx2_u6=%d|"
	       "a6=%d|dis=%d|fx2_rcv=%d|fx2_deliv=%d|fx2_addrerr=%d|"
	       "fx2_disc=%d|if6=%s\n",
	       c.tbl, c.chn, c.rd, c.st, c.meta, c.fore, c.fore2,
	       c.fx_ch, c.fx_u6, c.fx_rcv, c.fx2_ch, c.fx2_u6, c.a6, c.dis,
	       c.fx2_rcv, c.fx2_deliv, c.fx2_addrerr, c.fx2_disc, c.if6);

	{
		int rc = f579_move_ns("x0", nsfd);

		printf("F579 MOVE|dev=x0|rc=%d|here=%d\n", rc,
		       f555_ifindex("x0"));
	}
	printf("F579 CHILDUPA|rc=%d\n", f579_ask(1));
	usleep(600000);
	(void)f579_drain(NULL);

	/* ---- part B ---- */
	for (i = 0; i < NA579; i++)
		f579_armB(&A579[i]);

	f579_ask(0);
	waitpid(F579_KID, NULL, 0);
	f579_flush();
	{
		static const char *end[] = { "x1.100", "x0", "x1" };

		for (i = 0; i < 3; i++)
			f558_link_del(end[i]);
	}
	printf("F579 END|arms=%d|frames=%d\n", NA579, F579_NFRM);
	fflush(stdout);
	return 0;
}


/* ---------- a probe that can only answer one question ------------------ */

static int f579_probe(void)
{
	int pid, st;

	printf("F579 PROBE|start\n");
	fflush(stdout);
	pid = fork();
	if (pid == 0) {
		int u, x;

		alarm(30);
		setgid(1000);
		setuid(1000);
		printf("F579 PROBE|pre|uid=%d|euid=%d\n", (int)getuid(),
		       (int)geteuid());
		fflush(stdout);
		u = unshare(CLONE_NEWUSER | CLONE_NEWNET);
		printf("F579 PROBE|un=%d|errno=%d\n", u, errno);
		fflush(stdout);
		if (!u) {
			x = f579_wrfile("/proc/self/setgroups", "deny\n", 5);
			printf("F579 PROBE|setgroups=%d\n", x);
			fflush(stdout);
			x = f579_wrfile("/proc/self/uid_map", "0 1000 1\n", 9);
			printf("F579 PROBE|uidmap=%d\n", x);
			fflush(stdout);
			x = f579_wrfile("/proc/self/gid_map", "0 1000 1\n", 9);
			printf("F579 PROBE|gidmap=%d\n", x);
			fflush(stdout);
			x = setgid(0) | setuid(0);
			printf("F579 PROBE|inroot=%d|uid=%d\n", x, (int)getuid());
			fflush(stdout);
			x = link_add_veth("w0", "w1");
			printf("F579 PROBE|veth=%d|w0=%d|w1=%d\n", x,
			       f555_ifindex("w0"), f555_ifindex("w1"));
			fflush(stdout);
		}
		_exit(0);
	}
	waitpid(pid, &st, 0);
	printf("F579 PROBE|done|status=%d\n", st);
	fflush(stdout);
	return 0;
}

/* ---------- entry ------------------------------------------------------ */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "priv";

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("F579 BOOT|mode=%s|argc=%d\n", mode, argc);
	if (!strcmp(mode, "priv"))
		return f579_priv();
	if (!strcmp(mode, "probe"))
		return f579_probe();
	return f578_entry(argc, argv);
}
