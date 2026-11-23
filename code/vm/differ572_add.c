/* differ572_add.c -- turn 572 (F50).
 *
 *  THE DEBT (named at the end of 571): "the one door left where the same frame
 *  reaches the @nh guard with mac_len != 0 and pf = NFPROTO_IPV6 at once --
 *  ppp0 inside a bridge."
 *
 *  Mode `ll3br`: two veth pairs, one bridge br0 with ports x1 and y1, IPv6
 *  enabled on br0 only.  One frame is injected on x0 (80 bytes):
 *
 *    ethernet broadcast (14) | IPv6 fd02::11 -> fd02::92 (40) | UDP (8) | 18x77
 *
 *  and the same skb is presented to four doors in one boot:
 *
 *    in6   ip6    prerouting   (all devs)  <- the layer-3 door of the bridge
 *    i6in  ip6    input        (all devs)  <- witness: the same skb, one door on
 *    brp   bridge prerouting   on br0      <- the door of F37/F38, before the
 *                                             bridge makes its copies
 *    nd1   netdev ingress      on x1       <- the door of F44, no guard at all
 *
 *  Oracles: the rule's own counter (guard verdict), a read-back at the NEXT
 *  door of the same skb, two AF_PACKET taps (br0 = the local copy before the
 *  hook, y0 = the port's copy after the hook), the socket, the net-wide SNMP6
 *  counters and the per-device rx_otherhost_dropped from IFLA_STATS64.
 *
 *  Mode `ll3br` also closes the 571 debt by measurement: br_add_if() is asked
 *  to enslave ppp0 (ARPHRD_PPP, type 512) and lo, and the rc is printed.
 *
 *  Every helper below the new code is the one that produced F31..F49.
 */

#define F572_SID	99
#define F572_SPORT	40000
#define F572_DPORT	5000
#define F572_TAPN	2
#define F572_NDOOR	4
#define ND72		4

/* the IPv6 datagram the frame carries: fd02::11 -> fd02::92 (br0) */
static const unsigned char A72_SRC[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x11 };
static const unsigned char A72_DST[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x92 };
static const unsigned char A72_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const unsigned char A72_NEEDLE[6] = { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95 };
static const unsigned char A72_N2[2] = { 0x90, 0x91 };
static const unsigned char A72_N4[4] = { 0x90, 0x91, 0x92, 0x93 };

/* ---------- the four doors ---------- */

static struct f571_door D572[] = {
	{ "in6",  NFPROTO_IPV6,   "e72a", NULL,  0, 10, 20 },	/* prerouting */
	{ "i6in", NFPROTO_IPV6,   "e72b", NULL,  1, 30, 40 },	/* input      */
	/* NOTE: this kernel's nft_chain_parse_hook() accepts NFTA_HOOK_DEV only
	 * for the netdev family hooks; a bridge-family chain cannot be pinned
	 * to a device (-EOPNOTSUPP, measured in the first smoke). */
	{ "brp",  NFPROTO_BRIDGE, "e72c", NULL,  0, 50, 60 },	/* NF_BR_PRE  */
	{ "nd1",  NFPROTO_NETDEV, "e72d", "x1",  0, 70, 80 },	/* ingress    */
};
enum { E_IN6 = 0, E_I6IN, E_BRP, E_ND1 };

static unsigned char F572_X0M[6], F572_BRM[6];
static char F572_PPP[16];
static int F572_U6 = -1, F572_NFL = -1;
static unsigned char F572_FR[256];
static int F572_FRLEN = -1;

/* taps: 0 = br0 (the local copy, before the hook), 1 = y0 (the port's copy) */
struct f572_tap {
	int fd;
	int n;
	int len;	/* bytes copied into b[] */
	int flen;	/* the frame's real length */
	unsigned char b[64];
};
static struct f572_tap F572_TAP[F572_TAPN];
static const char *F572_TAPDEV[F572_TAPN] = { "br0", "y0" };

/* ---------- /sys readers ---------- */

static int f572_sysint(const char *path)
{
	FILE *f = fopen(path, "r");
	int v = -2;

	if (!f)
		return -1;
	if (fscanf(f, "%d", &v) != 1)
		v = -3;
	fclose(f);
	return v;
}

static int f572_exists(const char *path)
{
	FILE *f = fopen(path, "r");

	if (!f)
		return 0;
	fclose(f);
	return 1;
}

/* ---------- IFLA_STATS64: rx_otherhost_dropped lives only here ---------- */

struct f572_lst {
	unsigned long long rxp, txp, rxb, txb, rxd, txd, other;
	int ok;
};

static unsigned long long f572_u64(const unsigned char *p)
{
	unsigned long long v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = (v << 8) | (unsigned long long)p[i];
	return v;
}

#define F572_IFLA_STATS64 23	/* uapi/linux/if_link.h enum position */
#define F572_OFF_OTHERHOST 192	/* 24th u64 of struct rtnl_link_stats64 */

static void f572_stats(const char *dev, struct f572_lst *s)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req;
	unsigned char rbuf[8192];
	struct nlmsghdr *nlh;
	struct sockaddr_nl sa;
	int fd, idx = f555_ifindex(dev), r;

	memset(s, 0, sizeof(*s));
	if (idx < 0)
		return;
	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 7;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = idx;
	if (sendto(fd, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa,
		   sizeof(sa)) < 0) {
		close(fd);
		return;
	}
	r = (int)recv(fd, rbuf, sizeof(rbuf), 0);
	close(fd);
	if (r < (int)(NLMSG_HDRLEN + sizeof(struct ifinfomsg)))
		return;
	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR)
		return;
	{
		const char *p = (const char *)nlh + NLMSG_HDRLEN +
				sizeof(struct ifinfomsg);
		const char *end = (const char *)nlh + nlh->nlmsg_len;

		for (; p + (int)sizeof(struct nlattr) <= end; ) {
			const struct nlattr *a = (const struct nlattr *)p;
			int al = (int)a->nla_len, t;

			if (al < (int)sizeof(*a) || p + al > end)
				break;
			t = a->nla_type & 0x3fff;
			if (t == F572_IFLA_STATS64 &&
			    al - NLA_HDRLEN >= F572_OFF_OTHERHOST + 8) {
				const unsigned char *d =
					(const unsigned char *)a + NLA_HDRLEN;

				s->rxp = f572_u64(d + 0);
				s->txp = f572_u64(d + 8);
				s->rxb = f572_u64(d + 16);
				s->txb = f572_u64(d + 24);
				s->rxd = f572_u64(d + 48);
				s->txd = f572_u64(d + 56);
				s->other = f572_u64(d + F572_OFF_OTHERHOST);
				s->ok = 1;
			}
			p += NLA_ALIGN_(al);
		}
	}
}

/* ---------- environment ---------- */

/* the PPPoE unit of F49, bound on x0 (not a bridge port) */
static int f572_ppp_make(void)
{
	int u = -1, idx = -1, up, sock, fdu, fdc;

	sock = f563_pppoe_sock("x0", htons(F572_SID), F572_X0M);
	if (sock < 0) {
		printf("F572 PPP|fail|sock|%d\n", sock);
		return -1;
	}
	if (ioctl(sock, PPPIOCGCHAN, &idx) < 0) {
		printf("F572 PPP|fail|gchan|%d\n", errno);
		return -1;
	}
	fdu = open("/dev/ppp", O_RDWR);
	if (fdu < 0) {
		printf("F572 PPP|fail|unit|%d\n", errno);
		return -1;
	}
	if (ioctl(fdu, PPPIOCNEWUNIT, &u) < 0) {
		printf("F572 PPP|fail|newunit|%d\n", errno);
		return -1;
	}
	fdc = open("/dev/ppp", O_RDWR);
	if (fdc < 0) {
		printf("F572 PPP|fail|chan|%d\n", errno);
		return -1;
	}
	if (ioctl(fdc, PPPIOCATTCHAN, &idx) < 0) {
		printf("F572 PPP|fail|attchan|%d\n", errno);
		return -1;
	}
	if (ioctl(fdc, PPPIOCCONNECT, &u) < 0) {
		printf("F572 PPP|fail|connect|%d\n", errno);
		return -1;
	}
	snprintf(F572_PPP, sizeof(F572_PPP), "ppp%d", u);
	up = set_up(F572_PPP);
	printf("F572 PPP|unit=%d|chan=%d|dev=%s|ifindex=%d|up=%d|type=%d\n", u,
	       idx, F572_PPP, f555_ifindex(F572_PPP), up,
	       f572_sysint("/sys/class/net/ppp0/type"));
	return 0;
}

static int f572_env(void)
{
	char path[96];

	f572_stats("lo", &(struct f572_lst){ 0 });
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
	if (link_add_veth("x0", "x1") || link_add_veth("y0", "y1")) {
		printf("F572 FAIL|veth\n");
		return -1;
	}
	if (f556_link_add_kind("br0", "bridge")) {
		printf("F572 FAIL|bridge\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	set_up("y0");
	set_up("y1");
	set_up("br0");
	if (mac_get("x0", F572_X0M)) {
		printf("F572 FAIL|mac\n");
		return -1;
	}
	/* ports are enslaved after everything is up, so br_stp_enable_port()
	 * runs and the ports are FORWARDING with no STP */
	printf("F572 REF|arm=ok_x1|port=x1|master=br0|rc=%d\n",
	       f556_link_enslave("x1", "br0"));
	printf("F572 REF|arm=ok_y1|port=y1|master=br0|rc=%d\n",
	       f556_link_enslave("y1", "br0"));
	/* br0's MAC is recalculated when a port is added (br_stp_recalculate_
	 * bridge_id), so it must be read AFTER the enslave, not before. */
	if (mac_get("br0", F572_BRM)) {
		printf("F572 FAIL|mac_br\n");
		return -1;
	}

	f555_sysctl("/proc/sys/net/ipv6/conf/br0/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/accept_ra", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/autoconf", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/forwarding", "0");
	f555_sysctl("/sys/class/net/br0/bridge/multicast_snooping", "0");
	f555_sysctl("/sys/class/net/br0/bridge/multicast_querier", "0");
	printf("F572 ADDR6|rc=%d\n", f564_addr6("br0", A72_DST, 128));
	F572_U6 = f564_udp_bind(AF_INET6, 0, A72_DST, F572_DPORT);
	F572_NFL = nfl_open(5);
	F571_NFL = F572_NFL;	/* f571_nfl_drain() reads F571_NFL */
	F572_FRLEN = f570_frame_plain(F572_FR, A72_BC, F572_X0M, A72_SRC,
				      A72_DST, 0);
	if (f572_ppp_make())
		return -2;
	{
		char hx[64], hy[64], hf[256];

		printf("F572 ENV|u6=%d|nfl=%d|flen=%d|br0=%d|x1=%d|y0=%d|"
		       "br0mac=%s|x0mac=%s|frame=%s\n",
		       F572_U6, F572_NFL, F572_FRLEN, f555_ifindex("br0"),
		       f555_ifindex("x1"), f555_ifindex("y0"),
		       f559_hexs(hx, sizeof(hx), F572_BRM, 6),
		       f559_hexs(hy, sizeof(hy), F572_X0M, 6),
		       f559_hexs(hf, sizeof(hf), F572_FR, F572_FRLEN));
	}
	printf("F572 SYS|stp=%d|x1state=%d|y1state=%d|mcsnoop=%d|"
	       "br0v6=%d|br0dad=%d|x1v6=%d|y0v6=%d|br0mclen=%d\n",
	       f572_sysint("/sys/class/net/br0/bridge/stp_state"),
	       f572_sysint("/sys/class/net/x1/brport/state"),
	       f572_sysint("/sys/class/net/y1/brport/state"),
	       f572_sysint("/sys/class/net/br0/bridge/multicast_snooping"),
	       f572_sysint("/proc/sys/net/ipv6/conf/br0/disable_ipv6"),
	       f572_sysint("/proc/sys/net/ipv6/conf/br0/accept_dad"),
	       f572_sysint("/proc/sys/net/ipv6/conf/x1/disable_ipv6"),
	       f572_sysint("/proc/sys/net/ipv6/conf/y0/disable_ipv6"),
	       f572_sysint("/sys/class/net/br0/mtu"));
	{
		int i;

		for (i = 0; i < F572_TAPN; i++) {
			F572_TAP[i].fd = f571_tap_open(F572_TAPDEV[i]);
			F572_TAP[i].n = 0;
			F572_TAP[i].len = -1;
		}
		printf("F572 TAP|br0=%d|y0=%d\n", F572_TAP[0].fd,
		       F572_TAP[1].fd);
	}
	return 0;
}

static int f572_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND72; i++) {
		struct f571_door *D = &D572[i];
		int a, b, c;

		a = add_table(D->fam, D->table);
		b = f556_add_chain(D->fam, D->table, "pre0", D->hook,
				   (uint32_t)D->prio0, 1, D->dev);
		c = f556_add_chain(D->fam, D->table, "ch", D->hook,
				   (uint32_t)D->prio1, 1, D->dev);
		printf("F572 CH|door=%s|fam=%d|dev=%s|table=%d|pre0=%d|ch=%d\n",
		       D->tag, (int)D->fam, D->dev ? D->dev : "-", a, b, c);
		rc |= a | b | c;
	}
	/* the witness chain: a separate base chain at the input hook */
	{
		int w = f556_add_chain(NFPROTO_IPV6, D572[E_I6IN].table, "chk",
				       D572[E_I6IN].hook,
				       (uint32_t)(D572[E_I6IN].prio1 + 10), 1,
				       NULL);

		printf("F572 CH|door=chk|fam=10|dev=-|table=-1|pre0=-1|ch=%d\n",
		       w);
		rc |= w;
	}
	return rc;
}

static void f572_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND72; i++) {
		f557_flush(D572[i].fam, D572[i].table, "pre0", &acks);
		f557_flush(D572[i].fam, D572[i].table, "ch", &acks);
	}
	f557_flush(NFPROTO_IPV6, D572[E_I6IN].table, "chk", &acks);
}

/* ---------- the snapshot ---------- */

struct f572_rep {
	int u6n, u6len, u6sport;
	unsigned long long i6in, i6hdr, i6addr, i6unk, i6trunc, i6noroute,
			   i6deliv, u6in, u6err, u6noport, i6disc, i6mcast;
	unsigned long long brrxp, brrxb;
	unsigned long long y0rxp, y0rxd, y0other;
	int y0ok;
};

static void f572_u6_drain(struct f572_rep *R)
{
	unsigned char b[1024];
	struct sockaddr_in6 sa;
	socklen_t sl;
	int r, k;

	if (F572_U6 < 0)
		return;
	for (;;) {
		memset(&sa, 0, sizeof(sa));
		sl = sizeof(sa);
		r = (int)recvfrom(F572_U6, b, sizeof(b), MSG_DONTWAIT,
				  (struct sockaddr *)&sa, &sl);
		if (r < 0)
			break;
		if (!f568_needle(b, r))
			continue;
		R->u6n++;
		R->u6len = r;
		R->u6sport = ntohs(sa.sin6_port);
		k = r;
		(void)k;
	}
}

static void f572_snap(struct f572_rep *R)
{
	struct f572_lst s;

	f572_u6_drain(R);
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
	f572_stats("br0", &s);
	R->brrxp = s.rxp;
	R->brrxb = s.rxb;
	f572_stats("y0", &s);
	R->y0rxp = s.rxp;
	R->y0rxd = s.rxd;
	R->y0other = s.other;
	R->y0ok = s.ok;
}

static void f572_tap_drain(int i)
{
	unsigned char b[2048];
	int r;

	F572_TAP[i].n = 0;
	F572_TAP[i].len = -1;
	F572_TAP[i].flen = -1;
	if (F572_TAP[i].fd < 0)
		return;
	while ((r = (int)recv(F572_TAP[i].fd, b, sizeof(b), MSG_DONTWAIT)) >
	       0) {
		if (!f568_needle(b, r))
			continue;
		F572_TAP[i].n++;
		if (F572_TAP[i].len < 0) {
			F572_TAP[i].flen = r;
			int k = r < (int)sizeof(F572_TAP[i].b)
					? r : (int)sizeof(F572_TAP[i].b);

			memcpy(F572_TAP[i].b, b, (size_t)k);
			F572_TAP[i].len = k;
		}
	}
}

/* ---------- one arm ---------- */

/* W == NULL: no witness chain.  door2 == -1: witness not used. */
static void f572_arm(int door, const char *sec, const char *arm,
		     const struct f571_cfg *Cp, const struct f571_cfg *C,
		     const struct f571_cfg *W, int send, int maxp)
{
	struct f571_door *D = &D572[door];
	struct f571_cfg N, Z;
	struct f572_rep r0, r;
	struct f571_pl pl;
	unsigned long long c0p, c0s, c0w, c1p, c1s, c1w;
	int rcp = -1, rcs = -1, rcw = -1, acks = 0, snd = 0, polls = 0, k;
	const struct f571_msg *mp = NULL;
	char hx[300], hm[40], hy[400], hq[200], hr[200], ht[200], hb[80];

	memset(&r0, 0, sizeof(r0));
	memset(&r, 0, sizeof(r));
	f571_zero(&N, "pre");
	f571_zero(&Z, "w");
	f572_flush_all();
	f571_nfl_drain(NULL);
	for (k = 0; k < F572_TAPN; k++)
		f572_tap_drain(k);
	for (k = 0; k < F572_TAPN; k++) {
		F572_TAP[k].n = 0;
		F572_TAP[k].len = -1;
		F572_TAP[k].flen = -1;
	}
	f572_snap(&r0);
	rcp = f571_rule(D, "pre0", "p", Cp ? Cp : &N, &acks);
	if (C)
		rcs = f571_rule(D, "ch", "s", C, &acks);
	if (W)
		rcw = f571_rule(&D572[E_I6IN], "chk", "w", W, &acks);
	c0p = f555_count(D->fam, D->table, "pre0");
	c0s = f555_count(D->fam, D->table, "ch");
	c0w = f555_count(NFPROTO_IPV6, D572[E_I6IN].table, "chk");
	f572_u6_drain(&r0);
	if (send)
		snd = pkt_send_p("x0", F572_FR, F572_FRLEN, 0x86dd);
	if (send) {
		for (k = 0; k < maxp; k++) {
			usleep(120000);
			f572_snap(&r);
			polls++;
			if (r.u6n > r0.u6n || r.i6in > r0.i6in ||
			    r.i6disc > r0.i6disc || r.i6hdr > r0.i6hdr ||
			    r.i6deliv > r0.i6deliv ||
			    r.y0other > r0.y0other ||
			    r.y0rxp > r0.y0rxp)
				break;
		}
	} else {
		usleep(300000);
		f572_snap(&r);
		polls = 1;
	}
	f572_snap(&r);
	usleep(150000);
	f572_snap(&r);
	c1p = f555_count(D->fam, D->table, "pre0");
	c1s = f555_count(D->fam, D->table, "ch");
	c1w = f555_count(NFPROTO_IPV6, D572[E_I6IN].table, "chk");
	memset(&pl, 0, sizeof(pl));
	f571_nfl_drain(&pl);
	for (k = 0; k < pl.n; k++) {
		if (pl.m[k].prefix[0] == 's' && !mp)
			mp = &pl.m[k];
	}
	for (k = 0; k < F572_TAPN; k++)
		f572_tap_drain(k);

	printf("F572 A|sec=%s|arm=%s|door=%s|mode=%d|base=%u|off=%d|len=%d|"
	       "imm=%s|rcp=%d|rcs=%d|rcw=%d|sendrc=%d|snt=%d|"
	       "cntp=%llu|cnts=%llu|cntw=%lld|polls=%d|"
	       "u6n=%d|u6len=%d|u6sport=%d\n",
	       sec, arm, D->tag, C ? C->mode : -1, C ? C->base : 0,
	       C ? C->off : -1, C ? C->len : -1,
	       C ? f559_hexs(hx, sizeof(hx), C->imm, C->len) : "-", rcp, rcs,
	       rcw, snd, send, c1p - c0p, c1s - c0s,
	       W ? (long long)(c1w - c0w) : -1LL, polls, r.u6n - r0.u6n,
	       r.u6len, r.u6sport);
	printf("F572 B|i6in_d=%llu|i6hdr_d=%llu|i6addr_d=%llu|i6unk_d=%llu|"
	       "i6trunc_d=%llu|i6noroute_d=%llu|deliv_d=%llu|u6in_d=%llu|"
	       "u6err_d=%llu|i6disc_d=%llu|i6mcast_d=%llu|"
	       "brrxp_d=%llu|brrxb_d=%llu|y0rxp_d=%llu|y0rxd_d=%llu|"
	       "y0other_d=%llu|y0ok=%d\n",
	       r.i6in - r0.i6in, r.i6hdr - r0.i6hdr, r.i6addr - r0.i6addr,
	       r.i6unk - r0.i6unk, r.i6trunc - r0.i6trunc,
	       r.i6noroute - r0.i6noroute, r.i6deliv - r0.i6deliv,
	       r.u6in - r0.u6in, r.u6err - r0.u6err, r.i6disc - r0.i6disc,
	       r.i6mcast - r0.i6mcast, r.brrxp - r0.brrxp,
	       r.brrxb - r0.brrxb, r.y0rxp - r0.y0rxp, r.y0rxd - r0.y0rxd,
	       r.y0other - r0.y0other, r.y0ok);
	{
		char mb[600];
		int i2, o2 = 0;

		mb[0] = 0;
		for (i2 = 0; i2 < pl.n && i2 < F571_NPL; i2++) {
			char hh[80];
			int w = snprintf(mb + o2, sizeof(mb) - (size_t)o2,
					 "|m%d=%s:%s:%d", i2,
					 pl.m[i2].prefix,
					 f559_hexs(hh, sizeof(hh), pl.m[i2].hw,
						   pl.m[i2].hwlen2),
					 pl.m[i2].plen);

			if (w < 0 || w >= (int)sizeof(mb) - o2)
				break;
			o2 += w;
		}
		printf("F572 M|n=%d%s\n", pl.n, mb);
	}
	printf("F572 N|prelen=%d|pre=%s|prel2=%d|prehw=%d|preht=%d|prehh=%d|"
	       "preind=%d|prehwhex=%s|postlen=%d|postind=%d|posthw=%d\n",
	       mp ? mp->plen : -1,
	       mp ? f559_hexs(hy, sizeof(hy), mp->p, mp->plen) : "-",
	       mp ? mp->l2len : -1, mp ? mp->hwlen : -1, mp ? mp->hwtype : -1,
	       mp ? mp->hwhdr : -1, mp ? mp->indev : -1,
	       mp && mp->hwlen2 > 0
		       ? f559_hexs(hq, sizeof(hq), mp->hw, mp->hwlen2) : "-",
	       mp ? mp->plen : -1, mp ? mp->indev : -1, mp ? mp->hwlen : -1);
	{
		char d0[24], t0[16], d1[24], t1[16];

		d0[0] = t0[0] = d1[0] = t1[0] = 0;
		if (F572_TAP[0].len > 0)
			f559_hexs(d0, sizeof(d0), F572_TAP[0].b, 6);
		if (F572_TAP[0].len > 13)
			f559_hexs(t0, sizeof(t0), F572_TAP[0].b + 12, 2);
		if (F572_TAP[1].len > 0)
			f559_hexs(d1, sizeof(d1), F572_TAP[1].b, 6);
		if (F572_TAP[1].len > 13)
			f559_hexs(t1, sizeof(t1), F572_TAP[1].b + 12, 2);
		printf("F572 T|brn=%d|brlen=%d|brhex=%s|farn=%d|farlen=%d|"
		       "farhex=%s|brdst=%s|brtype=%s|fardst=%s|bartype=%s\n",
		       F572_TAP[0].n, F572_TAP[0].flen,
		       F572_TAP[0].len > 0
			       ? f559_hexs(hr, sizeof(hr), F572_TAP[0].b, 20)
			       : "-",
		       F572_TAP[1].n, F572_TAP[1].flen,
		       F572_TAP[1].len > 0
			       ? f559_hexs(ht, sizeof(ht), F572_TAP[1].b, 20)
			       : "-",
		       d0[0] ? d0 : "-", t0[0] ? t0 : "-",
		       d1[0] ? d1 : "-", t1[0] ? t1 : "-");
	}
}

/* ---------- config builders ---------- */

static void f572_rd(struct f571_cfg *C, const char *arm, uint32_t base,
		    int off, int len, const unsigned char *src)
{
	f571_rd(C, arm, base, off, len, src);
}

static void f572_wr(struct f571_cfg *C, const char *arm, uint32_t base,
		    int off, int len, const unsigned char *imm)
{
	f571_wr(C, arm, base, off, len, imm, 0, 0);
}

/* a read cell whose immediate is `imm` itself (f571_rd() takes src+off,
 * which is right for "what the frame carries" and wrong for "what a store
 * should have put there") */
static void f572_rdv(struct f571_cfg *C, const char *arm, uint32_t base,
		     int off, int len, const unsigned char *imm)
{
	f571_zero(C, arm);
	C->mode = 3;
	C->base = base;
	C->off = off;
	C->len = len;
	memcpy(C->imm, imm, (size_t)len);
}

/* ---------- section `ref`: the door of 571 does not exist ---------- */

static void f572_ref(const char *arm, const char *port, const char *master)
{
	char p[128];
	int rc = f556_link_enslave(port, master), type, masterf;

	snprintf(p, sizeof(p), "/sys/class/net/%s/master", port);
	masterf = f572_exists(p);
	snprintf(p, sizeof(p), "/sys/class/net/%s/type", port);
	type = f572_sysint(p);
	printf("F572 R|arm=%s|port=%s|master=%s|rc=%d|type=%d|masterf=%d|"
	       "iff=%d\n", arm, port, master, rc, type, masterf,
	       f555_ifindex(port));
}

static void f572_sec_ref(void)
{
	f572_ref("ref_ppp", F572_PPP, "br0");
	f572_ref("ref_lo", "lo", "br0");
	f572_ref("ok_y1", "y1", "br0");
	f572_ref("ok_x1", "x1", "br0");
}

/* ---------- section `rd`: the read domain of @ll at a layer-3 door ------ */

static const int F572_OFFS[12] = { 0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24 };
static const int F572_LENS[3] = { 1, 2, 4 };

static void f572_sec_rd(void)
{
	struct f571_cfg C;
	const unsigned char *fr = F572_FR;
	const unsigned char *ip = F572_FR + 14;
	int i, j;
	char nm[24];

	for (i = 0; i < 12; i++) {
		for (j = 0; j < 3; j++) {
			snprintf(nm, sizeof(nm), "r%d_%d", F572_OFFS[i],
				 F572_LENS[j]);
			f572_rd(&C, nm, NFT_PAYLOAD_LL_HEADER, F572_OFFS[i],
				F572_LENS[j], fr);
			f572_arm(E_IN6, "rd", nm, NULL, &C, NULL, 1, 10);
		}
	}
	/* the same base at the netdev ingress door of F44 */
	snprintf(nm, sizeof(nm), "r0_6_nd");
	f572_rd(&C, nm, NFT_PAYLOAD_LL_HEADER, 0, 6, fr);
	f572_arm(E_ND1, "rd", nm, NULL, &C, NULL, 1, 10);
	snprintf(nm, sizeof(nm), "r14_2_nd");
	f572_rd(&C, nm, NFT_PAYLOAD_LL_HEADER, 14, 2, fr);
	f572_arm(E_ND1, "rd", nm, NULL, &C, NULL, 1, 10);
	snprintf(nm, sizeof(nm), "r13_1_nd");
	f572_rd(&C, nm, NFT_PAYLOAD_LL_HEADER, 13, 1, fr);
	f572_arm(E_ND1, "rd", nm, NULL, &C, NULL, 1, 10);
	/* @nh at the layer-3 door of the bridge: base at 14, not 0 */
	snprintf(nm, sizeof(nm), "nh0");
	f572_rd(&C, nm, NFT_PAYLOAD_NETWORK_HEADER, 0, 4, ip);
	f572_arm(E_IN6, "rd", nm, NULL, &C, NULL, 1, 10);
	snprintf(nm, sizeof(nm), "nh7");
	f572_rd(&C, nm, NFT_PAYLOAD_NETWORK_HEADER, 7, 1, ip);
	f572_arm(E_IN6, "rd", nm, NULL, &C, NULL, 1, 10);
	/* state->pf, measured */
	snprintf(nm, sizeof(nm), "pf6");
	f571_zero(&C, nm);
	C.meta = NFT_META_NFPROTO;
	C.mv[0] = 10;
	C.mlen = 1;
	f572_arm(E_IN6, "rd", nm, NULL, &C, NULL, 1, 10);
	snprintf(nm, sizeof(nm), "pfbr");
	f571_zero(&C, nm);
	C.meta = NFT_META_NFPROTO;
	C.mv[0] = 7;
	C.mlen = 1;
	f572_arm(E_BRP, "rd", nm, NULL, &C, NULL, 1, 10);
	{
		struct f571_cfg M2;

		f571_zero(&M2, "ctlb");
		f572_arm(E_BRP, "rd", "ctlb", NULL, &M2, NULL, 1, 10);
	}
}

/* ---------- section `wr`: the write domain of @ll at the same door ------ */

static void f572_sec_wr(void)
{
	struct f571_cfg C;
	int i, j;
	char nm[24];

	for (i = 0; i < 12; i++) {
		for (j = 0; j < 3; j++) {
			snprintf(nm, sizeof(nm), "w%d_%d", F572_OFFS[i],
				 F572_LENS[j]);
			if (F572_LENS[j] == 1)
				f572_wr(&C, nm, NFT_PAYLOAD_LL_HEADER,
					F572_OFFS[i], 1, A72_N4);
			else if (F572_LENS[j] == 2)
				f572_wr(&C, nm, NFT_PAYLOAD_LL_HEADER,
					F572_OFFS[i], 2, A72_N2);
			else
				f572_wr(&C, nm, NFT_PAYLOAD_LL_HEADER,
					F572_OFFS[i], 4, A72_N4);
			f572_arm(E_IN6, "wr", nm, NULL, &C, NULL, 1, 12);
		}
	}
	snprintf(nm, sizeof(nm), "w12_4_nd");
	f572_wr(&C, nm, NFT_PAYLOAD_LL_HEADER, 12, 4, A72_N4);
	f572_arm(E_ND1, "wr", nm, NULL, &C, NULL, 1, 12);
	snprintf(nm, sizeof(nm), "w14_1_nd");
	f572_wr(&C, nm, NFT_PAYLOAD_LL_HEADER, 14, 1, A72_N4);
	f572_arm(E_ND1, "wr", nm, NULL, &C, NULL, 1, 12);
	snprintf(nm, sizeof(nm), "w20_4_nd");
	f572_wr(&C, nm, NFT_PAYLOAD_LL_HEADER, 20, 4, A72_N4);
	f572_arm(E_ND1, "wr", nm, NULL, &C, NULL, 1, 12);
}

/* ---------- section `inv`: what the same accept means at two doors ------ */

static void f572_sec_inv(void)
{
	struct f571_cfg C, W;
	static const unsigned char et86dd[2] = { 0x86, 0xdd };
	static const unsigned char et0806[2] = { 0x08, 0x06 };

	/* control: no store anywhere, the witness reads the broadcast MAC */
	f571_zero(&C, "ctl");
	f572_rdv(&W, "w_bc", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_BC);
	f572_arm(E_IN6, "inv", "ctl", NULL, &C, &W, 1, 12);

	/* the dst MAC written at the layer-3 door of the bridge */
	f572_wr(&C, "pre_dst", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_NEEDLE);
	f572_rdv(&W, "w_dst", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_NEEDLE);
	f572_arm(E_IN6, "inv", "pre_dst", NULL, &C, &W, 1, 12);

	/* the same write at the netdev ingress door: before the bridge */
	f572_wr(&C, "nd_dst", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_NEEDLE);
	f572_rdv(&W, "w_dst", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_NEEDLE);
	f572_arm(E_ND1, "inv", "nd_dst", NULL, &C, &W, 1, 12);

	/* the same write at the bridge prerouting door: after ingress, before
	 * the forwarding decision */
	f572_wr(&C, "br_dst", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_NEEDLE);
	f572_rdv(&W, "w_dst", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_NEEDLE);
	f572_arm(E_BRP, "inv", "br_dst", NULL, &C, &W, 1, 12);

	/* and the same door with the bridge's OWN address as the value */
	f572_wr(&C, "br_dst_br", NFT_PAYLOAD_LL_HEADER, 0, 6, F572_BRM);
	f572_rdv(&W, "w_br", NFT_PAYLOAD_LL_HEADER, 0, 6, F572_BRM);
	f572_arm(E_BRP, "inv", "br_dst_br", NULL, &C, &W, 1, 12);

	/* the bridge door again, but with the value the frame already carries */
	f572_wr(&C, "br_dst_bc", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_BC);
	f572_rdv(&W, "w_bc", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_BC);
	f572_arm(E_BRP, "inv", "br_dst_bc", NULL, &C, &W, 1, 12);

	/* the src MAC written at the layer-3 door */
	f572_wr(&C, "pre_src", NFT_PAYLOAD_LL_HEADER, 6, 6, A72_NEEDLE);
	f572_rdv(&W, "w_src", NFT_PAYLOAD_LL_HEADER, 6, 6, A72_NEEDLE);
	f572_arm(E_IN6, "inv", "pre_src", NULL, &C, &W, 1, 12);

	/* the ethertype written at the layer-3 door */
	f572_wr(&C, "pre_et", NFT_PAYLOAD_LL_HEADER, 12, 2, et0806);
	f572_rdv(&W, "w_et", NFT_PAYLOAD_LL_HEADER, 12, 2, et0806);
	f572_arm(E_IN6, "inv", "pre_et", NULL, &C, &W, 1, 12);

	/* the same write at the bridge prerouting door */
	f572_wr(&C, "br_et", NFT_PAYLOAD_LL_HEADER, 12, 2, et0806);
	f572_rdv(&W, "w_et", NFT_PAYLOAD_LL_HEADER, 12, 2, et0806);
	f572_arm(E_BRP, "inv", "br_et", NULL, &C, &W, 1, 12);

	/* the same value the frame already carries: a same-value control */
	f572_wr(&C, "pre_et6", NFT_PAYLOAD_LL_HEADER, 12, 2, et86dd);
	f572_rdv(&W, "w_et6", NFT_PAYLOAD_LL_HEADER, 12, 2, et86dd);
	f572_arm(E_IN6, "inv", "pre_et6", NULL, &C, &W, 1, 12);

	/* the write at the layer-3 door that the guard refuses: 14+1 */
	f572_wr(&C, "pre_w15", NFT_PAYLOAD_LL_HEADER, 14, 1, A72_N4);
	f572_rdv(&W, "w_dst4", NFT_PAYLOAD_LL_HEADER, 0, 6, A72_BC);
	f572_arm(E_IN6, "inv", "pre_w15", NULL, &C, &W, 1, 12);
}

/* ---------- section `comp`: does the guard read the frame or the cache? -- */

static void f572_sec_comp(void)
{
	struct f571_cfg C;
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	static const unsigned char et0800[2] = { 0x08, 0x00 };
	int acks = 0;

	/* one rule, two expressions, at the bridge door:
	 *   @ll,12,2 = 0800     (accepted: 12+2 = 14 <= 14)
	 *   @nh,10,2 = 9091     (ip4 allows offset 10; ip6 has no case 10) */
	f572_flush_all();
	f571_nfl_drain(NULL);
	{
		struct f571_cfg N;
		struct f572_rep r0, r;
		unsigned long long c0p, c0s, c1p, c1s;
		int k;

		memset(&r0, 0, sizeof(r0));
		memset(&r, 0, sizeof(r));
		f571_zero(&N, "pre");
		f572_snap(&r0);
		f571_rule(&D572[E_BRP], "pre0", "p", &N, &acks);
		nlh = msg_start(opbuf, (int)sizeof(opbuf),
				(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
				NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
					NLM_F_APPEND, NFPROTO_BRIDGE);
		put_str(nlh, NFTA_RULE_TABLE, D572[E_BRP].table);
		put_str(nlh, NFTA_RULE_CHAIN, "ch");
		exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
		f565_store(nlh, NFT_PAYLOAD_LL_HEADER, 12, 2, et0800, 0, 0);
		f565_store(nlh, NFT_PAYLOAD_NETWORK_HEADER, 10, 2, A72_N2, 0, 0);
		log_expr(nlh, 5, "s");
		counter_expr(nlh);
		accept_expr(nlh);
		nest_end(nlh, exprs);
		printf("F572 C|arm=comp_l2l3|rc=%d\n",
		       f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks));
		c0p = f555_count(NFPROTO_BRIDGE, D572[E_BRP].table, "pre0");
		c0s = f555_count(NFPROTO_BRIDGE, D572[E_BRP].table, "ch");
		f572_u6_drain(&r0);
		pkt_send_p("x0", F572_FR, F572_FRLEN, 0x86dd);
		for (k = 0; k < 12; k++) {
			usleep(120000);
			f572_snap(&r);
			if (r.u6n > r0.u6n || r.i6in > r0.i6in ||
			    r.y0rxp > r0.y0rxp)
				break;
		}
		f572_snap(&r);
		c1p = f555_count(NFPROTO_BRIDGE, D572[E_BRP].table, "pre0");
		c1s = f555_count(NFPROTO_BRIDGE, D572[E_BRP].table, "ch");
		{
			struct f571_pl pl;
			const struct f571_msg *mp = NULL;
			char hy[400], hr[200];

			memset(&pl, 0, sizeof(pl));
			f571_nfl_drain(&pl);
			for (k = 0; k < pl.n; k++)
				if (pl.m[k].prefix[0] == 's')
					mp = &pl.m[k];
			f572_tap_drain(0);
			printf("F572 A|sec=comp|arm=comp_l2l3|door=brp|mode=9|"
			       "base=0|off=-1|len=-1|imm=-|rcp=0|rcs=0|rcw=-1|"
			       "sendrc=%d|snt=1|cntp=%llu|cnts=%llu|cntw=-1|"
			       "polls=%d|u6n=%d|u6len=%d|u6sport=%d\n",
			       0, c1p - c0p, c1s - c0s, k, r.u6n - r0.u6n,
			       r.u6len, r.u6sport);
			printf("F572 N|prelen=%d|pre=%s|postlen=%d|"
			       "postind=%d|posthw=-1|prel2=-1|prehw=-1\n",
			       mp ? mp->plen : -1,
			       mp ? f559_hexs(hy, sizeof(hy), mp->p, mp->plen)
				  : "-",
			       mp ? mp->plen : -1, mp ? mp->indev : -1);
			printf("F572 T|brn=%d|brlen=%d|brhex=%s|farn=-1|"
			       "farlen=-1|farhex=-|brdst=%s|brtype=%s|"
			       "fardst=-|bartype=-\n",
			       F572_TAP[0].n, F572_TAP[0].len,
			       F572_TAP[0].len > 0
				       ? f559_hexs(hr, sizeof(hr),
						   F572_TAP[0].b, 20) : "-",
			       F572_TAP[0].len > 0
				       ? f559_hexs(hr, sizeof(hr),
						   F572_TAP[0].b, 6) : "-",
			       F572_TAP[0].len > 13
				       ? f559_hexs(hr, sizeof(hr),
						   F572_TAP[0].b + 12, 2) : "-");
		}
	}
	(void)C;

	/* the reverse: rewrite 86dd -> 0800 is above; now an ip6-only cell
	 * (offset 7) must be refused if the guard still sees ip6 -- and the
	 * same rule with a cell ip6 refuses but ip4 allows is `comp_l2l3`. */
	f572_flush_all();
	f571_nfl_drain(NULL);
	{
		struct f571_cfg N;
		struct f572_rep r0, r;
		unsigned long long c0p, c0s, c1p, c1s;
		int k;

		memset(&r0, 0, sizeof(r0));
		memset(&r, 0, sizeof(r));
		f571_zero(&N, "pre");
		f572_snap(&r0);
		f571_rule(&D572[E_BRP], "pre0", "p", &N, &acks);
		nlh = msg_start(opbuf, (int)sizeof(opbuf),
				(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
				NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
					NLM_F_APPEND, NFPROTO_BRIDGE);
		put_str(nlh, NFTA_RULE_TABLE, D572[E_BRP].table);
		put_str(nlh, NFTA_RULE_CHAIN, "ch");
		exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
		f565_store(nlh, NFT_PAYLOAD_LL_HEADER, 12, 2, et0800, 0, 0);
		f565_store(nlh, NFT_PAYLOAD_NETWORK_HEADER, 7, 1, A72_N4, 0, 0);
		log_expr(nlh, 5, "s");
		counter_expr(nlh);
		accept_expr(nlh);
		nest_end(nlh, exprs);
		printf("F572 C|arm=comp_h7|rc=%d\n",
		       f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks));
		c0p = f555_count(NFPROTO_BRIDGE, D572[E_BRP].table, "pre0");
		c0s = f555_count(NFPROTO_BRIDGE, D572[E_BRP].table, "ch");
		f572_u6_drain(&r0);
		pkt_send_p("x0", F572_FR, F572_FRLEN, 0x86dd);
		for (k = 0; k < 12; k++) {
			usleep(120000);
			f572_snap(&r);
			if (r.u6n > r0.u6n || r.i6in > r0.i6in ||
			    r.y0rxp > r0.y0rxp)
				break;
		}
		f572_snap(&r);
		c1p = f555_count(NFPROTO_BRIDGE, D572[E_BRP].table, "pre0");
		c1s = f555_count(NFPROTO_BRIDGE, D572[E_BRP].table, "ch");
		f572_tap_drain(0);
		printf("F572 A|sec=comp|arm=comp_h7|door=brp|mode=9|base=0|"
		       "off=-1|len=-1|imm=-|rcp=0|rcs=0|rcw=-1|sendrc=0|snt=1|"
		       "cntp=%llu|cnts=%llu|cntw=-1|polls=%d|u6n=%d|u6len=%d|"
		       "u6sport=%d\n", c1p - c0p, c1s - c0s, k,
		       r.u6n - r0.u6n, r.u6len, r.u6sport);
		{
			char hr[200];

			printf("F572 T|brn=%d|brlen=%d|brhex=%s|farn=-1|"
			       "farlen=-1|farhex=-|brdst=-|brtype=%s|fardst=-|"
			       "bartype=-\n", F572_TAP[0].n, F572_TAP[0].len,
			       F572_TAP[0].len > 0
				       ? f559_hexs(hr, sizeof(hr),
						   F572_TAP[0].b, 20) : "-",
			       F572_TAP[0].len > 13
				       ? f559_hexs(hr, sizeof(hr),
						   F572_TAP[0].b + 12, 2) : "-");
		}
		printf("F572 N|prelen=-1|pre=-|postlen=-1|postind=-1|posthw=-1|"
		       "prel2=-1|prehw=-1\n");
	}
}


/* ---------- section `diag`: when is the nflog message built? ------------ */

static void f572_sec_diag(void)
{
	struct f571_cfg S, E;

	/* dg1: the store lives in the chain that runs FIRST (prio 10) and logs
	 * as 'p'; the second chain (prio 20) only logs, as 's'. */
	f572_wr(&S, "st", NFT_PAYLOAD_LL_HEADER, 6, 6, A72_NEEDLE);
	f571_zero(&E, "e");
	f572_arm(E_IN6, "diag", "dg1", &S, &E, NULL, 1, 12);

	/* dg2: the store lives in the chain that runs SECOND (prio 20) and logs
	 * as 's'; the first chain only logs, as 'p'. */
	f572_wr(&S, "st", NFT_PAYLOAD_LL_HEADER, 6, 6, A72_NEEDLE);
	f571_zero(&E, "e");
	f572_arm(E_IN6, "diag", "dg2", &E, &S, NULL, 1, 12);
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "ll3br";
	int rc;

	printf("F572 BEGIN|mode=%s\n", mode);
	rc = f572_env();
	printf("F572 ENVRC|rc=%d\n", rc);
	if (rc)
		return 3;
	rc = f572_chains();
	printf("F572 CHAINS|rc=%d\n", rc);
	if (rc)
		return 4;
	printf("F572 START\n");
	fflush(stdout);

	f572_sec_ref();
	f572_sec_diag();
	f572_sec_rd();
	f572_sec_wr();
	f572_sec_inv();
	f572_sec_comp();

	printf("F572 END\n");
	return 0;
}
