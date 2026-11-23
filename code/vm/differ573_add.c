/* differ573_add.c -- turn 573 (F51).
 *
 *  THE DEBT (named at the end of 572): a frame flooded to SEVERAL ports -- does
 *  a store at a bridge door reach every copy or only the last, and who shares
 *  the head after __skb_clone()?  Plus: the layer-3 door of a *VLAN-filtering*
 *  bridge.
 *
 *  Mode `flood`: three veth pairs x0/x1, y0/y1, z0/z1, one bridge br0 with the
 *  ports x1, y1, z1, IPv6 enabled on br0 only (fd02::92/128, UDP6 socket on
 *  5000).  Three frames, all IPv6 fd02::11 -> fd02::92, UDP 40000->5000:
 *
 *    A  ethernet broadcast                        (80 bytes)
 *    B  ethernet unicast to br0's MAC             (80 bytes)
 *    C  ethernet broadcast, 802.1Q vid 100        (84 bytes)
 *
 *  Four doors of the same frame:
 *
 *    brp  bridge prerouting  (NF_BR_PRE_ROUTING)  before br_flood() splits it
 *    brf  bridge forward     (NF_BR_FORWARD)      once per port copy
 *    brl  bridge input       (NF_BR_LOCAL_IN)     the local copy only
 *    in6  ip6  prerouting                         the local copy, after br0
 *
 *  Every arm carries a counter+log+accept at prio 0 in all four doors (the
 *  census: how many copies each door sees) and at most one counter+store/read+
 *  log+accept at prio 10 in one door.  Oracles: the doors' own counters, the
 *  NFLOG messages (prefix, indev, outdev, payload = skb->data at that moment),
 *  four AF_PACKET taps opened per arm by a mask (x1 = the ingress port, y0 and
 *  z0 = the ports, br0 = the local copy), the UDP6 socket, the net-wide SNMP6
 *  counters and IFLA_STATS64 (rx_otherhost_dropped) of the ports.
 *
 *  The question the arms answer: a store reaches exactly the copies made AFTER
 *  it, and it is in place or a head copy depending on whether anything cloned
 *  the skb BEFORE it (__skb_clone() marks the source too: skbuff.c:1637).
 *
 *  Every helper below the new code is the one that produced F31..F50.
 */

#define F573_SPORT	40000
#define F573_DPORT	5000
#define F573_TAPN	4
#define F573_NPL	16
#define ND73		4

static const unsigned char A73_SRC[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x11 };
static const unsigned char A73_DST[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x92 };
static const unsigned char A73_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const unsigned char A73_N6[6] = { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95 };
/* N7 is never stored into a *source*, so the bridge never learns it: the FDB
 * entry that a source store teaches would turn a later destination store into
 * a known unicast back to the ingress port (measured in smoke a). */
static const unsigned char A73_N7[6] = { 0x90, 0x91, 0x92, 0x93, 0x94, 0x97 };
static const unsigned char A73_ET[2] = { 0x08, 0x06 };
static const unsigned char A73_HL[1] = { 0x90 };

/* ---------- the four doors ---------- */

static struct f571_door D573[] = {
	{ "brp", NFPROTO_BRIDGE, "e73a", NULL, 0, 10, 20 },	/* PRE_ROUTING */
	{ "brf", NFPROTO_BRIDGE, "e73b", NULL, 2, 30, 40 },	/* FORWARD     */
	{ "brl", NFPROTO_BRIDGE, "e73c", NULL, 1, 50, 60 },	/* LOCAL_IN    */
	{ "in6", NFPROTO_IPV6,   "e73d", NULL, 0, 70, 80 },	/* PRE_ROUTING */
};
enum { E73_BRP = 0, E73_BRF, E73_BRL, E73_IN6 };

/* taps: 0 = x1 (ingress port), 1 = y0, 2 = z0, 3 = br0 (the local copy) */
enum { T_X1 = 0, T_Y0, T_Z0, T_BR0 };
#define T_Y0Z0	((1 << T_Y0) | (1 << T_Z0))
#define T_ALL3	((1 << T_Y0) | (1 << T_Z0) | (1 << T_BR0))
#define T_ALL4	((1 << T_X1) | T_ALL3)

struct f573_tap {
	int fd;
	int n;
	int flen;
	int len;
	unsigned char b[112];
};
static struct f573_tap F573_TAP[F573_TAPN];
static const char *F573_TAPDEV[F573_TAPN] = { "x1", "y0", "z0", "br0" };

static unsigned char F573_X0M[6], F573_BRM[6];
static int F573_U6 = -1, F573_NFL = -1;
static unsigned char F573_FA[128], F573_FB[128], F573_FC[128];
static int F573_LA = -1, F573_LB = -1, F573_LC = -1;

/* ---------- /sys helpers ---------- */

static int f573_sysint(const char *path)
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

static int f573_exists(const char *path)
{
	FILE *f = fopen(path, "r");

	if (!f)
		return 0;
	fclose(f);
	return 1;
}

/* ---------- IFLA_STATS64 (rx_otherhost_dropped lives only here) ---------- */
struct f573_lst {
	unsigned long long rxp, rxb, rxd, other;
	int ok;
};

static unsigned long long f573_u64(const unsigned char *p)
{
	unsigned long long v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = (v << 8) | (unsigned long long)p[i];
	return v;
}

#define F573_IFLA_STATS64	23
#define F573_OFF_OTHERHOST	192

static void f573_stats(const char *dev, struct f573_lst *s)
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
	req.nlh.nlmsg_seq = 9;
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
			if (t == F573_IFLA_STATS64 &&
			    al - NLA_HDRLEN >= F573_OFF_OTHERHOST + 8) {
				const unsigned char *d =
					(const unsigned char *)a + NLA_HDRLEN;

				s->rxp = f573_u64(d + 0);
				s->rxb = f573_u64(d + 16);
				s->rxd = f573_u64(d + 48);
				s->other = f573_u64(d + F573_OFF_OTHERHOST);
				s->ok = 1;
			}
			p += NLA_ALIGN_(al);
		}
	}
}

/* ---------- NFLOG drain: up to F573_NPL messages with their provenance ---- */

struct f573_msg {
	int plen;
	unsigned char p[96];
	int indev, outdev;
	char prefix[8];
};
struct f573_pl {
	int n;
	struct f573_msg m[F573_NPL];
};

static void f573_nfl_drain(struct f573_pl *v)
{
	unsigned char b[16384];
	int guard = 0, rl;

	if (v)
		memset(v, 0, sizeof(*v));
	if (F573_NFL < 0)
		return;
	while (guard++ < 64) {
		struct nlmsghdr *h;
		int len;

		rl = (int)recv(F573_NFL, b, sizeof(b), MSG_DONTWAIT);
		if (rl <= 0)
			break;
		len = rl;
		for (h = (struct nlmsghdr *)b; NLMSG_OK(h, len);
		     h = NLMSG_NEXT(h, len)) {
			const char *p, *end, *prefix = NULL;
			const unsigned char *pl = NULL;
			int pll = 0, ind = -1, outd = -1;

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
				} else if (t == NFULA_IFINDEX_INDEV_) {
					__be32 x;

					memcpy(&x, (const char *)a + NLA_HDRLEN,
					       4);
					ind = (int)ntohl(x);
				} else if (t == NFULA_IFINDEX_OUTDEV_) {
					__be32 x;

					memcpy(&x, (const char *)a + NLA_HDRLEN,
					       4);
					outd = (int)ntohl(x);
				}
				p += NLA_ALIGN_(al);
			}
			if (!v || !prefix || prefix[0] == 0)
				continue;
			if (v->n < F573_NPL) {
				struct f573_msg *M = &v->m[v->n];
				int k;

				snprintf(M->prefix, sizeof(M->prefix), "%s",
					 prefix);
				if (pl) {
					k = pll < (int)sizeof(M->p) ? pll
						     : (int)sizeof(M->p);
					memcpy(M->p, pl, (size_t)k);
					M->plen = k;
				}
				M->indev = ind;
				M->outdev = outd;
			}
			v->n++;
		}
	}
}

/* ---------- the environment ---------- */

static int f573_frame_tag(unsigned char *out, const unsigned char *dmac,
			  const unsigned char *smac)
{
	memset(out, 0, 128);
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x81;
	out[13] = 0x00;			/* TPID 802.1Q */
	out[14] = 0x00;			/* priority 0  */
	out[15] = 0x64;			/* vid 100     */
	out[16] = 0x86;			/* inner ethertype */
	out[17] = 0xdd;
	return 18 + f570_ip6(out + 18, A73_SRC, A73_DST, 0, F573_SPORT,
			     F573_DPORT);
}

static int f573_env(void)
{
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
	if (link_add_veth("x0", "x1") || link_add_veth("y0", "y1") ||
	    link_add_veth("z0", "z1")) {
		printf("F573 FAIL|veth\n");
		return -1;
	}
	if (f556_link_add_kind("br0", "bridge")) {
		printf("F573 FAIL|bridge\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	set_up("y0");
	set_up("y1");
	set_up("z0");
	set_up("z1");
	set_up("br0");
	if (mac_get("x0", F573_X0M)) {
		printf("F573 FAIL|mac\n");
		return -1;
	}
	/* ports are enslaved after everything is up, so br_stp_enable_port()
	 * runs and the ports are FORWARDING with no STP */
	printf("F573 REF|port=x1|master=br0|rc=%d\n",
	       f556_link_enslave("x1", "br0"));
	printf("F573 REF|port=y1|master=br0|rc=%d\n",
	       f556_link_enslave("y1", "br0"));
	printf("F573 REF|port=z1|master=br0|rc=%d\n",
	       f556_link_enslave("z1", "br0"));
	/* br0's MAC is recalculated when a port is added, so read it AFTER */
	if (mac_get("br0", F573_BRM)) {
		printf("F573 FAIL|mac_br\n");
		return -1;
	}
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/accept_ra", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/autoconf", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/forwarding", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/drop_unicast_in_l2_multicast",
		    "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/br0/router_solicitations", "0");
	f555_sysctl("/sys/class/net/br0/bridge/multicast_snooping", "0");
	f555_sysctl("/sys/class/net/br0/bridge/multicast_querier", "0");
	printf("F573 ADDR6|rc=%d\n", f564_addr6("br0", A73_DST, 128));
	F573_U6 = f564_udp_bind(AF_INET6, 0, A73_DST, F573_DPORT);
	F573_NFL = nfl_open(5);
	F571_NFL = F573_NFL;		/* the inherited drain reads F571_NFL */
	F573_LA = f570_frame_plain(F573_FA, A73_BC, F573_X0M, A73_SRC,
				   A73_DST, 0);
	F573_LB = f570_frame_plain(F573_FB, F573_BRM, F573_X0M, A73_SRC,
				   A73_DST, 0);
	F573_LC = f573_frame_tag(F573_FC, A73_BC, F573_X0M);
	{
		char hb[32], hx[32], ha[256], hc[256];

		printf("F573 ENV|u6=%d|nfl=%d|la=%d|lb=%d|lc=%d|br0=%d|x1=%d|"
		       "y0=%d|z0=%d|y1=%d|z1=%d|br0mac=%s|x0mac=%s\n",
		       F573_U6, F573_NFL, F573_LA, F573_LB, F573_LC,
		       f555_ifindex("br0"), f555_ifindex("x1"),
		       f555_ifindex("y0"), f555_ifindex("z0"),
		       f555_ifindex("y1"), f555_ifindex("z1"),
		       f559_hexs(hb, sizeof(hb), F573_BRM, 6),
		       f559_hexs(hx, sizeof(hx), F573_X0M, 6));
		printf("F573 FRM|a=%s\n", f559_hexs(ha, sizeof(ha), F573_FA,
						    F573_LA));
		printf("F573 FRM|c=%s\n", f559_hexs(hc, sizeof(hc), F573_FC,
						    F573_LC));
	}
	/* let the RS/MLD burst of the address come and go */
	usleep(4000000);
	printf("F573 SYS|stp=%d|x1state=%d|y1state=%d|z1state=%d|"
	       "mcsnoop=%d|br0v6=%d|y0v6=%d|z0v6=%d|x1v6=%d|br0mclen=%d|"
	       "vf=%d|vfpath=%d\n",
	       f573_sysint("/sys/class/net/br0/bridge/stp_state"),
	       f573_sysint("/sys/class/net/x1/brport/state"),
	       f573_sysint("/sys/class/net/y1/brport/state"),
	       f573_sysint("/sys/class/net/z1/brport/state"),
	       f573_sysint("/sys/class/net/br0/bridge/multicast_snooping"),
	       f573_sysint("/proc/sys/net/ipv6/conf/br0/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/y0/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/z0/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x1/disable_ipv6"),
	       f573_sysint("/sys/class/net/br0/mtu"),
	       f573_sysint("/sys/class/net/br0/bridge/vlan_filtering"),
	       f573_exists("/sys/class/net/br0/bridge/vlan_filtering"));
	return 0;
}

static int f573_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND73; i++) {
		struct f571_door *D = &D573[i];
		int a, b, c;

		a = add_table(D->fam, D->table);
		b = f556_add_chain(D->fam, D->table, "pre0", D->hook,
				   (uint32_t)D->prio0, 1, D->dev);
		c = f556_add_chain(D->fam, D->table, "ch", D->hook,
				   (uint32_t)D->prio1, 1, D->dev);
		printf("F573 CH|door=%s|fam=%d|hook=%u|table=%d|pre0=%d|ch=%d\n",
		       D->tag, (int)D->fam, D->hook, a, b, c);
		rc |= a | b | c;
	}
	return rc;
}

static void f573_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND73; i++) {
		f557_flush(D573[i].fam, D573[i].table, "pre0", &acks);
		f557_flush(D573[i].fam, D573[i].table, "ch", &acks);
	}
}

/* ---------- the snapshot ---------- */

struct f573_rep {
	int u6n, u6len, u6sport;
	unsigned long long i6in, i6hdr, i6addr, i6unk, i6trunc, i6nor, i6deliv,
			   i6disc, i6mcast, u6in, u6err, u6nop;
	unsigned long long yrxp, yrxd, yoth, zrxp, zrxd, zoth, brrxp, brrxb,
			   x1rxp;
};

static void f573_u6_drain(struct f573_rep *R)
{
	unsigned char b[1024];
	struct sockaddr_in6 sa;
	socklen_t sl;
	int r;

	if (F573_U6 < 0)
		return;
	for (;;) {
		memset(&sa, 0, sizeof(sa));
		sl = sizeof(sa);
		r = (int)recvfrom(F573_U6, b, sizeof(b), MSG_DONTWAIT,
				  (struct sockaddr *)&sa, &sl);
		if (r < 0)
			break;
		if (!f568_needle(b, r))
			continue;
		R->u6n++;
		R->u6len = r;
		R->u6sport = ntohs(sa.sin6_port);
	}
}

static void f573_snap(struct f573_rep *R)
{
	struct f573_lst s;

	f573_u6_drain(R);
	R->i6in = f564_snmp6("Ip6InReceives");
	R->i6hdr = f564_snmp6("Ip6InHdrErrors");
	R->i6addr = f564_snmp6("Ip6InAddrErrors");
	R->i6unk = f564_snmp6("Ip6InUnknownProtos");
	R->i6trunc = f564_snmp6("Ip6InTruncatedPkts");
	R->i6nor = f564_snmp6("Ip6InNoRoutes");
	R->i6deliv = f564_snmp6("Ip6InDelivers");
	R->i6disc = f564_snmp6("Ip6InDiscards");
	R->i6mcast = f564_snmp6("Ip6InMcastPkts");
	R->u6in = f564_snmp6("Udp6InDatagrams");
	R->u6err = f564_snmp6("Udp6InErrors");
	R->u6nop = f564_snmp6("Udp6NoPorts");
	f573_stats("y0", &s);
	R->yrxp = s.rxp;
	R->yrxd = s.rxd;
	R->yoth = s.other;
	f573_stats("z0", &s);
	R->zrxp = s.rxp;
	R->zrxd = s.rxd;
	R->zoth = s.other;
	f573_stats("br0", &s);
	R->brrxp = s.rxp;
	R->brrxb = s.rxb;
	f573_stats("x1", &s);
	R->x1rxp = s.rxp;
}

/* ---------- settle: no IPv6 chatter from the address setup ---------- */

/* Enabling IPv6 on br0 makes the kernel send RS/MLD, the bridge floods them to
 * every port and each port's ip6_rcv_core counts them (Ip6InReceives before
 * the disable_ipv6 check).  An arm that starts while that burst is still in
 * flight measures the burst, not the frame -- the F569 counter=2 lesson.  Wait
 * until two consecutive snapshots agree on every counter the arms use. */
struct f573_key {
	unsigned long long k[6];
};

static void f573_key_get(struct f573_key *K)
{
	struct f573_rep R;

	memset(&R, 0, sizeof(R));
	f573_snap(&R);
	K->k[0] = R.i6in;
	K->k[1] = R.i6disc;
	K->k[2] = R.yrxp;
	K->k[3] = R.zrxp;
	K->k[4] = R.brrxp;
	K->k[5] = R.u6in;
}

static int f573_settle(void)
{
	struct f573_key a, b;
	int i;

	memset(&a, 0, sizeof(a));
	{
		int stable = 0;

		for (i = 0; i < 30; i++) {
			f573_key_get(&a);
			usleep(300000);
			f573_key_get(&b);
			stable = memcmp(&a, &b, sizeof(a)) ? 0 : stable + 1;
			if (stable >= 3)
				return i + 1;
		}
	}
	return -1;
}

static void f573_tap_close_all(void)
{
	int i;

	for (i = 0; i < F573_TAPN; i++) {
		if (F573_TAP[i].fd >= 0)
			close(F573_TAP[i].fd);
		F573_TAP[i].fd = -1;
		F573_TAP[i].n = 0;
		F573_TAP[i].len = -1;
		F573_TAP[i].flen = -1;
	}
}

static void f573_tap_open_mask(int mask)
{
	int i;

	for (i = 0; i < F573_TAPN; i++) {
		F573_TAP[i].n = 0;
		F573_TAP[i].len = -1;
		F573_TAP[i].flen = -1;
		F573_TAP[i].fd = -1;
		if (!(mask & (1 << i)))
			continue;
		F573_TAP[i].fd = f571_tap_open(F573_TAPDEV[i]);
	}
}

static void f573_tap_drain(int i)
{
	unsigned char b[2048];
	int r;

	F573_TAP[i].n = 0;
	F573_TAP[i].len = -1;
	F573_TAP[i].flen = -1;
	if (F573_TAP[i].fd < 0)
		return;
	while ((r = (int)recv(F573_TAP[i].fd, b, sizeof(b), MSG_DONTWAIT)) >
	       0) {
		int k;

		if (!f568_needle(b, r))
			continue;
		F573_TAP[i].n++;
		if (F573_TAP[i].len < 0) {
			F573_TAP[i].flen = r;
			k = r < (int)sizeof(F573_TAP[i].b) ? r
			    : (int)sizeof(F573_TAP[i].b);
			memcpy(F573_TAP[i].b, b, (size_t)k);
			F573_TAP[i].len = k;
		}
	}
}

/* ---------- one arm ---------- */

/* fk: 0 = frame A, 1 = frame B, 2 = frame C, -1 = no injection.
 * door: index into D573, or -1 for no store/read chain.
 * C == NULL with door >= 0: the ch chain carries only counter+log+accept. */
static void f573_arm(const char *arm, int fk, int tapmask, int door,
		     const struct f571_cfg *C)
{
	struct f571_cfg N;
	struct f573_rep r0, r;
	struct f573_pl pl;
	const unsigned char *fr = NULL;
	int flen = 0, proto = 0x86dd;
	unsigned long long c0[ND73], c1[ND73], s0 = 0, s1 = 0;
	int i, acks = 0, snd = 0, polls = 0, k, maxp = 12, st = -9;
	char hx[64];
	const char *fkn = "A";

	memset(&r0, 0, sizeof(r0));
	memset(&r, 0, sizeof(r));
	f571_zero(&N, "p");
	if (fk == 0) {
		fr = F573_FA;
		flen = F573_LA;
		fkn = "A";
	} else if (fk == 1) {
		fr = F573_FB;
		flen = F573_LB;
		fkn = "B";
	} else if (fk == 2) {
		fr = F573_FC;
		flen = F573_LC;
		proto = 0x8100;
		fkn = "C";
	}
	f573_flush_all();
	f573_nfl_drain(NULL);
	st = f573_settle();
	f573_tap_close_all();
	f573_tap_open_mask(tapmask);
	for (i = 0; i < F573_TAPN; i++)
		if (F573_TAP[i].fd >= 0)
			f573_tap_drain(i);
	/* every arm carries the census: counter+log+accept at prio 0 in all
	 * four doors */
	for (i = 0; i < ND73; i++) {
		char nm[8];

		snprintf(nm, sizeof(nm), "p%d", i);
		if (f571_rule(&D573[i], "pre0", nm, &N, &acks))
			printf("F573 RUFAIL|arm=%s|door=%s|chain=pre0\n", arm,
			       D573[i].tag);
	}
	if (door >= 0) {
		struct f571_cfg Z;

		f571_zero(&Z, "s");
		if (f571_rule(&D573[door], "ch", "s", C ? C : &Z, &acks))
			printf("F573 RUFAIL|arm=%s|door=%s|chain=ch\n", arm,
			       D573[door].tag);
	}
	for (i = 0; i < ND73; i++)
		c0[i] = f555_count(D573[i].fam, D573[i].table, "pre0");
	s0 = door >= 0 ? f555_count(D573[door].fam, D573[door].table, "ch") : 0;
	f573_snap(&r0);		/* the baseline: every delta is against this */
	f573_u6_drain(&r0);
	if (fk >= 0) {
		snd = pkt_send_p("x0", fr, flen, (unsigned short)proto);
		for (k = 0; k < maxp; k++) {
			usleep(120000);
			f573_snap(&r);
			polls++;
			if (r.u6n > r0.u6n || r.i6in > r0.i6in ||
			    r.i6disc > r0.i6disc || r.yrxp > r0.yrxp ||
			    r.zrxp > r0.zrxp || r.brrxp > r0.brrxp)
				break;
		}
	} else {
		usleep(300000);
		polls = 1;
	}
	f573_snap(&r);
	usleep(150000);
	f573_snap(&r);
	for (i = 0; i < ND73; i++)
		c1[i] = f555_count(D573[i].fam, D573[i].table, "pre0");
	s1 = door >= 0 ? f555_count(D573[door].fam, D573[door].table, "ch") : 0;
	memset(&pl, 0, sizeof(pl));
	f573_nfl_drain(&pl);
	for (i = 0; i < F573_TAPN; i++)
		f573_tap_drain(i);

	printf("F573 A|arm=%s|fk=%s|door=%s|mode=%d|base=%u|off=%d|len=%d|"
	       "imm=%s|rcs=%d|snt=%d|sendrc=%d|polls=%d|tapmask=%d|"
	       "u6n=%d|u6len=%d|u6sport=%d|nfl=%d|st=%d\n",
	       arm, fkn, door >= 0 ? D573[door].tag : "-",
	       C ? C->mode : (door >= 0 ? 0 : -1), C ? C->base : 0,
	       C ? C->off : -1, C ? C->len : -1,
	       C ? f559_hexs(hx, sizeof(hx), C->imm, C->len) : "-", acks,
	       fk >= 0, snd, polls, tapmask, r.u6n - r0.u6n, r.u6len, r.u6sport,
	       pl.n, st);
	printf("F573 C|brp=%llu,%lld|brf=%llu,%lld|brl=%llu,%lld|"
	       "in6=%llu,%lld\n",
	       c1[E73_BRP] - c0[E73_BRP],
	       door == E73_BRP ? (long long)(s1 - s0) : -1LL,
	       c1[E73_BRF] - c0[E73_BRF],
	       door == E73_BRF ? (long long)(s1 - s0) : -1LL,
	       c1[E73_BRL] - c0[E73_BRL],
	       door == E73_BRL ? (long long)(s1 - s0) : -1LL,
	       c1[E73_IN6] - c0[E73_IN6],
	       door == E73_IN6 ? (long long)(s1 - s0) : -1LL);
	printf("F573 B|i6in_d=%llu|i6hdr_d=%llu|i6addr_d=%llu|i6unk_d=%llu|"
	       "i6trunc_d=%llu|i6nor_d=%llu|deliv_d=%llu|disc_d=%llu|"
	       "mcas_d=%llu|u6in_d=%llu|u6err_d=%llu|u6nop_d=%llu|"
	       "y0rxp_d=%llu|y0rxd_d=%llu|y0oth_d=%llu|z0rxp_d=%llu|"
	       "z0rxd_d=%llu|z0oth_d=%llu|brrxp_d=%llu|brrxb_d=%llu|"
	       "x1rxp_d=%llu\n",
	       r.i6in - r0.i6in, r.i6hdr - r0.i6hdr, r.i6addr - r0.i6addr,
	       r.i6unk - r0.i6unk, r.i6trunc - r0.i6trunc,
	       r.i6nor - r0.i6nor, r.i6deliv - r0.i6deliv,
	       r.i6disc - r0.i6disc, r.i6mcast - r0.i6mcast,
	       r.u6in - r0.u6in, r.u6err - r0.u6err, r.u6nop - r0.u6nop,
	       r.yrxp - r0.yrxp, r.yrxd - r0.yrxd, r.yoth - r0.yoth,
	       r.zrxp - r0.zrxp, r.zrxd - r0.zrxd, r.zoth - r0.zoth,
	       r.brrxp - r0.brrxp, r.brrxb - r0.brrxb, r.x1rxp - r0.x1rxp);
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
		printf("F573 M|n=%d%s\n", pl.n, mb);
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
		printf("F573 T|%s\n", tb[0] ? tb + 1 : tb);
	}
}

/* ---------- config builders ---------- */

static void f573_wr(struct f571_cfg *C, uint32_t base, int off, int len,
		    const unsigned char *imm)
{
	f571_wr(C, "s", base, off, len, imm, 0, 0);
}

static void f573_rdv(struct f571_cfg *C, uint32_t base, int off, int len,
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

static void f573_sec_topo(void)
{
	f573_arm("topo", -1, 0, -1, NULL);
}

static void f573_sec_ctl(void)
{
	f573_arm("ctlA", 0, T_Y0Z0 | (1 << T_BR0), -1, NULL);
	f573_arm("ctlX", 0, T_ALL4, -1, NULL);
	f573_arm("uniC", 1, T_Y0Z0 | (1 << T_BR0), -1, NULL);
}

static void f573_sec_pre(void)
{
	struct f571_cfg C;

	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 6, 6, A73_N6);
	f573_arm("preS", 0, T_Y0Z0 | (1 << T_BR0), E73_BRP, &C);
	f573_arm("preS_x1", 0, T_ALL4, E73_BRP, &C);
	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A73_N6);
	/* preS just taught the bridge that N6 lives on x1, so this store turns
	 * the frame into a known unicast *back to the ingress port* */
	f573_arm("preD", 0, T_Y0Z0 | (1 << T_BR0), E73_BRP, &C);
	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A73_N7);
	f573_arm("preD7", 0, T_Y0Z0 | (1 << T_BR0), E73_BRP, &C);
	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, A73_ET);
	f573_arm("preE", 0, T_Y0Z0 | (1 << T_BR0), E73_BRP, &C);
}

static void f573_sec_fwd(void)
{
	struct f571_cfg C;

	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 6, 6, A73_N6);
	f573_arm("fwdS", 0, T_Y0Z0 | (1 << T_BR0), E73_BRF, &C);
	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A73_N6);
	f573_arm("fwdD", 0, T_Y0Z0 | (1 << T_BR0), E73_BRF, &C);
	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, A73_ET);
	f573_arm("fwdE", 0, T_Y0Z0 | (1 << T_BR0), E73_BRF, &C);
}

static void f573_sec_local(void)
{
	struct f571_cfg C;

	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A73_N6);
	f573_arm("in6D", 0, T_Y0Z0 | (1 << T_BR0), E73_IN6, &C);
	f573_arm("in6D_noT", 0, T_Y0Z0, E73_IN6, &C);
	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, A73_ET);
	f573_arm("in6E", 0, T_Y0Z0 | (1 << T_BR0), E73_IN6, &C);
	f573_wr(&C, NFT_PAYLOAD_NETWORK_HEADER, 7, 1, A73_HL);
	f573_arm("brlH", 0, T_Y0Z0 | (1 << T_BR0), E73_BRL, &C);
	/* the same local door on the unicast frame: no flood, so the
	 * instrument's own tap is the only clone before the store */
	f573_wr(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A73_N6);
	f573_arm("uniD", 1, T_Y0Z0 | (1 << T_BR0), E73_IN6, &C);
	f573_arm("uniD_noT", 1, 0, E73_IN6, &C);
}

/* The VLAN section is deliberately small: CONFIG_BRIDGE_VLAN_FILTERING is not
 * set (see F573 SYS: vfpath=0), so the *named* debt cannot be built here, and a
 * tagged frame on a non-filtering bridge produced, in the smoke, counters that
 * disagree with the bytes the taps saw.  These two arms are recorded as
 * observations with the contradiction named, not as a claim. */
static void f573_sec_vlan(void)
{
	struct f571_cfg C;
	unsigned char v2[2] = { 0x86, 0xdd };

	f573_arm("vlanC", 2, T_Y0Z0 | (1 << T_BR0), -1, NULL);
	/* the inner ethertype would be at 12 if the tag were popped */
	f573_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, v2);
	f573_arm("vlanR", 2, T_Y0Z0 | (1 << T_BR0), E73_BRP, &C);
}

/* the read machinery of this instrument, proven on a frame we know */
static void f573_sec_rd(void)
{
	struct f571_cfg C;

	f573_rdv(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A73_BC);
	f573_arm("rdA", 0, T_Y0Z0 | (1 << T_BR0), E73_BRP, &C);
	f573_rdv(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A73_N7);
	f573_arm("rdAmiss", 0, T_Y0Z0 | (1 << T_BR0), E73_BRP, &C);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "flood";
	int rc;

	printf("F573 BEGIN|mode=%s\n", mode);
	rc = f573_env();
	printf("F573 ENVRC|rc=%d\n", rc);
	if (rc)
		return 3;
	rc = f573_chains();
	printf("F573 CHAINS|rc=%d\n", rc);
	if (rc)
		return 4;
	printf("F573 START\n");
	fflush(stdout);

	f573_sec_topo();
	f573_sec_ctl();
	f573_sec_pre();
	f573_sec_fwd();
	f573_sec_local();
	f573_sec_rd();
	f573_sec_vlan();

	printf("F573 END\n");
	return 0;
}
