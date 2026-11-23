/* differ577_add.c -- turn 577 (F55).
 *
 *  THE HOLE named at the end of 576: "the one channel a rule can still use is
 *  skb->priority plus an egress QoS map -- vlan_dev_get_egress_qos_mask() is
 *  the only reader of the tag that a store could feed".
 *
 *  The tag has three parts and two owners.  F54 showed the vid belongs to the
 *  egress device: vlan_dev_hard_header() writes vlan->vlan_id and a store into
 *  the TCI does not survive.  The PCP is the other part, and it is the only
 *  one a rule can reach -- not by writing the tag but by writing skb->priority
 *  and letting the DEVICE's egress map translate it:
 *
 *      vlan_tci = vlan->vlan_id | vlan_dev_get_egress_qos_mask(dev,
 *                                                              skb->priority)
 *
 *  Two laws in that mask function: the bucket is `skprio & 0xF`, the match is
 *  the full 32-bit value; the returned word is already shifted (PCP << 13).
 *
 *  Where the reader sits: vlan_dev_hard_header() is reached through
 *  dev_hard_header() from neigh_resolve_output()/neigh_connected_output()
 *  (net/core/neighbour.c), i.e. BEFORE dev_queue_xmit() and therefore before
 *  the egress hook of the VLAN device.  The doors bracket that point:
 *
 *      g6  ip6 prerouting      store here  -> in time
 *      f6  ip6 forward         store here  -> in time
 *      e0  netdev egress x1.102 (hard header already built)
 *      e3  netdev egress x1.103
 *      n1  netdev ingress x1   (the tag is metadata; the ingress map ran)
 *      r0  netdev ingress x0   (the far end: NFULA_VLAN is the wire)
 *
 *  Receive side: vlan_do_receive() sets skb->priority from the INGRESS map
 *  keyed by the arriving PCP, then clears the tag metadata.  With an ingress
 *  map 3->5 and an egress map 5->7 a frame that arrives with PCP 3 leaves
 *  with PCP 7 and no rule at all.
 *
 *  Witnesses of the wire, three mechanisms: the far end's NFULA_VLAN
 *  attribute, the far end's @ll,14,2 read (rebuilt from the metadata by
 *  nft_payload_copy_vlan), and the AF_PACKET auxdata (PACKET_AUXDATA) of the
 *  tap on x0, which carries skb->vlan_tci as it arrived.
 */

#include <sys/syscall.h>

#define F577_SPORT	43200
#define F577_DPORT	5000

static const unsigned char A77_SRC[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x11 };
/* two destinations, two egress devices */
static const unsigned char A77_D2[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x92 };
static const unsigned char A77_D3[16] = { 0xfd, 0x03, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x92 };
static const unsigned char A77_L2[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x91 };
static const unsigned char A77_L3[16] = { 0xfd, 0x03, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x91 };

#define F577_B_LL	0

#define F577_PREROUTING_	0
#define F577_FORWARD_		2
#define F577_ND_INGRESS_	0
#define F577_ND_EGRESS_		1

#define F577_IFLA_VLAN_EGRESS_QOS_	3
#define F577_IFLA_VLAN_INGRESS_QOS_	4
#define F577_IFLA_VLAN_QOS_MAPPING_	1

static struct f571_door D577[] = {
	{ "f6", NFPROTO_IPV6,   "e77a", NULL,     F577_FORWARD_,    210, 220 },
	{ "g6", NFPROTO_IPV6,   "e77b", NULL,     F577_PREROUTING_, 230, 240 },
	{ "e0", NFPROTO_NETDEV, "e77c", "x1.102", F577_ND_EGRESS_,  250, 260 },
	{ "e3", NFPROTO_NETDEV, "e77d", "x1.103", F577_ND_EGRESS_,  270, 280 },
	{ "n1", NFPROTO_NETDEV, "e77e", "x1",     F577_ND_INGRESS_, 290, 300 },
	{ "r0", NFPROTO_NETDEV, "e77f", "x0",     F577_ND_INGRESS_, 310, 320 },
};
enum { E77_F6 = 0, E77_G6, E77_E0, E77_E3, E77_N1, E77_R0 };
#define ND77 6

static unsigned char F577_X0M[6], F577_X1M[6];
static int F577_NFL = -1;
static unsigned char F577_F0[192], F577_F3[192], F577_FB[192];
static int F577_L0 = -1, F577_L3 = -1, F577_LB = -1;
static int F577_ST = -9;

/* ---------- the tap on x0, with PACKET_AUXDATA ---------- */

#define F577_TAPN 1
struct f577_tap {
	int fd;
	int n;
	int flen;
	int len;
	unsigned char b[192];
	int auxn;
	int atci;
	int atpid;
	int astat;
};
static struct f577_tap F577_TAP[F577_TAPN];
static const char *F577_TAPDEV[F577_TAPN] = { "x0" };

static int f577_tap_open_aux(const char *dev)
{
	struct sockaddr_ll sll;
	int fd, one = 1, idx = f555_ifindex(dev);

	if (idx < 0)
		return -1;
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return -2;
	if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one)) < 0) {
		close(fd);
		return -3;
	}
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = idx;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		close(fd);
		return -4;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	return fd;
}

static void f577_tap_open_mask(int mask)
{
	int i;

	for (i = 0; i < F577_TAPN; i++) {
		if (F577_TAP[i].fd >= 0)
			close(F577_TAP[i].fd);
		F577_TAP[i].fd = -1;
		F577_TAP[i].n = 0;
		F577_TAP[i].len = -1;
		F577_TAP[i].flen = -1;
		F577_TAP[i].auxn = 0;
		F577_TAP[i].atci = -1;
		F577_TAP[i].atpid = -1;
		F577_TAP[i].astat = -1;
	}
	for (i = 0; i < F577_TAPN; i++) {
		if (!(mask & (1 << i)))
			continue;
		F577_TAP[i].fd = f577_tap_open_aux(F577_TAPDEV[i]);
		if (F577_TAP[i].fd < 0)
			printf("F577 TAPFAIL|dev=%s|fd=%d\n", F577_TAPDEV[i],
			       F577_TAP[i].fd);
	}
}

static void f577_tap_drain(int i)
{
	unsigned char b[2048], cb[256];
	int r;

	F577_TAP[i].n = 0;
	F577_TAP[i].len = -1;
	F577_TAP[i].flen = -1;
	F577_TAP[i].auxn = 0;
	F577_TAP[i].atci = -1;
	F577_TAP[i].atpid = -1;
	F577_TAP[i].astat = -1;
	if (F577_TAP[i].fd < 0)
		return;
	for (;;) {
		struct sockaddr_ll from;
		struct iovec iov;
		struct msghdr msg;
		struct cmsghdr *cm;
		int k;

		memset(&from, 0, sizeof(from));
		iov.iov_base = b;
		iov.iov_len = sizeof(b);
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &from;
		msg.msg_namelen = sizeof(from);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cb;
		msg.msg_controllen = sizeof(cb);
		r = (int)recvmsg(F577_TAP[i].fd, &msg, MSG_DONTWAIT);
		if (r <= 0)
			break;
		/* the tap also sees what this box transmits */
		if (from.sll_pkttype == 4 /* PACKET_OUTGOING */)
			continue;
		if (!f568_needle(b, r))
			continue;
		F577_TAP[i].n++;
		if (F577_TAP[i].len < 0) {
			F577_TAP[i].flen = r;
			k = r < (int)sizeof(F577_TAP[i].b) ?
			    r : (int)sizeof(F577_TAP[i].b);
			memcpy(F577_TAP[i].b, b, (size_t)k);
			F577_TAP[i].len = k;
		}
		for (cm = CMSG_FIRSTHDR(&msg); cm;
		     cm = CMSG_NXTHDR(&msg, cm)) {
			struct tpacket_auxdata aux;

			if (cm->cmsg_level != SOL_PACKET ||
			    cm->cmsg_type != PACKET_AUXDATA)
				continue;
			if (cm->cmsg_len < CMSG_LEN(sizeof(aux)))
				continue;
			memcpy(&aux, CMSG_DATA(cm), sizeof(aux));
			F577_TAP[i].auxn++;
			if (F577_TAP[i].atci < 0) {
				F577_TAP[i].atci = (int)aux.tp_vlan_tci;
				F577_TAP[i].atpid = (int)aux.tp_vlan_tpid;
				F577_TAP[i].astat = (int)aux.tp_status;
			}
		}
	}
}

/* ---------- frames: tagged, PCP and destination are the parameters -------- */

static int f577_frame(unsigned char *out, const unsigned char *dmac,
		      const unsigned char *smac, unsigned short tci,
		      const unsigned char *dst)
{
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x81;
	out[13] = 0x00;
	out[14] = (unsigned char)(tci >> 8);
	out[15] = (unsigned char)(tci & 0xff);
	out[16] = 0x86;
	out[17] = 0xdd;
	return 18 + f570_ip6(out + 18, A77_SRC, dst, 0, F577_SPORT,
			     F577_DPORT);
}

/* ---------- the egress / ingress QoS map, set and read back -------------- */

static int f577_qos_set(const char *dev, int egress, uint32_t from,
			uint32_t to)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[512];
	} req;
	struct nlattr *li, *data, *qos;
	struct {
		uint32_t f;
		uint32_t t;
	} m;
	int fd, rc, idx = f555_ifindex(dev);

	if (idx < 0)
		return -1;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = 3;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = idx;
	li = nest_start(&req.nlh, IFLA_LINKINFO);
	attr_put(&req.nlh, IFLA_INFO_KIND, "vlan", 5);
	data = nest_start(&req.nlh, IFLA_INFO_DATA);
	qos = nest_start(&req.nlh, egress ? F577_IFLA_VLAN_EGRESS_QOS_ :
					    F577_IFLA_VLAN_INGRESS_QOS_);
	m.f = from;
	m.t = to;
	attr_put(&req.nlh, F577_IFLA_VLAN_QOS_MAPPING_, &m, 8);
	nest_end(&req.nlh, qos);
	nest_end(&req.nlh, data);
	nest_end(&req.nlh, li);
	fd = rtnl_open();
	if (fd < 0)
		return -2;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* read the two QoS nests out of the kernel's own RTM_GETLINK dump */
static void f577_qos_readback(const char *dev)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req;
	unsigned char rbuf[8192];
	struct nlmsghdr *nlh;
	struct sockaddr_nl sa;
	char eg[128], in[128];
	int fd, idx = f555_ifindex(dev), r, oeg = 0, oin = 0;

	eg[0] = 0;
	in[0] = 0;
	if (idx < 0) {
		printf("F577 Q|dev=%s|eg=-|in=-\n", dev);
		return;
	}
	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 22;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = idx;
	if (sendto(fd, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa,
		   sizeof(sa)) < 0) {
		close(fd);
		return;
	}
	r = (int)recv(fd, rbuf, sizeof(rbuf), 0);
	close(fd);
	if (r <= 0) {
		printf("F577 Q|dev=%s|eg=-|in=-\n", dev);
		return;
	}
	for (nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, r);
	     nlh = NLMSG_NEXT(nlh, r)) {
		const char *p, *end;

		if (nlh->nlmsg_type != RTM_NEWLINK)
			continue;
		p = (const char *)nlh + NLMSG_HDRLEN +
		    sizeof(struct ifinfomsg);
		end = (const char *)nlh + nlh->nlmsg_len;
		for (; p + (int)sizeof(struct nlattr) <= end; ) {
			const struct nlattr *a = (const struct nlattr *)p;
			int al = (int)a->nla_len;
			int t;

			if (al < (int)sizeof(*a) || p + al > end)
				break;
			t = a->nla_type & 0x3fff;
			if (t == IFLA_LINKINFO) {
				const char *q = p + NLA_HDRLEN;
				const char *qend = p + al;

				for (; q + (int)sizeof(struct nlattr) <= qend; ) {
					const struct nlattr *b =
						(const struct nlattr *)q;
					int bl = (int)b->nla_len;
					int bt = b->nla_type & 0x3fff;

					if (bl < (int)sizeof(*b) ||
					    q + bl > qend)
						break;
					if (bt == IFLA_INFO_DATA) {
						const char *s = q + NLA_HDRLEN;
						const char *send = q + bl;

						for (; s + (int)sizeof(
							struct nlattr) <= send; ) {
							const struct nlattr *c =
							  (const struct nlattr *)s;
							int cl = (int)c->nla_len;
							int ct = c->nla_type &
								 0x3fff;

							if (cl < (int)sizeof(*c) ||
							    s + cl > send)
								break;
							if (ct == 3 || ct == 4) {
								char *o = ct == 3 ?
									eg : in;
								int *oo = ct == 3 ?
									&oeg : &oin;
								int pos;

								for (pos = NLA_HDRLEN;
								     pos + 12 <= cl; ) {
									const struct nlattr *k2 =
									  (const struct nlattr *)
									  (s + pos);
									int kl2 = (int)k2->nla_len;
									uint32_t f2, t2;
									int w;

									if (kl2 < 12 ||
									    pos + kl2 > cl)
										break;
									memcpy(&f2,
									       s + pos +
									       NLA_HDRLEN, 4);
									memcpy(&t2,
									       s + pos +
									       NLA_HDRLEN + 4, 4);
									w = snprintf(o + *oo,
										(size_t)(120 - *oo),
										"%s%u:%u",
										*oo ? "," : "",
										f2, t2);
									if (w > 0)
										*oo += w;
									pos += NLA_ALIGN_(kl2);
								}
							}
							s += NLA_ALIGN_(cl);
						}
					}
					q += NLA_ALIGN_(bl);
				}
			}
			p += NLA_ALIGN_(al);
		}
	}
	printf("F577 Q|dev=%s|eg=%s|in=%s\n", dev, oeg ? eg : "-",
	       oin ? in : "-");
}

static void f577_maps_none(void)
{
	f577_qos_set("x1.101", 0, 3, 0);
	f577_qos_set("x1.102", 1, 5, 0);
	f577_qos_set("x1.102", 1, 0x15, 0);
	f577_qos_set("x1.103", 1, 5, 0);
}

/* ---------- snapshot ---------- */

struct f577_rep {
	unsigned long long i6in, i6deliv, i6disc, i6hdr, i6nor, i6addr,
		i6unk, i6trunc, i6mcast, i6fwd;
	unsigned long long u6in, u6err, u6nop;
	unsigned long long x0rxp, x0rxb, x0oth;
	unsigned long long x1rxp, x1oth;
	unsigned long long a101p, a102p, a103p;
	unsigned long long b101p, b101b, b102p, b103p;
};

static void f577_snap(struct f577_rep *R)
{
	struct f573_lst s;

	memset(R, 0, sizeof(*R));
	R->i6in = f564_snmp6("Ip6InReceives");
	R->i6hdr = f564_snmp6("Ip6InHdrErrors");
	R->i6addr = f564_snmp6("Ip6InAddrErrors");
	R->i6unk = f564_snmp6("Ip6InUnknownProtos");
	R->i6trunc = f564_snmp6("Ip6InTruncatedPkts");
	R->i6nor = f564_snmp6("Ip6InNoRoutes");
	R->i6deliv = f564_snmp6("Ip6InDelivers");
	R->i6disc = f564_snmp6("Ip6InDiscards");
	R->i6mcast = f564_snmp6("Ip6InMcastPkts");
	R->i6fwd = f564_snmp6("Ip6OutForwDatagrams");
	R->u6in = f564_snmp6("Udp6InDatagrams");
	R->u6err = f564_snmp6("Udp6InErrors");
	R->u6nop = f564_snmp6("Udp6NoPorts");
	f573_stats("x0", &s);
	R->x0rxp = s.rxp;
	R->x0rxb = s.rxb;
	R->x0oth = s.other;
	f573_stats("x1", &s);
	R->x1rxp = s.rxp;
	R->x1oth = s.other;
	f573_stats("x0.101", &s);
	R->a101p = s.rxp;
	f573_stats("x0.102", &s);
	R->a102p = s.rxp;
	f573_stats("x0.103", &s);
	R->a103p = s.rxp;
	f573_stats("x1.101", &s);
	R->b101p = s.rxp;
	R->b101b = s.rxb;
	f573_stats("x1.102", &s);
	R->b102p = s.rxp;
	f573_stats("x1.103", &s);
	R->b103p = s.rxp;
}

/* ---------- topology ---------- */

static int f577_env(void)
{
	int r1, r2, r3, r4, r5;
	char path[160];
	const char *v6[3] = { "x1.101", "x1.102", "x1.103" };
	int i;

	f558_link_del("br0");
	f558_link_del("x0");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
	if (link_add_veth("x0", "x1")) {
		printf("F577 FAIL|veth\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	if (mac_get("x0", F577_X0M) || mac_get("x1", F577_X1M)) {
		printf("F577 FAIL|mac\n");
		return -1;
	}
	r1 = f575_link_add_vlan("x1.101", "x1", 101, 0, 1);
	r2 = f575_link_add_vlan("x1.102", "x1", 102, 0, 1);
	r3 = f575_link_add_vlan("x1.103", "x1", 103, 0, 1);
	r4 = f575_link_add_vlan("x0.101", "x0", 101, 0, 0);
	r5 = f575_link_add_vlan("x0.102", "x0", 102, 0, 0);
	printf("F577 VNEW|x1_101=%d|x1_102=%d|x1_103=%d|x0_101=%d|x0_102=%d\n",
	       r1, r2, r3, r4, r5);
	if (r1 | r2 | r3 | r4 | r5)
		return -6;
	printf("F577 VNEW2|x0_103=%d\n",
	       f575_link_add_vlan("x0.103", "x0", 103, 0, 0));
	f575_vlan_readback("x1.101");
	f575_vlan_readback("x1.102");
	f575_vlan_readback("x1.103");
	set_up("x1.101");
	set_up("x1.102");
	set_up("x1.103");
	set_up("x0.101");
	set_up("x0.102");
	set_up("x0.103");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	for (i = 0; i < 3; i++) {
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", v6[i]);
		f555_sysctl(path, "0");
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/accept_dad", v6[i]);
		f555_sysctl(path, "0");
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/dad_transmits", v6[i]);
		f555_sysctl(path, "0");
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/accept_ra", v6[i]);
		f555_sysctl(path, "0");
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/autoconf", v6[i]);
		f555_sysctl(path, "0");
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/router_solicitations",
			 v6[i]);
		f555_sysctl(path, "0");
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/forwarding", v6[i]);
		f555_sysctl(path, "1");
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/send_redirects", v6[i]);
		f555_sysctl(path, "0");
	}
	printf("F577 ADDR6|rc2=%d|rc3=%d\n",
	       f564_addr6("x1.102", A77_L2, 64),
	       f564_addr6("x1.103", A77_L3, 64));
	printf("F577 NEIGH|rc2=%d|rc3=%d\n",
	       f569_neigh6_add("x1.102", A77_D2, F577_X0M),
	       f569_neigh6_add("x1.103", A77_D3, F577_X0M));
	F577_NFL = nfl_open(5);
	F573_NFL = F577_NFL;
	F571_NFL = F577_NFL;
	F577_L0 = f577_frame(F577_F0, F577_X1M, F577_X0M, 0x0065, A77_D2);
	F577_L3 = f577_frame(F577_F3, F577_X1M, F577_X0M, 0x6065, A77_D2);
	F577_LB = f577_frame(F577_FB, F577_X1M, F577_X0M, 0x0065, A77_D3);
	{
		char h0[512], h3[512], hb[512], a[32], b[32];
		char p2[20], p3[20], p4[20];

		printf("F577 ENV|nfl=%d|l0=%d|l3=%d|lb=%d|x0=%d|x1=%d|"
		       "d101=%d|d102=%d|d103=%d|a102=%d|a103=%d|"
		       "x0mac=%s|x1mac=%s\n",
		       F577_NFL, F577_L0, F577_L3, F577_LB, f555_ifindex("x0"),
		       f555_ifindex("x1"), f555_ifindex("x1.101"),
		       f555_ifindex("x1.102"), f555_ifindex("x1.103"),
		       f555_ifindex("x0.102"), f555_ifindex("x0.103"),
		       f559_hexs(a, sizeof(a), F577_X0M, 6),
		       f559_hexs(b, sizeof(b), F577_X1M, 6));
		printf("F577 FRM|f0=%s\n", f559_hexs(h0, sizeof(h0), F577_F0,
						    F577_L0));
		printf("F577 FRM|f3=%s\n", f559_hexs(h3, sizeof(h3), F577_F3,
						    F577_L3));
		printf("F577 FRM|fb=%s\n", f559_hexs(hb, sizeof(hb), F577_FB,
						    F577_LB));
		(void)p2;
		(void)p3;
		(void)p4;
	}
	f577_maps_none();
	f577_qos_readback("x1.101");
	f577_qos_readback("x1.102");
	f577_qos_readback("x1.103");
	usleep(4000000);
	F577_ST = f573_settle();
	printf("F577 SETTLE|st=%d|v6=%d|fwd=%d|a102v6=%d|a103v6=%d\n", F577_ST,
	       f573_sysint("/proc/sys/net/ipv6/conf/x1.101/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x1.101/forwarding"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x0.102/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x0.103/disable_ipv6"));
	return 0;
}

static int f577_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND77; i++) {
		struct f571_door *D = &D577[i];
		int a, b, c;

		a = add_table(D->fam, D->table);
		b = f556_add_chain(D->fam, D->table, "pre0", D->hook,
				   (uint32_t)D->prio0, 1, D->dev);
		c = f556_add_chain(D->fam, D->table, "ch", D->hook,
				   (uint32_t)D->prio1, 1, D->dev);
		printf("F577 CH|door=%s|fam=%d|hook=%u|dev=%s|table=%d|"
		       "pre0=%d|ch=%d\n", D->tag, (int)D->fam, D->hook,
		       D->dev ? D->dev : "-", a, b, c);
		rc |= a | b | c;
	}
	return rc;
}

static void f577_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND77; i++) {
		f557_flush(D577[i].fam, D577[i].table, "pre0", &acks);
		f557_flush(D577[i].fam, D577[i].table, "ch", &acks);
	}
}

/* ---------- one action = one rule ---------- */

struct f577_act {
	int door;
	int set;
	uint32_t setval;
	int cmpm;
	uint32_t cmpval;
	int nrd;
	int rdoff[2];
	int rdlen[2];
	unsigned char rdimm[2][4];
};

static void f577_meta_set(struct nlmsghdr *nlh, uint32_t v)
{
	unsigned char b[4];
	struct nlattr *e, *d;

	/* skb->priority = value, where value is *sreg read as a host u32 */
	memcpy(b, &v, 4);
	imm_value(nlh, F562_WR_SREG, b, 4);
	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "meta");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_META_KEY, NFT_META_PRIORITY);
	put_be32(nlh, NFTA_META_SREG, F562_WR_SREG);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

static int f577_rule(const struct f571_door *D, const char *chain,
		     const char *prefix, const struct f577_act *A, int *acks)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	unsigned char b[4];
	int i;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			D->fam);
	put_str(nlh, NFTA_RULE_TABLE, D->table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	if (A->cmpm) {
		memcpy(b, &A->cmpval, 4);
		f570_put_meta(nlh, NFT_META_PRIORITY);
		f562_cmp(nlh, F562_RD_DREG, b, 4);
	}
	if (A->set)
		f577_meta_set(nlh, A->setval);
	for (i = 0; i < A->nrd && i < 2; i++) {
		f562_read(nlh, F577_B_LL, (uint32_t)A->rdoff[i],
			  (uint32_t)A->rdlen[i]);
		f562_cmp(nlh, F562_RD_DREG, A->rdimm[i], A->rdlen[i]);
	}
	log_expr(nlh, 5, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

/* ---------- one arm ---------- */

static void f577_arm(const char *arm, int fk, int nsend, const struct f577_act *A,
		     int na)
{
	struct f571_cfg N;
	struct f577_rep r0, r;
	struct f575_pl pl;
	const unsigned char *fr = NULL;
	int flen = 0;
	unsigned long long c0[ND77], c1[ND77], s0[2], s1[2];
	int i, j, acks = 0, snd = 0, polls = 0, k, rcs[2] = { -99, -99 };
	char hx[64], hx2[64];
	const char *fkn = "0";

	memset(&r0, 0, sizeof(r0));
	memset(&r, 0, sizeof(r));
	memset(s0, 0, sizeof(s0));
	memset(s1, 0, sizeof(s1));
	f571_zero(&N, "p");
	if (fk == 0) {
		fr = F577_F0;
		flen = F577_L0;
		fkn = "0";
	} else if (fk == 3) {
		fr = F577_F3;
		flen = F577_L3;
		fkn = "3";
	} else if (fk == 4) {
		fr = F577_FB;
		flen = F577_LB;
		fkn = "B";
	}
	f577_flush_all();
	f575_nfl_drain(NULL);
	F577_ST = f573_settle();
	f577_qos_readback("x1.101");
	f577_qos_readback("x1.102");
	f577_qos_readback("x1.103");
	f577_tap_open_mask(1);
	for (i = 0; i < F577_TAPN; i++)
		if (F577_TAP[i].fd >= 0)
			f577_tap_drain(i);
	for (i = 0; i < ND77; i++) {
		char nm[8];

		snprintf(nm, sizeof(nm), "p%d", i);
		if (f571_rule(&D577[i], "pre0", nm, &N, &acks))
			printf("F577 RUFAIL|arm=%s|door=%s|chain=pre0\n", arm,
			       D577[i].tag);
	}
	for (j = 0; j < na && j < 2; j++)
		rcs[j] = f577_rule(&D577[A[j].door], "ch", "s", &A[j], &acks);
	for (i = 0; i < ND77; i++)
		c0[i] = f555_count(D577[i].fam, D577[i].table, "pre0");
	for (j = 0; j < na && j < 2; j++)
		s0[j] = f555_count(D577[A[j].door].fam, D577[A[j].door].table,
				   "ch");
	f577_snap(&r0);
	if (fk >= 0 && nsend > 0) {
		for (k = 0; k < nsend; k++) {
			snd += (pkt_send_p("x0", fr, flen,
					   (unsigned short)0x86dd) == 0);
			if (k + 1 < nsend)
				usleep(120000);
		}
		for (k = 0; k < 14; k++) {
			int any = 0;

			usleep(110000);
			f577_snap(&r);
			polls++;
			for (i = 0; i < ND77; i++)
				if (f555_count(D577[i].fam, D577[i].table,
					       "pre0") > c0[i])
					any = 1;
			for (j = 0; j < na && j < 2; j++)
				if (f555_count(D577[A[j].door].fam,
					       D577[A[j].door].table, "ch") >
				    s0[j])
					any = 1;
			if (r.a102p > r0.a102p || r.a103p > r0.a103p ||
			    r.i6in > r0.i6in || r.i6fwd > r0.i6fwd)
				break;
			if (any && polls >= 3)
				break;
		}
	} else {
		usleep(300000);
		polls = 1;
	}
	f577_snap(&r);
	usleep(200000);
	f577_snap(&r);
	for (i = 0; i < ND77; i++)
		c1[i] = f555_count(D577[i].fam, D577[i].table, "pre0");
	for (j = 0; j < na && j < 2; j++)
		s1[j] = f555_count(D577[A[j].door].fam, D577[A[j].door].table,
				   "ch");
	f575_nfl_drain(&pl);
	for (i = 0; i < F577_TAPN; i++)
		if (F577_TAP[i].fd >= 0)
			f577_tap_drain(i);

	printf("F577 A|arm=%s|fk=%s|nsend=%d|snt=%d|polls=%d|st=%d|na=%d|"
	       "a0=%s|set0=%u|cmp0=%u|r0a=%d:%d:%s|r0b=%d:%d:%s|rc0=%d|"
	       "a1=%s|set1=%u|cmp1=%u|r1a=%d:%d:%s|r1b=%d:%d:%s|rc1=%d|"
	       "u6n=%llu|nfl=%d\n",
	       arm, fkn, nsend, snd, polls, F577_ST, na,
	       na > 0 ? D577[A[0].door].tag : "-",
	       na > 0 && A[0].set ? A[0].setval : 0,
	       na > 0 && A[0].cmpm ? A[0].cmpval : 0,
	       na > 0 && A[0].nrd > 0 ? A[0].rdoff[0] : -1,
	       na > 0 && A[0].nrd > 0 ? A[0].rdlen[0] : 0,
	       na > 0 && A[0].nrd > 0 ?
		       f559_hexs(hx, sizeof(hx), A[0].rdimm[0], A[0].rdlen[0]) :
		       "-"
	       , na > 0 && A[0].nrd > 1 ? A[0].rdoff[1] : -1,
	       na > 0 && A[0].nrd > 1 ? A[0].rdlen[1] : 0,
	       na > 0 && A[0].nrd > 1 ?
		       f559_hexs(hx2, sizeof(hx2), A[0].rdimm[1],
				 A[0].rdlen[1]) : "-"
	       , na > 0 ? rcs[0] : -99,
	       na > 1 ? D577[A[1].door].tag : "-",
	       na > 1 && A[1].set ? A[1].setval : 0,
	       na > 1 && A[1].cmpm ? A[1].cmpval : 0,
	       na > 1 && A[1].nrd > 0 ? A[1].rdoff[0] : -1,
	       na > 1 && A[1].nrd > 0 ? A[1].rdlen[0] : 0,
	       na > 1 && A[1].nrd > 0 ?
		       f559_hexs(hx, sizeof(hx), A[1].rdimm[0], A[1].rdlen[0]) :
		       "-"
	       , na > 1 && A[1].nrd > 1 ? A[1].rdoff[1] : -1,
	       na > 1 && A[1].nrd > 1 ? A[1].rdlen[1] : 0,
	       na > 1 && A[1].nrd > 1 ?
		       f559_hexs(hx2, sizeof(hx2), A[1].rdimm[1],
				 A[1].rdlen[1]) : "-"
	       , na > 1 ? rcs[1] : -99,
	       r.u6in - r0.u6in, pl.n);
	printf("F577 C|f6=%llu|g6=%llu|e0=%llu|e3=%llu|n1=%llu|r0=%llu|"
	       "ch0=%lld|ch1=%lld\n",
	       c1[E77_F6] - c0[E77_F6], c1[E77_G6] - c0[E77_G6],
	       c1[E77_E0] - c0[E77_E0], c1[E77_E3] - c0[E77_E3],
	       c1[E77_N1] - c0[E77_N1], c1[E77_R0] - c0[E77_R0],
	       na > 0 ? (long long)(s1[0] - s0[0]) : -1LL,
	       na > 1 ? (long long)(s1[1] - s0[1]) : -1LL);
	printf("F577 B|i6in_d=%llu|deliv_d=%llu|disc_d=%llu|hdr_d=%llu|"
	       "nor_d=%llu|addr_d=%llu|unk_d=%llu|trunc_d=%llu|mcast_d=%llu|"
	       "fwd_d=%llu|u6in_d=%llu|u6err_d=%llu|u6nop_d=%llu\n",
	       r.i6in - r0.i6in, r.i6deliv - r0.i6deliv, r.i6disc - r0.i6disc,
	       r.i6hdr - r0.i6hdr, r.i6nor - r0.i6nor, r.i6addr - r0.i6addr,
	       r.i6unk - r0.i6unk, r.i6trunc - r0.i6trunc,
	       r.i6mcast - r0.i6mcast, r.i6fwd - r0.i6fwd,
	       r.u6in - r0.u6in, r.u6err - r0.u6err, r.u6nop - r0.u6nop);
	printf("F577 F|v101_d=%llu|v102_d=%llu|v103_d=%llu|"
	       "x0rxp_d=%llu|x0rxb_d=%llu|x0oth_d=%llu|x1rxp_d=%llu|"
	       "x1oth_d=%llu|b101_d=%llu|b101b_d=%llu|b102_d=%llu|"
	       "b103_d=%llu\n",
	       r.a101p - r0.a101p, r.a102p - r0.a102p, r.a103p - r0.a103p,
	       r.x0rxp - r0.x0rxp, r.x0rxb - r0.x0rxb, r.x0oth - r0.x0oth,
	       r.x1rxp - r0.x1rxp, r.x1oth - r0.x1oth,
	       r.b101p - r0.b101p, r.b101b - r0.b101b,
	       r.b102p - r0.b102p, r.b103p - r0.b103p);
	{
		char mb[2600];
		int o2 = 0;

		mb[0] = 0;
		for (i = 0; i < pl.n && i < F575_NPL; i++) {
			char hh[120], hw[80], l2[80];
			int w = snprintf(mb + o2, sizeof(mb) - (size_t)o2,
					 "|m%d=%s:%d:%d:%d:%d:%d:%s:%d:%s:"
					 "%d:%04x:%04x:%d:%s", i,
					 pl.m[i].prefix, pl.m[i].indev,
					 pl.m[i].outdev, pl.m[i].hwtype,
					 pl.m[i].hwlen, pl.m[i].hlen,
					 f559_hexs(hw, sizeof(hw), pl.m[i].h,
						   pl.m[i].hlen),
					 pl.m[i].llen,
					 f559_hexs(l2, sizeof(l2), pl.m[i].l,
						   pl.m[i].llen),
					 pl.m[i].vpresent, pl.m[i].vproto,
					 pl.m[i].vtci, pl.m[i].plen,
					 f559_hexs(hh, sizeof(hh), pl.m[i].p,
						   pl.m[i].plen > 42 ?
						   42 : pl.m[i].plen));

			if (w < 0 || w >= (int)sizeof(mb) - o2)
				break;
			o2 += w;
		}
		printf("F577 M|n=%d%s\n", pl.n, mb);
	}
	{
		char tb[1400];
		int o2 = 0;

		tb[0] = 0;
		for (i = 0; i < F577_TAPN; i++) {
			int w;

			if (F577_TAP[i].len > 0) {
				char hh[500];

				w = snprintf(tb + o2, sizeof(tb) - (size_t)o2,
					     "|t%d=%s:%d:%d:%s", i,
					     F577_TAPDEV[i], F577_TAP[i].n,
					     F577_TAP[i].flen,
					     f559_hexs(hh, sizeof(hh),
						       F577_TAP[i].b,
						       F577_TAP[i].len));
			} else {
				w = snprintf(tb + o2, sizeof(tb) - (size_t)o2,
					     "|t%d=%s:%d:%d:-", i,
					     F577_TAPDEV[i], F577_TAP[i].n,
					     F577_TAP[i].flen);
			}
			if (w < 0 || w >= (int)sizeof(tb) - o2)
				break;
			o2 += w;
		}
		printf("F577 T|%s|auxn=%d|atci=%d|atpid=%d|astat=%d\n",
		       tb[0] ? tb + 1 : tb, F577_TAP[0].auxn, F577_TAP[0].atci,
		       F577_TAP[0].atpid, F577_TAP[0].astat);
	}
}

/* ---------- the section ---------- */

static void f577_rd2(struct f577_act *A, int off0, int len0,
		     const unsigned char *imm0, int off1, int len1,
		     const unsigned char *imm1)
{
	A->nrd = 2;
	A->rdoff[0] = off0;
	A->rdlen[0] = len0;
	memcpy(A->rdimm[0], imm0, (size_t)len0);
	A->rdoff[1] = off1;
	A->rdlen[1] = len1;
	memcpy(A->rdimm[1], imm1, (size_t)len1);
}

static void f577_sec_pcp(void)
{
	struct f577_act A[2];
	unsigned char t65[2] = { 0x00, 0x65 };
	unsigned char t66[2] = { 0x00, 0x66 };
	unsigned char t67[2] = { 0x00, 0x67 };
	unsigned char tpid[2] = { 0x81, 0x00 };
	unsigned char t6066[2] = { 0x60, 0x66 };

	/* 0. nothing sent: the baseline of every counter */
	f577_maps_none();
	f577_arm("n0", -1, 0, NULL, 0);

	/* 1. control, map installed but nothing sets the priority */
	f577_maps_none();
	f577_qos_set("x1.102", 1, 5, 3);
	f577_arm("ctl", 0, 1, NULL, 0);

	/* 2. the tag as the frame carries it at the egress door, and the
	 *    TPID next to it: the assembled header is 18 bytes */
	{
		struct f577_act R;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 3);
		memset(&R, 0, sizeof(R));
		R.door = E77_E0;
		f577_rd2(&R, 12, 2, tpid, 14, 2, t66);
		A[0] = R;
		f577_arm("rd_e0", 0, 1, A, 1);
	}

	/* 3. the store alone: priority 5, no map at all */
	{
		struct f577_act S, R;

		f577_maps_none();
		memset(&S, 0, sizeof(S));
		S.door = E77_F6;
		S.set = 1;
		S.setval = 5;
		memset(&R, 0, sizeof(R));
		R.door = E77_E0;
		R.cmpm = 1;
		R.cmpval = 5;
		A[0] = S;
		A[1] = R;
		f577_arm("p5_nomap", 0, 1, A, 2);
	}

	/* 4. store 5, egress map 5->3: the wire should carry 0x6066 */
	{
		struct f577_act S;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 3);
		memset(&S, 0, sizeof(S));
		S.door = E77_F6;
		S.set = 1;
		S.setval = 5;
		A[0] = S;
		f577_arm("p5_m3", 0, 1, A, 1);
	}

	/* 5. store 0x15 with a mapping from=5: same bucket, no match */
	{
		struct f577_act S;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 3);
		memset(&S, 0, sizeof(S));
		S.door = E77_F6;
		S.set = 1;
		S.setval = 0x15;
		A[0] = S;
		f577_arm("p15_m5", 0, 1, A, 1);
	}

	/* 6. store 0x15 with a mapping from=0x15: the full value matches */
	{
		struct f577_act S;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 0x15, 5);
		memset(&S, 0, sizeof(S));
		S.door = E77_F6;
		S.set = 1;
		S.setval = 0x15;
		A[0] = S;
		f577_arm("p15_m15", 0, 1, A, 1);
	}

	/* 7. the PCP is the map's value: 5 -> 7 */
	{
		struct f577_act S;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 7);
		memset(&S, 0, sizeof(S));
		S.door = E77_F6;
		S.set = 1;
		S.setval = 5;
		A[0] = S;
		f577_arm("p5_m7", 0, 1, A, 1);
	}

	/* 8. store 6, map 5->3: different bucket */
	{
		struct f577_act S;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 3);
		memset(&S, 0, sizeof(S));
		S.door = E77_F6;
		S.set = 1;
		S.setval = 6;
		A[0] = S;
		f577_arm("p6_m3", 0, 1, A, 1);
	}

	/* 9. store 5 at the egress door: after the header was built */
	{
		struct f577_act S;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 3);
		memset(&S, 0, sizeof(S));
		S.door = E77_E0;
		S.set = 1;
		S.setval = 5;
		A[0] = S;
		f577_arm("p5_e0", 0, 1, A, 1);
	}

	/* 10. store 5 at prerouting: in time, like forward */
	{
		struct f577_act S;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 3);
		memset(&S, 0, sizeof(S));
		S.door = E77_G6;
		S.set = 1;
		S.setval = 5;
		A[0] = S;
		f577_arm("p5_g6", 0, 1, A, 1);
	}

	/* 11. the map removed with to=0 */
	{
		struct f577_act S;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 3);
		f577_qos_set("x1.102", 1, 5, 0);
		memset(&S, 0, sizeof(S));
		S.door = E77_F6;
		S.set = 1;
		S.setval = 5;
		A[0] = S;
		f577_arm("p5_rm", 0, 1, A, 1);
	}

	/* 12. control for the second egress device */
	f577_maps_none();
	f577_qos_set("x1.103", 1, 5, 6);
	f577_arm("ctl_b", 4, 1, NULL, 0);

	/* 13. the same store, a different egress device and map */
	{
		struct f577_act S;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 3);
		f577_qos_set("x1.103", 1, 5, 6);
		memset(&S, 0, sizeof(S));
		S.door = E77_F6;
		S.set = 1;
		S.setval = 5;
		A[0] = S;
		f577_arm("p5_b", 4, 1, A, 1);
	}

	/* 14. the ingress map: priority is set before the first hook */
	{
		struct f577_act R1, R2;

		f577_maps_none();
		f577_qos_set("x1.101", 0, 3, 5);
		memset(&R1, 0, sizeof(R1));
		R1.door = E77_G6;
		R1.cmpm = 1;
		R1.cmpval = 5;
		memset(&R2, 0, sizeof(R2));
		R2.door = E77_F6;
		R2.cmpm = 1;
		R2.cmpval = 5;
		A[0] = R1;
		A[1] = R2;
		f577_arm("ing3_prio", 3, 1, A, 2);
	}

	/* 14b. where the ingress reader sits: the frame's PCP is 3, the ingress
	 * map is 3->5, and the netdev ingress door is BEFORE vlan_do_receive()
	 * (nf_ingress() is dev.c:6159, vlan_do_receive() dev.c:6175), so the
	 * same frame reads priority 0 at n1 and 5 at g6 */
	{
		struct f577_act R1, R2;

		f577_maps_none();
		f577_qos_set("x1.101", 0, 3, 5);
		memset(&R1, 0, sizeof(R1));
		R1.door = E77_N1;
		R1.cmpm = 1;
		R1.cmpval = 0;
		memset(&R2, 0, sizeof(R2));
		R2.door = E77_G6;
		R2.cmpm = 1;
		R2.cmpval = 5;
		A[0] = R1;
		A[1] = R2;
		f577_arm("ing_n1_g6", 3, 1, A, 2);
	}

	/* 15. PCP 3 in, PCP 7 out, no rule at all */
	f577_maps_none();
	f577_qos_set("x1.101", 0, 3, 5);
	f577_qos_set("x1.102", 1, 5, 7);
	f577_arm("ing3_e", 3, 1, NULL, 0);

	/* 16. PCP 0 in, the same chain: no mapping for priority 0 */
	f577_maps_none();
	f577_qos_set("x1.101", 0, 3, 5);
	f577_qos_set("x1.102", 1, 5, 7);
	f577_arm("ing0_e", 0, 1, NULL, 0);

	/* 17. the ingress tag as the frame carries it at forward */
	{
		struct f577_act R;

		f577_maps_none();
		memset(&R, 0, sizeof(R));
		R.door = E77_F6;
		R.nrd = 1;
		R.rdoff[0] = 14;
		R.rdlen[0] = 2;
		memcpy(R.rdimm[0], t65, 2);
		A[0] = R;
		f577_arm("rd_f6", 0, 1, A, 1);
	}

	/* 18. the far end rebuilt from metadata by nft_payload_copy_vlan:
	 * two reads on the receiving door of the wire witness */
	{
		struct f577_act S, R;

		f577_maps_none();
		f577_qos_set("x1.102", 1, 5, 3);
		memset(&S, 0, sizeof(S));
		S.door = E77_F6;
		S.set = 1;
		S.setval = 5;
		memset(&R, 0, sizeof(R));
		R.door = E77_R0;
		f577_rd2(&R, 12, 2, tpid, 14, 2, t6066);
		A[0] = S;
		A[1] = R;
		f577_arm("rd_r0", 0, 1, A, 2);
	}

	f577_maps_none();
}

static void f577_usage(const char *p)
{
	printf("usage: %s pcp\n", p);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "pcp";
	int rc;

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("F577 START|mode=%s\n", mode);
	if (strcmp(mode, "pcp")) {
		f577_usage(argv[0]);
		return 2;
	}
	rc = f577_env();
	if (rc) {
		printf("F577 ENVFAIL|rc=%d\n", rc);
		return 1;
	}
	rc = f577_chains();
	if (rc) {
		printf("F577 CHFAIL|rc=%d\n", rc);
		return 1;
	}
	f577_sec_pcp();
	printf("F577 DONE\n");
	return 0;
}
