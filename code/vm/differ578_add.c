/* differ578_add.c -- turn 578 (F56).
 *
 *  THE HOLES named at the end of 577:
 *   1. the bridged (L2) path for the same four tag bytes -- F52 saw the tag
 *      there only as metadata, F53 only on a layer-3 device behind a cleared
 *      VLAN_FLAG_REORDER_HDR, and 577 only the routed path;
 *   2. 802.1ad on the egress path -- a device whose vlan_proto is 88a8, where
 *      validate_xmit_vlan()'s rule about which tags are pushed into bytes is
 *      a different branch.
 *
 *  Both questions turn out to be the same question, asked on two topologies:
 *  WHERE THE TAG LIVES at the moment a rule touches it, and who reads it
 *  afterwards.
 *
 *  Mode `ad` (routed, one veth pair, four egress devices):
 *
 *      x1.101  vid 101 8100 reorder CLEARED   (ingress: tag put back in bytes)
 *      x1.102  vid 102 88a8 reorder CLEARED   -> fd02::92
 *      x1.103  vid 103 8100 reorder CLEARED   -> fd03::92
 *      x1.104  vid 104 88a8 reorder DEFAULT   -> fd04::92
 *
 *  The two call sites that consult a capability bit:
 *    vlan_dev_hard_start_xmit(): pops an in-band tag into skb->vlan_tci when
 *        vlan_hw_offload_capable(real_dev->features, vlan->vlan_proto);
 *    validate_xmit_vlan(): pushes a metadata tag into bytes when the device is
 *        NOT capable.  veth advertises BOTH CTAG_TX and STAG_TX, so with a
 *        veth peer the tag is a word; clear the bit with ETHTOOL_SFEATURES and
 *        the same tag becomes bytes.  That is the A/B of this turn.
 *
 *  Mode `br` (bridge, three veth pairs, VLAN devices as bridge ports):
 *
 *      br0 <- x1.101 (reorder CLEARED)  <- tagged 101 from x0
 *          <- z1.101 (reorder DEFAULT)  <- tagged 101 from z0
 *          -> y1.102 (reorder DEFAULT)  -> untagged? tagged 102 at y0
 *
 *  vlan_do_receive() skips the byte reinsertion when the VLAN device is a
 *  bridge port (netif_is_bridge_port), so the frame reaches every bridge door
 *  with the tag gone from bytes and from metadata, and the ingress flag is not
 *  consulted at all.  On the way out nobody calls vlan_dev_hard_header()
 *  (bridged frames do not go through neighbour resolution), so the egress port
 *  writes its own vid as a WORD, and @ll,12/14 at that door are the tag's
 *  fields, not the frame's.
 */

#define F578_SPORT	43200
#define F578_DPORT	5000

static const unsigned char A78_SRC[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x11 };
static const unsigned char A78_D2[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x92 };
static const unsigned char A78_L2[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x91 };
static const unsigned char A78_D3[16] = { 0xfd, 0x03, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x92 };
static const unsigned char A78_L3[16] = { 0xfd, 0x03, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x91 };
static const unsigned char A78_D4[16] = { 0xfd, 0x04, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x92 };
static const unsigned char A78_L4[16] = { 0xfd, 0x04, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x91 };
/* br0's own address: the IPv6 destination of the bridged frame, so the local
 * copy is delivered to the listener socket (a fate witness, not a byte one) */
static const unsigned char A78_B6[16] = { 0xfd, 0x05, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00,
					  0x91 };
static const unsigned char A78_ANY[16];
static const unsigned char A78_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define F578_B_LL	0

#define F578_IFLA_VLAN_ID_	1
#define F578_IFLA_VLAN_PROTO_	2
#define F578_IFLA_VLAN_FLAGS_	3

/* payload bases / hooks come from the accumulated file; bridge hooks: */
#define F578_NF_BR_PRE_ROUTING	0
#define F578_NF_BR_LOCAL_IN	1
#define F578_NF_BR_FORWARD	2

static struct f571_door D578A[] = {
	/* tag: mode `ad` -- the routed path */
	{ "g6", NFPROTO_IPV6,   "f78a", NULL,     0, 110, 120 },
	{ "f6", NFPROTO_IPV6,   "f78b", NULL,     2, 130, 140 },
	{ "e2", NFPROTO_NETDEV, "f78c", "x1.102", 1, 150, 160 },
	{ "e3", NFPROTO_NETDEV, "f78d", "x1.103", 1, 170, 180 },
	{ "e4", NFPROTO_NETDEV, "f78e", "x1.104", 1, 190, 200 },
	{ "p1", NFPROTO_NETDEV, "f78f", "x1",     1, 210, 220 },
	{ "r0", NFPROTO_NETDEV, "f78g", "x0",     0, 230, 240 },
};
enum { A_G6 = 0, A_F6, A_E2, A_E3, A_E4, A_P1, A_R0 };
#define NDA78 7

static struct f571_door D578B[] = {
	/* tag: mode `br` -- the bridged path */
	{ "bv", NFPROTO_BRIDGE, "f78h", NULL,     F578_NF_BR_PRE_ROUTING, 110, 120 },
	{ "bf", NFPROTO_BRIDGE, "f78i", NULL,     F578_NF_BR_FORWARD,     130, 140 },
	{ "bl", NFPROTO_BRIDGE, "f78j", NULL,     F578_NF_BR_LOCAL_IN,    150, 160 },
	{ "gv", NFPROTO_IPV6,   "f78k", NULL,     0, 170, 180 },
	{ "n1", NFPROTO_NETDEV, "f78l", "x1",     0, 190, 200 },
	{ "nz", NFPROTO_NETDEV, "f78m", "z1",     0, 210, 220 },
	{ "q1", NFPROTO_NETDEV, "f78n", "x1.101", 0, 230, 240 },
	{ "e2", NFPROTO_NETDEV, "f78o", "y1.102", 1, 250, 260 },
	{ "p1", NFPROTO_NETDEV, "f78p", "y1",     1, 270, 280 },
	{ "ry", NFPROTO_NETDEV, "f78q", "y0",     0, 290, 300 },
};
enum { B_BV = 0, B_BF, B_BL, B_GV, B_N1, B_NZ, B_Q1, B_E2, B_P1, B_RY };
#define NDB78 10

#define F578_NTAP 2
struct f578_tap {
	int fd;
	int only_out;
	int n;
	int skip;
	int flen;
	int len;
	unsigned char b[192];
	int auxn;
	int atci;
	int atpid;
	int astat;
	int apkt;
	int aproto;
	int alen_bytes;
	int amac;
	int anet;
	int alen;
	int asnap;
};
static struct f578_tap F578_TAP[F578_NTAP];
static const char *F578_TAPDEV[F578_NTAP][2] = {
	{ "x1", "y1" },		/* tap 0: the wire, OUTGOING copies only */
	{ "x0", "y0" },		/* tap 1: the receiver, everything */
};

static unsigned char F578_X0M[6], F578_X1M[6], F578_Y0M[6], F578_Y1M[6];
static unsigned char F578_Z0M[6], F578_Z1M[6], F578_BRM[6];
static int F578_NFL = -1;
static int F578_U6 = -1;
static unsigned char F578_FA[192], F578_FB[192], F578_FE[192];
static unsigned char F578_FC[192], F578_FD[192];
static int F578_LA = -1, F578_LB = -1, F578_LE = -1, F578_LC = -1, F578_LD = -1;
static int F578_ST = -9;
static int F578_MODE = -1;
static unsigned long long F578_U6TOT;	/* datagrams drained in this arm */
static int F578_U6LEN = -1, F578_U6SPORT = -1;

/* ---------- tap ---------------------------------------------------------- */

static int f578_tap_open_aux(const char *dev)
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

static void f578_tap_reset(int i)
{
	F578_TAP[i].n = 0;
	F578_TAP[i].skip = 0;
	F578_TAP[i].len = -1;
	F578_TAP[i].flen = -1;
	F578_TAP[i].auxn = 0;
	F578_TAP[i].atci = -1;
	F578_TAP[i].atpid = -1;
	F578_TAP[i].astat = -1;
	F578_TAP[i].apkt = -1;
	F578_TAP[i].aproto = -1;
	F578_TAP[i].alen_bytes = -1;
	F578_TAP[i].amac = -1;
	F578_TAP[i].anet = -1;
	F578_TAP[i].alen = -1;
	F578_TAP[i].asnap = -1;
}

static void f578_tap_open_mask(int mask)
{
	int i;

	for (i = 0; i < F578_NTAP; i++) {
		if (F578_TAP[i].fd >= 0)
			close(F578_TAP[i].fd);
		F578_TAP[i].fd = -1;
		f578_tap_reset(i);
	}
	for (i = 0; i < F578_NTAP; i++) {
		const char *dev = F578_TAPDEV[i][F578_MODE == 1 ? 1 : 0];

		if (!(mask & (1 << i)))
			continue;
		F578_TAP[i].fd = f578_tap_open_aux(dev);
		F578_TAP[i].only_out = (i == 0);
		if (F578_TAP[i].fd < 0)
			printf("F578 TAPFAIL|dev=%s|fd=%d\n", dev,
			       F578_TAP[i].fd);
	}
}

static void f578_tap_drain(int i)
{
	unsigned char b[2048], cb[256];
	int r;

	f578_tap_reset(i);
	if (F578_TAP[i].fd < 0)
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
		r = (int)recvmsg(F578_TAP[i].fd, &msg, MSG_DONTWAIT);
		if (r <= 0)
			break;
		if (F578_TAP[i].only_out) {
			if (from.sll_pkttype != 4 /* PACKET_OUTGOING */)
				continue;
		} else {
			if (from.sll_pkttype == 4)
				continue;
		}
		if (!f568_needle(b, r)) {
			F578_TAP[i].skip++;
			continue;
		}
		F578_TAP[i].n++;
		if (F578_TAP[i].apkt < 0) {
			F578_TAP[i].apkt = (int)from.sll_pkttype;
			F578_TAP[i].aproto = (int)ntohs(from.sll_protocol);
		}
		if (F578_TAP[i].len < 0) {
			F578_TAP[i].flen = r;
			k = r < (int)sizeof(F578_TAP[i].b) ?
			    r : (int)sizeof(F578_TAP[i].b);
			memcpy(F578_TAP[i].b, b, (size_t)k);
			F578_TAP[i].len = k;
		}
		for (cm = CMSG_FIRSTHDR(&msg); cm;
		     cm = CMSG_NXTHDR(&msg, cm)) {
			struct tpacket_auxdata aux;

			if (cm->cmsg_level != SOL_PACKET ||
			    cm->cmsg_type != PACKET_AUXDATA)
				continue;
			F578_TAP[i].alen_bytes = (int)cm->cmsg_len -
						 (int)CMSG_LEN(0);
			if (cm->cmsg_len < CMSG_LEN(sizeof(aux)))
				continue;
			memcpy(&aux, CMSG_DATA(cm), sizeof(aux));
			F578_TAP[i].auxn++;
			if (F578_TAP[i].atci < 0) {
				F578_TAP[i].atci = (int)aux.tp_vlan_tci;
				F578_TAP[i].atpid = (int)aux.tp_vlan_tpid;
				F578_TAP[i].astat = (int)aux.tp_status;
				F578_TAP[i].amac = (int)aux.tp_mac;
				F578_TAP[i].anet = (int)aux.tp_net;
				F578_TAP[i].alen = (int)aux.tp_len;
				F578_TAP[i].asnap = (int)aux.tp_snaplen;
			}
		}
	}
}

/* ---------- features: the bit that decides bytes-vs-word ---------------- */

#define F578_ETHTOOL_GFEATURES	0x0000003a
#define F578_ETHTOOL_SFEATURES	0x0000003b
#define F578_NETIF_F_HW_VLAN_CTAG_TX_BIT	7
#define F578_NETIF_F_HW_VLAN_STAG_TX_BIT	45

struct f578_gf {
	uint32_t cmd;
	uint32_t size;
	struct {
		uint32_t avail;
		uint32_t req;
		uint32_t act;
		uint32_t nch;
	} b[2];
};

struct f578_sf {
	uint32_t cmd;
	uint32_t size;
	struct {
		uint32_t valid;
		uint32_t req;
	} b[2];
};

static int f578_feat_get(const char *dev, struct f578_gf *g)
{
	struct ifreq ifr;
	int fd, rc;

	memset(g, 0, sizeof(*g));
	g->cmd = F578_ETHTOOL_GFEATURES;
	g->size = 2;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
	ifr.ifr_data = (void *)g;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	if (rc < 0)
		rc = -errno;
	close(fd);
	return rc;
}

static int f578_feat_set(const char *dev, int bit, int on)
{
	struct f578_sf s;
	struct ifreq ifr;
	int fd, rc;

	memset(&s, 0, sizeof(s));
	s.cmd = F578_ETHTOOL_SFEATURES;
	s.size = 2;
	s.b[bit / 32].valid = 1u << (bit % 32);
	if (on)
		s.b[bit / 32].req = 1u << (bit % 32);
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
	ifr.ifr_data = (void *)&s;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	if (rc < 0)
		rc = -errno;
	close(fd);
	return rc;
}

/* feat: 0 = both bits on, 1 = STAG off, 2 = CTAG off */
static void f578_feat_arm(const char *arm, int feat)
{
	struct f578_gf g;
	int r1, r2, r3;

	r1 = f578_feat_set("x1", F578_NETIF_F_HW_VLAN_CTAG_TX_BIT,
			   feat != 2);
	r2 = f578_feat_set("x1", F578_NETIF_F_HW_VLAN_STAG_TX_BIT,
			   feat != 1);
	r3 = f578_feat_get("x1", &g);
	printf("F578 FEAT|arm=%s|feat=%d|r1=%d|r2=%d|r3=%d|"
	       "av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       arm, feat, r1, r2, r3, g.b[0].avail, g.b[0].act,
	       g.b[1].avail, g.b[1].act);
}

/* ---------- frames ------------------------------------------------------ */

static int f578_frame(unsigned char *out, const unsigned char *dmac,
		      const unsigned char *smac, unsigned short tpid,
		      unsigned short tci, const unsigned char *dst)
{
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = (unsigned char)(tpid >> 8);
	out[13] = (unsigned char)(tpid & 0xff);
	out[14] = (unsigned char)(tci >> 8);
	out[15] = (unsigned char)(tci & 0xff);
	out[16] = 0x86;
	out[17] = 0xdd;
	return 18 + f570_ip6(out + 18, A78_SRC, dst, 0, F578_SPORT,
			     F578_DPORT);
}

/* ---------- snapshot ---------------------------------------------------- */

#define F578_NDEV 13
static const char *F578_DEV[F578_NDEV] = {
	"x0", "x1", "x1.101", "x1.102", "x1.103", "x1.104",
	"x0.102", "x0.103", "x0.104",
	"y0", "y1", "y0.102", "y1.102",
};

struct f578_rep {
	unsigned long long i6in, i6deliv, i6disc, i6hdr, i6nor, i6addr,
		i6unk, i6trunc, i6mcast, i6fwd;
	unsigned long long u6in, u6err, u6nop;
	unsigned long long rxp[F578_NDEV], rxb[F578_NDEV], oth[F578_NDEV];
	unsigned long long u6n;
	int u6len;
	int u6sport;
	int bstp[3];
};

static void f578_u6_drain(struct f578_rep *R)
{
	unsigned char b[1024];
	struct sockaddr_in6 sa;
	socklen_t sl;
	int r;

	if (F578_U6 < 0)
		return;
	for (;;) {
		memset(&sa, 0, sizeof(sa));
		sl = sizeof(sa);
		r = (int)recvfrom(F578_U6, b, sizeof(b), MSG_DONTWAIT,
				  (struct sockaddr *)&sa, &sl);
		if (r < 0)
			break;
		if (!f568_needle(b, r))
			continue;
		R->u6n++;
		F578_U6TOT++;
		R->u6len = r;
		R->u6sport = ntohs(sa.sin6_port);
		F578_U6LEN = r;
		F578_U6SPORT = ntohs(sa.sin6_port);
	}
}

static void f578_snap(struct f578_rep *R)
{
	struct f573_lst s;
	int i;

	memset(R, 0, sizeof(*R));
	R->u6len = -1;
	R->u6sport = -1;
	f578_u6_drain(R);
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
	for (i = 0; i < F578_NDEV; i++) {
		f573_stats(F578_DEV[i], &s);
		if (!s.ok)
			continue;
		R->rxp[i] = s.rxp;
		R->rxb[i] = s.rxb;
		R->oth[i] = s.other;
	}
}

/* ---------- environment ------------------------------------------------ */

static void f578_clean(void)
{
	f558_link_del("br0");
	f558_link_del("x0");
	f558_link_del("y0");
	f558_link_del("z0");
}

static void f578_v6dev(const char *dev, int fwd, int en)
{
	char p[160];

	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", dev);
	f555_sysctl(p, en ? "0" : "1");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/accept_dad", dev);
	f555_sysctl(p, "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/dad_transmits", dev);
	f555_sysctl(p, "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/accept_ra", dev);
	f555_sysctl(p, "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/autoconf", dev);
	f555_sysctl(p, "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/forwarding", dev);
	f555_sysctl(p, fwd ? "1" : "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/send_redirects", dev);
	f555_sysctl(p, "0");
}

static int f578_env_ad(void)
{
	int r[8];
	char a[32], b[32], ab[400];
	const char *v6[4] = { "x1.101", "x1.102", "x1.103", "x1.104" };
	int i;

	f578_clean();
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	if (link_add_veth("x0", "x1")) {
		printf("F578 FAIL|veth\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	if (mac_get("x0", F578_X0M) || mac_get("x1", F578_X1M)) {
		printf("F578 FAIL|mac\n");
		return -1;
	}
	r[0] = f575_link_add_vlan("x1.101", "x1", 101, 0x0000, 1);
	r[1] = f575_link_add_vlan("x1.102", "x1", 102, 0x88a8, 1);
	r[2] = f575_link_add_vlan("x1.103", "x1", 103, 0x0000, 1);
	r[3] = f575_link_add_vlan("x1.104", "x1", 104, 0x88a8, 0);
	r[4] = f575_link_add_vlan("x0.102", "x0", 102, 0x88a8, 0);
	r[5] = f575_link_add_vlan("x0.103", "x0", 103, 0x0000, 0);
	r[6] = f575_link_add_vlan("x0.104", "x0", 104, 0x88a8, 0);
	printf("F578 VNEW|i101=%d|i102=%d|i103=%d|i104=%d|o102=%d|o103=%d|"
	       "o104=%d\n", r[0], r[1], r[2], r[3], r[4], r[5], r[6]);
	for (i = 0; i < 7; i++)
		if (r[i])
			return -6;
	f575_vlan_readback("x1.101");
	f575_vlan_readback("x1.102");
	f575_vlan_readback("x1.103");
	f575_vlan_readback("x1.104");
	f575_vlan_readback("x0.102");
	f575_vlan_readback("x0.103");
	f575_vlan_readback("x0.104");
	set_up("x1.101");
	set_up("x1.102");
	set_up("x1.103");
	set_up("x1.104");
	set_up("x0.102");
	set_up("x0.103");
	set_up("x0.104");
	for (i = 0; i < 4; i++)
		f578_v6dev(v6[i], 1, 1);
	f578_feat_arm("env", 0);
	printf("F578 ADDR|a2=%d|a3=%d|a4=%d\n",
	       f564_addr6("x1.102", A78_L2, 64),
	       f564_addr6("x1.103", A78_L3, 64),
	       f564_addr6("x1.104", A78_L4, 64));
	printf("F578 NEIGH|n2=%d|n3=%d|n4=%d\n",
	       f569_neigh6_add("x1.102", A78_D2, F578_X0M),
	       f569_neigh6_add("x1.103", A78_D3, F578_X0M),
	       f569_neigh6_add("x1.104", A78_D4, F578_X0M));
	F578_LA = f578_frame(F578_FA, F578_X1M, F578_X0M, 0x8100, 0x0065,
			     A78_D2);
	F578_LB = f578_frame(F578_FB, F578_X1M, F578_X0M, 0x8100, 0x0065,
			     A78_D3);
	F578_LE = f578_frame(F578_FE, F578_X1M, F578_X0M, 0x8100, 0x0065,
			     A78_D4);
	printf("F578 ENV|mode=ad|x0=%d|x1=%d|e2=%d|e3=%d|e4=%d|r0=%d|"
	       "x0mac=%s|x1mac=%s\n",
	       f555_ifindex("x0"), f555_ifindex("x1"), f555_ifindex("x1.102"),
	       f555_ifindex("x1.103"), f555_ifindex("x1.104"),
	       f555_ifindex("x0.102"), f559_hexs(a, sizeof(a), F578_X0M, 6),
	       f559_hexs(b, sizeof(b), F578_X1M, 6));
	printf("F578 FRM|fa=%s\n", f559_hexs(ab, sizeof(ab), F578_FA, F578_LA));
	printf("F578 FRM|fb=%s\n", f559_hexs(ab, sizeof(ab), F578_FB, F578_LB));
	printf("F578 FRM|fe=%s\n", f559_hexs(ab, sizeof(ab), F578_FE, F578_LE));
	printf("F578 FLEN|fa=%d|fb=%d|fe=%d\n", F578_LA, F578_LB, F578_LE);
	usleep(3000000);
	F578_ST = f573_settle();
	printf("F578 SETTLE|mode=ad|st=%d\n", F578_ST);
	return 0;
}

static int f578_env_br(void)
{
	int r[4];
	char a[32], b[32], c[32], ab[400];
	int i;

	f578_clean();
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
	if (link_add_veth("x0", "x1") || link_add_veth("y0", "y1") ||
	    link_add_veth("z0", "z1")) {
		printf("F578 FAIL|veth\n");
		return -1;
	}
	if (f556_link_add_kind("br0", "bridge")) {
		printf("F578 FAIL|bridge\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	set_up("y0");
	set_up("y1");
	set_up("z0");
	set_up("z1");
	set_up("br0");
	if (mac_get("x0", F578_X0M) || mac_get("x1", F578_X1M) ||
	    mac_get("y0", F578_Y0M) || mac_get("y1", F578_Y1M) ||
	    mac_get("z0", F578_Z0M) || mac_get("z1", F578_Z1M)) {
		printf("F578 FAIL|mac\n");
		return -1;
	}
	r[0] = f575_link_add_vlan("x1.101", "x1", 101, 0x0000, 1);
	r[1] = f575_link_add_vlan("z1.101", "z1", 101, 0x0000, 0);
	r[2] = f575_link_add_vlan("y1.102", "y1", 102, 0x0000, 0);
	r[3] = f575_link_add_vlan("y0.102", "y0", 102, 0x0000, 0);
	printf("F578 VNEW|x1_101=%d|z1_101=%d|y1_102=%d|y0_102=%d\n",
	       r[0], r[1], r[2], r[3]);
	for (i = 0; i < 4; i++)
		if (r[i])
			return -6;
	f575_vlan_readback("x1.101");
	f575_vlan_readback("z1.101");
	f575_vlan_readback("y1.102");
	f575_vlan_readback("y0.102");
	set_up("x1.101");
	set_up("z1.101");
	set_up("y1.102");
	set_up("y0.102");
	printf("F578 ENS|x1_101=%d|z1_101=%d|y1_102=%d\n",
	       f556_link_enslave("x1.101", "br0"),
	       f556_link_enslave("z1.101", "br0"),
	       f556_link_enslave("y1.102", "br0"));
	if (mac_get("br0", F578_BRM)) {
		printf("F578 FAIL|mac_br\n");
		return -1;
	}
	f578_v6dev("br0", 0, 1);
	f555_sysctl("/sys/class/net/br0/bridge/multicast_snooping", "0");
	f555_sysctl("/sys/class/net/br0/bridge/multicast_querier", "0");
	printf("F578 ADDR6|rc=%d\n", f564_addr6("br0", A78_B6, 64));
	F578_LC = f578_frame(F578_FC, A78_BC, F578_X0M, 0x8100, 0x0065,
			     A78_B6);
	F578_LD = f578_frame(F578_FD, A78_BC, F578_Z0M, 0x8100, 0x0065,
			     A78_B6);
	printf("F578 ENV|mode=br|br0=%d|x1=%d|n1=%d|nz=%d|q1=%d|e2=%d|"
	       "p1=%d|ry=%d|br0mac=%s\n",
	       f555_ifindex("br0"), f555_ifindex("x1"),
	       f555_ifindex("x1.101"), f555_ifindex("z1.101"),
	       f555_ifindex("x1.101"), f555_ifindex("y1.102"),
	       f555_ifindex("y1"), f555_ifindex("y0"),
	       f559_hexs(a, sizeof(a), F578_BRM, 6));
	printf("F578 FRM|fc=%s\n", f559_hexs(ab, sizeof(ab), F578_FC, F578_LC));
	printf("F578 FRM|fd=%s\n", f559_hexs(ab, sizeof(ab), F578_FD, F578_LD));
	printf("F578 FLEN|fc=%d|fd=%d\n", F578_LC, F578_LD);
	printf("F578 SYS|stp=%d|x1state=%d|z1state=%d|y1state=%d|"
	       "br0v6=%d|x1v6=%d|y0v6=%d|y0_102v6=%d\n",
	       f573_sysint("/sys/class/net/br0/bridge/stp_state"),
	       f573_sysint("/sys/class/net/x1.101/brport/state"),
	       f573_sysint("/sys/class/net/z1.101/brport/state"),
	       f573_sysint("/sys/class/net/y1.102/brport/state"),
	       f573_sysint("/proc/sys/net/ipv6/conf/br0/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x1/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/y0/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/y0.102/disable_ipv6"));
	usleep(3000000);
	F578_ST = f573_settle();
	printf("F578 SETTLE|mode=br|st=%d\n", F578_ST);
	(void)b;
	(void)c;
	return 0;
}

/* ---------- chains ------------------------------------------------------ */

static int f578_chains_mode(int mode)
{
	struct f571_door *D = mode == 1 ? D578B : D578A;
	int n = mode == 1 ? NDB78 : NDA78;
	int i, rc = 0;

	for (i = 0; i < n; i++) {
		int a, b, c;

		a = add_table(D[i].fam, D[i].table);
		b = f556_add_chain(D[i].fam, D[i].table, "pre0", D[i].hook,
				   (uint32_t)D[i].prio0, 1, D[i].dev);
		c = f556_add_chain(D[i].fam, D[i].table, "ch", D[i].hook,
				   (uint32_t)D[i].prio1, 1, D[i].dev);
		printf("F578 CH|mode=%d|door=%s|fam=%d|hook=%u|dev=%s|"
		       "table=%d|pre0=%d|ch=%d\n", mode, D[i].tag,
		       (int)D[i].fam, D[i].hook, D[i].dev ? D[i].dev : "-",
		       a, b, c);
		rc |= a | b | c;
	}
	return rc;
}

static void f578_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < NDA78; i++) {
		f557_flush(D578A[i].fam, D578A[i].table, "pre0", &acks);
		f557_flush(D578A[i].fam, D578A[i].table, "ch", &acks);
	}
	for (i = 0; i < NDB78; i++) {
		f557_flush(D578B[i].fam, D578B[i].table, "pre0", &acks);
		f557_flush(D578B[i].fam, D578B[i].table, "ch", &acks);
	}
}

/* ---------- one action -------------------------------------------------- */

struct f578_act {
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

#define F578_ACT_SET(d, off, len, v)					\
	{ .door = (d), .set = 1, .setval = (v),			\
	  .rdoff = { (off), 0 }, .rdlen = { (len), 0 } }
#define F578_ACT_RD(d, off, len, v)					\
	{ .door = (d), .nrd = 1, .rdoff = { (off), 0 },			\
	  .rdlen = { (len), 0 },					\
	  .rdimm = { { (unsigned char)(((v) >> 8) & 0xff),		\
		       (unsigned char)((v) & 0xff) } } }
#define F578_ACT_RD1(d, off, v)						\
	{ .door = (d), .nrd = 1, .rdoff = { (off), 0 },			\
	  .rdlen = { 1, 0 },						\
	  .rdimm = { { (unsigned char)((v) & 0xff) } } }
#define F578_ACT_RD2(d, o1, l1, v1, o2, l2, v2)				\
	{ .door = (d), .nrd = 2, .rdoff = { (o1), (o2) },		\
	  .rdlen = { (l1), (l2) },					\
	  .rdimm = { { (unsigned char)(((v1) >> 8) & 0xff),		\
		       (unsigned char)((v1) & 0xff) },			\
		     { (unsigned char)(((v2) >> 8) & 0xff),		\
		       (unsigned char)((v2) & 0xff) } } }
#define F578_ACT_PRIO(d, v)						\
	{ .door = (d), .cmpm = 1, .cmpval = (v) }
#define F578_ACT_PRIO_RD(d, v, off, len, rv)				\
	{ .door = (d), .cmpm = 1, .cmpval = (v), .nrd = 1,		\
	  .rdoff = { (off), 0 }, .rdlen = { (len), 0 },			\
	  .rdimm = { { (unsigned char)(((rv) >> 8) & 0xff),		\
		       (unsigned char)((rv) & 0xff) } } }

static int f578_rule(const struct f571_door *D, const char *chain,
		     const char *prefix, const struct f578_act *A, int *acks)
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
	if (A->set) {
		unsigned char s[4];

		memset(s, 0, sizeof(s));
		s[0] = (unsigned char)((A->setval >> 8) & 0xff);
		s[1] = (unsigned char)(A->setval & 0xff);
		{
			/* len is carried in rdlen[0] for a store */
			int len = A->rdlen[0] ? A->rdlen[0] : 2;

			f565_store(nlh, F578_B_LL, (uint32_t)A->rdoff[0],
				   (uint32_t)len, s, 0, 0);
		}
	}
	for (i = 0; i < A->nrd && i < 2; i++) {
		f562_read(nlh, F578_B_LL, (uint32_t)A->rdoff[i],
			  (uint32_t)A->rdlen[i]);
		f562_cmp(nlh, F562_RD_DREG, A->rdimm[i], A->rdlen[i]);
	}
	log_expr(nlh, 5, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

/* ---------- one arm ----------------------------------------------------- */

struct f578_arm {
	const char *name;
	int mode;
	int fk;			/* 0..4 -> FA FB FE FC FD */
	int sdev;		/* 0 = x0, 1 = z0 */
	int feat;		/* 0 none, 1 STAG off, 2 CTAG off */
	struct f578_act a[2];
};

static void f578_arm(const struct f578_arm *A)
{
	struct f571_cfg N;
	struct f578_rep r0, r;
	struct f575_pl pl;
	struct f571_door *D = A->mode == 1 ? D578B : D578A;
	int nd = A->mode == 1 ? NDB78 : NDA78;
	const unsigned char *fr = NULL;
	int flen = 0, na = 0, i, j, acks = 0, snd = 0, polls = 0;
	unsigned long long c0[16], c1[16], s0[2], s1[2];
	int rcs[2] = { -99, -99 };
	char hx[64], hx2[64];
	const char *fkn = "A";

	memset(&r0, 0, sizeof(r0));
	memset(&r, 0, sizeof(r));
	memset(s0, 0, sizeof(s0));
	memset(s1, 0, sizeof(s1));
	switch (A->fk) {
	case 0: fr = F578_FA; flen = F578_LA; fkn = "A"; break;
	case 1: fr = F578_FB; flen = F578_LB; fkn = "B"; break;
	case 2: fr = F578_FE; flen = F578_LE; fkn = "E"; break;
	case 3: fr = F578_FC; flen = F578_LC; fkn = "C"; break;
	default: fr = F578_FD; flen = F578_LD; fkn = "D"; break;
	}
	for (i = 0; i < 2; i++)
		if (A->a[i].door >= 0)
			na = i + 1;
	F578_U6TOT = 0;
	F578_U6LEN = -1;
	F578_U6SPORT = -1;
	f578_flush_all();
	f575_nfl_drain(NULL);
	usleep(120000);		/* the settle was 3 s per arm: 30 arms cost more
				 * than the measurement itself (F56 #3) */
	if (A->mode == 0)
		f578_feat_arm(A->name, A->feat);
	f578_tap_open_mask(3);
	for (i = 0; i < F578_NTAP; i++)
		if (F578_TAP[i].fd >= 0)
			f578_tap_drain(i);
	f571_zero(&N, "p");
	for (i = 0; i < nd; i++) {
		char nm[8];

		snprintf(nm, sizeof(nm), "p%d", i);
		if (f571_rule(&D[i], "pre0", nm, &N, &acks))
			printf("F578 RUFAIL|arm=%s|door=%s\n", A->name,
			       D[i].tag);
	}
	for (j = 0; j < na; j++)
		rcs[j] = f578_rule(&D[A->a[j].door], "ch", "s", &A->a[j],
				   &acks);
	for (i = 0; i < nd; i++)
		c0[i] = f555_count(D[i].fam, D[i].table, "pre0");
	for (j = 0; j < na; j++)
		s0[j] = f555_count(D[A->a[j].door].fam,
				   D[A->a[j].door].table, "ch");
	f578_snap(&r0);
	snd += (pkt_send_p(A->sdev == 1 ? "z0" : "x0", fr, flen,
			   (unsigned short)0x86dd) == 0);
	/* one counter, not seventeen: the poll is a netlink dump each time and
	 * the first arm of F56 spent 2.8 minutes per arm on that alone */
	for (polls = 0; polls < 20; polls++) {
		usleep(60000);
		f578_snap(&r);
		if (F578_U6TOT > 0)
			break;
		if (na > 0) {
			if (f555_count(D[A->a[0].door].fam,
				       D[A->a[0].door].table, "ch") > s0[0])
				break;
		} else {
			int hit = 0;

			for (i = 0; i < nd; i++)
				if (i == 0 || i == nd - 1)
					hit |= f555_count(D[i].fam, D[i].table,
							  "pre0") > c0[i];
			if (hit)
				break;
		}
	}
	f578_snap(&r);
	usleep(150000);
	f578_snap(&r);
	for (i = 0; i < nd; i++)
		c1[i] = f555_count(D[i].fam, D[i].table, "pre0");
	for (j = 0; j < na; j++)
		s1[j] = f555_count(D[A->a[j].door].fam,
				   D[A->a[j].door].table, "ch");
	f575_nfl_drain(&pl);
	for (i = 0; i < F578_NTAP; i++)
		if (F578_TAP[i].fd >= 0)
			f578_tap_drain(i);

	printf("F578 A|arm=%s|mode=%d|fk=%s|feat=%d|sdev=%d|nsend=1|snt=%d|"
	       "polls=%d|st=%d|na=%d|"
	       "a0=%s|op0=%d|set0=%u|cmp0=%u|r0a=%d:%d:%s|r0b=%d:%d:%s|"
	       "rc0=%d|a1=%s|op1=%d|set1=%u|cmp1=%u|r1a=%d:%d:%s|"
	       "r1b=%d:%d:%s|rc1=%d\n",
	       A->name, A->mode, fkn, A->feat, A->sdev, snd, polls, F578_ST,
	       na,
	       na > 0 ? D[A->a[0].door].tag : "-",
	       na > 0 ? (A->a[0].set ? 1 : (A->a[0].nrd ? 2 :
					    (A->a[0].cmpm ? 3 : 0))) : -1,
	       na > 0 && A->a[0].set ? A->a[0].setval : 0,
	       na > 0 && A->a[0].cmpm ? A->a[0].cmpval : 0,
	       na > 0 && (A->a[0].nrd > 0 || A->a[0].set) ? A->a[0].rdoff[0] : -1,
	       na > 0 && (A->a[0].nrd > 0 || A->a[0].set) ? A->a[0].rdlen[0] : 0,
	       na > 0 && A->a[0].nrd > 0 ?
		       f559_hexs(hx, sizeof(hx), A->a[0].rdimm[0],
				 A->a[0].rdlen[0]) : "-",
	       na > 0 && A->a[0].nrd > 1 ? A->a[0].rdoff[1] : -1,
	       na > 0 && A->a[0].nrd > 1 ? A->a[0].rdlen[1] : 0,
	       na > 0 && A->a[0].nrd > 1 ?
		       f559_hexs(hx2, sizeof(hx2), A->a[0].rdimm[1],
				 A->a[0].rdlen[1]) : "-",
	       na > 0 ? rcs[0] : -99,
	       na > 1 ? D[A->a[1].door].tag : "-",
	       na > 1 ? (A->a[1].set ? 1 : (A->a[1].nrd ? 2 :
					    (A->a[1].cmpm ? 3 : 0))) : -1,
	       na > 1 && A->a[1].set ? A->a[1].setval : 0,
	       na > 1 && A->a[1].cmpm ? A->a[1].cmpval : 0,
	       na > 1 && (A->a[1].nrd > 0 || A->a[1].set) ? A->a[1].rdoff[0] : -1,
	       na > 1 && (A->a[1].nrd > 0 || A->a[1].set) ? A->a[1].rdlen[0] : 0,
	       na > 1 && A->a[1].nrd > 0 ?
		       f559_hexs(hx, sizeof(hx), A->a[1].rdimm[0],
				 A->a[1].rdlen[0]) : "-",
	       na > 1 && A->a[1].nrd > 1 ? A->a[1].rdoff[1] : -1,
	       na > 1 && A->a[1].nrd > 1 ? A->a[1].rdlen[1] : 0,
	       na > 1 && A->a[1].nrd > 1 ?
		       f559_hexs(hx2, sizeof(hx2), A->a[1].rdimm[1],
				 A->a[1].rdlen[1]) : "-",
	       na > 1 ? rcs[1] : -99);
	{
		char cb[640];
		int o = 0;

		cb[0] = 0;
		for (i = 0; i < nd; i++) {
			int w = snprintf(cb + o, sizeof(cb) - (size_t)o,
					 "|%s=%llu", D[i].tag, c1[i] - c0[i]);

			if (w < 0 || w >= (int)sizeof(cb) - o)
				break;
			o += w;
		}
		snprintf(cb + o, sizeof(cb) - (size_t)o, "|ch0=%lld|ch1=%lld",
			 na > 0 ? (long long)(s1[0] - s0[0]) : -1LL,
			 na > 1 ? (long long)(s1[1] - s0[1]) : -1LL);
		printf("F578 C|arm=%s%s\n", A->name, cb);
	}
	printf("F578 B|arm=%s|i6in_d=%llu|deliv_d=%llu|disc_d=%llu|"
	       "hdr_d=%llu|nor_d=%llu|addr_d=%llu|unk_d=%llu|fwd_d=%llu|"
	       "u6in_d=%llu|u6err_d=%llu|u6nop_d=%llu|u6n=%llu|u6len=%d|"
	       "u6sport=%d\n",
	       A->name, r.i6in - r0.i6in, r.i6deliv - r0.i6deliv,
	       r.i6disc - r0.i6disc, r.i6hdr - r0.i6hdr,
	       r.i6nor - r0.i6nor, r.i6addr - r0.i6addr,
	       r.i6unk - r0.i6unk, r.i6fwd - r0.i6fwd,
	       r.u6in - r0.u6in, r.u6err - r0.u6err, r.u6nop - r0.u6nop,
	       F578_U6TOT, F578_U6LEN, F578_U6SPORT);
	{
		char fb[1200];
		int o = 0;

		fb[0] = 0;
		for (i = 0; i < F578_NDEV; i++) {
			int w = snprintf(fb + o, sizeof(fb) - (size_t)o,
					 "|%s=%llu:%llu:%llu", F578_DEV[i],
					 r.rxp[i] - r0.rxp[i],
					 r.rxb[i] - r0.rxb[i],
					 r.oth[i] - r0.oth[i]);

			if (w < 0 || w >= (int)sizeof(fb) - o)
				break;
			o += w;
		}
		printf("F578 F|arm=%s%s\n", A->name, fb);
	}
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
		printf("F578 M|arm=%s|n=%d%s\n", A->name, pl.n, mb);
	}
	{
		char tb[600];
		int o = 0;

		tb[0] = 0;
		for (i = 0; i < F578_NTAP; i++) {
			char hb[400];
			int w = snprintf(tb + o, sizeof(tb) - (size_t)o,
					 "|t%d=%d:%d:%d:%s:aux=%d:%d:%04x:%d:"
					 "skip=%d:pkt=%d:proto=%04x:alen=%d:"
					 "amac=%d:anet=%d:atplen=%d:asnap=%d:"
					 "sz=%d", i, F578_TAP[i].n,
					 F578_TAP[i].flen, F578_TAP[i].len,
					 F578_TAP[i].len > 0 ?
					 f559_hexs(hb, sizeof(hb),
						   F578_TAP[i].b,
						   F578_TAP[i].len > 24 ?
						   24 : F578_TAP[i].len) : "-",
					 F578_TAP[i].auxn, F578_TAP[i].atci,
					 F578_TAP[i].atpid,
					 F578_TAP[i].astat,
					 F578_TAP[i].skip, F578_TAP[i].apkt,
					 F578_TAP[i].aproto,
					 F578_TAP[i].alen_bytes, F578_TAP[i].amac,
					 F578_TAP[i].anet, F578_TAP[i].alen,
					 F578_TAP[i].asnap,
					 (int)sizeof(struct tpacket_auxdata));

			if (w < 0 || w >= (int)sizeof(tb) - o)
				break;
			o += w;
		}
		printf("F578 T|arm=%s%s\n", A->name, tb);
	}
}

/* ---------- the arms ---------------------------------------------------- */

static const struct f578_arm F578_ARMS[] = {
	/* ---- mode `ad`: the tag, in bytes or in a word ------------------- */
	{ "ctl2", 0, 0, 0, 0, { { .door = -1 }, { .door = -1 } } },
	{ "rd_e2", 0, 0, 0, 0,
	  { F578_ACT_RD(A_E2, 12, 2, 0x88a8), { .door = -1 } } },
	{ "rd_p1", 0, 0, 0, 0,
	  { F578_ACT_RD2(A_P1, 12, 2, 0x88a8, 14, 2, 0x0066),
	    { .door = -1 } } },
	{ "w14_e2", 0, 0, 0, 0,
	  { { .door = A_E2, .set = 1, .setval = 0x2066,
	      .rdoff = { 14, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "ctl2s", 0, 0, 0, 1, { { .door = -1 }, { .door = -1 } } },
	{ "w14_e2s", 0, 0, 0, 1,
	  { { .door = A_E2, .set = 1, .setval = 0x2066,
	      .rdoff = { 14, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "ctl3", 0, 1, 0, 0, { { .door = -1 }, { .door = -1 } } },
	{ "w14_e3", 0, 1, 0, 0,
	  { { .door = A_E3, .set = 1, .setval = 0x6067,
	      .rdoff = { 14, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "ctl3c", 0, 1, 0, 2, { { .door = -1 }, { .door = -1 } } },
	{ "w14_e3c", 0, 1, 0, 2,
	  { { .door = A_E3, .set = 1, .setval = 0x6067,
	      .rdoff = { 14, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "ctl4", 0, 2, 0, 0, { { .door = -1 }, { .door = -1 } } },
	{ "w14_e4", 0, 2, 0, 0,
	  { { .door = A_E4, .set = 1, .setval = 0x2066,
	      .rdoff = { 14, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "w12_e4", 0, 2, 0, 0,
	  { { .door = A_E4, .set = 1, .setval = 0x0806,
	      .rdoff = { 12, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "w_tci_p1", 0, 0, 0, 0,
	  { { .door = A_P1, .set = 1, .setval = 0x0067,
	      .rdoff = { 14, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "w_proto_p1", 0, 0, 0, 0,
	  { { .door = A_P1, .set = 1, .setval = 0x0806,
	      .rdoff = { 12, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "rd_r0", 0, 0, 0, 0,
	  { F578_ACT_RD2(A_R0, 12, 2, 0x88a8, 14, 2, 0x0066),
	    { .door = -1 } } },
	/* ---- mode `br`: the tag on the bridged path --------------------- */
	{ "ctl_x", 1, 3, 0, 0, { { .door = -1 }, { .door = -1 } } },
	{ "rd_bv", 1, 3, 0, 0,
	  { F578_ACT_RD(B_BV, 12, 2, 0x86dd), { .door = -1 } } },
	{ "rd_bvt", 1, 3, 0, 0,
	  { F578_ACT_RD(B_BV, 12, 2, 0x8100), { .door = -1 } } },
	{ "rd_n1", 1, 3, 0, 0,
	  { F578_ACT_RD(B_N1, 12, 2, 0x86dd), { .door = -1 } } },
	{ "rd_bv_z", 1, 4, 1, 0,
	  { F578_ACT_RD(B_BV, 12, 2, 0x86dd), { .door = -1 } } },
	{ "rd_nz", 1, 4, 1, 0,
	  { F578_ACT_RD(B_NZ, 12, 2, 0x86dd), { .door = -1 } } },
	{ "rd_q1", 1, 3, 0, 0,
	  { F578_ACT_PRIO_RD(B_Q1, 0, 12, 2, 0x86dd), { .door = -1 } } },
	{ "rd_e2", 1, 3, 0, 0,
	  { F578_ACT_RD2(B_E2, 12, 2, 0x86dd, 18, 2, 0x001a),
	    { .door = -1 } } },
	{ "rd_bl", 1, 3, 0, 0,
	  { F578_ACT_RD(B_BL, 12, 2, 0x86dd), { .door = -1 } } },
	{ "rd_ry", 1, 3, 0, 0,
	  { F578_ACT_RD2(B_RY, 12, 2, 0x8100, 14, 2, 0x0066),
	    { .door = -1 } } },
	{ "w12_bv", 1, 3, 0, 0,
	  { { .door = B_BV, .set = 1, .setval = 0x0806,
	      .rdoff = { 12, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "w12_e2", 1, 3, 0, 0,
	  { { .door = B_E2, .set = 1, .setval = 0x0806,
	      .rdoff = { 12, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "w14_e2", 1, 3, 0, 0,
	  { { .door = B_E2, .set = 1, .setval = 0x0067,
	      .rdoff = { 14, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
	{ "w16_ry", 1, 3, 0, 0,
	  { { .door = B_RY, .set = 1, .setval = 0x0806,
	      .rdoff = { 16, 0 }, .rdlen = { 2, 0 } }, { .door = -1 } } },
};

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "ad";
	int i, n = (int)(sizeof(F578_ARMS) / sizeof(F578_ARMS[0]));
	int want = -1;

	if (!strcmp(mode, "ad"))
		want = 0;
	else if (!strcmp(mode, "br"))
		want = 1;
	else {
		printf("F578 USAGE|mode=%s\n", mode);
		return 2;
	}
	F578_MODE = want;
	f578_clean();
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	printf("F578 START|mode=%s|arms=%d\n", mode, n);
	F578_NFL = nfl_open(5);
	F573_NFL = F578_NFL;
	F571_NFL = F578_NFL;
	F578_U6 = f564_udp_bind(AF_INET6, 0, A78_ANY, F578_DPORT);
	printf("F578 SOCK|u6=%d|nfl=%d\n", F578_U6, F578_NFL);
	if (want == 0) {
		if (f578_env_ad())
			return 3;
	} else {
		if (f578_env_br())
			return 3;
	}
	if (f578_chains_mode(want))
		return 4;
	for (i = 0; i < n; i++) {
		if (F578_ARMS[i].mode != want)
			continue;
		f578_arm(&F578_ARMS[i]);
	}
	f578_flush_all();
	printf("F578 DONE|mode=%s\n", mode);
	return 0;
}
