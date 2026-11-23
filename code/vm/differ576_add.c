/* differ576_add.c -- turn 576 (F54).
 *
 *  THE TWO DEBTS, named at the end of 575:
 *
 *   1. A store into the 802.1Q tag that has a WIRE.  F52 measured the tag as
 *      skb metadata at a bridge door (the store changes no byte of the frame
 *      and decides everything); F53 measured it as frame bytes on a layer-3
 *      door behind a VLAN device with VLAN_FLAG_REORDER_HDR cleared (the store
 *      changes a byte and decides nothing).  Neither had a frame that leaves.
 *
 *      Here the frame is ROUTED.  It arrives tagged 8100/101 on x1, the VLAN
 *      device x1.101 (REORDER_HDR cleared) carries it, IPv6 forwarding sends
 *      it to fd02::92 out of that same VLAN device, and vlan_dev_hard_header()
 *      + vlan_dev_hard_start_xmit() decide what the real device transmits.
 *
 *      The witness of the wire is the FAR END's own VLAN demux: x0 carries
 *      x0.101 and x0.102, and their rx_packets say which vid actually left the
 *      box.  That fact does not depend on how veth represents the tag (bytes
 *      or metadata), on a hexdump, or on my reading of one.
 *
 *      Doors, in the order the frame meets them:
 *        n1  netdev ingress x1        (the tag is metadata here: F53)
 *        g6  ip6 prerouting           (the frame is out of x1.101's L3)
 *        f6  ip6 forward
 *        e0  netdev egress x1.101     (after vlan_dev_hard_header, before
 *                                      vlan_dev_hard_start_xmit)
 *        e1  netdev egress x1         (the last door before the wire)
 *        r0  netdev ingress x0        (the far end, in the same netns)
 *
 *   2. A minimal reproduction of the WARN `invalid VLAN protocol: 0x%04x`
 *      that F53 met by accident.  The first smoke of this turn showed that
 *      the store alone is not enough: vlan_find_dev() only reaches
 *      vlan_proto_idx() when the receiving device HAS a vlan_info, so a bare
 *      veth pair cannot warn.  Mode `warn` therefore carries exactly one VLAN
 *      device and one rule.
 */

#include <sys/syscall.h>

#define F576_SPORT	43000
#define F576_DPORT	5000

static const unsigned char A76_SRC[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x11 };
/* the frame's destination: NOT a local address, on-link behind x1.101 */
static const unsigned char A76_DST[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x92 };
/* x1.101's own address */
static const unsigned char A76_LOC[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x93 };
static const unsigned char A76_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define F576_B_LL	0

/* hook numbers as this kernel numbers them: NF_INET_PRE_ROUTING = 0,
 * NF_INET_FORWARD = 2, NF_NETDEV_INGRESS = 0, NF_NETDEV_EGRESS = 1. */
#define F576_PREROUTING_	0
#define F576_FORWARD_		2
#define F576_ND_INGRESS_	0
#define F576_ND_EGRESS_		1

static struct f571_door D576[] = {
	{ "g6", NFPROTO_IPV6,   "e76a", NULL,     F576_PREROUTING_, 210, 220 },
	{ "f6", NFPROTO_IPV6,   "e76b", NULL,     F576_FORWARD_,    230, 240 },
	{ "n1", NFPROTO_NETDEV, "e76c", "x1",     F576_ND_INGRESS_, 290, 300 },
	{ "e0", NFPROTO_NETDEV, "e76d", "x1.102", F576_ND_EGRESS_,  310, 320 },
	{ "e1", NFPROTO_NETDEV, "e76e", "x1",     F576_ND_EGRESS_,  330, 340 },
	{ "r0", NFPROTO_NETDEV, "e76f", "x0",     F576_ND_INGRESS_, 350, 360 },
};
enum { E76_G6 = 0, E76_F6, E76_N1, E76_E0, E76_E1, E76_R0 };
#define ND76 6

static unsigned char F576_X0M[6], F576_X1M[6];
static int F576_NFL = -1;
static unsigned char F576_FT[192], F576_FP[192];	/* tagged, plain */
static int F576_LT = -1, F576_LP = -1;
static int F576_ST = -9;
static unsigned int F576_DOORMASK = 0x3f;

/* ---------- taps: the far end of the port, and the port itself ---------- */

#define F576_TAPN	2
struct f576_tap {
	int fd;
	int n;
	int flen;
	int len;
	unsigned char b[160];
};
static struct f576_tap F576_TAP[F576_TAPN];
static const char *F576_TAPDEV[F576_TAPN] = { "x0", "x1" };
#define T576_X0	(1 << 0)
#define T576_X1	(1 << 1)

static void f576_tap_open_mask(int mask)
{
	int i;

	for (i = 0; i < F576_TAPN; i++) {
		if (F576_TAP[i].fd >= 0)
			close(F576_TAP[i].fd);
		F576_TAP[i].fd = -1;
		F576_TAP[i].n = 0;
		F576_TAP[i].len = -1;
		F576_TAP[i].flen = -1;
	}
	for (i = 0; i < F576_TAPN; i++) {
		if (!(mask & (1 << i)))
			continue;
		F576_TAP[i].fd = f571_tap_open(F576_TAPDEV[i]);
	}
}

static void f576_tap_drain(int i)
{
	unsigned char b[2048];
	int r;

	F576_TAP[i].n = 0;
	F576_TAP[i].len = -1;
	F576_TAP[i].flen = -1;
	if (F576_TAP[i].fd < 0)
		return;
	for (;;) {
		struct sockaddr_ll from;
		socklen_t fl = sizeof(from);
		int k;

		memset(&from, 0, sizeof(from));
		r = (int)recvfrom(F576_TAP[i].fd, b, sizeof(b), MSG_DONTWAIT,
				  (struct sockaddr *)&from, &fl);
		if (r <= 0)
			break;
		/* the tap sees what this box transmits as well (packet_snd ->
		 * dev_queue_xmit_nit); the wire witness is what arrives */
		if (from.sll_pkttype == 4 /* PACKET_OUTGOING */)
			continue;
		if (!f568_needle(b, r))
			continue;
		F576_TAP[i].n++;
		if (F576_TAP[i].len < 0) {
			F576_TAP[i].flen = r;
			k = r < (int)sizeof(F576_TAP[i].b) ?
			    r : (int)sizeof(F576_TAP[i].b);
			memcpy(F576_TAP[i].b, b, (size_t)k);
			F576_TAP[i].len = k;
		}
	}
}

/* ---------- frames ---------- */

static int f576_frame_tag(unsigned char *out, const unsigned char *dmac,
			  const unsigned char *smac, unsigned short tpid,
			  unsigned short tci)
{
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = (unsigned char)(tpid >> 8);
	out[13] = (unsigned char)(tpid & 0xff);
	out[14] = (unsigned char)(tci >> 8);
	out[15] = (unsigned char)(tci & 0xff);
	out[16] = 0x86;
	out[17] = 0xdd;
	return 18 + f570_ip6(out + 18, A76_SRC, A76_DST, 0, F576_SPORT,
			     F576_DPORT);
}

static int f576_frame_plain(unsigned char *out, const unsigned char *dmac,
			    const unsigned char *smac)
{
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	return 14 + f570_ip6(out + 14, A76_SRC, A76_DST, 0, F576_SPORT,
			     F576_DPORT);
}

/* ---------- snapshot: the far end's demux is the wire witness ---------- */

struct f576_rep {
	unsigned long long i6in, i6deliv, i6disc, i6hdr, i6nor, i6addr,
		i6unk, i6trunc, i6mcast, i6fwd;
	unsigned long long u6in, u6err, u6nop;
	unsigned long long x0rxp, x0oth, x0rxb;
	unsigned long long x1rxp, x1oth;
	unsigned long long v101p, v101b, v101d;
	unsigned long long v102p, v102b, v102d;
	unsigned long long v111p, v111b;
};

static void f576_snap(struct f576_rep *R)
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
	R->v101p = s.rxp;
	R->v101b = s.rxb;
	R->v101d = s.rxd;
	f573_stats("x0.102", &s);
	R->v102p = s.rxp;
	R->v102b = s.rxb;
	R->v102d = s.rxd;
	f573_stats("x1.101", &s);
	R->v111p = s.rxp;
	R->v111b = s.rxb;
}

/* ---------- kmsg: how many splats did the kernel print ---------- */

#define F576_KMSG_MAX 262144
static char F576_KMSG[F576_KMSG_MAX];

/* returns the number of lines containing `needle` in the whole ring buffer;
 * up to `keep` of them are copied into out, separated by '|' */
static int f576_kmsg(const char *needle, char *out, int maxout, int keep)
{
	long r;
	int n = 0, o = 0, kept = 0, i = 0;

	if (out && maxout > 0)
		out[0] = 0;
	r = syscall(SYS_syslog, 3 /* SYSLOG_ACTION_READ_ALL */, F576_KMSG,
		    F576_KMSG_MAX - 1);
	if (r <= 0)
		return -1;
	F576_KMSG[r] = 0;
	while (i < (int)r) {
		int j = i, k;

		while (j < (int)r && F576_KMSG[j] != '\n')
			j++;
		F576_KMSG[j] = 0;
		if (strstr(F576_KMSG + i, needle)) {
			n++;
			if (out && kept < keep) {
				k = (int)strlen(F576_KMSG + i);
				if (k > 150)
					k = 150;
				if (o + k + 2 < maxout) {
					if (o)
						out[o++] = '|';
					memcpy(out + o, F576_KMSG + i,
					       (size_t)k);
					o += k;
					out[o] = 0;
				}
				kept++;
			}
		}
		i = j + 1;
	}
	return n;
}


/* ---------- topology of mode `xf` ---------- */

static int f576_env(void)
{
	int r1, r2, r3;
	char path[160];
	/* the on-link /64 lives on the EGRESS device, so the forwarded
	 * frame leaves through a device other than the one it arrived on
	 * (ip6_forward() sends an ICMPv6 redirect when they are equal). */
	const char *v6dev = "x1.102";

	f558_link_del("br0");
	f558_link_del("x0");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
	if (link_add_veth("x0", "x1")) {
		printf("F576 FAIL|veth\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	if (mac_get("x0", F576_X0M) || mac_get("x1", F576_X1M)) {
		printf("F576 FAIL|mac\n");
		return -1;
	}
	r1 = f575_link_add_vlan("x1.101", "x1", 101, 0, 1);
	r2 = f575_link_add_vlan("x1.102", "x1", 102, 0, 1);
	r3 = f575_link_add_vlan("x0.101", "x0", 101, 0, 0);
	printf("F576 VNEW|x1_101=%d|x1_102=%d|x0_101=%d\n", r1, r2, r3);
	if (r1 | r2 | r3)
		return -6;
	printf("F576 VNEW2|x0_102=%d\n",
	       f575_link_add_vlan("x0.102", "x0", 102, 0, 0));
	f575_vlan_readback("x1.101");
	f575_vlan_readback("x1.102");
	set_up("x1.101");
	set_up("x1.102");
	set_up("x0.101");
	set_up("x0.102");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6",
		 v6dev);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/x1.101/disable_ipv6");
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/x1.101/forwarding");
	f555_sysctl(path, "1");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/x1.101/accept_dad");
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path),
		 "/proc/sys/net/ipv6/conf/x1.101/router_solicitations");
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/x1.101/accept_ra");
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/x1.101/autoconf");
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/accept_dad",
		 v6dev);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path),
		 "/proc/sys/net/ipv6/conf/%s/dad_transmits", v6dev);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/accept_ra",
		 v6dev);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/autoconf",
		 v6dev);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path),
		 "/proc/sys/net/ipv6/conf/%s/router_solicitations", v6dev);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/forwarding",
		 v6dev);
	f555_sysctl(path, "1");
	snprintf(path, sizeof(path),
		 "/proc/sys/net/ipv6/conf/%s/drop_unicast_in_l2_multicast",
		 v6dev);
	f555_sysctl(path, "0");
	/* forwarding in and out of the same device normally sends an
	 * ICMPv6 redirect; that redirect needs the SOURCE resolved, so it
	 * emits a neighbour solicitation -- a second frame through every
	 * door below.  Measured in the first smoke (e0=2, r0=2 per packet). */
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/send_redirects",
		 v6dev);
	f555_sysctl(path, "0");
	printf("F576 ADDR6|rc=%d|dev=%s\n", f564_addr6(v6dev, A76_LOC, 64),
	       v6dev);
	printf("F576 INADDR|v6=%d|addr=%d\n",
	       f573_sysint("/proc/sys/net/ipv6/conf/x1.101/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x1.101/forwarding"));
	printf("F576 NEIGH|rc=%d\n",
	       f569_neigh6_add("x1.102", A76_DST, F576_X0M));
	F576_NFL = nfl_open(5);
	F573_NFL = F576_NFL;
	F571_NFL = F576_NFL;
	F576_LT = f576_frame_tag(F576_FT, F576_X1M, F576_X0M, 0x8100, 0x0065);
	F576_LP = f576_frame_plain(F576_FP, A76_BC, F576_X0M);
	{
		char ht[512], hp[512], hx[32], hb[32];

		printf("F576 ENV|nfl=%d|lt=%d|lp=%d|x0=%d|x1=%d|d101=%d|"
		       "d101x=%d|d102x=%d|d102=%d|x0mac=%s|x1mac=%s\n",
		       F576_NFL, F576_LT, F576_LP, f555_ifindex("x0"),
		       f555_ifindex("x1"), f555_ifindex("x1.101"),
		       f555_ifindex("x0.101"), f555_ifindex("x0.102"),
		       f555_ifindex("x1.102"),
		       f559_hexs(hx, sizeof(hx), F576_X0M, 6),
		       f559_hexs(hb, sizeof(hb), F576_X1M, 6));
		printf("F576 FRM|t=%s\n",
		       f559_hexs(ht, sizeof(ht), F576_FT, F576_LT));
		printf("F576 FRM|p=%s\n",
		       f559_hexs(hp, sizeof(hp), F576_FP, F576_LP));
	}
	usleep(4000000);
	F576_ST = f573_settle();
	printf("F576 SETTLE|st=%d|v6=%d|fwd=%d|allfwd=%d|d101v6=%d|d102v6=%d|"
	       "x1v6=%d\n", F576_ST,
	       f573_sysint("/proc/sys/net/ipv6/conf/x1.101/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x1.101/forwarding"),
	       f573_sysint("/proc/sys/net/ipv6/conf/all/forwarding"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x0.101/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x0.102/disable_ipv6"),
	       f573_sysint("/proc/sys/net/ipv6/conf/x1/disable_ipv6"));
	return 0;
}

static int f576_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND76; i++) {
		struct f571_door *D = &D576[i];
		int a, b, c;

		if (!(F576_DOORMASK & (1u << i)))
			continue;
		a = add_table(D->fam, D->table);
		b = f556_add_chain(D->fam, D->table, "pre0", D->hook,
				   (uint32_t)D->prio0, 1, D->dev);
		c = f556_add_chain(D->fam, D->table, "ch", D->hook,
				   (uint32_t)D->prio1, 1, D->dev);
		printf("F576 CH|door=%s|fam=%d|hook=%u|dev=%s|table=%d|"
		       "pre0=%d|ch=%d\n", D->tag, (int)D->fam, D->hook,
		       D->dev ? D->dev : "-", a, b, c);
		rc |= a | b | c;
	}
	return rc;
}

static void f576_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND76; i++) {
		if (!(F576_DOORMASK & (1u << i)))
			continue;
		f557_flush(D576[i].fam, D576[i].table, "pre0", &acks);
		f557_flush(D576[i].fam, D576[i].table, "ch", &acks);
	}
}

/* ---------- one arm of mode `xf` ---------- */

struct f576_act {
	int door;
	const struct f571_cfg *C;
};

static void f576_arm(const char *arm, int fk, int nsend, int tapmask,
		     const struct f576_act *A, int na)
{
	struct f571_cfg N;
	struct f576_rep r0, r;
	struct f575_pl pl;
	const unsigned char *fr = NULL;
	int flen = 0, proto = 0x86dd;
	unsigned long long c0[ND76], c1[ND76], s0[2], s1[2];
	int i, j, acks = 0, snd = 0, polls = 0, k, rcs[2] = { -99, -99 };
	char hx[64];
	const char *fkn = "T";

	memset(&r0, 0, sizeof(r0));
	memset(&r, 0, sizeof(r));
	memset(s0, 0, sizeof(s0));
	memset(s1, 0, sizeof(s1));
	f571_zero(&N, "p");
	if (fk == 0) {
		fr = F576_FT;
		flen = F576_LT;
		fkn = "T";
	} else if (fk == 1) {
		fr = F576_FP;
		flen = F576_LP;
		fkn = "P";
	}
	f576_flush_all();
	f575_nfl_drain(NULL);
	F576_ST = f573_settle();
	f576_tap_open_mask(tapmask);
	for (i = 0; i < F576_TAPN; i++)
		if (F576_TAP[i].fd >= 0)
			f576_tap_drain(i);
	for (i = 0; i < ND76; i++) {
		char nm[8];

		if (!(F576_DOORMASK & (1u << i)))
			continue;
		snprintf(nm, sizeof(nm), "p%d", i);
		if (f571_rule(&D576[i], "pre0", nm, &N, &acks))
			printf("F576 RUFAIL|arm=%s|door=%s|chain=pre0\n", arm,
			       D576[i].tag);
	}
	for (j = 0; j < na && j < 2; j++)
		rcs[j] = f571_rule(&D576[A[j].door], "ch", "s", A[j].C, &acks);
	for (i = 0; i < ND76; i++)
		c0[i] = (F576_DOORMASK & (1u << i)) ?
			f555_count(D576[i].fam, D576[i].table, "pre0") : 0;
	for (j = 0; j < na && j < 2; j++)
		s0[j] = f555_count(D576[A[j].door].fam, D576[A[j].door].table,
				   "ch");
	f576_snap(&r0);
	if (fk >= 0 && nsend > 0) {
		for (k = 0; k < nsend; k++) {
			snd += (pkt_send_p("x0", fr, flen,
					   (unsigned short)proto) == 0);
			if (k + 1 < nsend)
				usleep(120000);
		}
		for (k = 0; k < 14; k++) {
			int any = 0;

			usleep(110000);
			f576_snap(&r);
			polls++;
			for (i = 0; i < ND76; i++)
				if ((F576_DOORMASK & (1u << i)) &&
				    f555_count(D576[i].fam, D576[i].table,
					       "pre0") > c0[i])
					any = 1;
			for (j = 0; j < na && j < 2; j++)
				if (f555_count(D576[A[j].door].fam,
					       D576[A[j].door].table, "ch") >
				    s0[j])
					any = 1;
			if (r.v101p > r0.v101p || r.i6in > r0.i6in ||
			    r.i6fwd > r0.i6fwd || r.x1oth > r0.x1oth)
				break;
			if (any && polls >= 3)
				break;
		}
	} else {
		usleep(300000);
		polls = 1;
	}
	f576_snap(&r);
	usleep(200000);
	f576_snap(&r);
	for (i = 0; i < ND76; i++)
		c1[i] = (F576_DOORMASK & (1u << i)) ?
			f555_count(D576[i].fam, D576[i].table, "pre0") : 0;
	for (j = 0; j < na && j < 2; j++)
		s1[j] = f555_count(D576[A[j].door].fam, D576[A[j].door].table,
				   "ch");
	f575_nfl_drain(&pl);
	for (i = 0; i < F576_TAPN; i++)
		if (F576_TAP[i].fd >= 0)
			f576_tap_drain(i);

	printf("F576 A|arm=%s|fk=%s|nsend=%d|snt=%d|polls=%d|tab=%d|st=%d|"
	       "na=%d|d0=%s|off0=%d|len0=%d|imm0=%s|rc0=%d|d1=%s|rc1=%d|"
	       "u6n=%llu|nfl=%d\n",
	       arm, fkn, nsend, snd, polls, tapmask, F576_ST, na,
	       na > 0 ? D576[A[0].door].tag : "-",
	       na > 0 ? A[0].C->off : -1, na > 0 ? A[0].C->len : -1,
	       na > 0 ? f559_hexs(hx, sizeof(hx), A[0].C->imm,
				  A[0].C->len) : "-",
	       na > 0 ? rcs[0] : -99,
	       na > 1 ? D576[A[1].door].tag : "-", na > 1 ? rcs[1] : -99,
	       r.u6in - r0.u6in, pl.n);
	printf("F576 C|g6=%llu|f6=%llu|n1=%llu|e0=%llu|e1=%llu|r0=%llu|"
	       "ch0=%lld|ch1=%lld\n",
	       c1[E76_G6] - c0[E76_G6], c1[E76_F6] - c0[E76_F6],
	       c1[E76_N1] - c0[E76_N1], c1[E76_E0] - c0[E76_E0],
	       c1[E76_E1] - c0[E76_E1], c1[E76_R0] - c0[E76_R0],
	       na > 0 ? (long long)(s1[0] - s0[0]) : -1LL,
	       na > 1 ? (long long)(s1[1] - s0[1]) : -1LL);
	printf("F576 B|i6in_d=%llu|deliv_d=%llu|disc_d=%llu|hdr_d=%llu|"
	       "nor_d=%llu|addr_d=%llu|unk_d=%llu|trunc_d=%llu|mcast_d=%llu|"
	       "fwd_d=%llu|u6in_d=%llu|u6err_d=%llu|u6nop_d=%llu\n",
	       r.i6in - r0.i6in, r.i6deliv - r0.i6deliv, r.i6disc - r0.i6disc,
	       r.i6hdr - r0.i6hdr, r.i6nor - r0.i6nor, r.i6addr - r0.i6addr,
	       r.i6unk - r0.i6unk, r.i6trunc - r0.i6trunc,
	       r.i6mcast - r0.i6mcast, r.i6fwd - r0.i6fwd,
	       r.u6in - r0.u6in, r.u6err - r0.u6err, r.u6nop - r0.u6nop);
	/* the wire witness: the far end's own VLAN demux */
	printf("F576 F|v101p_d=%llu|v101b_d=%llu|v101d_d=%llu|v102p_d=%llu|"
	       "v102b_d=%llu|v102d_d=%llu|v111p_d=%llu|v111b_d=%llu|"
	       "x0rxp_d=%llu|x0rxb_d=%llu|x0oth_d=%llu|x1rxp_d=%llu|"
	       "x1oth_d=%llu\n",
	       r.v101p - r0.v101p, r.v101b - r0.v101b, r.v101d - r0.v101d,
	       r.v102p - r0.v102p, r.v102b - r0.v102b, r.v102d - r0.v102d,
	       r.v111p - r0.v111p, r.v111b - r0.v111b,
	       r.x0rxp - r0.x0rxp, r.x0rxb - r0.x0rxb, r.x0oth - r0.x0oth,
	       r.x1rxp - r0.x1rxp, r.x1oth - r0.x1oth);
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
		printf("F576 M|n=%d%s\n", pl.n, mb);
	}
	{
		char tb[1400];
		int o2 = 0;

		tb[0] = 0;
		for (i = 0; i < F576_TAPN; i++) {
			int w;

			if (F576_TAP[i].len > 0) {
				char hh[400];

				w = snprintf(tb + o2, sizeof(tb) - (size_t)o2,
					     "|t%d=%s:%d:%d:%s", i,
					     F576_TAPDEV[i], F576_TAP[i].n,
					     F576_TAP[i].flen,
					     f559_hexs(hh, sizeof(hh),
						       F576_TAP[i].b,
						       F576_TAP[i].len));
			} else {
				w = snprintf(tb + o2, sizeof(tb) - (size_t)o2,
					     "|t%d=%s:%d:%d:-", i,
					     F576_TAPDEV[i], F576_TAP[i].n,
					     F576_TAP[i].flen);
			}
			if (w < 0 || w >= (int)sizeof(tb) - o2)
				break;
			o2 += w;
		}
		printf("F576 T|%s\n", tb[0] ? tb + 1 : tb);
	}
}

/* ---------- config helpers ---------- */

static void f576_wr(struct f571_cfg *C, uint32_t base, int off, int len,
		    const unsigned char *imm)
{
	f571_wr(C, "s", base, off, len, imm, 0, 0);
}

static void f576_rd(struct f571_cfg *C, uint32_t base, int off, int len,
		    const unsigned char *imm)
{
	f571_zero(C, "s");
	C->mode = 3;
	C->base = base;
	C->off = off;
	C->len = len;
	memcpy(C->imm, imm, (size_t)len);
}

/* ---------- sections of mode `xf` ---------- */

static void f576_sec_xf(void)
{
	struct f576_act A[2];
	unsigned char tci67[2] = { 0x00, 0x67 };
	unsigned char tci66[2] = { 0x00, 0x66 };
	unsigned char tci65[2] = { 0x00, 0x65 };
	unsigned char pc1[2] = { 0x20, 0x65 };
	unsigned char tpid[2] = { 0x81, 0x00 };
	unsigned char zero4[4] = { 0, 0, 0, 0 };

	/* 0. nothing sent: the baseline of every counter in this mode */
	f576_arm("n0", -1, 0, 0, NULL, 0);
	/* 1. control: the tagged frame is routed and leaves the box */
	f576_arm("ctl", 0, 1, T576_X0, NULL, 0);
	/* 2. the tag as the ingress device carried it (vid 101) */
	{
		struct f571_cfg r2;

		f576_rd(&r2, F576_B_LL, 14, 2, tci65);
		A[0].door = E76_G6;
		A[0].C = &r2;
		f576_arm("rd_g6_65", 0, 1, T576_X0, A, 1);
	}
	/* 3. store vid 103 at prerouting, read it back at FORWARD */
	{
		struct f571_cfg w2, r2;

		f576_wr(&w2, F576_B_LL, 14, 2, tci67);
		f576_rd(&r2, F576_B_LL, 14, 2, tci67);
		A[0].door = E76_G6;
		A[0].C = &w2;
		A[1].door = E76_F6;
		A[1].C = &r2;
		f576_arm("w67_g6_rd_f6", 0, 1, T576_X0, A, 2);
	}
	/* 4. the same store at FORWARD, read at the egress door of the egress
	 *    VLAN device -- vlan_dev_hard_header() runs between these doors */
	{
		struct f571_cfg w2, r2;

		f576_wr(&w2, F576_B_LL, 14, 2, tci67);
		f576_rd(&r2, F576_B_LL, 14, 2, tci66);
		A[0].door = E76_F6;
		A[0].C = &w2;
		A[1].door = E76_E0;
		A[1].C = &r2;
		f576_arm("w67_f6_rd_e0_66", 0, 1, T576_X0, A, 2);
	}
	/* 5. the same store, read at the LAST door before the wire */
	{
		struct f571_cfg w2, r2;

		f576_wr(&w2, F576_B_LL, 14, 2, tci67);
		f576_rd(&r2, F576_B_LL, 14, 2, tci66);
		A[0].door = E76_F6;
		A[0].C = &w2;
		A[1].door = E76_E1;
		A[1].C = &r2;
		f576_arm("w67_f6_rd_e1_66", 0, 1, T576_X0, A, 2);
	}
	/* 6. the value the frame already carries at that point: value, not act */
	{
		struct f571_cfg w2, r2;

		f576_wr(&w2, F576_B_LL, 14, 2, tci66);
		f576_rd(&r2, F576_B_LL, 14, 2, tci66);
		A[0].door = E76_F6;
		A[0].C = &w2;
		A[1].door = E76_E0;
		A[1].C = &r2;
		f576_arm("same66_f6_rd_e0", 0, 1, T576_X0, A, 2);
	}
	/* 7. the priority bits: stored in the frame, read where the device
	 *    composes its own tag */
	{
		struct f571_cfg w2, r2;

		f576_wr(&w2, F576_B_LL, 14, 2, pc1);
		f576_rd(&r2, F576_B_LL, 14, 2, tci66);
		A[0].door = E76_F6;
		A[0].C = &w2;
		A[1].door = E76_E0;
		A[1].C = &r2;
		f576_arm("pc1_f6_rd_e0_66", 0, 1, T576_X0, A, 2);
	}
	/* 8. what the last door before the wire reads by itself */
	{
		struct f571_cfg r2;

		f576_rd(&r2, F576_B_LL, 12, 2, tpid);
		A[0].door = E76_E1;
		A[0].C = &r2;
		f576_arm("e1_rd_tpid", 0, 1, T576_X0, A, 1);
	}
	/* 9. the four bytes that deleted the tag in F52: here the tag is frame
	 *    bytes, so this deletes it from the frame */
	{
		struct f571_cfg w2;

		f576_wr(&w2, F576_B_LL, 12, 4, zero4);
		A[0].door = E76_G6;
		A[0].C = &w2;
		f576_arm("del12_g6", 0, 1, T576_X0, A, 1);
	}
	/* 10. store the metadata TCI at ingress: retarget to vid 103 */
	{
		struct f571_cfg w2;

		f576_wr(&w2, F576_B_LL, 14, 2, tci67);
		A[0].door = E76_N1;
		A[0].C = &w2;
		f576_arm("n67", 0, 1, T576_X0, A, 1);
	}
	/* 11. store the metadata PCP at ingress, same vid */
	{
		struct f571_cfg w2;

		f576_wr(&w2, F576_B_LL, 14, 2, pc1);
		A[0].door = E76_N1;
		A[0].C = &w2;
		f576_arm("n_pc1", 0, 1, T576_X0, A, 1);
	}
}

/* ---------- mode `warn`: one rule, one frame, one VLAN device ---------- */

static int f576_warn_env(void)
{
	f558_link_del("br0");
	f558_link_del("x0");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	if (link_add_veth("x0", "x1")) {
		printf("F576 WFAIL|veth\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	if (mac_get("x0", F576_X0M) || mac_get("x1", F576_X1M)) {
		printf("F576 WFAIL|mac\n");
		return -1;
	}
	/* the one device that makes vlan_find_dev() reach vlan_proto_idx() */
	printf("F576 WVNEW|rc=%d\n",
	       f575_link_add_vlan("x1.101", "x1", 101, 0, 0));
	set_up("x1.101");
	F576_NFL = nfl_open(5);
	F573_NFL = F576_NFL;
	F571_NFL = F576_NFL;
	F576_LT = f576_frame_tag(F576_FT, A76_BC, F576_X0M, 0x8100, 0x0065);
	F576_LP = f576_frame_plain(F576_FP, A76_BC, F576_X0M);
	{
		char ht[512], hx[32], hb[32];

		printf("F576 WENV|nfl=%d|lt=%d|lp=%d|x0=%d|x1=%d|d101=%d|"
		       "x0mac=%s|x1mac=%s\n", F576_NFL, F576_LT, F576_LP,
		       f555_ifindex("x0"), f555_ifindex("x1"),
		       f555_ifindex("x1.101"),
		       f559_hexs(hx, sizeof(hx), F576_X0M, 6),
		       f559_hexs(hb, sizeof(hb), F576_X1M, 6));
		printf("F576 FRM|t=%s\n",
		       f559_hexs(ht, sizeof(ht), F576_FT, F576_LT));
	}
	usleep(600000);
	F576_ST = f573_settle();
	return 0;
}

static void f576_warn_arm(const char *arm, const struct f571_cfg *C,
			  int fk, int nsend)
{
	struct f576_rep s0, s1;
	const unsigned char *fr;
	int flen, snd = 0, k, rcs = -99, acks = 0;
	int spl0, spl1;
	char msg[900];
	unsigned long long ch0 = 0, ch1 = 0;

	fr = fk == 0 ? F576_FT : F576_FP;
	flen = fk == 0 ? F576_LT : F576_LP;
	f576_flush_all();
	f575_nfl_drain(NULL);
	f576_tap_open_mask(T576_X0);
	f576_tap_drain(0);
	if (C)
		rcs = f571_rule(&D576[E76_N1], "ch", "s", C, &acks);
	ch0 = f555_count(D576[E76_N1].fam, D576[E76_N1].table, "ch");
	spl0 = f576_kmsg("invalid VLAN protocol", NULL, 0, 0);
	f576_snap(&s0);
	for (k = 0; k < nsend; k++) {
		snd += (pkt_send_p("x0", fr, flen, 0x8100) == 0);
		usleep(150000);
	}
	usleep(400000);
	spl1 = f576_kmsg("invalid VLAN protocol", msg, (int)sizeof(msg), 4);
	f576_snap(&s1);
	ch1 = f555_count(D576[E76_N1].fam, D576[E76_N1].table, "ch");
	f576_tap_drain(0);
	printf("F576 W|arm=%s|fk=%s|nsend=%d|snt=%d|rcs=%d|ch=%lld|"
	       "spl0=%d|spl1=%d|dspl=%d|st=%d|tapx0=%d|tapx0len=%d|"
	       "x1rxp_d=%llu|x1oth_d=%llu|v111p_d=%llu\n",
	       arm, fk == 0 ? "T" : "P", nsend, snd, rcs,
	       (long long)(ch1 - ch0), spl0, spl1,
	       (spl1 >= 0 && spl0 >= 0) ? spl1 - spl0 : -99, F576_ST,
	       F576_TAP[0].n, F576_TAP[0].flen,
	       s1.x1rxp - s0.x1rxp, s1.x1oth - s0.x1oth,
	       s1.v111p - s0.v111p);
	printf("F576 WM|arm=%s|%s\n", arm, msg);
}

static void f576_sec_warn(void)
{
	struct f571_cfg w;
	unsigned char bad[2] = { 0x08, 0x06 };
	unsigned char good[2] = { 0x81, 0x00 };

	/* 0. the same frame with no rule at all */
	f576_warn_arm("w_ctl", NULL, 0, 1);
	/* 1. one rule, one store, one frame */
	f576_wr(&w, F576_B_LL, 12, 2, bad);
	f576_warn_arm("w_tag", &w, 0, 1);
	/* 2. three frames: is the message per packet or once? */
	f576_warn_arm("w_tag_x3", &w, 0, 3);
	/* 3. the same rule on a frame that carries no tag */
	f576_warn_arm("w_untag", &w, 1, 1);
	/* 4. the value the frame already carries */
	f576_wr(&w, F576_B_LL, 12, 2, good);
	f576_warn_arm("w_same", &w, 0, 1);
}

/* ---------- entry ---------- */

static void f576_usage(const char *p)
{
	printf("F576 USAGE|%s <warn|xf>\n", p);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "";

	if (!strcmp(mode, "warn")) {
		F576_DOORMASK = 1u << E76_N1;
		if (f576_warn_env())
			return 2;
		if (f576_chains())
			return 3;
		f576_sec_warn();
		printf("F576 WARN_DONE\n");
		return 0;
	}
	if (!strcmp(mode, "xf")) {
		F576_DOORMASK = 0x3f;
		if (f576_env())
			return 2;
		if (f576_chains())
			return 3;
		f576_sec_xf();
		printf("F576 XF_DONE\n");
		return 0;
	}
	f576_usage(argv[0]);
	return 1;
}
