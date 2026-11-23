/* differ584_add.c -- turn 584 (F62): ON THE GSO PATH THE BILL IS PAID BY
 * WHOEVER SEGMENTS -- AND THE TWO DOORS SEGMENT IN DIFFERENT PLACES.
 *
 *  The debt named in F61 §11: clearing NETIF_F_HW_CSUM on the exit device also
 *  clears NETIF_F_GSO_UDP_L4 (bit 33, ac1 bit 1: 0x...612e -> 0x...612c).  So a
 *  UDP_SEGMENT datagram (one big GSO skb, gso_size = mss) that exits on y1 goes
 *  to the wire as ONE frame and is segmented by the RECEIVER
 *  (udp_unexpected_gso() -> udp_rcv_segment() -> __udp_gso_segment()), while the
 *  same datagram exiting on y2 is segmented by the EXIT DEVICE
 *  (validate_xmit_skb() -> skb_gso_segment() -> __udp_gso_segment()).
 *
 *  Topology is F61's, unchanged: three netns.
 *    parent = THE ROUTER.  x0 fd02::91/64, y1 fd03::91/64 (HW_CSUM kept),
 *             y2 fd04::91/64 (HW_CSUM cleared).  ip6 table f84p, chain fwd,
 *             hook forward prio 0, one rule per arm:
 *             [meta l4proto 17] counter [store] log(84:NN) accept.
 *             Two multi-frame taps on y1/y2, PACKET_OUTGOING only.
 *    child S = THE SENDER.  x1 fd02::11/64, default via fd02::91.  One socket
 *             with UDP_SEGMENT = 512; per arm sendto() 1200 bytes (GSO, one
 *             skb, 3 segments) or inject a hand-built 1262-byte frame with
 *             AF_PACKET (CHECKSUM_NONE, no GSO).
 *    child D = THE RECEIVER.  y3 fd03::92/64, y4 fd04::92/64; TWO sockets:
 *             a plain one on 5000 and one with UDP_GRO on 5001 (ACCEPT_L4, so
 *             udp_unexpected_gso() is false and the GSO skb is delivered
 *             whole), plus multi-frame taps on y3/y4.
 *
 *  Frame: 14 eth + 40 IPv6 + 8 UDP + 1200 payload = 1262 bytes,
 *  payload[i] = 0x80 + (i & 0x7f); segments 512/512/176.
 *
 *  Arithmetic the verifier checks (one's complement, fold16):
 *    P(L)      pseudo-header sum with the 32-bit length L
 *    seed(L)   = fold16(P(L))            the PARTIAL field of a datagram of L
 *    correct(L, pay) = ~fold16(P(L) + H0(L) + sum(pay))
 *    segmenter: check_i = seed(L) - L + len_i   (a segment's PARTIAL seed)
 *    software writer: field = ~fold16(H_i + check_i + G_i)
 */

#define F584_GROUP	84
#define F584_SPORT	43580
#define F584_DPORT	5000
#define F584_DPORT_G	5001
#define F584_D		1200	/* payload bytes */
#define F584_MSS	512	/* UDP_SEGMENT size -> 512/512/176 */
#define F584_FRAME	(14 + 40 + 8 + F584_D)
#define B584_NH		1
#define B584_TH		2
#define F584_HWCSUM_BIT	3	/* NETIF_F_HW_CSUM_BIT */
#define F584_GSOUDP_BIT	33	/* NETIF_F_GSO_UDP_L4_BIT (ac1 bit 1) */

#ifndef UDP_SEGMENT
#define UDP_SEGMENT	103
#endif
#ifndef UDP_GRO
#define UDP_GRO		104
#endif
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO	49
#endif
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO		50
#endif
struct f584_pktinfo {
	struct in6_addr ipi6_addr;
	unsigned int ipi6_ifindex;
};

#define F584_TAPN	4
#define F584_TAPB	1400

static int f584_deltable(uint8_t fam, const char *table)
{
	struct nlmsghdr *nlh;
	int acks = 0;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
			NLM_F_REQUEST | NLM_F_ACK, fam);
	put_str(nlh, NFTA_TABLE_NAME, table);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

static const unsigned char A84_S6[16] = { 0xfd, 0x02, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x11 };
static const unsigned char A84_R6[16] = { 0xfd, 0x02, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x91 };
static const unsigned char A84_DA[16] = { 0xfd, 0x03, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x92 };
static const unsigned char A84_DB[16] = { 0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x92 };
static const unsigned char A84_RA[16] = { 0xfd, 0x03, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x91 };
static const unsigned char A84_RB[16] = { 0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x91 };

static unsigned char F584_X0M[6], F584_X1M[6];
static unsigned char F584_PAY[F584_D];

/* ---------- arithmetic ---------------------------------------------- */

static uint32_t f584_sum32(const unsigned char *b, int n)
{
	uint32_t s = 0;
	int i;

	for (i = 0; i + 1 < n; i += 2)
		s += ((uint32_t)b[i] << 8) | b[i + 1];
	if (n & 1)
		s += (uint32_t)b[n - 1] << 8;
	return s;
}

static unsigned short f584_fold(uint32_t s)
{
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (unsigned short)(s & 0xffff);
}

static unsigned short f584_seed(const unsigned char *saddr,
				const unsigned char *daddr, int len)
{
	unsigned char ph[40];
	uint32_t s;

	memcpy(ph, saddr, 16);
	memcpy(ph + 16, daddr, 16);
	ph[32] = 0;
	ph[33] = 0;
	ph[34] = (unsigned char)((len >> 8) & 0xff);
	ph[35] = (unsigned char)(len & 0xff);
	ph[36] = 0;
	ph[37] = 0;
	ph[38] = 0;
	ph[39] = 17;
	s = f584_sum32(ph, 40);
	return f584_fold(s);
}

/* the correct checksum of a UDP datagram of length udplen (header + payload) */
static unsigned short f584_correct(const unsigned char *saddr,
				   const unsigned char *daddr,
				   int udplen, const unsigned char *pay, int n)
{
	unsigned char h[8], ph[40];
	uint32_t s;

	h[0] = (F584_SPORT >> 8) & 0xff;
	h[1] = F584_SPORT & 0xff;
	h[2] = (F584_DPORT >> 8) & 0xff;
	h[3] = F584_DPORT & 0xff;
	h[4] = (unsigned char)((udplen >> 8) & 0xff);
	h[5] = (unsigned char)(udplen & 0xff);
	h[6] = 0;
	h[7] = 0;
	memcpy(ph, saddr, 16);
	memcpy(ph + 16, daddr, 16);
	memset(ph + 32, 0, 8);
	ph[34] = (unsigned char)((udplen >> 8) & 0xff);
	ph[35] = (unsigned char)(udplen & 0xff);
	ph[39] = 17;
	s = f584_sum32(h, 8) + f584_sum32(pay, n) + f584_sum32(ph, 40);
	return (unsigned short)(~f584_fold(s) & 0xffff);
}

/* ---------- frames ------------------------------------------------------ */

static int f584_mk6(unsigned char *out, const unsigned char *dmac,
		    const unsigned char *smac, const unsigned char *daddr)
{
	unsigned short c;

	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	out[14] = 0x60;
	out[15] = 0;
	out[16] = 0;
	out[17] = 0;
	out[18] = (unsigned char)(((8 + F584_D) >> 8) & 0xff);
	out[19] = (unsigned char)((8 + F584_D) & 0xff);
	out[20] = 17;
	out[21] = 64;
	memcpy(out + 22, A84_S6, 16);
	memcpy(out + 38, daddr, 16);
	out[54] = (F584_SPORT >> 8) & 0xff;
	out[55] = F584_SPORT & 0xff;
	out[56] = (F584_DPORT >> 8) & 0xff;
	out[57] = F584_DPORT & 0xff;
	out[58] = (unsigned char)(((8 + F584_D) >> 8) & 0xff);
	out[59] = (unsigned char)((8 + F584_D) & 0xff);
	out[60] = 0;
	out[61] = 0;
	memcpy(out + 62, F584_PAY, F584_D);
	c = f584_correct(A84_S6, daddr, 8 + F584_D, out + 62, F584_D);
	out[60] = (unsigned char)(c >> 8);
	out[61] = (unsigned char)(c & 0xff);
	return F584_FRAME;
}

static int f584_send_frame(const unsigned char *f, int flen, const char *dev)
{
	struct sockaddr_ll sll;
	int fd, rc, idx = f555_ifindex(dev);

	if (idx < 0)
		return -1;
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return -2;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = idx;
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, f, 6);
	rc = (int)sendto(fd, f, (size_t)flen, 0, (struct sockaddr *)&sll,
			 sizeof(sll));
	if (rc < 0)
		rc = -errno;
	close(fd);
	return rc;
}

/* Our frames only: ethertype IPv6, next header UDP, destination port in
 * {5000, 5001}, destination address in {fd03::92, fd04::92}.  Keyed on the
 * destination, never on the source port (F61 error 1). */
static int f584_isours(const unsigned char *b, int r)
{
	int dport;

	if (r < 62)
		return 0;
	if (b[12] != 0x86 || b[13] != 0xdd)
		return 0;
	if (b[20] != 17)
		return 0;
	dport = (b[56] << 8) | b[57];
	if (dport != F584_DPORT && dport != F584_DPORT_G)
		return 0;
	if (memcmp(b + 38, A84_DA, 16) && memcmp(b + 38, A84_DB, 16))
		return 0;
	return 1;
}

/* ---------- a multi-frame tap ------------------------------------------- */

struct f584_tap {
	int fd;
	int only_out;
	int nall;
	int n;
	int len[F584_TAPN];
	int stat[F584_TAPN];
	unsigned char b[F584_TAPN][F584_TAPB];
};

static void f584_tap_zero(struct f584_tap *T)
{
	T->nall = 0;
	T->n = 0;
	memset(T->len, 0, sizeof(T->len));
	memset(T->stat, 0, sizeof(T->stat));
}

static void f584_tap_drain(struct f584_tap *T)
{
	static unsigned char b[F584_TAPB + 64];
	static unsigned char cb[256];

	f584_tap_zero(T);
	if (T->fd < 0)
		return;
	for (;;) {
		struct sockaddr_ll from;
		struct iovec iov;
		struct msghdr msg;
		struct cmsghdr *cm;
		int r, k;

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
		r = (int)recvmsg(T->fd, &msg, MSG_DONTWAIT);
		if (r <= 0)
			break;
		if (T->only_out) {
			if (from.sll_pkttype != PACKET_OUTGOING)
				continue;
		} else {
			if (from.sll_pkttype == PACKET_OUTGOING)
				continue;
		}
		T->nall++;
		if (!f584_isours(b, r))
			continue;
		if (T->n >= F584_TAPN) {
			T->n++;
			continue;
		}
		k = T->n++;
		T->len[k] = r < F584_TAPB ? r : F584_TAPB;
		memcpy(T->b[k], b, (size_t)T->len[k]);
		T->stat[k] = -1;
		for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
			struct tpacket_auxdata aux;

			if (cm->cmsg_level != SOL_PACKET ||
			    cm->cmsg_type != PACKET_AUXDATA)
				continue;
			if (cm->cmsg_len < CMSG_LEN(sizeof(aux)))
				continue;
			memcpy(&aux, CMSG_DATA(cm), sizeof(aux));
			T->stat[k] = (int)aux.tp_status;
		}
	}
}

static void f584_tap_print(const struct f584_tap *T, int idx, const char *dev)
{
	static const char hexd[] = "0123456789abcdef";
	static char hx[2 * F584_TAPB + 8];
	int k, i;

	for (k = 0; k < T->n && k < F584_TAPN; k++) {
		int at = 0;

		for (i = 0; i < T->len[k] && at + 3 < (int)sizeof(hx); i++) {
			hx[at++] = hexd[(T->b[k][i] >> 4) & 0xf];
			hx[at++] = hexd[T->b[k][i] & 0xf];
		}
		hx[at] = 0;
		printf("F584 TAP|i=%02d|dev=%s|k=%d|len=%d|stat=%d|hex=%s\n",
		       idx, dev, k, T->len[k], T->stat[k], hx);
	}
	if (T->n > F584_TAPN)
		printf("F584 TAPX|i=%02d|dev=%s|n=%d\n", idx, dev, T->n);
}

/* ---------- children ---------------------------------------------------- */

struct f584_conn {
	int up[2], dn[2];
	pid_t pid;
};

static struct f584_conn F584_S, F584_C;
static struct f584_tap F584_TA, F584_TB;
static int F584_NFL = -1;

static int f584_wait_byte(int fd, int ms)
{
	fd_set rf;
	struct timeval tv;
	int rc;

	FD_ZERO(&rf);
	FD_SET(fd, &rf);
	tv.tv_sec = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	rc = select(fd + 1, &rf, NULL, NULL, &tv);
	if (rc <= 0)
		return -1;
	{
		unsigned char c;

		if (read(fd, &c, 1) != 1)
			return -1;
		return (int)c;
	}
}

/* 3-byte command: cmd, arg1, arg2 */
static int f584_cmd(struct f584_conn *C, int cmd, int a1, int a2)
{
	unsigned char c[3];

	c[0] = (unsigned char)cmd;
	c[1] = (unsigned char)a1;
	c[2] = (unsigned char)a2;
	if (write(C->dn[1], c, 3) != 3)
		return -2;
	return f584_wait_byte(C->up[0], 8000) < 0 ? -3 : 0;
}

static int f584_veth_ns(const char *a, const char *b, int pid)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[512];
	} req;
	struct ifinfomsg zifi;
	struct nlattr *li, *data, *peer;
	int fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	attr_put(&req.nlh, IFLA_IFNAME, a, (int)strlen(a) + 1);
	li = nest_start(&req.nlh, IFLA_LINKINFO);
	attr_put(&req.nlh, IFLA_INFO_KIND, "veth", 5);
	data = nest_start(&req.nlh, IFLA_INFO_DATA);
	memset(&zifi, 0, sizeof(zifi));
	zifi.ifi_family = AF_UNSPEC;
	peer = attr_put(&req.nlh, (uint16_t)(VETH_INFO_PEER | NLA_F_NESTED),
			&zifi, (int)sizeof(zifi));
	attr_put(&req.nlh, IFLA_IFNAME, b, (int)strlen(b) + 1);
	attr_put(&req.nlh, IFLA_NET_NS_PID, &pid, 4);
	nest_end(&req.nlh, peer);
	nest_end(&req.nlh, data);
	nest_end(&req.nlh, li);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

static int f584_v6dev(const char *dev, int fwd)
{
	char p[128];
	int rc = 0;

	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", dev);
	rc |= f555_sysctl(p, "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/accept_dad", dev);
	rc |= f555_sysctl(p, "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/dad_transmits", dev);
	rc |= f555_sysctl(p, "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/autoconf", dev);
	rc |= f555_sysctl(p, "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/accept_ra", dev);
	rc |= f555_sysctl(p, "0");
	snprintf(p, sizeof(p), "/proc/sys/net/ipv6/conf/%s/forwarding", dev);
	rc |= f555_sysctl(p, fwd ? "1" : "0");
	return rc;
}

/* The sender's address must never be tentative: without IFA_F_NODAD the
 * address needs DAD to finish, and bind() to a tentative address returns
 * EADDRNOTAVAIL.  Smoke a won that race by luck; both full boots lost it
 * (s6=-99, errno=99) and every socket arm silently became an unsent one.
 * Fix: ask for NODAD explicitly and still retry the bind. */
#define F584_IFA_F_NODAD	0x02

static int f584_addr6_nodad(const char *dev, const unsigned char *a, int plen)
{
	struct {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
		char attrs[128];
	} req;
	int fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nlh.nlmsg_type = RTM_NEWADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
	req.nlh.nlmsg_seq = 1;
	req.ifa.ifa_family = AF_INET6;
	req.ifa.ifa_prefixlen = (uint8_t)plen;
	req.ifa.ifa_index = (uint32_t)f555_ifindex(dev);
	req.ifa.ifa_flags = F584_IFA_F_NODAD;
	attr_put(&req.nlh, IFA_LOCAL, a, 16);
	attr_put(&req.nlh, IFA_ADDRESS, a, 16);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

static int f584_route6(const unsigned char *gw, const char *dev)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char attrs[128];
	} req;
	int oif = f555_ifindex(dev), fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_type = RTM_NEWROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
	req.nlh.nlmsg_seq = 1;
	req.rtm.rtm_family = AF_INET6;
	req.rtm.rtm_dst_len = 0;
	req.rtm.rtm_table = 254;
	req.rtm.rtm_protocol = 4;
	req.rtm.rtm_scope = 0;
	req.rtm.rtm_type = 1;
	attr_put(&req.nlh, 5 /* RTA_GATEWAY */, gw, 16);
	attr_put(&req.nlh, 4 /* RTA_OIF */, &oif, 4);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* the sender: THE WIRE.  Never returns. */
static void f584_child_s(void)
{
	unsigned char msg[8], c[3];
	unsigned char frA[F584_FRAME + 8], frB[F584_FRAME + 8];
	int s6, i, rc, lA, lB, mss = F584_MSS, gso_rc = -1;

	close(F584_S.up[0]);
	close(F584_S.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F584 CHILDS|unshare=%d\n", errno);
		_exit(1);
	}
	c[0] = 'U';
	if (write(F584_S.up[1], c, 1) != 1)
		_exit(2);
	if (read(F584_S.dn[0], msg, 7) != 7 || msg[0] != 'M')
		_exit(3);
	memcpy(F584_X0M, msg + 1, 6);
	set_up("lo");
	for (i = 0; i < 200 && f555_ifindex("x1") < 0; i++)
		usleep(20000);
	set_up("x1");
	(void)f584_v6dev("x1", 0);
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	rc = f584_addr6_nodad("x1", A84_S6, 64);
	rc |= f584_route6(A84_R6, "x1");
	i = mac_get("x1", F584_X1M);
	lA = f584_mk6(frA, F584_X0M, F584_X1M, A84_DA);
	lB = f584_mk6(frB, F584_X0M, F584_X1M, A84_DB);
	s6 = -1;
	{
		int try_n = 0, last = 0;

		for (try_n = 0; try_n < 60; try_n++) {
			s6 = f564_udp_bind(AF_INET6, 0, A84_S6, F584_SPORT);
			if (s6 >= 0)
				break;
			last = -s6;
			usleep(50000);
		}
		errno = last;
	}
	if (s6 >= 0)
		gso_rc = setsockopt(s6, IPPROTO_UDP, UDP_SEGMENT, &mss,
				    (socklen_t)sizeof(mss));
	printf("F584 CHILDS|rc=%d|macrc=%d|x1=%d|s6=%d|gso_rc=%d|errno=%d|"
	       "lA=%d|lB=%d|m0=%02x%02x%02x%02x%02x%02x|"
	       "m1=%02x%02x%02x%02x%02x%02x\n",
	       rc, i, f555_ifindex("x1"), s6, gso_rc,
	       gso_rc < 0 ? errno : 0, lA, lB,
	       F584_X0M[0], F584_X0M[1], F584_X0M[2], F584_X0M[3],
	       F584_X0M[4], F584_X0M[5], F584_X1M[0], F584_X1M[1],
	       F584_X1M[2], F584_X1M[3], F584_X1M[4], F584_X1M[5]);
	{
		static char hx[2 * F584_FRAME + 8];

		f559_hexs(hx, 200, frA, 30);	/* just the head, for provenance */
		printf("F584 FRMPY|id=a|len=%d|head=%s|ck=%04x|seed=%04x\n",
		       lA, hx, (frA[60] << 8) | frA[61],
		       f584_seed(A84_S6, A84_DA, 8 + F584_D));
		f559_hexs(hx, 200, frB, 30);
		printf("F584 FRMPY|id=b|len=%d|head=%s|ck=%04x|seed=%04x\n",
		       lB, hx, (frB[60] << 8) | frB[61],
		       f584_seed(A84_S6, A84_DB, 8 + F584_D));
	}
	c[0] = 'R';
	if (write(F584_S.up[1], c, 1) != 1)
		_exit(4);
	for (;;) {
		struct sockaddr_in6 d6;
		int port;

		if (read(F584_S.dn[0], c, 3) != 3)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		port = c[2] == 'g' ? F584_DPORT_G : F584_DPORT;
		if (c[0] == 's') {
			memset(&d6, 0, sizeof(d6));
			d6.sin6_family = AF_INET6;
			memcpy(&d6.sin6_addr, c[1] == 'a' ? A84_DA : A84_DB, 16);
			d6.sin6_port = htons((unsigned short)port);
			rc = (int)sendto(s6, F584_PAY, F584_D, 0,
					 (struct sockaddr *)&d6, sizeof(d6));
			printf("F584 CHILDS|cmd=s%c%c|rc=%d|errno=%d\n", c[1],
			       c[2], rc, rc < 0 ? errno : 0);
		} else if (c[0] == 'p') {
			rc = f584_send_frame(c[1] == 'a' ? frA : frB,
					     c[1] == 'a' ? lA : lB, "x1");
			printf("F584 CHILDS|cmd=p%c%c|rc=%d\n", c[1], c[2], rc);
		}
		c[0] = 'D';
		if (write(F584_S.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* the receiver: the far end.  Never returns. */
static void f584_child_d(void)
{
	static unsigned char buf[4096];
	static unsigned char cb[256];
	unsigned char msg[8], c[3];
	static struct f584_tap t3, t4;
	struct f580_sn prev, cur;
	int i, rc, s, sg;

	close(F584_C.up[0]);
	close(F584_C.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F584 CHILDD|unshare=%d\n", errno);
		_exit(1);
	}
	c[0] = 'U';
	if (write(F584_C.up[1], c, 1) != 1)
		_exit(2);
	if (read(F584_C.dn[0], msg, 1) != 1)
		_exit(3);
	set_up("lo");
	for (i = 0; i < 400 && f555_ifindex("y3") < 0; i++)
		usleep(20000);
	set_up("y3");
	set_up("y4");
	(void)f584_v6dev("y3", 0);
	(void)f584_v6dev("y4", 0);
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	rc = f564_addr6("y3", A84_DA, 64);
	rc |= f564_addr6("y4", A84_DB, 64);
	s = -1;
	sg = -1;
	{
		unsigned char any[16];
		int one = 1;

		memset(any, 0, sizeof(any));
		s = f564_udp_bind(AF_INET6, 0, any, F584_DPORT);
		if (s >= 0)
			setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one,
				   sizeof(one));
		sg = f564_udp_bind(AF_INET6, 0, any, F584_DPORT_G);
		if (sg >= 0) {
			int gro = 1;

			setsockopt(sg, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one,
				   sizeof(one));
			rc |= setsockopt(sg, IPPROTO_UDP, UDP_GRO, &gro,
					 (socklen_t)sizeof(gro));
		}
	}
	t3.fd = f578_tap_open_aux("y3");
	t4.fd = f578_tap_open_aux("y4");
	t3.only_out = 0;
	t4.only_out = 0;
	printf("F584 CHILDD|rc=%d|s=%d|sg=%d|y3=%d|y4=%d|t3=%d|t4=%d\n", rc, s,
	       sg, f555_ifindex("y3"), f555_ifindex("y4"), t3.fd, t4.fd);
	f580_snmp(&prev);
	c[0] = 'R';
	if (write(F584_C.up[1], &c, 1) != 1)
		_exit(4);
	for (;;) {
		int idx, pass, nd[2] = { 0, 0 };
		int dl[2][4], dg[2][4];
		char dh[2][4][40];
		static const char hexd[] = "0123456789abcdef";
		int ports[2];
		int sock[2];

		if (read(F584_C.dn[0], c, 3) != 3)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		if (c[0] != 'r')
			continue;
		idx = c[1];
		sock[0] = s;
		sock[1] = sg;
		ports[0] = F584_DPORT;
		ports[1] = F584_DPORT_G;
		memset(dl, 0, sizeof(dl));
		memset(dg, 0, sizeof(dg));
		memset(dh, 0, sizeof(dh));
		{
			int empty = 0;

			for (pass = 0; pass < 120 && empty < 10; pass++) {
				int got = 0, w;

				for (w = 0; w < 2; w++) {
				if (sock[w] < 0)
					continue;
				for (;;) {
					struct msghdr m;
					struct iovec iov;
					struct sockaddr_in6 from;
					int r;

					memset(&from, 0, sizeof(from));
					iov.iov_base = buf;
					iov.iov_len = sizeof(buf);
					memset(&m, 0, sizeof(m));
					m.msg_name = &from;
					m.msg_namelen = sizeof(from);
					m.msg_iov = &iov;
					m.msg_iovlen = 1;
					m.msg_control = cb;
					m.msg_controllen = sizeof(cb);
					r = (int)recvmsg(sock[w], &m,
							 MSG_DONTWAIT);
					if (r < 0)
						break;
					got++;
					if (nd[w] < 4) {
						struct cmsghdr *cm;
						int k = nd[w], b;

						dl[w][k] = r;
						dg[w][k] = -1;
						for (b = 0; b < 16 && b < r;
						     b++) {
							dh[w][k][2 * b] =
								hexd[(buf[b] >> 4) &
								     0xf];
							dh[w][k][2 * b + 1] =
								hexd[buf[b] & 0xf];
						}
						dh[w][k][16] = 0;
						for (cm = CMSG_FIRSTHDR(&m); cm;
						     cm = CMSG_NXTHDR(&m, cm)) {
							int v;

							if (cm->cmsg_level !=
								 IPPROTO_UDP ||
							    cm->cmsg_type !=
								 UDP_GRO)
								continue;
							memcpy(&v,
							       CMSG_DATA(cm), 4);
							dg[w][k] = v;
						}
					}
					nd[w]++;
				}
			}
			if (!got) {
				empty++;
				usleep(4000);
			} else {
				empty = 0;
			}
			}
		}
		usleep(40000);
		f584_tap_drain(&t3);
		f584_tap_drain(&t4);
		f580_snmp(&cur);
		printf("F584 RCV|i=%02d|a=%d|b=%d|"
		       "a0=%d:%d:%s|a1=%d:%d:%s|a2=%d:%d:%s|"
		       "b0=%d:%d:%s|b1=%d:%d:%s|b2=%d:%d:%s|"
		       "u6in=%llu|u6err=%llu|du6in=%lld|du6err=%lld|"
		       "ddeliv=%lld|dhdr=%lld|ddisc=%lld|noroute=%llu|"
		       "t3=%d|t4=%d\n",
		       idx, nd[0], nd[1],
		       dl[0][0], dg[0][0], dh[0][0],
		       dl[0][1], dg[0][1], dh[0][1],
		       dl[0][2], dg[0][2], dh[0][2],
		       dl[1][0], dg[1][0], dh[1][0],
		       dl[1][1], dg[1][1], dh[1][1],
		       dl[1][2], dg[1][2], dh[1][2],
		       cur.udp, cur.udperr,
		       (long long)cur.udp - (long long)prev.udp,
		       (long long)cur.udperr - (long long)prev.udperr,
		       (long long)cur.deliv - (long long)prev.deliv,
		       (long long)cur.hdrerr - (long long)prev.hdrerr,
		       (long long)cur.disc - (long long)prev.disc,
		       cur.noroutes, t3.n, t4.n);
		prev = cur;
		fflush(stdout);
		f584_tap_print(&t3, idx, "y3");
		f584_tap_print(&t4, idx, "y4");
		fflush(stdout);
		c[0] = 'D';
		if (write(F584_C.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* ---------- the arms ---------------------------------------------------- */

struct f584_arm {
	const char *name;
	char prov;		/* 's' GSO sendmsg, 'p' AF_PACKET frame */
	char dst;		/* 'a' fd03::92 via y1, 'b' fd04::92 via y2 */
	char skt;		/* 'p' plain 5000, 'g' UDP_GRO 5001 */
	int store;
	int base;
	unsigned int off, len;
	const char *hex;
	int ct;
	unsigned int co;
	unsigned int cf;
};

static const struct f584_arm AF584[] = {
	/* --- census ------------------------------------------------------- */
	{ "c_a",	's', 'a', 'p', 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_b",	's', 'b', 'p', 0, 0, 0, 0, NULL, 0, 0, 0 },
	/* --- payload stores, first / middle / last segment ----------------- */
	{ "w_a",	's', 'a', 'p', 1, B584_TH, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "w_b",	's', 'b', 'p', 1, B584_TH, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "wm_a",	's', 'a', 'p', 1, B584_TH, 520, 4, "b0b1b2b3", 0, 0, 0 },
	{ "wm_b",	's', 'b', 'p', 1, B584_TH, 520, 4, "b0b1b2b3", 0, 0, 0 },
	{ "wl_a",	's', 'a', 'p', 1, B584_TH, 1204, 4, "c0c1c2c3", 0, 0, 0 },
	{ "wl_b",	's', 'b', 'p', 1, B584_TH, 1204, 4, "c0c1c2c3", 0, 0, 0 },
	/* --- the store writes what is already there ------------------------ */
	{ "lens_a",	's', 'a', 'p', 1, B584_TH, 4, 2, "04b8", 0, 0, 0 },
	/* --- the store writes a field the segmenter reads ------------------ */
	{ "len_a",	's', 'a', 'p', 1, B584_TH, 4, 2, "0020", 0, 0, 0 },
	{ "len_b",	's', 'b', 'p', 1, B584_TH, 4, 2, "0020", 0, 0, 0 },
	{ "lenbig_a",	's', 'a', 'p', 1, B584_TH, 4, 2, "ffff", 0, 0, 0 },
	{ "chk_a",	's', 'a', 'p', 1, B584_TH, 6, 2, "dead", 0, 0, 0 },
	{ "chk_b",	's', 'b', 'p', 1, B584_TH, 6, 2, "dead", 0, 0, 0 },
	/* --- csum flags on a PARTIAL skb ----------------------------------- */
	{ "wfl_a",	's', 'a', 'p', 1, B584_TH, 8, 4, "a0a1a2a3", 0, 0, 1 },
	{ "wfl_b",	's', 'b', 'p', 1, B584_TH, 8, 4, "a0a1a2a3", 0, 0, 1 },
	/* --- packet provenance: the same 1262 bytes, CHECKSUM_NONE --------- */
	{ "c_p_a",	'p', 'a', 'p', 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_p_b",	'p', 'b', 'p', 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "w_p_a",	'p', 'a', 'p', 1, B584_TH, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "wb_p_a",	'p', 'a', 'p', 1, B584_TH, 8, 4, "a0a1a2a3", 0, 0, 1 },
	/* --- the UDP_GRO socket: nothing is left to segment ---------------- */
	{ "g_a",	's', 'a', 'g', 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "g_b",	's', 'b', 'g', 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "gw_a",	's', 'a', 'g', 1, B584_TH, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "gw_b",	's', 'b', 'g', 1, B584_TH, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "glen_a",	's', 'a', 'g', 1, B584_TH, 4, 2, "0020", 0, 0, 0 },
};
#define NAF584 ((int)(sizeof(AF584) / sizeof(AF584[0])))

static int f584_imm(const struct f584_arm *A, unsigned char *imm)
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
	return -1;
}

/* [meta l4proto 17] counter [store] log accept */
static int f584_rule(const struct f584_arm *A, int idx,
		     const unsigned char *imm, int immlen)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs, *e, *d;
	char pre[16];
	int acks = 0;

	snprintf(pre, sizeof(pre), "84:%02d", idx);
	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			NFPROTO_IPV6);
	put_str(nlh, NFTA_RULE_TABLE, "f84p");
	put_str(nlh, NFTA_RULE_CHAIN, "fwd");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	{
		unsigned char l4 = 17;

		f567_meta_l4(nlh);
		f562_cmp(nlh, F562_RD_DREG, &l4, 1);
	}
	counter_expr(nlh);
	if (A->store) {
		imm_value(nlh, NFT_REG32_00, imm, immlen);
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
	log_expr(nlh, F584_GROUP, pre);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

static void f584_arm(const struct f584_arm *A, int idx)
{
	struct f580_sn a, b;
	struct f575_pl pl;
	unsigned char imm[64];
	char hxi[512] = "-", lgfirst[64] = "-", lgudp[32] = "-", lgtail[64] = "-";
	int rc = -99, ilen = -1, ch = -1, nl = 0, lgplen = -1, i, cmdrc = 0;
	int acks = 0;

	(void)f557_flush(NFPROTO_IPV6, "f84p", "fwd", &acks);
	f584_tap_drain(&F584_TA);
	f584_tap_drain(&F584_TB);
	f575_nfl_drain(&pl);
	if (A->store) {
		ilen = f584_imm(A, imm);
		rc = ilen < 0 ? -99 : f584_rule(A, idx, imm, ilen);
		f559_hexs(hxi, sizeof(hxi), imm, ilen > 0 ? ilen : 0);
	} else {
		rc = f584_rule(A, idx, NULL, 0);
	}
	f580_snmp(&a);
	cmdrc |= f584_cmd(&F584_S, A->prov, A->dst, A->skt);
	cmdrc |= f584_cmd(&F584_C, 'r', idx, 0) ? 4 : 0;
	usleep(120000);
	f584_tap_drain(&F584_TA);
	f584_tap_drain(&F584_TB);
	f575_nfl_drain(&pl);
	f580_snmp(&b);
	ch = (int)f555_count(NFPROTO_IPV6, "f84p", "fwd");
	for (i = 0; i < pl.n && i < F575_NPL; i++) {
		if (!strncmp(pl.m[i].prefix, "84:", 3) && !nl) {
			struct f575_msg *M = &pl.m[i];
			int j, at = 0;

			nl = 1;
			lgplen = M->plen;
			for (j = 0; j < 16 && j < M->plen; j++)
				at += snprintf(lgfirst + at,
					       sizeof(lgfirst) - (size_t)at,
					       "%02x", M->p[j]);
			at = 0;
			for (j = 40; j < 48 && j < M->plen; j++)
				at += snprintf(lgudp + at,
					       sizeof(lgudp) - (size_t)at,
					       "%02x", M->p[j]);
			at = 0;
			for (j = M->plen > 16 ? M->plen - 16 : 0; j < M->plen && j < (int)sizeof(M->p);
			     j++)
				at += snprintf(lgtail + at,
					       sizeof(lgtail) - (size_t)at,
					       "%02x", M->p[j]);
		}
	}
	printf("F584 ARM|i=%02d|name=%s|prov=%c|dst=%c|skt=%c|store=%d|"
	       "base=%d|off=%u|len=%u|hex=%s|ct=%d|cf=%u|rc=%d|cmdrc=%d|"
	       "ch=%d|nl=%d|lgplen=%d|lgfirst=%s|lgudp=%s|lgtail=%s|"
	       "an=%d|anall=%d|bn=%d|bnall=%d|"
	       "rcv=%llu|deliv=%llu|hdr=%llu|addr=%llu|disc=%llu|"
	       "noroute=%llu|uk=%llu\n",
	       idx, A->name, A->prov, A->dst, A->skt, A->store, A->base,
	       A->off, A->len, hxi, A->ct, A->cf, rc, cmdrc, ch, nl, lgplen,
	       lgfirst, lgudp, lgtail,
	       F584_TA.n, F584_TA.nall, F584_TB.n, F584_TB.nall,
	       b.rcv - a.rcv, b.deliv - a.deliv, b.hdrerr - a.hdrerr,
	       b.addrerr - a.addrerr, b.disc - a.disc,
	       b.noroutes - a.noroutes, b.ukproto - a.ukproto);
	fflush(stdout);
	f584_tap_print(&F584_TA, idx, "a");
	f584_tap_print(&F584_TB, idx, "b");
	fflush(stdout);
}

/* ---------- mode gso ---------------------------------------------------- */

static int f584_gso(void)
{
	static const char *old[] = { "x0", "x1", "y1", "y3", "y2", "y4" };
	struct f578_gf g;
	unsigned char msg[8];
	int i, rc, r1, r2;

	f584_tap_zero(&F584_TA);
	f584_tap_zero(&F584_TB);
	for (i = 0; i < F584_D; i++)
		F584_PAY[i] = (unsigned char)(0x80 + (i & 0x7f));
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv4/ip_forward", "0");
	for (i = 0; i < 6; i++)
		f558_link_del(old[i]);
	{
		int acks = 0;

		(void)f557_flush(NFPROTO_IPV6, "f84p", "fwd", &acks);
		(void)f584_deltable(NFPROTO_IPV6, "f84p");
	}
	if (pipe(F584_S.up) || pipe(F584_S.dn) || pipe(F584_C.up) ||
	    pipe(F584_C.dn)) {
		printf("F584 FAIL|pipe\n");
		return -1;
	}
	F584_S.pid = fork();
	if (F584_S.pid < 0) {
		printf("F584 FAIL|fork\n");
		return -1;
	}
	if (F584_S.pid == 0)
		f584_child_s();
	F584_C.pid = fork();
	if (F584_C.pid < 0) {
		printf("F584 FAIL|fork2\n");
		return -1;
	}
	if (F584_C.pid == 0)
		f584_child_d();
	close(F584_S.up[1]);
	close(F584_S.dn[0]);
	close(F584_C.up[1]);
	close(F584_C.dn[0]);
	if (f584_wait_byte(F584_S.up[0], 5000) != 'U') {
		printf("F584 FAIL|senderns\n");
		return -1;
	}
	if (f584_wait_byte(F584_C.up[0], 5000) != 'U') {
		printf("F584 FAIL|recvns\n");
		return -1;
	}
	rc = f584_veth_ns("x0", "x1", (int)F584_S.pid);
	rc |= f584_veth_ns("y1", "y3", (int)F584_C.pid);
	rc |= f584_veth_ns("y2", "y4", (int)F584_C.pid);
	if (rc) {
		printf("F584 FAIL|veth|rc=%d\n", rc);
		return -1;
	}
	set_up("x0");
	set_up("y1");
	set_up("y2");
	(void)f584_v6dev("x0", 1);
	(void)f584_v6dev("y1", 1);
	(void)f584_v6dev("y2", 1);
	rc = f564_addr6("x0", A84_R6, 64);
	rc |= f564_addr6("y1", A84_RA, 64);
	rc |= f564_addr6("y2", A84_RB, 64);
	mac_get("x0", F584_X0M);
	msg[0] = 'M';
	memcpy(msg + 1, F584_X0M, 6);
	if (write(F584_S.dn[1], msg, 7) != 7) {
		printf("F584 FAIL|mactx\n");
		return -1;
	}
	{
		unsigned char c = 'R';

		if (write(F584_C.dn[1], &c, 1) != 1) {
			printf("F584 FAIL|dsync\n");
			return -1;
		}
	}
	if (f584_wait_byte(F584_S.up[0], 8000) != 'R' ||
	    f584_wait_byte(F584_C.up[0], 8000) != 'R') {
		printf("F584 FAIL|childready\n");
		return -1;
	}
	r1 = f578_feat_set("y1", F584_HWCSUM_BIT, 1);
	r2 = f578_feat_set("y2", F584_HWCSUM_BIT, 0);
	printf("F584 FEAT|r1=%d|r2=%d|hwcsumbit=%d|gsoudpbit=%d\n", r1, r2,
	       F584_HWCSUM_BIT, F584_GSOUDP_BIT);
	f578_feat_get("y1", &g);
	printf("F584 FEAT|dev=y1|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y2", &g);
	printf("F584 FEAT|dev=y2|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	(void)f579_tbl(NFPROTO_IPV6, "f84p");
	{
		int k = 0;

		k |= f580_chn(NFPROTO_IPV6, "f84p", "fwd", NULL,
			      NF_INET_FORWARD, 0);
		printf("F584 CHAINS|rc=%d\n", k);
	}
	F573_NFL = nfl_open(F584_GROUP);
	F584_NFL = F573_NFL;
	F584_TA.fd = f578_tap_open_aux("y1");
	F584_TB.fd = f578_tap_open_aux("y2");
	F584_TA.only_out = 1;
	F584_TB.only_out = 1;
	printf("F584 ENV|x0=%d|y1=%d|y2=%d|nfl=%d|ta=%d|tb=%d|addr=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|D=%d|mss=%d\n",
	       f555_ifindex("x0"), f555_ifindex("y1"), f555_ifindex("y2"),
	       F573_NFL, F584_TA.fd, F584_TB.fd, rc, F584_X0M[0],
	       F584_X0M[1], F584_X0M[2], F584_X0M[3], F584_X0M[4],
	       F584_X0M[5], F584_D, F584_MSS);
	for (i = 0; i < NAF584; i++)
		f584_arm(&AF584[i], i);
	(void)f584_cmd(&F584_S, 'q', 0, 0);
	(void)f584_cmd(&F584_C, 'q', 0, 0);
	printf("F584 END|mode=gso|arms=%d\n", NAF584);
	fflush(stdout);
	return 0;
}

/* ---------- entry ------------------------------------------------------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "gso";

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("F584 BOOT|mode=%s|argc=%d\n", mode, argc);
	if (!strcmp(mode, "gso"))
		return f584_gso();
	return f583_entry(argc, argv);
}
