/* differ583_add.c -- turn 583 (F61): ON THE FORWARDED PATH THE BILL IS PAID
 * BY THE EXIT DEVICE, IN THE FIELD IT FINDS -- AND ONLY FOR THE PACKETS THAT
 * ARRIVED SAYING SOMEBODY ELSE WOULD PAY.
 *
 *  The debt named in F60 §14: every F60 datagram was born and died in one
 *  netns.  Here the datagram arrives from another netns, is FORWARDED by us,
 *  and leaves on one of two devices: y1 keeps NETIF_F_HW_CSUM, y2 has it
 *  cleared with ETHTOOL_SFEATURES.  So for the first time there is an entity
 *  that can pay -- skb_checksum_help() inside validate_xmit_skb(), which
 *  computes `~fold(sum of the L4 region as it currently stands)` and writes
 *  that at csum_offset, then sets ip_summed = CHECKSUM_NONE.
 *
 *  Three netns:
 *    parent = THE ROUTER.  x0 fd02::91/64 (to the sender), y1 fd03::91/64
 *             (exit with the offload bit ON), y2 fd04::91/64 (bit OFF).
 *             IPv6 forwarding on.  ip6 table f83p, chain fwd, hook forward
 *             prio 0, one rule per arm: [meta l4proto udp] counter [store]
 *             log(83:NN) accept.  Two AF_PACKET taps on y1/y2, outgoing
 *             frames only -- they see the frame AFTER validate_xmit_skb.
 *    child S = THE SENDER.  x1 fd02::11/64, default via fd02::91.  Per arm
 *             either sendto() one 18-byte UDP datagram from a socket bound to
 *             fd02::11:43580 (provenance s -> CHECKSUM_PARTIAL, the field
 *             carries the pseudo-header seed P) or injects with AF_PACKET the
 *             same 80 bytes in a frame built by hand with the correct
 *             checksum (provenance p -> CHECKSUM_NONE).
 *    child D = THE RECEIVER.  y3 fd03::92/64, y4 fd04::92/64, one socket on
 *             [::]:5000 with IPV6_RECVPKTINFO, plus two AF_PACKET taps on
 *             y3/y4 that report tp_status of the ARRIVING frame.
 *
 *  Frame: 14 eth + 40 IPv6 (fd02::11 -> fd03::92 or fd04::92, hop 64) + 8 UDP
 *  (43580 -> 5000, len 26) + 18 bytes 0x80..0x91.  80 bytes.
 *
 *  Arithmetic the verifier checks (all in one's complement, fold16):
 *    P     = fold16(pseudo header)                   the sender's seed
 *    S0    = fold16(UDP region with a zero field)
 *    C     = ~fold32(P + S0)                         the true checksum
 *    help  = ~fold32(S0 + field_in)                  what y2 writes
 *  A datagram is valid for a CHECKSUM_NONE receiver iff
 *    fold32(P + S0 + field) == 0xffff.
 */

#define F583_GROUP	83
#define F583_SPORT	43580
#define F583_DPORT	5000
#define F583_PAY	18
#define B583_NH		1
#define B583_TH		2
#define F583_HWCSUM_BIT	3	/* NETIF_F_HW_CSUM_BIT */

#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO	49
#endif
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO		50
#endif
/* glibc only declares struct in6_pktinfo under _GNU_SOURCE; spell it out */
struct f583_pktinfo {
	struct in6_addr ipi6_addr;
	unsigned int ipi6_ifindex;
};

static int f583_deltable(uint8_t fam, const char *table)
{
	struct nlmsghdr *nlh;
	int acks = 0;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
			NLM_F_REQUEST | NLM_F_ACK, fam);
	put_str(nlh, NFTA_TABLE_NAME, table);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

static const unsigned char A83_S6[16] = { 0xfd, 0x02, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x11 };
static const unsigned char A83_R6[16] = { 0xfd, 0x02, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x91 };
static const unsigned char A83_DA[16] = { 0xfd, 0x03, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x92 };
static const unsigned char A83_DB[16] = { 0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x92 };
static const unsigned char A83_RA[16] = { 0xfd, 0x03, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x91 };
static const unsigned char A83_RB[16] = { 0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x91 };
static const unsigned char A83_NEW[16] = { 0xfd, 0x02, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 0x77 };

static unsigned char F583_X0M[6], F583_X1M[6];

/* ---------- frames ------------------------------------------------------ */

static unsigned short f583_csum(const unsigned char *b, int n)
{
	uint32_t s = 0;
	int i;

	if (n & 1)
		return 0;
	for (i = 0; i < n; i += 2)
		s += ((uint32_t)b[i] << 8) | b[i + 1];
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (unsigned short)(~s & 0xffff);
}

static int f583_mk6(unsigned char *out, const unsigned char *dmac,
		    const unsigned char *smac, const unsigned char *daddr)
{
	unsigned char ph[96];
	int n = 0, i;

	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	out[14] = 0x60;			/* version 6, tc 0 */
	out[15] = 0;
	out[16] = 0;
	out[17] = 0;
	out[18] = 0;			/* payload length 26 */
	out[19] = 8 + F583_PAY;
	out[20] = 17;			/* next header UDP */
	out[21] = 64;			/* hop limit */
	memcpy(out + 22, A83_S6, 16);
	memcpy(out + 38, daddr, 16);
	out[54] = (F583_SPORT >> 8) & 0xff;
	out[55] = F583_SPORT & 0xff;
	out[56] = (F583_DPORT >> 8) & 0xff;
	out[57] = F583_DPORT & 0xff;
	out[58] = 0;
	out[59] = 8 + F583_PAY;
	out[60] = 0;			/* checksum, zero for now */
	out[61] = 0;
	for (i = 0; i < F583_PAY; i++)
		out[62 + i] = (unsigned char)(0x80 + i);
	memcpy(ph, out + 22, 16);
	memcpy(ph + 16, out + 38, 16);
	ph[32] = 0;
	ph[33] = 0;
	ph[34] = 0;
	ph[35] = 8 + F583_PAY;
	ph[36] = 0;
	ph[37] = 0;
	ph[38] = 0;
	ph[39] = 17;
	memcpy(ph + 40, out + 54, 8 + F583_PAY);
	n = 40 + 8 + F583_PAY;
	{
		unsigned short c = f583_csum(ph, n);

		out[60] = (unsigned char)(c >> 8);
		out[61] = (unsigned char)(c & 0xff);
	}
	return 14 + 40 + 8 + F583_PAY;
}

static int f583_send_frame(const unsigned char *f, int flen, const char *dev)
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

/* Keyed on the DESTINATION port and address, never on the source port: one
 * of the arms writes the source port (sp_s_*), and a filter keyed on sport
 * would have thrown away the very frame it was measuring (smoke a: sp arms
 * printed an=0/bn=0 while the datagram demonstrably arrived). */
static int f583_isours(const unsigned char *b, int r)
{
	if (r < 62)
		return 0;
	if (b[12] != 0x86 || b[13] != 0xdd)
		return 0;
	if (b[20] != 17)
		return 0;
	if (((b[56] << 8) | b[57]) != F583_DPORT)
		return 0;
	if (memcmp(b + 38, A83_DA, 16) && memcmp(b + 38, A83_DB, 16))
		return 0;
	return 1;
}

/* ---------- a tap ------------------------------------------------------- */

struct f583_tap {
	int fd;
	int only_out;
	int nall;
	int n;
	int len;
	int stat;
	unsigned char b[192];
};

static void f583_tap_drain(struct f583_tap *T)
{
	unsigned char b[2048], cb[256];

	T->nall = 0;
	T->n = 0;
	T->len = -1;
	T->stat = -1;
	if (T->fd < 0)
		return;
	for (;;) {
		struct sockaddr_ll from;
		struct iovec iov;
		struct msghdr msg;
		struct cmsghdr *cm;
		int r;

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
		if (!f583_isours(b, r))
			continue;
		T->n++;
		if (T->len < 0) {
			T->len = r < (int)sizeof(T->b) ? r : (int)sizeof(T->b);
			memcpy(T->b, b, (size_t)T->len);
			for (cm = CMSG_FIRSTHDR(&msg); cm;
			     cm = CMSG_NXTHDR(&msg, cm)) {
				struct tpacket_auxdata aux;

				if (cm->cmsg_level != SOL_PACKET ||
				    cm->cmsg_type != PACKET_AUXDATA)
					continue;
				if (cm->cmsg_len < CMSG_LEN(sizeof(aux)))
					continue;
				memcpy(&aux, CMSG_DATA(cm), sizeof(aux));
				T->stat = (int)aux.tp_status;
			}
		}
	}
}

/* ---------- children ---------------------------------------------------- */

struct f583_conn {
	int up[2], dn[2];
	pid_t pid;
};

static struct f583_conn F583_S, F583_D;
static struct f583_tap F583_TA, F583_TB;
static int F583_NFL = -1;

static int f583_wait_byte(int fd, int ms)
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

/* cmd: 'q' quits, everything else is passed with one argument byte. */
static int f583_cmd(struct f583_conn *C, int cmd, int arg)
{
	unsigned char c[2];

	c[0] = (unsigned char)cmd;
	c[1] = (unsigned char)arg;
	if (write(C->dn[1], c, 2) != 2)
		return -2;
	return f583_wait_byte(C->up[0], 8000) < 0 ? -3 : 0;
}

static int f583_veth_ns(const char *a, const char *b, int pid)
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

static int f583_v6dev(const char *dev, int fwd)
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

static int f583_route6(const unsigned char *gw, const char *dev)
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
	req.rtm.rtm_table = 254;	/* RT_TABLE_MAIN */
	req.rtm.rtm_protocol = 4;	/* RTPROT_STATIC */
	req.rtm.rtm_scope = 0;		/* RT_SCOPE_UNIVERSE */
	req.rtm.rtm_type = 1;		/* RTN_UNICAST */
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
static void f583_child_s(void)
{
	unsigned char msg[8], c[2];
	unsigned char frA[128], frB[128];
	char hx[512];
	int s6, i, rc, lA, lB;

	close(F583_S.up[0]);
	close(F583_S.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F583 CHILDS|unshare=%d\n", errno);
		_exit(1);
	}
	c[0] = 'U';
	if (write(F583_S.up[1], c, 1) != 1)
		_exit(2);
	if (read(F583_S.dn[0], msg, 7) != 7 || msg[0] != 'M')
		_exit(3);
	memcpy(F583_X0M, msg + 1, 6);
	set_up("lo");
	for (i = 0; i < 200 && f555_ifindex("x1") < 0; i++)
		usleep(20000);
	set_up("x1");
	(void)f583_v6dev("x1", 0);
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	rc = f564_addr6("x1", A83_S6, 64);
	rc |= f583_route6(A83_R6, "x1");
	i = mac_get("x1", F583_X1M);
	lA = f583_mk6(frA, F583_X0M, F583_X1M, A83_DA);
	lB = f583_mk6(frB, F583_X0M, F583_X1M, A83_DB);
	s6 = f564_udp_bind(AF_INET6, 0, A83_S6, F583_SPORT);
	printf("F583 CHILDS|rc=%d|macrc=%d|x1=%d|s6=%d|lA=%d|lB=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|m1=%02x%02x%02x%02x%02x%02x\n",
	       rc, i, f555_ifindex("x1"), s6, lA, lB,
	       F583_X0M[0], F583_X0M[1], F583_X0M[2], F583_X0M[3],
	       F583_X0M[4], F583_X0M[5], F583_X1M[0], F583_X1M[1],
	       F583_X1M[2], F583_X1M[3], F583_X1M[4], F583_X1M[5]);
	printf("F583 FRMPY|id=a|len=%d|hex=%s\n", lA,
	       f559_hexs(hx, sizeof(hx), frA, lA));
	printf("F583 FRMPY|id=b|len=%d|hex=%s\n", lB,
	       f559_hexs(hx, sizeof(hx), frB, lB));
	c[0] = 'R';
	if (write(F583_S.up[1], c, 1) != 1)
		_exit(4);
	for (;;) {
		struct sockaddr_in6 d6;

		if (read(F583_S.dn[0], c, 2) != 2)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		if (c[0] == 's') {
			memset(&d6, 0, sizeof(d6));
			d6.sin6_family = AF_INET6;
			memcpy(&d6.sin6_addr, c[1] == 'a' ? A83_DA : A83_DB, 16);
			d6.sin6_port = htons(F583_DPORT);
			rc = (int)sendto(s6, frA + 62, F583_PAY, 0,
					 (struct sockaddr *)&d6, sizeof(d6));
			printf("F583 CHILDS|cmd=s%c|rc=%d|errno=%d\n", c[1], rc,
			       rc < 0 ? errno : 0);
		} else if (c[0] == 'p') {
			rc = f583_send_frame(c[1] == 'a' ? frA : frB,
					     c[1] == 'a' ? lA : lB, "x1");
			printf("F583 CHILDS|cmd=p%c|rc=%d\n", c[1], rc);
		}
		c[0] = 'D';
		if (write(F583_S.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* the receiver: the far end.  Never returns. */
static void f583_child_d(void)
{
	static unsigned char buf[2048];
	static unsigned char cb[256];
	unsigned char msg[8], c;
	struct f583_tap t3, t4;
	struct f580_sn a, b;
	int i, rc, s;

	close(F583_D.up[0]);
	close(F583_D.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F583 CHILDD|unshare=%d\n", errno);
		_exit(1);
	}
	c = 'U';
	if (write(F583_D.up[1], &c, 1) != 1)
		_exit(2);
	if (read(F583_D.dn[0], msg, 1) != 1)
		_exit(3);
	set_up("lo");
	for (i = 0; i < 400 && f555_ifindex("y3") < 0; i++)
		usleep(20000);
	set_up("y3");
	set_up("y4");
	(void)f583_v6dev("y3", 0);
	(void)f583_v6dev("y4", 0);
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	rc = f564_addr6("y3", A83_DA, 64);
	rc |= f564_addr6("y4", A83_DB, 64);
	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s >= 0) {
		int one = 1;
		struct sockaddr_in6 sa;

		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one,
			   sizeof(one));
		memset(&sa, 0, sizeof(sa));
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(F583_DPORT);
		if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)
			s = -errno;
	}
	memset(&t3, 0, sizeof(t3));
	memset(&t4, 0, sizeof(t4));
	t3.fd = f578_tap_open_aux("y3");
	t4.fd = f578_tap_open_aux("y4");
	t3.only_out = 0;
	t4.only_out = 0;
	printf("F583 CHILDD|rc=%d|s=%d|y3=%d|y4=%d|t3=%d|t4=%d\n", rc, s,
	       f555_ifindex("y3"), f555_ifindex("y4"), t3.fd, t4.fd);
	c = 'R';
	if (write(F583_D.up[1], &c, 1) != 1)
		_exit(4);
	for (;;) {
		fd_set rf;
		struct timeval tv;
		struct msghdr m;
		struct iovec iov;
		struct sockaddr_in6 from;
		char payh[512] = "-", t3h[512] = "-", t4h[512] = "-";
		char tmp[512];
		int n = 0, ifidx = -1, sport = -1, r;

		if (read(F583_D.dn[0], &c, 1) != 1)
			_exit(0);
		if (c == 'q')
			_exit(0);
		if (c != 'r')
			continue;
		f580_snmp(&a);
		if (s >= 0) {
			FD_ZERO(&rf);
			FD_SET(s, &rf);
			tv.tv_sec = 0;
			tv.tv_usec = 400000;
			r = select(s + 1, &rf, NULL, NULL, &tv);
		} else {
			r = 0;
		}
		if (r > 0) {
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
			r = (int)recvmsg(s, &m, MSG_DONTWAIT);
			if (r >= 0) {
				struct cmsghdr *cm;
				int len = r > 64 ? 64 : r;

				n = 1;
				f559_hexs(tmp, sizeof(tmp), buf, len);
				snprintf(payh, sizeof(payh), "%s", tmp);
				sport = ntohs(from.sin6_port);
				for (cm = CMSG_FIRSTHDR(&m); cm;
				     cm = CMSG_NXTHDR(&m, cm)) {
					struct f583_pktinfo *pi;

					if (cm->cmsg_level != IPPROTO_IPV6 ||
					    cm->cmsg_type != IPV6_PKTINFO)
						continue;
					pi = (struct f583_pktinfo *)CMSG_DATA(cm);
					ifidx = (int)pi->ipi6_ifindex;
				}
			} else {
				n = -1;
			}
		}
		usleep(60000);
		f583_tap_drain(&t3);
		f583_tap_drain(&t4);
		if (t3.len > 0) {
			f559_hexs(tmp, sizeof(tmp), t3.b, t3.len);
			snprintf(t3h, sizeof(t3h), "%s", tmp);
		}
		if (t4.len > 0) {
			f559_hexs(tmp, sizeof(tmp), t4.b, t4.len);
			snprintf(t4h, sizeof(t4h), "%s", tmp);
		}
		f580_snmp(&b);
		/* ABSOLUTE counters, not deltas: the datagram is delivered
		 * before this command is even read, so a snapshot taken here
		 * is already after the fact (smoke a printed rcv=0/deliv=0 for
		 * every arm).  The verifier differences arm k against arm k-1.*/
		printf("F583 RCV|n=%d|sport=%d|ifidx=%d|ifname=%s|pay=%s|"
		       "t3n=%d|t3len=%d|t3stat=%d|t3=%s|"
		       "t4n=%d|t4len=%d|t4stat=%d|t4=%s|"
		       "u6in=%llu|u6err=%llu|rcv=%llu|"
		       "deliv=%llu|hdr=%llu|addr=%llu|disc=%llu|noroute=%llu|"
		       "uk=%llu\n",
		       n, sport, ifidx, f580_ifname(ifidx), payh,
		       t3.n, t3.len, t3.stat, t3h,
		       t4.n, t4.len, t4.stat, t4h,
		       b.udp, b.udperr,
		       b.rcv, b.deliv, b.hdrerr,
		       b.addrerr, b.disc,
		       b.noroutes, b.ukproto);
		fflush(stdout);
		c = 'D';
		if (write(F583_D.up[1], &c, 1) != 1)
			_exit(5);
	}
}

/* ---------- the arms ---------------------------------------------------- */

struct f583_arm {
	const char *name;
	char prov;		/* 's' socket datagram, 'p' AF_PACKET frame */
	char dst;		/* 'a' fd03::92 via y1, 'b' fd04::92 via y2 */
	int base;
	int store;
	unsigned int off, len;
	const char *hex;
	int ct;
	unsigned int co;
	unsigned int cf;
};

static const struct f583_arm AF583[] = {
	/* --- census: no rule, both devices, both provenances --------------- */
	{ "c_s_a",	's', 'a', 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_s_b",	's', 'b', 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_p_a",	'p', 'a', 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_p_b",	'p', 'b', 0, 0, 0, 0, NULL, 0, 0, 0 },
	/* --- A: a store in the payload, socket provenance ------------------ */
	{ "w_s_a",	's', 'a', B583_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "w_s_b",	's', 'b', B583_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "wcs_s_a",	's', 'a', B583_TH, 1, 8, 4, "a0a1a2a3",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	{ "wcs_s_b",	's', 'b', B583_TH, 1, 8, 4, "a0a1a2a3",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	{ "wfl_s_a",	's', 'a', B583_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 1 },
	{ "wfl_s_b",	's', 'b', B583_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 1 },
	/* --- B: the store covers the checksum field itself ----------------- */
	{ "d_s_a",	's', 'a', B583_TH, 1, 6, 2, "dead", 0, 0, 0 },
	{ "d_s_b",	's', 'b', B583_TH, 1, 6, 2, "dead", 0, 0, 0 },
	{ "d_p_a",	'p', 'a', B583_TH, 1, 6, 2, "dead", 0, 0, 0 },
	{ "d_p_b",	'p', 'b', B583_TH, 1, 6, 2, "dead", 0, 0, 0 },
	/* --- C: the same payload store, packet provenance ------------------ */
	{ "w_p_a",	'p', 'a', B583_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "w_p_b",	'p', 'b', B583_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "wcs_p_a",	'p', 'a', B583_TH, 1, 8, 4, "a0a1a2a3",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	/* --- D: a field the L4 sum covers, but not the pseudo header ------ */
	{ "sp_s_a",	's', 'a', B583_TH, 1, 0, 2, "beef", 0, 0, 0 },
	{ "sp_s_b",	's', 'b', B583_TH, 1, 0, 2, "beef", 0, 0, 0 },
	/* --- E: a field the pseudo header covers --------------------------- */
	{ "n_s_a",	's', 'a', B583_NH, 1, 8, 16, NULL, 0, 0, 0 },
	{ "n_s_b",	's', 'b', B583_NH, 1, 8, 16, NULL, 0, 0, 0 },
	{ "ncs_s_b",	's', 'b', B583_NH, 1, 8, 16, NULL,
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	/* --- F: the field the payer trusts ---------------------------------- */
	{ "dz_s_b",	's', 'b', B583_TH, 1, 6, 2, "fad5", 0, 0, 0 },
	/* --- G: the same stores in the CHECKSUM_NONE world ------------------ */
	{ "wfl_p_a",	'p', 'a', B583_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 1 },
	{ "sp_p_a",	'p', 'a', B583_TH, 1, 0, 2, "beef", 0, 0, 0 },
};
#define NAF583 ((int)(sizeof(AF583) / sizeof(AF583[0])))

static int f583_imm(const struct f583_arm *A, unsigned char *imm)
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
		imm[i] = A83_NEW[i];
	return n;
}

/* [meta l4proto 17] counter [store] log accept */
static int f583_rule(const struct f583_arm *A, int idx,
		     const unsigned char *imm, int immlen)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs, *e, *d;
	char pre[16];
	int acks = 0;

	snprintf(pre, sizeof(pre), "83:%02d", idx);
	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			NFPROTO_IPV6);
	put_str(nlh, NFTA_RULE_TABLE, "f83p");
	put_str(nlh, NFTA_RULE_CHAIN, "fwd");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	{
		unsigned char l4 = 17;

		f567_meta_l4(nlh);
		f562_cmp(nlh, F562_RD_DREG, &l4, 1);
	}
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
	log_expr(nlh, F583_GROUP, pre);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

static void f583_arm(const struct f583_arm *A, int idx)
{
	struct f580_sn a, b;
	struct f575_pl pl;
	unsigned char imm[64];
	char hxi[512] = "-", lgh[512] = "-";
	char ph[512] = "-", qh[512] = "-";
	char lgh2[512] = "-";
	int rc = -99, ilen = -1, ch = -1, nl = 0, lglen = -1, i, cmdrc = 0;
	int acks = 0;

	(void)f557_flush(NFPROTO_IPV6, "f83p", "fwd", &acks);
	f583_tap_drain(&F583_TA);
	f583_tap_drain(&F583_TB);
	f575_nfl_drain(&pl);
	if (A->store) {
		ilen = f583_imm(A, imm);
		rc = ilen < 0 ? -99 : f583_rule(A, idx, imm, ilen);
		f559_hexs(hxi, sizeof(hxi), imm, ilen > 0 ? ilen : 0);
	} else {
		rc = f583_rule(A, idx, NULL, 0);
	}
	f580_snmp(&a);
	cmdrc |= f583_cmd(&F583_S, A->prov == 's' ? 's' : 'p', A->dst);
	cmdrc |= f583_cmd(&F583_D, 'r', 0) ? 4 : 0;
	usleep(120000);
	f583_tap_drain(&F583_TA);
	f583_tap_drain(&F583_TB);
	f575_nfl_drain(&pl);
	f580_snmp(&b);
	ch = (int)f555_count(NFPROTO_IPV6, "f83p", "fwd");
	for (i = 0; i < pl.n && i < F575_NPL; i++) {
		if (!strncmp(pl.m[i].prefix, "83:", 3) && !nl) {
			struct f575_msg *M = &pl.m[i];

			nl = 1;
			lglen = M->plen;
			f559_hexs(lgh, sizeof(lgh), M->p, M->plen);
			snprintf(lgh2, sizeof(lgh2), "in=%d:out=%d:hw=%d:%d",
				 M->indev, M->outdev, M->hwtype, M->hwlen);
		}
	}
	if (F583_TA.len > 0)
		f559_hexs(ph, sizeof(ph), F583_TA.b, F583_TA.len);
	if (F583_TB.len > 0)
		f559_hexs(qh, sizeof(qh), F583_TB.b, F583_TB.len);
	printf("F583 ARM|i=%02d|name=%s|prov=%c|dst=%c|base=%d|store=%d|off=%u|"
	       "len=%u|hex=%s|ct=%d|co=%u|cf=%u|rc=%d|cmdrc=%d|ch=%d|nl=%d|"
	       "lglen=%d|lg=%s|lgh=%s|"
	       "an=%d|anall=%d|alen=%d|astat=%d|a=%s|"
	       "bn=%d|bnall=%d|blen=%d|bstat=%d|b=%s|"
	       "rcv=%llu|deliv=%llu|hdr=%llu|addr=%llu|disc=%llu|"
	       "noroute=%llu|uk=%llu\n",
	       idx, A->name, A->prov, A->dst, A->base, A->store, A->off,
	       A->len, hxi, A->ct, A->co, A->cf, rc, cmdrc, ch, nl,
	       lglen, lgh, lgh2,
	       F583_TA.n, F583_TA.nall, F583_TA.len, F583_TA.stat, ph,
	       F583_TB.n, F583_TB.nall, F583_TB.len, F583_TB.stat, qh,
	       b.rcv - a.rcv, b.deliv - a.deliv, b.hdrerr - a.hdrerr,
	       b.addrerr - a.addrerr, b.disc - a.disc,
	       b.noroutes - a.noroutes, b.ukproto - a.ukproto);
	fflush(stdout);
}

/* ---------- mode fwd ---------------------------------------------------- */

static int f583_fwd(void)
{
	static const char *old[] = { "x0", "x1", "y1", "y3", "y2", "y4" };
	struct f578_gf g;
	unsigned char msg[8];
	int i, rc, r1, r2;

	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv4/ip_forward", "0");
	for (i = 0; i < 6; i++)
		f558_link_del(old[i]);
	{
		int acks = 0;

		(void)f557_flush(NFPROTO_IPV6, "f83p", "fwd", &acks);
		(void)f583_deltable(NFPROTO_IPV6, "f83p");
	}
	if (pipe(F583_S.up) || pipe(F583_S.dn) || pipe(F583_D.up) ||
	    pipe(F583_D.dn)) {
		printf("F583 FAIL|pipe\n");
		return -1;
	}
	F583_S.pid = fork();
	if (F583_S.pid < 0) {
		printf("F583 FAIL|fork\n");
		return -1;
	}
	if (F583_S.pid == 0)
		f583_child_s();
	F583_D.pid = fork();
	if (F583_D.pid < 0) {
		printf("F583 FAIL|fork2\n");
		return -1;
	}
	if (F583_D.pid == 0)
		f583_child_d();
	close(F583_S.up[1]);
	close(F583_S.dn[0]);
	close(F583_D.up[1]);
	close(F583_D.dn[0]);
	if (f583_wait_byte(F583_S.up[0], 5000) != 'U') {
		printf("F583 FAIL|senderns\n");
		return -1;
	}
	if (f583_wait_byte(F583_D.up[0], 5000) != 'U') {
		printf("F583 FAIL|recvns\n");
		return -1;
	}
	rc = f583_veth_ns("x0", "x1", (int)F583_S.pid);
	rc |= f583_veth_ns("y1", "y3", (int)F583_D.pid);
	rc |= f583_veth_ns("y2", "y4", (int)F583_D.pid);
	if (rc) {
		printf("F583 FAIL|veth|rc=%d\n", rc);
		return -1;
	}
	set_up("x0");
	set_up("y1");
	set_up("y2");
	(void)f583_v6dev("x0", 1);
	(void)f583_v6dev("y1", 1);
	(void)f583_v6dev("y2", 1);
	rc = f564_addr6("x0", A83_R6, 64);
	rc |= f564_addr6("y1", A83_RA, 64);
	rc |= f564_addr6("y2", A83_RB, 64);
	mac_get("x0", F583_X0M);
	msg[0] = 'M';
	memcpy(msg + 1, F583_X0M, 6);
	if (write(F583_S.dn[1], msg, 7) != 7) {
		printf("F583 FAIL|mactx\n");
		return -1;
	}
	{
		unsigned char c = 'R';

		if (write(F583_D.dn[1], &c, 1) != 1) {
			printf("F583 FAIL|dsync\n");
			return -1;
		}
	}
	if (f583_wait_byte(F583_S.up[0], 8000) != 'R' ||
	    f583_wait_byte(F583_D.up[0], 8000) != 'R') {
		printf("F583 FAIL|childready\n");
		return -1;
	}
	/* the bit: y1 keeps HW_CSUM, y2 loses it */
	r1 = f578_feat_set("y1", F583_HWCSUM_BIT, 1);
	r2 = f578_feat_set("y2", F583_HWCSUM_BIT, 0);
	printf("F583 FEAT|r1=%d|r2=%d\n", r1, r2);
	f578_feat_get("y1", &g);
	printf("F583 FEAT|dev=y1|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y2", &g);
	printf("F583 FEAT|dev=y2|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	(void)f579_tbl(NFPROTO_IPV6, "f83p");
	{
		int k = 0;

		k |= f580_chn(NFPROTO_IPV6, "f83p", "fwd", NULL,
			      NF_INET_FORWARD, 0);
		printf("F583 CHAINS|rc=%d\n", k);
	}
	F573_NFL = nfl_open(F583_GROUP);
	F583_NFL = F573_NFL;
	memset(&F583_TA, 0, sizeof(F583_TA));
	memset(&F583_TB, 0, sizeof(F583_TB));
	F583_TA.fd = f578_tap_open_aux("y1");
	F583_TB.fd = f578_tap_open_aux("y2");
	F583_TA.only_out = 1;
	F583_TB.only_out = 1;
	printf("F583 ENV|x0=%d|y1=%d|y2=%d|nfl=%d|ta=%d|tb=%d|addr=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|hwcsumbit=%d\n",
	       f555_ifindex("x0"), f555_ifindex("y1"), f555_ifindex("y2"),
	       F573_NFL, F583_TA.fd, F583_TB.fd, rc, F583_X0M[0],
	       F583_X0M[1], F583_X0M[2], F583_X0M[3], F583_X0M[4],
	       F583_X0M[5], F583_HWCSUM_BIT);
	for (i = 0; i < NAF583; i++)
		f583_arm(&AF583[i], i);
	(void)f583_cmd(&F583_S, 'q', 0);
	(void)f583_cmd(&F583_D, 'q', 0);
	printf("F583 END|mode=fwd|arms=%d\n", NAF583);
	fflush(stdout);
	return 0;
}

/* ---------- entry ------------------------------------------------------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "fwd";

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("F583 BOOT|mode=%s|argc=%d\n", mode, argc);
	if (!strcmp(mode, "fwd"))
		return f583_fwd();
	return f582_entry(argc, argv);
}
