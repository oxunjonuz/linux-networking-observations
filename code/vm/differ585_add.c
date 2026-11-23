/* differ585_add.c -- turn 585 (F63): THE AGGREGATE IS A PACKET THE RULE DID
 * NOT SEND -- GRO DECIDES WHAT THE RULE READS, AND THE SPLITTER THAT COPIES
 * NOTHING BILLS NOBODY.
 *
 * The debt named in F62 §11, word for word: the SKB_GSO_FRAGLIST branch
 * (udp_rcv_segment() -> __udp_gso_segment_list() -> skb_segment_list()) was
 * never reached, "it needs GRO at the receiver, not a GSO frame on the wire".
 *
 * GRO needs two per-device bits that are OFF by default
 * (NETIF_F_SOFT_FEATURES_OFF): rx-gro-list (GRO_FRAGLIST, bit 57) and
 * rx-udp-gro-forwarding (GRO_UDP_FWD, bit 59).  For a plain UDP flow there is
 * no socket in udp_gro_receive() (sk == NULL unless a UDP tunnel registered),
 * so with neither bit udp_gro_receive() flushes; with GRO_UDP_FWD the
 * aggregate is LINEAR (skb_gro_receive); with GRO_FRAGLIST it is a FRAGLIST
 * (skb_gro_receive_list).  Three datagrams become ONE packet for the stack in
 * both shapes -- but not the same packet: in the fraglist only the FIRST
 * datagram is linear data, the other two are separate skbs in frag_list.
 *
 * Topology (three netns; the parent is THE ROUTER):
 *   parent: x0 fd02::91/64 (ingress from S), y1 fd03::91/64, y2 fd04::91/64.
 *           ip6 table f85p, chains `out` (hook output prio 0) and `fwd` (hook
 *           forward prio 0); one rule per arm:
 *           [meta l4proto 17] counter [store] log(86:NN) accept.
 *   S: x1 fd02::11/64, default via fd02::91.  Three datagrams of 512 bytes
 *      from one socket (src 'F'), or three hand-built AF_PACKET frames with
 *      correct checksums (src 'P'), or -- for src 'L' -- the ROUTER ITSELF
 *      sends the three datagrams through its own output chain.
 *   D: y3 fd03::92/64, y4 fd04::92/64; sockets on 5000 (plain) and 5001
 *      (UDP_GRO); a witness chain in ITS OWN netns (ip6 prerouting prio 0)
 *      with three counters keyed on the IPv6 payload length:
 *        0x0608 = 1544 = an aggregate of three, 0x0208 = 520 = one datagram.
 *
 * GRO is made deterministic by gro_flush_timeout (20 ms) on the device that
 * aggregates: the GRO list is kept between NAPI polls, so three sendto()s in a
 * row land in one aggregate instead of three.
 *
 * Every arm prints: the rule's counter, the NFLOG payload (the aggregate's own
 * bytes, 1584 of them, with each datagram's IPv6+UDP header readable), both
 * egress taps frame by frame (length, IPv6 payload length, hop limit, UDP
 * length and checksum, bytes), and from D: the witness counters, the socket's
 * datagrams, its taps and its snmp deltas.
 */

#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>

#define F585_GROUP	86
#define F585_SPORT	43580
#define F585_DPORT	5000
#define F585_DPORT_G	5001
#define F585_P		512		/* payload bytes per datagram */
#define F585_N		3		/* datagrams per arm */
#define F585_FRAME	(14 + 40 + 8 + F585_P)		/* 574 */
#define F585_AGGR	(40 + 8 + F585_N * F585_P)	/* 1584 */
#define F585_TAPN	4
#define F585_TAPB	760
#define B585_TH		2
#define F585_HWCSUM_BIT	3
#define F585_GSOUDP_BIT	33
#define F585_TSO_BIT	16
#define F585_TSOECN_BIT	18
#define F585_TSOMID_BIT	19
#define F585_TSO6_BIT	20
#define F585_GSOFL_BIT	34	/* NETIF_F_GSO_FRAGLIST_BIT */
#define F585_GROFL_BIT	57	/* NETIF_F_GRO_FRAGLIST_BIT */
#define F585_GROFWD_BIT	59	/* NETIF_F_GRO_UDP_FWD_BIT */

#ifndef UDP_GRO
#define UDP_GRO		104
#endif
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO	49
#endif
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO		50
#endif
struct f585_pktinfo {
	struct in6_addr ipi6_addr;
	unsigned int ipi6_ifindex;
};

static const unsigned char A85_S6[16] = { 0xfd, 0x02, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x11 };
static const unsigned char A85_R6[16] = { 0xfd, 0x02, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x91 };
static const unsigned char A85_DA[16] = { 0xfd, 0x03, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x92 };
static const unsigned char A85_DB[16] = { 0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x92 };
static const unsigned char A85_RA[16] = { 0xfd, 0x03, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x91 };
static const unsigned char A85_RB[16] = { 0xfd, 0x04, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x91 };
static unsigned char F585_X0M[6], F585_X1M[6], F585_Y3M[6], F585_Y4M[6];
static unsigned char F585_PAY[F585_N][F585_P];

/* ---------- arithmetic ------------------------------------------------ */

static uint32_t f585_sum32(const unsigned char *b, int n)
{
	uint32_t s = 0;
	int i;

	for (i = 0; i + 1 < n; i += 2)
		s += ((uint32_t)b[i] << 8) | b[i + 1];
	if (n & 1)
		s += (uint32_t)b[n - 1] << 8;
	return s;
}

static unsigned short f585_fold(uint32_t s)
{
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (unsigned short)(s & 0xffff);
}

/* the PARTIAL field a socket writes for a datagram of udplen bytes:
 * ~csum_ipv6_magic(saddr, daddr, udplen, 17, 0), folded. */
static unsigned short f585_seed(const unsigned char *saddr,
				const unsigned char *daddr, int udplen)
{
	unsigned char ph[40];

	memcpy(ph, saddr, 16);
	memcpy(ph + 16, daddr, 16);
	memset(ph + 32, 0, 8);
	ph[34] = (unsigned char)((udplen >> 8) & 0xff);
	ph[35] = (unsigned char)(udplen & 0xff);
	ph[39] = 17;
	return f585_fold(f585_sum32(ph, 40));
}

static unsigned short f585_correct(const unsigned char *saddr,
				   const unsigned char *daddr,
				   unsigned short sport, unsigned short dport,
				   int udplen, const unsigned char *pay, int n)
{
	unsigned char h[8], ph[40];
	uint32_t s;

	h[0] = (unsigned char)(sport >> 8);
	h[1] = (unsigned char)(sport & 0xff);
	h[2] = (unsigned char)(dport >> 8);
	h[3] = (unsigned char)(dport & 0xff);
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
	s = f585_sum32(h, 8) + f585_sum32(pay, n) + f585_sum32(ph, 40);
	return (unsigned short)(~f585_fold(s) & 0xffff);
}

/* ---------- frames ---------------------------------------------------- */

static int f585_mkframe(unsigned char *out, const unsigned char *dmac,
			const unsigned char *smac, const unsigned char *daddr,
			unsigned short dport, int seq)
{
	unsigned short c;
	int udplen = 8 + F585_P;

	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	out[14] = 0x60;
	out[15] = 0;
	out[16] = 0;
	out[17] = 0;
	out[18] = (unsigned char)((udplen >> 8) & 0xff);
	out[19] = (unsigned char)(udplen & 0xff);
	out[20] = 17;
	out[21] = 64;
	memcpy(out + 22, A85_S6, 16);
	memcpy(out + 38, daddr, 16);
	out[54] = (unsigned char)(F585_SPORT >> 8);
	out[55] = (unsigned char)(F585_SPORT & 0xff);
	out[56] = (unsigned char)(dport >> 8);
	out[57] = (unsigned char)(dport & 0xff);
	out[58] = (unsigned char)((udplen >> 8) & 0xff);
	out[59] = (unsigned char)(udplen & 0xff);
	out[60] = 0;
	out[61] = 0;
	memcpy(out + 62, F585_PAY[seq], F585_P);
	c = f585_correct(A85_S6, daddr, F585_SPORT, dport, udplen,
			 out + 62, F585_P);
	out[60] = (unsigned char)(c >> 8);
	out[61] = (unsigned char)(c & 0xff);
	return F585_FRAME;
}

static int f585_send_frame(const unsigned char *f, int flen, const char *dev)
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

/* our datagrams only: ethertype IPv6, next header UDP, destination port in
 * {5000,5001}, destination address in {fd03::92, fd04::92} */
static int f585_isours(const unsigned char *b, int r)
{
	int dport;

	if (r < 62)
		return 0;
	if (b[12] != 0x86 || b[13] != 0xdd)
		return 0;
	if (b[20] != 17)
		return 0;
	dport = (b[56] << 8) | b[57];
	if (dport != F585_DPORT && dport != F585_DPORT_G)
		return 0;
	if (memcmp(b + 38, A85_DA, 16) && memcmp(b + 38, A85_DB, 16))
		return 0;
	return 1;
}

/* ---------- a multi-frame tap ----------------------------------------- */

struct f585_tap {
	int fd;
	int only_out;
	int nall;
	int n;
	int flen[F585_TAPN];
	int len[F585_TAPN];
	int stat[F585_TAPN];
	unsigned char b[F585_TAPN][F585_TAPB];
};

static void f585_tap_zero(struct f585_tap *T)
{
	T->nall = 0;
	T->n = 0;
	memset(T->flen, 0, sizeof(T->flen));
	memset(T->len, 0, sizeof(T->len));
	memset(T->stat, 0, sizeof(T->stat));
}

static void f585_tap_drain(struct f585_tap *T)
{
	static unsigned char b[F585_TAPB + 64];
	static unsigned char cb[256];

	f585_tap_zero(T);
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
		r = (int)recvmsg(T->fd, &msg, MSG_DONTWAIT | MSG_TRUNC);
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
		if (!f585_isours(b, r))
			continue;
		if (T->n >= F585_TAPN) {
			T->n++;
			continue;
		}
		k = T->n++;
		T->flen[k] = r;
		T->len[k] = r < F585_TAPB ? r : F585_TAPB;
		if (T->len[k] > (int)sizeof(b))
			T->len[k] = (int)sizeof(b);
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

/* the fields of one frame that decide its fate, then its bytes */
static void f585_tap_print(const struct f585_tap *T, int idx, const char *dev)
{
	static const char hexd[] = "0123456789abcdef";
	static char hx[2 * F585_TAPB + 8];
	int k, i;

	for (k = 0; k < T->n && k < F585_TAPN; k++) {
		int at = 0, f = T->len[k];
		int iplen = f > 19 ? ((T->b[k][18] << 8) | T->b[k][19]) : -1;
		int hop = f > 21 ? T->b[k][21] : -1;
		int uhlen = f > 59 ? ((T->b[k][58] << 8) | T->b[k][59]) : -1;
		int uhck = f > 61 ? ((T->b[k][60] << 8) | T->b[k][61]) : -1;

		for (i = 0; i < T->len[k] && at + 3 < (int)sizeof(hx); i++) {
			hx[at++] = hexd[(T->b[k][i] >> 4) & 0xf];
			hx[at++] = hexd[T->b[k][i] & 0xf];
		}
		hx[at] = 0;
		printf("F585 TAP|i=%02d|dev=%s|k=%d|flen=%d|len=%d|trunc=%d|"
		       "iplen=%d|hop=%d|uhlen=%d|uhck=%04x|stat=%d|hex=%s\n",
		       idx, dev, k, T->flen[k], T->len[k],
		       T->flen[k] > T->len[k] ? 1 : 0, iplen, hop, uhlen,
		       uhck < 0 ? 0 : uhck, T->stat[k], hx);
	}
	if (T->n > F585_TAPN)
		printf("F585 TAPX|i=%02d|dev=%s|n=%d\n", idx, dev, T->n);
}

/* ---------- children --------------------------------------------------- */

struct f585_conn {
	int up[2], dn[2];
	pid_t pid;
};

static struct f585_conn F585_S, F585_C;
static struct f585_tap F585_TA, F585_TB;
static int F585_NFL = -1;

static int f585_wait_byte(int fd, int ms)
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

static int f585_cmd(struct f585_conn *C, int cmd, int a1, int a2)
{
	unsigned char c[3];

	c[0] = (unsigned char)cmd;
	c[1] = (unsigned char)a1;
	c[2] = (unsigned char)a2;
	if (write(C->dn[1], c, 3) != 3)
		return -2;
	return f585_wait_byte(C->up[0], 20000) < 0 ? -3 : 0;
}

static int f585_veth_ns(const char *a, const char *b, int pid)
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

static int f585_v6dev(const char *dev, int fwd)
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

#define F585_IFA_F_NODAD	0x02

static int f585_addr6_nodad(const char *dev, const unsigned char *a, int plen)
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
	req.ifa.ifa_flags = F585_IFA_F_NODAD;
	attr_put(&req.nlh, IFA_LOCAL, a, 16);
	attr_put(&req.nlh, IFA_ADDRESS, a, 16);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

static int f585_route6(const unsigned char *gw, const char *dev)
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

static int F585_SYS2 = -1;

/* /sys was mounted by init in the netns it was mounted in, so a fresh netns
 * sees the WRONG devices under /sys/class/net.  A second sysfs mounted from
 * inside the child shows the child's own. */
static void f585_mount_sys2(void)
{
	DIR *d;
	struct dirent *e;
	int rc, k = 0, mk;
	char names[160] = "";

	mk = mkdir("/sys2", 0755);
	rc = mount("sysfs", "/sys2", "sysfs", 0, NULL);
	F585_SYS2 = rc ? -1 : 0;
	printf("F585 SYS2|rc=%d|errno=%d|mkdir=%d\n", rc, rc ? errno : 0, mk);
	d = opendir("/sys2/class/net");
	if (!d) {
		printf("F585 SYS2LS|errno=%d\n", errno);
		return;
	}
	while ((e = readdir(d)) && k < 8) {
		if (e->d_name[0] == '.')
			continue;
		strncat(names, e->d_name, 20);
		strncat(names, ",", 2);
		k++;
	}
	closedir(d);
	printf("F585 SYS2LS|n=%d|names=%s\n", k, names);
}

static int F585_E1 = -1, F585_E2 = -1;

static int f585_sysw(const char *fmt, const char *dev, const char *name,
		     const char *v)
{
	char p[160];
	int rc;

	F585_E1 = -1;
	F585_E2 = -1;
	snprintf(p, sizeof(p), fmt, F585_SYS2 == 0 ? "/sys2" : "/sys", dev,
		 name);
	rc = f555_sysctl(p, v);
	if (rc)
		F585_E1 = errno;
	if (rc && F585_SYS2 == 0) {
		snprintf(p, sizeof(p), fmt, "/sys", dev, name);
		rc = f555_sysctl(p, v);
		if (rc)
			F585_E2 = errno;
	}
	return rc;
}

static int f585_mtu_nl(const char *dev, unsigned int mtu)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[64];
	} req;
	int fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = f555_ifindex(dev);
	attr_put(&req.nlh, IFLA_MTU, &mtu, 4);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

#define F585_GRO_BIT	14	/* NETIF_F_GRO_BIT: the master switch */

static void f585_mtu(const char *dev, const char *v)
{
	int rc;

	f585_sysw("%s/class/net/%s/mtu", dev, "", v);	/* may ENOENT */
	rc = f585_mtu_nl(dev, (unsigned int)atoi(v));
	if (rc)
		printf("F585 MTUFAIL|dev=%s|v=%s|rc=%d|errno=%d\n", dev, v, rc,
		       errno);
}

static void f585_groto(const char *dev, const char *ns)
{
	int r1, r2;

	r1 = f585_sysw("%s/class/net/%s/gro_flush_timeout", dev, "", ns);
	r2 = f585_sysw("%s/class/net/%s/napi_defer_hard_irqs", dev, "", "1");
	if (r1 || r2)
		printf("F585 GROTOFAIL|dev=%s|to=%d|defer=%d|e1=%d|e2=%d\n",
		       dev, r1, r2, F585_E1, F585_E2);
}

/* the sender: THE WIRE.  Never returns. */
static void f585_child_s(void)
{
	unsigned char msg[8], c[3];
	unsigned char fr[F585_FRAME + 8];
	static const unsigned short ports[2] = { F585_DPORT, F585_DPORT_G };
	int s6 = -1, i, k, rc;

	close(F585_S.up[0]);
	close(F585_S.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F585 CHILDS|unshare=%d\n", errno);
		_exit(1);
	}
	c[0] = 'U';
	if (write(F585_S.up[1], c, 1) != 1)
		_exit(2);
	if (read(F585_S.dn[0], msg, 7) != 7 || msg[0] != 'M')
		_exit(3);
	memcpy(F585_X0M, msg + 1, 6);
	set_up("lo");
	for (i = 0; i < 200 && f555_ifindex("x1") < 0; i++)
		usleep(20000);
	set_up("x1");
	f585_mount_sys2();
	(void)f585_v6dev("x1", 0);
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	rc = f585_addr6_nodad("x1", A85_S6, 64);
	rc |= f585_route6(A85_R6, "x1");
	rc |= f569_neigh6_add("x1", A85_R6, F585_X0M);
	f585_mtu("x1", "9000");
	i = mac_get("x1", F585_X1M);
	for (k = 0; k < 60; k++) {
		s6 = f564_udp_bind(AF_INET6, 0, A85_S6, F585_SPORT);
		if (s6 >= 0)
			break;
		usleep(50000);
	}
	printf("F585 CHILDS|rc=%d|macrc=%d|x1=%d|s6=%d|errno=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|m1=%02x%02x%02x%02x%02x%02x\n",
	       rc, i, f555_ifindex("x1"), s6, s6 < 0 ? errno : 0,
	       F585_X0M[0], F585_X0M[1], F585_X0M[2], F585_X0M[3],
	       F585_X0M[4], F585_X0M[5], F585_X1M[0], F585_X1M[1],
	       F585_X1M[2], F585_X1M[3], F585_X1M[4], F585_X1M[5]);
	c[0] = 'R';
	if (write(F585_S.up[1], c, 1) != 1)
		_exit(4);
	for (;;) {
		struct sockaddr_in6 d6;
		int psel;

		if (read(F585_S.dn[0], c, 3) != 3)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		psel = c[2] & 1;
		if (c[0] == 's') {
			int n = 0;

			memset(&d6, 0, sizeof(d6));
			d6.sin6_family = AF_INET6;
			memcpy(&d6.sin6_addr, c[1] == 'a' ? A85_DA : A85_DB, 16);
			d6.sin6_port = htons(ports[psel]);
			for (k = 0; k < F585_N; k++) {
				rc = (int)sendto(s6, F585_PAY[k], F585_P, 0,
						 (struct sockaddr *)&d6,
						 sizeof(d6));
				if (rc == F585_P)
					n++;
			}
			printf("F585 CHILDS|cmd=s%c%d|sent=%d|rc=%d|errno=%d\n",
			       c[1], psel, n, rc, rc < 0 ? errno : 0);
		} else if (c[0] == 'p') {
			int n = 0;

			for (k = 0; k < F585_N; k++) {
				int fl = f585_mkframe(fr, F585_X0M, F585_X1M,
						      c[1] == 'a' ? A85_DA :
						      A85_DB, ports[psel], k);

				rc = f585_send_frame(fr, fl, "x1");
				if (rc == fl)
					n++;
			}
			printf("F585 CHILDS|cmd=p%c%d|sent=%d|rc=%d\n",
			       c[1], psel, n, rc);
		}
		c[0] = 'D';
		if (write(F585_S.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* D's witness chain: three counters on the IPv6 payload length, in D's OWN
 * netns, so that "what the receiver's stack saw" is a number, not a story. */
static int f585_wrule(int which)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	unsigned char l4 = 17;
	static const unsigned char p1544[2] = { 0x06, 0x08 };
	static const unsigned char p520[2] = { 0x02, 0x08 };
	int acks = 0;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			NFPROTO_IPV6);
	put_str(nlh, NFTA_RULE_TABLE, "f85d");
	put_str(nlh, NFTA_RULE_CHAIN, "w");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	f567_meta_l4(nlh);
	f562_cmp(nlh, F562_RD_DREG, &l4, 1);
	if (which == 0 || which == 1) {
		f562_read(nlh, F580_B_NH, 4, 2);
		f562_cmp(nlh, F562_RD_DREG, which ? p520 : p1544, 2);
	}
	counter_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

/* every counter of a chain, in rule order */
static int f585_counts(uint8_t family, const char *table, const char *chain,
		       unsigned long long *out, int max)
{
	char buf[1024];
	static char rbuf[65536];
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;
	int fd, sent, n = 0;

	out[0] = out[1] = out[2] = out[3] = 0;
	fd = nl_open();
	if (fd < 0)
		return -1;
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
		return -1;
	}
	for (;;) {
		int rl = (int)recv(fd, rbuf, sizeof(rbuf), 0);
		struct nlmsghdr *h;

		if (rl <= 0)
			break;
		for (h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, rl);
		     h = NLMSG_NEXT(h, rl)) {
			const char *p, *end;

			if (h->nlmsg_type == NLMSG_DONE ||
			    h->nlmsg_type == NLMSG_ERROR)
				goto out;
			if (h->nlmsg_type != (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) |
							NFT_MSG_NEWRULE))
				continue;
			p = (const char *)h + NLMSG_HDRLEN + sizeof(*nfg);
			end = (const char *)h + h->nlmsg_len;
			for (; p + (int)sizeof(struct nlattr) <= end; ) {
				const struct nlattr *a = (const struct nlattr *)p;
				int alen = (int)a->nla_len;

				if (alen < (int)sizeof(*a) || p + alen > end)
					break;
				if ((a->nla_type & 0x3fff) == NFTA_RULE_EXPRESSIONS) {
					const char *q = (const char *)a + NLA_HDRLEN;
					const char *qe = (const char *)a + alen;
					int got = 0;

					for (; q + (int)sizeof(struct nlattr) <= qe && !got; ) {
						const struct nlattr *el =
							(const struct nlattr *)q;
						int ell = (int)el->nla_len;
						const char *r, *re;
						int is_cnt = 0;

						if (ell < (int)sizeof(*el) || q + ell > qe)
							break;
						r = (const char *)el + NLA_HDRLEN;
						re = (const char *)el + ell;
						for (; r + (int)sizeof(struct nlattr) <= re; ) {
							const struct nlattr *ea =
								(const struct nlattr *)r;
							int eal = (int)ea->nla_len;

							if (eal < (int)sizeof(*ea) || r + eal > re)
								break;
							if ((ea->nla_type & 0x3fff) == NFTA_EXPR_NAME &&
							    !strcmp((const char *)ea + NLA_HDRLEN, "counter"))
								is_cnt = 1;
							r += NLA_ALIGN_(eal);
						}
						if (!is_cnt) {
							q += NLA_ALIGN_(ell);
							continue;
						}
						r = (const char *)el + NLA_HDRLEN;
						re = (const char *)el + ell;
						for (; r + (int)sizeof(struct nlattr) <= re; ) {
							const struct nlattr *ea =
								(const struct nlattr *)r;
							int eal = (int)ea->nla_len;

							if (eal < (int)sizeof(*ea) || r + eal > re)
								break;
							if ((ea->nla_type & 0x3fff) == NFTA_EXPR_DATA) {
								const char *d = (const char *)ea + NLA_HDRLEN;
								const char *de = (const char *)ea + eal;

								for (; d + (int)sizeof(struct nlattr) <= de; ) {
									const struct nlattr *da =
										(const struct nlattr *)d;
									int dal = (int)da->nla_len;

									if (dal < (int)sizeof(*da) || d + dal > de)
										break;
									if ((da->nla_type & 0x3fff) == NFTA_COUNTER_PACKETS) {
										int k2, bl = dal - NLA_HDRLEN;
										unsigned long long v = 0;
										const unsigned char *bb =
											(const unsigned char *)da + NLA_HDRLEN;

										for (k2 = 0; k2 < bl && k2 < 8; k2++) {
											if (k2 < bl - 8)
												continue;
											v = (v << 8) | bb[k2];
										}
										if (n < max)
											out[n] = v;
										n++;
										got = 1;
										break;
									}
									d += NLA_ALIGN_(dal);
								}
							}
							r += NLA_ALIGN_(eal);
						}
						q += NLA_ALIGN_(ell);
					}
				}
				p += NLA_ALIGN_(alen);
			}
		}
	}
out:
	close(fd);
	return n;
}

/* the receiver: the far end, and its own witnesses.  Never returns. */
static void f585_child_d(void)
{
	static unsigned char buf[4096];
	static unsigned char cb[256];
	unsigned char msg[16], c[3];
	static struct f585_tap t3, t4;
	struct f580_sn prev, cur;
	unsigned long long cw[4];
	int i, rc, s, sg, wrc = 0;

	close(F585_C.up[0]);
	close(F585_C.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F585 CHILDD|unshare=%d\n", errno);
		_exit(1);
	}
	c[0] = 'U';
	if (write(F585_C.up[1], c, 1) != 1)
		_exit(2);
	if (read(F585_C.dn[0], msg, 1) != 1)
		_exit(3);
	set_up("lo");
	for (i = 0; i < 400 && f555_ifindex("y3") < 0; i++)
		usleep(20000);
	set_up("y3");
	set_up("y4");
	f585_mount_sys2();
	printf("F585 GROSW|y3=%d|y4=%d\n",
	       f578_feat_set("y3", F585_GRO_BIT, 1),
	       f578_feat_set("y4", F585_GRO_BIT, 1));
	(void)f585_v6dev("y3", 0);
	(void)f585_v6dev("y4", 0);
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	rc = f585_addr6_nodad("y3", A85_DA, 64);
	rc |= f585_addr6_nodad("y4", A85_DB, 64);
	f585_mtu("y3", "9000");
	f585_mtu("y4", "9000");
	f585_groto("y3", "20000000");
	f585_groto("y4", "20000000");
	i = mac_get("y3", F585_Y3M);
	i |= mac_get("y4", F585_Y4M);
	{
		char rb[32] = "-";
		int fd = open("/sys2/class/net/y3/gro_flush_timeout", O_RDONLY);
		int n = -1;

		if (fd >= 0) {
			n = (int)read(fd, rb, sizeof(rb) - 1);
			close(fd);
			if (n > 0)
				rb[n - 1] = 0;
		}
		printf("F585 GROTO|fd=%d|val=%s\n", fd, fd >= 0 ? rb : "-");
	}
	s = -1;
	sg = -1;
	{
		unsigned char any[16];
		int one = 1;

		memset(any, 0, sizeof(any));
		s = f564_udp_bind(AF_INET6, 0, any, F585_DPORT);
		if (s >= 0)
			setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one,
				   sizeof(one));
		sg = f564_udp_bind(AF_INET6, 0, any, F585_DPORT_G);
		if (sg >= 0) {
			int gro = 1;

			setsockopt(sg, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one,
				   sizeof(one));
			rc |= setsockopt(sg, IPPROTO_UDP, UDP_GRO, &gro,
					 (socklen_t)sizeof(gro));
		}
	}
	{
		(void)f584_deltable(NFPROTO_IPV6, "f85d");
		(void)f579_tbl(NFPROTO_IPV6, "f85d");
		wrc |= f580_chn(NFPROTO_IPV6, "f85d", "w", NULL, 0, 0);
		wrc |= f585_wrule(0);
		wrc |= f585_wrule(1);
		wrc |= f585_wrule(2);
	}
	t3.fd = f578_tap_open_aux("y3");
	t4.fd = f578_tap_open_aux("y4");
	t3.only_out = 0;
	t4.only_out = 0;
	printf("F585 CHILDD|rc=%d|s=%d|sg=%d|y3=%d|y4=%d|t3=%d|t4=%d|wrc=%d|"
	       "m3=%02x%02x%02x%02x%02x%02x|m4=%02x%02x%02x%02x%02x%02x\n",
	       rc, s, sg, f555_ifindex("y3"), f555_ifindex("y4"), t3.fd,
	       t4.fd, wrc, F585_Y3M[0], F585_Y3M[1], F585_Y3M[2], F585_Y3M[3],
	       F585_Y3M[4], F585_Y3M[5], F585_Y4M[0], F585_Y4M[1],
	       F585_Y4M[2], F585_Y4M[3], F585_Y4M[4], F585_Y4M[5]);
	f580_snmp(&prev);
	msg[0] = 'M';
	memcpy(msg + 1, F585_Y3M, 6);
	memcpy(msg + 7, F585_Y4M, 6);
	fflush(stdout);
	if (write(F585_C.up[1], msg, 13) != 13)
		_exit(4);
	for (;;) {
		int idx, pass, nd[2] = { 0, 0 }, mode, psel, ncnt;
		int dl[2][4], dg[2][4];
		char dh[2][4][40];
		static const char hexd[] = "0123456789abcdef";
		int sock[2];
		struct f578_gf g;

		if (read(F585_C.dn[0], c, 3) != 3)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		if (c[0] == 'p') {
			/* the shape bits must be in force BEFORE the traffic, not
			 * after: the first build set them in the 'r' handler and
			 * every arm measured the previous arm's shape.  The byte
			 * travels in c[1] -- the first version read c[2] and cleared
			 * both bits on every arm. */
			struct f578_gf g2;

			mode = c[1] & 3;
			f578_feat_set("y3", F585_GROFL_BIT, mode == 2);
			f578_feat_set("y3", F585_GROFWD_BIT, mode == 1);
			f578_feat_set("y4", F585_GROFL_BIT, mode == 2);
			f578_feat_set("y4", F585_GROFWD_BIT, mode == 1);
			f578_feat_get("y3", &g2);
			printf("F585 DFEAT|cmd=%d|mode=%d|act0=%08x|act1=%08x\n",
			       c[1], mode, g2.b[0].act, g2.b[1].act);
			fflush(stdout);
			c[0] = 'D';
			if (write(F585_C.up[1], c, 1) != 1)
				_exit(6);
			continue;
		}
		if (c[0] != 'r')
			continue;
		idx = c[1];
		mode = c[2] & 3;
		psel = (c[2] >> 4) & 1;
		f578_feat_get("y3", &g);
		sock[0] = s;
		sock[1] = sg;
		memset(dl, 0, sizeof(dl));
		memset(dg, 0, sizeof(dg));
		memset(dh, 0, sizeof(dh));
		{
			int empty = 0;

			for (pass = 0; pass < 200 && empty < 12; pass++) {
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
							for (b = 0; b < 16 && b < r; b++) {
								dh[w][k][2 * b] =
									hexd[(buf[b] >> 4) & 0xf];
								dh[w][k][2 * b + 1] =
									hexd[buf[b] & 0xf];
							}
							dh[w][k][16] = 0;
							for (cm = CMSG_FIRSTHDR(&m); cm;
							     cm = CMSG_NXTHDR(&m, cm)) {
								int v;

								if (cm->cmsg_level != IPPROTO_UDP ||
								    cm->cmsg_type != UDP_GRO)
									continue;
								memcpy(&v, CMSG_DATA(cm), 4);
								dg[w][k] = v;
							}
						}
						nd[w]++;
					}
				}
				if (!got) {
					empty++;
					usleep(3000);
				} else {
					empty = 0;
				}
			}
		}
		usleep(20000);
		f585_tap_drain(&t3);
		f585_tap_drain(&t4);
		f580_snmp(&cur);
		ncnt = f585_counts(NFPROTO_IPV6, "f85d", "w", cw, 3);
		printf("F585 RCV|i=%02d|mode=%d|psel=%d|n=%d|n2=%d|ncnt=%d|"
		       "a0=%d|ah0=%s|g0=%d|a1=%d|ah1=%s|a2=%d|ah2=%s|"
		       "a3=%d|ah3=%s|b0=%d|bh0=%s|bg0=%d|"
		       "w1544=%llu|w520=%llu|woth=%llu|"
		       "rcv=%lld|deliv=%lld|udp=%lld|udperr=%lld|"
		       "hdr=%lld|disc=%lld|nop=%lld|"
		       "fac=%08x|fac1=%08x|t3=%d|t4=%d\n",
		       idx, mode, psel, nd[0], nd[1], ncnt,
		       dl[0][0], dh[0][0], dg[0][0],
		       dl[0][1], dh[0][1], dl[0][2], dh[0][2],
		       dl[0][3], dh[0][3],
		       dl[1][0], dh[1][0], dg[1][0],
		       cw[0], cw[1], cw[2],
		       (long long)cur.rcv - (long long)prev.rcv,
		       (long long)cur.deliv - (long long)prev.deliv,
		       (long long)cur.udp - (long long)prev.udp,
		       (long long)cur.udperr - (long long)prev.udperr,
		       (long long)cur.hdrerr - (long long)prev.hdrerr,
		       (long long)cur.disc - (long long)prev.disc,
		       (long long)cur.udpnop - (long long)prev.udpnop,
		       g.b[0].act, g.b[1].act, t3.n, t4.n);
		prev = cur;
		fflush(stdout);
		f585_tap_print(&t3, idx, "y3");
		f585_tap_print(&t4, idx, "y4");
		fflush(stdout);
		c[0] = 'D';
		if (write(F585_C.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* ---------- the arms ---------------------------------------------------- */

struct f585_arm {
	const char *name;
	char src;	/* 'L' router's own socket, 'F' S's socket, 'P' S's frames */
	char dst;	/* 'a' y1 fd03::92, 'b' y2 fd04::92 */
	char xg;	/* GRO at x0: 'n' none, 'u' udp_fwd (linear), 'f' fraglist */
	char dg;	/* GRO at y3/y4: same alphabet */
	char skt;	/* 'p' port 5000 plain, 'g' port 5001 UDP_GRO */
	int store;
	unsigned int off, len;
	const char *hex;
};

static const struct f585_arm AF585[] = {
	/* census: no aggregation, then each bit that can or cannot aggregate */
	{ "A_none_a",	'L', 'a', 'n', 'n', 'p', 0, 0, 0, NULL },
	{ "A_none_b",	'L', 'b', 'n', 'n', 'p', 0, 0, 0, NULL },
	{ "C_UFWD_local", 'L', 'a', 'n', 'u', 'p', 0, 0, 0, NULL },
	{ "C_FLIST",	'L', 'a', 'n', 'f', 'p', 0, 0, 0, NULL },
	{ "C_GRO_SOCK",	'L', 'a', 'n', 'u', 'g', 0, 0, 0, NULL },
	{ "C_FG_SOCK",	'L', 'a', 'n', 'f', 'g', 0, 0, 0, NULL },
	{ "B_UFWD_x0",	'F', 'a', 'u', 'n', 'p', 0, 0, 0, NULL },
	{ "B_FLIST_x0",	'F', 'a', 'f', 'n', 'p', 0, 0, 0, NULL },
	{ "B_FLIST_x0_b", 'F', 'b', 'f', 'n', 'p', 0, 0, 0, NULL },
	/* a store in the first datagram's payload */
	{ "A_w",	'L', 'a', 'n', 'n', 'p', 1, 8, 4, "a0a1a2a3" },
	{ "C_FLIST_w",	'L', 'a', 'n', 'f', 'p', 1, 8, 4, "a0a1a2a3" },
	{ "B_UFWD_w",	'F', 'a', 'u', 'n', 'p', 1, 8, 4, "a0a1a2a3" },
	{ "B_UFWD_w_b",	'F', 'b', 'u', 'n', 'p', 1, 8, 4, "a0a1a2a3" },
	{ "B_FLIST_w_a", 'F', 'a', 'f', 'n', 'p', 1, 8, 4, "a0a1a2a3" },
	{ "B_FLIST_w_b", 'F', 'b', 'f', 'n', 'p', 1, 8, 4, "a0a1a2a3" },
	/* a store in the UDP length field */
	{ "A_len",	'L', 'a', 'n', 'n', 'p', 1, 4, 2, "0020" },
	{ "C_FLIST_len", 'L', 'a', 'n', 'f', 'p', 1, 4, 2, "0020" },
	{ "B_FLIST_len_a", 'F', 'a', 'f', 'n', 'p', 1, 4, 2, "0020" },
	{ "B_FLIST_len_b", 'F', 'b', 'f', 'n', 'p', 1, 4, 2, "0020" },
	/* a store in the checksum field */
	{ "B_FLIST_chk_b", 'F', 'b', 'f', 'n', 'p', 1, 6, 2, "dead" },
	{ "B_UFWD_chk_b", 'F', 'b', 'u', 'n', 'p', 1, 6, 2, "dead" },
	{ "B_FLIST_chk0_b", 'F', 'b', 'f', 'n', 'p', 1, 6, 2, "0000" },
	/* a store past the first datagram's payload: the pull */
	{ "B_FLIST_pull_a", 'F', 'a', 'f', 'n', 'p', 1, 520, 4, "f0f1f2f3" },
	{ "B_FLIST_pull_b", 'F', 'b', 'f', 'n', 'p', 1, 520, 4, "f0f1f2f3" },
	/* provenance CHECKSUM_NONE: the sender paid, so GRO can refuse */
	{ "P_FLIST_none", 'P', 'a', 'n', 'f', 'p', 0, 0, 0, NULL },
	{ "P_FLIST_w",	'P', 'a', 'n', 'f', 'p', 1, 8, 4, "a0a1a2a3" },
};

#define NAF585 ((int)(sizeof(AF585) / sizeof(AF585[0])))

static int f585_imm(const struct f585_arm *A, unsigned char *imm)
{
	int n = (int)A->len, i;

	if (n <= 0 || n > 64)
		return -1;
	if (!A->hex || (int)strlen(A->hex) != 2 * n)
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

/* [meta l4proto 17] counter [store] log accept -- in `out` or in `fwd` */
static int f585_rule(const struct f585_arm *A, int idx,
		     const unsigned char *imm, int immlen)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs, *e, *d;
	char pre[16];
	int acks = 0;

	snprintf(pre, sizeof(pre), "86:%02d", idx);
	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			NFPROTO_IPV6);
	put_str(nlh, NFTA_RULE_TABLE, "f85p");
	put_str(nlh, NFTA_RULE_CHAIN, A->src == 'L' ? "out" : "fwd");
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
		put_be32(nlh, NFTA_PAYLOAD_BASE, B585_TH);
		put_be32(nlh, NFTA_PAYLOAD_OFFSET, A->off);
		put_be32(nlh, NFTA_PAYLOAD_LEN, A->len);
		put_be32(nlh, NFTA_PAYLOAD_CSUM_TYPE, NFT_PAYLOAD_CSUM_NONE);
		put_be32(nlh, NFTA_PAYLOAD_CSUM_OFFSET, 0);
		nest_end(nlh, d);
		nest_end(nlh, e);
	}
	log_expr(nlh, F585_GROUP, pre);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

/* the router's own three datagrams: one socket, three sendto()s */
static int f585_local_send(const struct f585_arm *A, int idx)
{
	static int sa = -1, sb = -1;
	struct sockaddr_in6 d6;
	int rc = -9, k, n = 0;
	int *sk = A->dst == 'a' ? &sa : &sb;

	if (*sk < 0) {
		*sk = f564_udp_bind(AF_INET6, 0,
				    A->dst == 'a' ? A85_RA : A85_RB, F585_SPORT);
		if (*sk < 0)
			return -1;
	}
	memset(&d6, 0, sizeof(d6));
	d6.sin6_family = AF_INET6;
	memcpy(&d6.sin6_addr, A->dst == 'a' ? A85_DA : A85_DB, 16);
	d6.sin6_port = htons(A->skt == 'g' ? F585_DPORT_G : F585_DPORT);
	for (k = 0; k < F585_N; k++) {
		rc = (int)sendto(*sk, F585_PAY[k], F585_P, 0,
				 (struct sockaddr *)&d6, sizeof(d6));
		if (rc == F585_P)
			n++;
	}
	printf("F585 LOCALSEND|i=%02d|dst=%c|sent=%d|rc=%d|errno=%d\n",
	       idx, A->dst, n, rc, rc < 0 ? errno : 0);
	return n == F585_N ? 0 : -1;
}

static void f585_hexrange(char *out, size_t osz, const unsigned char *p,
			  int from, int to, int plen)
{
	int at = 0, i;

	if (from >= plen || to <= from) {
		snprintf(out, osz, "-");
		return;
	}
	if (to > plen)
		to = plen;
	for (i = from; i < to && at + 3 < (int)osz; i++)
		at += snprintf(out + at, osz - (size_t)at, "%02x", p[i]);
	out[at] = 0;
}

static void f585_arm(const struct f585_arm *A, int idx)
{
	struct f575_pl pl;
	unsigned char imm[64];
	char hxi[128] = "-", lgfirst[40] = "-", lgudp[24] = "-";
	char lgf1[40] = "-", lgf2[40] = "-", lgtail[40] = "-";
	int rc = -99, ilen = -1, ch = -1, nl = 0, lgplen = -1, i, cmdrc = 0;
	int acks = 0;
	const char *chain = A->src == 'L' ? "out" : "fwd";

	/* 1. the router's ingress decides whether THE RULE sees an aggregate */
	f578_feat_set("x0", F585_GROFL_BIT, A->xg == 'f');
	f578_feat_set("x0", F585_GROFWD_BIT, A->xg == 'u');
	/* 2. clean slate */
	(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
	(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
	f585_tap_drain(&F585_TA);
	f585_tap_drain(&F585_TB);
	f575_nfl_drain(&pl);
	/* 3. the rule */
	if (A->store) {
		ilen = f585_imm(A, imm);
		rc = ilen < 0 ? -99 : f585_rule(A, idx, imm, ilen);
		f559_hexs(hxi, sizeof(hxi), imm, ilen > 0 ? ilen : 0);
	} else {
		rc = f585_rule(A, idx, NULL, 0);
	}
	/* 4. the receiver's GRO mode, before the traffic */
	cmdrc |= f585_cmd(&F585_C, 'p',
			  (A->dg == 'f' ? 2 : (A->dg == 'u' ? 1 : 0)) |
			  ((A->skt == 'g' ? 1 : 0) << 4), 0) ? 1 : 0;
	/* 5. the traffic */
	if (A->src == 'L')
		cmdrc |= f585_local_send(A, idx) ? 2 : 0;
	else
		cmdrc |= f585_cmd(&F585_S, A->src == 'F' ? 's' : 'p',
				  A->dst == 'a' ? 'a' : 'b',
				  A->skt == 'g' ? 1 : 0) ? 4 : 0;
	/* 6. past the GRO timer, then read */
	usleep(220000);
	cmdrc |= f585_cmd(&F585_C, 'r', idx,
			  (A->dg == 'f' ? 2 : (A->dg == 'u' ? 1 : 0)) |
			  ((A->skt == 'g' ? 1 : 0) << 4)) ? 8 : 0;
	f585_tap_drain(&F585_TA);
	f585_tap_drain(&F585_TB);
	f575_nfl_drain(&pl);
	ch = (int)f555_count(NFPROTO_IPV6, "f85p", chain);
	for (i = 0; i < pl.n && i < F575_NPL; i++) {
		if (!strncmp(pl.m[i].prefix, "86:", 3) && !nl) {
			struct f575_msg *M = &pl.m[i];

			nl = 1;
			lgplen = M->plen;
			f585_hexrange(lgfirst, sizeof(lgfirst), M->p, 0, 16,
				      M->plen);
			f585_hexrange(lgudp, sizeof(lgudp), M->p, 40, 48,
				      M->plen);
			f585_hexrange(lgf1, sizeof(lgf1), M->p, 560, 576,
				      M->plen);
			f585_hexrange(lgf2, sizeof(lgf2), M->p, 1120, 1136,
				      M->plen);
			f585_hexrange(lgtail, sizeof(lgtail), M->p,
				      M->plen - 16, M->plen, M->plen);
		}
	}
	printf("F585 ARM|i=%02d|name=%s|src=%c|dst=%c|xg=%c|dg=%c|skt=%c|"
	       "store=%d|off=%u|len=%u|hex=%s|rc=%d|cmdrc=%d|ch=%d|nl=%d|"
	       "lgplen=%d|lgind=%d|lgout=%d|lgfirst=%s|lgudp=%s|lgf1=%s|"
	       "lgf2=%s|lgtail=%s|an=%d|anall=%d|bn=%d|bnall=%d\n",
	       idx, A->name, A->src, A->dst, A->xg, A->dg, A->skt, A->store,
	       A->off, A->len, hxi, rc, cmdrc, ch, nl, lgplen,
	       pl.n > 0 ? pl.m[0].indev : -1, pl.n > 0 ? pl.m[0].outdev : -1,
	       lgfirst, lgudp, lgf1, lgf2, lgtail, F585_TA.n, F585_TA.nall,
	       F585_TB.n, F585_TB.nall);
	fflush(stdout);
	f585_tap_print(&F585_TA, idx, "a");
	f585_tap_print(&F585_TB, idx, "b");
	fflush(stdout);
}

/* ---------- mode aggr --------------------------------------------------- */

static int f585_aggr(int limit)
{
	static const char *old[] = { "x0", "x1", "y1", "y3", "y2", "y4" };
	struct f578_gf g;
	unsigned char msg[16];
	int i, rc, r1, r2;

	f585_tap_zero(&F585_TA);
	f585_tap_zero(&F585_TB);
	for (i = 0; i < F585_N; i++) {
		int k;

		for (k = 0; k < F585_P; k++)
			F585_PAY[i][k] = (unsigned char)(0x80 + (k & 0x7f));
		F585_PAY[i][0] = (unsigned char)(0x10 + i);
	}
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv4/ip_forward", "0");
	for (i = 0; i < 6; i++)
		f558_link_del(old[i]);
	{
		int acks = 0;

		(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
		(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
		(void)f584_deltable(NFPROTO_IPV6, "f85p");
		(void)f584_deltable(NFPROTO_IPV6, "f85d");
	}
	if (pipe(F585_S.up) || pipe(F585_S.dn) || pipe(F585_C.up) ||
	    pipe(F585_C.dn)) {
		printf("F585 FAIL|pipe\n");
		return -1;
	}
	F585_S.pid = fork();
	if (F585_S.pid < 0) {
		printf("F585 FAIL|fork\n");
		return -1;
	}
	if (F585_S.pid == 0)
		f585_child_s();
	F585_C.pid = fork();
	if (F585_C.pid < 0) {
		printf("F585 FAIL|fork2\n");
		return -1;
	}
	if (F585_C.pid == 0)
		f585_child_d();
	close(F585_S.up[1]);
	close(F585_S.dn[0]);
	close(F585_C.up[1]);
	close(F585_C.dn[0]);
	if (f585_wait_byte(F585_S.up[0], 5000) != 'U') {
		printf("F585 FAIL|senderns\n");
		return -1;
	}
	if (f585_wait_byte(F585_C.up[0], 5000) != 'U') {
		printf("F585 FAIL|recvns\n");
		return -1;
	}
	rc = f585_veth_ns("x0", "x1", (int)F585_S.pid);
	rc |= f585_veth_ns("y1", "y3", (int)F585_C.pid);
	rc |= f585_veth_ns("y2", "y4", (int)F585_C.pid);
	if (rc) {
		printf("F585 FAIL|veth|rc=%d\n", rc);
		return -1;
	}
	set_up("x0");
	set_up("y1");
	set_up("y2");
	printf("F585 GROSW|x0=%d\n", f578_feat_set("x0", F585_GRO_BIT, 1));
	(void)f585_v6dev("x0", 1);
	(void)f585_v6dev("y1", 1);
	(void)f585_v6dev("y2", 1);
	rc = f585_addr6_nodad("x0", A85_R6, 64);
	rc |= f585_addr6_nodad("y1", A85_RA, 64);
	rc |= f585_addr6_nodad("y2", A85_RB, 64);
	f585_mtu("x0", "9000");
	f585_mtu("y1", "9000");
	f585_mtu("y2", "9000");
	f585_groto("x0", "20000000");
	mac_get("x0", F585_X0M);
	msg[0] = 'M';
	memcpy(msg + 1, F585_X0M, 6);
	if (write(F585_S.dn[1], msg, 7) != 7) {
		printf("F585 FAIL|mactx\n");
		return -1;
	}
	{
		unsigned char c = 'R';

		if (write(F585_C.dn[1], &c, 1) != 1) {
			printf("F585 FAIL|dsync\n");
			return -1;
		}
	}
	if (f585_wait_byte(F585_S.up[0], 8000) != 'R') {
		printf("F585 FAIL|senderready\n");
		return -1;
	}
	/* the receiver announces itself with one 13-byte message: 'M' + 12 */
	{
		unsigned char b[13];
		int got = 0;

		for (i = 0; i < 300 && got < 13; i++) {
			int r = (int)read(F585_C.up[0], b + got,
					  (size_t)(13 - got));

			if (r > 0)
				got += r;
			else
				usleep(10000);
		}
		if (got == 13 && b[0] == 'M') {
			memcpy(F585_Y3M, b + 1, 6);
			memcpy(F585_Y4M, b + 7, 6);
		} else {
			printf("F585 FAIL|dmac|got=%d\n", got);
			return -1;
		}
	}
	rc |= f569_neigh6_add("y1", A85_DA, F585_Y3M);
	rc |= f569_neigh6_add("y2", A85_DB, F585_Y4M);
	/* y1 keeps every bit it was born with.  y2 loses HW_CSUM (F62:
	 * GSO_UDP_L4 goes with it) and the TSO family -- TSO_ECN is bit 18,
	 * which is also SKB_GSO_FRAGLIST, so clearing it is the only way to
	 * make skb_gso_ok() say "no" to a fraglist. */
	r1 = 0;
	r1 |= f578_feat_set("y1", F585_TSO_BIT, 0);
	r1 |= f578_feat_set("y1", F585_TSOECN_BIT, 0);
	r1 |= f578_feat_set("y1", F585_TSOMID_BIT, 0);
	r1 |= f578_feat_set("y1", F585_TSO6_BIT, 0);
	r2 = f578_feat_set("y2", F585_HWCSUM_BIT, 0);
	r2 |= f578_feat_set("y2", F585_TSO_BIT, 0);
	r2 |= f578_feat_set("y2", F585_TSOECN_BIT, 0);
	r2 |= f578_feat_set("y2", F585_TSOMID_BIT, 0);
	r2 |= f578_feat_set("y2", F585_TSO6_BIT, 0);
	r2 |= f578_feat_set("y2", F585_GSOUDP_BIT, 0);
	r2 |= f578_feat_set("y2", F585_GSOFL_BIT, 0);
	printf("F585 FEAT|r1=%d|r2=%d|hwcsum=%d|gsoudp=%d|tso=%d|tsoecn=%d|"
	       "grofl=%d|grofwd=%d\n", r1, r2, F585_HWCSUM_BIT, F585_GSOUDP_BIT,
	       F585_TSO_BIT, F585_TSOECN_BIT, F585_GROFL_BIT, F585_GROFWD_BIT);
	f578_feat_get("x0", &g);
	printf("F585 FEAT|dev=x0|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y1", &g);
	printf("F585 FEAT|dev=y1|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y2", &g);
	printf("F585 FEAT|dev=y2|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	(void)f579_tbl(NFPROTO_IPV6, "f85p");
	{
		int k = 0;

		k |= f580_chn(NFPROTO_IPV6, "f85p", "out", NULL, 3, 0);
		k |= f580_chn(NFPROTO_IPV6, "f85p", "fwd", NULL, 2, 0);
		printf("F585 CHAINS|rc=%d\n", k);
	}
	F573_NFL = nfl_open(F585_GROUP);
	F585_NFL = F573_NFL;
	/* No tap on y1/y2: an AF_PACKET clone there makes the skb shared and
	 * veth_xdp_rcv() then calls netif_receive_skb() instead of
	 * napi_gro_receive() -- the witness would switch off the effect. */
	F585_TA.fd = -1;
	F585_TB.fd = -1;
	printf("F585 ENV|x0=%d|y1=%d|y2=%d|nfl=%d|ta=%d|tb=%d|addr=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|P=%d|N=%d\n",
	       f555_ifindex("x0"), f555_ifindex("y1"), f555_ifindex("y2"),
	       F573_NFL, F585_TA.fd, F585_TB.fd, rc, F585_X0M[0], F585_X0M[1],
	       F585_X0M[2], F585_X0M[3], F585_X0M[4], F585_X0M[5], F585_P,
	       F585_N);
	usleep(300000);
	for (i = 0; i < NAF585; i++) {
		if (limit > 0 && i >= limit) {
			printf("F585 SKIP|from=%d|limit=%d\n", i, limit);
			break;
		}
		f585_arm(&AF585[i], i);
	}
	(void)f585_cmd(&F585_S, 'q', 0, 0);
	(void)f585_cmd(&F585_C, 'q', 0, 0);
	printf("F585 END|mode=aggr|arms=%d\n", i);
	fflush(stdout);
	return 0;
}

/* ---------- entry ------------------------------------------------------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "aggr";
	int limit = argc > 2 ? atoi(argv[2]) : 0;
	char mbuf[32];

	if (strchr(mode, ':')) {	/* "aggr:9" = mode plus an arm limit */
		const char *c = strchr(mode, ':');
		int n = (int)(c - mode);

		if (n > 0 && n < (int)sizeof(mbuf)) {
			memcpy(mbuf, mode, (size_t)n);
			mbuf[n] = 0;
			mode = mbuf;
			limit = atoi(c + 1);
		}
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("F585 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "aggr"))
		return f585_aggr(limit);
	return f584_entry(argc, argv);
}
