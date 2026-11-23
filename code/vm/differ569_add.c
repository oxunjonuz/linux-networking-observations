/* differ569_add.c -- turn 569.
 *
 *  PART 1 (mode `iso`): the F46 anomaly `post/loc n0_1 cntp=2`, reproduced on
 *  purpose.  One `inet` base chain at postrouting with counter+log+accept; an
 *  IPv4 datagram is sent while the parent's own stack emits IPv6 packets, and
 *  the counter is read under four conditions:
 *      ctl4    IPv6 off            -> 1 packet
 *      v6on    IPv6 just enabled   -> k packets, none of them ours
 *      v6plus  the same + one IPv4 -> k+1
 *      guard   the same, with a `meta nfproto ipv4` chain in front -> 1
 *      v6off   IPv6 off again      -> 0
 *  If those five numbers hold, `cntp=2` was never a double count: an `inet`
 *  chain counts both families, and the second packet was IPv6.
 *
 *  PART 2 (mode `v6`): F47 -- IPv6 at the egress doors.  The same six doors
 *  and two traffic classes as F46, with an IPv6/UDP frame instead of an IPv4
 *  one.  IPv6 has no header checksum, so the question is what replaces it as
 *  the toll: the hop limit at FORWARD, the pseudo-header at the transport
 *  layer, the route lookup, or nothing at all.
 *
 *  Every helper below the new code (netlink toolkit, rtnetlink, NFLOG, capture,
 *  counters, chain install) is the one that produced F31..F46.
 */

/* ---------- addresses ---------- */

static const unsigned char A6_X0[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
					 0, 0, 0, 0, 0, 0, 0, 1 };
static const unsigned char A6_X1[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
					 0, 0, 0, 0, 0, 0, 0, 2 };
static const unsigned char A6_FS[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
					 0, 0, 0, 0, 0, 0x08, 0, 2 };
static const unsigned char A6_BAD[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x99 };
static const unsigned char A6_ZERO[16] = { 0 };

#define F569_PAY	18
#define F569_UDP6LEN	(8 + F569_PAY)

/* ---------- an IPv6/UDP frame ---------- */

static int f569_mk6(unsigned char *out, const unsigned char *dmac,
		    const unsigned char *s16, const unsigned char *d16,
		    unsigned short sport, unsigned short dport)
{
	static const unsigned char sm[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x69 };

	memset(out, 0, 128);
	memcpy(out, dmac, 6);
	memcpy(out + 6, sm, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	out[14] = 0x60;					/* version 6, tc 0 */
	out[18] = (unsigned char)(F569_UDP6LEN >> 8);
	out[19] = (unsigned char)(F569_UDP6LEN & 0xff);
	out[20] = 17;					/* nexthdr: UDP */
	out[21] = 64;					/* hop limit */
	memcpy(out + 22, s16, 16);
	memcpy(out + 38, d16, 16);
	out[54] = (unsigned char)(sport >> 8);
	out[55] = (unsigned char)(sport & 0xff);
	out[56] = (unsigned char)(dport >> 8);
	out[57] = (unsigned char)(dport & 0xff);
	out[58] = (unsigned char)(F569_UDP6LEN >> 8);
	out[59] = (unsigned char)(F569_UDP6LEN & 0xff);
	memcpy(out + 62, F568_PAY, F569_PAY);
	f564_udp6_csum(out + 14, F569_UDP6LEN);
	return 14 + 40 + F569_UDP6LEN;			/* 80 */
}

/* an NDP entry, so that no arm waits for a solicitation */
static int f569_neigh6_add(const char *dev, const unsigned char *dst,
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
	req.ndm.ndm_family = AF_INET6;
	req.ndm.ndm_ifindex = f555_ifindex(dev);
	req.ndm.ndm_state = NUD_PERMANENT;
	attr_put(&req.nlh, NDA_DST, dst, 16);
	attr_put(&req.nlh, NDA_LLADDR, mac, 6);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* ---------- every NFLOG payload of an arm, not just the last ---------- */

#define F569_NMSG 8
struct f569_pl {
	int n;
	int plen[F569_NMSG];
	unsigned char p[F569_NMSG][56];
};

static void f569_drain(int fd, struct f569_pl *v)
{
	unsigned char b[16384];
	int guard = 0, rl;

	memset(v, 0, sizeof(*v));
	if (fd < 0)
		return;
	while (guard++ < 64) {
		struct nlmsghdr *h;
		int len;

		rl = (int)recv(fd, b, sizeof(b), MSG_DONTWAIT);
		if (rl <= 0)
			break;
		len = rl;
		for (h = (struct nlmsghdr *)b; NLMSG_OK(h, len);
		     h = NLMSG_NEXT(h, len)) {
			const char *p, *end, *prefix = NULL;
			const unsigned char *pl = NULL;
			int pll = 0;

			if (h->nlmsg_type == NLMSG_DONE ||
			    h->nlmsg_type == NLMSG_ERROR)
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
				}
				p += NLA_ALIGN_(al);
			}
			if (!prefix || !pl || prefix[0] != 'p')
				continue;
			if (v->n < F569_NMSG) {
				int k = pll < (int)sizeof(v->p[0]) ? pll
								   : (int)sizeof(v->p[0]);

				memcpy(v->p[v->n], pl, (size_t)k);
				v->plen[v->n] = k;
			}
			v->n++;
		}
	}
}

/* ---------- the receiving side in the child netns ---------- */

struct f569_rep6 {
	int tapn, taplen;
	char taphex[600];
	int u6n, u6len0, u6sport0;
	char u6pay[40];
	unsigned long long i6in, i6hdr, i6addr, i6unk, i6trunc, i6noroute,
			   i6deliv, u6in, u6err, u6noport, i6out, i6outnoroute,
			   icmp6in;
	int taptot, u6tot, alltot;
	unsigned long long i6octets, i6mcast;
};

/* a frame on the wire that is IPv6/UDP and carries our payload: an ICMPv6
 * error quoting the packet has nexthdr 58 and must not be counted */
static int f569_tap6(const unsigned char *b, int n)
{
	if (n < 14 + 40 + 8)
		return 0;
	if (b[12] != 0x86 || b[13] != 0xdd)
		return 0;
	if (b[20] != 17)
		return 0;
	return f568_needle(b, n);
}

static int F569_TAPTOT, F569_U6TOT, F569_ALLTOT;

static void f569_child_snap(int tapfd, int ufd, int ufd6, int wfd)
{
	unsigned char b[2048], first[512];
	int r, tapn = 0, firstlen = -1;
	int u6n = 0, u6len0 = -1, u6sport0 = -1;
	char pay[40] = "-", hx[600] = "-";

	/* Under TCG the frames sit in the backlog until this process yields;
	 * draining twice with a yield in between is what makes the tap and the
	 * socket see the packet of the arm they are asked about. */
	usleep(40000);
	while ((r = (int)recv(tapfd, b, sizeof(b), MSG_DONTWAIT)) > 0) {
		F569_ALLTOT++;
		if (!f569_tap6(b, r))
			continue;
		tapn++;
		F569_TAPTOT++;
		if (firstlen >= 0)
			continue;
		firstlen = r < (int)sizeof(first) ? r : (int)sizeof(first);
		memcpy(first, b, (size_t)firstlen);
	}
	for (;;) {
		struct sockaddr_in6 from;
		socklen_t fl = sizeof(from);

		memset(&from, 0, sizeof(from));
		r = (int)recvfrom(ufd6, b, sizeof(b), MSG_DONTWAIT,
				  (struct sockaddr *)&from, &fl);
		if (r < 0)
			break;
		if (u6n == 0) {
			int k, n = r < 8 ? r : 8;
			char *o = pay;

			u6len0 = r;
			u6sport0 = (int)ntohs(from.sin6_port);
			for (k = 0; k < n; k++)
				o += sprintf(o, "%02x", b[k]);
		}
		u6n++;
		F569_U6TOT++;
		if (u6n > 32)
			break;
	}
	if (firstlen > 0) {
		int k, n = firstlen < 200 ? firstlen : 200;
		char *o = hx;

		for (k = 0; k < n; k++)
			o += sprintf(o, "%02x", first[k]);
	}
	(void)ufd;
	dprintf(wfd, "R6|%d|%d|%s|%d|%d|%d|%s|%llu|%llu|%llu|%llu|%llu|%llu|%llu|"
		"%llu|%llu|%llu|%llu|%llu|%llu|%d|%d|%llu|%llu|%d\n",
		tapn, firstlen, hx, u6n, u6len0, u6sport0, pay,
		f564_snmp6("Ip6InReceives"), f564_snmp6("Ip6InHdrErrors"),
		f564_snmp6("Ip6InAddrErrors"), f564_snmp6("Ip6InUnknownProtos"),
		f564_snmp6("Ip6InTruncatedPkts"), f564_snmp6("Ip6InNoRoutes"),
		f564_snmp6("Ip6InDelivers"), f564_snmp6("Udp6InDatagrams"),
		f564_snmp6("Udp6InErrors"), f564_snmp6("Udp6NoPorts"),
		f564_snmp6("Ip6OutRequests"), f564_snmp6("Ip6OutNoRoutes"),
		f564_snmp6("Icmp6InMsgs"), F569_TAPTOT, F569_U6TOT,
		f564_snmp6("Ip6InOctets"), f564_snmp6("Ip6InMcastPkts"),
		F569_ALLTOT);
	(void)0;
}

static void f569_child_loop(int rfd, int wfd);

static int f569_start_child(void)
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
		f569_child_loop(to_ch[0], to_p[1]);
		_exit(0);
	}
	close(to_ch[0]);
	close(to_p[1]);
	P_W = to_ch[1];
	P_R = to_p[0];
	CHILD = pid;
	return 0;
}

/* The child: unshare, wait for x1, configure IPv4 and IPv6, serve. */
static void f569_child_loop(int rfd, int wfd)
{
	char cmd[64];
	int tapfd, ufd, ufd6, one = 1;

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
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/accept_ra", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/rtr_solicitations", "0");
	dprintf(wfd, "A|%d|%d\n", f555_addr_add("x1", htonl(A_X1), 24),
		f564_addr6("x1", A6_X1, 64));
	{
		struct sockaddr_in sa;

		ufd = socket(AF_INET, SOCK_DGRAM, 0);
		setsockopt(ufd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(5000);
	}
	{
		struct sockaddr_in6 sa6;

		ufd6 = socket(AF_INET6, SOCK_DGRAM, 0);
		setsockopt(ufd6, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		setsockopt(ufd6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
		memset(&sa6, 0, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		memcpy(&sa6.sin6_addr, A6_X1, 16);
		sa6.sin6_port = htons(5000);
		{
			/* the address may still be tentative (DAD runs the moment
			 * it is added, whatever accept_dad says): retry */
			int k, rc = -1;

			for (k = 0; k < 20; k++) {
				rc = bind(ufd6, (struct sockaddr *)&sa6, sizeof(sa6));
				if (rc == 0)
					break;
				usleep(200000);
			}
			dprintf(wfd, "B6|rc=%d|tries=%d|errno=%d\n", rc, k,
				rc ? errno : 0);
			if (rc)
				dprintf(wfd, "E|bind6|%d\n", errno);
		}
	}
	tapfd = cap_open("x1");
	{
		char ifa[128] = "-", car[32] = "-";
		FILE *f = fopen("/proc/net/if_inet6", "r");

		if (f) {
			char l[256];

			while (fgets(l, sizeof(l), f))
				if (strstr(l, "x1")) {
					snprintf(ifa, sizeof(ifa), "%s", l);
					break;
				}
			fclose(f);
		}
		f = fopen("/sys/class/net/x1/carrier", "r");
		if (f) {
			if (fgets(car, sizeof(car), f)) {
				char *n = strchr(car, '\n');

				if (n)
					*n = 0;
			}
			fclose(f);
		}
		dprintf(wfd, "READY|%d|%d|dis6=%llu|carrier=%s|ifa=%s\n", tapfd,
			f555_ifindex("x1"),
			f567_read_ll("/proc/sys/net/ipv6/conf/x1/disable_ipv6"),
			car, ifa);
	}
	for (;;) {
		int n = (int)read(rfd, cmd, sizeof(cmd) - 1);

		if (n <= 0)
			_exit(3);
		cmd[n] = 0;
		if (cmd[0] == 'Q')
			_exit(0);
		if (cmd[0] == 'S')
			f569_child_snap(tapfd, ufd, ufd6, wfd);
	}
}

static int f569_snapshot6(struct f569_rep6 *R)
{
	char line[3072], *f[32];
	int n;

	memset(R, 0, sizeof(*R));
	R->taplen = -1;
	R->u6len0 = -1;
	R->u6sport0 = -1;
	snprintf(R->taphex, sizeof(R->taphex), "-");
	snprintf(R->u6pay, sizeof(R->u6pay), "-");
	f568_ask("S");
	if (f568_read_line(line, (int)sizeof(line), 8000) < 0)
		return -1;
	n = f568_split(line, f, 32);
	if (n < 26 || f[0][0] != 'R' || f[0][1] != '6')
		return -2;
	R->tapn = atoi(f[1]);
	R->taplen = atoi(f[2]);
	snprintf(R->taphex, sizeof(R->taphex), "%s", f[3]);
	R->u6n = atoi(f[4]);
	R->u6len0 = atoi(f[5]);
	R->u6sport0 = atoi(f[6]);
	snprintf(R->u6pay, sizeof(R->u6pay), "%s", f[7]);
	R->i6in = strtoull(f[8], NULL, 10);
	R->i6hdr = strtoull(f[9], NULL, 10);
	R->i6addr = strtoull(f[10], NULL, 10);
	R->i6unk = strtoull(f[11], NULL, 10);
	R->i6trunc = strtoull(f[12], NULL, 10);
	R->i6noroute = strtoull(f[13], NULL, 10);
	R->i6deliv = strtoull(f[14], NULL, 10);
	R->u6in = strtoull(f[15], NULL, 10);
	R->u6err = strtoull(f[16], NULL, 10);
	R->u6noport = strtoull(f[17], NULL, 10);
	R->i6out = strtoull(f[18], NULL, 10);
	R->i6outnoroute = strtoull(f[19], NULL, 10);
	R->icmp6in = strtoull(f[20], NULL, 10);
	R->taptot = atoi(f[21]);
	R->u6tot = atoi(f[22]);
	R->i6octets = strtoull(f[23], NULL, 10);
	R->i6mcast = strtoull(f[24], NULL, 10);
	R->alltot = atoi(f[25]);
	return 0;
}

/* ---------- PART 2: the six doors, IPv6 ---------- */

static unsigned char FWD6[128], IN6[128];
static int FWD6_LEN = -1, IN6_LEN = -1;
static int LOC6_SOCK = -1;

static void f569_emit(int cls)
{
	if (cls == C_LOC) {
		struct sockaddr_in6 sa;

		memset(&sa, 0, sizeof(sa));
		sa.sin6_family = AF_INET6;
		memcpy(&sa.sin6_addr, A6_X1, 16);
		sa.sin6_port = htons(5000);
		sendto(LOC6_SOCK, F568_PAY, F569_PAY, 0, (struct sockaddr *)&sa,
		       sizeof(sa));
	} else {
		pkt_send_p("o1", FWD6, FWD6_LEN, 0x86dd);
	}
}

static void f569_arm(const char *sec, const struct f568_pair *P, const char *arm,
		     int off, int len, const unsigned char *imm, int mode,
		     int rfd)
{
	struct f568_door *D = &D568[P->door];
	const char *cn = CLSN[P->cls];
	unsigned long long c0p, c0s, c1p, c1s;
	struct f569_rep6 r, r0;
	struct f569_pl pl;
	int rcp = -1, rcs = -1, acks = 0, snd = 0, rc0 = -9, rc1 = -9, npolls = 0;
	unsigned long long p0in, p0hdr, p0out, p0disc, q0rx, q0tx, p0addr, p0idisc;
	char hx[600], hx2[600];
	int i;

	memset(&r, 0, sizeof(r));
	memset(&r0, 0, sizeof(r0));
	p0addr = f564_snmp6("Ip6InAddrErrors");
	p0idisc = f564_snmp6("Ip6InDiscards");
	q0rx = f567_read_ll("/sys/class/net/o0/statistics/rx_packets");
	q0tx = f567_read_ll("/sys/class/net/x0/statistics/tx_packets");
	p0in = f564_snmp6("Ip6InReceives");
	p0hdr = f564_snmp6("Ip6InHdrErrors");
	p0out = f564_snmp6("Ip6OutRequests");
	p0disc = f564_snmp6("Ip6OutDiscards");
	f568_flush_all();
	f569_drain(rfd, &pl);
	rcp = f568_rule(D, "pre0", "p", 0, 0, 0, NULL, 0, 0, 0, &acks);
	rcs = f568_rule(D, "ch", "s", 1, off, len, imm, mode, 0, 0, &acks);
	c0p = f555_count(D->fam, D->table, "pre0");
	c0s = f555_count(D->fam, D->table, "ch");
	/* clear whatever the previous arm left in the child's buffers, so that
	 * no delivery can be attributed to the wrong arm */
	rc0 = f569_snapshot6(&r0);
	f569_emit(P->cls);
	snd = P->cls == C_LOC ? F569_PAY : FWD6_LEN;
	{
		int k, polls = 0;
		unsigned long long o0rx0 = f567_read_ll("/sys/class/net/o0/statistics/rx_packets");

		rc1 = -1;
		for (k = 0; k < 20; k++) {
			unsigned long long o0rx;

			usleep(250000);
			rc1 = f569_snapshot6(&r);
			polls++;
			if (rc1)
				break;
			o0rx = f567_read_ll("/sys/class/net/o0/statistics/rx_packets");
			/* the arm ends when its own packet has been seen, wherever
			 * it is seen: the wire, the receive counters, the socket */
			if (r.u6tot > r0.u6tot || r.alltot > r0.alltot ||
			    r.i6in > r0.i6in || r.i6hdr > r0.i6hdr ||
			    r.i6addr > r0.i6addr || r.i6trunc > r0.i6trunc ||
			    r.i6unk > r0.i6unk || r.i6noroute > r0.i6noroute ||
			    o0rx > o0rx0)
				break;
		}
		npolls = polls;
	}
	f569_drain(rfd, &pl);
	c1p = f555_count(D->fam, D->table, "pre0");
	c1s = f555_count(D->fam, D->table, "ch");

	printf("F569 A|sec=%s|door=%s|cls=%s|arm=%s|mode=%d|off=%d|len=%d|imm=%s|"
	       "rcp=%d|rcs=%d|sendrc=%d|cntp=%llu|lives=%llu|nmsg=%d|"
	       "rc0=%d|rc1=%d|u6n0=%d|i6in0=%llu|in_d=%llu|u6in_d=%llu|polls=%d|"
	       "tapd=%d|u6d=%d|all_d=%d|deliv_d=%llu|oct_d=%llu|mcast_d=%llu|",
	       sec, D->tag, cn, arm, mode, off, len,
	       f559_hexs(hx, sizeof(hx), imm, len), rcp, rcs, snd,
	       c1p - c0p, c1s - c0s, pl.n, rc0, rc1, r0.u6n, r0.i6in,
	       r.i6in - r0.i6in, r.u6in - r0.u6in, npolls, r.taptot - r0.taptot,
	       r.u6tot - r0.u6tot, r.alltot - r0.alltot,
	       r.i6deliv - r0.i6deliv, r.i6octets - r0.i6octets,
	       r.i6mcast - r0.i6mcast);
	for (i = 0; i < pl.n && i < F569_NMSG; i++)
		printf("m%d=%s|", i,
		       f559_hexs(hx2, sizeof(hx2), pl.p[i], pl.plen[i]));
	printf("paddr_d=%llu|pidisc_d=%llu|", f564_snmp6("Ip6InAddrErrors") - p0addr,
	       f564_snmp6("Ip6InDiscards") - p0idisc);
	printf("o0rx_d=%llu|x0tx_d=%llu|pin_d=%llu|phdr_d=%llu|pout_d=%llu|pdisc_d=%llu|",
	       f567_read_ll("/sys/class/net/o0/statistics/rx_packets") - q0rx,
	       f567_read_ll("/sys/class/net/x0/statistics/tx_packets") - q0tx,
	       f564_snmp6("Ip6InReceives") - p0in,
	       f564_snmp6("Ip6InHdrErrors") - p0hdr,
	       f564_snmp6("Ip6OutRequests") - p0out,
	       f564_snmp6("Ip6OutDiscards") - p0disc);
	printf("tapn=%d|taplen=%d|tap=%s|u6n=%d|u6len=%d|u6sport=%d|u6pay=%s|",
	       r.tapn, r.taplen, r.taphex, r.u6n, r.u6len0, r.u6sport0, r.u6pay);
	printf("i6in=%llu|i6hdr=%llu|i6addr=%llu|i6unk=%llu|i6trunc=%llu|"
	       "i6noroute=%llu|i6deliv=%llu|u6in=%llu|u6err=%llu|u6noport=%llu|"
	       "i6out=%llu|i6outnoroute=%llu|icmp6in=%llu\n",
	       r.i6in, r.i6hdr, r.i6addr, r.i6unk, r.i6trunc, r.i6noroute,
	       r.i6deliv, r.u6in, r.u6err, r.u6noport, r.i6out,
	       r.i6outnoroute, r.icmp6in);
}

struct f569_cell { const char *tag; int off, len; unsigned char imm[16]; };

static void f569_sec_v6(int rfd)
{
	static const struct f568_pair P[] = {
		{ 0, C_LOC }, { 1, C_LOC }, { 5, C_LOC },
		{ 1, C_FWD }, { 2, C_FWD }, { 5, C_FWD }, { 3, C_FWD },
	};
	static const struct f569_cell K[] = {
		{ "hop90",  7, 1, { 0x90 } },
		{ "hop00",  7, 1, { 0x00 } },
		{ "hop01",  7, 1, { 0x01 } },
		{ "hop64",  7, 1, { 0x40 } },		/* the value the frame carries */
		{ "flow2",  2, 2, { 0x90, 0x91 } },
		{ "tc4",    0, 4, { 0x60, 0x91, 0x92, 0x93 } },
		{ "ver9",   0, 4, { 0x90, 0x91, 0x92, 0x93 } },
		{ "saddr",  8, 16, { 0 } },		/* filled below */
		{ "saddr_same", 8, 16, { 0 } },
		{ "daddr",  24, 16, { 0 } },
		{ "plen2",  4, 2, { 0x90, 0x91 } },	/* refused: no case for 4 */
		{ "nh1",    6, 1, { 0x90 } },		/* refused: no case for 6 */
	};
	const int NK = (int)(sizeof(K) / sizeof(K[0]));
	const int NPAIR = (int)(sizeof(P) / sizeof(P[0]));
	int i, j;
	unsigned char imm[16];

	for (i = 0; i < NK; i++) {
		for (j = 0; j < NPAIR; j++) {
			int cls = P[j].cls;
			char arm[64];

			memcpy(imm, K[i].imm, 16);
			if (!strcmp(K[i].tag, "saddr")) {
				memcpy(imm, A6_BAD, 16);
			} else if (!strcmp(K[i].tag, "saddr_same")) {
				memcpy(imm, cls == C_LOC ? A6_X0 : A6_FS, 16);
			} else if (!strcmp(K[i].tag, "daddr")) {
				memcpy(imm, A6_BAD, 16);
			}
			snprintf(arm, sizeof(arm), "%s", K[i].tag);
			f569_arm("v6", &P[j], arm, K[i].off, K[i].len, imm, 1, rfd);
		}
	}
	/* the read side of the same coordinate: mode 3 reads the cell and
	 * compares it with the immediate, and the counter after the compare
	 * says how many packets matched */
	for (j = 0; j < NPAIR; j++) {
		int cls = P[j].cls;

		memset(imm, 0, 16);
		imm[0] = 0x40;			/* the hop limit the frame carries */
		f569_arm("v6", &P[j], "rd_hop64", 7, 1, imm, 3, rfd);
		imm[0] = 0x00;			/* nothing carries zero */
		f569_arm("v6", &P[j], "rd_hop00", 7, 1, imm, 3, rfd);
		memcpy(imm, cls == C_LOC ? A6_X0 : A6_FS, 16);
		f569_arm("v6", &P[j], "rd_src", 8, 16, imm, 3, rfd);
		memcpy(imm, cls == C_LOC ? A6_X1 : A6_X1, 16);
		f569_arm("v6", &P[j], "rd_dst", 24, 16, imm, 3, rfd);
	}
}

/* ---------- PART 1: the isolation ---------- */

static void f569_meta_nfproto(struct nlmsghdr *nlh)
{
	struct nlattr *e, *d;

	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "meta");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_META_KEY, NFT_META_NFPROTO);
	put_be32(nlh, NFTA_META_DREG, F562_RD_DREG);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

static int f569_gu_rule(void)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	unsigned char v4 = 2;		/* NFPROTO_IPV4 */
	int acks = 0;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			NFPROTO_INET);
	put_str(nlh, NFTA_RULE_TABLE, "e69a");
	put_str(nlh, NFTA_RULE_CHAIN, "gu");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	f569_meta_nfproto(nlh);
	f562_cmp(nlh, F562_RD_DREG, &v4, 1);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

/* send one IPv4 datagram into the receiver netns (mode iso: x1 is local) */
static void f569_send4(int sock, uint32_t dst)
{
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(dst);
	sin.sin_port = htons(5000);
	sendto(sock, F568_PAY, sizeof(F568_PAY), 0, (struct sockaddr *)&sin,
	       sizeof(sin));
}

/* one counted arm: drain, read the counters, do something, read again */
static void f569_iso_arm(const char *arm, int nfl, int have_gu, int send4,
			 int sock, int action)
{
	unsigned long long c0, c1, g0, g1;
	struct f569_pl pl;
	char hx[600];
	int i;

	f569_drain(nfl, &pl);
	c0 = f555_count(NFPROTO_INET, "e69a", "pre0");
	g0 = have_gu ? f555_count(NFPROTO_INET, "e69a", "gu") : 0;
	if (action == 1) {			/* IPv6 on */
		f555_sysctl("/proc/sys/net/ipv6/conf/x0/disable_ipv6", "0");
	} else if (action == 2) {		/* off, then on again */
		f555_sysctl("/proc/sys/net/ipv6/conf/x0/disable_ipv6", "1");
		usleep(400000);
		f555_sysctl("/proc/sys/net/ipv6/conf/x0/disable_ipv6", "0");
	} else if (action == 3) {		/* off */
		f555_sysctl("/proc/sys/net/ipv6/conf/x0/disable_ipv6", "1");
	}
	if (send4)
		f569_send4(sock, A_X1);
	usleep(600000);
	f569_drain(nfl, &pl);
	c1 = f555_count(NFPROTO_INET, "e69a", "pre0");
	g1 = have_gu ? f555_count(NFPROTO_INET, "e69a", "gu") : 0;
	printf("F569 ISO|arm=%s|gu=%d|send4=%d|act=%d|cnt=%llu|gcnt=%llu|nmsg=%d|",
	       arm, have_gu, send4, action, c1 - c0, g1 - g0, pl.n);
	for (i = 0; i < pl.n && i < F569_NMSG; i++)
		printf("m%d=%s|", i,
		       f559_hexs(hx, sizeof(hx), pl.p[i], pl.plen[i]));
	printf("\n");
}

static void f569_sec_iso(void)
{
	static struct f568_door ISO = { "iso", NFPROTO_INET, "e69a", NULL,
					NF_INET_POST_, 0, 10 };
	int rfd, acks = 0, i, rc, s;

	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	if (link_add_veth("x0", "x1"))
		printf("F569 FAIL|veth x\n");
	set_up("x0");
	set_up("x1");
	f555_addr_add("x0", htonl(A_X0), 24);
	f555_addr_add("x1", htonl(A_X1), 24);
	f555_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/disable_ipv6", "1");

	if (add_table(NFPROTO_INET, "e69a") ||
	    f556_add_chain(NFPROTO_INET, "e69a", "pre0", NF_INET_POST_, 0, 1,
			   NULL) ||
	    f556_add_chain(NFPROTO_INET, "e69a", "gu", NF_INET_POST_, 0, 1,
			   NULL)) {
		printf("F569 FAIL|chains\n");
		return;
	}
	rc = f568_rule(&ISO, "pre0", "p", 0, 0, 0, NULL, 0, 0, 0, &acks);
	printf("F569 ISO_RULE|rc=%d|acks=%d\n", rc, acks);
	rfd = nfl_open(5);
	printf("F569 NFL|%d\n", rfd);
	s = f564_udp_bind(AF_INET, A_X0, NULL, 40000);
	printf("F569 SOCK|%d\n", s);

	/* 1. IPv6 off: the datagram, and the ICMP error it provokes, are the
	 *    only two packets the chain can see */
	f569_iso_arm("ctl4", rfd, 0, 1, s, 0);

	/* 2. IPv6 enabled on x0 and not a byte sent: whatever the chain
	 *    counts here was emitted by the IPv6 stack, not by the rule */
	f569_iso_arm("v6on", rfd, 0, 0, s, 1);
	usleep(500000);
	f569_iso_arm("v6on2", rfd, 0, 0, s, 0);

	/* 3. the same enable *and* one IPv4 datagram in one arm: the two
	 *    families counted by one `inet` counter */
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/disable_ipv6", "1");
	usleep(400000);
	f569_iso_arm("v6plus", rfd, 0, 1, s, 1);

	/* 4. the same with `meta nfproto ipv4` in front of a second counter */
	rc = f569_gu_rule();
	printf("F569 ISO_GU|rc=%d\n", rc);
	f569_iso_arm("guard", rfd, 1, 1, s, 2);

	/* 5. IPv6 off again: the IPv6 half disappears, the IPv4 half does not */
	f569_iso_arm("v6off", rfd, 1, 1, s, 3);

	/* 6. controls: nothing at all, four times */
	f569_iso_arm("quiet", rfd, 1, 0, s, 0);
	for (i = 0; i < 3; i++) {
		usleep(400000);
		f569_iso_arm("quiet2", rfd, 1, 0, s, 0);
	}
	f569_iso_arm("state", rfd, 1, 0, s, 0);
	printf("F569 ISO_END|dad=%llu|dis=%llu\n",
	       f567_read_ll("/proc/sys/net/ipv6/conf/x0/accept_dad"),
	       f567_read_ll("/proc/sys/net/ipv6/conf/x0/disable_ipv6"));
	close(s);
}

/* ---------- the IPv6 environment of mode `v6` ---------- */

static void f569_setup_v6(void)
{
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	if (link_add_veth("x0", "x1"))
		printf("F569 FAIL|veth x\n");
	if (link_add_veth("o0", "o1"))
		printf("F569 FAIL|veth o\n");
	if (mac_get("x1", X1_MAC))
		printf("F569 FAIL|mac x1\n");
	set_up("x0"); set_up("x1"); set_up("o0"); set_up("o1");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/o0/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/o1/disable_ipv6", "0");
	usleep(600000);
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/accept_ra", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/rtr_solicitations", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	printf("F569 ADDR6|rc=%d\n", f564_addr6("x0", A6_X0, 64));
	printf("F569 SYS6|x0=%llu|o0=%llu|o1=%llu|o0rx=%llu|x0tx=%llu\n",
	       f567_read_ll("/proc/sys/net/ipv6/conf/x0/disable_ipv6"),
	       f567_read_ll("/proc/sys/net/ipv6/conf/o0/disable_ipv6"),
	       f567_read_ll("/proc/sys/net/ipv6/conf/o1/disable_ipv6"),
	       f567_read_ll("/sys/class/net/o0/statistics/rx_packets"),
	       f567_read_ll("/sys/class/net/x0/statistics/tx_packets"));
	usleep(300000);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "v6";
	char line[1024], hx[600];

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F569 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F569 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F569 KERNEL|7.3.4-T563\n");

	if (!strcmp(mode, "iso")) {
		f569_sec_iso();
		printf("F569 DONE\n");
		return 0;
	}

	f569_setup_v6();
	{
		int rc = f569_start_child();

		printf("F569 FORK|rc=%d|pid=%d\n", rc, (int)CHILD);
	}
	{
		int n;

		if (f568_read_line(line, (int)sizeof(line), 20000) < 0 || line[0] != 'U')
			printf("F569 FAIL|child unshare|%s\n", line);
		else
			printf("F569 CHILD|%s\n", line);
		printf("F569 MOVE|rc=%d\n", f568_move_link("x1", (int)CHILD));
		f568_ask("C");
		for (;;) {
			if (f568_read_line(line, (int)sizeof(line), 20000) < 0) {
				printf("F569 FAIL|child cfg\n");
				break;
			}
			printf("F569 CHILDR|%s\n", line);
			n = (int)strlen(line);
			if (!strncmp(line, "READY", 5) || (n && line[0] == 'E'))
				break;
		}
	}
	{
		unsigned char mo[6];
		int rfd;

		if (mac_get("o0", mo))
			printf("F569 FAIL|mac o0\n");
		FWD6_LEN = f569_mk6(FWD6, mo, A6_FS, A6_X1, 40000, 5000);
		printf("F569 FRAME|fwd|len=%d|wire=%s\n", FWD6_LEN,
		       f559_hexs(hx, sizeof(hx), FWD6, FWD6_LEN));
		LOC6_SOCK = f564_udp_bind(AF_INET6, 0, A6_X0, 40000);
		printf("F569 SOCK|loc6=%d\n", LOC6_SOCK);
		printf("F569 NEIGH6|rc=%d\n", f569_neigh6_add("x0", A6_X1, X1_MAC));
		rfd = nfl_open(5);
		printf("F569 NFL|%d\n", rfd);
		if (f568_chains()) {
			printf("F569 FAIL|chains\n");
			return 0;
		}
		{
			struct f569_rep6 r;
			int k, got = 0;

			memset(&r, 0, sizeof(r));
			f568_flush_all();
			for (k = 0; k < 6; k++) {
				struct sockaddr_in6 sa;

				memset(&sa, 0, sizeof(sa));
				sa.sin6_family = AF_INET6;
				memcpy(&sa.sin6_addr, A6_X1, 16);
				sa.sin6_port = htons(5000);
				sendto(LOC6_SOCK, F568_PAY, F569_PAY, 0,
				       (struct sockaddr *)&sa, sizeof(sa));
				usleep(150000);
				if (f569_snapshot6(&r) == 0 && r.u6n > 0) {
					got = 1;
					break;
				}
			}
			printf("F569 WARM|got=%d|tapn=%d|u6n=%d|i6deliv=%llu\n",
			       got, r.tapn, r.u6n, r.i6deliv);
			printf("F569 P6OUT|req=%llu|noroute=%llu|discard=%llu|tx=%llu\n",
			       f564_snmp6("Ip6OutRequests"),
			       f564_snmp6("Ip6OutNoRoutes"),
			       f564_snmp6("Ip6OutDiscards"),
			       f564_snmp6("Ip6OutTransmits"));
		}
		f569_sec_v6(rfd);
	}
	f568_ask("Q");
	printf("F569 DONE\n");
	return 0;
}
