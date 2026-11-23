/* differ582_add.c -- turn 582 (F60): THE FIXUP IS SKIPPED ON THE PACKETS THAT
 * TRUST SOMEBODY ELSE -- AND ON A VETH THAT SOMEBODY IS NOBODY.
 *
 *  Two debts named in F59 §10.
 *
 *  1. CHECKSUM_PARTIAL.  Every frame this project ever measured was thrown in
 *     with AF_PACKET, i.e. CHECKSUM_NONE.  The whole fixup block of
 *     nft_payload_set_eval() is guarded by
 *
 *         (csum_type == INET || csum_flags) &&
 *         ((base != TRANSPORT_HEADER && base != INNER_HEADER) ||
 *          skb->ip_summed != CHECKSUM_PARTIAL)
 *
 *     so on a packet whose L4 checksum "somebody else" will compute, a store
 *     at the transport base writes its bytes and NOTHING is fixed -- neither
 *     `csum type inet` nor `csum flags`.  veth advertises NETIF_F_HW_CSUM and
 *     forwards the skb without computing anything, and skb_scrub_packet()
 *     (dev.c) does not touch ip_summed/csum_start: the flag arrives at the far
 *     end still saying "the hardware pays".  On the receive side the same flag
 *     makes skb_csum_unnecessary() true, so UDP never verifies.  One flag, two
 *     readers, opposite conclusions.
 *
 *  2. IPv4 with options.  nft_nh_write_ok_ip4() is a switch over
 *     offsetof(struct iphdr, ...) -- a 20-byte template -- while a legal IPv4
 *     header is ihl*4 <= 60 bytes.  Meanwhile nft_thoff() = ihl*4, so @th
 *     follows the header while @nh cannot.
 *
 *  Mode `part`, topology: parent netns = US (device x0, fd02::91/64,
 *  10.59.0.1/24, the receiving sockets on 5000, the nft tables, one AF_PACKET
 *  tap).  Child netns (unshare in a forked child) = THE WIRE (x1,
 *  fd02::11/64, 10.59.0.11/24).  Per arm the child either sendto()s one
 *  18-byte UDP datagram from a socket bound to port 43580 (provenance s) or
 *  injects with AF_PACKET the same 18 bytes in a frame built by hand
 *  (provenance p) -- same frame bytes, same rule, same receiving socket.
 *
 *  Mode `opt`: the F59 topology (one netns, x0 -> x1), AF_PACKET frames only,
 *  door ipv4 prerouting, header lengths 4/5/6/15, two fragments.
 *
 *  doors (part): 0 n0 = netdev ingress x0 | 1 g6 = ip6 prerouting |
 *                2 g4 = ip4 prerouting.   plus one witness chain per
 *                layer-3 door (prio 20) that logs every frame: PR / Q4.
 *
 *  Frames: F1 IPv6/UDP (14+40+8+18 = 80 B), F2 IPv4/UDP ihl 5 (60 B),
 *          F6 ihl 6 (64 B), F7 ihl 15 (100 B), F8 ihl 4, F9 ihl 15 totlen 30,
 *          F11 first fragment (MF), F12 non-first fragment (offset 1480).
 *          Payload byte i = 0x80+i, so a written immediate is locatable.
 */

#define F582_GROUP	82
#define F582_SPORT	43580
#define F582_DPORT	5000
#define F582_PAY	18
#define B582_NH		1
#define B582_TH		2

#define A82_IP4_S	0x0a3b000bU	/* 10.59.0.11 the sender    */
#define A82_IP4_D	0x0a3b0001U	/* 10.59.0.1  us            */
#define A82_IP4_X	0x0a3b0063U	/* 10.59.0.99 written saddr */

static const unsigned char A82_S6[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x11 };
static const unsigned char A82_D6[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					  0x00, 0x00, 0x00, 0x91 };
static const unsigned char A82_BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* ---------- the doors --------------------------------------------------- */

struct f582_door {
	uint8_t fam;
	const char *tbl;
	const char *chn;
	const char *dev;
	uint32_t hook;
	int prio;
	const char *name;
};

static const struct f582_door DP582[3] = {
	{ NFPROTO_NETDEV, "f82n", "c0", "x0", 0, 0, "n0" },
	{ NFPROTO_IPV6,   "f82g", "c0", NULL, 0, 0, "g6" },
	{ NFPROTO_IPV4,   "f82p", "c0", NULL, 0, 0, "g4" },
};

static int F582_U6 = -1, F582_U4 = -1;

/* ---------- frames ------------------------------------------------------ */

static unsigned short f582_csum(const unsigned char *b, int n)
{
	unsigned int sum = 0;
	int i;

	for (i = 0; i + 1 < n; i += 2)
		sum += (unsigned int)((b[i] << 8) | b[i + 1]);
	if (n & 1)
		sum += (unsigned int)(b[n - 1] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (unsigned short)(~sum & 0xffff);
}

static void f582_payload(unsigned char *p, int n)
{
	int i;

	for (i = 0; i < n; i++)
		p[i] = (unsigned char)(0x80 + i);
}

/* F1: IPv6/UDP, checksum from the pseudo header. */
static int f582_mk6(unsigned char *out, const unsigned char *dst,
		    const unsigned char *src, unsigned short sport,
		    unsigned short dport)
{
	int off = 14, tot = 8 + F582_PAY;
	unsigned char *ip, *udp, tmp[192];
	unsigned short c;

	memset(out, 0, 192);
	memcpy(out, dst, 6);
	memcpy(out + 6, src, 6);
	out[12] = 0x86;
	out[13] = 0xdd;
	ip = out + off;
	udp = ip + 40;
	ip[0] = 0x60;
	ip[4] = (unsigned char)(tot >> 8);
	ip[5] = (unsigned char)(tot & 0xff);
	ip[6] = 17;
	ip[7] = 64;
	memcpy(ip + 8, A82_S6, 16);
	memcpy(ip + 24, A82_D6, 16);
	udp[0] = (unsigned char)(sport >> 8);
	udp[1] = (unsigned char)(sport & 0xff);
	udp[2] = (unsigned char)(dport >> 8);
	udp[3] = (unsigned char)(dport & 0xff);
	udp[4] = (unsigned char)(tot >> 8);
	udp[5] = (unsigned char)(tot & 0xff);
	f582_payload(udp + 8, F582_PAY);
	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, ip + 8, 32);
	tmp[32] = 0;
	tmp[33] = 17;
	tmp[34] = (unsigned char)(tot >> 8);
	tmp[35] = (unsigned char)(tot & 0xff);
	memcpy(tmp + 36, udp, (size_t)tot);
	c = f582_csum(tmp, 36 + tot);
	if (!c)
		c = 0xffff;
	udp[6] = (unsigned char)(c >> 8);
	udp[7] = (unsigned char)(c & 0xff);
	return off + 40 + tot;
}

/* F2/F6/F7/F8/F9/F11/F12: IPv4/UDP with a variable header.
 * ihl 5 = plain; >5 = options 01..01,00; fragoff/mf make fragments;
 * totlen_override != 0 fakes a short total length (F9). */
static int f582_mk4(unsigned char *out, const unsigned char *dst,
		    const unsigned char *src, int ihl, unsigned int fragoff,
		    int mf, int totlen_override)
{
	int off = 14, hl = ihl * 4, tot, flen;
	unsigned char *ip, *udp, tmp[192];
	unsigned short c;
	unsigned int fo = 0;
	int i, complete = !fragoff && !mf;

	tot = totlen_override ? totlen_override : hl + 8 + F582_PAY;
	memset(out, 0, 192);
	memcpy(out, dst, 6);
	memcpy(out + 6, src, 6);
	out[12] = 0x08;
	out[13] = 0x00;
	ip = out + off;
	udp = ip + hl;
	ip[0] = (unsigned char)(0x40 | (ihl & 0x0f));
	ip[1] = 0;
	ip[2] = (unsigned char)(tot >> 8);
	ip[3] = (unsigned char)(tot & 0xff);
	ip[4] = 0x00;
	ip[5] = 0x00;
	ip[8] = 64;
	ip[9] = 17;
	ip[10] = 0;
	ip[11] = 0;
	be32_out(ip + 12, A82_IP4_S);
	be32_out(ip + 16, A82_IP4_D);
	for (i = 20; i < hl; i++)
		ip[i] = 0x01;			/* NOP */
	if (hl > 20)
		ip[hl - 1] = 0x00;		/* EOL */
	if (mf)
		fo |= 0x2000;
	else if (!fragoff)
		fo |= 0x4000;			/* DF, like the socket's own */
	fo |= (fragoff / 8) & 0x1fff;
	ip[6] = (unsigned char)(fo >> 8);
	ip[7] = (unsigned char)(fo & 0xff);
	if (totlen_override && totlen_override < hl) {
		c = f582_csum(ip, hl);
		ip[10] = (unsigned char)(c >> 8);
		ip[11] = (unsigned char)c;
		flen = off + hl;
		return flen < 60 ? 60 : flen;
	}
	if (complete && !totlen_override) {
		udp[0] = (unsigned char)(F582_SPORT >> 8);
		udp[1] = (unsigned char)(F582_SPORT & 0xff);
		udp[2] = (unsigned char)(F582_DPORT >> 8);
		udp[3] = (unsigned char)(F582_DPORT & 0xff);
		udp[4] = (unsigned char)((8 + F582_PAY) >> 8);
		udp[5] = (unsigned char)((8 + F582_PAY) & 0xff);
		udp[6] = 0;
		udp[7] = 0;
		f582_payload(udp + 8, F582_PAY);
		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, ip + 12, 8);
		tmp[8] = 0;
		tmp[9] = 17;
		tmp[10] = (unsigned char)((8 + F582_PAY) >> 8);
		tmp[11] = (unsigned char)(8 + F582_PAY);
		memcpy(tmp + 12, udp, (size_t)(8 + F582_PAY));
		c = f582_csum(tmp, 12 + 8 + F582_PAY);
		if (!c)
			c = 0xffff;
		udp[6] = (unsigned char)(c >> 8);
		udp[7] = (unsigned char)(c & 0xff);
	} else if (fragoff) {
		/* non-first fragment: raw data, no L4 header */
		f582_payload(udp, 16);
	} else {
		/* first fragment: the whole UDP header and payload */
		udp[0] = (unsigned char)(F582_SPORT >> 8);
		udp[1] = (unsigned char)(F582_SPORT & 0xff);
		udp[2] = (unsigned char)(F582_DPORT >> 8);
		udp[3] = (unsigned char)(F582_DPORT & 0xff);
		udp[4] = (unsigned char)((8 + F582_PAY) >> 8);
		udp[5] = (unsigned char)((8 + F582_PAY) & 0xff);
		udp[6] = 0xab;
		udp[7] = 0xcd;
		f582_payload(udp + 8, F582_PAY);
	}
	c = f582_csum(ip, hl);
	ip[10] = (unsigned char)(c >> 8);
	ip[11] = (unsigned char)c;
	flen = off + tot;
	return flen < 60 ? 60 : flen;
}

static int f582_optframe(unsigned char *out, int id,
			 const unsigned char *dst, const unsigned char *src)
{
	switch (id) {
	case 2:
		return f582_mk4(out, dst, src, 5, 0, 0, 0);
	case 6:
		return f582_mk4(out, dst, src, 6, 0, 0, 0);
	case 7:
		return f582_mk4(out, dst, src, 15, 0, 0, 0);
	case 8:
		return f582_mk4(out, dst, src, 4, 0, 0, 0);
	case 9:
		return f582_mk4(out, dst, src, 15, 0, 0, 30);
	case 11:
		return f582_mk4(out, dst, src, 5, 0, 1, 0);
	case 12:
		return f582_mk4(out, dst, src, 5, 1480, 0, 36);
	}
	return -1;
}

/* the frame signature: payload byte 0..3 = 80 81 82 83 */
static int f582_needle(const unsigned char *b, int n)
{
	int i;

	for (i = 0; i + 4 <= n; i++)
		if (b[i] == 0x80 && b[i + 1] == 0x81 && b[i + 2] == 0x82 &&
		    b[i + 3] == 0x83)
			return 1;
	return 0;
}

/* ---------- a frame thrown in on a named device ------------------------- */

static int f582_send_on(const unsigned char *f, int flen, const char *dev)
{
	struct sockaddr_ll sa;
	int s, rc, ifi = f555_ifindex(dev);

	if (ifi < 0)
		return -10;
	s = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
	if (s < 0)
		return -errno;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = ifi;
	sa.sll_halen = 6;
	memcpy(sa.sll_addr, f, 6);
	rc = (int)sendto(s, f, (size_t)flen, 0, (struct sockaddr *)&sa,
			 sizeof(sa));
	close(s);
	return rc == flen ? flen : -errno;
}

/* ---------- the receiving sockets --------------------------------------- */

struct f582_rx {
	int n, len, sport;
	unsigned char p[64];
};

static void f582_drain(int s, struct f582_rx *r)
{
	unsigned char b[512];
	int got, first = 1;

	memset(r, 0, sizeof(*r));
	r->len = -1;
	r->sport = -1;
	if (s < 0)
		return;
	for (;;) {
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);

		memset(&ss, 0, sizeof(ss));
		got = (int)recvfrom(s, b, sizeof(b), MSG_DONTWAIT,
				    (struct sockaddr *)&ss, &sl);
		if (got < 0)
			break;
		r->n++;
		if (first) {
			int k = got < (int)sizeof(r->p) ? got :
				(int)sizeof(r->p);

			first = 0;
			r->len = got;
			memcpy(r->p, b, (size_t)k);
			if (ss.ss_family == AF_INET6) {
				struct sockaddr_in6 *s6 = (void *)&ss;

				r->sport = (int)ntohs(s6->sin6_port);
			} else if (ss.ss_family == AF_INET) {
				struct sockaddr_in *s4 = (void *)&ss;

				r->sport = (int)ntohs(s4->sin_port);
			}
		}
	}
}

/* ---------- the tap with auxdata ---------------------------------------- */

struct f582_tap {
	int fd;
	int n, flen, len;
	int auxn, astat, atci, apkt;
	unsigned char b[192];
};

static struct f582_tap T582;

static void f582_tap_open(const char *dev)
{
	struct sockaddr_ll sll;
	int one = 1, idx = f555_ifindex(dev);

	T582.fd = -1;
	T582.n = 0;
	if (idx < 0)
		return;
	T582.fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (T582.fd < 0)
		return;
	setsockopt(T582.fd, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one));
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = idx;
	if (bind(T582.fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		close(T582.fd);
		T582.fd = -1;
		return;
	}
	fcntl(T582.fd, F_SETFL, fcntl(T582.fd, F_GETFL, 0) | O_NONBLOCK);
}

static void f582_tap_drain(void)
{
	unsigned char b[2048], cb[256];

	T582.n = 0;
	T582.flen = -1;
	T582.len = -1;
	T582.auxn = 0;
	T582.astat = -1;
	T582.atci = -1;
	T582.apkt = -1;
	if (T582.fd < 0)
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
		r = (int)recvmsg(T582.fd, &msg, MSG_DONTWAIT);
		if (r <= 0)
			break;
		if (from.sll_pkttype == PACKET_OUTGOING)
			continue;
		if (!f582_needle(b, r))
			continue;
		T582.n++;
		if (T582.len >= 0)
			continue;
		T582.flen = r;
		k = r < (int)sizeof(T582.b) ? r : (int)sizeof(T582.b);
		memcpy(T582.b, b, (size_t)k);
		T582.len = k;
		T582.apkt = (int)from.sll_pkttype;
		for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
			struct tpacket_auxdata aux;

			if (cm->cmsg_level != SOL_PACKET ||
			    cm->cmsg_type != PACKET_AUXDATA)
				continue;
			if (cm->cmsg_len < CMSG_LEN(sizeof(aux)))
				continue;
			memcpy(&aux, CMSG_DATA(cm), sizeof(aux));
			T582.auxn++;
			if (T582.astat < 0) {
				T582.astat = (int)aux.tp_status;
				T582.atci = (int)aux.tp_vlan_tci;
			}
		}
	}
}

/* ---------- snmp -------------------------------------------------------- */

struct f582_s4 {
	unsigned long long in, hdr, csum, addr, uk, disc, deliv;
	unsigned long long udp, udperr, udpnop;
};

static void f582_snmp4(struct f582_s4 *s)
{
	memset(s, 0, sizeof(*s));
	s->in = f564_snmp("Ip", "InReceives");
	s->hdr = f564_snmp("Ip", "InHdrErrors");
	s->csum = f564_snmp("Ip", "InCsumErrors");
	s->addr = f564_snmp("Ip", "InAddrErrors");
	s->uk = f564_snmp("Ip", "InUnknownProtos");
	s->disc = f564_snmp("Ip", "InDiscards");
	s->deliv = f564_snmp("Ip", "InDelivers");
	s->udp = f564_snmp("Udp", "InDatagrams");
	s->udperr = f564_snmp("Udp", "InErrors");
	s->udpnop = f564_snmp("Udp", "NoPorts");
}

/* ---------- the arms ---------------------------------------------------- */

struct f582_arm {
	const char *name;
	char prov;		/* 's' socket datagram, 'p' AF_PACKET frame */
	int ver;		/* 4 or 6 */
	int door;
	int base;
	int store;
	unsigned int off, len;
	const char *hex;
	int ct;
	unsigned int co;
	unsigned int cf;
};

static const struct f582_arm AP582[] = {
	/* --- census: each door, each provenance, no store --- */
	{ "c_n0_s6",	's', 6, 0, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_n0_p6",	'p', 6, 0, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_n0_s4",	's', 4, 0, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_n0_p4",	'p', 4, 0, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_g6_s6",	's', 6, 1, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "c_g4_s4",	's', 4, 2, 0, 0, 0, 0, NULL, 0, 0, 0 },
	/* --- A: one @th store, IPv6, two provenances --- */
	{ "s_th8_n0",	's', 6, 0, B582_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "p_th8_n0",	'p', 6, 0, B582_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "s_th8_n0_cs", 's', 6, 0, B582_TH, 1, 8, 4, "a0a1a2a3",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	{ "p_th8_n0_cs", 'p', 6, 0, B582_TH, 1, 8, 4, "a0a1a2a3",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	{ "s_th8_n0_fl", 's', 6, 0, B582_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 1 },
	{ "p_th8_n0_fl", 'p', 6, 0, B582_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 1 },
	{ "s_th8_g6",	's', 6, 1, B582_TH, 1, 8, 4, "a0a1a2a3", 0, 0, 0 },
	{ "s_th8_g6_cs", 's', 6, 1, B582_TH, 1, 8, 4, "a0a1a2a3",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	/* --- B: the store that covers the checksum field itself --- */
	{ "s_th6_n0",	's', 6, 0, B582_TH, 1, 6, 2, "dead", 0, 0, 0 },
	{ "p_th6_n0",	'p', 6, 0, B582_TH, 1, 6, 2, "dead", 0, 0, 0 },
	{ "p_th6_n0_cs", 'p', 6, 0, B582_TH, 1, 6, 2, "dead",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	{ "s_th6_n0_cs", 's', 6, 0, B582_TH, 1, 6, 2, "dead",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	/* --- C: IPv4, a field both checksums cover --- */
	{ "s4_sr_no",	's', 4, 0, B582_NH, 1, 12, 4, "0a3b0063", 0, 0, 0 },
	{ "p4_sr_no",	'p', 4, 0, B582_NH, 1, 12, 4, "0a3b0063", 0, 0, 0 },
	{ "s4_sr_cs",	's', 4, 0, B582_NH, 1, 12, 4, "0a3b0063",
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	{ "p4_sr_cs",	'p', 4, 0, B582_NH, 1, 12, 4, "0a3b0063",
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	{ "s4_sr_csfl", 's', 4, 0, B582_NH, 1, 12, 4, "0a3b0063",
	  NFT_PAYLOAD_CSUM_INET, 10, 1 },
	{ "p4_sr_csfl", 'p', 4, 0, B582_NH, 1, 12, 4, "0a3b0063",
	  NFT_PAYLOAD_CSUM_INET, 10, 1 },
	/* --- D: IPv6 source address -- the csum guard says no for IPV6 --- */
	{ "s6_sr_cs",	's', 6, 1, B582_NH, 1, 8, 16, NULL,
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	{ "p6_sr_cs",	'p', 6, 1, B582_NH, 1, 8, 16, NULL,
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	{ "s6_sr_fl",	's', 6, 1, B582_NH, 1, 8, 16, NULL, 0, 0, 1 },
	{ "p6_sr_fl",	'p', 6, 1, B582_NH, 1, 8, 16, NULL, 0, 0, 1 },
};
#define NAP582 ((int)(sizeof(AP582) / sizeof(AP582[0])))

static const struct f582_arm AO582[] = {
	/* --- E: the IPv4 header is not 20 bytes --- */
	{ "q_ctl5",	'p', 4, 2, 0, 0, 0, 0, NULL, 0, 0, 0 },	/* F2  */
	{ "q_ctl6",	'p', 4, 2, 0, 0, 0, 0, NULL, 0, 0, 0 },	/* F6  */
	{ "q_ctl15",	'p', 4, 2, 0, 0, 0, 0, NULL, 0, 0, 0 },	/* F7  */
	{ "q_o17_2",	'p', 4, 2, B582_NH, 1, 17, 2, "beef", 0, 0, 0 },
	{ "q_o18_2",	'p', 4, 2, B582_NH, 1, 18, 2, "beef", 0, 0, 0 },
	{ "q_o20_4",	'p', 4, 2, B582_NH, 1, 20, 4, "deadbeef", 0, 0, 0 },
	{ "q_o24_2",	'p', 4, 2, B582_NH, 1, 24, 2, "beef", 0, 0, 0 },
	{ "q_o40_2",	'p', 4, 2, B582_NH, 1, 40, 2, "beef", 0, 0, 0 },
	{ "q_o56_4",	'p', 4, 2, B582_NH, 1, 56, 4, "deadbeef", 0, 0, 0 },
	{ "q_o16_4",	'p', 4, 2, B582_NH, 1, 16, 4, "0a3b0063", 0, 0, 0 },
	{ "q_o12_4",	'p', 4, 2, B582_NH, 1, 12, 4, "0a3b0063", 0, 0, 0 },
	{ "q_o12_4_cs", 'p', 4, 2, B582_NH, 1, 12, 4, "0a3b0063",
	  NFT_PAYLOAD_CSUM_INET, 10, 0 },
	{ "q_o12_4_cf", 'p', 4, 2, B582_NH, 1, 12, 4, "0a3b0063",
	  NFT_PAYLOAD_CSUM_INET, 10, 1 },
	{ "q_o0_2",	'p', 4, 2, B582_NH, 1, 0, 2, "4f00", 0, 0, 0 },
	{ "q_o0_2s",	'p', 4, 2, B582_NH, 1, 0, 2, "4600", 0, 0, 0 },
	{ "q_o8_2s",	'p', 4, 2, B582_NH, 1, 8, 2, "3f11", 0, 0, 0 },
	{ "q_o8_2c",	'p', 4, 2, B582_NH, 1, 8, 2, "3f06", 0, 0, 0 },
	/* --- F: @th follows ihl, @nh does not --- */
	{ "q_th20_5",	'p', 4, 2, B582_TH, 1, 20, 2, "beef", 0, 0, 0 },
	{ "q_th20_5_cs", 'p', 4, 2, B582_TH, 1, 20, 2, "beef",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	{ "q_th20_6_cs", 'p', 4, 2, B582_TH, 1, 20, 2, "beef",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	{ "q_th0_6_cs",	'p', 4, 2, B582_TH, 1, 0, 2, "1234",
	  NFT_PAYLOAD_CSUM_INET, 6, 0 },
	/* --- G: what never reaches the door, and fragments --- */
	{ "q_ihl4",	'p', 4, 2, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "q_ihl4_st",	'p', 4, 2, B582_NH, 1, 12, 4, "0a3b0063", 0, 0, 0 },
	{ "q_short",	'p', 4, 2, 0, 0, 0, 0, NULL, 0, 0, 0 },
	{ "q_frag1",	'p', 4, 2, B582_TH, 1, 0, 2, "beef", 0, 0, 0 },
	{ "q_frag2",	'p', 4, 2, B582_TH, 1, 0, 2, "beef", 0, 0, 0 },
};
#define NAO582 ((int)(sizeof(AO582) / sizeof(AO582[0])))

static int f582_imm(const struct f582_arm *A, unsigned char *imm)
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
		imm[i] = (unsigned char)(0xa0 + i);
	return n;
}

/* counter, [store], log, accept */
static int f582_rule(const struct f582_arm *A, int idx,
		     const unsigned char *imm, int immlen)
{
	const struct f582_door *D = &DP582[A->door];
	struct nlmsghdr *nlh;
	struct nlattr *exprs, *e, *d;
	char pre[16];
	int acks = 0;

	snprintf(pre, sizeof(pre), "60:%02d", idx);
	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			D->fam);
	put_str(nlh, NFTA_RULE_TABLE, D->tbl);
	put_str(nlh, NFTA_RULE_CHAIN, D->chn);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	/* every frame here is UDP; this keeps the counter from counting the
	 * neighbour-discovery and ARP noise that also arrives at the door */
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
	log_expr(nlh, F582_GROUP, pre);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

static void f582_flush(void)
{
	int acks = 0, i;

	for (i = 0; i < 3; i++)
		f557_flush(DP582[i].fam, DP582[i].tbl, DP582[i].chn, &acks);
}

static int f582_deltable(uint8_t fam, const char *table)
{
	struct nlmsghdr *nlh;
	int acks = 0;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
			NLM_F_REQUEST | NLM_F_ACK, fam);
	put_str(nlh, NFTA_TABLE_NAME, table);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

/* ---------- the second netns ------------------------------------------- */

static int F582_UP[2], F582_DN[2];
static pid_t F582_PID = -1;
static unsigned char F582_X0M[6], F582_X1M[6];

static int f582_veth_ns(const char *a, const char *b, int pid)
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
	peer = attr_put(&req.nlh, (uint16_t)(VETH_INFO_PEER | NLA_F_NESTED), &zifi,
			(int)sizeof(zifi));
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

static int f582_wait_byte(int fd, int ms)
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

static int f582_cmd(int cmd)
{
	unsigned char c = (unsigned char)cmd;
	int r;

	if (write(F582_DN[1], &c, 1) != 1)
		return -2;
	r = f582_wait_byte(F582_UP[0], 5000);
	return r < 0 ? -3 : 0;
}

/* the child: THE WIRE.  Returns never. */
static void f582_child(void)
{
	unsigned char msg[8], c;
	unsigned char fr6[192], fr4[192];
	int s6, s4, l6, l4, i, rc;

	close(F582_UP[0]);
	close(F582_DN[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F582 CHILD|unshare=%d\n", errno);
		_exit(1);
	}
	c = 'U';
	if (write(F582_UP[1], &c, 1) != 1)
		_exit(2);
	if (read(F582_DN[0], msg, 7) != 7 || msg[0] != 'M')
		_exit(3);
	memcpy(F582_X0M, msg + 1, 6);
	set_up("lo");
	for (i = 0; i < 100 && f555_ifindex("x1") < 0; i++)
		usleep(20000);
	set_up("x1");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/autoconf", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x1/accept_ra", "0");
	rc = f564_addr6("x1", A82_S6, 64);
	rc |= f555_addr_add("x1", htonl(A82_IP4_S), 24);
	i = mac_get("x1", F582_X1M);
	printf("F582 CHILDEV|rc=%d|macrc=%d|x1=%d|m6=%02x%02x%02x%02x%02x%02x|"
	       "m4=%02x%02x%02x%02x%02x%02x\n", rc, i, f555_ifindex("x1"),
	       F582_X0M[0], F582_X0M[1], F582_X0M[2], F582_X0M[3],
	       F582_X0M[4], F582_X0M[5], F582_X1M[0], F582_X1M[1],
	       F582_X1M[2], F582_X1M[3], F582_X1M[4], F582_X1M[5]);
	s6 = f564_udp_bind(AF_INET6, 0, A82_S6, F582_SPORT);
	s4 = f564_udp_bind(AF_INET, A82_IP4_S, NULL, F582_SPORT);
	l6 = f582_mk6(fr6, F582_X0M, F582_X1M, F582_SPORT, F582_DPORT);
	l4 = f582_mk4(fr4, F582_X0M, F582_X1M, 5, 0, 0, 0);
	{
		char bx[1024];

		printf("F582 CHILDSOCK|s6=%d|s4=%d|l6=%d|l4=%d\n", s6, s4,
		       l6, l4);
		printf("F582 FRMPY|id=6|len=%d|hex=%s\n", l6,
		       f559_hexs(bx, sizeof(bx), fr6, l6));
		printf("F582 FRMPY|id=2|len=%d|hex=%s\n", l4,
		       f559_hexs(bx, sizeof(bx), fr4, l4));
	}
	c = 'R';
	if (write(F582_UP[1], &c, 1) != 1)
		_exit(4);
	for (;;) {
		struct sockaddr_in6 d6;
		struct sockaddr_in d4;

		if (read(F582_DN[0], &c, 1) != 1)
			_exit(0);
		if (c == 'q')
			_exit(0);
		memset(&d6, 0, sizeof(d6));
		d6.sin6_family = AF_INET6;
		memcpy(&d6.sin6_addr, A82_D6, 16);
		d6.sin6_port = htons(F582_DPORT);
		memset(&d4, 0, sizeof(d4));
		d4.sin_family = AF_INET;
		d4.sin_addr.s_addr = htonl(A82_IP4_D);
		d4.sin_port = htons(F582_DPORT);
		switch (c) {
		case 'w':
			rc = (int)sendto(s6, fr6 + 62, F582_PAY, 0,
					 (struct sockaddr *)&d6, sizeof(d6));
			rc += (int)sendto(s4, fr4 + 42, F582_PAY, 0,
					  (struct sockaddr *)&d4, sizeof(d4));
			printf("F582 CHILDW|rc=%d\n", rc);
			break;
		case '6':
			rc = (int)sendto(s6, fr6 + 62, F582_PAY, 0,
					 (struct sockaddr *)&d6, sizeof(d6));
			printf("F582 CHILDS|cmd=6|rc=%d|errno=%d\n", rc, errno);
			break;
		case '4':
			rc = (int)sendto(s4, fr4 + 42, F582_PAY, 0,
					 (struct sockaddr *)&d4, sizeof(d4));
			printf("F582 CHILDS|cmd=4|rc=%d|errno=%d\n", rc, errno);
			break;
		case 'p':
			rc = f582_send_on(fr6, l6, "x1");
			printf("F582 CHILDS|cmd=p|rc=%d\n", rc);
			break;
		case 'P':
			rc = f582_send_on(fr4, l4, "x1");
			printf("F582 CHILDS|cmd=P|rc=%d\n", rc);
			break;
		default:
			break;
		}
		c = 'D';
		if (write(F582_UP[1], &c, 1) != 1)
			_exit(5);
	}
}

/* ---------- one arm of mode part --------------------------------------- */

static void f582_arm_part(const struct f582_arm *A, int idx)
{
	struct f580_sn a, b;
	struct f582_s4 c, d;
	struct f575_pl pl;
	struct f582_rx r6, r4;
	struct f573_lst st0, st1;
	unsigned char imm[64];
	char hxi[512] = "-", h6[128] = "-", h4[128] = "-", pw[512] = "-";
	char tapx[512] = "-";
	char pretx[16] = "-", indev[20] = "-";
	char pindev[20] = "-", pph[512] = "-", ppre[8] = "-";
	char lgh[512] = "-";
	int rc = -99, nd = -1, ch = -1, nl = 0, ilen = -1;
	int pnl = 0, pplen = -1, i, cmd, lglen = -1;
	unsigned long long oth0, oth1;
	int oth_ok;

	f582_flush();
	(void)f582_drain(F582_U6, &r6);
	(void)f582_drain(F582_U4, &r4);
	f582_tap_drain();
	(void)f575_nfl_drain(&pl);
	if (A->store) {
		ilen = f582_imm(A, imm);
		rc = ilen < 0 ? -99 : f582_rule(A, idx, imm, ilen);
		f559_hexs(hxi, sizeof(hxi), imm, ilen > 0 ? ilen : 0);
	} else {
		rc = f582_rule(A, idx, NULL, 0);
	}
	f573_stats("x0", &st0);
	f580_snmp(&a);
	f582_snmp4(&c);
	cmd = A->prov == 's' ? (A->ver == 6 ? '6' : '4') :
		(A->ver == 6 ? 'p' : 'P');
	nd = f582_cmd(cmd);
	usleep(300000);
	f582_drain(F582_U6, &r6);
	f582_drain(F582_U4, &r4);
	f582_tap_drain();
	(void)f575_nfl_drain(&pl);
	f580_snmp(&b);
	f582_snmp4(&d);
	f573_stats("x0", &st1);
	oth_ok = st0.ok && st1.ok;
	oth0 = st0.other;
	oth1 = st1.other;
	for (i = 0; i < pl.n && i < F575_NPL; i++) {
		if (!strncmp(pl.m[i].prefix, "60:", 3)) {
			if (!nl) {
				struct f575_msg *M = &pl.m[i];

				nl = 1;
				lglen = M->plen;
				snprintf(pretx, sizeof(pretx), "%s", M->prefix);
				snprintf(indev, sizeof(indev), "%d:%s",
					 M->indev, f580_ifname(M->indev));
				f559_hexs(lgh, sizeof(lgh), M->p, M->plen);
			}
		} else if (!strcmp(pl.m[i].prefix, "PR") ||
			   !strcmp(pl.m[i].prefix, "Q4")) {
			if (!pnl) {
				struct f575_msg *Q = &pl.m[i];

				pnl = 1;
				snprintf(pindev, sizeof(pindev), "%d:%s",
					 Q->indev, f580_ifname(Q->indev));
				snprintf(ppre, sizeof(ppre), "%s", Q->prefix);
				pplen = Q->plen;
				f559_hexs(pph, sizeof(pph), Q->p, Q->plen);
			}
		}
	}
	ch = (int)f555_count(DP582[A->door].fam, DP582[A->door].tbl,
			     DP582[A->door].chn);
	if (r6.n)
		f559_hexs(h6, sizeof(h6), r6.p, r6.len);
	if (r4.n)
		f559_hexs(h4, sizeof(h4), r4.p, r4.len);
	if (T582.len >= 0)
		f559_hexs(tapx, sizeof(tapx), T582.b, T582.len);
	snprintf(pw, sizeof(pw), "%s", pph);
	printf("F582 ARM|i=%02d|name=%s|prov=%c|ver=%d|door=%d|base=%d|store=%d|"
	       "off=%u|len=%u|hex=%s|ct=%d|co=%u|cf=%u|rc=%d|cmdrc=%d|"
	       "ch=%d|nl=%d|pre=%s|indev=%s|lglen=%d|lg=%s|"
	       "u6n=%d|u6l=%d|u6s=%d|u6p=%s|u4n=%d|u4l=%d|u4s=%d|u4p=%s|"
	       "rcv=%llu|deliv=%llu|hdrerr=%llu|disc=%llu|udp6=%llu|"
	       "udperr6=%llu|ipin=%llu|iphdr=%llu|ipcsum=%llu|ipaddr=%llu|"
	       "ipdisc=%llu|ipdeliv=%llu|u4=%llu|u4err=%llu|"
	       "tapn=%d|taplen=%d|tapstat=%d|tap=%s|"
	       "pnl=%d|ppre=%s|pindev=%s|pplen=%d|pp=%s|oth_ok=%d|oth=%llu\n",
	       idx, A->name, A->prov, A->ver, A->door, A->base, A->store,
	       A->off, A->len, hxi, A->ct, A->co, A->cf,
	       rc, nd, ch, nl, pretx, indev, lglen, lgh,
	       r6.n, r6.len, r6.sport, h6,
	       r4.n, r4.len, r4.sport, h4,
	       b.rcv - a.rcv, b.deliv - a.deliv, b.hdrerr - a.hdrerr,
	       b.disc - a.disc, b.udp - a.udp, b.udperr - a.udperr,
	       d.in - c.in, d.hdr - c.hdr, d.csum - c.csum, d.addr - c.addr,
	       d.disc - c.disc, d.deliv - c.deliv, d.udp - c.udp,
	       d.udperr - c.udperr,
	       T582.n, T582.flen, T582.astat, tapx,
	       pnl, ppre, pindev, pplen, pw, oth_ok, oth1 - oth0);
	fflush(stdout);
}


/* ---------- mode part --------------------------------------------------- */

static int f582_part(void)
{
	static const char *old[] = { "x0", "x1" };
	struct f575_pl pl;
	unsigned char c, msg[8];
	int i, k = 0;

	f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	f555_sysctl("/proc/sys/net/ipv4/ip_forward", "0");
	for (i = 0; i < 2; i++)
		f558_link_del(old[i]);
	for (i = 0; i < 3; i++)
		f582_deltable(DP582[i].fam, DP582[i].tbl);
	if (pipe(F582_UP) || pipe(F582_DN)) {
		printf("F582 FAIL|pipe\n");
		return -1;
	}
	F582_PID = fork();
	if (F582_PID < 0) {
		printf("F582 FAIL|fork|%d\n", errno);
		return -1;
	}
	if (F582_PID == 0)
		f582_child();
	close(F582_UP[1]);
	close(F582_DN[0]);
	if (f582_wait_byte(F582_UP[0], 5000) != 'U') {
		printf("F582 FAIL|child_unshare\n");
		return -1;
	}
	k = f582_veth_ns("x0", "x1", (int)F582_PID);
	set_up("x0");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/disable_ipv6", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/accept_dad", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/dad_transmits", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/autoconf", "0");
	f555_sysctl("/proc/sys/net/ipv6/conf/x0/accept_ra", "0");
	f555_addr_add("x0", htonl(A82_IP4_D), 24);
	f564_addr6("x0", A82_D6, 64);
	mac_get("x0", F582_X0M);
	snprintf((char *)msg, sizeof(msg), "M%c%c%c%c%c%c", F582_X0M[0], F582_X0M[1],
		 F582_X0M[2], F582_X0M[3], F582_X0M[4], F582_X0M[5]);
	if (write(F582_DN[1], msg, 7) != 7 ||
	    f582_wait_byte(F582_UP[0], 20000) != 'R') {
		printf("F582 FAIL|child_ready\n");
		return -1;
	}
	F582_U6 = f564_udp_bind(AF_INET6, 0, A82_D6, F582_DPORT);
	F582_U4 = f564_udp_bind(AF_INET, A82_IP4_D, NULL, F582_DPORT);
	F579_U6 = F582_U6;
	F573_NFL = nfl_open(F582_GROUP);
	f582_tap_open("x0");
	printf("F582 ENV|veth=%d|x0=%d|u6=%d|u4=%d|nfl=%d|tap=%d|uid=%d\n",
	       k, f555_ifindex("x0"), F582_U6, F582_U4, F573_NFL, T582.fd,
	       (int)getuid());
	k = 0;
	for (i = 0; i < 3; i++) {
		k |= f579_tbl(DP582[i].fam, DP582[i].tbl);
		k |= f580_chn(DP582[i].fam, DP582[i].tbl, DP582[i].chn,
			      DP582[i].dev, DP582[i].hook, DP582[i].prio);
	}
	/* two witness chains: every frame that reaches layer 3 */
	k |= f580_chn(NFPROTO_IPV6, "f82g", "w6", NULL, 0, 20);
	k |= f580_chn(NFPROTO_IPV4, "f82p", "w4", NULL, 0, 20);
	printf("F582 WCHAINS|rc=%d\n", k);
	{
		struct nlmsghdr *nlh;
		struct nlattr *exprs;
		int acks = 0;
		static const char *tg[2] = { "f82g", "f82p" };
		static const char *tc[2] = { "w6", "w4" };
		static const char *tp[2] = { "PR", "Q4" };
		static const uint8_t tf[2] = { NFPROTO_IPV6, NFPROTO_IPV4 };

		for (i = 0; i < 2; i++) {
			unsigned char l4 = 17;

			nlh = msg_start(opbuf, (int)sizeof(opbuf),
					(NFNL_SUBSYS_NFTABLES << 8) |
					NFT_MSG_NEWRULE,
					NLM_F_REQUEST | NLM_F_ACK |
					NLM_F_CREATE | NLM_F_APPEND, tf[i]);
			put_str(nlh, NFTA_RULE_TABLE, tg[i]);
			put_str(nlh, NFTA_RULE_CHAIN, tc[i]);
			exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
			f567_meta_l4(nlh);
			f562_cmp(nlh, F562_RD_DREG, &l4, 1);
			log_expr(nlh, F582_GROUP, tp[i]);
			accept_expr(nlh);
			nest_end(nlh, exprs);
			f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
		}
	}
	/* warm-up: resolve ARP and ND before the first arm */
	(void)f582_cmd('w');
	usleep(300000);
	{
		struct f582_rx junk;

		(void)f582_drain(F582_U6, &junk);
		(void)f582_drain(F582_U4, &junk);
	}
	(void)f575_nfl_drain(&pl);
	f582_tap_drain();
	for (i = 0; i < NAP582; i++)
		f582_arm_part(&AP582[i], i);
	{
		unsigned char q = 'q';

		(void)write(F582_DN[1], &q, 1);
	}
	usleep(100000);
	if (F582_PID > 0) {
		kill(F582_PID, SIGKILL);
		waitpid(F582_PID, NULL, 0);
	}
	f582_flush();
	if (T582.fd >= 0)
		close(T582.fd);
	printf("F582 END|mode=part|arms=%d\n", NAP582);
	fflush(stdout);
	(void)c;
	return 0;
}

/* ---------- one arm of mode opt ---------------------------------------- */

static void f582_arm_opt(const struct f582_arm *A, int idx)
{
	struct f580_sn a, b;
	struct f582_s4 c, d;
	struct f575_pl pl;
	struct f582_rx r6, r4;
	unsigned char imm[64], fr[192];
	char hxi[512] = "-", h4[128] = "-", pw[512] = "-", tapx[512] = "-";
	char pretx[16] = "-", indev[20] = "-";
	char pindev[20] = "-", pph[512] = "-", ppre[8] = "-";
	char lgh[512] = "-";
	int rc = -99, ch = -1, nl = 0, ilen = -1, flen = -1, snd;
	int pnl = 0, pplen = -1, fid, i, lglen = -1;

	fid = 2;
	if (!strcmp(A->name, "q_ctl6") || !strcmp(A->name, "q_th20_6_cs") ||
	    !strcmp(A->name, "q_th0_6_cs"))
		fid = 6;
	else if (!strcmp(A->name, "q_ctl15") || !strcmp(A->name, "q_o17_2") ||
		 !strcmp(A->name, "q_o18_2") || !strcmp(A->name, "q_o20_4") ||
		 !strcmp(A->name, "q_o24_2") || !strcmp(A->name, "q_o40_2") ||
		 !strcmp(A->name, "q_o56_4") || !strcmp(A->name, "q_o16_4") ||
		 !strcmp(A->name, "q_o12_4") || !strcmp(A->name, "q_o12_4_cs") ||
		 !strcmp(A->name, "q_o12_4_cf") || !strcmp(A->name, "q_o0_2") ||
		 !strcmp(A->name, "q_o0_2s") || !strcmp(A->name, "q_o8_2s") ||
		 !strcmp(A->name, "q_o8_2c"))
		fid = 7;
	else if (!strcmp(A->name, "q_ihl4") || !strcmp(A->name, "q_ihl4_st"))
		fid = 8;
	else if (!strcmp(A->name, "q_short"))
		fid = 9;
	else if (!strcmp(A->name, "q_frag1"))
		fid = 11;
	else if (!strcmp(A->name, "q_frag2"))
		fid = 12;
	flen = f582_optframe(fr, fid, A82_BC, F582_X1M);
	f582_flush();
	(void)f582_drain(F582_U6, &r6);
	(void)f582_drain(F582_U4, &r4);
	f582_tap_drain();
	(void)f575_nfl_drain(&pl);
	if (A->store) {
		ilen = f582_imm(A, imm);
		rc = ilen < 0 ? -99 : f582_rule(A, idx, imm, ilen);
		f559_hexs(hxi, sizeof(hxi), imm, ilen > 0 ? ilen : 0);
	} else {
		rc = f582_rule(A, idx, NULL, 0);
	}
	f580_snmp(&a);
	f582_snmp4(&c);
	snd = f582_send_on(fr, flen, "x0");
	usleep(300000);
	f582_drain(F582_U6, &r6);
	f582_drain(F582_U4, &r4);
	f582_tap_drain();
	(void)f575_nfl_drain(&pl);
	f580_snmp(&b);
	f582_snmp4(&d);
	for (i = 0; i < pl.n && i < F575_NPL; i++) {
		if (!strncmp(pl.m[i].prefix, "60:", 3)) {
			if (!nl) {
				struct f575_msg *M = &pl.m[i];

				nl = 1;
				lglen = M->plen;
				snprintf(pretx, sizeof(pretx), "%s", M->prefix);
				snprintf(indev, sizeof(indev), "%d:%s",
					 M->indev, f580_ifname(M->indev));
				f559_hexs(lgh, sizeof(lgh), M->p, M->plen);
			}
		} else if (!strcmp(pl.m[i].prefix, "Q4")) {
			if (!pnl) {
				struct f575_msg *Q = &pl.m[i];

				pnl = 1;
				snprintf(pindev, sizeof(pindev), "%d:%s",
					 Q->indev, f580_ifname(Q->indev));
				snprintf(ppre, sizeof(ppre), "%s", Q->prefix);
				pplen = Q->plen;
				f559_hexs(pph, sizeof(pph), Q->p, Q->plen);
			}
		}
	}
	ch = (int)f555_count(DP582[A->door].fam, DP582[A->door].tbl,
			     DP582[A->door].chn);
	if (r4.n)
		f559_hexs(h4, sizeof(h4), r4.p, r4.len);
	if (T582.len >= 0)
		f559_hexs(tapx, sizeof(tapx), T582.b, T582.len);
	snprintf(pw, sizeof(pw), "%s", pph);
	printf("F582 ARM|i=%02d|name=%s|prov=p|ver=4|door=%d|base=%d|store=%d|"
	       "off=%u|len=%u|hex=%s|ct=%d|co=%u|cf=%u|fid=%d|flen=%d|rc=%d|"
	       "snd=%d|ch=%d|nl=%d|pre=%s|indev=%s|lglen=%d|lg=%s|"
	       "u6n=%d|u6l=%d|u6s=%d|u6p=-|u4n=%d|u4l=%d|u4s=%d|u4p=%s|"
	       "rcv=%llu|deliv=%llu|hdrerr=%llu|disc=%llu|udp6=%llu|"
	       "udperr6=%llu|ipin=%llu|iphdr=%llu|ipcsum=%llu|ipaddr=%llu|"
	       "ipdisc=%llu|ipdeliv=%llu|u4=%llu|u4err=%llu|"
	       "tapn=%d|taplen=%d|tapstat=%d|tap=%s|"
	       "pnl=%d|ppre=%s|pindev=%s|pplen=%d|pp=%s\n",
	       idx, A->name, A->door, A->base, A->store, A->off, A->len,
	       hxi, A->ct, A->co, A->cf, fid, flen, rc, snd, ch,
	       nl, pretx, indev, lglen, lgh,
	       r6.n, r6.len, r6.sport, r4.n, r4.len, r4.sport, h4,
	       b.rcv - a.rcv, b.deliv - a.deliv, b.hdrerr - a.hdrerr,
	       b.disc - a.disc, b.udp - a.udp, b.udperr - a.udperr,
	       d.in - c.in, d.hdr - c.hdr, d.csum - c.csum, d.addr - c.addr,
	       d.disc - c.disc, d.deliv - c.deliv, d.udp - c.udp,
	       d.udperr - c.udperr,
	       T582.n, T582.flen, T582.astat, tapx,
	       pnl, ppre, pindev, pplen, pw);
	fflush(stdout);
}


static int f582_opt(void)
{
	static const char *old[] = { "x0", "x1" };
	unsigned char fr[192];
	char hx[1024];
	int i, k = 0, n;

	f555_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f555_sysctl("/proc/sys/net/ipv4/ip_forward", "0");
	for (i = 0; i < 2; i++)
		f558_link_del(old[i]);
	for (i = 0; i < 3; i++)
		f582_deltable(DP582[i].fam, DP582[i].tbl);
	if (link_add_veth("x0", "x1")) {
		printf("F582 FAIL|veth\n");
		return -1;
	}
	set_up("x0");
	set_up("x1");
	f555_addr_add("x1", htonl(A82_IP4_D), 24);
	mac_get("x1", F582_X1M);
	F582_U4 = f564_udp_bind(AF_INET, A82_IP4_D, NULL, F582_DPORT);
	F582_U6 = -1;
	F573_NFL = nfl_open(F582_GROUP);
	f582_tap_open("x1");
	printf("F582 ENV|veth=0|x1=%d|u6=%d|u4=%d|nfl=%d|tap=%d|m1=%02x%02x"
	       "%02x%02x%02x%02x\n", f555_ifindex("x1"), F582_U6, F582_U4,
	       F573_NFL, T582.fd, F582_X1M[0], F582_X1M[1], F582_X1M[2],
	       F582_X1M[3], F582_X1M[4], F582_X1M[5]);
	k |= f579_tbl(NFPROTO_IPV4, "f82p");
	k |= f580_chn(NFPROTO_IPV4, "f82p", "c0", NULL, 0, 0);
	k |= f580_chn(NFPROTO_IPV4, "f82p", "w4", NULL, 0, 20);
	printf("F582 WCHAINS|rc=%d\n", k);
	{
		struct nlmsghdr *nlh;
		struct nlattr *exprs;
		int acks = 0;

		nlh = msg_start(opbuf, (int)sizeof(opbuf),
				(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
				NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
				NLM_F_APPEND, NFPROTO_IPV4);
		put_str(nlh, NFTA_RULE_TABLE, "f82p");
		put_str(nlh, NFTA_RULE_CHAIN, "w4");
		exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
		{
			unsigned char l4 = 17;

			f567_meta_l4(nlh);
			f562_cmp(nlh, F562_RD_DREG, &l4, 1);
		}
		log_expr(nlh, F582_GROUP, "Q4");
		accept_expr(nlh);
		nest_end(nlh, exprs);
		f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
	}
	for (i = 2; i <= 12; i++) {
		if (i == 3 || i == 4 || i == 5 || i == 10)
			continue;
		n = f582_optframe(fr, i, A82_BC, F582_X1M);
		if (n < 0)
			continue;
		printf("F582 FRMPY|id=%d|len=%d|hex=%s\n", i, n,
		       f559_hexs(hx, sizeof(hx), fr, n));
	}
	for (i = 0; i < NAO582; i++)
		f582_arm_opt(&AO582[i], i);
	f582_flush();
	if (T582.fd >= 0)
		close(T582.fd);
	printf("F582 END|mode=opt|arms=%d\n", NAO582);
	fflush(stdout);
	return 0;
}

/* ---------- entry ------------------------------------------------------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "part";

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("F582 BOOT|mode=%s|argc=%d\n", mode, argc);
	if (!strcmp(mode, "part"))
		return f582_part();
	if (!strcmp(mode, "opt"))
		return f582_opt();
	return f581_entry(argc, argv);
}
