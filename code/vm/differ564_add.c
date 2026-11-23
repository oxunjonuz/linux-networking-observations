/* differ564_add.c -- turn 564 / F42.
 *
 * Three sentences F41 left open, closed on the same image (7.3.4-T563,
 * sha 1efbc957...2033) -- no new kernel:
 *
 * DEBT 1 -- PPPoE in the PPPOX_BOUND state.
 * F41 measured only the socket queue: a PPPoX socket in PPPOX_CONNECTED gets
 * the frame via skb_queue_tail() and recv() returns it.  pppox.c's
 * PPPIOCGCHAN sets PPPOX_BOUND and pppoe_rcv_core() then calls
 * ppp_input(&po->chan, skb) instead -- and that is the first place in this
 * whole project where a byte written by a bridge rule reaches a *real IP
 * stack* as a packet: ppp_input -> ppp_receive_nonmp_frame -> skb_pull(2) ->
 * netif_rx on pppN -> ip_rcv.  Section `bound` attaches a real unit
 * (/dev/ppp: PPPIOCNEWUNIT + PPPIOCATTCHAN + PPPIOCCONNECT, no pppd, no
 * negotiation), brings pppN up, gives it 10.9.0.7 peer 10.1.0.1 and binds a
 * UDP socket on 10.9.0.7:5000 -- so the oracle is a userspace recv() of the
 * 18 payload bytes, plus IpInReceives/InHdrErrors/InDelivers, plus pppN's own
 * /proc/net/dev rx bytes, plus the unit file queue (control frames).
 *
 * DEBT 2 -- IPv6 inside PPPoE.
 * nf_flow_pppoe_proto() knows PPP_IPV6, so `meta protocol` on a PPPoE frame
 * carrying 0x0057 sets ethertype 0x86dd and nhoff = 8, and the ip6 white list
 * applies to the store -- which still lands at skb_network_offset() = 14, i.e.
 * EIGHT bytes before the IPv6 header.  One cell of that list (offset 7,
 * hop_limit, len 1) lands on wire byte 21: the low byte of the PPP protocol
 * field, the field that decides data-vs-control.  Section `v6p` measures it,
 * with a real UDPv6 socket on fd00::99:9:5000 and a correct UDPv6 checksum.
 *
 * DEBT 3 -- ARP behind a real VLAN device.
 * F41 could only say "vid != 0 is invisible to the ARP stack".  Section
 * `vlan` sends the same single-tagged ARP frame twice: before `v1` (a vlan on
 * br0, id 100) exists and after -- vlan_do_receive() returns true only in the
 * second case.
 *
 * Views: r0 = the far side of the bridge (AF_PACKET), fd_u = the ppp unit file
 * (control/unknown PPP frames), fd_c = the channel file, u4/u6 = the UDP
 * sockets on pppN.
 */

#include <linux/if_pppox.h>
#include <linux/ppp-ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ---------- counters ---------- */

static unsigned long long f564_snmp(const char *group, const char *field)
{
	FILE *f = fopen("/proc/net/snmp", "r");
	char hdr[4096], val[4096];
	unsigned long long out = 0;
	size_t gl = strlen(group);

	if (!f)
		return 0;
	while (fgets(hdr, sizeof(hdr), f)) {
		char *save = NULL, *tok;
		int idx = 0, want = -1;

		if (strncmp(hdr, group, gl) || hdr[gl] != ':')
			continue;
		if (!fgets(val, sizeof(val), f))
			break;
		tok = strtok_r(hdr + gl + 1, " \t\n", &save);
		while (tok) {
			idx++;
			if (!strcmp(tok, field)) {
				want = idx;
				break;
			}
			tok = strtok_r(NULL, " \t\n", &save);
		}
		if (want < 0)
			break;
		save = NULL;
		idx = 0;
		tok = strtok_r(val + gl + 1, " \t\n", &save);
		while (tok) {
			idx++;
			if (idx == want) {
				out = strtoull(tok, NULL, 10);
				break;
			}
			tok = strtok_r(NULL, " \t\n", &save);
		}
		break;
	}
	fclose(f);
	return out;
}

static unsigned long long f564_snmp6(const char *name)
{
	FILE *f = fopen("/proc/net/snmp6", "r");
	char line[256], nm[64];
	unsigned long long x, v = 0;

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%63s %llu", nm, &x) == 2 && !strcmp(nm, name)) {
			v = x;
			break;
		}
	}
	fclose(f);
	return v;
}

/* /proc/net/dev: the device's own rx bytes/packets (ppp adds
 * skb->len - PPP_PROTO_LEN before the protocol decision, so this counts frames
 * the IP stack never sees).  sysfs is useless here: sysfs is mounted before
 * unshare() and does not know this netns. */
static void f564_devrx(const char *dev, unsigned long long *b,
		       unsigned long long *p)
{
	FILE *f = fopen("/proc/net/dev", "r");
	char line[512];
	size_t dl = strlen(dev);

	*b = 0;
	*p = 0;
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *c = strchr(line, ':'), *s = line;

		while (*s == ' ' || *s == '\t')
			s++;
		if (!c || strncmp(s, dev, dl) || s + dl != c)
			continue;
		if (sscanf(c + 1, "%llu %llu", b, p) != 2)
			*b = *p = 0;
		break;
	}
	fclose(f);
}

/* read everything queued on a ppp file fd (one skb per read) */
static int f564_drainf(int fd, unsigned char *buf, int max, int ms)
{
	int total = 0;

	if (fd < 0)
		return -1;
	for (;;) {
		struct timeval tv;
		fd_set rfds;
		int r;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = ms * 1000;
		if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0)
			break;
		r = (int)read(fd, buf + total, (size_t)(max - total));
		if (r <= 0)
			break;
		total += r;
		if (total > max - 8)
			break;
	}
	return total;
}

/* ---------- the bound unit ---------- */

struct f564_ppp {
	int sock, fd_u, fd_c, unit, u4, u6, ok;
	char dev[IFNAMSIZ];
};
static struct f564_ppp P564 = {
	.sock = -1, .fd_u = -1, .fd_c = -1, .unit = -1,
	.u4 = -1, .u6 = -1, .ok = 0, .dev = ""
};
static const char *F564_SEC = "-";

static int f564_addr_peer(const char *dev, uint32_t local_be, uint32_t peer_be,
			  int plen)
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
	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_prefixlen = (uint8_t)plen;
	req.ifa.ifa_index = (uint32_t)f555_ifindex(dev);
	attr_put(&req.nlh, IFA_LOCAL, &local_be, 4);
	attr_put(&req.nlh, IFA_ADDRESS, &peer_be, 4);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

static int f564_addr6(const char *dev, const unsigned char *a, int plen)
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
	attr_put(&req.nlh, IFA_LOCAL, a, 16);
	attr_put(&req.nlh, IFA_ADDRESS, a, 16);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

static int f564_udp_bind(int fam, uint32_t a4, const unsigned char *a6,
			 unsigned short port)
{
	struct timeval tv;
	int s, one = 1;

	s = socket(fam, SOCK_DGRAM, 0);
	if (s < 0)
		return -errno;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (fam == AF_INET) {
		struct sockaddr_in sa;

		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(a4);
		sa.sin_port = htons(port);
		if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			int e = errno;

			close(s);
			return -e;
		}
	} else {
		struct sockaddr_in6 sa;

		memset(&sa, 0, sizeof(sa));
		sa.sin6_family = AF_INET6;
		memcpy(&sa.sin6_addr, a6, 16);
		sa.sin6_port = htons(port);
		if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			int e = errno;

			close(s);
			return -e;
		}
	}
	tv.tv_sec = 0;
	tv.tv_usec = 250000;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return s;
}

/* the pppd sequence, without pppd: PPPIOCGCHAN marks the socket PPPOX_BOUND,
 * PPPIOCATTCHAN+PPPIOCCONNECT hang the channel on a fresh unit. */
static int f564_ppp_setup(void)
{
	int u = -1, idx = -1, up;

	if (P564.ok)
		return 0;
	P564.sock = f563_pppoe_sock("br0", htons(99), MAC_SRC);
	if (P564.sock < 0) {
		printf("F564 PPP|fail|sock|%d\n", P564.sock);
		return -1;
	}
	if (ioctl(P564.sock, PPPIOCGCHAN, &idx) < 0) {
		printf("F564 PPP|fail|gchan|%d\n", errno);
		return -1;
	}
	P564.fd_u = open("/dev/ppp", O_RDWR);
	if (P564.fd_u < 0) {
		printf("F564 PPP|fail|open_unit|%d\n", errno);
		return -1;
	}
	if (ioctl(P564.fd_u, PPPIOCNEWUNIT, &u) < 0) {
		printf("F564 PPP|fail|newunit|%d\n", errno);
		return -1;
	}
	P564.unit = u;
	P564.fd_c = open("/dev/ppp", O_RDWR);
	if (P564.fd_c < 0) {
		printf("F564 PPP|fail|open_chan|%d\n", errno);
		return -1;
	}
	if (ioctl(P564.fd_c, PPPIOCATTCHAN, &idx) < 0) {
		printf("F564 PPP|fail|attchan|%d\n", errno);
		return -1;
	}
	if (ioctl(P564.fd_c, PPPIOCCONNECT, &u) < 0) {
		printf("F564 PPP|fail|connect|%d\n", errno);
		return -1;
	}
	snprintf(P564.dev, sizeof(P564.dev), "ppp%d", u);
	up = set_up(P564.dev);
	/* ppp_receive_nonmp_frame() frees the frame when the device is down:
	 * `if ((dev->flags & IFF_UP) == 0) kfree_skb()`. */
	printf("F564 PPP|unit=%d|chan=%d|dev=%s|ifindex=%d|up=%d\n", u, idx,
	       P564.dev, f555_ifindex(P564.dev), up);
	printf("F564 PPP|addr4|rc=%d\n",
	       f564_addr_peer(P564.dev, htonl(0x0a090007), htonl(0x0a010001), 32));
	f555_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
	f555_sysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0");
	P564.u4 = f564_udp_bind(AF_INET, 0x0a090007, NULL, 5000);
	printf("F564 PPP|u4=%d\n", P564.u4);
	P564.ok = 1;
	return 0;
}

static const unsigned char F564_V6DST[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
					      0, 0, 0, 0, 0, 0x99, 0, 9 };

static int f564_ppp6_setup(void)
{
	char path[96];

	if (!P564.ok)
		return -1;
	if (P564.u6 >= 0)
		return 0;
	snprintf(path, sizeof(path),
		 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", P564.dev);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/dad_transmits",
		 P564.dev);
	f555_sysctl(path, "0");
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/accept_dad",
		 P564.dev);
	f555_sysctl(path, "0");
	printf("F564 PPP6|addr6|rc=%d\n", f564_addr6(P564.dev, F564_V6DST, 128));
	P564.u6 = f564_udp_bind(AF_INET6, 0, F564_V6DST, 5000);
	printf("F564 PPP6|u6=%d\n", P564.u6);
	return 0;
}

/* ---------- the IPv6-in-PPPoE datagram ---------- */

static unsigned int f564_sum(const unsigned char *p, int n, unsigned int acc)
{
	int i;

	for (i = 0; i + 1 < n; i += 2)
		acc += ((unsigned int)p[i] << 8) | p[i + 1];
	if (n & 1)
		acc += (unsigned int)p[n - 1] << 8;
	return acc;
}

static unsigned short f564_fold(unsigned int acc)
{
	while (acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);
	return (unsigned short)~acc;
}

/* the UDPv6 checksum: a zero checksum is legal only for IPv4, and ip6's
 * udp_rcv() drops a zero-checksum datagram before any socket sees it. */
static void f564_udp6_csum(unsigned char *pkt, int paylen)
{
	unsigned int acc = 0;
	unsigned short c;

	acc = f564_sum(pkt + 8, 32, 0);		/* src + dst */
	acc += (unsigned int)paylen;		/* upper-layer length */
	acc += 17;				/* next header: UDP */
	pkt[40 + 6] = 0;
	pkt[40 + 7] = 0;
	acc = f564_sum(pkt + 40, paylen, acc);
	c = f564_fold(acc);
	if (!c)
		c = 0xffff;
	pkt[40 + 6] = (unsigned char)(c >> 8);
	pkt[40 + 7] = (unsigned char)c;
}

/* ---------- A. the bound unit: what the IP stack does with the frame ---------- */

struct f564_pa {
	const char *arm;
	int gate;
	uint32_t base;
	int off, len, wr;
	unsigned char imm[16];
	const char *what;
};

static void f564_sec_bound(struct f563_frame *F, int rfd)
{
	static struct f564_pa A[] = {
		{ "ctl",      1, NFT_PAYLOAD_NETWORK_HEADER, 0, 0, 0, { 0 },
		  "control: no store" },
		{ "bare",     0, NFT_PAYLOAD_NETWORK_HEADER, 4, 2, 1, { 0x00, 0x04 },
		  "bare gate: the same cell, no meta protocol, no branch" },
		{ "vt",       1, NFT_PAYLOAD_NETWORK_HEADER, 0, 2, 1, { 0x11, 0x91 },
		  "pppoe ver/type+code (first byte must equal the old one)" },
		{ "tos",      1, NFT_PAYLOAD_NETWORK_HEADER, 1, 1, 1, { 0x91 },
		  "tos -> pppoe code" },
		{ "id4",      1, NFT_PAYLOAD_NETWORK_HEADER, 4, 2, 1, { 0x00, 0x04 },
		  "ipv4 id -> pppoe length = 4" },
		{ "idbig",    1, NFT_PAYLOAD_NETWORK_HEADER, 4, 2, 1, { 0x90, 0x91 },
		  "ipv4 id -> pppoe length = 0x9091" },
		{ "ttl",      1, NFT_PAYLOAD_NETWORK_HEADER, 8, 1, 1, { 0x90 },
		  "ttl -> ip ver/ihl" },
		{ "ttlsame",  1, NFT_PAYLOAD_NETWORK_HEADER, 8, 1, 1, { 0x45 },
		  "ttl -> ip ver/ihl, same value: the write changes nothing" },
		{ "ttl2",     1, NFT_PAYLOAD_NETWORK_HEADER, 8, 2, 1, { 0x90, 0x00 },
		  "ttl(2b) -> ver/ihl + tos" },
		{ "csum",     1, NFT_PAYLOAD_NETWORK_HEADER, 10, 2, 1, { 0x90, 0x91 },
		  "check -> ip tot_len" },
		{ "saddr",    1, NFT_PAYLOAD_NETWORK_HEADER, 12, 4, 1,
		  { 0x90, 0x91, 0x92, 0x93 }, "saddr -> ip id + frag_off" },
		{ "daddr",    1, NFT_PAYLOAD_NETWORK_HEADER, 16, 4, 1,
		  { 0x90, 0x91, 0x92, 0x93 }, "daddr -> ttl + proto + csum" },
		{ "trsaddr",  1, NFT_PAYLOAD_NETWORK_HEADER, 20, 4, 1,
		  { 0x90, 0x91, 0x92, 0x93 }, "the real saddr: refused by the list" },
		{ "trdaddr",  1, NFT_PAYLOAD_NETWORK_HEADER, 24, 4, 1,
		  { 0x90, 0x91, 0x92, 0x93 }, "the real daddr: refused by the list" },
		{ "nh6",      1, NFT_PAYLOAD_NETWORK_HEADER, 6, 2, 1,
		  { 0xff, 0xff }, "the PPP protocol field: no such cell in the ip4 list" },
		{ "ll6",      1, NFT_PAYLOAD_LL_HEADER, 6, 2, 1, { 0xff, 0xff },
		  "@ll offset 6: inside the 14-boundary, writes the source MAC" },
		{ "ll13",     1, NFT_PAYLOAD_LL_HEADER, 13, 1, 1, { 0xff },
		  "@ll offset 13: the last allowed byte, the ethertype's low byte" },
		{ "ll14",     1, NFT_PAYLOAD_LL_HEADER, 14, 2, 1, { 0x90, 0x91 },
		  "@ll offset 14: the PPPoE header, refused (boundary 14)" },
	};
	int i, n = (int)(sizeof(A) / sizeof(A[0]));

	F564_SEC = "bound";
	if (f564_ppp_setup())
		return;
	for (i = 0; i < n; i++) {
		struct f559_out o;
		unsigned char ub[1024], cb[1024], rx[1024], rf[1024];
		unsigned long long ip0[4], ip1[4], pb, pp, pb1, pp1;
		char hi[80], hux[256], hun[256], hc[128], hr[260], hw[260];
		int un, cn, rxn, rn, sk = 0;

		memset(&o, 0, sizeof(o));
		memset(&ip0, 0, sizeof(ip0));
		f564_drainf(P564.fd_u, ub, (int)sizeof(ub), 0);
		f564_drainf(P564.fd_c, cb, (int)sizeof(cb), 0);
		while (P564.u4 >= 0 && recv(P564.u4, rx, sizeof(rx), MSG_DONTWAIT) >= 0)
			;
		snprintf(PRE57, sizeof(PRE57), "f64.bb.%s", A[i].arm);
		f557_flush(NFPROTO_BRIDGE, "p64", "g", &o.acks);
		o.rc = f563_install(NFPROTO_BRIDGE, "p64", "g", PRE57, A[i].gate,
				    A[i].base, 0, 0, A[i].off, A[i].len, NULL,
				    A[i].wr, 0, A[i].imm, 1, 1);
		nfl_drain(NFL59);
		o.cnt0 = f555_count(NFPROTO_BRIDGE, "p64", "g");
		ip0[0] = f564_snmp("Ip", "InReceives");
		ip0[1] = f564_snmp("Ip", "InHdrErrors");
		ip0[2] = f564_snmp("Ip", "InAddrErrors");
		ip0[3] = f564_snmp("Ip", "InDelivers");
		f564_devrx(P564.dev, &pb, &pp);
		if (rfd >= 0)
			cap_drain(rfd);
		o.snd = pkt_send_p("s0", F[1].wire, F[1].wlen, F[1].sproto);
		usleep(60000);
		rxn = -1;
		if (P564.u4 >= 0) {
			rxn = (int)recv(P564.u4, rx, sizeof(rx), MSG_DONTWAIT);
			/* keep rx: the drain below reads into a scratch buffer */
			{
				unsigned char sc[256];

				while (recv(P564.u4, sc, sizeof(sc),
					    MSG_DONTWAIT) >= 0)
					;
			}
		}
		ip1[0] = f564_snmp("Ip", "InReceives");
		ip1[1] = f564_snmp("Ip", "InHdrErrors");
		ip1[2] = f564_snmp("Ip", "InAddrErrors");
		ip1[3] = f564_snmp("Ip", "InDelivers");
		f564_devrx(P564.dev, &pb1, &pp1);
		un = f564_drainf(P564.fd_u, ub, (int)sizeof(ub), 0);
		cn = f564_drainf(P564.fd_c, cb, (int)sizeof(cb), 0);
		o.cnt = f555_count(NFPROTO_BRIDGE, "p64", "g");
		rn = f558_cap_match(rfd, rf, (int)sizeof(rf), 250, F[1].magic,
				    F[1].mlen, &sk, &o.rpt);
		printf("F564 B|sec=bound|arm=%s|gate=%d|base=%u|off=%d|len=%d|wr=%d|"
		       "imm=%s|what=%s|rc=%d|acks=%d|snd=%d|cnt0=%llu|cnt=%llu|"
		       "live=%llu|ipin=%llu|ihdr=%llu|iaddr=%llu|ideliv=%llu|"
		       "prx=%llu|prp=%llu|udp4=%d|uhex=%s|urn=%d|urhex=%s|"
		       "crn=%d|rn=%d|rhex=%s\n",
		       A[i].arm, A[i].gate, (unsigned)A[i].base, A[i].off,
		       A[i].len, A[i].wr,
		       A[i].wr ? f559_hexs(hi, sizeof(hi), A[i].imm, A[i].len) : "-",
		       A[i].what, o.rc, o.acks, o.snd, o.cnt0, o.cnt,
		       o.cnt - o.cnt0, ip1[0] - ip0[0], ip1[1] - ip0[1],
		       ip1[2] - ip0[2], ip1[3] - ip0[3], pb1 - pb, pp1 - pp,
		       rxn, rxn > 0 ? f559_hexs(hux, sizeof(hux), rx, rxn) : "-",
		       un, un > 0 ? f559_hexs(hun, sizeof(hun), ub, un) : "-",
		       cn, rn, rn > 0 ? f559_hexs(hr, sizeof(hr), rf,
						  rn < 48 ? rn : 48) : "-");
	}

	/* The ll13 arm above wrote the ethertype's low byte (0x8864 -> 0x88ff)
	 * and the frame was STILL delivered.  Either the receive path reads the
	 * byte (and 0x88ff is somehow a session frame), or it uses the
	 * skb->protocol that eth_type_trans() cached before the hook ran.
	 * The same bytes, sent from outside with no rule at all, decide it. */
	{
		struct f559_out o;
		unsigned char fr2[128], rx[1024];
		unsigned long long ip0, ip1, pb, pp, pb1, pp1;
		int rxn, ack2 = 0;

		memset(&o, 0, sizeof(o));
		memcpy(fr2, F[1].wire, (size_t)F[1].wlen);
		fr2[12] = 0x88;
		fr2[13] = 0xff;
		f564_drainf(P564.fd_u, (unsigned char[256]){ 0 }, 256, 0);
		while (P564.u4 >= 0 && recv(P564.u4, rx, sizeof(rx), MSG_DONTWAIT) >= 0)
			;
		f557_flush(NFPROTO_BRIDGE, "p64", "g", &ack2);
		o.cnt0 = f555_count(NFPROTO_BRIDGE, "p64", "g");
		ip0 = f564_snmp("Ip", "InReceives");
		f564_devrx(P564.dev, &pb, &pp);
		o.snd = pkt_send_p("s0", fr2, F[1].wlen, 0x88ff);
		usleep(60000);
		rxn = -1;
		if (P564.u4 >= 0)
			rxn = (int)recv(P564.u4, rx, sizeof(rx), MSG_DONTWAIT);
		ip1 = f564_snmp("Ip", "InReceives");
		f564_devrx(P564.dev, &pb1, &pp1);
		o.cnt = f555_count(NFPROTO_BRIDGE, "p64", "g");
		printf("F564 B|sec=bound|arm=pre88ff|gate=-1|base=-1|off=-1|len=-1|"
		       "wr=0|imm=-|what=the ll13 bytes, sent from outside with no rule|"
		       "rc=-1|acks=0|snd=%d|cnt0=%llu|cnt=%llu|live=%llu|ipin=%llu|"
		       "ihdr=0|iaddr=0|ideliv=0|prx=%llu|prp=%llu|udp4=%d|uhex=-|"
		       "urn=0|urhex=-|crn=0|rn=-1|rhex=-\n",
		       o.snd, o.cnt0, o.cnt, o.cnt - o.cnt0, ip1 - ip0,
		       pb1 - pb, pp1 - pp, rxn);
	}
}

/* ---------- B. IPv6 inside PPPoE ---------- */

static void f564_sec_v6p(struct f563_frame *F, int rfd)
{
	static struct f564_pa A[] = {
		{ "ctl",      1, NFT_PAYLOAD_NETWORK_HEADER, 0, 0, 0, { 0 },
		  "control: no store" },
		{ "hop",      1, NFT_PAYLOAD_NETWORK_HEADER, 7, 1, 1, { 0x90 },
		  "hop_limit (len 1) -> wire 21 = the PPP protocol's low byte" },
		{ "hopsame",  1, NFT_PAYLOAD_NETWORK_HEADER, 7, 1, 1, { 0x57 },
		  "the same cell, the PPP protocol's own byte: no change" },
		{ "dscp",     1, NFT_PAYLOAD_NETWORK_HEADER, 0, 4, 1,
		  { 0x60, 0x90, 0x91, 0x92 },
		  "version/tc (len 4) -> pppoe ver/type + code + sid" },
		{ "flow2",    1, NFT_PAYLOAD_NETWORK_HEADER, 2, 2, 1, { 0x90, 0x91 },
		  "flow label low half -> pppoe sid" },
		{ "hdr_same", 1, NFT_PAYLOAD_NETWORK_HEADER, 8, 16, 1,
		  { 0x60, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x11, 0x40,
		    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		  "saddr (16) -> wire 22: the header's first 16 bytes, unchanged" },
		{ "hdr_bad",  1, NFT_PAYLOAD_NETWORK_HEADER, 8, 16, 1,
		  { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f },
		  "saddr (16) -> wire 22: version 9" },
		{ "dst",      1, NFT_PAYLOAD_NETWORK_HEADER, 24, 16, 1,
		  { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f },
		  "daddr (16) -> wire 38: saddr[8..15] + daddr[0..7]" },
		{ "one",      1, NFT_PAYLOAD_NETWORK_HEADER, 1, 2, 1, { 0x90, 0x91 },
		  "offset 1: no such cell in the ip6 list" },
		{ "three",    1, NFT_PAYLOAD_NETWORK_HEADER, 3, 2, 1, { 0x90, 0x91 },
		  "offset 3: no such cell in the ip6 list" },
		{ "six",      1, NFT_PAYLOAD_NETWORK_HEADER, 6, 1, 1, { 0x90 },
		  "offset 6: no such cell in the ip6 list" },
	};
	unsigned char plain[256], fr[320];
	int i, n = (int)(sizeof(A) / sizeof(A[0])), plen, flen;

	F564_SEC = "v6p";
	if (f564_ppp_setup() || f564_ppp6_setup())
		return;
	plen = f556_mk_ip6(plain, 0x00, 64);
	f564_udp6_csum(plain + 14, 26);
	flen = f563_pppoe(plain, plen, fr, 99, 0x0057);
	printf("F564 V6|frame|len=%d|wire=%s\n", flen,
	       f559_hexs((char[256]){ 0 }, 256, fr, flen));
	for (i = 0; i < n; i++) {
		struct f559_out o;
		unsigned char ub[1024], cb[1024], rx[1024], rf[1024];
		unsigned long long i0[5], i1[5], pb, pp, pb1, pp1;
		char hi[80], hux[256], hun[256], hr[260];
		int un, cn, rxn, rn, sk = 0;

		memset(&o, 0, sizeof(o));
		f564_drainf(P564.fd_u, ub, (int)sizeof(ub), 0);
		f564_drainf(P564.fd_c, cb, (int)sizeof(cb), 0);
		while (P564.u6 >= 0 && recv(P564.u6, rx, sizeof(rx), MSG_DONTWAIT) >= 0)
			;
		snprintf(PRE57, sizeof(PRE57), "f64.vv.%s", A[i].arm);
		f557_flush(NFPROTO_BRIDGE, "p64", "g", &o.acks);
		o.rc = f563_install(NFPROTO_BRIDGE, "p64", "g", PRE57, A[i].gate,
				    A[i].base, 0, 0, A[i].off, A[i].len, NULL,
				    A[i].wr, 0, A[i].imm, 1, 1);
		nfl_drain(NFL59);
		o.cnt0 = f555_count(NFPROTO_BRIDGE, "p64", "g");
		i0[0] = f564_snmp6("Ip6InReceives");
		i0[1] = f564_snmp6("Ip6InHdrErrors");
		i0[2] = f564_snmp6("Ip6InAddrErrors");
		i0[3] = f564_snmp6("Ip6InDelivers");
		i0[4] = f564_snmp6("Udp6InErrors");
		f564_devrx(P564.dev, &pb, &pp);
		if (rfd >= 0)
			cap_drain(rfd);
		o.snd = pkt_send_p("s0", fr, flen, 0x8864);
		usleep(60000);
		rxn = -1;
		if (P564.u6 >= 0) {
			rxn = (int)recv(P564.u6, rx, sizeof(rx), MSG_DONTWAIT);
			{
				unsigned char sc[256];

				while (recv(P564.u6, sc, sizeof(sc),
					    MSG_DONTWAIT) >= 0)
					;
			}
		}
		i1[0] = f564_snmp6("Ip6InReceives");
		i1[1] = f564_snmp6("Ip6InHdrErrors");
		i1[2] = f564_snmp6("Ip6InAddrErrors");
		i1[3] = f564_snmp6("Ip6InDelivers");
		i1[4] = f564_snmp6("Udp6InErrors");
		f564_devrx(P564.dev, &pb1, &pp1);
		un = f564_drainf(P564.fd_u, ub, (int)sizeof(ub), 0);
		cn = f564_drainf(P564.fd_c, cb, (int)sizeof(cb), 0);
		o.cnt = f555_count(NFPROTO_BRIDGE, "p64", "g");
		rn = f558_cap_match(rfd, rf, (int)sizeof(rf), 250, F[0].magic,
				    F[0].mlen, &sk, &o.rpt);
		printf("F564 V|sec=v6p|arm=%s|gate=%d|off=%d|len=%d|wr=%d|imm=%s|"
		       "what=%s|rc=%d|acks=%d|snd=%d|cnt0=%llu|cnt=%llu|live=%llu|"
		       "i6in=%llu|i6hdr=%llu|i6addr=%llu|i6deliv=%llu|u6err=%llu|"
		       "prx=%llu|prp=%llu|udp6=%d|uhex=%s|urn=%d|urhex=%s|"
		       "crn=%d|rn=%d|rhex=%s\n",
		       A[i].arm, A[i].gate, A[i].off, A[i].len, A[i].wr,
		       A[i].wr ? f559_hexs(hi, sizeof(hi), A[i].imm, A[i].len) : "-",
		       A[i].what, o.rc, o.acks, o.snd, o.cnt0, o.cnt,
		       o.cnt - o.cnt0, i1[0] - i0[0], i1[1] - i0[1],
		       i1[2] - i0[2], i1[3] - i0[3], i1[4] - i0[4],
		       pb1 - pb, pp1 - pp, rxn,
		       rxn > 0 ? f559_hexs(hux, sizeof(hux), rx, rxn) : "-",
		       un, un > 0 ? f559_hexs(hun, sizeof(hun), ub, un) : "-",
		       cn, rn, rn > 0 ? f559_hexs(hr, sizeof(hr), rf,
						  rn < 48 ? rn : 48) : "-");
	}
}

/* ---------- C. ARP behind a real VLAN device ---------- */

static void f564_sec_vlan(struct f563_frame *F, int rfd, int sfd)
{
	struct f563_frame fr;
	static const struct {
		const char *arm;
		int off, len, wr;
		unsigned char imm[16];
		const char *what;
	} A[] = {
		{ "ctl_novlan", 0, 0, 0, { 0 }, "vid 100, no vlan device: control" },
		{ "sha_novlan", 8, 2, 1, { 0x90, 0x91 }, "vid 100, no vlan device: sha[0..1]" },
	};
	static const struct {
		const char *arm;
		int off, len, wr;
		unsigned char imm[16];
		const char *what;
	} B[] = {
		{ "ctl_vlan",  0, 0, 0, { 0 }, "vid 100, v1 on br0: control" },
		{ "sha_vlan",  8, 2, 1, { 0x90, 0x91 }, "vid 100, v1 on br0: sha[0..1]" },
		{ "op_vlan",   6, 2, 1, { 0x90, 0x91 }, "vid 100, v1: ar_op = 0x9091 (unknown)" },
		{ "hln_vlan",  4, 2, 1, { 0x90, 0x91 }, "vid 100, v1: offset 4 (ar_hln/pln) is not in the ARP list" },
	};
	unsigned char brmac[6], req[1024], rep[1024], wrq[512];
	int i, ack = 0, have_ar, rn, repn, wrn, sk, bcnt0, bcnt;
	char hx[80], hq[256], hr[256], hw[256], ent[256];

	F564_SEC = "vlan";
	/* the same frame F41 measured without a device: one 0x8100 tag, vid 100 */
	memset(&fr, 0, sizeof(fr));
	fr.kind = F563_KIND_ARP;
	f563_arp_build(&fr, 1, 0x8100, 0x0064, 0, 0);
	f563_getmac("br0", brmac);
	printf("F564 L|brmac=%02x%02x%02x%02x%02x%02x|wire=%s\n",
	       brmac[0], brmac[1], brmac[2], brmac[3], brmac[4], brmac[5],
	       f559_hexs((char[256]){ 0 }, 256, fr.wire, fr.wlen));
	f563_set_noarp("s0");
	printf("F564 L|addr_br0|rc=%d\n",
	       f555_addr_add("br0", htonl(0x0a090001), 24));
	have_ar = 0;
	f557_flush(NFPROTO_ARP, "p64a", "in", &ack);
	f557_flush(NFPROTO_BRIDGE, "p64", "g", &ack);
	if (!add_table(NFPROTO_ARP, "p64a") &&
	    !f556_add_chain(NFPROTO_ARP, "p64a", "in", 0, 0, 1, NULL))
		have_ar = 1;
	else
		printf("F564 FAIL|arp_chain|%d\n", ack);

	/* pass 1: no vlan device */
	for (i = 0; i < (int)(sizeof(A) / sizeof(A[0])); i++) {
		struct f559_out o;
		int cnt0, cnt, ack2 = 0;

		memset(&o, 0, sizeof(o));
		fr.spa = 0x0a010030u + (unsigned int)i;
		f563_arp_build(&fr, 1, 0x8100, 0x0064, 0, 0);
		snprintf(PRE57, sizeof(PRE57), "f64.ll.%s", A[i].arm);
		f557_flush(NFPROTO_BRIDGE, "p64", "g", &ack2);
		if (have_ar) {
			f557_flush(NFPROTO_ARP, "p64a", "in", &ack2);
			f563_install(NFPROTO_ARP, "p64a", "in", PRE57, 0,
				     NFT_PAYLOAD_NETWORK_HEADER, 0, 0, 0, 0, NULL,
				     0, 0, NULL, 1, 0);
		}
		o.rc = f563_install(NFPROTO_BRIDGE, "p64", "g", PRE57, 1,
				    NFT_PAYLOAD_NETWORK_HEADER, 0, 0, A[i].off,
				    A[i].len, NULL, A[i].wr, 0, A[i].imm, 1, 1);
		nfl_drain(NFL59);
		cnt0 = have_ar ? (int)f555_count(NFPROTO_ARP, "p64a", "in") : -1;
		bcnt0 = (int)f555_count(NFPROTO_BRIDGE, "p64", "g");
		if (rfd >= 0)
			cap_drain(rfd);
		if (sfd >= 0)
			cap_drain(sfd);
		usleep(15000);
		o.snd = pkt_send_p("r0", fr.wire, fr.wlen, fr.sproto);
		rn = f558_cap_match(rfd, req, (int)sizeof(req), 400, fr.magic,
				    fr.mlen, &sk, &o.rpt);
		sk = 0;
		wrn = f558_cap_match(sfd, wrq, (int)sizeof(wrq), 300, fr.magic,
				     fr.mlen, &sk, &o.wpt);
		sk = 0;
		repn = f558_cap_match(rfd, rep, (int)sizeof(rep), 300, brmac, 6,
				      &sk, &o.wpt);
		cnt = have_ar ? (int)f555_count(NFPROTO_ARP, "p64a", "in") : -1;
		bcnt = (int)f555_count(NFPROTO_BRIDGE, "p64", "g");
		f563_arpent(fr.spa, ent, sizeof(ent));
		printf("F564 L|pass=novlan|arm=%s|off=%d|len=%d|wr=%d|imm=%s|what=%s|"
		       "spa=%08x|rc=%d|snd=%d|live=%d|reqn=%d|wrn=%d|reqhex=%s|repn=%d|"
		       "rephex=%s|arccnt0=%d|arccnt=%d|arc=%d|ent=%s\n",
		       A[i].arm, A[i].off, A[i].len, A[i].wr,
		       A[i].wr ? f559_hexs(hx, sizeof(hx), A[i].imm, A[i].len) : "-",
		       A[i].what, fr.spa, o.rc, o.snd, bcnt - bcnt0, rn, wrn,
		       rn > 0 ? f559_hexs(hq, sizeof(hq), req, rn < 46 ? rn : 46) : "-",
		       repn,
		       repn > 0 ? f559_hexs(hr, sizeof(hr), rep, repn < 46 ? repn : 46) : "-",
		       cnt0, cnt, cnt < 0 ? -1 : cnt - cnt0, ent[0] ? ent : "-");
	}

	/* now the device exists: vlan 100 on top of br0 -- the device the
	 * receive path looks for in vlan_do_receive(). */
	ack = f558_link_add_vlan("v1", "br0", 100);
	printf("F564 L|vlan_add|rc=%d|ifindex=%d\n", ack, f555_ifindex("v1"));
	{
		char path[96];

		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/v1/disable_ipv6");
		f555_sysctl(path, "1");
	}
	ack = set_up("v1");
	printf("F564 L|vlan_up|rc=%d\n", ack);
	usleep(150000);

	for (i = 0; i < (int)(sizeof(B) / sizeof(B[0])); i++) {
		struct f559_out o;
		int cnt0, cnt, ack2 = 0;

		memset(&o, 0, sizeof(o));
		fr.spa = 0x0a010040u + (unsigned int)i;
		f563_arp_build(&fr, 1, 0x8100, 0x0064, 0, 0);
		snprintf(PRE57, sizeof(PRE57), "f64.lm.%s", B[i].arm);
		f557_flush(NFPROTO_BRIDGE, "p64", "g", &ack2);
		if (have_ar) {
			f557_flush(NFPROTO_ARP, "p64a", "in", &ack2);
			f563_install(NFPROTO_ARP, "p64a", "in", PRE57, 0,
				     NFT_PAYLOAD_NETWORK_HEADER, 0, 0, 0, 0, NULL,
				     0, 0, NULL, 1, 0);
		}
		o.rc = f563_install(NFPROTO_BRIDGE, "p64", "g", PRE57, 1,
				    NFT_PAYLOAD_NETWORK_HEADER, 0, 0, B[i].off,
				    B[i].len, NULL, B[i].wr, 0, B[i].imm, 1, 1);
		nfl_drain(NFL59);
		cnt0 = have_ar ? (int)f555_count(NFPROTO_ARP, "p64a", "in") : -1;
		bcnt0 = (int)f555_count(NFPROTO_BRIDGE, "p64", "g");
		if (rfd >= 0)
			cap_drain(rfd);
		if (sfd >= 0)
			cap_drain(sfd);
		usleep(15000);
		o.snd = pkt_send_p("r0", fr.wire, fr.wlen, fr.sproto);
		rn = f558_cap_match(rfd, req, (int)sizeof(req), 400, fr.magic,
				    fr.mlen, &sk, &o.rpt);
		sk = 0;
		wrn = f558_cap_match(sfd, wrq, (int)sizeof(wrq), 300, fr.magic,
				     fr.mlen, &sk, &o.wpt);
		sk = 0;
		repn = f558_cap_match(rfd, rep, (int)sizeof(rep), 300, brmac, 6,
				      &sk, &o.wpt);
		cnt = have_ar ? (int)f555_count(NFPROTO_ARP, "p64a", "in") : -1;
		bcnt = (int)f555_count(NFPROTO_BRIDGE, "p64", "g");
		f563_arpent(fr.spa, ent, sizeof(ent));
		printf("F564 L|pass=vlan|arm=%s|off=%d|len=%d|wr=%d|imm=%s|what=%s|"
		       "spa=%08x|rc=%d|snd=%d|live=%d|reqn=%d|wrn=%d|reqhex=%s|repn=%d|"
		       "rephex=%s|arccnt0=%d|arccnt=%d|arc=%d|ent=%s\n",
		       B[i].arm, B[i].off, B[i].len, B[i].wr,
		       B[i].wr ? f559_hexs(hx, sizeof(hx), B[i].imm, B[i].len) : "-",
		       B[i].what, fr.spa, o.rc, o.snd, bcnt - bcnt0, rn, wrn,
		       rn > 0 ? f559_hexs(hq, sizeof(hq), req, rn < 46 ? rn : 46) : "-",
		       repn,
		       repn > 0 ? f559_hexs(hr, sizeof(hr), rep, repn < 46 ? repn : 46) : "-",
		       cnt0, cnt, cnt < 0 ? -1 : cnt - cnt0, ent[0] ? ent : "-");
	}
	(void)F;
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	static struct f563_frame F[6];
	const char *mode = argc > 1 ? argv[1] : "f564";
	int wfd, rfd, sfd;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F564 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F564 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F564 KERNEL|7.3.4-T563\n");
	f556_env_setup();
	{
		static const char *dv[] = { "all", "default", "lo", "i0", "i1",
					    "s0", "s1", "r0", "r1", "br0" };
		char path[96];
		int i;

		for (i = 0; i < (int)(sizeof(dv) / sizeof(dv[0])); i++) {
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", dv[i]);
			f555_sysctl(path, "1");
		}
	}
	NFL59 = nfl_open(5);
	printf("F564 NFL|%d\n", NFL59);

	memset(F, 0, sizeof(F));
	F[0].tag = "p";
	F[0].kind = F563_KIND_IP;
	F[0].plainlen = f556_mk_ip4(F[0].plain, 5, 17, 64);
	memcpy(F[0].cap, F[0].plain, (size_t)F[0].plainlen);
	F[0].caplen = F[0].plainlen;
	memcpy(F[0].wire, F[0].plain, (size_t)F[0].plainlen);
	F[0].wlen = F[0].plainlen;
	F[0].sproto = 0x0800;
	memcpy(F[0].magic, M561_77, 8);
	F[0].mlen = 8;

	F[1].tag = "ps";
	F[1].kind = F563_KIND_IP;
	F[1].wlen = f563_pppoe(F[0].plain, F[0].plainlen, F[1].wire, 99, 0x0021);
	memcpy(F[1].cap, F[1].wire, (size_t)F[1].wlen);
	F[1].caplen = F[1].wlen;
	memcpy(F[1].plain, F[0].plain, (size_t)F[0].plainlen);
	F[1].plainlen = F[0].plainlen;
	F[1].sproto = 0x8864;
	memcpy(F[1].magic, M561_77, 8);
	F[1].mlen = 8;

	/* the PPPoE frame bytes, so the verifier can rebuild every arm from the
	 * log instead of trusting the C literal */
	printf("F564 FRAME|ps|len=%d|wire=%s\n", F[1].wlen,
	       f559_hexs((char[512]){ 0 }, 512, F[1].wire, F[1].wlen));

	if (add_table(NFPROTO_BRIDGE, "p64") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p64", "g", 0, 0, 1, NULL)) {
		printf("F564 FAIL|chain\n");
		return 0;
	}
	wfd = cap_open("r1");
	rfd = cap_open("r0");
	sfd = cap_open("s0");

	if (!strcmp(mode, "f564b")) {
		f564_sec_bound(F, rfd);
	} else if (!strcmp(mode, "f564v")) {
		f564_sec_v6p(F, rfd);
	} else if (!strcmp(mode, "f564l")) {
		f564_sec_vlan(F, rfd, sfd);
	} else {
		f564_sec_bound(F, rfd);
		f564_sec_v6p(F, rfd);
		f564_sec_vlan(F, rfd, sfd);
	}
	sh("/nft flush ruleset");
	printf("F564 DONE\n");
	return 0;
}
