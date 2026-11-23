/* ================= turn 591 (F69) =======================================
 *
 * Two debts named in F68 §9, one instrument.
 *
 * (A) THE FRAGLIST BYTE CAP ON IPv4.  F68 wrote "the cap was never reached,
 *     the length rule binds first".  Re-reading udp_gro_receive_segment()
 *     shows WHY the long-head arms (th950..th982) split after the head:
 *
 *         if (ret || ulen != udp_get_len_short(uh2) ||
 *             NAPI_GRO_CB(p)->count >= UDP_GRO_CNT_MAX)
 *                 pp = p;
 *
 *     -- an incoming datagram whose UDP length differs from the head's is
 *     merged and then FINISHES the flow, so a long head can only ever be
 *     followed by one shorter datagram.  The byte cap is reachable only with
 *     EQUAL lengths, and then it competes with UDP_GRO_CNT_MAX = 64.
 *     Model (H = 28, p->len starts at H+P, grows by P):
 *         fraglist: merge the (n+1)-th iff 2H + (n+1)P <= 65535  -> n = 65479/P
 *         linear  : merge the (n+1)-th iff  H + (n+1)P <= 65535  -> n = 65507/P
 *     The doors differ only inside a 28-byte window.  40 datagrams of 1637
 *     bytes land in it: 40*1637 = 65480.
 *
 * (B) THE PRICE OF AN AGGREGATE.  F67/F68 charged 64 x 512 as 64 x 2540 and
 *     could not name the 20-byte wobble.  skb_segment_list() -- the fraglist
 *     segmenter -- subtracts len and data_len from the head and never touches
 *     truesize, so the FIRST segment carries the whole aggregate's truesize
 *     and the other k-1 carry their own:
 *         A(k) = k*s + (k-1)*s = (2k-1)*s     (fraglist door)
 *         A(k) = k*s                          (linear door)
 *     with s = SKB_TRUESIZE(alloclen) = 1280 (512 B) / 2304 (1200 B).
 *     skb_condense(), called only when rmem > rcvbuf>>1, overwrites the head's
 *     truesize with SKB_TRUESIZE(skb_end_offset()) = one datagram -- which is
 *     exactly why F68's filler arms, already above half, showed no doubling.
 *
 * Topology, rule, taps, primer and receiver handshake are F68's unchanged:
 * three netns, the parent is the router, IPv4 throughout, one rule per arm
 * [meta l4proto 17] counter log(91:NN) accept on the ip chain `fwd`.
 */

#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>

#define F591_DPORT	5000
#define F591_DPORT_G	5001
#define F591_SPORT	43580
#define F591_DPORT_W	5002	/* the primer's port: no socket listens here */
#define F591_GROUP	91
#define F591_ND		66
#define F591_MAXPL	2048

#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>

#define F591_DPORT	5000
#define F591_DPORT_G	5001
#define F591_SPORT	43580
#define F591_DPORT_W	5002	/* the primer's port: no socket listens here */
#define F591_GROUP	86
#define F591_ND		66
#define F591_MAXPL	2048

/* the four subnets: 10.63.0.0/24 ingress, 10.64.0.0/24 door a,
 * 10.65.0.0/24 door b */
#define A90_X0	0x0a3f005bU	/* 10.63.0.91 the router's ingress */
#define A90_S	0x0a3f000bU	/* 10.63.0.11 the sender            */
#define A90_RA	0x0a40005bU	/* 10.64.0.91 door a's own address  */
#define A90_RB	0x0a41005bU	/* 10.65.0.91 door b's own address  */
#define A90_DA	0x0a40005cU	/* 10.64.0.92 the receiver on y3    */
#define A90_DB	0x0a41005cU	/* 10.65.0.92 the receiver on y4    */

static unsigned char F591_PAY[F591_ND][F591_MAXPL];
static unsigned char F591_FPAY[F591_ND][F591_MAXPL];
static unsigned char F591_X0M[6], F591_Y3M[6], F591_Y4M[6], F591_X1M[6];
static int F591_DEF;		/* SO_RCVBUF the receiver was born with */

/* ---------- rtnetlink helpers this turn needs -------------------------- */

static int f591_neigh4(const char *dev, uint32_t dst_be, const unsigned char *mac)
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
	req.ndm.ndm_family = AF_INET;
	req.ndm.ndm_ifindex = f555_ifindex(dev);
	req.ndm.ndm_state = NUD_PERMANENT;
	attr_put(&req.nlh, NDA_DST, &dst_be, 4);
	attr_put(&req.nlh, NDA_LLADDR, mac, 6);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

static int f591_route4_default(uint32_t gw_be, const char *dev)
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
	req.rtm.rtm_family = AF_INET;
	req.rtm.rtm_dst_len = 0;
	req.rtm.rtm_table = 254;
	req.rtm.rtm_protocol = 4;	/* RTPROT_STATIC */
	req.rtm.rtm_scope = 0;
	req.rtm.rtm_type = 1;		/* RTN_UNICAST */
	attr_put(&req.nlh, 5 /* RTA_GATEWAY */, &gw_be, 4);
	attr_put(&req.nlh, 4 /* RTA_OIF */, &oif, 4);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* the queued bytes of the socket bound to the given local port */
static int f591_proc_rmem(int port)
{
	FILE *f = fopen("/proc/net/udp", "r");
	char line[512];
	int rmem = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char local[80], rem[80], st[16], txrx[80];
		unsigned int la = 0, lp = 0;

		if (sscanf(line, "%*d: %79s %79s %15s %79s", local, rem, st,
			   txrx) != 4)
			continue;
		if (sscanf(local, "%x:%x", &la, &lp) != 2)
			continue;
		if ((int)lp != port)
			continue;
		{
			char *colon = strchr(txrx, ':');

			if (colon)
				rmem = (int)strtoul(colon + 1, NULL, 16);
		}
		break;
	}
	fclose(f);
	return rmem;
}

/* Udp InDatagrams / InErrors, absolute -- the verifier differences them */
static void f591_snmp4(long long *in, long long *err)
{
	FILE *f = fopen("/proc/net/snmp", "r");
	char line[1024];
	int hdr = 0, dat = 0;

	*in = -1;
	*err = -1;
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Udp:", 4))
			continue;
		if (!hdr) {
			hdr = 1;
			continue;
		}
		{
			char *p = line + 4;
			long long v[8];
			int n = 0;

			while (n < 8) {
				char *end;
				long long x = strtoll(p, &end, 10);

				if (end == p)
					break;
				v[n++] = x;
				p = end;
			}
			if (n >= 3) {
				*in = v[0];
				*err = v[2];
				dat = 1;
			}
		}
		break;
	}
	fclose(f);
	(void)dat;
}

/* ---------- our datagrams only: ethertype IPv4, proto UDP, our ports ---- */

static int f591_isours4(const unsigned char *b, int r)
{
	static const unsigned char da[4] = { 0x0a, 0x40, 0x00, 0x5c };
	static const unsigned char db[4] = { 0x0a, 0x41, 0x00, 0x5c };
	int dport;

	if (r < 42)
		return 0;
	if (b[12] != 0x08 || b[13] != 0x00)
		return 0;
	if (b[23] != 17)
		return 0;
	dport = (b[36] << 8) | b[37];
	if (dport != F591_DPORT && dport != F591_DPORT_G)
		return 0;
	if (memcmp(b + 30, da, 4) && memcmp(b + 30, db, 4))
		return 0;
	return 1;
}

/* ---------- a multi-frame tap that keeps IPv4 datagrams ---------------- */

static void f591_tap_drain(struct f585_tap *T)
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
		if (!f591_isours4(b, r))
			continue;
		if (T->n >= F585_TAPN) {
			T->n++;
			continue;
		}
		k = T->n++;
		T->flen[k] = r;
		T->len[k] = r < F585_TAPB ? r : F585_TAPB;
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

static void f591_tap_print(const struct f585_tap *T, int idx, const char *dev)
{
	static const char hexd[] = "0123456789abcdef";
	static char hx[2 * F585_TAPB + 8];
	int k, i;

	for (k = 0; k < T->n && k < F585_TAPN; k++) {
		int at = 0, f = T->len[k];
		int tot = f > 17 ? ((T->b[k][16] << 8) | T->b[k][17]) : -1;
		int ttl = f > 22 ? T->b[k][22] : -1;
		int uhlen = f > 39 ? ((T->b[k][38] << 8) | T->b[k][39]) : -1;
		int uhck = f > 41 ? ((T->b[k][40] << 8) | T->b[k][41]) : -1;

		for (i = 0; i < T->len[k] && at + 3 < (int)sizeof(hx); i++) {
			hx[at++] = hexd[(T->b[k][i] >> 4) & 0xf];
			hx[at++] = hexd[T->b[k][i] & 0xf];
		}
		hx[at] = 0;
		printf("F591 TAP|i=%02d|dev=%s|k=%d|flen=%d|len=%d|trunc=%d|"
		       "tot=%d|ttl=%d|uhlen=%d|uhck=%04x|stat=%d|hex=%s\n",
		       idx, dev, k, T->flen[k], T->len[k],
		       T->flen[k] > T->len[k] ? 1 : 0, tot, ttl, uhlen,
		       uhck < 0 ? 0 : uhck, T->stat[k], hx);
	}
	if (T->n > F585_TAPN)
		printf("F591 TAPX|i=%02d|dev=%s|n=%d|nall=%d\n", idx, dev, T->n,
		       T->nall);
}

/* ---------- the rule: [meta l4proto 17] counter log(86:NN) accept ------ */

static int f591_rule(int idx)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	unsigned char l4 = 17;
	char pre[16];
	int acks = 0;

	snprintf(pre, sizeof(pre), "91:%02d", idx);
	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			NFPROTO_IPV4);
	put_str(nlh, NFTA_RULE_TABLE, "f90p");
	put_str(nlh, NFTA_RULE_CHAIN, "fwd");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	f567_meta_l4(nlh);
	f562_cmp(nlh, F562_RD_DREG, &l4, 1);
	counter_expr(nlh);
	log_expr(nlh, F591_GROUP, pre);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

/* ---------- a 16-byte command to S (sl and pl do not fit a byte) -------- */

static int f591_readn(int fd, unsigned char *m, int n)
{
	int got = 0;

	while (got < n) {
		int r = (int)read(fd, m + got, (size_t)(n - got));

		if (r <= 0) {
			if (errno == EINTR)
				continue;
			return got;
		}
		got += r;
	}
	return got;
}

static int f591_send_s(struct f585_conn *C, int c0, int dst, int psel, int n,
		       int sh, int sl, int pl, int head)
{
	unsigned char m[16];

	memset(m, 0, sizeof(m));
	m[0] = (unsigned char)c0;
	m[1] = (unsigned char)dst;
	m[2] = (unsigned char)psel;
	m[3] = (unsigned char)n;
	m[4] = (unsigned char)sh;
	m[5] = (unsigned char)((sl >> 8) & 0xff);
	m[6] = (unsigned char)(sl & 0xff);
	m[7] = (unsigned char)((pl >> 8) & 0xff);
	m[8] = (unsigned char)(pl & 0xff);
	m[9] = (unsigned char)((head >> 8) & 0xff);
	m[10] = (unsigned char)(head & 0xff);
	if (write(C->dn[1], m, sizeof(m)) != (ssize_t)sizeof(m))
		return -1;
	return f585_wait_byte(C->up[0], 20000) == 'D' ? 0 : -1;
}

/* ---------- S: the sender ---------------------------------------------- */

/* command: c0 's' test payloads / 'f' filler payloads, c1 'a'|'b' the dost,
 * c2 port selector (0: 5000, 1: 5001), c3 n, c4 sh (0xff none), c5 sl,
 * c6..c7 default payload length. */
static void f591_child_s(void)
{
	unsigned char msg[8], c[16];
	int s = -1, i, rc, k;

	close(F585_S.up[0]);
	close(F585_S.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F591 CHILDS|unshare=%d\n", errno);
		_exit(1);
	}
	c[0] = 'U';
	if (write(F585_S.up[1], c, 1) != 1)
		_exit(2);
	if (read(F585_S.dn[0], msg, 7) != 7 || msg[0] != 'M')
		_exit(3);
	memcpy(F591_X0M, msg + 1, 6);
	set_up("lo");
	for (i = 0; i < 200 && f555_ifindex("x1") < 0; i++)
		usleep(20000);
	set_up("x1");
	rc = f555_addr_add("x1", htonl(A90_S), 24);
	rc |= f591_route4_default(htonl(A90_X0), "x1");
	rc |= f591_neigh4("x1", htonl(A90_X0), F591_X0M);
	f585_mtu("x1", "65000");
	f555_sysctl("/proc/sys/net/ipv4/conf/all/forwarding", "0");
	i = mac_get("x1", F591_X1M);
	for (k = 0; k < 60; k++) {
		s = f564_udp_bind(AF_INET, A90_S, NULL, F591_SPORT);
		if (s >= 0)
			break;
		usleep(50000);
	}
	printf("F591 CHILDS|rc=%d|x1=%d|s=%d|errno=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|m1=%02x%02x%02x%02x%02x%02x\n",
	       rc, f555_ifindex("x1"), s, s < 0 ? errno : 0,
	       F591_X0M[0], F591_X0M[1], F591_X0M[2], F591_X0M[3],
	       F591_X0M[4], F591_X0M[5], F591_X1M[0], F591_X1M[1],
	       F591_X1M[2], F591_X1M[3], F591_X1M[4], F591_X1M[5]);
	c[0] = 'R';
	if (write(F585_S.up[1], c, 1) != 1)
		_exit(4);
	for (;;) {
		struct sockaddr_in d4;
		int n, sh, sl, psel, pl, hl, sent = 0, last = -9;

		if (f591_readn(F585_S.dn[0], c, 16) != 16)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		psel = c[2] & 3;
		n = c[3];
		sh = c[4] == 0xff ? -1 : c[4];
		sl = (c[5] << 8) | c[6];
		pl = (c[7] << 8) | c[8];
		hl = (c[9] << 8) | c[10];
		memset(&d4, 0, sizeof(d4));
		d4.sin_family = AF_INET;
		d4.sin_addr.s_addr = htonl(c[1] == 'a' ? A90_DA : A90_DB);
		d4.sin_port = htons(psel == 0 ? F591_DPORT :
				    psel == 1 ? F591_DPORT_G : F591_DPORT_W);
		if (c[0] == 's' || c[0] == 'f') {
			const unsigned char *pay = c[0] == 's' ?
				&F591_PAY[0][0] : &F591_FPAY[0][0];

			for (k = 0; k < n; k++) {
				int l = (k == sh) ? sl : (k == 0 && hl) ? hl : pl;

				rc = (int)sendto(s, pay + (size_t)k * F591_MAXPL,
						 (size_t)l, 0,
						 (struct sockaddr *)&d4,
						 sizeof(d4));
				last = rc;
				if (rc == l)
					sent++;
			}
			printf("F591 CHILDS|cmd=%c%c%d|n=%d|sh=%d|sl=%d|pl=%d|"
			       "sent=%d|rc=%d|errno=%d\n",
			       c[0], c[1], psel, n, sh, sl, pl, sent, last,
			       last < 0 ? errno : 0);
		}
		c[0] = 'D';
		if (write(F585_S.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* ---------- D: the receiver -------------------------------------------- */

static void f591_child_d(void)
{
	static unsigned char buf[4096];
	unsigned char msg[16], c[8], b[13];
	int s = -1, i, rc;

	close(F585_C.up[0]);
	close(F585_C.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F591 CHILDD|unshare=%d\n", errno);
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
	/* the receiver must not aggregate: all three GRO bits off */
	rc = f578_feat_set("y3", F585_GRO_BIT, 0);
	rc |= f578_feat_set("y3", F585_GROFL_BIT, 0);
	rc |= f578_feat_set("y3", F585_GROFWD_BIT, 0);
	rc |= f578_feat_set("y4", F585_GRO_BIT, 0);
	rc |= f578_feat_set("y4", F585_GROFL_BIT, 0);
	rc |= f578_feat_set("y4", F585_GROFWD_BIT, 0);
	printf("F591 GROSW|y3=%d|y4=%d\n", f555_ifindex("y3"),
	       f555_ifindex("y4"));
	i = f555_addr_add("y3", htonl(A90_DA), 24);
	i |= f555_addr_add("y4", htonl(A90_DB), 24);
	f585_mtu("y3", "65000");
	f585_mtu("y4", "65000");
	rc |= mac_get("y3", F591_Y3M);
	rc |= mac_get("y4", F591_Y4M);
	s = f564_udp_bind(AF_INET, 0, NULL, F591_DPORT);
	{
		unsigned int dv = 0;
		socklen_t dvl = (socklen_t)sizeof(dv);

		if (s >= 0)
			getsockopt(s, SOL_SOCKET, SO_RCVBUF, &dv, &dvl);
		F591_DEF = (int)dv;
	}
	printf("F591 DEFRB|def=%d|half=%d\n", F591_DEF, F591_DEF >> 1);
	b[0] = 'M';
	memcpy(b + 1, F591_Y3M, 6);
	memcpy(b + 7, F591_Y4M, 6);
	if (write(F585_C.up[1], b, 13) != 13)
		_exit(4);
	printf("F591 CHILDD|rc=%d|y3=%d|y4=%d|s=%d|addr=%d|"
	       "m3=%02x%02x%02x%02x%02x%02x|m4=%02x%02x%02x%02x%02x%02x\n",
	       rc, f555_ifindex("y3"), f555_ifindex("y4"), s, i,
	       F591_Y3M[0], F591_Y3M[1], F591_Y3M[2], F591_Y3M[3],
	       F591_Y3M[4], F591_Y3M[5], F591_Y4M[0], F591_Y4M[1],
	       F591_Y4M[2], F591_Y4M[3], F591_Y4M[4], F591_Y4M[5]);
	fflush(stdout);
	for (;;) {
		if (f586_read8(F585_C.dn[0], c) != 8)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		if (c[0] == 'p') {
			int req = (int)(((unsigned int)c[1] << 24) |
					((unsigned int)c[2] << 16) |
					((unsigned int)c[3] << 8) |
					(unsigned int)c[4]);
			unsigned int rb = 0;
			socklen_t rbl = (socklen_t)sizeof(rb);
			int got = 0;

			if (req < 0)
				req = F591_DEF / 2;
			if (req > 0 && s >= 0)
				(void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, &req,
						 (socklen_t)sizeof(req));
			if (s >= 0)
				getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rb, &rbl);
			for (;;) {
				int r = s < 0 ? -1 :
					(int)recv(s, buf, sizeof(buf),
						  MSG_DONTWAIT);

				if (r < 0)
					break;
				got++;
			}
			printf("F591 PREP|req=%d|rb=%u|drained=%d|rmem=%d\n",
			       req, rb, got, f591_proc_rmem(F591_DPORT));
		} else if (c[0] == 'w') {
			int want = (int)(((unsigned int)c[1] << 24) |
					 ((unsigned int)c[2] << 16) |
					 ((unsigned int)c[3] << 8) |
					 (unsigned int)c[4]);
			long long t0 = f587_ms();
			int last = -2, stable = 0, ok = 0;

			while (f587_ms() - t0 < 6000) {
				int r = f591_proc_rmem(F591_DPORT);

				if (r != last) {
					last = r;
					stable = 0;
				} else {
					stable++;
				}
				if ((want > 0 ? (last >= want) : (last > 0)) &&
				    stable >= 100) {
					ok = 1;
					break;
				}
				usleep(5000);
			}
			printf("F591 WAIT|want=%d|rmem=%d|ms=%lld|stable=%d|ok=%d\n",
			       want, last, f587_ms() - t0, stable, ok);
		} else if (c[0] == 'r') {
			int idx = c[1], att = c[2];
			int win = (c[3] << 8) | c[4];
			int lazy = c[6];
			int nd = 0, nf = 0, nt = 0, empt = 0, pass = 0;
			long long t1 = -1, tl = -1;
			int dl[8] = { -1, -1, -1, -1, -1, -1, -1, -1 };
			int dv = 0, first = -1;
			unsigned int rb = 0;
			socklen_t rbl = (socklen_t)sizeof(rb);
			long long t0;
			long long in, err;

			if (lazy)
				usleep((useconds_t)lazy * 1000);
			if (s >= 0)
				getsockopt(s, SOL_SOCKET, SO_RCVBUF, &rb, &rbl);
			/* the queue AS IT WAS BUILT, before a single read */
			dv = f591_proc_rmem(F591_DPORT);
			t0 = f587_ms();
			while (f587_ms() - t0 < win && pass < 4000) {
				int got = 0;

				pass++;
				for (;;) {
					int r = s < 0 ? -1 :
						(int)recv(s, buf, sizeof(buf),
							  MSG_DONTWAIT);

					if (r < 0)
						break;
					if (nd == 0) {
						first = (int)(unsigned char)buf[0];
						t1 = f587_ms() - t0;
					}
					tl = f587_ms() - t0;
					if (nd < 8)
						dl[nd] = r;
					nd++;
					got++;
					if ((unsigned char)buf[0] >= 0x80)
						nf++;
					else
						nt++;
				}
				if (!got)
					empt++;
				else
					empt = 0;
				usleep(2000);
			}
			f591_snmp4(&in, &err);
			printf("F591 RCV|i=%02d|att=%d|n=%d|nf=%d|nt=%d|"
			       "rmem=%d|rma=%d|rb=%u|lazy=%d|win=%d|pass=%d|"
			       "empt=%d|first=%d|dl0=%d|dl1=%d|dl2=%d|dl3=%d|"
			       "dl7=%d|udpin=%lld|udperr=%lld|ms=%lld|t1=%lld|"
			       "tl=%lld\n",
			       idx, att, nd, nf, nt, dv,
			       f591_proc_rmem(F591_DPORT), rb, lazy, win,
			       pass, empt, first, dl[0], dl[1], dl[2], dl[3],
			       dl[7], in, err, f587_ms() - t0, t1, tl);
		}
		fflush(stdout);
		c[0] = 'D';
		if (write(F585_C.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* ---------- the arms ---------------------------------------------------- */

struct f591_arm {
	const char *name;
	char kind;	/* 'c' byte cap, 'q' queue budget */
	char dst;	/* the test's door: 'a' y3 10.64.0.92, 'b' y4 10.65.0.92 */
	char xg;	/* GRO at x0: 'n' none, 'u' udp_fwd (linear), 'f' fraglist */
	char fdst;	/* the filler's door, 0 = no filler */
	int fn;		/* filler datagrams */
	int fpl;	/* filler payload */
	int n;		/* test datagrams */
	int pl;		/* test payload */
	int sh;		/* the odd one: index, or -1 */
	int sl;		/* its payload length */
	int rcvbuf;	/* SO_RCVBUF request; -1 = the socket's own default */
	int lazy;	/* ms the reader waits before reading */
	int exp;	/* packets the rule is expected to count */
	int primer;	/* payload of one datagram to port 5002 sent first, 0 none */
	int head;	/* payload of datagram 0 when it differs from the rest */
};

/* mode `cap`: the byte cap with EQUAL payloads.
 * `exp` counts packets INCLUDING the primer (a 72-byte datagram to port 5002),
 * which is why every value here is one more than predictions_591.md's column. */
static const struct f591_arm AF591_CAP[] = {
	/* name          k  dst xg  fd fn fpl  n     pl  sh  sl rcvbuf lazy exp pr head */
	{ "e1637x40_f", 'c', 'a', 'f', 0, 0, 0, 40, 1637, -1, 0, 212992, 0, 3, 64, 0 },
	{ "e1637x40_u", 'c', 'a', 'u', 0, 0, 0, 40, 1637, -1, 0, 212992, 0, 2, 64, 0 },
	{ "e1636x40_f", 'c', 'a', 'f', 0, 0, 0, 40, 1636, -1, 0, 212992, 0, 2, 64, 0 },
	{ "e1637x39_f", 'c', 'a', 'f', 0, 0, 0, 39, 1637, -1, 0, 212992, 0, 2, 64, 0 },
	{ "e1638x40_f", 'c', 'a', 'f', 0, 0, 0, 40, 1638, -1, 0, 212992, 0, 3, 64, 0 },
	{ "e1638x40_u", 'c', 'a', 'u', 0, 0, 0, 40, 1638, -1, 0, 212992, 0, 3, 64, 0 },
	{ "e1024x64_f", 'c', 'a', 'f', 0, 0, 0, 64, 1024, -1, 0, 212992, 0, 3, 64, 0 },
	{ "e1024x64_u", 'c', 'a', 'u', 0, 0, 0, 64, 1024, -1, 0, 212992, 0, 3, 64, 0 },
	{ "e1600x41_f", 'c', 'a', 'f', 0, 0, 0, 41, 1600, -1, 0, 212992, 0, 3, 64, 0 },
	{ "e2048x33_f", 'c', 'a', 'f', 0, 0, 0, 33, 2048, -1, 0, 212992, 0, 3, 64, 0 },
	{ "e512x65_f",  'c', 'a', 'f', 0, 0, 0, 65,  512, -1, 0, 212992, 0, 3, 64, 0 },
	{ "e512x64_f",  'c', 'a', 'f', 0, 0, 0, 64,  512, -1, 0, 212992, 0, 2, 64, 0 },
	/* the two arms that pin the byte instead of the window: 2H + sum is
	 * exactly 65535 (merges) here and exactly 65536 in e1637x40_f (refuses);
	 * and a linear packet long enough for the NFLOG ceiling of 65531. */
	{ "x1636t_f",   'c', 'a', 'f', 0, 0, 0, 40, 1637, 39, 1636, 212992, 0, 2, 64, 0 },
	{ "x993t_u",    'c', 'a', 'u', 0, 0, 0, 64, 1024, 63,  993, 212992, 0, 2, 64, 0 },
};

/* mode `price`: the truesize ladder.  Kind 'q' waits for the queue to stop
 * growing, then reads it BEFORE a single recv (F67's handshake), so `rmem` on
 * the RCV line is the charge of exactly the aggregate measured on the wire. */
static const struct f591_arm AF591_PRICE[] = {
	{ "p512_1_f",	'q', 'a', 'f', 0, 0, 0,  1,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_2_f",	'q', 'a', 'f', 0, 0, 0,  2,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_3_f",	'q', 'a', 'f', 0, 0, 0,  3,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_4_f",	'q', 'a', 'f', 0, 0, 0,  4,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_8_f",	'q', 'a', 'f', 0, 0, 0,  8,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_16_f",	'q', 'a', 'f', 0, 0, 0, 16,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_32_f",	'q', 'a', 'f', 0, 0, 0, 32,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_64_f",	'q', 'a', 'f', 0, 0, 0, 64,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_64b_f",	'q', 'a', 'f', 0, 0, 0, 64,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_64c_f",	'q', 'a', 'f', 0, 0, 0, 64,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_8_u",	'q', 'a', 'u', 0, 0, 0,  8,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p512_64_u",	'q', 'a', 'u', 0, 0, 0, 64,  512, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p1200_1_f",	'q', 'a', 'f', 0, 0, 0,  1, 1200, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p1200_2_f",	'q', 'a', 'f', 0, 0, 0,  2, 1200, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p1200_4_f",	'q', 'a', 'f', 0, 0, 0,  4, 1200, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p1200_8_f",	'q', 'a', 'f', 0, 0, 0,  8, 1200, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p1200_16_f",	'q', 'a', 'f', 0, 0, 0, 16, 1200, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p1200_32_f",	'q', 'a', 'f', 0, 0, 0, 32, 1200, -1, 0, 212992, 0, 2, 64, 0 },
	{ "p1200_8_u",	'q', 'a', 'u', 0, 0, 0,  8, 1200, -1, 0, 212992, 0, 2, 64, 0 },
};

/* every message this attempt left in the drain buffer */
static int f591_msgs(const struct f575_pl *pl, int idx, int att)
{
	int n = 0, i;

	for (i = 0; i < pl->n && i < F575_NPL; i++) {
		const struct f575_msg *M = &pl->m[i];
		char h16[40] = "-", h32[72] = "-";
		int tot = -1, id = -1, ff = -1, ttl = -1, proto = -1;
		int uh = -1, ck = -1, p0 = -1, k;

		if (strncmp(M->prefix, "91:", 3))
			continue;
		f587_sl(h16, sizeof(h16), M->p, M->plen, 0, 16);
		f587_sl(h32, sizeof(h32), M->p, M->plen, 16, 32);
		if (M->plen >= 4)
			tot = (M->p[2] << 8) | M->p[3];
		if (M->plen >= 6)
			id = (M->p[4] << 8) | M->p[5];
		if (M->plen >= 8)
			ff = (M->p[6] << 8) | M->p[7];
		if (M->plen >= 9)
			ttl = M->p[8];
		if (M->plen >= 10)
			proto = M->p[9];
		if (M->plen >= 26)
			uh = (M->p[24] << 8) | M->p[25];
		if (M->plen >= 28)
			ck = (M->p[26] << 8) | M->p[27];
		if (M->plen >= 32) {
			p0 = 0;
			for (k = 28; k < 32; k++)
				p0 = (p0 << 8) | M->p[k];
		}
		printf("F591 LOG|i=%02d|att=%d|k=%d|pre=%s|plen=%d|tot=%d|id=%d|"
		       "ff=%04x|ttl=%d|proto=%d|uh=%d|ck=%04x|p0=%08x|"
		       "h16=%s|h32=%s\n",
		       idx, att, n, M->prefix, M->plen, tot, id,
		       ff < 0 ? 0 : ff, ttl, proto, uh, ck < 0 ? 0 : ck, p0,
		       h16, h32);
		n++;
	}
	return n;
}

static void f591_arm(const struct f591_arm *A, int idx)
{
	struct f575_pl pl;
	int rc = -99, ch0 = -1, ch1, att, agr = -1, cmdrc = 0, acks = 0;
	int mn = 0, mn0 = 0;
	int win = A->kind == 'c' ? 700 : A->lazy + 600;

	memset(&pl, 0, sizeof(pl));
	for (att = 0; att < 2; att++) {
		/* 1. the shape of x0's GRO -- a device bit the rule cannot see */
		f578_feat_set("x0", F585_GRO_BIT, 1);
		f578_feat_set("x0", F585_GROFL_BIT, A->xg == 'f');
		f578_feat_set("x0", F585_GROFWD_BIT, A->xg == 'u');
		/* 2. clean slate: the rule, the buffer, the queue */
		(void)f557_flush(NFPROTO_IPV4, "f90p", "fwd", &acks);
		f575_nfl_drain(&pl);
		cmdrc |= f586_cmd(&F585_C, 'p',
				  (A->rcvbuf >> 24) & 0xff,
				  (A->rcvbuf >> 16) & 0xff,
				  (A->rcvbuf >> 8) & 0xff,
				  A->rcvbuf & 0xff, 0, 0, 0) ? 1 : 0;
		f591_tap_drain(&F585_TA);
		f591_tap_drain(&F585_TB);
		(void)f557_flush(NFPROTO_IPV4, "f90p", "fwd", &acks);
		f575_nfl_drain(&pl);
		/* 3. the rule */
		/* a quiet gap: a GRO timer left by the previous attempt was
		 * measured to fire in the MIDDLE of a burst and split it */
		usleep(300000);
		rc = f591_rule(idx);
		/* 3b. the primer: one datagram to a port nobody listens on, so
		 *     that x0's NAPI is already inside a poll/timer cycle when
		 *     the measured burst starts.  Without it the FIRST datagram
		 *     of a burst is sometimes processed alone (measured in the
		 *     first smoke of this turn: 1 + 2 instead of 3).  It never
		 *     reaches the socket and the rule tells it apart by length. */
		if (A->primer > 0)
			cmdrc |= f591_send_s(&F585_S, 's', A->dst, 2, 1, 0xff,
					     0, A->primer, 0) ? 64 : 0;
		/* 4. the traffic: the filler first, so it is queued before the
		 *    test arrives, then the test itself */
		if (A->fn > 0) {
			cmdrc |= f591_send_s(&F585_S, 'f',
					     A->fdst ? A->fdst : 'b', 0,
					     A->fn, 0xff, 0, A->fpl, 0) ? 8 : 0;
			/* the filler must be IN the queue before the test
			 * arrives, or the arm measures nothing (F67's design) */
			cmdrc |= f586_cmd(&F585_C, 'w', 0, 0, 0, 0x3a, 0x98,
					  0, 0) ? 256 : 0;
			usleep(200000);
		}
		cmdrc |= f591_send_s(&F585_S, 's', A->dst, 0, A->n,
				     A->sh < 0 ? 0xff : A->sh, A->sl,
				     A->pl, A->head) ? 16 : 0;
		/* 5. the queue must be BUILT before it is read: the receiver
		 *    waits until the queue has stopped growing, then reads */
		if (A->kind == 'q')
			cmdrc |= f586_cmd(&F585_C, 'w', 0, 0, 0, 0, 0, 0, 0)
				 ? 128 : 0;
		cmdrc |= f586_cmd(&F585_C, 'r', idx, att,
				  (win >> 8) & 0xff, win & 0xff, 0,
				  A->lazy, 0) ? 32 : 0;
		f591_tap_drain(&F585_TA);
		f591_tap_drain(&F585_TB);
		f575_nfl_drain(&pl);
		ch1 = (int)f555_count(NFPROTO_IPV4, "f90p", "fwd");
		mn = f591_msgs(&pl, idx, att);
		if (att == 0) {
			ch0 = ch1;
			mn0 = mn;
		} else {
			agr = (ch1 == ch0 && mn == mn0) ? 1 : 0;
		}
	}
	printf("F591 ARM|i=%02d|name=%s|kind=%c|dst=%c|xg=%c|fdst=%c|fn=%d|"
	       "fpl=%d|n=%d|pl=%d|sh=%d|sl=%d|rcvbuf=%d|lazy=%d|win=%d|exp=%d|"
	       "primer=%d|head=%d|"
	       "rc=%d|cmdrc=%d|ch=%d|ch0=%d|agr=%d|mn=%d|mn0=%d|"
	       "an=%d|anall=%d|bn=%d|bnall=%d\n",
	       idx, A->name, A->kind, A->dst, A->xg,
	       A->fdst ? A->fdst : '-', A->fn, A->fpl, A->n, A->pl, A->sh,
	       A->sl, A->rcvbuf, A->lazy, win, A->exp, A->primer, A->head,
	       rc, cmdrc,
	       ch1, ch0,
	       agr, mn, mn0, F585_TA.n, F585_TA.nall, F585_TB.n,
	       F585_TB.nall);
	fflush(stdout);
	f591_tap_print(&F585_TA, idx, "y1");
	f591_tap_print(&F585_TB, idx, "y2");
	fflush(stdout);
}

/* ---------- the common setup ------------------------------------------- */

static int f591_setup(void)
{
	static const char *old[] = { "x0", "x1", "y1", "y2", "y3", "y4" };
	struct f578_gf g;
	unsigned char msg[16];
	int i, rc, r1, r2;

	f585_tap_zero(&F585_TA);
	f585_tap_zero(&F585_TB);
	F585_TA.fd = -1;
	F585_TB.fd = -1;
	F585_TA.only_out = 1;
	F585_TB.only_out = 1;
	for (i = 0; i < F591_ND; i++) {
		int k;

		for (k = 0; k < F591_MAXPL; k++)
			F591_PAY[i][k] = (unsigned char)(0x40 + (k & 0x3f));
		F591_PAY[i][0] = (unsigned char)(0x10 + (i & 0x0f));
		F591_PAY[i][1] = (unsigned char)i;
	}
	for (i = 0; i < F591_ND; i++) {
		int k;

		for (k = 0; k < F591_MAXPL; k++)
			F591_FPAY[i][k] = (unsigned char)(0x40 + (k & 0x3f));
		F591_FPAY[i][0] = (unsigned char)(0xE0 | (i & 0x1f));
		F591_FPAY[i][1] = (unsigned char)i;
	}
	f555_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
	f555_sysctl("/proc/sys/net/ipv4/conf/all/forwarding", "1");
	f555_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
	f555_sysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0");
	for (i = 0; i < 6; i++)
		f558_link_del(old[i]);
	{
		int acks = 0;

		(void)f557_flush(NFPROTO_IPV4, "f90p", "fwd", &acks);
		(void)f584_deltable(NFPROTO_IPV4, "f90p");
	}
	if (pipe(F585_S.up) || pipe(F585_S.dn) || pipe(F585_C.up) ||
	    pipe(F585_C.dn)) {
		printf("F591 FAIL|pipe\n");
		return -1;
	}
	F585_S.pid = fork();
	if (F585_S.pid < 0) {
		printf("F591 FAIL|fork\n");
		return -1;
	}
	if (F585_S.pid == 0)
		f591_child_s();
	F585_C.pid = fork();
	if (F585_C.pid < 0) {
		printf("F591 FAIL|fork2\n");
		return -1;
	}
	if (F585_C.pid == 0)
		f591_child_d();
	close(F585_S.up[1]);
	close(F585_S.dn[0]);
	close(F585_C.up[1]);
	close(F585_C.dn[0]);
	if (f585_wait_byte(F585_S.up[0], 5000) != 'U') {
		printf("F591 FAIL|senderns\n");
		return -1;
	}
	if (f585_wait_byte(F585_C.up[0], 5000) != 'U') {
		printf("F591 FAIL|recvns\n");
		return -1;
	}
	rc = f585_veth_ns("x0", "x1", (int)F585_S.pid);
	rc |= f585_veth_ns("y1", "y3", (int)F585_C.pid);
	rc |= f585_veth_ns("y2", "y4", (int)F585_C.pid);
	if (rc) {
		printf("F591 FAIL|veth|rc=%d\n", rc);
		return -1;
	}
	set_up("x0");
	set_up("y1");
	set_up("y2");
	printf("F591 GROSW|x0=%d\n", f578_feat_set("x0", F585_GRO_BIT, 1));
	rc = f555_addr_add("x0", htonl(A90_X0), 24);
	rc |= f555_addr_add("y1", htonl(A90_RA), 24);
	rc |= f555_addr_add("y2", htonl(A90_RB), 24);
	f555_sysctl("/proc/sys/net/ipv4/conf/x0/rp_filter", "0");
	f555_sysctl("/proc/sys/net/ipv4/conf/y1/rp_filter", "0");
	f555_sysctl("/proc/sys/net/ipv4/conf/y2/rp_filter", "0");
	f585_mtu("x0", "65000");
	f585_mtu("y1", "65000");
	f585_mtu("y2", "65000");
	f585_groto("x0", "200000000");
	mac_get("x0", F591_X0M);
	msg[0] = 'M';
	memcpy(msg + 1, F591_X0M, 6);
	if (write(F585_S.dn[1], msg, 7) != 7) {
		printf("F591 FAIL|mactx\n");
		return -1;
	}
	{
		unsigned char c = 'R';

		if (write(F585_C.dn[1], &c, 1) != 1) {
			printf("F591 FAIL|dsync\n");
			return -1;
		}
	}
	if (f585_wait_byte(F585_S.up[0], 8000) != 'R') {
		printf("F591 FAIL|senderready\n");
		return -1;
	}
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
			memcpy(F591_Y3M, b + 1, 6);
			memcpy(F591_Y4M, b + 7, 6);
		} else {
			printf("F591 FAIL|dmac|got=%d\n", got);
			return -1;
		}
	}
	rc |= f591_neigh4("y1", htonl(A90_DA), F591_Y3M);
	rc |= f591_neigh4("y2", htonl(A90_DB), F591_Y4M);
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
	printf("F591 FEAT|r1=%d|r2=%d\n", r1, r2);
	f578_feat_get("x0", &g);
	printf("F591 FEAT|dev=x0|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y1", &g);
	printf("F591 FEAT|dev=y1|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y2", &g);
	printf("F591 FEAT|dev=y2|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	{
		int k = 0;

		k |= f579_tbl(NFPROTO_IPV4, "f90p");
		k |= f580_chn(NFPROTO_IPV4, "f90p", "fwd", NULL, 2, 0);
		printf("F591 CHAINS|rc=%d\n", k);
	}
	F573_NFL = nfl_open(F591_GROUP);
	F585_NFL = F573_NFL;
	f586_taps(1);
	printf("F591 ENV|x0=%d|y1=%d|y2=%d|nfl=%d|addr=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|m3=%02x%02x%02x%02x%02x%02x|"
	       "m4=%02x%02x%02x%02x%02x%02x|ND=%d\n",
	       f555_ifindex("x0"), f555_ifindex("y1"), f555_ifindex("y2"),
	       F573_NFL, rc, F591_X0M[0], F591_X0M[1], F591_X0M[2],
	       F591_X0M[3], F591_X0M[4], F591_X0M[5],
	       F591_Y3M[0], F591_Y3M[1], F591_Y3M[2], F591_Y3M[3],
	       F591_Y3M[4], F591_Y3M[5],
	       F591_Y4M[0], F591_Y4M[1], F591_Y4M[2], F591_Y4M[3],
	       F591_Y4M[4], F591_Y4M[5], F591_ND);
	return 0;
}

static void f591_shutdown(void)
{
	(void)f586_cmd(&F585_S, 'q', 0, 0, 0, 0, 0, 0, 0);
	(void)f586_cmd(&F585_C, 'q', 0, 0, 0, 0, 0, 0, 0);
}

static int f591_run(const struct f591_arm *T, int n, int limit, const char *nm)
{
	int i;

	printf("F591 GROTO_PLAN|timeout=200000000|defer=1\n");
	if (f591_setup())
		return -1;
	for (i = 0; i < n; i++) {
		if (limit > 0 && i >= limit) {
			printf("F591 SKIP|from=%d|limit=%d\n", i, limit);
			break;
		}
		f591_arm(&T[i], i);
	}
	f591_shutdown();
	printf("F591 END|mode=%s|arms=%d\n", nm, i);
	fflush(stdout);
	return 0;
}

/* ---------- entry ------------------------------------------------------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "cap4";
	int limit = argc > 2 ? atoi(argv[2]) : 0;
	static char mbuf[32];

	if (strchr(mode, ':')) {
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
	printf("F591 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "cap"))
		return f591_run(AF591_CAP,
				(int)(sizeof(AF591_CAP) / sizeof(AF591_CAP[0])),
				limit, "cap");
	if (!strcmp(mode, "price"))
		return f591_run(AF591_PRICE,
				(int)(sizeof(AF591_PRICE) / sizeof(AF591_PRICE[0])),
				limit, "price");
	return f589_entry(argc, argv);
}
