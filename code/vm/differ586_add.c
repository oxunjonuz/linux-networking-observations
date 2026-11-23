/* differ586_add.c -- turn 586 (F64): THE GEOMETRY OF AN AGGREGATE -- THE
 * LENGTH THE RULE READS IS ONE NO DATAGRAM IN IT HAS.
 *
 * The three debts F63 left, and the fourth it could not reach:
 *   (1) a short tail inside one aggregate (512,512,512,200): the aggregate's
 *       uh->len is the SUM, and the splitter computes the tail's length in a
 *       clause of its own (`if (!skb_is_gso(seg))` , net/ipv4/udp_offload.c:592);
 *   (2) UDP_GRO_CNT_MAX = 64 (net/ipv4/udp_offload.c:694,766): 65 datagrams
 *       must become two packets, and the one that did not fit is a PLAIN
 *       packet (gro_complete() sets gso_size = 0 when count == 1,
 *       net/core/gro.c:280);
 *   (3) a short datagram in the MIDDLE (`ulen > udp_get_len_short(uh2)`)
 *       ends the aggregate and does not start a new one with what follows;
 *   (4) mss > payload: `gso_skb->len <= sizeof(*uh) + mss` -> -EINVAL
 *       (net/ipv4/udp_offload.c:517), drop_count = gso_segs.
 *
 * Topology is F63's, unchanged (three netns; the parent is THE ROUTER):
 *   parent: x0 (ingress from S), y1 fd03::91, y2 fd04::91; ip6 table f85p
 *           with chain `fwd` (hook forward prio 0); one rule per arm:
 *           [meta l4proto 17] counter [store] log(86:NN) accept.
 *   S: x1 fd02::11/64, sends n datagrams from ONE socket ('F', CHECKSUM_PARTIAL)
 *      or n hand-built AF_PACKET frames with correct checksums ('P').
 *   D: y3 fd03::92, y4 fd04::92; sockets on 5000 (plain) and 5001 (UDP_GRO);
 *      a witness chain in ITS OWN netns counting every UDP packet it sees.
 *
 * Every arm prints: the rule's counter, the NFLOG message (its TRUE length
 * from the netlink attribute, the IPv6 payload length, the UDP header, the
 * payload at four profile positions and the last 8 bytes), D's witness
 * counters, the datagram lengths the socket actually read (first six, last
 * two, and the datagram index carried in each payload's first byte), the snmp
 * deltas, and the wire frames as D's taps see them.
 *
 * Profile is per arm: n datagrams of 512 bytes, one of them (`sh`) `sl` long.
 * "g_c65_*" sends 65, "g_mid_*" puts the short one in the middle.
 */

#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>

#define F586_DPORT	5000
#define F586_DPORT_G	5001
#define F586_DPORT_W	5002	/* warm-up: no socket listens here */
#define F586_MSS	512
#define F586_SL		200
#define F586_ND		66		/* max datagrams in one arm */
#define F586_BIGP	1200		/* the frame of the mss>payload arm */

static unsigned char F586_PAY[F586_ND][F586_MSS];
static unsigned char F586_BIG[F586_BIGP];

/* ---------- one frame, any payload length ------------------------------ */

static int f586_mkframe(unsigned char *out, const unsigned char *dmac,
			const unsigned char *smac, const unsigned char *daddr,
			unsigned short dport, int seq, int paylen)
{
	unsigned short c;
	int udplen = 8 + paylen;

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
	memcpy(out + 62, F586_PAY[seq], (size_t)paylen);
	c = f585_correct(A85_S6, daddr, F585_SPORT, dport, udplen,
			 out + 62, paylen);
	out[60] = (unsigned char)(c >> 8);
	out[61] = (unsigned char)(c & 0xff);
	return 62 + paylen;
}

/* ---------- commands to the children (8-byte messages) ----------------- */

static int f586_cmd(struct f585_conn *C, int c0, int c1, int c2, int c3,
		    int c4, int c5, int c6, int c7)
{
	unsigned char m[8];
	int i, r;

	m[0] = (unsigned char)c0;
	m[1] = (unsigned char)c1;
	m[2] = (unsigned char)c2;
	m[3] = (unsigned char)c3;
	m[4] = (unsigned char)c4;
	m[5] = (unsigned char)c5;
	m[6] = (unsigned char)c6;
	m[7] = (unsigned char)c7;
	for (i = 0; i < 8; i += r) {
		r = (int)write(C->dn[1], m + i, (size_t)(8 - i));
		if (r <= 0)
			return -1;
	}
	return f585_wait_byte(C->up[0], 20000) == 'D' ? 0 : -1;
}

static int f586_read8(int fd, unsigned char *m)
{
	int got = 0;

	while (got < 8) {
		int r = (int)read(fd, m + got, (size_t)(8 - got));

		if (r <= 0) {
			if (errno == EINTR)
				continue;
			return got;
		}
		got += r;
	}
	return got;
}

/* ---------- S: the sender, one socket or hand-built frames -------------- */

static void f586_child_s(void)
{
	unsigned char msg[8], c[8];
	unsigned char fr[62 + F586_MSS + 8];
	static const unsigned short ports[3] = { F586_DPORT, F586_DPORT_G, F586_DPORT_W };
	int s6 = -1, i, rc, k;

	close(F585_S.up[0]);
	close(F585_S.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F586 CHILDS|unshare=%d\n", errno);
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
	f585_mtu("x1", "65000");
	i = mac_get("x1", F585_X1M);
	for (k = 0; k < 60; k++) {
		s6 = f564_udp_bind(AF_INET6, 0, A85_S6, F585_SPORT);
		if (s6 >= 0)
			break;
		usleep(50000);
	}
	printf("F586 CHILDS|rc=%d|macrc=%d|x1=%d|s6=%d|errno=%d|"
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
		int n, sh, sl, mss, psel, sent = 0, last = -9;

		if (f586_read8(F585_S.dn[0], c) != 8)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		psel = c[2] & 3;
		n = c[3];
		sh = c[4] == 0xff ? -1 : c[4];
		sl = c[5];
		mss = (c[6] << 8) | c[7];
		memset(&d6, 0, sizeof(d6));
		d6.sin6_family = AF_INET6;
		memcpy(&d6.sin6_addr, c[1] == 'a' ? A85_DA : A85_DB, 16);
		d6.sin6_port = htons(ports[psel]);
		if (c[0] == 's') {
			int gro = mss;

			if (mss)
				(void)setsockopt(s6, IPPROTO_UDP, UDP_SEGMENT,
						 &gro, (socklen_t)sizeof(gro));
			for (k = 0; k < n; k++) {
				int pl = (k == sh) ? sl :
					 (mss ? F586_BIGP : F586_MSS);
				const unsigned char *pp = mss ? F586_BIG :
							 F586_PAY[k];

				rc = (int)sendto(s6, pp, (size_t)pl, 0,
						 (struct sockaddr *)&d6,
						 sizeof(d6));
				last = rc;
				if (rc == pl)
					sent++;
			}
			if (mss) {
				gro = 0;
				(void)setsockopt(s6, IPPROTO_UDP, UDP_SEGMENT,
						 &gro, (socklen_t)sizeof(gro));
			}
			printf("F586 CHILDS|cmd=s%c%d|n=%d|sh=%d|sl=%d|mss=%d|"
			       "sent=%d|rc=%d|errno=%d\n",
			       c[1], psel, n, sh, sl, mss, sent, last,
			       last < 0 ? errno : 0);
		} else if (c[0] == 'p') {
			for (k = 0; k < n; k++) {
				int pl = (k == sh) ? sl : F586_MSS;
				int fl = f586_mkframe(fr, F585_X0M, F585_X1M,
						      c[1] == 'a' ? A85_DA :
						      A85_DB, ports[psel], k, pl);

				rc = f585_send_frame(fr, fl, "x1");
				last = rc;
				if (rc == fl)
					sent++;
			}
			printf("F586 CHILDS|cmd=p%c%d|n=%d|sh=%d|sl=%d|"
			       "sent=%d|rc=%d\n",
			       c[1], psel, n, sh, sl, sent, last);
		}
		c[0] = 'D';
		if (write(F585_S.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* ---------- D: the receiver -------------------------------------------- */

static int f586_wrule(void)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	unsigned char l4 = 17;
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
	counter_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

static void f586_child_d(void)
{
	static unsigned char buf[4096];
	static unsigned char cb[256];
	unsigned char msg[16], c[8];
	static struct f585_tap t3, t4;
	struct f580_sn prev, cur;
	static int dl[2][F586_ND];
	static int db[2][F586_ND];
	static int dg[2][F586_ND];
	unsigned long long cw[4];
	static unsigned long long cwp[4];
	int i, rc, s, sg, wrc = 0;

	close(F585_C.up[0]);
	close(F585_C.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F586 CHILDD|unshare=%d\n", errno);
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
	printf("F586 GROSW|y3=%d|y4=%d\n",
	       f578_feat_set("y3", F585_GRO_BIT, 1),
	       f578_feat_set("y4", F585_GRO_BIT, 1));
	(void)f585_v6dev("y3", 0);
	(void)f585_v6dev("y4", 0);
	f555_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");
	rc = f585_addr6_nodad("y3", A85_DA, 64);
	rc |= f585_addr6_nodad("y4", A85_DB, 64);
	f585_mtu("y3", "65000");
	f585_mtu("y4", "65000");
	f585_groto("y3", "20000000");
	f585_groto("y4", "20000000");
	i = mac_get("y3", F585_Y3M);
	i |= mac_get("y4", F585_Y4M);
	s = -1;
	sg = -1;
	{
		unsigned char any[16];
		int one = 1;

		memset(any, 0, sizeof(any));
		s = f564_udp_bind(AF_INET6, 0, any, F586_DPORT);
		if (s >= 0)
			setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one,
				   sizeof(one));
		sg = f564_udp_bind(AF_INET6, 0, any, F586_DPORT_G);
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
		wrc |= f586_wrule();
	}
	t3.fd = f578_tap_open_aux("y3");
	t4.fd = f578_tap_open_aux("y4");
	t3.only_out = 0;
	t4.only_out = 0;
	printf("F586 CHILDD|rc=%d|s=%d|sg=%d|y3=%d|y4=%d|t3=%d|t4=%d|wrc=%d|"
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
		int idx, pass, nd[2] = { 0, 0 }, psel, ncnt;
		int sock[2];

		if (f586_read8(F585_C.dn[0], c) != 8)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		if (c[0] == 'b') {
			f580_snmp(&prev);
			f585_tap_drain(&t3);
			f585_tap_drain(&t4);
			c[0] = 'D';
			if (write(F585_C.up[1], c, 1) != 1)
				_exit(7);
			continue;
		}
		if (c[0] == 'p') {
			f578_feat_set("y3", F585_GROFL_BIT, c[1] == 2);
			f578_feat_set("y3", F585_GROFWD_BIT, c[1] == 1);
			f578_feat_set("y4", F585_GROFL_BIT, c[1] == 2);
			f578_feat_set("y4", F585_GROFWD_BIT, c[1] == 1);
			c[0] = 'D';
			if (write(F585_C.up[1], c, 1) != 1)
				_exit(6);
			continue;
		}
		if (c[0] != 'r')
			continue;
		idx = c[1] & 0x7f;
		psel = (c[2] >> 4) & 1;
		sock[0] = s;
		sock[1] = sg;
		memset(dl, 0, sizeof(dl));
		memset(db, 0, sizeof(db));
		memset(dg, 0, sizeof(dg));
		{
			int empty = 0;

			for (pass = 0; pass < 400 && empty < 14; pass++) {
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
						if (nd[w] < F586_ND) {
							struct cmsghdr *cm;
							int k = nd[w];

							dl[w][k] = r;
							db[w][k] = r > 0 ? buf[0] : -1;
							dg[w][k] = -1;
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
		if (c[1] & 0x80) {	/* quiet attempt: no print, just the ack */
			prev = cur;
			c[0] = 'D';
			if (write(F585_C.up[1], c, 1) != 1)
				_exit(8);
			continue;
		}
		printf("F586 RCV|i=%02d|psel=%d|n=%d|n2=%d|ncnt=%d|"
		       "L=%d,%d,%d,%d,%d,%d,%d,%d|B=%d,%d,%d,%d,%d,%d,%d,%d|"
		       "g0=%d|nn=%d|nn2=%d|"
		       "wany=%llu|w520=%llu|"
		       "rcv=%lld|deliv=%lld|udp=%lld|udperr=%lld|"
		       "hdr=%lld|disc=%lld|nop=%lld|t3=%d|t4=%d\n",
		       idx, psel, nd[0], nd[1], ncnt,
		       dl[0][0], dl[0][1], dl[0][2], dl[0][3],
		       dl[0][4], dl[0][5],
		       nd[0] > 1 ? dl[0][nd[0] - 2] : -1,
		       nd[0] > 0 ? dl[0][nd[0] - 1] : -1,
		       db[0][0], db[0][1], db[0][2], db[0][3],
		       db[0][4], db[0][5],
		       nd[0] > 1 ? db[0][nd[0] - 2] : -1,
		       nd[0] > 0 ? db[0][nd[0] - 1] : -1,
		       dg[0][0],
		       nd[1] > 0 ? nd[1] : -1,
		       nd[1] > 1 ? dl[1][1] : -1,
		       cw[2] - cwp[2], cw[1] - cwp[1],
		       (long long)cur.rcv - (long long)prev.rcv,
		       (long long)cur.deliv - (long long)prev.deliv,
		       (long long)cur.udp - (long long)prev.udp,
		       (long long)cur.udperr - (long long)prev.udperr,
		       (long long)cur.hdrerr - (long long)prev.hdrerr,
		       (long long)cur.disc - (long long)prev.disc,
		       (long long)cur.udpnop - (long long)prev.udpnop,
		       t3.n, t4.n);
		cwp[0] = cw[0];
		cwp[1] = cw[1];
		cwp[2] = cw[2];
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

struct f586_arm {
	struct f585_arm b;
	int n;		/* datagrams */
	int sh;		/* index of the short one, -1 none */
	int sl;		/* its payload length */
	int mss;	/* UDP_SEGMENT value, 0 = none */
	int tap;	/* 1: keep the parent's y1/y2 taps open during this arm */
	int xgro;	/* 1: x0's GRO master bit on, 0: off */
};

/* the parent taps must be closed for any arm that wants GRO at the receiver:
 * dev_queue_xmit_nit() clones the skb, and veth_xdp_rcv() then hands a shared
 * skb to netif_receive_skb() instead of napi_gro_receive() (F63, measured). */
static void f586_taps(int on)
{
	if (on) {
		if (F585_TA.fd < 0)
			F585_TA.fd = f578_tap_open_aux("y1");
		if (F585_TB.fd < 0)
			F585_TB.fd = f578_tap_open_aux("y2");
	} else {
		if (F585_TA.fd >= 0) {
			close(F585_TA.fd);
			F585_TA.fd = -1;
		}
		if (F585_TB.fd >= 0) {
			close(F585_TB.fd);
			F585_TB.fd = -1;
		}
	}
}

static const struct f586_arm AF586[] = {
	/* the tail: 512,512,512,200 versus the equal-length control */
	{ { "g_eq_a", 'F', 'a', 'f', 'n', 'p', 0, 0, 0, NULL }, 3, -1, 0, 0, 1, 1 },
	{ { "g_eq_b", 'F', 'b', 'f', 'n', 'p', 0, 0, 0, NULL }, 3, -1, 0, 0, 1, 1 },
	{ { "g_t3_a", 'F', 'a', 'f', 'n', 'p', 0, 0, 0, NULL }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_t3_b", 'F', 'b', 'f', 'n', 'p', 0, 0, 0, NULL }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_t3u_a", 'F', 'a', 'u', 'n', 'p', 0, 0, 0, NULL }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_t3u_b", 'F', 'b', 'u', 'n', 'p', 0, 0, 0, NULL }, 4, 3, F586_SL, 0, 1, 1 },
	/* a store in the tail's payload */
	{ { "g_t3_w_a", 'F', 'a', 'f', 'n', 'p', 1, 1544, 4, "a0a1a2a3" }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_t3_w_b", 'F', 'b', 'f', 'n', 'p', 1, 1544, 4, "a0a1a2a3" }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_t3u_w_b", 'F', 'b', 'u', 'n', 'p', 1, 1544, 4, "a0a1a2a3" }, 4, 3, F586_SL, 0, 1, 1 },
	/* a store in the aggregate's length field: on an aggregate, and on ONE
	 * datagram, where nothing rewrites the length afterwards */
	{ { "g_t3_len_b", 'F', 'b', 'f', 'n', 'p', 1, 4, 2, "0020" }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_t3u_len_b", 'F', 'b', 'u', 'n', 'p', 1, 4, 2, "0020" }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_one_len_b", 'F', 'b', 'f', 'n', 'p', 1, 4, 2, "0020" }, 1, -1, 0, 0, 1, 1 },
	{ { "g_one_len_a", 'F', 'a', 'f', 'n', 'p', 1, 4, 2, "0020" }, 1, -1, 0, 0, 1, 1 },
	/* the short one in the middle */
	{ { "g_mid_a", 'F', 'a', 'f', 'n', 'p', 0, 0, 0, NULL }, 4, 2, F586_SL, 0, 1, 1 },
	/* the cap: 65 and 66 datagrams */
	{ { "g_c65_a", 'F', 'a', 'f', 'n', 'p', 0, 0, 0, NULL }, 65, -1, 0, 0, 1, 1 },
	{ { "g_c65u_a", 'F', 'a', 'u', 'n', 'p', 0, 0, 0, NULL }, 65, -1, 0, 0, 1, 1 },
	/* a frame smaller than its own mss, with x0's GRO on and off */
	{ { "g_mssbig_a", 'F', 'a', 'n', 'n', 'p', 0, 0, 0, NULL }, 1, -1, 0, 9000, 1, 1 },
	{ { "g_mssbig_b", 'F', 'b', 'n', 'n', 'p', 0, 0, 0, NULL }, 1, -1, 0, 9000, 1, 1 },
	{ { "g_mssbig_ng_a", 'F', 'a', 'n', 'n', 'p', 0, 0, 0, NULL }, 1, -1, 0, 9000, 1, 0 },
	{ { "g_mssbig_ng_b", 'F', 'b', 'n', 'n', 'p', 0, 0, 0, NULL }, 1, -1, 0, 9000, 1, 0 },
	/* provenance CHECKSUM_NONE: what the sender already paid for */
	{ { "g_t3n_a", 'P', 'a', 'f', 'n', 'p', 0, 0, 0, NULL }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_t3n_w_a", 'P', 'a', 'f', 'n', 'p', 1, 1544, 4, "a0a1a2a3" }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_t3n_w_a2", 'P', 'a', 'f', 'n', 'p', 1, 1544, 4, "a0a1a2a3" }, 4, 3, F586_SL, 0, 0, 1 },
	{ { "g_t3n_w0_a", 'P', 'a', 'f', 'n', 'p', 1, 8, 4, "a0a1a2a3" }, 4, 3, F586_SL, 0, 1, 1 },
	{ { "g_t3n_w1_a", 'P', 'a', 'f', 'n', 'p', 1, 520, 4, "a0a1a2a3" }, 4, 3, F586_SL, 0, 1, 1 },
	/* NONE provenance with GRO at the RECEIVER (F63's configuration) */
	{ { "g_t3nd_a", 'P', 'a', 'n', 'f', 'p', 0, 0, 0, NULL }, 4, 3, F586_SL, 0, 0, 1 },
};

#define NAF586 ((int)(sizeof(AF586) / sizeof(AF586[0])))

static int f586_imm(const struct f585_arm *A, unsigned char *imm)
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

/* a slice of the logged bytes, clamped to what was actually stored */
static void f586_sl(char *out, size_t osz, const unsigned char *p, int stored,
		    int from, int to)
{
	int at = 0, i;

	if (from < 0 || to <= from || from >= stored) {
		snprintf(out, osz, "-");
		return;
	}
	if (to > stored)
		to = stored;
	for (i = from; i < to && at + 3 < (int)osz; i++)
		at += snprintf(out + at, osz - (size_t)at, "%02x", p[i]);
	out[at] = 0;
}

static void f586_arm(const struct f586_arm *A, int idx)
{
	const struct f585_arm *B = &A->b;
	struct f575_pl pl;
	unsigned char imm[64];
	char hxi[128] = "-";
	char lg6[16] = "-", lgudp[40] = "-", lgp0[40] = "-", lgp1[40] = "-";
	char lgp2[40] = "-", lgp3[40] = "-";
	int rc = -99, ilen = -1, ch = -1, nl = 0, lgplen = -1, lgst = -1;
	int lgn = 0, lg2 = -1, i, cmdrc = 0, att;
	int ch0 = -1, plen0 = -1, plen0b = -1, lgn0 = -1, agr = -1;
	int acks = 0;
	const char *chain = B->src == 'L' ? "out" : "fwd";

	/* 1. the shape of the ingress decides whether THE RULE sees a packet */
	f578_feat_set("x0", F585_GRO_BIT, A->xgro);
	f578_feat_set("x0", F585_GROFL_BIT, B->xg == 'f');
	f578_feat_set("x0", F585_GROFWD_BIT, B->xg == 'u');
	/* 2. clean slate */
	(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
	(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
	f575_nfl_drain(&pl);
	/* 2b. the receiver's GRO shape, before the traffic.
	 * A warm-up batch was tried here and removed: with the 200 ms flush
	 * timeout the warm-up flow is still in the GRO list when the measured
	 * batch starts, and it is forwarded LATER, through the rule that is by
	 * then installed -- five arms carried an extra 1584-byte packet because
	 * of it (measured in six boots).  The timeout alone is the fix. */
	cmdrc |= f586_cmd(&F585_C, 'p', B->dg == 'f' ? 2 : (B->dg == 'u' ? 1 : 0),
			  0, 0, 0, 0, 0, 0) ? 1 : 0;
	/* 3. the rule, then the traffic -- twice, and the second attempt is the
	 * one reported.  A packet held in the GRO list survives a poll-end flush
	 * only if it arrived in the same jiffy (__gro_flush_chain(),
	 * net/core/gro.c: flush_old && age == jiffies -> keep), so the FIRST
	 * datagram of a batch can be delivered alone while the rest aggregate.
	 * Measured, not assumed: one boot in ~30 differed before this loop. */
	(void)f586_cmd(&F585_C, 'b', 0, 0, 0, 0, 0, 0, 0);
	f586_taps(A->tap);
	for (att = 0; att < 2; att++) {
		(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
		(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
		f575_nfl_drain(&pl);
		if (B->store) {
			ilen = f586_imm(B, imm);
			rc = ilen < 0 ? -99 : f585_rule(B, idx, imm, ilen);
			f559_hexs(hxi, sizeof(hxi), imm, ilen > 0 ? ilen : 0);
		} else {
			rc = f585_rule(B, idx, NULL, 0);
		}
		cmdrc |= f586_cmd(&F585_S, B->src == 'F' ? 's' : 'p',
				  B->dst == 'a' ? 'a' : 'b',
				  B->skt == 'g' ? 1 : 0, A->n,
				  A->sh < 0 ? 0xff : A->sh, A->sl,
				  (A->mss >> 8) & 0xff, A->mss & 0xff) ? 2 : 0;
		usleep(260000);
		if (att == 0) {
			usleep(320000);
			cmdrc |= f586_cmd(&F585_C, 'r', 0xff, 0, 0, 0, 0, 0, 0) ? 16 : 0;
		}
		cmdrc |= f586_cmd(&F585_C, 'r', idx | (att == 0 ? 0x80 : 0),
				  B->skt == 'g' ? 0x10 : 0, 0, 0, 0, 0, 0) ? 8 : 0;
		f585_tap_drain(&F585_TA);
		f585_tap_drain(&F585_TB);
		f575_nfl_drain(&pl);
		ch = (int)f555_count(NFPROTO_IPV6, "f85p", chain);
		{
			int lgp = -1, lgq = -1, lgc = 0, k;

			for (k = 0; k < pl.n && k < F575_NPL; k++) {
				if (strncmp(pl.m[k].prefix, "86:", 3))
					continue;
				if (lgc == 0)
					lgp = pl.m[k].plen;
				else if (lgc == 1)
					lgq = pl.m[k].plen;
				lgc++;
			}
			if (att == 0) {
				ch0 = ch;
				plen0 = lgp;
				plen0b = lgq;
				lgn0 = lgc;
			} else {
				agr = (ch == ch0 && lgp == plen0 &&
				       lgq == plen0b && lgc == lgn0) ? 1 : 0;
			}
		}
	}
	/* 4. what the reported attempt saw */
	{
		int i2;

		for (i2 = 0; i2 < pl.n && i2 < F575_NPL; i2++) {
			if (!strncmp(pl.m[i2].prefix, "86:", 3)) {
				struct f575_msg *M = &pl.m[i2];
				int st = 1680;

				if (lgn == 0) {
					nl = 1;
					lgplen = M->plen;
					lgst = st;
					f586_sl(lg6, sizeof(lg6), M->p, st, 4, 6);
					f586_sl(lgudp, sizeof(lgudp), M->p, st, 40, 48);
					f586_sl(lgp0, sizeof(lgp0), M->p, st, 48, 56);
					f586_sl(lgp1, sizeof(lgp1), M->p, st, 560, 568);
					f586_sl(lgp2, sizeof(lgp2), M->p, st, 1072, 1080);
					f586_sl(lgp3, sizeof(lgp3), M->p, st, 1584, 1592);
					lgn = 1;
				} else if (lgn == 1) {
					lg2 = M->plen;
					lgn = 2;
				} else {
					lgn++;
				}
			}
		}
	}
	printf("F586 ARM|i=%02d|name=%s|src=%c|dst=%c|xg=%c|n=%d|sh=%d|"
	       "sl=%d|mss=%d|store=%d|off=%u|len=%u|hex=%s|rc=%d|cmdrc=%d|"
	       "ch=%d|nl=%d|lgn=%d|lgplen=%d|lg2=%d|lgst=%d|lg6=%s|lgudp=%s|"
	       "lgp0=%s|lgp1=%s|lgp2=%s|lgp3=%s|tap=%d|att=2|agr=%d|ch0=%d|"
	       "plen0=%d|plen0b=%d|lgn0=%d|an=%d|anall=%d|bn=%d|"
	       "bnall=%d\n",
	       idx, B->name, B->src, B->dst, B->xg, A->n, A->sh, A->sl,
	       A->mss, B->store, B->off, B->len, hxi, rc, cmdrc, ch, nl, lgn,
	       lgplen, lg2, lgst, lg6, lgudp, lgp0, lgp1, lgp2, lgp3,
	       A->tap, agr, ch0, plen0, plen0b, lgn0,
	       F585_TA.n, F585_TA.nall, F585_TB.n, F585_TB.nall);
	fflush(stdout);
	f585_tap_print(&F585_TA, idx, "y1");
	f585_tap_print(&F585_TB, idx, "y2");
	fflush(stdout);
}

/* ---------- mode geom --------------------------------------------------- */

static int f586_geom(int limit)
{
	static const char *old[] = { "x0", "x1", "y1", "y2", "y3", "y4" };
	struct f578_gf g;
	unsigned char msg[16];
	int i, rc, r1, r2;

	f585_tap_zero(&F585_TA);
	f585_tap_zero(&F585_TB);
	for (i = 0; i < F586_ND; i++) {
		int k;

		for (k = 0; k < F586_MSS; k++)
			F586_PAY[i][k] = (unsigned char)(0x80 + (k & 0x7f));
		F586_PAY[i][0] = (unsigned char)i;
	}
	for (i = 0; i < F586_BIGP; i++)
		F586_BIG[i] = (unsigned char)(0x40 + (i & 0x3f));
	F586_BIG[0] = 0x77;
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
		printf("F586 FAIL|pipe\n");
		return -1;
	}
	F585_S.pid = fork();
	if (F585_S.pid < 0) {
		printf("F586 FAIL|fork\n");
		return -1;
	}
	if (F585_S.pid == 0)
		f586_child_s();
	F585_C.pid = fork();
	if (F585_C.pid < 0) {
		printf("F586 FAIL|fork2\n");
		return -1;
	}
	if (F585_C.pid == 0)
		f586_child_d();
	close(F585_S.up[1]);
	close(F585_S.dn[0]);
	close(F585_C.up[1]);
	close(F585_C.dn[0]);
	if (f585_wait_byte(F585_S.up[0], 5000) != 'U') {
		printf("F586 FAIL|senderns\n");
		return -1;
	}
	if (f585_wait_byte(F585_C.up[0], 5000) != 'U') {
		printf("F586 FAIL|recvns\n");
		return -1;
	}
	rc = f585_veth_ns("x0", "x1", (int)F585_S.pid);
	rc |= f585_veth_ns("y1", "y3", (int)F585_C.pid);
	rc |= f585_veth_ns("y2", "y4", (int)F585_C.pid);
	if (rc) {
		printf("F586 FAIL|veth|rc=%d\n", rc);
		return -1;
	}
	set_up("x0");
	set_up("y1");
	set_up("y2");
	printf("F586 GROSW|x0=%d\n", f578_feat_set("x0", F585_GRO_BIT, 1));
	(void)f585_v6dev("x0", 1);
	(void)f585_v6dev("y1", 1);
	(void)f585_v6dev("y2", 1);
	rc = f585_addr6_nodad("x0", A85_R6, 64);
	rc |= f585_addr6_nodad("y1", A85_RA, 64);
	rc |= f585_addr6_nodad("y2", A85_RB, 64);
	f585_mtu("x0", "65000");
	f585_mtu("y1", "65000");
	f585_mtu("y2", "65000");
	f585_groto("x0", "200000000");
	mac_get("x0", F585_X0M);
	msg[0] = 'M';
	memcpy(msg + 1, F585_X0M, 6);
	if (write(F585_S.dn[1], msg, 7) != 7) {
		printf("F586 FAIL|mactx\n");
		return -1;
	}
	{
		unsigned char c = 'R';

		if (write(F585_C.dn[1], &c, 1) != 1) {
			printf("F586 FAIL|dsync\n");
			return -1;
		}
	}
	if (f585_wait_byte(F585_S.up[0], 8000) != 'R') {
		printf("F586 FAIL|senderready\n");
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
			memcpy(F585_Y3M, b + 1, 6);
			memcpy(F585_Y4M, b + 7, 6);
		} else {
			printf("F586 FAIL|dmac|got=%d\n", got);
			return -1;
		}
	}
	rc |= f569_neigh6_add("y1", A85_DA, F585_Y3M);
	rc |= f569_neigh6_add("y2", A85_DB, F585_Y4M);
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
	printf("F586 FEAT|r1=%d|r2=%d\n", r1, r2);
	f578_feat_get("x0", &g);
	printf("F586 FEAT|dev=x0|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y1", &g);
	printf("F586 FEAT|dev=y1|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y2", &g);
	printf("F586 FEAT|dev=y2|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	(void)f579_tbl(NFPROTO_IPV6, "f85p");
	{
		int k = 0;

		k |= f580_chn(NFPROTO_IPV6, "f85p", "out", NULL, 3, 0);
		k |= f580_chn(NFPROTO_IPV6, "f85p", "fwd", NULL, 2, 0);
		printf("F586 CHAINS|rc=%d\n", k);
	}
	F573_NFL = nfl_open(F585_GROUP);
	F585_NFL = F573_NFL;
	f586_taps(1);
	printf("F586 ENV|x0=%d|y1=%d|y2=%d|nfl=%d|addr=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|P=%d\n",
	       f555_ifindex("x0"), f555_ifindex("y1"), f555_ifindex("y2"),
	       F573_NFL, rc, F585_X0M[0], F585_X0M[1], F585_X0M[2],
	       F585_X0M[3], F585_X0M[4], F585_X0M[5], F586_MSS);
	for (i = 0; i < NAF586; i++) {
		if (limit > 0 && i >= limit) {
			printf("F586 SKIP|from=%d|limit=%d\n", i, limit);
			break;
		}
		f586_arm(&AF586[i], i);
	}
	(void)f586_cmd(&F585_S, 'q', 0, 0, 0, 0, 0, 0, 0);
	(void)f586_cmd(&F585_C, 'q', 0, 0, 0, 0, 0, 0, 0);
	printf("F586 END|mode=geom|arms=%d\n", i);
	fflush(stdout);
	return 0;
}

/* ---------- entry ------------------------------------------------------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "geom";
	int limit = argc > 2 ? atoi(argv[2]) : 0;
	char mbuf[32];

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
	printf("F586 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "geom"))
		return f586_geom(limit);
	return f585_entry(argc, argv);
}
