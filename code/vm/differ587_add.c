/* differ587_add.c -- turn 587 (F65): THE PACKET THAT NOTHING FOLLOWS.
 *
 * Two debts from F64 §7:
 *   (a) the flow-starter: in F64's g_mid_a (512,512,200,512) the fourth
 *       datagram fell into neither the rule's message nor the tap.  The
 *       aggregate of three was completed by the MISMATCH (a short datagram
 *       ends the flow, udp_gro_receive_segment()), and the fourth datagram
 *       became the head of a new flow that nothing followed.  F64's reader
 *       gave up 42 ms after it started; this receiver reads for 700 ms and
 *       stamps every datagram it gets, so the answer is a time, not a guess.
 *   (b) BIG TCP: udp_set_len() writes a ZERO UDP length at or above
 *       GRO_LEGACY_MAX_SIZE (include/linux/udp.h:44) and udp_get_len() reads a
 *       zero length back as skb->len - dataoff when the skb is GSO.  Is that
 *       branch reachable for UDP on this kernel?
 *
 * Topology is F64's: three netns, the parent is the router.
 *   parent: x0 (ingress from S), y1 fd03::91, y2 fd04::91; ip6 table f85p,
 *           chain `fwd`, one rule per arm: [meta l4proto 17] counter [store]
 *           log(86:NN) accept.
 *   S: x1 fd02::11/64, one socket (CHECKSUM_PARTIAL), n datagrams of 62+pl
 *      bytes, one of them (`sh`) `sl` long.
 *   D: y3 fd03::92, y4 fd04::92, sockets on 5000 (plain) and 5001 (UDP_GRO),
 *      a witness chain in its own netns, taps on y3/y4.
 *
 * Modes: `flow` (9 arms: the shape of one send, and the leftover) and
 * `cap` (8 arms: which cap decides -- 64 datagrams, or 65536 bytes).
 */

#define F587_ND		66
#define F587_MAXPL	1280
#define F587_DPORT	5000
#define F587_DPORT_G	5001

static unsigned char F587_PAY[F587_ND][F587_MAXPL];

/* ---------- time ------------------------------------------------------- */

static long long f587_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + (long long)ts.tv_nsec / 1000000;
}

/* ---------- one frame, any payload length ------------------------------ */

static int f587_mkframe(unsigned char *out, const unsigned char *dmac,
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
	memcpy(out + 62, F587_PAY[seq], (size_t)paylen);
	c = f585_correct(A85_S6, daddr, F585_SPORT, dport, udplen,
			 out + 62, paylen);
	out[60] = (unsigned char)(c >> 8);
	out[61] = (unsigned char)(c & 0xff);
	return 62 + paylen;
}

/* ---------- S: the sender ---------------------------------------------- */

/* command: c0 's' socket / 'p' frame, c1 'a'|'b', c2 dport selector,
 * c3 n, c4 sh (0xff none), c5 sl, c6..c7 default payload length.
 * payload(k) = (k == sh) ? sl : default.  No GSO: every datagram is a
 * CHECKSUM_PARTIAL skb of its own, which is what GRO aggregates. */
static void f587_child_s(void)
{
	unsigned char msg[8], c[8];
	static unsigned char fr[62 + F587_MAXPL + 8];
	int s6 = -1, i, rc, k;

	close(F585_S.up[0]);
	close(F585_S.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F587 CHILDS|unshare=%d\n", errno);
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
	printf("F587 CHILDS|rc=%d|macrc=%d|x1=%d|s6=%d|errno=%d|"
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
		int n, sh, sl, defpl, psel, sent = 0, last = -9;

		if (f586_read8(F585_S.dn[0], c) != 8)
			_exit(0);
		if (c[0] == 'q')
			_exit(0);
		psel = c[2] & 3;
		n = c[3];
		sh = c[4] == 0xff ? -1 : c[4];
		sl = c[5];
		defpl = (c[6] << 8) | c[7];
		memset(&d6, 0, sizeof(d6));
		d6.sin6_family = AF_INET6;
		memcpy(&d6.sin6_addr, c[1] == 'a' ? A85_DA : A85_DB, 16);
		d6.sin6_port = htons(psel == 1 ? F587_DPORT_G : F587_DPORT);
		for (k = 0; k < n; k++) {
			int pl = (k == sh) ? sl : defpl;

			if (c[0] == 's') {
				rc = (int)sendto(s6, F587_PAY[k], (size_t)pl, 0,
						 (struct sockaddr *)&d6,
						 sizeof(d6));
			} else {
				int fl = f587_mkframe(fr, F585_X0M, F585_X1M,
						      c[1] == 'a' ? A85_DA :
						      A85_DB,
						      psel == 1 ? F587_DPORT_G :
						      F587_DPORT, k, pl);

				rc = f585_send_frame(fr, fl, "x1");
			}
			last = rc;
			if (rc == pl)
				sent++;
		}
		printf("F587 CHILDS|cmd=%c%c%d|n=%d|sh=%d|sl=%d|defpl=%d|"
		       "sent=%d|rc=%d|errno=%d\n",
		       c[0], c[1], psel, n, sh, sl, defpl, sent, last,
		       last < 0 ? errno : 0);
		c[0] = 'D';
		if (write(F585_S.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* ---------- D: the receiver, with arrival times ------------------------ */

/* 'r' is: c[1] idx, c[2] psel << 4, c[3] attempt, c[4..5] read window in ms.
 * Every datagram is stamped with the time since the command arrived, so the
 * answer to "when did the packet that nothing follows reach the stack" is a
 * number with ~2 ms resolution -- the counter read costs ~100 ms and cannot
 * time a 200 ms timer. */
static void f587_child_d(void)
{
	static unsigned char buf[4096];
	static unsigned char cb[256];
	unsigned char msg[16], c[8];
	static struct f585_tap t3, t4;
	struct f580_sn prev, cur;
	static int dl[2][F587_ND];
	static int db[2][F587_ND];
	static int dg[2][F587_ND];
	static int ta[2][F587_ND];
	unsigned long long cw[4];
	static unsigned long long cwp[4];
	int i, rc, s, sg, wrc = 0;

	close(F585_C.up[0]);
	close(F585_C.dn[1]);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F587 CHILDD|unshare=%d\n", errno);
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
	printf("F587 GROSW|y3=%d|y4=%d\n",
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
		s = f564_udp_bind(AF_INET6, 0, any, F587_DPORT);
		if (s >= 0)
			setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one,
				   sizeof(one));
		sg = f564_udp_bind(AF_INET6, 0, any, F587_DPORT_G);
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
	printf("F587 CHILDD|rc=%d|s=%d|sg=%d|y3=%d|y4=%d|t3=%d|t4=%d|wrc=%d|"
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
		int idx, att, win, pass, nd[2] = { 0, 0 }, psel, ncnt;
		int sock[2];
		long long t0;

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
		att = c[3];
		win = (c[4] << 8) | c[5];
		sock[0] = s;
		sock[1] = sg;
		memset(dl, 0, sizeof(dl));
		memset(db, 0, sizeof(db));
		memset(dg, 0, sizeof(dg));
		memset(ta, 0, sizeof(ta));
		t0 = f587_ms();
		for (pass = 0; pass < 4000; pass++) {
			int got = 0, w;
			long long now = f587_ms() - t0;

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
					if (nd[w] < F587_ND) {
						struct cmsghdr *cm;
						int k = nd[w];

						dl[w][k] = r;
						db[w][k] = r > 0 ? buf[0] : -1;
						dg[w][k] = -1;
						ta[w][k] = (int)(f587_ms() - t0);
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
				if (now >= win)
					break;
				usleep(2000);
			}
		}
		usleep(20000);
		f585_tap_drain(&t3);
		f585_tap_drain(&t4);
		f580_snmp(&cur);
		ncnt = f585_counts(NFPROTO_IPV6, "f85d", "w", cw, 3);
		printf("F587 RCV|i=%02d|att=%d|n=%d|n2=%d|ncnt=%d|"
		       "L=%d,%d,%d,%d,%d,%d,%d,%d|B=%d,%d,%d,%d,%d,%d,%d,%d|"
		       "T=%d,%d,%d,%d,%d,%d,%d,%d|"
		       "g0=%d|nn=%d|nn2=%d|"
		       "wany=%llu|w520=%llu|"
		       "rcv=%lld|deliv=%lld|udp=%lld|udperr=%lld|"
		       "hdr=%lld|disc=%lld|nop=%lld|t3=%d|t4=%d\n",
		       idx, att, nd[0], nd[1], ncnt,
		       dl[0][0], dl[0][1], dl[0][2], dl[0][3],
		       dl[0][4], dl[0][5],
		       nd[0] > 1 ? dl[0][nd[0] - 2] : -1,
		       nd[0] > 0 ? dl[0][nd[0] - 1] : -1,
		       db[0][0], db[0][1], db[0][2], db[0][3],
		       db[0][4], db[0][5],
		       nd[0] > 1 ? db[0][nd[0] - 2] : -1,
		       nd[0] > 0 ? db[0][nd[0] - 1] : -1,
		       ta[0][0], ta[0][1], ta[0][2], ta[0][3],
		       ta[0][4], ta[0][5],
		       nd[0] > 1 ? ta[0][nd[0] - 2] : -1,
		       nd[0] > 0 ? ta[0][nd[0] - 1] : -1,
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
		f585_tap_print(&t3, idx, att ? "y3b" : "y3a");
		f585_tap_print(&t4, idx, att ? "y4b" : "y4a");
		fflush(stdout);
		c[0] = 'D';
		if (write(F585_C.up[1], c, 1) != 1)
			_exit(5);
	}
}

/* ---------- the arms ---------------------------------------------------- */

struct f587_arm {
	const char *name;
	char src;	/* 's' socket (CHECKSUM_PARTIAL), 'p' hand-built frame */
	char dst;	/* 'a' y1 fd03::92, 'b' y2 fd04::92 */
	char xg;	/* GRO at x0: 'n' none, 'u' udp_fwd (linear), 'f' fraglist */
	int n;		/* datagrams */
	int pl;		/* default payload length */
	int sh;		/* index of the short one, -1 none */
	int sl;		/* its payload length */
	int store;
	unsigned int off, len;
	const char *hex;
	int exp;	/* packets the rule is expected to count */
};

static const struct f587_arm AF587_FLOW[] = {
	/* the datagram that nothing follows, and the same send with a mate */
	{ "l_one_a",	's', 'a', 'f', 1, 512, -1, 0, 0, 0, 0, NULL, 1 },
	{ "l_one_b",	's', 'b', 'f', 1, 512, -1, 0, 0, 0, 0, NULL, 1 },
	{ "l_two_a",	's', 'a', 'f', 2, 512, -1, 0, 0, 0, 0, NULL, 1 },
	{ "l_two_u",	's', 'a', 'u', 2, 512, -1, 0, 0, 0, 0, NULL, 1 },
	{ "l_mid_a",	's', 'a', 'f', 4, 512, 2, 200, 0, 0, 0, NULL, 2 },
	{ "l_mid_b",	's', 'b', 'f', 4, 512, 2, 200, 0, 0, 0, NULL, 2 },
	{ "l_mid_len_a", 's', 'a', 'f', 4, 512, 2, 200, 1, 4, 2, "0020", 2 },
	{ "l_mid_len_b", 's', 'b', 'f', 4, 512, 2, 200, 1, 4, 2, "0020", 2 },
	{ "l_mid_len_u", 's', 'b', 'u', 4, 512, 2, 200, 1, 4, 2, "0020", 2 },
};

static const struct f587_arm AF587_CAP[] = {
	/* the byte cap against the count cap: 64 datagrams of 512, 961, 962,
	 * 1015, 1016 and 1200 bytes */
	{ "k512x64_a",	's', 'a', 'f', 64, 512, -1, 0, 0, 0, 0, NULL, 1 },
	{ "k961x64_a",	's', 'a', 'f', 64, 961, -1, 0, 0, 0, 0, NULL, 1 },
	{ "k962x64_a",	's', 'a', 'f', 64, 962, -1, 0, 0, 0, 0, NULL, 1 },
	{ "k1015x64_a", 's', 'a', 'f', 64, 1015, -1, 0, 0, 0, 0, NULL, 1 },
	{ "k1016x64_a", 's', 'a', 'f', 64, 1016, -1, 0, 0, 0, 0, NULL, 1 },
	{ "k1017x64_a", 's', 'a', 'f', 64, 1017, -1, 0, 0, 0, 0, NULL, 0 },
	{ "k1018x64_a", 's', 'a', 'f', 64, 1018, -1, 0, 0, 0, 0, NULL, 0 },
	{ "k1019x64_a", 's', 'a', 'f', 64, 1019, -1, 0, 0, 0, 0, NULL, 0 },
	{ "k1020x64_a", 's', 'a', 'f', 64, 1020, -1, 0, 0, 0, 0, NULL, 0 },
	{ "k1021x64_a", 's', 'a', 'f', 64, 1021, -1, 0, 0, 0, 0, NULL, 0 },
	{ "k1022x64_a", 's', 'a', 'f', 64, 1022, -1, 0, 0, 0, 0, NULL, 0 },
	{ "k1023x64_a", 's', 'a', 'f', 64, 1023, -1, 0, 0, 0, 0, NULL, 2 },
	{ "k1024x64_a", 's', 'a', 'f', 64, 1024, -1, 0, 0, 0, 0, NULL, 2 },
	{ "k1200x64_a", 's', 'a', 'f', 64, 1200, -1, 0, 0, 0, 0, NULL, 2 },
	{ "k1200x64_b", 's', 'b', 'f', 64, 1200, -1, 0, 0, 0, 0, NULL, 2 },
	{ "k961x65_a",	's', 'a', 'f', 65, 961, -1, 0, 0, 0, 0, NULL, 2 },
};

static void f587_shutdown(void);

/* a slice of the logged bytes, clamped to what was actually stored */
static void f587_sl(char *out, size_t osz, const unsigned char *p, int stored,
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

/* the messages this attempt left in the drain buffer: count, the first two
 * lengths, and the header slices of each */
static int f587_msgs(const struct f575_pl *pl, int *l1, int *l2,
		     char *a6, char *audp, char *ap0,
		     char *b6, char *budp, char *bp0)
{
	int n = 0, i;

	*l1 = -1;
	*l2 = -1;
	for (i = 0; i < pl->n && i < F575_NPL; i++) {
		const struct f575_msg *M = &pl->m[i];
		int st = 1680;

		if (strncmp(M->prefix, "86:", 3))
			continue;
		if (n == 0) {
			*l1 = M->plen;
			f587_sl(a6, 16, M->p, st, 4, 6);
			f587_sl(audp, 40, M->p, st, 40, 48);
			f587_sl(ap0, 40, M->p, st, 48, 56);
		} else if (n == 1) {
			*l2 = M->plen;
			f587_sl(b6, 16, M->p, st, 4, 6);
			f587_sl(budp, 40, M->p, st, 40, 48);
			f587_sl(bp0, 40, M->p, st, 48, 56);
		}
		n++;
	}
	return n;
}

#define F587_WIN	700	/* the reader's window, ms -- F64 gave up at 42 */

static void f587_arm(const struct f587_arm *A, int idx)
{
	struct f575_pl pl;
	struct f585_arm B;
	unsigned char imm[64];
	char hxi[128] = "-";
	char m1_6[16] = "-", m1_udp[40] = "-", m1_p0[40] = "-";
	char m2_6[16] = "-", m2_udp[40] = "-", m2_p0[40] = "-";
	int rc = -99, ilen = -1, cmdrc = 0, att, acks = 0;
	int ch0 = -1, ch1 = -1, lgn0 = -1, l10 = -1, l20 = -1, agr = -1;
	int lgn = 0, l1 = -1, l2 = -1;
	int exp = A->exp;

	memset(&B, 0, sizeof(B));
	B.name = A->name;
	B.src = 'F';
	B.dst = A->dst;
	B.xg = A->xg;
	B.skt = 'p';
	B.store = A->store;
	B.off = A->off;
	B.len = A->len;
	B.hex = A->hex;
	if (A->store) {
		ilen = f586_imm(&B, imm);
		if (ilen > 0)
			f559_hexs(hxi, sizeof(hxi), imm, ilen);
	}
	/* 1. the shape of x0's GRO -- a device bit the rule cannot see */
	f578_feat_set("x0", F585_GRO_BIT, A->xg == 'n' ? 0 : 1);
	f578_feat_set("x0", F585_GROFL_BIT, A->xg == 'f');
	f578_feat_set("x0", F585_GROFWD_BIT, A->xg == 'u');
	/* 2. clean slate, receiver GRO off (its taps are open anyway) */
	(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
	(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
	f575_nfl_drain(&pl);
	cmdrc |= f586_cmd(&F585_C, 'p', 0, 0, 0, 0, 0, 0, 0) ? 1 : 0;
	cmdrc |= f586_cmd(&F585_C, 'b', 0, 0, 0, 0, 0, 0, 0) ? 2 : 0;
	f586_taps(1);
	for (att = 0; att < 2; att++) {
		(void)f557_flush(NFPROTO_IPV6, "f85p", "out", &acks);
		(void)f557_flush(NFPROTO_IPV6, "f85p", "fwd", &acks);
		f575_nfl_drain(&pl);
		rc = ilen < 0 ? f585_rule(&B, idx, NULL, 0) :
				f585_rule(&B, idx, imm, ilen);
		cmdrc |= f586_cmd(&F585_S, A->src, A->dst == 'a' ? 'a' : 'b',
				  0, A->n, A->sh < 0 ? 0xff : A->sh, A->sl,
				  (A->pl >> 8) & 0xff, A->pl & 0xff) ? 4 : 0;
		/* the receiver reads for F587_WIN ms and stamps every datagram:
		 * this is where "when" is measured, not the 100 ms counter */
		cmdrc |= f586_cmd(&F585_C, 'r', idx, 0, att,
				  (F587_WIN >> 8) & 0xff, F587_WIN & 0xff,
				  0, 0) ? 8 : 0;
		f585_tap_drain(&F585_TA);
		f585_tap_drain(&F585_TB);
		f575_nfl_drain(&pl);
		ch1 = (int)f555_count(NFPROTO_IPV6, "f85p", "fwd");
		lgn = f587_msgs(&pl, &l1, &l2, m1_6, m1_udp, m1_p0,
				m2_6, m2_udp, m2_p0);
		if (att == 0) {
			ch0 = ch1;
			lgn0 = lgn;
			l10 = l1;
			l20 = l2;
		} else {
			agr = (ch1 == ch0 && lgn == lgn0 && l1 == l10 &&
			       l2 == l20) ? 1 : 0;
		}
	}
	printf("F587 ARM|i=%02d|name=%s|src=%c|dst=%c|xg=%c|n=%d|pl=%d|sh=%d|"
	       "sl=%d|store=%d|off=%u|len=%u|hex=%s|rc=%d|cmdrc=%d|exp=%d|"
	       "ch=%d|ch0=%d|agr=%d|lgn=%d|lgplen=%d|lg2=%d|lg6=%s|"
	       "lgudp=%s|lgp0=%s|lg2_6=%s|lg2_udp=%s|lg2_p0=%s|win=%d|"
	       "an=%d|anall=%d|bn=%d|bnall=%d\n",
	       idx, A->name, A->src, A->dst, A->xg, A->n, A->pl, A->sh,
	       A->sl, A->store, A->off, A->len, hxi, rc, cmdrc, exp,
	       ch1, ch0, agr, lgn, l1, l2,
	       m1_6, m1_udp, m1_p0, m2_6, m2_udp, m2_p0, F587_WIN,
	       F585_TA.n, F585_TA.nall, F585_TB.n, F585_TB.nall);
	fflush(stdout);
	f585_tap_print(&F585_TA, idx, "y1");
	f585_tap_print(&F585_TB, idx, "y2");
	fflush(stdout);
}

/* ---------- the common setup ------------------------------------------- */

static int f587_setup(void)
{
	static const char *old[] = { "x0", "x1", "y1", "y2", "y3", "y4" };
	struct f578_gf g;
	unsigned char msg[16];
	int i, rc, r1, r2;

	f585_tap_zero(&F585_TA);
	f585_tap_zero(&F585_TB);
	/* F64's parent taps never opened: the globals start at fd 0, not -1, and
	 * f586_taps() only opens a tap whose fd is negative.  Every an/anall in
	 * F64 was zero for that reason (found by verify587). */
	F585_TA.fd = -1;
	F585_TB.fd = -1;
	for (i = 0; i < F587_ND; i++) {
		int k;

		for (k = 0; k < F587_MAXPL; k++)
			F587_PAY[i][k] = (unsigned char)(0x80 + (k & 0x7f));
		F587_PAY[i][0] = (unsigned char)i;
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
		printf("F587 FAIL|pipe\n");
		return -1;
	}
	F585_S.pid = fork();
	if (F585_S.pid < 0) {
		printf("F587 FAIL|fork\n");
		return -1;
	}
	if (F585_S.pid == 0)
		f587_child_s();
	F585_C.pid = fork();
	if (F585_C.pid < 0) {
		printf("F587 FAIL|fork2\n");
		return -1;
	}
	if (F585_C.pid == 0)
		f587_child_d();
	close(F585_S.up[1]);
	close(F585_S.dn[0]);
	close(F585_C.up[1]);
	close(F585_C.dn[0]);
	if (f585_wait_byte(F585_S.up[0], 5000) != 'U') {
		printf("F587 FAIL|senderns\n");
		return -1;
	}
	if (f585_wait_byte(F585_C.up[0], 5000) != 'U') {
		printf("F587 FAIL|recvns\n");
		return -1;
	}
	rc = f585_veth_ns("x0", "x1", (int)F585_S.pid);
	rc |= f585_veth_ns("y1", "y3", (int)F585_C.pid);
	rc |= f585_veth_ns("y2", "y4", (int)F585_C.pid);
	if (rc) {
		printf("F587 FAIL|veth|rc=%d\n", rc);
		return -1;
	}
	set_up("x0");
	set_up("y1");
	set_up("y2");
	printf("F587 GROSW|x0=%d\n", f578_feat_set("x0", F585_GRO_BIT, 1));
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
		printf("F587 FAIL|mactx\n");
		return -1;
	}
	{
		unsigned char c = 'R';

		if (write(F585_C.dn[1], &c, 1) != 1) {
			printf("F587 FAIL|dsync\n");
			return -1;
		}
	}
	if (f585_wait_byte(F585_S.up[0], 8000) != 'R') {
		printf("F587 FAIL|senderready\n");
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
			printf("F587 FAIL|dmac|got=%d\n", got);
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
	printf("F587 FEAT|r1=%d|r2=%d\n", r1, r2);
	f578_feat_get("x0", &g);
	printf("F587 FEAT|dev=x0|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y1", &g);
	printf("F587 FEAT|dev=y1|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	f578_feat_get("y2", &g);
	printf("F587 FEAT|dev=y2|av0=%08x|ac0=%08x|av1=%08x|ac1=%08x\n",
	       g.b[0].avail, g.b[0].act, g.b[1].avail, g.b[1].act);
	(void)f579_tbl(NFPROTO_IPV6, "f85p");
	{
		int k = 0;

		k |= f580_chn(NFPROTO_IPV6, "f85p", "out", NULL, 3, 0);
		k |= f580_chn(NFPROTO_IPV6, "f85p", "fwd", NULL, 2, 0);
		printf("F587 CHAINS|rc=%d\n", k);
	}
	F573_NFL = nfl_open(F585_GROUP);
	F585_NFL = F573_NFL;
	f586_taps(1);
	printf("F587 ENV|x0=%d|y1=%d|y2=%d|nfl=%d|addr=%d|"
	       "m0=%02x%02x%02x%02x%02x%02x|ND=%d|WIN=%d\n",
	       f555_ifindex("x0"), f555_ifindex("y1"), f555_ifindex("y2"),
	       F573_NFL, rc, F585_X0M[0], F585_X0M[1], F585_X0M[2],
	       F585_X0M[3], F585_X0M[4], F585_X0M[5], F587_ND, F587_WIN);
	return 0;
}

static void f587_shutdown(void)
{
	(void)f586_cmd(&F585_S, 'q', 0, 0, 0, 0, 0, 0, 0);
	(void)f586_cmd(&F585_C, 'q', 0, 0, 0, 0, 0, 0, 0);
}

/* ---------- modes ------------------------------------------------------- */

static int f587_flow(int limit)
{
	int i;

	printf("F587 GROTO_PLAN|timeout=200000000|defer=1\n");
	if (f587_setup())
		return -1;
	for (i = 0; i < (int)(sizeof(AF587_FLOW) / sizeof(AF587_FLOW[0])); i++) {
		if (limit > 0 && i >= limit) {
			printf("F587 SKIP|from=%d|limit=%d\n", i, limit);
			break;
		}
		f587_arm(&AF587_FLOW[i], i);
	}
	f587_shutdown();
	printf("F587 END|mode=flow|arms=%d\n", i);
	fflush(stdout);
	return 0;
}

static int f587_cap(int limit)
{
	int i;

	printf("F587 GROTO_PLAN|timeout=200000000|defer=1\n");
	if (f587_setup())
		return -1;
	for (i = 0; i < (int)(sizeof(AF587_CAP) / sizeof(AF587_CAP[0])); i++) {
		if (limit > 0 && i >= limit) {
			printf("F587 SKIP|from=%d|limit=%d\n", i, limit);
			break;
		}
		f587_arm(&AF587_CAP[i], 100 + i);
	}
	f587_shutdown();
	printf("F587 END|mode=cap|arms=%d\n", i);
	fflush(stdout);
	return 0;
}

/* ---------- entry ------------------------------------------------------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "flow";
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
	printf("F587 BOOT|mode=%s|argc=%d|limit=%d\n", mode, argc, limit);
	if (!strcmp(mode, "flow"))
		return f587_flow(limit);
	if (!strcmp(mode, "cap"))
		return f587_cap(limit);
	return f586_entry(argc, argv);
}
