/* differ558_add.c -- turn 558.
 *
 * Three debts that F35 left as readings, and one config line to pay for:
 *
 *  A. `why`  -- F35's far-side capture returned n=-1 on every arm but one, and
 *     the one frame it caught was an ICMPv6 report from the bridge.  The first
 *     smoke with this instrument found the reason and two instrument facts
 *     worth keeping: (1) matching on the payload instead of taking the first
 *     frame is enough to see our frame at r0 (PACKET_HOST) and at r1
 *     (PACKET_OUTGOING); (2) a veth pair advertises NETIF_F_HW_VLAN_CTAG_TX/RX
 *     (drivers/net/veth.c VETH_FEATURES), so validate_xmit_vlan() never puts
 *     the tag back into the frame: on a veth the 802.1Q tag travels as skb
 *     METADATA and the frame is 60 bytes on both taps.  "The bytes of the tag
 *     on the wire" therefore cannot be measured with AF_PACKET here at all --
 *     but the tag's EFFECT can, at the far side, because vid 0 is delivered to
 *     IPv4 and vid != 0 is marked PACKET_OTHERHOST and dropped.
 *
 *  B. `bytes` -- the store F35 could describe only from the source.  Four arms
 *     on one tagged frame through the bridge, each read twice (TX tap on r1,
 *     RX tap on r0) and once at the far side (IpInReceives):
 *       (16,2) = 0x0806  writes the frame buffer at data-2 = the ethertype
 *       (14,2) = 0x0099  assigns skb->vlan_tci raw: bit 0x1000 (PRESENT) is
 *                        gone, so the frame stops being tagged at all
 *       (14,2) = 0x1064  the same store keeping the PRESENT bit: vid 100
 *       (12,4) = 0x8100 0x0000  full tag through __vlan_hwaccel_put_tag()
 *
 *  C. `vlan` -- the ip family never sees a tagged frame on any image this
 *     project has booted, and F35 recorded that as a config line:
 *     `# CONFIG_VLAN_8021Q is not set`.  T558 is T557 + that symbol, so the
 *     same tagged frame can now arrive through a real vlan device.  Four
 *     envelopes in one boot: plain (p4), tagged without a vlan device (novd,
 *     measured on T557 and on T558), tagged through v1 (vd), and a
 *     priority-tagged frame with vid 0 (v0), which needs no device at all.
 *
 * Instrument note: /sys/class/net is NOT netns-aware here -- the guest mounts
 * sysfs as init and the reproducer unshares CLONE_NEWNET afterwards, so every
 * /sys/class/net/<dev> read is ENOENT while /proc/net/dev is correct.
 */

/* ---------- frames ---------- */

/* f557_mk_vlan() with the TCI as a parameter: vid 100 and vid 0 are then the
 * SAME frame with one 12-bit field different, which is the whole point of the
 * `v0` envelope. */
static int f558_mk_vlan_tci(unsigned char *out, unsigned short tci)
{
	unsigned char tmp[256];
	int n = f556_frame(FK33_IP4, tmp);

	memset(out, 0, 256);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = 0x81; out[13] = 0x00;
	out[14] = (unsigned char)(tci >> 8);
	out[15] = (unsigned char)tci;
	out[16] = 0x08; out[17] = 0x00;
	memcpy(out + 18, tmp + 14, (size_t)(n - 14));
	return n + 4;
}

/* ---------- rtnetlink: a vlan device, and deletion ---------- */

static int f558_link_add_vlan(const char *name, const char *parent,
			      unsigned short vid)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[256];
	} req;
	struct nlattr *li, *data;
	uint32_t pidx = (uint32_t)f555_ifindex(parent);
	int fd, rc;

	if ((int)pidx < 0)
		return -10;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	attr_put(&req.nlh, IFLA_IFNAME, name, (int)strlen(name) + 1);
	attr_put(&req.nlh, IFLA_LINK, &pidx, 4);
	li = nest_start(&req.nlh, IFLA_LINKINFO);
	attr_put(&req.nlh, IFLA_INFO_KIND, "vlan", 5);
	data = nest_start(&req.nlh, IFLA_INFO_DATA);
	attr_put(&req.nlh, IFLA_VLAN_ID, &vid, 2);	/* u16, native order */
	nest_end(&req.nlh, data);
	nest_end(&req.nlh, li);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

static int f558_link_del(const char *name)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[64];
	} req;
	int fd, rc, idx = f555_ifindex(name);

	if (idx < 0)
		return -10;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_DELLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = idx;
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* ---------- capture: match on the payload, not on being first ---------- */

/* F35's f557_cap_first() opened a fresh socket per arm and took whatever
 * arrived first; on every arm but one that was ICMPv6 noise from the bridge.
 * This one opens once, drains once, and looks for the 0x77 payload the
 * instrument's own datagram carries -- printing how many frames it skipped,
 * so "no frame" and "someone else's frame" cannot be confused. */
static int f558_cap_match(int s, unsigned char *buf, int max, int ms,
			  const unsigned char *needle, int nlen,
			  int *skipped, int *pkttype)
{
	struct timeval now0, now1;
	struct timeval tv;
	fd_set rfds;
	int r, i;

	*skipped = 0;
	*pkttype = -1;
	if (s < 0)
		return -1;
	gettimeofday(&now0, NULL);
	tv.tv_sec = 0;
	tv.tv_usec = ms * 1000;
	for (;;) {
		struct sockaddr_ll from;
		socklen_t fl = sizeof(from);

		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		if (select(s + 1, &rfds, NULL, NULL, &tv) <= 0)
			return -1;
		memset(&from, 0, sizeof(from));
		r = (int)recvfrom(s, buf, (size_t)max, 0,
				  (struct sockaddr *)&from, &fl);
		if (r <= 0)
			return -1;
		for (i = 0; i + nlen <= r; i++) {
			if (!memcmp(buf + i, needle, (size_t)nlen)) {
				*pkttype = (int)from.sll_pkttype;
				return r;
			}
		}
		(*skipped)++;
		gettimeofday(&now1, NULL);
		{
			long used = (now1.tv_sec - now0.tv_sec) * 1000 +
				    (now1.tv_usec - now0.tv_usec) / 1000;

			if (used >= ms)
				return -1;
			tv.tv_sec = 0;
			tv.tv_usec = (ms - used) * 1000;
		}
	}
}

static void f558_hex(const unsigned char *b, int n)
{
	int i;

	for (i = 0; i < n; i++)
		printf("%02x", b[i]);
}

/* diff of two frames, "index:ctl>got" */
static int f558_chg(char *out, size_t osz, const unsigned char *ctl, int clen,
		    const unsigned char *got, int glen)
{
	int i, n = 0;

	out[0] = 0;
	if (clen <= 0 || glen <= 0)
		return 0;
	for (i = 0; i < glen && i < clen; i++) {
		size_t at;

		if (got[i] == ctl[i])
			continue;
		n++;
		at = strlen(out);
		if (at < osz - 24)
			snprintf(out + at, osz - at, "%s%d:%02x>%02x",
				 n > 1 ? "," : "", i, ctl[i], got[i]);
	}
	if (glen != clen) {
		size_t at = strlen(out);

		if (at < osz - 24)
			snprintf(out + at, osz - at, "%slen:%d>%d",
				 n ? "," : "", clen, glen);
		n++;
	}
	return n;
}

/* IpInReceives of the whole netns.  This is the far side's own decision about
 * our frame: a tagged frame with vid != 0 is PACKET_OTHERHOST by the time
 * ip_rcv() runs and is dropped there, a tag with vid 0 (or no tag at all) is
 * received.  Nothing else in this guest speaks IPv4, so the delta is ours. */
static unsigned long long f558_ipin(void)
{
	FILE *f = fopen("/proc/net/snmp", "r");
	char line[1024];
	unsigned long long fw, ttl, in;

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Ip: ", 4))
			continue;
		if (strstr(line, "Forwarding"))
			continue;
		if (sscanf(line, "Ip: %llu %llu %llu", &fw, &ttl, &in) == 3) {
			fclose(f);
			return in;
		}
	}
	fclose(f);
	return 0;
}

/* one capture view: a socket, the control frame it saw, and its length */
struct f558_view {
	const char *tag;		/* "tx" or "rx" */
	int fd;
	unsigned char ctl[2048];
	int clen;
};

static void f558_view_report(const char *env, const char *arm,
			     struct f558_view *v, const unsigned char *cap,
			     int n, int skip, int pt)
{
	char chg[512];
	int k = 0;

	printf("F558 VIEW|env=%s|arm=%s|view=%s|n=%d|skip=%d|pt=%d|",
	       env, arm, v->tag, n, skip, pt);
	if (n > 0 && v->clen > 0) {
		k = f558_chg(chg, sizeof(chg), v->ctl, v->clen, cap, n);
		printf("nchg=%d|chg=%s|", k, chg[0] ? chg : "-");
	} else {
		printf("nchg=-|chg=-|");
	}
	printf("hex=");
	if (n > 0)
		f558_hex(cap, n > 96 ? 96 : n);
	printf("\n");
}

/* ---------- one arm: install, send, capture twice, count three ---------- */

/* off < 0 => control arm (no store at all).  Each view may be inactive. */
static unsigned long long f558_run(const struct f557_env *e, const char *tag,
				   int off, int len, const unsigned char *imm,
				   int immlen, const unsigned char *fr, int flen,
				   struct f558_view *tx, struct f558_view *rx)
{
	static const unsigned char magic[8] = { 0x77, 0x77, 0x77, 0x77,
						0x77, 0x77, 0x77, 0x77 };
	unsigned char cap[2048];
	unsigned char pay[192];
	unsigned long long cnt, cnt0, ip0, ip1;
	int rc, acks = -1, snd = 0, nfl = 0, i;

	snprintf(PRE57, sizeof(PRE57), "f57.%s.%s", e->tag, tag);
	f557_flush(e->fam, e->table, e->chain, &acks);
	if (off < 0)
		rc = f557_install(e->fam, e->table, e->chain, e->iif, 0, 0, 0,
				  NULL, 0, 0, 5, PRE57, &acks);
	else
		rc = f557_install(e->fam, e->table, e->chain, e->iif, e->base,
				  (uint32_t)off, (uint32_t)len, imm, immlen, 1,
				  5, PRE57, &acks);
	if (tx && tx->fd >= 0)
		cap_drain(tx->fd);
	if (rx && rx->fd >= 0)
		cap_drain(rx->fd);
	usleep(20000);
	nfl_drain(NFL57);
	cnt0 = (rc == 0) ? f555_count(e->fam, e->table, e->chain) : 0;
	ip0 = f558_ipin();
	if (rc == 0 && !e->send_raw) {
		usleep(15000);
		/* drain HERE, immediately before the send: the whole payload of
		 * every arm is identical, so a frame left over from the previous
		 * arm would be indistinguishable from this one and would be
		 * reported as this arm's bytes.  (A second base chain at the same
		 * hook, left over from an earlier section, is the other way the
		 * same mistake shows up: it rewrites every later frame.) */
		if (tx && tx->fd >= 0)
			cap_drain(tx->fd);
		if (rx && rx->fd >= 0)
			cap_drain(rx->fd);
		snd = pkt_send_p(e->dev, fr, flen, f557_proto(e->kind));
		if (tx && tx->fd >= 0) {
			int n, skip = 0, pt = -1;

			memset(cap, 0, sizeof(cap));
			n = f558_cap_match(tx->fd, cap, (int)sizeof(cap), 800,
					   magic, 8, &skip, &pt);
			f558_view_report(e->tag, tag, tx, cap, n, skip, pt);
			if (off < 0 && n > 0) {
				memcpy(tx->ctl, cap, (size_t)n);
				tx->clen = n;
			}
		}
		if (rx && rx->fd >= 0) {
			int n, skip = 0, pt = -1;

			memset(cap, 0, sizeof(cap));
			n = f558_cap_match(rx->fd, cap, (int)sizeof(cap), 500,
					   magic, 8, &skip, &pt);
			f558_view_report(e->tag, tag, rx, cap, n, skip, pt);
			if (off < 0 && n > 0) {
				memcpy(rx->ctl, cap, (size_t)n);
				rx->clen = n;
			}
		}
	}
	usleep(20000);
	ip1 = f558_ipin();
	cnt = (rc == 0) ? f555_count(e->fam, e->table, e->chain) : 0;
	/* the second witness: the rule's own log, read back by prefix.  It tells
	 * "our frame" from "some other frame crossed this chain", which the bare
	 * counter cannot: an ICMPv6 report through the bridge increments the
	 * same counter as our IPv4 datagram. */
	if (rc == 0 && !e->send_raw)
		nfl = nfl_wait(NFL57, PRE57, pay, (int)sizeof(pay), 250);
	printf("F558 RUN|env=%s|arm=%s|off=%d|len=%d|rc=%d|acks=%d|snd=%d|"
	       "cnt0=%llu|cnt=%llu|live=%llu|ipin=%llu|nfl=%d|nflhex=", e->tag,
	       tag, off, len, rc, acks, snd, cnt0, cnt, cnt - cnt0, ip1 - ip0,
	       nfl);
	for (i = 0; i < nfl && i < 24; i++)
		printf("%02x", pay[i]);
	printf("\n");
	return cnt - cnt0;
}

static unsigned long long f558_gframe(const struct f557_env *e,
				      const unsigned char *fr, int flen)
{
	static const int offs[12] = { 0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24 };
	static const int lens[3] = { 1, 2, 4 };
	unsigned char imm[16];
	char tag[32];
	int i, j;
	unsigned long long live = 0;

	for (i = 0; i < 12; i++) {
		for (j = 0; j < 3; j++) {
			f557_imm(offs[i], lens[j], imm);
			snprintf(tag, sizeof(tag), "g%d_%d", offs[i], lens[j]);
			if (f558_run(e, tag, offs[i], lens[j], imm, lens[j], fr,
				     flen, NULL, NULL))
				live++;
		}
	}
	printf("F558 GRID|env=%s|live=%llu|of=36\n", e->tag, live);
	return live;
}

/* ---------- A: why did the far side show nothing ---------- */

static void f558_sec_why(void)
{
	unsigned char fr[512], vl[512];
	int c0 = cap_open("r0"), c1 = cap_open("r1");
	int fl, n, pt = -1, rc, sk = 0;

	/* the two tagged-frame builders must agree: f557_mk_vlan() is the one
	 * F35 measured, f558_mk_vlan_tci() is the parameterised one. */
	fl = f557_frame(F557_VLAN, fr);
	n = f558_mk_vlan_tci(vl, 100);
	printf("F558 WHY|frame_same=%d|len557=%d|len558=%d\n",
	       n == fl && !memcmp(fr, vl, (size_t)fl), fl, n);
	printf("F558 WHY|cap_r0=%d|cap_r1=%d|s0=%d|s1=%d|r0=%d|r1=%d|br0=%d\n",
	       c0, c1, f555_ifindex("s0"), f555_ifindex("s1"),
	       f555_ifindex("r0"), f555_ifindex("r1"), f555_ifindex("br0"));
	/* sysfs is not netns-aware here; this is the evidence, not noise */
	f557_sysline("/sys/class/net/br0/flags");
	f557_devline("s1");
	f557_devline("r1");
	f557_devline("r0");

	/* no nft rules at all: does the bridge forward our frame? */
	sh("/nft flush ruleset");
	fl = f557_frame(F557_PLAIN, fr);
	if (c0 >= 0)
		cap_drain(c0);
	if (c1 >= 0)
		cap_drain(c1);
	usleep(20000);
	rc = pkt_send_p("s0", fr, fl, 0x0800);
	{
		unsigned char cap[2048];

		n = f558_cap_match(c0, cap, (int)sizeof(cap), 800,
				   (const unsigned char *)"\x77\x77\x77\x77\x77\x77\x77\x77",
				   8, &sk, &pt);
		printf("F558 WHY|plain|arm=rx_r0|send_rc=%d|flen=%d|n=%d|skip=%d|pt=%d|hex=",
		       rc, fl, n, sk, pt);
		if (n > 0)
			f558_hex(cap, n > 96 ? 96 : n);
		printf("\n");
		sk = 0;
		pt = -1;
		n = f558_cap_match(c1, cap, (int)sizeof(cap), 400,
				   (const unsigned char *)"\x77\x77\x77\x77\x77\x77\x77\x77",
				   8, &sk, &pt);
		printf("F558 WHY|plain|arm=tx_r1|n=%d|skip=%d|pt=%d|hex=", n, sk, pt);
		if (n > 0)
			f558_hex(cap, n > 96 ? 96 : n);
		printf("\n");
	}
	/* the same frame TAGGED, still with no rule: both views */
	fl = f558_mk_vlan_tci(fr, 100);
	if (c0 >= 0)
		cap_drain(c0);
	if (c1 >= 0)
		cap_drain(c1);
	usleep(20000);
	rc = pkt_send_p("s0", fr, fl, 0x8100);
	{
		unsigned char cap[2048], pl[512];
		int plen = f557_frame(F557_PLAIN, pl);
		char chg[512];

		n = f558_cap_match(c1, cap, (int)sizeof(cap), 800,
				   (const unsigned char *)"\x77\x77\x77\x77\x77\x77\x77\x77",
				   8, &sk, &pt);
		f558_chg(chg, sizeof(chg), pl, plen, cap, n);
		printf("F558 WHY|tagged|arm=tx_r1|send_rc=%d|flen=%d|n=%d|skip=%d|pt=%d|vs_plain=%s|hex=",
		       rc, fl, n, sk, pt, chg[0] ? chg : "-");
		if (n > 0)
			f558_hex(cap, n > 96 ? 96 : n);
		printf("\n");
		sk = 0;
		pt = -1;
		n = f558_cap_match(c0, cap, (int)sizeof(cap), 500,
				   (const unsigned char *)"\x77\x77\x77\x77\x77\x77\x77\x77",
				   8, &sk, &pt);
		f558_chg(chg, sizeof(chg), pl, plen, cap, n);
		printf("F558 WHY|tagged|arm=rx_r0|n=%d|skip=%d|pt=%d|vs_plain=%s|hex=",
		       n, sk, pt, chg[0] ? chg : "-");
		if (n > 0)
			f558_hex(cap, n > 96 ? 96 : n);
		printf("\n");
	}
	f557_devline("s1");
	f557_devline("r1");
	f557_devline("r0");

	/* How many frames does ONE send put through a bridge chain?  The bare
	 * counter cannot tell our frame from someone else's, so the witness is
	 * the rule's own log: read every message it produced, not the first. */
	{
		struct f557_env eb;
		unsigned long long c0, c1;
		unsigned char pay[192];
		int acks = -1, n, k = 0;

		memset(&eb, 0, sizeof(eb));
		eb.tag = "wy"; eb.fam = NFPROTO_BRIDGE; eb.table = "p58w";
		eb.chain = "pre"; eb.hook = 0; eb.policy = 1;
		eb.base = NFT_PAYLOAD_LL_HEADER; eb.dev = "s0";
		eb.kind = F557_PLAIN;
		if (!f557_chain(&eb)) {
			fl = f557_frame(F557_PLAIN, fr);
			snprintf(PRE57, sizeof(PRE57), "f57.wy.one");
			f557_flush(eb.fam, eb.table, eb.chain, &acks);
			f557_install(eb.fam, eb.table, eb.chain, 0, 0, 0, 0, NULL,
				     0, 0, 5, PRE57, &acks);
			nfl_drain(NFL57);
			usleep(20000);
			c0 = f555_count(eb.fam, eb.table, eb.chain);
			pkt_send_p(eb.dev, fr, fl, 0x0800);
			while (k < 8) {
				n = nfl_wait(NFL57, PRE57, pay, (int)sizeof(pay), 150);
				if (n <= 0)
					break;
				printf("F558 WHY|one_send|msg=%d|n=%d|hex=", k, n);
				f558_hex(pay, n > 24 ? 24 : n);
				printf("\n");
				k++;
			}
			c1 = f555_count(eb.fam, eb.table, eb.chain);
			printf("F558 WHY|one_send|cnt_delta=%llu|msgs=%d\n", c1 - c0, k);
		}
	}
	sh("/nft flush ruleset");
}

/* ---------- B: what an accepted store actually does ---------- */

static void f558_sec_bytes(void)
{
	static const struct {
		const char *tag;
		int off, len;
		unsigned char v[4];
	} arms[] = {
		{ "s16_2", 16, 2, { 0x08, 0x06 } },	/* ethertype in the buffer */
		{ "s14_99", 14, 2, { 0x00, 0x99 } },	/* vlan_tci = 153 */
		{ "s14_0", 14, 2, { 0x00, 0x00 } },	/* vlan_tci = 0 -> vid 0 */
		{ "s14_1064", 14, 2, { 0x10, 0x64 } },	/* vlan_tci = 100 */
		{ "s12_4z", 12, 4, { 0x81, 0x00, 0x00, 0x00 } }, /* put_tag vid 0 */
	};
	struct f557_env e;
	struct f558_view tx, rx;
	unsigned char fr[512];
	unsigned char imm[16];
	int fl, k;

	memset(&tx, 0, sizeof(tx));
	memset(&rx, 0, sizeof(rx));
	tx.tag = "tx";
	rx.tag = "rx";
	tx.fd = cap_open("r1");		/* the frame the driver is given */
	rx.fd = cap_open("r0");		/* the frame the next hop's stack sees */
	memset(&e, 0, sizeof(e));
	e.tag = "by"; e.fam = NFPROTO_BRIDGE; e.table = "p58z";
	e.chain = "pre"; e.hook = 0; e.policy = 1;
	e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "s0"; e.kind = F557_VLAN;
	fl = f557_frame(e.kind, fr);
	if (f557_chain(&e))
		return;
	printf("F558 BY|tx_fd=%d|rx_fd=%d|flen=%d\n", tx.fd, rx.fd, fl);

	/* control: the tagged frame through the bridge, no store at all */
	f558_run(&e, "ctl", -1, 0, NULL, 0, fr, fl, &tx, &rx);
	/* the PLAIN frame through the same chain: no store at all (the far side
	 * receives it TWICE -- once forwarded to r0, once flooded up to the br0
	 * device -- so "ipin" needs this baseline), and then the very store the
	 * tagged arms test, which must be DEAD here: 16 + 2 > 14.  Same table,
	 * so each arm's own flush removes the previous rule; the views are
	 * copies so the tagged control is not overwritten. */
	{
		struct f558_view txp = tx, rxp = rx;
		unsigned char fp[512];
		int flp = f557_frame(F557_PLAIN, fp);

		txp.clen = 0;
		rxp.clen = 0;
		f558_run(&e, "ctl_plain", -1, 0, NULL, 0, fp, flp, &txp, &rxp);
		f558_run(&e, "s16_2_plain", 16, 2,
			 (const unsigned char *)"\x08\x06", 2, fp, flp,
			 &txp, &rxp);
	}
	for (k = 0; k < (int)(sizeof(arms) / sizeof(arms[0])); k++) {
		memset(imm, 0, sizeof(imm));
		memcpy(imm, arms[k].v, (size_t)arms[k].len);
		f558_run(&e, arms[k].tag, arms[k].off, arms[k].len, imm,
			 arms[k].len, fr, fl, &tx, &rx);
	}
	sh("/nft flush ruleset");
}

/* ---------- C: the ip family meets a tag ---------- */

static void f558_sec_vlan(const char *only)
{
	struct f557_env e;
	unsigned char fr[512], fr0[512];
	int fl = 0, fl0 = 0, rc, add_rc = -99;

	if (!only || !strcmp(only, "p4")) {
		memset(&e, 0, sizeof(e));
		e.tag = "p4"; e.fam = NFPROTO_IPV4; e.table = "p58a";
		e.chain = "pre"; e.hook = 0; e.policy = 1;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
		e.kind = F557_PLAIN;
		if (!f557_chain(&e)) {
			f557_ctl(&e, "ctl", 1);
			f557_grid(&e, G57_OFF, 12, G57_LEN, 3, 1);
		}
	}
	if (!only || !strcmp(only, "novd")) {
		fl = f558_mk_vlan_tci(fr, 100);
		memset(&e, 0, sizeof(e));
		e.tag = "novd"; e.fam = NFPROTO_IPV4; e.table = "p58b";
		e.chain = "pre"; e.hook = 0; e.policy = 1;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
		e.kind = F557_VLAN;
		if (!f557_chain(&e)) {
			f558_run(&e, "ctl", -1, 0, NULL, 0, fr, fl, NULL, NULL);
			f558_run(&e, "g12_2", 12, 2,
				 (const unsigned char *)"\x00\x64", 2, fr, fl,
				 NULL, NULL);
		}
	}
	/* the vlan device: on T557 this is -EOPNOTSUPP, which is itself the
	 * measurement of the config line F35 named. */
	if (!only || !strcmp(only, "vd") || !strcmp(only, "novd")) {
		add_rc = f558_link_add_vlan("v1", "i1", 100);
		if (add_rc == 0)
			set_up("v1");
		printf("F558 VLANDEV|add_rc=%d|idx=%d\n", add_rc,
		       f555_ifindex("v1"));
	}
	if (!only || !strcmp(only, "vd")) {
		if (add_rc != 0) {
			printf("F558 VLANDEV|vd_skipped|reason=no_vlan_device\n");
		} else {
			fl = f558_mk_vlan_tci(fr, 100);
			memset(&e, 0, sizeof(e));
			e.tag = "vd"; e.fam = NFPROTO_IPV4; e.table = "p58c";
			e.chain = "pre"; e.hook = 0; e.policy = 1;
			e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
			e.kind = F557_VLAN;
			if (!f557_chain(&e)) {
				f558_run(&e, "ctl", -1, 0, NULL, 0, fr, fl,
					 NULL, NULL);
				f558_gframe(&e, fr, fl);
			}
		}
	}
	if (!only || !strcmp(only, "vd")) {
		rc = f558_link_del("v1");
		printf("F558 VLANDEV|del_rc=%d|idx=%d\n", rc, f555_ifindex("v1"));
		fl = f558_mk_vlan_tci(fr, 100);
		memset(&e, 0, sizeof(e));
		e.tag = "novd2"; e.fam = NFPROTO_IPV4; e.table = "p58e";
		e.chain = "pre"; e.hook = 0; e.policy = 1;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
		e.kind = F557_VLAN;
		if (!f557_chain(&e))
			f558_run(&e, "ctl", -1, 0, NULL, 0, fr, fl, NULL, NULL);
	}
	/* vid 0: a priority tag needs no vlan device at all */
	if (!only || !strcmp(only, "v0")) {
		fl0 = f558_mk_vlan_tci(fr0, 0);
		memset(&e, 0, sizeof(e));
		e.tag = "v0"; e.fam = NFPROTO_IPV4; e.table = "p58d";
		e.chain = "pre"; e.hook = 0; e.policy = 1;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
		e.kind = F557_VLAN;
		if (!f557_chain(&e)) {
			f558_run(&e, "ctl", -1, 0, NULL, 0, fr0, fl0, NULL, NULL);
			f558_gframe(&e, fr0, fl0);
		}
	}
	sh("/nft flush ruleset");
}

/* ---------- D: the instrument's own pollution, measured on purpose -------- */

/* One send through a bridge chain with no match expression, run twice: with
 * IPv6 off on the devices (what every other section of this instrument runs
 * with) and with it back on.  The counter cannot tell our IPv4 datagram from
 * the kernel's own MLD/NS chatter, and the rule's log can: each message is
 * printed with its first bytes, so 0x45 is ours and 0x60 is not. */
static void f558_one_send(const char *tag)
{
	struct f557_env eb;
	unsigned long long c0, c1;
	unsigned char fr[512], pay[192];
	static const char *dv[] = { "r0", "s0", "s1", "r1", "br0", "i0", "i1" };
	char path[96];
	int acks = -1, n, k = 0, i, fl;

	memset(&eb, 0, sizeof(eb));
	eb.tag = "wy"; eb.fam = NFPROTO_BRIDGE; eb.table = "p58w";
	eb.chain = "pre"; eb.hook = 0; eb.policy = 1;
	eb.base = NFT_PAYLOAD_LL_HEADER; eb.dev = "s0";
	eb.kind = F557_PLAIN;
	if (f557_chain(&eb))
		return;
	fl = f557_frame(F557_PLAIN, fr);
	snprintf(PRE57, sizeof(PRE57), "f57.wy.%s", tag);
	f557_flush(eb.fam, eb.table, eb.chain, &acks);
	f557_install(eb.fam, eb.table, eb.chain, 0, 0, 0, 0, NULL, 0, 0, 5,
		     PRE57, &acks);
	nfl_drain(NFL57);
	usleep(30000);
	c0 = f555_count(eb.fam, eb.table, eb.chain);
	pkt_send_p(eb.dev, fr, fl, 0x0800);
	while (k < 8) {
		n = nfl_wait(NFL57, PRE57, pay, (int)sizeof(pay), 200);
		if (n <= 0)
			break;
		printf("F558 ONE|%s|msg=%d|n=%d|hex=", tag, k, n);
		f558_hex(pay, n > 24 ? 24 : n);
		printf("\n");
		k++;
	}
	c1 = f555_count(eb.fam, eb.table, eb.chain);
	printf("F558 ONE|%s|cnt_delta=%llu|msgs=%d\n", tag, c1 - c0, k);
	(void)dv;
	(void)path;
	(void)i;
}

static void f558_sec_ipv6(void)
{
	static const char *dv[] = { "r0", "s0", "s1", "r1", "br0" };
	char path[96];
	int i;

	f558_one_send("v6off");
	for (i = 0; i < (int)(sizeof(dv) / sizeof(dv[0])); i++) {
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", dv[i]);
		f555_sysctl(path, "0");
	}
	usleep(300000);
	f558_one_send("v6on1");
	usleep(300000);
	f558_one_send("v6on2");
	for (i = 0; i < (int)(sizeof(dv) / sizeof(dv[0])); i++) {
		snprintf(path, sizeof(path),
			 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", dv[i]);
		f555_sysctl(path, "1");
	}
	usleep(200000);
	f558_one_send("v6off2");
	sh("/nft flush ruleset");
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "f558";
	const char *only = argc > 2 ? argv[2] : NULL;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F558 BEGIN|mode=%s|only=%s\n", mode, only ? only : "-");
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F558 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F558 KERNEL|%s\n", "7.3.4-T557/T558");
	f556_env_setup();
	/* The counter on an nft chain has no match expression: it counts any
	 * frame that crosses the chain.  The kernel's own IPv6 chatter (MLD/NS
	 * emitted out of r0 and s0, which arrive at their peers r1 and s1 --
	 * bridge ports) therefore lands in the same counter as our IPv4 frame:
	 * measured in `why`, one send produced one IPv4 log message and one
	 * IPv6 one, cnt_delta=2.  IPv6 is turned off on every device of this
	 * netns so that "one frame through the bridge" means one. */
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
	NFL57 = nfl_open(5);
	printf("F558 NFL|%d\n", NFL57);
	if (!strcmp(mode, "f558why")) {
		f558_sec_why();
	} else if (!strcmp(mode, "f558bytes")) {
		f558_sec_bytes();
	} else if (!strcmp(mode, "f558ipv6")) {
		f558_sec_ipv6();
	} else if (!strcmp(mode, "f558vlan")) {
		f558_sec_vlan(NULL);
	} else if (!strncmp(mode, "f558vlan:", 9)) {
		f558_sec_vlan(mode + 9);
	} else {
		f558_sec_why();
		f558_sec_bytes();
		f558_sec_vlan(only);
	}
	printf("F558 DONE\n");
	return 0;
}
