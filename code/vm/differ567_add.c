/* ==========================================================================
 * Turn 567 -- F45: the constructor that WALKS.
 *
 * F44 established that `@th` has one coordinate across four doors because
 * IPv4 computes it as a formula (`ihl*4`).  The IPv6 constructors do not:
 * `nft_set_pktinfo_ipv6()`, `__nft_set_pktinfo_ipv6_validate()` and
 * `nft_set_pktinfo_ipv6_ingress()` all take `thoff` from `ipv6_find_hdr()`,
 * which walks the extension-header chain and also fills `tprot` and
 * `fragoff`.  Same question as F44, one family over: where does `@th` land,
 * what does the guard say, and what happens when the walk fails.
 *
 * differ567.c is GENERATED: differ566.c with its main() renamed to f566_main,
 * plus this file.  Every helper under the new code -- netlink toolkit,
 * veth/bridge/rtnetlink, NFLOG reader, AF_PACKET capture, counter read-back --
 * is byte-for-byte the one that produced F31..F44.
 * ========================================================================== */

#define NFULA_L2HDR_	21

static int U567_6A = -1;	/* UDP6 [fd00::99:9]:5000 */
static int U567_6B = -1;	/* UDP6 [fd00::99:9]:5001 */
static int U567_4A = -1;	/* UDP4 10.9.0.7:5000     */
static int NFL67 = -1;

/* ---------- the five doors ---------- */

struct f567_door {
	const char *tag;
	uint8_t fam;
	const char *table;
	const char *dev;	/* NULL for the layer-3 hooks */
	uint32_t hook;
	int prio0;
	int prio1;
};

static struct f567_door D567[] = {
	{ "ip4p", NFPROTO_IPV4,   "d67a", NULL, 0,  0, 10 },
	{ "ip6p", NFPROTO_IPV6,   "d67b", NULL, 0, 20, 30 },
	{ "inp",  NFPROTO_INET,   "d67c", NULL, 0, 40, 50 },
	{ "ndg",  NFPROTO_NETDEV, "d67d", "s1", 0, 60, 70 },
	{ "ieg",  NFPROTO_INET,   "d67e", "s1", 5,  0, 10 },
};
#define ND67 5

/* ---------- frames ---------- */

struct f567_frame {
	const char *tag;
	unsigned char wire[900];
	int wlen;
	unsigned short sproto;
};

enum {
	K6_PLAIN = 0, K6_HBH, K6_DST, K6_HBDST, K6_FRAG0, K6_FRAGN,
	K6_NONE, K6_BADEXT, K6_DOBAD, K6_TRUNC, K6_VER5, K6_TCP, K6_NKIND
};
#define K6_P4	K6_NKIND	/* the IPv4 control frame, last slot */

static const unsigned char V6SRC[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0,
					 0, 0, 0, 0, 0, 0x98, 0, 1 };

/* ---------- small helpers the add file needs its own copy of ---------- */

static int f567_netstat(const char *group, const char *field)
{
	FILE *f = fopen("/proc/net/netstat", "r");
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

static int f567_drain(int fd, int *firstlen)
{
	unsigned char b[512];
	int n = 0, r;

	if (firstlen)
		*firstlen = -1;
	if (fd < 0)
		return -1;
	while (n < 8) {
		r = (int)recv(fd, b, sizeof(b), MSG_DONTWAIT);
		if (r <= 0)
			break;
		if (n == 0 && firstlen)
			*firstlen = r;
		n++;
	}
	return n;
}

static unsigned long long f567_read_ll(const char *path)
{
	FILE *f = fopen(path, "r");
	unsigned long long v = 0;

	if (!f)
		return 0;
	if (fscanf(f, "%llu", &v) != 1)
		v = 0;
	fclose(f);
	return v;
}

/* ---------- the IPv6/UDP frame builders ---------- */

/* UDP checksum over an IPv6 pseudo-header.  `ip` points at the IPv6 header,
 * `udp` at the UDP header, `paylen` is the upper-layer length. */
static void f567_csum6(unsigned char *ip, unsigned char *udp, int paylen)
{
	unsigned int acc = 0;
	unsigned short c;

	acc = f564_sum(ip + 8, 32, 0);
	acc += (unsigned int)paylen;
	acc += 17;
	udp[6] = 0;
	udp[7] = 0;
	acc = f564_sum(udp, paylen, acc);
	c = f564_fold(acc);
	if (!c)
		c = 0xffff;
	udp[6] = (unsigned char)(c >> 8);
	udp[7] = (unsigned char)c;
}

/* kind == K6_TCP gets a TCP header instead of UDP */
static int f567_mk6(unsigned char *out, int kind, unsigned short dport)
{
	unsigned char *ip = out + 14, *ext = ip + 40;
	unsigned char *l4;
	int next, extlen = 0, pay, i, fragoff_word = 0;

	memset(out, 0, 900);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = 0x86;
	out[13] = 0xdd;

	switch (kind) {
	case K6_PLAIN:  next = 17; extlen = 0;  break;
	case K6_HBH:    next = 0;  extlen = 8;  break;
	case K6_DST:    next = 60; extlen = 8;  break;
	case K6_HBDST:  next = 0;  extlen = 16; break;
	case K6_FRAG0:  next = 44; extlen = 8;  break;
	case K6_FRAGN:  next = 44; extlen = 8; fragoff_word = 8; break;
	case K6_NONE:   next = 59; extlen = 0;  break;
	case K6_BADEXT: next = 0;  extlen = 8;  break;
	case K6_DOBAD:  next = 60; extlen = 8;  break;
	case K6_TRUNC:  next = 17; extlen = 0;  break;
	case K6_VER5:   next = 17; extlen = 0;  break;
	case K6_TCP:    next = 6;  extlen = 0;  break;
	default:        next = 17; extlen = 0;  break;
	}

	if (kind == K6_TCP)
		pay = 20 + 18;
	else if (kind == K6_NONE)
		pay = 0;
	else
		pay = 8 + 18;

	ip[0] = (kind == K6_VER5) ? 0x50 : 0x60;
	if (kind == K6_TRUNC) {
		ip[4] = 0x02;		/* claims 512 bytes of payload */
		ip[5] = 0x00;
	} else {
		ip[4] = (unsigned char)(((extlen + pay) >> 8) & 0xff);
		ip[5] = (unsigned char)((extlen + pay) & 0xff);
	}
	ip[6] = (unsigned char)next;
	ip[7] = 64;
	memcpy(ip + 8, V6SRC, 16);
	memcpy(ip + 24, F564_V6DST, 16);

	/* extension headers */
	if (kind == K6_HBH || kind == K6_BADEXT) {
		ext[0] = 17;		/* next: UDP */
		ext[1] = (kind == K6_BADEXT) ? 15 : 0;	/* 128 bytes vs 8 */
	} else if (kind == K6_HBDST) {
		ext[0] = 60;		/* next: DSTOPTS */
		ext[1] = 0;
		ext[8] = 17;		/* next: UDP */
		ext[9] = 0;
	} else if (kind == K6_DST) {
		ext[0] = 17;
		ext[1] = 0;
	} else if (kind == K6_DOBAD) {
		ext[0] = 17;
		ext[1] = 15;		/* claims 128 bytes, 8 present */
	} else if (kind == K6_FRAG0 || kind == K6_FRAGN) {
		ext[0] = 17;
		ext[1] = 0;
		ext[2] = (unsigned char)(fragoff_word >> 8);
		ext[3] = (unsigned char)fragoff_word;	/* 8 => offset 8 bytes */
		ext[4] = 0x11;
		ext[5] = 0x22;
		ext[6] = 0x33;
		ext[7] = 0x44;
	}

	if (kind == K6_NONE)
		return 14 + 40;

	l4 = ip + 40 + extlen;
	l4[0] = 0x9c;			/* sport 40000 */
	l4[1] = 0x40;
	l4[2] = (unsigned char)(dport >> 8);
	l4[3] = (unsigned char)dport;
	if (kind == K6_TCP) {
		l4[4] = 0x00;
		l4[5] = 0x01;		/* seq */
		l4[12] = 0x50;		/* doff 5 */
		l4[13] = 0x02;		/* SYN */
		l4[14] = 0x20;
		l4[15] = 0x00;
		memset(l4 + 20, 0x77, 18);
		return 14 + 40 + extlen + pay;
	}
	l4[4] = 0x00;
	l4[5] = 26;
	l4[6] = 0;
	l4[7] = 0;
	for (i = 0; i < 18; i++)
		l4[8 + i] = 0x77;
	f567_csum6(ip, l4, 26);
	return 14 + 40 + extlen + pay;
}

/* ---------- chains ---------- */

static int f567_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND67; i++) {
		struct f567_door *D = &D567[i];

		rc |= add_table(D->fam, D->table);
		rc |= f556_add_chain(D->fam, D->table, "pre0", D->hook,
				     (uint32_t)D->prio0, 1, D->dev);
		rc |= f556_add_chain(D->fam, D->table, "ch", D->hook,
				     (uint32_t)D->prio1, 1, D->dev);
	}
	return rc;
}

static void f567_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND67; i++) {
		f557_flush(D567[i].fam, D567[i].table, "pre0", &acks);
		f557_flush(D567[i].fam, D567[i].table, "ch", &acks);
	}
}

/* meta l4proto -> dreg: the only expression that can tell "flags has no
 * L4PROTO" (rule does not fire) from "tprot exists but there is no header"
 * (rule fires and compares 59). */
static void f567_meta_l4(struct nlmsghdr *nlh)
{
	struct nlattr *e, *d;

	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "meta");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_META_KEY, NFT_META_L4PROTO);
	put_be32(nlh, NFTA_META_DREG, F562_RD_DREG);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

/* mode 0: none; 1: store; 2: payload read + cmp; 3: meta(l4proto) + cmp;
 * 4: meta(protocol) + cmp */
static int f567_rule(const struct f567_door *D, const char *chain,
		     const char *prefix, int gate, uint32_t base, int off,
		     int len, const unsigned char *imm, int mode, int mkey,
		     int *acks)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			D->fam);
	put_str(nlh, NFTA_RULE_TABLE, D->table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	if (gate)
		f562_meta_proto(nlh);
	(void)mkey;
	if (mode == 1)
		f565_store(nlh, base, (uint32_t)off, (uint32_t)len, imm, 0, 0);
	else if (mode == 2) {
		f562_read(nlh, base, (uint32_t)off, (uint32_t)len);
		f562_cmp(nlh, F562_RD_DREG, imm, len);
	} else if (mode == 3) {
		f567_meta_l4(nlh);
		f562_cmp(nlh, F562_RD_DREG, imm, len);
	} else if (mode == 4) {
		f562_meta_proto(nlh);
		f562_cmp(nlh, F562_RD_DREG, imm, len);
	}
	log_expr(nlh, 5, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

/* ---------- NFLOG reader (same parser as F44) ---------- */

struct f567_log {
	int seen;
	int l2;
	int plen;
	unsigned char p[128];
};

static void f567_parse_log(unsigned char *buf, int len, struct f567_log *pre,
			   struct f567_log *post)
{
	struct nlmsghdr *h;

	for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
		const char *p, *end, *prefix = NULL;
		const unsigned char *pl = NULL;
		int pll = 0, l2 = 0;

		if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
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
			} else if (t == NFULA_L2HDR_)
				l2 = al - NLA_HDRLEN;
			p += NLA_ALIGN_(al);
		}
		if (!prefix || !pl)
			continue;
		if (prefix[0] == 'p') {
			pre->seen++;
			pre->l2 = l2;
			pre->plen = pll < (int)sizeof(pre->p) ? pll : (int)sizeof(pre->p);
			memcpy(pre->p, pl, (size_t)pre->plen);
		} else {
			post->seen++;
			post->l2 = l2;
			post->plen = pll < (int)sizeof(post->p) ? pll : (int)sizeof(post->p);
			memcpy(post->p, pl, (size_t)post->plen);
		}
	}
}

static void f567_logs(int fd, struct f567_log *pre, struct f567_log *post)
{
	unsigned char b[16384];
	int guard = 0, rl;

	memset(pre, 0, sizeof(*pre));
	memset(post, 0, sizeof(*post));
	if (fd < 0)
		return;
	while (guard++ < 64) {
		rl = (int)recv(fd, b, sizeof(b), MSG_DONTWAIT);
		if (rl <= 0)
			break;
		f567_parse_log(b, rl, pre, post);
	}
}

/* ---------- one arm ---------- */

static void f567_arm(const char *sec, const struct f567_door *D,
		     const struct f567_frame *E, const char *arm,
		     int gate, uint32_t base, int off, int len,
		     const unsigned char *imm, int mode, int rfd,
		     struct f559_out *ctl, struct f559_out *out)
{
	struct f559_out o;
	struct f567_log pre, post;
	unsigned char rf[1024];
	char hi[160], hpre[300], hpost[300], hr[440], cw[440];
	unsigned long long cntp0, cnts0, cntp1, cnts1;
	unsigned long long ip0[3], ip1[3], i60[6], i61[6];
	int rcp, rcs, acks, snd, rn = 0, sk = 0, rchg = 0;
	int f0 = -1, f1 = -1, f2 = -1, u6a = 0, u6b = 0, u4 = 0;

	f567_flush_all();
	acks = 0;
	rcp = f567_rule(D, "pre0", "p", 0, 0, 0, 0, NULL, 0, 0, &acks);
	acks = 0;
	rcs = f567_rule(D, "ch", "s", gate, base, off, len, imm, mode, 0, &acks);

	nfl_drain(NFL67);
	cntp0 = f555_count(D->fam, D->table, "pre0");
	cnts0 = f555_count(D->fam, D->table, "ch");
	ip0[0] = f564_snmp("Ip", "InReceives");
	ip0[1] = f564_snmp("Ip", "InDelivers");
	ip0[2] = f567_netstat("IpExt", "InTruncatedPkts");
	i60[0] = f564_snmp6("Ip6InReceives");
	i60[1] = f564_snmp6("Ip6InHdrErrors");
	i60[2] = f564_snmp6("Ip6InTruncatedPkts");
	i60[3] = f564_snmp6("Ip6InDelivers");
	i60[4] = f564_snmp6("Ip6InReasmReqds");
	i60[5] = f564_snmp6("Ip6InUnknownProtos");
	f567_drain(U567_6A, &f0);
	f567_drain(U567_6B, &f1);
	f567_drain(U567_4A, &f2);
	if (rfd >= 0)
		cap_drain(rfd);
	memset(&o, 0, sizeof(o));
	o.wpt = -1;
	o.rpt = -1;
	snd = pkt_send_p("s0", E->wire, E->wlen, E->sproto);
	usleep(70000);
	u6a = f567_drain(U567_6A, NULL);
	u6b = f567_drain(U567_6B, NULL);
	u4 = f567_drain(U567_4A, NULL);
	cntp1 = f555_count(D->fam, D->table, "pre0");
	cnts1 = f555_count(D->fam, D->table, "ch");
	ip1[0] = f564_snmp("Ip", "InReceives");
	ip1[1] = f564_snmp("Ip", "InDelivers");
	ip1[2] = f567_netstat("IpExt", "InTruncatedPkts");
	i61[0] = f564_snmp6("Ip6InReceives");
	i61[1] = f564_snmp6("Ip6InHdrErrors");
	i61[2] = f564_snmp6("Ip6InTruncatedPkts");
	i61[3] = f564_snmp6("Ip6InDelivers");
	i61[4] = f564_snmp6("Ip6InReasmReqds");
	i61[5] = f564_snmp6("Ip6InUnknownProtos");
	f567_logs(NFL67, &pre, &post);
	if (rfd >= 0) {
		o.rn = f558_cap_match(rfd, rf, (int)sizeof(rf), 250, M561_77, 8,
				      &sk, &o.rpt);
		rn = o.rn;
		if (rn > 0)
			memcpy(o.r, rf, (size_t)(rn < (int)sizeof(o.r) ? rn : (int)sizeof(o.r)));
	}
	if (ctl && ctl->rn > 0 && rn > 0)
		rchg = f558_chg(cw, sizeof(cw), ctl->r, ctl->rn, rf, rn);
	printf("F567 A|sec=%s|door=%s|env=%s|arm=%s|gate=%d|base=%u|off=%d|"
	       "len=%d|mode=%d|imm=%s|rcp=%d|rcs=%d|sendrc=%d|",
	       sec, D->tag, E->tag, arm, gate, (unsigned)base, off, len, mode,
	       (len > 0 && imm) ? f559_hexs(hi, sizeof(hi), imm, len) : "-",
	       rcp, rcs, snd);
	printf("cntp0=%llu|cntp=%llu|livep=%llu|cnts0=%llu|cnts=%llu|lives=%llu|",
	       cntp0, cntp1, cntp1 - cntp0, cnts0, cnts1, cnts1 - cnts0);
	printf("ipin=%llu|ideliv=%llu|itrun=%llu|i6in=%llu|i6hdr=%llu|"
	       "i6trun=%llu|i6deliv=%llu|i6reasm=%llu|i6unk=%llu|",
	       ip1[0] - ip0[0], ip1[1] - ip0[1], ip1[2] - ip0[2],
	       i61[0] - i60[0], i61[1] - i60[1], i61[2] - i60[2],
	       i61[3] - i60[3], i61[4] - i60[4], i61[5] - i60[5]);
	printf("u6a=%d|u6b=%d|u4=%d|f6a=%d|f6b=%d|f4=%d|npre=%d|npost=%d|l2=%d|",
	       u6a, u6b, u4, f0, f1, f2, pre.seen, post.seen, post.l2);
	printf("prelen=%d|pre=%s|postlen=%d|post=%s|",
	       pre.plen, pre.seen ? f559_hexs(hpre, sizeof(hpre), pre.p, pre.plen) : "-",
	       post.plen, post.seen ? f559_hexs(hpost, sizeof(hpost), post.p, post.plen) : "-");
	if (rn > 0)
		f559_hexs(hr, sizeof(hr), rf, rn < 128 ? rn : 128);
	printf("rn=%d|rpt=%d|rchg=%d|rchgs=%s|rhex=%s\n", rn, o.rpt, rchg,
	       rchg > 0 ? cw : "-", rn > 0 ? hr : "-");
	if (out)
		memcpy(out, &o, sizeof(o));
}

/* ---------- cells ---------- */

struct f567_spec {
	const char *arm;
	uint32_t base;
	int off, len;
	unsigned char imm[32];
};

/* the transport base: F43's eight cells, unchanged */
static struct f567_spec T567[] = {
	{ "ctl",  0, 0, 0, { 0 } },
	{ "t0_2", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x90, 0x91 } },
	{ "t2_2", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x90, 0x91 } },
	{ "t4_2", NFT_PAYLOAD_TRANSPORT_HEADER, 4, 2, { 0x90, 0x91 } },
	{ "t6_2", NFT_PAYLOAD_TRANSPORT_HEADER, 6, 2, { 0x90, 0x91 } },
	{ "t8_2", NFT_PAYLOAD_TRANSPORT_HEADER, 8, 2, { 0x90, 0x91 } },
	{ "t0_4", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "t12_4", NFT_PAYLOAD_TRANSPORT_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "t16_2", NFT_PAYLOAD_TRANSPORT_HEADER, 16, 2, { 0x90, 0x91 } },
};

/* the network base for IPv6: every branch of nft_nh_write_ok_ip6() plus
 * cells it does not name, and two cells whose verdict reads the VALUE */
static struct f567_spec N567[] = {
	{ "n0_1",  NFT_PAYLOAD_NETWORK_HEADER, 0, 1, { 0x60 } },
	{ "n0_1x", NFT_PAYLOAD_NETWORK_HEADER, 0, 1, { 0x90 } },
	{ "n0_2v", NFT_PAYLOAD_NETWORK_HEADER, 0, 2, { 0x61, 0x00 } },
	{ "n0_2x", NFT_PAYLOAD_NETWORK_HEADER, 0, 2, { 0x90, 0x91 } },
	{ "n1_1",  NFT_PAYLOAD_NETWORK_HEADER, 1, 1, { 0x90 } },
	{ "n2_2",  NFT_PAYLOAD_NETWORK_HEADER, 2, 2, { 0x90, 0x91 } },
	{ "n2_4",  NFT_PAYLOAD_NETWORK_HEADER, 2, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n4_2",  NFT_PAYLOAD_NETWORK_HEADER, 4, 2, { 0x90, 0x91 } },
	{ "n6_2",  NFT_PAYLOAD_NETWORK_HEADER, 6, 2, { 0x90, 0x91 } },
	{ "n7_1",  NFT_PAYLOAD_NETWORK_HEADER, 7, 1, { 0x90 } },
	{ "n7_2",  NFT_PAYLOAD_NETWORK_HEADER, 7, 2, { 0x90, 0x91 } },
	{ "n8_1",  NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x90 } },
	{ "n8_2",  NFT_PAYLOAD_NETWORK_HEADER, 8, 2, { 0x90, 0x91 } },
	{ "n8_16", NFT_PAYLOAD_NETWORK_HEADER, 8, 16,
	  { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f } },
	{ "n24_4", NFT_PAYLOAD_NETWORK_HEADER, 24, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n24_16", NFT_PAYLOAD_NETWORK_HEADER, 24, 16,
	  { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f } },
	{ "n28_4", NFT_PAYLOAD_NETWORK_HEADER, 28, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n40_2", NFT_PAYLOAD_NETWORK_HEADER, 40, 2, { 0x90, 0x91 } },
	{ "n44_2", NFT_PAYLOAD_NETWORK_HEADER, 44, 2, { 0x90, 0x91 } },
};

/* ---------- sections ---------- */

/* A. the walk: four envelopes, four doors, eight cells */
static void f567_sec_td(struct f567_frame *E, int rfd)
{
	static const int doors[4] = { 1, 2, 3, 4 };
	static const int envs[4] = { K6_PLAIN, K6_HBH, K6_DST, K6_HBDST };
	int di, ei, i;
	int n = (int)(sizeof(T567) / sizeof(T567[0]));

	for (di = 0; di < 4; di++) {
		for (ei = 0; ei < 4; ei++) {
			struct f559_out ctl;

			memset(&ctl, 0, sizeof(ctl));
			f567_arm("td", &D567[doors[di]], &E[envs[ei]], "ctl", 0,
				 0, 0, 0, NULL, 0, rfd, NULL, &ctl);
			for (i = 1; i < n; i++)
				f567_arm("td", &D567[doors[di]], &E[envs[ei]],
					 T567[i].arm, 0, T567[i].base,
					 T567[i].off, T567[i].len, T567[i].imm, 1,
					 rfd, &ctl, NULL);
		}
	}
}

/* B. fragments and the none-header */
static void f567_sec_tf(struct f567_frame *E, int rfd)
{
	static const int doors[4] = { 1, 2, 3, 4 };
	static const int envs[3] = { K6_FRAG0, K6_FRAGN, K6_NONE };
	int di, ei, i;
	int n = (int)(sizeof(T567) / sizeof(T567[0]));

	for (di = 0; di < 4; di++) {
		for (ei = 0; ei < 3; ei++) {
			struct f559_out ctl;

			memset(&ctl, 0, sizeof(ctl));
			f567_arm("tf", &D567[doors[di]], &E[envs[ei]], "ctl", 0,
				 0, 0, 0, NULL, 0, rfd, NULL, &ctl);
			for (i = 1; i < n; i++)
				f567_arm("tf", &D567[doors[di]], &E[envs[ei]],
					 T567[i].arm, 0, T567[i].base,
					 T567[i].off, T567[i].len, T567[i].imm, 1,
					 rfd, &ctl, NULL);
		}
	}
}

/* C. the network base: ip6 whitelist vs the ingress constant */
static void f567_sec_nh(struct f567_frame *E, int rfd)
{
	static const int doors[4] = { 1, 2, 3, 4 };
	int di, i;
	int n = (int)(sizeof(N567) / sizeof(N567[0]));

	for (di = 0; di < 4; di++) {
		struct f559_out ctl;

		memset(&ctl, 0, sizeof(ctl));
		f567_arm("nh", &D567[doors[di]], &E[K6_PLAIN], "ctl", 0, 0, 0, 0,
			 NULL, 0, rfd, NULL, &ctl);
		for (i = 0; i < n; i++)
			f567_arm("nh", &D567[doors[di]], &E[K6_PLAIN],
				 N567[i].arm, 0, N567[i].base, N567[i].off,
				 N567[i].len, N567[i].imm, 1, rfd, &ctl, NULL);
	}
}

/* D. one chain, one rule, two families */
struct f567_xf {
	const char *arm;
	int off, len;
	unsigned char imm[4];
};

static struct f567_xf X567[] = {
	{ "x2_2",  2, 2, { 0x90, 0x91 } },
	{ "x4_2",  4, 2, { 0x90, 0x91 } },
	{ "x7_1",  7, 1, { 0x90 } },
	{ "x0_2x", 0, 2, { 0x90, 0x91 } },
	{ "x0_2v", 0, 2, { 0x60, 0x00 } },
	{ "x0_2d", 0, 2, { 0x45, 0x00 } },
};

static void f567_sec_xf(struct f567_frame *E, int rfd)
{
	static const int envs[2] = { K6_PLAIN, K6_P4 };
	int ei, i;
	int n = (int)(sizeof(X567) / sizeof(X567[0]));

	for (ei = 0; ei < 2; ei++) {
		struct f559_out ctl;

		memset(&ctl, 0, sizeof(ctl));
		f567_arm("xf", &D567[2], &E[envs[ei]], "ctl", 0, 0, 0, 0, NULL,
			 0, rfd, NULL, &ctl);
		for (i = 0; i < n; i++)
			f567_arm("xf", &D567[2], &E[envs[ei]], X567[i].arm, 0,
				 NFT_PAYLOAD_NETWORK_HEADER, X567[i].off,
				 X567[i].len, X567[i].imm, 1, rfd, &ctl, NULL);
		/* the transport base in both families: same rule, two
		 * coordinates */
		f567_arm("xf", &D567[2], &E[envs[ei]], "xt0_2", 0,
			 NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, T567[1].imm, 1,
			 rfd, &ctl, NULL);
		f567_arm("xf", &D567[2], &E[envs[ei]], "xt2_2", 0,
			 NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, T567[2].imm, 1,
			 rfd, &ctl, NULL);
		f567_arm("xf", &D567[2], &E[envs[ei]], "xt12_4", 0,
			 NFT_PAYLOAD_TRANSPORT_HEADER, 12, 4, T567[7].imm, 1,
			 rfd, &ctl, NULL);
	}
}

/* E. read side: does the read land where the write does */
static void f567_sec_rd(struct f567_frame *E, int rfd)
{
	static const struct {
		const char *arm;
		int off, len;
		unsigned char imm[2];
	} rd[3] = {
		{ "r0_2", 0, 2, { 0x9c, 0x40 } },
		{ "r2_2", 2, 2, { 0x13, 0x88 } },
		{ "r4_2", 4, 2, { 0x00, 0x1a } },
	};
	static const int doors[2] = { 2, 4 };
	static const int envs[2] = { K6_PLAIN, K6_HBH };
	int di, ei, i;

	for (di = 0; di < 2; di++)
		for (ei = 0; ei < 2; ei++)
			for (i = 0; i < 3; i++)
				f567_arm("rd", &D567[doors[di]], &E[envs[ei]],
					 rd[i].arm, 0,
					 NFT_PAYLOAD_TRANSPORT_HEADER, rd[i].off,
					 rd[i].len, rd[i].imm, 2, rfd, NULL, NULL);
}

/* F. meta: does tprot exist when there is no transport header */
struct f567_meta {
	const char *arm;
	int len, mode;
	unsigned char imm[2];
};

static const struct f567_meta M567[4] = {
	{ "l4_17", 1, 3, { 0x11 } },		/* tprot == UDP  */
	{ "l4_59", 1, 3, { 0x3b } },		/* tprot == NONE */
	{ "pr_86", 2, 4, { 0x86, 0xdd } },	/* meta protocol */
	{ "pr_08", 2, 4, { 0x08, 0x00 } },
};

static void f567_mp_pass(const char *sec, struct f567_frame *E, int rfd)
{
	static const int envs[4] = { K6_PLAIN, K6_NONE, K6_BADEXT, K6_DOBAD };
	int ei, i;

	for (ei = 0; ei < 4; ei++)
		for (i = 0; i < 4; i++)
			f567_arm(sec, &D567[2], &E[envs[ei]], M567[i].arm, 0, 0,
				 0, M567[i].len, M567[i].imm, M567[i].mode, rfd,
				 NULL, NULL);
}

/* G. malformed: one frame, three doors, three outcomes */
static const int MD_FRAMES[4] = { K6_TRUNC, K6_BADEXT, K6_DOBAD, K6_NONE };
static const char *MD_NAMES[4] = { "mtrunc", "mexth", "mdobad", "none" };

static void f567_md_pass(const char *sec, struct f567_door *D,
			 struct f567_frame *E, int rfd)
{
	unsigned char imm[1] = { 0x90 };
	int i;

	for (i = 0; i < 4; i++) {
		int k = MD_FRAMES[i];
		struct f559_out ctl;

		memset(&ctl, 0, sizeof(ctl));
		f567_arm(sec, D, &E[k], "ctl", 0, 0, 0, 0, NULL, 0, rfd, NULL,
			 &ctl);
		f567_arm(sec, D, &E[k], MD_NAMES[i], 0,
			 NFT_PAYLOAD_NETWORK_HEADER, 8, 1, imm, 1, rfd, &ctl,
			 NULL);
		f567_arm(sec, D, &E[k], "th0_2", 0,
			 NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, T567[1].imm, 1,
			 rfd, &ctl, NULL);
		f567_arm(sec, D, &E[k], "th2_2", 0,
			 NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, T567[2].imm, 1,
			 rfd, &ctl, NULL);
	}
}

static void f567_sec_md(struct f567_frame *E, int rfd)
{
	int i;

	/* 1. both ingress doors present, inet first by priority */
	f567_md_pass("md_both_ndg", &D567[3], E, rfd);
	f567_md_pass("md_both_ieg", &D567[4], E, rfd);

	/* 2. the inet ingress table deleted: the netdev door alone -- and now
	 * the same frames reach the two layer-3 doors, which live behind
	 * ip6_rcv_core() and were never touched while ieg dropped them. */
	sh("/nft delete table inet d67e");
	printf("F567 MD|deleted=inet d67e\n");
	f567_md_pass("md_ndg_only", &D567[3], E, rfd);
	f567_md_pass("md_inp_l3", &D567[2], E, rfd);
	f567_md_pass("md_ip6p_l3", &D567[1], E, rfd);
	f567_mp_pass("mp_l3", E, rfd);

	/* 3. the netdev table deleted instead: the inet door alone */
	add_table(NFPROTO_INET, "d67e");
	for (i = 4; i <= 4; i++) {
		f556_add_chain(D567[i].fam, D567[i].table, "pre0",
			       D567[i].hook, (uint32_t)D567[i].prio0, 1,
			       D567[i].dev);
		f556_add_chain(D567[i].fam, D567[i].table, "ch",
			       D567[i].hook, (uint32_t)D567[i].prio1, 1,
			       D567[i].dev);
	}
	sh("/nft delete table netdev d67d");
	printf("F567 MD|deleted=netdev d67d\n");
	f567_md_pass("md_ieg_only", &D567[4], E, rfd);
	/* both again, for the record */
	add_table(NFPROTO_NETDEV, "d67d");
	for (i = 3; i <= 3; i++) {
		f556_add_chain(D567[i].fam, D567[i].table, "pre0",
			       D567[i].hook, (uint32_t)D567[i].prio0, 1,
			       D567[i].dev);
		f556_add_chain(D567[i].fam, D567[i].table, "ch",
			       D567[i].hook, (uint32_t)D567[i].prio1, 1,
			       D567[i].dev);
	}
	printf("F567 MD|restored=netdev d67d\n");
	f567_md_pass("md_again_ieg", &D567[4], E, rfd);
	f567_md_pass("md_again_ndg", &D567[3], E, rfd);
}

/* H. cross-family: IPv4 frames in the same boot, before and after a dropped
 * IPv6 frame */
static void f567_sec_xc(struct f567_frame *E, int rfd)
{
	static const int seq[6] = { K6_P4, K6_PLAIN, K6_TRUNC, K6_P4,
				    K6_BADEXT, K6_P4 };
	int i, acks = 0;

	(void)rfd;
	for (i = 0; i < ND67; i++)
		f567_rule(&D567[i], "ch", "s", 0, 0, 0, 0, NULL, 0, 0, &acks);
	for (i = 0; i < 6; i++) {
		unsigned long long c0[ND67], c1[ND67];
		int d, u4, u6, f0 = -1;

		for (d = 0; d < ND67; d++)
			c0[d] = f555_count(D567[d].fam, D567[d].table, "ch");
		f567_drain(U567_4A, &f0);
		f567_drain(U567_6A, NULL);
		pkt_send_p("s0", E[seq[i]].wire, E[seq[i]].wlen, E[seq[i]].sproto);
		usleep(70000);
		u4 = f567_drain(U567_4A, NULL);
		u6 = f567_drain(U567_6A, NULL);
		for (d = 0; d < ND67; d++)
			c1[d] = f555_count(D567[d].fam, D567[d].table, "ch");
		printf("F567 XC|i=%d|env=%s|ipp=%llu|ip6p=%llu|inp=%llu|ndg=%llu|"
		       "ieg=%llu|u4=%d|u6=%d|f4=%d\n", i, E[seq[i]].tag,
		       c1[0] - c0[0], c1[1] - c0[1], c1[2] - c0[2],
		       c1[3] - c0[3], c1[4] - c0[4], u4, u6, f0);
	}
}

/* I. diagnostic: which door sees which frame */
static void f567_sec_diag(struct f567_frame *E, int rfd)
{
	static const int order[K6_NKIND + 1] = {
		K6_PLAIN, K6_HBH, K6_DST, K6_HBDST, K6_FRAG0, K6_FRAGN,
		K6_NONE, K6_BADEXT, K6_DOBAD, K6_TRUNC, K6_VER5, K6_TCP, K6_P4
	};
	int i, e, acks = 0;
	unsigned long long c0[ND67], c1[ND67];

	printf("F567 DIAG|capfd=%d\n", rfd);
	for (i = 0; i < ND67; i++)
		f567_rule(&D567[i], "ch", "s", 0, 0, 0, 0, NULL, 0, 0, &acks);
	for (e = 0; e <= K6_NKIND; e++) {
		unsigned long long i0[6], i1[6], q0, q1;
		int d, u6a, u6b, f0 = -1;

		for (d = 0; d < ND67; d++)
			c0[d] = f555_count(D567[d].fam, D567[d].table, "ch");
		i0[0] = f564_snmp6("Ip6InReceives");
		i0[1] = f564_snmp6("Ip6InHdrErrors");
		i0[2] = f564_snmp6("Ip6InTruncatedPkts");
		i0[3] = f564_snmp6("Ip6InDelivers");
		i0[4] = f564_snmp6("Ip6InReasmReqds");
		i0[5] = f564_snmp6("Ip6InUnknownProtos");
		q0 = f564_snmp("Ip", "InReceives");
		f567_drain(U567_6A, &f0);
		f567_drain(U567_6B, NULL);
		pkt_send_p("s0", E[order[e]].wire, E[order[e]].wlen,
			   E[order[e]].sproto);
		usleep(70000);
		u6a = f567_drain(U567_6A, NULL);
		u6b = f567_drain(U567_6B, NULL);
		for (d = 0; d < ND67; d++)
			c1[d] = f555_count(D567[d].fam, D567[d].table, "ch");
		i1[0] = f564_snmp6("Ip6InReceives");
		i1[1] = f564_snmp6("Ip6InHdrErrors");
		i1[2] = f564_snmp6("Ip6InTruncatedPkts");
		i1[3] = f564_snmp6("Ip6InDelivers");
		i1[4] = f564_snmp6("Ip6InReasmReqds");
		i1[5] = f564_snmp6("Ip6InUnknownProtos");
		q1 = f564_snmp("Ip", "InReceives");
		printf("F567 DIAG|env=%s|ipp=%llu|ip6p=%llu|inp=%llu|ndg=%llu|"
		       "ieg=%llu|i6in=%llu|i6hdr=%llu|i6trun=%llu|i6deliv=%llu|"
		       "i6reasm=%llu|i6unk=%llu|ipin=%llu|u6a=%d|u6b=%d|f6a=%d\n",
		       E[order[e]].tag, c1[0] - c0[0], c1[1] - c0[1],
		       c1[2] - c0[2], c1[3] - c0[3], c1[4] - c0[4],
		       i1[0] - i0[0], i1[1] - i0[1], i1[2] - i0[2],
		       i1[3] - i0[3], i1[4] - i0[4], i1[5] - i0[5],
		       q1 - q0, u6a, u6b, f0);
	}
}

/* J. delivery probe: is one of these frames a real datagram to a real socket? */
static void f567_sec_dbg(struct f567_frame *E, int rfd)
{
	static const int envs[5] = { K6_PLAIN, K6_HBH, K6_DST, K6_HBDST,
				     K6_FRAG0 };
	char line[256];
	FILE *f;
	int i;

	(void)rfd;
	printf("F567 DBG|if_inet6_begin\n");
	f = fopen("/proc/net/if_inet6", "r");
	if (f) {
		while (fgets(line, sizeof(line), f))
			printf("F567 DBG6|%s", line);
		fclose(f);
	}
	printf("F567 DBG|if_inet6_end\n");
	for (i = 0; i < 5; i++) {
		unsigned long long a0[6], a1[6];
		int u6a;

		a0[0] = f564_snmp6("Ip6InReceives");
		a0[1] = f564_snmp6("Ip6InAddrErrors");
		a0[2] = f564_snmp6("Ip6InNoRoutes");
		a0[3] = f564_snmp6("Ip6InDiscards");
		a0[4] = f564_snmp6("Ip6InDelivers");
		a0[5] = f564_snmp6("Ip6InMcastPkts");
		f567_drain(U567_6A, NULL);
		pkt_send_p("s0", E[envs[i]].wire, E[envs[i]].wlen,
			   E[envs[i]].sproto);
		usleep(90000);
		u6a = f567_drain(U567_6A, NULL);
		a1[0] = f564_snmp6("Ip6InReceives");
		a1[1] = f564_snmp6("Ip6InAddrErrors");
		a1[2] = f564_snmp6("Ip6InNoRoutes");
		a1[3] = f564_snmp6("Ip6InDiscards");
		a1[4] = f564_snmp6("Ip6InDelivers");
		a1[5] = f564_snmp6("Ip6InMcastPkts");
		printf("F567 DBG|env=%s|i6in=%llu|i6addr=%llu|i6noroute=%llu|"
		       "i6disc=%llu|i6deliv=%llu|i6mcast=%llu|u6a=%d\n",
		       E[envs[i]].tag, a1[0] - a0[0], a1[1] - a0[1],
		       a1[2] - a0[2], a1[3] - a0[3], a1[4] - a0[4],
		       a1[5] - a0[5], u6a);
	}
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "f567";
	struct f567_frame E[K6_NKIND + 1];
	char hx[400];
	int rfd = -1, i;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F567 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F567 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F567 KERNEL|7.3.4-T563\n");
	/* every new device comes up with IPv6 off; only br0 gets it back.
	 * IPv6 delivers a unicast packet only on the device that owns the
	 * address (strict), and the bridge hands the frame up on br0 -- so the
	 * address has to live there, not on i1 like the IPv4 one. */
	f555_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
	f556_env_setup();
	{
		static const char *on[] = { "br0" };
		char path[96];
		int k;

		for (k = 0; k < 1; k++) {
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/dad_transmits", on[k]);
			f555_sysctl(path, "0");
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/accept_dad", on[k]);
			f555_sysctl(path, "0");
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/accept_ra", on[k]);
			f555_sysctl(path, "0");
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", on[k]);
			f555_sysctl(path, "0");
		}
		printf("F567 V6ON|br0=%llu|s1=%llu|s0=%llu\n",
		       f567_read_ll("/proc/sys/net/ipv6/conf/br0/disable_ipv6"),
		       f567_read_ll("/proc/sys/net/ipv6/conf/s1/disable_ipv6"),
		       f567_read_ll("/proc/sys/net/ipv6/conf/s0/disable_ipv6"));
		printf("F567 V6ADDR|rc=%d\n", f564_addr6("br0", F564_V6DST, 128));
		printf("F567 ADDR4|rc=%d\n",
		       f555_addr_add("i1", htonl(0x0a090007), 24));
		usleep(400000);
	}
	NFL67 = nfl_open(5);
	printf("F567 NFL|%d\n", NFL67);

	if (f567_chains()) {
		printf("F567 FAIL|chains\n");
		return 0;
	}

	memset(E, 0, sizeof(E));
	for (i = 0; i < K6_NKIND; i++) {
		E[i].tag = (i == K6_PLAIN) ? "v6" : (i == K6_HBH) ? "hb" :
			   (i == K6_DST) ? "do" : (i == K6_HBDST) ? "hbdo" :
			   (i == K6_FRAG0) ? "fr0" : (i == K6_FRAGN) ? "frn" :
			   (i == K6_NONE) ? "none" : (i == K6_BADEXT) ? "mexth" :
			   (i == K6_DOBAD) ? "mdobad" :
			   (i == K6_TRUNC) ? "mtrunc" : (i == K6_VER5) ? "mver" :
			   "t6";
		E[i].wlen = f567_mk6(E[i].wire, i, 5000);
		E[i].sproto = 0x86dd;
	}
	E[K6_P4].tag = "p4";
	E[K6_P4].wlen = f565_udp4(E[K6_P4].wire, 40000, 5000, 0, 0x77);
	E[K6_P4].sproto = 0x0800;

	for (i = 0; i <= K6_NKIND; i++)
		printf("F567 FRAME|%s|len=%d|wire=%s\n", E[i].tag, E[i].wlen,
		       f559_hexs(hx, sizeof(hx), E[i].wire,
				 E[i].wlen < 128 ? E[i].wlen : 128));

	rfd = cap_open("r0");
	printf("F567 CAP|rfd=%d\n", rfd);
	U567_6A = f564_udp_bind(AF_INET6, 0, F564_V6DST, 5000);
	U567_6B = f564_udp_bind(AF_INET6, 0, F564_V6DST, 5001);
	U567_4A = f564_udp_bind(AF_INET, 0x0a090007, NULL, 5000);
	printf("F567 SOCK|u6a=%d|u6b=%d|u4=%d\n", U567_6A, U567_6B, U567_4A);

	if (!strcmp(mode, "diag"))
		f567_sec_diag(E, rfd);
	else if (!strcmp(mode, "dbg"))
		f567_sec_dbg(E, rfd);
	else if (!strcmp(mode, "td"))
		f567_sec_td(E, rfd);
	else if (!strcmp(mode, "tf"))
		f567_sec_tf(E, rfd);
	else if (!strcmp(mode, "nh"))
		f567_sec_nh(E, rfd);
	else if (!strcmp(mode, "xf"))
		f567_sec_xf(E, rfd);
	else if (!strcmp(mode, "rd"))
		f567_sec_rd(E, rfd);
	else if (!strcmp(mode, "mp"))
		f567_mp_pass("mp", E, rfd);
	else if (!strcmp(mode, "md"))
		f567_sec_md(E, rfd);
	else if (!strcmp(mode, "xc"))
		f567_sec_xc(E, rfd);
	else {
		f567_sec_dbg(E, rfd);
		f567_sec_diag(E, rfd);
		f567_sec_td(E, rfd);
		f567_sec_tf(E, rfd);
		f567_sec_nh(E, rfd);
		f567_sec_xf(E, rfd);
		f567_sec_rd(E, rfd);
		f567_mp_pass("mp", E, rfd);
		f567_sec_xc(E, rfd);
		f567_sec_md(E, rfd);
	}
	printf("F567 DONE\n");
	return 0;
}
