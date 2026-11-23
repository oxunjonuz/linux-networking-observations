
/* ==========================================================================
 * Turn 566 -- F44: the two pktinfo constructors F43 never measured
 * (`nft_set_pktinfo_ipv4()` at the layer-3 hooks of families `ip`/`inet`,
 * and `nft_set_pktinfo_ipv4_ingress()` at the inet ingress door), plus the
 * guard asymmetry the two ingress doors create: `nft_nh_write_ok()` and
 * `nft_in_ingress()` read `pkt->state->pf`, and one of the two handlers
 * rewrites that field before building the pktinfo.
 *
 * differ566.c is GENERATED: differ565.c with its main() renamed to f564_main,
 * plus this file.  Every helper under the new code is byte-for-byte the one
 * that produced F31..F43.
 * ========================================================================== */

#define NFULA_L2HDR_	21	/* nfulnl_attr_type, system header has no name */

static int U566_4B = -1;	/* UDP 10.9.0.7:5001 */
static int NFL66 = -1;

/* ---------- frames ---------- */

struct f566_frame {
	const char *tag;
	unsigned char wire[600];
	int wlen;
	unsigned short sproto;
};

/* ---------- the four doors ---------- */

struct f566_door {
	const char *tag;
	uint8_t fam;
	const char *table;
	const char *dev;	/* NULL for the layer-3 hooks */
	uint32_t hook;
	int prio0;		/* counter-only chain  */
	int prio1;		/* store/read chain    */
};

/* hook numbers: NF_INET_PRE_ROUTING = 0, NF_NETDEV_INGRESS = 1,
 * NF_INET_INGRESS = 5 (uapi/linux/netfilter.h). */
static struct f566_door D566[] = {
	{ "ipp", NFPROTO_IPV4,   "d66a", NULL, 0,  0, 10 },
	{ "inp", NFPROTO_INET,   "d66b", NULL, 0, 20, 30 },
	{ "ndg", NFPROTO_NETDEV, "d66c", "s1", 0, 40, 50 },
	{ "ieg", NFPROTO_INET,   "d66d", "s1", 5,  0, 10 },
};
#define ND66 4

/* ---------- /proc/net/netstat (IPExt), which /proc/net/snmp lacks ---------- */

static unsigned long long f566_netstat(const char *group, const char *field)
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

/* ---------- chains: two per door ----------
 * `pre0` (prio 0)  counter + log("p") + accept   -- did the hook run at all?
 * `ch`   (prio 10) [meta] [store|read] log("s") + counter + accept
 * The two are separate base chains, so an `accept` in the first does not keep
 * the second from running (measured in F37: two base chains, one hook).
 */

static int f566_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND66; i++) {
		struct f566_door *D = &D566[i];

		rc |= add_table(D->fam, D->table);
		rc |= f556_add_chain(D->fam, D->table, "pre0", D->hook,
				     (uint32_t)D->prio0, 1, D->dev);
		rc |= f556_add_chain(D->fam, D->table, "ch", D->hook,
				     (uint32_t)D->prio1, 1, D->dev);
	}
	return rc;
}

static void f566_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND66; i++) {
		f557_flush(D566[i].fam, D566[i].table, "pre0", &acks);
		f557_flush(D566[i].fam, D566[i].table, "ch", &acks);
	}
}

/* mode 0: none; 1: store; 2: read + cmp against `imm` */
static int f566_rule(const struct f566_door *D, const char *chain,
		     const char *prefix, int gate, uint32_t base, int off,
		     int len, const unsigned char *imm, int mode, int *acks)
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
	if (mode == 1)
		f565_store(nlh, base, (uint32_t)off, (uint32_t)len, imm, 0, 0);
	else if (mode == 2) {
		f562_read(nlh, base, (uint32_t)off, (uint32_t)len);
		f562_cmp(nlh, F562_RD_DREG, imm, len);
	}
	log_expr(nlh, 5, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

/* ---------- the NFLOG reader: what the hook saw, after the store ---------- */

struct f566_log {
	int seen;
	int l2;
	int plen;
	unsigned char p[96];
};

static void f566_parse_log(unsigned char *buf, int len, struct f566_log *pre,
			   struct f566_log *post)
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

static void f566_logs(int fd, struct f566_log *pre, struct f566_log *post)
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
		f566_parse_log(b, rl, pre, post);
	}
}

static int f566_drain(int fd, int *firstlen)
{
	unsigned char b[512];
	int n = 0, r;

	if (firstlen)
		*firstlen = -1;
	if (fd < 0)
		return -1;
	while (n < 6) {
		r = (int)recv(fd, b, sizeof(b), MSG_DONTWAIT);
		if (r <= 0)
			break;
		if (n == 0 && firstlen)
			*firstlen = r;
		n++;
	}
	return n;
}

/* ---------- one arm ---------- */

static void f566_arm(const char *sec, const struct f566_door *D,
		     const struct f566_frame *E, const char *arm,
		     int gate, uint32_t base, int off, int len,
		     const unsigned char *imm, int mode, int rfd,
		     const struct f559_out *ctl, struct f559_out *out)
{
	struct f559_out o;
	struct f566_log pre, post;
	unsigned char rf[1024];
	char hi[64], hpre[220], hpost[220], hr[440], cw[440];
	unsigned long long cntp0, cnts0, cntp1, cnts1;
	unsigned long long ip0[4], ip1[4];
	int rcp, rcs, acks, snd, rn = 0, sk = 0, rchg = 0;
	int u5000 = 0, u5001 = 0, f0 = -1, f1 = -1;

	f566_flush_all();
	acks = 0;
	rcp = f566_rule(D, "pre0", "p", 0, 0, 0, 0, NULL, 0, &acks);
	acks = 0;
	rcs = f566_rule(D, "ch", "s", gate, base, off, len, imm, mode, &acks);

	nfl_drain(NFL66);
	cntp0 = f555_count(D->fam, D->table, "pre0");
	cnts0 = f555_count(D->fam, D->table, "ch");
	ip0[0] = f564_snmp("Ip", "InReceives");
	ip0[1] = f564_snmp("Ip", "InHdrErrors");
	ip0[2] = f564_snmp("Ip", "InDelivers");
	ip0[3] = f566_netstat("IpExt", "InTruncatedPkts");
	f566_drain(P564.u4, NULL);
	f566_drain(U566_4B, NULL);
	if (rfd >= 0)
		cap_drain(rfd);
	memset(&o, 0, sizeof(o));
	o.rn = 0;
	o.wpt = -1;
	o.rpt = -1;
	snd = pkt_send_p("s0", E->wire, E->wlen, E->sproto);
	usleep(70000);
	u5000 = f566_drain(P564.u4, &f0);
	u5001 = f566_drain(U566_4B, &f1);
	cntp1 = f555_count(D->fam, D->table, "pre0");
	cnts1 = f555_count(D->fam, D->table, "ch");
	ip1[0] = f564_snmp("Ip", "InReceives");
	ip1[1] = f564_snmp("Ip", "InHdrErrors");
	ip1[2] = f564_snmp("Ip", "InDelivers");
	ip1[3] = f566_netstat("IpExt", "InTruncatedPkts");
	f566_logs(NFL66, &pre, &post);
	if (rfd >= 0) {
		o.rn = f558_cap_match(rfd, rf, (int)sizeof(rf), 250, M561_77, 8,
				      &sk, &o.rpt);
		rn = o.rn;
		if (rn > 0)
			memcpy(o.r, rf, (size_t)(rn < (int)sizeof(o.r) ? rn : (int)sizeof(o.r)));
	}
	if (ctl && ctl->rn > 0 && rn > 0)
		rchg = f558_chg(cw, sizeof(cw), ctl->r, ctl->rn, rf, rn);
	printf("F566 A|sec=%s|door=%s|env=%s|arm=%s|gate=%d|base=%u|off=%d|"
	       "len=%d|mode=%d|imm=%s|rcp=%d|rcs=%d|sendrc=%d|"
	       "cntp0=%llu|cntp=%llu|livep=%llu|cnts0=%llu|cnts=%llu|lives=%llu|",
	       sec, D->tag, E->tag, arm, gate, (unsigned)base, off, len, mode,
	       (mode && len > 0) ? f559_hexs(hi, sizeof(hi), imm, len) : "-",
	       rcp, rcs, snd, cntp0, cntp1, cntp1 - cntp0, cnts0, cnts1,
	       cnts1 - cnts0);
	printf("ipin=%llu|ihdr=%llu|ideliv=%llu|itrun=%llu|u5000=%d|u5001=%d|"
	       "f0=%d|f1=%d|npre=%d|npost=%d|l2=%d|",
	       ip1[0] - ip0[0], ip1[1] - ip0[1], ip1[2] - ip0[2],
	       ip1[3] - ip0[3], u5000, u5001, f0, f1, pre.seen, post.seen,
	       post.l2);
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

/* ---------- specs ---------- */

struct f566_spec {
	const char *arm;
	uint32_t base;
	int off, len;
	unsigned char imm[8];
};

/* the transport base: F43's own eight cells */
static struct f566_spec T566[] = {
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

/* the link base, twelve cells: five inside the first twelve bytes, four on
 * the tag boundary, three past it */
static struct f566_spec L566[] = {
	{ "l0_2",  NFT_PAYLOAD_LL_HEADER, 0, 2, { 0x90, 0x91 } },
	{ "l0_4",  NFT_PAYLOAD_LL_HEADER, 0, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "l6_2",  NFT_PAYLOAD_LL_HEADER, 6, 2, { 0x90, 0x91 } },
	{ "l8_1",  NFT_PAYLOAD_LL_HEADER, 8, 1, { 0x90 } },
	{ "l10_2", NFT_PAYLOAD_LL_HEADER, 10, 2, { 0x90, 0x91 } },
	{ "l12_2", NFT_PAYLOAD_LL_HEADER, 12, 2, { 0x90, 0x91 } },
	{ "l12_4", NFT_PAYLOAD_LL_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "l13_1", NFT_PAYLOAD_LL_HEADER, 13, 1, { 0x90 } },
	{ "l14_2", NFT_PAYLOAD_LL_HEADER, 14, 2, { 0x90, 0x91 } },
	{ "l16_2", NFT_PAYLOAD_LL_HEADER, 16, 2, { 0x90, 0x91 } },
	{ "l20_4", NFT_PAYLOAD_LL_HEADER, 20, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "l24_4", NFT_PAYLOAD_LL_HEADER, 24, 4, { 0x90, 0x91, 0x92, 0x93 } },
};

/* the network base, twenty cells: the whole ip4 whitelist plus twelve cells
 * it does not name */
static struct f566_spec N566[] = {
	{ "n0_1",  NFT_PAYLOAD_NETWORK_HEADER, 0, 1, { 0x90 } },
	{ "n0_2",  NFT_PAYLOAD_NETWORK_HEADER, 0, 2, { 0x90, 0x91 } },
	{ "n0_4",  NFT_PAYLOAD_NETWORK_HEADER, 0, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n1_1",  NFT_PAYLOAD_NETWORK_HEADER, 1, 1, { 0x90 } },
	{ "n2_2",  NFT_PAYLOAD_NETWORK_HEADER, 2, 2, { 0x90, 0x91 } },
	{ "n4_2",  NFT_PAYLOAD_NETWORK_HEADER, 4, 2, { 0x90, 0x91 } },
	{ "n4_4",  NFT_PAYLOAD_NETWORK_HEADER, 4, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n6_2",  NFT_PAYLOAD_NETWORK_HEADER, 6, 2, { 0x90, 0x91 } },
	{ "n6_4",  NFT_PAYLOAD_NETWORK_HEADER, 6, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n8_1",  NFT_PAYLOAD_NETWORK_HEADER, 8, 1, { 0x90 } },
	{ "n8_2",  NFT_PAYLOAD_NETWORK_HEADER, 8, 2, { 0x90, 0x91 } },
	{ "n10_2", NFT_PAYLOAD_NETWORK_HEADER, 10, 2, { 0x90, 0x91 } },
	{ "n10_4", NFT_PAYLOAD_NETWORK_HEADER, 10, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n12_2", NFT_PAYLOAD_NETWORK_HEADER, 12, 2, { 0x90, 0x91 } },
	{ "n12_4", NFT_PAYLOAD_NETWORK_HEADER, 12, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n16_2", NFT_PAYLOAD_NETWORK_HEADER, 16, 2, { 0x90, 0x91 } },
	{ "n16_4", NFT_PAYLOAD_NETWORK_HEADER, 16, 4, { 0x90, 0x91, 0x92, 0x93 } },
	{ "n18_2", NFT_PAYLOAD_NETWORK_HEADER, 18, 2, { 0x90, 0x91 } },
	{ "n20_2", NFT_PAYLOAD_NETWORK_HEADER, 20, 2, { 0x90, 0x91 } },
	{ "n20_4", NFT_PAYLOAD_NETWORK_HEADER, 20, 4, { 0x90, 0x91, 0x92, 0x93 } },
};

/* ---------- sections ---------- */

static void f566_sec_td(struct f566_frame *E, int rfd)
{
	int d, e, i;
	int n = (int)(sizeof(T566) / sizeof(T566[0]));

	for (d = 0; d < ND66; d++) {
		for (e = 0; e < 5; e++) {
			struct f559_out ctl;

			memset(&ctl, 0, sizeof(ctl));
			f566_arm("td", &D566[d], &E[e], "ctl", 0, 0, 0, 0,
				 NULL, 0, rfd, NULL, &ctl);
			for (i = 1; i < n; i++)
				f566_arm("td", &D566[d], &E[e], T566[i].arm, 0,
					 T566[i].base, T566[i].off, T566[i].len,
					 T566[i].imm, 1, rfd, &ctl, NULL);
		}
	}
}

/* meta protocol at the two ingress doors, on the two envelopes whose
 * skb->protocol is not 0x0800 */
static void f566_sec_tm(struct f566_frame *E, int rfd)
{
	static const int doors[2] = { 2, 3 };
	static const int envs[2] = { 3, 4 };
	int di, ei, i;
	int n = (int)(sizeof(T566) / sizeof(T566[0]));

	for (di = 0; di < 2; di++) {
		for (ei = 0; ei < 2; ei++) {
			struct f559_out ctl;

			memset(&ctl, 0, sizeof(ctl));
			f566_arm("tm", &D566[doors[di]], &E[envs[ei]], "ctl", 1,
				 0, 0, 0, NULL, 0, rfd, NULL, &ctl);
			for (i = 1; i < n; i++)
				f566_arm("tm", &D566[doors[di]], &E[envs[ei]],
					 T566[i].arm, 1, T566[i].base,
					 T566[i].off, T566[i].len, T566[i].imm, 1,
					 rfd, &ctl, NULL);
		}
	}
}

static void f566_sec_gd(struct f566_frame *E, int rfd)
{
	int d, i;
	int nl = (int)(sizeof(L566) / sizeof(L566[0]));
	int nn = (int)(sizeof(N566) / sizeof(N566[0]));

	for (d = 2; d <= 3; d++) {
		int e;

		for (e = 0; e <= 1; e++) {
			struct f559_out ctl;

			memset(&ctl, 0, sizeof(ctl));
			f566_arm("gd", &D566[d], &E[e], "ctl", 0, 0, 0, 0,
				 NULL, 0, rfd, NULL, &ctl);
			for (i = 0; i < nl; i++)
				f566_arm("gd", &D566[d], &E[e], L566[i].arm, 0,
					 L566[i].base, L566[i].off, L566[i].len,
					 L566[i].imm, 1, rfd, &ctl, NULL);
		}
	}
	/* the network base, bare frame only: the whitelist is the point */
	for (d = 2; d <= 3; d++) {
		struct f559_out ctl;

		memset(&ctl, 0, sizeof(ctl));
		f566_arm("gn", &D566[d], &E[0], "ctl", 0, 0, 0, 0, NULL, 0, rfd,
			 NULL, &ctl);
		for (i = 0; i < nn; i++)
			f566_arm("gn", &D566[d], &E[0], N566[i].arm, 0,
				 N566[i].base, N566[i].off, N566[i].len,
				 N566[i].imm, 1, rfd, &ctl, NULL);
	}
}

/* read == write? three cells whose value in the frame is known */
static void f566_sec_rf(struct f566_frame *E, int rfd)
{
	static const struct {
		const char *arm;
		int off, len;
		unsigned char imm[2];
	} rd[3] = {
		{ "r0_2", 0, 2, { 0x9c, 0x40 } },	/* sport 40000 */
		{ "r2_2", 2, 2, { 0x13, 0x88 } },	/* dport 5000  */
		{ "r6_2", 6, 2, { 0x00, 0x00 } },	/* csum 0      */
	};
	int d, i;

	for (d = 0; d < ND66; d++) {
		struct f559_out ctl;

		memset(&ctl, 0, sizeof(ctl));
		for (i = 0; i < 3; i++)
			f566_arm("rf", &D566[d], &E[0], rd[i].arm, 0,
				 NFT_PAYLOAD_TRANSPORT_HEADER, rd[i].off,
				 rd[i].len, rd[i].imm, 2, rfd, NULL, NULL);
	}
}

/* the socket oracle for "the write landed on the true dport": write 5001
 * into @th,2,2 and ask the UDP socket bound to 10.9.0.7:5001 */
static void f566_sec_dp(struct f566_frame *E, int rfd)
{
	static const int envs[2] = { 0, 4 };	/* p and ps */
	unsigned char imm[2] = { 0x13, 0x89 };
	int d, e;

	for (d = 0; d < ND66; d++)
		for (e = 0; e < 2; e++)
			f566_arm("dp", &D566[d], &E[envs[e]], "dp5001", 0,
				 NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, imm, 1, rfd,
				 NULL, NULL);
}

/* malformed IPv4.  The two ingress doors live in ONE per-device hook list,
 * and the inet door's handler validates before any rule of either family can
 * run -- so the netdev door is measured twice: once with the inet ingress
 * chains present (they drop the frame first) and once with that table gone.
 */
static void f566_md_pass(const char *sec, struct f566_door *D,
			 struct f566_frame *M, int rfd)
{
	static const char *names[3] = { "badver", "ihl4", "trunc" };
	unsigned char imm[1] = { 0x90 };
	int i;

	for (i = 0; i < 3; i++) {
		struct f559_out ctl;

		memset(&ctl, 0, sizeof(ctl));
		f566_arm(sec, D, &M[i], "ctl", 0, 0, 0, 0, NULL, 0, rfd, NULL,
			 &ctl);
		f566_arm(sec, D, &M[i], names[i], 0,
			 NFT_PAYLOAD_NETWORK_HEADER, 8, 1, imm, 1, rfd, &ctl,
			 NULL);
	}
}

static void f566_sec_md(struct f566_frame *M, int rfd)
{
	int i, acks;

	/* 1. both doors present, inet ingress first by priority */
	f566_md_pass("md_both", &D566[2], M, rfd);

	/* 2. the inet ingress table deleted: the netdev door alone */
	sh("/nft delete table inet d66d");
	printf("F566 MD|deleted=inet d66d\n");
	f566_md_pass("md_ndg", &D566[2], M, rfd);

	/* 3. bring the inet ingress door back, delete the netdev one */
	add_table(NFPROTO_INET, "d66d");
	for (i = 3; i <= 3; i++) {
		f556_add_chain(D566[i].fam, D566[i].table, "pre0",
			       D566[i].hook, (uint32_t)D566[i].prio0, 1,
			       D566[i].dev);
		f556_add_chain(D566[i].fam, D566[i].table, "ch",
			       D566[i].hook, (uint32_t)D566[i].prio1, 1,
			       D566[i].dev);
	}
	sh("/nft delete table netdev d66c");
	printf("F566 MD|deleted=netdev d66c\n");
	f566_md_pass("md_ieg", &D566[3], M, rfd);
	(void)acks;
}

/* ---------- diagnostic: which of the eight chains see which frame ---------- */

static void f566_sec_diag(struct f566_frame *E, struct f566_frame *M, int rfd)
{
	int i, e, acks, brc = -1, tfd;
	unsigned long long c0[ND66], c1[ND66], b0, b1;
	struct f566_frame *all[8];
	unsigned long long ip0, ih0, it0;

	for (e = 0; e < 5; e++)
		all[e] = &E[e];
	for (e = 0; e < 3; e++)
		all[5 + e] = &M[e];

	/* a fifth counter at the bridge family, to tell "reached the bridge"
	 * from "reached the stack" */
	add_table(NFPROTO_BRIDGE, "b66z");
	brc = f556_add_chain(NFPROTO_BRIDGE, "b66z", "pre", 0, 0, 1, NULL);
	f566_rule(&D566[0], "pre0", "p", 0, 0, 0, 0, NULL, 0, &acks);
	printf("F566 DIAG|capfd=%d|bridge=%d\n", rfd, brc);
	tfd = cap_open("s1");
	printf("F566 DIAG|tap_s1=%d\n", tfd);
	for (i = 0; i < ND66; i++)
		f566_rule(&D566[i], "ch", "s", 0, 0, 0, 0, NULL, 0, &acks);
	{
		struct nlmsghdr *nlh;
		struct nlattr *exprs;

		nlh = msg_start(opbuf, (int)sizeof(opbuf),
				(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
				NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
				NFPROTO_BRIDGE);
		put_str(nlh, NFTA_RULE_TABLE, "b66z");
		put_str(nlh, NFTA_RULE_CHAIN, "pre");
		exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
		counter_expr(nlh);
		accept_expr(nlh);
		nest_end(nlh, exprs);
		f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
	}
	for (e = 0; e < 8; e++) {
		unsigned char buf[1024], rb[1024];
		int got = 0, sk2 = 0, pt = -1;

		for (i = 0; i < ND66; i++)
			c0[i] = f555_count(D566[i].fam, D566[i].table, "ch");
		b0 = f555_count(NFPROTO_BRIDGE, "b66z", "pre");
		ip0 = f564_snmp("Ip", "InReceives");
		ih0 = f564_snmp("Ip", "InHdrErrors");
		it0 = f566_netstat("IpExt", "InTruncatedPkts");
		if (tfd >= 0)
			cap_drain(tfd);
		pkt_send_p("s0", all[e]->wire, all[e]->wlen, all[e]->sproto);
		if (tfd >= 0) {
			got = f558_cap_match(tfd, buf, (int)sizeof(buf), 300,
					     M561_77, 8, &sk2, &pt);
			if (got <= 0)
				got = 0;
			(void)rb;
		}
		usleep(60000);
		for (i = 0; i < ND66; i++)
			c1[i] = f555_count(D566[i].fam, D566[i].table, "ch");
		b1 = f555_count(NFPROTO_BRIDGE, "b66z", "pre");
		printf("F566 DIAG|env=%s|ipp=%llu|inp=%llu|ndg=%llu|ieg=%llu|"
		       "br=%llu|s1=%d|s1pt=%d|ipin=%llu|ihdr=%llu|itrun=%llu\n",
		       all[e]->tag, c1[0] - c0[0], c1[1] - c0[1], c1[2] - c0[2],
		       c1[3] - c0[3], b1 - b0, got, pt,
		       f564_snmp("Ip", "InReceives") - ip0,
		       f564_snmp("Ip", "InHdrErrors") - ih0,
		       f566_netstat("IpExt", "InTruncatedPkts") - it0);
	}
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "f566";
	unsigned char plain[256], v6[256];
	struct f566_frame E[5], M[3];
	int plen, rfd = -1, i;

	set_up("lo");
	f556_fams();
	printf("F566 KERNEL|7.3.4-T563\n");
	{
		int rc = add_table(NFPROTO_INET, "d66probe");

		printf("F566 FAM|inet|%d\n", rc);
		if (rc == 0)
			sh("/nft delete table inet d66probe");
	}
	f556_env_setup();
	{
		static const char *dv[] = { "all", "default", "lo", "i0", "i1",
					    "s0", "s1", "r0", "r1", "br0" };
		char path[96];

		for (i = 0; i < (int)(sizeof(dv) / sizeof(dv[0])); i++) {
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/disable_ipv6", dv[i]);
			f555_sysctl(path, "1");
		}
	}
	NFL66 = nfl_open(5);
	printf("F566 NFL|%d\n", NFL66);

	if (f566_chains()) {
		printf("F566 FAIL|chains\n");
		return 0;
	}

	/* ---- the frames ---- */
	plen = f565_udp4(plain, 40000, 5000, 0, 0x77);
	memset(E, 0, sizeof(E));
	memset(M, 0, sizeof(M));
	E[0].tag = "p";
	memcpy(E[0].wire, plain, (size_t)plen);
	E[0].wlen = plen;
	E[0].sproto = 0x0800;
	{
		unsigned char tg[4] = { 0x81, 0x00, 0x00, 0x64 };

		E[1].tag = "w";
		E[1].wlen = f565_tagged(E[1].wire, plain, plen, tg, 1);
		E[1].sproto = 0x8100;
	}
	{
		/* the same four bytes, vid 0: the priority tag F36 measured as
		 * deliverable, unlike vid 100 */
		unsigned char tg[4] = { 0x81, 0x00, 0x00, 0x00 };

		E[2].tag = "w0";
		E[2].wlen = f565_tagged(E[2].wire, plain, plen, tg, 1);
		E[2].sproto = 0x8100;
	}
	{
		unsigned char tg[8] = { 0x88, 0xa8, 0x00, 0xc8,
					0x81, 0x00, 0x00, 0x64 };

		E[3].tag = "q";
		E[3].wlen = f565_tagged(E[3].wire, plain, plen, tg, 2);
		E[3].sproto = 0x88a8;
	}
	E[4].tag = "ps";
	E[4].wlen = f563_pppoe(plain, plen, E[4].wire, 99, 0x0021);
	E[4].sproto = 0x8864;

	/* malformed: version 6, ihl 4, totlen 300 */
	M[0].tag = "badver";
	memcpy(M[0].wire, plain, (size_t)plen);
	M[0].wire[14] = 0x65;
	M[0].wlen = plen;
	M[0].sproto = 0x0800;
	M[1].tag = "ihl4";
	memcpy(M[1].wire, plain, (size_t)plen);
	M[1].wire[14] = 0x44;
	M[1].wlen = plen;
	M[1].sproto = 0x0800;
	M[2].tag = "trunc";
	memcpy(M[2].wire, plain, (size_t)plen);
	M[2].wire[16] = 0x01;
	M[2].wire[17] = 0x2c;
	M[2].wlen = plen;
	M[2].sproto = 0x0800;

	for (i = 0; i < 5; i++)
		printf("F566 FRAME|%s|len=%d|sproto=%04x|wire=%s\n", E[i].tag,
		       E[i].wlen, E[i].sproto,
		       f559_hexs((char *)v6, sizeof(v6), E[i].wire,
				 E[i].wlen < 96 ? E[i].wlen : 96));
	for (i = 0; i < 3; i++)
		printf("F566 MFRAME|%s|len=%d|wire=%s\n", M[i].tag, M[i].wlen,
		       f559_hexs((char *)v6, sizeof(v6), M[i].wire,
				 M[i].wlen < 96 ? M[i].wlen : 96));

	rfd = cap_open("r0");
	printf("F566 CAP|rfd=%d\n", rfd);
	if (f564_ppp_setup()) {
		printf("F566 FAIL|ppp\n");
		return 0;
	}
	U566_4B = f564_udp_bind(AF_INET, 0x0a090007, NULL, 5001);
	printf("F566 SOCK|u4_5000=%d|u4_5001=%d\n", P564.u4, U566_4B);

	if (!strcmp(mode, "diag")) {
		f566_sec_diag(E, M, rfd);
	} else if (!strcmp(mode, "td")) {
		f566_sec_td(E, rfd);
	} else if (!strcmp(mode, "tm")) {
		f566_sec_tm(E, rfd);
	} else if (!strcmp(mode, "gd")) {
		f566_sec_gd(E, rfd);
	} else if (!strcmp(mode, "rf")) {
		f566_sec_rf(E, rfd);
	} else if (!strcmp(mode, "dp")) {
		f566_sec_dp(E, rfd);
	} else if (!strcmp(mode, "md")) {
		f566_sec_md(M, rfd);
	} else {
		f566_sec_td(E, rfd);
		f566_sec_tm(E, rfd);
		f566_sec_gd(E, rfd);
		f566_sec_rf(E, rfd);
		f566_sec_dp(E, rfd);
		f566_sec_md(M, rfd);
	}
	printf("F566 DONE\n");
	return 0;
}
