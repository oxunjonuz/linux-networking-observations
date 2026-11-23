
/* ==========================================================================
 * Turn 565 -- F43: the transport base (@th), its three coordinate systems,
 * and the checksum the guard does not pay for.
 *
 * differ565.c is GENERATED: differ564.c with its main() renamed to f564_main,
 * plus this file.  Every helper under the new code is byte-for-byte the one
 * that produced F31..F42; nothing here re-implements netlink, veth, the PPPoX
 * socket or the AF_PACKET tap.
 * ========================================================================== */

static int U565_4B = -1;	/* UDP 10.9.0.7:5001  (the port the rule writes) */
static int U565_6B = -1;	/* UDP [fd00::99:9]:5001                         */

/* ---------- frames ---------- */

/* eth + IPv4 (ihl 5) + UDP + 18 bytes of `fill`.  csum != 0 puts a real
 * UDP checksum in bytes 40..41; with csum == 0 the field stays 0, which is the
 * legal IPv4 "not computed" value the earlier turns measured on. */
static int f565_udp4(unsigned char *out, unsigned short sport,
		     unsigned short dport, int csum, unsigned char fill)
{
	int tot = 20 + 26;
	unsigned char *ip = out + 14, *u = out + 34;
	unsigned int acc;
	unsigned short c;

	memset(out, 0, 256);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = 0x08;
	out[13] = 0x00;
	ip[0] = 0x45;
	ip[2] = (unsigned char)(tot >> 8);
	ip[3] = (unsigned char)tot;
	ip[4] = 0x12;
	ip[5] = 0x34;
	ip[8] = 64;
	ip[9] = 17;
	ip[12] = 0x0a; ip[13] = 0x01; ip[14] = 0x00; ip[15] = 0x01;
	ip[16] = 0x0a; ip[17] = 0x09; ip[18] = 0x00; ip[19] = 0x07;
	c = f556_csum(ip, 20);
	ip[10] = (unsigned char)(c >> 8);
	ip[11] = (unsigned char)c;
	u[0] = (unsigned char)(sport >> 8);
	u[1] = (unsigned char)sport;
	u[2] = (unsigned char)(dport >> 8);
	u[3] = (unsigned char)dport;
	u[4] = 0x00;
	u[5] = 26;
	u[6] = 0x00;
	u[7] = 0x00;
	memset(u + 8, fill, 18);
	if (csum) {
		acc = f564_sum(ip + 12, 8, 0);	/* saddr + daddr */
		acc += 17;			/* protocol       */
		acc += 26;			/* UDP length     */
		acc = f564_sum(u, 26, acc);
		c = f564_fold(acc);
		if (!c)
			c = 0xffff;
		u[6] = (unsigned char)(c >> 8);
		u[7] = (unsigned char)c;
	}
	return 14 + tot;
}

/* eth + IPv4 (proto 6) + TCP (doff 5, SYN) + 18 bytes of 0x77 */
static int f565_tcp4(unsigned char *out, unsigned short sport,
		     unsigned short dport)
{
	int tot = 20 + 20 + 18;
	unsigned char *ip = out + 14, *t = out + 34;
	unsigned short c;

	memset(out, 0, 256);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = 0x08;
	out[13] = 0x00;
	ip[0] = 0x45;
	ip[2] = (unsigned char)(tot >> 8);
	ip[3] = (unsigned char)tot;
	ip[4] = 0x12;
	ip[5] = 0x34;
	ip[8] = 64;
	ip[9] = 6;
	ip[12] = 0x0a; ip[13] = 0x01; ip[14] = 0x00; ip[15] = 0x01;
	ip[16] = 0x0a; ip[17] = 0x09; ip[18] = 0x00; ip[19] = 0x07;
	c = f556_csum(ip, 20);
	ip[10] = (unsigned char)(c >> 8);
	ip[11] = (unsigned char)c;
	t[0] = (unsigned char)(sport >> 8);
	t[1] = (unsigned char)sport;
	t[2] = (unsigned char)(dport >> 8);
	t[3] = (unsigned char)dport;
	t[5] = 0x01;			/* seq = 1 */
	t[12] = 0x50;			/* data offset 5, reserved 0 */
	t[13] = 0x02;			/* SYN */
	t[14] = 0x20;
	t[15] = 0x00;
	memset(t + 20, 0x77, 18);
	return 14 + tot;
}

/* put `ntag` tags (4 bytes each) between the two MACs and the ethertype */
static int f565_tagged(unsigned char *out, const unsigned char *in, int inlen,
		       const unsigned char *tags, int ntag)
{
	memcpy(out, in, 12);
	memcpy(out + 12, tags, (size_t)(4 * ntag));
	memcpy(out + 12 + 4 * ntag, in + 12, (size_t)(inlen - 12));
	return inlen + 4 * ntag;
}

/* ---------- one payload-set expression, with or without the inet csum ---------- */

static void f565_store(struct nlmsghdr *nlh, uint32_t base, uint32_t off,
		       uint32_t len, const unsigned char *imm,
		       int csum, unsigned int csum_off)
{
	struct nlattr *e, *d;

	imm_value(nlh, F562_WR_SREG, imm, (int)len);
	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "payload");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_PAYLOAD_SREG, F562_WR_SREG);
	put_be32(nlh, NFTA_PAYLOAD_BASE, base);
	put_be32(nlh, NFTA_PAYLOAD_OFFSET, off);
	put_be32(nlh, NFTA_PAYLOAD_LEN, len);
	put_be32(nlh, NFTA_PAYLOAD_CSUM_TYPE, (uint32_t)csum);
	put_be32(nlh, NFTA_PAYLOAD_CSUM_OFFSET, csum ? csum_off : 0);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

static int f565_install(uint8_t fam, const char *table, const char *chain,
			const char *pre, int gate, uint32_t base,
			int off, int len, const unsigned char *imm,
			int csum, unsigned int csum_off)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	int acks = 0;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			fam);
	put_str(nlh, NFTA_RULE_TABLE, table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	if (gate)
		f562_meta_proto(nlh);
	if (len > 0)
		f565_store(nlh, base, (uint32_t)off, (uint32_t)len, imm, csum,
			   csum_off);
	counter_expr(nlh);
	accept_expr(nlh);
	log_expr(nlh, 5, pre);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

/* ---------- one arm ---------- */

struct f565_env {
	const char *tag;
	unsigned char wire[512];
	int wlen;
	unsigned short sproto;
};

struct f565_spec {
	const char *arm;
	uint32_t base;
	int off, len;
	unsigned char imm[16];
	int csum;
	unsigned int csum_off;
	const char *what;
};

static void f565_run(const char *sec, const struct f565_env *E,
		     struct f565_spec *S, int n, int gate, int rfd)
{
	int i;

	for (i = 0; i < n; i++) {
		struct f559_out o;
		unsigned char rf[1024], r4[512], r6[512], sc[512];
		unsigned long long ip0[6], ip1[6], pb, pp, pb1, pp1;
		char hi[80], hr[420], h4a[220], h4b[220];
		int rn, sk, u4a = -2, u4b = -2, u6a = -2, u6b = -2;
		int n4a = 0, n4b = 0, n6a = 0, n6b = 0;

		memset(&o, 0, sizeof(o));
		memset(ip0, 0, sizeof(ip0));
		r4[0] = 0;
		r6[0] = 0;
		if (P564.u4 >= 0)
			while (recv(P564.u4, sc, sizeof(sc), MSG_DONTWAIT) >= 0)
				;
		if (U565_4B >= 0)
			while (recv(U565_4B, sc, sizeof(sc), MSG_DONTWAIT) >= 0)
				;
		if (P564.u6 >= 0)
			while (recv(P564.u6, sc, sizeof(sc), MSG_DONTWAIT) >= 0)
				;
		if (U565_6B >= 0)
			while (recv(U565_6B, sc, sizeof(sc), MSG_DONTWAIT) >= 0)
				;
		snprintf(PRE57, sizeof(PRE57), "f65.%s.%s", E->tag, S[i].arm);
		f557_flush(NFPROTO_BRIDGE, "p65", "g", &o.acks);
		o.rc = f565_install(NFPROTO_BRIDGE, "p65", "g", PRE57,
				    S[i].len > 0 ? gate : 0, S[i].base,
				    S[i].off, S[i].len, S[i].imm, S[i].csum,
				    S[i].csum_off);
		nfl_drain(NFL59);
		o.cnt0 = f555_count(NFPROTO_BRIDGE, "p65", "g");
		ip0[0] = f564_snmp("Ip", "InReceives");
		ip0[1] = f564_snmp("Ip", "InHdrErrors");
		ip0[2] = f564_snmp("Ip", "InDelivers");
		ip0[3] = f564_snmp("Udp", "InErrors");
		ip0[4] = f564_snmp6("Ip6InReceives");
		ip0[5] = f564_snmp6("Udp6InErrors");
		f564_devrx(P564.dev, &pb, &pp);
		if (rfd >= 0)
			cap_drain(rfd);
		o.snd = pkt_send_p("s0", E->wire, E->wlen, E->sproto);
		usleep(60000);
		if (P564.u4 >= 0) {
			u4a = (int)recv(P564.u4, r4, sizeof(r4), MSG_DONTWAIT);
			if (u4a > 0)
				n4a = u4a;
		}
		if (U565_4B >= 0) {
			u4b = (int)recv(U565_4B, r4 + 300, 200, MSG_DONTWAIT);
			if (u4b > 0)
				n4b = u4b;
		}
		if (P564.u6 >= 0) {
			u6a = (int)recv(P564.u6, r6, sizeof(r6), MSG_DONTWAIT);
			if (u6a > 0)
				n6a = u6a;
		}
		if (U565_6B >= 0) {
			u6b = (int)recv(U565_6B, r6 + 300, 200, MSG_DONTWAIT);
			if (u6b > 0)
				n6b = u6b;
		}
		ip1[0] = f564_snmp("Ip", "InReceives");
		ip1[1] = f564_snmp("Ip", "InHdrErrors");
		ip1[2] = f564_snmp("Ip", "InDelivers");
		ip1[3] = f564_snmp("Udp", "InErrors");
		ip1[4] = f564_snmp6("Ip6InReceives");
		ip1[5] = f564_snmp6("Udp6InErrors");
		f564_devrx(P564.dev, &pb1, &pp1);
		o.cnt = f555_count(NFPROTO_BRIDGE, "p65", "g");
		rn = f558_cap_match(rfd, rf, (int)sizeof(rf), 250, M561_77, 8,
				    &sk, &o.rpt);
		printf("F565 R|sec=%s|env=%s|arm=%s|gate=%d|base=%u|off=%d|len=%d|"
		       "csum=%d|coff=%u|imm=%s|what=%s|rc=%d|acks=%d|snd=%d|"
		       "cnt0=%llu|cnt=%llu|live=%llu|ipin=%llu|ihdr=%llu|"
		       "ideliv=%llu|udperr=%llu|i6in=%llu|u6err=%llu|"
		       "u5000=%d|u5001=%d|u6_5000=%d|u6_5001=%d|"
		       "prx=%llu|prp=%llu|rn=%d|rpt=%d|rhex=%s|h5000=%s|h5001=%s|"
		       "h6_5000=%s|h6_5001=%s\n",
		       sec, E->tag, S[i].arm, S[i].len > 0 ? gate : 0,
		       (unsigned)S[i].base, S[i].off, S[i].len, S[i].csum,
		       S[i].csum_off,
		       S[i].len > 0 ? f559_hexs(hi, sizeof(hi), S[i].imm,
						S[i].len) : "-",
		       S[i].what, o.rc, o.acks, o.snd, o.cnt0, o.cnt,
		       o.cnt - o.cnt0, ip1[0] - ip0[0], ip1[1] - ip0[1],
		       ip1[2] - ip0[2], ip1[3] - ip0[3], ip1[4] - ip0[4],
		       ip1[5] - ip0[5], u4a, u4b, u6a, u6b, pb1 - pb, pp1 - pp,
		       rn, o.rpt,
		       rn > 0 ? f559_hexs(hr, sizeof(hr), rf, rn < 96 ? rn : 96) : "-",
		       n4a > 0 ? f559_hexs(h4a, sizeof(h4a), r4, n4a) : "-",
		       n4b > 0 ? f559_hexs(h4b, sizeof(h4b), r4 + 300, n4b) : "-",
		       n6a > 0 ? "seen" : "-", n6b > 0 ? "seen" : "-");
	}
}

/* ---------- the arm tables ---------- */

static struct f565_spec G565[] = {
	{ "ctl",  0, 0, 0, { 0 }, 0, 0, "control: counter and accept only" },
	{ "t0_2", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x90, 0x91 }, 0, 0,
	  "sport" },
	{ "t2_2", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x90, 0x91 }, 0, 0,
	  "dport" },
	{ "t4_2", NFT_PAYLOAD_TRANSPORT_HEADER, 4, 2, { 0x90, 0x91 }, 0, 0,
	  "udp length" },
	{ "t6_2", NFT_PAYLOAD_TRANSPORT_HEADER, 6, 2, { 0x90, 0x91 }, 0, 0,
	  "udp checksum" },
	{ "t8_2", NFT_PAYLOAD_TRANSPORT_HEADER, 8, 2, { 0x90, 0x91 }, 0, 0,
	  "first payload word" },
	{ "t0_4", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 4, { 0x90, 0x91, 0x92, 0x93 },
	  0, 0, "sport+dport" },
	{ "t12_4", NFT_PAYLOAD_TRANSPORT_HEADER, 12, 4,
	  { 0x90, 0x91, 0x92, 0x93 }, 0, 0, "payload" },
	{ "t16_2", NFT_PAYLOAD_TRANSPORT_HEADER, 16, 2, { 0x90, 0x91 }, 0, 0,
	  "payload" },
};

static struct f565_spec T565[] = {
	{ "ctl",  0, 0, 0, { 0 }, 0, 0, "control: counter and accept only" },
	{ "t0_2", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x90, 0x91 }, 0, 0,
	  "tcp sport" },
	{ "t10_4", NFT_PAYLOAD_TRANSPORT_HEADER, 10, 4,
	  { 0x90, 0x91, 0x92, 0x93 }, 0, 0, "straddles ack_seq's first byte" },
	{ "t12_1", NFT_PAYLOAD_TRANSPORT_HEADER, 12, 1, { 0x90 }, 0, 0,
	  "ack_seq, len 1" },
	{ "t12_2", NFT_PAYLOAD_TRANSPORT_HEADER, 12, 2, { 0x90, 0x91 }, 0, 0,
	  "ack_seq, len 2" },
	{ "t12_4", NFT_PAYLOAD_TRANSPORT_HEADER, 12, 4,
	  { 0x90, 0x91, 0x92, 0x93 }, 0, 0, "ack_seq, len 4" },
	{ "t16_2", NFT_PAYLOAD_TRANSPORT_HEADER, 16, 2, { 0x90, 0x91 }, 0, 0,
	  "after ack_seq: flags + window" },
};

/* the same cell, three bases, one packet */
static struct f565_spec R565[] = {
	{ "ll0", NFT_PAYLOAD_LL_HEADER, 0, 2, { 0x90, 0x91 }, 0, 0,
	  "@ll 0: destination MAC" },
	{ "nh0", NFT_PAYLOAD_NETWORK_HEADER, 0, 2, { 0x11, 0x91 }, 0, 0,
	  "@nh 0: the store offset is skb_network_offset() alone (case 0 compares the value with data[0], so the first byte must be the old one)" },
	{ "th0", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x90, 0x91 }, 0, 0,
	  "@th 0: the true sport" },
};

/* the checksum section: a datagram whose UDP checksum is real */
static struct f565_spec C565[] = {
	{ "ctl",  0, 0, 0, { 0 }, 0, 0, "control: no store" },
	{ "dp_nc", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x13, 0x89 }, 0, 0,
	  "dport -> 5001, no csum update" },
	{ "dp_cs", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x13, 0x89 }, 1, 6,
	  "dport -> 5001, CSUM_INET at offset 6" },
	{ "sp_cs", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x99, 0x99 }, 1, 6,
	  "sport -> 0x9999, CSUM_INET" },
	{ "ck_nc", NFT_PAYLOAD_TRANSPORT_HEADER, 6, 2, { 0x90, 0x91 }, 0, 0,
	  "the checksum field itself, no update" },
	{ "ck_cs", NFT_PAYLOAD_TRANSPORT_HEADER, 6, 2, { 0x90, 0x91 }, 1, 6,
	  "the checksum field itself, CSUM_INET at the same offset" },
	{ "pay_cs", NFT_PAYLOAD_TRANSPORT_HEADER, 24, 2, { 0x90, 0x91 }, 1, 6,
	  "payload byte, CSUM_INET" },
	{ "pay_nc", NFT_PAYLOAD_TRANSPORT_HEADER, 24, 2, { 0x90, 0x91 }, 0, 0,
	  "payload byte, no update" },
};

static struct f565_spec V565[] = {
	{ "ctl",  0, 0, 0, { 0 }, 0, 0, "control: no store" },
	{ "t0_2", NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, { 0x90, 0x91 }, 0, 0,
	  "udp6 sport" },
	{ "t2_2", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x90, 0x91 }, 0, 0,
	  "udp6 dport" },
	{ "t6_2", NFT_PAYLOAD_TRANSPORT_HEADER, 6, 2, { 0x90, 0x91 }, 0, 0,
	  "udp6 checksum" },
	{ "t8_2", NFT_PAYLOAD_TRANSPORT_HEADER, 8, 2, { 0x90, 0x91 }, 0, 0,
	  "udp6 first payload word" },
	{ "dp_nc", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x13, 0x89 }, 0, 0,
	  "udp6 dport -> 5001, no csum update (IPv6 has no 'not computed')" },
	{ "dp_cs", NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, { 0x13, 0x89 }, 1, 6,
	  "udp6 dport -> 5001, CSUM_INET at offset 6" },
};

/* ---------- the sections ---------- */

static void f565_setup(void)
{
	U565_4B = f564_udp_bind(AF_INET, 0x0a090007, NULL, 5001);
	U565_6B = f564_udp_bind(AF_INET6, 0, F564_V6DST, 5001);
	printf("F565 SOCK|u4_5001=%d|u6_5001=%d\n", U565_4B, U565_6B);
}

static void f565_print_frames(struct f565_env *E, int n)
{
	int i;
	char h[600];

	for (i = 0; i < n; i++)
		printf("F565 FRAME|%s|len=%d|proto=%04x|wire=%s\n", E[i].tag,
		       E[i].wlen, E[i].sproto,
		       f559_hexs(h, sizeof(h), E[i].wire, E[i].wlen));
}

static void f565_sec_grid(struct f565_env *E, int rfd)
{
	int g;

	for (g = 0; g <= 1; g++) {
		f565_run("thg", &E[0], G565,
			 (int)(sizeof(G565) / sizeof(G565[0])), g, rfd);
		f565_run("thg", &E[1], G565,
			 (int)(sizeof(G565) / sizeof(G565[0])), g, rfd);
		f565_run("thg", &E[2], G565,
			 (int)(sizeof(G565) / sizeof(G565[0])), g, rfd);
		f565_run("thg", &E[3], G565,
			 (int)(sizeof(G565) / sizeof(G565[0])), g, rfd);
	}
}

static void f565_sec_tcp(struct f565_env *E, int rfd)
{
	f565_run("tht", &E[4], T565, (int)(sizeof(T565) / sizeof(T565[0])), 0,
		 rfd);
	f565_run("tht", &E[5], T565, (int)(sizeof(T565) / sizeof(T565[0])), 0,
		 rfd);
	f565_run("tht", &E[5], T565, (int)(sizeof(T565) / sizeof(T565[0])), 1,
		 rfd);
}

static void f565_sec_reach(struct f565_env *E, int rfd)
{
	f565_run("thr", &E[3], R565, (int)(sizeof(R565) / sizeof(R565[0])), 1,
		 rfd);
}

static void f565_sec_csum(struct f565_env *E, int rfd)
{
	f565_run("cs", &E[6], C565, (int)(sizeof(C565) / sizeof(C565[0])), 0,
		 rfd);
	f565_run("cs", &E[7], C565, (int)(sizeof(C565) / sizeof(C565[0])), 1,
		 rfd);
}

static void f565_sec_v6(struct f565_env *E, int rfd)
{
	f565_run("v6", &E[8], V565, (int)(sizeof(V565) / sizeof(V565[0])), 0,
		 rfd);
	f565_run("v6", &E[8], V565, (int)(sizeof(V565) / sizeof(V565[0])), 1,
		 rfd);
}

int main(int argc, char **argv)
{
	static struct f565_env E[9];
	const char *mode = argc > 1 ? argv[1] : "f565";
	unsigned char plain[256], plain_c[256], tcp[256], v6[256];
	int plen, plen_c, tlen, v6len, rfd;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F565 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F565 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F565 KERNEL|7.3.4-T563\n");
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
	printf("F565 NFL|%d\n", NFL59);

	if (add_table(NFPROTO_BRIDGE, "p65") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p65", "g", 0, 0, 1, NULL)) {
		printf("F565 FAIL|chain\n");
		return 0;
	}

	plen = f565_udp4(plain, 40000, 5000, 0, 0x77);
	plen_c = f565_udp4(plain_c, 40000, 5000, 1, 0x77);
	tlen = f565_tcp4(tcp, 40000, 5000);
	v6len = f556_mk_ip6(v6, 0, 64);
	f564_udp6_csum(v6 + 14, 26);	/* the helper wants the IPv6 header */

	/* 0: bare */
	E[0].tag = "p";
	memcpy(E[0].wire, plain, (size_t)plen);
	E[0].wlen = plen;
	E[0].sproto = 0x0800;
	/* 1: one 802.1Q tag, vid 100 */
	{
		unsigned char tg[4] = { 0x81, 0x00, 0x00, 0x64 };

		E[1].tag = "w";
		E[1].wlen = f565_tagged(E[1].wire, plain, plen, tg, 1);
		E[1].sproto = 0x8100;
	}
	/* 2: Q-in-Q 0x88a8 vid 200 + 0x8100 vid 100 */
	{
		unsigned char tg[8] = { 0x88, 0xa8, 0x00, 0xc8,
					0x81, 0x00, 0x00, 0x64 };

		E[2].tag = "q";
		E[2].wlen = f565_tagged(E[2].wire, plain, plen, tg, 2);
		E[2].sproto = 0x88a8;
	}
	/* 3: PPPoE session */
	E[3].tag = "ps";
	E[3].wlen = f563_pppoe(plain, plen, E[3].wire, 99, 0x0021);
	E[3].sproto = 0x8864;
	/* 4: bare TCP */
	E[4].tag = "pt";
	memcpy(E[4].wire, tcp, (size_t)tlen);
	E[4].wlen = tlen;
	E[4].sproto = 0x0800;
	/* 5: TCP inside PPPoE */
	E[5].tag = "pst";
	E[5].wlen = f563_pppoe(tcp, tlen, E[5].wire, 99, 0x0021);
	E[5].sproto = 0x8864;
	/* 6: bare, real UDP checksum */
	E[6].tag = "pu";
	memcpy(E[6].wire, plain_c, (size_t)plen_c);
	E[6].wlen = plen_c;
	E[6].sproto = 0x0800;
	/* 7: the same datagram inside PPPoE */
	E[7].tag = "psu";
	E[7].wlen = f563_pppoe(plain_c, plen_c, E[7].wire, 99, 0x0021);
	E[7].sproto = 0x8864;
	/* 8: IPv6 inside PPPoE */
	E[8].tag = "ps6";
	E[8].wlen = f563_pppoe(v6, v6len, E[8].wire, 99, 0x0057);
	E[8].sproto = 0x8864;

	f565_print_frames(E, 9);

	rfd = cap_open("r0");
	if (f564_ppp_setup()) {
		printf("F565 FAIL|ppp\n");
		return 0;
	}
	/* the unit's addresses exist only now, so the 5001 sockets are bound
	 * after the unit is up -- a bind to 10.9.0.7 before that is EADDRNOTAVAIL */
	f565_setup();

	if (!strcmp(mode, "f565g")) {
		f565_sec_grid(E, rfd);
	} else if (!strcmp(mode, "f565t")) {
		f565_sec_tcp(E, rfd);
		f565_sec_reach(E, rfd);
	} else if (!strcmp(mode, "f565c")) {
		f565_sec_csum(E, rfd);
	} else if (!strcmp(mode, "f565v")) {
		f564_ppp6_setup();
		if (U565_6B < 0)
			U565_6B = f564_udp_bind(AF_INET6, 0, F564_V6DST, 5001);
		printf("F565 SOCK6|u6_5001=%d\n", U565_6B);
		f565_sec_v6(E, rfd);
	} else {
		f565_sec_grid(E, rfd);
		f565_sec_tcp(E, rfd);
		f565_sec_reach(E, rfd);
		f565_sec_csum(E, rfd);
		f564_ppp6_setup();
		if (U565_6B < 0)
			U565_6B = f564_udp_bind(AF_INET6, 0, F564_V6DST, 5001);
		printf("F565 SOCK6|u6_5001=%d\n", U565_6B);
		f565_sec_v6(E, rfd);
	}
	sh("/nft flush ruleset");
	printf("F565 DONE\n");
	return 0;
}
