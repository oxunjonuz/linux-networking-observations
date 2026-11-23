/* differ563_add.c -- turn 563 / F41.
 *
 * Two debts were named and left open by turn 562, and both are closed here on
 * one new image, 7.3.4-T563 = T558 + CONFIG_PPP + CONFIG_PPPOE (config delta:
 * exactly the PPP/PPPOE block and SLHC; nft_payload.c, nft_meta.c,
 * nf_tables_core.c, nft_chain_filter.c, arp.c, dev.c byte-identical to T558).
 *
 * DEBT 1 -- PPPoE is the SECOND carrier of pkt->nhoff.
 * nft_meta.c:
 *      case htons(ETH_P_PPP_SES):
 *              if (!nf_flow_pppoe_proto(skb, &ethertype)) return;
 *              nhoff = PPPOE_SES_HLEN;              <- 8, not 6 (F40 wrote 6)
 *              break;
 *      nhoff += skb_network_offset(skb);
 * so on a PPPoE session frame `meta protocol` sets pkt->nhoff = 8 and the read
 * (skb_network_offset + nhoff + off) lands on the true IPv4 header while the
 * store (skb_network_offset + off) lands EIGHT bytes earlier, inside the PPPoE
 * session header.  Sections rd / st / pair / ih measure the grid; `pppd`
 * measures the receiving side on a real PPPoX session socket (no pppd, no
 * negotiation: pppoe_connect() binds a session when sid != 0 and queues frames
 * on the socket -- so recv() is the receiver's own verdict, in bytes).
 *
 * DEBT 2 -- the ARP frame the guard makes invalid.
 * F40 said `(8,2)` on a Q-in-Q ARP frame writes ar_hln/ar_pln and "arp_rcv()
 * refuses a frame whose ar_hln is not the device's".  Section `arpd` measures
 * the death instead of reading it, with three oracles per arm: the releasing
 * chain's counter, the arp-family counter at NF_ARP_IN (arp_rcv's own NF_HOOK),
 * and the reply frame the kernel sends back (plus /proc/net/arp).  It also
 * measures the entry F40 did not see: in the netdev INGRESS envelope the guard
 * is the constant `true`, so the cell at offset 4 -- refused by the ARP list --
 * writes ar_hln there, and that frame does die in arp_rcv.
 *
 * Views: w = AF_PACKET on r1 (the bridge port), r = AF_PACKET on r0 (the far
 * side).  ARP arms send from r0 so that the reply comes back the same way.
 */

#include <linux/if_pppox.h>

/* ---------- frames ---------- */

#define F563_KIND_IP	0
#define F563_KIND_ARP	1

struct f563_frame {
	const char *tag;
	int kind;
	int ntag;
	unsigned int tp[2], tc[2];
	unsigned char wire[512];
	int wlen;
	unsigned char cap[512];		/* mac_header on, after the receive path */
	int caplen;
	unsigned char plain[512];	/* the untagged layout (mac at 0) */
	int plainlen;
	unsigned short sproto;
	unsigned char magic[8];
	int mlen;
	unsigned int spa;		/* ARP sender protocol address */
};

/* the PPPoE session frame: eth | 0x8864 | ver/code | sid | length | ppp proto | datagram */
static int f563_pppoe(const unsigned char *plain, int plainlen, unsigned char *out,
		      unsigned short sid, unsigned short pppproto)
{
	int dlen = plainlen - 14;

	memcpy(out, plain, 12);
	out[12] = 0x88;
	out[13] = 0x64;
	out[14] = 0x11;			/* version 1, type 1 */
	out[15] = 0x00;			/* code: PPPOE_SESS_DATA */
	out[16] = (unsigned char)(sid >> 8);
	out[17] = (unsigned char)sid;
	out[18] = (unsigned char)((2 + dlen) >> 8);
	out[19] = (unsigned char)(2 + dlen);
	out[20] = (unsigned char)(pppproto >> 8);
	out[21] = (unsigned char)pppproto;
	memcpy(out + 22, plain + 14, (size_t)dlen);
	return 22 + dlen;
}

static void f563_arp_build(struct f563_frame *f, int ntag, unsigned int tp1,
			   unsigned int tc1, unsigned int tp2, unsigned int tc2)
{
	unsigned int tp[2], tc[2];
	int n, i;

	f->ntag = ntag;
	f->tp[0] = tp1; f->tc[0] = tc1;
	f->tp[1] = tp2; f->tc[1] = tc2;
	n = build_arp(f->plain, 1, f->spa, 0x0a090001, MAC_SRC, 6, 4, 1);
	f->plainlen = n;
	tp[0] = tp1; tc[0] = tc1; tp[1] = tp2; tc[1] = tc2;
	memcpy(f->wire, f->plain, 12);
	for (i = 0; i < ntag; i++) {
		f->wire[12 + 4 * i] = (unsigned char)(tp[i] >> 8);
		f->wire[13 + 4 * i] = (unsigned char)tp[i];
		f->wire[14 + 4 * i] = (unsigned char)(tc[i] >> 8);
		f->wire[15 + 4 * i] = (unsigned char)tc[i];
	}
	memcpy(f->wire + 12 + 4 * ntag, f->plain + 12, (size_t)(n - 12));
	f->wlen = n + 4 * ntag;
	/* one tag is popped by the receive path; a second one stays in bytes */
	memcpy(f->cap, f->plain, 12);
	if (ntag >= 2) {
		f->cap[12] = (unsigned char)(tp2 >> 8);
		f->cap[13] = (unsigned char)tp2;
		f->cap[14] = (unsigned char)(tc2 >> 8);
		f->cap[15] = (unsigned char)tc2;
		memcpy(f->cap + 16, f->plain + 12, (size_t)(n - 12));
		f->caplen = n + 4;
	} else {
		memcpy(f->cap + 12, f->plain + 12, (size_t)(n - 12));
		f->caplen = n;
	}
	f->sproto = ntag ? (unsigned short)tp1 : 0x0806;
	f->magic[0] = (unsigned char)(f->spa >> 24);
	f->magic[1] = (unsigned char)(f->spa >> 16);
	f->magic[2] = (unsigned char)(f->spa >> 8);
	f->magic[3] = (unsigned char)f->spa;
	f->mlen = 4;
}

/* candidate coordinates.  A = the STORE's byte (data + off, data = cap + 14),
 * B = where a read lands when pkt->nhoff == 8 (cap + 22 + off), P = the plain
 * frame's byte at the same cell, T = the true transport header. */
static const unsigned char *f563_cand(const struct f563_frame *f, int which, int off)
{
	switch (which) {
	case 1: return f->cap + 22 + off;
	case 2: return f->plain + 14 + off;
	case 3: return f->plain + 34 + off;
	}
	return f->cap + 14 + off;
}

static const char *f563_candname(int which)
{
	switch (which) {
	case 0: return "A";
	case 1: return "B";
	case 2: return "P";
	case 3: return "T";
	}
	return "?";
}

/* the value a store writes.  The two cells whose verdict reads the frame
 * (ip4 case 0 at data+0, case 8+len2 at data+9) get the byte the guard will
 * compare with, so that the LENGTH is what each cell measures. */
static void f563_imm(const struct f563_frame *f, int off, int len, unsigned char *imm)
{
	int i;

	memset(imm, 0, 16);
	for (i = 0; i < len && i < 16; i++)
		imm[i] = (unsigned char)(0x90 + i);
	if (off == 0 && f->caplen > 14)
		imm[0] = f->cap[14];
	if (off == 8 && len >= 2 && f->caplen > 23)
		imm[1] = f->cap[23];
}

/* ---------- one rule in any family ---------- */

static int f563_install(uint8_t fam, const char *table, const char *chain,
			const char *pre, int gate, uint32_t base,
			int do_rd, int cand, int off, int len,
			const unsigned char *cv, int do_wr, int wr_first,
			const unsigned char *imm, int cnt, int acc)
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
	if (do_rd && do_wr && !wr_first) {
		f562_read(nlh, base, (uint32_t)off, (uint32_t)len);
		f562_cmp(nlh, F562_RD_DREG, cv, len);
		f562_store(nlh, base, (uint32_t)off, (uint32_t)len, imm);
	} else if (do_rd && do_wr) {
		f562_store(nlh, base, (uint32_t)off, (uint32_t)len, imm);
		f562_read(nlh, base, (uint32_t)off, (uint32_t)len);
		f562_cmp(nlh, F562_RD_DREG, cv, len);
	} else if (do_rd) {
		f562_read(nlh, base, (uint32_t)off, (uint32_t)len);
		f562_cmp(nlh, F562_RD_DREG, cv, len);
	} else if (do_wr) {
		f562_store(nlh, base, (uint32_t)off, (uint32_t)len, imm);
	}
	if (cnt)
		counter_expr(nlh);
	if (acc)
		accept_expr(nlh);
	log_expr(nlh, 5, pre);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, &acks);
}

/* ---------- one arm on the bridge chain (the envelope sections) ---------- */

static const char *F563_SEC = "-";

static void f563_arm(const char *env, const char *arm, const char *rep,
		     int gate, uint32_t base, int off, int len,
		     int do_rd, int cand, int do_wr, int wr_first,
		     const unsigned char *imm, const struct f563_frame *f,
		     const char *sdev, int wfd, int rfd,
		     const struct f559_out *ctl, struct f559_out *out)
{
	struct f559_out o;
	char cw[1024], cr[1024], hw[512], hr[512], hc[512], hi[64];
	const unsigned char *cv = f563_cand(f, cand, off);
	int kw = 0, kr = 0;

	cw[0] = 0;
	cr[0] = 0;
	memset(&o, 0, sizeof(o));
	snprintf(PRE57, sizeof(PRE57), "f63.%s.%s", env, arm);
	f557_flush(NFPROTO_BRIDGE, "p63", "g", &o.acks);
	o.rc = f563_install(NFPROTO_BRIDGE, "p63", "g", PRE57, gate, base,
			    do_rd, cand, off, len, cv, do_wr, wr_first, imm,
			    1, 1);
	nfl_drain(NFL59);
	o.cnt0 = f555_count(NFPROTO_BRIDGE, "p63", "g");
	{
		unsigned long long ip0 = f558_ipin();

		f560_send2(sdev, f->sproto, f->wire, f->wlen, f->magic, f->mlen,
			   wfd, rfd, &o);
		usleep(20000);
		o.ipin = f558_ipin() - ip0;
	}
	o.cnt = f555_count(NFPROTO_BRIDGE, "p63", "g");
	if (ctl && o.wn > 0 && ctl->wn > 0)
		kw = f558_chg(cw, sizeof(cw), ctl->w, ctl->wn, o.w, o.wn);
	if (ctl && o.rn > 0 && ctl->rn > 0)
		kr = f558_chg(cr, sizeof(cr), ctl->r, ctl->rn, o.r, o.rn);
	printf("F563 R|sec=%s|env=%s.%s|rep=%s|gate=%d|base=%u|off=%d|len=%d|"
	       "rd=%d|cand=%s|cv=%s|wr=%d|first=%d|imm=%s|"
	       "rc=%d|acks=%d|snd=%d|cnt0=%llu|cnt=%llu|live=%llu|ipin=%llu|"
	       "wn=%d|wpt=%d|wchg=%d|wchgs=%s|whex=%s|"
	       "rn=%d|rpt=%d|rchg=%d|rchgs=%s|rhex=%s\n",
	       F563_SEC, env, arm, rep, gate, (unsigned)base, off, len,
	       do_rd, do_rd ? f563_candname(cand) : "-",
	       do_rd ? f559_hexs(hc, sizeof(hc), cv, len) : "-",
	       do_wr, wr_first,
	       do_wr ? f559_hexs(hi, sizeof(hi), imm, len) : "-",
	       o.rc, o.acks, o.snd, o.cnt0, o.cnt, o.cnt - o.cnt0, o.ipin,
	       o.wn, o.wpt, kw, cw[0] ? cw : "-",
	       o.wn > 0 ? f559_hexs(hw, sizeof(hw), o.w, o.wn) : "-",
	       o.rn, o.rpt, kr, cr[0] ? cr : "-",
	       o.rn > 0 ? f559_hexs(hr, sizeof(hr), o.r, o.rn) : "-");
	if (out)
		memcpy(out, &o, sizeof(o));
}

/* ---------- ctl: every envelope reaches the hook ---------- */

static void f563_sec_ctl(struct f563_frame *F, int n, int wfd, int rfd,
			 struct f559_out *ctls)
{
	int i;

	F563_SEC = "ctl";
	for (i = 0; i < n; i++) {
		unsigned char zero[16];

		memset(zero, 0, sizeof(zero));
		printf("F563 REP|rep=%s|kind=%d|plainlen=%d|caplen=%d|ntag=%d|"
		       "sproto=%04x|wlen=%d|spa=%08x\n",
		       F[i].tag, F[i].kind, F[i].plainlen, F[i].caplen,
		       F[i].ntag, F[i].sproto, F[i].wlen, F[i].spa);
		memset(&ctls[i], 0, sizeof(ctls[i]));
		f563_arm(F[i].tag, "ctl", F[i].tag, 0,
			 NFT_PAYLOAD_NETWORK_HEADER, 0, 0, 0, 0, 0, 0,
			 zero, &F[i], "s0", wfd, rfd, NULL, &ctls[i]);
	}
}

/* ---------- rd: the read grid, 40 cells, two candidates ---------- */

static void f563_sec_rd(struct f563_frame *F, int wfd, int rfd,
			const struct f559_out *ctls)
{
	unsigned char zero[16];
	int i, j, c, g, k;

	memset(zero, 0, sizeof(zero));
	F563_SEC = "rd";
	/* r = 0 (plain) and 1 (PPPoE) */
	for (k = 0; k < 2; k++) {
		int r = k;
		int gmax = (r == 0) ? 1 : 2;	/* p: meta only, ps: bare + meta */

		for (g = 0; g < gmax; g++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", F[r].tag,
				 g ? "meta" : "bare");
			for (c = 0; c < 2; c++) {
				for (i = 0; i < G33_NOFF; i++) {
					for (j = 0; j < G33_NLEN; j++) {
						char arm[64];

						snprintf(arm, sizeof(arm), "%s.g%d_%d",
							 env, G33_OFF[i], G33_LEN[j]);
						f563_arm(env, arm, F[r].tag, g,
							 NFT_PAYLOAD_NETWORK_HEADER,
							 G33_OFF[i], G33_LEN[j],
							 1, c, 0, 0, zero, &F[r],
							 "s0", wfd, rfd, &ctls[r], NULL);
					}
				}
				for (i = 0; i < G33_NEXT; i++) {
					char arm[64];

					snprintf(arm, sizeof(arm), "%s.x%d_%d", env,
						 G33_XOFF[i], G33_XLEN[i]);
					f563_arm(env, arm, F[r].tag, g,
						 NFT_PAYLOAD_NETWORK_HEADER,
						 G33_XOFF[i], G33_XLEN[i],
						 1, c, 0, 0, zero, &F[r], "s0",
						 wfd, rfd, &ctls[r], NULL);
				}
			}
		}
	}
}

/* ---------- st: the store grid on the PPPoE envelope ---------- */

static void f563_sec_st(struct f563_frame *F, int wfd, int rfd,
			const struct f559_out *ctls)
{
	int i, j, g;

	F563_SEC = "st";
	for (g = 0; g < 2; g++) {
		char env[32];

		snprintf(env, sizeof(env), "%s.%s", F[1].tag,
			 g ? "meta" : "bare");
		for (i = 0; i < G33_NOFF; i++) {
			for (j = 0; j < G33_NLEN; j++) {
				char arm[64];
				unsigned char imm[16];

				f563_imm(&F[1], G33_OFF[i], G33_LEN[j], imm);
				snprintf(arm, sizeof(arm), "s%d_%d",
					 G33_OFF[i], G33_LEN[j]);
				f563_arm(env, arm, F[1].tag, g,
					 NFT_PAYLOAD_NETWORK_HEADER,
					 G33_OFF[i], G33_LEN[j], 0, 0, 1, 0,
					 imm, &F[1], "s0", wfd, rfd,
					 &ctls[1], NULL);
			}
		}
		for (i = 0; i < G33_NEXT; i++) {
			char arm[64];
			unsigned char imm[16];

			f563_imm(&F[1], G33_XOFF[i], G33_XLEN[i], imm);
			snprintf(arm, sizeof(arm), "x%d_%d",
				 G33_XOFF[i], G33_XLEN[i]);
			f563_arm(env, arm, F[1].tag, g,
				 NFT_PAYLOAD_NETWORK_HEADER,
				 G33_XOFF[i], G33_XLEN[i], 0, 0, 1, 0, imm,
				 &F[1], "s0", wfd, rfd, &ctls[1], NULL);
		}
	}
}

/* ---------- pair: one rule, one packet, two places ---------- */

static const struct {
	int off, len;
} F563_PAIR[2] = { { 8, 1 }, { 16, 4 } };

static void f563_sec_pair(struct f563_frame *F, int wfd, int rfd,
			  const struct f559_out *ctls)
{
	int k, g, p, kind;

	F563_SEC = "pair";
	for (k = 0; k < 2; k++) {
		int r = k;

		for (g = 0; g < 2; g++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", F[r].tag,
				 g ? "meta" : "bare");
			for (p = 0; p < 2; p++) {
				for (kind = 0; kind < 3; kind++) {
					char arm[64];
					unsigned char imm[16];
					int i;

					memset(imm, 0, sizeof(imm));
					for (i = 0; i < F563_PAIR[p].len; i++)
						imm[i] = (unsigned char)(0x90 + i);
					snprintf(arm, sizeof(arm), "%s_%d.%s",
						 kind == 0 ? "wr" :
						 kind == 1 ? "rdwr" : "wrrd",
						 F563_PAIR[p].off,
						 F563_PAIR[p].len == 1 ? "b" : "d");
					f563_arm(env, arm, F[r].tag, g,
						 NFT_PAYLOAD_NETWORK_HEADER,
						 F563_PAIR[p].off,
						 F563_PAIR[p].len,
						 kind != 0, 1, 1,
						 kind == 2, imm, &F[r], "s0",
						 wfd, rfd, &ctls[r], NULL);
				}
			}
		}
	}
}

/* ---------- ih: the transport base inside a PPPoE frame ---------- */

static const struct {
	int off, len;
} F563_IH[5] = {
	{ 0, 2 }, { 0, 4 }, { 2, 2 }, { 2, 4 }, { 4, 2 },
};

static void f563_sec_ih(struct f563_frame *F, int wfd, int rfd,
			const struct f559_out *ctls)
{
	int k, g, p, kind;

	F563_SEC = "ih";
	for (k = 0; k < 2; k++) {
		int r = k;

		for (g = 0; g < 2; g++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", F[r].tag,
				 g ? "meta" : "bare");
			for (p = 0; p < 5; p++) {
				for (kind = 0; kind < 3; kind++) {
					char arm[64];
					unsigned char imm[16];
					int i;

					memset(imm, 0, sizeof(imm));
					for (i = 0; i < F563_IH[p].len; i++)
						imm[i] = (unsigned char)(0x90 + i);
					snprintf(arm, sizeof(arm), "%s_%d_%d",
						 kind == 0 ? "rdT" :
						 kind == 1 ? "rdW" : "wr",
						 F563_IH[p].off, F563_IH[p].len);
					f563_arm(env, arm, F[r].tag, g,
						 NFT_PAYLOAD_TRANSPORT_HEADER,
						 F563_IH[p].off, F563_IH[p].len,
						 kind != 2, kind == 0 ? 3 : 2,
						 kind == 2, 0, imm, &F[r], "s0",
						 wfd, rfd, &ctls[r], NULL);
				}
			}
		}
	}
}

/* ---------- pppd: the receiving side, on a real PPPoX session ---------- */

/* pppoe_connect() binds a session when sid != 0 -- no discovery, no pppd, no
 * PPP negotiation.  pppoe_rcv() then finds it by (sid, source MAC, ifindex),
 * and because the socket is not PPPOX_BOUND the skb is queued on it, so
 * recv() is the receiving stack's own verdict in bytes. */
static int f563_pppoe_sock(const char *dev, unsigned short sid_be,
			   const unsigned char *mac)
{
	struct sockaddr_pppox sp;
	int s, e;

	s = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OE);
	if (s < 0)
		return -errno;
	memset(&sp, 0, sizeof(sp));
	sp.sa_family = AF_PPPOX;
	sp.sa_protocol = PX_PROTO_OE;
	sp.sa_addr.pppoe.sid = sid_be;
	memcpy(sp.sa_addr.pppoe.remote, mac, 6);
	strncpy(sp.sa_addr.pppoe.dev, dev, IFNAMSIZ - 1);
	if (connect(s, (struct sockaddr *)&sp, sizeof(sp)) < 0) {
		e = errno;
		close(s);
		return -e;
	}
	return s;
}

static int f563_recv(int fd, unsigned char *buf, int max, int ms)
{
	struct timeval tv;
	fd_set rfds;
	int r;

	if (fd < 0)
		return -1;
	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = ms * 1000;
		r = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (r <= 0)
			return -1;
		r = (int)recv(fd, buf, (size_t)max, 0);
		if (r >= 0)
			return r;
		if (errno != EAGAIN && errno != EINTR)
			return -1;
	}
}

struct f563_pa {
	const char *arm;
	int gate;
	int off, len;
	int wr;
	unsigned char imm[16];
	const char *what;	/* what the rule names */
};

static void f563_sec_pppd(struct f563_frame *F, int wfd, int rfd, int sfd)
{
	static struct f563_pa A[] = {
		{ "ctl",      1,  0, 0, 0, { 0 },                 "no store" },
		{ "id_small", 1,  4, 2, 1, { 0x00, 0x04 },        "ipv4 id -> pppoe length = 4" },
		{ "id_large", 1,  4, 2, 1, { 0x90, 0x91 },        "ipv4 id -> pppoe length = 0x9091" },
		{ "vt",       1,  0, 2, 1, { 0x11, 0x91 },        "version/ihl -> pppoe ver/type + code" },
		{ "tos",      1,  1, 1, 1, { 0x91 },              "tos -> pppoe code" },
		{ "ttl",      1,  8, 1, 1, { 0x90 },              "ttl -> ipv4 version/ihl" },
		{ "ttl2",     1,  8, 2, 1, { 0x90, 0x00 },        "ttl(2b) -> ipv4 version/ihl + tos" },
		{ "saddr",    1, 12, 4, 1, { 0x90, 0x91, 0x92, 0x93 }, "saddr -> ipv4 id + frag_off" },
		{ "daddr",    1, 16, 4, 1, { 0x90, 0x91, 0x92, 0x93 }, "daddr -> ipv4 ttl + proto + csum" },
		{ "tsaddr",   1, 20, 4, 1, { 0x90, 0x91, 0x92, 0x93 }, "the real saddr: refused" },
		{ "trdaddr",  1, 24, 4, 1, { 0x90, 0x91, 0x92, 0x93 }, "the real daddr: refused" },
		{ "id_bare",  0,  4, 2, 1, { 0x00, 0x04 },        "bare gate: no branch" },
	};
	int ppfd, i;
	char hx[256];

	F563_SEC = "pppd";
	ppfd = f563_pppoe_sock("br0", htons(99), MAC_SRC);
	printf("F563 PPSOCK|rc=%d|sid=%04x|dev=br0|remote=%02x%02x%02x%02x%02x%02x\n",
	       ppfd, 99, MAC_SRC[0], MAC_SRC[1], MAC_SRC[2], MAC_SRC[3],
	       MAC_SRC[4], MAC_SRC[5]);
	for (i = 0; i < (int)(sizeof(A) / sizeof(A[0])); i++) {
		struct f559_out o;
		unsigned char rx[512];
		int rxn, cnt;
		char env[32];
		unsigned char tmp[512];
		char hi[64], hrx[256], hw[256], hr[256];

		memset(&o, 0, sizeof(o));
		snprintf(env, sizeof(env), "%s.%s", F[1].tag,
			 A[i].gate ? "meta" : "bare");
		snprintf(PRE57, sizeof(PRE57), "f63.%s.%s", env, A[i].arm);
		f557_flush(NFPROTO_BRIDGE, "p63", "g", &o.acks);
		o.rc = f563_install(NFPROTO_BRIDGE, "p63", "g", PRE57, A[i].gate,
				    NFT_PAYLOAD_NETWORK_HEADER, 0, 0, A[i].off,
				    A[i].len, NULL, A[i].wr, 0, A[i].imm, 1, 1);
		nfl_drain(NFL59);
		while (ppfd >= 0 && recv(ppfd, tmp, sizeof(tmp), MSG_DONTWAIT) >= 0)
			;
		o.cnt0 = f555_count(NFPROTO_BRIDGE, "p63", "g");
		f560_send2("s0", F[1].sproto, F[1].wire, F[1].wlen, F[1].magic,
			   F[1].mlen, wfd, rfd, &o);
		/* the reply may be queued a moment after the frame is forwarded */
		usleep(30000);
		rxn = f563_recv(ppfd, rx, (int)sizeof(rx), 300);
		cnt = 0;
		while (ppfd >= 0 && recv(ppfd, tmp, sizeof(tmp), MSG_DONTWAIT) >= 0)
			cnt++;
		o.cnt = f555_count(NFPROTO_BRIDGE, "p63", "g");
		printf("F563 P|sec=pppd|env=%s.%s|rep=%s|off=%d|len=%d|wr=%d|"
		       "imm=%s|what=%s|rc=%d|acks=%d|snd=%d|cnt0=%llu|cnt=%llu|"
		       "live=%llu|rxn=%d|rxmore=%d|rxhex=%s|whex=%s|rhex=%s\n",
		       env, A[i].arm, F[1].tag, A[i].off, A[i].len, A[i].wr,
		       A[i].wr ? f559_hexs(hi, sizeof(hi), A[i].imm, A[i].len) : "-",
		       A[i].what, o.rc, o.acks, o.snd, o.cnt0, o.cnt,
		       o.cnt - o.cnt0, rxn, cnt,
		       rxn > 0 ? f559_hexs(hrx, sizeof(hrx), rx, rxn < 40 ? rxn : 40) : "-",
		       o.wn > 0 ? f559_hexs(hw, sizeof(hw), o.w, o.wn < 40 ? o.wn : 40) : "-",
		       o.rn > 0 ? f559_hexs(hr, sizeof(hr), o.r, o.rn < 40 ? o.rn : 40) : "-");
	}
	if (ppfd >= 0)
		close(ppfd);
}

/* ---------- arpd: the receiving side of an ARP frame ---------- */

static unsigned int F563_BRMAC;

static void f563_getmac(const char *dev, unsigned char *out)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	memset(out, 0, 6);
	if (s >= 0 && ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
		memcpy(out, ifr.ifr_hwaddr.sa_data, 6);
	if (s >= 0)
		close(s);
}

/* s0 is the sender in every other section; in this one it is an unwelcome
 * THIRD receiver: the frame is flooded to s1, its peer s0 has an in_device of
 * its own, and the s0 copy reaches NF_ARP_IN too (measured: the arp counter
 * read 2 per accepted frame, and /proc/net/arp showed the entry on s0).
 * IFF_NOARP is the surgical way out: s0 stays in the bridge (so the frame it
 * sees is the post-store byte image) and arp_rcv() consumes its copy before
 * the hook. */
static void f563_set_noarp(const char *dev)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	if (s < 0)
		return;
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
		ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_NOARP);
		ioctl(s, SIOCSIFFLAGS, &ifr);
	}
	close(s);
}

static void f563_arpent(unsigned int spa, char *out, size_t osz)
{
	FILE *f = fopen("/proc/net/arp", "r");
	char line[512], ip[32];
	size_t ipl;

	out[0] = 0;
	snprintf(ip, sizeof(ip), "%u.%u.%u.%u", (spa >> 24) & 255,
		 (spa >> 16) & 255, (spa >> 8) & 255, spa & 255);
	ipl = strlen(ip);
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		size_t i, at = 0;
		int sp = 0;

		if (strncmp(line, ip, ipl) || (line[ipl] != ' ' && line[ipl] != '\t'))
			continue;
		/* keep the five columns after the address, spaces -> '_' */
		for (i = ipl; i < strlen(line) && at + 2 < osz; i++) {
			if (line[i] == '\n')
				break;
			if (line[i] == ' ' || line[i] == '\t') {
				if (sp)
					continue;
				sp = 1;
				out[at++] = ';';
			} else {
				sp = 0;
				out[at++] = line[i];
			}
		}
		out[at] = 0;
		break;
	}
	fclose(f);
}

struct f563_aa {
	const char *tag;	/* arm name */
	const char *env;	/* "br" or "nd" */
	int frame;		/* index into F[] */
	int gate;
	int off, len, wr;
	unsigned char imm[16];
	const char *what;
};

static void f563_sec_arpd(struct f563_frame *F, int wfd, int rfd, int sfd)
{
	static struct f563_aa A[] = {
		{ "br_pa_ctl",    "br", 2, 0,  0, 0, 0, { 0 },                 "control: no store" },
		{ "br_pa_opbad",  "br", 2, 0,  6, 2, 1, { 0x90, 0x91 },        "ar_op = 0x9091 (unknown)" },
		{ "br_pa_oprepl", "br", 2, 0,  6, 2, 1, { 0x00, 0x02 },        "ar_op = REPLY" },
		{ "br_pa_sha0",   "br", 2, 0,  8, 2, 1, { 0x90, 0x91 },        "sha[0..1]" },
		{ "br_pa_sha2",   "br", 2, 0, 10, 2, 1, { 0x90, 0x91 },        "sha[2..3]" },
		{ "br_tag0_ctl",  "br", 3, 0,  0, 0, 0, { 0 },                 "single 802.1Q tag, vid 0: control" },
		{ "br_q0_ctl",    "br", 4, 1,  0, 0, 0, { 0 },                 "Q-in-Q vid 0: control" },
		{ "br_q0_pro",    "br", 4, 1,  6, 2, 1, { 0x90, 0x91 },        "Q-in-Q: ar_pro (F40's shifted cell 6)" },
		{ "br_q0_op",     "br", 4, 1, 10, 2, 1, { 0x90, 0x91 },        "Q-in-Q: the real ar_op (offset 10)" },
		{ "br_q0_hln",    "br", 4, 1,  8, 2, 1, { 0x90, 0x91 },        "Q-in-Q: the shifted cell (writes ar_hln)" },
		{ "br_q200_ctl",  "br", 5, 1,  0, 0, 0, { 0 },                 "Q-in-Q inner vid 200: control" },
		{ "nd_pa_ctl",    "nd", 2, 0,  0, 0, 0, { 0 },                 "ingress, control" },
		{ "nd_pa_hln",    "nd", 2, 0,  4, 2, 1, { 0x90, 0x91 },        "ingress: ar_hln/ar_pln (offset 4, refused by the ARP list)" },
		{ "nd_pa_op",     "nd", 2, 0,  6, 2, 1, { 0x90, 0x91 },        "ingress: ar_op" },
		{ "nd_pa_sha0",   "nd", 2, 0,  8, 2, 1, { 0x90, 0x91 },        "ingress: sha[0..1]" },
		{ "nd_q0_hln",    "nd", 4, 1,  4, 2, 1, { 0x90, 0x91 },        "ingress on Q-in-Q: offset 4 lands in the tag" },
	};
	unsigned char brmac[6];
	int i, have_nd = 0, have_ar = 0, ackz = 0;

	F563_SEC = "arpd";
	f563_getmac("br0", brmac);
	F563_BRMAC = ((unsigned int)brmac[0] << 24) | ((unsigned int)brmac[1] << 16) |
		     ((unsigned int)brmac[2] << 8) | brmac[3];
	printf("F563 BRMAC|%02x%02x%02x%02x%02x%02x\n", brmac[0], brmac[1],
	       brmac[2], brmac[3], brmac[4], brmac[5]);
	printf("F563 ADDR|br0|rc=%d\n",
	       f555_addr_add("br0", htonl(0x0a090001), 24));
	f563_set_noarp("s0");
	printf("F563 NOARP|s0\n");
	usleep(150000);
	if (wfd >= 0) cap_drain(wfd);
	if (rfd >= 0) cap_drain(rfd);
	if (sfd >= 0) cap_drain(sfd);

	if (add_table(NFPROTO_ARP, "p63a") ||
	    f556_add_chain(NFPROTO_ARP, "p63a", "in", 0, 0, 1, NULL))
		printf("F563 FAIL|arp_chain\n");
	else
		have_ar = 1;
	if (add_table(NFPROTO_NETDEV, "p63n") ||
	    f556_add_chain(NFPROTO_NETDEV, "p63n", "ing", 0, 0, 1, "r1"))
		printf("F563 FAIL|nd_chain\n");
	else
		have_nd = 1;

	for (i = 0; i < (int)(sizeof(A) / sizeof(A[0])); i++) {
		struct f563_frame fr = F[A[i].frame];
		struct f563_frame *f = &fr;
		struct f559_out o;
		unsigned char req[1024], rep[1024], wrq[1024], rneedle[6];
		char ent[256], hx[256], hq[256], hr[256], hw[256];
		int rn = -1, repn = -1, wrn = -1, sk = 0, cnt0, cnt, ack2 = 0;
		uint8_t dfam = NFPROTO_BRIDGE;
		const char *dtab = "p63", *dch = "g";

		memset(&o, 0, sizeof(o));
		/* one sender address per arm: the neighbour table is keyed by
		 * (address, device), so a shared one would answer for the arm
		 * that created it -- measured, twice. */
		if (fr.kind == F563_KIND_ARP) {
			fr.spa = 0x0a010090u + (unsigned int)i;
			f563_arp_build(&fr, fr.ntag, fr.tp[0], fr.tc[0],
				       fr.tp[1], fr.tc[1]);
		}
		if (!strcmp(A[i].env, "nd")) {
			dfam = NFPROTO_NETDEV;
			dtab = "p63n";
			dch = "ing";
		}
		/* the two chains: the releasing rule, then the arp counter */
		snprintf(PRE57, sizeof(PRE57), "f63.%s.%s", A[i].env, A[i].tag);
		f557_flush(NFPROTO_BRIDGE, "p63", "g", &ack2);
		f557_flush(NFPROTO_NETDEV, "p63n", "ing", &ack2);
		if (have_ar) {
			f557_flush(NFPROTO_ARP, "p63a", "in", &ack2);
			f563_install(NFPROTO_ARP, "p63a", "in", PRE57, 0,
				     NFT_PAYLOAD_NETWORK_HEADER, 0, 0, 0, 0,
				     NULL, 0, 0, NULL, 1, 0);
		}
		o.rc = f563_install(dfam, dtab, dch, PRE57, A[i].gate,
				    NFT_PAYLOAD_NETWORK_HEADER, 0, 0, A[i].off,
				    A[i].len, NULL, A[i].wr, 0, A[i].imm, 1, 1);
		nfl_drain(NFL59);
		cnt0 = have_ar ? (int)f555_count(NFPROTO_ARP, "p63a", "in") : -1;
		if (rfd >= 0) cap_drain(rfd);
		if (wfd >= 0) cap_drain(wfd);
		usleep(10000);
		if (rfd >= 0) cap_drain(rfd);
		if (wfd >= 0) cap_drain(wfd);
		o.snd = pkt_send_p("r0", f->wire, f->wlen, f->sproto);
		rn = f558_cap_match(rfd, req, (int)sizeof(req), 400, f->magic,
				    f->mlen, &sk, &o.rpt);
		sk = 0;
		wrn = f558_cap_match(sfd, wrq, (int)sizeof(wrq), 300, f->magic,
				     f->mlen, &sk, &o.wpt);
		memcpy(rneedle, brmac, 6);
		sk = 0;
		repn = f558_cap_match(rfd, rep, (int)sizeof(rep), 400, rneedle, 6,
				      &sk, &o.wpt);
		cnt = have_ar ? (int)f555_count(NFPROTO_ARP, "p63a", "in") : -1;
		f563_arpent(f->spa, ent, sizeof(ent));
		printf("F563 A|sec=arpd|env=%s|arm=%s|frame=%s|gate=%d|off=%d|"
		       "len=%d|wr=%d|imm=%s|what=%s|spa=%08x|rc=%d|acks=%d|"
		       "snd=%d|reqn=%d|reqhex=%s|wrn=%d|whex=%s|repn=%d|"
		       "reppkt=%d|rephex=%s|arccnt0=%d|arccnt=%d|arc=%d|ent=%s\n",
		       A[i].env, A[i].tag, f->tag, A[i].gate, A[i].off,
		       A[i].len, A[i].wr,
		       A[i].wr ? f559_hexs(hx, sizeof(hx), A[i].imm, A[i].len) : "-",
		       A[i].what, f->spa, o.rc, o.acks, o.snd, rn,
		       rn > 0 ? f559_hexs(hq, sizeof(hq), req, rn < 46 ? rn : 46) : "-",
		       wrn,
		       wrn > 0 ? f559_hexs(hw, sizeof(hw), wrq, wrn < 46 ? wrn : 46) : "-",
		       repn, o.wpt,
		       repn > 0 ? f559_hexs(hr, sizeof(hr), rep, repn < 46 ? repn : 46) : "-",
		       cnt0, cnt, cnt < 0 ? -1 : cnt - cnt0, ent[0] ? ent : "-");
	}
	/* leave no envelope behind that could judge a later section */
	f557_flush(NFPROTO_NETDEV, "p63n", "ing", &ackz);
	f557_flush(NFPROTO_ARP, "p63a", "in", &ackz);
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	static struct f563_frame F[6];
	static struct f559_out ctls[6];
	const char *mode = argc > 1 ? argv[1] : "f563";
	int wfd, rfd, sfd;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F563 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F563 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F563 KERNEL|%s\n", "7.3.4-T563");
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
	printf("F563 NFL|%d\n", NFL59);

	/* 0: p   plain ethernet, IPv4/UDP, the 0x77 payload
	 * 1: ps  the same datagram inside a PPPoE session frame (sid 99)
	 * 2: pa  plain ARP request
	 * 3: tag0 ARP behind one 802.1Q tag, vid 0
	 * 4: q0  ARP behind Q-in-Q, outer 0x88a8 vid 0, inner 0x8100 vid 0
	 * 5: q200 ARP behind Q-in-Q, inner vid 200
	 */
	memset(F, 0, sizeof(F));
	F[0].tag = "p";  F[0].kind = F563_KIND_IP;
	F[0].plainlen = f556_mk_ip4(F[0].plain, 5, 17, 64);
	memcpy(F[0].cap, F[0].plain, (size_t)F[0].plainlen);
	F[0].caplen = F[0].plainlen;
	memcpy(F[0].wire, F[0].plain, (size_t)F[0].plainlen);
	F[0].wlen = F[0].plainlen;
	F[0].sproto = 0x0800;
	memcpy(F[0].magic, M561_77, 8);
	F[0].mlen = 8;

	F[1].tag = "ps"; F[1].kind = F563_KIND_IP;
	F[1].wlen = f563_pppoe(F[0].plain, F[0].plainlen, F[1].wire, 99, 0x0021);
	memcpy(F[1].cap, F[1].wire, (size_t)F[1].wlen);
	F[1].caplen = F[1].wlen;
	memcpy(F[1].plain, F[0].plain, (size_t)F[0].plainlen);
	F[1].plainlen = F[0].plainlen;
	F[1].sproto = 0x8864;
	memcpy(F[1].magic, M561_77, 8);
	F[1].mlen = 8;

	F[2].tag = "pa";   F[2].kind = F563_KIND_ARP; F[2].spa = 0x0a010090;
	f563_arp_build(&F[2], 0, 0, 0, 0, 0);
	F[3].tag = "tag0"; F[3].kind = F563_KIND_ARP; F[3].spa = 0x0a010091;
	f563_arp_build(&F[3], 1, 0x8100, 0x0000, 0, 0);
	F[4].tag = "q0";   F[4].kind = F563_KIND_ARP; F[4].spa = 0x0a010092;
	f563_arp_build(&F[4], 2, 0x88a8, 0x0000, 0x8100, 0x0000);
	F[5].tag = "q200"; F[5].kind = F563_KIND_ARP; F[5].spa = 0x0a010093;
	f563_arp_build(&F[5], 2, 0x88a8, 0x0000, 0x8100, 0x00c8);

	if (add_table(NFPROTO_BRIDGE, "p63") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p63", "g", 0, 0, 1, NULL)) {
		printf("F563 FAIL|chain\n");
		return 0;
	}
	wfd = cap_open("r1");
	rfd = cap_open("r0");
	sfd = cap_open("s0");
	printf("F563 SECTION|open|wfd=%d|rfd=%d|sfd=%d\n", wfd, rfd, sfd);

	if (!strcmp(mode, "f563ctl")) {
		f563_sec_ctl(F, 6, wfd, rfd, ctls);
		goto done;
	}
	f563_sec_ctl(F, 6, wfd, rfd, ctls);
	if (!strcmp(mode, "f563rd")) {
		f563_sec_rd(F, wfd, rfd, ctls);
	} else if (!strcmp(mode, "f563st")) {
		f563_sec_st(F, wfd, rfd, ctls);
	} else if (!strcmp(mode, "f563pair")) {
		f563_sec_pair(F, wfd, rfd, ctls);
	} else if (!strcmp(mode, "f563ih")) {
		f563_sec_ih(F, wfd, rfd, ctls);
	} else if (!strcmp(mode, "f563ppp")) {
		f563_sec_pppd(F, wfd, rfd, sfd);
	} else if (!strcmp(mode, "f563arp")) {
		f563_sec_arpd(F, wfd, rfd, sfd);
	} else {
		f563_sec_rd(F, wfd, rfd, ctls);
		f563_sec_st(F, wfd, rfd, ctls);
		f563_sec_pair(F, wfd, rfd, ctls);
		f563_sec_ih(F, wfd, rfd, ctls);
		f563_sec_pppd(F, wfd, rfd, sfd);
		f563_sec_arpd(F, wfd, rfd, sfd);
	}
done:
	sh("/nft flush ruleset");
	printf("F563 DONE\n");
	return 0;
}
