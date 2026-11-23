/* differ562_add.c -- turn 562 / F40: the read side of @nh.
 *
 * F39 ended with the one guard input it saw in code and had not measured:
 *   nft_payload_eval()   (read)  offset = skb_network_offset(skb) + pkt->nhoff
 *   nft_payload_set_eval (store) offset = skb_network_offset(skb)
 * so a cell (offset,len) names one byte to a read and another to a store as
 * soon as pkt->nhoff != 0.  nhoff becomes 4 in exactly one place:
 * nft_meta_pktinfo_may_update(), reached from `meta protocol`, on an skb whose
 * skb->protocol is 0x8100 -- a Q-in-Q frame after the receive path popped
 * exactly one tag (F39's `q`).
 *
 * Same kernel as F36..F39 (7.3.4-T558, sha 459f02a5...): every file that
 * decides this (nft_payload.c, nft_meta.c, nf_tables_core.c, skbuff.c) is
 * byte-for-byte the one those findings measured.
 *
 * Sections:
 *   ctl    one counter-only rule per representation: the envelope arrives.
 *   rd     the read grid: 40 cells x {p, w, q} x {bare, meta} x 2 candidates.
 *          Candidate A = cap[14+off], the byte the STORE of that cell writes.
 *          Candidate B = cap[18+off], where a read lands if pkt->nhoff == 4.
 *          No store in these arms: neither the guard nor skb_ensure_writable
 *          is between the read and the counter.
 *   pair   one rule on one packet: read and store of the SAME cell, in both
 *          orders (rdwr: read then store; wrrd: store then read).
 *   ih     the transport base: meta's repair sets pkt->thoff from nhoff, and
 *          both the read and the store use nft_thoff() -- so they agree there.
 *   qarp   ARP in Q-in-Q: meta sets pkt->ethertype = 0x0806 but validates
 *          nothing, so nhoff stays 0 and the guard writes "ar_op" into ar_pro.
 *
 * Views: w = AF_PACKET on r1 (after xmit), r = AF_PACKET on r0.  Oracle for
 * every arm: the rule's own counter, read before and after one send.
 * Frame layout on the capture: cap starts at mac_header, skb->data is 14
 * bytes further, so a data-relative offset D is cap[14+D].
 */

/* ---------- frames ---------- */

struct f562_frame {
	const char *tag;
	int kind;			/* FK33_IP4 or FK33_ARP */
	int ntag;
	unsigned int tp1, tc1, tp2, tc2;
	unsigned char plain[256];	/* the untagged layout, as captured */
	int plainlen;
	unsigned char cap[256];		/* the captured layout (mac_header on) */
	int caplen;
	unsigned short sproto;		/* what the sender declares */
	unsigned char magic[8];		/* capture needle: the UDP payload 0x77.. */
	int mlen;			/* for IPv4, the ARP sender protocol address */
};

static int f562_wire(const struct f562_frame *f, unsigned char *out)
{
	unsigned int tp[2], tc[2];
	int i, n = f->plainlen;

	tp[0] = f->tp1; tc[0] = f->tc1;
	tp[1] = f->tp2; tc[1] = f->tc2;
	memcpy(out, f->plain, 12);
	for (i = 0; i < f->ntag; i++) {
		out[12 + 4 * i] = (unsigned char)(tp[i] >> 8);
		out[13 + 4 * i] = (unsigned char)tp[i];
		out[14 + 4 * i] = (unsigned char)(tc[i] >> 8);
		out[15 + 4 * i] = (unsigned char)tc[i];
	}
	memcpy(out + 12 + 4 * f->ntag, f->plain + 12, (size_t)(n - 12));
	return n + 4 * f->ntag;
}

/* The capture is what leaves the bridge.  Receive path, in order:
 * eth_type_trans() pulls 14; __netif_receive_skb_core() pops ONE tag
 * (skb_vlan_untag), sets skb->protocol to the next ethertype and
 * skb_reorder_vlan_header() moves the MACs forward by VLAN_HLEN.  So:
 *   no tag   -> captured = plain;
 *   one tag  -> the tag is in skb->vlan_all and veth reinserts nothing
 *               (HW_VLAN_*_TX set), captured = plain;
 *   two tags -> the outer tag is gone, the INNER one remains in the bytes,
 *               captured = MACs + inner tag + plain[12..].
 */
static void f562_build(struct f562_frame *f)
{
	int n = f->kind == FK33_ARP
		? build_arp(f->plain, 1, 0x0a010009, 0x0a090001, MAC_SRC, 6, 4, 1)
		: f556_frame(FK33_IP4, f->plain);

	f->plainlen = n;
	memcpy(f->cap, f->plain, 12);
	if (f->ntag >= 2) {
		f->cap[12] = (unsigned char)(f->tp2 >> 8);
		f->cap[13] = (unsigned char)f->tp2;
		f->cap[14] = (unsigned char)(f->tc2 >> 8);
		f->cap[15] = (unsigned char)f->tc2;
		memcpy(f->cap + 16, f->plain + 12, (size_t)(n - 12));
		f->caplen = n + 4;
	} else {
		memcpy(f->cap + 12, f->plain + 12, (size_t)(n - 12));
		f->caplen = n;
	}
	f->sproto = f->ntag ? (unsigned short)f->tp1 : f556_proto(f->kind);
	/* The capture is matched by content, not by being the next frame: the
	 * first frame on a fresh socket is ICMPv6 noise (F35).  The IPv4 frame
	 * carries 18 bytes of 0x77; the ARP frame carries none, so it is
	 * matched on its sender protocol address, which nothing else writes. */
	if (f->kind == FK33_ARP) {
		static const unsigned char arp_needle[4] = { 0x0a, 0x01, 0x00,
							     0x09 };

		memcpy(f->magic, arp_needle, 4);
		f->mlen = 4;
	} else {
		memcpy(f->magic, M561_77, 8);
		f->mlen = 8;
	}
}

/* A = the store's coordinate, B = nhoff==4, P = plain[14+off] (the value a
 * plain frame gives at this cell), T = the true transport header. */
static const unsigned char *f562_cand(const struct f562_frame *f, int which,
				      int off)
{
	switch (which) {
	case 1:
		return f->cap + 18 + off;
	case 2:
		return f->plain + 14 + off;
	case 3:
		return f->plain + 34 + off;
	}
	return f->cap + 14 + off;
}

static const char *f562_candname(int which)
{
	switch (which) {
	case 0: return "A";
	case 1: return "B";
	case 2: return "P";
	case 3: return "T";
	}
	return "?";
}

/* ---------- rule pieces ---------- */

#define F562_RD_DREG	NFT_REG32_08
#define F562_WR_SREG	NFT_REG32_00

static void f562_meta_proto(struct nlmsghdr *nlh)
{
	struct nlattr *e, *d;

	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "meta");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_META_KEY, NFT_META_PROTOCOL);
	put_be32(nlh, NFTA_META_DREG, F562_RD_DREG);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

static void f562_cmp(struct nlmsghdr *nlh, uint32_t sreg,
		     const unsigned char *val, int len)
{
	struct nlattr *e, *d, *cd;

	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "cmp");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_CMP_SREG, sreg);
	put_be32(nlh, NFTA_CMP_OP, NFT_CMP_EQ);
	cd = nest_start(nlh, NFTA_CMP_DATA);
	attr_put(nlh, NFTA_DATA_VALUE, val, len);
	nest_end(nlh, cd);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

static void f562_read(struct nlmsghdr *nlh, uint32_t base, uint32_t off,
		      uint32_t len)
{
	struct nlattr *e, *d;

	e = nest_start(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "payload");
	d = nest_start(nlh, NFTA_EXPR_DATA);
	put_be32(nlh, NFTA_PAYLOAD_DREG, F562_RD_DREG);
	put_be32(nlh, NFTA_PAYLOAD_BASE, base);
	put_be32(nlh, NFTA_PAYLOAD_OFFSET, off);
	put_be32(nlh, NFTA_PAYLOAD_LEN, len);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

static void f562_store(struct nlmsghdr *nlh, uint32_t base, uint32_t off,
		       uint32_t len, const unsigned char *imm)
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
	put_be32(nlh, NFTA_PAYLOAD_CSUM_TYPE, NFT_PAYLOAD_CSUM_NONE);
	put_be32(nlh, NFTA_PAYLOAD_CSUM_OFFSET, 0);
	nest_end(nlh, d);
	nest_end(nlh, e);
}

/* ---------- one arm ---------- */

static const char *F562_SEC = "-";

static void f562_arm(const char *env, const char *arm, const char *rep,
		     int gate, uint32_t base, int off, int len,
		     int do_rd, int cand, int do_wr, int wr_first,
		     const unsigned char *imm, const struct f562_frame *f,
		     const unsigned char *wire, int wlen,
		     int wfd, int rfd, const struct f559_out *ctl,
		     struct f559_out *out)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;
	struct f559_out o;
	char cw[1024], cr[1024], hw[512], hr[512], hc[512];
	const unsigned char *cv = f562_cand(f, cand, off);
	int kw = 0, kr = 0;

	cw[0] = 0;
	cr[0] = 0;
	memset(&o, 0, sizeof(o));
	snprintf(PRE57, sizeof(PRE57), "f62.%s.%s", env, arm);
	f557_flush(NFPROTO_BRIDGE, "p62", "g", &o.acks);

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			NFPROTO_BRIDGE);
	put_str(nlh, NFTA_RULE_TABLE, "p62");
	put_str(nlh, NFTA_RULE_CHAIN, "g");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	if (gate)
		f562_meta_proto(nlh);
	if (do_rd && do_wr && !wr_first) {
		f562_read(nlh, base, (uint32_t)off, (uint32_t)len);
		f562_cmp(nlh, F562_RD_DREG, cv, len);
		f562_store(nlh, base, (uint32_t)off, (uint32_t)len, imm);
	} else if (do_rd && do_wr && wr_first) {
		f562_store(nlh, base, (uint32_t)off, (uint32_t)len, imm);
		f562_read(nlh, base, (uint32_t)off, (uint32_t)len);
		f562_cmp(nlh, F562_RD_DREG, cv, len);
	} else if (do_rd) {
		f562_read(nlh, base, (uint32_t)off, (uint32_t)len);
		f562_cmp(nlh, F562_RD_DREG, cv, len);
	} else if (do_wr) {
		f562_store(nlh, base, (uint32_t)off, (uint32_t)len, imm);
	}
	log_expr(nlh, 5, PRE57);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	o.rc = f557_nft_one(opbuf, (int)nlh->nlmsg_len, &o.acks);

	nfl_drain(NFL59);
	o.cnt0 = f555_count(NFPROTO_BRIDGE, "p62", "g");
	{
		unsigned long long ip0 = f558_ipin();

		f560_send2("s0", f->sproto, wire, wlen, f->magic, f->mlen,
			   wfd, rfd, &o);
		usleep(20000);
		o.ipin = f558_ipin() - ip0;
	}
	o.cnt = f555_count(NFPROTO_BRIDGE, "p62", "g");
	if (ctl && o.wn > 0 && ctl->wn > 0)
		kw = f558_chg(cw, sizeof(cw), ctl->w, ctl->wn, o.w, o.wn);
	if (ctl && o.rn > 0 && ctl->rn > 0)
		kr = f558_chg(cr, sizeof(cr), ctl->r, ctl->rn, o.r, o.rn);
	printf("F562 R|env=%s.%s|rep=%s|gate=%d|base=%u|off=%d|len=%d|"
	       "rd=%d|cand=%s|cv=%s|wr=%d|first=%d|"
	       "rc=%d|acks=%d|snd=%d|cnt0=%llu|cnt=%llu|live=%llu|ipin=%llu|"
	       "wn=%d|wpt=%d|wchg=%d|wchgs=%s|whex=%s|"
	       "rn=%d|rpt=%d|rchg=%d|rchgs=%s|rhex=%s\n",
	       F562_SEC, env, rep, gate, (unsigned)base, off, len,
	       do_rd, do_rd ? f562_candname(cand) : "-",
	       do_rd ? f559_hexs(hc, sizeof(hc), cv, len) : "-",
	       do_wr, wr_first,
	       o.rc, o.acks, o.snd, o.cnt0, o.cnt, o.cnt - o.cnt0, o.ipin,
	       o.wn, o.wpt, kw, cw[0] ? cw : "-",
	       o.wn > 0 ? f559_hexs(hw, sizeof(hw), o.w, o.wn) : "-",
	       o.rn, o.rpt, kr, cr[0] ? cr : "-",
	       o.rn > 0 ? f559_hexs(hr, sizeof(hr), o.r, o.rn) : "-");
	if (out)
		memcpy(out, &o, sizeof(o));
}

/* ---------- ctl: the envelope arrives ---------- */

static void f562_sec_ctl(struct f562_frame *F, int n, int wfd, int rfd,
			 struct f559_out *ctls)
{
	unsigned char wire[256];
	int i;

	F562_SEC = "ctl";
	for (i = 0; i < n; i++) {
		int wlen = f562_wire(&F[i], wire);

		printf("F562 REP|rep=%s|plainlen=%d|caplen=%d|ntag=%d|"
		       "sproto=%04x|wlen=%d\n",
		       F[i].tag, F[i].plainlen, F[i].caplen, F[i].ntag,
		       F[i].sproto, wlen);
		memset(&ctls[i], 0, sizeof(ctls[i]));
		f562_arm(F[i].tag, "ctl", F[i].tag, 0,
			 NFT_PAYLOAD_NETWORK_HEADER, 0, 0, 0, 0, 0, 0, NULL,
			 &F[i], wire, wlen, wfd, rfd, NULL, &ctls[i]);
	}
}

/* ---------- rd: the read grid ---------- */

static void f562_sec_rd(struct f562_frame *F, int n, int wfd, int rfd,
			const struct f559_out *ctls)
{
	unsigned char wire[256];
	static const int reps[3] = { 0, 1, 2 };	/* p, w, q */
	int k, g, i, j, c;

	F562_SEC = "rd";
	for (k = 0; k < 3; k++) {
		int r = reps[k];
		int wlen = f562_wire(&F[r], wire);

		for (g = 0; g < 2; g++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", F[r].tag,
				 g ? "meta" : "bare");
			for (c = 0; c < 2; c++) {
				for (i = 0; i < G33_NOFF; i++) {
					for (j = 0; j < G33_NLEN; j++) {
						char arm[48];

						snprintf(arm, sizeof(arm),
							 "%s.g%d_%d", env,
							 G33_OFF[i], G33_LEN[j]);
						f562_arm(env, arm,
							 F[r].tag, g,
							 NFT_PAYLOAD_NETWORK_HEADER,
							 G33_OFF[i], G33_LEN[j],
							 1, c, 0, 0, NULL, &F[r],
							 wire, wlen, wfd, rfd,
							 &ctls[r], NULL);
					}
				}
				for (i = 0; i < G33_NEXT; i++) {
					char arm[48];

					snprintf(arm, sizeof(arm), "%s.x%d_%d",
						 env, G33_XOFF[i], G33_XLEN[i]);
					f562_arm(env, arm, F[r].tag, g,
						 NFT_PAYLOAD_NETWORK_HEADER,
						 G33_XOFF[i], G33_XLEN[i],
						 1, c, 0, 0, NULL, &F[r],
						 wire, wlen, wfd, rfd,
						 &ctls[r], NULL);
				}
			}
		}
	}
}

/* ---------- pair: one rule, one packet, two places ---------- */

static const struct {
	int off, len;
} F562_PAIR[2] = { { 8, 1 }, { 16, 4 } };

static void f562_sec_pair(struct f562_frame *F, int wfd, int rfd,
			  const struct f559_out *ctls)
{
	static const int reps[2] = { 0, 2 };	/* p, q */
	unsigned char wire[256], imm[16];
	int k, g, p, kind;

	F562_SEC = "pair";
	for (k = 0; k < 2; k++) {
		int r = reps[k];
		int wlen = f562_wire(&F[r], wire);

		for (g = 0; g < 2; g++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", F[r].tag,
				 g ? "meta" : "bare");
			for (p = 0; p < 2; p++) {
				for (kind = 0; kind < 3; kind++) {
					char arm[48];
					int i;

					for (i = 0; i < F562_PAIR[p].len; i++)
						imm[i] = (unsigned char)(0x90 + i);
					snprintf(arm, sizeof(arm),
						 "%s.%s_%d.%s", env,
						 kind == 0 ? "wr" :
						 kind == 1 ? "rdwr" : "wrrd",
						 F562_PAIR[p].off,
						 F562_PAIR[p].len == 1 ? "b" : "d");
					f562_arm(env, arm, F[r].tag, g,
						 NFT_PAYLOAD_NETWORK_HEADER,
						 F562_PAIR[p].off,
						 F562_PAIR[p].len,
						 kind != 0, 2, 1,
						 kind == 2, imm, &F[r], wire,
						 wlen, wfd, rfd, &ctls[r],
						 NULL);
				}
			}
		}
	}
}

/* ---------- ih: the transport base under the same repair ---------- */

static const struct {
	int off, len;
} F562_IH[5] = {
	{ 0, 2 }, { 0, 4 }, { 2, 2 }, { 2, 4 }, { 4, 2 },
};

static void f562_sec_ih(struct f562_frame *F, int wfd, int rfd,
			const struct f559_out *ctls)
{
	static const int reps[2] = { 0, 2 };	/* p, q */
	unsigned char wire[256], imm[16];
	int k, g, p, kind;

	F562_SEC = "ih";
	for (k = 0; k < 2; k++) {
		int r = reps[k];
		int wlen = f562_wire(&F[r], wire);

		for (g = 0; g < 2; g++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", F[r].tag,
				 g ? "meta" : "bare");
			for (p = 0; p < 5; p++) {
				for (kind = 0; kind < 3; kind++) {
					char arm[48];
					int i;

					for (i = 0; i < F562_IH[p].len; i++)
						imm[i] = (unsigned char)(0x90 + i);
					/* kind 0: cmp against T (the true
					 * transport header), kind 1: against
					 * data 0+off, kind 2: store only. */
					snprintf(arm, sizeof(arm),
						 "%s.%s_%d_%d", env,
						 kind == 0 ? "rdT" :
						 kind == 1 ? "rdW" : "wr",
						 F562_IH[p].off,
						 F562_IH[p].len);
					f562_arm(env, arm, F[r].tag, g,
						 NFT_PAYLOAD_TRANSPORT_HEADER,
						 F562_IH[p].off, F562_IH[p].len,
						 kind != 2, kind == 0 ? 3 : 0,
						 kind == 2, 0, imm, &F[r],
						 wire, wlen, wfd, rfd,
						 &ctls[r], NULL);
				}
			}
		}
	}
}

/* ---------- qarp: ARP in Q-in-Q, where the repair never happens ---------- */

static const struct {
	int off, len;
} F562_ARP[6] = {
	{ 0, 2 }, { 2, 2 }, { 4, 2 }, { 6, 2 }, { 8, 2 }, { 10, 2 },
};

static void f562_sec_qarp(struct f562_frame *F, int wfd, int rfd,
			  const struct f559_out *ctls)
{
	static const int reps[2] = { 3, 4 };	/* pa, qa */
	unsigned char wire[256], imm[16];
	int k, g, p, c;

	F562_SEC = "qarp";
	for (k = 0; k < 2; k++) {
		int r = reps[k];
		int wlen = f562_wire(&F[r], wire);

		for (g = 0; g < 2; g++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", F[r].tag,
				 g ? "meta" : "bare");
			for (p = 0; p < 6; p++) {
				for (c = 0; c < 2; c++) {
					char arm[48];

					snprintf(arm, sizeof(arm),
						 "%s.rd%s_%d", env,
						 f562_candname(c),
						 F562_ARP[p].off);
					f562_arm(env, arm, F[r].tag, g,
						 NFT_PAYLOAD_NETWORK_HEADER,
						 F562_ARP[p].off,
						 F562_ARP[p].len, 1, c, 0, 0,
						 NULL, &F[r], wire, wlen, wfd,
						 rfd, &ctls[r], NULL);
				}
				{
					char arm[48];
					int i;

					for (i = 0; i < F562_ARP[p].len; i++)
						imm[i] = (unsigned char)(0x90 + i);
					snprintf(arm, sizeof(arm), "%s.wr_%d",
						 env, F562_ARP[p].off);
					f562_arm(env, arm, F[r].tag, g,
						 NFT_PAYLOAD_NETWORK_HEADER,
						 F562_ARP[p].off,
						 F562_ARP[p].len, 0, 0, 1, 0,
						 imm, &F[r], wire, wlen, wfd,
						 rfd, &ctls[r], NULL);
				}
			}
		}
	}
}

/* ---------- val: the two cells whose verdict reads the packet ----------
 *
 * nft_nh_write_ok_ip4() does not only look at (offset,len):
 *   case 0:  requires len == 2 AND src[0] == the byte at data+0
 *   case 8:  with len == 2, requires src[1] == the byte at data+9
 * On a plain frame those bytes are the IPv4 version/ihl and the protocol
 * number.  On Q-in-Q with `meta protocol` in front they are the high byte of
 * the INNER tag's TCI and the low byte of the IP id -- so the value the guard
 * compares with is itself a byte of the envelope, and the cell becomes live
 * or dead depending on a byte that is not in the field the cell names.
 */
static void f562_sec_val(struct f562_frame *F, int wfd, int rfd,
			 const struct f559_out *ctls)
{
	static const int reps[2] = { 0, 2 };	/* p, q */
	unsigned char wire[256], imm[16];
	int k, g, p, v;

	F562_SEC = "val";
	for (k = 0; k < 2; k++) {
		int r = reps[k];
		int wlen = f562_wire(&F[r], wire);
		const unsigned char *data = F[r].cap + 14;

		for (g = 0; g < 2; g++) {
			char env[32];

			snprintf(env, sizeof(env), "%s.%s", F[r].tag,
				 g ? "meta" : "bare");
			for (p = 0; p < 2; p++) {
				for (v = 0; v < 2; v++) {
					char arm[48];
					int off = p ? 8 : 0;
					int i;

					for (i = 0; i < 2; i++)
						imm[i] = (unsigned char)(0x90 + i);
					if (!p)
						imm[0] = 0x45;	/* the ip4 way in */
					else
						imm[1] = 0x11;	/* keep proto */
					if (v) {
						/* the byte the guard actually
						 * reads, at data+off(+1) */
						if (!p)
							imm[0] = data[0];
						else
							imm[1] = data[9];
					}
					snprintf(arm, sizeof(arm), "%s.%s%d", env,
						 v ? "alt" : "std", off);
					f562_arm(env, arm, F[r].tag, g,
						 NFT_PAYLOAD_NETWORK_HEADER,
						 (uint32_t)off, 2, 0, 0, 1, 0,
						 imm, &F[r], wire, wlen, wfd,
						 rfd, &ctls[r], NULL);
				}
			}
		}
	}
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	static struct f562_frame F[5];
	static struct f559_out ctls[5];
	const char *mode = argc > 1 ? argv[1] : "f562";
	int wfd, rfd;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F562 BEGIN|mode=%s\n", mode);
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F562 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F562 KERNEL|%s\n", "7.3.4-T558");
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
	printf("F562 NFL|%d\n", NFL59);

	memset(F, 0, sizeof(F));
	F[0].tag = "p";   F[0].kind = FK33_IP4; F[0].ntag = 0;
	F[1].tag = "w";   F[1].kind = FK33_IP4; F[1].ntag = 1;
	F[1].tp1 = 0x8100; F[1].tc1 = 0x0064;
	F[2].tag = "q";   F[2].kind = FK33_IP4; F[2].ntag = 2;
	F[2].tp1 = 0x88a8; F[2].tc1 = 0x0064;
	F[2].tp2 = 0x8100; F[2].tc2 = 0x00c8;
	F[3].tag = "pa";  F[3].kind = FK33_ARP; F[3].ntag = 0;
	F[4].tag = "qa";  F[4].kind = FK33_ARP; F[4].ntag = 2;
	F[4].tp1 = 0x88a8; F[4].tc1 = 0x0064;
	F[4].tp2 = 0x8100; F[4].tc2 = 0x00c8;
	{
		int i;

		for (i = 0; i < 5; i++)
			f562_build(&F[i]);
	}

	if (add_table(NFPROTO_BRIDGE, "p62") ||
	    f556_add_chain(NFPROTO_BRIDGE, "p62", "g", 0, 0, 1, NULL)) {
		printf("F562 FAIL|chain\n");
		return 0;
	}
	wfd = cap_open("r1");
	rfd = cap_open("r0");
	printf("F562 SECTION|open|wfd=%d|rfd=%d\n", wfd, rfd);

	f562_sec_ctl(F, 5, wfd, rfd, ctls);
	if (!strcmp(mode, "f562ctl")) {
		goto done;
	} else if (!strcmp(mode, "f562rd")) {
		f562_sec_rd(F, 3, wfd, rfd, ctls);
	} else if (!strcmp(mode, "f562pair")) {
		f562_sec_pair(F, wfd, rfd, ctls);
	} else if (!strcmp(mode, "f562ih")) {
		f562_sec_ih(F, wfd, rfd, ctls);
	} else if (!strcmp(mode, "f562qarp")) {
		f562_sec_qarp(F, wfd, rfd, ctls);
	} else if (!strcmp(mode, "f562val")) {
		f562_sec_val(F, wfd, rfd, ctls);
	} else {
		f562_sec_rd(F, 3, wfd, rfd, ctls);
		f562_sec_pair(F, wfd, rfd, ctls);
		f562_sec_ih(F, wfd, rfd, ctls);
		f562_sec_qarp(F, wfd, rfd, ctls);
		f562_sec_val(F, wfd, rfd, ctls);
	}
done:
	sh("/nft flush ruleset");
	printf("F562 DONE\n");
	return 0;
}
