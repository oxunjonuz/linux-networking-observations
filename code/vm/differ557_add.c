/* differ557_add.c -- turn 557 / F35: is the ll boundary a property of the
 * WRITE or of the ENVELOPE?
 *
 * F33 measured the shape of nft_ll_write_ok() on ethernet frames and found a
 * boundary at 14 -- exactly the ethernet header length.  The guard is
 *
 *	static bool nft_ll_write_ok(pkt, int offset)
 *	{
 *		if (nft_in_ingress(pkt->state)) return true;
 *		return offset <= skb_network_offset(pkt->skb);
 *	}
 *
 * called as `nft_ll_write_ok(pkt, priv->len + priv->offset + offset)` where
 * `offset = skb_mac_header(skb) - skb->data - vlan_hlen`, and in 7.3
 * `skb_network_offset()` is `skb_network_header() - skb->data` (NOT relative
 * to the mac header -- that changed long ago and the guard's arithmetic
 * depends on it).  Substituting, the condition is
 *
 *	priv->offset + priv->len  <=  skb_network_header - skb_mac_header + vlan_hlen
 *
 * i.e. "the write ends at or before the network header", where the right
 * side is the length of the LINK HEADER OF THIS ENVELOPE, plus vlan_hlen.
 * On ethernet that is 14.  This differ asks what it is when the envelope is
 *
 *   VLAN    an 802.1Q frame whose tag the receive path pulled into skb
 *           metadata (skb_vlan_tag_present): vlan_hlen = 4 for stores at
 *           offset >= 16, and mac_header was advanced by 4 by
 *           skb_reorder_vlan_header().  The two do NOT cancel: the right
 *           side becomes 18 (prediction).
 *
 *   ipip    an L3 tunnel: ipip_tunnel_rcv() calls skb_reset_mac_header()
 *           right after iptunnel_pull_header(), so mac_header == data and
 *           the right side is 0 (prediction): EVERY ll store dies.
 *
 *   vxlan   an L2 tunnel: vxlan_set_mac() calls skb_reset_mac_header() and
 *           then eth_type_trans(), so the inner packet looks exactly like a
 *           received ethernet frame and the right side is 14 again
 *           (prediction).
 *
 * Sections
 *   A  the 40-cell grid of F33 on plain and VLAN frames, in the ip family
 *      (prerouting) and the bridge family (prerouting).  p4s is the SAME
 *      grid through the OLD (2 s ACK window) helper, as a calibration of the
 *      fast helper used everywhere else in this file.
 *   B  the verdict: chain policy drop, `@ll,... counter accept`.  On an
 *      untagged frame cell (12,1) is alive and (16,2) is dead; on a tagged
 *      frame the same two cells must swap (prediction).
 *   C  the tunnels: the same grid on the packet that comes OUT of an ipip
 *      device and out of a vxlan device, with the rule gated on `meta iif`
 *      so the OUTER packet is not counted.  The control arm (no store) is
 *      the proof that the inner packet really reaches the chain.
 *
 * Oracle per arm: the kernel's own counter, placed AFTER the store in the
 * same rule (cnt=1: the guard passed and the rest of the rule ran, cnt=0: the
 * store was refused and log/counter/verdict never ran).  NFLOG carries the
 * frame as it looks at the log point, so every alive cell also gets its bytes
 * against the control arm.
 */

#include <linux/if_tunnel.h>

/* ---------- fast nfnetlink: same batch, a 250 ms ACK window ----------
 *
 * nl_open() in differ555.c sets SO_RCVTIMEO to 2 s and batch_send() drains
 * ACKs until recv() times out, so every single-message transaction costs the
 * full 2 s (the F33 arm timings show ms=2009,2048,...).  This differ needs
 * ~200 arms per boot, so the wait is shortened to 250 ms and the number of
 * ACKs is PRINTED in every arm, which is what makes the speed-up auditable:
 * a transaction that was not acknowledged shows up as acks=0.
 */
static int f557_nl_open(int tmo_ms)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	tv.tv_sec = tmo_ms / 1000;
	tv.tv_usec = (tmo_ms % 1000) * 1000;
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -2;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int f557_batch(char *buf, int len, int *acks)
{
	char rbuf[8192];
	int fd, err = 0, n = 0;

	*acks = 0;
	fd = f557_nl_open(250);
	if (fd < 0)
		return -1;
	if (send(fd, buf, (size_t)len, 0) != len) {
		close(fd);
		return -2;
	}
	for (;;) {
		int rl = (int)recv(fd, rbuf, sizeof(rbuf), 0);
		struct nlmsghdr *h;

		if (rl <= 0)
			break;
		for (h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, rl);
		     h = NLMSG_NEXT(h, rl)) {
			if (h->nlmsg_type != NLMSG_ERROR)
				continue;
			{
				struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);

				n++;
				if (e->error && !err)
					err = e->error;
			}
		}
	}
	close(fd);
	*acks = n;
	return err;
}

static int f557_nft_one(char *msgbuf, int msglen, int *acks)
{
	char batch[8192];
	struct nlmsghdr *bn, *en;
	int off;

	bn = msg_start(batch, (int)sizeof(batch), NFNL_MSG_BATCH_BEGIN,
		       NLM_F_REQUEST, 0);
	((struct nfgenmsg *)NLMSG_DATA(bn))->res_id = htons(NFNL_SUBSYS_NFTABLES);
	off = (int)NLMSG_ALIGN(bn->nlmsg_len);
	memcpy(batch + off, msgbuf, (size_t)NLMSG_ALIGN(msglen));
	off += (int)NLMSG_ALIGN(msglen);
	en = msg_start(batch + off, (int)(sizeof(batch) - off),
		       NFNL_MSG_BATCH_END, NLM_F_REQUEST, 0);
	((struct nfgenmsg *)NLMSG_DATA(en))->res_id = htons(NFNL_SUBSYS_NFTABLES);
	off += (int)NLMSG_ALIGN(en->nlmsg_len);
	return f557_batch(batch, off, acks);
}

static int f557_flush(uint8_t fam, const char *table, const char *chain,
		      int *acks)
{
	struct nlmsghdr *nlh;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELRULE,
			NLM_F_REQUEST | NLM_F_ACK, fam);
	put_str(nlh, NFTA_RULE_TABLE, table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

/* one rule: [meta iif == iif ][store <base>+off = imm][log][counter][accept]
 * iif == 0 means: no match, the rule sees every packet that reaches the
 * chain (this is how every non-tunnel arm runs). */
static int f557_install(uint8_t fam, const char *table, const char *chain,
			uint32_t iif, uint32_t base, uint32_t off, uint32_t len,
			const unsigned char *imm, int immlen, int do_store,
			int loggroup, const char *prefix, int *acks)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs, *e, *d, *cd;
	/* nft_meta_store_ifindex() writes the index with *dest = ifindex,
	 * i.e. NATIVE order -- comparing against htonl() never matches
	 * (measured: every gated arm was 0, including a gate on the device
	 * the frame demonstrably arrives on). */
	uint32_t iif_be = iif;

	nlh = msg_start(opbuf, (int)sizeof(opbuf),
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			fam);
	put_str(nlh, NFTA_RULE_TABLE, table);
	put_str(nlh, NFTA_RULE_CHAIN, chain);
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS);
	if (iif) {
		e = nest_start(nlh, NFTA_LIST_ELEM);
		put_str(nlh, NFTA_EXPR_NAME, "meta");
		d = nest_start(nlh, NFTA_EXPR_DATA);
		put_be32(nlh, NFTA_META_KEY, NFT_META_IIF);
		put_be32(nlh, NFTA_META_DREG, NFT_REG32_00);
		nest_end(nlh, d);
		nest_end(nlh, e);

		e = nest_start(nlh, NFTA_LIST_ELEM);
		put_str(nlh, NFTA_EXPR_NAME, "cmp");
		d = nest_start(nlh, NFTA_EXPR_DATA);
		put_be32(nlh, NFTA_CMP_SREG, NFT_REG32_00);
		put_be32(nlh, NFTA_CMP_OP, NFT_CMP_EQ);
		cd = nest_start(nlh, NFTA_CMP_DATA);
		attr_put(nlh, NFTA_DATA_VALUE, &iif_be, 4);
		nest_end(nlh, cd);
		nest_end(nlh, d);
		nest_end(nlh, e);
	}
	if (do_store) {
		imm_value(nlh, NFT_REG32_00, imm, immlen);
		e = nest_start(nlh, NFTA_LIST_ELEM);
		put_str(nlh, NFTA_EXPR_NAME, "payload");
		d = nest_start(nlh, NFTA_EXPR_DATA);
		put_be32(nlh, NFTA_PAYLOAD_SREG, NFT_REG32_00);
		put_be32(nlh, NFTA_PAYLOAD_BASE, base);
		put_be32(nlh, NFTA_PAYLOAD_OFFSET, off);
		put_be32(nlh, NFTA_PAYLOAD_LEN, len);
		put_be32(nlh, NFTA_PAYLOAD_CSUM_TYPE, NFT_PAYLOAD_CSUM_NONE);
		put_be32(nlh, NFTA_PAYLOAD_CSUM_OFFSET, 0);
		nest_end(nlh, d);
		nest_end(nlh, e);
	}
	log_expr(nlh, loggroup, prefix);
	counter_expr(nlh);
	accept_expr(nlh);
	nest_end(nlh, exprs);
	return f557_nft_one(opbuf, (int)nlh->nlmsg_len, acks);
}

/* ---------- frames ---------- */

enum { F557_PLAIN = 0, F557_VLAN, F557_IPIP, F557_VXLAN };

/* the plain ethernet + IPv4 + UDP frame, unchanged from F33 */
static int f557_mk_plain(unsigned char *out)
{
	return f556_frame(FK33_IP4, out);
}

/* the SAME datagram inside an 802.1Q frame: dst, src, 0x8100, TCI 0x0064,
 * inner ethertype 0x0800, then the identical IPv4 header and payload.  The
 * receive path will pull the 4 tag bytes into skb metadata, which is the
 * envelope this arm is about. */
static int f557_mk_vlan(unsigned char *out)
{
	unsigned char tmp[256];
	int n = f556_frame(FK33_IP4, tmp);

	memset(out, 0, 256);
	memcpy(out, M33_BC, 6);		/* dst */
	memcpy(out + 6, MAC_SRC, 6);		/* src */
	out[12] = 0x81; out[13] = 0x00;		/* 802.1Q */
	out[14] = 0x00; out[15] = 0x64;		/* TCI: prio 0, vlan 100 */
	out[16] = 0x08; out[17] = 0x00;		/* inner ethertype */
	memcpy(out + 18, tmp + 14, (size_t)(n - 14));
	return n + 4;
}

/* ethernet + IPv4(proto 4) + IPv4(proto 17) + UDP, outer dst = the guest's
 * own address on i1, so the frame is delivered locally and ipip_tunnel_rcv()
 * decapsulates it into the ipip device. */
static int f557_mk_ipip(unsigned char *out)
{
	unsigned char *oip = out + 14;
	unsigned char *iip = oip + 20;
	unsigned char *u = iip + 20;
	int tot = 20 + 20 + 8 + 18;
	unsigned short c;

	memset(out, 0, 512);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = 0x08; out[13] = 0x00;
	oip[0] = 0x45;
	oip[2] = (unsigned char)(tot >> 8);
	oip[3] = (unsigned char)tot;
	oip[4] = 0x12; oip[5] = 0x35;
	oip[8] = 64; oip[9] = 4;
	oip[12] = 0x0a; oip[13] = 0x01; oip[14] = 0x00; oip[15] = 0x01;
	oip[16] = 0x0a; oip[17] = 0x09; oip[18] = 0x00; oip[19] = 0x07;
	c = f556_csum(oip, 20);
	oip[10] = (unsigned char)(c >> 8); oip[11] = (unsigned char)c;

	iip[0] = 0x45;
	iip[2] = 0; iip[3] = 20 + 8 + 18;
	iip[4] = 0x12; iip[5] = 0x36;
	iip[8] = 63; iip[9] = 17;
	iip[12] = 0x0a; iip[13] = 0x42; iip[14] = 0x01; iip[15] = 0x01;	/* 10.66.1.1 */
	iip[16] = 0x0a; iip[17] = 0x42; iip[18] = 0x01; iip[19] = 0x02;	/* 10.66.1.2 */
	c = f556_csum(iip, 20);
	iip[10] = (unsigned char)(c >> 8); iip[11] = (unsigned char)c;

	u[0] = 0x9c; u[1] = 0x41; u[2] = 0x13; u[3] = 0x89;
	u[4] = 0x00; u[5] = 26;
	memset(u + 8, 0x77, 18);
	return 14 + tot;
}

/* ethernet + IPv4(proto 17) + UDP:4789 + VXLAN(VNI 557) + ethernet +
 * IPv4(proto 17) + UDP.  The outer destination is the guest's address on i1,
 * the vxlan device is bound to it, and the inner frame is a completely
 * ordinary ethernet frame -- that is the L2 envelope. */
static int f557_mk_vxlan(unsigned char *out)
{
	unsigned char *oip = out + 14;
	unsigned char *u = oip + 20;
	unsigned char *vx = u + 8;
	unsigned char *ieh = vx + 8;
	unsigned char *iip = ieh + 14;
	unsigned char *iu = iip + 20;
	int udp_len = 8 + 8 + 14 + 20 + 8 + 18;
	int tot = 20 + udp_len;
	unsigned short c;

	memset(out, 0, 512);
	memcpy(out, M33_BC, 6);
	memcpy(out + 6, MAC_SRC, 6);
	out[12] = 0x08; out[13] = 0x00;

	oip[0] = 0x45;
	oip[2] = (unsigned char)(tot >> 8);
	oip[3] = (unsigned char)tot;
	oip[4] = 0x12; oip[5] = 0x37;
	oip[8] = 64; oip[9] = 17;
	oip[12] = 0x0a; oip[13] = 0x01; oip[14] = 0x00; oip[15] = 0x01;
	oip[16] = 0x0a; oip[17] = 0x09; oip[18] = 0x00; oip[19] = 0x07;
	c = f556_csum(oip, 20);
	oip[10] = (unsigned char)(c >> 8); oip[11] = (unsigned char)c;

	u[0] = 0x9c; u[1] = 0x42;			/* sport 40002 */
	u[2] = 0x12; u[3] = 0xb5;			/* dport 4789 */
	u[4] = (unsigned char)(udp_len >> 8);
	u[5] = (unsigned char)udp_len;
	u[6] = 0; u[7] = 0;				/* checksum 0: legal v4 */

	vx[0] = 0x08;					/* VNI valid */
	vx[4] = 0x00; vx[5] = 0x02; vx[6] = 0x2d;	/* VNI 557 */
	vx[7] = 0x00;

	memcpy(ieh, M33_BC, 6);
	memcpy(ieh + 6, MAC_SRC, 6);
	ieh[12] = 0x08; ieh[13] = 0x00;

	iip[0] = 0x45;
	iip[2] = 0; iip[3] = 20 + 8 + 18;
	iip[4] = 0x12; iip[5] = 0x38;
	iip[8] = 63; iip[9] = 17;
	iip[12] = 0x0a; iip[13] = 0x42; iip[14] = 0x02; iip[15] = 0x01;	/* 10.66.2.1 */
	iip[16] = 0x0a; iip[17] = 0x42; iip[18] = 0x02; iip[19] = 0x02;	/* 10.66.2.2 */
	c = f556_csum(iip, 20);
	iip[10] = (unsigned char)(c >> 8); iip[11] = (unsigned char)c;

	iu[0] = 0x9c; iu[1] = 0x43; iu[2] = 0x13; iu[3] = 0x8a;
	iu[4] = 0x00; iu[5] = 26;
	memset(iu + 8, 0x77, 18);
	return 14 + tot;
}

static int f557_frame(int kind, unsigned char *out)
{
	switch (kind) {
	case F557_PLAIN:
		return f557_mk_plain(out);
	case F557_VLAN:
		return f557_mk_vlan(out);
	case F557_IPIP:
		return f557_mk_ipip(out);
	case F557_VXLAN:
		return f557_mk_vxlan(out);
	}
	return 0;
}

static unsigned short f557_proto(int kind)
{
	return kind == F557_VLAN ? 0x8100 : 0x0800;
}

/* ---------- one envelope ---------- */

struct f557_env {
	const char *tag;
	uint8_t fam;
	const char *table;
	const char *chain;
	uint32_t hook;
	uint32_t base;
	const char *dev;
	const char *rule_dev;
	uint32_t iif;
	int kind;
	int policy;		/* 1 = accept, 0 = drop */
	int send_raw;		/* 0 = ethernet frame, 4 = ipip outer,
				 * 17 = vxlan outer, both via a raw socket */
};

static int NFL57 = -1;
static char PRE57[96];
static int f557_raw_send(int proto, const unsigned char *payload, int plen);
static int f557_inner_only(unsigned char *out);
static int f557_vxlan_payload(unsigned char *out);

static void f557_imm(int off, int len, unsigned char *imm)
{
	int i;

	memset(imm, 0, 16);
	for (i = 0; i < len && i < 16; i++)
		imm[i] = (unsigned char)(0x90 + i);
}

static unsigned long long f557_ctl(const struct f557_env *e, const char *tag,
				   int fast)
{
	unsigned char fr[512], pay[192];
	unsigned long long cnt, cnt0;
	int flen, n = 0, rc, acks = -1, i;

	flen = f557_frame(e->kind, fr);
	snprintf(PRE57, sizeof(PRE57), "f57.%s.%s", e->tag, tag);
	if (fast) {
		f557_flush(e->fam, e->table, e->chain, &acks);
		rc = f557_install(e->fam, e->table, e->chain, e->iif, 0, 0, 0,
				  NULL, 0, 0, 5, PRE57, &acks);
	} else {
		flush_chain(e->fam, e->table, e->chain);
		rc = install_ctl(e->fam, e->table, e->chain, 5, PRE57);
	}
	nfl_drain(NFL57);
	cnt0 = (rc == 0) ? f555_count(e->fam, e->table, e->chain) : 0;
	if (rc == 0) {
		usleep(15000);
		if (e->send_raw) {
			unsigned char inner[512];
			int il = e->send_raw == 17 ? f557_vxlan_payload(inner)
						   : f557_inner_only(inner);

			f557_raw_send(e->send_raw, inner, il);
		} else {
			pkt_send_p(e->dev, fr, flen, f557_proto(e->kind));
		}
		n = nfl_wait(NFL57, PRE57, pay, (int)sizeof(pay), 300);
	}
	cnt = f555_count(e->fam, e->table, e->chain);
	printf("F557 CTL|env=%s|kind=%d|fast=%d|rc=%d|acks=%d|cnt=%llu|cnt0=%llu|nfl=%d|hex=",
	       e->tag, e->kind, fast, rc, acks, cnt, cnt0, n);
	for (i = 0; i < n && i < 96; i++)
		printf("%02x", pay[i]);
	printf("\n");
	return cnt;
}

static unsigned long long f557_arm(const struct f557_env *e, const char *tag,
				   int off, int len, const unsigned char *imm,
				   int immlen, int fast)
{
	unsigned char fr[512], pay[192];
	unsigned long long cnt, cnt0;
	int flen, n = 0, rc, acks = -1, i;
	long t0, t1;

	flen = f557_frame(e->kind, fr);
	snprintf(PRE57, sizeof(PRE57), "f57.%s.%s", e->tag, tag);
	t0 = f33_ms();
	if (fast) {
		f557_flush(e->fam, e->table, e->chain, &acks);
		rc = f557_install(e->fam, e->table, e->chain, e->iif, e->base,
				  (uint32_t)off, (uint32_t)len, imm, immlen, 1,
				  5, PRE57, &acks);
	} else {
		flush_chain(e->fam, e->table, e->chain);
		rc = f556_install_store(e->fam, e->table, e->chain, e->base, off,
					len, imm, immlen, 5, PRE57);
	}
	t1 = f33_ms();
	nfl_drain(NFL57);
	cnt0 = (rc == 0) ? f555_count(e->fam, e->table, e->chain) : 0;
	if (rc == 0) {
		usleep(15000);
		if (e->send_raw) {
			unsigned char inner[512];
			int il = e->send_raw == 17 ? f557_vxlan_payload(inner)
						   : f557_inner_only(inner);

			f557_raw_send(e->send_raw, inner, il);
		} else {
			pkt_send_p(e->dev, fr, flen, f557_proto(e->kind));
		}
		n = nfl_wait(NFL57, PRE57, pay, (int)sizeof(pay), 200);
	}
	cnt = f555_count(e->fam, e->table, e->chain);
	printf("F557 R|env=%s|arm=%s|off=%d|len=%d|kind=%d|fast=%d|rc=%d|acks=%d|"
	       "cnt=%llu|cnt0=%llu|nfl=%d|ms=%ld|hex=",
	       e->tag, tag, off, len, e->kind, fast, rc, acks, cnt, cnt0, n,
	       t1 - t0);
	for (i = 0; i < n && i < 96; i++)
		printf("%02x", pay[i]);
	printf("\n");
	return cnt;
}

/* create table + one chain */
static int f557_chain(const struct f557_env *e)
{
	int rc, rc2;

	rc = add_table(e->fam, e->table);
	rc2 = f556_add_chain(e->fam, e->table, e->chain, e->hook, 0,
			     (uint32_t)e->policy, e->rule_dev);
	printf("F557 CHAIN|env=%s|table=%d|chain=%d|policy=%d\n", e->tag, rc, rc2,
	       e->policy);
	return rc || rc2;
}

static const int G57_OFF[12] = { 0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24 };
static const int G57_LEN[3] = { 1, 2, 4 };
static const int T57_OFF[7] = { 0, 6, 10, 12, 14, 16, 20 };

static void f557_grid(const struct f557_env *e, const int *offs, int noff,
		      const int *lens, int nlen, int fast)
{
	unsigned char imm[16];
	char tag[32];
	int i, j;

	for (i = 0; i < noff; i++) {
		for (j = 0; j < nlen; j++) {
			f557_imm(offs[i], lens[j], imm);
			snprintf(tag, sizeof(tag), "g%d_%d", offs[i], lens[j]);
			f557_arm(e, tag, offs[i], lens[j], imm, lens[j], fast);
		}
	}
}


/* ---------- A: plain vs VLAN, in the ip family and in the bridge ---------- */

static void f557_sec_grid(const char *only)
{
	struct f557_env e;
	struct f556_env e33;
	unsigned char imm[16];
	char tag[32];
	int i, j;

	/* p4s: the F33 cell-for-cell reference, through the OLD helper
	 * (2 s ACK window), plain ethernet frame, ip family prerouting.
	 * Whatever the fast helper says in p4 has to match this. */
	if (!only || !strcmp(only, "p4s")) {
		memset(&e33, 0, sizeof(e33));
		e33.tag = "p4s"; e33.fam = NFPROTO_IPV4; e33.table = "p57s";
		e33.chain = "pre"; e33.hook = 0;
		e33.base = NFT_PAYLOAD_LL_HEADER; e33.dev = "i0";
		e33.kind = FK33_IP4;
		if (!f556_chain(&e33)) {
			f556_ctl(&e33, FK33_IP4);
			for (i = 0; i < 12; i++) {
				for (j = 0; j < 3; j++) {
					f556_imm(FK33_IP4, G57_OFF[i],
						 G57_LEN[j], imm);
					snprintf(tag, sizeof(tag), "g%d_%d",
						 G57_OFF[i], G57_LEN[j]);
					f556_arm(&e33, tag, G57_OFF[i],
						 G57_LEN[j], imm, G57_LEN[j],
						 FK33_IP4);
				}
			}
			sh("/nft flush ruleset");
		}
	}
	/* p4: the same grid, same envelope, FAST helper */
	if (!only || !strcmp(only, "p4")) {
		memset(&e, 0, sizeof(e));
		e.tag = "p4"; e.fam = NFPROTO_IPV4; e.table = "p57a";
		e.chain = "pre"; e.hook = 0; e.policy = 1;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
		e.kind = F557_PLAIN;
		if (!f557_chain(&e)) {
			f557_ctl(&e, "ctl", 1);
			f557_grid(&e, G57_OFF, 12, G57_LEN, 3, 1);
		}
	}
	/* v4: 802.1Q frame, same family, same hook, same grid */
	if (!only || !strcmp(only, "v4")) {
		memset(&e, 0, sizeof(e));
		e.tag = "v4"; e.fam = NFPROTO_IPV4; e.table = "p57b";
		e.chain = "pre"; e.hook = 0; e.policy = 1;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
		e.kind = F557_VLAN;
		if (!f557_chain(&e)) {
			f557_ctl(&e, "ctl", 1);
			f557_grid(&e, G57_OFF, 12, G57_LEN, 3, 1);
		}
	}
	/* pB: plain frame at the bridge prerouting hook -- NFLOG here logs
	 * the L2 frame, so this envelope carries the BYTE evidence */
	if (!only || !strcmp(only, "pB")) {
		memset(&e, 0, sizeof(e));
		e.tag = "pB"; e.fam = NFPROTO_BRIDGE; e.table = "p57c";
		e.chain = "pre"; e.hook = 0; e.policy = 1;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "s0";
		e.kind = F557_PLAIN;
		if (!f557_chain(&e)) {
			f557_ctl(&e, "ctl", 1);
			f557_grid(&e, G57_OFF, 12, G57_LEN, 3, 1);
		}
	}
	/* vB: the same, tagged */
	if (!only || !strcmp(only, "vB")) {
		memset(&e, 0, sizeof(e));
		e.tag = "vB"; e.fam = NFPROTO_BRIDGE; e.table = "p57d";
		e.chain = "pre"; e.hook = 0; e.policy = 1;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "s0";
		e.kind = F557_VLAN;
		if (!f557_chain(&e)) {
			f557_ctl(&e, "ctl", 1);
			f557_grid(&e, G57_OFF, 12, G57_LEN, 3, 1);
		}
	}
}

/* ---------- B: the verdict, under policy drop ---------- */

/* Chain policy is DROP and the rule ends in accept, so the kernel's counter
 * answers two questions at once: did the guard pass the store (cnt=1), and
 * did the packet get accepted (cnt=1 for the same reason).  The control arm
 * has the same rule with no store and must be 1 on both frames -- otherwise
 * "cnt=0" would not distinguish "the store was refused" from "the frame never
 * reached this chain". */
static void f557_sec_verdict(const char *only)
{
	static const struct {
		const char *tag;
		int off, len;
		unsigned char v[2];
	} arms[] = {
		{ "b12_1", 12, 1, { 0x90, 0x00 } },
		{ "b14_2", 14, 2, { 0x00, 0x64 } },
		{ "b16_2", 16, 2, { 0x08, 0x06 } },
	};
	struct f557_env e;
	unsigned char imm[16];
	unsigned int k;

	if (!only || !strcmp(only, "verdict")) {
		/* plain frame */
		memset(&e, 0, sizeof(e));
		e.tag = "vp"; e.fam = NFPROTO_IPV4; e.table = "p57e";
		e.chain = "pre"; e.hook = 0; e.policy = 0;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
		e.kind = F557_PLAIN;
		if (!f557_chain(&e)) {
			f557_ctl(&e, "ctl", 1);
			for (k = 0; k < 3; k++) {
				memset(imm, 0, sizeof(imm));
				memcpy(imm, arms[k].v, 2);
				f557_arm(&e, arms[k].tag, arms[k].off,
					 arms[k].len, imm, arms[k].len, 1);
			}
		}
		/* tagged frame, same three arms */
		memset(&e, 0, sizeof(e));
		e.tag = "vv"; e.fam = NFPROTO_IPV4; e.table = "p57f";
		e.chain = "pre"; e.hook = 0; e.policy = 0;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
		e.kind = F557_VLAN;
		if (!f557_chain(&e)) {
			f557_ctl(&e, "ctl", 1);
			for (k = 0; k < 3; k++) {
				memset(imm, 0, sizeof(imm));
				memcpy(imm, arms[k].v, 2);
				f557_arm(&e, arms[k].tag, arms[k].off,
					 arms[k].len, imm, arms[k].len, 1);
			}
		}
		/* the same three arms in the BRIDGE family, where the tagged
		 * frame demonstrably arrives (T557 has no CONFIG_VLAN_8021Q,
		 * so the ip family never sees it: measured, see DIAG9) */
		memset(&e, 0, sizeof(e));
		e.tag = "bp"; e.fam = NFPROTO_BRIDGE; e.table = "p57g";
		e.chain = "pre"; e.hook = 0; e.policy = 0;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "s0";
		e.kind = F557_PLAIN;
		if (!f557_chain(&e)) {
			f557_ctl(&e, "ctl", 1);
			for (k = 0; k < 3; k++) {
				memset(imm, 0, sizeof(imm));
				memcpy(imm, arms[k].v, 2);
				f557_arm(&e, arms[k].tag, arms[k].off,
					 arms[k].len, imm, arms[k].len, 1);
			}
		}
		memset(&e, 0, sizeof(e));
		e.tag = "bv"; e.fam = NFPROTO_BRIDGE; e.table = "p57i";
		e.chain = "pre"; e.hook = 0; e.policy = 0;
		e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "s0";
		e.kind = F557_VLAN;
		if (!f557_chain(&e)) {
			f557_ctl(&e, "ctl", 1);
			for (k = 0; k < 3; k++) {
				memset(imm, 0, sizeof(imm));
				memcpy(imm, arms[k].v, 2);
				f557_arm(&e, arms[k].tag, arms[k].off,
					 arms[k].len, imm, arms[k].len, 1);
			}
		}
		sh("/nft flush ruleset");
	}
}

/* ---------- C: the tunnels ---------- */

static int f557_link_add_vxlan(const char *name, uint32_t vni,
			       uint32_t local_be, uint16_t port, uint8_t learn)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[512];
	} req;
	struct nlattr *li, *data;
	uint32_t v = vni;		/* IFLA_VXLAN_ID is read with nla_get_u32() */
	uint16_t p = htons(port);
	int fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	attr_put(&req.nlh, IFLA_IFNAME, name, (int)strlen(name) + 1);
	li = nest_start(&req.nlh, IFLA_LINKINFO);
	attr_put(&req.nlh, IFLA_INFO_KIND, "vxlan", 6);
	data = nest_start(&req.nlh, IFLA_INFO_DATA);
	attr_put(&req.nlh, IFLA_VXLAN_ID, &v, 4);
	if (local_be)
		attr_put(&req.nlh, IFLA_VXLAN_LOCAL, &local_be, 4);
	if (port)
		attr_put(&req.nlh, IFLA_VXLAN_PORT, &p, 2);
	attr_put(&req.nlh, IFLA_VXLAN_LEARNING, &learn, 1);
	nest_end(&req.nlh, data);
	nest_end(&req.nlh, li);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

static void f557_sec_tunnel(const char *only)
{
	struct f557_env e;
	int rc, idx;

	if (only && strcmp(only, "tunnel"))
		return;
	/* the outer datagram is addressed to the guest's own i1, so it is
	 * delivered locally and the tunnel device decapsulates it */
	f555_addr_add("i1", htonl(0x0a090007), 24);
	f555_addr_add("i0", htonl(0x0a010001), 24);

	/* ---- ipip: an L3 tunnel ----
	 * Not created here: ipip_init_net() already made the fallback device
	 * tunl0 in this netns (it is in /proc/net/dev before any code of
	 * this differ runs), with all-zero params, i.e. exactly the wildcard
	 * tunnel a decapsulation needs.  Creating a second one with the same
	 * params returns -EEXIST from ip_tunnel_newlink() -- measured, see
	 * the f557diag arms. */
	rc = set_up("tunl0");
	f555_addr_add("tunl0", htonl(0x0a420102), 32);	/* 10.66.1.2 */
	idx = f555_ifindex("tunl0");
	printf("F557 TUN|ipip|link=%d|ifindex=%d\n", rc, idx);
	memset(&e, 0, sizeof(e));
	e.tag = "ipip"; e.fam = NFPROTO_IPV4; e.table = "p57t";
	e.chain = "pre"; e.hook = 0; e.policy = 1;
	e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
	e.iif = (uint32_t)idx; e.kind = F557_IPIP; e.send_raw = 4;
	if (!f557_chain(&e)) {
		unsigned long long c = f557_ctl(&e, "ctl", 1);

		printf("F557 TUNCTL|ipip|cnt=%llu\n", c);
		if (c)
			f557_grid(&e, T57_OFF, 7, G57_LEN, 3, 1);
	}

	/* ---- vxlan: an L2 tunnel ---- */
	rc = f557_link_add_vxlan("v557", 557, htonl(0x0a090007), 4789, 1);
	set_up("v557");
	f555_addr_add("v557", htonl(0x0a420202), 24);	/* 10.66.2.2 */
	idx = f555_ifindex("v557");
	printf("F557 TUN|vxlan|link=%d|ifindex=%d\n", rc, idx);
	memset(&e, 0, sizeof(e));
	e.tag = "vxlan"; e.fam = NFPROTO_IPV4; e.table = "p57u";
	e.chain = "pre"; e.hook = 0; e.policy = 1;
	e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0";
	e.iif = (uint32_t)idx; e.kind = F557_VXLAN; e.send_raw = 17;
	if (!f557_chain(&e)) {
		unsigned long long c = f557_ctl(&e, "ctl", 1);

		printf("F557 TUNCTL|vxlan|cnt=%llu\n", c);
		if (c)
			f557_grid(&e, T57_OFF, 7, G57_LEN, 3, 1);
	}
	sh("/nft flush ruleset");
}


/* ---------- D: why a tunnel device does not come up ---------- */

static void f557_devlist(void)
{
	int fd = open("/proc/net/dev", O_RDONLY);
	char buf[2048];
	int n;

	if (fd < 0) {
		printf("F557 DEV|open_failed|%d\n", errno);
		return;
	}
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) {
		printf("F557 DEV|read_failed|%d\n", n);
		return;
	}
	buf[n] = 0;
	{
		char *l = buf;
		char *nl;

		while ((nl = strchr(l, '\n')) != NULL) {
			*nl = 0;
			if (strchr(l, ':'))
				printf("F557 DEV|%s\n", l);
			l = nl + 1;
		}
	}
}

static void f557_diag(const char *only)
{
	int rc;

	(void)only;
	rc = f556_link_add_kind("t557", "ipip");
	printf("F557 DIAG|ipip_bare|%d|ifindex=%d\n", rc, f555_ifindex("t557"));
	f555_addr_add("i1", htonl(0x0a090007), 24);
	printf("F557 DIAG|tunl0_ifindex|%d|up=%d\n",
	       f555_ifindex("tunl0"), set_up("tunl0"));
	rc = f556_link_add_kind("p557", "ipip");
	printf("F557 DIAG|ipip_second_name|%d|ifindex=%d\n", rc,
	       f555_ifindex("p557"));
	rc = f556_link_add_kind("g557", "gretap");
	printf("F557 DIAG|gretap_bare|%d|ifindex=%d\n", rc, f555_ifindex("g557"));
	rc = f557_link_add_vxlan("x557", 557, 0, 0, 1);
	printf("F557 DIAG|vxlan_id_only|%d|ifindex=%d\n", rc, f555_ifindex("x557"));
	rc = f557_link_add_vxlan("y557", 557, htonl(0x0a090007), 4789, 1);
	printf("F557 DIAG|vxlan_full|%d|ifindex=%d\n", rc, f555_ifindex("y557"));
	f557_devlist();
}


/* ---------- E: does the tunnel decapsulate at all? ----------
 *
 * A chain at ip prerouting with NO meta-iif gate sees the outer packet and,
 * if the tunnel device decapsulated it, the inner packet too: cnt=2 means
 * decapsulation happened, cnt=1 means only the outer packet arrived.  The
 * /proc/net/dev counters of the tunnel device say the same thing from the
 * other side.
 */
static void f557_devline(const char *name)
{
	int fd = open("/proc/net/dev", O_RDONLY);
	char buf[4096];
	int n;

	if (fd < 0)
		return;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = 0;
	{
		char *l = buf;

		while (l && *l) {
			char *nl = strchr(l, '\n');
			char *colon;

			if (nl)
				*nl = 0;
			colon = strchr(l, ':');
			if (colon && strstr(l, name) == l + (colon - l) -
			    (int)strlen(name)) {
				printf("F557 DEVLINE|%s|%s\n", name, colon + 1);
				break;
			}
			l = nl ? nl + 1 : NULL;
		}
	}
}

static void f557_diag2(void)
{
	struct f557_env e;
	unsigned char fr[512];
	unsigned long long cnt;
	int flen;

	f555_addr_add("i1", htonl(0x0a090007), 24);
	f555_addr_add("i0", htonl(0x0a010001), 24);
	set_up("tunl0");
	f555_addr_add("tunl0", htonl(0x0a420102), 32);

	/* --- ipip --- */
	memset(&e, 0, sizeof(e));
	e.tag = "d2ip"; e.fam = NFPROTO_IPV4; e.table = "p57x";
	e.chain = "pre"; e.hook = 0; e.policy = 1;
	e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0"; e.iif = 0;
	e.kind = F557_IPIP;
	if (!f557_chain(&e)) {
		f557_ctl(&e, "ctl", 1);
		cnt = f557_ctl(&e, "ctl2", 1);
		printf("F557 DIAG2|ipip|no_iif_gate|cnt=%llu\n", cnt);
	}
	f557_devline("tunl0");

	/* --- vxlan: the device must exist BEFORE the arm that measures --- */
	{
		int rc = f557_link_add_vxlan("v557", 557, htonl(0x0a090007),
					     4789, 1);

		set_up("v557");
		f555_addr_add("v557", htonl(0x0a420202), 24);
		printf("F557 DIAG2|vxlan_create|%d|ifindex=%d\n", rc,
		       f555_ifindex("v557"));
	}
	memset(&e, 0, sizeof(e));
	e.tag = "d2vx"; e.fam = NFPROTO_IPV4; e.table = "p57y";
	e.chain = "pre"; e.hook = 0; e.policy = 1;
	e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0"; e.iif = 0;
	e.kind = F557_VXLAN;
	if (!f557_chain(&e)) {
		f557_ctl(&e, "ctl", 1);
		cnt = f557_ctl(&e, "ctl2", 1);
		printf("F557 DIAG2|vxlan|no_iif_gate|cnt=%llu\n", cnt);
	}
	f557_devline("v557");

	(void)flen; (void)fr;
}


/* ---------- F: where does the tunnel packet go? ---------- */

static void f557_sysline(const char *path)
{
	int fd = open(path, O_RDONLY);
	char buf[128];
	int n;

	if (fd < 0) {
		printf("F557 SYS|%s|open_failed|%d\n", path, errno);
		return;
	}
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) {
		printf("F557 SYS|%s|read_failed\n", path);
		return;
	}
	buf[n] = 0;
	if (buf[n - 1] == '\n')
		buf[n - 1] = 0;
	printf("F557 SYS|%s|%s\n", path, buf);
}

static int f557_link_add_ipip(const char *name, uint32_t local_be,
			      uint32_t remote_be)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[256];
	} req;
	struct nlattr *li, *data;
	int fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	attr_put(&req.nlh, IFLA_IFNAME, name, (int)strlen(name) + 1);
	li = nest_start(&req.nlh, IFLA_LINKINFO);
	attr_put(&req.nlh, IFLA_INFO_KIND, "ipip", 5);
	data = nest_start(&req.nlh, IFLA_INFO_DATA);
	attr_put(&req.nlh, IFLA_IPTUN_LOCAL, &local_be, 4);
	attr_put(&req.nlh, IFLA_IPTUN_REMOTE, &remote_be, 4);
	nest_end(&req.nlh, data);
	nest_end(&req.nlh, li);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* counters at three hooks of the ip family, one frame, then the numbers */
static char TBL57[32];

static unsigned long long f557_hookcount(uint32_t hook, const char *tag)
{
	struct f557_env e;
	unsigned long long c;

	memset(&e, 0, sizeof(e));
	e.tag = tag; e.fam = NFPROTO_IPV4;
	snprintf(TBL57, sizeof(TBL57), "p57h%d", hook);
	e.table = TBL57;
	e.chain = "c"; e.hook = hook; e.policy = 1;
	e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0"; e.iif = 0;
	e.kind = F557_IPIP;
	if (f557_chain(&e))
		return 0;
	f555_count(e.fam, e.table, e.chain);
	c = f557_ctl(&e, "c1", 1);
	return c;
}

static void f557_diag3(void)
{
	int rc1, rc2, rc3;
	unsigned char fr[512];
	int flen;

	rc1 = f555_addr_add("i1", htonl(0x0a090007), 24);
	rc2 = f555_addr_add("i0", htonl(0x0a010001), 24);
	rc3 = set_up("tunl0");
	printf("F557 DIAG3|addr_i1=%d|addr_i0=%d|tunl0_up=%d|tunl0_ifindex=%d\n",
	       rc1, rc2, rc3, f555_ifindex("tunl0"));
	f555_addr_add("tunl0", htonl(0x0a420102), 32);
	f557_sysline("/sys/class/net/tunl0/flags");

	printf("F557 DIAG3|prerouting_cnt=%llu\n", f557_hookcount(0, "p0"));
	printf("F557 DIAG3|local_in_cnt=%llu\n", f557_hookcount(1, "p1"));
	printf("F557 DIAG3|forward_cnt=%llu\n", f557_hookcount(2, "p2"));

	/* an explicit tunnel with named endpoints, if the fallback is the
	 * problem: same frame, the same three probes */
	rc1 = f557_link_add_ipip("t557", htonl(0x0a090007), htonl(0x0a010001));
	set_up("t557");
	f555_addr_add("t557", htonl(0x0a420102), 32);
	printf("F557 DIAG3|explicit_tunnel|link=%d|ifindex=%d\n", rc1,
	       f555_ifindex("t557"));
	f557_sysline("/sys/class/net/t557/flags");

	f557_sysline("/sys/class/net/i0/flags");
	f557_sysline("/sys/class/net/tunl0/operstate");
	f557_sysline("/sys/class/net/tunl0/type");
	if (f555_ifindex("t557") >= 0) {
		char path[64];
		int idx = f555_ifindex("t557");

		snprintf(path, sizeof(path), "/sys/class/net/t557/uevent");
		f557_sysline(path);
		printf("F557 DIAG3|t557_index=%d\n", idx);
	}
	f557_devlist();
	flen = f557_frame(F557_IPIP, fr);
	printf("F557 DIAG3|frame_len=%d\n", flen);
}


/* ---------- G: routing, rp_filter, and a plain frame as a control ---------- */

static void f557_syswrite(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	int rc = -1;

	if (fd >= 0) {
		rc = (int)write(fd, val, strlen(val));
		close(fd);
	}
	printf("F557 SYSW|%s|%s|rc=%d\n", path, val, rc);
}

static unsigned long long f557_hookcnt_kind(uint32_t hook, const char *tag,
					    int kind)
{
	struct f557_env e;
	char tbl[32];

	memset(&e, 0, sizeof(e));
	snprintf(tbl, sizeof(tbl), "p57k%d_%d", hook, kind);
	e.tag = tag; e.fam = NFPROTO_IPV4; e.table = tbl;
	e.chain = "c"; e.hook = hook; e.policy = 1;
	e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "i0"; e.iif = 0;
	e.kind = kind;
	if (f557_chain(&e))
		return 0;
	f555_count(e.fam, e.table, e.chain);
	return f557_ctl(&e, "c1", 1);
}

static void f557_diag4(void)
{
	f555_addr_add("i1", htonl(0x0a090007), 24);
	f555_addr_add("i0", htonl(0x0a010001), 24);
	set_up("tunl0");
	f555_addr_add("tunl0", htonl(0x0a420102), 32);

	f557_sysline("/proc/sys/net/ipv4/conf/all/rp_filter");
	f557_sysline("/proc/sys/net/ipv4/conf/default/rp_filter");
	f557_sysline("/proc/sys/net/ipv4/conf/i1/rp_filter");
	f557_sysline("/proc/sys/net/ipv4/ip_forward");
	f557_sysline("/proc/sys/net/ipv4/conf/all/accept_local");

	/* control: an ordinary UDP frame to the same destination address */
	printf("F557 DIAG4|plain_local_in=%llu\n",
	       f557_hookcnt_kind(1, "gpl", F557_PLAIN));
	printf("F557 DIAG4|plain_prerouting=%llu\n",
	       f557_hookcnt_kind(0, "gpp", F557_PLAIN));

	/* ipip frame, before and after rp_filter is forced off */
	printf("F557 DIAG4|ipip_local_in_before=%llu\n",
	       f557_hookcnt_kind(1, "gil0", F557_IPIP));
	f557_syswrite("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
	f557_syswrite("/proc/sys/net/ipv4/conf/default/rp_filter", "0");
	f557_syswrite("/proc/sys/net/ipv4/conf/i1/rp_filter", "0");
	printf("F557 DIAG4|ipip_local_in_after=%llu\n",
	       f557_hookcnt_kind(1, "gil1", F557_IPIP));
	printf("F557 DIAG4|ipip_prerouting=%llu\n",
	       f557_hookcnt_kind(0, "gip", F557_IPIP));
	f557_devline("tunl0");
}


/* ---------- H: is the address really there? ---------- */

static void f557_procgrep(const char *path, const char *needle)
{
	int fd = open(path, O_RDONLY);
	char *buf;
	int n, total = 0;

	buf = (char *)malloc(1 << 16);
	if (!buf)
		return;
	if (fd < 0) {
		free(buf);
		printf("F557 PROC|%s|open_failed|%d\n", path, errno);
		return;
	}
	while (total < (1 << 16) - 1) {
		n = (int)read(fd, buf + total, (1 << 16) - 1 - total);
		if (n <= 0)
			break;
		total += n;
	}
	close(fd);
	buf[total] = 0;
	{
		char *l = buf;

		while (l && *l) {
			char *nl = strchr(l, '\n');

			if (nl)
				*nl = 0;
			if (strstr(l, needle))
				printf("F557 PROC|%s|%s\n", path, l);
			l = nl ? nl + 1 : NULL;
		}
	}
	free(buf);
}

static void f557_diag5(void)
{
	int rc1 = f555_addr_add("i1", htonl(0x0a090007), 24);
	int rc2 = f555_addr_add("i0", htonl(0x0a010001), 24);

	printf("F557 DIAG5|addr_rc|i1=%d|i0=%d\n", rc1, rc2);
	f557_procgrep("/proc/net/fib_trie", "10.9.0");
	f557_procgrep("/proc/net/fib_trie", "10.1.0");
	f557_procgrep("/proc/net/route", "i1");
	f557_procgrep("/proc/net/fib_trie", "LOCAL");
}


/* ---------- I: WHY does the frame not arrive locally? ---------- */

static void f557_snmp(const char *tag)
{
	int fd = open("/proc/net/snmp", O_RDONLY);
	char buf[8192];
	int n;

	if (fd < 0)
		return;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = 0;
	{
		char *l = buf;
		int seen = 0;

		while (l && *l && seen < 2) {
			char *nl = strchr(l, '\n');

			if (nl)
				*nl = 0;
			if (!strncmp(l, "Ip:", 3)) {
				printf("F557 SNMP|%s|%s\n", tag, l);
				seen++;
			}
			l = nl ? nl + 1 : NULL;
		}
	}
}

static void f557_diag6(void)
{
	struct f557_env e;
	unsigned char fr[512];
	unsigned long long cnt;

	f555_addr_add("i1", htonl(0x0a090007), 24);
	f555_addr_add("i0", htonl(0x0a010001), 24);
	set_up("tunl0");

	/* local_in chain on a plain frame */
	printf("F557 DIAG6|plain_local_in=%llu\n",
	       f557_hookcnt_kind(1, "h0", F557_PLAIN));

	/* what does the stack say about the plain frame? */
	memset(&e, 0, sizeof(e));
	e.tag = "h1"; e.fam = NFPROTO_IPV4; e.table = "p57m"; e.chain = "c";
	e.hook = 0; e.policy = 1; e.base = NFT_PAYLOAD_LL_HEADER;
	e.dev = "i0"; e.kind = F557_PLAIN;
	if (!f557_chain(&e)) {
		f557_snmp("before");
		f557_ctl(&e, "c1", 1);
		f557_snmp("after_plain");
	}

	/* and the ipip frame */
	memset(&e, 0, sizeof(e));
	e.tag = "h2"; e.fam = NFPROTO_IPV4; e.table = "p57n"; e.chain = "c";
	e.hook = 0; e.policy = 1; e.base = NFT_PAYLOAD_LL_HEADER;
	e.dev = "i0"; e.kind = F557_IPIP;
	if (!f557_chain(&e)) {
		f557_ctl(&e, "c1", 1);
		f557_snmp("after_ipip");
	}
	(void)fr; (void)cnt;
}


/* ---------- J: inject the outer datagram with a raw socket ----------
 *
 * The hand-built ethernet frame reaches ip prerouting and then disappears
 * without incrementing a single IP counter (measured: IpInReceives +1,
 * InDelivers/ForwDatagrams/InAddrErrors all +0), so the outer datagram is
 * never handed to the tunnel's protocol handler.  A UDP/IP datagram the
 * kernel itself addresses to 10.9.0.7 IS delivered locally (loopback path),
 * so the same outer header -- protocol 4, source 10.1.0.1, destination
 * 10.9.0.7 -- is sent here with IP_HDRINCL and the kernel's own routing.
 * The INNER packet, which is the envelope this turn measures, is built by
 * iptunnel_pull_header()/netif_rx() either way.
 */
static int f557_raw_send(int proto, const unsigned char *payload, int plen)
{
	unsigned char pkt[512];
	unsigned char *ip = pkt;
	struct sockaddr_in dst;
	int s, hl = 20, tot = hl + plen, one = 1;
	unsigned short c;

	memset(pkt, 0, sizeof(pkt));
	ip[0] = 0x45;
	ip[2] = (unsigned char)(tot >> 8);
	ip[3] = (unsigned char)tot;
	ip[4] = 0x12; ip[5] = 0x39;
	ip[8] = 64;
	ip[9] = (unsigned char)proto;
	ip[12] = 0x0a; ip[13] = 0x01; ip[14] = 0x00; ip[15] = 0x01;
	ip[16] = 0x0a; ip[17] = 0x09; ip[18] = 0x00; ip[19] = 0x07;
	c = f556_csum(ip, hl);
	ip[10] = (unsigned char)(c >> 8); ip[11] = (unsigned char)c;
	memcpy(ip + hl, payload, (size_t)plen);

	s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s < 0)
		return -errno;
	setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(0x0a090007);
	if (sendto(s, pkt, (size_t)tot, 0, (struct sockaddr *)&dst,
		   sizeof(dst)) != tot) {
		int e = errno;

		close(s);
		return -e;
	}
	close(s);
	return 0;
}

/* the inner datagram of the ipip probe: IPv4 + UDP + payload, no ethernet */
static int f557_inner_only(unsigned char *out)
{
	unsigned char *iip = out;
	unsigned char *u = out + 20;
	unsigned short c;

	memset(out, 0, 128);
	iip[0] = 0x45;
	iip[2] = 0;
	iip[3] = 20 + 8 + 18;
	iip[4] = 0x12; iip[5] = 0x36;
	iip[8] = 63; iip[9] = 17;
	iip[12] = 0x0a; iip[13] = 0x42; iip[14] = 0x01; iip[15] = 0x01;
	iip[16] = 0x0a; iip[17] = 0x42; iip[18] = 0x01; iip[19] = 0x02;
	c = f556_csum(iip, 20);
	iip[10] = (unsigned char)(c >> 8); iip[11] = (unsigned char)c;
	u[0] = 0x9c; u[1] = 0x41; u[2] = 0x13; u[3] = 0x89;
	u[4] = 0x00; u[5] = 26;
	memset(u + 8, 0x77, 18);
	return 20 + 8 + 18;
}

/* UDP + VXLAN + inner ethernet frame, i.e. everything after the outer IPv4
 * header -- the outer header is built by f557_raw_send(17, ...) */
static int f557_vxlan_payload(unsigned char *out)
{
	unsigned char full[512];
	int n = f557_mk_vxlan(full);

	memcpy(out, full + 14 + 20, (size_t)(n - 34));
	return n - 34;
}

static void f557_diag7(void)
{
	struct f557_env e;
	unsigned char inner[128];
	unsigned long long cnt;
	int rc, n;

	f555_addr_add("i1", htonl(0x0a090007), 24);
	f555_addr_add("i0", htonl(0x0a010001), 24);
	set_up("tunl0");
	f555_addr_add("tunl0", htonl(0x0a420102), 32);

	n = f557_inner_only(inner);
	rc = f557_raw_send(4, inner, n);
	printf("F557 DIAG7|raw_send|rc=%d|len=%d\n", rc, n);

	/* prerouting, no gate: outer (if routed) + inner (if decapsulated) */
	printf("F557 DIAG7|prerouting_cnt=%llu\n",
	       f557_hookcnt_kind(0, "j0", F557_IPIP));
	rc = f557_raw_send(4, inner, n);
	printf("F557 DIAG7|raw_send2|rc=%d\n", rc);
	{
		struct f557_env e2;
		char tbl[32];

		memset(&e2, 0, sizeof(e2));
		snprintf(tbl, sizeof(tbl), "p57jp");
		e2.tag = "j1"; e2.fam = NFPROTO_IPV4; e2.table = tbl;
		e2.chain = "c"; e2.hook = 0; e2.policy = 1;
		e2.base = NFT_PAYLOAD_LL_HEADER; e2.dev = "i0"; e2.iif = 0;
		e2.kind = F557_IPIP;
		if (!f557_chain(&e2)) {
			cnt = f557_ctl(&e2, "c1", 1);
			printf("F557 DIAG7|with_own_send_cnt=%llu\n", cnt);
		}
	}
	f557_devline("tunl0");
	(void)e;
}


/* ---------- K: does the meta-iif gate work, and does the inner packet
 * reach ip prerouting at all? ---------- */

static unsigned long long f557_gate_ctl(uint32_t iif, int send_raw,
					const char *tag)
{
	struct f557_env e;
	char tbl[40];

	memset(&e, 0, sizeof(e));
	snprintf(tbl, sizeof(tbl), "p57g_%u_%d", iif, send_raw);
	e.tag = tag; e.fam = NFPROTO_IPV4; e.table = tbl; e.chain = "c";
	e.hook = 0; e.policy = 1; e.base = NFT_PAYLOAD_LL_HEADER;
	e.dev = "i0"; e.iif = iif; e.kind = F557_IPIP; e.send_raw = send_raw;
	if (f557_chain(&e))
		return 0;
	f555_count(e.fam, e.table, e.chain);
	return f557_ctl(&e, "c1", 1);
}

static void f557_diag8(void)
{
	int lo, tl, i1;

	f555_addr_add("i1", htonl(0x0a090007), 24);
	f555_addr_add("i0", htonl(0x0a010001), 24);
	set_up("tunl0");
	f555_addr_add("tunl0", htonl(0x0a420102), 32);
	lo = f555_ifindex("lo");
	tl = f555_ifindex("tunl0");
	i1 = f555_ifindex("i1");
	printf("F557 DIAG8|idx|lo=%d|tunl0=%d|i1=%d\n", lo, tl, i1);

	printf("F557 DIAG8|raw_nogate=%llu\n", f557_gate_ctl(0, 1, "k0"));
	printf("F557 DIAG8|raw_iif_lo=%llu\n", f557_gate_ctl((uint32_t)lo, 1, "k1"));
	printf("F557 DIAG8|raw_iif_tunl0=%llu\n", f557_gate_ctl((uint32_t)tl, 1, "k2"));
	printf("F557 DIAG8|raw_iif_i1=%llu\n", f557_gate_ctl((uint32_t)i1, 1, "k3"));
	printf("F557 DIAG8|frame_iif_lo=%llu\n", f557_gate_ctl((uint32_t)lo, 0, "k4"));
	/* the gate itself, on a packet whose path is known: the hand-built
	 * frame arrives on i1, so a gate on i1 must count it and a gate on
	 * tunl0 must not */
	printf("F557 DIAG8|frame_iif_tunl0=%llu\n", f557_gate_ctl((uint32_t)tl, 0, "k5"));
	printf("F557 DIAG8|frame_iif_i1=%llu\n", f557_gate_ctl((uint32_t)i1, 0, "k6"));
	f557_devline("tunl0");
}


/* ---------- L: where does the 802.1Q frame go? ---------- */

static unsigned long long f557_env_ctl(uint8_t fam, uint32_t hook,
				       const char *rule_dev, int kind,
				       const char *tag)
{
	struct f557_env e;
	char tbl[40];

	memset(&e, 0, sizeof(e));
	snprintf(tbl, sizeof(tbl), "p57q_%u_%d", hook, kind);
	e.tag = tag; e.fam = fam; e.table = tbl; e.chain = "c";
	e.hook = hook; e.policy = 1; e.base = NFT_PAYLOAD_LL_HEADER;
	e.dev = "i0"; e.rule_dev = rule_dev; e.kind = kind;
	if (f557_chain(&e))
		return 0;
	f555_count(e.fam, e.table, e.chain);
	return f557_ctl(&e, "c1", 1);
}

static void f557_diag9(void)
{
	int i1 = f555_ifindex("i1");

	printf("F557 DIAG9|idx_i1=%d\n", i1);
	f557_snmp("before_vlan");
	printf("F557 DIAG9|ip_pre_plain=%llu\n",
	       f557_env_ctl(NFPROTO_IPV4, 0, NULL, F557_PLAIN, "l0"));
	f557_snmp("after_plain");
	printf("F557 DIAG9|ip_pre_vlan=%llu\n",
	       f557_env_ctl(NFPROTO_IPV4, 0, NULL, F557_VLAN, "l1"));
	f557_snmp("after_vlan");
	printf("F557 DIAG9|nd_ing_vlan=%llu\n",
	       f557_env_ctl(NFPROTO_NETDEV, 0, "i1", F557_VLAN, "l2"));
	f557_snmp("after_nd_vlan");
}


/* ---------- M: does the sender's sll_protocol decide it? ---------- */

static unsigned long long f557_ctl_proto(int kind, unsigned short proto,
					 const char *tag)
{
	struct f557_env e;
	unsigned char fr[512], pay[192];
	unsigned long long cnt, cnt0;
	char tbl[40];
	int flen, n = 0, rc, acks = -1;

	flen = f557_frame(kind, fr);
	memset(&e, 0, sizeof(e));
	snprintf(tbl, sizeof(tbl), "p57r_%04x_%d", proto, kind);
	e.tag = tag; e.fam = NFPROTO_IPV4; e.table = tbl; e.chain = "c";
	e.hook = 0; e.policy = 1; e.base = NFT_PAYLOAD_LL_HEADER;
	e.dev = "i0"; e.kind = kind;
	if (f557_chain(&e))
		return 0;
	snprintf(PRE57, sizeof(PRE57), "f57.%s.ctl", tag);
	f557_flush(e.fam, e.table, e.chain, &acks);
	rc = f557_install(e.fam, e.table, e.chain, 0, 0, 0, 0, NULL, 0, 0, 5,
			  PRE57, &acks);
	nfl_drain(NFL57);
	cnt0 = (rc == 0) ? f555_count(e.fam, e.table, e.chain) : 0;
	if (rc == 0) {
		usleep(15000);
		pkt_send_p(e.dev, fr, flen, proto);
		n = nfl_wait(NFL57, PRE57, pay, (int)sizeof(pay), 300);
	}
	cnt = f555_count(e.fam, e.table, e.chain);
	printf("F557 R|env=%s|arm=ctl|off=0|len=0|kind=%d|fast=1|rc=%d|acks=%d|"
	       "cnt=%llu|cnt0=%llu|nfl=%d|ms=0|hex=", tag, kind, rc, acks, cnt,
	       cnt0, n);
	printf("\n");
	return cnt;
}

static void f557_diag10(void)
{
	printf("F557 DIAG10|vlan_sll_8100=%llu\n",
	       f557_ctl_proto(F557_VLAN, 0x8100, "m0"));
	printf("F557 DIAG10|vlan_sll_all=%llu\n",
	       f557_ctl_proto(F557_VLAN, 0x0003, "m1"));
	printf("F557 DIAG10|vlan_sll_0800=%llu\n",
	       f557_ctl_proto(F557_VLAN, 0x0800, "m2"));
	printf("F557 DIAG10|plain_sll_all=%llu\n",
	       f557_ctl_proto(F557_PLAIN, 0x0003, "m3"));
}


/* ---------- N: is the AF_PACKET tap what kills the tagged frame? ---------- */

static void f557_diag11(void)
{
	printf("F557 DIAG11|vlan_ip_pre_with_taps=%llu\n",
	       f557_ctl_proto(F557_VLAN, 0x8100, "n0"));
	/* the differ keeps AF_PACKET taps open on i0/i1/o1 for the byte
	 * evidence of other envelopes; every frame those sockets see is a
	 * CLONE, i.e. skb_shared().  Close them and repeat the same arm. */
	if (CAP_I0 >= 0) { close(CAP_I0); CAP_I0 = -1; }
	if (CAP_I1 >= 0) { close(CAP_I1); CAP_I1 = -1; }
	if (CAP_O1 >= 0) { close(CAP_O1); CAP_O1 = -1; }
	printf("F557 DIAG11|vlan_ip_pre_without_taps=%llu\n",
	       f557_ctl_proto(F557_VLAN, 0x8100, "n1"));
	printf("F557 DIAG11|plain_ip_pre_without_taps=%llu\n",
	       f557_ctl_proto(F557_PLAIN, 0x0800, "n2"));
}


/* ---------- O: the BYTES the accepted store leaves on the wire ----------
 *
 * The counter says the guard passed the store; it does not say what the store
 * wrote.  NFLOG at the bridge hook logs from the network header (the hex of
 * every arm starts with 45 00), so the L2 frame is captured on the other
 * bridge port instead: the frame arrives on s1 and leaves towards r1.
 */
static int f557_cap_first(const char *dev, unsigned char *buf, int max, int ms)
{
	int s = cap_open(dev);
	int n = -1, waited = 0;

	if (s < 0)
		return -1;
	/* cap_open() sets O_NONBLOCK, and veth delivers through NAPI, so the
	 * frame is not in the socket buffer when sendto() returns: poll. */
	while (waited < ms) {
		n = (int)recv(s, buf, (size_t)max, 0);
		if (n > 0)
			break;
		usleep(5000);
		waited += 5;
	}
	close(s);
	return n;
}

static void f557_sec_bytes(const char *only)
{
	struct f557_env e;
	unsigned char fr[512], cap[256];
	unsigned char imm[16];
	int flen, n, i;

	if (only && strcmp(only, "bytes"))
		return;
	memset(&e, 0, sizeof(e));
	e.tag = "by"; e.fam = NFPROTO_BRIDGE; e.table = "p57z";
	e.chain = "pre"; e.hook = 0; e.policy = 1;
	e.base = NFT_PAYLOAD_LL_HEADER; e.dev = "s0"; e.kind = F557_VLAN;
	flen = f557_frame(e.kind, fr);
	if (f557_chain(&e))
		return;

	printf("F557 BYTES|idx|s0=%d|s1=%d|r0=%d|r1=%d|br0=%d\n",
	       f555_ifindex("s0"), f555_ifindex("s1"), f555_ifindex("r0"),
	       f555_ifindex("r1"), f555_ifindex("br0"));
	/* control A: a PLAIN frame through the same bridge, no store at all */
	{
		int acks = -1;
		unsigned char frp[256];
		int flp = f557_frame(F557_PLAIN, frp);

		f557_flush(e.fam, e.table, e.chain, &acks);
		f557_install(e.fam, e.table, e.chain, 0, 0, 0, 0, NULL, 0, 0, 5,
			     "f57.by.ctlp", &acks);
		usleep(15000);
		n = f557_cap_first("r0", cap, (int)sizeof(cap), 400);
		pkt_send_p(e.dev, frp, flp, 0x0800);
		n = f557_cap_first("r0", cap, (int)sizeof(cap), 400);
		printf("F557 BYTES|ctl_plain|n=%d|hex=", n);
		for (i = 0; i < n && i < 40; i++)
			printf("%02x", cap[i]);
		printf("\n");
	}
	/* control: no store */
	{
		int acks = -1;

		f557_flush(e.fam, e.table, e.chain, &acks);
		f557_install(e.fam, e.table, e.chain, 0, 0, 0, 0, NULL, 0, 0, 5,
			     "f57.by.ctl", &acks);
		usleep(15000);
		n = f557_cap_first("r0", cap, (int)sizeof(cap), 400);	/* drain */
		pkt_send_p(e.dev, fr, flen, 0x8100);
		n = f557_cap_first("r0", cap, (int)sizeof(cap), 400);
		printf("F557 BYTES|ctl|n=%d|hex=", n);
		for (i = 0; i < n && i < 40; i++)
			printf("%02x", cap[i]);
		printf("\n");
	}
	/* the accepted store: off 16 len 2 = the inner ethertype, value 0x0806 */
	{
		int acks = -1;

		memset(imm, 0, sizeof(imm));
		imm[0] = 0x08;
		imm[1] = 0x06;
		f557_flush(e.fam, e.table, e.chain, &acks);
		f557_install(e.fam, e.table, e.chain, 0, NFT_PAYLOAD_LL_HEADER,
			     16, 2, imm, 2, 1, 5, "f57.by.s16", &acks);
		usleep(15000);
		n = f557_cap_first("r0", cap, (int)sizeof(cap), 400);
		pkt_send_p(e.dev, fr, flen, 0x8100);
		n = f557_cap_first("r0", cap, (int)sizeof(cap), 400);
		printf("F557 BYTES|s16_2|n=%d|hex=", n);
		for (i = 0; i < n && i < 40; i++)
			printf("%02x", cap[i]);
		printf("\n");
	}
	sh("/nft flush ruleset");
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "f557";
	const char *only = argc > 2 ? argv[2] : NULL;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("F557 BEGIN|mode=%s|only=%s\n", mode, only ? only : "-");
	if (unshare(CLONE_NEWNET) < 0) {
		printf("F557 FAIL|unshare|%d\n", errno);
		return 0;
	}
	set_up("lo");
	f556_fams();
	printf("F557 KERNEL|%s\n", "7.3.4-T557");
	f556_env_setup();
	NFL57 = nfl_open(5);
	printf("F557 NFL|%d\n", NFL57);
	if (!strcmp(mode, "f557diag11")) {
		f557_diag11();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag10")) {
		f557_diag10();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag9")) {
		f557_diag9();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag8")) {
		f557_diag8();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag7")) {
		f557_diag7();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag6")) {
		f557_diag6();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag5")) {
		f557_diag5();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag4")) {
		f557_diag4();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag3")) {
		f557_diag3();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag2")) {
		f557_diag2();
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557diag")) {
		f557_diag(only);
		printf("F557 DONE\n");
		return 0;
	}
	if (!strcmp(mode, "f557grid")) {
		f557_sec_grid(NULL);
	} else if (!strcmp(mode, "f557verdict")) {
		f557_sec_verdict(NULL);
	} else if (!strcmp(mode, "f557tun")) {
		f557_sec_tunnel(NULL);
	} else if (!strcmp(mode, "f557bytes")) {
		f557_sec_bytes(NULL);
	} else if (!strncmp(mode, "f557one:", 8)) {
		f557_sec_grid(mode + 8);
	} else {
		f557_sec_grid(only);
		f557_sec_verdict(only);
		f557_sec_bytes(only);
		f557_sec_tunnel(only);
	}
	printf("F557 DONE\n");
	return 0;
}
