/* ==========================================================================
 * differ551_add.c -- turn 551: F29 -- the byte-12 guard protects a BASE, not
 *                    a byte.
 *
 * WHAT F28 LEFT OPEN
 * ------------------
 * F28 counted 14 nft spellings whose compiled store covers transport byte 12
 * and showed the guard `nft_th_write_ok()` kills all of them on 7.3/7.3.4,
 * including two that cannot change doff.  Reading the same function shows the
 * inner base never reaches the guard at all:
 *
 *     case NFT_PAYLOAD_INNER_HEADER:
 *             offset = nft_payload_inner_offset(pkt);
 *             if (offset < 0) goto err;
 *             break;
 *
 * -- no nft_th_write_ok(), and no way to call it: `pkt->tprot` is the OUTER
 * protocol, and `priv->offset` for this base is measured from the end of the
 * outer UDP/GRE header, not from any L4 header.  This turn asks the question
 * the source cannot answer by itself: on a forwarded tunnel frame, does the
 * same byte -- the TCP data-offset byte of a real inner TCP header -- move
 * when it is named through the inner base?
 *
 * THE ANSWERS THE KERNEL CAN GIVE
 * -------------------------------
 * Only two: a frame on the wire, and nft's own packet counter.  Every arm
 * therefore sends ONE hand-built frame through the forward hook and reads
 * back the datagram the far side captured.  The frame is built here, byte by
 * byte, and the log carries it in hex; the verifier re-parses those bytes in
 * Python and derives the inner L3/L4 positions ITSELF (it never trusts the
 * offsets printed here).
 *
 * FRAMES (all forwarded to 10.8.0.5, so they leave through fv0)
 *   plain    eth+ip4+TCP              (byte-identical to F27/F28's probe)
 *   vxlan    eth+ip4+UDP:4789+VXLAN8+eth+ip4+TCP
 *   geneve2  eth+ip4+UDP:6081+GENEVE(opt_len 2)+eth+ip4+TCP
 *   ipip     eth+ip4(proto 4)+ip4+TCP
 *
 * WHERE THE BYTE IS, PER TUNNEL (skb offsets; inner base = nft_payload_inner_offset)
 *   vxlan    inner base 42  inner TCP 84  doff byte 96  = @ih 54  csum @ih 58
 *   geneve2  inner base 42  inner TCP 92  doff byte 104 = @ih 62  csum @ih 66
 *   ipip     inner base 34  inner TCP 54  doff byte 66  = @ih 32  csum @ih 36
 *   plain    inner base = thoff + tcp hdr len = 54 (nothing there: the frame
 *            ends at 70, so an inner store on a plain frame lands past it)
 *
 * SECTIONS
 *   A  stock nft(8): the same byte through @th (outer, plain frame) and
 *      through @ih (inner, tunnel frame), in one boot.  nft's own netlink
 *      message prints the geometry it declares.
 *   B  the geometry swept at the netlink level on both bases, in a chain with
 *      `policy drop` and an accept AFTER the store: delivery is the answer.
 *   C  the consequence, with nft's counter: does the verdict still run?
 *   D  the checksum: csum type inet pointed at the inner TCP checksum, even
 *      and odd store offsets (F26's parity defect, on the inner base).
 * ========================================================================== */

#define F551_CAP	128
#define F551_MAXF	256
#define F551_INNER_SRC	0x0a660101U	/* 10.102.1.1 */
#define F551_INNER_DST	0x0a660102U	/* 10.102.1.2 */

enum { F551_PLAIN = 0, F551_VXLAN, F551_GENEVE2, F551_IPIP, F551_VXUDP };
#define F551_KINDS 5

static struct f539_env *f551_envp;

/* the no-rule control datagram per frame kind, captured once and shared by
 * every section that needs a baseline */
static unsigned char f551_ctl[F551_KINDS][F551_CAP];
static int f551_ctl_len[F551_KINDS], f551_ctl_ok[F551_KINDS];

struct f551_fr {
	unsigned char f[F551_MAXF];
	int flen;		/* whole Ethernet frame            */
	int ip_len;		/* outer datagram length           */
	int proto;		/* outer IPv4 protocol             */
	int l3;			/* skb offset of the inner IP hdr  */
	int l4;			/* skb offset of the inner TCP hdr */
	int l4len;		/* TCP header + payload            */
};

/* ---------------- checksums, computed here and nowhere else ---------------- */

static unsigned int f551_sum(const unsigned char *p, int n, unsigned int acc)
{
	int i;

	for (i = 0; i + 1 < n; i += 2)
		acc += ((unsigned int)p[i] << 8) | p[i + 1];
	if (n & 1)
		acc += (unsigned int)p[n - 1] << 8;
	return acc;
}

static unsigned short f551_fold(unsigned int acc)
{
	while (acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);
	return (unsigned short)(~acc & 0xffff);
}

/* the value to store at TCP+16; the pseudo header is built here, in network
 * order, from the two addresses the frame carries */
static unsigned short f551_tcp_csum(const unsigned char *tcp, int tcplen,
				    uint32_t saddr, uint32_t daddr)
{
	unsigned char ph[12];
	unsigned int acc;

	ph[0] = (unsigned char)(saddr >> 24); ph[1] = (unsigned char)(saddr >> 16);
	ph[2] = (unsigned char)(saddr >> 8);  ph[3] = (unsigned char)saddr;
	ph[4] = (unsigned char)(daddr >> 24); ph[5] = (unsigned char)(daddr >> 16);
	ph[6] = (unsigned char)(daddr >> 8);  ph[7] = (unsigned char)daddr;
	ph[8] = 0;
	ph[9] = 6;				/* TCP */
	ph[10] = (unsigned char)(tcplen >> 8);
	ph[11] = (unsigned char)(tcplen & 0xff);
	acc = f551_sum(ph, 12, 0);
	acc = f551_sum(tcp, tcplen, acc);
	return f551_fold(acc);
}

/* ---------------- the frames ---------------- */

static int f551_tcphdr(unsigned char *d, int off, int sport, int dport,
		       uint32_t saddr, uint32_t daddr, int paylen)
{
	unsigned short cs;

	memset(d + off, 0, (size_t)(20 + paylen));
	d[off + 0] = (unsigned char)(sport >> 8);
	d[off + 1] = (unsigned char)(sport & 0xff);
	d[off + 2] = (unsigned char)(dport >> 8);
	d[off + 3] = (unsigned char)(dport & 0xff);
	d[off + 4] = 0x11; d[off + 5] = 0x11; d[off + 6] = 0x11; d[off + 7] = 0x11;
	d[off + 8] = 0x22; d[off + 9] = 0x22; d[off + 10] = 0x22; d[off + 11] = 0x22;
	d[off + 12] = 0x50;			/* doff 5, reserved 0 */
	d[off + 13] = 0x18;			/* PSH|ACK */
	d[off + 14] = 0x12;
	d[off + 15] = 0x34;
	d[off + 16] = 0;
	d[off + 17] = 0;			/* checksum, below */
	d[off + 18] = 0;
	d[off + 19] = 0;
	if (paylen >= 4) {
		d[off + 20] = 0xc1;
		d[off + 21] = 0xc2;
		d[off + 22] = 0xc3;
		d[off + 23] = 0xc4;
	}
	cs = f551_tcp_csum(d + off, 20 + paylen, saddr, daddr);
	d[off + 16] = (unsigned char)(cs >> 8);
	d[off + 17] = (unsigned char)(cs & 0xff);
	return off + 20 + paylen;
}

/* UDP checksum over the datagram's UDP header + payload, pseudo-header built
 * here; returns the value to store (0xffff if it folds to zero) */
static unsigned short f551_udp_csum_val(const unsigned char *udp, int ulen,
					uint32_t saddr, uint32_t daddr)
{
	unsigned char ph[12];
	unsigned int acc;
	unsigned short v;

	ph[0] = (unsigned char)(saddr >> 24); ph[1] = (unsigned char)(saddr >> 16);
	ph[2] = (unsigned char)(saddr >> 8);  ph[3] = (unsigned char)saddr;
	ph[4] = (unsigned char)(daddr >> 24); ph[5] = (unsigned char)(daddr >> 16);
	ph[6] = (unsigned char)(daddr >> 8);  ph[7] = (unsigned char)daddr;
	ph[8] = 0;
	ph[9] = 17;				/* UDP */
	ph[10] = (unsigned char)(ulen >> 8);
	ph[11] = (unsigned char)(ulen & 0xff);
	acc = f551_sum(ph, 12, 0);
	acc = f551_sum(udp, ulen, acc);
	v = f551_fold(acc);
	return v ? v : 0xffff;
}

/* is the OUTER UDP checksum valid in a captured datagram?  0 = bad, 1 = ok,
 * -1 = not a UDP datagram, -2 = checksum field is zero ("not computed") */
static int f551_outer_udp_ok(const unsigned char *cap, int caplen)
{
	int ihl, ulen;
	uint32_t s, t;
	unsigned short v;

	if (caplen < 28 || cap[9] != 17)
		return -1;
	ihl = (cap[0] & 0x0f) * 4;
	if (ihl < 20 || ihl + 8 > caplen)
		return -1;
	ulen = (cap[ihl + 4] << 8) | cap[ihl + 5];
	if (ulen < 8 || ihl + ulen > caplen)
		return -1;
	if (cap[ihl + 6] == 0 && cap[ihl + 7] == 0)
		return -2;
	s = f22_be32(cap + 12);
	t = f22_be32(cap + 16);
	{
		unsigned char ph[12];
		unsigned int acc;

		ph[0] = (unsigned char)(s >> 24); ph[1] = (unsigned char)(s >> 16);
		ph[2] = (unsigned char)(s >> 8);  ph[3] = (unsigned char)s;
		ph[4] = (unsigned char)(t >> 24); ph[5] = (unsigned char)(t >> 16);
		ph[6] = (unsigned char)(t >> 8);  ph[7] = (unsigned char)t;
		ph[8] = 0;
		ph[9] = 17;
		ph[10] = (unsigned char)(ulen >> 8);
		ph[11] = (unsigned char)(ulen & 0xff);
		acc = f551_sum(ph, 12, 0);
		/* the UDP header WITH its checksum field: the fold is zero exactly
		 * when the checksum is valid */
		acc = f551_sum(cap + ihl, ulen, acc);
		v = f551_fold(acc);
	}
	return v == 0;
}

static void f551_build(int kind, struct f551_fr *o)
{
	unsigned char *d = o->f;
	int q, udp_off = -1, pay = 24;	/* TCP header + 4 bytes of payload */

	memset(o, 0, sizeof(*o));
	o->l3 = o->l4 = -1;
	memset(d, 0, sizeof(o->f));
	memcpy(d, f539_mac_me, 6);
	memcpy(d + 6, f539_mac_far, 6);
	d[12] = 0x08;
	d[13] = 0x00;

	if (kind == F551_PLAIN) {
		int n = f543_expect(d + 14, 16, 0x50, 0x18);

		o->flen = 14 + n;
		o->ip_len = n;
		o->proto = 6;
		o->l3 = -1;
		o->l4 = 34;			/* skb offset of the TCP header */
		o->l4len = n - 20;
		return;
	}

	q = 34;					/* after eth + outer IPv4 */
	if (kind != F551_IPIP) {
		udp_off = q;
		q += 8;				/* UDP header, length patched below */
		if (kind == F551_VXLAN || kind == F551_VXUDP) {
			d[q + 0] = 0x08;	/* VXLAN flags: I */
			d[q + 1] = 0x00; d[q + 2] = 0x00; d[q + 3] = 0x00;
			d[q + 4] = 0x00; d[q + 5] = 0x00; d[q + 6] = 0x2a;
			d[q + 7] = 0x00;
			q += 8;
		} else {
			int gi;

			d[q + 0] = 0x02;	/* GENEVE opt_len = 2 (8 bytes) */
			d[q + 1] = 0x00;
			d[q + 2] = 0x08; d[q + 3] = 0x00;	/* proto 0x0800 */
			d[q + 4] = 0x00; d[q + 5] = 0x00; d[q + 6] = 0x2b;
			d[q + 7] = 0x00;
			q += 8;
			memset(d + q, 0, 8);
			for (gi = 0; gi < 8; gi += 4) {
				d[q + gi + 0] = 0x01;
				d[q + gi + 1] = 0x02;
				d[q + gi + 3] = (unsigned char)(gi / 4);
			}
			q += 8;
		}
		q = f22_ethhdr(d, q, 0x0800);
	}

	o->l3 = q;
	q = f22_ip4hdr(d, q, pay, 6, F551_INNER_SRC, F551_INNER_DST, 0x5555);
	o->l4 = q;
	q = f551_tcphdr(d, q, 5555, 6666, F551_INNER_SRC, F551_INNER_DST, 4);
	o->l4len = pay;

	if (udp_off >= 0) {
		int ulen = q - udp_off;

		d[udp_off + 0] = 0x9c;		/* sport 40000 */
		d[udp_off + 1] = 0x40;
		d[udp_off + 2] = (unsigned char)((kind == F551_GENEVE2 ? 6081 : 4789) >> 8);
		d[udp_off + 3] = (unsigned char)((kind == F551_GENEVE2 ? 6081 : 4789) & 0xff);
		d[udp_off + 4] = (unsigned char)(ulen >> 8);
		d[udp_off + 5] = (unsigned char)(ulen & 0xff);
		d[udp_off + 6] = 0;
		d[udp_off + 7] = 0;
		if (kind == F551_VXUDP) {
			/* a tunnel frame whose OUTER UDP checksum is real: nft's
			 * L4CSUM_PSEUDOHDR update is skipped when it is zero, and
			 * this frame is the one where that update actually runs */
			unsigned short u = f551_udp_csum_val(d + udp_off, ulen,
							    F539_ADDR_PEER,
							    F539_ADDR_DST);

			d[udp_off + 6] = (unsigned char)(u >> 8);
			d[udp_off + 7] = (unsigned char)(u & 0xff);
		}
	}
	f22_ip4hdr(d, 14, q - 34, kind == F551_IPIP ? 4 : 17,
		   F539_ADDR_PEER, F539_ADDR_DST, 0x4444);
	o->flen = q;
	o->ip_len = q - 14;
	o->proto = kind == F551_IPIP ? 4 : 17;
}

/* is the inner TCP checksum valid in the frame as built?  -1 if no inner TCP */
static int f551_inner_csum_ok_fr(const struct f551_fr *o)
{
	if (o->l3 < 0 || o->l4 < 0 || o->l4 + o->l4len > o->flen)
		return -1;
	return f551_tcp_csum(o->f + o->l4, o->l4len, F551_INNER_SRC,
			     F551_INNER_DST) == 0;
}

/* the same question for a datagram captured off the wire: parse it here (the
 * verifier parses the logged hex again, in Python, on its own) */
static int f551_inner_csum_ok_cap(const unsigned char *cap, int caplen,
				  int inner_l3, int inner_l4)
{
	uint32_t s, t;
	int l4len;

	if (inner_l3 < 0 || inner_l4 < 0 || inner_l4 + 20 > caplen ||
	    inner_l3 + 20 > caplen)
		return -1;
	s = f22_be32(cap + inner_l3 + 12);
	t = f22_be32(cap + inner_l3 + 16);
	l4len = ((cap[inner_l3 + 2] << 8) | cap[inner_l3 + 3]) -
		(inner_l4 - inner_l3);
	if (l4len < 20 || inner_l4 + l4len > caplen)
		return -1;
	return f551_tcp_csum(cap + inner_l4, l4len, s, t) == 0;
}

/* ---------------- the probe: send these bytes, read back what was forwarded */

static int f551_xmit(struct f539_env *e, const struct f551_fr *fr,
		     unsigned char *cap, int *iplen, int *nsent, int *ncap)
{
	char req[2 * F551_MAXF + 16], line[1600];
	int i, k = 0, rc = -1;

	req[k++] = 'W';
	req[k++] = ' ';
	for (i = 0; i < fr->flen; i++)
		k += snprintf(req + k, sizeof(req) - (size_t)k, "%02x", fr->f[i]);
	req[k++] = '\n';
	req[k] = 0;
	memset(cap, 0, F551_CAP);
	*iplen = 0;
	*nsent = 0;
	*ncap = 0;
	if (f539_write_all(e->cmd, req, k) < 0)
		return -1;
	if (f539_read_line(e->ack, line, sizeof(line), 8000) < 0)
		return -1;
	{
		unsigned int ns = 0, nc = 0, il = 0, iz = 0;
		int prc = 0, pwlen = 0, pseen = 0, pfirst = 0, praw = 0, plast = 0;
		char echo[32], hex[1600];

		echo[0] = 0;
		hex[0] = 0;
		if (sscanf(line + 1, "%d %d %d %u %u %u %u %d %x %d %x %24s %1000s",
			   &prc, &pwlen, &rc, &ns, &nc, &il, &iz, &pseen, &pfirst,
			   &praw, &plast, echo, hex) < 12)
			return -2;
		*nsent = rc;
		*ncap = (int)ns;
		*iplen = (int)nc;
		for (i = 0; i < F551_CAP && hex[2 * i] && hex[2 * i + 1]; i++) {
			unsigned int b = 0;

			if (sscanf(hex + 2 * i, "%2x", &b) != 1)
				break;
			cap[i] = (unsigned char)b;
		}
	}
	return 0;
}

/* how many bytes of the forwarded datagram differ from the no-rule control */
static int f551_diff(const unsigned char *cap, int iplen, const unsigned char *ctl,
		     int ctllen, char *out, size_t cap_out, char *bytes, size_t nbytes)
{
	int i, n = 0;

	out[0] = 0;
	bytes[0] = 0;
	if (!iplen || iplen != ctllen)
		return -1;
	for (i = 0; i < iplen; i++) {
		size_t at;

		if (cap[i] == ctl[i])
			continue;
		n++;
		at = strlen(bytes);
		if (at < nbytes - 8)
			snprintf(bytes + at, nbytes - at, "%s%d", n > 1 ? "," : "",
				 i + 14);	/* skb/frame coordinates */
		at = strlen(out);
		if (at < cap_out - 16)
			snprintf(out + at, cap_out - at, "%s%d:%02x>%02x",
				 n > 1 ? "," : "", i + 14, ctl[i], cap[i]);
	}
	return n;
}

static void f551_hexline(const unsigned char *p, int n)
{
	int i;

	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
}

/* ---------------- A: stock nft, the same byte through two bases ---------------- */

static int f551_sh(const char *cmd)
{
	int rc = system(cmd);

	if (rc < 0)
		return -1;
	return WEXITSTATUS(rc);
}

struct f551_nft {
	const char *tag;
	const char *rule;	/* NULL = no rule (the control) */
	int kind;
};

static const struct f551_nft f551_nft_arms[] = {
	{ "ctl.plain",   NULL,                          F551_PLAIN  },
	{ "ctl.vxlan",   NULL,                          F551_VXLAN  },
	{ "ctl.geneve2", NULL,                          F551_GENEVE2 },
	{ "ctl.ipip",    NULL,                          F551_IPIP   },
	{ "ctl.vxudp",   NULL,                          F551_VXUDP  },
	{ "th.do6",      "@th,96,8 set 0x60",           F551_PLAIN  },
	{ "th.flags",    "@th,104,8 set 0x02",          F551_PLAIN  },
	{ "ih.vx.do6",   "@ih,432,8 set 0x60",          F551_VXLAN  },
	{ "ih.vx.flags", "@ih,440,8 set 0x02",          F551_VXLAN  },
	{ "ih.vx.do6w",  "@ih,432,16 set 0x6018",       F551_VXLAN  },
	{ "ih.gn.do6",   "@ih,496,8 set 0x60",          F551_GENEVE2 },
	{ "ih.ipip.do6", "@ih,256,8 set 0x60",          F551_IPIP   },
	{ "ih.vx.eth",   "@ih,64,8 set 0xaa",           F551_VXLAN  },
	{ "ih.vx.tun0",  "@ih,0,8 set 0x64",            F551_VXLAN  },
	{ "ih.udp.do6",  "@ih,432,8 set 0x60",          F551_VXUDP  },
	{ "ih.udp.flag", "@ih,440,8 set 0x02",          F551_VXUDP  },
	{ "ih.plain.do6", "@ih,432,8 set 0x60",         F551_PLAIN  },
};

static void f551_nft_section(void)
{
	static unsigned char ctl[F551_KINDS][F551_CAP];
	static int ctl_len[F551_KINDS], ctl_ok[F551_KINDS];
	unsigned char cap[F551_CAP];
	struct f551_fr fr;
	char cmd[1024], extra[512], chg[512], chgb[256];
	int rc, sent = 0, ncap = 0, iplen = 0, nchg;
	unsigned int k;

	/* separate calls: C leaves argument evaluation order unspecified */
	rc = f551_sh("/nft flush ruleset");
	rc |= f551_sh("/nft add table ip p551") << 1;
	rc |= f551_sh("/nft 'add chain ip p551 c { type filter hook forward priority 0; policy accept; }'") << 2;
	printf("F551 NSETUP|rc=%d\n", rc);

	for (k = 0; k < sizeof(f551_nft_arms) / sizeof(f551_nft_arms[0]); k++) {
		const struct f551_nft *a = &f551_nft_arms[k];

		f551_sh("/nft flush chain ip p551 c");
		if (a->rule) {
			snprintf(cmd, sizeof(cmd),
				 "/nft --debug=netlink add rule ip p551 c '%s' >/tmp/f551nl 2>&1; "
				 "echo \"F551RC %s $?\"", a->rule, a->tag);
			rc = f551_sh(cmd);
			snprintf(cmd, sizeof(cmd), "sed 's/^/F551NL %s /' /tmp/f551nl", a->tag);
			f551_sh(cmd);
		} else {
			rc = 0;
		}
		f551_build(a->kind, &fr);
		snprintf(extra, sizeof(extra), "kind=%d|rule=%s|nftrc=%d|il3=%d|il4=%d",
			 a->kind, a->rule ? a->rule : "none", rc, fr.l3, fr.l4);
		if (f551_xmit(f551_envp, &fr, cap, &iplen, &sent, &ncap) != 0) {
			printf("F551 A.%s|%s|PROBEFAIL\n", a->tag, extra);
			continue;
		}
		if (!a->rule) {
			memcpy(ctl[a->kind], cap, sizeof(cap));
			ctl_len[a->kind] = iplen;
			ctl_ok[a->kind] = 1;
		}
		nchg = ctl_ok[a->kind] ?
			f551_diff(cap, iplen, ctl[a->kind], ctl_len[a->kind],
				  chg, sizeof(chg), chgb, sizeof(chgb)) : -1;
		printf("F551 A.%s|%s|sent=%d|cap=%d|iplen=%d|nchg=%d|chg=%s|"
		       "itcsum=%d|oucsum=%d|frame=", a->tag, extra, sent, ncap, iplen, nchg,
		       nchg > 0 ? chg : "-",
		       ncap == 1 && a->kind != F551_PLAIN && fr.l4 >= 0 ?
		       f551_inner_csum_ok_cap(cap, iplen, fr.l3 - 14, fr.l4 - 14) : -1,
		       ncap == 1 ? f551_outer_udp_ok(cap, iplen) : -1);
		f551_hexline(fr.f, fr.flen);
		printf("|cap=");
		f551_hexline(cap, ncap == 1 ? iplen : 0);
		printf("\n");
	}
	f551_sh("/nft delete table ip p551");
}

/* ---------------- B/D: the netlink sweep on both bases ---------------- */

struct f551_arm {
	const char *tag;
	int kind;
	uint32_t base, off, len;
	uint32_t csum_type, csum_off;
	const unsigned char *val;	/* NULL = the 0xa0+k pattern */
};

static struct nlmsghdr *f551_newrule(const char *table, const char *chain,
				     uint32_t base, uint32_t off, uint32_t len,
				     uint32_t csum_type, uint32_t csum_off,
				     const unsigned char *imm, int immlen,
				     int with_accept)
{
	struct nlmsghdr *nlh = f542_rule_begin(table, chain);
	struct nlattr *exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS, "q.exprs");

	if (len) {
		struct nlattr *e, *d;

		exfil_imm_value(nlh, NFT_REG32_00, imm, immlen);
		e = nest_start(nlh, NFTA_LIST_ELEM, "q.elem");
		put_str(nlh, NFTA_EXPR_NAME, "payload", "q.name");
		d = nest_start(nlh, NFTA_EXPR_DATA, "q.data");
		put_be32(nlh, NFTA_PAYLOAD_SREG, NFT_REG32_00, "q.sreg");
		put_be32(nlh, NFTA_PAYLOAD_BASE, base, "q.base");
		put_be32(nlh, NFTA_PAYLOAD_OFFSET, off, "q.offset");
		put_be32(nlh, NFTA_PAYLOAD_LEN, len, "q.len");
		put_be32(nlh, NFTA_PAYLOAD_CSUM_TYPE, csum_type, "q.csum_type");
		put_be32(nlh, NFTA_PAYLOAD_CSUM_OFFSET, csum_off, "q.csum_off");
		nest_end(nlh, d);
		nest_end(nlh, e);
	}
	if (with_accept)
		exfil_imm_verdict(nlh, NF_ACCEPT);
	nest_end(nlh, exprs);
	nops++;
	return nlh;
}

static void f551_arm_run(const char *table, const char *chain,
			 const struct f551_arm *a,
			 const unsigned char ctl[F551_KINDS][F551_CAP],
			 const int ctl_len[F551_KINDS], const int ctl_ok[F551_KINDS])
{
	unsigned char imm[16];
	unsigned char cap[F551_CAP];
	struct f551_fr fr;
	char chg[512], chgb[256];
	int errs, nattr = 0, sent = 0, ncap = 0, iplen = 0, nchg = -1;
	int k, covers = -1;

	for (k = 0; k < 16; k++)
		imm[k] = (unsigned char)(0xa0 + k);
	if (a->val)
		memcpy(imm, a->val, a->len);

	f551_build(a->kind, &fr);
	nops = 0;
	nrecs = 0;
	f551_newrule(table, chain, a->base, a->off, a->len, a->csum_type,
		     a->csum_type ? a->csum_off : 0, imm, 16, 1);
	errs = f543_send_checked(&nattr, &nattr);
	if (errs != 0) {
		printf("F551 %s|setup=ERR|errno=%d|base=%u|off=%u|len=%u\n", a->tag,
		       g_err ? -g_err : 0, a->base, a->off, a->len);
		return;
	}
	if (f551_xmit(f551_envp, &fr, cap, &iplen, &sent, &ncap) != 0) {
		printf("F551 %s|base=%u|off=%u|len=%u|PROBEFAIL\n", a->tag, a->base,
		       a->off, a->len);
		return;
	}
	if (ctl_ok[a->kind])
		nchg = f551_diff(cap, iplen, ctl[a->kind], ctl_len[a->kind],
				 chg, sizeof(chg), chgb, sizeof(chgb));
	/* for the transport base, does the store range cover byte 12 of the
	 * header that base names?  For the inner base the same byte sits at a
	 * tunnel-dependent offset the kernel never computes: -1. */
	if (a->base == 2)
		covers = (a->off <= 12 && a->off + a->len > 12);
	printf("F551 %s|kind=%d|base=%u|off=%u|len=%u|csum=%u,%u|covers12=%d|"
	       "sent=%d|cap=%d|iplen=%d|nchg=%d|chg=%s|itcsum=%d|oucsum=%d|frame=",
	       a->tag, a->kind, a->base, a->off, a->len, a->csum_type,
	       a->csum_type ? a->csum_off : 0, covers, sent, ncap, iplen, nchg,
	       nchg > 0 ? chg : "-",
	       ncap == 1 && a->kind != F551_PLAIN && fr.l4 >= 0 ?
	       f551_inner_csum_ok_cap(cap, iplen, fr.l3 - 14, fr.l4 - 14) : -1,
	       ncap == 1 ? f551_outer_udp_ok(cap, iplen) : -1);
	f551_hexline(fr.f, fr.flen);
	printf("|cap=");
	f551_hexline(cap, ncap == 1 ? iplen : 0);
	printf("\n");
	nops = 0;
	nrecs = 0;
	op_delrule_flush543(table, chain);
	f543_send_checked(&nattr, &nattr);
}

static const unsigned char f551_b54[16] = { 0x60, 0x18 };
static const unsigned char f551_b55[16] = { 0x02 };
static const unsigned char f551_b54f[16] = { 0x60 };
static const unsigned char f551_b23[16] = { 0x0a };
static const unsigned char f551_b22[16] = { 0x0a, 0x66, 0x01, 0x09 };

static const struct f551_arm f551_b_arms[] = {
	/* control: the accept alone, in a chain that drops by policy */
	{ "B.ctl.accept",     F551_PLAIN,  2,  0,  0, 0,  0, NULL },
	/* the transport base: byte 12 of the TCP header (F28's sweep, in boot) */
	{ "B.t.11.2",         F551_PLAIN,  2, 11,  2, 1, 16, NULL },
	{ "B.t.12.1",         F551_PLAIN,  2, 12,  1, 1, 16, NULL },
	{ "B.t.12.2",         F551_PLAIN,  2, 12,  2, 1, 16, NULL },
	{ "B.t.12.4",         F551_PLAIN,  2, 12,  4, 1, 16, NULL },
	{ "B.t.13.1",         F551_PLAIN,  2, 13,  1, 1, 16, NULL },
	{ "B.t.12.same",      F551_PLAIN,  2, 12,  1, 1, 16, f551_b54f },
	/* the inner base: the SAME byte, named from the tunnel payload */
	{ "B.i.50.8",         F551_VXLAN,  3, 50,  8, 1, 58, NULL },
	{ "B.i.52.2",         F551_VXLAN,  3, 52,  2, 1, 58, NULL },
	{ "B.i.53.2",         F551_VXLAN,  3, 53,  2, 1, 58, NULL },
	{ "B.i.54.1",         F551_VXLAN,  3, 54,  1, 1, 58, NULL },
	{ "B.i.54.2",         F551_VXLAN,  3, 54,  2, 1, 58, f551_b54 },
	{ "B.i.54.4",         F551_VXLAN,  3, 54,  4, 1, 58, NULL },
	{ "B.i.55.1",         F551_VXLAN,  3, 55,  1, 1, 58, f551_b55 },
	{ "B.i.56.2",         F551_VXLAN,  3, 56,  2, 1, 58, NULL },
	/* the inner base where the byte is named through a second tunnel */
	{ "B.i.gn.62.1",      F551_GENEVE2, 3, 62, 1, 1, 66, f551_b54f },
	{ "B.i.ipip.32.1",    F551_IPIP,   3, 32,  1, 1, 36, f551_b54f },
	/* the inner base on a frame with no tunnel at all */
	{ "B.i.plain.54.1",   F551_PLAIN,  3, 54,  1, 1, 58, f551_b54f },
};

static const struct f551_arm f551_d_arms[] = {
	/* even store offset -> the fixup lands on the same 16-bit grid */
	{ "D.align.54",  F551_VXLAN, 3, 54, 1, 1, 58, f551_b54f },
	/* odd store offset -> F26's parity defect, on the inner base */
	{ "D.odd.55",    F551_VXLAN, 3, 55, 1, 1, 58, f551_b55 },
	/* the same store with no fixup at all */
	{ "D.none.55",   F551_VXLAN, 3, 55, 1, 0,  0, f551_b55 },
	/* the inner IP saddr (@ih 22 is the inner IP header start, so the
	 * saddr is at 34): the pseudo-header change the fixup exists for */
	{ "D.saddr.34",  F551_VXLAN, 3, 34, 4, 1, 58, f551_b22 },
	/* a store in the inner IP header, which the TCP checksum does NOT
	 * cover: the kernel still applies the fixup, because for the inner base
	 * nft_payload_csum_write_ok() returns true without looking */
	{ "D.ip.22",     F551_VXLAN, 3, 22, 4, 1, 58, f551_b22 },
	{ "D.ip.23",     F551_VXLAN, 3, 23, 1, 1, 58, f551_b23 },
};

static void f551_raw_section(void)
{
	static unsigned char ctl[F551_KINDS][F551_CAP];
	static int ctl_len[F551_KINDS], ctl_ok[F551_KINDS];
	struct f551_fr fr;
	unsigned char cap[F551_CAP];
	char tab[32];
	int nattr = 0, errs, sent = 0, ncap = 0, iplen = 0;
	unsigned int k, kind;

	memset(ctl_ok, 0, sizeof(ctl_ok));
	/* the no-rule controls, one per frame kind, in a chain that accepts */
	snprintf(tab, sizeof(tab), "p551_%d", (int)getpid());
	nops = 0;
	nrecs = 0;
	op_newtable(tab);
	op_newchain(tab, "c", NF_INET_FORWARD, 0, NF_ACCEPT);
	errs = f543_send_checked(&nattr, &nattr);
	printf("F551 RAWSETUP|errs=%d|table=%s\n", errs, tab);
	for (kind = 0; kind < F551_KINDS; kind++) {
		f551_build((int)kind, &fr);
		memset(cap, 0, sizeof(cap));
		sent = ncap = iplen = 0;
		if (f551_xmit(f551_envp, &fr, cap, &iplen, &sent, &ncap) != 0 ||
		    ncap != 1) {
			printf("F551 B.ctl.kind%u|cap=%d|PROBEFAIL\n", kind, ncap);
			continue;
		}
		memcpy(ctl[kind], cap, sizeof(cap));
		ctl_len[kind] = iplen;
		ctl_ok[kind] = 1;
		printf("F551 B.ctl.kind%u|sent=%d|cap=%d|iplen=%d|nchg=0|itcsum=%d|oucsum=%d|frame=",
		       kind, sent, ncap, iplen,
		       kind != 0 && fr.l4 >= 0 ?
		       f551_inner_csum_ok_cap(cap, iplen, fr.l3 - 14, fr.l4 - 14) : -1,
		       ncap == 1 ? f551_outer_udp_ok(cap, iplen) : -1);
		f551_hexline(fr.f, fr.flen);
		printf("|cap=");
		f551_hexline(cap, ncap == 1 ? iplen : 0);
		printf("\n");
	}

	for (kind = 0; kind < F551_KINDS; kind++) {
		memcpy(f551_ctl[kind], ctl[kind], F551_CAP);
		f551_ctl_len[kind] = ctl_len[kind];
		f551_ctl_ok[kind] = ctl_ok[kind];
	}
	/* the probe chain: policy drop, and an accept AFTER the store */
	nops = 0;
	nrecs = 0;
	op_deltable_f540(tab);
	op_newtable(tab);
	op_newchain(tab, "c", NF_INET_FORWARD, 0, NF_DROP);
	errs = f543_send_checked(&nattr, &nattr);
	printf("F551 RAWDROP|errs=%d\n", errs);
	for (k = 0; k < sizeof(f551_b_arms) / sizeof(f551_b_arms[0]); k++)
		f551_arm_run(tab, "c", &f551_b_arms[k], ctl, ctl_len, ctl_ok);
	for (k = 0; k < sizeof(f551_d_arms) / sizeof(f551_d_arms[0]); k++)
		f551_arm_run(tab, "c", &f551_d_arms[k], ctl, ctl_len, ctl_ok);

	nops = 0;
	nrecs = 0;
	op_deltable_f540(tab);
	f543_send_checked(&nattr, &nattr);
}

/* ---------------- C: does the verdict still run? ---------------- */

static void f551_counter(const char *dst)
{
	FILE *fp;
	char ctr[128];

	ctr[0] = 0;
	fp = fopen(dst, "r");
	if (fp) {
		if (fgets(ctr, sizeof(ctr), fp)) {
			size_t n = strlen(ctr);

			while (n && (ctr[n - 1] == '\n' || ctr[n - 1] == '\r'))
				ctr[--n] = 0;
		}
		fclose(fp);
	}
	printf("%s", ctr[0] ? ctr : "none");
}

static void f551_verdict_arm(const char *tag, const char *rule, int kind)
{
	unsigned char cap[F551_CAP];
	struct f551_fr fr;
	char cmd[1024], chg[512], chgb[256];
	int rc, sent = 0, ncap = 0, iplen = 0, nchg = -1;

	(void)chgb;
	f551_sh("/nft flush chain ip p551v v");
	if (rule && rule[0]) {
		snprintf(cmd, sizeof(cmd), "/nft add rule ip p551v v '%s' counter accept", rule);
		rc = f551_sh(cmd);
	} else if (rule) {
		/* the chain's own accept, no store: the control for the verdict */
		rc = f551_sh("/nft add rule ip p551v v counter accept");
	} else {
		rc = 0;
	}
	f551_sh("/nft list chain ip p551v v 2>&1 | tr -d '\\r' | grep -o 'counter packets [0-9]*' "
		"| head -1 | sed 's/.*packets //' >/tmp/f551ctr0");
	f551_build(kind, &fr);
	if (f551_xmit(f551_envp, &fr, cap, &iplen, &sent, &ncap) != 0) {
		printf("F551 C.%s|rule=%s|PROBEFAIL\n", tag, rule ? rule : "none");
		return;
	}
	if (f551_ctl_ok[kind])
		nchg = f551_diff(cap, iplen, f551_ctl[kind], f551_ctl_len[kind],
				 chg, sizeof(chg), chgb, sizeof(chgb));
	f551_sh("/nft list chain ip p551v v 2>&1 | tr -d '\\r' | grep -o 'counter packets [0-9]*' "
		"| head -1 | sed 's/.*packets //' >/tmp/f551ctr1");
	printf("F551 C.%s|kind=%d|rule=%s|nftrc=%d|sent=%d|cap=%d|iplen=%d|nchg=%d|"
	       "chg=%s|itcsum=%d|counter_before=",
	       tag, kind, rule ? rule : "none", rc, sent, ncap, iplen, nchg,
	       nchg > 0 ? chg : "-",
	       ncap == 1 && kind != F551_PLAIN && fr.l4 >= 0 ?
	       f551_inner_csum_ok_cap(cap, iplen, fr.l3 - 14, fr.l4 - 14) : -1);
	f551_counter("/tmp/f551ctr0");
	printf("|counter_after=");
	f551_counter("/tmp/f551ctr1");
	printf("|frame=");
	f551_hexline(fr.f, fr.flen);
	printf("|cap=");
	f551_hexline(cap, ncap == 1 ? iplen : 0);
	printf("\n");
}

static void f551_verdict_section(void)
{
	f551_sh("/nft flush ruleset");
	f551_sh("/nft add table ip p551v");
	f551_sh("/nft 'add chain ip p551v v { type filter hook forward priority 0; policy drop; }'");
	f551_verdict_arm("ctl.norule", NULL, F551_PLAIN);
	f551_verdict_arm("ctl.accept", "", F551_PLAIN);
	f551_verdict_arm("ctl.accept.vx", "", F551_VXLAN);
	f551_verdict_arm("th.do6", "@th,96,8 set 0x60", F551_PLAIN);
	f551_verdict_arm("th.flags", "@th,104,8 set 0x02", F551_PLAIN);
	f551_verdict_arm("ih.vx.do6", "@ih,432,8 set 0x60", F551_VXLAN);
	f551_verdict_arm("ih.vx.flags", "@ih,440,8 set 0x02", F551_VXLAN);
	f551_verdict_arm("ih.plain.do6", "@ih,432,8 set 0x60", F551_PLAIN);
	f551_sh("/nft delete table ip p551v");
}

/* ---------------- the mode ---------------- */

static void run_f551(void)
{
	struct f539_env e;
	struct f551_fr fr;
	char out[512];
	int k;

	if (f539_env_open(&e, out, sizeof(out)) < 0) {
		printf("F551 SETUP|fail|%s\n", out);
		f539_env_close(&e);
		return;
	}
	f539_route_add("fv0", F539_NET_FAR, 24, 0);
	f539_sysctl("/proc/sys/net/netfilter/nf_conntrack_checksum", "0");
	f551_envp = &e;

	/* the frames themselves, before any rule: the inner TCP checksum must be
	 * valid in the frame this file builds, or nothing downstream means
	 * anything.  (Printed so the verifier can check the same hex itself.) */
	for (k = 0; k < F551_KINDS; k++) {
		f551_build(k, &fr);
		printf("F551 FRAME|kind=%d|flen=%d|iplen=%d|proto=%d|il3=%d|il4=%d|"
		       "itcsum=%d|frame=", k, fr.flen, fr.ip_len, fr.proto, fr.l3,
		       fr.l4, f551_inner_csum_ok_fr(&fr));
		f551_hexline(fr.f, fr.flen);
		printf("\n");
	}

	f551_nft_section();
	f551_raw_section();
	f551_verdict_section();

	f551_sh("/nft flush ruleset");
	printf("F551 DONE\n");
	nf_flush();
	f539_env_close(&e);
}
