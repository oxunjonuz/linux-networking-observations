/* differ552_add.c -- turn 552 additions to vm/differ552.c
 *
 * F30: the last two of the four bases a payload store can name.
 *
 * F27/F28 measured the transport guard (nft_th_write_ok) and F29 the inner
 * base.  The network guard (nft_nh_write_ok, dispatch at nft_payload.c:963)
 * and the link guard (nft_ll_write_ok, :986) have never been measured on any
 * kernel.  Both live in the same function, are called from the same three
 * lines of nft_payload_set_eval(), and are written for the same purpose --
 * "a store must not spill into the next header".  They are not the same kind
 * of check:
 *
 *   ll : "end <= skb_network_offset()"                        -- a boundary.
 *   nh : switch (priv->offset) { 0, 1, 4, 8, 10, 12, 16 }     -- a whitelist.
 *
 * A whitelist can kill a store that is perfectly safe, and it does: nft's own
 * `ip6 ecn set` and `ip6 flowlabel set` compile to stores at network offset 1
 * (IPv6 has no header checksum, so nft's "round up to even" rule, which exists
 * for the IPv4 csum fixup, does not fire), and the whitelist has no case 1.
 * The IPv4 twin of the same operator is expanded to 2b @0 by that very rule
 * and survives.
 *
 * What is measured here, and with what answer:
 *
 *   A4  every `ip <field> set` nft 1.1.7 accepts, in an *accept* chain:
 *       nft's --debug=netlink geometry, nft's exit code, and the frame that
 *       arrives on the far side, byte for byte against a control run.
 *   A6  the same for `ip6 <field> set`, over a hand-built Ethernet+IPv6+TCP
 *       frame (IPv6 has no IP ID and no header checksum, so the control frame
 *       is reproducible, which is why this base is measurable at all).
 *   A0  `ether ...` and raw `@ll` stores.  For a *forwarded* packet the L2
 *       header is rebuilt at transmit, so a link store is invisible on the
 *       wire; the oracle here is the verdict only (policy drop + accept
 *       after the store).
 *   B4/B6  the predicate itself, at the netlink level: base=network, offset
 *       0..19 (IPv4) / 0..39 (IPv6), len 1 and 2, in a chain with
 *       `policy drop` and `accept` after the store.  Delivered = the guard
 *       let the store through.  Values keep the bytes the guard compares
 *       (version/ihl at 0, protocol at 9), so what is measured is the offset
 *       rule and not the byte rule; the byte rule gets its own arms.
 *   C4/C6  the consequence for every spelling: `<rule> counter accept` under
 *       `policy drop`.  Counter 0 and no packet = the rule's verdict was
 *       skipped along with the store.
 *
 * Nothing here asks the kernel "did the store work"; the frame and the counter
 * are the only answers it gives.
 */

#include <linux/neighbour.h>

#define F552_V6_PLEN 16

/* uapi enum nft_counter_attributes: UNSPEC, BYTES, PACKETS */
#ifndef NFTA_COUNTER_PACKETS
#define NFTA_COUNTER_PACKETS 2
#endif

/* fam 4/6 -> nfproto for the netlink messages: NFPROTO_IPV4 is 2, not 4 */
/* uapi/linux/netfilter.h: NFPROTO_IPV4 = 2, NFPROTO_IPV6 = 10.  Spelled as
 * numbers because this file reaches the nf_tables uapi without the netfilter
 * family enum. */
#define F552_PF(f) ((f) == 4 ? 2 : 10)

static struct f539_env *f552_envp;

static int f552_sh(const char *cmd)
{
	int rc = system(cmd);

	if (rc < 0)
		return -1;
	return WEXITSTATUS(rc);
}

/* neither address is local to the near side: the frame is routed, not
 * delivered, so it traverses the forward hook */
static const unsigned char f552_v6_src[16] = {
	0xfd, 0, 0, 0x98, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
};
static const unsigned char f552_v6_dst[16] = {
	0xfd, 0, 0, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
};

/* ---------- IPv6 plumbing on the near side ---------- */

static int f552_v6_route(const char *dev)
{
	char buf[512];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct rtmsg *rtm;
	int32_t oif;
	int fd, rc, idx = f539_ifindex(dev);

	if (idx < 0)
		return -50;
	rt_init(nlh, buf, (int)sizeof(buf), RTM_NEWROUTE, sizeof(struct rtmsg));
	nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE;
	rtm = (struct rtmsg *)NLMSG_DATA(nlh);
	rtm->rtm_family = AF_INET6;
	rtm->rtm_dst_len = 64;
	rtm->rtm_table = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_BOOT;
	rtm->rtm_scope = RT_SCOPE_LINK;
	rtm->rtm_type = RTN_UNICAST;
	attr_put(nlh, RTA_DST, f552_v6_dst, 16, NULL);
	oif = idx;
	attr_put(nlh, RTA_OIF, &oif, 4, NULL);
	fd = rtnl_open();
	if (fd < 0)
		return -51;
	rc = rtnl_talk(fd, nlh);
	close(fd);
	return rc;
}

static int f552_v6_neigh(const char *dev, const unsigned char *ip6,
			 const unsigned char *mac)
{
	char buf[512];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ndmsg *ndm;
	unsigned char ll[6];
	int fd, rc, idx = f539_ifindex(dev);

	if (idx < 0)
		return -60;
	rt_init(nlh, buf, (int)sizeof(buf), RTM_NEWNEIGH, sizeof(struct ndmsg));
	nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE;
	ndm = (struct ndmsg *)NLMSG_DATA(nlh);
	ndm->ndm_family = AF_INET6;
	ndm->ndm_ifindex = idx;
	ndm->ndm_state = NUD_PERMANENT;
	ndm->ndm_type = RTN_UNICAST;
	attr_put(nlh, NDA_DST, ip6, 16, NULL);
	memcpy(ll, mac, 6);
	attr_put(nlh, NDA_LLADDR, ll, 6, NULL);
	fd = rtnl_open();
	if (fd < 0)
		return -61;
	rc = rtnl_talk(fd, nlh);
	close(fd);
	return rc;
}

static int f552_v6_setup(void)
{
	int rc = 0;

	rc |= f552_v6_route("fv0");
	rc |= f552_v6_neigh("fv0", f552_v6_dst, f539_mac_far);
	{
		/* `ip6 daddr set` must not make the packet unroutable, or the
		 * accept chain would look identical to a refused store */
		unsigned char d9[16] = { 0xfd, 0, 0, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 };

		rc |= f552_v6_neigh("fv0", d9, f539_mac_far);
	}
	f539_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
	f539_sysctl("/proc/sys/net/ipv6/conf/fv0/forwarding", "1");
	f539_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");
	f539_sysctl("/proc/sys/net/ipv6/conf/fv0/disable_ipv6", "0");
	return rc;
}

/* ---------- far side: one hand-built Ethernet+IPv6+TCP frame, read back ---- */

static int f552_peer_v6(int plen, unsigned char *out, int *flen, int *nsent,
			int *ncap)
{
	struct sockaddr_ll sll;
	struct pollfd pfd;
	unsigned char *f, buf[2048];
	int s, i, idx = f539_ifindex("fv1");
	int tot = 14 + 40 + 20 + plen;

	*nsent = 0;
	*ncap = 0;
	*flen = 0;
	if (idx < 0 || plen < 0 || plen > 600)
		return 41;
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
		return 42;
	f = calloc(1, (size_t)tot);
	if (!f) {
		close(s);
		return 43;
	}
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex = idx;
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, f539_mac_me, 6);

	/* drain anything already queued (nd/ra chatter of a fresh veth) */
	while (recv(s, buf, sizeof(buf), MSG_DONTWAIT) > 0)
		;

	memcpy(f, f539_mac_me, 6);
	memcpy(f + 6, f539_mac_far, 6);
	f[12] = 0x86;
	f[13] = 0xdd;
	{
		unsigned char *ip6 = f + 14;
		unsigned char *tcp = f + 54;

		memset(ip6, 0, 40);
		ip6[0] = 0x60;			/* version 6, tc 0          */
		ip6[1] = 0x01;			/* flow label 0x12345       */
		ip6[2] = 0x23;
		ip6[3] = 0x45;
		ip6[4] = 0x00;
		ip6[5] = (unsigned char)(20 + plen);
		ip6[6] = IPPROTO_TCP;
		ip6[7] = 64;			/* hop limit                */
		memcpy(ip6 + 8, f552_v6_src, 16);
		memcpy(ip6 + 24, f552_v6_dst, 16);

		memset(tcp, 0, (size_t)(20 + plen));
		tcp[0] = 0x9c;			/* sport 40000              */
		tcp[1] = 0x40;
		tcp[2] = 0x27;			/* dport 9999               */
		tcp[3] = 0x0f;
		tcp[4] = 0x11;			/* seq 0x11223344           */
		tcp[5] = 0x22;
		tcp[6] = 0x33;
		tcp[7] = 0x44;
		tcp[12] = 0x50;			/* doff 5                   */
		tcp[13] = 0x02;			/* SYN                      */
		tcp[14] = 0xff;
		tcp[15] = 0xff;
		/* checksum 0: a forwarded packet is not checksum-verified */
		memset(tcp + 20, 0x77, (size_t)plen);
	}

	if (sendto(s, f, (size_t)tot, 0, (struct sockaddr *)&sll, sizeof(sll)) >= 0)
		(*nsent)++;

	pfd.fd = s;
	pfd.events = POLLIN;
	for (i = 0; i < 40; i++) {
		struct sockaddr_ll from;
		socklen_t fl = sizeof(from);
		ssize_t r;

		if (*ncap > 0)
			break;
		if (poll(&pfd, 1, 10) <= 0)
			continue;
		r = recvfrom(s, buf, sizeof(buf), MSG_DONTWAIT,
			     (struct sockaddr *)&from, &fl);
		if (r < 54)
			continue;
		if (from.sll_pkttype == PACKET_OUTGOING)
			continue;
		if (buf[12] != 0x86 || buf[13] != 0xdd)
			continue;
		if (memcmp(buf, f539_mac_far, 6))
			continue;
		memcpy(out, buf, (size_t)r);
		*flen = (int)r;
		(*ncap)++;
	}
	free(f);
	close(s);
	return 0;
}

/* the same reply protocol as the 'Z' probe: "D <sent> <cap> <flen> [hex]",
 * and a dropped packet is a normal outcome, not a failure -- so three fields
 * are enough (the same sscanf floor f543_probe_request uses). */
static int f552_p6(int *nsent, int *ncap, unsigned char *fr, int *flen)
{
	char req[64], line[2048], hex[1024];
	unsigned int a = 0, b = 0, nc = 0;
	int i;

	snprintf(req, sizeof(req), "V %d\n", F552_V6_PLEN);
	if (f539_write_all(f552_envp->cmd, req, (int)strlen(req)) < 0)
		return -1;
	if (f539_read_line(f552_envp->ack, line, sizeof(line), 8000) < 0)
		return -2;
	memset(hex, 0, sizeof(hex));
	if (sscanf(line + 1, "%u %u %u %1000s", &a, &b, &nc, hex) < 3)
		return -3;
	*nsent = (int)a;
	*ncap = (int)b;
	*flen = 0;
	for (i = 0; i < (int)nc && i < 400 && hex[2 * i] && hex[2 * i + 1]; i++) {
		unsigned int v = 0;

		sscanf(hex + 2 * i, "%2x", &v);
		fr[i] = (unsigned char)v;
		*flen = i + 1;
	}
	return 0;
}

/* ---------- one report line: the frame against the control ---------- */

static void f552_report(const char *tag, const char *rule,
			const unsigned char *cap, int flen, int sent, int ncap,
			const unsigned char *ctl, int clen)
{
	char chg[768];
	int i, nchg = 0;

	chg[0] = 0;
	if (ncap == 1 && ctl && clen > 0) {
		for (i = 0; i < flen && i < clen; i++) {
			size_t at;

			if (cap[i] == ctl[i])
				continue;
			nchg++;
			at = strlen(chg);
			if (at < sizeof(chg) - 24)
				snprintf(chg + at, sizeof(chg) - at, "%s%d:%02x>%02x",
					 nchg > 1 ? "," : "", i, ctl[i], cap[i]);
		}
	}
	printf("F552 %s|rule=%s|sent=%d|cap=%d|flen=%d|nchg=%d|chg=%s|hex=",
	       tag, rule ? rule : "none", sent, ncap, flen, nchg, chg);
	for (i = 0; i < flen && i < 400; i++)
		printf("%02x", cap[i]);
	printf("\n");
}

/* ---------- nft-driven arms: one list of spellings, two families ---------- */

struct f552_spell {
	const char *tag;
	const char *rule;	/* NULL = the control run */
};

static const struct f552_spell f552_ip4[] = {
	{ "ctl.none",        NULL },
	{ "ip.dscp",         "ip dscp set 0x2e" },
	{ "ip.ecn",          "ip ecn set 1" },
	{ "ip.id",           "ip id set 0x1234" },
	{ "ip.ttl",          "ip ttl set 61" },
	{ "ip.checksum",     "ip checksum set 0x1234" },
	{ "ip.saddr",        "ip saddr set 10.9.0.7" },
	{ "ip.version4",     "ip version set 4" },
	{ "ip.version6",     "ip version set 6" },
	{ "ip.hdrlength5",   "ip hdrlength set 5" },
	{ "ip.hdrlength6",   "ip hdrlength set 6" },
	{ "ip.length",       "ip length set 0x0030" },
	{ "ip.fragoff",      "ip frag-off set 0x4000" },
	{ "ip.protocol",     "ip protocol set 17" },
};

static const struct f552_spell f552_ip6[] = {
	{ "ctl.none",        NULL },
	{ "ip6.dscp",        "ip6 dscp set 0x2e" },
	{ "ip6.ecn",         "ip6 ecn set 1" },
	{ "ip6.flowlabel",   "ip6 flowlabel set 0x54321" },
	{ "ip6.hoplimit",    "ip6 hoplimit set 61" },
	{ "ip6.saddr",       "ip6 saddr set fd00:98::7" },
	{ "ip6.daddr",       "ip6 daddr set fd00:99::9" },
	{ "ip6.version6",    "ip6 version set 6" },
	{ "ip6.version5",    "ip6 version set 5" },
	{ "ip6.length",      "ip6 length set 0x0030" },
	{ "ip6.nexthdr",     "ip6 nexthdr set 17" },
};

static const struct f552_spell f552_ll[] = {
	{ "ctl.none",        NULL },
	{ "ll.saddr",        "ether saddr set aa:bb:cc:dd:ee:07" },
	{ "ll.daddr",        "ether daddr set aa:bb:cc:dd:ee:08" },
	{ "ll.type",         "ether type set 0x0806" },
	{ "ll.raw0",         "@ll,0,16 set 0x8899" },
	{ "ll.raw96",        "@ll,96,16 set 0x0806" },
	{ "ll.raw112",       "@ll,112,8 set 0x45" },
	{ "ll.raw0_128",     "@ll,0,128 set 0x112233445566778899aabbccddeeff50" },
};

/* A4/A6: an accept chain, so the frame *is* the answer */
static void f552_nft_section(const char *fam, const struct f552_spell *arms,
			     int n, int v6)
{
	unsigned char cap[512], ctl[512];
	char cmd[1024], tag[64];
	int k, ctl_len = 0, sent = 0, ncap = 0, flen = 0, rc;

	f552_sh("/nft flush ruleset");
	snprintf(cmd, sizeof(cmd), "/nft add table %s p552", fam);
	f552_sh(cmd);
	snprintf(cmd, sizeof(cmd),
		 "/nft 'add chain %s p552 c { type filter hook forward priority 0; policy accept; }'",
		 fam);
	rc = f552_sh(cmd);
	printf("F552 SETUP.%s|rc=%d|hook=forward|policy=accept\n", fam, rc);

	for (k = 0; k < n; k++) {
		snprintf(cmd, sizeof(cmd), "/nft flush chain %s p552 c", fam);
		f552_sh(cmd);
		if (arms[k].rule) {
			snprintf(cmd, sizeof(cmd),
				 "/nft --debug=netlink add rule %s p552 c '%s counter' "
				 ">/tmp/f552nl 2>&1; echo \"F552RC %s.%s $?\"",
				 fam, arms[k].rule, fam, arms[k].tag);
			f552_sh(cmd);
			snprintf(cmd, sizeof(cmd),
				 "sed 's/^/F552NL %s.%s /' /tmp/f552nl", fam, arms[k].tag);
			f552_sh(cmd);
		} else {
			printf("F552RC %s.%s 0\n", fam, arms[k].tag);
		}
		memset(cap, 0, sizeof(cap));
		flen = 0;
		ncap = 0;
		sent = 0;
		if (v6)
			rc = f552_p6(&sent, &ncap, cap, &flen);
		else
			rc = f543_probe_request(f552_envp, 16, 0x50, 0x18, &sent,
						&ncap, cap, &flen);
		if (!arms[k].rule && rc == 0 && ncap == 1) {
			memcpy(ctl, cap, sizeof(ctl));
			ctl_len = flen;
		}
		snprintf(tag, sizeof(tag), "%s.%s", fam, arms[k].tag);
		if (rc != 0 || ncap != 1) {
			printf("F552 %s|rule=%s|sent=%d|cap=%d|PROBEFAIL\n",
			       tag, arms[k].rule ? arms[k].rule : "none", sent, ncap);
			continue;
		}
		f552_report(tag, arms[k].rule, cap, flen, sent, ncap, ctl, ctl_len);
		snprintf(cmd, sizeof(cmd),
			 "/nft list chain %s p552 c 2>&1 | tr -d '\\r' | sed 's/^/F552CA %s /'",
			 fam, tag);
		f552_sh(cmd);
	}
	f552_sh("/nft flush ruleset");
}

/* A0: the link base -- the L2 header of a forwarded packet is rebuilt at
 * transmit, so the byte is not the answer; the verdict is. */
static void f552_ll_section(void)
{
	char cmd[1024], tag[64];
	int k, rc, sent = 0, ncap = 0, flen = 0;
	unsigned char cap[512];

	f552_sh("/nft flush ruleset");
	f552_sh("/nft add table ip p552ll");
	f552_sh("/nft 'add chain ip p552ll v { type filter hook forward priority 0; policy drop; }'");
	for (k = 0; k < (int)(sizeof(f552_ll) / sizeof(f552_ll[0])); k++) {
		f552_sh("/nft flush chain ip p552ll v");
		if (f552_ll[k].rule) {
			snprintf(cmd, sizeof(cmd),
				 "/nft --debug=netlink add rule ip p552ll v '%s' counter accept "
				 ">/tmp/f552nl 2>&1; echo \"F552RC ll.%s $?\"",
				 f552_ll[k].rule, f552_ll[k].tag);
			f552_sh(cmd);
			snprintf(cmd, sizeof(cmd),
				 "sed 's/^/F552NL ll.%s /' /tmp/f552nl", f552_ll[k].tag);
			f552_sh(cmd);
		} else {
			printf("F552RC ll.%s 0\n", f552_ll[k].tag);
		}
		memset(cap, 0, sizeof(cap));
		flen = 0;
		ncap = 0;
		sent = 0;
		rc = f543_probe_request(f552_envp, 16, 0x50, 0x18, &sent, &ncap,
					cap, &flen);
		snprintf(tag, sizeof(tag), "ll.%s", f552_ll[k].tag);
		printf("F552 %s|rule=%s|sent=%d|cap=%d|flen=%d|deliv=%d\n",
		       tag, f552_ll[k].rule ? f552_ll[k].rule : "none",
		       sent, ncap, flen, rc == 0 && ncap == 1);
		snprintf(cmd, sizeof(cmd),
			 "/nft list chain ip p552ll v 2>&1 | tr -d '\\r' | sed 's/^/F552V %s /'",
			 tag);
		f552_sh(cmd);
	}
	f552_sh("/nft flush ruleset");
}

/* ---------- B: the predicate, at the netlink level ---------- */

static struct nlmsghdr *f552_newrule_store(int family, const char *table,
					   const char *chain, uint32_t base,
					   uint32_t off, uint32_t len,
					   uint32_t csum_type, uint32_t csum_off,
					   const unsigned char *imm, int immlen,
					   int verdict)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs, *e, *d;

	cur_op = nops;
	nlh = msg_start(opbuf[nops],
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			F552_PF(family));
	put_str(nlh, NFTA_RULE_TABLE, table, "f30.rule.table");
	put_str(nlh, NFTA_RULE_CHAIN, chain, "f30.rule.chain");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS, "f30.exprs");

	exfil_imm_value(nlh, NFT_REG32_00, imm, immlen);
	e = nest_start(nlh, NFTA_LIST_ELEM, "f30.elem");
	put_str(nlh, NFTA_EXPR_NAME, "payload", "f30.name");
	d = nest_start(nlh, NFTA_EXPR_DATA, "f30.data");
	put_be32(nlh, NFTA_PAYLOAD_SREG, NFT_REG32_00, "f30.sreg");
	put_be32(nlh, NFTA_PAYLOAD_BASE, base, "f30.base");
	put_be32(nlh, NFTA_PAYLOAD_OFFSET, off, "f30.offset");
	put_be32(nlh, NFTA_PAYLOAD_LEN, len, "f30.len");
	put_be32(nlh, NFTA_PAYLOAD_CSUM_TYPE, csum_type, "f30.csum_type");
	put_be32(nlh, NFTA_PAYLOAD_CSUM_OFFSET, csum_off, "f30.csum_off");
	nest_end(nlh, d);
	nest_end(nlh, e);
	/* a counter between the store and the verdict is the second oracle:
	 * NFT_BREAK skips the rest of the rule, so packets 0 means "the guard
	 * refused" even when the packet would have been lost afterwards for a
	 * routing reason (a rewritten destination address). */
	if (verdict) {
		e = nest_start(nlh, NFTA_LIST_ELEM, "f30.cnt");
		put_str(nlh, NFTA_EXPR_NAME, "counter", "f30.cnt.name");
		d = nest_start(nlh, NFTA_EXPR_DATA, "f30.cnt.data");
		nest_end(nlh, d);
		nest_end(nlh, e);
		exfil_imm_verdict(nlh, NF_ACCEPT);
	}
	nest_end(nlh, exprs);
	nops++;
	return nlh;
}

static struct nlmsghdr *f552_newrule_accept(int family, const char *table,
					    const char *chain)
{
	struct nlmsghdr *nlh;
	struct nlattr *exprs;

	cur_op = nops;
	nlh = msg_start(opbuf[nops],
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
			F552_PF(family));
	put_str(nlh, NFTA_RULE_TABLE, table, "f30.v.table");
	put_str(nlh, NFTA_RULE_CHAIN, chain, "f30.v.chain");
	exprs = nest_start(nlh, NFTA_RULE_EXPRESSIONS, "f30.v.exprs");
	exfil_imm_verdict(nlh, NF_ACCEPT);
	nest_end(nlh, exprs);
	nops++;
	return nlh;
}

static struct nlmsghdr *f552_newtable(int family, const char *table)
{
	struct nlmsghdr *nlh;

	cur_op = nops;
	nlh = msg_start(opbuf[nops],
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			F552_PF(family));
	put_str(nlh, NFTA_TABLE_NAME, table, "f30.table.name");
	nops++;
	return nlh;
}

static struct nlmsghdr *f552_newchain(int family, const char *table,
				      const char *chain, int hooknum,
				      int priority, uint32_t policy)
{
	struct nlmsghdr *nlh;
	struct nlattr *hook;

	cur_op = nops;
	nlh = msg_start(opbuf[nops],
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
			F552_PF(family));
	put_str(nlh, NFTA_CHAIN_TABLE, table, "f30.chain.table");
	put_str(nlh, NFTA_CHAIN_NAME, chain, "f30.chain.name");
	put_str(nlh, NFTA_CHAIN_TYPE, "filter", "f30.chain.type");
	put_be32(nlh, NFTA_CHAIN_POLICY, policy, "f30.chain.policy");
	hook = nest_start(nlh, NFTA_CHAIN_HOOK, "f30.chain.hook");
	put_be32(nlh, NFTA_HOOK_HOOKNUM, (uint32_t)hooknum, "f30.chain.hooknum");
	put_be32(nlh, NFTA_HOOK_PRIORITY, (uint32_t)priority, "f30.chain.prio");
	nest_end(nlh, hook);
	nops++;
	return nlh;
}

static struct nlmsghdr *f552_deltable(int family, const char *table)
{
	struct nlmsghdr *nlh;

	cur_op = nops;
	nlh = msg_start(opbuf[nops],
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
			NLM_F_REQUEST | NLM_F_ACK, F552_PF(family));
	put_str(nlh, NFTA_TABLE_NAME, table, "f30.del.table");
	nops++;
	return nlh;
}

static void f552_flush_chain(int family, const char *table, const char *chain)
{
	struct nlmsghdr *nlh;
	int nattr = 0;

	cur_op = nops;
	nlh = msg_start(opbuf[nops],
			(NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELRULE,
			NLM_F_REQUEST | NLM_F_ACK, F552_PF(family));
	put_str(nlh, NFTA_RULE_TABLE, table, "f30.f.table");
	put_str(nlh, NFTA_RULE_CHAIN, chain, "f30.f.chain");
	nops++;
	f543_send_checked(&nattr, &nattr);
	nops = 0;
	nrecs = 0;
}

/* the immediate keeps the bytes the guard compares, so the arm measures the
 * offset rule and not the byte rule */
static void f552_imm_for(int fam, uint32_t off, uint32_t len, unsigned char *imm)
{
	int k;

	for (k = 0; k < 16; k++)
		imm[k] = (unsigned char)(0xa0 + k);
	if (fam == 4) {
		if (off == 0 && len >= 1)
			imm[0] = 0x45;			/* version 4, ihl 5 */
		if (off <= 9 && off + len > 9)
			imm[9 - off] = 0x06;		/* keep the protocol */
	} else {
		if (off == 0 && len >= 1)
			imm[0] = 0x61;			/* version 6        */
	}
}


/* ---------- reading the counter back, without nft's printer ----------
 * nft 1.1.7 aborts on a 4-byte store into ip daddr (its printer resolves the
 * payload to `ip daddr set <16-byte constant>` and asserts), so the counter
 * for exactly the arms that rewrite the destination cannot be read through
 * it.  The number is in the kernel either way: one GETRULE dump per arm. */
static unsigned long long f552_attr_u64(const struct nlattr *a)
{
	unsigned long long v = 0;
	int i;

	for (i = 0; i < 8; i++)
		v = (v << 8) | ((const unsigned char *)a + NLA_HDRLEN)[i];
	return v;
}

static unsigned long long f552_count(int family, const char *table,
				     const char *chain)
{
	char buf[1024], rbuf[16384];
	struct nlmsghdr *nlh;
	struct nfgenmsg_ *nfg;
	unsigned long long pkts = 0;
	int fd, sent;

	fd = nl_open();
	if (fd < 0)
		return 0;
	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_HDRLEN + sizeof(*nfg);
	nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = 1;
	nfg = (struct nfgenmsg_ *)NLMSG_DATA(nlh);
	nfg->nfgen_family = (uint8_t)F552_PF(family);
	nfg->version = 0;
	nfg->res_id = htons(0);
	attr_put(nlh, NFTA_RULE_TABLE, table, (int)strlen(table) + 1, "c.t");
	attr_put(nlh, NFTA_RULE_CHAIN, chain, (int)strlen(chain) + 1, "c.c");
	sent = (int)nlh->nlmsg_len;
	if (send(fd, buf, (size_t)sent, 0) != sent) {
		close(fd);
		return 0;
	}
	for (;;) {
		int rl = (int)recv(fd, rbuf, sizeof(rbuf), 0);
		struct nlmsghdr *h;

		if (rl <= 0)
			break;
		for (h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, rl);
		     h = NLMSG_NEXT(h, rl)) {
			const char *p, *end;

			if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
				goto out;
			if (h->nlmsg_type != (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) |
							NFT_MSG_NEWRULE))
				continue;
			p = (const char *)h + NLMSG_HDRLEN + sizeof(*nfg);
			end = (const char *)h + h->nlmsg_len;
			for (; p + (int)sizeof(struct nlattr) <= end; ) {
				const struct nlattr *a = (const struct nlattr *)p;
				int alen = (int)a->nla_len;

				if (alen < (int)sizeof(*a) || p + alen > end)
					break;
				if ((a->nla_type & 0x3fff) == NFTA_RULE_EXPRESSIONS) {
					const char *q = (const char *)a + NLA_HDRLEN;
					const char *qe = (const char *)a + alen;

					for (; q + (int)sizeof(struct nlattr) <= qe; ) {
						const struct nlattr *el = (const struct nlattr *)q;
						int ellen = (int)el->nla_len;
						const char *r, *re;
						int is_counter = 0;

						if (ellen < (int)sizeof(*el) || q + ellen > qe)
							break;
						r = (const char *)el + NLA_HDRLEN;
						re = (const char *)el + ellen;
						for (; r + (int)sizeof(struct nlattr) <= re; ) {
							const struct nlattr *ea = (const struct nlattr *)r;
							int ealen = (int)ea->nla_len;

							if (ealen < (int)sizeof(*ea) || r + ealen > re)
								break;
							if ((ea->nla_type & 0x3fff) == NFTA_EXPR_NAME &&
							    !strcmp((const char *)ea + NLA_HDRLEN, "counter"))
								is_counter = 1;
							r += NLA_ALIGN_(ealen);
						}
						if (is_counter) {
							r = (const char *)el + NLA_HDRLEN;
							for (; r + (int)sizeof(struct nlattr) <= re; ) {
								const struct nlattr *ea = (const struct nlattr *)r;
								int ealen = (int)ea->nla_len;

								if (ealen < (int)sizeof(*ea) || r + ealen > re)
									break;
								if ((ea->nla_type & 0x3fff) == NFTA_EXPR_DATA) {
									const char *d = (const char *)ea + NLA_HDRLEN;
									const char *de = (const char *)ea + ealen;

									for (; d + (int)sizeof(struct nlattr) <= de; ) {
										const struct nlattr *da = (const struct nlattr *)d;
										int dalen = (int)da->nla_len;

										if (dalen < (int)sizeof(*da) || d + dalen > de)
											break;
										if ((da->nla_type & 0x3fff) ==
										    NFTA_COUNTER_PACKETS &&
										    dalen >= NLA_HDRLEN + 8)
											pkts += f552_attr_u64(da);
										d += NLA_ALIGN_(dalen);
									}
								}
								r += NLA_ALIGN_(ealen);
							}
						}
						q += NLA_ALIGN_(ellen);
					}
				}
				p += NLA_ALIGN_(alen);
			}
		}
	}
out:
	close(fd);
	return pkts;
}

struct f552_raw_arm {
	const char *tag;
	uint32_t off, len;
	int keep;		/* 1 = keep the bytes the guard compares */
	int csum;		/* 1 = csum type inet                   */
	int bad;		/* 1 = change byte 0, 2 = change byte 1 */
};

static void f552_raw_one(int fam, const char *table, const char *chain,
			 const struct f552_raw_arm *a)
{
	unsigned char imm[16];
	unsigned char cap[512];
	int k, errs, nattr = 0, sent = 0, ncap = 0, flen = 0, rc;
	uint32_t csum_off = (fam == 4) ? 10 : 0;

	for (k = 0; k < 16; k++)
		imm[k] = (unsigned char)(0xa0 + k);
	if (a->keep)
		f552_imm_for(fam, a->off, a->len, imm);
	if (a->bad == 1)
		imm[0] = 0x95;
	if (a->bad == 2)
		imm[1] = 0x11;

	f552_flush_chain(fam, table, chain);
	nops = 0;
	nrecs = 0;
	if (a->len == 0)
		f552_newrule_accept(fam, table, chain);
	else
		f552_newrule_store(fam, table, chain, 1 /* network */, a->off,
				   a->len, a->csum ? 1 : 0,
				   a->csum ? csum_off : 0, imm, 16, 1);
	errs = f543_send_checked(&nattr, &nattr);
	if (errs != 0) {
		printf("F552 B%d.%s|setup=ERR|errno=%d\n", fam, a->tag,
		       g_err ? -g_err : 0);
		return;
	}
	memset(cap, 0, sizeof(cap));
	if (fam == 4)
		rc = f543_probe_request(f552_envp, 16, 0x50, 0x18, &sent, &ncap,
					cap, &flen);
	else
		rc = f552_p6(&sent, &ncap, cap, &flen);
	printf("F552 B%d.%s|off=%u|len=%u|keep=%d|csum=%d|bad=%d|sent=%d|cap=%d|deliv=%d\n",
	       fam, a->tag, a->off, a->len, a->keep, a->csum, a->bad, sent, ncap,
	       rc == 0 && ncap == 1);
	printf("F552CNT %d.%s|pkts=%llu\n", fam, a->tag,
	       f552_count(fam, table, chain));
}

static void f552_raw_section(int fam)
{
	char tab[32], tag[32];
	int nattr = 0, errs, off, len;
	unsigned int k;
	static const uint32_t big[][2] = {
		{ 0, 4 }, { 0, 8 }, { 2, 3 }, { 2, 4 }, { 7, 1 }, { 7, 2 },
		{ 10, 10 }, { 10, 12 }, { 12, 8 }, { 12, 9 },
		{ 16, 4 }, { 16, 5 }, { 8, 16 }, { 8, 32 }, { 8, 33 },
		{ 24, 16 }, { 24, 17 },
	};

	snprintf(tab, sizeof(tab), "p552_%d_%d", fam, (int)getpid());
	nops = 0;
	nrecs = 0;
	f552_newtable(fam, tab);
	f552_newchain(fam, tab, "c", NF_INET_FORWARD, 0, NF_DROP);
	errs = f543_send_checked(&nattr, &nattr);
	printf("F552 RAWSETUP.%d|errs=%d|table=%s\n", fam, errs, tab);

	{
		struct f552_raw_arm a;

		memset(&a, 0, sizeof(a));
		a.tag = "none";
		a.keep = 1;
		f552_raw_one(fam, tab, "c", &a);
	}
	for (off = 0; off < (fam == 4 ? 20 : 40); off++) {
		for (len = 1; len <= 2; len++) {
			struct f552_raw_arm a;

			memset(&a, 0, sizeof(a));
			snprintf(tag, sizeof(tag), "%d.%d", off, len);
			a.tag = tag;
			a.off = (uint32_t)off;
			a.len = (uint32_t)len;
			a.keep = 1;
			f552_raw_one(fam, tab, "c", &a);
		}
	}
	for (k = 0; k < sizeof(big) / sizeof(big[0]); k++) {
		struct f552_raw_arm a;

		memset(&a, 0, sizeof(a));
		snprintf(tag, sizeof(tag), "w%u.%u", big[k][0], big[k][1]);
		a.tag = tag;
		a.off = big[k][0];
		a.len = big[k][1];
		a.keep = 1;
		f552_raw_one(fam, tab, "c", &a);
	}
	/* the byte rule, separated from the offset rule */
	{
		struct f552_raw_arm a;

		memset(&a, 0, sizeof(a));
		a.tag = "bad0.2";	/* IPv4: version/ihl changed; IPv6: version 9 */
		a.off = 0;
		a.len = 2;
		a.keep = 1;
		a.bad = 1;
		f552_raw_one(fam, tab, "c", &a);

		memset(&a, 0, sizeof(a));
		a.tag = "badp.2";	/* IPv4 8.2: the protocol byte changed  */
		a.off = (fam == 4) ? 8 : 0;
		a.len = 2;
		a.keep = 1;
		a.bad = 2;
		f552_raw_one(fam, tab, "c", &a);
	}
	/* the csum fixup on this base: does it change what is allowed? */
	{
		struct f552_raw_arm a;

		memset(&a, 0, sizeof(a));
		a.tag = "cs.12.4";
		a.off = 12;
		a.len = 4;
		a.keep = 1;
		a.csum = 1;
		f552_raw_one(fam, tab, "c", &a);

		memset(&a, 0, sizeof(a));
		a.tag = "cs.2.2";
		a.off = 2;
		a.len = 2;
		a.keep = 1;
		a.csum = 1;
		f552_raw_one(fam, tab, "c", &a);
	}

	nops = 0;
	nrecs = 0;
	f552_deltable(fam, tab);
	f543_send_checked(&nattr, &nattr);
}

/* ---------- C: does a refused store also skip the verdict? ---------- */

static void f552_verdict_section(const char *fam, const struct f552_spell *arms,
				 int n, int v6)
{
	char cmd[1024], tag[64];
	unsigned char cap[512];
	int k, rc, sent = 0, ncap = 0, flen = 0;

	f552_sh("/nft flush ruleset");
	snprintf(cmd, sizeof(cmd), "/nft add table %s p552v", fam);
	f552_sh(cmd);
	snprintf(cmd, sizeof(cmd),
		 "/nft 'add chain %s p552v v { type filter hook forward priority 0; policy drop; }'",
		 fam);
	f552_sh(cmd);
	for (k = 0; k < n; k++) {
		snprintf(cmd, sizeof(cmd), "/nft flush chain %s p552v v", fam);
		f552_sh(cmd);
		if (arms[k].rule) {
			snprintf(cmd, sizeof(cmd),
				 "/nft add rule %s p552v v '%s' counter accept",
				 fam, arms[k].rule);
			rc = f552_sh(cmd);
		} else {
			rc = 0;
		}
		memset(cap, 0, sizeof(cap));
		sent = ncap = flen = 0;
		if (v6)
			f552_p6(&sent, &ncap, cap, &flen);
		else
			f543_probe_request(f552_envp, 16, 0x50, 0x18, &sent, &ncap,
					   cap, &flen);
		snprintf(tag, sizeof(tag), "C.%s.%s", fam, arms[k].tag);
		printf("F552 %s|rule=%s|nftrc=%d|sent=%d|cap=%d|deliv=%d\n",
		       tag, arms[k].rule ? arms[k].rule : "none", rc, sent, ncap,
		       ncap == 1);
		snprintf(cmd, sizeof(cmd),
			 "/nft list chain %s p552v v 2>&1 | tr -d '\\r' | sed 's/^/F552V %s /'",
			 fam, tag);
		f552_sh(cmd);
	}
	f552_sh("/nft flush ruleset");
}

static void run_f552(void)
{
	struct f539_env e;
	char out[512];
	int rc6;

	if (f539_env_open(&e, out, sizeof(out)) < 0) {
		printf("F552 SETUP|fail|%s\n", out);
		f539_env_close(&e);
		return;
	}
	f552_envp = &e;
	f539_route_add("fv0", F539_NET_FAR, 24, 0);
	f539_sysctl("/proc/sys/net/netfilter/nf_conntrack_checksum", "0");
	rc6 = f552_v6_setup();
	printf("F552 ENV|v6setup=%d\n", rc6);
	f552_sh("echo \"F552 SYSCTL|v4fwd=$(cat /proc/sys/net/ipv4/ip_forward)\""
		"\"|v6fwd=$(cat /proc/sys/net/ipv6/conf/all/forwarding)\""
		"\"|v6fv0=$(cat /proc/sys/net/ipv6/conf/fv0/forwarding 2>&1)\"");

	f552_nft_section("ip", f552_ip4,
			 (int)(sizeof(f552_ip4) / sizeof(f552_ip4[0])), 0);
	f552_ll_section();
	f552_nft_section("ip6", f552_ip6,
			 (int)(sizeof(f552_ip6) / sizeof(f552_ip6[0])), 1);
	f552_raw_section(4);
	f552_raw_section(6);
	f552_verdict_section("ip", f552_ip4,
			     (int)(sizeof(f552_ip4) / sizeof(f552_ip4[0])), 0);
	f552_verdict_section("ip6", f552_ip6,
			     (int)(sizeof(f552_ip6) / sizeof(f552_ip6[0])), 1);

	f552_sh("/nft flush ruleset");
	printf("F552 DONE\n");
	nf_flush();
	f539_env_close(&e);
}
