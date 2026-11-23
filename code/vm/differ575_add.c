/* differ575_add.c -- turn 575 (F53).
 *
 *  THE QUESTION (named at the end of 574): VLAN_FLAG_REORDER_HDR, cleared from
 *  userspace, is the one configuration in this family where the kernel puts the
 *  tag BACK into the frame between vlan_do_receive() and the hook -- so it is
 *  the one place where `@ll` should read a physically tagged frame at a
 *  layer-3 door.
 *
 *  Mode `reorder`: F51's three-port bridge (br0 with x1/y1/z1, IPv6 only on
 *  br0, fd02::92 on br0, UDP6 socket on 5000) plus four VLAN devices on top of
 *  br0:
 *
 *    br0.100      8100 vid 100  flags default (REORDER_HDR set)   control
 *    br0.101      8100 vid 101  flags cleared (flags=0, mask=1)   the question
 *    br0.102      88a8 vid 102  flags cleared                     QinQ outer
 *    br0.102.200  8100 vid 200  flags default                     QinQ inner
 *
 *  Two doors:
 *    g6  ip6 prerouting, all devices     (the door of F52's group D; which
 *        device delivered the frame is NFULA_IFINDEX_INDEV of its message --
 *        a device-specific ip6 chain is refused with -EOPNOTSUPP)
 *    n1  netdev ingress, x1              (the tag is still metadata here)
 *
 *  Frames, all broadcast, IPv6 fd02::11 -> fd02::92, UDP 42000 -> 5000:
 *    A  plain                                             (74 + 18)
 *    B  8100 vid 100                                      (78 + 18)
 *    E  8100 vid 101                                      (78 + 18)
 *    Q  88a8 vid 102 + 8100 vid 200                       (82 + 18)
 *
 *  Every arm carries the census (counter+log+accept at prio0 in both doors)
 *  and at most one counter+store/read+log+accept rule at prio1 in one door.
 */

#define F575_SPORT	42000
#define F575_DPORT	F573_DPORT

static const unsigned char A75_SRC[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x11 };
static const unsigned char A75_DST[16] = { 0xfd, 0x02, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x00, 0x00, 0x00, 0x00, 0x00,
					   0x92 };
static const unsigned char A75_N6[6] = { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95 };

/* ---------- the five doors ---------- */

/* ip6 chains take no NFTA_HOOK_DEV in this kernel (the CREATE returns
 * -EOPNOTSUPP -- measured in the first smoke), so the layer-3 door is one
 * chain for all devices and the device is read from NFULA_IFINDEX_INDEV. */
static struct f571_door D575[] = {
	{ "g6", NFPROTO_IPV6,   "e75a", NULL, 0, 210, 220 },
	{ "n1", NFPROTO_NETDEV, "e75e", "x1", 0, 290, 300 },
};
enum { E75_G6 = 0, E75_N1 };
#define ND75 2

/* ---------- taps on the VLAN devices (the state the user sees) ---------- */

#define F575_TAPN	3
struct f575_tap {
	int fd;
	int n;
	int flen;
	int len;
	unsigned char b[128];
};
static struct f575_tap F575_TAP[F575_TAPN];
static const char *F575_TAPDEV[F575_TAPN] = { "br0.100", "br0.101",
					      "br0.102.200" };
#define T575_A	(1 << 0)
#define T575_B	(1 << 1)
#define T575_Q	(1 << 2)
#define T575_AB	(T575_A | T575_B)
#define T575_ALL3 (T575_A | T575_B | T575_Q)

static void f575_tap_reset(void)
{
	int i;

	for (i = 0; i < F575_TAPN; i++) {
		if (F575_TAP[i].fd >= 0)
			close(F575_TAP[i].fd);
		F575_TAP[i].fd = -1;
		F575_TAP[i].n = 0;
		F575_TAP[i].len = -1;
		F575_TAP[i].flen = -1;
	}
}

static void f575_tap_open_mask(int mask)
{
	int i;

	f575_tap_reset();
	for (i = 0; i < F575_TAPN; i++) {
		if (!(mask & (1 << i)))
			continue;
		F575_TAP[i].fd = f571_tap_open(F575_TAPDEV[i]);
	}
}

static void f575_tap_drain(int i)
{
	unsigned char b[2048];
	int r;

	F575_TAP[i].n = 0;
	F575_TAP[i].len = -1;
	F575_TAP[i].flen = -1;
	if (F575_TAP[i].fd < 0)
		return;
	while ((r = (int)recv(F575_TAP[i].fd, b, sizeof(b), MSG_DONTWAIT)) >
	       0) {
		int k;

		if (!f568_needle(b, r))
			continue;
		F575_TAP[i].n++;
		if (F575_TAP[i].len < 0) {
			F575_TAP[i].flen = r;
			k = r < (int)sizeof(F575_TAP[i].b) ? r
			    : (int)sizeof(F575_TAP[i].b);
			memcpy(F575_TAP[i].b, b, (size_t)k);
			F575_TAP[i].len = k;
		}
	}
}

/* ---------- NFLOG drain with the hardware header and the vlan tag ---------- */

#define F575_NPL	16

struct f575_msg {
	char prefix[8];
	int indev, outdev;
	int hwtype, hwlen;
	int hlen;
	unsigned char h[32];
	int llen;
	unsigned char l[24];
	int vpresent, vproto, vtci;
	int plen;
	unsigned char p[96];
	char atrs[160];
};
struct f575_pl {
	int n;
	struct f575_msg m[F575_NPL];
};

#define F575_NFULA_HWTYPE	15
#define F575_NFULA_HWHEADER	16
#define F575_NFULA_HWLEN	17
#define F575_NFULA_VLAN		20
#define F575_NFULA_L2HDR	21
#define F575_NFULA_VLAN_PROTO	1
#define F575_NFULA_VLAN_TCI	2

static int f575_be16(const void *p)
{
	const unsigned char *b = (const unsigned char *)p;

	return ((int)b[0] << 8) | (int)b[1];
}

static void f575_nfl_drain(struct f575_pl *v)
{
	unsigned char b[16384];
	int guard = 0, rl;

	if (v)
		memset(v, 0, sizeof(*v));
	if (F573_NFL < 0)
		return;
	while (guard++ < 64) {
		struct nlmsghdr *h;
		int len;

		rl = (int)recv(F573_NFL, b, sizeof(b), MSG_DONTWAIT);
		if (rl <= 0)
			break;
		len = rl;
		for (h = (struct nlmsghdr *)b; NLMSG_OK(h, len);
		     h = NLMSG_NEXT(h, len)) {
			const char *p, *end, *prefix = NULL;
			const unsigned char *pl = NULL, *hw = NULL, *l2 = NULL;
			int pll = 0, hwl = 0, l2l = 0, ind = -1, outd = -1;
			int hwt = -1, hwln = -1, vp = 0, vpr = -1, vtc = -1;

			if (h->nlmsg_type == NLMSG_DONE ||
			    h->nlmsg_type == NLMSG_ERROR)
				continue;
			p = (const char *)h + NLMSG_HDRLEN +
			    sizeof(struct nfgenmsg);
			end = (const char *)h + h->nlmsg_len;
			for (; p + (int)sizeof(struct nlattr) <= end; ) {
				const struct nlattr *a = (const struct nlattr *)p;
				int al = (int)a->nla_len;
				int t;

				if (al < (int)sizeof(*a) || p + al > end)
					break;
				t = a->nla_type & 0x3fff;
				if (t == NFULA_PREFIX_) {
					prefix = (const char *)a + NLA_HDRLEN;
				} else if (t == NFULA_PAYLOAD_) {
					pl = (const unsigned char *)a +
					     NLA_HDRLEN;
					pll = al - NLA_HDRLEN;
				} else if (t == NFULA_IFINDEX_INDEV_) {
					__be32 x;

					memcpy(&x, (const char *)a + NLA_HDRLEN,
					       4);
					ind = (int)ntohl(x);
				} else if (t == NFULA_IFINDEX_OUTDEV_) {
					__be32 x;

					memcpy(&x, (const char *)a + NLA_HDRLEN,
					       4);
					outd = (int)ntohl(x);
				} else if (t == F575_NFULA_HWTYPE) {
					hwt = f575_be16((const char *)a +
							NLA_HDRLEN);
				} else if (t == F575_NFULA_HWLEN) {
					hwln = f575_be16((const char *)a +
							 NLA_HDRLEN);
				} else if (t == F575_NFULA_HWHEADER) {
					hw = (const unsigned char *)a +
					     NLA_HDRLEN;
					hwl = al - NLA_HDRLEN;
				} else if (t == F575_NFULA_L2HDR) {
					l2 = (const unsigned char *)a +
					     NLA_HDRLEN;
					l2l = al - NLA_HDRLEN;
				} else if (t == F575_NFULA_VLAN) {
					const char *q = (const char *)a +
							NLA_HDRLEN;
					const char *qend = (const char *)a + al;

					vp = 1;
					for (; q + (int)sizeof(struct nlattr)
					       <= qend; ) {
						const struct nlattr *b2 =
							(const struct nlattr *)q;
						int bl = (int)b2->nla_len;
						int bt;

						if (bl < (int)sizeof(*b2) ||
						    q + bl > qend)
							break;
						bt = b2->nla_type & 0x3fff;
						if (bt == F575_NFULA_VLAN_TCI)
							vtc = f575_be16(q +
								NLA_HDRLEN);
						else if (bt ==
							 F575_NFULA_VLAN_PROTO)
							vpr = f575_be16(q +
								NLA_HDRLEN);
						q += NLA_ALIGN_(bl);
					}
				}
				p += NLA_ALIGN_(al);
			}
			if (!v || !prefix || prefix[0] == 0)
				continue;
			if (v->n < F575_NPL) {
				struct f575_msg *M = &v->m[v->n];
				int k;

				{
					const char *q = (const char *)h + NLMSG_HDRLEN +
							sizeof(struct nfgenmsg);
					int o2 = 0;

					M->atrs[0] = 0;
					while (q + (int)sizeof(struct nlattr) <= end &&
					       o2 < (int)sizeof(M->atrs) - 16) {
						const struct nlattr *a2 =
							(const struct nlattr *)q;
						int al2 = (int)a2->nla_len;

						if (al2 < (int)sizeof(*a2) ||
						    q + al2 > end)
							break;
						o2 += snprintf(M->atrs + o2,
							       sizeof(M->atrs) - (size_t)o2,
							       "%d:%d,",
							       a2->nla_type & 0x3fff,
							       al2 - NLA_HDRLEN);
						q += NLA_ALIGN_(al2);
					}
				}

				snprintf(M->prefix, sizeof(M->prefix), "%s",
					 prefix);
				if (pl) {
					k = pll < (int)sizeof(M->p) ? pll
						     : (int)sizeof(M->p);
					memcpy(M->p, pl, (size_t)k);
					M->plen = k;
				}
				if (hw) {
					k = hwl < (int)sizeof(M->h) ? hwl
						   : (int)sizeof(M->h);
					memcpy(M->h, hw, (size_t)k);
					M->hlen = k;
				}
				if (l2) {
					k = l2l < (int)sizeof(M->l) ? l2l
						   : (int)sizeof(M->l);
					memcpy(M->l, l2, (size_t)k);
					M->llen = k;
				}
				M->indev = ind;
				M->outdev = outd;
				M->hwtype = hwt;
				M->hwlen = hwln;
				M->vpresent = vp;
				M->vproto = vpr;
				M->vtci = vtc;
			}
			v->n++;
		}
	}
}

/* ---------- the VLAN devices ---------- */

#define F575_IFLA_VLAN_ID	1
#define F575_IFLA_VLAN_FLAGS	2
#define F575_IFLA_VLAN_PROTOCOL	5

/* proto == 0: leave the kernel default (0x8100).  clear_reorder: send
 * IFLA_VLAN_FLAGS{flags = 0, mask = VLAN_FLAG_REORDER_HDR}. */
static int f575_link_add_vlan(const char *name, const char *link,
			      unsigned short vid, unsigned short proto,
			      int clear_reorder)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
		char attrs[320];
	} req;
	struct nlattr *li, *data;
	uint32_t lidx = (uint32_t)f555_ifindex(link);
	int fd, rc;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_NEWLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	attr_put(&req.nlh, IFLA_IFNAME, name, (int)strlen(name) + 1);
	attr_put(&req.nlh, IFLA_LINK, &lidx, 4);
	li = nest_start(&req.nlh, IFLA_LINKINFO);
	attr_put(&req.nlh, IFLA_INFO_KIND, "vlan", 5);
	data = nest_start(&req.nlh, IFLA_INFO_DATA);
	attr_put(&req.nlh, F575_IFLA_VLAN_ID, &vid, 2);
	if (proto) {
		unsigned short be = htons(proto);

		attr_put(&req.nlh, F575_IFLA_VLAN_PROTOCOL, &be, 2);
	}
	if (clear_reorder) {
		uint32_t fl[2];

		fl[0] = 0;		/* flags */
		fl[1] = 1;		/* mask: VLAN_FLAG_REORDER_HDR */
		attr_put(&req.nlh, F575_IFLA_VLAN_FLAGS, fl, 8);
	}
	nest_end(&req.nlh, data);
	nest_end(&req.nlh, li);
	fd = rtnl_open();
	if (fd < 0)
		return -1;
	rc = rtnl_talk(fd, &req.nlh);
	close(fd);
	return rc;
}

/* Read the VLAN configuration back from the kernel: IFLA_LINKINFO ->
 * IFLA_INFO_DATA -> {PROTOCOL, ID, FLAGS}.  vlan_fill_info() emits FLAGS only
 * when vlan->flags is nonzero, so "absent" is the oracle for a cleared flag. */
static void f575_vlan_readback(const char *dev)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req;
	unsigned char rbuf[8192];
	struct nlmsghdr *nlh;
	struct sockaddr_nl sa;
	int fd, idx = f555_ifindex(dev), r, got = 0;
	int proto = -1, id = -1, flags = -1, mask = -1, present = 0;

	if (idx < 0) {
		printf("F575 VDEV|dev=%s|idx=-1\n", dev);
		return;
	}
	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 21;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = idx;
	if (sendto(fd, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa,
		   sizeof(sa)) < 0) {
		close(fd);
		return;
	}
	r = (int)recv(fd, rbuf, sizeof(rbuf), 0);
	close(fd);
	if (r <= 0)
		return;
	for (nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, r);
	     nlh = NLMSG_NEXT(nlh, r)) {
		struct ifinfomsg *ifi;
		const char *p, *end;

		if (nlh->nlmsg_type != RTM_NEWLINK)
			continue;
		ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
		(void)ifi;
		p = (const char *)nlh + NLMSG_HDRLEN + sizeof(struct ifinfomsg);
		end = (const char *)nlh + nlh->nlmsg_len;
		for (; p + (int)sizeof(struct nlattr) <= end; ) {
			const struct nlattr *a = (const struct nlattr *)p;
			int al = (int)a->nla_len;
			int t = a->nla_type & 0x3fff;

			if (al < (int)sizeof(*a) || p + al > end)
				break;
			if (t == IFLA_LINKINFO) {
				const char *q = p + NLA_HDRLEN;
				const char *qend = p + al;

				for (; q + (int)sizeof(struct nlattr) <= qend; ) {
					const struct nlattr *b2 =
						(const struct nlattr *)q;
					int bl = (int)b2->nla_len;
					int bt = b2->nla_type & 0x3fff;

					if (bl < (int)sizeof(*b2) ||
					    q + bl > qend)
						break;
					if (bt == IFLA_INFO_DATA) {
						const char *s = q + NLA_HDRLEN;
						const char *send = q + bl;

						for (; s + (int)sizeof(struct nlattr)
						       <= send; ) {
							const struct nlattr *c =
							  (const struct nlattr *)s;
							int cl = (int)c->nla_len;
							int ct = c->nla_type &
								 0x3fff;

							if (cl < (int)sizeof(*c) ||
							    s + cl > send)
								break;
							if (ct ==
							    F575_IFLA_VLAN_PROTOCOL)
								proto = f575_be16(s +
									NLA_HDRLEN);
							else if (ct ==
								 F575_IFLA_VLAN_ID) {
								const unsigned char *v =
								  (const unsigned char *)s +
								  NLA_HDRLEN;

								id = (int)v[0] |
								     ((int)v[1] << 8);
							}
							else if (ct ==
								 F575_IFLA_VLAN_FLAGS) {
								const unsigned char *f =
								  (const unsigned char *)s +
								  NLA_HDRLEN;

								if (cl >=
								    (int)sizeof(*c) +
								    8) {
									memcpy(&flags,
									       f, 4);
									memcpy(&mask,
									       f + 4,
									       4);
									present = 1;
								}
							}
							s += NLA_ALIGN_(cl);
						}
					}
					q += NLA_ALIGN_(bl);
					got = 1;
				}
			}
			p += NLA_ALIGN_(al);
		}
	}
	printf("F575 VDEV|dev=%s|idx=%d|linkinfo=%d|flags_present=%d|"
	       "flags=%d|mask=%d|proto=%04x|vid=%d\n",
	       dev, idx, got, present, flags, mask, proto, id);
}

/* ---------- environment ---------- */

static unsigned char F575_FA[160], F575_FB[160], F575_FE[160], F575_FQ[160];
static int F575_LA = -1, F575_LB = -1, F575_LE = -1, F575_LQ = -1;

/* a 802.1Q frame with an explicit TPID: 14 + 4 + IPv6/UDP */
static int f575_frame_tag(unsigned char *out, unsigned short tpid,
			  const unsigned char *dmac, const unsigned char *smac,
			  unsigned int tci)
{
	memset(out, 0, 160);
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = (unsigned char)((tpid >> 8) & 0xff);
	out[13] = (unsigned char)(tpid & 0xff);
	out[14] = (unsigned char)((tci >> 8) & 0xff);
	out[15] = (unsigned char)(tci & 0xff);
	out[16] = 0x86;
	out[17] = 0xdd;
	return 18 + f570_ip6(out + 18, A75_SRC, A75_DST, 0, F575_SPORT,
			     F575_DPORT);
}

/* 88a8/outer + 8100/inner + IPv6/UDP */
static int f575_frame_qinq(unsigned char *out, const unsigned char *dmac,
			   const unsigned char *smac, unsigned int otci,
			   unsigned int itci)
{
	int n;

	memset(out, 0, 160);
	memcpy(out, dmac, 6);
	memcpy(out + 6, smac, 6);
	out[12] = 0x88;
	out[13] = 0xa8;
	out[14] = (unsigned char)((otci >> 8) & 0xff);
	out[15] = (unsigned char)(otci & 0xff);
	out[16] = 0x81;
	out[17] = 0x00;
	out[18] = (unsigned char)((itci >> 8) & 0xff);
	out[19] = (unsigned char)(itci & 0xff);
	out[20] = 0x86;
	out[21] = 0xdd;
	n = f570_ip6(out + 22, A75_SRC, A75_DST, 0, F575_SPORT, F575_DPORT);
	return 22 + n;
}

static int f575_env(void)
{
	int rc = f574_env();
	char hb[256], hc[256], hd[256], he[256];
	int r1, r2, r3, r4;

	printf("F575 ENVRC|f574=%d\n", rc);
	if (rc)
		return rc;
	F575_LA = F574_LA;
	memcpy(F575_FA, F574_FA, (size_t)F574_LA);
	printf("F575 FRM|a=%s\n", f559_hexs(hb, sizeof(hb), F575_FA, F575_LA));
	F575_LB = f575_frame_tag(F575_FB, 0x8100, A74_BC, F573_X0M, 0x0064);
	F575_LE = f575_frame_tag(F575_FE, 0x8100, A74_BC, F573_X0M, 0x0065);
	F575_LQ = f575_frame_qinq(F575_FQ, A74_BC, F573_X0M, 0x0066, 0x00c8);
	printf("F575 FRM|b=%s\n", f559_hexs(hc, sizeof(hc), F575_FB, F575_LB));
	printf("F575 FRM|e=%s\n", f559_hexs(hd, sizeof(hd), F575_FE, F575_LE));
	printf("F575 FRM|q=%s\n", f559_hexs(he, sizeof(he), F575_FQ, F575_LQ));

	r1 = f575_link_add_vlan("br0.100", "br0", 100, 0, 0);
	r2 = f575_link_add_vlan("br0.101", "br0", 101, 0, 1);
	r3 = f575_link_add_vlan("br0.102", "br0", 102, 0x88a8, 1);
	printf("F575 VNEW|d100=%d|d101=%d|d102=%d\n", r1, r2, r3);
	f575_vlan_readback("br0.100");
	f575_vlan_readback("br0.101");
	f575_vlan_readback("br0.102");
	if (r1 || r2 || r3)
		return -5;
	set_up("br0.100");
	set_up("br0.101");
	set_up("br0.102");
	r4 = f575_link_add_vlan("br0.102.200", "br0.102", 200, 0, 0);
	printf("F575 VNEW|d102_200=%d\n", r4);
	f575_vlan_readback("br0.102.200");
	if (r4)
		return -6;
	set_up("br0.102.200");
	{
		const char *dv[] = { "br0.100", "br0.101", "br0.102",
				     "br0.102.200" };
		char path[160];
		int i;

		for (i = 0; i < 4; i++) {
			int a;

			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/disable_ipv6",
				 dv[i]);
			f555_sysctl(path, "0");
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/accept_dad", dv[i]);
			f555_sysctl(path, "0");
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/dad_transmits",
				 dv[i]);
			f555_sysctl(path, "0");
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/accept_ra", dv[i]);
			f555_sysctl(path, "0");
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/autoconf", dv[i]);
			f555_sysctl(path, "0");
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/forwarding", dv[i]);
			f555_sysctl(path, "0");
			a = f564_addr6(dv[i], A75_DST, 128);
			snprintf(path, sizeof(path),
				 "/proc/sys/net/ipv6/conf/%s/disable_ipv6",
				 dv[i]);
			printf("F575 VADDR|dev=%s|rc=%d|v6=%d|idx=%d\n", dv[i],
			       a, f573_sysint(path), f555_ifindex(dv[i]));
		}
	}
	usleep(3000000);
	f573_settle();
	{
		char hx[64];

		printf("F575 ENV|br0=%d|x1=%d|d100=%d|d101=%d|d102=%d|d102200=%d|"
		       "la=%d|lb=%d|le=%d|lq=%d|x0mac=%s\n",
		       f555_ifindex("br0"), f555_ifindex("x1"),
		       f555_ifindex("br0.100"), f555_ifindex("br0.101"),
		       f555_ifindex("br0.102"), f555_ifindex("br0.102.200"),
		       F575_LA, F575_LB, F575_LE, F575_LQ,
		       f559_hexs(hx, sizeof(hx), F573_X0M, 6));
	}
	return 0;
}

static int f575_chains(void)
{
	int i, rc = 0;

	for (i = 0; i < ND75; i++) {
		struct f571_door *D = &D575[i];
		int a, b, c;

		a = add_table(D->fam, D->table);
		b = f556_add_chain(D->fam, D->table, "pre0", D->hook,
				   (uint32_t)D->prio0, 1, D->dev);
		c = f556_add_chain(D->fam, D->table, "ch", D->hook,
				   (uint32_t)D->prio1, 1, D->dev);
		printf("F575 CH|door=%s|fam=%d|hook=%u|dev=%s|table=%d|"
		       "pre0=%d|ch=%d\n", D->tag, (int)D->fam, D->hook,
		       D->dev ? D->dev : "-", a, b, c);
		rc |= a | b | c;
	}
	return rc;
}

static void f575_flush_all(void)
{
	int i, acks = 0;

	for (i = 0; i < ND75; i++) {
		f557_flush(D575[i].fam, D575[i].table, "pre0", &acks);
		f557_flush(D575[i].fam, D575[i].table, "ch", &acks);
	}
}

/* ---------- one arm ---------- */

static void f575_arm(const char *arm, int fk, int tapmask, int door,
		     const struct f571_cfg *C)
{
	struct f571_cfg N, Z;
	struct f573_rep r0, r;
	struct f575_pl pl;
	const unsigned char *fr = NULL;
	int flen = 0, proto = 0x86dd;
	unsigned long long c0[ND75], c1[ND75], s0 = 0, s1 = 0;
	int i, acks = 0, snd = 0, polls = 0, k, maxp = 12, st = -9, rcs = -99;
	char hx[64];
	const char *fkn = "A";

	memset(&r0, 0, sizeof(r0));
	memset(&r, 0, sizeof(r));
	f571_zero(&N, "p");
	if (fk == 0) {
		fr = F575_FA;
		flen = F575_LA;
		fkn = "A";
	} else if (fk == 1) {
		fr = F575_FB;
		flen = F575_LB;
		fkn = "B";
	} else if (fk == 2) {
		fr = F575_FE;
		flen = F575_LE;
		fkn = "E";
	} else if (fk == 3) {
		fr = F575_FQ;
		flen = F575_LQ;
		fkn = "Q";
	}
	f575_flush_all();
	f575_nfl_drain(NULL);
	st = f573_settle();
	f575_tap_open_mask(tapmask);
	for (i = 0; i < F575_TAPN; i++)
		if (F575_TAP[i].fd >= 0)
			f575_tap_drain(i);
	for (i = 0; i < ND75; i++) {
		char nm[8];

		snprintf(nm, sizeof(nm), "p%d", i);
		if (f571_rule(&D575[i], "pre0", nm, &N, &acks))
			printf("F575 RUFAIL|arm=%s|door=%s|chain=pre0\n", arm,
			       D575[i].tag);
	}
	if (door >= 0) {
		f571_zero(&Z, "s");
		rcs = f571_rule(&D575[door], "ch", "s", C ? C : &Z, &acks);
	}
	for (i = 0; i < ND75; i++)
		c0[i] = f555_count(D575[i].fam, D575[i].table, "pre0");
	s0 = door >= 0 ? f555_count(D575[door].fam, D575[door].table, "ch") : 0;
	f573_snap(&r0);
	f573_u6_drain(&r0);
	if (fk >= 0) {
		snd = pkt_send_p("x0", fr, flen, (unsigned short)proto);
		for (k = 0; k < maxp; k++) {
			usleep(120000);
			f573_snap(&r);
			polls++;
			if (r.u6n > r0.u6n || r.i6in > r0.i6in ||
			    r.i6hdr > r0.i6hdr || r.i6disc > r0.i6disc ||
			    r.brrxp > r0.brrxp || r.x1rxp > r0.x1rxp)
				break;
			{
				int any = 0;

				for (i = 0; i < ND75; i++) {
					unsigned long long cv =
						f555_count(D575[i].fam,
							   D575[i].table,
							   "pre0");

					if (cv > c0[i])
						any = 1;
				}
				if (any && polls >= 3)
					break;
			}
		}
	} else {
		usleep(300000);
		polls = 1;
	}
	f573_snap(&r);
	usleep(150000);
	f573_snap(&r);
	for (i = 0; i < ND75; i++)
		c1[i] = f555_count(D575[i].fam, D575[i].table, "pre0");
	s1 = door >= 0 ? f555_count(D575[door].fam, D575[door].table, "ch") : 0;
	f575_nfl_drain(&pl);
	for (i = 0; i < F575_TAPN; i++)
		f575_tap_drain(i);

	printf("F575 A|arm=%s|fk=%s|door=%s|mode=%d|base=%u|off=%d|len=%d|"
	       "imm=%s|rcs=%d|snt=%d|sendrc=%d|polls=%d|tapmask=%d|u6n=%d|"
	       "u6len=%d|u6sport=%d|nfl=%d|st=%d\n",
	       arm, fkn, door >= 0 ? D575[door].tag : "-",
	       C ? C->mode : (door >= 0 ? 0 : -1), C ? C->base : 0,
	       C ? C->off : -1, C ? C->len : -1,
	       C ? f559_hexs(hx, sizeof(hx), C->imm, C->len) : "-", rcs,
	       fk >= 0, snd, polls, tapmask, r.u6n, r.u6len, r.u6sport, pl.n,
	       st);
	printf("F575 C|g6=%llu|n1=%llu|ch=%lld\n",
	       c1[E75_G6] - c0[E75_G6], c1[E75_N1] - c0[E75_N1],
	       door >= 0 ? (long long)(s1 - s0) : -1LL);
	printf("F575 B|i6in_d=%llu|i6hdr_d=%llu|i6addr_d=%llu|i6unk_d=%llu|"
	       "i6trunc_d=%llu|i6nor_d=%llu|deliv_d=%llu|disc_d=%llu|"
	       "mcas_d=%llu|u6in_d=%llu|u6err_d=%llu|u6nop_d=%llu|"
	       "brrxp_d=%llu|brrxb_d=%llu|x1rxp_d=%llu\n",
	       r.i6in - r0.i6in, r.i6hdr - r0.i6hdr, r.i6addr - r0.i6addr,
	       r.i6unk - r0.i6unk, r.i6trunc - r0.i6trunc,
	       r.i6nor - r0.i6nor, r.i6deliv - r0.i6deliv,
	       r.i6disc - r0.i6disc, r.i6mcast - r0.i6mcast,
	       r.u6in - r0.u6in, r.u6err - r0.u6err, r.u6nop - r0.u6nop,
	       r.brrxp - r0.brrxp, r.brrxb - r0.brrxb, r.x1rxp - r0.x1rxp);
	{
		char mb[2400];
		int o2 = 0;

		mb[0] = 0;
		for (i = 0; i < pl.n && i < F575_NPL; i++) {
			char hh[160], hw[80], l2[80];
			int w = snprintf(mb + o2, sizeof(mb) - (size_t)o2,
					 "|m%d=%s:%d:%d:%d:%d:%d:%s:%d:%s:"
					 "%d:%04x:%04x:%d:%s", i,
					 pl.m[i].prefix, pl.m[i].indev,
					 pl.m[i].outdev, pl.m[i].hwtype,
					 pl.m[i].hwlen, pl.m[i].hlen,
					 f559_hexs(hw, sizeof(hw), pl.m[i].h,
						   pl.m[i].hlen),
					 pl.m[i].llen,
					 f559_hexs(l2, sizeof(l2), pl.m[i].l,
						   pl.m[i].llen),
					 pl.m[i].vpresent, pl.m[i].vproto,
					 pl.m[i].vtci, pl.m[i].plen,
					 f559_hexs(hh, sizeof(hh), pl.m[i].p,
						   pl.m[i].plen > 42 ? 42
								     : pl.m[i].plen));

			if (w < 0 || w >= (int)sizeof(mb) - o2)
				break;
			o2 += w;
		}
		printf("F575 M|n=%d%s\n", pl.n, mb);
		if (pl.n > 0)
			printf("F575 ATTR|m0=%s\n", pl.m[0].atrs);
	}
	{
		char tb[1400];
		int o2 = 0;

		tb[0] = 0;
		for (i = 0; i < F575_TAPN; i++) {
			char hh[260];
			int w;

			if (F575_TAP[i].len > 0) {
				w = snprintf(tb + o2, sizeof(tb) - (size_t)o2,
					     "|t%d=%s:%d:%d:%s", i,
					     F575_TAPDEV[i], F575_TAP[i].n,
					     F575_TAP[i].flen,
					     f559_hexs(hh, sizeof(hh),
						       F575_TAP[i].b,
						       F575_TAP[i].len));
			} else {
				w = snprintf(tb + o2, sizeof(tb) - (size_t)o2,
					     "|t%d=%s:%d:%d:-", i,
					     F575_TAPDEV[i], F575_TAP[i].n,
					     F575_TAP[i].flen);
			}
			if (w < 0 || w >= (int)sizeof(tb) - o2)
				break;
			o2 += w;
		}
		printf("F575 T|%s\n", tb[0] ? tb + 1 : tb);
	}
}

/* ---------- config builders ---------- */

static void f575_wr(struct f571_cfg *C, uint32_t base, int off, int len,
		    const unsigned char *imm)
{
	f571_wr(C, "s", base, off, len, imm, 0, 0);
}

static void f575_rdv(struct f571_cfg *C, uint32_t base, int off, int len,
		     const unsigned char *imm)
{
	f571_zero(C, "s");
	C->mode = 3;
	C->base = base;
	C->off = off;
	C->len = len;
	memcpy(C->imm, imm, (size_t)len);
}

/* ---------- sections ---------- */

static void f575_sec_topo(void)
{
	f575_arm("topo", -1, 0, -1, NULL);
}

/* A: an untagged frame is nobody's VLAN frame */
static void f575_sec_a(void)
{
	struct f571_cfg C;
	unsigned char i12[2] = { 0x86, 0xdd };

	f575_arm("a_ctl", 0, T575_AB, -1, NULL);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, i12);
	f575_arm("a_r12", 0, T575_AB, E75_G6, &C);
}

/* B: the control -- br0.100 with the flag set (F52's group D, same door) */
static void f575_sec_b(void)
{
	struct f571_cfg C;
	unsigned char i12[2] = { 0x86, 0xdd };
	unsigned char t12[2] = { 0x81, 0x00 };
	unsigned char v14[2] = { 0x60, 0x00 };
	unsigned char z16[2] = { 0x00, 0x00 };
	unsigned char p18[2] = { 0x00, 0x1a };
	unsigned char hl[1] = { 0x40 };
	unsigned char z14[2] = { 0x00, 0x00 };

	f575_arm("b_ctl", 1, T575_AB, -1, NULL);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, i12);
	f575_arm("b_r12_i", 1, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, t12);
	f575_arm("b_r12_t", 1, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, v14);
	f575_arm("b_r14", 1, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, z16);
	f575_arm("b_r16", 1, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 18, 2, p18);
	f575_arm("b_r18", 1, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_NETWORK_HEADER, 7, 1, hl);
	f575_arm("b_nh7", 1, T575_AB, E75_G6, &C);
	/* the store boundary: off+len <= mac_len = 14 at this door */
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, t12);
	f575_arm("b_w12", 1, T575_AB, E75_G6, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, z14);
	f575_arm("b_w14", 1, T575_AB, E75_G6, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, z14);
	f575_arm("b_w16", 1, T575_AB, E75_G6, &C);
	/* probes: a value that is neither 8100 nor 86dd, and a store well inside
	 * the MAC header -- both must be visible in NFULA_HWHEADER if the store
	 * reaches the frame at all */
	{
		unsigned char alt[2] = { 0x12, 0x34 };

		f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, alt);
		f575_arm("b_w12x", 1, T575_AB, E75_G6, &C);
		f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 6, 6, A75_N6);
		f575_arm("b_w6", 1, T575_AB, E75_G6, &C);
	}
}

/* E: the question -- br0.101 with VLAN_FLAG_REORDER_HDR cleared */
static void f575_sec_e(void)
{
	struct f571_cfg C;
	unsigned char t12[2] = { 0x81, 0x00 };
	unsigned char i12[2] = { 0x86, 0xdd };
	unsigned char t14[2] = { 0x00, 0x65 };
	unsigned char v16[2] = { 0x60, 0x00 };
	unsigned char z18[2] = { 0x00, 0x00 };
	unsigned char hl[1] = { 0x40 };
	unsigned char z14[2] = { 0x00, 0x00 };
	unsigned char et[2] = { 0x08, 0x06 };

	f575_arm("e_ctl", 2, T575_AB, -1, NULL);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A74_BC);
	f575_arm("e_r0", 2, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, t12);
	f575_arm("e_r12_t", 2, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, i12);
	f575_arm("e_r12_i", 2, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, t14);
	f575_arm("e_r14", 2, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, i12);
	f575_arm("e_r16", 2, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 18, 2, v16);
	f575_arm("e_r18", 2, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 20, 2, z18);
	f575_arm("e_r20", 2, T575_AB, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_NETWORK_HEADER, 7, 1, hl);
	f575_arm("e_nh7", 2, T575_AB, E75_G6, &C);
	/* the same store boundary, now off+len <= mac_len = 18 */
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, et);
	f575_arm("e_w12", 2, T575_AB, E75_G6, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, z14);
	f575_arm("e_w14", 2, T575_AB, E75_G6, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, et);
	f575_arm("e_w16", 2, T575_AB, E75_G6, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 18, 2, z14);
	f575_arm("e_w18", 2, T575_AB, E75_G6, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 0, 6, A75_N6);
	f575_arm("e_w0", 2, T575_AB, E75_G6, &C);
	{
		unsigned char alt[2] = { 0x12, 0x34 };

		f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, alt);
		f575_arm("e_w12x", 2, T575_AB, E75_G6, &C);
		f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 6, 6, A75_N6);
		f575_arm("e_w6", 2, T575_AB, E75_G6, &C);
	}
}

/* M: the same four bytes while they are still metadata (netdev ingress) */
static void f575_sec_m(void)
{
	struct f571_cfg C;
	unsigned char t14[2] = { 0x00, 0x65 };
	unsigned char tnew[2] = { 0x00, 0x66 };
	unsigned char et[2] = { 0x08, 0x06 };
	unsigned char i16[2] = { 0x86, 0xdd };
	unsigned char v4[2] = { 0x08, 0x00 };

	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, t14);
	f575_arm("m_r14", 2, T575_AB, E75_N1, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, i16);
	f575_arm("m_r16", 2, T575_AB, E75_N1, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, t14);
	f575_arm("m_w14_same", 2, T575_AB, E75_N1, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, tnew);
	f575_arm("m_w14_102", 2, T575_AB, E75_N1, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, et);
	f575_arm("m_w12", 2, T575_AB, E75_N1, &C);
	f575_wr(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, v4);
	f575_arm("m_w16", 2, T575_AB, E75_N1, &C);
}

/* Q: two tags, the outer device with the flag cleared */
static void f575_sec_q(void)
{
	struct f571_cfg C;
	unsigned char s12[2] = { 0x88, 0xa8 };
	unsigned char o14[2] = { 0x01, 0x02 };
	unsigned char i16[2] = { 0x86, 0xdd };
	unsigned char v18[2] = { 0x60, 0x00 };
	unsigned char q12[2] = { 0x81, 0x00 };

	f575_arm("q_ctl", 3, T575_ALL3, -1, NULL);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, s12);
	f575_arm("q_r12", 3, T575_ALL3, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 12, 2, q12);
	f575_arm("q_r12_q", 3, T575_ALL3, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, o14);
	f575_arm("q_r14", 3, T575_ALL3, E75_G6, &C);
	{
		unsigned char otci[2] = { 0x00, 0x66 };

		f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 14, 2, otci);
		f575_arm("q_r14b", 3, T575_ALL3, E75_G6, &C);
	}
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 16, 2, i16);
	f575_arm("q_r16", 3, T575_ALL3, E75_G6, &C);
	f575_rdv(&C, NFT_PAYLOAD_LL_HEADER, 18, 2, v18);
	f575_arm("q_r18", 3, T575_ALL3, E75_G6, &C);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "reorder";
	int rc;

	printf("F575 BEGIN|mode=%s\n", mode);
	rc = f575_env();
	if (rc)
		return 3;
	rc = f575_chains();
	printf("F575 CHAINS|rc=%d\n", rc);
	if (rc)
		return 4;
	printf("F575 START\n");
	fflush(stdout);

	f575_sec_topo();
	f575_sec_a();
	f575_sec_b();
	f575_sec_e();
	f575_sec_m();
	f575_sec_q();

	printf("F575 END\n");
	return 0;
}
