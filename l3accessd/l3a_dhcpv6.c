#include "lib/zebra.h"

#include "lib/typesafe.h"
#include "lib/jhash.h"
#include "lib/printfrr.h"
#include "lib/log.h"
#include "lib/privs.h"
#include "lib/thread.h"
#include "lib/network.h"
#include "lib/table.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"
#include "lib/vty.h"

#include "l3a.h"

#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <linux/filter.h>

#include <gdbm.h>

/* 'ip6 and udp and (port 546 or port 547)' */
static struct sock_filter dhcpv6filter[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 9, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 7, 0x00000011 },
	{ 0x28, 0, 0, 0x00000036 },
	{ 0x15, 4, 0, 0x00000222 },
	{ 0x15, 3, 0, 0x00000223 },
	{ 0x28, 0, 0, 0x00000038 },
	{ 0x15, 1, 0, 0x00000222 },
	{ 0x15, 0, 1, 0x00000223 },
	{ 0x06, 0, 0, 0x00040000 },
	{ 0x06, 0, 0, 0x00000000 },
};

static struct sock_fprog dhcpv6bpf = {
	.len = array_size(dhcpv6filter),
	.filter = dhcpv6filter,
};

extern struct zebra_privs_t l3a_privs;
extern struct thread_master *master;

struct dhcpv6_option {
	uint16_t option_code;
	size_t len;
	uint8_t *data;
};

static bool dhcpv6_parse(struct dhcpv6_option *out, size_t maxout, size_t *n,
			 uint8_t *data, uint8_t *end)
{
	size_t i = 0;

	*n = 0;
	while (data < end && i < maxout) {
		if (end - data < 4)
			return false;

		out[i].option_code = (data[0] << 8) | data[1];
		out[i].len         = (data[2] << 8) | data[3];
		if (end - data < (ptrdiff_t)out[i].len)
			return false;

		data += 4;
		out[i].data = data;
		data += out[i].len;

		i++;
	}
	*n = i;
	return true;
}

static bool pull(uint8_t **p, uint8_t *end, void *dst, size_t dstsize)
{
	if (end - *p < (ptrdiff_t)dstsize)
		return false;
	memcpy(dst, *p, dstsize);
	*p += dstsize;
	return true;
}

#define DHCPV6_MSG_REPLY	7
#define DHCPV6_MSG_RELEASE	8

#define DHCPV6_OPT_CLIENTID	1
#define DHCPV6_OPT_SERVERID	2
#define DHCPV6_OPT_STATUS	13
#define DHCPV6_OPT_IA_PD	25
#define DHCPV6_OPT_IA_PD_PREFIX	26

PREDECL_SORTLIST_UNIQ(dhcpv6_pd_prefixes)
PREDECL_HEAP(dhcpv6_pd_expiry)

struct dhcpv6_pd_binding;

struct dhcpv6_pd_prefix {
	struct dhcpv6_pd_prefixes_item itm;
	struct dhcpv6_pd_expiry_item exp_itm;

	struct dhcpv6_pd_binding *binding;

	struct prefix_ipv6 pd;
	struct timeval preferred, valid;
	bool release;
};

static int dhcpv6_pd_prefix_cmp(const struct dhcpv6_pd_prefix *a,
				const struct dhcpv6_pd_prefix *b)
{
	return prefix_cmp((const struct prefix *)&a->pd,
			  (const struct prefix *)&b->pd);
}

DECLARE_SORTLIST_UNIQ(dhcpv6_pd_prefixes, struct dhcpv6_pd_prefix, itm,
		      dhcpv6_pd_prefix_cmp)

static int dhcpv6_pd_prefix_expiry_cmp(const struct dhcpv6_pd_prefix *a,
				       const struct dhcpv6_pd_prefix *b)
{
	if (timercmp(&a->valid, &b->valid, <))
		return -1;
	if (timercmp(&a->valid, &b->valid, >))
		return 1;
	return 0;
}

DECLARE_HEAP(dhcpv6_pd_expiry, struct dhcpv6_pd_prefix, exp_itm,
	     dhcpv6_pd_prefix_expiry_cmp)

PREDECL_HASH(dhcpv6_pd_binding_hash)

struct dhcpv6_pd_binding {
	struct dhcpv6_pd_binding_hash_item hash_itm;

	uint8_t *cid;
	size_t cid_len;
	uint32_t iaid;

	struct l3a_if *l3a_if;
	struct in6_addr lladdr;
	struct dhcpv6_pd_prefixes_head prefixes;
};

static int dhcpv6_pd_binding_cmp(const struct dhcpv6_pd_binding *a,
				 const struct dhcpv6_pd_binding *b)
{
	int rv;

	if (a->cid_len < b->cid_len)
		return -1;
	if (a->cid_len > b->cid_len)
		return 1;
	if ((rv = memcmp(a->cid, b->cid, a->cid_len)))
		return rv;
	if (a->iaid < b->iaid)
		return -1;
	if (a->iaid > b->iaid)
		return 1;
	return 0;
}

static uint32_t dhcpv6_pd_binding_key(const struct dhcpv6_pd_binding *a)
{
	uint32_t hashval = 0x55aa8811;
	hashval = jhash(a->cid, a->cid_len, hashval);
	hashval = jhash(&a->iaid, sizeof(a->iaid), hashval);
	return hashval;
}

DECLARE_HASH(dhcpv6_pd_binding_hash, struct dhcpv6_pd_binding, hash_itm,
	     dhcpv6_pd_binding_cmp, dhcpv6_pd_binding_key)

static struct dhcpv6_pd_binding_hash_head pd_bindings;
static struct dhcpv6_pd_expiry_head pd_expiry;

#define opt_get(o) ((opts[i].data[o] << 24) | (opts[i].data[o+1] << 16) | (opts[i].data[o+2] << 8) | (opts[i].data[o+3]))

DEFINE_MTYPE_STATIC(L3A, L3A_DHCPV6_BINDING, "DHCPv6 binding")
DEFINE_MTYPE_STATIC(L3A, L3A_DHCPV6_PD_PREFIX, "DHCPv6 PD prefix")

extern struct thread_master *master;
static struct thread *dhcpv6_thread_expire;
static GDBM_FILE db;

struct db_prefix {
	struct in6_addr addr;
	uint8_t prefixlen;
	uint64_t valid, preferred;
};

struct db_binding {
	uint32_t cid_len;
	uint8_t cid[64];
	uint32_t iaid;

	struct in6_addr lladdr;
	char ifname[16];

	struct db_prefix prefixes[0];
};

static void dhcpv6_binding_check_empty(struct dhcpv6_pd_binding *binding);

static void dhcpv6_db_update(struct dhcpv6_pd_binding *binding)
{
	struct db_binding *buf;
	struct dhcpv6_pd_prefix *prefix;
	size_t i, dlen;
	struct timeval tv;
	datum key, val;

	if (!db || binding->cid_len > sizeof(buf->cid))
		return;

	dlen = sizeof(struct db_binding)
		+ dhcpv6_pd_prefixes_count(&binding->prefixes)
			* sizeof(struct db_prefix);
	buf = XCALLOC(MTYPE_TMP, dlen);

	buf->cid_len = binding->cid_len;
	memcpy(buf->cid, binding->cid, binding->cid_len);
	buf->iaid = binding->iaid;
	buf->lladdr = binding->lladdr;
	strcpy(buf->ifname, binding->l3a_if->ifp->name);

	gettimeofday(&tv, NULL);

	i = 0;
	frr_each (dhcpv6_pd_prefixes, &binding->prefixes, prefix) {
		memcpy(&buf->prefixes[i].addr, &prefix->pd.prefix, 16);
		buf->prefixes[i].prefixlen = prefix->pd.prefixlen;
		buf->prefixes[i].valid = tv.tv_sec
			+ monotime_until(&prefix->valid, NULL) / 1000000;
		buf->prefixes[i].preferred = tv.tv_sec
			+ monotime_until(&prefix->preferred, NULL) / 1000000;

		i++;
	}

	key.dptr = (char *)buf;
	key.dsize = offsetof(struct db_binding, lladdr);
	val.dptr = (char *)buf;
	val.dsize = dlen;

	if (!i)
		gdbm_delete(db, key);
	else
		gdbm_store(db, key, val, GDBM_REPLACE);

	XFREE(MTYPE_TMP, buf);
}

void l3a_dhcpv6_db(const char *filename)
{
	struct timeval tv, mono;
	datum key, val;
	char *prev;

	if (db)
		gdbm_close(db);
	db = gdbm_open(filename, 0, GDBM_WRCREAT, 0600, NULL);
	if (!db) {
		zlog_err("failed to open DB %s: %s", filename, gdbm_strerror(gdbm_errno));
		return;
	}

	gettimeofday(&tv, NULL);
	monotime(&mono);

	key = gdbm_firstkey(db);
	while (key.dptr) {
		struct db_binding *dbbind;
		struct dhcpv6_pd_binding *binding, dummy;
		union g_addr gw;
		size_t n_prefixes, i;

		val = gdbm_fetch(db, key);
		if (!val.dptr)
			goto fail;

		dbbind = (struct db_binding *)val.dptr;
		n_prefixes = (val.dsize - sizeof(struct db_binding))
			/ sizeof(struct db_prefix);

		zlog_info("db: IA %.*pHXc.%u with %zu prefixes",
			  (int)dbbind->cid_len, dbbind->cid, dbbind->iaid,
			  n_prefixes);

		dummy.cid = dbbind->cid;
		dummy.cid_len = dbbind->cid_len;
		dummy.iaid = dbbind->iaid;
		binding = dhcpv6_pd_binding_hash_find(&pd_bindings, &dummy);
		if (!binding) {
			binding = XCALLOC(MTYPE_L3A_DHCPV6_BINDING,
					  sizeof(*binding) + dbbind->cid_len);
			binding->cid = (void *)(binding + 1);
			memcpy(binding->cid, dbbind->cid, dbbind->cid_len);
			binding->cid_len = dbbind->cid_len;
			binding->iaid = dbbind->iaid;
			dhcpv6_pd_binding_hash_add(&pd_bindings, binding);
			dhcpv6_pd_prefixes_init(&binding->prefixes);
		}

		binding->l3a_if = l3a_if_get_byname(dbbind->ifname);
		binding->lladdr = dbbind->lladdr;
		gw.ipv6 = dbbind->lladdr;

		for (i = 0; i < n_prefixes; i++) {
			struct db_prefix *dbp = &dbbind->prefixes[i];
			struct dhcpv6_pd_prefix *prefix, pdummy;
			struct prefix_ipv6 p6;
			int64_t remain;
			uint32_t valid, preferred;

			p6.family = AF_INET6;
			p6.prefixlen = dbp->prefixlen;
			memcpy(&p6.prefix, &dbp->addr, 16);
			apply_mask_ipv6(&p6);
			
			remain = dbp->valid - tv.tv_sec;
			if (remain < 0) {
				zlog_info("db: %pFX has expired", &p6);
				continue;
			}

			valid = mono.tv_sec + remain;
			preferred = mono.tv_sec + (dbp->preferred - tv.tv_sec);

			pdummy.pd = p6;
			prefix = dhcpv6_pd_prefixes_find(&binding->prefixes,
							 &pdummy);
			if (prefix) {
				if (prefix->valid.tv_sec >= remain) {
					zlog_info("db: %pFX already known",
						  &p6);
					continue;
				}
				dhcpv6_pd_expiry_del(&pd_expiry, prefix);
			} else {
				prefix = XCALLOC(MTYPE_L3A_DHCPV6_PD_PREFIX,
						 sizeof(*prefix));
				prefix->pd = p6;
				dhcpv6_pd_prefixes_add(&binding->prefixes, prefix);
			}
			prefix->valid.tv_sec = valid;
			prefix->preferred.tv_sec = preferred;
			prefix->binding = binding;

			dhcpv6_pd_expiry_add(&pd_expiry, prefix);

			zlog_debug("db: %pFX valid %Lu", &p6, remain);

			l3a_route_update(&p6, valid * 1000, &gw,
					 binding->l3a_if->ifp->name, NULL, 0);

		}

		dhcpv6_binding_check_empty(binding);

		free(val.dptr);

fail:
		prev = key.dptr;
		key = gdbm_nextkey(db, key);
		free(prev);
	}
}

static void dhcpv6_binding_check_empty(struct dhcpv6_pd_binding *binding)
{
	if (dhcpv6_pd_prefixes_first(&binding->prefixes))
		return;
	zlog_debug("binding is empty, releasing");
	dhcpv6_db_update(binding);
	dhcpv6_pd_prefixes_fini(&binding->prefixes);
	dhcpv6_pd_binding_hash_del(&pd_bindings, binding);
	XFREE(MTYPE_L3A_DHCPV6_BINDING, binding);
}

static void dhcpv6_resched(void);

static int dhcpv6_expire(struct thread *t)
{
	struct dhcpv6_pd_prefix *prefix;
	struct dhcpv6_pd_binding *binding;

	while ((prefix = dhcpv6_pd_expiry_first(&pd_expiry))) {
		if (monotime_until(&prefix->valid, NULL) > 0)
			break;

		assert(dhcpv6_pd_expiry_pop(&pd_expiry) == prefix);
		binding = prefix->binding;

		zlog_debug("%.*pHX.%u prefix %pFX expired",
			   (int)binding->cid_len, binding->cid, binding->iaid,
			   &prefix->pd);

		/* l3a_route_update(&prefix->pd, 0, NULL, NULL, NULL, 0); */
		dhcpv6_pd_prefixes_del(&binding->prefixes, prefix);
		XFREE(MTYPE_L3A_DHCPV6_PD_PREFIX, prefix);

		dhcpv6_binding_check_empty(binding);
	}
	dhcpv6_resched();
	return 0;
}

static void dhcpv6_resched(void)
{
	struct dhcpv6_pd_prefix *prefix;
	struct timeval tv;

	THREAD_OFF(dhcpv6_thread_expire);
	prefix = dhcpv6_pd_expiry_first(&pd_expiry);
	if (!prefix)
		return;

	monotime_until(&prefix->valid, &tv);
	thread_add_timer_tv(master, dhcpv6_expire, NULL, &tv,
			    &dhcpv6_thread_expire);
}


static void dhcpv6_reply_iapd(struct dhcpv6_pd_binding *binding,
			      bool release,
			      struct dhcpv6_option *opts, size_t nopts)
{
	struct dhcpv6_option *status = NULL;
	struct dhcpv6_pd_prefix *prefix, dummy;
	union g_addr gw;
	uint16_t status_code;

	gw.ipv6 = binding->lladdr;

	if (!release) {
		for (size_t i = 0; i < nopts; i++) {
			if (opts[i].option_code != DHCPV6_OPT_STATUS)
				continue;
			if (status) {
				zlog_warn("IA_PD with duplicate STATUS option");
				return;
			}
			status = &opts[i];
		}

		if (!status || status->len < 2) {
			zlog_warn("IA_PD REPLY without STATUS option");
			return;
		}
		status_code = (status->data[0] << 8) | status->data[1];

		/* XXX ??? */
		if (status_code != 0)
			release = true;
	}

	frr_each (dhcpv6_pd_prefixes, &binding->prefixes, prefix)
		prefix->release = release;

	for (size_t i = 0; i < nopts; i++) {
		uint32_t preferred, valid;
		struct prefix_ipv6 p6;

		if (opts[i].option_code != DHCPV6_OPT_IA_PD_PREFIX)
			continue;
		if (opts[i].len < 25) {
			zlog_warn("malformed IA_PD prefix (%5zu)", opts[i].len);
			continue;
		}

		preferred = opt_get(0);
		valid = opt_get(4);

		p6.family = AF_INET6;
		p6.prefixlen = opts[i].data[8];
		memcpy(&p6.prefix, opts[i].data + 9, 16);
		apply_mask_ipv6(&p6);

		dummy.pd = p6;
		prefix = dhcpv6_pd_prefixes_find(&binding->prefixes, &dummy);
		if (release) {
			if (prefix)
				prefix->release = true;
			continue;
		}
		if (!prefix) {
			prefix = XCALLOC(MTYPE_L3A_DHCPV6_PD_PREFIX,
					 sizeof(*prefix));
			prefix->pd = p6;
			dhcpv6_pd_prefixes_add(&binding->prefixes, prefix);
		} else
			dhcpv6_pd_expiry_del(&pd_expiry, prefix);

		prefix->binding = binding;
		prefix->release = false;

		monotime(&prefix->valid);
		prefix->valid.tv_sec += valid;
		monotime(&prefix->preferred);
		prefix->preferred.tv_sec += preferred;

		dhcpv6_pd_expiry_add(&pd_expiry, prefix);

		zlog_debug("IAID %u prefix %pFX valid %u", binding->iaid, &p6, valid);

		l3a_route_update(&p6, valid * 1000, &gw,
				 binding->l3a_if->ifp->name, NULL, 0);
	}

	frr_each_safe (dhcpv6_pd_prefixes, &binding->prefixes, prefix) {
		if (!prefix->release)
			continue;

		zlog_debug("IAID %u prefix %pFX released", binding->iaid, &prefix->pd);

		l3a_route_update(&prefix->pd, 0, NULL, NULL, NULL, 0);
		dhcpv6_pd_expiry_del(&pd_expiry, prefix);
		dhcpv6_pd_prefixes_del(&binding->prefixes, prefix);
		XFREE(MTYPE_L3A_DHCPV6_PD_PREFIX, prefix);
	}

	dhcpv6_db_update(binding);
}

static void dhcpv6_process(struct l3a_if *l3a_if, struct ip6_hdr *ip6h,
			   uint8_t msg_type, uint32_t txn,
			   struct dhcpv6_option *cid,
			   struct dhcpv6_option *sid,
			   struct dhcpv6_option *opts, size_t nopts)
{
	bool release;

	switch (msg_type) {
	case DHCPV6_MSG_REPLY:
		release = false;
		break;
	case DHCPV6_MSG_RELEASE:
		release = true;
		break;
	default:
		return;
	}

	if (!cid || !sid) {
		zlog_warn("DHCPv6: missing Client-ID or Server-ID");
		return;
	}

	for (size_t i = 0; i < nopts; i++) {
		struct dhcpv6_pd_binding *binding, dummy;
		uint32_t iaid;
		struct dhcpv6_option subopts[512];
		size_t nsubopts;

		if (opts[i].option_code != DHCPV6_OPT_IA_PD)
			continue;
		if (opts[i].len < 12) {
			zlog_warn("malformed IA_PD (%5zu)", opts[i].len);
			continue;
		}

		iaid = opt_get(0);
#if 0
		t1 = opt_get(4);
		t2 = opt_get(8);
#endif

		if (!dhcpv6_parse(subopts, array_size(subopts), &nsubopts,
				  opts[i].data + 12,
				  opts[i].data + opts[i].len)) {
			zlog_warn("DHCPv6 malformed IA_PD");
			continue;
		}

		zlog_debug("binding update IAID %u", iaid);

		dummy.cid = cid->data;
		dummy.cid_len = cid->len;
		dummy.iaid = iaid;
		binding = dhcpv6_pd_binding_hash_find(&pd_bindings, &dummy);
		if (!binding && release) {
			zlog_warn("RELEASE for unknown binding");
			continue;
		} else if (!binding) {
			binding = XCALLOC(MTYPE_L3A_DHCPV6_BINDING,
					  sizeof(*binding) + cid->len);
			binding->cid = (void *)(binding + 1);
			memcpy(binding->cid, cid->data, cid->len);
			binding->cid_len = cid->len;
			binding->iaid = iaid;
			dhcpv6_pd_binding_hash_add(&pd_bindings, binding);
			dhcpv6_pd_prefixes_init(&binding->prefixes);
		}

		binding->l3a_if = l3a_if;
		binding->lladdr = ip6h->ip6_dst;

		dhcpv6_reply_iapd(binding, release, subopts, nsubopts);

		dhcpv6_binding_check_empty(binding);
	}

	dhcpv6_resched();
}

printfrr_ext_autoreg_p("HX", printfrr_hx)
static ssize_t printfrr_hx(char *buf, size_t bsz, const char *fmt,
			   int prec, const void *ptr)
{
	const uint8_t *p = ptr;
	char sep = ' ';
	int rv = 2;
	struct fbuf fb = { .buf = buf, .pos = buf, .len = bsz - 1 };

	if (fmt[2] == 'c') {
		sep = ':';
		rv = 3;
	}

	for (int i = 0; i < prec; i++)
		bprintfrr(&fb, "%02x%c", *p++, sep);

	if (fb.pos > fb.buf && fb.pos[-1] == sep)
		fb.pos[-1] = '\0';
	fb.pos[0] = '\0';
	return rv;
}


void l3a_dhcpv6_show(struct vty *vty)
{
	struct dhcpv6_pd_binding *binding;
	struct dhcpv6_pd_prefix *prefix;

	vty_out(vty, "DHCPv6 PD binding table\n");
	vty_out(vty, "=======================\n");

	frr_each (dhcpv6_pd_binding_hash, &pd_bindings, binding) {
		vty_out(vty, "%-20s %-40pI6 %.*pHXc.%u\n",
			binding->l3a_if->ifp->name, &binding->lladdr,
			(int)binding->cid_len, binding->cid, binding->iaid);
		frr_each (dhcpv6_pd_prefixes, &binding->prefixes, prefix) {
			vty_out(vty, "%25s %pFX (preferred %f, valid %f)\n",
				"", &prefix->pd,
				0.000001 * monotime_until(&prefix->preferred, NULL),
				0.000001 * monotime_until(&prefix->valid, NULL));
		}
	}
}

#if 0
	for (size_t i = 0; i < nopt; i++) {
		uint32_t iaid, t1, t2;

		uint32_t preferred, valid;
		struct prefix_ipv6 p6;
		union g_addr gw;

		size_t n;
		hexbuf[0] = '\0';
		for (n = 0; (n < 32) && (n < opts[i].len); n++) {
			sprintf(&hexbuf[n * 3], " %02x", opts[i].data[n]);
		}

#define sub_get(o) ((subopts[j].data[o] << 24) | (subopts[j].data[o+1] << 16) | (subopts[j].data[o+2] << 8) | (subopts[j].data[o+3]))
		switch (opts[i].option_code) {
		case 1:
			/* CLIENTID */
			zlog_info("-> CLIENTID (%5zu)%s", opts[i].len, hexbuf);
			break;
		case 2:
			/* SERVERID */
			zlog_info("-> SERVERID (%5zu)%s", opts[i].len, hexbuf);
			break;
		case 3:
			/* IA_NA */
			zlog_info("-> IA_NA    (%5zu)%s", opts[i].len, hexbuf);
			break;
		case 7:
			/* PREFERENCE */
			zlog_info("-> PREFEREN (%5zu)%s", opts[i].len, hexbuf);
			break;
		case 13:
			/* STATUS */
			n = opts[i].len - 2;
			if (n > sizeof(hexbuf) - 1)
				n = sizeof(hexbuf) - 1;
			memcpy(hexbuf, opts[i].data + 2, n);
			hexbuf[n] = '\0';

			zlog_info("-> STATUS   (%5zu) %u \"%s\"", opts[i].len,
				  (opts[i].data[0] << 8) | opts[i].data[1], hexbuf);
			break;
		case 25:
			/* IA_PD */
			if (opts[i].len < 12) {
				zlog_warn("malformed IA_PD (%5zu)%s", opts[i].len, hexbuf);
				break;
			}
			iaid = opt_get(0);
			t1 = opt_get(4);
			t2 = opt_get(8);

			zlog_info("-> IA_PD    (%5zu) iaid=%08x, t1=%u, t2=%u",
				  opts[i].len, iaid, t1, t2);
	
			nsubopt = dhcpv6_parse(subopts, array_size(subopts),
					       opts[i].data + 12, opts[i].data + opts[i].len);

			for (size_t j = 0; j < nsubopt; j++) {
				hexbuf[0] = '\0';
				for (n = 0; (n < 64) && (n < subopts[j].len); n++) {
					sprintf(&hexbuf[n * 3], " %02x", subopts[j].data[n]);
				}
				switch (subopts[j].option_code) {
				case 26:
					preferred = sub_get(0);
					valid = sub_get(4);

					p6.family = AF_INET6;
					p6.prefixlen = subopts[j].data[8];
					memcpy(&p6.prefix, subopts[j].data + 9, 16);
					apply_mask_ipv6(&p6);

					hexbuf[0] = '\0';
					for (n = 0; (n < 32) && (n < subopts[j].len - 25); n++) {
						sprintf(&hexbuf[n * 3], " %02x", subopts[j].data[25 + n]);
					}
					zlog_info("---> IAPREFIX (%5zu) preferred=%u valid=%u %pFX options%s",
						  subopts[j].len, preferred, valid, &p6, hexbuf);
					break;
				case 13:
					/* STATUS */
					n = subopts[j].len - 2;
					if (n > sizeof(hexbuf) - 1)
						n = sizeof(hexbuf) - 1;
					memcpy(hexbuf, subopts[j].data + 2, n);
					hexbuf[n] = '\0';

					zlog_info("---> STATUS   (%5zu) %u \"%s\"", subopts[j].len,
						  (subopts[j].data[0] << 8) | subopts[j].data[1], hexbuf);
					break;
				default:
					zlog_info("---> SUBOPT-%u (%5zu)%s",
						  subopts[j].option_code, subopts[j].len, hexbuf);
				}
			}

			gw.ipv6 = ip6h.ip6_dst;
			l3a_route_update(&p6, valid * 1000, &gw, l3a_if->ifp->name, NULL, 0);
			break;
		default:
			zlog_info("-> OPTION-%u (%5zu)%s",
			  opts[i].option_code, opts[i].len, hexbuf);
		}
	}
#endif

static int l3a_dhcpv6_read(struct thread *t)
{
	struct l3a_if *l3a_if = THREAD_ARG(t);
	struct sockaddr_ll sll;
	socklen_t slen = sizeof(sll);
	uint8_t buf[65536], *bp, *end;
	ssize_t nread;

	thread_add_read(master, l3a_dhcpv6_read, l3a_if, l3a_if->snoop_fd,
			&l3a_if->snoop_thread);

	nread = recvfrom(l3a_if->snoop_fd, buf, sizeof(buf), 0,
			 (struct sockaddr *)&sll, &slen);
	if (nread <= 0) {
		zlog_warn("read from %s failed (%zd): %m",
			  l3a_if->ifp->name, nread);
		return 0;
	}
	end = buf + nread;
	bp = buf;

	if (nread < 14 || bp[12] != 0x86 || bp[13] != 0xdd) {
		zlog_info("DHCPv6 packet (%zd) on %s is not IPv6?",
			  nread, l3a_if->ifp->name);
		return 0;
	}
	bp += 14;

	struct ip6_hdr ip6h;
	if (!pull(&bp, end, &ip6h, sizeof(ip6h)))
		goto out_truncated;

	if (ip6h.ip6_nxt != IPPROTO_UDP) {
		zlog_info("DHCPv6 packet (%zd) on %s is not UDP",
			  nread, l3a_if->ifp->name);
		return 0;
	}

	struct udphdr uh;
	if (!pull(&bp, end, &uh, sizeof(uh)))
		goto out_truncated;

	uint8_t msg_type = bp[0];
	uint32_t txn = (bp[1] << 16) | (bp[2] << 8) | bp[3];
	struct dhcpv6_option opts[512];
	size_t nopts;

	bp += 4;

	if (!dhcpv6_parse(opts, array_size(opts), &nopts, bp, end)) {
		zlog_warn("DHCPv6 malformed %s [%pI6]:%u -> [%pI6]:%u type %02x txn %06x",
			  l3a_if->ifp->name,
			  &ip6h.ip6_src, ntohs(uh.uh_sport),
			  &ip6h.ip6_dst, ntohs(uh.uh_dport),
			  msg_type, txn);
		return 0;
	}

	zlog_debug("DHCPv6 %s [%pI6]:%u -> [%pI6]:%u type %02x txn %06x",
		   l3a_if->ifp->name,
		   &ip6h.ip6_src, ntohs(uh.uh_sport),
		   &ip6h.ip6_dst, ntohs(uh.uh_dport),
		   msg_type, txn);

	struct dhcpv6_option *cid = NULL, *sid = NULL;

	for (size_t i = 0; i < nopts; i++) {
		switch (opts[i].option_code) {
		case DHCPV6_OPT_CLIENTID:
			if (cid) {
				zlog_warn("DHCPv6: duplicate Client-ID");
				return 0;
			}
			cid = &opts[i];
			break;
		case DHCPV6_OPT_SERVERID:
			if (sid) {
				zlog_warn("DHCPv6: duplicate Server-ID");
				return 0;
			}
			sid = &opts[i];
			break;
		}
	}

	dhcpv6_process(l3a_if, &ip6h, msg_type, txn, cid, sid, opts, nopts);
	return 0;

out_truncated:
	zlog_warn("DHCPv6 packet (%zd bytes) on %s is truncated",
		  nread, l3a_if->ifp->name);
	return 0;
}

void l3a_dhcpv6_snoop(struct l3a_if *l3a_if)
{
	int fd;

	if (l3a_if->ifp->ifindex == IFINDEX_INTERNAL) {
		zlog_warn("cannot snoop %s - does not exist", l3a_if->ifp->name);
		return;
	}
	if (l3a_if->snoop_fd != -1) {
		zlog_warn("already snooping %s", l3a_if->ifp->name);
		return;
	}

	frr_elevate_privs (&l3a_privs) {
		struct sockaddr_ll sll;
		struct packet_mreq mr;

		fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
		if (fd < 0) {
			zlog_warn("socket(PF_PACKET) failed: %m");
			return;
		}

		if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
			       &dhcpv6bpf, sizeof(dhcpv6bpf))) {
			zlog_warn("SO_ATTACH_FILTER failed: %m");
			close(fd);
			return;
		}

		memset(&sll, 0, sizeof(sll));
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL);
		sll.sll_ifindex = l3a_if->ifp->ifindex;

		if (bind(fd, (struct sockaddr *)(&sll), sizeof(sll))) {
			zlog_warn("bind(PF_PACKET) failed: %m");
			close(fd);
			return;
		}

		memset(&mr, 0, sizeof(mr));
		mr.mr_ifindex = l3a_if->ifp->ifindex;
		mr.mr_type = PACKET_MR_PROMISC;

		if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
			       &mr, sizeof(mr))) {
			zlog_warn("PACKET_ADD_MEMBERSHIP failed: %m");
			close(fd);
			return;
		}
	}
	set_nonblocking(fd);

	l3a_if->snoop_fd = fd;

	thread_add_read(master, l3a_dhcpv6_read, l3a_if, fd,
			&l3a_if->snoop_thread);
	zlog_info("iface %s snoopfd %d", l3a_if->ifp->name, fd);
}
