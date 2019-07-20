#include "lib/zebra.h"

#include "lib/typesafe.h"
#include "lib/thread.h"
#include "lib/table.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"

#include "l3a.h"

DEFINE_MTYPE_STATIC(L3A, L3A_ROUTE, "L3 access route")
DEFINE_MTYPE_STATIC(L3A, L3A_ROUTE_IFNAME, "L3 access route interface name")

static int l3a_route_lifetime_cmp(const struct l3a_route *a,
				  const struct l3a_route *b)
{
	if (timercmp(&a->lifetime, &b->lifetime, <))
		return -1;
	if (timercmp(&a->lifetime, &b->lifetime, >))
		return 1;
	return 0;
}

DECLARE_HEAP(l3a_route_heap, struct l3a_route, heap_itm, l3a_route_lifetime_cmp)

static struct l3a_route_heap_head l3a_v6_heap;
struct route_table *l3a_v6;

static struct thread_master *l3a_tm;
static struct thread *l3a_thread_expire;

static void l3a_route_kill(struct l3a_route *l3ar, struct route_node *rn)
{
	l3a_zebra_remove(l3ar);
	rn->info = NULL;
	route_unlock_node(rn);
	XFREE(MTYPE_L3A_ROUTE_IFNAME, l3ar->ifname);
	XFREE(MTYPE_L3A_ROUTE, l3ar);
}

static void l3a_route_resched(void);

static int l3a_route_expire(struct thread *t)
{
	struct l3a_route *l3ar;
	struct route_node *rn;

	while ((l3ar = l3a_route_heap_first(&l3a_v6_heap))) {
		if (monotime_until(&l3ar->lifetime, NULL) > 0)
			break;

		assert(l3a_route_heap_pop(&l3a_v6_heap) == l3ar);

		rn = route_node_lookup(l3a_v6, &l3ar->p);
		assert(rn);
		route_unlock_node(rn);

		l3a_route_kill(l3ar, rn);
	}
	l3a_route_resched();
	return 0;
}

static void l3a_route_resched(void)
{
	struct l3a_route *l3ar;
	struct timeval tv;

	THREAD_OFF(l3a_thread_expire);
	l3ar = l3a_route_heap_first(&l3a_v6_heap);
	if (!l3ar)
		return;

	monotime_until(&l3ar->lifetime, &tv);
	thread_add_timer_tv(l3a_tm, l3a_route_expire, NULL, &tv,
			    &l3a_thread_expire);
}

void l3a_route_update(union prefixconstptr pfx, int64_t lifetime,
		      const union g_addr *addr, const char *ifname,
		      uint64_t *tags, size_t n_tags)
{
	struct l3a_route *l3ar;
	struct route_node *rn;

	if (lifetime <= 0) {
		rn = route_node_lookup(l3a_v6, pfx);
		if (!rn)
			return;
		l3ar = rn->info;
		assert(l3ar);
		route_unlock_node(rn);

		l3a_route_heap_del(&l3a_v6_heap, l3ar);
		l3a_route_kill(l3ar, rn);
		return;
	}

	rn = route_node_get(l3a_v6, pfx);
	if (!rn->info) {
		l3ar = XCALLOC(MTYPE_L3A_ROUTE, sizeof(*l3ar));
		prefix_copy(&l3ar->p, pfx.p);
		rn->info = l3ar;
	} else {
		l3ar = rn->info;
		XFREE(MTYPE_L3A_ROUTE_IFNAME, l3ar->ifname);
		l3a_route_heap_del(&l3a_v6_heap, l3ar);
		route_unlock_node(rn);
	}
	assert(rn->lock == 1);

	monotime(&l3ar->lifetime);
	l3ar->lifetime.tv_usec += (lifetime % 1000) * 1000;
	if (l3ar->lifetime.tv_usec >= 1000000) {
		l3ar->lifetime.tv_usec -= 1000000;
		l3ar->lifetime.tv_sec++;
	}
	l3ar->lifetime.tv_sec += lifetime / 1000;

	l3ar->ifname = XSTRDUP(MTYPE_L3A_ROUTE_IFNAME, ifname);
	l3ar->gw = *addr;

	l3a_zebra_update(l3ar);

	l3a_route_heap_add(&l3a_v6_heap, l3ar);
	l3a_route_resched();
}

void l3a_route_init(struct thread_master *tm)
{
	l3a_tm = tm;

	l3a_v6 = route_table_init();
	l3a_route_heap_init(&l3a_v6_heap);
}
