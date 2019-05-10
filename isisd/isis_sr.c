/*
 * This is an implementation of Segment Routing for IS-IS
 * as per draft draft-ietf-isis-segment-routing-extensions-25
 *
 * Copyright (C) 2019 Orange Labs http://www.orange.com
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Contributor: Renato Westphal <renato@opensourcerouting.org> for NetDEF
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "zclient.h"
#include "lib/lib_errors.h"

#include "isisd/isisd.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_route.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_errors.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_SR_INFO, "ISIS segment routing information")

static void isis_sr_prefix_uninstall(struct sr_prefix *srp);
static void isis_sr_prefix_reinstall(struct sr_prefix *srp,
				     bool input_label_change);

//-----------------------------------------------------------------------------

static inline int sr_prefix_sid_compare(const struct sr_prefix *a,
					const struct sr_prefix *b)
{
	return prefix_cmp(&a->prefix, &b->prefix);
}
DECLARE_RBTREE_UNIQ(tree_sr_node_prefix, struct sr_prefix, node_entry,
		    sr_prefix_sid_compare)
DECLARE_RBTREE_UNIQ(tree_sr_area_prefix, struct sr_prefix, area_entry,
		    sr_prefix_sid_compare)

static inline int sr_prefix_sid_cfg_compare(const struct sr_prefix_cfg *a,
					    const struct sr_prefix_cfg *b)
{
	return prefix_cmp(&a->prefix, &b->prefix);
}
DECLARE_RBTREE_UNIQ(tree_sr_prefix_cfg, struct sr_prefix_cfg, entry,
		    sr_prefix_sid_cfg_compare)

static inline int sr_node_compare(const struct sr_node *a,
				  const struct sr_node *b)
{
	return memcmp(a->sysid, b->sysid, ISIS_SYS_ID_LEN);
}
DECLARE_RBTREE_UNIQ(tree_sr_node, struct sr_node, entry, sr_node_compare)

//-----------------------------------------------------------------------------

static bool isis_sr_prefix_is_node_sid(const struct interface *ifp,
				       const struct prefix *prefix)
{
	if (if_is_loopback(ifp) && is_host_route(prefix))
		return true;
	return false;
}

int isis_sr_cfg_srgb_update(struct isis_area *area, uint32_t lower_bound,
			    uint32_t upper_bound)
{
	struct isis_sr_db *srdb = &area->srdb;

	if (srdb->config.enabled)
		isis_zebra_release_label_range(srdb->config.srgb_lower_bound,
					       srdb->config.srgb_upper_bound);

	srdb->config.srgb_lower_bound = lower_bound;
	srdb->config.srgb_upper_bound = upper_bound;

	if (srdb->config.enabled) {
		struct sr_prefix *srp;

		if (isis_zebra_request_label_range(
			    srdb->config.srgb_lower_bound,
			    srdb->config.srgb_upper_bound
				    - srdb->config.srgb_lower_bound + 1))
			return -1;

		/* Reinstall local Prefix-SIDs to update their input labels. */
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			frr_each (tree_sr_area_prefix,
				  &area->srdb.prefix_sids[level - 1], srp) {
				isis_sr_prefix_reinstall(srp, true);
			}
		}

		lsp_regenerate_schedule(area, area->is_type, 0);
	}

	return 0;
}

void isis_sr_cfg_msd_update(struct isis_area *area)
{
	lsp_regenerate_schedule(area, area->is_type, 0);
}

struct sr_prefix_cfg *isis_sr_cfg_prefix_add(struct isis_area *area,
					     const struct prefix *prefix)
{
	struct sr_prefix_cfg *pcfg;
	struct interface *ifp;

	pcfg = XCALLOC(MTYPE_ISIS_SR_INFO, sizeof(*pcfg));
	pcfg->prefix = *prefix;
	pcfg->area = area;

	/* Pull defaults from the YANG module. */
	pcfg->sid_type = yang_get_default_enum(
		"%s/prefix-sid-map/prefix-sid/sid-value-type", ISIS_SR);
	pcfg->last_hop_behavior = yang_get_default_enum(
		"%s/prefix-sid-map/prefix-sid/last-hop-behavior", ISIS_SR);

	/* Set the N-flag when appropriate. */
	ifp = if_lookup_prefix(prefix, VRF_DEFAULT);
	if (ifp && isis_sr_prefix_is_node_sid(ifp, prefix))
		SET_FLAG(pcfg->flags, ISIS_PREFIX_SID_NODE);

	/* Save prefix-sid configuration. */
	tree_sr_prefix_cfg_add(&area->srdb.config.prefix_sids, pcfg);

	return pcfg;
}

void isis_sr_cfg_prefix_del(struct sr_prefix_cfg *pcfg)
{
	struct isis_area *area;

	area = pcfg->area;
	tree_sr_prefix_cfg_del(&area->srdb.config.prefix_sids, pcfg);
	XFREE(MTYPE_ISIS_SR_INFO, pcfg);
}

struct sr_prefix_cfg *isis_sr_cfg_prefix_find(struct isis_area *area,
					      union prefixconstptr prefix)
{
	struct sr_prefix_cfg pcfg = {};

	prefix_copy(&pcfg.prefix, prefix.p);
	return tree_sr_prefix_cfg_find(&area->srdb.config.prefix_sids, &pcfg);
}

struct sr_prefix_cfg *isis_sr_cfg_sid_find(struct isis_area *area, uint32_t sid)
{
	struct sr_prefix_cfg *pcfg;

	frr_each (tree_sr_prefix_cfg, &area->srdb.config.prefix_sids, pcfg) {
		if (pcfg->sid == sid)
			return pcfg;
	}

	return NULL;
}

void isis_sr_prefix_cfg2subtlv(const struct sr_prefix_cfg *pcfg, bool external,
			       struct isis_prefix_sid *psid)
{
	struct isis_sr_db *srdb = &pcfg->area->srdb;

	/* Set SID algorithm. */
	psid->algorithm = SR_ALGORITHM_SPF;

	/* Set SID flags. */
	psid->flags = 0;
	switch (pcfg->last_hop_behavior) {
	case SR_LAST_HOP_BEHAVIOR_EXP_NULL:
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_NO_PHP);
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_EXPLICIT_NULL);
		break;
	case SR_LAST_HOP_BEHAVIOR_NO_PHP:
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_NO_PHP);
		UNSET_FLAG(psid->flags, ISIS_PREFIX_SID_EXPLICIT_NULL);
		break;
	case SR_LAST_HOP_BEHAVIOR_PHP:
		UNSET_FLAG(psid->flags, ISIS_PREFIX_SID_NO_PHP);
		UNSET_FLAG(psid->flags, ISIS_PREFIX_SID_EXPLICIT_NULL);
		break;
	}
	if (external)
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_READVERTISED);

	/* Set SID value. */
	switch (pcfg->sid_type) {
	case SR_SID_VALUE_TYPE_INDEX:
		psid->value = pcfg->sid;
		break;
	case SR_SID_VALUE_TYPE_ABSOLUTE:
		/* Map absolute label to SID index. */
		psid->value = pcfg->sid - srdb->config.srgb_lower_bound;
		break;
	}
}

//-----------------------------------------------------------------------------

static struct sr_prefix *isis_sr_prefix_add(struct isis_area *area,
					    struct sr_node *srn,
					    union prefixconstptr prefix,
					    bool local,
					    const struct isis_prefix_sid *psid)
{
	struct sr_prefix *srp;

	srp = XCALLOC(MTYPE_ISIS_SR_INFO, sizeof(*srp));
	prefix_copy(&srp->prefix, prefix.p);
	srp->sid = *psid;
	srp->local = local;
	srp->local_label = MPLS_INVALID_LABEL;
	srp->srn = srn;
	tree_sr_node_prefix_add(&srn->prefix_sids, srp);
	/* TODO: this might fail if we have Anycast SIDs in the IS-IS area. */
	tree_sr_area_prefix_add(&area->srdb.prefix_sids[srn->level - 1], srp);

	return srp;
}

static void isis_sr_prefix_del(struct isis_area *area, struct sr_node *srn,
			       struct sr_prefix *srp)
{
	isis_sr_prefix_uninstall(srp);
	tree_sr_node_prefix_del(&srn->prefix_sids, srp);
	tree_sr_area_prefix_del(&area->srdb.prefix_sids[srn->level - 1], srp);
	XFREE(MTYPE_ISIS_SR_INFO, srp);
}

static struct sr_prefix *isis_sr_prefix_find_area(struct isis_area *area,
						  int level,
						  union prefixconstptr prefix)
{
	struct sr_prefix srp = {};

	prefix_copy(&srp.prefix, prefix.p);
	return tree_sr_area_prefix_find(&area->srdb.prefix_sids[level - 1],
					&srp);
}

static struct sr_prefix *isis_sr_prefix_find_node(struct sr_node *srn,
						  union prefixconstptr prefix)
{
	struct sr_prefix srp = {};

	prefix_copy(&srp.prefix, prefix.p);
	return tree_sr_node_prefix_find(&srn->prefix_sids, &srp);
}

struct sr_prefix *isis_sr_prefix_sid_find_area(struct isis_area *area,
					       int level, uint32_t sid)
{
	struct sr_prefix *srp;

	frr_each (tree_sr_area_prefix, &area->srdb.prefix_sids[level - 1],
		  srp) {
		if (srp->sid.value == sid)
			return srp;
	}

	return NULL;
}

static struct sr_node *isis_sr_node_add(struct isis_area *area, int level,
					const uint8_t *sysid,
					const struct isis_srgb *srgb)
{
	struct sr_node *srn;

	srn = XCALLOC(MTYPE_ISIS_SR_INFO, sizeof(*srn));
	srn->level = level;
	memcpy(srn->sysid, sysid, ISIS_SYS_ID_LEN);
	srn->srgb = *srgb;
	srn->area = area;
	tree_sr_node_prefix_init(&srn->prefix_sids);
	tree_sr_node_add(&area->srdb.sr_nodes[level - 1], srn);

	return srn;
}

static void isis_sr_node_del(struct isis_area *area, int level,
			     struct sr_node *srn)
{
	/* Remove and uninstall Prefix-SIDs. */
	while (tree_sr_node_prefix_count(&srn->prefix_sids) > 0) {
		struct sr_prefix *srp;

		srp = tree_sr_node_prefix_first(&srn->prefix_sids);
		isis_sr_prefix_del(area, srn, srp);
	}

	tree_sr_node_del(&area->srdb.sr_nodes[level - 1], srn);
	XFREE(MTYPE_ISIS_SR_INFO, srn);
}

struct sr_node *isis_sr_node_find(struct isis_area *area, int level,
				  const uint8_t *sysid)
{
	struct sr_node srn = {};

	memcpy(srn.sysid, sysid, ISIS_SYS_ID_LEN);
	return tree_sr_node_find(&area->srdb.sr_nodes[level - 1], &srn);
}

static void isis_sr_adj_srgb_update(struct sr_node *srn, int level)
{
	struct isis_area *area = srn->area;
	struct sr_prefix *srp;

	frr_each (tree_sr_area_prefix, &area->srdb.prefix_sids[level - 1],
		  srp) {
		struct listnode *node;
		struct isis_nexthop *nh;

		if (srp->rinfo == NULL)
			continue;

		for (ALL_LIST_ELEMENTS_RO(srp->rinfo->nexthops, node, nh)) {
			if (memcmp(nh->adj->sysid, srn->sysid, ISIS_SYS_ID_LEN)
			    != 0)
				continue;

			/*
			 * Reinstall all Prefix-SID nexthops using route replace
			 * semantics.
			 */
			isis_sr_prefix_reinstall(srp, false);
			break;
		}
	}
}

//-----------------------------------------------------------------------------

static mpls_label_t isis_sr_prefix_in_label(const struct sr_prefix *srp)
{
	const struct sr_node *srn = srp->srn;
	struct isis_area *area = srn->area;

	/* Index SID value. */
	if (srp->sid.value > (area->srdb.config.srgb_upper_bound
			      - area->srdb.config.srgb_lower_bound + 1))
		return MPLS_INVALID_LABEL;

	return (area->srdb.config.srgb_lower_bound + srp->sid.value);
}

static mpls_label_t isis_sr_prefix_out_label(const struct sr_prefix *srp,
					     const struct sr_node *srn_nexthop,
					     const struct isis_adjacency *adj)
{
	const struct sr_node *srn = srp->srn;

	/* Is the adjacency the last hop? */
	if (memcmp(adj->sysid, srn->sysid, ISIS_SYS_ID_LEN) == 0) {
		if (!CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP))
			return MPLS_LABEL_IMPLICIT_NULL;

		if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_EXPLICIT_NULL)) {
			if (srp->prefix.family == AF_INET)
				return MPLS_LABEL_IPV4_EXPLICIT_NULL;
			else
				return MPLS_LABEL_IPV6_EXPLICIT_NULL;
		}
		/* Fallthrough */
	}

	/* Index SID value. */
	if (srp->sid.value > srn_nexthop->srgb.range_size)
		return MPLS_INVALID_LABEL;

	return (srn_nexthop->srgb.lower_bound + srp->sid.value);
}

struct isis_route_info *isis_sr_prefix_lookup_route(struct isis_area *area,
						    int tree_id,
						    struct sr_prefix *srp)
{
	struct route_node *rn;
	int level = srp->srn->level;

	rn = route_node_lookup(area->spftree[tree_id][level - 1]->route_table,
			       &srp->prefix);
	if (rn) {
		route_unlock_node(rn);
		if (rn->info)
			return rn->info;
	}

	return NULL;
}

static int isis_sr_prefix_install_local(struct sr_prefix *srp)
{
	const struct sr_node *srn = srp->srn;
	struct isis_area *area = srn->area;
	mpls_label_t local_label;
	struct zapi_labels zl;
	struct zapi_nexthop_label *znh;
	struct interface *ifp;

	/*
	 * No need to install LSP to local Prefix-SID unless the
	 * no-PHP option is configured.
	 */
	if (!CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP)
	    || CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_EXPLICIT_NULL))
		return 0;

	if (IS_DEBUG_ISIS(DEBUG_SR)) {
		zlog_debug(
			"ISIS-SR (%s) installing Prefix-SID %pFX index %u (%s)",
			area->area_tag, &srp->prefix, srp->sid.value,
			circuit_t2string(srn->level));
		zlog_debug("  nexthop self");
	}

	/* Calculate local label. */
	local_label = isis_sr_prefix_in_label(srp);
	if (local_label == MPLS_INVALID_LABEL) {
		flog_warn(EC_ISIS_SID_OVERFLOW,
			  "%s: SID index %u falls outside local SRGB range",
			  __func__, srp->sid.value);
		return -1;
	}

	ifp = if_lookup_by_name("lo", VRF_DEFAULT);
	if (!ifp) {
		zlog_warn(
			"%s: couldn't install Prefix-SID %pFX: loopback interface not found",
			__func__, &srp->prefix);
		return -1;
	}

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = local_label;
	SET_FLAG(zl.message, ZAPI_LABELS_FTN);
	zl.route.prefix = srp->prefix;
	zl.route.type = ZEBRA_ROUTE_ISIS;
	zl.route.instance = 0;
	zl.nexthop_num = 1;
	znh = &zl.nexthops[0];
	znh->type = NEXTHOP_TYPE_IFINDEX;
	znh->ifindex = ifp->ifindex;
	znh->label = MPLS_LABEL_IMPLICIT_NULL;

	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_REPLACE, &zl);
	srp->local_label = local_label;

	return 0;
}

static int isis_sr_prefix_install_remote(struct sr_prefix *srp)
{
	const struct sr_node *srn = srp->srn;
	struct isis_area *area = srn->area;
	enum spf_tree_id tree_id;
	struct listnode *node;
	struct isis_nexthop *nexthop;
	mpls_label_t local_label;
	enum nexthop_types_t nh_type;
	struct zapi_labels zl;
	struct zapi_nexthop_label *znh;

	switch (srp->prefix.family) {
	case AF_INET:
		tree_id = SPFTREE_IPV4;
		nh_type = NEXTHOP_TYPE_IPV4_IFINDEX;
		break;
	case AF_INET6:
		tree_id = SPFTREE_IPV6;
		nh_type = NEXTHOP_TYPE_IPV6_IFINDEX;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown prefix family",
			 __func__);
		exit(1);
	}

	/* Lookup associated IS-IS route. */
	srp->rinfo = isis_sr_prefix_lookup_route(area, tree_id, srp);
	if (!srp->rinfo)
		/* SPF hasn't converged for this route yet. */
		return -1;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug(
			"ISIS-SR (%s) installing Prefix-SID %pFX index %u (%s)",
			area->area_tag, &srp->prefix, srp->sid.value,
			circuit_t2string(srn->level));

	/* Calculate local label. */
	local_label = isis_sr_prefix_in_label(srp);
	if (local_label == MPLS_INVALID_LABEL) {
		flog_warn(EC_ISIS_SID_OVERFLOW,
			  "%s: SID index %u falls outside local SRGB range",
			  __func__, srp->sid.value);
		return -1;
	}

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = local_label;
	SET_FLAG(zl.message, ZAPI_LABELS_FTN);
	zl.route.prefix = srp->prefix;
	zl.route.type = ZEBRA_ROUTE_ISIS;
	zl.route.instance = 0;

	for (ALL_LIST_ELEMENTS_RO(srp->rinfo->nexthops, node, nexthop)) {
		struct isis_adjacency *adj;
		struct sr_node *srn_nexthop;
		mpls_label_t remote_label;


		/* Check if the nexthop advertised a SRGB. */
		adj = nexthop->adj;
		srn_nexthop = isis_sr_node_find(area, srn->level, adj->sysid);
		if (!srn_nexthop)
			continue;

		/*
		 * Check if the nexthop can handle SR-MPLS encapsulated IPv4 or
		 * IPv6 packets.
		 */
		if ((nexthop->family == AF_INET
		     && !IS_SR_IPV4(srn_nexthop->srgb))
		    || (nexthop->family == AF_INET6
			&& !IS_SR_IPV6(srn_nexthop->srgb)))
			continue;

		remote_label = isis_sr_prefix_out_label(srp, srn_nexthop, adj);
		if (remote_label == MPLS_INVALID_LABEL) {
			flog_warn(
				EC_ISIS_SID_OVERFLOW,
				"%s: SID index %u falls outside remote SRGB range",
				__func__, srp->sid.value);
			continue;
		}

		znh = &zl.nexthops[zl.nexthop_num++];
		znh->type = nh_type;
		znh->family = nexthop->family;
		znh->address = nexthop->ip;
		znh->ifindex = nexthop->ifindex;
		znh->label = remote_label;

		if (IS_DEBUG_ISIS(DEBUG_SR)) {
			static char buf[INET6_ADDRSTRLEN];

			inet_ntop(nexthop->family, &nexthop->ip, buf,
				  sizeof(buf));
			zlog_debug("  nexthop %s label %u", buf, remote_label);
		}
	}
	if (zl.nexthop_num == 0) {
		if (IS_DEBUG_ISIS(DEBUG_SR))
			zlog_debug("  no SR-capable nexthops");
		return -1;
	}

	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_REPLACE, &zl);
	srp->local_label = local_label;

	return 0;
}

static void isis_sr_prefix_install(struct sr_prefix *srp)
{
	const struct sr_node *srn = srp->srn;
	struct isis_area *area = srn->area;
	int ret;

	/* L1 routes are preferred over the L2 ones. */
	if (area->is_type == IS_LEVEL_1_AND_2) {
		struct sr_prefix *srp_l1, *srp_l2;

		switch (srn->level) {
		case ISIS_LEVEL1:
			srp_l2 = isis_sr_prefix_find_area(area, ISIS_LEVEL2,
							  &srp->prefix);
			if (srp_l2)
				isis_sr_prefix_uninstall(srp_l2);
			break;
		case ISIS_LEVEL2:
			srp_l1 = isis_sr_prefix_find_area(area, ISIS_LEVEL1,
							  &srp->prefix);
			if (srp_l1)
				return;
			break;
		default:
			break;
		}
	}

	if (srp->local)
		ret = isis_sr_prefix_install_local(srp);
	else
		ret = isis_sr_prefix_install_remote(srp);
	if (ret != 0)
		isis_sr_prefix_uninstall(srp);
}

static void isis_sr_prefix_uninstall(struct sr_prefix *srp)
{
	const struct sr_node *srn = srp->srn;
	struct zapi_labels zl;

	if (srp->local_label == MPLS_INVALID_LABEL)
		return;

	memset(&zl, 0, sizeof(zl));
	SET_FLAG(zl.message, ZAPI_LABELS_FTN);
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = srp->local_label;
	zl.route.prefix = srp->prefix;
	zl.route.type = ZEBRA_ROUTE_ISIS;
	zl.route.instance = 0;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug(
			"ISIS-SR (%s) uninstalling Prefix-SID %pFX index %u (%s)",
			srn->area->area_tag, &srp->prefix, srp->sid.value,
			circuit_t2string(srn->level));

	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_DELETE, &zl);

	srp->local_label = MPLS_INVALID_LABEL;
}

static void isis_sr_prefix_reinstall(struct sr_prefix *srp,
				     bool input_label_change)
{
	/*
	 * If the local SRGB has changed, we can't use route replace semantics
	 * to update the Prefix-SID in the LFIB. It need to be uninstalled first
	 * using the old label.
	 */
	if (input_label_change)
		isis_sr_prefix_uninstall(srp);

	isis_sr_prefix_install(srp);
}

//-----------------------------------------------------------------------------

static struct sr_node *
isis_sr_parse_route_cap_tlv(struct isis_area *area, int level,
			    const uint8_t *sysid,
			    const struct isis_router_cap *router_cap)
{
	struct sr_node *srn;

	if (!router_cap)
		return NULL;

	srn = isis_sr_node_find(area, level, sysid);
	if (srn) {
		if (memcmp(&srn->srgb, &router_cap->srgb, sizeof(srn->srgb))
		    != 0) {
			srn->srgb = router_cap->srgb;
			SET_FLAG(srn->parse_flags, F_ISIS_SR_NODE_MODIFIED);
		} else
			SET_FLAG(srn->parse_flags, F_ISIS_SR_NODE_UNCHANGED);
	} else {
		srn = isis_sr_node_add(area, level, sysid, &router_cap->srgb);
		SET_FLAG(srn->parse_flags, F_ISIS_SR_NODE_NEW);
	}

	return srn;
}

static void isis_sr_parse_prefix_sid_subtlvs(struct sr_node *srn,
					     union prefixconstptr prefix,
					     bool local,
					     struct isis_item_list *prefix_sids)
{
	struct isis_area *area = srn->area;
	struct isis_item *i;

	for (i = prefix_sids->head; i; i = i->next) {
		struct isis_prefix_sid *psid = (struct isis_prefix_sid *)i;
		struct sr_prefix *srp;

		if (psid->algorithm != SR_ALGORITHM_SPF)
			continue;

		/*
		 * The draft is unclear about how these flags should be used.
		 * We support absolute labels by mapping them to SRGB indexes,
		 * like other implementations do.
		 */
		if (CHECK_FLAG(psid->flags,
			       ISIS_PREFIX_SID_VALUE | ISIS_PREFIX_SID_LOCAL))
			continue;

		srp = isis_sr_prefix_find_node(srn, prefix);
		if (srp) {
			if (srp->sid.flags != psid->flags
			    || srp->sid.algorithm != psid->algorithm
			    || srp->sid.value != psid->value) {
				srp->sid = *psid;
				SET_FLAG(srp->parse_flags,
					 F_ISIS_SR_PREFIX_SID_MODIFIED);
			} else
				SET_FLAG(srp->parse_flags,
					 F_ISIS_SR_PREFIX_SID_UNCHANGED);
		} else {
			srp = isis_sr_prefix_add(area, srn, prefix, local,
						 psid);
			SET_FLAG(srp->parse_flags, F_ISIS_SR_PREFIX_SID_NEW);
		}
		/*
		 * Stop the Prefix-SID iteration since we only support the SPF
		 * algorithm for now.
		 */
		break;
	}
}

static void isis_sr_parse_lsp(struct isis_area *area, int level,
			      struct isis_lsp *lsp)
{
	struct isis_item_list *items;
	struct isis_item *i;
	bool local = lsp->own_lsp;
	struct listnode *fragnode = NULL;
	struct sr_node *srn = NULL;

lspfragloop:
	if (lsp->hdr.seqno == 0) {
		zlog_warn("%s: lsp with 0 seq_num - ignore", __func__);
		return;
	}

	/* Parse the Router Capability TLV. */
	if (srn == NULL) {
		srn = isis_sr_parse_route_cap_tlv(area, level, lsp->hdr.lsp_id,
						  lsp->tlvs->router_cap);
		if (!srn)
			return;
	}

	/* Parse the Extended IP Reachability TLV. */
	items = &lsp->tlvs->extended_ip_reach;
	for (i = items->head; i; i = i->next) {
		struct isis_extended_ip_reach *ir;

		ir = (struct isis_extended_ip_reach *)i;
		if (!ir->subtlvs)
			continue;

		isis_sr_parse_prefix_sid_subtlvs(srn, &ir->prefix, local,
						 &ir->subtlvs->prefix_sids);
	}

	/* Parse Multi Topology Reachable IPv6 Prefixes TLV. */
	items = isis_lookup_mt_items(&lsp->tlvs->mt_ipv6_reach,
				     ISIS_MT_IPV6_UNICAST);
	for (i = items ? items->head : NULL; i; i = i->next) {
		struct isis_ipv6_reach *ir;

		ir = (struct isis_ipv6_reach *)i;
		if (!ir->subtlvs)
			continue;

		isis_sr_parse_prefix_sid_subtlvs(srn, &ir->prefix, local,
						 &ir->subtlvs->prefix_sids);
	}

	/* Process next fragment, if any. */
	if (fragnode == NULL)
		fragnode = listhead(lsp->lspu.frags);
	else
		fragnode = listnextnode(fragnode);
	if (fragnode) {
		lsp = listgetdata(fragnode);
		goto lspfragloop;
	}
}

static void isis_sr_parse_lspdb(struct isis_area *area)
{
	struct isis_lsp *lsp;

	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		frr_each (lspdb, &area->lspdb[level - 1], lsp) {
			if (LSP_PSEUDO_ID(lsp->hdr.lsp_id))
				continue;
			if (!lsp->tlvs)
				continue;

			isis_sr_parse_lsp(area, level, lsp);
		}
	}
}

static void isis_sr_process_prefix_changes(struct sr_node *srn,
					   struct sr_prefix *srp)
{
	struct isis_area *area = srn->area;

	/* Log any Prefix-SID change in the LSPDB. */
	if (IS_DEBUG_ISIS(DEBUG_SR)) {
		if (CHECK_FLAG(srp->parse_flags, F_ISIS_SR_PREFIX_SID_NEW))
			zlog_debug(
				"ISIS-SR (%s) Prefix-SID created: %pFX (sysid %s)",
				area->area_tag, &srp->prefix,
				sysid_print(srn->sysid));
		else if (CHECK_FLAG(srp->parse_flags,
				    F_ISIS_SR_PREFIX_SID_MODIFIED))
			zlog_debug(
				"ISIS-SR (%s) Prefix-SID modified: %pFX (sysid %s)",
				area->area_tag, &srp->prefix,
				sysid_print(srn->sysid));
		else if (!CHECK_FLAG(srp->parse_flags,
				     F_ISIS_SR_PREFIX_SID_UNCHANGED))
			zlog_debug(
				"ISIS-SR (%s) Prefix-SID removed: %pFX (sysid %s)",
				area->area_tag, &srp->prefix,
				sysid_print(srn->sysid));
	}

	/* Install/reinstall/uninstall Prefix-SID if necessary. */
	if (CHECK_FLAG(srp->parse_flags, F_ISIS_SR_PREFIX_SID_NEW))
		isis_sr_prefix_install(srp);
	else if (CHECK_FLAG(srp->parse_flags, F_ISIS_SR_PREFIX_SID_MODIFIED))
		isis_sr_prefix_reinstall(srp, false);
	else if (!CHECK_FLAG(srp->parse_flags,
			     F_ISIS_SR_PREFIX_SID_UNCHANGED)) {
		isis_sr_prefix_del(area, srn, srp);
		return;
	}

	srp->parse_flags = 0;
}

static void isis_sr_process_node_changes(struct isis_area *area, int level,
					 struct sr_node *srn)
{
	struct sr_prefix *srp;
	bool adjacent;

	/* Log any SRGB change in the LSPDB. */
	if (IS_DEBUG_ISIS(DEBUG_SR)) {
		if (CHECK_FLAG(srn->parse_flags, F_ISIS_SR_NODE_NEW))
			zlog_debug("ISIS-SR (%s) SRGB created (sysid %s)",
				   area->area_tag, sysid_print(srn->sysid));
		else if (CHECK_FLAG(srn->parse_flags, F_ISIS_SR_NODE_MODIFIED))
			zlog_debug("ISIS-SR (%s) SRGB modified (sysid %s)",
				   area->area_tag, sysid_print(srn->sysid));
		else if (!CHECK_FLAG(srn->parse_flags,
				     F_ISIS_SR_NODE_UNCHANGED))
			zlog_debug("ISIS-SR (%s) SRGB removed (sysid %s)",
				   area->area_tag, sysid_print(srn->sysid));
	}

	/*
	 * If an adjacent router's SRGB was changed or created, then reinstall
	 * all Prefix-SIDs from all nodes.
	 */
	adjacent = isis_adj_exists(area, srn->sysid);
	if (CHECK_FLAG(srn->parse_flags,
		       F_ISIS_SR_NODE_NEW | F_ISIS_SR_NODE_MODIFIED)) {
		if (adjacent)
			isis_sr_adj_srgb_update(srn, level);
	} else if (!CHECK_FLAG(srn->parse_flags, F_ISIS_SR_NODE_UNCHANGED)) {
		isis_sr_node_del(area, level, srn);

		if (adjacent)
			isis_sr_adj_srgb_update(srn, level);
		return;
	}

	srn->parse_flags = 0;

	frr_each_safe (tree_sr_node_prefix, &srn->prefix_sids, srp)
		isis_sr_process_prefix_changes(srn, srp);
}

void isis_area_verify_sr(struct isis_area *area)
{
	struct sr_node *srn;

	if (!area->srdb.enabled)
		return;

	/* Parse LSPDB to detect new/deleted/modified SR (sub-)TLVs. */
	isis_sr_parse_lspdb(area);

	/* Process possible SR-related changes in the LDPSB. */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		frr_each_safe (tree_sr_node, &area->srdb.sr_nodes[level - 1],
			       srn)
			isis_sr_process_node_changes(area, level, srn);
	}
}

#ifndef FABRICD
static int isis_sr_route_update(struct isis_area *area, struct prefix *prefix,
				struct isis_route_info *route_info)
{
	struct sr_prefix *srp;

	if (!area->srdb.enabled)
		return 0;

	switch (area->is_type) {
	case IS_LEVEL_1:
		srp = isis_sr_prefix_find_area(area, ISIS_LEVEL1, prefix);
		break;
	case IS_LEVEL_2:
		srp = isis_sr_prefix_find_area(area, ISIS_LEVEL2, prefix);
		break;
	case IS_LEVEL_1_AND_2:
		srp = isis_sr_prefix_find_area(area, ISIS_LEVEL1, prefix);
		if (!srp)
			srp = isis_sr_prefix_find_area(area, ISIS_LEVEL2,
						       prefix);
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown area level",
			 __func__);
		exit(1);
	}

	if (!srp)
		return 0;

	if (CHECK_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ACTIVE))
		isis_sr_prefix_reinstall(srp, false);
	else
		isis_sr_prefix_uninstall(srp);

	return 0;
}
#endif /* FABRICD */

//-----------------------------------------------------------------------------

/* Get Label for (LAN-)Adj-SID */
static mpls_label_t isis_sr_get_local_label(void)
{
	return isis_zebra_request_dynamic_label();
}

static void isis_sr_adj_sid_install_uninstall(
	bool install, const struct isis_circuit *circuit,
	const struct isis_adjacency *adj, mpls_label_t local_label, int family,
	const void *address)
{
	struct zapi_labels zl;
	struct zapi_nexthop_label *znh;
	int cmd;

	cmd = install ? ZEBRA_MPLS_LABELS_ADD : ZEBRA_MPLS_LABELS_DELETE;

	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = local_label;
	zl.nexthop_num = 1;
	znh = &zl.nexthops[0];
	switch (family) {
	case AF_INET:
		znh->family = AF_INET;
		znh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
		memcpy(&znh->address.ipv4, address, sizeof(znh->address.ipv4));
		break;
	case AF_INET6:
		znh->family = AF_INET6;
		znh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
		memcpy(&znh->address.ipv6, address, sizeof(znh->address.ipv6));
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown address family",
			 __func__);
		exit(1);
	}
	znh->ifindex = circuit->interface->ifindex;
	znh->label = MPLS_LABEL_IMPLICIT_NULL;

	(void)zebra_send_mpls_labels(zclient, cmd, &zl);
}

static void isis_sr_circuit_add_ipv4_adj_sid(struct isis_circuit *circuit,
					     struct isis_adjacency *adj)
{
	struct isis_adj_sid *adj_sid;
	struct isis_lan_adj_sid *ladj_sid;
	mpls_label_t local_label;

	if (!circuit->ip_router)
		return;

	if (circuit->ext == NULL)
		circuit->ext = isis_alloc_ext_subtlvs();

	local_label = isis_sr_get_local_label();

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		ladj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*ladj_sid));
		ladj_sid->family = AF_INET;
		ladj_sid->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				  | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
		ladj_sid->weight = 0;
		memcpy(ladj_sid->neighbor_id, adj->sysid,
		       sizeof(ladj_sid->neighbor_id));
		ladj_sid->sid = local_label;

		isis_tlvs_add_lan_adj_sid(circuit->ext, ladj_sid);
		adj->sr.ipv4.ladj_sid = ladj_sid;
		break;
	case CIRCUIT_T_P2P:
		adj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*adj_sid));
		adj_sid->family = AF_INET;
		adj_sid->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				 | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
		adj_sid->weight = 0;
		adj_sid->sid = local_label;

		isis_tlvs_add_adj_sid(circuit->ext, adj_sid);
		adj->sr.ipv4.adj_sid = adj_sid;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}

	isis_sr_adj_sid_install_uninstall(true, circuit, adj, local_label,
					  AF_INET, &adj->ipv4_addresses[0]);
}

static void isis_sr_circuit_add_ipv6_adj_sid(struct isis_circuit *circuit,
					     struct isis_adjacency *adj)
{
	struct isis_adj_sid *adj_sid;
	struct isis_lan_adj_sid *ladj_sid;
	mpls_label_t local_label;

	if (!circuit->ipv6_router)
		return;

	if (circuit->ext == NULL)
		circuit->ext = isis_alloc_ext_subtlvs();

	local_label = isis_sr_get_local_label();

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		ladj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*ladj_sid));
		ladj_sid->family = AF_INET6;
		ladj_sid->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				  | EXT_SUBTLV_LINK_ADJ_SID_LFLG
				  | EXT_SUBTLV_LINK_ADJ_SID_FFLG;
		ladj_sid->weight = 0;
		memcpy(ladj_sid->neighbor_id, adj->sysid,
		       sizeof(ladj_sid->neighbor_id));
		ladj_sid->sid = local_label;

		isis_tlvs_add_lan_adj_sid(circuit->ext, ladj_sid);
		adj->sr.ipv6.ladj_sid = ladj_sid;
		break;
	case CIRCUIT_T_P2P:
		adj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*adj_sid));
		adj_sid->family = AF_INET6;
		adj_sid->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
				 | EXT_SUBTLV_LINK_ADJ_SID_LFLG
				 | EXT_SUBTLV_LINK_ADJ_SID_FFLG;
		adj_sid->weight = 0;
		adj_sid->sid = local_label;

		isis_tlvs_add_adj_sid(circuit->ext, adj_sid);
		adj->sr.ipv6.adj_sid = adj_sid;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}

	isis_sr_adj_sid_install_uninstall(true, circuit, adj, local_label,
					  AF_INET6, &adj->ipv6_addresses[0]);
}

static void isis_sr_circuit_del_ipv4_adj_sid(struct isis_circuit *circuit,
					     struct isis_adjacency *adj)
{
	struct isis_adj_sid *adj_sid;
	struct isis_lan_adj_sid *ladj_sid;

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		ladj_sid = adj->sr.ipv4.ladj_sid;
		if (ladj_sid) {
			isis_sr_adj_sid_install_uninstall(
				false, circuit, adj, ladj_sid->sid, AF_INET,
				&adj->ipv4_addresses[0]);
			isis_tlvs_del_lan_adj_sid(circuit->ext, ladj_sid);
			adj->sr.ipv4.ladj_sid = NULL;
		}
		break;
	case CIRCUIT_T_P2P:
		adj_sid = adj->sr.ipv4.adj_sid;
		if (adj_sid) {
			isis_sr_adj_sid_install_uninstall(
				false, circuit, adj, adj_sid->sid, AF_INET,
				&adj->ipv4_addresses[0]);
			isis_tlvs_del_adj_sid(circuit->ext, adj_sid);
			adj->sr.ipv4.adj_sid = NULL;
		}
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}
}

static void isis_sr_circuit_del_ipv6_adj_sid(struct isis_circuit *circuit,
					     struct isis_adjacency *adj)
{
	struct isis_adj_sid *adj_sid;
	struct isis_lan_adj_sid *ladj_sid;

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		ladj_sid = adj->sr.ipv6.ladj_sid;
		if (ladj_sid) {
			isis_sr_adj_sid_install_uninstall(
				false, circuit, adj, ladj_sid->sid, AF_INET6,
				&adj->ipv6_addresses[0]);
			isis_tlvs_del_lan_adj_sid(circuit->ext, ladj_sid);
			adj->sr.ipv6.ladj_sid = NULL;
		}
		break;
	case CIRCUIT_T_P2P:
		adj_sid = adj->sr.ipv6.adj_sid;
		if (adj_sid) {
			isis_sr_adj_sid_install_uninstall(
				false, circuit, adj, adj_sid->sid, AF_INET6,
				&adj->ipv6_addresses[0]);
			isis_tlvs_del_adj_sid(circuit->ext, adj_sid);
			adj->sr.ipv6.adj_sid = NULL;
		}
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}
}

#ifndef FABRICD
static int isis_sr_adj_state_change(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit = adj->circuit;

	if (!circuit->area->srdb.enabled)
		return 0;

	if (adj->adj_state != ISIS_ADJ_UP) {
		isis_sr_circuit_del_ipv4_adj_sid(circuit, adj);
		isis_sr_circuit_del_ipv6_adj_sid(circuit, adj);
	}

	return 0;
}

static int isis_sr_adj_ipv4_enabled(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit = adj->circuit;

	if (!circuit->area->srdb.enabled)
		return 0;

	isis_sr_circuit_add_ipv4_adj_sid(circuit, adj);

	return 0;
}

static int isis_sr_adj_ipv4_disabled(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit = adj->circuit;

	if (!circuit->area->srdb.enabled)
		return 0;

	isis_sr_circuit_del_ipv4_adj_sid(circuit, adj);

	return 0;
}

static int isis_sr_adj_ipv6_enabled(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit = adj->circuit;

	if (!circuit->area->srdb.enabled)
		return 0;

	isis_sr_circuit_add_ipv6_adj_sid(circuit, adj);

	return 0;
}

static int isis_sr_adj_ipv6_disabled(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit = adj->circuit;

	if (!circuit->area->srdb.enabled)
		return 0;

	isis_sr_circuit_del_ipv6_adj_sid(circuit, adj);

	return 0;
}

static int isis_sr_if_new_hook(struct interface *ifp)
{
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct connected *connected;
	struct listnode *node;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return 0;

	area = circuit->area;
	if (!area)
		return 0;

	/*
	 * Update the Node-SID flag of the configured Prefix-SID mappings if
	 * necessary. This needs to be done here since isisd reads the startup
	 * configuration before receiving interface information from zebra.
	 */
	FOR_ALL_INTERFACES_ADDRESSES (ifp, connected, node) {
		struct sr_prefix_cfg *pcfg;

		pcfg = isis_sr_cfg_prefix_find(area, connected->address);
		if (!pcfg)
			continue;

		if (isis_sr_prefix_is_node_sid(ifp, &pcfg->prefix)
		    && !CHECK_FLAG(pcfg->flags, ISIS_PREFIX_SID_NODE)) {
			SET_FLAG(pcfg->flags, ISIS_PREFIX_SID_NODE);
			lsp_regenerate_schedule(area, area->is_type, 0);
		}
	}

	return 0;
}
#endif /* FABRICD */

//-----------------------------------------------------------------------------

int isis_sr_start(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;
	struct isis_circuit *circuit;
	struct listnode *node;

	/*
	 * Request SGRB to the label manager. If the allocation fails, return
	 * an error to disable SR until a new SRGB is successfully allocated.
	 */
	if (isis_zebra_request_label_range(
		    srdb->config.srgb_lower_bound,
		    srdb->config.srgb_upper_bound
			    - srdb->config.srgb_lower_bound + 1))
		return -1;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Starting Segment Routing", __func__);

	/* Create Adj-SIDs for existing adjacencies. */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		struct isis_adjacency *adj;
		struct listnode *anode;

		switch (circuit->circ_type) {
		case CIRCUIT_T_BROADCAST:
			for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[0], anode,
						  adj)) {
				if (adj->ipv4_address_count > 0)
					isis_sr_circuit_add_ipv4_adj_sid(
						circuit, adj);
				if (adj->ipv6_address_count > 0)
					isis_sr_circuit_add_ipv6_adj_sid(
						circuit, adj);
			}
			for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[1], anode,
						  adj)) {
				if (adj->ipv4_address_count > 0)
					isis_sr_circuit_add_ipv4_adj_sid(
						circuit, adj);
				if (adj->ipv6_address_count > 0)
					isis_sr_circuit_add_ipv6_adj_sid(
						circuit, adj);
			}
			break;
		case CIRCUIT_T_P2P:
			adj = circuit->u.p2p.neighbor;
			if (adj && adj->ipv4_address_count > 0)
				isis_sr_circuit_add_ipv4_adj_sid(circuit, adj);
			if (adj && adj->ipv6_address_count > 0)
				isis_sr_circuit_add_ipv6_adj_sid(circuit, adj);
			break;
		default:
			break;
		}
	}

	/* Regenerate LSPs. */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return 0;
}

void isis_sr_stop(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;
	struct isis_circuit *circuit;
	struct listnode *node;

	if (IS_DEBUG_ISIS(DEBUG_SR))
		zlog_debug("SR (%s): Stopping Segment Routing", __func__);

	/* Uninstall Adj-SIDs. */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		struct isis_adjacency *adj;
		struct listnode *anode;

		switch (circuit->circ_type) {
		case CIRCUIT_T_BROADCAST:
			for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[0], anode,
						  adj)) {
				isis_sr_circuit_del_ipv4_adj_sid(circuit, adj);
				isis_sr_circuit_del_ipv6_adj_sid(circuit, adj);
			}
			for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[1], anode,
						  adj)) {
				isis_sr_circuit_del_ipv4_adj_sid(circuit, adj);
				isis_sr_circuit_del_ipv6_adj_sid(circuit, adj);
			}
			break;
		case CIRCUIT_T_P2P:
			adj = circuit->u.p2p.neighbor;
			if (adj) {
				isis_sr_circuit_del_ipv4_adj_sid(circuit, adj);
				isis_sr_circuit_del_ipv6_adj_sid(circuit, adj);
			}
			break;
		default:
			break;
		}
	}

	/* Uninstall Prefix-SIDs. */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		while (tree_sr_node_count(&srdb->sr_nodes[level - 1]) > 0) {
			struct sr_node *srn;

			srn = tree_sr_node_first(&srdb->sr_nodes[level - 1]);
			isis_sr_node_del(area, level, srn);
		}
	}

	/* Release SRGB. */
	isis_zebra_release_label_range(srdb->config.srgb_lower_bound,
				       srdb->config.srgb_upper_bound);

	/* Regenerate LSPs. */
	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_area_init(struct isis_area *area)
{
#ifndef FABRICD
	struct isis_sr_db *srdb = &area->srdb;

	memset(srdb, 0, sizeof(*srdb));
	srdb->enabled = false;
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		tree_sr_node_init(&srdb->sr_nodes[level - 1]);
		tree_sr_area_prefix_init(&srdb->prefix_sids[level - 1]);
	}

	/* Pull defaults from the YANG module. */
	srdb->config.enabled = yang_get_default_bool("%s/enabled", ISIS_SR);
	srdb->config.srgb_lower_bound =
		yang_get_default_uint32("%s/srgb/lower-bound", ISIS_SR);
	srdb->config.srgb_upper_bound =
		yang_get_default_uint32("%s/srgb/upper-bound", ISIS_SR);
	srdb->config.msd = 0;
	tree_sr_prefix_cfg_init(&srdb->config.prefix_sids);
#endif /* FABRICD */
}

void isis_sr_area_term(struct isis_area *area)
{
#ifndef FABRICD
	struct isis_sr_db *srdb = &area->srdb;

	/* Stop Segment Routing */
	if (area->srdb.enabled)
		isis_sr_stop(area);

	/* Clear Prefix-SID configuration. */
	while (tree_sr_prefix_cfg_count(&srdb->config.prefix_sids) > 0) {
		struct sr_prefix_cfg *pcfg;

		pcfg = tree_sr_prefix_cfg_first(&srdb->config.prefix_sids);
		isis_sr_cfg_prefix_del(pcfg);
	}
#endif /* FABRICD */
}

void isis_sr_init(void)
{
#ifndef FABRICD
	/* Register hooks. */
	hook_register(isis_adj_state_change_hook, isis_sr_adj_state_change);
	hook_register(isis_adj_ipv4_enabled_hook, isis_sr_adj_ipv4_enabled);
	hook_register(isis_adj_ipv4_disabled_hook, isis_sr_adj_ipv4_disabled);
	hook_register(isis_adj_ipv6_enabled_hook, isis_sr_adj_ipv6_enabled);
	hook_register(isis_adj_ipv6_disabled_hook, isis_sr_adj_ipv6_disabled);
	hook_register(isis_route_update_hook, isis_sr_route_update);
	hook_register(isis_if_new_hook, isis_sr_if_new_hook);
#endif /* FABRICD */
}

void isis_sr_term(void)
{
#ifndef FABRICD
	/* Unregister hooks. */
	hook_unregister(isis_adj_state_change_hook, isis_sr_adj_state_change);
	hook_unregister(isis_adj_ipv4_enabled_hook, isis_sr_adj_ipv4_enabled);
	hook_unregister(isis_adj_ipv4_disabled_hook, isis_sr_adj_ipv4_disabled);
	hook_unregister(isis_adj_ipv6_enabled_hook, isis_sr_adj_ipv6_enabled);
	hook_unregister(isis_adj_ipv6_disabled_hook, isis_sr_adj_ipv6_disabled);
	hook_unregister(isis_route_update_hook, isis_sr_route_update);
	hook_unregister(isis_if_new_hook, isis_sr_if_new_hook);
#endif /* FABRICD */
}
