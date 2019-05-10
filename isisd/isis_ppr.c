/*
 * Copyright (C) 2019  NetDEF, Inc.
 *                     Renato Westphal
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

#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "termtable.h"
#include "prefix.h"
#include "table.h"
#include "zclient.h"
#include "vrf.h"
#include "vty.h"
#include "log.h"
#include "lib_errors.h"

#include "isisd/isisd.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_memory.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_route.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_ppr.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_errors.h"

#ifndef VTYSH_EXTRACT_PL
#include "isisd/isis_ppr_clippy.c"
#endif

DEFINE_MTYPE_STATIC(ISISD, ISIS_PPR, "ISIS PPR Info");

static inline int isis_ppr_compare(const struct isis_ppr *a,
				   const struct isis_ppr *b)
{
	int ret;

	if (memcmp(a->sysid, b->sysid, ISIS_SYS_ID_LEN) < 0)
		return -1;
	if (memcmp(a->sysid, b->sysid, ISIS_SYS_ID_LEN) > 0)
		return 1;

	ret = ppr_id_compare(&a->id, &b->id);
	if (ret < 0)
		return -1;
	if (ret > 0)
		return 1;

	return a->attr.metric - b->attr.metric;
}
RB_GENERATE(isis_ppr_head, isis_ppr, entry, isis_ppr_compare);

static inline int isis_ppr_adv_compare(const struct isis_ppr_adv *a,
				       const struct isis_ppr_adv *b)
{
	return strcmp(a->name, b->name);
}
RB_GENERATE(isis_ppr_adv_head, isis_ppr_adv, entry, isis_ppr_adv_compare);

//-----------------------------------------------------------------------------

static bool isis_ppr_on_path_check_mpls_psid(struct isis_area *area,
					     const struct ppr_pde *pde)
{
	uint32_t sid = pde->id_value.mpls;

	if (isis_sr_cfg_sid_find(area, sid))
		return true;

	return false;
}

static bool isis_ppr_on_path_check_ip_addr(const struct isis_area *area,
					   const struct ppr_pde *pde)
{
	struct interface *ifp;
	struct isis_circuit *circuit;
	const struct prefix *pde_id = &pde->id_value.prefix;

	/* Check if the system has the PDE-ID node address. */
	ifp = if_lookup_exact_address((void *)&pde_id->u.prefix, pde_id->family,
				      VRF_DEFAULT);
	if (!ifp)
		return false;

	/* Check if this address is enabled on the IS-IS area. */
	circuit = ifp->info;
	if (!circuit || circuit->area != area)
		return false;

	/*
	 * NOTE: the checks above should be equivalent to looking for the PDE
	 * node address in the local LSP.
	 */

	return true;
}

static bool isis_ppr_on_path_check(struct isis_area *area,
				   const struct ppr_pde *pde)
{
	/* Ignore non-topological PDEs. */
	if (pde->type == PPR_PDE_TYPE_NON_TOPOLOGICAL)
		return false;

	switch (pde->id_type) {
	case PPR_PDE_ID_TYPE_SID_LABEL:
	case PPR_PDE_ID_TYPE_SRMPLS_ADJ_SID:
		/* TODO: SR-MPLS. */
		return false;
	case PPR_PDE_ID_TYPE_SRMPLS_PREFIX_SID:
		return isis_ppr_on_path_check_mpls_psid(area, pde);
	case PPR_PDE_ID_TYPE_IPV4_NODE_ADDR:
	case PPR_PDE_ID_TYPE_IPV6_NODE_ADDR:
	case PPR_PDE_ID_TYPE_IPV4_IFACE_ADDR:
	case PPR_PDE_ID_TYPE_IPV6_IFACE_ADDR:
		return isis_ppr_on_path_check_ip_addr(area, pde);
	case PPR_PDE_ID_TYPE_SRV6_NODE_SID:
	case PPR_PDE_ID_TYPE_SRV6_ADJ_SID:
		/* TODO: SRv6. */
		return false;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown PDE-ID type: %u",
			 __func__, pde->id_type);
		exit(1);
	}

	return false;
}

//-----------------------------------------------------------------------------

#if 0
static bool isis_adj_has_addr(const struct isis_adjacency *adj,
			      const struct prefix *prefix)
{
	switch (prefix->family) {
	case AF_INET:
		for (unsigned int i = 0; i < adj->ipv4_address_count; i++) {
			struct in_addr *ipv4_addr;

			ipv4_addr = &adj->ipv4_addresses[i];
			if (IPV4_ADDR_SAME(&prefix->u.prefix4, ipv4_addr))
				return true;
		}
		break;
	case AF_INET6:
		for (unsigned int i = 0; i < adj->ipv6_address_count; i++) {
			struct in6_addr *ipv6_addr;

			ipv6_addr = &adj->ipv6_addresses[i];
			if (IPV6_ADDR_SAME(&prefix->u.prefix6, ipv6_addr))
				return true;
		}
		break;
	default:
		break;
	}

	return false;
}

static struct isis_adjacency *
isis_ppr_get_adj_p2p_addr(const struct isis_area *area,
			  const struct ppr_pde *pde)
{
	struct isis_circuit *circuit;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		struct isis_adjacency *adj;

		if (circuit->circ_type != CIRCUIT_T_P2P)
			continue;

		adj = circuit->u.p2p.neighbor;
		if (isis_adj_has_addr(adj, &pde->id_value.prefix))
			return adj;
	}

	return NULL;
}

static struct isis_adjacency *
isis_ppr_get_adj_lan_addr(const struct isis_area *area,
			  const struct ppr_pde *pde)
{
	struct isis_circuit *circuit;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		struct isis_adjacency *adj;
		struct listnode *anode;

		if (circuit->circ_type != CIRCUIT_T_BROADCAST)
			continue;

		for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[0], anode, adj)) {
			if (isis_adj_has_addr(adj, &pde->id_value.prefix))
				return adj;
		}
		for (ALL_LIST_ELEMENTS_RO(circuit->u.bc.adjdb[1], anode, adj)) {
			if (isis_adj_has_addr(adj, &pde->id_value.prefix))
				return adj;
		}
	}

	return NULL;
}
#endif

struct isis_route_info *
isis_area_find_route_spftree(const struct isis_area *area,
			     const struct prefix *prefix)
{
	enum spf_tree_id tree_id;
	struct route_table *table;
	struct route_node *rn;

	switch (prefix->family) {
	case AF_INET:
		tree_id = SPFTREE_IPV4;
		break;
	case AF_INET6:
		tree_id = SPFTREE_IPV6;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown prefix family",
			 __func__);
		exit(1);
	}

	table = area->spftree[tree_id][area->is_type - 1]->route_table;
	rn = route_node_lookup(table, prefix);
	if (!rn)
		return NULL;

	return rn->info;
}

static void
isis_zebra_install_ppr_mpls_psid_tailend(struct isis_ppr *ppr,
					 const struct ppr_pde *pde_next)
{
	struct isis_area *area = ppr->area;
	mpls_label_t local_label;
	struct zapi_labels zl;
	struct zapi_nexthop_label *znh;
	uint32_t sid_ppr_id = ppr->id.value.mpls;

	/* Calculate local label. */
	local_label = area->srdb.config.srgb_lower_bound + sid_ppr_id;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_PPR;
	zl.local_label = local_label;
	znh = &zl.nexthops[zl.nexthop_num++];
	znh->type = NEXTHOP_TYPE_IFINDEX;
	znh->ifindex = 1; /* loopback */
	znh->label = MPLS_LABEL_IMPLICIT_NULL;

	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_REPLACE, &zl);
	if (ppr->status != PPR_INSTALL_SUCCESS)
		ppr->uptime = time(NULL);
	ppr->status = PPR_INSTALL_SUCCESS;
	ppr->installed_label = local_label;
}

static void isis_zebra_install_ppr_mpls_psid(struct isis_ppr *ppr,
					     const struct ppr_pde *pde_next)
{
	struct isis_area *area = ppr->area;
	struct sr_prefix *srp;
	const struct sr_node *srn;
	enum spf_tree_id tree_id;
	struct isis_route_info *rinfo;
	struct listnode *node;
	struct isis_nexthop *nexthop;
	mpls_label_t local_label;
	enum nexthop_types_t nh_type;
	struct zapi_labels zl;
	struct zapi_nexthop_label *znh;
	uint32_t sid_pde_next = pde_next->id_value.mpls;
	uint32_t sid_ppr_id = ppr->id.value.mpls;

	if (ppr->position == PPR_TAIL_END) {
		isis_zebra_install_ppr_mpls_psid_tailend(ppr, pde_next);
		return;
	}

	srp = isis_sr_prefix_sid_find_area(area, area->is_type, sid_pde_next);
	if (!srp) {
		if (IS_DEBUG_ISIS(DEBUG_PPR))
			zlog_debug("ISIS-PPR (%s) Prefix-SID not found: %u",
				   area->area_tag, sid_pde_next);
		return;
	}
	srn = srp->srn;

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
	rinfo = isis_sr_prefix_lookup_route(area, tree_id, srp);
	if (!rinfo)
		/* SPF hasn't converged for this route yet. */
		return;

	/* Calculate local label. */
	if (sid_ppr_id > (area->srdb.config.srgb_upper_bound
			  - area->srdb.config.srgb_lower_bound + 1)) {
		flog_warn(
			EC_ISIS_SID_OVERFLOW,
			"%s: PPR-ID SID index %u falls outside local SRGB range",
			__func__, srp->sid.value);
		return;
	}
	local_label = area->srdb.config.srgb_lower_bound + sid_ppr_id;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_PPR;
	zl.local_label = local_label;

	for (ALL_LIST_ELEMENTS_RO(rinfo->nexthops, node, nexthop)) {
		struct isis_adjacency *adj;
		struct sr_node *srn_nexthop;
		mpls_label_t remote_label;

		adj = nexthop->adj;

		/* Check if the nexthop advertised a SRGB. */
		srn_nexthop = isis_sr_node_find(area, srn->level, adj->sysid);
		if (!srn_nexthop)
			continue;

		/*
		 * Check if the nexthop can handle SR-MPLS encapsulated
		 * IPv4 or IPv6 packets.
		 */
		if ((nexthop->family == AF_INET
		     && !IS_SR_IPV4(srn_nexthop->srgb))
		    || (nexthop->family == AF_INET6
			&& !IS_SR_IPV6(srn_nexthop->srgb)))
			continue;

		if (sid_ppr_id > srn_nexthop->srgb.range_size) {
			flog_warn(
				EC_ISIS_SID_OVERFLOW,
				"%s: PPR-ID SID index %u falls outside remote SRGB range",
				__func__, sid_ppr_id);
			continue;
		}
		remote_label = srn_nexthop->srgb.lower_bound + sid_ppr_id;

		znh = &zl.nexthops[zl.nexthop_num++];
		znh->type = nh_type;
		znh->family = nexthop->family;
		znh->address = nexthop->ip;
		znh->ifindex = nexthop->ifindex;
		znh->label = remote_label;
	}
	if (zl.nexthop_num == 0)
		return;

	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_REPLACE, &zl);
	if (ppr->status != PPR_INSTALL_SUCCESS)
		ppr->uptime = time(NULL);
	ppr->status = PPR_INSTALL_SUCCESS;
	ppr->installed_label = local_label;
}

static void isis_zebra_install_ppr_node_addr(struct isis_ppr *ppr,
					     const struct ppr_pde *pde_next)
{
	struct isis_area *area = ppr->area;
	struct isis_route_info *rinfo;
	struct isis_nexthop *nexthop;
	struct listnode *node;
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	const struct prefix *pde_next_addr = &pde_next->id_value.prefix;

	/* Nothing to do. */
	if (ppr->position == PPR_TAIL_END)
		return;

	rinfo = isis_area_find_route_spftree(area, pde_next_addr);
	if (!rinfo) {
		ppr->status = PPR_INSTALL_FAILURE_PDE_UNREACHABLE;
		zlog_warn("ISIS-PPR (%s) next PDE not found in the SPT: %pFX",
			  area->area_tag, pde_next_addr);
		return;
	}
	if (rinfo->depth == 1) {
		ppr->status = PPR_INSTALL_FAILURE_PDE_LOCAL;
		zlog_warn("ISIS-PPR (%s) next PDE points to local IP prefix",
			  area->area_tag);
		return;
	}
	if (!pde_next->loose && rinfo->depth > 2) {
		ppr->status = PPR_INSTALL_FAILURE_PDE_NOT_ADJ;
		zlog_warn(
			"ISIS-PPR (%s) next PDE is not adjacent and the loose flag is not set",
			area->area_tag);
		return;
	}

	/* Prepare message. */
	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = PROTO_TYPE;
	api.safi = SAFI_UNICAST;
	api.prefix = ppr->id.value.prefix;
	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = ppr->attr.metric;

	/* Set nexthops. */
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	for (ALL_LIST_ELEMENTS_RO(rinfo->nexthops, node, nexthop)) {
		api_nh = &api.nexthops[api.nexthop_num];
		api_nh->vrf_id = VRF_DEFAULT;
		switch (ppr->id.value.prefix.family) {
		case AF_INET:
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			break;
		case AF_INET6:
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			break;
		default:
			break;
		}
		api_nh->gate = nexthop->ip;
		api_nh->ifindex = nexthop->ifindex;
		api.nexthop_num++;
	}

	if (ppr->status != PPR_INSTALL_SUCCESS)
		ppr->uptime = time(NULL);
	ppr->status = PPR_INSTALL_SUCCESS;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

static void isis_zebra_install_ppr_iface_addr(struct isis_ppr *ppr,
					      const struct ppr_pde *pde_next)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
#if 0
	struct isis_adjacency *adj;

	adj = isis_ppr_get_adj_p2p_addr(ppr->area, pde_next);
	if (adj == NULL) {
		zlog_warn("ISIS-PPR (%s) can't find adjacency for %s",
			  area->area_tag, ppr_pdeid2str(pde_next));
		return;
	}
#endif

	/* Nothing to do. */
	if (ppr->position == PPR_TAIL_END)
		return;

	/* Prepare message. */
	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = PROTO_TYPE;
	api.safi = SAFI_UNICAST;
	api.prefix = ppr->id.value.prefix;
	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = ppr->attr.metric;

	/* Set nexthops. */
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	api.nexthop_num++;
	api_nh = &api.nexthops[0];
	api_nh->vrf_id = VRF_DEFAULT;

	switch (ppr->id.value.prefix.family) {
	case AF_INET:
		// api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
		api_nh->type = NEXTHOP_TYPE_IPV4;
		api_nh->gate.ipv4 = pde_next->id_value.prefix.u.prefix4;
		// api_nh->ifindex = adj->circuit->interface->ifindex;
		break;
	case AF_INET6:
		// api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
		api_nh->type = NEXTHOP_TYPE_IPV6;
		api_nh->gate.ipv6 = pde_next->id_value.prefix.u.prefix6;
		// api_nh->ifindex = adj->circuit->interface->ifindex;
		break;
	default:
		break;
	}

	if (ppr->status != PPR_INSTALL_SUCCESS)
		ppr->uptime = time(NULL);
	ppr->status = PPR_INSTALL_SUCCESS;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

static void isis_zebra_install_ppr(struct isis_ppr *ppr)
{
	struct isis_area *area = ppr->area;
	const struct isis_ppr_pde_stlv *pde = ppr->pde_next;

	if (IS_DEBUG_ISIS(DEBUG_PPR))
		zlog_debug("ISIS-PPR (%s) installing PPR-ID %s (%s)",
			   area->area_tag, ppr_idtype2str(ppr->id.type),
			   ppr_id2str(&ppr->id));

	switch (pde->info.id_type) {
	case PPR_PDE_ID_TYPE_SID_LABEL:
	case PPR_PDE_ID_TYPE_SRMPLS_ADJ_SID:
		/* TODO: SR-MPLS */
		break;
	case PPR_PDE_ID_TYPE_SRMPLS_PREFIX_SID:
		isis_zebra_install_ppr_mpls_psid(ppr, &pde->info);
		break;
	case PPR_PDE_ID_TYPE_IPV4_NODE_ADDR:
	case PPR_PDE_ID_TYPE_IPV6_NODE_ADDR:
		isis_zebra_install_ppr_node_addr(ppr, &pde->info);
		break;
	case PPR_PDE_ID_TYPE_IPV4_IFACE_ADDR:
	case PPR_PDE_ID_TYPE_IPV6_IFACE_ADDR:
		isis_zebra_install_ppr_iface_addr(ppr, &pde->info);
		break;
	case PPR_PDE_ID_TYPE_SRV6_NODE_SID:
	case PPR_PDE_ID_TYPE_SRV6_ADJ_SID:
		/* TODO: SRv6 */
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown PDE-ID type: %u",
			 __func__, pde->info.id_type);
		exit(1);
	}
}

static void isis_zebra_uninstall_ppr_mpls(struct isis_ppr *ppr)
{
	struct zapi_labels zl;

	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = ppr->installed_label;

	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_DELETE, &zl);
	ppr->installed_label = MPLS_INVALID_LABEL;
}

static void isis_zebra_uninstall_ppr_ip_addr(struct isis_ppr *ppr)
{
	struct zapi_route api;

	/* Prepare message. */
	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = PROTO_TYPE;
	api.safi = SAFI_UNICAST;
	api.prefix = ppr->id.value.prefix;

	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
}

static void isis_zebra_uninstall_ppr(struct isis_ppr *ppr)
{
	struct isis_area *area = ppr->area;

	if (ppr->status != PPR_INSTALL_SUCCESS)
		return;

	if (IS_DEBUG_ISIS(DEBUG_PPR))
		zlog_debug("ISIS-PPR (%s) uninstalling PPR-ID %s (%s)",
			   area->area_tag, ppr_idtype2str(ppr->id.type),
			   ppr_id2str(&ppr->id));

	switch (ppr->id.type) {
	case PPR_ID_TYPE_MPLS:
		isis_zebra_uninstall_ppr_mpls(ppr);
		break;
	case PPR_ID_TYPE_IPV4:
	case PPR_ID_TYPE_IPV6:
		isis_zebra_uninstall_ppr_ip_addr(ppr);
		break;
	case PPR_ID_TYPE_SRV6:
		/* TODO: SRv6 */
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown PPR-ID type: %u",
			 __func__, ppr->id.type);
		exit(1);
	}

	ppr->status = PPR_UNINSTALLED;
}

//-----------------------------------------------------------------------------

static struct isis_ppr *isis_ppr_add(struct isis_area *area,
				     const struct ppr_id *ppr_id,
				     const uint8_t *sysid, uint32_t metric)
{
	struct isis_ppr *ppr;

	ppr = XCALLOC(MTYPE_ISIS_PPR, sizeof(*ppr));
	memcpy(ppr->sysid, sysid, ISIS_SYS_ID_LEN);
	ppr->id = *ppr_id;
	ppr->area = area;
	ppr->attr.metric = metric;
	ppr->position = PPR_OFF_PATH;
	ppr->status = PPR_UNINSTALLED;
	ppr->installed_label = MPLS_INVALID_LABEL;
	RB_INSERT(isis_ppr_head, &area->pprdb.ppr_list, ppr);

	return ppr;
}

static void isis_ppr_del(struct isis_ppr *ppr)
{
	struct isis_area *area = ppr->area;

	isis_zebra_uninstall_ppr(ppr);
	RB_REMOVE(isis_ppr_head, &area->pprdb.ppr_list, ppr);
	XFREE(MTYPE_ISIS_PPR, ppr);
}

static struct isis_ppr *isis_ppr_find(const struct isis_area *area,
				      const struct ppr_id *ppr_id,
				      const uint8_t *sysid, uint32_t metric)
{
	struct isis_ppr ppr = {};

	memcpy(ppr.sysid, sysid, ISIS_SYS_ID_LEN);
	ppr.id = *ppr_id;
	ppr.attr.metric = metric;
	return RB_FIND(isis_ppr_head, &area->pprdb.ppr_list, &ppr);
}

//-----------------------------------------------------------------------------

static void isis_ppr_process(struct isis_area *area, struct isis_ppr *ppr)
{
	ppr->last_change = time(NULL);
	ppr->position = PPR_OFF_PATH;
	ppr->pde_local = NULL;
	ppr->pde_next = NULL;

	/* TODO: check for loops in the PDE list. */

	/* Iterate over PPR PDE Sub-TLVs. */
	for (struct isis_ppr_pde_stlv *pde =
		     (struct isis_ppr_pde_stlv *)ppr->pdes;
	     pde; pde = pde->next) {
		/* Check if we are part of the PPR path. */
		if (!isis_ppr_on_path_check(area, &pde->info))
			continue;

		ppr->pde_local = pde;
		if (pde == (struct isis_ppr_pde_stlv *)ppr->pdes)
			ppr->position = PPR_HEAD_END;
		else if (!pde->next)
			ppr->position = PPR_TAIL_END;
		else
			ppr->position = PPR_MID_POINT;

		if (isis->debugs & DEBUG_PPR)
			zlog_debug(
				"ISIS-PPR (%s) on-path PPR-ID [%s] PDE-ID [%s]",
				area->area_tag, ppr_id2str(&ppr->id),
				ppr_pdeid2str(&pde->info));

		if (!pde->next
		    && !CHECK_FLAG(pde->flags, ISIS_PPR_PDE_FLAG_NODE)) {
			ppr->status = PPR_INSTALL_FAILURE_PDE_INVALID;
			zlog_warn(
				"ISIS-PPR (%s) last PPR PDE doesn't have the Node bit set",
				area->area_tag);
			break;
		}

		// TODO: this is a hack for PPR-MPLS. Revisit this later...
		if (pde->next)
			ppr->pde_next = pde->next;
		else
			ppr->pde_next = pde;
		isis_zebra_install_ppr(ppr);
		break;
	}

	if (ppr->position == PPR_OFF_PATH)
		isis_zebra_uninstall_ppr(ppr);
}

static void isis_ppr_verify_changes(struct isis_area *area,
				    struct isis_ppr *ppr)
{
	/* Log any PPR change in the LSPDB. */
	if (IS_DEBUG_ISIS(DEBUG_PPR)) {
		if (CHECK_FLAG(ppr->parse_flags, F_ISIS_PPR_TLV_NEW))
			zlog_debug(
				"ISIS-PPR (%s) PPR TLV created: %s (sysid %s)",
				area->area_tag, ppr_id2str(&ppr->id),
				sysid_print(ppr->sysid));
		else if (CHECK_FLAG(ppr->parse_flags, F_ISIS_PPR_TLV_MODIFIED))
			zlog_debug(
				"ISIS-PPR (%s) PPR TLV modified: %s (sysid %s)",
				area->area_tag, ppr_id2str(&ppr->id),
				sysid_print(ppr->sysid));
		else if (!CHECK_FLAG(ppr->parse_flags,
				     F_ISIS_PPR_TLV_UNCHANGED))
			zlog_debug(
				"ISIS-PPR (%s) PPR TLV removed: %s (sysid %s)",
				area->area_tag, ppr_id2str(&ppr->id),
				sysid_print(ppr->sysid));
	}

	/* Install/reinstall/uninstall PPR if necessary. */
	if (CHECK_FLAG(ppr->parse_flags, F_ISIS_PPR_TLV_NEW
						 | F_ISIS_PPR_TLV_MODIFIED
						 | F_ISIS_PPR_TLV_UNCHANGED))
		isis_ppr_process(area, ppr);
	else {
		isis_ppr_del(ppr);
		return;
	}

	ppr->parse_flags = 0;
}

#if 0
static bool isis_ppr_pde_equal(const struct isis_ppr_pde_stlv *pde1,
			       const struct isis_ppr_pde_stlv *pde2)
{
	assert(pde1 || pde2);
	if (!!pde1 != !!pde2)
		return false;

	if (pde1->flags != pde2->flags)
		return false;

	if (memcmp(&pde1->info, &pde2->info, sizeof(pde1->info)) != 0)
		return false;

	return true;
}
#endif

static bool isis_ppr_tlv_changed(const struct isis_ppr *ppr,
				 const struct isis_ppr_tlv *ppr_tlv)
{
#if 0
	struct isis_ppr_pde_stlv *pde1, *pde2;
#endif
	uint32_t metric = 0;

	/* Compare PPR fields. */
	if (ppr->flags != ppr_tlv->flags || ppr->mtid != ppr_tlv->mtid
	    || ppr->algorithm != ppr_tlv->algorithm)
		return true;

	/* Compare PPR-Prefix. */
	if (prefix_cmp(&ppr->prefix, &ppr_tlv->subtlvs->ppr.prefix->prefix)
	    != 0)
		return true;

		/* Compare PPR-PDEs. */
		/*
		 * TODO: ppr->pdes needs to be a deep copy and not a shallow
		 * copy of the PPR PDE Sub-TLVs.
		 */
#if 0
		pde1 = ppr->pdes;
		pde2 = (struct isis_ppr_pde_stlv *)ppr_tlv->subtlvs->ppr.pdes.head;
		while (pde1 != NULL || pde2 != NULL) {
			if (!isis_ppr_pde_equal(pde1, pde2))
				return true;

			pde1 = pde1->next;
			pde2 = pde2->next;
		}
#endif

	/* Compare PPR-Attributes. */
	if (ppr_tlv->subtlvs->ppr.attr.metric)
		metric = ppr_tlv->subtlvs->ppr.attr.metric->value.metric;
	if (ppr->attr.metric != metric) {
		zlog_debug(" @@@ metric change");
		return true;
	}

	return false;
}

static void isis_ppr_parse_lsp(struct isis_area *area, struct isis_lsp *lsp)
{
	/* Iterate over PPR TLVs. */
	for (struct isis_ppr_tlv *ppr_tlv =
		     (struct isis_ppr_tlv *)lsp->tlvs->ppr.head;
	     ppr_tlv; ppr_tlv = ppr_tlv->next) {
		struct isis_ppr *ppr;
		struct ppr_id *ppr_id;
		uint32_t metric = 0;

		if (ppr_tlv->subtlvs->ppr.attr.metric)
			metric =
				ppr_tlv->subtlvs->ppr.attr.metric->value.metric;

		ppr_id = &ppr_tlv->subtlvs->ppr.id->info;
		ppr = isis_ppr_find(area, ppr_id, lsp->hdr.lsp_id, metric);
		if (ppr) {
			if (isis_ppr_tlv_changed(ppr, ppr_tlv))
				SET_FLAG(ppr->parse_flags,
					 F_ISIS_PPR_TLV_MODIFIED);
			else
				SET_FLAG(ppr->parse_flags,
					 F_ISIS_PPR_TLV_UNCHANGED);
		} else {
			ppr = isis_ppr_add(area, ppr_id, lsp->hdr.lsp_id,
					   metric);
			SET_FLAG(ppr->parse_flags, F_ISIS_PPR_TLV_NEW);
		}

		/* Set/update PPR information. */
		ppr->flags = ppr_tlv->flags;
		ppr->mtid = ppr_tlv->mtid;
		ppr->algorithm = ppr_tlv->algorithm;
		ppr->prefix = ppr_tlv->subtlvs->ppr.prefix->prefix;
		ppr->pdes = (struct isis_ppr_pde_stlv *)
				    ppr_tlv->subtlvs->ppr.pdes.head;
	}
}

static void isis_ppr_parse_lspdb(struct isis_area *area)
{
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
		struct isis_lsp *lsp;

		frr_each (lspdb, &area->lspdb[level - 1], lsp) {
			if (!lsp->tlvs || lsp->hdr.rem_lifetime == 0)
				continue;

			isis_ppr_parse_lsp(area, lsp);
		}
	}
}

void isis_area_verify_ppr(struct isis_area *area)
{
	struct isis_ppr *ppr, *ppr_safe;

	if (!area->pprdb.config.enabled)
		return;

	/* Parse LSPDB to detect new/deleted/modified PPRs TLVs. */
	isis_ppr_parse_lspdb(area);

	/* Process PPR-related changes in the LDPSB. */
	RB_FOREACH_SAFE (ppr, isis_ppr_head, &area->pprdb.ppr_list, ppr_safe)
		isis_ppr_verify_changes(area, ppr);
}

void isis_area_disable_ppr(struct isis_area *area)
{
	while (!RB_EMPTY(isis_ppr_head, &area->pprdb.ppr_list)) {
		struct isis_ppr *ppr;

		ppr = RB_ROOT(isis_ppr_head, &area->pprdb.ppr_list);
		isis_ppr_del(ppr);
	}
}

//-----------------------------------------------------------------------------

struct isis_ppr_adv *isis_ppr_adv_new(struct isis_area *area, const char *name)
{
	struct isis_ppr_adv *adv;

	adv = XCALLOC(MTYPE_ISIS_PPR, sizeof(*adv));
	strlcpy(adv->name, name, sizeof(adv->name));
	adv->area = area;
	adv->group = ppr_group_find(name);
	assert(adv->group);
	RB_INSERT(isis_ppr_adv_head, &area->pprdb.config.adv_groups, adv);

	/* Regenerate local LSP. */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return adv;
}

void isis_ppr_adv_del(struct isis_ppr_adv *adv)
{
	struct isis_area *area = adv->area;

	RB_REMOVE(isis_ppr_adv_head, &area->pprdb.config.adv_groups, adv);
	XFREE(MTYPE_ISIS_PPR, adv);

	/* Regenerate local LSP. */
	lsp_regenerate_schedule(area, area->is_type, 0);
}

static struct isis_ppr_adv *isis_ppr_adv_find(struct isis_area *area,
					      const char *name)
{
	struct isis_ppr_adv adv = {};

	strlcpy(adv.name, name, sizeof(adv.name));
	return RB_FIND(isis_ppr_adv_head, &area->pprdb.config.adv_groups, &adv);
}

static int isis_ppr_group_update(struct ppr_group *group)
{
	struct listnode *node;
	struct isis_area *area;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		if (isis_ppr_adv_find(area, group->name))
			lsp_regenerate_schedule(area, area->is_type, 0);
	}

	return 0;
}

//-----------------------------------------------------------------------------

const char *isis_pprflags2str(uint16_t flags)
{
	static char buf[BUFSIZ];

	snprintf(buf, sizeof(buf), "F:%u D:%u A:%u U:%u",
		 CHECK_FLAG(flags, ISIS_PPR_FLAG_FLOOD) ? 1 : 0,
		 CHECK_FLAG(flags, ISIS_PPR_FLAG_DOWN) ? 1 : 0,
		 CHECK_FLAG(flags, ISIS_PPR_FLAG_ATTACH) ? 1 : 0,
		 CHECK_FLAG(flags, ISIS_PPR_FLAG_ULT) ? 1 : 0);

	return buf;
}

const char *isis_ppridflags2str(uint16_t flags)
{
	/* No flags definedd so far. */
	return "";
}

const char *isis_pprpdeflags2str(uint16_t flags)
{
	static char buf[BUFSIZ];

	snprintf(buf, sizeof(buf), "L:%u N:%u E:%u",
		 CHECK_FLAG(flags, ISIS_PPR_PDE_FLAG_LOOSE) ? 1 : 0,
		 CHECK_FLAG(flags, ISIS_PPR_PDE_FLAG_NODE) ? 1 : 0,
		 CHECK_FLAG(flags, ISIS_PPR_PDE_FLAG_EGRESS) ? 1 : 0);

	return buf;
}

//-----------------------------------------------------------------------------

static bool isis_ppr_show_filter(struct vty *vty, const struct isis_ppr *ppr,
				 const char *id_type, const char *id_value_str,
				 const struct prefix *id_value,
				 const char *position, const char *prefix_str,
				 const struct prefix *prefix,
				 const char *originator)
{
	/* Filter based on PPR-ID. */
	if (id_value_str) {
		if (prefix_cmp(&ppr->id.value.prefix, id_value))
			return true;
	} else if (id_type) {
		enum ppr_id_type filter;

		if (strmatch(id_type, "ipv4"))
			filter = PPR_ID_TYPE_IPV4;
		else if (strmatch(id_type, "ipv6"))
			filter = PPR_ID_TYPE_IPV6;
		else
			filter = PPR_ID_TYPE_MPLS;

		if (ppr->id.type != filter)
			return true;
	}

	/* Filter based on PPR path position. */
	if (position) {
		enum ppr_position filter;

		if (strmatch(position, "head-end"))
			filter = PPR_HEAD_END;
		else if (strmatch(position, "mid-point"))
			filter = PPR_MID_POINT;
		else
			filter = PPR_TAIL_END;

		if (ppr->position != filter)
			return true;
	}

	/* Filter based on PPR-Prefix value. */
	if (prefix_str && prefix_cmp(&ppr->prefix, prefix))
		return true;

	/* Filter based on PPR TLV originator. */
	if (originator) {
		uint8_t sysid[ISIS_SYS_ID_LEN];

		if (sysid2buff(sysid, originator) == 0) {
			struct isis_dynhn *dynhn;

			dynhn = dynhn_find_by_name(originator);
			if (dynhn == NULL) {
				vty_out(vty, "Invalid system id %s\n",
					originator);
				return CMD_SUCCESS;
			}
			memcpy(sysid, dynhn->id, ISIS_SYS_ID_LEN);
		}

		if (memcmp(ppr->sysid, sysid, ISIS_SYS_ID_LEN) != 0)
			return true;
	}

	return false;
}

static bool isis_ppr_show_brief(struct vty *vty, const char *id_type,
				const char *id_value_str,
				const struct prefix *id_value,
				const char *position, const char *prefix_str,
				const struct prefix *prefix,
				const char *originator)
{
	struct ttable *tt;
	struct listnode *node;
	struct isis_area *area;

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt,
		       "Area|Level|ID|Prefix|Metric|Position|Status|Uptime");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		struct isis_ppr *ppr;
		static char buf1[BUFSIZ];
		static char buf2[BUFSIZ];

		RB_FOREACH (ppr, isis_ppr_head, &area->pprdb.ppr_list) {
			if (isis_ppr_show_filter(
				    vty, ppr, id_type, id_value_str, id_value,
				    position, prefix_str, prefix, originator))
				continue;

			ttable_add_row(
				tt, "%s|%s|%s (%s)|%s|%u|%s|%s|%s",
				area->area_tag, circuit_t2string(area->is_type),
				ppr_id2str(&ppr->id),
				ppr_idtype2str(ppr->id.type),
				prefix2str(&ppr->prefix, buf1, sizeof(buf1)),
				ppr->attr.metric,
				ppr_position2str(ppr->position),
				ppr_status2str(ppr->status, false),
				ppr->status == PPR_INSTALL_SUCCESS
					? log_uptime(ppr->uptime, buf2,
						     sizeof(buf2))
					: "-");
		}
	}

	/* Dump the generated table. */
	if (tt->nrows > 1) {
		char *table;

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
	}
	ttable_del(tt);

	return CMD_SUCCESS;
}

static bool isis_ppr_show_detail(struct vty *vty, const char *id_type,
				 const char *id_value_str,
				 const struct prefix *id_value,
				 const char *position, const char *prefix_str,
				 const struct prefix *prefix,
				 const char *originator)
{
	struct listnode *node;
	struct isis_area *area;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		struct isis_ppr *ppr;
		static char buf[BUFSIZ];

		vty_out(vty, "Area %s:\n", area->area_tag);
		RB_FOREACH (ppr, isis_ppr_head, &area->pprdb.ppr_list) {
			struct isis_ppr_pde_stlv *pde;

			if (isis_ppr_show_filter(
				    vty, ppr, id_type, id_value_str, id_value,
				    position, prefix_str, prefix, originator))
				continue;

			vty_out(vty, "  PPR-ID: %s (%s)\n",
				ppr_id2str(&ppr->id),
				ppr_idtype2str(ppr->id.type));
			vty_out(vty, "    PPR-Prefix: %s\n",
				prefix2str(&ppr->prefix, buf, sizeof(buf)));

			vty_out(vty, "    PDEs:\n");
			for (pde = ppr->pdes; pde; pde = pde->next) {
				vty_out(vty, "      %s (%s)",
					ppr_pdeid2str(&pde->info),
					ppr_pdeidtype2str(pde->info.id_type));
				if (pde == ppr->pde_local)
					vty_out(vty, " [LOCAL]");
				else if (pde == ppr->pde_next)
					vty_out(vty, " [NEXT]");
				vty_out(vty, "\n");
			}

			vty_out(vty, "    Attributes:\n");
			vty_out(vty, "      Metric: %u\n", ppr->attr.metric);
			vty_out(vty, "    Position: %s\n",
				ppr_position2str(ppr->position));
			vty_out(vty, "    Originator: %s\n",
				sysid_print(ppr->sysid));
			vty_out(vty, "    Level: %s\n",
				circuit_t2string(area->is_type));
			vty_out(vty, "    Algorithm: %u\n", ppr->algorithm);
			vty_out(vty, "    MT-ID: %s\n",
				isis_mtid2str(ppr->mtid));
			vty_out(vty, "    Status: %s\n",
				ppr_status2str(ppr->status, true));
			if (ppr->status == PPR_INSTALL_SUCCESS)
				vty_out(vty, "      Uptime: %s\n",
					log_uptime(ppr->uptime, buf,
						   sizeof(buf)));
			vty_out(vty, "    Last change: %s\n",
				log_uptime(ppr->last_change, buf, sizeof(buf)));
			vty_out(vty, "\n");
		}
	}

	return CMD_SUCCESS;
}

/* TODO: can't use PROTO_NAME because of DEFPY. */
DEFPY(show_ppr, show_ppr_cmd,
      "show isis ppr\
	[{\
	  id <ipv4$id_type [A.B.C.D/M$id_value]|ipv6$id_type [X:X::X:X/M$id_value]|mpls$id_type>\
	  |position <head-end|mid-point|tail-end>$position\
	  |prefix <A.B.C.D/M|X:X::X:X/M>$prefix\
	  |originator WORD$originator\
	}] [detail$detail]",
      SHOW_STR PROTO_HELP
      "Preferred Path Routing\n"
      "PPR-ID\n"
      "Preferred path using IPv4 data plane\n"
      "PPR-ID address/mask\n"
      "Preferred path using IPv6 data plane\n"
      "PPR-ID address/mask\n"
      "Preferred path using MPLS data plane\n"
      "PPR path position\n"
      "Head-End of the PPR path\n"
      "Mid-Point of the PPR path\n"
      "Tail-End of the PPR path\n"
      "PPR-Prefix\n"
      "IPv4 prefix\n"
      "IPv6 prefix\n"
      "PPR TLV originator\n"
      "System-ID\n"
      "Show detailed information\n")
{
	if (detail)
		return isis_ppr_show_detail(vty, id_type, id_value_str,
					    id_value, position, prefix_str,
					    prefix, originator);

	return isis_ppr_show_brief(vty, id_type, id_value_str, id_value,
				   position, prefix_str, prefix, originator);
}

//-----------------------------------------------------------------------------

void isis_ppr_area_init(struct isis_area *area)
{
	RB_INIT(isis_ppr_head, &area->pprdb.ppr_list);
	RB_INIT(isis_ppr_adv_head, &area->pprdb.config.adv_groups);
}

void isis_ppr_area_term(struct isis_area *area)
{
	struct isis_ppr_db *pprdb = &area->pprdb;

	isis_area_disable_ppr(area);

	/* Remove PPR config. */
	while (!RB_EMPTY(isis_ppr_adv_head, &pprdb->config.adv_groups)) {
		struct isis_ppr_adv *adv;

		adv = RB_ROOT(isis_ppr_adv_head, &pprdb->config.adv_groups);
		RB_REMOVE(isis_ppr_adv_head, &pprdb->config.adv_groups, adv);
		XFREE(MTYPE_ISIS_PPR, adv);
	}
}

void isis_ppr_init(void)
{
	ppr_init();

	hook_register(ppr_group_update_hook, isis_ppr_group_update);

	install_element(VIEW_NODE, &show_ppr_cmd);
}

void isis_ppr_term(void)
{
	hook_unregister(ppr_group_update_hook, isis_ppr_group_update);
}
