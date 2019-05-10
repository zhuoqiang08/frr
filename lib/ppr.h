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

#ifndef FRR_PPR_H
#define FRR_PPR_H

#include <zebra.h>

#include "openbsd-tree.h"
#include "hook.h"
#include "prefix.h"
#include "yang.h"

#define SR_ALGORITHM_SPF	1
#define SR_ALGORITHM_STRICT_SPF	2

/* PPR-ID */
enum ppr_id_type {
	PPR_ID_TYPE_MPLS = 1,
	PPR_ID_TYPE_IPV4 = 2,
	PPR_ID_TYPE_IPV6 = 3,
	PPR_ID_TYPE_SRV6 = 4,
};

struct ppr_id {
	enum ppr_id_type type;
	union {
		uint32_t mpls;
		struct prefix prefix;
	} value;
};

struct ppr_id_node {
	RB_ENTRY(ppr_id_node) entry;

	/* PPR-ID information. */
	struct ppr_id info;
};
RB_HEAD(ppr_id_node_head, ppr_id_node);
RB_PROTOTYPE(ppr_id_node_head, ppr_id_node, entry, ppr_id_node_compare);

struct ppr_cfg {
	/* PPR-ID information. */
	struct ppr_id_node id;

	/* PPR-Prefix information. */
	struct prefix prefix;

	/* Ordered list of PPR-PDEs. */
	struct list *pdes;

	/* Backpointer to PPR group. */
	struct ppr_group *group;

	/* PPR metric attribute. */
	uint32_t metric;
};

/* PPR-PDE */
enum ppr_pde_type {
	PPR_PDE_TYPE_TOPOLOGICAL = 1,
	PPR_PDE_TYPE_NON_TOPOLOGICAL = 2,
};

enum ppr_pde_id_type {
	PPR_PDE_ID_TYPE_NON_TOPOLOGICAL = 0,
	PPR_PDE_ID_TYPE_SID_LABEL = 1,
	PPR_PDE_ID_TYPE_SRMPLS_PREFIX_SID = 2,
	PPR_PDE_ID_TYPE_SRMPLS_ADJ_SID = 3,
	PPR_PDE_ID_TYPE_IPV4_NODE_ADDR = 4,
	PPR_PDE_ID_TYPE_IPV4_IFACE_ADDR = 5,
	PPR_PDE_ID_TYPE_IPV6_NODE_ADDR = 6,
	PPR_PDE_ID_TYPE_IPV6_IFACE_ADDR = 7,
	PPR_PDE_ID_TYPE_SRV6_NODE_SID = 8,
	PPR_PDE_ID_TYPE_SRV6_ADJ_SID = 9,
};

struct ppr_pde {
	enum ppr_pde_type type;
	enum ppr_pde_id_type id_type;
	union {
		uint32_t mpls;
		struct prefix prefix;
	} id_value;
	bool loose;
};

struct ppr_pde_cfg {
	/* PPR-PDE information. */
	struct ppr_pde pde;

	/* Backpointer to PPR configuration. */
	struct ppr_cfg *ppr;
};

/* PPR Group. */
struct ppr_group {
	RB_ENTRY(ppr_group) entry;

	/* Group name. */
	char name[128];

	/* List of PPR paths. */
	struct ppr_id_node_head ppr_list;
};
RB_HEAD(ppr_group_head, ppr_group);
RB_PROTOTYPE(ppr_group_head, ppr_group, entry, ppr_group_compare)

/* PPR path position. */
enum ppr_position {
	PPR_OFF_PATH = 0,
	PPR_HEAD_END,
	PPR_MID_POINT,
	PPR_TAIL_END,
};

/* PPR forwarding status. */
enum ppr_forwarding_status {
	PPR_UNINSTALLED = 0,
	PPR_INSTALL_SUCCESS,
	PPR_INSTALL_FAILURE_PDE_UNREACHABLE,
	PPR_INSTALL_FAILURE_PDE_LOCAL,
	PPR_INSTALL_FAILURE_PDE_NOT_ADJ,
	PPR_INSTALL_FAILURE_PDE_INVALID,
};

DECLARE_HOOK(ppr_group_update_hook, (struct ppr_group *), (group))

/* PPR northbound information. */
extern const struct frr_yang_module_info frr_ppr_info;

/* Prototypes. */
extern int ppr_id_compare(const struct ppr_id *a, const struct ppr_id *b);
extern struct ppr_group *ppr_group_find(const char *name);
extern const char *ppr_algo2str(uint8_t algorithm);
extern const char *ppr_idtype2str(enum ppr_id_type type);
extern const char *ppr_id2str(const struct ppr_id *i);
extern const char *ppr_pdetype2str(enum ppr_pde_type type);
extern const char *ppr_pdeidtype2str(enum ppr_pde_id_type type);
extern const char *ppr_pdeid2str(const struct ppr_pde *p);
extern const char *ppr_position2str(enum ppr_position position);
extern const char *ppr_status2str(enum ppr_forwarding_status status,
				  bool extended);

extern void ppr_init(void);

#endif /* FRR_PPR_H */
