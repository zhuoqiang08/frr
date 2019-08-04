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

#ifndef _FRR_ISIS_SR_H
#define _FRR_ISIS_SR_H

#include "lib/mpls.h"
#include "lib/typesafe.h"

/*
 * Segment Routing information is transported through the following Sub-TLVs:
 *
 * Sub-TLV Name                         Value   TLVs
 * ---------------------------------------------------------------------
 * SID Label				 1
 *
 * Prefix Segment Identifier		 3	135, 235, 236 and 237
 *
 * Adjacency Segment Identifier		31	22, 23, 141, 222 and 223
 * LAN Adjacency Segment Identifier	32	22, 23, 141, 222 and 223
 *
 * Segment Routing Capability		 2	242
 * Segment Routing Algorithm		19	242
 * Node Maximum Stack Depth (MSD)	23	242
 *
 * Sub-TLV definitions, serialization and de-serialization are defined
 * in isis_tlvs.[c,h].
 */

PREDECL_RBTREE_UNIQ(tree_sr_node)
PREDECL_RBTREE_UNIQ(tree_sr_node_prefix)
PREDECL_RBTREE_UNIQ(tree_sr_area_prefix)
PREDECL_RBTREE_UNIQ(tree_sr_prefix_cfg)

/* SR Prefix-SID. */
struct sr_prefix {
	/* RB-tree entries. */
	struct tree_sr_node_prefix_item node_entry;
	struct tree_sr_area_prefix_item area_entry;

	/* IP prefix. */
	struct prefix prefix;

	/* SID value, algorithm and flags. */
	struct isis_prefix_sid sid;

	/* This is set for local Prefix-SIDs. */
	bool local;

	/* Local label value. */
	mpls_label_t installed_label;

	/* Backpointer to SR node. */
	struct sr_node *srn;

	/* Flags used while the LSPDB is being parsed. */
	uint8_t parse_flags;
#define F_ISIS_SR_PREFIX_SID_NEW	0x01
#define F_ISIS_SR_PREFIX_SID_MODIFIED	0x02
#define F_ISIS_SR_PREFIX_SID_UNCHANGED	0x04
};

/* SR node. */
struct sr_node {
	/* RB-tree entry. */
	struct tree_sr_node_item entry;

	/* IS-IS node identifier. */
	uint8_t sysid[ISIS_SYS_ID_LEN];

	/* IS-IS node SRGB (Segment Routing Global Block). */
	struct isis_srgb srgb;

	/* List of Prefix-SIDs advertised by this node. */
	struct tree_sr_node_prefix_head prefix_sids;

	/* Backpointer to IS-IS area. */
	struct isis_area *area;

	/* Flags used while the LSPDB is being parsed. */
	uint8_t parse_flags;
#define F_ISIS_SR_NODE_NEW		0x01
#define F_ISIS_SR_NODE_MODIFIED		0x02
#define F_ISIS_SR_NODE_UNCHANGED	0x04
};

/* NOTE: these values must be in sync with the YANG module. */
enum sr_sid_value_type {
	SR_SID_VALUE_TYPE_INDEX = 0,
	SR_SID_VALUE_TYPE_ABSOLUTE = 1,
};

/* NOTE: these values must be in sync with the YANG module. */
enum sr_last_hop_behavior {
	SR_LAST_HOP_BEHAVIOR_EXP_NULL = 0,
	SR_LAST_HOP_BEHAVIOR_NO_PHP = 1,
	SR_LAST_HOP_BEHAVIOR_PHP = 2,
};

/* SR Prefix-SID configuration. */
struct sr_prefix_cfg {
	/* RB-tree entry. */
	struct tree_sr_prefix_cfg_item entry;

	/* IP prefix. */
	struct prefix prefix;

	/* SID value. */
	uint32_t sid;

	/* SID value type. */
	enum sr_sid_value_type sid_type;

	/* SID last hop behavior. */
	enum sr_last_hop_behavior last_hop_behavior;

	/* SID flags. */
	uint8_t flags;

	/* Backpointer to IS-IS area. */
	struct isis_area *area;
};

/* Per-area IS-IS Segment Routing information. */
struct isis_sr_db {
	/* Operational status of Segment Routing. */
	bool enabled;

	/* SR information from all nodes. */
	struct tree_sr_node_head sr_nodes;

	/* Prefix-SIDs. */
	struct tree_sr_area_prefix_head prefix_sids;

	/* Area SR configuration. */
	struct {
		/* Administrative status of Segment Routing. */
		bool enabled;

		/* Segment Routing Global Block lower & upper bound. */
		uint32_t srgb_lower_bound;
		uint32_t srgb_upper_bound;

		/* Maximum SID Depth supported by the node. */
		uint8_t msd;

		/* Prefix-SID mappings. */
		struct tree_sr_prefix_cfg_head prefix_sids;
	} config;
};

/* Prototypes. */
extern int isis_sr_cfg_srgb_update(struct isis_area *area, uint32_t lower_bound,
				   uint32_t upper_bound);
extern void isis_sr_cfg_msd_update(struct isis_area *area);
extern struct sr_prefix_cfg *
isis_sr_cfg_prefix_add(struct isis_area *area, const struct prefix *prefix);
extern void isis_sr_cfg_prefix_del(struct sr_prefix_cfg *pcfg);
extern struct sr_prefix_cfg *
isis_sr_cfg_prefix_find(struct isis_area *area, union prefixconstptr prefix);
extern void isis_sr_prefix_cfg2subtlv(const struct sr_prefix_cfg *pcfg,
				      bool external,
				      struct isis_prefix_sid *psid);
extern void isis_area_verify_sr(struct isis_area *area);
extern int isis_sr_start(struct isis_area *area);
extern void isis_sr_stop(struct isis_area *area);
extern void isis_sr_area_init(struct isis_area *area);
extern void isis_sr_area_term(struct isis_area *area);
extern void isis_sr_init(void);
extern void isis_sr_term(void);

#endif /* _FRR_ISIS_SR_H */
