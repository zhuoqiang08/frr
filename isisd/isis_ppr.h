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

#ifndef ISIS_PPR_H
#define ISIS_PPR_H

#include <zebra.h>

#include "openbsd-tree.h"
#include "ppr.h"

#include "isisd/isisd.h"
#include "isisd/isis_tlvs.h"

/* PPR-ID node. */
struct isis_ppr {
	RB_ENTRY(isis_ppr) entry;

	/* IS-IS node identifier. */
	uint8_t sysid[ISIS_SYS_ID_LEN];

	/* PPR-ID information. */
	struct ppr_id id;
	uint16_t flags;
	uint16_t mtid;
	uint8_t algorithm;

	/* PPR-Prefix information. */
	struct prefix prefix;

	/* Ordered list of PPR-PDEs. */
	struct isis_ppr_pde_stlv *pdes;
	struct isis_ppr_pde_stlv *pde_local;
	struct isis_ppr_pde_stlv *pde_next;

	/* PPR-Attributes. */
	struct {
		uint32_t metric;
	} attr;

	/* PPR path position. */
	enum ppr_position position;

	/* PPR forwarding status. */
	enum ppr_forwarding_status status;

	/* Local label value (PPR-MPLS). */
	mpls_label_t installed_label;

	/* PPR uptime and last change. */
	time_t uptime;
	time_t last_change;

	/* Backpointer to IS-IS area. */
	struct isis_area *area;

	/* Flags used while the LSPDB is being parsed. */
	uint8_t parse_flags;
};
RB_HEAD(isis_ppr_head, isis_ppr);
RB_PROTOTYPE(isis_ppr_head, isis_ppr, entry, isis_ppr_compare);

#define F_ISIS_PPR_TLV_NEW 0x01
#define F_ISIS_PPR_TLV_MODIFIED 0x02
#define F_ISIS_PPR_TLV_UNCHANGED 0x04

/* PPR group advertisement list. */
struct isis_ppr_adv {
	RB_ENTRY(isis_ppr_advertise) entry;

	/* Group name. */
	char name[128];

	/* Backpointer to IS-IS area. */
	struct isis_area *area;

	/* PPR Group. */
	struct ppr_group *group;
};
RB_HEAD(isis_ppr_adv_head, isis_ppr_adv);
RB_PROTOTYPE(isis_ppr_adv_head, isis_ppr_adv, entry, isis_ppr_adv_compare);

/* Per-area PPR information. */
struct isis_ppr_db {
	/* PPR paths in the IS-IS area. */
	struct isis_ppr_head ppr_list;

	/* IS-IS PPR configuration. */
	struct {
		bool enabled;
		struct isis_ppr_adv_head adv_groups;
	} config;
};

/* Prototypes. */
extern struct isis_route_info *
isis_area_find_route_spftree(const struct isis_area *area,
			     const struct prefix *prefix);
extern struct isis_ppr_adv *isis_ppr_adv_new(struct isis_area *area,
					     const char *name);
extern void isis_ppr_adv_del(struct isis_ppr_adv *adv);
extern const char *isis_pprflags2str(uint16_t flags);
extern const char *isis_ppridflags2str(uint16_t flags);
extern const char *isis_pprpdeflags2str(uint16_t flags);
extern void isis_area_verify_ppr(struct isis_area *area);
extern void isis_area_disable_ppr(struct isis_area *area);
extern void isis_ppr_area_init(struct isis_area *area);
extern void isis_ppr_area_term(struct isis_area *area);
extern void isis_ppr_init(void);
extern void isis_ppr_term(void);

#endif /* ISIS_PPR_H */
