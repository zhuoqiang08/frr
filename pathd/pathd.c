/*
 * Copyright (C) 2019  NetDEF, Inc.
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

#include "memory.h"
#include "log.h"
#include "lib_errors.h"

#include "pathd/pathd.h"
#include "pathd/path_memory.h"

DEFINE_MTYPE_STATIC(PATHD, PATH_INFO, "TE path information")
DEFINE_MTYPE_STATIC(PATHD, PATH_NHLFE, "TE NHLFE information")

int te_path_nhlfe_compare(const struct te_path_nhlfe *a,
			  const struct te_path_nhlfe *b)
{
	if (a->nexthop.ipa_type < b->nexthop.ipa_type)
		return -1;
	if (a->nexthop.ipa_type > b->nexthop.ipa_type)
		return 1;

	switch (a->nexthop.ipa_type) {
	case IPADDR_V4:
		if (a->nexthop.ipaddr_v4.s_addr == b->nexthop.ipaddr_v4.s_addr)
			return (0);
		return ((ntohl(a->nexthop.ipaddr_v4.s_addr)
			 > ntohl(b->nexthop.ipaddr_v4.s_addr))
				? 1
				: -1);
	case IPADDR_V6:
		return (memcmp(&a->nexthop.ipaddr_v6, &b->nexthop.ipaddr_v6,
			       sizeof(struct in6_addr)));
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown address-family: %u",
			 __func__, a->nexthop.ipa_type);
		exit(1);
	}
}

int te_path_compare(const struct te_path *a, const struct te_path *b)
{
	return a->input_label - b->input_label;
}

struct tree_te_path_head te_paths;

/*----------------------------------------------------------------------------*/

struct te_path *te_path_add(mpls_label_t input_label)
{
	struct te_path *path;

	path = XCALLOC(MTYPE_PATH_INFO, sizeof(*path));
	path->input_label = input_label;
	tree_te_path_nhlfe_init(&path->nhlfes);
	tree_te_path_add(&te_paths, path);

	return path;
}

void te_path_del(struct te_path *path)
{
	te_path_uninstall_zebra(path);
	tree_te_path_del(&te_paths, path);
	XFREE(MTYPE_PATH_INFO, path);
}

struct te_path *te_path_find(mpls_label_t input_label)
{
	struct te_path path = {};

	path.input_label = input_label;
	return tree_te_path_find(&te_paths, &path);
}

struct te_path_nhlfe *te_path_nhlfe_add(struct te_path *path,
					struct ipaddr *nexthop)
{
	struct te_path_nhlfe *nhlfe;

	nhlfe = XCALLOC(MTYPE_PATH_NHLFE, sizeof(*nhlfe));
	nhlfe->nexthop = *nexthop;
	nhlfe->pref = yang_get_default_uint32(
		"/frr-pathd:pathd/mpls/lsp/nhlfe/preference");
	nhlfe->path = path;
	tree_te_path_nhlfe_add(&path->nhlfes, nhlfe);

	return nhlfe;
}

void te_path_nhlfe_del(struct te_path_nhlfe *nhlfe)
{
	tree_te_path_nhlfe_del(&nhlfe->path->nhlfes, nhlfe);
	XFREE(MTYPE_PATH_NHLFE, nhlfe);
}

struct te_path_nhlfe *te_path_nhlfe_find(struct te_path *path,
					 struct ipaddr *nexthop)
{
	struct te_path_nhlfe nhlfe = {};

	nhlfe.nexthop = *nexthop;
	return tree_te_path_nhlfe_find(&path->nhlfes, &nhlfe);
}
