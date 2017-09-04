/*
 * CLI/command dummy handling tester
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "plist.h"
#include "lib/cli/common_cli.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"

#include "bgpd/test_rmap_clippy.c"

struct zebra_privs_t *bgpd_privs = NULL;

static struct bgp s_bgp, *bgp = &s_bgp;
static struct peer s_peer, *peer = &s_peer;
static struct attr s_attr, *attr = &s_attr;

static void do_test_exit(void)
{
	if (attr->aspath)
		aspath_unintern(&attr->aspath);
	if (attr->lcommunity)
		lcommunity_unintern(&attr->lcommunity);

	bgp_fini();
}

DEFUN(set_aspath, set_aspath_cmd,
      "test set aspath ASPATH...",
      "test\nset\naspath\naspath\n")
{
	char *str;
	if (attr->aspath)
		aspath_unintern(&attr->aspath);

	str = argv_concat(argv + 3, argc - 3, 0);
	attr->aspath = aspath_str2aspath(str);
	XFREE(MTYPE_TMP, str);

	if (attr->aspath) {
		attr->aspath = aspath_intern(attr->aspath);
		aspath_print_vty(vty, "ASpath: %s\n", attr->aspath, "");
	} else
		vty_out(vty, "as-path cleared\n");

	return CMD_SUCCESS;
}

DEFUN(set_lcom, set_lcom_cmd,
      "test set lcommunity LCOM...",
      "test\nset\nlcommunity\nlarge community\n")
{
	char *str;
	if (attr->lcommunity)
		lcommunity_unintern(&attr->lcommunity);

	str = argv_concat(argv + 3, argc - 3, 0);
	attr->lcommunity = lcommunity_str2com(str);
	XFREE(MTYPE_TMP, str);

	if (attr->lcommunity) {
		attr->lcommunity = lcommunity_intern(attr->lcommunity);
		vty_out(vty, "lcom %s\n", lcommunity_str(attr->lcommunity));
	} else
		vty_out(vty, "lcom cleared\n");

	return CMD_SUCCESS;
}

DEFPY(eval_rmap, eval_rmap_cmd,
      "test evaluate <A.B.C.D/M|X:X::X:X/M>$prefix route-map RMAPNAME <out$out|in$in>",
      "test\nevaluate\nprefix\nroute-map\nroute-map name\nmode: out\nmode: in\n")
{
	/* struct bgp_info_extra dummy_info_extra; */
	struct route_map *rmap;
	struct attr attr_copy;
	struct bgp_info info = {
		.peer = peer,
		.attr = &attr_copy,
	};
	struct prefix p;
	int ret;

	rmap = route_map_lookup_by_name(rmapname);
	if (!rmap) {
		vty_out(vty, "no such route-map %s\n", rmapname);
		return CMD_WARNING;
	}
		
	attr_copy = *attr;
	if (out)
		SET_FLAG(peer->rmap_type, PEER_RMAP_TYPE_OUT);
	else if (in)
		SET_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IN);
	else
		vty_out(vty, "wtf mode?\n");

	p = *prefix;
	ret = route_map_apply(rmap, &p, RMAP_BGP, &info);

	vty_out(vty, "as-path %s\n", attr_copy.aspath
		? aspath_print(attr_copy.aspath)
		: "(null)");
	if (attr->aspath != attr_copy.aspath) {
		vty_out(vty, "AS-path modified\n\n");
		if (attr_copy.aspath) {
			assert(attr_copy.aspath->refcnt == 0);
			aspath_free(attr_copy.aspath);
		}
	}

	vty_out(vty, "lcom %s\n", attr_copy.lcommunity
		? lcommunity_str(attr_copy.lcommunity)
		: "(null)");
	if (attr->lcommunity != attr_copy.lcommunity) {
		vty_out(vty, "large communities modified\n\n");
		if (attr_copy.lcommunity) {
			assert(attr_copy.lcommunity->refcnt == 0);
			lcommunity_free(&attr_copy.lcommunity);
		}
	}

	switch (ret) {
	case RMAP_MATCH:
		vty_out(vty, "RMAP_MATCH\n\n");
		break;
	case RMAP_DENYMATCH:
		vty_out(vty, "RMAP_DENYMATCH\n\n");
		break;
	case RMAP_NOMATCH:
		vty_out(vty, "RMAP_NOMATCH\n\n");
		break;
	case RMAP_ERROR:
		vty_out(vty, "RMAP_ERROR\n\n");
		break;
	case RMAP_OKAY:
		vty_out(vty, "RMAP_OKAY\n\n");
		break;
	default:
		vty_out(vty, "??? ret = %d\n\n", ret);
		break;
	}
	return CMD_SUCCESS;
}

void test_init(int argc, char **argv)
{
	bgp_master_init(master);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	bgp_init();

	test_exit = do_test_exit;

	memset(&s_bgp, 0, sizeof(s_bgp));
	memset(&s_peer, 0, sizeof(s_peer));
	memset(&s_attr, 0, sizeof(s_attr));

	peer->bgp = bgp;
	peer->host = (char *)"none";
	peer->fd = -1;

	install_element(ENABLE_NODE, &eval_rmap_cmd);
	install_element(ENABLE_NODE, &set_aspath_cmd);
	install_element(ENABLE_NODE, &set_lcom_cmd);
}
