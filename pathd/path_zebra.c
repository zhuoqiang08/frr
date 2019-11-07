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

#include "thread.h"
#include "log.h"
#include "lib_errors.h"
#include "if.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "linklist.h"
#include "nexthop.h"
#include "vrf.h"
#include "typesafe.h"

#include "pathd/pathd.h"

static struct zclient *zclient;

/* Install TE path in the forwarding plane. */
void te_path_install_zebra(struct te_path *path)
{
	struct te_path_nhlfe *nhlfe;
	struct zapi_labels zl;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_TE;
	zl.local_label = path->input_label;
	frr_each (tree_te_path_nhlfe, &path->nhlfes, nhlfe) {
		struct zapi_nexthop_label *znh;

		if (zl.nexthop_num >= MULTIPATH_NUM)
			break;
		znh = &zl.nexthops[zl.nexthop_num++];

		switch (nhlfe->nexthop.ipa_type) {
		case IPADDR_V4:
			znh->type = NEXTHOP_TYPE_IPV4;
			znh->family = AF_INET;
			znh->address.ipv4 = nhlfe->nexthop.ipaddr_v4;
			break;
		case IPADDR_V6:
			znh->type = NEXTHOP_TYPE_IPV6;
			znh->family = AF_INET6;
			znh->address.ipv6 = nhlfe->nexthop.ipaddr_v6;
			break;
		default:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown address-family: %u", __func__,
				 nhlfe->nexthop.ipa_type);
			exit(1);
		}
		/* znh->ifindex = ; TODO ignore the interface for now. */
		znh->label = nhlfe->labels[0];
	}

	/* Send message to zebra. */
	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_REPLACE, &zl);
}

/* Uninstall TE path from the forwarding plane. */
void te_path_uninstall_zebra(struct te_path *path)
{
	struct zapi_labels zl;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_TE;
	zl.local_label = path->input_label;

	/* Send message to zebra. */
	(void)zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_DELETE, &zl);
}

static void path_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

void path_zebra_init(struct thread_master *master)
{
	/* Initialize asynchronous zclient. */
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, ZEBRA_ROUTE_TE, 0, &pathd_privs);
	zclient->zebra_connected = path_zebra_connected;
}
