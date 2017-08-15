/* MPLS forwarding table updates using netlink over GNU/Linux system.
 * Copyright (C) 2016  Cumulus Networks, Inc.
 *
 * This file is part of Quagga.
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

#ifdef HAVE_NETLINK

#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_rnh.h"

/*
 * Install Label Forwarding entry into the kernel.
 */
int kernel_add_lsp(zebra_lsp_t *lsp)
{
	int ret;

	if (!lsp || !lsp->best_nhlfe) // unexpected
		return -1;

	UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);
	ret = netlink_mpls_multipath(RTM_NEWROUTE, lsp, NULL);
	if (!ret)
		SET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
	else
		clear_nhlfe_installed(lsp);

	return ret;
}

/*
 * Update Label Forwarding entry in the kernel. This means that the Label
 * forwarding entry is already installed and needs an update - either a new
 * path is to be added, an installed path has changed (e.g., outgoing label)
 * or an installed path (but not all paths) has to be removed.
 * TODO: Performs a DEL followed by ADD now, need to change to REPLACE. Note
 * that REPLACE was originally implemented for IPv4 nexthops but removed as
 * it was not functioning when moving from swap to PHP as that was signaled
 * through the metric field (before kernel-MPLS). This shouldn't be an issue
 * any longer, so REPLACE can be reintroduced.
 */
int kernel_upd_lsp(zebra_lsp_t *lsp)
{
	int ret;

	if (!lsp || !lsp->best_nhlfe) // unexpected
		return -1;

	UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);

	/* First issue a DEL and clear the installed flag. */
	netlink_mpls_multipath(RTM_DELROUTE, lsp, NULL);
	UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);

	/* Then issue an ADD. */
	ret = netlink_mpls_multipath(RTM_NEWROUTE, lsp, NULL);
	if (!ret)
		SET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
	else
		clear_nhlfe_installed(lsp);

	return ret;
}

/*
 * Delete Label Forwarding entry from the kernel.
 */
int kernel_del_lsp(zebra_lsp_t *lsp)
{
	if (!lsp) // unexpected
		return -1;

	if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED)) {
		netlink_mpls_multipath(RTM_DELROUTE, lsp, NULL);
		UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
	}

	return 0;
}

static struct nexthop *pw_nexthops(struct nexthop *nh, mpls_label_t pwlabel)
{
	struct nexthop *nexthop, *out = NULL;
	struct nexthop *nh1;

	for (nh1 = nh; nh1; nh1 = nh1->next) {
		nexthop = nexthop_new();
		nexthop->ifindex = nh1->ifindex;
		nexthop->type = nh1->type;
		nexthop->flags = nh1->flags;
		memcpy(&nexthop->gate, &nh1->gate, sizeof(nh1->gate));
		memcpy(&nexthop->src, &nh1->src, sizeof(nh1->src));
		memcpy(&nexthop->rmap_src, &nh1->rmap_src, sizeof(nh1->rmap_src));
		nexthop->rparent = NULL;

		struct nexthop_label *nh1l = nh1->nh_label;
		size_t newlabels = nh1l ? nh1l->num_labels + 1 : 1;
		mpls_label_t labels[newlabels];
		if (nh1l && nh1l->num_labels) {
			memcpy(labels, nh1l->label,
			       nh1l->num_labels * sizeof(labels[0]));
			if (labels[newlabels - 2] == MPLS_IMP_NULL_LABEL)
				newlabels--;
		}
		labels[newlabels - 1] = pwlabel;

		nexthop_add_labels(nexthop, ZEBRA_LSP_NONE, newlabels, labels);
		nexthop_add(&out, nexthop);
	}
	return out;
}

static int kernel_pw(struct zebra_pw *pw, int op)
{
	zebra_lsp_t lsp;
	zebra_nhlfe_t nhlfe;
	struct netlink_pw npw;
	int ret;

	if (op == RTM_NEWROUTE && (!pw->rnh || !pw->rnh->state)) {
		zlog_warn("PW RNH unavailable");
		return -1;
	}
	if (pw->group_ifindex == 0 || pw->group_ifindex == IFINDEX_INTERNAL)
		return -1;

	memset(&lsp, 0, sizeof(lsp));
	lsp.ile.in_label = pw->local_label;
	lsp.nhlfe_list = &nhlfe;
	lsp.num_ecmp = 1;

	memset(&nhlfe, 0, sizeof(nhlfe));
	nhlfe.lsp = &lsp;
	nhlfe.type = ZEBRA_LSP_NONE;
	nhlfe.flags = (op == RTM_NEWROUTE) ? NHLFE_FLAG_SELECTED
					   : NHLFE_FLAG_INSTALLED;
	nhlfe.distance = 1;
	if (op == RTM_NEWROUTE)
		nhlfe.nexthop = pw_nexthops(pw->rnh->state->nexthop,
					    pw->remote_label);
	
	npw.ifindex = pw->group_ifindex;
	npw.use_cw = !!(pw->flags & F_PSEUDOWIRE_CWORD);

	ret = netlink_mpls_multipath(op, &lsp, &npw);

	nexthops_free(nhlfe.nexthop);
	return ret;
}

static int kernel_pw_install(struct zebra_pw *pw)
{
	return kernel_pw(pw, RTM_NEWROUTE);
}

static int kernel_pw_uninstall(struct zebra_pw *pw)
{
	return kernel_pw(pw, RTM_DELROUTE);
}

int mpls_kernel_init(void)
{
	struct stat st;

	/*
	 * Check if the MPLS module is loaded in the kernel.
	 */
	if (stat("/proc/sys/net/mpls", &st) != 0)
		return -1;

	hook_register(pw_install, kernel_pw_install);
	hook_register(pw_uninstall, kernel_pw_uninstall);

	return 0;
};

#endif /* HAVE_NETLINK */
