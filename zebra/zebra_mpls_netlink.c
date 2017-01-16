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
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_mpls.h"
#include "znl.h"
#include "zbuf.h"
#include "privs.h"
#include <linux/genetlink.h>

int genlfd = -1;
uint16_t vpls_family = -1;
extern struct zebra_privs_t zserv_privs;

/*
 * Install Label Forwarding entry into the kernel.
 */
int
kernel_add_lsp (zebra_lsp_t *lsp)
{
  int ret;

  if (!lsp || !lsp->best_nhlfe) // unexpected
    return -1;

  UNSET_FLAG (lsp->flags, LSP_FLAG_CHANGED);
  ret = netlink_mpls_multipath (RTM_NEWROUTE, lsp);
  if (!ret)
    SET_FLAG (lsp->flags, LSP_FLAG_INSTALLED);
  else
    clear_nhlfe_installed (lsp);

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
int
kernel_upd_lsp (zebra_lsp_t *lsp)
{
  int ret;

  if (!lsp || !lsp->best_nhlfe) // unexpected
    return -1;

  UNSET_FLAG (lsp->flags, LSP_FLAG_CHANGED);

  /* First issue a DEL and clear the installed flag. */
  netlink_mpls_multipath (RTM_DELROUTE, lsp);
  UNSET_FLAG (lsp->flags, LSP_FLAG_INSTALLED);

  /* Then issue an ADD. */
  ret = netlink_mpls_multipath (RTM_NEWROUTE, lsp);
  if (!ret)
    SET_FLAG (lsp->flags, LSP_FLAG_INSTALLED);
  else
    clear_nhlfe_installed (lsp);

  return ret;
}

/*
 * Delete Label Forwarding entry from the kernel.
 */
int
kernel_del_lsp (zebra_lsp_t *lsp)
{
  if (!lsp) // unexpected
    return -1;

  if (CHECK_FLAG (lsp->flags, LSP_FLAG_INSTALLED))
    {
      netlink_mpls_multipath (RTM_DELROUTE, lsp);
      UNSET_FLAG (lsp->flags, LSP_FLAG_INSTALLED);
    }

  return 0;
}

enum {
	VPLS_ATTR_UNSPEC = 0,
	VPLS_ATTR_IFINDEX,
	VPLS_ATTR_WIREID,
	VPLS_ATTR_LABEL_IN,
	VPLS_ATTR_LABEL_OUT,
	VPLS_ATTR_NH_DEV,
	VPLS_ATTR_NH_IP,
	__VPLS_ATTR_MAX,
};
#define VPLS_ATTR_MAX (__VPLS_ATTR_MAX - 1)

enum {
	VPLS_CMD_UNSPEC = 0,

	VPLS_CMD_NEWWIRE = 4,
	VPLS_CMD_DELWIRE,
	VPLS_CMD_GETWIRE,
	VPLS_CMD_SETWIRE,
	__VPLS_CMD_MAX,
};
#define VPLS_CMD_MAX (__VPLS_CMD_MAX - 1)

int
mpls_pw_update(ifindex_t vplsif, unsigned wire,
               int af, union g_addr *gate,
               unsigned in_label, unsigned out_label, ifindex_t oif)
{
  struct zbuf *zb = zbuf_alloc(512), zpl;
  struct nlmsghdr *nlh;
  struct genlmsghdr *ghdr;

#define zlog_warn(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
  if (af != AF_INET)
          return 1;

  nlh = znl_nlmsg_push(zb, vpls_family, NLM_F_CREATE | NLM_F_EXCL
                  | NLM_F_REQUEST | NLM_F_ACK);
  ghdr = znl_push(zb, sizeof(*ghdr));
  ghdr->cmd = VPLS_CMD_NEWWIRE;
  ghdr->version = 1;
  znl_rta_push_u32(zb, VPLS_ATTR_IFINDEX, vplsif);
  znl_rta_push_u32(zb, VPLS_ATTR_WIREID, wire);
  znl_rta_push_u32(zb, VPLS_ATTR_LABEL_IN, in_label);
  znl_rta_push_u32(zb, VPLS_ATTR_LABEL_OUT, out_label);
  znl_rta_push_u32(zb, VPLS_ATTR_NH_DEV, oif);
  znl_rta_push_u32(zb, VPLS_ATTR_NH_IP, gate->ipv4.s_addr);
  char buf[64];
  zlog_warn("upd if %u wire %u in %u out %u oif %u gate %s",
           vplsif, wire, in_label, out_label, oif, inet_ntop(AF_INET,
		   &gate->ipv4, buf, sizeof(buf)));
  znl_nlmsg_complete(zb, nlh);

  zserv_privs.change (ZPRIVS_RAISE);

  genlfd = znl_open(NETLINK_GENERIC, 0);
  if (zbuf_send(zb, genlfd) <= 0) {
    zlog_warn("failed to send vpls request: %s", safe_strerror(errno));
    zbuf_free(zb);
    return 1;
  };
  zbuf_reset(zb);

  if (zbuf_recv(zb, genlfd) <= 0) {
    zlog_warn("failed to recv vpls response: %s", safe_strerror(errno));
    zbuf_free(zb);
    return 1;
  } else {
    zlog_warn("vpls response received");
  }
  close(genlfd);

  zserv_privs.change (ZPRIVS_LOWER);

  nlh = znl_nlmsg_pull(zb, &zpl);
  if (nlh->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(nlh);
    if (err->error) {
      zlog_warn("vpls error response: %s", safe_strerror(err->error));
      zbuf_free(zb);
      return 1;
    } else {
      zlog_warn("vpls error = OK");
    }
  } else {
    zlog_warn("vpls response wtf %d", nlh->nlmsg_type);
  }

  zbuf_free(zb);
  return 0;
}

int
mpls_pw_delete(ifindex_t vplsif, unsigned wire)
{
  struct zbuf *zb = zbuf_alloc(512), zpl;
  struct nlmsghdr *nlh;
  struct genlmsghdr *ghdr;

#define zlog_warn(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while (0)

  nlh = znl_nlmsg_push(zb, vpls_family, NLM_F_REQUEST | NLM_F_ACK);
  ghdr = znl_push(zb, sizeof(*ghdr));
  ghdr->cmd = VPLS_CMD_DELWIRE;
  ghdr->version = 1;
  znl_rta_push_u32(zb, VPLS_ATTR_IFINDEX, vplsif);
  znl_rta_push_u32(zb, VPLS_ATTR_WIREID, wire);
  zlog_warn("delete if %u wire %u", vplsif, wire);
  znl_nlmsg_complete(zb, nlh);

  zserv_privs.change (ZPRIVS_RAISE);

  genlfd = znl_open(NETLINK_GENERIC, 0);
  if (zbuf_send(zb, genlfd) <= 0) {
    zlog_warn("failed to send vpls request: %s", safe_strerror(errno));
    zbuf_free(zb);
    return 1;
  };
  zbuf_reset(zb);

  if (zbuf_recv(zb, genlfd) <= 0) {
    zlog_warn("failed to recv vpls response: %s", safe_strerror(errno));
    zbuf_free(zb);
    return 1;
  } else {
    zlog_warn("vpls response received");
  }
  close(genlfd);

  zserv_privs.change (ZPRIVS_LOWER);

  nlh = znl_nlmsg_pull(zb, &zpl);
  if (nlh->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(nlh);
    if (err->error) {
      zlog_warn("vpls error response: %s", safe_strerror(err->error));
      zbuf_free(zb);
      return 1;
    } else {
      zlog_warn("vpls error = OK");
    }
  } else {
    zlog_warn("vpls response wtf %d", nlh->nlmsg_type);
  }

  zbuf_free(zb);
  return 0;
}

int
mpls_kernel_init (void)
{
  struct stat st;

  /*
   * Check if the MPLS module is loaded in the kernel.
   */
  if (stat ("/proc/sys/net/mpls", &st) != 0)
    return -1;

  genlfd = znl_open(NETLINK_GENERIC, 0);
  if (genlfd < 0) {
    zlog_warn("failed to open genl socket: %s", safe_strerror(errno));
    return 0;
  }

  struct zbuf *zb = zbuf_alloc(512), zpl, za;
  struct nlmsghdr *nlh;
  struct genlmsghdr *ghdr;

  nlh = znl_nlmsg_push(zb, GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);
  ghdr = znl_push(zb, sizeof(*ghdr));
  ghdr->cmd = CTRL_CMD_GETFAMILY;
  znl_rta_push(zb, CTRL_ATTR_FAMILY_NAME, "vpls", 5);
  znl_nlmsg_complete(zb, nlh);

#define zlog_warn(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
  if (zbuf_send(zb, genlfd) <= 0) {
    zlog_warn("failed to send genl request: %s", safe_strerror(errno));
    zbuf_free(zb);
    return 0;
  };
  zbuf_reset(zb);

  if (zbuf_recv(zb, genlfd) <= 0) {
    zlog_warn("failed to recv genl response: %s", safe_strerror(errno));
    zbuf_free(zb);
    return 0;
  };

  nlh = znl_nlmsg_pull(zb, &zpl);
  ghdr = znl_pull(&zpl, sizeof(*ghdr));
  if (nlh->nlmsg_type != GENL_ID_CTRL || ghdr->cmd != CTRL_CMD_NEWFAMILY) {
    zlog_warn("unexpected genl response #1");
    zbuf_free(zb);
    return 0;
  };

  struct rtattr *rta;
  while ((rta = znl_rta_pull(&zpl, &za))) {
    if (rta->rta_type == CTRL_ATTR_FAMILY_ID) {
      if (rta->rta_len != sizeof(uint16_t) + sizeof(*rta)) {
        zlog_warn("unexpected genl response #2");
      } else {
        vpls_family = zbuf_get16(&za);
        break;
      }
    }
  }
  zlog_warn("vpls family %x", vpls_family);
  zbuf_free(zb);
  close(genlfd);

  return 0;
};
