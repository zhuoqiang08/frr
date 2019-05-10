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

#include "printfrr.h"
#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "table.h"
#include "zclient.h"
#include "vty.h"
#include "log.h"
#include "lib_errors.h"
#include "northbound_cli.h"
#include "ppr.h"

#ifndef VTYSH_EXTRACT_PL
#include "lib/ppr_clippy.c"
#endif

DEFINE_MTYPE_STATIC(LIB, PPR_CONFIG, "PPR Configuration");

DEFINE_HOOK(ppr_group_update_hook, (struct ppr_group * group), (group))

static void ppr_cfg_del(struct ppr_cfg *ppr);
static void ppr_pde_cfg_free(struct ppr_pde_cfg *pde);

static inline int ppr_group_compare(const struct ppr_group *a,
				    const struct ppr_group *b)
{
	return strcmp(a->name, b->name);
}
RB_GENERATE(ppr_group_head, ppr_group, entry, ppr_group_compare)

int ppr_id_compare(const struct ppr_id *a, const struct ppr_id *b)
{
	if (a->type < b->type)
		return -1;
	if (a->type > b->type)
		return 1;

	switch (a->type) {
	case PPR_ID_TYPE_MPLS:
		/* TODO */
		break;
	case PPR_ID_TYPE_IPV4:
	case PPR_ID_TYPE_IPV6:
	case PPR_ID_TYPE_SRV6:
		if (a->value.prefix.family < b->value.prefix.family)
			return -1;
		if (a->value.prefix.family > b->value.prefix.family)
			return 1;

		switch (a->value.prefix.family) {
		case AF_INET:
			if (ntohl(a->value.prefix.u.prefix4.s_addr)
			    < ntohl(b->value.prefix.u.prefix4.s_addr))
				return -1;
			if (ntohl(a->value.prefix.u.prefix4.s_addr)
			    > ntohl(b->value.prefix.u.prefix4.s_addr))
				return 1;
			break;
		case AF_INET6:
			if (memcmp(&a->value.prefix.u.prefix6,
				   &b->value.prefix.u.prefix6,
				   sizeof(struct in6_addr))
			    < 0)
				return -1;
			if (memcmp(&a->value.prefix.u.prefix6,
				   &b->value.prefix.u.prefix6,
				   sizeof(struct in6_addr))
			    > 0)
				return 1;
			break;
		default:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown prefix family", __func__);
			exit(1);
		}

		if (a->value.prefix.prefixlen < b->value.prefix.prefixlen)
			return -1;
		if (a->value.prefix.prefixlen > b->value.prefix.prefixlen)
			return 1;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown PPR-ID type",
			 __func__);
		exit(1);
	}

	return 0;
}

static inline int ppr_id_node_compare(const struct ppr_id_node *a,
				      const struct ppr_id_node *b)
{
	return ppr_id_compare(&a->info, &b->info);
}
RB_GENERATE(ppr_id_node_head, ppr_id_node, entry, ppr_id_node_compare)

static struct ppr_group_head ppr_groups = RB_INITIALIZER(&ppr_groups);

/* ------------------------------------ */

static struct ppr_group *ppr_group_new(const char *name)
{
	struct ppr_group *group;

	group = XCALLOC(MTYPE_PPR_CONFIG, sizeof(*group));
	strlcpy(group->name, name, sizeof(group->name));
	RB_INIT(ppr_id_node_head, &group->ppr_list);

	RB_INSERT(ppr_group_head, &ppr_groups, group);

	return group;
}

static void ppr_group_del(struct ppr_group *group)
{
	while (!RB_EMPTY(ppr_id_node_head, &group->ppr_list)) {
		struct ppr_cfg *ppr;

		ppr = (struct ppr_cfg *)RB_ROOT(ppr_id_node_head,
						&group->ppr_list);
		ppr_cfg_del(ppr);
	}

	RB_REMOVE(ppr_group_head, &ppr_groups, group);
	XFREE(MTYPE_PPR_CONFIG, group);
}

struct ppr_group *ppr_group_find(const char *name)
{
	struct ppr_group group;

	strlcpy(group.name, name, sizeof(group.name));

	return (RB_FIND(ppr_group_head, &ppr_groups, &group));
}

static struct ppr_cfg *ppr_cfg_add(struct ppr_group *group,
				   enum ppr_id_type id_type,
				   const struct prefix *id_value)
{
	struct ppr_cfg *ppr;

	ppr = XCALLOC(MTYPE_PPR_CONFIG, sizeof(*ppr));
	ppr->id.info.type = id_type;
	ppr->id.info.value.prefix = *id_value;
	ppr->pdes = list_new();
	ppr->pdes->del = (void (*)(void *))ppr_pde_cfg_free;
	ppr->group = group;
	RB_INSERT(ppr_id_node_head, &group->ppr_list, &ppr->id);

	return ppr;
}

static void ppr_cfg_del(struct ppr_cfg *ppr)
{
	struct ppr_group *group = ppr->group;

	list_delete(&ppr->pdes);
	RB_REMOVE(ppr_id_node_head, &group->ppr_list, &ppr->id);
	XFREE(MTYPE_PPR_CONFIG, ppr);
}

static struct ppr_pde_cfg *ppr_pde_cfg_add(struct ppr_cfg *ppr,
					   enum ppr_pde_type type,
					   enum ppr_pde_id_type id_type,
					   const struct prefix *id_value)
{
	struct ppr_pde_cfg *pde;

	pde = XCALLOC(MTYPE_PPR_CONFIG, sizeof(*pde));
	pde->pde.type = type;
	pde->pde.id_type = id_type;
	pde->pde.id_value.prefix = *id_value;
	pde->ppr = ppr;
	listnode_add(ppr->pdes, pde);

	return pde;
}

static void ppr_pde_cfg_free(struct ppr_pde_cfg *pde)
{
	XFREE(MTYPE_PPR_CONFIG, pde);
}

static void ppr_pde_cfg_del(struct ppr_pde_cfg *pde)
{
	struct ppr_cfg *ppr = pde->ppr;

	listnode_delete(ppr->pdes, pde);
	ppr_pde_cfg_free(pde);
}

/* ----------- CLI commands ----------- */

/*
 * XPath: /frr-ppr:ppr/group
 */
DEFPY_NOSH(ppr_group, ppr_group_cmd, "ppr group NAME$name",
	   "Preferred Path Routing\n"
	   "Preferred path group\n"
	   "PPR path group name\n")
{
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath, XPATH_MAXLEN, "/frr-ppr:ppr/group[name='%s']", name);
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, xpath);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(PPR_NODE, xpath);

	return ret;
}

DEFPY(no_ppr_group, no_ppr_group_cmd, "no ppr group NAME$name",
      NO_STR
      "Preferred Path Routing\n"
      "Preferred path group\n"
      "PPR path group name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, XPATH_MAXLEN, "/frr-ppr:ppr/group[name='%s']", name);
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, xpath);
}

static void cli_show_ppr_group(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults)
{
	vty_out(vty, "!\n");
	vty_out(vty, "ppr group %s\n", yang_dnode_get_string(dnode, "./name"));
}

static void cli_show_ppr_id_end(struct vty *vty, struct lyd_node *dnode)
{
	vty_out(vty, " !\n");
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4
 */
DEFPY_NOSH(
	ppr_id_ipv4, ppr_id_ipv4_cmd,
	"ppr-id ipv4 A.B.C.D/M$id_prefix prefix A.B.C.D/M$prefix [metric (0-4294967295)$metric]",
	"Preferred Path Routing ID\n"
	"Preferred path using IPv4 data plane\n"
	"PPR-ID address/mask\n"
	"PPR-Prefix\n"
	"IPv4 prefix\n"
	"Metric of the path presented by the PPR-ID\n"
	"Metric value\n")
{
	int ret;
	char base_xpath[XPATH_MAXLEN];
	char full_xpath[XPATH_MAXLEN];

	snprintf(base_xpath, XPATH_MAXLEN, "./ipv4[ppr-id='%s']",
		 id_prefix_str);
	snprintf(full_xpath, XPATH_MAXLEN, "%s/ipv4[ppr-id='%s']",
		 VTY_CURR_XPATH, id_prefix_str);

	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./ppr-prefix", NB_OP_MODIFY, prefix_str);
	if (metric_str)
		nb_cli_enqueue_change(vty, "./attributes/ppr-metric",
				      NB_OP_MODIFY, metric_str);

	ret = nb_cli_apply_changes(vty, base_xpath);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(PPR_IPV4_NODE, full_xpath);

	return ret;
}

DEFPY(no_ppr_id_ipv4, no_ppr_id_ipv4_cmd,
      "no ppr-id ipv4 A.B.C.D/M$id_prefix [prefix A.B.C.D/M [metric (0-4294967295)]]",
      NO_STR
      "Preferred Path Routing ID\n"
      "Preferred path using IPv4 data plane\n"
      "PPR-ID address/mask\n"
      "PPR-Prefix\n"
      "IPv4 prefix\n"
      "Metric of the path presented by the PPR-ID\n"
      "Metric value\n")
{
	char base_xpath[XPATH_MAXLEN];

	snprintf(base_xpath, XPATH_MAXLEN, "./ipv4[ppr-id='%s']",
		 id_prefix_str);

	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, base_xpath);
}

static void cli_show_ppr_id_ipv4(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " ppr-id ipv4 %s prefix %s",
		yang_dnode_get_string(dnode, "./ppr-id"),
		yang_dnode_get_string(dnode, "./ppr-prefix"));
	if (yang_dnode_exists(dnode, "./attributes/ppr-metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode,
					      "./attributes/ppr-metric"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4/ppr-pde
 */
DEFPY(ppr_ipv4_pde, ppr_ipv4_pde_cmd,
      "[no] pde <ipv4-node|ipv4-interface>$id_type A.B.C.D/M$id_value",
      NO_STR
      "Path Description Element (PDE)\n"
      "IPv4 Node Address\n"
      "IPv4 Interface Address\n"
      "PDE-ID Value\n")
{
	char base_xpath[XPATH_MAXLEN];

	snprintf(base_xpath, XPATH_MAXLEN, "./ppr-pde[pde-id='%s']",
		 id_value_str);

	if (no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./pde-id-type", NB_OP_MODIFY,
				      id_type);
		nb_cli_enqueue_change(vty, "./pde-type", NB_OP_MODIFY,
				      "topological");
	}

	return nb_cli_apply_changes(vty, base_xpath);
}

static void cli_show_ppr_ipv4_pde(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults)
{
	vty_out(vty, "  pde %s %s\n",
		yang_dnode_get_string(dnode, "./pde-id-type"),
		yang_dnode_get_string(dnode, "./pde-id"));
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6
 */
DEFPY_NOSH(
	ppr_id_ipv6, ppr_id_ipv6_cmd,
	"ppr-id ipv6 X:X::X:X/M$id_prefix prefix X:X::X:X/M$prefix [metric (0-4294967295)$metric]",
	"Preferred Path Routing ID\n"
	"Preferred path using IPv6 data plane\n"
	"PPR-ID address/mask\n"
	"PPR-Prefix\n"
	"IPv6 prefix\n"
	"Metric of the path presented by the PPR-ID\n"
	"Metric value\n")
{
	int ret;
	char base_xpath[XPATH_MAXLEN];
	char full_xpath[XPATH_MAXLEN];

	snprintf(base_xpath, XPATH_MAXLEN, "./ipv6[ppr-id='%s']",
		 id_prefix_str);
	snprintf(full_xpath, XPATH_MAXLEN, "%s/ipv6[ppr-id='%s']",
		 VTY_CURR_XPATH, id_prefix_str);

	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./ppr-prefix", NB_OP_MODIFY, prefix_str);
	if (metric_str)
		nb_cli_enqueue_change(vty, "./attributes/ppr-metric",
				      NB_OP_MODIFY, metric_str);

	ret = nb_cli_apply_changes(vty, base_xpath);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(PPR_IPV6_NODE, full_xpath);

	return ret;
}

DEFPY(no_ppr_id_ipv6, no_ppr_id_ipv6_cmd,
      "no ppr-id ipv6 X:X::X:X/M$id_prefix [prefix X:X::X:X/M [metric (0-4294967295)]]",
      NO_STR
      "Preferred Path Routing ID\n"
      "Preferred path using IPv6 data plane\n"
      "PPR-ID address/mask\n"
      "PPR-Prefix\n"
      "IPv6 prefix\n"
      "Metric of the path presented by the PPR-ID\n"
      "Metric value\n")
{
	char base_xpath[XPATH_MAXLEN];

	snprintf(base_xpath, XPATH_MAXLEN, "./ipv6[ppr-id='%s']",
		 id_prefix_str);

	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, base_xpath);
}

static void cli_show_ppr_id_ipv6(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " ppr-id ipv6 %s prefix %s",
		yang_dnode_get_string(dnode, "./ppr-id"),
		yang_dnode_get_string(dnode, "./ppr-prefix"));
	if (yang_dnode_exists(dnode, "./attributes/ppr-metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode,
					      "./attributes/ppr-metric"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6/ppr-pde
 */
DEFPY(ppr_ipv6_pde, ppr_ipv6_pde_cmd,
      "[no] pde <ipv6-node|ipv6-interface>$id_type X:X::X:X/M$id_value",
      NO_STR
      "Path Description Element (PDE)\n"
      "IPv6 Node Address\n"
      "IPv6 Interface Address\n"
      "PDE-ID Value\n")
{
	char base_xpath[XPATH_MAXLEN];

	snprintf(base_xpath, XPATH_MAXLEN, "./ppr-pde[pde-id='%s']",
		 id_value_str);

	if (no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./pde-id-type", NB_OP_MODIFY,
				      id_type);
		nb_cli_enqueue_change(vty, "./pde-type", NB_OP_MODIFY,
				      "topological");
	}

	return nb_cli_apply_changes(vty, base_xpath);
}

static void cli_show_ppr_ipv6_pde(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults)
{
	vty_out(vty, "  pde %s %s\n",
		yang_dnode_get_string(dnode, "./pde-id-type"),
		yang_dnode_get_string(dnode, "./pde-id"));
}

/* ------- Northbound callbacks ------- */

/*
 * XPath: /frr-ppr:ppr/group
 */
static int ppr_group_create(enum nb_event event, const struct lyd_node *dnode,
			    union nb_resource *resource)
{
	struct ppr_group *group;
	const char *name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(dnode, "./name");
	group = ppr_group_new(name);
	nb_running_set_entry(dnode, group);

	return NB_OK;
}

static int ppr_group_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	struct ppr_group *group;

	if (event != NB_EV_APPLY)
		return NB_OK;

	group = nb_running_unset_entry(dnode);
	ppr_group_del(group);

	return NB_OK;
}

static void ppr_group_apply_finish(const struct lyd_node *dnode)
{
	struct ppr_group *group;

	group = nb_running_get_entry(dnode, NULL, true);
	hook_call(ppr_group_update_hook, group);
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4
 */
static int ppr_group_ipv4_create(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource)
{
	struct ppr_group *group;
	const char *id_value_str;
	struct prefix id_value;
	struct ppr_cfg *ppr;

	switch (event) {
	case NB_EV_VALIDATE:
		id_value_str = yang_dnode_get_string(dnode, "./ppr-id");
		if (str2prefix_ipv4(id_value_str,
				    (struct prefix_ipv4 *)&id_value)
		    != 1) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Invalid PPR-ID prefix: %s", id_value_str);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(dnode, NULL, true);
		id_value_str = yang_dnode_get_string(dnode, "./ppr-id");
		(void)str2prefix_ipv4(id_value_str,
				      (struct prefix_ipv4 *)&id_value);

		ppr = ppr_cfg_add(group, PPR_ID_TYPE_IPV4, &id_value);
		nb_running_set_entry(dnode, ppr);
		break;
	}

	return NB_OK;
}

static int ppr_group_ipv4_destroy(enum nb_event event,
				  const struct lyd_node *dnode)
{
	struct ppr_cfg *ppr;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ppr = nb_running_unset_entry(dnode);
	ppr_cfg_del(ppr);

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4/ppr-prefix
 */
static int ppr_group_ipv4_ppr_prefix_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct ppr_cfg *ppr;
	struct prefix ppr_prefix;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ppr = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv4p(&ppr_prefix, dnode, NULL);

	ppr->prefix = ppr_prefix;

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4/ppr-pde
 */
static int ppr_group_ipv4_ppr_pde_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct ppr_cfg *ppr;
	struct ppr_pde_cfg *pde;
	const char *id_value_str;
	enum ppr_pde_id_type id_type;
	struct prefix id_value;

	switch (event) {
	case NB_EV_VALIDATE:
		id_value_str = yang_dnode_get_string(dnode, "./pde-id");
		if (str2prefix_ipv4(id_value_str,
				    (struct prefix_ipv4 *)&id_value)
		    != 1) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Invalid PDE-ID prefix: %s", id_value_str);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ppr = nb_running_get_entry(dnode, NULL, true);
		id_type = yang_dnode_get_enum(dnode, "./pde-id-type");
		id_value_str = yang_dnode_get_string(dnode, "./pde-id");
		(void)str2prefix_ipv4(id_value_str,
				      (struct prefix_ipv4 *)&id_value);

		pde = ppr_pde_cfg_add(ppr, PPR_PDE_TYPE_TOPOLOGICAL, id_type,
				      &id_value);
		nb_running_set_entry(dnode, pde);
		break;
	}

	return NB_OK;
}

static int ppr_group_ipv4_ppr_pde_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct ppr_pde_cfg *pde;

	if (event != NB_EV_APPLY)
		return NB_OK;

	pde = nb_running_unset_entry(dnode);
	ppr_pde_cfg_del(pde);

	return NB_OK;
}

static int ppr_group_ipv4_ppr_pde_move(enum nb_event event,
				       const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4/ppr-pde/pde-id-type
 */
static int
ppr_group_ipv4_ppr_pde_pde_id_type_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct ppr_pde_cfg *pde;
	enum ppr_pde_id_type id_type = yang_dnode_get_enum(dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
		if (id_type < PPR_PDE_ID_TYPE_IPV4_NODE_ADDR
		    || id_type > PPR_PDE_ID_TYPE_IPV4_IFACE_ADDR) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Unsupported PDE-ID type: %s",
				  yang_dnode_get_string(dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pde = nb_running_get_entry(dnode, NULL, true);
		pde->pde.id_type = id_type;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4/ppr-pde/loose
 */
static int ppr_group_ipv4_ppr_pde_loose_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct ppr_pde_cfg *pde;

	if (event != NB_EV_APPLY)
		return NB_OK;

	pde = nb_running_get_entry(dnode, NULL, true);
	pde->pde.loose = yang_dnode_get_bool(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4/ppr-pde/pde-type
 */
static int ppr_group_ipv4_ppr_pde_pde_type_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct ppr_pde_cfg *pde;
	enum ppr_pde_type type = yang_dnode_get_enum(dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
		if (type != PPR_PDE_TYPE_TOPOLOGICAL) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Unsupported PDE type: %s",
				  yang_dnode_get_string(dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pde = nb_running_get_entry(dnode, NULL, true);
		pde->pde.type = type;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4/attributes/count-packets
 */
static int
ppr_group_ipv4_attributes_count_packets_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4/attributes/count-bytes
 */
static int
ppr_group_ipv4_attributes_count_bytes_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv4/attributes/ppr-metric
 */
static int
ppr_group_ipv4_attributes_ppr_metric_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct ppr_cfg *ppr;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ppr = nb_running_get_entry(dnode, NULL, true);
	ppr->metric = yang_dnode_get_uint32(dnode, NULL);

	return NB_OK;
}

static int
ppr_group_ipv4_attributes_ppr_metric_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct ppr_cfg *ppr;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ppr = nb_running_get_entry(dnode, NULL, true);
	ppr->metric = 0;

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6
 */
static int ppr_group_ipv6_create(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource)
{
	struct ppr_group *group;
	const char *id_value_str;
	struct prefix id_value;
	struct ppr_cfg *ppr;

	switch (event) {
	case NB_EV_VALIDATE:
		id_value_str = yang_dnode_get_string(dnode, "./ppr-id");
		if (str2prefix_ipv6(id_value_str,
				    (struct prefix_ipv6 *)&id_value)
		    != 1) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Invalid PPR-ID prefix: %s", id_value_str);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = nb_running_get_entry(dnode, NULL, true);
		id_value_str = yang_dnode_get_string(dnode, "./ppr-id");
		(void)str2prefix_ipv6(id_value_str,
				      (struct prefix_ipv6 *)&id_value);

		ppr = ppr_cfg_add(group, PPR_ID_TYPE_IPV6, &id_value);
		nb_running_set_entry(dnode, ppr);
		break;
	}

	return NB_OK;
}

static int ppr_group_ipv6_destroy(enum nb_event event,
				  const struct lyd_node *dnode)
{
	struct ppr_cfg *ppr;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ppr = nb_running_unset_entry(dnode);
	ppr_cfg_del(ppr);

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6/ppr-prefix
 */
static int ppr_group_ipv6_ppr_prefix_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct ppr_cfg *ppr;
	struct prefix ppr_prefix;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ppr = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv6p(&ppr_prefix, dnode, NULL);

	ppr->prefix = ppr_prefix;

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6/ppr-pde
 */
static int ppr_group_ipv6_ppr_pde_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct ppr_cfg *ppr;
	struct ppr_pde_cfg *pde;
	const char *id_value_str;
	enum ppr_pde_id_type id_type;
	struct prefix id_value;

	switch (event) {
	case NB_EV_VALIDATE:
		id_value_str = yang_dnode_get_string(dnode, "./pde-id");
		if (str2prefix_ipv6(id_value_str,
				    (struct prefix_ipv6 *)&id_value)
		    != 1) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Invalid PDE-ID prefix: %s", id_value_str);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ppr = nb_running_get_entry(dnode, NULL, true);
		id_type = yang_dnode_get_enum(dnode, "./pde-id-type");
		id_value_str = yang_dnode_get_string(dnode, "./pde-id");
		(void)str2prefix_ipv6(id_value_str,
				      (struct prefix_ipv6 *)&id_value);

		pde = ppr_pde_cfg_add(ppr, PPR_PDE_TYPE_TOPOLOGICAL, id_type,
				      &id_value);
		nb_running_set_entry(dnode, pde);
		break;
	}

	return NB_OK;
}

static int ppr_group_ipv6_ppr_pde_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct ppr_pde_cfg *pde;

	if (event != NB_EV_APPLY)
		return NB_OK;

	pde = nb_running_unset_entry(dnode);
	ppr_pde_cfg_del(pde);

	return NB_OK;
}

static int ppr_group_ipv6_ppr_pde_move(enum nb_event event,
				       const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6/ppr-pde/pde-id-type
 */
static int
ppr_group_ipv6_ppr_pde_pde_id_type_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct ppr_pde_cfg *pde;
	enum ppr_pde_id_type id_type = yang_dnode_get_enum(dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
		if (id_type < PPR_PDE_ID_TYPE_IPV6_NODE_ADDR
		    || id_type > PPR_PDE_ID_TYPE_IPV6_IFACE_ADDR) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Unsupported PDE-ID type: %s",
				  yang_dnode_get_string(dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pde = nb_running_get_entry(dnode, NULL, true);
		pde->pde.id_type = id_type;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6/ppr-pde/loose
 */
static int ppr_group_ipv6_ppr_pde_loose_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct ppr_pde_cfg *pde;

	if (event != NB_EV_APPLY)
		return NB_OK;

	pde = nb_running_get_entry(dnode, NULL, true);
	pde->pde.loose = yang_dnode_get_bool(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6/ppr-pde/pde-type
 */
static int ppr_group_ipv6_ppr_pde_pde_type_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct ppr_pde_cfg *pde;
	enum ppr_pde_type type = yang_dnode_get_enum(dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
		if (type != PPR_PDE_TYPE_TOPOLOGICAL) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Unsupported PDE type: %s",
				  yang_dnode_get_string(dnode, NULL));
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pde = nb_running_get_entry(dnode, NULL, true);
		pde->pde.type = type;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6/attributes/count-packets
 */
static int
ppr_group_ipv6_attributes_count_packets_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6/attributes/count-bytes
 */
static int
ppr_group_ipv6_attributes_count_bytes_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ppr:ppr/group/ipv6/attributes/ppr-metric
 */
static int
ppr_group_ipv6_attributes_ppr_metric_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct ppr_cfg *ppr;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ppr = nb_running_get_entry(dnode, NULL, true);
	ppr->metric = yang_dnode_get_uint32(dnode, NULL);

	return NB_OK;
}

static int
ppr_group_ipv6_attributes_ppr_metric_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct ppr_cfg *ppr;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ppr = nb_running_get_entry(dnode, NULL, true);
	ppr->metric = 0;

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_ppr_info = {
	.name = "frr-ppr",
	.nodes = {
		{
			.xpath = "/frr-ppr:ppr/group",
			.cbs.create = ppr_group_create,
			.cbs.destroy = ppr_group_destroy,
			.cbs.apply_finish = ppr_group_apply_finish,
			.cbs.cli_show = cli_show_ppr_group,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv4",
			.cbs.create = ppr_group_ipv4_create,
			.cbs.destroy = ppr_group_ipv4_destroy,
			.cbs.cli_show = cli_show_ppr_id_ipv4,
			.cbs.cli_show_end = cli_show_ppr_id_end,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv4/ppr-prefix",
			.cbs.modify = ppr_group_ipv4_ppr_prefix_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv4/ppr-pde",
			.cbs.create = ppr_group_ipv4_ppr_pde_create,
			.cbs.destroy = ppr_group_ipv4_ppr_pde_destroy,
			.cbs.move = ppr_group_ipv4_ppr_pde_move,
			.cbs.cli_show = cli_show_ppr_ipv4_pde,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv4/ppr-pde/pde-id-type",
			.cbs.modify = ppr_group_ipv4_ppr_pde_pde_id_type_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv4/ppr-pde/loose",
			.cbs.modify = ppr_group_ipv4_ppr_pde_loose_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv4/ppr-pde/pde-type",
			.cbs.modify = ppr_group_ipv4_ppr_pde_pde_type_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv4/attributes/count-packets",
			.cbs.modify = ppr_group_ipv4_attributes_count_packets_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv4/attributes/count-bytes",
			.cbs.modify = ppr_group_ipv4_attributes_count_bytes_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv4/attributes/ppr-metric",
			.cbs.modify = ppr_group_ipv4_attributes_ppr_metric_modify,
			.cbs.destroy = ppr_group_ipv4_attributes_ppr_metric_destroy,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv6",
			.cbs.create = ppr_group_ipv6_create,
			.cbs.destroy = ppr_group_ipv6_destroy,
			.cbs.cli_show = cli_show_ppr_id_ipv6,
			.cbs.cli_show_end = cli_show_ppr_id_end,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv6/ppr-prefix",
			.cbs.modify = ppr_group_ipv6_ppr_prefix_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv6/ppr-pde",
			.cbs.create = ppr_group_ipv6_ppr_pde_create,
			.cbs.destroy = ppr_group_ipv6_ppr_pde_destroy,
			.cbs.move = ppr_group_ipv6_ppr_pde_move,
			.cbs.cli_show = cli_show_ppr_ipv6_pde,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv6/ppr-pde/pde-id-type",
			.cbs.modify = ppr_group_ipv6_ppr_pde_pde_id_type_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv6/ppr-pde/loose",
			.cbs.modify = ppr_group_ipv6_ppr_pde_loose_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv6/ppr-pde/pde-type",
			.cbs.modify = ppr_group_ipv6_ppr_pde_pde_type_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv6/attributes/count-packets",
			.cbs.modify = ppr_group_ipv6_attributes_count_packets_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv6/attributes/count-bytes",
			.cbs.modify = ppr_group_ipv6_attributes_count_bytes_modify,
		},
		{
			.xpath = "/frr-ppr:ppr/group/ipv6/attributes/ppr-metric",
			.cbs.modify = ppr_group_ipv6_attributes_ppr_metric_modify,
			.cbs.destroy = ppr_group_ipv6_attributes_ppr_metric_destroy,
		},
		{
			.xpath = NULL,
		},
	}
};

/* ----- Logging helper functions ----- */

const char *ppr_algo2str(uint8_t algorithm)
{
	static char buf[BUFSIZ];

	switch (algorithm) {
	case SR_ALGORITHM_SPF:
		return "SPF";
	case SR_ALGORITHM_STRICT_SPF:
		return "Strict SPF";
	default:
		snprintf(buf, sizeof(buf), "Unknown (%" PRIu8 ")", algorithm);
		return buf;
	}
}

const char *ppr_idtype2str(enum ppr_id_type type)
{
	static char buf[BUFSIZ];

	switch (type) {
	case PPR_ID_TYPE_MPLS:
		return "MPLS";
	case PPR_ID_TYPE_IPV4:
		return "Native IPv4";
	case PPR_ID_TYPE_IPV6:
		return "Native IPv6";
	case PPR_ID_TYPE_SRV6:
		return "SRv6";
	default:
		snprintf(buf, sizeof(buf), "Unknown (%u)", type);
		return buf;
	}
}

const char *ppr_id2str(const struct ppr_id *i)
{
	static char buf[BUFSIZ];

	switch (i->type) {
	case PPR_ID_TYPE_MPLS:
		snprintf(buf, sizeof(buf), "%u", i->value.mpls);
		break;
	case PPR_ID_TYPE_IPV4:
	case PPR_ID_TYPE_IPV6:
	case PPR_ID_TYPE_SRV6:
		prefix2str(&i->value.prefix, buf, sizeof(buf));
		break;
	default:
		snprintf(buf, sizeof(buf), "Unknown (%u)", i->type);
		break;
	}

	return buf;
}

const char *ppr_pdetype2str(enum ppr_pde_type type)
{
	static char buf[BUFSIZ];

	switch (type) {
	case PPR_PDE_TYPE_TOPOLOGICAL:
		return "Topological";
	case PPR_PDE_TYPE_NON_TOPOLOGICAL:
		return "Non-Topological";
	default:
		snprintf(buf, sizeof(buf), "Unknown (%" PRIu8 ")", type);
		return buf;
	}
}

const char *ppr_pdeidtype2str(enum ppr_pde_id_type type)
{
	static char buf[BUFSIZ];

	switch (type) {
	case PPR_PDE_ID_TYPE_NON_TOPOLOGICAL:
		return "Non-Topological";
	case PPR_PDE_ID_TYPE_SID_LABEL:
		return "SID/Label";
	case PPR_PDE_ID_TYPE_SRMPLS_PREFIX_SID:
		return "SR-MPLS Prefix SID";
	case PPR_PDE_ID_TYPE_SRMPLS_ADJ_SID:
		return "SR-MPLS Adjacency SID";
	case PPR_PDE_ID_TYPE_IPV4_NODE_ADDR:
		return "IPv4 Node Address";
	case PPR_PDE_ID_TYPE_IPV4_IFACE_ADDR:
		return "IPv4 Interface Address";
	case PPR_PDE_ID_TYPE_IPV6_NODE_ADDR:
		return "IPv6 Node Address";
	case PPR_PDE_ID_TYPE_IPV6_IFACE_ADDR:
		return "IPv6 Interface Address";
	case PPR_PDE_ID_TYPE_SRV6_NODE_SID:
		return "SRv6 Node SID";
	case PPR_PDE_ID_TYPE_SRV6_ADJ_SID:
		return "SRv6 Adjacency-SID";
	default:
		snprintf(buf, sizeof(buf), "Unknown (%" PRIu8 ")", type);
		return buf;
	}
}

const char *ppr_pdeid2str(const struct ppr_pde *pde)
{
	static char buf[BUFSIZ];

	switch (pde->id_type) {
	case PPR_PDE_ID_TYPE_SID_LABEL:
	case PPR_PDE_ID_TYPE_SRMPLS_PREFIX_SID:
	case PPR_PDE_ID_TYPE_SRMPLS_ADJ_SID:
		snprintf(buf, sizeof(buf), "%u", pde->id_value.mpls);
		break;
	case PPR_PDE_ID_TYPE_IPV4_NODE_ADDR:
	case PPR_PDE_ID_TYPE_IPV6_NODE_ADDR:
	case PPR_PDE_ID_TYPE_SRV6_NODE_SID:
	case PPR_PDE_ID_TYPE_SRV6_ADJ_SID:
		prefix2str(&pde->id_value.prefix, buf, sizeof(buf));
		break;
	case PPR_PDE_ID_TYPE_IPV4_IFACE_ADDR:
		snprintfrr(buf, sizeof(buf), "%pI4", &pde->id_value.prefix.u.prefix4);
		break;
	case PPR_PDE_ID_TYPE_IPV6_IFACE_ADDR:
		snprintfrr(buf, sizeof(buf), "%pI6", &pde->id_value.prefix.u.prefix6);
		break;
	default:
		snprintf(buf, sizeof(buf), "Unknown");
		break;
	}

	return buf;
}

const char *ppr_position2str(enum ppr_position position)
{
	switch (position) {
	case PPR_OFF_PATH:
		return "Off-Path";
	case PPR_HEAD_END:
		return "Head-End";
	case PPR_MID_POINT:
		return "Mid-Point";
	case PPR_TAIL_END:
		return "Tail-End";
	default:
		return "Unknown";
	}
}

const char *ppr_status2str(enum ppr_forwarding_status status, bool extended)
{
	if (!extended) {
		switch (status) {
		case PPR_UNINSTALLED:
			return "-";
		case PPR_INSTALL_SUCCESS:
			return "Up";
		case PPR_INSTALL_FAILURE_PDE_UNREACHABLE:
		case PPR_INSTALL_FAILURE_PDE_LOCAL:
		case PPR_INSTALL_FAILURE_PDE_NOT_ADJ:
		case PPR_INSTALL_FAILURE_PDE_INVALID:
			return "Down";
		default:
			return "Unknown";
		}
	}

	switch (status) {
	case PPR_UNINSTALLED:
		return "Uninstalled";
	case PPR_INSTALL_SUCCESS:
		return "Up";
	case PPR_INSTALL_FAILURE_PDE_UNREACHABLE:
		return "Down: PDE is unreachable";
	case PPR_INSTALL_FAILURE_PDE_LOCAL:
		return "Down: PDE refers to local address";
	case PPR_INSTALL_FAILURE_PDE_NOT_ADJ:
		return "Down: PDE is not adjacent";
	case PPR_INSTALL_FAILURE_PDE_INVALID:
		return "Down: PDE is invalid";
	default:
		return "Unknown";
	}
}

/* ------------------------------------ */

static int ppr_config_write(struct vty *vty)
{
	struct lyd_node *dnode;

	dnode = yang_dnode_get(running_config->dnode, "/frr-ppr:ppr");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		return 1;
	}

	return 0;
}

static int ppr_ipv4_config_write(struct vty *vty)
{
	return 0;
}

static int ppr_ipv6_config_write(struct vty *vty)
{
	return 0;
}

static struct cmd_node ppr_node = {PPR_NODE, "%s(config-ppr)# ", 1};
static struct cmd_node ppr_ipv4_node = {PPR_IPV4_NODE, "%s(config-ppr-ipv4)# ",
					1};
static struct cmd_node ppr_ipv6_node = {PPR_IPV6_NODE, "%s(config-ppr-ipv6)# ",
					1};

void ppr_init(void)
{
	install_node(&ppr_node, ppr_config_write);
	install_node(&ppr_ipv4_node, ppr_ipv4_config_write);
	install_node(&ppr_ipv6_node, ppr_ipv6_config_write);
	install_default(PPR_NODE);
	install_default(PPR_IPV4_NODE);
	install_default(PPR_IPV6_NODE);

	install_element(CONFIG_NODE, &ppr_group_cmd);
	install_element(CONFIG_NODE, &no_ppr_group_cmd);
	install_element(PPR_NODE, &ppr_id_ipv4_cmd);
	install_element(PPR_NODE, &no_ppr_id_ipv4_cmd);
	install_element(PPR_IPV4_NODE, &ppr_ipv4_pde_cmd);
	install_element(PPR_NODE, &ppr_id_ipv6_cmd);
	install_element(PPR_NODE, &no_ppr_id_ipv6_cmd);
	install_element(PPR_IPV6_NODE, &ppr_ipv6_pde_cmd);
}
