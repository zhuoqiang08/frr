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

#include "northbound.h"
#include "libfrr.h"

#include "pathd/pathd.h"
#include "pathd/path_nb.h"

/*
 * XPath: /frr-pathd:pathd/segment-list
 */
int pathd_te_segment_list_create(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource)
{
	struct te_segment_list *te_segment_list;
	const char *name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(dnode, "./name");
	te_segment_list = te_segment_list_create(strdup(name));
	nb_running_set_entry(dnode, te_segment_list);

	return NB_OK;
}

int pathd_te_segment_list_destroy(enum nb_event event,
				  const struct lyd_node *dnode)
{
	struct te_segment_list *te_segment_list;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_segment_list = nb_running_unset_entry(dnode);
	te_segment_list_del(te_segment_list);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/segment-list/segment
 */
int pathd_te_segment_list_segment_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct te_segment_list *te_segment_list;
	struct te_segment_list_segment *te_segment_list_segment;
	uint32_t index;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_segment_list = nb_running_get_entry(dnode, NULL, true);
	index = yang_dnode_get_uint32(dnode, "./index");
	te_segment_list_segment =
		te_segment_list_segment_add(te_segment_list, index);
	nb_running_set_entry(dnode, te_segment_list_segment);

	return NB_OK;
}

int pathd_te_segment_list_segment_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct te_segment_list *te_segment_list;
	struct te_segment_list_segment *te_segment_list_segment;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_segment_list = nb_running_get_entry(dnode, NULL, true);
	te_segment_list_segment = nb_running_unset_entry(dnode);
	te_segment_list_segment_del(te_segment_list, te_segment_list_segment);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/segment-list/segment/sid-value
 */
int pathd_te_segment_list_segment_sid_value_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	mpls_label_t sid_value;
	struct te_segment_list_segment *te_segment_list_segment;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_segment_list_segment = nb_running_get_entry(dnode, NULL, true);
	sid_value = yang_dnode_get_uint32(dnode, NULL);
	te_segment_list_segment_sid_value_add(te_segment_list_segment,
					      sid_value);

	return NB_OK;
}

int pathd_te_segment_list_segment_sid_value_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
int pathd_te_sr_policy_create(enum nb_event event, const struct lyd_node *dnode,
			      union nb_resource *resource)
{
	struct te_sr_policy *te_sr_policy;
	uint32_t color;
	struct ipaddr endpoint;

	if (event != NB_EV_APPLY)
		return NB_OK;

	color = yang_dnode_get_uint32(dnode, "./color");
	yang_dnode_get_ip(&endpoint, dnode, "./endpoint");
	te_sr_policy = te_sr_policy_create(color, &endpoint);

	nb_running_set_entry(dnode, te_sr_policy);

	return NB_OK;
}

int pathd_te_sr_policy_destroy(enum nb_event event,
			       const struct lyd_node *dnode)
{
	struct te_sr_policy *te_sr_policy;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_sr_policy = nb_running_unset_entry(dnode);
	te_sr_policy_del(te_sr_policy);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/name
 */
int pathd_te_sr_policy_name_modify(enum nb_event event,
				   const struct lyd_node *dnode,
				   union nb_resource *resource)
{
	const char *name;
	struct te_sr_policy *te_sr_policy;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_sr_policy = nb_running_get_entry(dnode, NULL, true);
	name = yang_dnode_get_string(dnode, NULL);
	te_sr_policy_name_add(te_sr_policy, strdup(name));

	return NB_OK;
}

int pathd_te_sr_policy_name_destroy(enum nb_event event,
				    const struct lyd_node *dnode)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/binding-sid
 */
int pathd_te_sr_policy_binding_sid_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	mpls_label_t binding_sid;
	struct te_sr_policy *te_sr_policy;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_sr_policy = nb_running_get_entry(dnode, NULL, true);
	binding_sid = yang_dnode_get_uint32(dnode, NULL);
	te_sr_policy_binding_sid_add(te_sr_policy, binding_sid);

	return NB_OK;
}

int pathd_te_sr_policy_binding_sid_destroy(enum nb_event event,
					   const struct lyd_node *dnode)
{
	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path
 */
int pathd_te_sr_policy_candidate_path_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct te_sr_policy *te_sr_policy;
	struct te_candidate_path *te_candidate_path;
	uint32_t preference;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_sr_policy = nb_running_get_entry(dnode, "..", true);
	preference = yang_dnode_get_uint32(dnode, "./preference");
	te_candidate_path =
		te_sr_policy_candidate_path_add(te_sr_policy, preference);
	nb_running_set_entry(dnode, te_candidate_path);

	return NB_OK;
}

void pathd_te_sr_policy_candidate_path_apply_finish(
	const struct lyd_node *dnode)
{
	struct te_candidate_path *te_candidate_path;

	te_candidate_path = nb_running_get_entry(dnode, NULL, true);
	te_sr_policy_candidate_path_set_active(te_candidate_path->sr_policy);
}

int pathd_te_sr_policy_candidate_path_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct te_candidate_path *te_candidate_path;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_candidate_path = nb_running_get_entry(dnode, NULL, true);
	te_sr_policy_candidate_path_delete(te_candidate_path);

	te_sr_policy_candidate_path_set_active(te_candidate_path->sr_policy);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/name
 */
int pathd_te_sr_policy_candidate_path_name_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct te_candidate_path *te_candidate_path;
	const char *name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_candidate_path = nb_running_get_entry(dnode, "..", true);
	name = yang_dnode_get_string(dnode, NULL);

	te_sr_policy_candidate_path_name_add(te_candidate_path, strdup(name));

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/protocol-origin
 */
int pathd_te_sr_policy_candidate_path_protocol_origin_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct te_candidate_path *te_candidate_path;
	enum te_protocol_origin protocol_origin;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_candidate_path = nb_running_get_entry(dnode, "..", true);
	protocol_origin = yang_dnode_get_enum(dnode, NULL);

	te_sr_policy_candidate_path_protocol_origin_add(te_candidate_path,
							protocol_origin);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/originator
 */
int pathd_te_sr_policy_candidate_path_originator_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct te_candidate_path *te_candidate_path;
	struct ipaddr originator;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_candidate_path = nb_running_get_entry(dnode, "..", true);
	yang_dnode_get_ip(&originator, dnode, NULL);

	te_sr_policy_candidate_path_originator_add(te_candidate_path,
						   &originator);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/type
 */
int pathd_te_sr_policy_candidate_path_type_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct te_candidate_path *te_candidate_path;
	enum te_candidate_path_type type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_candidate_path = nb_running_get_entry(dnode, "..", true);
	type = yang_dnode_get_enum(dnode, NULL);

	te_sr_policy_candidate_path_type_add(te_candidate_path, type);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/segment-list-name
 */
int pathd_te_sr_policy_candidate_path_segment_list_name_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct te_candidate_path *te_candidate_path;
	const char *segment_list_name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	te_candidate_path = nb_running_get_entry(dnode, "..", true);
	segment_list_name = yang_dnode_get_string(dnode, NULL);

	te_sr_policy_candidate_path_segment_list_name_add(
		te_candidate_path, strdup(segment_list_name));

	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_segment_list_name_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return NB_OK;
}
