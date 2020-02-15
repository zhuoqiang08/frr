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
	struct srte_segment_list *segment_list;
	const char *name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(dnode, "./name");
	segment_list = srte_segment_list_add(name);
	nb_running_set_entry(dnode, segment_list);

	return NB_OK;
}

int pathd_te_segment_list_destroy(enum nb_event event,
				  const struct lyd_node *dnode)
{
	struct srte_segment_list *segment_list;

	if (event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_unset_entry(dnode);
	srte_segment_list_del(segment_list);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/segment-list/segment
 */
int pathd_te_segment_list_segment_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct srte_segment_list *segment_list;
	struct srte_segment_entry *segment;
	uint32_t index;

	if (event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_get_entry(dnode, NULL, true);
	index = yang_dnode_get_uint32(dnode, "./index");
	segment = srte_segment_entry_add(segment_list, index);
	nb_running_set_entry(dnode, segment);

	return NB_OK;
}

int pathd_te_segment_list_segment_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct srte_segment_list *segment_list;
	struct srte_segment_entry *segment;

	if (event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_get_entry(dnode, NULL, true);
	segment = nb_running_unset_entry(dnode);
	srte_segment_entry_del(segment_list, segment);

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
	struct srte_segment_entry *segment;

	if (event != NB_EV_APPLY)
		return NB_OK;

	segment = nb_running_get_entry(dnode, NULL, true);
	sid_value = yang_dnode_get_uint32(dnode, NULL);
	segment->sid_value = sid_value;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
int pathd_te_sr_policy_create(enum nb_event event, const struct lyd_node *dnode,
			      union nb_resource *resource)
{
	struct srte_policy *policy;
	uint32_t color;
	struct ipaddr endpoint;

	if (event != NB_EV_APPLY)
		return NB_OK;

	color = yang_dnode_get_uint32(dnode, "./color");
	yang_dnode_get_ip(&endpoint, dnode, "./endpoint");
	policy = srte_policy_add(color, &endpoint);

	nb_running_set_entry(dnode, policy);

	return NB_OK;
}

int pathd_te_sr_policy_destroy(enum nb_event event,
			       const struct lyd_node *dnode)
{
	struct srte_policy *policy;

	if (event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_unset_entry(dnode);
	srte_policy_del(policy);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/name
 */
int pathd_te_sr_policy_name_modify(enum nb_event event,
				   const struct lyd_node *dnode,
				   union nb_resource *resource)
{
	struct srte_policy *policy;
	const char *name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(dnode, NULL, true);
	name = yang_dnode_get_string(dnode, NULL);
	strlcpy(policy->name, name, sizeof(policy->name));

	return NB_OK;
}

int pathd_te_sr_policy_name_destroy(enum nb_event event,
				    const struct lyd_node *dnode)
{
	struct srte_policy *policy;

	if (event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(dnode, NULL, true);
	policy->name[0] = '\0';

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/binding-sid
 */
int pathd_te_sr_policy_binding_sid_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct srte_policy *policy;
	mpls_label_t binding_sid;

	if (event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(dnode, NULL, true);
	binding_sid = yang_dnode_get_uint32(dnode, NULL);
	srte_policy_update_binding_sid(policy, binding_sid);

	return NB_OK;
}

int pathd_te_sr_policy_binding_sid_destroy(enum nb_event event,
					   const struct lyd_node *dnode)
{
	struct srte_policy *policy;

	if (event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(dnode, NULL, true);
	srte_policy_update_binding_sid(policy, MPLS_LABEL_NONE);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path
 */
int pathd_te_sr_policy_candidate_path_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct srte_policy *policy;
	struct srte_candidate *candidate;
	uint32_t preference;

	if (event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(dnode, NULL, true);
	preference = yang_dnode_get_uint32(dnode, "./preference");
	candidate = srte_candidate_add(policy, preference);
	nb_running_set_entry(dnode, candidate);

	return NB_OK;
}

void pathd_te_sr_policy_candidate_path_apply_finish(
	const struct lyd_node *dnode)
{
	struct srte_candidate *candidate;

	candidate = nb_running_get_entry(dnode, NULL, true);
	srte_candidate_set_active(candidate->policy, candidate);
}

int pathd_te_sr_policy_candidate_path_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct srte_candidate *candidate;

	if (event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(dnode, NULL, true);
	srte_candidate_del(candidate);

	srte_candidate_set_active(candidate->policy, candidate);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/name
 */
int pathd_te_sr_policy_candidate_path_name_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct srte_candidate *candidate;
	const char *name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(dnode, NULL, true);
	name = yang_dnode_get_string(dnode, NULL);
	strlcpy(candidate->name, name, sizeof(candidate->name));

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/protocol-origin
 */
int pathd_te_sr_policy_candidate_path_protocol_origin_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct srte_candidate *candidate;
	enum srte_protocol_origin protocol_origin;

	if (event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(dnode, NULL, true);
	protocol_origin = yang_dnode_get_enum(dnode, NULL);
	candidate->protocol_origin = protocol_origin;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/originator
 */
int pathd_te_sr_policy_candidate_path_originator_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct srte_candidate *candidate;
	struct ipaddr originator;

	if (event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ip(&originator, dnode, NULL);
	candidate->originator = originator;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/discriminator
 */
int pathd_te_sr_policy_candidate_path_discriminator_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct srte_candidate *candidate;
	uint32_t discriminator;

	if (event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(dnode, NULL, true);
	discriminator = yang_dnode_get_uint32(dnode, NULL);
	candidate->discriminator = discriminator;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/type
 */
int pathd_te_sr_policy_candidate_path_type_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct srte_candidate *candidate;
	enum srte_candidate_type type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, NULL);
	candidate->type = type;

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/segment-list-name
 */
int pathd_te_sr_policy_candidate_path_segment_list_name_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct srte_candidate *candidate;
	const char *segment_list_name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(dnode, NULL, true);
	segment_list_name = yang_dnode_get_string(dnode, NULL);
	candidate->segment_list = srte_segment_list_find(segment_list_name);
	assert(candidate->segment_list);

	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_segment_list_name_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct srte_candidate *candidate;

	if (event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(dnode, NULL, true);
	candidate->segment_list = NULL;

	return NB_OK;
}
