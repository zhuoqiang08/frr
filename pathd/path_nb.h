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

#ifndef _FRR_PATH_NB_H_
#define _FRR_PATH_NB_H_

extern const struct frr_yang_module_info frr_pathd_info;

/* Mandatory callbacks. */
int pathd_te_segment_list_create(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource);
int pathd_te_segment_list_destroy(enum nb_event event,
				  const struct lyd_node *dnode);
const void *pathd_te_segment_list_get_next(const void *parent_list_entry,
					   const void *list_entry);
int pathd_te_segment_list_get_keys(const void *list_entry,
				   struct yang_list_keys *keys);
const void *
pathd_te_segment_list_lookup_entry(const void *parent_list_entry,
				   const struct yang_list_keys *keys);
int pathd_te_segment_list_segment_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource);
int pathd_te_segment_list_segment_destroy(enum nb_event event,
					  const struct lyd_node *dnode);
int pathd_te_segment_list_segment_sid_value_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource);
int pathd_te_segment_list_segment_sid_value_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int pathd_te_sr_policy_create(enum nb_event event, const struct lyd_node *dnode,
			      union nb_resource *resource);
int pathd_te_sr_policy_destroy(enum nb_event event,
			       const struct lyd_node *dnode);
const void *pathd_te_sr_policy_get_next(const void *parent_list_entry,
					const void *list_entry);
int pathd_te_sr_policy_get_keys(const void *list_entry,
				struct yang_list_keys *keys);
const void *pathd_te_sr_policy_lookup_entry(const void *parent_list_entry,
					    const struct yang_list_keys *keys);
int pathd_te_sr_policy_name_modify(enum nb_event event,
				   const struct lyd_node *dnode,
				   union nb_resource *resource);
int pathd_te_sr_policy_name_destroy(enum nb_event event,
				    const struct lyd_node *dnode);
int pathd_te_sr_policy_binding_sid_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource);
int pathd_te_sr_policy_binding_sid_destroy(enum nb_event event,
					   const struct lyd_node *dnode);
int pathd_te_sr_policy_candidate_path_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int pathd_te_sr_policy_candidate_path_destroy(enum nb_event event,
					      const struct lyd_node *dnode);
const void *
pathd_te_sr_policy_candidate_path_get_next(const void *parent_list_entry,
					   const void *list_entry);
int pathd_te_sr_policy_candidate_path_get_keys(const void *list_entry,
					       struct yang_list_keys *keys);
const void *pathd_te_sr_policy_candidate_path_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys);
int pathd_te_sr_policy_candidate_path_name_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource);
struct yang_data *
pathd_te_sr_policy_candidate_path_is_best_candidate_path_get_elem(
	const char *xpath, const void *list_entry);
int pathd_te_sr_policy_candidate_path_protocol_origin_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int pathd_te_sr_policy_candidate_path_originator_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int pathd_te_sr_policy_candidate_path_type_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource);
int pathd_te_sr_policy_candidate_path_segment_list_name_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);

/* Optional 'apply_finish' callbacks. */
void pathd_te_sr_policy_candidate_path_apply_finish(
	const struct lyd_node *dnode);

/* Optional 'cli_show' callbacks. */
void cli_show_te_path_segment_list(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_te_path_segment_list_segment(struct vty *vty,
					   struct lyd_node *dnode,
					   bool show_defaults);
void cli_show_te_path_sr_policy(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_te_path_sr_policy_name(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_te_path_sr_policy_binding_sid(struct vty *vty,
					    struct lyd_node *dnode,
					    bool show_defaults);
void cli_show_te_path_sr_policy_candidate_path(struct vty *vty,
					       struct lyd_node *dnode,
					       bool show_defaults);

#endif /* _FRR_PATH_NB_H_ */
