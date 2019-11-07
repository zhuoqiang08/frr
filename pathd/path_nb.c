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

#include "pathd/path_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_pathd_info = {
	.name = "frr-pathd",
	.nodes = {
		{
			.xpath = "/frr-pathd:pathd/mpls/lsp",
			.cbs = {
				.create = pathd_mpls_lsp_create,
				.destroy = pathd_mpls_lsp_destroy,
				.apply_finish = pathd_mpls_lsp_apply_finish,
				.cli_show = cli_show_te_path_mpls,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/mpls/lsp/nhlfe",
			.cbs = {
				.create = pathd_mpls_lsp_nhlfe_create,
				.destroy = pathd_mpls_lsp_nhlfe_destroy,
				.cli_show = cli_show_te_path_mpls_nhlfe,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/mpls/lsp/nhlfe/interface",
			.cbs = {
				.modify = pathd_mpls_lsp_nhlfe_interface_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/mpls/lsp/nhlfe/labels/label",
			.cbs = {
				.create = pathd_mpls_lsp_nhlfe_labels_label_create,
				.destroy = pathd_mpls_lsp_nhlfe_labels_label_destroy,
				.move = pathd_mpls_lsp_nhlfe_labels_label_move,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/mpls/lsp/nhlfe/preference",
			.cbs = {
				.modify = pathd_mpls_lsp_nhlfe_preference_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
