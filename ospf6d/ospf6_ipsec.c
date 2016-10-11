/*
 * Authentication/Confidentiality for OSPFv3 - RFC 4552
 *
 * Copyright (C) 2013 Digistar, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "if.h"
#include "vrf.h"
#include "log.h"
#include "command.h"
#include "vty.h"
#include "privs.h"
#include "memory.h"

#include "ospf6d.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_message.h"
#include "ospf6_neighbor.h"
#include "ospf6_proto.h"
#include "ospf6_ipsec.h"
#include "ospf6d/ospf6_ipsec_clippy.c"

extern struct zebra_privs_t ospf6d_privs;

/* Debug option */
static unsigned char conf_debug_ospf6_ipsec;
#define OSPF6_DEBUG_IPSEC_ON() (conf_debug_ospf6_ipsec = 1)
#define OSPF6_DEBUG_IPSEC_OFF() (conf_debug_ospf6_ipsec = 0)
#define IS_OSPF6_DEBUG_IPSEC (conf_debug_ospf6_ipsec)

struct ipsec_entry *ospf6_ipsec_install(struct ospf6_interface *oi,
					struct in6_addr *dst,
					u_int8_t ipsec_proto, u_int32_t spi,
					u_int8_t ip_proto, u_int8_t auth_type,
					char auth_key[], u_int8_t enc_type,
					char enc_key[], int in, int out)
{
	struct ipsec_entry *ie;

	ie = XCALLOC(MTYPE_TMP, sizeof(*ie));
	ie->ipsec_proto = ipsec_proto;
	memcpy(&ie->dst, dst, sizeof(struct in6_addr));
	ie->spi = spi;
	ie->ip_proto = ip_proto;
	ie->auth_type = auth_type;
	strncpy(ie->auth_key, auth_key, HMAC_MAX_KEY_SIZE);
	ie->enc_type = enc_type;
	strncpy(ie->enc_key, enc_key, IPSEC_KEY_SIZE_MAX);
	strlcpy(ie->ifname, oi->interface->name, sizeof(ie->ifname));
	ie->in = in;
	ie->out = out;
	listnode_add(oi->ipsec_entries, ie);

	ipsec_sad_add(ie);
	if (in)
		ipsec_spd_add(ie, IPSEC_SPD_IN);
	if (out)
		ipsec_spd_add(ie, IPSEC_SPD_OUT);

	return ie;
}

void ospf6_ipsec_uninstall(struct ospf6_interface *oi, struct ipsec_entry *ie)
{
	struct ospf6_neighbor *on;
	struct listnode *node;

	ipsec_sad_del(ie);
	if (ie->in)
		ipsec_spd_del(ie, IPSEC_SPD_IN);
	if (ie->out)
		ipsec_spd_del(ie, IPSEC_SPD_OUT);

	for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, node, on))
		on->ipsec_entry = NULL;

	listnode_delete(oi->ipsec_entries, ie);
	free(ie);
}

void ospf6_update_ipsec(struct ospf6_interface *oi)
{
	struct ospf6_ipsec *ipsec = &oi->ipsec;
	struct in6_addr dst;
	struct listnode *node, *nnode;
	struct ipsec_entry *ie;
	struct ospf6_neighbor *on;

	/* remove previously installed IPsec entries on this interface */
	for (ALL_LIST_ELEMENTS(oi->ipsec_entries, node, nnode, ie))
		ospf6_ipsec_uninstall(oi, ie);

	if (ipsec->proto == IPSEC_DISABLED)
		return;

	/* OSPFv3 All SPF routers */
	inet_pton(AF_INET6, ALLSPFROUTERS6, &dst);
	ospf6_ipsec_install(oi, &dst, ipsec->proto, ipsec->spi, IPPROTO_OSPFIGP,
			    ipsec->auth_type, ipsec->auth_key, ipsec->enc_type,
			    ipsec->enc_key, 1, 1);

	/* OSPFv3 All DR routers */
	inet_pton(AF_INET6, ALLDROUTERS6, &dst);
	ospf6_ipsec_install(oi, &dst, ipsec->proto, ipsec->spi, IPPROTO_OSPFIGP,
			    ipsec->auth_type, ipsec->auth_key, ipsec->enc_type,
			    ipsec->enc_key, 1, 1);

	/* Incoming unicast */
	if (oi->linklocal_addr) {
		ospf6_ipsec_install(oi, oi->linklocal_addr, ipsec->proto,
				    ipsec->spi, IPPROTO_OSPFIGP,
				    ipsec->auth_type, ipsec->auth_key,
				    ipsec->enc_type, ipsec->enc_key, 1, 0);
	}

	/* Outgoing unicast */
	for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, node, on)) {
		if (on->ospf6_if == oi && on->state != OSPF6_NEIGHBOR_DOWN) {
			ospf6_ipsec_install(oi, &on->linklocal_addr,
					    ipsec->proto, ipsec->spi,
					    IPPROTO_OSPFIGP, ipsec->auth_type,
					    ipsec->auth_key, ipsec->enc_type,
					    ipsec->enc_key, 0, 1);
		}
	}
}

static int is_hexstr(const char *string)
{
	size_t i;

	for (i = 0; i < strlen(string); i++)
		if (!isxdigit(string[i]))
			return 0;

	return 1;
}

static int vty_ospf6_ipsec(struct vty *vty, const char *negate,
			   const char *proto_str, unsigned long spi,
			   const char *enc_type_str, const char *enc_key,
			   const char *auth_type_str, const char *auth_key)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi, *oi_tmp;
	struct ospf6_ipsec *ipsec;
	u_int8_t proto;
	int auth_type = 0;
	int auth_key_len = 0;
	int enc_type = 0;
	int enc_key_len = 0;

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);
	ipsec = &oi->ipsec;

	if (strcmp(proto_str, "authentication") == 0)
		proto = IPSEC_AH;
	else
		proto = IPSEC_ESP;

	if (auth_type_str) {
		if (strcmp(auth_type_str, "md5") == 0) {
			auth_type = HASH_HMAC_MD5;
			auth_key_len = HMAC_MD5_KEY_SIZE;
		} else {
			auth_type = HASH_HMAC_SHA1;
			auth_key_len = HMAC_SHA1_KEY_SIZE;
		}
	}

	if (enc_type_str) {
		if (strcmp(enc_type_str, "triple-des") == 0)
			enc_type = IPSEC_ENC_3DES;
		else if (strcmp(enc_type_str, "aes-cbc-128") == 0)
			enc_type = IPSEC_ENC_AES_128;
		else if (strcmp(enc_type_str, "aes-cbc-192") == 0)
			enc_type = IPSEC_ENC_AES_192;
		else if (strcmp(enc_type_str, "aes-cbc-256") == 0)
			enc_type = IPSEC_ENC_AES_256;
		else if (strcmp(enc_type_str, "des") == 0)
			enc_type = IPSEC_ENC_DES;
		else if (strcmp(enc_type_str, "null") == 0)
			enc_type = IPSEC_ENC_NULL;
		else
			assert(0);

		if (enc_type != IPSEC_ENC_NULL)
			enc_key_len = ipsec_enc_key_size[enc_type];
	}

	if (negate) {
		if (ipsec->proto != proto)
			return CMD_SUCCESS;
		if (ipsec->spi != spi)
			return CMD_SUCCESS;

		memset(ipsec, 0, sizeof(*ipsec));
		ipsec->proto = IPSEC_DISABLED;
	} else {
		struct vrf *vrf;

		/* validate keys */
		if (strlen(auth_key) != (size_t)auth_key_len) {
			vty_out(vty, "%% Invalid authentication key length\n");
			return CMD_WARNING;
		}
		if (!is_hexstr(auth_key)) {
			vty_out(vty, "%% Invalid authentication key\n");
			return CMD_WARNING;
		}
		if (proto == IPSEC_ESP) {
			if (enc_type != IPSEC_ENC_NULL
			    && strlen(enc_key) != (size_t)enc_key_len) {
				vty_out(vty,
					"%% Invalid encryption key length\n");
				return CMD_WARNING;
			}
			if (enc_type != IPSEC_ENC_NULL && !is_hexstr(enc_key)) {
				vty_out(vty, "%% Invalid encryption key\n");
				return CMD_WARNING;
			}
		}

		/* additional consistency checks */
		if (proto == IPSEC_ESP && ipsec->proto == IPSEC_AH) {
			vty_out(vty,
				"OSPFv3: Interface %s is already configured with "
				"authentication so\n cannot configure encryption\n",
				oi->interface->name);
			return CMD_WARNING;
		} else if (proto == IPSEC_AH && ipsec->proto == IPSEC_ESP) {
			vty_out(vty,
				"OSPFv3: Interface %s is already configured with "
				"encryption so\n cannot configure authentication\n",
				oi->interface->name);
			return CMD_WARNING;
		}
		if (ipsec->proto != IPSEC_DISABLED && ipsec->spi == spi) {
			/* warning only */
			vty_out(vty,
				"OSPFv3: Interface %s is already configured with SPI "
				"%lu\n",
				oi->interface->name, spi);
		}

		vrf = vrf_lookup_by_id(VRF_DEFAULT);
		FOR_ALL_INTERFACES(vrf, ifp) {
			oi_tmp = (struct ospf6_interface *)ifp->info;
			if (!oi_tmp)
				continue;

			if (oi_tmp->ipsec.spi == spi && oi != oi_tmp) {
				vty_out(vty, "%% SPI %lu is already in use\n",
					spi);
				return CMD_WARNING;
			}
		}

		ipsec->proto = proto;
		ipsec->spi = spi;
		ipsec->auth_type = auth_type;
		memset(ipsec->auth_key, 0, HMAC_MAX_KEY_SIZE + 1);
		strncpy(ipsec->auth_key, auth_key, auth_key_len);
		if (proto == IPSEC_ESP) {
			ipsec->enc_type = enc_type;
			if (ipsec->enc_type != IPSEC_ENC_NULL) {
				memset(ipsec->enc_key, 0,
				       IPSEC_KEY_SIZE_MAX + 1);
				strncpy(ipsec->enc_key, enc_key, enc_key_len);
			}
		}
	}

	ospf6_update_ipsec(oi);

	return CMD_SUCCESS;
}

static int vty_ospf6_ipsec_debug(struct vty *vty, const char *negate)
{
	if (negate)
		OSPF6_DEBUG_IPSEC_OFF();
	else
		OSPF6_DEBUG_IPSEC_ON();

	return CMD_SUCCESS;
}

int config_write_ospf6_debug_ipsec(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_IPSEC)
		vty_out(vty, "debug ospf6 ipsec\n");
	return 0;
}

DEFPY  (ospf6_ipsec,
	ospf6_ipsec_cmd,
	"[no] ipv6 ospf6\
	    <\
	      authentication$proto ipsec spi (256-4294967295)\
	      |encryption$proto    ipsec spi (256-4294967295) esp\
	      <\
	        aes-cbc-128$enc_type  WORD$enc_key\
	        |aes-cbc-192$enc_type WORD$enc_key\
	        |aes-cbc-256$enc_type WORD$enc_key\
	        |des$enc_type         WORD$enc_key\
	        |triple-des$enc_type  WORD$enc_key\
	        |null$enc_type\
	      >\
	    >\
	    <md5$auth_type WORD$auth_key|sha1$auth_type WORD$auth_key>",
	NO_STR IPV6_STR
	OSPF6_STR
	"Enable authentication\n"
	"Use IPsec authentication\n"
	"Set the SPI (Security Parameters Index)\n"
	"SPI\n"
	"Enable encryption\n"
	"Use IPsec authentication\n"
	"Set the SPI (Security Parameters Index)\n"
	"SPI\n"
	"Use ESP encapsulation\n"
	"Use AES-CBC encryption (128 bit key)\n"
	"128bit key (32 chars)\n"
	"Use AES-CBC encryption (192 bit key)\n"
	"192bit key (48 chars)\n"
	"Use AES-CBC encryption (256 bit key)\n"
	"256bit key (64 chars)\n"
	"Use DES encryption\n"
	"64bit key (16 chars)\n"
	"Use 3DES encryption\n"
	"192bit key (48 chars)\n"
	"ESP with no encryption\n"
	"Use MD5 authentication\n"
	"MD5 key (32 chars)\n"
	"Use SHA-1 authentication\n"
	"SHA-1 key (40 chars)\n")
{
	return vty_ospf6_ipsec(vty, no, proto, spi, enc_type, enc_key,
			       auth_type, auth_key);
}

DEFPY  (debug_ospf6_ipsec,
	debug_ospf6_ipsec_cmd,
	"[no] debug ospf6 ipsec",
	NO_STR
	"Debugging functions (see also 'undebug')\n"
	OSPF6_STR
	"Debug OSPFv3 Interface\n")
{
	return vty_ospf6_ipsec_debug(vty, no);
}

void ospf6_ipsec_init(void)
{
	ipsec_init(&ospf6d_privs);

	install_element(INTERFACE_NODE, &ospf6_ipsec_cmd);
	install_element(ENABLE_NODE, &debug_ospf6_ipsec_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_ipsec_cmd);
}
