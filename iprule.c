/*
 * netifd - network interface daemon
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2013 Jo-Philipp Wich <jow@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "iprule.h"
#include "proto.h"
#include "ubus.h"
#include "system.h"

struct vlist_tree iprules;
static bool iprules_flushed = false;
static unsigned int iprules_counter[2];

enum {
	RULE_INTERFACE_IN,
	RULE_INTERFACE_OUT,
	RULE_INVERT,
	RULE_SRC,
	RULE_DEST,
	RULE_PRIORITY,
	RULE_TOS,
	RULE_FWMARK,
	RULE_LOOKUP,
	RULE_ACTION,
	RULE_GOTO,
	__RULE_MAX
};

static const struct blobmsg_policy rule_attr[__RULE_MAX] = {
	[RULE_INTERFACE_IN] = { .name = "in", .type = BLOBMSG_TYPE_STRING },
	[RULE_INTERFACE_OUT] = { .name = "out", .type = BLOBMSG_TYPE_STRING },
	[RULE_INVERT] = { .name = "invert", .type = BLOBMSG_TYPE_BOOL },
	[RULE_SRC] = { .name = "src", .type = BLOBMSG_TYPE_STRING },
	[RULE_DEST] = { .name = "dest", .type = BLOBMSG_TYPE_STRING },
	[RULE_PRIORITY] = { .name = "priority", .type = BLOBMSG_TYPE_INT32 },
	[RULE_TOS] = { .name = "tos", .type = BLOBMSG_TYPE_INT32 },
	[RULE_FWMARK] = { .name = "mark", .type = BLOBMSG_TYPE_STRING },
	[RULE_LOOKUP] = { .name = "lookup", .type = BLOBMSG_TYPE_STRING },
	[RULE_ACTION] = { .name = "action", .type = BLOBMSG_TYPE_STRING },
	[RULE_GOTO]   = { .name = "goto", .type = BLOBMSG_TYPE_INT32 },
};

const struct uci_blob_param_list rule_attr_list = {
	.n_params = __RULE_MAX,
	.params = rule_attr,
};


static bool
iprule_parse_mark(const char *mark, struct iprule *rule)
{
	char *s, *e;
	unsigned int n;

	if ((s = strchr(mark, '/')) != NULL)
		*s++ = 0;

	n = strtoul(mark, &e, 0);

	if (e == mark || *e)
		return false;

	rule->fwmark = n;
	rule->flags |= IPRULE_FWMARK;

	if (s) {
		n = strtoul(s, &e, 0);

		if (e == s || *e)
			return false;

		rule->fwmask = n;
		rule->flags |= IPRULE_FWMASK;
	}

	return true;
}

void
iprule_add(struct blob_attr *attr, bool v6)
{
	struct interface *iif = NULL, *oif = NULL;
	struct blob_attr *tb[__RULE_MAX], *cur;
	struct interface *iface;
	struct iprule *rule;
	int af = v6 ? AF_INET6 : AF_INET;

	blobmsg_parse(rule_attr, __RULE_MAX, tb, blobmsg_data(attr), blobmsg_data_len(attr));

	rule = calloc(1, sizeof(*rule));
	if (!rule)
		return;

	rule->flags = v6 ? IPRULE_INET6 : IPRULE_INET4;
	rule->order = iprules_counter[rule->flags]++;

	if ((cur = tb[RULE_INVERT]) != NULL)
		rule->invert = blobmsg_get_bool(cur);

	if ((cur = tb[RULE_INTERFACE_IN]) != NULL) {
		iif = vlist_find(&interfaces, blobmsg_data(cur), iface, node);

		if (!iif || !iif->l3_dev.dev) {
			DPRINTF("Failed to resolve device of network: %s\n", (char *) blobmsg_data(cur));
			goto error;
		}

		memcpy(rule->in_dev, iif->l3_dev.dev->ifname, sizeof(rule->in_dev));
		rule->flags |= IPRULE_IN;
	}

	if ((cur = tb[RULE_INTERFACE_OUT]) != NULL) {
		oif = vlist_find(&interfaces, blobmsg_data(cur), iface, node);

		if (!oif || !oif->l3_dev.dev) {
			DPRINTF("Failed to resolve device of network: %s\n", (char *) blobmsg_data(cur));
			goto error;
		}

		memcpy(rule->out_dev, oif->l3_dev.dev->ifname, sizeof(rule->out_dev));
		rule->flags |= IPRULE_OUT;
	}

	if ((cur = tb[RULE_SRC]) != NULL) {
		if (!parse_ip_and_netmask(af, blobmsg_data(cur), &rule->src_addr, &rule->src_mask)) {
			DPRINTF("Failed to parse rule source: %s\n", (char *) blobmsg_data(cur));
			goto error;
		}
		rule->flags |= IPRULE_SRC;
	}

	if ((cur = tb[RULE_DEST]) != NULL) {
		if (!parse_ip_and_netmask(af, blobmsg_data(cur), &rule->dest_addr, &rule->dest_mask)) {
			DPRINTF("Failed to parse rule destination: %s\n", (char *) blobmsg_data(cur));
			goto error;
		}
		rule->flags |= IPRULE_DEST;
	}

	if ((cur = tb[RULE_PRIORITY]) != NULL) {
		rule->priority = blobmsg_get_u32(cur);
		rule->flags |= IPRULE_PRIORITY;
	}

	if ((cur = tb[RULE_TOS]) != NULL) {
		if ((rule->tos = blobmsg_get_u32(cur)) > 255) {
			DPRINTF("Invalid TOS value: %u\n", blobmsg_get_u32(cur));
			goto error;
		}
		rule->flags |= IPRULE_TOS;
	}

	if ((cur = tb[RULE_FWMARK]) != NULL) {
		if (!iprule_parse_mark(blobmsg_data(cur), rule)) {
			DPRINTF("Failed to parse rule fwmark: %s\n", (char *) blobmsg_data(cur));
			goto error;
		}
		/* flags set by iprule_parse_mark() */
	}

	if ((cur = tb[RULE_LOOKUP]) != NULL) {
		if (!system_resolve_rt_table(blobmsg_data(cur), &rule->lookup)) {
			DPRINTF("Failed to parse rule lookup table: %s\n", (char *) blobmsg_data(cur));
			goto error;
		}
		rule->flags |= IPRULE_LOOKUP;
	}

	if ((cur = tb[RULE_ACTION]) != NULL) {
		if (!system_resolve_iprule_action(blobmsg_data(cur), &rule->action)) {
			DPRINTF("Failed to parse rule action: %s\n", (char *) blobmsg_data(cur));
			goto error;
		}
		rule->flags |= IPRULE_ACTION;
	}

	if ((cur = tb[RULE_GOTO]) != NULL) {
		rule->gotoid = blobmsg_get_u32(cur);
		rule->flags |= IPRULE_GOTO;
	}

	vlist_add(&iprules, &rule->node, &rule->flags);
	return;

error:
	free(rule);
}

void
iprule_update_start(void)
{
	if (!iprules_flushed) {
		system_flush_iprules();
		iprules_flushed = true;
	}

	iprules_counter[0] = 1;
	iprules_counter[1] = 1;
	vlist_update(&iprules);
}

void
iprule_update_complete(void)
{
	vlist_flush(&iprules);
}


static int
rule_cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, sizeof(struct iprule)-offsetof(struct iprule, flags));
}

static void
iprule_update_rule(struct vlist_tree *tree,
                   struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct iprule *rule_old, *rule_new;

	rule_old = container_of(node_old, struct iprule, node);
	rule_new = container_of(node_new, struct iprule, node);

	if (node_old) {
		system_del_iprule(rule_old);
		free(rule_old);
	}

	if (node_new)
		system_add_iprule(rule_new);
}

static void __init
iprule_init_list(void)
{
	vlist_init(&iprules, rule_cmp, iprule_update_rule);
}
