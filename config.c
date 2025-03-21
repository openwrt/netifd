/*
 * netifd - network interface daemon
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
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
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <uci.h>

#include <libubox/blobmsg_json.h>

#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "iprule.h"
#include "proto.h"
#include "config.h"
#include "ubus.h"
#include "ucode.h"

bool config_init = false;

static struct uci_context *uci_ctx;
static struct uci_package *uci_network;
static struct blob_attr *board_netdevs;
static struct blob_buf b;

static bool
config_bridge_has_vlans(const char *br_name)
{
	struct uci_element *e;

	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *name;

		if (strcmp(s->type, "bridge-vlan") != 0)
			continue;

		name = uci_lookup_option_string(uci_ctx, s, "device");
		if (!name)
			continue;

		if (!strcmp(name, br_name))
			return true;
	}

	return false;
}

static void
config_fixup_bridge_var(struct uci_section *s, const char *name, const char *val)
{
	struct uci_ptr ptr = {
		.p = s->package,
		.s = s,
		.option = name,
		.value = val,
	};

	uci_lookup_ptr(uci_ctx, &ptr, NULL, false);
	if (ptr.o)
		return;

	uci_set(uci_ctx, &ptr);
}

/**
 * config_fixup_bridge_ports - translate deprecated configs
 *
 * Old configs used "ifname" option for specifying bridge ports. For backward
 * compatibility translate it into the new "ports" option.
 */
static void config_fixup_bridge_ports(struct uci_section *s)
{
	struct uci_ptr ptr = {
		.p = s->package,
		.s = s,
		.option = "ifname",
	};

	if (uci_lookup_option(uci_ctx, s, "ports"))
		return;

	uci_lookup_ptr(uci_ctx, &ptr, NULL, false);
	if (!ptr.o)
		return;

	ptr.value = "ports";
	uci_rename(uci_ctx, &ptr);
}

static void
config_fixup_bridge_vlan_filtering(struct uci_section *s, const char *name)
{
	bool has_vlans = config_bridge_has_vlans(name);

	config_fixup_bridge_var(s, "__has_vlans", has_vlans ? "1" : "0");

	if (!has_vlans)
		return;

	config_fixup_bridge_var(s, "vlan_filtering", "1");
}

static int
config_parse_bridge_interface(struct uci_section *s, struct device_type *devtype)
{
	char *name;

	name = alloca(strlen(s->e.name) + strlen(devtype->name_prefix) + 2);
	sprintf(name, "%s-%s", devtype->name_prefix, s->e.name);
	blobmsg_add_string(&b, "name", name);

	config_fixup_bridge_ports(s);
	config_fixup_bridge_vlan_filtering(s, name);
	uci_to_blob(&b, s, devtype->config_params);
	if (!device_create(name, devtype, b.head)) {
		D(INTERFACE, "Failed to create '%s' device for interface '%s'",
			devtype->name, s->e.name);
	}

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "ifname", name);
	return 0;
}

static void
config_parse_interface(struct uci_section *s, bool alias)
{
	struct interface *iface;
	const char *type = NULL, *disabled;
	struct blob_attr *config;
	bool bridge = false;
	struct device_type *devtype = NULL;

	disabled = uci_lookup_option_string(uci_ctx, s, "disabled");
	if (disabled && !strcmp(disabled, "1"))
		return;

	blob_buf_init(&b, 0);

	if (!alias)
		type = uci_lookup_option_string(uci_ctx, s, "type");

	if (type)
		devtype = device_type_get(type);

	if (devtype && devtype->bridge_capability) {
		if (config_parse_bridge_interface(s, devtype))
			return;

		bridge = true;
	}

	uci_to_blob(&b, s, &interface_attr_list);

	iface = interface_alloc(s->e.name, b.head, false);
	if (!iface)
		return;

	if (iface->proto_handler && iface->proto_handler->config_params)
		uci_to_blob(&b, s, iface->proto_handler->config_params);

	if (!bridge && uci_to_blob(&b, s, simple_device_type.config_params))
		iface->device_config = true;

	config = blob_memdup(b.head);
	if (!config)
		goto error;

	if (alias) {
		if (!interface_add_alias(iface, config))
			goto error_free_config;
	} else {
		if (!interface_add(iface, config))
			goto error_free_config;
	}
	return;

error_free_config:
	free(config);
error:
	free(iface);
}

static void
config_parse_route(struct uci_section *s, bool v6)
{
	void *route;

	blob_buf_init(&b, 0);
	route = blobmsg_open_array(&b, "route");
	uci_to_blob(&b, s, &route_attr_list);
	blobmsg_close_array(&b, route);
	interface_ip_add_route(NULL, blob_data(b.head), v6);
}

static void
config_parse_neighbor(struct uci_section *s, bool v6)
{
	void *neighbor;
	blob_buf_init(&b,0);
	neighbor = blobmsg_open_array(&b, "neighbor");
	uci_to_blob(&b,s, &neighbor_attr_list);
	blobmsg_close_array(&b, neighbor);
	interface_ip_add_neighbor(NULL, blob_data(b.head), v6);
}

static void
config_parse_rule(struct uci_section *s, bool v6)
{
	void *rule;

	blob_buf_init(&b, 0);
	rule = blobmsg_open_array(&b, "rule");
	uci_to_blob(&b, s, &rule_attr_list);
	blobmsg_close_array(&b, rule);
	iprule_add(blob_data(b.head), v6);
}

static void
config_init_devices(bool bridge)
{
	struct uci_element *e;

	uci_foreach_element(&uci_network->sections, e) {
		const struct uci_blob_param_list *params = NULL;
		struct uci_section *s = uci_to_section(e);
		struct device_type *devtype = NULL;
		struct device *dev;
		const char *type, *name;

		if (strcmp(s->type, "device") != 0)
			continue;

		name = uci_lookup_option_string(uci_ctx, s, "name");
		if (!name)
			continue;

		type = uci_lookup_option_string(uci_ctx, s, "type");
		if (type)
			devtype = device_type_get(type);

		if (bridge != (devtype && devtype->bridge_capability))
			continue;

		if (devtype)
			params = devtype->config_params;
		if (!params)
			params = simple_device_type.config_params;

		if (devtype && devtype->bridge_capability) {
			config_fixup_bridge_ports(s);
			config_fixup_bridge_vlan_filtering(s, name);
		}

		blob_buf_init(&b, 0);
		uci_to_blob(&b, s, params);
		if (devtype) {
			dev = device_create(name, devtype, b.head);
			if (!dev)
				continue;
		} else {
			dev = device_get(name, 1);
			if (!dev)
				continue;

			dev->current_config = true;
			device_apply_config(dev, dev->type, b.head);
		}
		dev->default_config = false;
	}
}

static void
config_parse_vlan(struct device *dev, struct uci_section *s)
{
	enum {
		BRVLAN_ATTR_VID,
		BRVLAN_ATTR_LOCAL,
		BRVLAN_ATTR_PORTS,
		BRVLAN_ATTR_ALIAS,
		__BRVLAN_ATTR_MAX,
	};
	static const struct blobmsg_policy vlan_attrs[__BRVLAN_ATTR_MAX] = {
		[BRVLAN_ATTR_VID] = { "vlan", BLOBMSG_TYPE_INT32 },
		[BRVLAN_ATTR_LOCAL] = { "local", BLOBMSG_TYPE_BOOL },
		[BRVLAN_ATTR_PORTS] = { "ports", BLOBMSG_TYPE_ARRAY },
		[BRVLAN_ATTR_ALIAS] = { "alias", BLOBMSG_TYPE_ARRAY },
	};
	static const struct uci_blob_param_info vlan_attr_info[__BRVLAN_ATTR_MAX] = {
		[BRVLAN_ATTR_PORTS] = { .type = BLOBMSG_TYPE_STRING },
		[BRVLAN_ATTR_ALIAS] = { .type = BLOBMSG_TYPE_STRING },
	};
	static const struct uci_blob_param_list vlan_attr_list = {
		.n_params = __BRVLAN_ATTR_MAX,
		.params = vlan_attrs,
		.info = vlan_attr_info,
	};
	struct blob_attr *tb[__BRVLAN_ATTR_MAX];
	struct blob_attr *cur;
	struct bridge_vlan_port *port;
	struct bridge_vlan *vlan;
	unsigned int vid;
	const char *val;
	char *name_buf;
	int name_len = 0;
	int n_ports = 0;
	size_t rem;

	val = uci_lookup_option_string(uci_ctx, s, "vlan");
	if (!val)
		return;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &vlan_attr_list);
	blobmsg_parse(vlan_attrs, __BRVLAN_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if (!tb[BRVLAN_ATTR_VID])
		return;

	vid = blobmsg_get_u32(tb[BRVLAN_ATTR_VID]);
	if (!vid || vid > 4095)
		return;

	blobmsg_for_each_attr(cur, tb[BRVLAN_ATTR_PORTS], rem) {
		name_len += strlen(blobmsg_get_string(cur)) + 1;
		n_ports++;
	}

	vlan = calloc(1, sizeof(*vlan) + n_ports * sizeof(*port) + name_len);
	if (!vlan)
		return;

	vlan->vid = vid;
	vlan->local = true;
	if (tb[BRVLAN_ATTR_LOCAL])
		vlan->local = blobmsg_get_bool(tb[BRVLAN_ATTR_LOCAL]);

	vlan->n_ports = n_ports;
	vlan->ports = port = (struct bridge_vlan_port *)&vlan[1];
	INIT_LIST_HEAD(&vlan->hotplug_ports);
	name_buf = (char *)&port[n_ports];

	blobmsg_for_each_attr(cur, tb[BRVLAN_ATTR_PORTS], rem) {
		char *sep;

		port->ifname = name_buf;
		port->flags = BRVLAN_F_UNTAGGED;
		strcpy(name_buf, blobmsg_get_string(cur));

		sep = strchr(name_buf, ':');
		if (sep) {
			for (*sep = 0, sep++; *sep; sep++)
				switch (*sep) {
				case '*':
					port->flags |= BRVLAN_F_PVID;
					break;
				case 't':
					port->flags &= ~BRVLAN_F_UNTAGGED;
					break;
				}
		}

		name_buf += strlen(name_buf) + 1;
		port++;
	}

	blobmsg_for_each_attr(cur, tb[BRVLAN_ATTR_ALIAS], rem)
		kvlist_set(&dev->vlan_aliases, blobmsg_get_string(cur), &vid);

	vlist_add(&dev->vlans, &vlan->node, &vlan->vid);
}


static void
config_init_vlans(void)
{
	struct uci_element *e;
	struct device *dev;

	device_vlan_update(false);
	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *name;

		if (strcmp(s->type, "bridge-vlan") != 0)
			continue;

		name = uci_lookup_option_string(uci_ctx, s, "device");
		if (!name)
			continue;

		dev = device_get(name, 0);
		if (!dev || !dev->vlans.update)
			continue;

		config_parse_vlan(dev, s);
	}
	device_vlan_update(true);
}

static struct uci_package *
config_init_package(const char *config)
{
	struct uci_context *ctx = uci_ctx;
	struct uci_package *p = NULL;

	if (!ctx) {
		ctx = uci_alloc_context();
		uci_ctx = ctx;

		ctx->flags &= ~UCI_FLAG_STRICT;
		if (config_path)
			uci_set_confdir(ctx, config_path);

#ifdef DUMMY_MODE
		uci_set_savedir(ctx, "./tmp");
#endif
	} else {
		p = uci_lookup_package(ctx, config);
		if (p)
			uci_unload(ctx, p);
	}

	if (uci_load(ctx, config, &p))
		return NULL;

	return p;
}

static void
config_init_interfaces(void)
{
	struct uci_element *e;

	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "interface"))
			config_parse_interface(s, false);
	}

	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "alias"))
			config_parse_interface(s, true);
	}
}

static void
config_init_ip(void)
{
	struct interface *iface;
	struct uci_element *e;

	vlist_for_each_element(&interfaces, iface, node)
		interface_ip_update_start(&iface->config_ip);

	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "route"))
			config_parse_route(s, false);
		else if (!strcmp(s->type, "route6"))
			config_parse_route(s, true);
		if (!strcmp(s->type, "neighbor"))
			config_parse_neighbor(s, false);
		else if (!strcmp(s->type, "neighbor6"))
			config_parse_neighbor(s, true);
	}

	vlist_for_each_element(&interfaces, iface, node)
		interface_ip_update_complete(&iface->config_ip);
}

static void
config_init_rules(void)
{
	struct uci_element *e;

	iprule_update_start();

	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "rule"))
			config_parse_rule(s, false);
		else if (!strcmp(s->type, "rule6"))
			config_parse_rule(s, true);
	}

	iprule_update_complete();
}

static void
config_init_globals(void)
{
	struct uci_section *globals = uci_lookup_section(
			uci_ctx, uci_network, "globals");
	if (!globals)
		return;

	const char *ula_prefix = uci_lookup_option_string(
			uci_ctx, globals, "ula_prefix");
	interface_ip_set_ula_prefix(ula_prefix);
}

static struct blob_attr *
config_find_blobmsg_attr(struct blob_attr *attr, const char *name, int type)
{
	struct blobmsg_policy policy = { .name = name, .type = type };
	struct blob_attr *cur;

	blobmsg_parse(&policy, 1, &cur, blobmsg_data(attr), blobmsg_len(attr));

	return cur;
}

struct ether_addr *config_get_default_macaddr(const char *ifname)
{
	struct blob_attr *cur;

	if (!board_netdevs)
		return NULL;

	cur = config_find_blobmsg_attr(board_netdevs, ifname, BLOBMSG_TYPE_TABLE);
	if (!cur)
		return NULL;

	cur = config_find_blobmsg_attr(cur, "macaddr", BLOBMSG_TYPE_STRING);
	if (!cur)
		return NULL;

	return ether_aton(blobmsg_get_string(cur));
}

int config_get_default_gro(const char *ifname)
{
	struct blob_attr *cur;

	if (!board_netdevs)
		return -1;

	cur = config_find_blobmsg_attr(board_netdevs, ifname, BLOBMSG_TYPE_TABLE);
	if (!cur)
		return -1;

	cur = config_find_blobmsg_attr(cur, "gro", BLOBMSG_TYPE_BOOL);
	if (!cur)
		return -1;

	return blobmsg_get_bool(cur);
}

const char *config_get_default_conduit(const char *ifname)
{
	struct blob_attr *cur;

	if (!board_netdevs)
		return NULL;

	cur = config_find_blobmsg_attr(board_netdevs, ifname, BLOBMSG_TYPE_TABLE);
	if (!cur)
		return NULL;

	cur = config_find_blobmsg_attr(cur, "conduit", BLOBMSG_TYPE_STRING);
	if (!cur)
		return NULL;

	return blobmsg_get_string(cur);
}

static void
config_init_board(void)
{
	struct blob_attr *cur;

	blob_buf_init(&b, 0);

	if (!blobmsg_add_json_from_file(&b, DEFAULT_BOARD_JSON))
		return;

	free(board_netdevs);
	board_netdevs = NULL;

	cur = config_find_blobmsg_attr(b.head, "network_device",
				       BLOBMSG_TYPE_TABLE);
	if (!cur)
		return;

	board_netdevs = blob_memdup(cur);
}

int
config_init_all(void)
{
	int ret = 0;
	char *err;

	uci_network = config_init_package("network");
	if (!uci_network) {
		uci_get_errorstr(uci_ctx, &err, NULL);
		netifd_log_message(L_CRIT, "Failed to load network config (%s)\n", err);
		free(err);
		return -1;
	}

	config_init_board();

	vlist_update(&interfaces);
	config_init = true;

	device_reset_config();
	config_init_devices(true);
	config_init_vlans();
	config_init_devices(false);
	config_init_interfaces();
	config_init_ip();
	config_init_rules();
	config_init_globals();
	netifd_ucode_config_load(false);

	config_init = false;

	device_reset_old();
	device_init_pending();
	vlist_flush(&interfaces);
	interface_refresh_assignments(false);
	interface_start_pending();
	netifd_ucode_config_load(true);

	return ret;
}
