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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <uci.h>

#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "iprule.h"
#include "proto.h"
#include "wireless.h"
#include "config.h"

bool config_init = false;

static struct uci_context *uci_ctx;
static struct uci_package *uci_network;
static struct uci_package *uci_wireless;
static struct blob_buf b;

static int
config_parse_bridge_interface(struct uci_section *s)
{
	char *name;

	name = alloca(strlen(s->e.name) + 4);
	sprintf(name, "br-%s", s->e.name);
	blobmsg_add_string(&b, "name", name);

	uci_to_blob(&b, s, bridge_device_type.config_params);
	if (!device_create(name, &bridge_device_type, b.head)) {
		D(INTERFACE, "Failed to create bridge for interface '%s'\n", s->e.name);
		return -EINVAL;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "ifname", name);
	return 0;
}

static void
config_parse_interface(struct uci_section *s, bool alias)
{
	struct interface *iface;
	const char *type = NULL;
	struct blob_attr *config;
	struct device *dev;
	bool bridge = false;

	blob_buf_init(&b, 0);

	if (!alias)
		type = uci_lookup_option_string(uci_ctx, s, "type");
	if (type && !strcmp(type, "bridge")) {
		if (config_parse_bridge_interface(s))
			return;

		bridge = true;
	}

	uci_to_blob(&b, s, &interface_attr_list);

	iface = interface_alloc(s->e.name, b.head);
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
		interface_add(iface, config);
	}

	/*
	 * need to look up the interface name again, in case of config update,
	 * the pointer will have changed
	 */
	iface = vlist_find(&interfaces, s->e.name, iface, node);
	if (!iface)
		return;

	dev = iface->main_dev.dev;
	if (!dev || !dev->default_config)
		return;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, dev->type->config_params);
	if (blob_len(b.head) == 0)
		return;

	device_set_config(dev, dev->type, b.head);
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
config_init_devices(void)
{
	struct uci_element *e;

	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const struct device_type *devtype = NULL;
		const char *type, *name;

		if (strcmp(s->type, "device") != 0)
			continue;

		name = uci_lookup_option_string(uci_ctx, s, "name");
		if (!name)
			continue;

		type = uci_lookup_option_string(uci_ctx, s, "type");
		if (type) {
			if (!strcmp(type, "bridge"))
				devtype = &bridge_device_type;
			else if (!strcmp(type, "tunnel"))
				devtype = &tunnel_device_type;
			else if (!strcmp(type, "macvlan"))
				devtype = &macvlan_device_type;
		}

		if (!devtype)
			devtype = &simple_device_type;

		blob_buf_init(&b, 0);
		uci_to_blob(&b, s, devtype->config_params);
		device_create(name, devtype, b.head);
	}
}

static struct uci_package *
config_init_package(const char *config)
{
	struct uci_context *ctx = uci_ctx;
	struct uci_package *p = NULL;

	if (!ctx) {
		ctx = uci_alloc_context();
		uci_ctx = ctx;

#ifdef DUMMY_MODE
		uci_set_confdir(ctx, "./config");
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
config_init_routes(void)
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

static void
config_parse_wireless_device(struct uci_section *s)
{
	struct wireless_driver *drv;
	const char *driver_name;

	driver_name = uci_lookup_option_string(uci_ctx, s, "type");
	if (!driver_name)
		return;

	drv = avl_find_element(&wireless_drivers, driver_name, drv, node);
	if (!drv)
		return;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, drv->device.config);
	wireless_device_create(drv, s->e.name, b.head);
}

static void
config_parse_wireless_interface(struct wireless_device *wdev, struct uci_section *s)
{
	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, wdev->drv->interface.config);
	wireless_interface_create(wdev, b.head, s->e.name);
}

static void
config_init_wireless(void)
{
	struct wireless_device *wdev;
	struct uci_element *e;
	const char *dev_name;

	if (!uci_wireless) {
		DPRINTF("No wireless configuration found\n");
		return;
	}

	vlist_update(&wireless_devices);

	uci_foreach_element(&uci_wireless->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if (strcmp(s->type, "wifi-device") != 0)
			continue;

		config_parse_wireless_device(s);
	}

	vlist_flush(&wireless_devices);

	vlist_for_each_element(&wireless_devices, wdev, node) {
		wdev->vif_idx = 0;
		vlist_update(&wdev->interfaces);
	}

	uci_foreach_element(&uci_wireless->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "wifi-iface") != 0)
			continue;

		dev_name = uci_lookup_option_string(uci_ctx, s, "device");
		if (!dev_name)
			continue;

		wdev = vlist_find(&wireless_devices, dev_name, wdev, node);
		if (!wdev) {
			DPRINTF("device %s not found!\n", dev_name);
			continue;
		}

		config_parse_wireless_interface(wdev, s);
	}

	vlist_for_each_element(&wireless_devices, wdev, node)
		vlist_flush(&wdev->interfaces);
}

void
config_init_all(void)
{
	uci_network = config_init_package("network");
	if (!uci_network) {
		fprintf(stderr, "Failed to load network config\n");
		return;
	}

	uci_wireless = config_init_package("wireless");

	vlist_update(&interfaces);
	config_init = true;
	device_lock();

	device_reset_config();
	config_init_devices();
	config_init_interfaces();
	config_init_routes();
	config_init_rules();
	config_init_globals();
	config_init_wireless();

	config_init = false;
	device_unlock();

	device_reset_old();
	device_init_pending();
	vlist_flush(&interfaces);
	device_free_unused(NULL);
	interface_refresh_assignments(false);
	interface_start_pending();
	wireless_start_pending();
}
