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

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"
#include "ubus.h"
#include "config.h"
#include "system.h"

struct vlist_tree interfaces;
static LIST_HEAD(iface_all_users);

enum {
	IFACE_ATTR_IFNAME,
	IFACE_ATTR_PROTO,
	IFACE_ATTR_AUTO,
	IFACE_ATTR_DEFAULTROUTE,
	IFACE_ATTR_PEERDNS,
	IFACE_ATTR_DNS,
	IFACE_ATTR_DNS_SEARCH,
	IFACE_ATTR_METRIC,
	IFACE_ATTR_INTERFACE,
	IFACE_ATTR_IP6ASSIGN,
	IFACE_ATTR_IP6HINT,
	IFACE_ATTR_IP4TABLE,
	IFACE_ATTR_IP6TABLE,
	IFACE_ATTR_IP6CLASS,
	IFACE_ATTR_DELEGATE,
	IFACE_ATTR_MAX
};

static const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_AUTO] = { .name = "auto", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DEFAULTROUTE] = { .name = "defaultroute", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_PEERDNS] = { .name = "peerdns", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_METRIC] = { .name = "metric", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_DNS] = { .name = "dns", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_DNS_SEARCH] = { .name = "dns_search", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IP6ASSIGN] = { .name = "ip6assign", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ATTR_IP6HINT] = { .name = "ip6hint", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IP4TABLE] = { .name = "ip4table", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IP6TABLE] = { .name = "ip6table", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IP6CLASS] = { .name = "ip6class", .type = BLOBMSG_TYPE_ARRAY },
	[IFACE_ATTR_DELEGATE] = { .name = "delegate", .type = BLOBMSG_TYPE_BOOL },
};

static const struct uci_blob_param_info iface_attr_info[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_DNS] = { .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IP6CLASS] = { .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list interface_attr_list = {
	.n_params = IFACE_ATTR_MAX,
	.params = iface_attrs,
	.info = iface_attr_info,
};

static void
interface_clear_errors(struct interface *iface)
{
	struct interface_error *error, *tmp;

	list_for_each_entry_safe(error, tmp, &iface->errors, list) {
		list_del(&error->list);
		free(error);
	}
}

void interface_add_error(struct interface *iface, const char *subsystem,
			 const char *code, const char **data, int n_data)
{
	struct interface_error *error;
	int i, len = 0;
	int *datalen = NULL;
	char *dest, *d_subsys, *d_code;

	if (n_data) {
		len = n_data * sizeof(char *);
		datalen = alloca(len);
		for (i = 0; i < n_data; i++) {
			datalen[i] = strlen(data[i]) + 1;
			len += datalen[i];
		}
	}

	error = calloc_a(sizeof(*error) + sizeof(char *) + len,
		&d_subsys, subsystem ? strlen(subsystem) + 1 : 0,
		&d_code, code ? strlen(code) + 1 : 0);
	if (!error)
		return;

	list_add_tail(&error->list, &iface->errors);

	dest = (char *) &error->data[n_data + 1];
	for (i = 0; i < n_data; i++) {
		error->data[i] = dest;
		memcpy(dest, data[i], datalen[i]);
		dest += datalen[i];
	}
	error->data[n_data++] = NULL;

	if (subsystem)
		error->subsystem = strcpy(d_subsys, subsystem);

	if (code)
		error->code = strcpy(d_code, code);
}

static void
interface_data_del(struct interface *iface, struct interface_data *data)
{
	avl_delete(&iface->data, &data->node);
	free(data);
}

static void
interface_data_flush(struct interface *iface)
{
	struct interface_data *d, *tmp;

	avl_for_each_element_safe(&iface->data, d, node, tmp)
		interface_data_del(iface, d);
}

int
interface_add_data(struct interface *iface, const struct blob_attr *data)
{
	struct interface_data *n, *o;

	if (!blobmsg_check_attr(data, true))
		return UBUS_STATUS_INVALID_ARGUMENT;

	const char *name = blobmsg_name(data);
	unsigned len = blob_pad_len(data);

	o = avl_find_element(&iface->data, name, o, node);
	if (o) {
		if (blob_pad_len(o->data) == len && !memcmp(o->data, data, len))
			return 0;

		interface_data_del(iface, o);
	}

	n = calloc(1, sizeof(*n) + len);
	memcpy(n->data, data, len);
	n->node.key = blobmsg_name(n->data);
	avl_insert(&iface->data, &n->node);

	iface->updated |= IUF_DATA;
	return 0;
}

static void
interface_event(struct interface *iface, enum interface_event ev)
{
	struct interface_user *dep, *tmp;
	struct device *adev = NULL;

	list_for_each_entry_safe(dep, tmp, &iface->users, list)
		dep->cb(dep, iface, ev);

	list_for_each_entry_safe(dep, tmp, &iface_all_users, list)
		dep->cb(dep, iface, ev);

	switch (ev) {
	case IFEV_UP:
		adev = iface->l3_dev.dev;
		/* fall through */
	case IFEV_DOWN:
		alias_notify_device(iface->name, adev);
		break;
	default:
		break;
	}
}

static void
interface_flush_state(struct interface *iface)
{
	if (iface->l3_dev.dev)
		device_release(&iface->l3_dev);
	interface_data_flush(iface);
}

static void
mark_interface_down(struct interface *iface)
{
	enum interface_state state = iface->state;

	iface->state = IFS_DOWN;
	if (state == IFS_UP)
		interface_event(iface, IFEV_DOWN);
	interface_ip_set_enabled(&iface->config_ip, false);
	interface_ip_flush(&iface->proto_ip);
	interface_flush_state(iface);
	system_flush_routes();
}

void
__interface_set_down(struct interface *iface, bool force)
{
	if (iface->state == IFS_DOWN ||
		iface->state == IFS_TEARDOWN)
		return;

	if (iface->state == IFS_UP)
		interface_event(iface, IFEV_DOWN);
	iface->state = IFS_TEARDOWN;
	interface_proto_event(iface->proto, PROTO_CMD_TEARDOWN, force);
	if (force)
		interface_flush_state(iface);

	if (iface->dynamic)
		vlist_delete(&interfaces, &iface->node);
}

static void
interface_cb(struct device_user *dep, enum device_event ev)
{
	struct interface *iface;
	bool new_state;

	iface = container_of(dep, struct interface, main_dev);
	switch (ev) {
	case DEV_EVENT_ADD:
		new_state = true;
		break;
	case DEV_EVENT_REMOVE:
		new_state = false;
		break;
	default:
		return;
	}

	interface_set_available(iface, new_state);
	if (!new_state && dep->dev->external)
		interface_set_main_dev(iface, NULL);
}

void
interface_set_available(struct interface *iface, bool new_state)
{
	if (iface->available == new_state)
		return;

	D(INTERFACE, "Interface '%s', available=%d\n", iface->name, new_state);
	iface->available = new_state;

	if (new_state) {
		if (iface->autostart && !config_init)
			interface_set_up(iface);
	} else
		__interface_set_down(iface, true);
}

void
interface_add_user(struct interface_user *dep, struct interface *iface)
{
	if (!iface) {
		list_add(&dep->list, &iface_all_users);
		return;
	}

	dep->iface = iface;
	list_add(&dep->list, &iface->users);
	if (iface->state == IFS_UP)
		dep->cb(dep, iface, IFEV_UP);
}

void
interface_remove_user(struct interface_user *dep)
{
	list_del_init(&dep->list);
	dep->iface = NULL;
}

static void
interface_add_assignment_classes(struct interface *iface, struct blob_attr *list)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, list, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		if (!blobmsg_check_attr(cur, NULL))
			continue;

		struct interface_assignment_class *c = malloc(sizeof(*c) + blobmsg_data_len(cur));
		memcpy(c->name, blobmsg_data(cur), blobmsg_data_len(cur));
		list_add(&c->head, &iface->assignment_classes);
	}
}

static void
interface_clear_assignment_classes(struct interface *iface)
{
	while (!list_empty(&iface->assignment_classes)) {
		struct interface_assignment_class *c = list_first_entry(&iface->assignment_classes,
				struct interface_assignment_class, head);
		list_del(&c->head);
		free(c);
	}
}

static void
interface_merge_assignment_data(struct interface *old, struct interface *new)
{
	bool changed = (old->assignment_hint != new->assignment_hint ||
			old->assignment_length != new->assignment_length ||
			list_empty(&old->assignment_classes) != list_empty(&new->assignment_classes));

	struct interface_assignment_class *c;
	list_for_each_entry(c, &new->assignment_classes, head) {
		// Compare list entries one-by-one to see if there was a change
		if (list_empty(&old->assignment_classes)) // The new list is longer
			changed = true;

		if (changed)
			break;

		struct interface_assignment_class *c_old = list_first_entry(&old->assignment_classes,
				struct interface_assignment_class, head);

		if (strcmp(c_old->name, c->name)) // An entry didn't match
			break;

		list_del(&c_old->head);
		free(c_old);
	}

	// The old list was longer than the new one or the last entry didn't match
	if (!list_empty(&old->assignment_classes)) {
		interface_clear_assignment_classes(old);
		changed = true;
	}

	list_splice_init(&new->assignment_classes, &old->assignment_classes);

	if (changed) {
		old->assignment_hint = new->assignment_hint;
		old->assignment_length = new->assignment_length;
		interface_refresh_assignments(true);
	}
}

static void
interface_alias_cb(struct interface_user *dep, struct interface *iface, enum interface_event ev)
{
	struct interface *alias = container_of(dep, struct interface, parent_iface);
	struct device *dev = iface->l3_dev.dev;

	switch (ev) {
	case IFEV_UP:
		if (!dev)
			return;

		interface_set_main_dev(alias, dev);
		interface_set_available(alias, true);
		break;
	case IFEV_DOWN:
		interface_set_available(alias, false);
		interface_set_main_dev(alias, NULL);
		break;
	case IFEV_FREE:
		interface_remove_user(dep);
		break;
	case IFEV_RELOAD:
	case IFEV_UPDATE:
		break;
	}
}

static void
interface_claim_device(struct interface *iface)
{
	struct interface *parent;
	struct device *dev = NULL;

	if (iface->parent_iface.iface)
		interface_remove_user(&iface->parent_iface);

	if (iface->parent_ifname) {
		parent = vlist_find(&interfaces, iface->parent_ifname, parent, node);
		iface->parent_iface.cb = interface_alias_cb;
		interface_add_user(&iface->parent_iface, parent);
	} else if (iface->ifname &&
		!(iface->proto_handler->flags & PROTO_FLAG_NODEV)) {
		dev = device_get(iface->ifname, true);
	}

	if (dev)
		interface_set_main_dev(iface, dev);

	if (iface->proto_handler->flags & PROTO_FLAG_INIT_AVAILABLE)
		interface_set_available(iface, true);
}

static void
interface_cleanup_state(struct interface *iface)
{
	interface_set_available(iface, false);

	interface_flush_state(iface);
	interface_clear_errors(iface);
	interface_set_proto_state(iface, NULL);

	if (iface->main_dev.dev)
		interface_set_main_dev(iface, NULL);
}

static void
interface_cleanup(struct interface *iface)
{
	struct interface_user *dep, *tmp;

	if (iface->parent_iface.iface)
		interface_remove_user(&iface->parent_iface);

	list_for_each_entry_safe(dep, tmp, &iface->users, list)
		interface_remove_user(dep);

	interface_clear_assignment_classes(iface);
	interface_ip_flush(&iface->config_ip);
	interface_cleanup_state(iface);
}

static void
interface_do_free(struct interface *iface)
{
	interface_event(iface, IFEV_FREE);
	interface_cleanup(iface);
	free(iface->config);
	netifd_ubus_remove_interface(iface);
	avl_delete(&interfaces.avl, &iface->node.avl);
	free(iface);
}

static void
interface_do_reload(struct interface *iface)
{
	interface_event(iface, IFEV_RELOAD);
	interface_cleanup_state(iface);
	proto_init_interface(iface, iface->config);
	interface_claim_device(iface);
}

static void
interface_handle_config_change(struct interface *iface)
{
	enum interface_config_state state = iface->config_state;

	iface->config_state = IFC_NORMAL;
	switch(state) {
	case IFC_NORMAL:
		break;
	case IFC_RELOAD:
		interface_do_reload(iface);
		break;
	case IFC_REMOVE:
		interface_do_free(iface);
		return;
	}
	if (iface->autostart && iface->available)
		interface_set_up(iface);
}

static void
interface_proto_cb(struct interface_proto_state *state, enum interface_proto_event ev)
{
	struct interface *iface = state->iface;

	switch (ev) {
	case IFPEV_UP:
		if (iface->state != IFS_SETUP) {
			interface_event(iface, IFEV_UPDATE);
			return;
		}

		interface_ip_set_enabled(&iface->config_ip, true);
		system_flush_routes();
		iface->state = IFS_UP;
		iface->start_time = system_get_rtime();
		interface_event(iface, IFEV_UP);
		netifd_log_message(L_NOTICE, "Interface '%s' is now up\n", iface->name);
		break;
	case IFPEV_DOWN:
		if (iface->state == IFS_DOWN)
			return;

		netifd_log_message(L_NOTICE, "Interface '%s' is now down\n", iface->name);
		mark_interface_down(iface);
		if (iface->main_dev.dev)
			device_release(&iface->main_dev);
		interface_handle_config_change(iface);
		break;
	case IFPEV_LINK_LOST:
		if (iface->state != IFS_UP)
			return;

		netifd_log_message(L_NOTICE, "Interface '%s' has lost the connection\n", iface->name);
		mark_interface_down(iface);
		iface->state = IFS_SETUP;
		break;
	}

	interface_write_resolv_conf();
}

void interface_set_proto_state(struct interface *iface, struct interface_proto_state *state)
{
	if (iface->proto) {
		iface->proto->free(iface->proto);
		iface->proto = NULL;
	}
	iface->state = IFS_DOWN;
	iface->proto = state;
	if (!state)
		return;

	state->proto_event = interface_proto_cb;
	state->iface = iface;
}

struct interface *
interface_alloc(const char *name, struct blob_attr *config)
{
	struct interface *iface;
	struct blob_attr *tb[IFACE_ATTR_MAX];
	struct blob_attr *cur;
	const char *proto_name = NULL;
	char *iface_name;

	iface = calloc_a(sizeof(*iface), &iface_name, strlen(name) + 1);
	iface->name = strcpy(iface_name, name);
	INIT_LIST_HEAD(&iface->errors);
	INIT_LIST_HEAD(&iface->users);
	INIT_LIST_HEAD(&iface->hotplug_list);
	INIT_LIST_HEAD(&iface->assignment_classes);
	interface_ip_init(iface);
	avl_init(&iface->data, avl_strcmp, false, NULL);
	iface->config_ip.enabled = false;

	iface->main_dev.cb = interface_cb;

	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb,
		      blob_data(config), blob_len(config));

	if ((cur = tb[IFACE_ATTR_PROTO]))
		proto_name = blobmsg_data(cur);

	proto_attach_interface(iface, proto_name);

	iface->autostart = blobmsg_get_bool_default(tb[IFACE_ATTR_AUTO], true);
	iface->proto_ip.no_defaultroute =
		!blobmsg_get_bool_default(tb[IFACE_ATTR_DEFAULTROUTE], true);
	iface->proto_ip.no_dns =
		!blobmsg_get_bool_default(tb[IFACE_ATTR_PEERDNS], true);

	if ((cur = tb[IFACE_ATTR_DNS]))
		interface_add_dns_server_list(&iface->config_ip, cur);

	if ((cur = tb[IFACE_ATTR_DNS_SEARCH]))
		interface_add_dns_search_list(&iface->config_ip, cur);

	if ((cur = tb[IFACE_ATTR_METRIC]))
		iface->metric = blobmsg_get_u32(cur);

	if ((cur = tb[IFACE_ATTR_IP6ASSIGN]))
		iface->assignment_length = blobmsg_get_u32(cur);

	iface->assignment_hint = -1;
	if ((cur = tb[IFACE_ATTR_IP6HINT]))
		iface->assignment_hint = strtol(blobmsg_get_string(cur), NULL, 16) &
				~((1 << (64 - iface->assignment_length)) - 1);

	if ((cur = tb[IFACE_ATTR_IP6CLASS]))
		interface_add_assignment_classes(iface, cur);


	if ((cur = tb[IFACE_ATTR_IP4TABLE])) {
		if (!system_resolve_rt_table(blobmsg_data(cur), &iface->ip4table))
			DPRINTF("Failed to resolve routing table: %s\n", (char *) blobmsg_data(cur));
	}

	if ((cur = tb[IFACE_ATTR_IP6TABLE])) {
		if (!system_resolve_rt_table(blobmsg_data(cur), &iface->ip6table))
			DPRINTF("Failed to resolve routing table: %s\n", (char *) blobmsg_data(cur));
	}

	iface->proto_ip.no_delegation = !blobmsg_get_bool_default(tb[IFACE_ATTR_DELEGATE], true);

	iface->config_autostart = iface->autostart;
	return iface;
}

void interface_set_dynamic(struct interface *iface)
{
	iface->dynamic = true;
	iface->node.version = -1; // Don't delete on reload
}

static bool __interface_add(struct interface *iface, struct blob_attr *config, bool alias)
{
	struct blob_attr *tb[IFACE_ATTR_MAX];
	struct blob_attr *cur;

	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb,
		      blob_data(config), blob_len(config));

	if (alias) {
		if ((cur = tb[IFACE_ATTR_INTERFACE]))
			iface->parent_ifname = blobmsg_data(cur);

		if (!iface->parent_ifname)
			return false;
	} else {
		if ((cur = tb[IFACE_ATTR_IFNAME]))
			iface->ifname = blobmsg_data(cur);
	}


	iface->config = config;
	vlist_add(&interfaces, &iface->node, iface->name);
	return true;
}

void
interface_add(struct interface *iface, struct blob_attr *config)
{
	__interface_add(iface, config, false);
}

bool
interface_add_alias(struct interface *iface, struct blob_attr *config)
{
	if (iface->proto_handler->flags & PROTO_FLAG_NODEV)
		return false;

	return __interface_add(iface, config, true);
}

void
interface_set_l3_dev(struct interface *iface, struct device *dev)
{
	bool enabled = iface->config_ip.enabled;
	bool claimed = iface->l3_dev.claimed;

	if (iface->l3_dev.dev == dev)
		return;

	interface_ip_set_enabled(&iface->config_ip, false);
	interface_ip_flush(&iface->proto_ip);
	device_add_user(&iface->l3_dev, dev);

	if (dev) {
		if (claimed)
			device_claim(&iface->l3_dev);
		interface_ip_set_enabled(&iface->config_ip, enabled);
	}
}

void
interface_set_main_dev(struct interface *iface, struct device *dev)
{
	bool set_l3 = (iface->main_dev.dev == iface->l3_dev.dev);
	bool claimed = iface->l3_dev.claimed;

	if (iface->main_dev.dev == dev)
		return;

	if (set_l3)
		interface_set_l3_dev(iface, dev);

	device_add_user(&iface->main_dev, dev);
	if (!dev)
		return;

	if (claimed)
		device_claim(&iface->l3_dev);

	if (!iface->l3_dev.dev)
		interface_set_l3_dev(iface, dev);
}

int
interface_remove_link(struct interface *iface, struct device *dev)
{
	struct device *mdev = iface->main_dev.dev;

	if (mdev && mdev->hotplug_ops)
		return mdev->hotplug_ops->del(mdev, dev);

	if (!iface->main_dev.hotplug)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (dev != iface->main_dev.dev)
		return UBUS_STATUS_INVALID_ARGUMENT;

	device_remove_user(&iface->main_dev);
	return 0;
}

int
interface_add_link(struct interface *iface, struct device *dev)
{
	struct device *mdev = iface->main_dev.dev;

	if (mdev == dev)
		return 0;

	if (iface->main_dev.hotplug)
		device_remove_user(&iface->main_dev);

	if (mdev) {
		if (mdev->hotplug_ops)
			return mdev->hotplug_ops->add(mdev, dev);
		else
			return UBUS_STATUS_NOT_SUPPORTED;
	}

	interface_set_main_dev(iface, dev);
	iface->main_dev.hotplug = true;
	return 0;
}

int
interface_handle_link(struct interface *iface, const char *name, bool add)
{
	struct device *dev;
	int ret;

	device_lock();

	dev = device_get(name, add ? 2 : 0);
	if (!dev) {
		ret = UBUS_STATUS_NOT_FOUND;
		goto out;
	}

	if (add) {
		device_set_present(dev, true);
		if (iface->device_config)
			device_set_config(dev, &simple_device_type, iface->config);

		system_if_apply_settings(dev, &dev->settings);
		ret = interface_add_link(iface, dev);
	} else {
		ret = interface_remove_link(iface, dev);
	}

out:
	device_unlock();

	return ret;
}

int
interface_set_up(struct interface *iface)
{
	int ret;

	iface->autostart = true;

	if (iface->state != IFS_DOWN)
		return 0;

	interface_clear_errors(iface);
	if (!iface->available) {
		interface_add_error(iface, "interface", "NO_DEVICE", NULL, 0);
		return -1;
	}

	if (iface->main_dev.dev) {
		ret = device_claim(&iface->main_dev);
		if (ret)
			return ret;
	}

	iface->state = IFS_SETUP;
	ret = interface_proto_event(iface->proto, PROTO_CMD_SETUP, false);
	if (ret) {
		mark_interface_down(iface);
		return ret;
	}

	return 0;
}

int
interface_set_down(struct interface *iface)
{
	if (!iface) {
		vlist_for_each_element(&interfaces, iface, node)
			__interface_set_down(iface, false);
	} else {
		iface->autostart = false;
		__interface_set_down(iface, false);
	}

	return 0;
}

void
interface_start_pending(void)
{
	struct interface *iface;

	vlist_for_each_element(&interfaces, iface, node) {
		if (iface->available && iface->autostart)
			interface_set_up(iface);
	}
}

static void
set_config_state(struct interface *iface, enum interface_config_state s)
{
	iface->config_state = s;
	if (iface->state == IFS_DOWN)
		interface_handle_config_change(iface);
	else
		__interface_set_down(iface, false);
}

void
interface_update_start(struct interface *iface)
{
	iface->updated = 0;
	interface_ip_update_start(&iface->proto_ip);
}

void
interface_update_complete(struct interface *iface)
{
	interface_ip_update_complete(&iface->proto_ip);
}

static void
interface_replace_dns(struct interface_ip_settings *new, struct interface_ip_settings *old)
{
	vlist_simple_replace(&new->dns_servers, &old->dns_servers);
	vlist_simple_replace(&new->dns_search, &old->dns_search);
}

static void
interface_change_config(struct interface *if_old, struct interface *if_new)
{
	struct blob_attr *old_config = if_old->config;
	bool reload = false, reload_ip = false;

#define FIELD_CHANGED_STR(field)					\
		((!!if_old->field != !!if_new->field) ||		\
		 (if_old->field &&					\
		  strcmp(if_old->field, if_new->field) != 0))

	if (FIELD_CHANGED_STR(parent_ifname)) {
		if (if_old->parent_iface.iface)
			interface_remove_user(&if_old->parent_iface);
		reload = true;
	}

	if (FIELD_CHANGED_STR(ifname) ||
	    if_old->proto_handler != if_new->proto_handler)
		reload = true;

	if (!if_old->proto_handler->config_params)
		D(INTERFACE, "No config parameters for interface '%s'\n",
		  if_old->name);
	else if (!uci_blob_check_equal(if_old->config, if_new->config,
				       if_old->proto_handler->config_params))
		reload = true;

#define UPDATE(field, __var) ({						\
		bool __changed = (if_old->field != if_new->field);	\
		if_old->field = if_new->field;				\
		__var |= __changed;					\
	})

	if_old->config = if_new->config;
	if (!if_old->config_autostart && if_new->config_autostart)
		if_old->autostart = true;

	if_old->device_config = if_new->device_config;
	if_old->config_autostart = if_new->config_autostart;
	if_old->ifname = if_new->ifname;
	if_old->parent_ifname = if_new->parent_ifname;
	if_old->proto_handler = if_new->proto_handler;

	if_old->proto_ip.no_dns = if_new->proto_ip.no_dns;
	interface_replace_dns(&if_old->config_ip, &if_new->config_ip);

	UPDATE(metric, reload_ip);
	UPDATE(proto_ip.no_defaultroute, reload_ip);
	UPDATE(ip4table, reload_ip);
	UPDATE(ip6table, reload_ip);
	interface_merge_assignment_data(if_old, if_new);

#undef UPDATE

	if (reload) {
		D(INTERFACE, "Reload interface '%s' because of config changes\n",
		  if_old->name);
		interface_clear_errors(if_old);
		set_config_state(if_old, IFC_RELOAD);
		goto out;
	}

	if (reload_ip) {
		interface_ip_set_enabled(&if_old->config_ip, false);
		interface_ip_set_enabled(&if_old->proto_ip, false);
		interface_ip_set_enabled(&if_old->proto_ip, if_new->proto_ip.enabled);
		interface_ip_set_enabled(&if_old->config_ip, if_new->config_ip.enabled);
	}

	interface_write_resolv_conf();

out:
	if_new->config = NULL;
	interface_cleanup(if_new);
	free(old_config);
	free(if_new);
}

static void
interface_update(struct vlist_tree *tree, struct vlist_node *node_new,
		 struct vlist_node *node_old)
{
	struct interface *if_old = container_of(node_old, struct interface, node);
	struct interface *if_new = container_of(node_new, struct interface, node);

	if (node_old && node_new) {
		D(INTERFACE, "Update interface '%s'\n", if_new->name);
		interface_change_config(if_old, if_new);
	} else if (node_old) {
		D(INTERFACE, "Remove interface '%s'\n", if_old->name);
		set_config_state(if_old, IFC_REMOVE);
	} else if (node_new) {
		D(INTERFACE, "Create interface '%s'\n", if_new->name);
		proto_init_interface(if_new, if_new->config);
		interface_claim_device(if_new);
		netifd_ubus_add_interface(if_new);
	}
}


static void __init
interface_init_list(void)
{
	vlist_init(&interfaces, avl_strcmp, interface_update);
	interfaces.keep_old = true;
	interfaces.no_delete = true;
}
