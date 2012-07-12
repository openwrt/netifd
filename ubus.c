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

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"
#include "ubus.h"
#include "system.h"

static struct ubus_context *ctx = NULL;
static struct blob_buf b;
static struct netifd_fd ubus_fd;
static const char *ubus_path;

/* global object */

static int
netifd_handle_restart(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	netifd_restart();
	return 0;
}

static int
netifd_handle_reload(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	netifd_reload();
	return 0;
}

enum {
	HR_TARGET,
	HR_V6,
	__HR_MAX
};

static const struct blobmsg_policy route_policy[__HR_MAX] = {
	[HR_TARGET] = { .name = "target", .type = BLOBMSG_TYPE_STRING },
	[HR_V6] = { .name = "v6", .type = BLOBMSG_TYPE_BOOL },
};

static int
netifd_add_host_route(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[__HR_MAX];
	struct interface *iface;
	union if_addr a;
	bool v6 = false;

	blobmsg_parse(route_policy, __HR_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[HR_TARGET])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[HR_V6])
		v6 = blobmsg_get_bool(tb[HR_V6]);

	memset(&a, 0, sizeof(a));
	if (!inet_pton(v6 ? AF_INET6 : AF_INET, blobmsg_data(tb[HR_TARGET]), &a))
		return UBUS_STATUS_INVALID_ARGUMENT;


	iface = interface_ip_add_target_route(&a, v6);
	if (!iface)
		return UBUS_STATUS_NOT_FOUND;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "interface", iface->name);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
netifd_get_proto_handlers(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	proto_dump_handlers(&b);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static struct ubus_method main_object_methods[] = {
	{ .name = "restart", .handler = netifd_handle_restart },
	{ .name = "reload", .handler = netifd_handle_reload },
	UBUS_METHOD("add_host_route", netifd_add_host_route, route_policy),
	{ .name = "get_proto_handlers", .handler = netifd_get_proto_handlers },
};

static struct ubus_object_type main_object_type =
	UBUS_OBJECT_TYPE("netifd", main_object_methods);

static struct ubus_object main_object = {
	.name = "network",
	.type = &main_object_type,
	.methods = main_object_methods,
	.n_methods = ARRAY_SIZE(main_object_methods),
};

enum {
	DEV_NAME,
	__DEV_MAX,
};

static const struct blobmsg_policy dev_policy[__DEV_MAX] = {
	[DEV_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
};

static int
netifd_dev_status(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct device *dev = NULL;
	struct blob_attr *tb[__DEV_MAX];

	blobmsg_parse(dev_policy, __DEV_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[DEV_NAME]) {
		dev = device_get(blobmsg_data(tb[DEV_NAME]), false);
		if (!dev)
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	blob_buf_init(&b, 0);
	device_dump_status(&b, dev);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

enum {
	ALIAS_ATTR_ALIAS,
	ALIAS_ATTR_DEV,
	__ALIAS_ATTR_MAX,
};

static const struct blobmsg_policy alias_attrs[__ALIAS_ATTR_MAX] = {
	[ALIAS_ATTR_ALIAS] = { "alias", BLOBMSG_TYPE_ARRAY },
	[ALIAS_ATTR_DEV] = { "device", BLOBMSG_TYPE_STRING },
};

static int
netifd_handle_alias(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct device *dev = NULL;
	struct blob_attr *tb[__ALIAS_ATTR_MAX];
	struct blob_attr *cur;
	int rem;

	blobmsg_parse(alias_attrs, __ALIAS_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[ALIAS_ATTR_ALIAS])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if ((cur = tb[ALIAS_ATTR_DEV]) != NULL) {
		dev = device_get(blobmsg_data(cur), true);
		if (!dev)
			return UBUS_STATUS_NOT_FOUND;
	}

	blobmsg_for_each_attr(cur, tb[ALIAS_ATTR_ALIAS], rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			goto error;

		if (!blobmsg_check_attr(cur, NULL))
			goto error;

		alias_notify_device(blobmsg_data(cur), dev);
	}
	return 0;

error:
	device_free_unused(dev);
	return UBUS_STATUS_INVALID_ARGUMENT;
}

enum {
	DEV_STATE_NAME,
	DEV_STATE_DEFER,
	__DEV_STATE_MAX,
};

static const struct blobmsg_policy dev_state_policy[__DEV_STATE_MAX] = {
	[DEV_STATE_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[DEV_STATE_DEFER] = { .name = "defer", .type = BLOBMSG_TYPE_BOOL },
};

static int
netifd_handle_set_state(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct device *dev = NULL;
	struct blob_attr *tb[__DEV_STATE_MAX];
	struct blob_attr *cur;

	blobmsg_parse(dev_state_policy, __DEV_STATE_MAX, tb, blob_data(msg), blob_len(msg));

	cur = tb[DEV_STATE_NAME];
	if (!cur)
		return UBUS_STATUS_INVALID_ARGUMENT;

	dev = device_get(blobmsg_data(cur), false);
	if (!dev)
		return UBUS_STATUS_NOT_FOUND;

	cur = tb[DEV_STATE_DEFER];
	if (cur)
		device_set_deferred(dev, !!blobmsg_get_u8(cur));

	return 0;
}

static struct ubus_method dev_object_methods[] = {
	UBUS_METHOD("status", netifd_dev_status, dev_policy),
	UBUS_METHOD("set_alias", netifd_handle_alias, alias_attrs),
	UBUS_METHOD("set_state", netifd_handle_set_state, dev_state_policy),
};

static struct ubus_object_type dev_object_type =
	UBUS_OBJECT_TYPE("device", dev_object_methods);

static struct ubus_object dev_object = {
	.name = "network.device",
	.type = &dev_object_type,
	.methods = dev_object_methods,
	.n_methods = ARRAY_SIZE(dev_object_methods),
};

static void
netifd_ubus_add_fd(void)
{
	ubus_add_uloop(ctx);
	ubus_fd.fd = ctx->sock.fd;
	netifd_fd_add(&ubus_fd);
}

static void
netifd_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
	static struct uloop_timeout retry = {
		.cb = netifd_ubus_reconnect_timer,
	};
	int t = 2;

	if (ubus_reconnect(ctx, ubus_path) != 0) {
		DPRINTF("failed to reconnect, trying again in %d seconds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	DPRINTF("reconnected to ubus, new id: %08x\n", ctx->local_id);
	netifd_ubus_add_fd();
}

static void
netifd_ubus_connection_lost(struct ubus_context *ctx)
{
	netifd_fd_delete(&ubus_fd);
	netifd_ubus_reconnect_timer(NULL);
}

int
netifd_ubus_init(const char *path)
{
	int ret;

	uloop_init();
	ubus_path = path;

	ctx = ubus_connect(path);
	if (!ctx)
		return -EIO;

	DPRINTF("connected as %08x\n", ctx->local_id);
	ctx->connection_lost = netifd_ubus_connection_lost;
	netifd_ubus_add_fd();

	ret = ubus_add_object(ctx, &main_object);
	if (ret)
		goto out;

	ret = ubus_add_object(ctx, &dev_object);

out:
	if (ret != 0)
		fprintf(stderr, "Failed to publish object: %s\n", ubus_strerror(ret));
	return ret;
}

void
netifd_ubus_done(void)
{
	ubus_free(ctx);
}


/* per-interface object */

static int
netifd_handle_up(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct interface *iface;

	iface = container_of(obj, struct interface, ubus);
	interface_set_up(iface);

	return 0;
}

static int
netifd_handle_down(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct interface *iface;

	iface = container_of(obj, struct interface, ubus);
	interface_set_down(iface);

	return 0;
}

static void
netifd_add_interface_errors(struct blob_buf *b, struct interface *iface)
{
	struct interface_error *error;
	void *e, *e2, *e3;
	int i;

	e = blobmsg_open_array(b, "errors");
	list_for_each_entry(error, &iface->errors, list) {
		e2 = blobmsg_open_table(b, NULL);

		blobmsg_add_string(b, "subsystem", error->subsystem);
		blobmsg_add_string(b, "code", error->code);
		if (error->data[0]) {
			e3 = blobmsg_open_array(b, "data");
			for (i = 0; error->data[i]; i++)
				blobmsg_add_string(b, NULL, error->data[i]);
			blobmsg_close_array(b, e3);
		}

		blobmsg_close_table(b, e2);
	}
	blobmsg_close_array(b, e);
}

static void
interface_ip_dump_address_list(struct interface_ip_settings *ip, bool v6)
{
	struct device_addr *addr;
	char *buf;
	void *a;
	int buflen = 128;
	int af;

	vlist_for_each_element(&ip->addr, addr, node) {
		if ((addr->flags & DEVADDR_FAMILY) == DEVADDR_INET4)
			af = AF_INET;
		else
			af = AF_INET6;

		if (af != (v6 ? AF_INET6 : AF_INET))
			continue;

		a = blobmsg_open_table(&b, NULL);

		buf = blobmsg_alloc_string_buffer(&b, "address", buflen);
		inet_ntop(af, &addr->addr, buf, buflen);
		blobmsg_add_string_buffer(&b);

		blobmsg_add_u32(&b, "mask", addr->mask);

		blobmsg_close_table(&b, a);
	}
}

static void
interface_ip_dump_route_list(struct interface_ip_settings *ip)
{
	struct device_route *route;
	int buflen = 128;
	char *buf;
	void *r;
	int af;

	vlist_for_each_element(&ip->route, route, node) {
		if ((route->flags & DEVADDR_FAMILY) == DEVADDR_INET4)
			af = AF_INET;
		else
			af = AF_INET6;

		r = blobmsg_open_table(&b, NULL);

		buf = blobmsg_alloc_string_buffer(&b, "target", buflen);
		inet_ntop(af, &route->addr, buf, buflen);
		blobmsg_add_string_buffer(&b);

		blobmsg_add_u32(&b, "mask", route->mask);

		buf = blobmsg_alloc_string_buffer(&b, "nexthop", buflen);
		inet_ntop(af, &route->nexthop, buf, buflen);
		blobmsg_add_string_buffer(&b);

		if (route->flags & DEVROUTE_MTU)
			blobmsg_add_u32(&b, "mtu", route->mtu);

		if (route->flags & DEVROUTE_METRIC)
			blobmsg_add_u32(&b, "metric", route->metric);

		blobmsg_add_u8(&b, "enabled", route->enabled);

		blobmsg_close_table(&b, r);
	}
}

static void
interface_ip_dump_dns_server_list(struct interface_ip_settings *ip)
{
	struct dns_server *dns;
	int buflen = 128;
	char *buf;

	vlist_simple_for_each_element(&ip->dns_servers, dns, node) {
		buf = blobmsg_alloc_string_buffer(&b, NULL, buflen);
		inet_ntop(dns->af, &dns->addr, buf, buflen);
		blobmsg_add_string_buffer(&b);
	}
}

static void
interface_ip_dump_dns_search_list(struct interface_ip_settings *ip)
{
	struct dns_search_domain *dns;

	vlist_simple_for_each_element(&ip->dns_search, dns, node) {
		blobmsg_add_string(&b, NULL, dns->name);
	}
}

static int
netifd_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	struct interface *iface;
	struct interface_data *data;
	struct device *dev;
	void *a;

	iface = container_of(obj, struct interface, ubus);

	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "up", iface->state == IFS_UP);
	blobmsg_add_u8(&b, "pending", iface->state == IFS_SETUP);
	blobmsg_add_u8(&b, "available", iface->available);
	blobmsg_add_u8(&b, "autostart", iface->autostart);

	if (iface->state == IFS_UP) {
		time_t cur = system_get_rtime();
		blobmsg_add_u32(&b, "uptime", cur - iface->start_time);
		blobmsg_add_string(&b, "l3_device", iface->l3_dev.dev->ifname);
	}

	if (iface->proto_handler)
		blobmsg_add_string(&b, "proto", iface->proto_handler->name);

	dev = iface->main_dev.dev;
	if (dev && !dev->hidden &&
	    !(iface->proto_handler->flags & PROTO_FLAG_NODEV))
		blobmsg_add_string(&b, "device", dev->ifname);

	if (iface->state == IFS_UP) {
		blobmsg_add_u32(&b, "metric", iface->metric);
		a = blobmsg_open_array(&b, "ipv4-address");
		interface_ip_dump_address_list(&iface->config_ip, false);
		interface_ip_dump_address_list(&iface->proto_ip, false);
		blobmsg_close_array(&b, a);
		a = blobmsg_open_array(&b, "ipv6-address");
		interface_ip_dump_address_list(&iface->config_ip, true);
		interface_ip_dump_address_list(&iface->proto_ip, true);
		blobmsg_close_array(&b, a);
		a = blobmsg_open_array(&b, "route");
		interface_ip_dump_route_list(&iface->config_ip);
		interface_ip_dump_route_list(&iface->proto_ip);
		blobmsg_close_array(&b, a);
		a = blobmsg_open_array(&b, "dns-server");
		interface_ip_dump_dns_server_list(&iface->config_ip);
		interface_ip_dump_dns_server_list(&iface->proto_ip);
		blobmsg_close_array(&b, a);
		a = blobmsg_open_array(&b, "dns-search");
		interface_ip_dump_dns_search_list(&iface->config_ip);
		interface_ip_dump_dns_search_list(&iface->proto_ip);
		blobmsg_close_array(&b, a);
	}

	a = blobmsg_open_table(&b, "data");
	avl_for_each_element(&iface->data, data, node)
		blob_put(&b, blob_id(data->data), blob_data(data->data), blob_len(data->data));

	blobmsg_close_table(&b, a);

	if (!list_is_empty(&iface->errors))
		netifd_add_interface_errors(&b, iface);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
netifd_iface_handle_device(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	struct blob_attr *tb[__DEV_MAX];
	struct interface *iface;
	struct device *dev;
	bool add = !strncmp(method, "add", 3);
	int ret;

	iface = container_of(obj, struct interface, ubus);

	blobmsg_parse(dev_policy, __DEV_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[DEV_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	device_lock();

	dev = device_get(blobmsg_data(tb[DEV_NAME]), add ? 2 : 0);
	if (add && !dev)
		return UBUS_STATUS_NOT_FOUND;

	if (add)
		ret = interface_add_link(iface, dev);
	else
		ret = interface_remove_link(iface, dev);

	device_unlock();

	return ret;
}


static int
netifd_iface_notify_proto(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct interface *iface;

	iface = container_of(obj, struct interface, ubus);

	if (!iface->proto || !iface->proto->notify)
		return UBUS_STATUS_NOT_SUPPORTED;

	return iface->proto->notify(iface->proto, msg);
}

static void
netifd_iface_do_remove(struct uloop_timeout *timeout)
{
	struct interface *iface;

	iface = container_of(timeout, struct interface, remove_timer);
	vlist_delete(&interfaces, &iface->node);
}

static int
netifd_iface_remove(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct interface *iface;

	iface = container_of(obj, struct interface, ubus);
	if (iface->remove_timer.cb)
		return UBUS_STATUS_INVALID_ARGUMENT;

	iface->remove_timer.cb = netifd_iface_do_remove;
	uloop_timeout_set(&iface->remove_timer, 100);
	return 0;
}

static int
netifd_handle_iface_prepare(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	struct interface *iface;
	struct device *dev;
	const struct device_hotplug_ops *ops;

	iface = container_of(obj, struct interface, ubus);
	dev = iface->main_dev.dev;
	if (!dev)
		return 0;

	ops = dev->hotplug_ops;
	if (!ops)
		return 0;

	return ops->prepare(dev);
}

static int
netifd_handle_set_data(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct interface *iface;
	struct blob_attr *cur;
	int rem, ret;

	iface = container_of(obj, struct interface, ubus);

	blob_for_each_attr(cur, msg, rem) {
		ret = interface_add_data(iface, cur);
		if (ret)
			return ret;
	}

	return 0;
}

static struct ubus_method iface_object_methods[] = {
	{ .name = "up", .handler = netifd_handle_up },
	{ .name = "down", .handler = netifd_handle_down },
	{ .name = "status", .handler = netifd_handle_status },
	{ .name = "prepare", .handler = netifd_handle_iface_prepare },
	UBUS_METHOD("add_device", netifd_iface_handle_device, dev_policy ),
	UBUS_METHOD("remove_device", netifd_iface_handle_device, dev_policy ),
	{ .name = "notify_proto", .handler = netifd_iface_notify_proto },
	{ .name = "remove", .handler = netifd_iface_remove },
	{ .name = "set_data", .handler = netifd_handle_set_data },
};

static struct ubus_object_type iface_object_type =
	UBUS_OBJECT_TYPE("netifd_iface", iface_object_methods);


void
netifd_ubus_interface_event(struct interface *iface, bool up)
{
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "action", up ? "ifup" : "ifdown");
	blobmsg_add_string(&b, "interface", iface->name);
	ubus_send_event(ctx, "network.interface", b.head);
}

void
netifd_ubus_add_interface(struct interface *iface)
{
	struct ubus_object *obj = &iface->ubus;
	char *name = NULL;

	asprintf(&name, "%s.interface.%s", main_object.name, iface->name);
	if (!name)
		return;

	obj->name = name;
	obj->type = &iface_object_type;
	obj->methods = iface_object_methods;
	obj->n_methods = ARRAY_SIZE(iface_object_methods);
	if (ubus_add_object(ctx, &iface->ubus)) {
		DPRINTF("failed to publish ubus object for interface '%s'\n", iface->name);
		free(name);
		obj->name = NULL;
	}
}

void
netifd_ubus_remove_interface(struct interface *iface)
{
	if (!iface->ubus.name)
		return;

	ubus_remove_object(ctx, &iface->ubus);
	free((void *) iface->ubus.name);
}
