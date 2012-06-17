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

#include <arpa/inet.h>
#include <netinet/in.h>

#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"

static struct avl_tree handlers;

enum {
	OPT_IPADDR,
	OPT_IP6ADDR,
	OPT_NETMASK,
	OPT_BROADCAST,
	OPT_GATEWAY,
	OPT_IP6GW,
	__OPT_MAX,
};

static const struct blobmsg_policy proto_ip_attributes[__OPT_MAX] = {
	[OPT_IPADDR] = { .name = "ipaddr", .type = BLOBMSG_TYPE_ARRAY },
	[OPT_IP6ADDR] = { .name = "ip6addr", .type = BLOBMSG_TYPE_ARRAY },
	[OPT_NETMASK] = { .name = "netmask", .type = BLOBMSG_TYPE_STRING },
	[OPT_BROADCAST] = { .name = "broadcast", .type = BLOBMSG_TYPE_STRING },
	[OPT_GATEWAY] = { .name = "gateway", .type = BLOBMSG_TYPE_STRING },
	[OPT_IP6GW] = { .name = "ip6gw", .type = BLOBMSG_TYPE_STRING },
};

static const union config_param_info proto_ip_attr_info[__OPT_MAX] = {
	[OPT_IPADDR] = { .type = BLOBMSG_TYPE_STRING },
	[OPT_IP6ADDR] = { .type = BLOBMSG_TYPE_STRING },
};

const struct config_param_list proto_ip_attr = {
	.n_params = __OPT_MAX,
	.params = proto_ip_attributes,
	.info = proto_ip_attr_info,
};

enum {
	ADDR_IPADDR,
	ADDR_MASK,
	ADDR_BROADCAST,
	ADDR_PTP,
	__ADDR_MAX
};

static const struct blobmsg_policy proto_ip_addr[__ADDR_MAX] = {
	[ADDR_IPADDR] = { .name = "ipaddr", .type = BLOBMSG_TYPE_STRING },
	[ADDR_MASK] = { .name = "mask", .type = BLOBMSG_TYPE_STRING },
	[ADDR_BROADCAST] = { .name = "broadcast", .type = BLOBMSG_TYPE_STRING },
	[ADDR_PTP] = { .name = "ptp", .type = BLOBMSG_TYPE_STRING },
};

static struct device_addr *
alloc_device_addr(bool v6, bool ext)
{
	struct device_addr *addr;

	addr = calloc(1, sizeof(*addr));
	addr->flags = v6 ? DEVADDR_INET6 : DEVADDR_INET4;
	if (ext)
		addr->flags |= DEVADDR_EXTERNAL;

	return addr;
}

static bool
parse_addr(struct interface *iface, const char *str, bool v6, int mask,
	   bool ext, uint32_t broadcast)
{
	struct device_addr *addr;
	int af = v6 ? AF_INET6 : AF_INET;

	addr = alloc_device_addr(v6, ext);
	if (!addr)
		return false;

	addr->mask = mask;
	if (!parse_ip_and_netmask(af, str, &addr->addr, &addr->mask)) {
		interface_add_error(iface, "proto", "INVALID_ADDRESS", &str, 1);
		free(addr);
		return false;
	}

	if (broadcast)
		addr->broadcast = broadcast;

	vlist_add(&iface->proto_ip.addr, &addr->node, &addr->flags);
	return true;
}

static int
parse_static_address_option(struct interface *iface, struct blob_attr *attr,
			    bool v6, int netmask, bool ext, uint32_t broadcast)
{
	struct blob_attr *cur;
	int n_addr = 0;
	int rem;

	blobmsg_for_each_attr(cur, attr, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			return -1;

		n_addr++;
		if (!parse_addr(iface, blobmsg_data(cur), v6, netmask, ext,
				broadcast))
			return -1;
	}

	return n_addr;
}

static struct device_addr *
parse_address_item(struct blob_attr *attr, bool v6, bool ext)
{
	struct device_addr *addr;
	struct blob_attr *tb[__ADDR_MAX];
	struct blob_attr *cur;

	if (blobmsg_type(attr) != BLOBMSG_TYPE_TABLE)
		return NULL;

	addr = alloc_device_addr(v6, ext);
	if (!addr)
		return NULL;

	blobmsg_parse(proto_ip_addr, __ADDR_MAX, tb, blobmsg_data(attr), blobmsg_data_len(attr));

	addr->mask = v6 ? 128 : 32;
	if ((cur = tb[ADDR_MASK])) {
		unsigned int new_mask;

		new_mask = parse_netmask_string(blobmsg_data(cur), v6);
		if (new_mask > addr->mask)
			goto error;

		addr->mask = new_mask;
	}

	cur = tb[ADDR_IPADDR];
	if (!cur)
		goto error;

	if (!inet_pton(v6 ? AF_INET6 : AF_INET, blobmsg_data(cur), &addr->addr))
		goto error;

	if (!v6) {
		if ((cur = tb[ADDR_BROADCAST]) &&
		    !inet_pton(AF_INET, blobmsg_data(cur), &addr->broadcast))
			goto error;
		if ((cur = tb[ADDR_PTP]) &&
		    !inet_pton(AF_INET, blobmsg_data(cur), &addr->point_to_point))
			goto error;
	}

	return addr;

error:
	free(addr);
	return NULL;
}

static int
parse_address_list(struct interface *iface, struct blob_attr *attr, bool v6,
		   bool ext)
{
	struct device_addr *addr;
	struct blob_attr *cur;
	int n_addr = 0;
	int rem;

	blobmsg_for_each_attr(cur, attr, rem) {
		addr = parse_address_item(cur, v6, ext);
		if (!addr)
			return -1;

		n_addr++;
		vlist_add(&iface->proto_ip.addr, &addr->node, &addr->flags);
	}

	return n_addr;
}

static bool
parse_gateway_option(struct interface *iface, struct blob_attr *attr, bool v6)
{
	struct device_route *route;
	const char *str = blobmsg_data(attr);
	int af = v6 ? AF_INET6 : AF_INET;

	route = calloc(1, sizeof(*route));
	if (!inet_pton(af, str, &route->nexthop)) {
		interface_add_error(iface, "proto", "INVALID_GATEWAY", &str, 1);
		free(route);
		return false;
	}

	route->mask = 0;
	route->flags = (v6 ? DEVADDR_INET6 : DEVADDR_INET4);
	vlist_add(&iface->proto_ip.route, &route->node, &route->flags);

	return true;
}

int
proto_apply_static_ip_settings(struct interface *iface, struct blob_attr *attr)
{
	struct blob_attr *tb[__OPT_MAX];
	struct blob_attr *cur;
	const char *error;
	unsigned int netmask = 32;
	int n_v4 = 0, n_v6 = 0;
	struct in_addr bcast = {};

	blobmsg_parse(proto_ip_attributes, __OPT_MAX, tb, blob_data(attr), blob_len(attr));

	if ((cur = tb[OPT_NETMASK])) {
		netmask = parse_netmask_string(blobmsg_data(cur), false);
		if (netmask > 32) {
			error = "INVALID_NETMASK";
			goto error;
		}
	}

	if ((cur = tb[OPT_BROADCAST])) {
		if (!inet_pton(AF_INET, blobmsg_data(cur), &bcast)) {
			error = "INVALID_BROADCAST";
			goto error;
		}
	}

	if ((cur = tb[OPT_IPADDR]))
		n_v4 = parse_static_address_option(iface, cur, false,
			netmask, false, bcast.s_addr);

	if ((cur = tb[OPT_IP6ADDR]))
		n_v6 = parse_static_address_option(iface, cur, true,
			netmask, false, 0);

	if (!n_v4 && !n_v6) {
		error = "NO_ADDRESS";
		goto error;
	}

	if (n_v4 < 0 || n_v6 < 0)
		goto out;

	if ((cur = tb[OPT_GATEWAY])) {
		if (n_v4 && !parse_gateway_option(iface, cur, false))
			goto out;
	}

	if ((cur = tb[OPT_IP6GW])) {
		if (n_v6 && !parse_gateway_option(iface, cur, true))
			goto out;
	}

	return 0;

error:
	interface_add_error(iface, "proto", error, NULL, 0);
out:
	return -1;
}

int
proto_apply_ip_settings(struct interface *iface, struct blob_attr *attr, bool ext)
{
	struct blob_attr *tb[__OPT_MAX];
	struct blob_attr *cur;
	const char *error;
	int n_v4 = 0, n_v6 = 0;

	blobmsg_parse(proto_ip_attributes, __OPT_MAX, tb, blob_data(attr), blob_len(attr));

	if ((cur = tb[OPT_IPADDR]))
		n_v4 = parse_address_list(iface, cur, false, ext);

	if ((cur = tb[OPT_IP6ADDR]))
		n_v6 = parse_address_list(iface, cur, true, ext);

	if (!n_v4 && !n_v6) {
		error = "NO_ADDRESS";
		goto error;
	}

	if (n_v4 < 0 || n_v6 < 0)
		goto out;

	if ((cur = tb[OPT_GATEWAY])) {
		if (n_v4 && !parse_gateway_option(iface, cur, false))
			goto out;
	}

	if ((cur = tb[OPT_IP6GW])) {
		if (n_v6 && !parse_gateway_option(iface, cur, true))
			goto out;
	}

	return 0;

error:
	interface_add_error(iface, "proto", error, NULL, 0);
out:
	return -1;
}

void add_proto_handler(struct proto_handler *p)
{
	if (!handlers.comp)
		avl_init(&handlers, avl_strcmp, false, NULL);

	if (p->avl.key)
		return;

	p->avl.key = p->name;
	avl_insert(&handlers, &p->avl);
}

static void
default_proto_free(struct interface_proto_state *proto)
{
	free(proto);
}

static int
invalid_proto_handler(struct interface_proto_state *proto,
		      enum interface_proto_cmd cmd, bool force)
{
	return -1;
}

static int
no_proto_handler(struct interface_proto_state *proto,
		 enum interface_proto_cmd cmd, bool force)
{
	return 0;
}

static struct interface_proto_state *
default_proto_attach(const struct proto_handler *h,
		     struct interface *iface, struct blob_attr *attr)
{
	struct interface_proto_state *proto;

	proto = calloc(1, sizeof(*proto));
	proto->free = default_proto_free;
	proto->cb = no_proto_handler;

	return proto;
}

static const struct proto_handler no_proto = {
	.name = "none",
	.flags = PROTO_FLAG_IMMEDIATE,
	.attach = default_proto_attach,
};

static const struct proto_handler *
get_proto_handler(const char *name)
{
	struct proto_handler *proto;

	if (!strcmp(name, "none"))
	    return &no_proto;

	if (!handlers.comp)
		return NULL;

	return avl_find_element(&handlers, name, proto, avl);
}

void
proto_dump_handlers(struct blob_buf *b)
{
	struct proto_handler *p;
	void *c;

	avl_for_each_element(&handlers, p, avl) {
		c = blobmsg_open_table(b, p->name);
		blobmsg_add_u8(b, "no_device", !!(p->flags & PROTO_FLAG_NODEV));
		blobmsg_close_table(b, c);
	}
}

void
proto_init_interface(struct interface *iface, struct blob_attr *attr)
{
	const struct proto_handler *proto = iface->proto_handler;
	struct interface_proto_state *state = NULL;

	if (!proto)
		proto = &no_proto;

	state = proto->attach(proto, iface, attr);
	if (!state) {
		state = no_proto.attach(&no_proto, iface, attr);
		state->cb = invalid_proto_handler;
	}

	state->handler = proto;
	interface_set_proto_state(iface, state);
}

void
proto_attach_interface(struct interface *iface, const char *proto_name)
{
	const struct proto_handler *proto = &no_proto;

	if (proto_name) {
		proto = get_proto_handler(proto_name);
		if (!proto) {
			interface_add_error(iface, "proto", "INVALID_PROTO", NULL, 0);
			proto = &no_proto;
		}
	}

	iface->proto_handler = proto;
}

int
interface_proto_event(struct interface_proto_state *proto,
		      enum interface_proto_cmd cmd, bool force)
{
	enum interface_proto_event ev;
	int ret;

	ret = proto->cb(proto, cmd, force);
	if (ret || !(proto->handler->flags & PROTO_FLAG_IMMEDIATE))
		goto out;

	switch(cmd) {
	case PROTO_CMD_SETUP:
		ev = IFPEV_UP;
		break;
	case PROTO_CMD_TEARDOWN:
		ev = IFPEV_DOWN;
		break;
	default:
		return -EINVAL;
	}
	proto->proto_event(proto, ev);

out:
	return ret;
}
