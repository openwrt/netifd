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
	OPT_GATEWAY,
	OPT_IP6GW,
	OPT_DNS,
	__OPT_MAX,
};

static const struct blobmsg_policy proto_ip_attributes[__OPT_MAX] = {
	[OPT_IPADDR] = { .name = "ipaddr", .type = BLOBMSG_TYPE_ARRAY },
	[OPT_IP6ADDR] = { .name = "ip6addr", .type = BLOBMSG_TYPE_ARRAY },
	[OPT_NETMASK] = { .name = "netmask", .type = BLOBMSG_TYPE_STRING },
	[OPT_GATEWAY] = { .name = "gateway", .type = BLOBMSG_TYPE_STRING },
	[OPT_IP6GW] = { .name = "ip6gw", .type = BLOBMSG_TYPE_STRING },
	[OPT_DNS] = { .name = "dns", .type = BLOBMSG_TYPE_ARRAY },
};

static const union config_param_info proto_ip_attr_info[__OPT_MAX] = {
	[OPT_IPADDR] = { .type = BLOBMSG_TYPE_STRING },
	[OPT_IP6ADDR] = { .type = BLOBMSG_TYPE_STRING },
	[OPT_DNS] = { .type = BLOBMSG_TYPE_STRING },
};

const struct config_param_list proto_ip_attr = {
	.n_params = __OPT_MAX,
	.params = proto_ip_attributes,
	.info = proto_ip_attr_info,
};


unsigned int
parse_netmask_string(const char *str, bool v6)
{
	struct in_addr addr;
	unsigned int ret;
	char *err = NULL;

	if (!strchr(str, '.')) {
		ret = strtoul(str, &err, 0);
		if (err && *err)
			goto error;

		return ret;
	}

	if (v6)
		goto error;

	if (inet_aton(str, &addr) != 1)
		goto error;

	return 32 - fls(~(ntohl(addr.s_addr)));

error:
	return ~0;
}

static bool
split_netmask(char *str, unsigned int *netmask, bool v6)
{
	char *delim = strchr(str, '/');

	if (delim) {
		*(delim++) = 0;

		*netmask = parse_netmask_string(delim, v6);
	}
	return true;
}

static int
parse_ip_and_netmask(int af, const char *str, void *addr, unsigned int *netmask)
{
	char *astr = alloca(strlen(str) + 1);

	strcpy(astr, str);
	if (!split_netmask(astr, netmask, af == AF_INET6))
		return 0;

	if (af == AF_INET6) {
		if (*netmask > 128)
			return 0;
	} else {
		if (*netmask > 32)
			return 0;
	}

	return inet_pton(af, astr, addr);
}

struct device_addr *
proto_parse_ip_addr_string(const char *str, bool v6, int mask)
{
	struct device_addr *addr;
	int af = v6 ? AF_INET6 : AF_INET;

	addr = calloc(1, sizeof(*addr));
	addr->flags = v6 ? DEVADDR_INET6 : DEVADDR_INET4;
	addr->mask = mask;
	if (!parse_ip_and_netmask(af, str, &addr->addr, &addr->mask)) {
		free(addr);
		return NULL;
	}
	return addr;
}

static bool
parse_addr(struct interface *iface, const char *str, bool v6, int mask)
{
	struct device_addr *addr;

	addr = proto_parse_ip_addr_string(str, v6, mask);
	if (!addr) {
		interface_add_error(iface, "proto", "INVALID_ADDRESS", &str, 1);
		return false;
	}
	vlist_add(&iface->proto_ip.addr, &addr->node);
	return true;
}

static int
parse_address_option(struct interface *iface, struct blob_attr *attr, bool v6, int netmask)
{
	struct blob_attr *cur;
	int n_addr = 0;
	int rem;

	blobmsg_for_each_attr(cur, attr, rem) {
		n_addr++;
		if (!parse_addr(iface, blobmsg_data(cur), v6, netmask))
			return -1;
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
	route->flags = DEVADDR_DEVICE | (v6 ? DEVADDR_INET6 : DEVADDR_INET4);
	vlist_add(&iface->proto_ip.route, &route->node);

	return true;
}

int
proto_apply_ip_settings(struct interface *iface, struct blob_attr *attr)
{
	struct blob_attr *tb[__OPT_MAX];
	const char *error;
	unsigned int netmask = 32;
	int n_v4 = 0, n_v6 = 0;

	blobmsg_parse(proto_ip_attributes, __OPT_MAX, tb, blob_data(attr), blob_len(attr));

	if (tb[OPT_NETMASK]) {
		netmask = parse_netmask_string(blobmsg_data(tb[OPT_NETMASK]), false);
		if (netmask > 32) {
			error = "INVALID_NETMASK";
			goto error;
		}
	}

	if (tb[OPT_IPADDR])
		n_v4 = parse_address_option(iface, tb[OPT_IPADDR], false, netmask);

	if (tb[OPT_IP6ADDR])
		n_v6 = parse_address_option(iface, tb[OPT_IP6ADDR], true, netmask);

	if (!n_v4 && !n_v6) {
		error = "NO_ADDRESS";
		goto error;
	}

	if (n_v4 < 0 || n_v6 < 0)
		goto out;

	if (n_v4 && tb[OPT_GATEWAY]) {
		if (!parse_gateway_option(iface, tb[OPT_GATEWAY], false))
			goto out;
	}

	if (n_v6 && tb[OPT_IP6GW]) {
		if (!parse_gateway_option(iface, tb[OPT_IP6GW], true))
			goto out;
	}

	if (tb[OPT_DNS])
		interface_add_dns_server_list(&iface->proto_ip, tb[OPT_DNS]);

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
