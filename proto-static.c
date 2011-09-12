#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"
#include "system.h"

enum {
	OPT_IPADDR,
	OPT_IP6ADDR,
	OPT_NETMASK,
	OPT_GATEWAY,
	OPT_IP6GW,
	__OPT_MAX,
};

static const struct blobmsg_policy static_attrs[__OPT_MAX] = {
	[OPT_IPADDR] = { .name = "ipaddr", .type = BLOBMSG_TYPE_ARRAY },
	[OPT_IP6ADDR] = { .name = "ip6addr", .type = BLOBMSG_TYPE_ARRAY },
	[OPT_NETMASK] = { .name = "netmask", .type = BLOBMSG_TYPE_STRING },
	[OPT_GATEWAY] = { .name = "gateway", .type = BLOBMSG_TYPE_STRING },
	[OPT_IP6GW] = { .name = "ip6gw", .type = BLOBMSG_TYPE_STRING },
};

static const union config_param_info static_attr_info[__OPT_MAX] = {
	[OPT_IPADDR] = { .type = BLOBMSG_TYPE_STRING },
	[OPT_IP6ADDR] = { .type = BLOBMSG_TYPE_STRING },
};

static const struct config_param_list static_attr_list = {
	.n_params = __OPT_MAX,
	.params = static_attrs,
	.info = static_attr_info,
};

struct static_proto_state {
	struct interface_proto_state proto;

	struct blob_attr *config;
};

static bool
parse_addr(struct interface *iface, const char *str, bool v6, int mask)
{
	struct device_addr *addr;

	addr = proto_parse_ip_addr_string(str, v6, mask);
	if (!addr) {
		interface_add_error(iface, "proto-static", "INVALID_ADDRESS", &str, 1);
		return false;
	}
	vlist_add(&iface->proto_addr, &addr->node);
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
		interface_add_error(iface, "proto-static",
				"INVALID_GATEWAY", &str, 1);
		free(route);
		return false;
	}
	route->mask = 0;
	route->flags = DEVADDR_DEVICE | (v6 ? DEVADDR_INET6 : DEVADDR_INET4);
	vlist_add(&iface->proto_route, &route->node);

	return true;
}

static int
proto_apply_static_settings(struct interface *iface, struct blob_attr *attr)
{
	struct blob_attr *tb[__OPT_MAX];
	struct in_addr ina;
	const char *error;
	int netmask = 32;
	int n_v4 = 0, n_v6 = 0;

	blobmsg_parse(static_attrs, __OPT_MAX, tb, blob_data(attr), blob_len(attr));

	if (tb[OPT_NETMASK]) {
		if (!inet_aton(blobmsg_data(tb[OPT_NETMASK]), &ina)) {
			error = "INVALID_NETMASK";
			goto error;
		}

		netmask = 32 - fls(~(ntohl(ina.s_addr)));
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

	return 0;

error:
	interface_add_error(iface, "proto-static", error, NULL, 0);
out:
	return -1;
}

static bool
static_proto_setup(struct static_proto_state *state)
{
	return proto_apply_static_settings(state->proto.iface, state->config) == 0;
}

static int
static_handler(struct interface_proto_state *proto,
	       enum interface_proto_cmd cmd, bool force)
{
	struct static_proto_state *state;
	int ret = 0;

	state = container_of(proto, struct static_proto_state, proto);

	switch (cmd) {
	case PROTO_CMD_SETUP:
		if (!static_proto_setup(state))
			return -1;

		break;
	case PROTO_CMD_TEARDOWN:
		break;
	}
	return ret;
}

static void
static_free(struct interface_proto_state *proto)
{
	struct static_proto_state *state;

	state = container_of(proto, struct static_proto_state, proto);
	free(state->config);
	free(state);
}

struct interface_proto_state *
static_attach(const struct proto_handler *h, struct interface *iface,
	      struct blob_attr *attr)
{
	struct static_proto_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		return NULL;

	state->config = malloc(blob_pad_len(attr));
	if (!state->config)
		goto error;

	memcpy(state->config, attr, blob_pad_len(attr));
	state->proto.free = static_free;
	state->proto.cb = static_handler;

	return &state->proto;

error:
	free(state);
	return NULL;
}

static struct proto_handler static_proto = {
	.name = "static",
	.flags = PROTO_FLAG_IMMEDIATE,
	.config_params = &static_attr_list,
	.attach = static_attach,
};

static void __init
static_proto_init(void)
{
	add_proto_handler(&static_proto);
}
