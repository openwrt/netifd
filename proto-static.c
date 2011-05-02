#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"
#include "system.h"

struct static_proto_state {
	struct interface_proto_state proto;

	struct uci_section *section;
	struct interface *iface;
};

static bool
split_netmask(char *str, unsigned int *netmask)
{
	char *delim, *err = NULL;

	delim = strchr(str, '/');
	if (delim) {
		*(delim++) = 0;

		*netmask = strtoul(delim, &err, 10);
		if (err && *err)
			return false;
	}
	return true;
}

static int
parse_ip_and_netmask(int af, const char *str, void *addr, unsigned int *netmask)
{
	char *astr = alloca(strlen(str) + 1);

	strcpy(astr, str);
	if (!split_netmask(astr, netmask))
		return 0;

	if (af == AF_INET6) {
		if (*netmask > 128)
			return 0;
	} else {
		if (*netmask > 32)
			return 0;
	}

	return inet_pton(af, str, addr);
}

static bool
parse_addr(struct static_proto_state *state, const char *str, bool v6, int mask)
{
	struct device_addr *addr;
	int af = v6 ? AF_INET6 : AF_INET;

	addr = calloc(1, sizeof(*addr));
	addr->flags = v6 ? DEVADDR_INET6 : DEVADDR_INET4;
	addr->ctx = state;
	addr->mask = mask;
	if (!parse_ip_and_netmask(af, str, &addr->addr, &addr->mask)) {
		interface_add_error(state->iface, "proto-static", "INVALID_ADDRESS", &str, 1);
		free(addr);
		return false;
	}
	interface_add_address(state->iface, addr);
	return true;
}

static int
parse_address_option(struct static_proto_state *state, struct uci_option *o, bool v6, int netmask)
{
	struct uci_element *e;
	int n_addr = 0;

	if (o->type == UCI_TYPE_STRING) {
		n_addr++;
		if (!parse_addr(state, o->v.string, v6, netmask))
			return -1;
	} else {
		uci_foreach_element(&o->v.list, e) {
			n_addr++;
			if (!parse_addr(state, e->name, v6, netmask))
				return -1;
		}
	}

	return n_addr;
}

static bool
parse_gateway_option(struct static_proto_state *state, struct uci_option *o, bool v6)
{
	struct device_route *route;
	const char *str = o->v.string;
	int af = v6 ? AF_INET6 : AF_INET;

	route = calloc(1, sizeof(*route));
	if (!inet_pton(af, str, &route->nexthop)) {
		interface_add_error(state->iface, "proto-static",
				"INVALID_GATEWAY", &str, 1);
		free(route);
		return false;
	}
	route->mask = 0;
	route->flags = DEVADDR_DEVICE | (v6 ? DEVADDR_INET6 : DEVADDR_INET4);
	interface_add_route(state->iface, route);

	return true;
}

enum {
	OPT_IPADDR,
	OPT_IP6ADDR,
	OPT_NETMASK,
	OPT_GATEWAY,
	OPT_IP6GW,
	__OPT_MAX,
};

static const struct uci_parse_option opts[__OPT_MAX] = {
	[OPT_IPADDR] = { .name = "ipaddr" },
	[OPT_IP6ADDR] = { .name = "ip6addr" },
	[OPT_NETMASK] = { .name = "netmask", .type = UCI_TYPE_STRING },
	[OPT_GATEWAY] = { .name = "gateway", .type = UCI_TYPE_STRING },
	[OPT_IP6GW] = { .name = "ip6gw", .type = UCI_TYPE_STRING },
};

static bool
static_proto_setup(struct static_proto_state *state)
{
	struct uci_option *tb[__OPT_MAX];
	struct in_addr ina;
	const char *error;
	int netmask = 32;
	int n_v4 = 0, n_v6 = 0;

	uci_parse_section(state->section, opts, __OPT_MAX, tb);

	if (tb[OPT_NETMASK]) {
		if (!inet_aton(tb[OPT_NETMASK]->v.string, &ina)) {
			error = "INVALID_NETMASK";
			goto error;
		}

		netmask = 32 - fls(~(ntohl(ina.s_addr)));
	}

	if (tb[OPT_IPADDR])
		n_v4 = parse_address_option(state, tb[OPT_IPADDR], false, netmask);

	if (tb[OPT_IP6ADDR])
		n_v6 = parse_address_option(state, tb[OPT_IP6ADDR], true, netmask);

	if (!n_v4 && !n_v6) {
		error = "NO_ADDRESS";
		goto error;
	}

	if (n_v4 < 0 || n_v6 < 0)
		goto out;

	if (n_v4 && tb[OPT_GATEWAY]) {
		if (!parse_gateway_option(state, tb[OPT_GATEWAY], false))
			goto out;
	}

	if (n_v6 && tb[OPT_IP6GW]) {
		if (!parse_gateway_option(state, tb[OPT_IP6GW], true))
			goto out;
	}

	return true;

error:
	interface_add_error(state->iface, "proto-static", error, NULL, 0);
out:
	return false;
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
		if (static_proto_setup(state))
			break;

		/* fall through */
	case PROTO_CMD_TEARDOWN:
		interface_del_ctx_addr(state->iface, state);
		break;
	}
	return ret;
}

static void
static_free(struct interface_proto_state *proto)
{
	struct static_proto_state *state;

	state = container_of(proto, struct static_proto_state, proto);
	free(state);
}

struct interface_proto_state *
static_attach(struct proto_handler *h, struct interface *iface,
	      struct uci_section *s)
{
	struct static_proto_state *state;

	state = calloc(1, sizeof(*state));
	state->iface = iface;
	state->section = s;
	state->proto.free = static_free;
	state->proto.handler = static_handler;
	state->proto.flags = PROTO_FLAG_IMMEDIATE;

	return &state->proto;
}

static struct proto_handler static_proto = {
	.name = "static",
	.attach = static_attach,
};

static void __init
static_proto_init(void)
{
	add_proto_handler(&static_proto);
}
