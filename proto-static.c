#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"
#include "system.h"

struct v4_addr {
	unsigned int prefix;
	struct in_addr addr;
};

struct v6_addr {
	unsigned int prefix;
	struct in6_addr addr;
};

enum static_proto_flags {
	STATIC_F_IPV4GW		= (1 << 0),
	STATIC_F_IPV6GW		= (1 << 1),
};

struct static_proto_settings {
	uint32_t flags;

	int n_v4;
	struct v4_addr *v4;

	int n_v6;
	struct v6_addr *v6;

	struct in_addr ipv4gw;
	struct in6_addr ipv6gw;
};

struct static_proto_state {
    struct interface_proto_state proto;
	struct interface *iface;

	struct static_proto_settings s;
};

static int
static_handler(struct interface_proto_state *proto,
	       enum interface_proto_cmd cmd, bool force)
{
	struct static_proto_state *state;
	struct static_proto_settings *ps;
	struct device *dev;
	int ret = 0;
	int i;

	state = container_of(proto, struct static_proto_state, proto);
	ps = &state->s;
	dev = state->iface->main_dev.dev;

	switch (cmd) {
	case PROTO_CMD_SETUP:
		for (i = 0; i < state->s.n_v4; i++) {
			if (ret)
				break;
			ret = system_add_address(dev, AF_INET,
				&ps->v4[i].addr, ps->v4[i].prefix);
		}
		for (i = 0; i < state->s.n_v6; i++) {
			if (ret)
				break;
			ret = system_add_address(dev, AF_INET6,
				&ps->v6[i].addr, ps->v6[i].prefix);
		}

		if (!ret)
			return 0;

		interface_add_error(state->iface, "proto-static",
			"SET_ADDRESS_FAILED", NULL, 0);
		/* fall through */

	case PROTO_CMD_TEARDOWN:
		for (i = 0; i < ps->n_v4; i++)
			system_del_address(dev, AF_INET, &ps->v4[i].addr);
		for (i = 0; i < ps->n_v6; i++)
			system_del_address(dev, AF_INET6, &ps->v6[i].addr);
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
static_create_state(struct interface *iface, struct static_proto_settings *ps)
{
	struct static_proto_state *state;
	int v4_len = sizeof(struct v4_addr) * ps->n_v4;
	int v6_len = sizeof(struct v6_addr) * ps->n_v6;
	void *next;

	state = calloc(1, sizeof(*state) + v4_len + v6_len);
	state->iface = iface;
	state->proto.free = static_free;
	state->proto.handler = static_handler;
	state->proto.flags = PROTO_FLAG_IMMEDIATE;
	memcpy(&state->s, ps, sizeof(state->s));

	next = (void *) (state + 1);

	if (ps->n_v4) {
		ps->v4 = next;
		memcpy(next, ps->v4, sizeof(struct v4_addr) * ps->n_v4);

		next = ps->v4 + ps->n_v4;
	}

	if (ps->n_v6) {
		ps->v6 = next;
		memcpy(next, ps->v6, sizeof(struct v6_addr) * ps->n_v6);
	}

	return &state->proto;
}

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

static int
parse_v4(const char *str, struct v4_addr *v4, int netmask)
{
	v4->prefix = netmask;
	return parse_ip_and_netmask(AF_INET, str, &v4->addr, &v4->prefix);
}

static int
parse_v6(const char *str, struct v6_addr *v6, int netmask)
{
	v6->prefix = netmask;
	return parse_ip_and_netmask(AF_INET6, str, &v6->addr, &v6->prefix);
}

static int
count_list_entries(struct uci_option *o)
{
	struct uci_element *e;
	int n = 0;

	uci_foreach_element(&o->v.list, e)
		n++;

	return n;
}

enum {
	OPT_IPADDR,
	OPT_IP6ADDR,
	OPT_NETMASK,
	OPT_GATEWAY,
	OPT_IP6GW,
	OPT_DNS,
	__OPT_MAX,
};

static const struct uci_parse_option opts[__OPT_MAX] = {
	[OPT_IPADDR] = { .name = "ipaddr" },
	[OPT_IP6ADDR] = { .name = "ip6addr" },
	[OPT_NETMASK] = { .name = "netmask", .type = UCI_TYPE_STRING },
	[OPT_GATEWAY] = { .name = "gateway", .type = UCI_TYPE_STRING },
	[OPT_IP6GW] = { .name = "ip6gw", .type = UCI_TYPE_STRING },
	[OPT_DNS] = { .name = "dns" },
};

struct interface_proto_state *
static_attach(struct proto_handler *h, struct interface *iface,
	      struct uci_section *s)
{
	struct uci_option *tb[__OPT_MAX];
	struct uci_element *e;
	struct in_addr ina = {};
	const char *error = NULL;
	int netmask = 32;
	int i;
	struct static_proto_settings ps;

	memset(&ps, 0, sizeof(ps));
	uci_parse_section(s, opts, __OPT_MAX, tb);

	if (tb[OPT_NETMASK]) {
		if (!inet_aton(tb[OPT_NETMASK]->v.string, &ina)) {
			error = "INVALID_NETMASK";
			goto error;
		}

		netmask = 32 - fls(~(ntohl(ina.s_addr)));
	}

	if (tb[OPT_IPADDR]) {
		if (tb[OPT_IPADDR]->type == UCI_TYPE_STRING) {
			ps.n_v4 = 1;
			ps.v4 = alloca(sizeof(struct v4_addr));
			if (!parse_v4(tb[OPT_IPADDR]->v.string, ps.v4, netmask))
				goto invalid_addr;
		} else {
			i = 0;
			ps.n_v4 = count_list_entries(tb[OPT_IPADDR]);
			ps.v4 = alloca(sizeof(struct v4_addr) * ps.n_v4);
			uci_foreach_element(&tb[OPT_IPADDR]->v.list, e) {
				if (!parse_v4(e->name, &ps.v4[i++], netmask))
					goto invalid_addr;
			}
		}
	}

	if (tb[OPT_IP6ADDR]) {
		if (tb[OPT_IP6ADDR]->type == UCI_TYPE_STRING) {
			ps.n_v6 = 1;
			ps.v6 = alloca(sizeof(struct v6_addr));
			ps.v6->prefix = netmask;
			if (!parse_v6(tb[OPT_IP6ADDR]->v.string, ps.v6, netmask))
				goto invalid_addr;
		} else {
			i = 0;
			ps.n_v6 = count_list_entries(tb[OPT_IP6ADDR]);
			ps.v6 = alloca(sizeof(struct v6_addr) * ps.n_v6);
			uci_foreach_element(&tb[OPT_IP6ADDR]->v.list, e) {
				if (!parse_v6(e->name, &ps.v6[i++], netmask))
					goto invalid_addr;
			}
		}
	}

	if (!ps.n_v4 && !ps.n_v6) {
		error = "NO_ADDRESS";
		goto error;
	}

	if (ps.n_v4 && tb[OPT_GATEWAY]) {
		if (!inet_pton(AF_INET, tb[OPT_GATEWAY]->v.string, &ps.ipv4gw)) {
			error = "INVALID_GATEWAY";
			goto error;
		}
		ps.flags |= STATIC_F_IPV4GW;
	}

	if (ps.n_v6 && tb[OPT_IP6GW]) {
		if (!inet_pton(AF_INET6, tb[OPT_IP6GW]->v.string, &ps.ipv6gw)) {
			error = "INVALID_GATEWAY";
			goto error;
		}
		ps.flags |= STATIC_F_IPV6GW;
	}

	return static_create_state(iface, &ps);

invalid_addr:
	error = "INVALID_ADDRESS";

error:
	interface_add_error(iface, "proto-static", error, NULL, 0);
	return NULL;
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
