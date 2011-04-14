#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"

struct v4_addr {
	struct in_addr addr;
	unsigned int prefix;
};

struct v6_addr {
	struct in6_addr addr;
	unsigned int prefix;
};

struct static_proto_state {
    struct interface_proto_state proto;

	int n_v4;
	struct v4_addr *v4;

	int n_v6;
	struct v4_addr *v6;
};

static int
static_handler(struct interface_proto_state *proto,
	       enum interface_proto_cmd cmd, bool force)
{
	return 0;
}

static void
static_free(struct interface_proto_state *proto)
{
	struct static_proto_state *state;

	state = container_of(proto, struct static_proto_state, proto);
	free(state);
}

struct interface_proto_state *
static_create_state(struct v4_addr *v4, int n_v4, struct v6_addr *v6, int n_v6)
{
	struct static_proto_state *state;
	int v4_len = sizeof(struct v4_addr) * n_v4;
	int v6_len = sizeof(struct v6_addr) * n_v6;
	void *next;

	state = calloc(1, sizeof(*state) + v4_len + v6_len);
	state->proto.free = static_free;
	state->proto.handler = static_handler;
	state->proto.flags = PROTO_FLAG_IMMEDIATE;
	next = (void *) state + 1;

	if (n_v4) {
		state->v4 = next;
		memcpy(state->v4, v4, sizeof(*v4) * n_v4);
		next = state->v4 + n_v4;
	}

	if (n_v6) {
		state->v6 = next;
		memcpy(state->v6, v6, sizeof(*v6) * n_v6);
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
	OPT_DNS,
	__OPT_MAX,
};

static const struct uci_parse_option opts[__OPT_MAX] = {
	[OPT_IPADDR] = { .name = "ipaddr" },
	[OPT_IP6ADDR] = { .name = "ip6addr" },
	[OPT_NETMASK] = { .name = "netmask", .type = UCI_TYPE_STRING },
	[OPT_GATEWAY] = { .name = "gateway", .type = UCI_TYPE_STRING },
	[OPT_DNS] = { .name = "dns" },
};

struct interface_proto_state *
static_attach(struct proto_handler *h, struct interface *iface,
	      struct uci_section *s)
{
	struct uci_option *tb[__OPT_MAX];
	struct uci_element *e;
	struct v4_addr *v4 = NULL;
	struct v6_addr *v6 = NULL;
	int n_v4 = 0, n_v6 = 0;
	struct in_addr ina = {};
	const char *error = NULL;
	int netmask = 32;
	int i;

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
			n_v4 = 1;
			v4 = alloca(sizeof(*v4));
			if (!parse_v4(tb[OPT_IPADDR]->v.string, v4, netmask))
				goto invalid_addr;
		} else {
			i = 0;
			n_v4 = count_list_entries(tb[OPT_IPADDR]);
			v4 = alloca(sizeof(*v4) * n_v4);
			uci_foreach_element(&tb[OPT_IPADDR]->v.list, e) {
				if (!parse_v4(e->name, &v4[i++], netmask))
					goto invalid_addr;
			}
		}
	}

	if (tb[OPT_IP6ADDR]) {
		if (tb[OPT_IP6ADDR]->type == UCI_TYPE_STRING) {
			n_v6 = 1;
			v6 = alloca(sizeof(*v6));
			v6->prefix = netmask;
			if (!parse_v6(tb[OPT_IP6ADDR]->v.string, v6, netmask))
				goto invalid_addr;
		} else {
			i = 0;
			n_v6 = count_list_entries(tb[OPT_IP6ADDR]);
			v6 = alloca(sizeof(*v6) * n_v6);
			uci_foreach_element(&tb[OPT_IP6ADDR]->v.list, e) {
				if (!parse_v6(e->name, &v6[i++], netmask))
					goto invalid_addr;
			}
		}
	}


	if (!n_v4 && !n_v6) {
		error = "NO_ADDRESS";
		goto error;
	}

	return static_create_state(v4, n_v4, v6, n_v6);

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
