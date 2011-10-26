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
	const struct proto_handler *proto = NULL;

	if (!proto_name) {
		interface_add_error(iface, "proto", "NO_PROTO", NULL, 0);
		return;
	}

	proto = get_proto_handler(proto_name);
	if (!proto) {
		interface_add_error(iface, "proto", "INVALID_PROTO", NULL, 0);
		proto = &no_proto;
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
