#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"

static struct avl_tree handlers;

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
		     struct interface *iface,
		     struct uci_section *s)
{
	struct interface_proto_state *proto;

	proto = calloc(1, sizeof(*proto));
	proto->free = default_proto_free;
	proto->flags = PROTO_FLAG_IMMEDIATE;
	proto->handler = no_proto_handler;

	return proto;
}

static const struct proto_handler no_proto = {
	.name = "none",
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
proto_init_interface(struct interface *iface, struct uci_section *s)
{
	const struct proto_handler *proto = iface->proto_handler;
	struct interface_proto_state *state = NULL;

	if (proto)
		state = proto->attach(proto, iface, s);

	if (!state) {
		state = no_proto.attach(&no_proto, iface, s);
		state->handler = invalid_proto_handler;
	}

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
	if (!proto)
		interface_add_error(iface, "proto", "INVALID_PROTO", NULL, 0);

	iface->proto_handler = proto;
}

int
interface_proto_event(struct interface_proto_state *proto,
		      enum interface_proto_cmd cmd, bool force)
{
	enum interface_event ev;
	int ret;

	ret = proto->handler(proto, cmd, force);
	if (ret || !(proto->flags & PROTO_FLAG_IMMEDIATE))
		goto out;

	switch(cmd) {
	case PROTO_CMD_SETUP:
		ev = IFEV_UP;
		break;
	case PROTO_CMD_TEARDOWN:
		ev = IFEV_DOWN;
		break;
	default:
		return -EINVAL;
	}
	proto->proto_event(proto, ev);

out:
	return ret;
}
