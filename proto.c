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

static struct interface_proto_state *get_default_proto(void)
{
	struct interface_proto_state *proto;

	proto = calloc(1, sizeof(*proto));
	proto->free = default_proto_free;
	proto->flags = PROTO_FLAG_IMMEDIATE;

	return proto;
}

void proto_attach_interface(struct interface *iface, struct uci_section *s)
{
	struct interface_proto_state *state = NULL;
	struct proto_handler *proto = NULL;
	const char *proto_name;
	const char *error = NULL;

	proto_name = uci_lookup_option_string(uci_ctx, s, "proto");
	if (!proto_name) {
		error = "NO_PROTO";
		goto error;
	}

	if (!strcmp(proto_name, "none")) {
		state = get_default_proto();
		state->handler = no_proto_handler;
		goto out;
	}

	if (handlers.comp)
		proto = avl_find_element(&handlers, proto_name, proto, avl);

	if (!proto) {
		error = "INVALID_PROTO";
		goto error;
	}

	state = proto->attach(proto, iface);

error:
	if (error) {
		interface_add_error(iface, "proto", error, NULL, 0);
		state = get_default_proto();
		state->handler = invalid_proto_handler;
	}

out:
	interface_set_proto_state(iface, state);
}


int interface_proto_event(struct interface_proto_state *proto,
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
