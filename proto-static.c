#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "proto.h"

struct static_proto_state {
    struct interface_proto_state proto;
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
static_attach(struct proto_handler *h, struct interface *iface,
	      struct uci_section *s)
{
	struct static_proto_state *state;

	state = calloc(1, sizeof(*state));
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
