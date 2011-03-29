#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"

static void
default_proto_free(struct interface_proto_state *proto)
{
	free(proto);
}

static int
default_proto_handler(struct interface_proto_state *proto,
		      enum interface_proto_cmd cmd, bool force)
{
	enum interface_event ev;

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
	return 0;
}

struct interface_proto_state *get_default_proto(void)
{
	struct interface_proto_state *proto;

	proto = calloc(1, sizeof(*proto));
	proto->handler = default_proto_handler;
	proto->free = default_proto_free;
	return proto;
}
