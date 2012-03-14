#include "netifd.h"
#include "system.h"

static const struct blobmsg_policy tunnel_attrs[__TUNNEL_ATTR_MAX] = {
	[TUNNEL_ATTR_TYPE] = { "mode", BLOBMSG_TYPE_STRING },
	[TUNNEL_ATTR_LOCAL] = { "local", BLOBMSG_TYPE_STRING },
	[TUNNEL_ATTR_REMOTE] = { "remote", BLOBMSG_TYPE_STRING },
	[TUNNEL_ATTR_TTL] = { "ttl", BLOBMSG_TYPE_INT32 },
};

const struct config_param_list tunnel_attr_list = {
	.n_params = __TUNNEL_ATTR_MAX,
	.params = tunnel_attrs,
};
