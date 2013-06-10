/*
 * netifd - network interface daemon
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "netifd.h"
#include "system.h"
#include <fcntl.h>

static const struct blobmsg_policy tunnel_attrs[__TUNNEL_ATTR_MAX] = {
	[TUNNEL_ATTR_TYPE] = { "mode", BLOBMSG_TYPE_STRING },
	[TUNNEL_ATTR_LOCAL] = { "local", BLOBMSG_TYPE_STRING },
	[TUNNEL_ATTR_REMOTE] = { "remote", BLOBMSG_TYPE_STRING },
	[TUNNEL_ATTR_TTL] = { "ttl", BLOBMSG_TYPE_INT32 },
	[TUNNEL_ATTR_6RD_PREFIX] = { "6rd-prefix", BLOBMSG_TYPE_STRING },
	[TUNNEL_ATTR_6RD_RELAY_PREFIX] = { "6rd-relay-prefix", BLOBMSG_TYPE_STRING },
	[TUNNEL_ATTR_LINK] = { "link", BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list tunnel_attr_list = {
	.n_params = __TUNNEL_ATTR_MAX,
	.params = tunnel_attrs,
};

void system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}
