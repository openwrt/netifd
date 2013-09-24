/*
 * netifd - network interface daemon
 * Copyright (C) 2012-2013 Felix Fietkau <nbd@openwrt.org>
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
#ifndef __NETIFD_HANDLER_H
#define __NETIFD_HANDLER_H

#include <libubox/blobmsg_json.h>

typedef void (*script_dump_cb)(const char *name, json_object *obj);

int netifd_open_subdir(const char *name);
void netifd_init_script_handlers(int dir_fd, script_dump_cb cb);

#endif
