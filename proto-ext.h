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
#ifndef __NETIFD_PROTO_EXT_H
#define __NETIFD_PROTO_EXT_H

#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"

enum proto_ext_sm {
	S_IDLE,
	S_SETUP,
	S_SETUP_ABORT,
	S_TEARDOWN,
};

struct proto_ext_state {
	struct interface_proto_state proto;
	struct blob_attr *config;

	struct uloop_timeout teardown_timeout;

	int checkup_interval;
	struct uloop_timeout checkup_timeout;

	struct netifd_process script_task;
	struct netifd_process proto_task;

	enum proto_ext_sm sm;
	bool proto_task_killed;
	bool renew_pending;

	int last_error;

	struct list_head deps;
};

struct proto_ext_dep {
	struct list_head list;

	struct proto_ext_state *proto;
	struct interface_user dep;

	union if_addr host;
	bool v6;
	bool any;

	char interface[];
};

typedef int (*proto_ext_handler_cb)(struct proto_ext_state *state,
				    const char *action, const char *config,
				    char **envp);

void proto_ext_state_init(struct proto_ext_state *state,
			  struct interface *iface, struct blob_attr *attr,
			  int dir_fd);
int proto_ext_run(struct proto_ext_state *state,
		  enum interface_proto_cmd cmd, bool force,
		  proto_ext_handler_cb start_cb);
int proto_ext_notify(struct interface_proto_state *proto, struct blob_attr *attr);
void proto_ext_free(struct interface_proto_state *proto);

#endif
