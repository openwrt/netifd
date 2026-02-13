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
#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "proto.h"
#include "handler.h"
#include "proto-ext.h"

static int proto_fd = -1;

struct proto_shell_handler {
	struct list_head list;
	struct proto_handler proto;
	char *config_buf;
	char *script_name;
	bool init_available;

	struct uci_blob_param_list config;
};

static int
proto_shell_start(struct proto_ext_state *state, const char *action,
		  const char *config, char **envp)
{
	struct proto_shell_handler *handler;
	const char *argv[7];
	int i = 0;

	handler = container_of(state->proto.handler, struct proto_shell_handler, proto);

	argv[i++] = handler->script_name;
	argv[i++] = handler->proto.name;
	argv[i++] = action;
	argv[i++] = state->proto.iface->name;
	argv[i++] = config;
	if (state->proto.iface->main_dev.dev)
		argv[i++] = state->proto.iface->main_dev.dev->ifname;
	argv[i] = NULL;

	return netifd_start_process(argv, envp, &state->script_task);
}

static int
proto_shell_handler(struct interface_proto_state *proto,
		    enum interface_proto_cmd cmd, bool force)
{
	struct proto_ext_state *state;

	state = container_of(proto, struct proto_ext_state, proto);
	return proto_ext_run(state, cmd, force, proto_shell_start);
}

static struct interface_proto_state *
proto_shell_attach(const struct proto_handler *h, struct interface *iface,
		   struct blob_attr *attr)
{
	struct proto_ext_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		return NULL;

	proto_ext_state_init(state, iface, attr, proto_fd);
	if (!state->config) {
		free(state);
		return NULL;
	}

	state->proto.cb = proto_shell_handler;

	return &state->proto;
}

static void
proto_shell_add_handler(const char *script, const char *name, json_object *obj)
{
	struct proto_shell_handler *handler;
	struct proto_handler *proto;
	json_object *config, *tmp;
	char *proto_name, *script_name;

	handler = calloc_a(sizeof(*handler),
			   &proto_name, strlen(name) + 1,
			   &script_name, strlen(script) + 1);
	if (!handler)
		return;

	handler->script_name = strcpy(script_name, script);

	proto = &handler->proto;
	proto->name = strcpy(proto_name, name);
	proto->config_params = &handler->config;
	proto->attach = proto_shell_attach;

	tmp = json_get_field(obj, "no-device", json_type_boolean);
	if (tmp && json_object_get_boolean(tmp))
		handler->proto.flags |= PROTO_FLAG_NODEV;

	tmp = json_get_field(obj, "no-device-config", json_type_boolean);
	if (tmp && json_object_get_boolean(tmp))
		handler->proto.flags |= PROTO_FLAG_NODEV_CONFIG;

	tmp = json_get_field(obj, "no-proto-task", json_type_boolean);
	if (tmp && json_object_get_boolean(tmp))
		handler->proto.flags |= PROTO_FLAG_NO_TASK;

	tmp = json_get_field(obj, "available", json_type_boolean);
	if (tmp && json_object_get_boolean(tmp))
		handler->proto.flags |= PROTO_FLAG_INIT_AVAILABLE;

	tmp = json_get_field(obj, "renew-handler", json_type_boolean);
	if (tmp && json_object_get_boolean(tmp))
		handler->proto.flags |= PROTO_FLAG_RENEW_AVAILABLE;

	tmp = json_get_field(obj, "lasterror", json_type_boolean);
	if (tmp && json_object_get_boolean(tmp))
		handler->proto.flags |= PROTO_FLAG_LASTERROR;

	tmp = json_get_field(obj, "teardown-on-l3-link-down", json_type_boolean);
	if (tmp && json_object_get_boolean(tmp))
		handler->proto.flags |= PROTO_FLAG_TEARDOWN_ON_L3_LINK_DOWN;

	config = json_get_field(obj, "config", json_type_array);
	if (config)
		handler->config_buf = netifd_handler_parse_config(&handler->config, config);

	D(INTERFACE, "Add handler for script %s: %s", script, proto->name);
	add_proto_handler(proto);
}

void proto_shell_init(void)
{
	proto_fd = netifd_open_subdir("proto");
	if (proto_fd < 0)
		return;

	netifd_init_script_handlers(proto_fd, proto_shell_add_handler);
}
