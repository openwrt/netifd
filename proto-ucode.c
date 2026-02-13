/*
 * netifd - network interface daemon
 * Copyright (C) 2025 Felix Fietkau <nbd@nbd.name>
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
#include <limits.h>

#include <ucode/vm.h>
#include <ucode/lib.h>
#include <ucode/types.h>
#include <ucode/program.h>

#include "netifd.h"
#include "proto.h"
#include "proto-ext.h"
#include "proto-ucode.h"
#include "ucode.h"

struct proto_ucode_handler {
	struct proto_handler proto;
	uc_value_t *res;
	char *script_name;
};

static const struct blobmsg_policy proto_ucode_policy = {
	.name = "_ucode_config", .type = BLOBMSG_TYPE_STRING,
};

static const struct uci_blob_param_list proto_ucode_config_params = {
	.n_params = 1, .params = &proto_ucode_policy,
};

static void
proto_ucode_config_load(const struct proto_handler *h,
			struct uci_section *s, struct blob_buf *b)
{
	struct proto_ucode_handler *handler;
	uc_value_t *netifd_obj, *cb_obj, *fn, *config_cb, *ret;
	const char *str;

	handler = container_of(h, struct proto_ucode_handler, proto);

	netifd_obj = uc_vm_registry_get(&vm, "netifd.obj");
	if (!netifd_obj)
		return;

	cb_obj = ucv_object_get(netifd_obj, "cb", NULL);
	if (ucv_type(cb_obj) != UC_OBJECT)
		return;

	fn = ucv_object_get(cb_obj, "proto_config_load", NULL);
	if (!ucv_is_callable(fn))
		return;

	config_cb = ucv_resource_value_get(handler->res, 0);

	uc_vm_stack_push(&vm, ucv_get(fn));
	uc_vm_stack_push(&vm, ucv_get(config_cb));
	uc_vm_stack_push(&vm, ucv_string_new(s->e.name));

	if (uc_vm_call(&vm, false, 2) != EXCEPTION_NONE) {
		D(INTERFACE, "proto_config_load callback failed for '%s'",
		  handler->proto.name);
		return;
	}

	ret = uc_vm_stack_pop(&vm);
	str = ucv_string_get(ret);
	if (str)
		blobmsg_add_string(b, "_ucode_config", str);

	ucv_put(ret);
}

static int
proto_ucode_start(struct proto_ext_state *state, const char *action,
		  const char *config, char **envp)
{
	struct proto_ucode_handler *handler;
	char helper[PATH_MAX];
	const char *argv[9];
	int i = 0;

	handler = container_of(state->proto.handler, struct proto_ucode_handler, proto);

	snprintf(helper, sizeof(helper), "%s/proto-ucode.uc", main_path);

	argv[i++] = "ucode";
	argv[i++] = helper;
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
proto_ucode_handler(struct interface_proto_state *proto,
		    enum interface_proto_cmd cmd, bool force)
{
	struct proto_ext_state *state;

	state = container_of(proto, struct proto_ext_state, proto);
	return proto_ext_run(state, cmd, force, proto_ucode_start);
}

static struct interface_proto_state *
proto_ucode_attach(const struct proto_handler *h, struct interface *iface,
		   struct blob_attr *attr)
{
	struct proto_ext_state *state;

	state = calloc(1, sizeof(*state));
	if (!state)
		return NULL;

	proto_ext_state_init(state, iface, attr, -1);
	if (!state->config) {
		free(state);
		return NULL;
	}

	state->proto.cb = proto_ucode_handler;

	return &state->proto;
}

static char *
proto_ucode_get_script_path(uc_vm_t *vm)
{
	uc_callframe_t *frame;
	uc_source_t *source;

	for (size_t i = vm->callframes.count; i > 0; i--) {
		frame = &vm->callframes.entries[i - 1];

		if (!frame->closure)
			continue;

		source = uc_program_function_source(frame->closure->function);
		if (source && source->runpath)
			return source->runpath;
	}

	return NULL;
}

uc_value_t *
uc_netifd_add_proto_fn(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *obj = uc_fn_arg(0);
	uc_value_t *name_val, *config_val, *flag_val, *res;
	struct proto_ucode_handler *handler;
	struct proto_handler *proto;
	const char *name;
	char *script_path, *proto_name, *script_name;

	if (ucv_type(obj) != UC_OBJECT)
		return NULL;

	name_val = ucv_object_get(obj, "name", NULL);
	name = ucv_string_get(name_val);
	if (!name)
		return NULL;

	script_path = proto_ucode_get_script_path(vm);
	if (!script_path)
		return NULL;

	res = ucv_resource_create_ex(vm, "netifd.proto_handler",
				     (void **)&handler, 1,
				     sizeof(*handler) + strlen(name) + 1 +
				     strlen(script_path) + 1);
	if (!res)
		return NULL;

	proto_name = (char *)(handler + 1);
	script_name = proto_name + strlen(name) + 1;

	handler->res = res;
	handler->script_name = strcpy(script_name, script_path);

	proto = &handler->proto;
	proto->name = strcpy(proto_name, name);
	proto->attach = proto_ucode_attach;
	proto->config_load = proto_ucode_config_load;
	proto->config_params = &proto_ucode_config_params;

	config_val = ucv_object_get(obj, "config", NULL);
	if (ucv_is_callable(config_val)) {
		ucv_resource_value_set(res, 0, ucv_get(config_val));
	}

	flag_val = ucv_object_get(obj, "no-device", NULL);
	if (ucv_is_truish(flag_val))
		proto->flags |= PROTO_FLAG_NODEV;

	flag_val = ucv_object_get(obj, "no-device-config", NULL);
	if (ucv_is_truish(flag_val))
		proto->flags |= PROTO_FLAG_NODEV_CONFIG;

	flag_val = ucv_object_get(obj, "no_proto_task", NULL);
	if (ucv_is_truish(flag_val))
		proto->flags |= PROTO_FLAG_NO_TASK;

	flag_val = ucv_object_get(obj, "available", NULL);
	if (ucv_is_truish(flag_val))
		proto->flags |= PROTO_FLAG_INIT_AVAILABLE;

	flag_val = ucv_object_get(obj, "renew-handler", NULL);
	if (ucv_is_truish(flag_val))
		proto->flags |= PROTO_FLAG_RENEW_AVAILABLE;

	flag_val = ucv_object_get(obj, "lasterror", NULL);
	if (ucv_is_truish(flag_val))
		proto->flags |= PROTO_FLAG_LASTERROR;

	flag_val = ucv_object_get(obj, "teardown-on-l3-link-down", NULL);
	if (ucv_is_truish(flag_val))
		proto->flags |= PROTO_FLAG_TEARDOWN_ON_L3_LINK_DOWN;

	ucv_resource_persistent_set(res, true);

	D(INTERFACE, "Add ucode handler for script %s: %s",
	  handler->script_name, proto->name);
	add_proto_handler(proto);

	return ucv_boolean_new(true);
}
