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
#include <ucode/vm.h>
#include <ucode/lib.h>
#include <ucode/compiler.h>
#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "ucode.h"

static uc_vm_t vm;
static uc_value_t *netifd_obj;
static struct blob_buf b;

struct uc_netifd_process {
	struct netifd_process proc;
	uc_value_t *res;
};

static uc_value_t *
prop_get(uc_value_t *obj, const char *name, uc_type_t type)
{
	uc_value_t *data = ucv_object_get(obj, name, NULL);

	if (!type || ucv_type(data) != type)
		return NULL;

	return data;
}

static bool
prop_get_bool(uc_value_t *obj, const char *name, bool *val)
{
	uc_value_t *data = prop_get(obj, name, UC_BOOLEAN);

	if (data)
		*val = ucv_boolean_get(data);
	return !!data;
}


static bool
prop_get_int(uc_value_t *obj, const char *name, int *val)
{
	uc_value_t *data = prop_get(obj, name, UC_INTEGER);

	if (data)
		*val = ucv_int64_get(data);

	return !!data;
}

static uc_value_t *
uc_netifd_device_set(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *name = uc_fn_arg(0);
	uc_value_t *data = uc_fn_arg(1);
	struct device *dev;
	bool check_vlan = true;
	int external = 0;
	bool bval;
	int ival;

	if (ucv_type(name) != UC_STRING || ucv_type(data) != UC_OBJECT)
		return NULL;

	prop_get_int(data, "external", &external);
	prop_get_bool(data, "check_vlan", &check_vlan);
	dev = __device_get(ucv_string_get(name), external, check_vlan);
	if (!dev)
		return NULL;

	if (prop_get_bool(data, "isolate", &bval)) {
		dev->settings.flags |= DEV_OPT_ISOLATE;
		dev->settings.isolate = bval;
	}

	if (prop_get_int(data, "multicast_to_unicast", &ival)) {
		if (ival < 0) {
			dev->settings.flags &= ~DEV_OPT_MULTICAST_TO_UNICAST;
		} else {
			dev->settings.flags |= DEV_OPT_MULTICAST_TO_UNICAST;
			dev->settings.multicast_to_unicast = !!ival;
		}
	}

	if (prop_get_bool(data, "wireless", &bval))
		dev->wireless = bval;
	if (prop_get_bool(data, "wireless_isolate", &bval))
		dev->wireless_isolate = bval;
	if (prop_get_bool(data, "wireless_proxyarp", &bval))
		dev->wireless_proxyarp = bval;
	if (prop_get_bool(data, "wireless_ap", &bval)) {
		dev->wireless_ap = bval;
		if (bval)
			dev->bpdu_filter = 1;
	}

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_netifd_interface_get_bridge(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *name = uc_fn_arg(0);
	uc_value_t *obj = uc_fn_arg(1);
	struct device *dev, *orig_dev;
	struct interface *iface;

	if (ucv_type(name) != UC_STRING)
		return NULL;

	iface = vlist_find(&interfaces, ucv_string_get(name), iface, node);
	if (!iface)
		return NULL;

	dev = orig_dev = iface->main_dev.dev;
	if (!dev)
		return NULL;

	if (ucv_type(obj) == UC_OBJECT)
		ucv_get(obj);
	else
		obj = ucv_object_new(vm);

	if (!dev->hotplug_ops)
		return obj;

	if (dev->hotplug_ops && dev->hotplug_ops->prepare)
		dev->hotplug_ops->prepare(dev, &dev);

	if (!dev || !dev->type->bridge_capability)
		return obj;

	ucv_object_add(obj, "bridge", ucv_string_new(dev->ifname));
	ucv_object_add(obj, "bridge-ifname", ucv_string_new(orig_dev->ifname));
	if (dev->settings.flags & DEV_OPT_MULTICAST_TO_UNICAST)
		ucv_object_add(obj, "multicast_to_unicast",
			       ucv_boolean_new(dev->settings.multicast_to_unicast));

	return obj;
}

static uc_value_t *
uc_netifd_interface_handle_link(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *args = uc_fn_arg(0);
	uc_value_t *name = ucv_object_get(args, "name", NULL);
	uc_value_t *ifname = ucv_object_get(args, "ifname", NULL);
	uc_value_t *vlan = ucv_object_get(args, "vlan", NULL);
	bool up = ucv_is_truish(ucv_object_get(args, "up", NULL));
	bool link_ext = ucv_is_truish(ucv_object_get(args, "link_ext", NULL));
	struct blob_attr *vlan_attr = NULL;
	struct interface *iface;
	const char *net;
	int ret;

	if (ucv_type(name) != UC_STRING || ucv_type(ifname) != UC_STRING ||
	    (vlan && ucv_type(vlan) != UC_ARRAY))
		return NULL;

	net = ucv_string_get(name);
	iface = vlist_find(&interfaces, net, iface, node);
	if (!iface)
		return NULL;

	if (vlan) {
		size_t len = ucv_array_length(vlan);
		void *c;

		blob_buf_init(&b, 0);
		c = blobmsg_open_array(&b, "vlan");
		for (size_t i = 0; i < len; i++) {
			uc_value_t *val = ucv_array_get(vlan, i);
			if (ucv_type(val) == UC_STRING)
				blobmsg_add_string(&b, NULL, ucv_string_get(val));
		}
		blobmsg_close_array(&b, c);

		vlan_attr = blobmsg_data(b.head);
	}

	ret = interface_handle_link(iface, ucv_string_get(ifname), vlan_attr, up, link_ext);
	return ucv_boolean_new(ret == 0);
}

static void
netifd_call_cb(const char *name, size_t nargs, ...)
{
	uc_value_t *val;
	va_list ap;

	va_start(ap, nargs);
	val = ucv_object_get(netifd_obj, "cb", NULL);
	if (ucv_type(val) != UC_OBJECT)
		goto out;

	val = ucv_object_get(val, name, NULL);
	if (!ucv_is_callable(val))
		goto out;

	uc_vm_stack_push(&vm, ucv_get(val));
	for (size_t i = 0; i < nargs; i++)
		uc_vm_stack_push(&vm, va_arg(ap, void *));
	va_end(ap);

	if (uc_vm_call(&vm, false, nargs) == EXCEPTION_NONE)
		ucv_put(uc_vm_stack_pop(&vm));

	return;

out:
	for (size_t i = 0; i < nargs; i++)
		ucv_put(va_arg(ap, void *));
	va_end(ap);
}

void netifd_ucode_config_load(bool start)
{
	netifd_call_cb(start ? "config_start" : "config_init", 0);
}

void netifd_ucode_check_network_enabled(void)
{
	netifd_call_cb("check_interfaces", 0);
}

void netifd_ucode_hotplug_event(const char *name, bool add)
{
	netifd_call_cb("hotplug", 2, ucv_string_new(name), ucv_boolean_new(add));
}

static uc_value_t *
uc_netifd_interface_get_enabled(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *name = uc_fn_arg(0);
	struct interface *iface;
	struct device *dev;
	uc_value_t *val;

	if (ucv_type(name) != UC_STRING)
		return NULL;

	iface = vlist_find(&interfaces, ucv_string_get(name), iface, node);
	if (!iface)
		return NULL;

	val = ucv_object_new(vm);
	ucv_object_add(val, "enabled", ucv_boolean_new(!!iface->autostart));
	dev = iface->main_dev.dev;
	if (dev && dev->hotplug_ops)
		ucv_object_add(val, "ifindex", ucv_int64_new(dev->ifindex));

	return val;
}

static void
uc_netifd_process_cb(struct netifd_process *proc, int ret)
{
	struct uc_netifd_process *up = container_of(proc, struct uc_netifd_process, proc);

	uc_vm_stack_push(&vm, ucv_get(up->res));
	uc_vm_stack_push(&vm, ucv_get(ucv_resource_value_get(up->res, 0)));
	uc_vm_stack_push(&vm, ucv_int64_new(ret));

	if (uc_vm_call(&vm, true, 1) == EXCEPTION_NONE)
		ucv_put(uc_vm_stack_pop(&vm));
}

static bool
fill_array(char **dest, uc_value_t *arr, size_t len)
{
	if (ucv_type(arr) != UC_ARRAY)
		return false;

	for (size_t i = 0; i < len; i++) {
		uc_value_t *str = ucv_array_get(arr, i);
		if (ucv_type(str) != UC_STRING)
			return false;

		dest[i] = strdup(ucv_string_get(str));
	}
	dest[len] = NULL;

	return true;
}

static int
uc_netifd_start_process(uc_value_t *dir, uc_value_t *arg, uc_value_t *env, int *fd)
{
	uc_value_t *fn;
	char **argv;
	size_t len;
	int pfds[2];
	int pid;

	len = ucv_array_length(arg);
	if (!len)
		return -1;

	if (pipe(pfds) < 0)
		return -1;

	if ((pid = fork()) < 0)
		goto error;

	if (pid > 0) {
		close(pfds[1]);
		*fd = pfds[0];
		return pid;
	}

	switch (ucv_type(dir)) {
	case UC_OBJECT:
		fn = ucv_property_get(dir, "fileno");
		if (!ucv_is_callable(fn))
			break;

		uc_vm_stack_push(&vm, ucv_get(dir));
		uc_vm_stack_push(&vm, ucv_get(fn));
		if (uc_vm_call(&vm, true, 0) != EXCEPTION_NONE)
			break;

		dir = uc_vm_stack_pop(&vm);
		if (ucv_type(dir) != UC_INTEGER)
			break;
		fallthrough;
	case UC_INTEGER:
		if (fchdir(ucv_int64_get(dir)) < 0)
			exit(1);
		break;
	case UC_STRING:
		if (chdir(ucv_string_get(dir)) < 0)
			exit(1);
		break;
	default:
		break;
	}

	argv = calloc(len + 1, sizeof(*argv));
	if (!fill_array(argv, arg, len))
		exit(127);

	len = ucv_array_length(env);
	for (size_t i = 0; i < len; i++) {
		uc_value_t *strval = ucv_array_get(env, i);
		char *str = ucv_string_get(strval);

		if (!str)
			continue;

		putenv(strdup(str));
	}

	for (int i = 0; i <= 2; i++) {
		if (pfds[1] == i)
			continue;

		dup2(pfds[1], i);
	}

	if (pfds[1] > 2)
		close(pfds[1]);

	execvp(argv[0], (char **) argv);
	exit(127);

error:
	close(pfds[0]);
	close(pfds[1]);
	return -1;
}

static uc_value_t *
uc_netifd_log(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *prio = uc_fn_arg(0);
	uc_value_t *msg = uc_fn_arg(1);

	if (ucv_type(prio) != UC_INTEGER ||
	    ucv_type(msg) != UC_STRING)
		return NULL;

	netifd_log_message(ucv_int64_get(prio), "%s", ucv_string_get(msg));
	return NULL;
}

static uc_value_t *
uc_netifd_debug(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *msg = uc_fn_arg(0);

	if (ucv_type(msg) != UC_STRING)
		return NULL;

	netifd_udebug_printf("%s", ucv_string_get(msg));
	return NULL;
}

static uc_value_t *
uc_netifd_process(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *res, *cb, *arg, *env, *dir, *prefix;
	uc_value_t *args = uc_fn_arg(0);
	struct uc_netifd_process *up;
	const char *prefix_str;
	int pid, fd;

	if (ucv_type(args) != UC_OBJECT)
		return NULL;

	arg = ucv_object_get(args, "argv", NULL);
	if (!ucv_array_length(arg))
		return NULL;

	env = ucv_object_get(args, "envp", NULL);
	if (env && ucv_type(env) != UC_ARRAY)
		return NULL;

	dir = ucv_object_get(args, "dir", NULL);

	cb = ucv_object_get(args, "cb", NULL);
	if (!ucv_is_callable(cb))
		return NULL;

	prefix = ucv_object_get(args, "log_prefix", NULL);
	if (!prefix)
		prefix = ucv_array_get(arg, 0);
	if (ucv_type(prefix) != UC_STRING)
		return NULL;

	prefix_str = ucv_string_get(prefix);

	res = ucv_resource_create_ex(vm, "netifd.process", (void **)&up, 1, sizeof(*up) + strlen(prefix_str + 1));
	if (!res)
		return NULL;

	up->res = res;

	pid = uc_netifd_start_process(dir, arg, env, &fd);
	if (pid < 0) {
		ucv_put(res);
		return NULL;
	}

	up->proc.log_prefix = strcpy((char *)(up + 1), prefix_str);
	up->proc.cb = uc_netifd_process_cb;
	netifd_add_process(&up->proc, fd, pid);
	ucv_resource_persistent_set(res, true);
	ucv_resource_value_set(res, 0, ucv_get(cb));

	return res;
}

static uc_value_t *
uc_netifd_process_cancel(uc_vm_t *vm, size_t nargs)
{
	struct uc_netifd_process *up;
	bool cancelled;

	up = uc_fn_thisval("netifd.process");
	if (!up)
		return NULL;

	cancelled = up->proc.uloop.pending;
	ucv_resource_persistent_set(up->res, false);
	ucv_resource_value_set(up->res, 0, NULL);
	netifd_kill_process(&up->proc);

	return ucv_boolean_new(cancelled);
}

static void close_proc(void *ud)
{
	netifd_kill_process(ud);
}

static uc_value_t *
uc_netifd_process_check(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *pid = uc_fn_arg(0);
	uc_value_t *exe = uc_fn_arg(1);
	bool ret;

	if (ucv_type(pid) != UC_INTEGER || ucv_type(exe) != UC_STRING)
		return NULL;

	ret = check_pid_path(ucv_int64_get(pid), ucv_string_get(exe));

	return ucv_boolean_new(ret);
}

static const uc_function_list_t proc_fns[] = {
	{ "cancel",			uc_netifd_process_cancel },
};

static const uc_function_list_t netifd_fns[] = {
	{ "log",			uc_netifd_log },
	{ "debug",			uc_netifd_debug },
	{ "process",			uc_netifd_process },
	{ "process_check",		uc_netifd_process_check },
	{ "device_set",			uc_netifd_device_set },
	{ "interface_get_enabled",	uc_netifd_interface_get_enabled },
	{ "interface_handle_link",	uc_netifd_interface_handle_link },
	{ "interface_get_bridge",	uc_netifd_interface_get_bridge },
};


void netifd_ucode_init(void)
{
	static uc_parse_config_t config = {
		.strict_declarations = true,
		.lstrip_blocks = true,
		.trim_blocks = true,
		.raw_mode = true
	};
	uc_value_t *obj, *val;
	uc_source_t *source;
	uc_program_t *prog;
	char *err;

	source = uc_source_new_file(DEFAULT_MAIN_PATH "/main.uc");
	if (!source)
		return;

	uc_search_path_init(&config.module_search_path);
	uc_search_path_add(&config.module_search_path, DEFAULT_MAIN_PATH "/*.so");
	uc_search_path_add(&config.module_search_path, DEFAULT_MAIN_PATH "/*.uc");

	uc_vm_init(&vm, &config);
	uc_stdlib_load(uc_vm_scope_get(&vm));
	uc_type_declare(&vm, "netifd.process", proc_fns, close_proc);

	obj = netifd_obj = ucv_object_new(&vm);

	uc_vm_registry_set(&vm, "netifd.obj", ucv_get(obj));
	ucv_object_add(uc_vm_scope_get(&vm), "netifd", obj);
	ucv_object_add(obj, "cb", ucv_object_new(&vm));
	ucv_object_add(obj, "main_path", ucv_string_new(DEFAULT_MAIN_PATH));
	if (config_path)
		ucv_object_add(obj, "config_path", ucv_string_new(config_path));
#ifdef DUMMY_MODE
	ucv_object_add(obj, "dummy_mode", ucv_boolean_new(true));
#endif

#define ADD_CONST(n) ucv_object_add(obj, #n, ucv_int64_new(n))
	ADD_CONST(L_CRIT);
	ADD_CONST(L_WARNING);
	ADD_CONST(L_NOTICE);
	ADD_CONST(L_INFO);
	ADD_CONST(L_DEBUG);
#undef ADD_CONST

	uc_function_list_register(obj, netifd_fns);

	prog = uc_compile(vm.config, source, &err);
	uc_source_put(source);

	if (!prog) {
		netifd_log_message(L_CRIT, "Error loading ucode script: %s\n", err);
		netifd_ucode_free();
		return;
	}

	uc_vm_execute(&vm, prog, &val);
	uc_program_put(prog);
	ucv_put(val);
}

void netifd_ucode_free(void)
{
	if (!vm.config)
		return;

	uc_search_path_free(&vm.config->module_search_path);
	uc_vm_free(&vm);
}
