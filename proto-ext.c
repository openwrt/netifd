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
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "proto-ext.h"
#include "system.h"
#include "handler.h"

static void
proto_ext_check_dependencies(struct proto_ext_state *state)
{
	struct proto_ext_dep *dep;
	bool available = true;

	list_for_each_entry(dep, &state->deps, list) {
		if (dep->dep.iface)
			continue;

		available = false;
		break;
	}

	interface_set_available(state->proto.iface, available);
}

static void
proto_ext_if_up_cb(struct interface_user *dep, struct interface *iface,
		   enum interface_event ev);
static void
proto_ext_if_down_cb(struct interface_user *dep, struct interface *iface,
		     enum interface_event ev);

static void
proto_ext_update_host_dep(struct proto_ext_dep *dep)
{
	struct interface *iface = NULL;

	if (dep->dep.iface)
		goto out;

	if (dep->interface[0]) {
		iface = vlist_find(&interfaces, dep->interface, iface, node);

		if (!iface || iface->state != IFS_UP)
			goto out;
	}

	if (!dep->any)
		iface = interface_ip_add_target_route(&dep->host, dep->v6, iface, false);

	if (!iface)
		goto out;

	interface_remove_user(&dep->dep);
	dep->dep.cb = proto_ext_if_down_cb;
	interface_add_user(&dep->dep, iface);

out:
	proto_ext_check_dependencies(dep->proto);
}

static void
proto_ext_clear_host_dep(struct proto_ext_state *state)
{
	struct proto_ext_dep *dep, *tmp;

	list_for_each_entry_safe(dep, tmp, &state->deps, list) {
		interface_remove_user(&dep->dep);
		list_del(&dep->list);
		free(dep);
	}
}

static void
proto_ext_if_up_cb(struct interface_user *dep, struct interface *iface,
		   enum interface_event ev)
{
	struct proto_ext_dep *pdep;

	if (ev != IFEV_UP && ev != IFEV_UPDATE)
		return;

	pdep = container_of(dep, struct proto_ext_dep, dep);
	proto_ext_update_host_dep(pdep);
}

static void
proto_ext_if_down_cb(struct interface_user *dep, struct interface *iface,
		     enum interface_event ev)
{
	struct proto_ext_dep *pdep;
	struct proto_ext_state *state;

	if (ev != IFEV_UP_FAILED && ev != IFEV_DOWN && ev != IFEV_FREE)
		return;

	pdep = container_of(dep, struct proto_ext_dep, dep);
	interface_remove_user(dep);
	dep->cb = proto_ext_if_up_cb;
	interface_add_user(dep, NULL);

	state = pdep->proto;
	if (state->sm == S_IDLE) {
		state->proto.proto_event(&state->proto, IFPEV_LINK_LOST);
		state->proto.cb(&state->proto, PROTO_CMD_TEARDOWN, false);
	}
}

static void
proto_ext_task_finish(struct proto_ext_state *state,
		      struct netifd_process *task)
{
	switch (state->sm) {
	case S_IDLE:
		if (task == &state->proto_task)
			state->proto.proto_event(&state->proto, IFPEV_LINK_LOST);
		fallthrough;
	case S_SETUP:
		if (task == &state->proto_task)
			state->proto.cb(&state->proto, PROTO_CMD_TEARDOWN,
					false);
		else if (task == &state->script_task) {
			if (state->renew_pending)
				state->proto.cb(&state->proto,
						PROTO_CMD_RENEW, false);
			else if (!(state->proto.handler->flags & PROTO_FLAG_NO_TASK) &&
				 !state->proto_task.uloop.pending &&
				 state->sm == S_SETUP)
				state->proto.cb(&state->proto,
						PROTO_CMD_TEARDOWN,
						false);

			if (state->sm == S_SETUP && state->checkup_interval > 0) {
				uloop_timeout_set(&state->checkup_timeout,
						  state->checkup_interval * 1000);
			}
		}
		break;

	case S_SETUP_ABORT:
		if (state->script_task.uloop.pending ||
		    state->proto_task.uloop.pending)
			break;

		uloop_timeout_cancel(&state->teardown_timeout);
		uloop_timeout_cancel(&state->checkup_timeout);
		state->sm = S_IDLE;
		state->proto.cb(&state->proto, PROTO_CMD_TEARDOWN, false);
		break;

	case S_TEARDOWN:
		if (state->script_task.uloop.pending)
			break;

		if (state->proto_task.uloop.pending) {
			if (!state->proto_task_killed)
				kill(state->proto_task.uloop.pid, SIGTERM);
			break;
		}

		uloop_timeout_cancel(&state->teardown_timeout);
		uloop_timeout_cancel(&state->checkup_timeout);
		state->sm = S_IDLE;
		state->proto.proto_event(&state->proto, IFPEV_DOWN);
		break;
	}
}

static void
proto_ext_teardown_timeout_cb(struct uloop_timeout *timeout)
{
	struct proto_ext_state *state;

	state = container_of(timeout, struct proto_ext_state, teardown_timeout);

	netifd_kill_process(&state->script_task);
	netifd_kill_process(&state->proto_task);
	proto_ext_task_finish(state, NULL);
}

static void
proto_ext_script_cb(struct netifd_process *p, int ret)
{
	struct proto_ext_state *state;

	state = container_of(p, struct proto_ext_state, script_task);
	proto_ext_task_finish(state, p);
}

static void
proto_ext_task_cb(struct netifd_process *p, int ret)
{
	struct proto_ext_state *state;

	state = container_of(p, struct proto_ext_state, proto_task);

	if (state->sm == S_IDLE || state->sm == S_SETUP)
		state->last_error = WEXITSTATUS(ret);

	proto_ext_task_finish(state, p);
}

void
proto_ext_free(struct interface_proto_state *proto)
{
	struct proto_ext_state *state;

	state = container_of(proto, struct proto_ext_state, proto);
	uloop_timeout_cancel(&state->teardown_timeout);
	uloop_timeout_cancel(&state->checkup_timeout);
	proto_ext_clear_host_dep(state);
	netifd_kill_process(&state->script_task);
	netifd_kill_process(&state->proto_task);
	free(state->config);
	free(state);
}

static void
proto_ext_parse_route_list(struct interface *iface, struct blob_attr *attr,
			   bool v6)
{
	struct blob_attr *cur;
	size_t rem;

	blobmsg_for_each_attr(cur, attr, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE) {
			D(INTERFACE, "Ignore wrong route type: %d", blobmsg_type(cur));
			continue;
		}

		interface_ip_add_route(iface, cur, v6);
	}
}

static void
proto_ext_parse_neighbor_list(struct interface *iface, struct blob_attr *attr,
			      bool v6)
{
	struct blob_attr *cur;
	size_t rem;

	blobmsg_for_each_attr(cur, attr, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE) {
			D(INTERFACE, "Ignore wrong neighbor type: %d", blobmsg_type(cur));
			continue;
		}

		interface_ip_add_neighbor(iface, cur, v6);
	}
}

static void
proto_ext_parse_data(struct interface *iface, struct blob_attr *attr)
{
	struct blob_attr *cur;
	size_t rem;

	blobmsg_for_each_attr(cur, attr, rem)
		interface_add_data(iface, cur);
}

static struct device *
proto_ext_create_tunnel(const char *name, struct blob_attr *attr)
{
	struct device *dev;
	struct blob_buf b;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	blob_put(&b, 0, blobmsg_data(attr), blobmsg_data_len(attr));
	dev = device_create(name, &tunnel_device_type, blob_data(b.head));
	blob_buf_free(&b);

	return dev;
}

enum {
	NOTIFY_ACTION,
	NOTIFY_ERROR,
	NOTIFY_COMMAND,
	NOTIFY_ENV,
	NOTIFY_SIGNAL,
	NOTIFY_AVAILABLE,
	NOTIFY_LINK_UP,
	NOTIFY_IFNAME,
	NOTIFY_ADDR_EXT,
	NOTIFY_ROUTES,
	NOTIFY_ROUTES6,
	NOTIFY_TUNNEL,
	NOTIFY_DATA,
	NOTIFY_KEEP,
	NOTIFY_HOST,
	NOTIFY_DNS,
	NOTIFY_DNS_SEARCH,
	NOTIFY_NEIGHBORS,
	NOTIFY_NEIGHBORS6,
	__NOTIFY_LAST
};

static const struct blobmsg_policy notify_attr[__NOTIFY_LAST] = {
	[NOTIFY_ACTION] = { .name = "action", .type = BLOBMSG_TYPE_INT32 },
	[NOTIFY_ERROR] = { .name = "error", .type = BLOBMSG_TYPE_ARRAY },
	[NOTIFY_COMMAND] = { .name = "command", .type = BLOBMSG_TYPE_ARRAY },
	[NOTIFY_ENV] = { .name = "env", .type = BLOBMSG_TYPE_ARRAY },
	[NOTIFY_SIGNAL] = { .name = "signal", .type = BLOBMSG_TYPE_INT32 },
	[NOTIFY_AVAILABLE] = { .name = "available", .type = BLOBMSG_TYPE_BOOL },
	[NOTIFY_LINK_UP] = { .name = "link-up", .type = BLOBMSG_TYPE_BOOL },
	[NOTIFY_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[NOTIFY_ADDR_EXT] = { .name = "address-external", .type = BLOBMSG_TYPE_BOOL },
	[NOTIFY_ROUTES] = { .name = "routes", .type = BLOBMSG_TYPE_ARRAY },
	[NOTIFY_ROUTES6] = { .name = "routes6", .type = BLOBMSG_TYPE_ARRAY },
	[NOTIFY_TUNNEL] = { .name = "tunnel", .type = BLOBMSG_TYPE_TABLE },
	[NOTIFY_DATA] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	[NOTIFY_KEEP] = { .name = "keep", .type = BLOBMSG_TYPE_BOOL },
	[NOTIFY_HOST] = { .name = "host", .type = BLOBMSG_TYPE_STRING },
	[NOTIFY_DNS] = { .name = "dns", .type = BLOBMSG_TYPE_ARRAY },
	[NOTIFY_DNS_SEARCH] = { .name = "dns_search", .type = BLOBMSG_TYPE_ARRAY },
	[NOTIFY_NEIGHBORS]= {.name = "neighbor", .type = BLOBMSG_TYPE_ARRAY},
	[NOTIFY_NEIGHBORS6]= {.name = "neighbor6", .type = BLOBMSG_TYPE_ARRAY},
};

static int
proto_ext_update_link(struct proto_ext_state *state, struct blob_attr *data, struct blob_attr **tb)
{
	struct interface *iface = state->proto.iface;
	struct blob_attr *cur;
	struct device *dev;
	const char *devname;
	int dev_create = 1;
	bool addr_ext = false;
	bool keep = false;
	bool up;

	if (state->sm == S_TEARDOWN || state->sm == S_SETUP_ABORT)
		return UBUS_STATUS_PERMISSION_DENIED;

	if (!tb[NOTIFY_LINK_UP])
		return UBUS_STATUS_INVALID_ARGUMENT;

	up = blobmsg_get_bool(tb[NOTIFY_LINK_UP]);
	if (!up) {
		state->proto.proto_event(&state->proto, IFPEV_LINK_LOST);
		return 0;
	}

	if ((cur = tb[NOTIFY_KEEP]) != NULL)
		keep = blobmsg_get_bool(cur);

	if ((cur = tb[NOTIFY_ADDR_EXT]) != NULL) {
		addr_ext = blobmsg_get_bool(cur);
		if (addr_ext)
			dev_create = 2;
	}

	if (iface->state != IFS_UP || !iface->l3_dev.dev)
		keep = false;

	if (!keep) {
		dev = iface->main_dev.dev;
		if (tb[NOTIFY_IFNAME]) {
			keep = false;
			devname = blobmsg_data(tb[NOTIFY_IFNAME]);
			if (tb[NOTIFY_TUNNEL])
				dev = proto_ext_create_tunnel(devname, tb[NOTIFY_TUNNEL]);
			else
				dev = device_get(devname, dev_create);
		}

		if (!dev)
			return UBUS_STATUS_INVALID_ARGUMENT;

		interface_set_l3_dev(iface, dev);
		if (device_claim(&iface->l3_dev) < 0)
			return UBUS_STATUS_UNKNOWN_ERROR;

		device_set_present(dev, true);
	}

	interface_update_start(iface, keep);

	proto_apply_ip_settings(iface, data, addr_ext);

	if ((cur = tb[NOTIFY_ROUTES]) != NULL)
		proto_ext_parse_route_list(state->proto.iface, cur, false);

	if ((cur = tb[NOTIFY_ROUTES6]) != NULL)
		proto_ext_parse_route_list(state->proto.iface, cur, true);

	if ((cur = tb[NOTIFY_NEIGHBORS]) != NULL)
		proto_ext_parse_neighbor_list(state->proto.iface, cur, false);

	if ((cur = tb[NOTIFY_NEIGHBORS6]) != NULL)
		proto_ext_parse_neighbor_list(state->proto.iface, cur, true);

	if ((cur = tb[NOTIFY_DNS]))
		interface_add_dns_server_list(&iface->proto_ip, cur);

	if ((cur = tb[NOTIFY_DNS_SEARCH]))
		interface_add_dns_search_list(&iface->proto_ip, cur);

	if ((cur = tb[NOTIFY_DATA]))
		proto_ext_parse_data(state->proto.iface, cur);

	interface_update_complete(state->proto.iface);

	if ((state->sm != S_SETUP_ABORT) && (state->sm != S_TEARDOWN)) {
		state->proto.proto_event(&state->proto, IFPEV_UP);
		state->sm = S_IDLE;
	}

	return 0;
}

static bool
fill_string_list(struct blob_attr *attr, char **argv, int max)
{
	struct blob_attr *cur;
	int argc = 0;
	size_t rem;

	if (!attr)
		goto out;

	blobmsg_for_each_attr(cur, attr, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			return false;

		if (!blobmsg_check_attr(cur, false))
			return false;

		argv[argc++] = blobmsg_data(cur);
		if (argc == max - 1)
			return false;
	}

out:
	argv[argc] = NULL;
	return true;
}

static int
proto_ext_run_command(struct proto_ext_state *state, struct blob_attr **tb)
{
	static char *argv[64];
	static char *env[32];

	if (state->sm == S_TEARDOWN || state->sm == S_SETUP_ABORT)
		return UBUS_STATUS_PERMISSION_DENIED;

	if (!tb[NOTIFY_COMMAND])
		goto error;

	if (!fill_string_list(tb[NOTIFY_COMMAND], argv, ARRAY_SIZE(argv)))
		goto error;

	if (!fill_string_list(tb[NOTIFY_ENV], env, ARRAY_SIZE(env)))
		goto error;

	netifd_start_process((const char **) argv, (char **) env, &state->proto_task);

	return 0;

error:
	return UBUS_STATUS_INVALID_ARGUMENT;
}

static int
proto_ext_kill_command(struct proto_ext_state *state, struct blob_attr **tb)
{
	unsigned int signal = ~0;

	if (tb[NOTIFY_SIGNAL])
		signal = blobmsg_get_u32(tb[NOTIFY_SIGNAL]);

	if (signal > 31)
		signal = SIGTERM;

	if (state->proto_task.uloop.pending) {
		if (signal == SIGTERM || signal == SIGKILL)
			state->proto_task_killed = true;
		kill(state->proto_task.uloop.pid, signal);
	}

	return 0;
}

static int
proto_ext_notify_error(struct proto_ext_state *state, struct blob_attr **tb)
{
	struct blob_attr *cur;
	char *data[16];
	int n_data = 0;
	size_t rem;

	if (!tb[NOTIFY_ERROR])
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_for_each_attr(cur, tb[NOTIFY_ERROR], rem) {
		if (n_data + 1 == ARRAY_SIZE(data))
			goto error;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			goto error;

		if (!blobmsg_check_attr(cur, false))
			goto error;

		data[n_data++] = blobmsg_data(cur);
	}

	if (!n_data)
		goto error;

	interface_add_error(state->proto.iface, state->proto.handler->name,
			data[0], (const char **) &data[1], n_data - 1);

	return 0;

error:
	return UBUS_STATUS_INVALID_ARGUMENT;
}

static int
proto_ext_block_restart(struct proto_ext_state *state, struct blob_attr **tb)
{
	state->proto.iface->autostart = false;
	return 0;
}

static int
proto_ext_set_available(struct proto_ext_state *state, struct blob_attr **tb)
{
	if (!tb[NOTIFY_AVAILABLE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	interface_set_available(state->proto.iface, blobmsg_get_bool(tb[NOTIFY_AVAILABLE]));
	return 0;
}

static int
proto_ext_add_host_dependency(struct proto_ext_state *state, struct blob_attr **tb)
{
	struct proto_ext_dep *dep;
	const char *ifname = tb[NOTIFY_IFNAME] ? blobmsg_data(tb[NOTIFY_IFNAME]) : "";
	const char *host = tb[NOTIFY_HOST] ? blobmsg_data(tb[NOTIFY_HOST]) : "";

	if (state->sm == S_TEARDOWN || state->sm == S_SETUP_ABORT)
		return UBUS_STATUS_PERMISSION_DENIED;

	dep = calloc(1, sizeof(*dep) + strlen(ifname) + 1);
	if (!dep)
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (!host[0] && ifname[0]) {
		dep->any = true;
	} else if (inet_pton(AF_INET, host, &dep->host) < 1) {
		if (inet_pton(AF_INET6, host, &dep->host) < 1) {
			free(dep);
			return UBUS_STATUS_INVALID_ARGUMENT;
		} else {
			dep->v6 = true;
		}
	}

	dep->proto = state;
	strcpy(dep->interface, ifname);

	dep->dep.cb = proto_ext_if_up_cb;
	interface_add_user(&dep->dep, NULL);
	list_add(&dep->list, &state->deps);
	proto_ext_update_host_dep(dep);
	if (!dep->dep.iface)
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

static int
proto_ext_setup_failed(struct proto_ext_state *state)
{
	int ret = 0;

	switch (state->sm) {
	case S_IDLE:
		state->proto.proto_event(&state->proto, IFPEV_LINK_LOST);
		fallthrough;
	case S_SETUP:
		state->proto.cb(&state->proto, PROTO_CMD_TEARDOWN, false);
		break;
	case S_SETUP_ABORT:
	case S_TEARDOWN:
	default:
		ret = UBUS_STATUS_PERMISSION_DENIED;
		break;
	}
	return ret;
}

int
proto_ext_notify(struct interface_proto_state *proto, struct blob_attr *attr)
{
	struct proto_ext_state *state;
	struct blob_attr *tb[__NOTIFY_LAST];

	state = container_of(proto, struct proto_ext_state, proto);

	blobmsg_parse_attr(notify_attr, __NOTIFY_LAST, tb, attr);
	if (!tb[NOTIFY_ACTION])
		return UBUS_STATUS_INVALID_ARGUMENT;

	switch(blobmsg_get_u32(tb[NOTIFY_ACTION])) {
	case 0:
		return proto_ext_update_link(state, attr, tb);
	case 1:
		return proto_ext_run_command(state, tb);
	case 2:
		return proto_ext_kill_command(state, tb);
	case 3:
		return proto_ext_notify_error(state, tb);
	case 4:
		return proto_ext_block_restart(state, tb);
	case 5:
		return proto_ext_set_available(state, tb);
	case 6:
		return proto_ext_add_host_dependency(state, tb);
	case 7:
		return proto_ext_setup_failed(state);
	default:
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
}

static void
proto_ext_checkup_timeout_cb(struct uloop_timeout *timeout)
{
	struct proto_ext_state *state = container_of(timeout, struct
			proto_ext_state, checkup_timeout);
	struct interface_proto_state *proto = &state->proto;
	struct interface *iface = proto->iface;

	if (!iface->autostart)
		return;

	if (iface->state == IFS_UP)
		return;

	D(INTERFACE, "Interface '%s' is not up after %d sec",
			iface->name, state->checkup_interval);
	state->proto.cb(proto, PROTO_CMD_TEARDOWN, false);
}

static void
proto_ext_checkup_attach(struct proto_ext_state *state,
		const struct blob_attr *attr)
{
	struct blob_attr *tb;
	struct blobmsg_policy checkup_policy = {
		.name = "checkup_interval",
		.type = BLOBMSG_TYPE_INT32
	};

	blobmsg_parse_attr(&checkup_policy, 1, &tb, (struct blob_attr *)attr);
	if (!tb) {
		state->checkup_interval = -1;
		state->checkup_timeout.cb = NULL;
	} else {
		state->checkup_interval = blobmsg_get_u32(tb);
		state->checkup_timeout.cb = proto_ext_checkup_timeout_cb;
	}
}

void
proto_ext_state_init(struct proto_ext_state *state,
		     struct interface *iface, struct blob_attr *attr,
		     int dir_fd)
{
	INIT_LIST_HEAD(&state->deps);

	state->config = malloc(blob_pad_len(attr));
	if (!state->config)
		return;

	memcpy(state->config, attr, blob_pad_len(attr));
	proto_ext_checkup_attach(state, state->config);
	state->proto.free = proto_ext_free;
	state->proto.notify = proto_ext_notify;
	state->teardown_timeout.cb = proto_ext_teardown_timeout_cb;
	state->script_task.cb = proto_ext_script_cb;
	state->script_task.dir_fd = dir_fd;
	state->script_task.log_prefix = iface->name;
	state->proto_task.cb = proto_ext_task_cb;
	state->proto_task.dir_fd = dir_fd;
	state->proto_task.log_prefix = iface->name;
}

int
proto_ext_run(struct proto_ext_state *state,
	      enum interface_proto_cmd cmd, bool force,
	      proto_ext_handler_cb start_cb)
{
	struct interface_proto_state *proto = &state->proto;
	static char error_buf[32];
	char *envp[2];
	const char *action;
	char *config;
	int ret, j = 0;

	if (cmd == PROTO_CMD_SETUP) {
		switch (state->sm) {
		case S_IDLE:
			action = "setup";
			state->last_error = -1;
			proto_ext_clear_host_dep(state);
			state->sm = S_SETUP;
			break;

		default:
			return -1;
		}
	} else if (cmd == PROTO_CMD_RENEW) {
		if (!(proto->handler->flags & PROTO_FLAG_RENEW_AVAILABLE))
			return 0;

		if (state->script_task.uloop.pending) {
			state->renew_pending = true;
			return 0;
		}

		state->renew_pending = false;
		action = "renew";
	} else {
		switch (state->sm) {
		case S_SETUP:
			if (state->script_task.uloop.pending) {
				uloop_timeout_set(&state->teardown_timeout, 1000);
				kill(state->script_task.uloop.pid, SIGTERM);
				if (state->proto_task.uloop.pending)
					kill(state->proto_task.uloop.pid, SIGTERM);
				state->renew_pending = false;
				state->sm = S_SETUP_ABORT;
				return 0;
			}
		fallthrough;
		case S_IDLE:
			action = "teardown";
			state->renew_pending = false;
			state->sm = S_TEARDOWN;
			if (state->last_error >= 0) {
				snprintf(error_buf, sizeof(error_buf), "ERROR=%d", state->last_error);
				envp[j++] = error_buf;
			}
			uloop_timeout_set(&state->teardown_timeout, 5000);
			break;

		case S_TEARDOWN:
			return 0;

		default:
			return -1;
		}
	}

	D(INTERFACE, "run %s for interface '%s'", action, proto->iface->name);
	config = blobmsg_format_json(state->config, true);
	if (!config)
		return -1;

	envp[j] = NULL;

	ret = start_cb(state, action, config, envp);
	free(config);

	return ret;
}
