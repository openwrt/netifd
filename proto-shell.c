#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <glob.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <libubox/blobmsg_json.h>

#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"

static LIST_HEAD(handlers);
static int proto_fd;

struct proto_shell_handler {
	struct list_head list;
	struct proto_handler proto;
	struct config_param_list config;
	char *config_buf;
	char script_name[];
};

struct proto_shell_state {
	struct interface_proto_state proto;
	struct proto_shell_handler *handler;
	struct blob_attr *config;

	struct device_user l3_dev;

	struct uloop_timeout setup_timeout;
	struct uloop_process setup_task;
	struct uloop_process teardown_task;
	bool teardown_pending;
};

static int
run_script(const char **argv, struct uloop_process *proc)
{
	int pid;

	if ((pid = fork()) < 0)
		return -1;

	if (!pid) {
		fchdir(proto_fd);
		execvp(argv[0], (char **) argv);
		exit(127);
	}

	if (pid < 0)
		return -1;

	proc->pid = pid;
	uloop_process_add(proc);

	return 0;
}

static int
proto_shell_handler(struct interface_proto_state *proto,
		    enum interface_proto_cmd cmd, bool force)
{
	struct proto_shell_state *state;
	struct proto_shell_handler *handler;
	struct uloop_process *proc;
	const char *argv[6];
	const char *action;
	char *config;
	int ret, i = 0;

	state = container_of(proto, struct proto_shell_state, proto);
	handler = state->handler;

	if (cmd == PROTO_CMD_SETUP) {
		action = "setup";
		proc = &state->setup_task;
	} else {
		action = "teardown";
		proc = &state->teardown_task;
		if (state->setup_task.pending) {
			uloop_timeout_set(&state->setup_timeout, 1000);
			kill(state->setup_task.pid, SIGINT);
			state->teardown_pending = true;
			return 0;
		}
	}

	config = blobmsg_format_json(state->config, true);
	if (!config)
		return -1;

	argv[i++] = handler->script_name;
	argv[i++] = handler->proto.name;
	argv[i++] = action;
	argv[i++] = proto->iface->name;
	argv[i++] = config;
	if (proto->iface->main_dev.dev)
		argv[i++] = proto->iface->main_dev.dev->ifname;
	argv[i] = NULL;

	ret = run_script(argv, proc);
	free(config);

	return ret;
}

static void
proto_shell_setup_timeout_cb(struct uloop_timeout *timeout)
{
	struct proto_shell_state *state;

	state = container_of(timeout, struct proto_shell_state, setup_timeout);
	kill(state->setup_task.pid, SIGKILL);
}

static void
proto_shell_setup_cb(struct uloop_process *p, int ret)
{
	struct proto_shell_state *state;

	state = container_of(p, struct proto_shell_state, setup_task);
	uloop_timeout_cancel(&state->setup_timeout);
	if (state->teardown_pending) {
		state->teardown_pending = false;
		proto_shell_handler(&state->proto, PROTO_CMD_TEARDOWN, false);
	}
}

static void
proto_shell_teardown_cb(struct uloop_process *p, int ret)
{
	struct proto_shell_state *state;

	state = container_of(p, struct proto_shell_state, teardown_task);
	state->proto.proto_event(&state->proto, IFPEV_DOWN);
	if (state->l3_dev.dev)
		device_remove_user(&state->l3_dev);
}

static void
proto_shell_free(struct interface_proto_state *proto)
{
	struct proto_shell_state *state;

	state = container_of(proto, struct proto_shell_state, proto);
	free(state->config);
	free(state);
}

enum {
	NOTIFY_LINK_UP,
	NOTIFY_IFNAME,
	__NOTIFY_LAST
};

static const struct blobmsg_policy notify_attr[__NOTIFY_LAST] = {
	[NOTIFY_LINK_UP] = { .name = "link-up", .type = BLOBMSG_TYPE_BOOL },
	[NOTIFY_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};

static int
proto_shell_notify(struct interface_proto_state *proto, struct blob_attr *attr)
{
	struct proto_shell_state *state;
	struct blob_attr *tb[__NOTIFY_LAST];
	bool up;

	state = container_of(proto, struct proto_shell_state, proto);

	blobmsg_parse(notify_attr, __NOTIFY_LAST, tb, blob_data(attr), blob_len(attr));
	if (!tb[NOTIFY_LINK_UP])
		return UBUS_STATUS_INVALID_ARGUMENT;

	up = blobmsg_get_bool(tb[NOTIFY_LINK_UP]);
	if (up) {
		if (!tb[NOTIFY_IFNAME])
			return UBUS_STATUS_INVALID_ARGUMENT;

		if (!state->l3_dev.dev) {
			device_add_user(&state->l3_dev,
				device_get(blobmsg_data(tb[NOTIFY_IFNAME]), true));
			device_claim(&state->l3_dev);
			state->proto.iface->l3_dev = &state->l3_dev;
		}
		state->proto.proto_event(&state->proto, IFPEV_UP);
	} else {
		state->proto.proto_event(&state->proto, IFPEV_LINK_LOST);
	}

	return 0;
}

struct interface_proto_state *
proto_shell_attach(const struct proto_handler *h, struct interface *iface,
		   struct blob_attr *attr)
{
	struct proto_shell_state *state;

	state = calloc(1, sizeof(*state));
	state->config = malloc(blob_pad_len(attr));
	if (!state->config)
		goto error;

	memcpy(state->config, attr, blob_pad_len(attr));
	state->proto.free = proto_shell_free;
	state->proto.notify = proto_shell_notify;
	state->proto.cb = proto_shell_handler;
	state->setup_timeout.cb = proto_shell_setup_timeout_cb;
	state->setup_task.cb = proto_shell_setup_cb;
	state->teardown_task.cb = proto_shell_teardown_cb;
	state->handler = container_of(h, struct proto_shell_handler, proto);

	return &state->proto;

error:
	free(state);
	return NULL;
}

static json_object *
check_type(json_object *obj, json_type type)
{
	if (!obj)
		return NULL;

	if (json_object_get_type(obj) != type)
		return NULL;

	return obj;
}

static inline json_object *
get_field(json_object *obj, const char *name, json_type type)
{
	return check_type(json_object_object_get(obj, name), type);
}

static char *
proto_shell_parse_config(struct config_param_list *config, json_object *obj)
{
	struct blobmsg_policy *attrs;
	char *str_buf, *str_cur;
	int str_len = 0;
	int i;

	attrs = calloc(1, sizeof(*attrs));
	if (!attrs)
		return NULL;

	config->n_params = json_object_array_length(obj);
	config->params = attrs;
	for (i = 0; i < config->n_params; i++) {
		json_object *cur, *name, *type;

		cur = check_type(json_object_array_get_idx(obj, i), json_type_array);
		if (!cur)
			goto error;

		name = check_type(json_object_array_get_idx(cur, 0), json_type_string);
		if (!name)
			goto error;

		type = check_type(json_object_array_get_idx(cur, 1), json_type_int);
		if (!type)
			goto error;

		attrs[i].name = json_object_get_string(name);
		attrs[i].type = json_object_get_int(type);
		if (attrs[i].type > BLOBMSG_TYPE_LAST)
			goto error;

		str_len += strlen(attrs[i].name + 1);
	}

	str_buf = malloc(str_len);
	if (!str_buf)
		goto error;

	str_cur = str_buf;
	for (i = 0; i < config->n_params; i++) {
		const char *name = attrs[i].name;

		attrs[i].name = str_cur;
		str_cur += sprintf(str_cur, "%s", name) + 1;
	}

	return str_buf;

error:
	free(attrs);
	config->n_params = 0;
	return NULL;
}

static void
proto_shell_add_handler(const char *script, json_object *obj)
{
	struct proto_shell_handler *handler;
	struct proto_handler *proto;
	json_object *config, *tmp;
	const char *name;
	char *str;

	if (!check_type(obj, json_type_object))
		return;

	tmp = get_field(obj, "name", json_type_string);
	if (!tmp)
		return;

	name = json_object_get_string(tmp);

	handler = calloc(1, sizeof(*handler) +
			 strlen(script) + 1 +
			 strlen(name) + 1);
	if (!handler)
		return;

	strcpy(handler->script_name, script);

	str = handler->script_name + strlen(handler->script_name) + 1;
	strcpy(str, name);

	proto = &handler->proto;
	proto->name = str;
	proto->config_params = &handler->config;
	proto->attach = proto_shell_attach;

	tmp = get_field(obj, "no-device", json_type_boolean);
	if (tmp && json_object_get_boolean(tmp))
		handler->proto.flags |= PROTO_FLAG_NODEV;

	config = get_field(obj, "config", json_type_array);
	if (config)
		handler->config_buf = proto_shell_parse_config(&handler->config, config);

	DPRINTF("Add handler for script %s: %s\n", script, proto->name);
	add_proto_handler(proto);
}

static void proto_shell_add_script(const char *name)
{
	struct json_tokener *tok = NULL;
	json_object *obj;
	static char buf[512];
	char *start, *end, *cmd;
	FILE *f;
	int buflen, len;

#define DUMP_SUFFIX	" '' dump"

	cmd = alloca(strlen(name) + 1 + sizeof(DUMP_SUFFIX));
	sprintf(cmd, "%s" DUMP_SUFFIX, name);

	f = popen(cmd, "r");
	if (!f)
		return;

	do {
		buflen = fread(buf, 1, sizeof(buf) - 1, f);
		if (buflen <= 0)
			continue;

		start = buf;
		len = buflen;
		do {
			end = memchr(start, '\n', len);
			if (end)
				len = end - start;

			if (!tok)
				tok = json_tokener_new();

			obj = json_tokener_parse_ex(tok, start, len);
			if (!is_error(obj)) {
				proto_shell_add_handler(name, obj);
				json_object_put(obj);
				json_tokener_free(tok);
				tok = NULL;
			}

			if (end) {
				start = end + 1;
				len = buflen - (start - buf);
			}
		} while (len > 0);
	} while (!feof(f) && !ferror(f));

	if (tok)
		json_tokener_free(tok);

	pclose(f);
}

void __init proto_shell_init(void)
{
	glob_t g;
	int main_fd;
	int i;

	main_fd = open(".", O_RDONLY | O_DIRECTORY);
	if (main_fd < 0)
		return;

	if (chdir(main_path)) {
		perror("chdir(main path)");
		goto close_cur;
	}

	if (chdir("./proto"))
		goto close_cur;

	proto_fd = open(".", O_RDONLY | O_DIRECTORY);
	if (proto_fd < 0)
		goto close_cur;

	glob("./*.sh", 0, NULL, &g);
	for (i = 0; i < g.gl_pathc; i++)
		proto_shell_add_script(g.gl_pathv[i]);

close_cur:
	fchdir(main_fd);
	close(main_fd);
}
