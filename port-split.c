#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <uci.h>

#include "netifd.h"
#include "port-split.h"
#include "system.h"

#define PORT_SPLIT_WAIT_TIMEOUT_MS 2000

struct port_split_config {
	struct list_head list;
	char *device;
	uint32_t count;
	bool ignore;
	bool done;
};

struct port_split_state {
	struct list_head list;
	char *device;
	uint32_t count;
	uint32_t split_group;
	struct system_devlink_port parent;
	struct system_devlink_port member;
};

static LIST_HEAD(port_split_states);

static bool
port_split_parse_count(const char *str, uint32_t *count)
{
	char *end;
	unsigned long val;

	errno = 0;
	val = strtoul(str, &end, 0);
	if (errno || end == str || *end || val > UINT32_MAX)
		return false;

	*count = val;
	return true;
}

static struct port_split_config *
port_split_config_find(struct list_head *configs, const char *device)
{
	struct port_split_config *cfg;

	list_for_each_entry(cfg, configs, list)
		if (!strcmp(cfg->device, device))
			return cfg;

	return NULL;
}

static struct port_split_state *
port_split_state_find(const char *device)
{
	struct port_split_state *st;

	list_for_each_entry(st, &port_split_states, list)
		if (!strcmp(st->device, device))
			return st;

	return NULL;
}

static void
port_split_config_add(struct list_head *configs, const char *device,
		      uint32_t count, bool ignore)
{
	struct port_split_config *cfg;

	cfg = port_split_config_find(configs, device);
	if (!cfg) {
		cfg = calloc(1, sizeof(*cfg));
		if (!cfg)
			return;

		cfg->device = strdup(device);
		if (!cfg->device) {
			free(cfg);
			return;
		}

		list_add_tail(&cfg->list, configs);
	}

	cfg->count = count;
	cfg->ignore = ignore;
}

static void
port_split_config_load(struct uci_context *ctx, struct uci_package *pkg,
		       struct list_head *configs)
{
	struct uci_element *e;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *device, *split;
		uint32_t count;

		if (strcmp(s->type, "device") != 0)
			continue;

		device = uci_lookup_option_string(ctx, s, "name");
		split = uci_lookup_option_string(ctx, s, "split");
		if (!device || !split)
			continue;

		if (!port_split_parse_count(split, &count)) {
			netifd_log_message(L_WARNING,
					   "%s: invalid port split count '%s'\n",
					   device, split);
			port_split_config_add(configs, device, 0, true);
			continue;
		}

		port_split_config_add(configs, device, count >= 2 ? count : 0,
				      false);
	}
}

static void
port_split_state_free(struct port_split_state *st)
{
	list_del(&st->list);
	free(st->device);
	free(st);
}

static void
port_split_config_free(struct port_split_config *cfg)
{
	list_del(&cfg->list);
	free(cfg->device);
	free(cfg);
}

static int
port_split_unsplit_state(struct port_split_state *st)
{
	int ret;

	ret = system_devlink_port_unsplit(&st->member);
	if (ret) {
		netifd_log_message(L_WARNING,
				   "%s: failed to unsplit managed devlink group %u (%d)\n",
				   st->device, st->split_group, ret);
		return ret;
	}

	ret = system_devlink_port_wait_ifname(st->device, &st->parent,
					       PORT_SPLIT_WAIT_TIMEOUT_MS);
	if (ret)
		netifd_log_message(L_WARNING,
				   "%s: parent netdev did not reappear after unsplit (%d)\n",
				   st->device, ret);

	return 0;
}

static void
port_split_apply_config(struct port_split_config *cfg)
{
	struct port_split_state *st;
	int ret;

	if (port_split_state_find(cfg->device)) {
		cfg->done = true;
		return;
	}

	st = calloc(1, sizeof(*st));
	if (!st)
		return;

	st->device = strdup(cfg->device);
	if (!st->device) {
		free(st);
		return;
	}

	ret = system_devlink_port_from_ifname(cfg->device, &st->parent);
	if (ret) {
		netifd_log_message(L_WARNING,
				   "%s: unable to resolve devlink port for split (%d)\n",
				   cfg->device, ret);
		goto error;
	}

	ret = system_devlink_port_split(&st->parent, cfg->count, &st->member,
					&st->split_group);
	if (ret) {
		netifd_log_message(L_WARNING,
				   "%s: failed to split devlink port into %u ports (%d)\n",
				   cfg->device, cfg->count, ret);
		goto error;
	}

	st->count = cfg->count;
	list_add_tail(&st->list, &port_split_states);
	cfg->done = true;
	return;

error:
	free(st->device);
	free(st);
}

void
port_split_config_init(struct uci_context *ctx, struct uci_package *pkg)
{
	LIST_HEAD(configs);
	struct port_split_state *st, *st_tmp;
	struct port_split_config *cfg, *cfg_tmp;

	if (!pkg)
		return;

	port_split_config_load(ctx, pkg, &configs);

	list_for_each_entry_safe(st, st_tmp, &port_split_states, list) {
		cfg = port_split_config_find(&configs, st->device);
		if (!cfg) {
			if (!port_split_unsplit_state(st))
				port_split_state_free(st);
			continue;
		}

		if (cfg->ignore) {
			cfg->done = true;
			continue;
		}

		if (!cfg->count) {
			cfg->done = true;
			if (!port_split_unsplit_state(st))
				port_split_state_free(st);
			continue;
		}

		if (cfg->count == st->count) {
			cfg->done = true;
			continue;
		}

		if (!port_split_unsplit_state(st))
			port_split_state_free(st);
		else
			cfg->done = true;
	}

	list_for_each_entry(cfg, &configs, list) {
		if (cfg->ignore || cfg->done || !cfg->count)
			continue;

		port_split_apply_config(cfg);
	}

	list_for_each_entry_safe(cfg, cfg_tmp, &configs, list)
		port_split_config_free(cfg);
}

void
port_split_shutdown(void)
{
	struct port_split_state *st, *tmp;

	list_for_each_entry_safe(st, tmp, &port_split_states, list) {
		if (!port_split_unsplit_state(st))
			port_split_state_free(st);
	}
}
