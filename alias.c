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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "device.h"

static struct avl_tree aliases;

struct alias_device {
	struct avl_node avl;
	struct device dev;
	struct device_user dep;
	bool cleanup;
	char name[];
};

static const struct device_type alias_device_type;

static int
alias_device_set_state(struct device *dev, bool state)
{
	struct alias_device *alias;

	alias = container_of(dev, struct alias_device, dev);
	if (!alias->dep.dev)
		return -1;

	if (state)
		return device_claim(&alias->dep);

	device_release(&alias->dep);
	if (alias->cleanup)
		device_remove_user(&alias->dep);
	return 0;
}

static struct device *
alias_device_create(const char *name, struct blob_attr *attr)
{
	struct alias_device *alias;

	alias = calloc(1, sizeof(*alias) + strlen(name) + 1);
	strcpy(alias->name, name);
	alias->dev.set_state = alias_device_set_state;
	alias->dev.hidden = true;
	device_init_virtual(&alias->dev, &alias_device_type, NULL);
	alias->avl.key = alias->name;
	avl_insert(&aliases, &alias->avl);

	return &alias->dev;
}

static void alias_device_free(struct device *dev)
{
	struct alias_device *alias;

	alias = container_of(dev, struct alias_device, dev);
	avl_delete(&aliases, &alias->avl);
	free(alias);
}

static const struct device_type alias_device_type = {
	.name = "Network alias",
	.create = alias_device_create,
	.free = alias_device_free,
};

void
alias_notify_device(const char *name, struct device *dev)
{
	struct alias_device *alias;

	device_lock();

	alias = avl_find_element(&aliases, name, alias, avl);
	if (!alias)
		return;

	alias->cleanup = !dev;
	if (dev) {
		if (dev != alias->dep.dev) {
			device_remove_user(&alias->dep);
			strcpy(alias->dev.ifname, dev->ifname);
			device_add_user(&alias->dep, dev);
			alias->dev.hidden = false;
			device_broadcast_event(&alias->dev, DEV_EVENT_UPDATE_IFNAME);
		}
	}

	device_set_present(&alias->dev, !!dev);

	if (!dev && alias->dep.dev && !alias->dep.dev->active) {
		device_remove_user(&alias->dep);
		alias->dev.hidden = true;
		alias->dev.ifname[0] = 0;
		device_broadcast_event(&alias->dev, DEV_EVENT_UPDATE_IFNAME);
	}

	device_unlock();
}

struct device *
device_alias_get(const char *name)
{
	struct alias_device *alias;

	alias = avl_find_element(&aliases, name, alias, avl);
	if (alias)
		return &alias->dev;

	return alias_device_create(name, NULL);
}

static void __init alias_init(void)
{
	avl_init(&aliases, avl_strcmp, false, NULL);
}
