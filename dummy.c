/*
 * netifd - network interface daemon
 * Copyright (C) 2026 Joshua Covington <joshuacov@gmail.com>
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

/*
 * Linux "dummy" network device (IFLA_INFO_KIND "dummy", kmod-dummy).
 *
 * Not to be confused with system-dummy.c / DUMMY_MODE, which is netifd's
 * kernel-less test backend.
 *
 * No reload hook: no own attributes (generic ones handled by device.c).
 * Link is created on up, deleted on down.
 */
#include <stdlib.h>

#include "netifd.h"
#include "device.h"
#include "system.h"

struct dummy {
	struct device dev;
	device_state_cb set_state;
};

static int
dummy_set_state(struct device *dev, bool up)
{
	struct dummy *dm = container_of(dev, struct dummy, dev);
	int ret;

	D(SYSTEM, "dummy_set_state(%s, %u)", dev->ifname, up);

	if (!up) {
		ret = dm->set_state(dev, false);
		system_dummy_del(dev);
		return ret;
	}

	/* Remove any stale link of this name (e.g. left behind by a
	 * netifd crash) so the NLM_F_EXCL create below is authoritative */
	system_dummy_del(dev);

	ret = system_dummy_add(dev);
	if (ret < 0)
		return ret;

	ret = dm->set_state(dev, true);
	if (ret)
		system_dummy_del(dev);

	return ret;
}

static void
dummy_config_init(struct device *dev)
{
	device_set_present(dev, true);
}

static struct device *
dummy_create(const char *name, struct device_type *devtype,
	     struct blob_attr *attr)
{
	struct dummy *dm;
	struct device *dev;

	dm = calloc(1, sizeof(*dm));
	if (!dm)
		return NULL;

	dev = &dm->dev;
	if (device_init(dev, devtype, name) < 0) {
		device_cleanup(dev);
		free(dm);
		return NULL;
	}

	dev->config_pending = true;

	dm->set_state = dev->set_state;
	dev->set_state = dummy_set_state;

	device_init_config(dev, attr);

	return dev;
}

static void
dummy_free(struct device *dev)
{
	free(container_of(dev, struct dummy, dev));
}

static struct device_type dummy_device_type = {
	.name = "dummy",
	.config_params = &device_attr_list,
	.create = dummy_create,
	.config_init = dummy_config_init,
	.free = dummy_free,
};

static void __init dummy_device_type_init(void)
{
	device_type_add(&dummy_device_type);
}
