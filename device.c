#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <libubox/uapi.h>

#include "netifd.h"
#include "system.h"

static struct avl_tree devices;

static int avl_strcmp(const void *k1, const void *k2, void *ptr)
{
	return strcmp(k1, k2);
}

static void API_CTOR dev_init(void)
{
	avl_init(&devices, avl_strcmp, false, NULL);
}

static void free_device(struct device *dev)
{
	cleanup_device(dev);
	free(dev);
}

static void broadcast_device_event(struct device *dev, enum device_event ev)
{
	struct device_user *dep, *tmp;

	list_for_each_entry_safe(dep, tmp, &dev->users, list) {
		if (!dep->cb)
			continue;

		dep->cb(dep, ev);
	}
}

static int set_device_state(struct device *dev, bool state)
{
	if (state) {
		broadcast_device_event(dev, DEV_EVENT_SETUP);
		system_if_up(dev);
		broadcast_device_event(dev, DEV_EVENT_UP);
	} else {
		broadcast_device_event(dev, DEV_EVENT_TEARDOWN);
		system_if_down(dev);
		broadcast_device_event(dev, DEV_EVENT_DOWN);
	}
	return 0;
}

int claim_device(struct device *dev)
{
	int ret;

	DPRINTF("claim device %s, new refcount: %d\n", dev->ifname, dev->active + 1);
	if (++dev->active != 1)
		return 0;

	ret = dev->set_state(dev, true);
	if (ret != 0)
		dev->active = 0;

	return ret;
}

void release_device(struct device *dev)
{
	dev->active--;
	DPRINTF("release device %s, new refcount: %d\n", dev->ifname, dev->active);
	assert(dev->active >= 0);

	if (!dev->active)
		dev->set_state(dev, false);
}

int check_device_state(struct device *dev)
{
	if (!dev->type->check_state)
		return 0;

	return dev->type->check_state(dev);
}

void init_virtual_device(struct device *dev, const struct device_type *type, const char *name)
{
	assert(dev);
	assert(type);

	fprintf(stderr, "Initialize interface '%s'\n", dev->ifname);
	INIT_LIST_HEAD(&dev->users);
	dev->type = type;

	if (name)
		strncpy(dev->ifname, name, IFNAMSIZ);
}

int init_device(struct device *dev, const struct device_type *type, const char *ifname)
{
	int ret;

	init_virtual_device(dev, type, ifname);

	if (!dev->set_state)
		dev->set_state = set_device_state;

	dev->avl.key = dev->ifname;

	ret = avl_insert(&devices, &dev->avl);
	if (ret < 0)
		return ret;

	check_device_state(dev);

	return 0;
}

struct device *get_device(const char *name, bool create)
{
	static const struct device_type simple_type = {
		.name = "Device",
		.check_state = system_if_check,
		.free = free_device,
	};
	struct device *dev;


	if (strchr(name, '.'))
		return get_vlan_device_chain(name, create);

	dev = avl_find_element(&devices, name, dev, avl);
	if (dev)
		return dev;

	if (!create)
		return NULL;

	dev = calloc(1, sizeof(*dev));
	init_device(dev, &simple_type, name);

	return dev;
}

void cleanup_device(struct device *dev)
{
	struct device_user *dep, *tmp;

	fprintf(stderr, "Clean up interface '%s'\n", dev->ifname);
	list_for_each_entry_safe(dep, tmp, &dev->users, list) {
		if (!dep->cb)
			continue;

		dep->cb(dep, DEV_EVENT_REMOVE);
	}

	if (dev->avl.key)
		avl_delete(&devices, &dev->avl);
}

void set_device_present(struct device *dev, bool state)
{
	if (dev->present == state)
		return;

	DPRINTF("Device '%s' %s present\n", dev->ifname, state ? "is now" : "is no longer" );
	dev->present = state;
	broadcast_device_event(dev, state ? DEV_EVENT_ADD : DEV_EVENT_REMOVE);
}

void add_device_user(struct device_user *dep, struct device *dev)
{
	dep->dev = dev;
	list_add(&dep->list, &dev->users);
	if (dep->cb && dev->present) {
		dep->cb(dep, DEV_EVENT_ADD);
		if (dev->active)
			dep->cb(dep, DEV_EVENT_UP);
	}
}

void remove_device_user(struct device_user *dep)
{
	struct device *dev = dep->dev;

	list_del(&dep->list);

	if (list_empty(&dev->users)) {
		/* all references have gone away, remove this interface */
		dev->type->free(dev);
	}

	dep->dev = NULL;
}
