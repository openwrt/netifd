#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#include "netifd.h"
#include "system.h"
#include "config.h"

static struct avl_tree devices;

enum {
	DEV_ATTR_NAME,
	DEV_ATTR_TYPE,
	DEV_ATTR_MTU,
	DEV_ATTR_MACADDR,
	DEV_ATTR_TXQUEUELEN,
	__DEV_ATTR_MAX,
};

static const struct blobmsg_policy dev_attrs[__DEV_ATTR_MAX] = {
	[DEV_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[DEV_ATTR_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[DEV_ATTR_MTU] = { "mtu", BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_MACADDR] = { "macaddr", BLOBMSG_TYPE_STRING },
	[DEV_ATTR_TXQUEUELEN] = { "txqueuelen", BLOBMSG_TYPE_INT32 },
};

const struct config_param_list device_attr_list = {
	.n_params = __DEV_ATTR_MAX,
	.params = dev_attrs,
};

static void
device_init_settings(struct device *dev, struct blob_attr **tb)
{
	struct blob_attr *cur;
	struct ether_addr *ea;

	dev->flags = 0;

	if ((cur = tb[DEV_ATTR_MTU])) {
		dev->mtu = blobmsg_get_u32(cur);
		dev->flags |= DEV_OPT_MTU;
	}

	if ((cur = tb[DEV_ATTR_TXQUEUELEN])) {
		dev->txqueuelen = blobmsg_get_u32(cur);
		dev->flags |= DEV_OPT_TXQUEUELEN;
	}

	if ((cur = tb[DEV_ATTR_MACADDR])) {
		ea = ether_aton(blob_data(cur));
		if (ea) {
			memcpy(dev->macaddr, ea, sizeof(dev->macaddr));
			dev->flags |= DEV_OPT_MACADDR;
		}
	}
}

struct device *
device_create(struct blob_attr *attr, struct uci_section *s)
{
	struct blob_attr *tb[__DEV_ATTR_MAX];
	struct blob_attr *cur;
	struct device *dev = NULL;
	const char *name;

	blobmsg_parse(dev_attrs, __DEV_ATTR_MAX, tb, blob_data(attr), blob_len(attr));
	if (!tb[DEV_ATTR_NAME])
		return NULL;

	name = blobmsg_data(tb[DEV_ATTR_NAME]);
	if ((cur = tb[DEV_ATTR_TYPE])) {
		if (!strcmp(blobmsg_data(cur), "bridge"))
			dev = bridge_create(name, s);
	} else {
		dev = get_device(name, true);
	}

	if (!dev)
		return NULL;

	device_init_settings(dev, tb);

	return dev;
}


static void __init dev_init(void)
{
	avl_init(&devices, avl_strcmp, false, NULL);
}

static void free_simple_device(struct device *dev)
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
	if (state)
		system_if_up(dev);
	else
		system_if_down(dev);

	return 0;
}

int claim_device(struct device *dev)
{
	int ret;

	DPRINTF("claim device %s, new refcount: %d\n", dev->ifname, dev->active + 1);
	if (++dev->active != 1)
		return 0;

	broadcast_device_event(dev, DEV_EVENT_SETUP);
	ret = dev->set_state(dev, true);
	if (ret == 0)
		broadcast_device_event(dev, DEV_EVENT_UP);
	else
		dev->active = 0;

	return ret;
}

void release_device(struct device *dev)
{
	dev->active--;
	DPRINTF("release device %s, new refcount: %d\n", dev->ifname, dev->active);
	assert(dev->active >= 0);

	if (dev->active)
		return;

	broadcast_device_event(dev, DEV_EVENT_TEARDOWN);
	dev->set_state(dev, false);
	broadcast_device_event(dev, DEV_EVENT_DOWN);
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

	if (name)
		strncpy(dev->ifname, name, IFNAMSIZ);

	fprintf(stderr, "Initialize device '%s'\n", dev->ifname);
	INIT_LIST_HEAD(&dev->users);
	dev->type = type;
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
		.free = free_simple_device,
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

	fprintf(stderr, "Clean up device '%s'\n", dev->ifname);
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
		/* all references have gone away, remove this device */
		free_device(dev);
	}

	dep->dev = NULL;
}

void
device_free_all(void)
{
	struct device *dev, *tmp;

	avl_for_each_element_safe(&devices, dev, avl, tmp) {
		if (!list_empty(&dev->users))
			continue;

		free_device(dev);
	}
}
