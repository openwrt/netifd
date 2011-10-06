#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#ifdef linux
#include <netinet/ether.h>
#endif

#include "netifd.h"
#include "system.h"
#include "config.h"

static struct avl_tree devices;

static const struct blobmsg_policy dev_attrs[__DEV_ATTR_MAX] = {
	[DEV_ATTR_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[DEV_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[DEV_ATTR_IFNAME] = { "ifname", BLOBMSG_TYPE_ARRAY },
	[DEV_ATTR_MTU] = { "mtu", BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_MACADDR] = { "macaddr", BLOBMSG_TYPE_STRING },
	[DEV_ATTR_TXQUEUELEN] = { "txqueuelen", BLOBMSG_TYPE_INT32 },
};

const struct config_param_list device_attr_list = {
	.n_params = __DEV_ATTR_MAX,
	.params = dev_attrs,
};

static struct device *
simple_device_create(struct blob_attr *attr)
{
	struct blob_attr *tb[__DEV_ATTR_MAX];
	struct device *dev = NULL;
	const char *name;

	blobmsg_parse(dev_attrs, __DEV_ATTR_MAX, tb, blob_data(attr), blob_len(attr));
	if (!tb[DEV_ATTR_NAME])
		return NULL;

	name = blobmsg_data(tb[DEV_ATTR_NAME]);
	if (!name)
		return NULL;

	dev = device_get(name, true);
	if (!dev)
		return NULL;

	device_init_settings(dev, tb);

	return dev;
}

static void simple_device_free(struct device *dev)
{
	device_cleanup(dev);
	free(dev);
}

const struct device_type simple_device_type = {
	.name = "Network device",
	.config_params = &device_attr_list,

	.create = simple_device_create,
	.check_state = system_if_check,
	.free = simple_device_free,
};

void
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

static void __init dev_init(void)
{
	avl_init(&devices, avl_strcmp, true, NULL);
}

static void device_broadcast_event(struct device *dev, enum device_event ev)
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

int device_claim(struct device_user *dep)
{
	struct device *dev = dep->dev;
	int ret;

	if (dep->claimed)
		return 0;

	dep->claimed = true;
	D(DEVICE, "claim device %s, new refcount: %d\n", dev->ifname, dev->active + 1);
	if (++dev->active != 1)
		return 0;

	device_broadcast_event(dev, DEV_EVENT_SETUP);
	ret = dev->set_state(dev, true);
	if (ret == 0)
		device_broadcast_event(dev, DEV_EVENT_UP);
	else {
		D(DEVICE, "claim device %s failed: %d\n", dev->ifname, ret);
		dev->active = 0;
		dep->claimed = false;
	}

	return ret;
}

void device_release(struct device_user *dep)
{
	struct device *dev = dep->dev;

	if (!dep->claimed)
		return;

	dep->claimed = false;
	dev->active--;
	D(DEVICE, "release device %s, new refcount: %d\n", dev->ifname, dev->active);
	assert(dev->active >= 0);

	if (dev->active)
		return;

	device_broadcast_event(dev, DEV_EVENT_TEARDOWN);
	dev->set_state(dev, false);
	device_broadcast_event(dev, DEV_EVENT_DOWN);
}

int device_check_state(struct device *dev)
{
	if (!dev->type->check_state)
		return 0;

	return dev->type->check_state(dev);
}

void device_init_virtual(struct device *dev, const struct device_type *type, const char *name)
{
	assert(dev);
	assert(type);

	if (name)
		strncpy(dev->ifname, name, IFNAMSIZ);

	D(DEVICE, "Initialize device '%s'\n", dev->ifname);
	INIT_LIST_HEAD(&dev->users);
	dev->type = type;
}

int device_init(struct device *dev, const struct device_type *type, const char *ifname)
{
	int ret;

	device_init_virtual(dev, type, ifname);

	if (!dev->set_state)
		dev->set_state = set_device_state;

	dev->avl.key = dev->ifname;

	ret = avl_insert(&devices, &dev->avl);
	if (ret < 0)
		return ret;

	device_check_state(dev);

	return 0;
}

static struct device *
device_create_default(const char *name)
{
	struct device *dev;

	D(DEVICE, "Create simple device '%s'\n", name);
	dev = calloc(1, sizeof(*dev));
	device_init(dev, &simple_device_type, name);
	dev->default_config = true;
	return dev;
}

struct device *
device_get(const char *name, bool create)
{
	struct device *dev;

	if (strchr(name, '.'))
		return get_vlan_device_chain(name, create);

	dev = avl_find_element(&devices, name, dev, avl);
	if (dev)
		return dev;

	if (!create)
		return NULL;

	return device_create_default(name);
}

static void
device_delete(struct device *dev)
{
	if (!dev->avl.key)
		return;

	D(DEVICE, "Delete device '%s' from list\n", dev->ifname);
	avl_delete(&devices, &dev->avl);
	dev->avl.key = NULL;
}

void device_cleanup(struct device *dev)
{
	struct device_user *dep, *tmp;

	D(DEVICE, "Clean up device '%s'\n", dev->ifname);
	list_for_each_entry_safe(dep, tmp, &dev->users, list) {
		if (!dep->cb)
			continue;

		dep->cb(dep, DEV_EVENT_REMOVE);
		device_release(dep);
	}

	device_delete(dev);
}

void device_set_present(struct device *dev, bool state)
{
	if (dev->present == state)
		return;

	D(DEVICE, "Device '%s' %s present\n", dev->ifname, state ? "is now" : "is no longer" );
	dev->present = state;
	device_broadcast_event(dev, state ? DEV_EVENT_ADD : DEV_EVENT_REMOVE);
}

void device_add_user(struct device_user *dep, struct device *dev)
{
	dep->dev = dev;
	list_add_tail(&dep->list, &dev->users);
	if (dep->cb && dev->present) {
		dep->cb(dep, DEV_EVENT_ADD);
		if (dev->active)
			dep->cb(dep, DEV_EVENT_UP);
	}
}

static void
__device_free_unused(struct device *dev)
{
	if (!list_empty(&dev->users) || dev->current_config)
		return;

	device_free(dev);
}

void device_remove_user(struct device_user *dep)
{
	struct device *dev = dep->dev;

	if (dep->claimed)
		device_release(dep);

	list_del(&dep->list);
	dep->dev = NULL;
	__device_free_unused(dev);
}

void
device_free_unused(struct device *dev)
{
	struct device *tmp;

	if (dev)
		return __device_free_unused(dev);

	avl_for_each_element_safe(&devices, dev, avl, tmp)
		__device_free_unused(dev);
}

void
device_init_pending(void)
{
	struct device *dev, *tmp;

	avl_for_each_element_safe(&devices, dev, avl, tmp) {
		if (!dev->config_pending)
			continue;

		dev->type->config_init(dev);
		dev->config_pending = false;
	}
}

enum dev_change_type
device_reload_config(struct device *dev, struct blob_attr *attr)
{
	struct blob_attr *tb[__DEV_ATTR_MAX], *tb1[__DEV_ATTR_MAX];
	const struct config_param_list *cfg = dev->type->config_params;

	blobmsg_parse(cfg->params, cfg->n_params, tb,
		blob_data(attr), blob_len(attr));
	if (dev->config)
		blobmsg_parse(cfg->params, cfg->n_params, tb1,
			blob_data(dev->config), blob_len(dev->config));
	else
		memset(tb1, 0, sizeof(tb1));

	if (!config_diff(tb, tb1, cfg, NULL))
		return DEV_CONFIG_NO_CHANGE;

	if (cfg == &device_attr_list) {
		device_init_settings(dev, tb);
		return DEV_CONFIG_APPLIED;
	} else
		return DEV_CONFIG_RECREATE;
}

static enum dev_change_type
device_check_config(struct device *dev, const struct device_type *type,
		    struct blob_attr *attr)
{
	if (type != dev->type)
		return DEV_CONFIG_RECREATE;

	if (dev->type->reload)
		return dev->type->reload(dev, attr);

	return device_reload_config(dev, attr);
}

static void
device_replace(struct device *dev, struct device *odev)
{
	struct device_user *dep, *tmp;
	bool present = odev->present;

	if (present)
		device_set_present(odev, false);

	list_for_each_entry_safe(dep, tmp, &odev->users, list) {
		device_release(dep);
		list_move_tail(&dep->list, &dev->users);
		dep->dev = dev;
	}
	device_free(odev);

	if (present)
		device_set_present(dev, true);
}

void
device_reset_config(void)
{
	struct device *dev;

	avl_for_each_element(&devices, dev, avl)
		dev->current_config = false;
}

void
device_reset_old(void)
{
	struct device *dev, *tmp, *ndev;

	avl_for_each_element_safe(&devices, dev, avl, tmp) {
		if (dev->current_config || dev->default_config)
			continue;

		if (dev->type != &simple_device_type)
			continue;

		ndev = device_create_default(dev->ifname);
		device_replace(ndev, dev);
	}
}

struct device *
device_create(const char *name, const struct device_type *type,
	      struct blob_attr *config)
{
	struct device *odev = NULL, *dev;
	enum dev_change_type change;

	D(DEVICE, "Create new device '%s' (%s)\n", name, type->name);
	config = config_memdup(config);
	if (!config)
		return NULL;

	odev = device_get(name, false);
	if (odev) {
		odev->current_config = true;
		change = device_check_config(odev, type, config);
		switch (change) {
		case DEV_CONFIG_APPLIED:
			D(DEVICE, "Device '%s': config applied\n", odev->ifname);
			free(odev->config);
			odev->config = config;
			if (odev->present) {
				device_set_present(odev, false);
				device_set_present(odev, true);
			}
			return odev;
		case DEV_CONFIG_NO_CHANGE:
			D(DEVICE, "Device '%s': no configuration change\n", odev->ifname);
			free(config);
			return odev;
		case DEV_CONFIG_RECREATE:
			D(DEVICE, "Device '%s': recreate device\n", odev->ifname);
			device_delete(odev);
			break;
		}
	}

	dev = type->create(config);
	if (!dev)
		return NULL;

	dev->current_config = true;
	dev->config = config;
	if (odev)
		device_replace(dev, odev);

	if (!config_init && dev->config_pending)
		type->config_init(dev);

	return dev;
}
