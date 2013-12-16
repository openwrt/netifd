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
	[DEV_ATTR_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
	[DEV_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_ARRAY },
	[DEV_ATTR_MTU] = { .name = "mtu", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_MACADDR] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
	[DEV_ATTR_TXQUEUELEN] = { .name = "txqueuelen", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_ENABLED] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
};

const struct uci_blob_param_list device_attr_list = {
	.n_params = __DEV_ATTR_MAX,
	.params = dev_attrs,
};

static int __devlock = 0;

void device_lock(void)
{
	__devlock++;
}

void device_unlock(void)
{
	__devlock--;
	if (!__devlock)
		device_free_unused(NULL);
}

static int set_device_state(struct device *dev, bool state)
{
	if (state)
		system_if_up(dev);
	else
		system_if_down(dev);

	return 0;
}

static int
simple_device_set_state(struct device *dev, bool state)
{
	struct device *pdev;
	int ret = 0;

	pdev = dev->parent.dev;
	if (state && !pdev) {
		pdev = system_if_get_parent(dev);
		if (pdev)
			device_add_user(&dev->parent, pdev);
	}

	if (pdev) {
		if (state)
			ret = device_claim(&dev->parent);
		else
			device_release(&dev->parent);

		if (ret < 0)
			return ret;
	}
	return set_device_state(dev, state);
}

static struct device *
simple_device_create(const char *name, struct blob_attr *attr)
{
	struct blob_attr *tb[__DEV_ATTR_MAX];
	struct device *dev = NULL;

	blobmsg_parse(dev_attrs, __DEV_ATTR_MAX, tb, blob_data(attr), blob_len(attr));
	dev = device_get(name, true);
	if (!dev)
		return NULL;

	dev->set_state = simple_device_set_state;
	device_init_settings(dev, tb);

	return dev;
}

static void simple_device_free(struct device *dev)
{
	if (dev->parent.dev)
		device_remove_user(&dev->parent);
	free(dev);
}

const struct device_type simple_device_type = {
	.name = "Network device",
	.config_params = &device_attr_list,

	.create = simple_device_create,
	.check_state = system_if_check,
	.free = simple_device_free,
};

static void
device_merge_settings(struct device *dev, struct device_settings *n)
{
	struct device_settings *os = &dev->orig_settings;
	struct device_settings *s = &dev->settings;

	memset(n, 0, sizeof(*n));
	n->mtu = s->flags & DEV_OPT_MTU ? s->mtu : os->mtu;
	n->txqueuelen = s->flags & DEV_OPT_TXQUEUELEN ?
		s->txqueuelen : os->txqueuelen;
	memcpy(n->macaddr,
		(s->flags & DEV_OPT_MACADDR ? s->macaddr : os->macaddr),
		sizeof(n->macaddr));
	n->flags = s->flags | os->flags;
}

void
device_init_settings(struct device *dev, struct blob_attr **tb)
{
	struct device_settings *s = &dev->settings;
	struct blob_attr *cur;
	struct ether_addr *ea;
	bool disabled = false;

	s->flags = 0;
	if ((cur = tb[DEV_ATTR_ENABLED]))
		disabled = !blobmsg_get_bool(cur);

	if ((cur = tb[DEV_ATTR_MTU])) {
		s->mtu = blobmsg_get_u32(cur);
		s->flags |= DEV_OPT_MTU;
	}

	if ((cur = tb[DEV_ATTR_TXQUEUELEN])) {
		s->txqueuelen = blobmsg_get_u32(cur);
		s->flags |= DEV_OPT_TXQUEUELEN;
	}

	if ((cur = tb[DEV_ATTR_MACADDR])) {
		ea = ether_aton(blobmsg_data(cur));
		if (ea) {
			memcpy(s->macaddr, ea, 6);
			s->flags |= DEV_OPT_MACADDR;
		}
	}

	device_set_disabled(dev, disabled);
}

static void __init dev_init(void)
{
	avl_init(&devices, avl_strcmp, true, NULL);
}

static int device_broadcast_cb(void *ctx, struct safe_list *list)
{
	struct device_user *dep = container_of(list, struct device_user, list);
	int *ev = ctx;

	/* device might have been removed by an earlier callback */
	if (!dep->dev)
		return 0;

	if (dep->cb)
		dep->cb(dep, *ev);
	return 0;
}

void device_broadcast_event(struct device *dev, enum device_event ev)
{
	int dev_ev = ev;

	safe_list_for_each(&dev->aliases, device_broadcast_cb, &dev_ev);
	safe_list_for_each(&dev->users, device_broadcast_cb, &dev_ev);
}

int device_claim(struct device_user *dep)
{
	struct device *dev = dep->dev;
	int ret;

	if (dep->claimed)
		return 0;

	dep->claimed = true;
	D(DEVICE, "Claim %s %s, new refcount: %d\n", dev->type->name, dev->ifname, dev->active + 1);
	if (++dev->active != 1)
		return 0;

	device_broadcast_event(dev, DEV_EVENT_SETUP);
	ret = dev->set_state(dev, true);
	if (ret == 0)
		device_broadcast_event(dev, DEV_EVENT_UP);
	else {
		D(DEVICE, "claim %s %s failed: %d\n", dev->type->name, dev->ifname, ret);
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
	D(DEVICE, "Release %s %s, new refcount: %d\n", dev->type->name, dev->ifname, dev->active);
	assert(dev->active >= 0);

	if (dev->active)
		return;

	device_broadcast_event(dev, DEV_EVENT_TEARDOWN);
	if (!dep->hotplug)
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
	INIT_SAFE_LIST(&dev->users);
	INIT_SAFE_LIST(&dev->aliases);
	dev->type = type;

	if (!dev->set_state)
		dev->set_state = set_device_state;
}

int device_init(struct device *dev, const struct device_type *type, const char *ifname)
{
	int ret;

	device_init_virtual(dev, type, ifname);

	dev->avl.key = dev->ifname;

	ret = avl_insert(&devices, &dev->avl);
	if (ret < 0)
		return ret;

	system_if_clear_state(dev);
	device_check_state(dev);

	return 0;
}

static struct device *
device_create_default(const char *name, bool external)
{
	struct device *dev;

	if (!external && system_if_force_external(name))
		return NULL;

	D(DEVICE, "Create simple device '%s'\n", name);
	dev = calloc(1, sizeof(*dev));
	dev->external = external;
	dev->set_state = simple_device_set_state;
	device_init(dev, &simple_device_type, name);
	dev->default_config = true;
	return dev;
}

struct device *
device_get(const char *name, int create)
{
	struct device *dev;

	if (strchr(name, '.'))
		return get_vlan_device_chain(name, create);

	if (name[0] == '@')
		return device_alias_get(name + 1);

	dev = avl_find_element(&devices, name, dev, avl);
	if (dev) {
		if (create > 1 && !dev->external) {
			dev->external = true;
			device_set_present(dev, true);
		}
		return dev;
	}

	if (!create)
		return NULL;

	return device_create_default(name, create > 1);
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

static int device_cleanup_cb(void *ctx, struct safe_list *list)
{
	struct device_user *dep = container_of(list, struct device_user, list);
	if (dep->cb)
		dep->cb(dep, DEV_EVENT_REMOVE);

	device_release(dep);
	return 0;
}

void device_cleanup(struct device *dev)
{
	D(DEVICE, "Clean up device '%s'\n", dev->ifname);
	safe_list_for_each(&dev->users, device_cleanup_cb, NULL);
	safe_list_for_each(&dev->aliases, device_cleanup_cb, NULL);
	device_delete(dev);
}

static void __device_set_present(struct device *dev, bool state)
{
	if (dev->present == state)
		return;

	dev->present = state;
	device_broadcast_event(dev, state ? DEV_EVENT_ADD : DEV_EVENT_REMOVE);
}

void
device_refresh_present(struct device *dev)
{
	bool state = dev->sys_present;

	if (dev->disabled || dev->deferred)
		state = false;

	__device_set_present(dev, state);
}

void device_set_present(struct device *dev, bool state)
{
	if (dev->sys_present == state)
		return;

	D(DEVICE, "%s '%s' %s present\n", dev->type->name, dev->ifname, state ? "is now" : "is no longer" );
	dev->sys_present = state;
	device_refresh_present(dev);
}

static int device_refcount(struct device *dev)
{
	struct list_head *list;
	int count = 0;

	list_for_each(list, &dev->users.list)
		count++;

	list_for_each(list, &dev->aliases.list)
		count++;

	return count;
}

void device_add_user(struct device_user *dep, struct device *dev)
{
	struct safe_list *head;

	if (dep->dev == dev)
		return;

	if (dep->dev)
		device_remove_user(dep);

	if (!dev)
		return;

	dep->dev = dev;

	if (dep->alias)
		head = &dev->aliases;
	else
		head = &dev->users;

	safe_list_add(&dep->list, head);
	D(DEVICE, "Add user for device '%s', refcount=%d\n", dev->ifname, device_refcount(dev));

	if (dep->cb && dev->present) {
		dep->cb(dep, DEV_EVENT_ADD);
		if (dev->active)
			dep->cb(dep, DEV_EVENT_UP);
	}
}

void
device_free(struct device *dev)
{
	__devlock++;
	free(dev->config);
	device_cleanup(dev);
	dev->type->free(dev);
	__devlock--;
}

static void
__device_free_unused(struct device *dev)
{
	if (!safe_list_empty(&dev->users) ||
		!safe_list_empty(&dev->aliases) ||
	    dev->current_config || __devlock)
		return;

	device_free(dev);
}

void device_remove_user(struct device_user *dep)
{
	struct device *dev = dep->dev;

	if (!dep->dev)
		return;

	dep->hotplug = false;
	if (dep->claimed)
		device_release(dep);

	safe_list_del(&dep->list);
	dep->dev = NULL;
	D(DEVICE, "Remove user for device '%s', refcount=%d\n", dev->ifname, device_refcount(dev));
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

static enum dev_change_type
device_reload_config(struct device *dev, struct blob_attr *attr)
{
	struct blob_attr *tb[__DEV_ATTR_MAX];
	const struct uci_blob_param_list *cfg = dev->type->config_params;

	if (uci_blob_check_equal(dev->config, attr, cfg))
		return DEV_CONFIG_NO_CHANGE;

	if (cfg == &device_attr_list) {
		memset(tb, 0, sizeof(tb));

		if (attr)
			blobmsg_parse(dev_attrs, __DEV_ATTR_MAX, tb,
				blob_data(attr), blob_len(attr));

		device_init_settings(dev, tb);
		return DEV_CONFIG_RESTART;
	} else
		return DEV_CONFIG_RECREATE;
}

enum dev_change_type
device_set_config(struct device *dev, const struct device_type *type,
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

	list_for_each_entry_safe(dep, tmp, &odev->users.list, list.list) {
		device_release(dep);
		safe_list_del(&dep->list);
		safe_list_add(&dep->list, &dev->users);
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

		ndev = device_create_default(dev->ifname, dev->external);
		device_replace(ndev, dev);
	}
}

struct device *
device_create(const char *name, const struct device_type *type,
	      struct blob_attr *config)
{
	struct device *odev = NULL, *dev;
	enum dev_change_type change;

	config = blob_memdup(config);
	if (!config)
		return NULL;

	odev = device_get(name, false);
	if (odev) {
		odev->current_config = true;
		change = device_set_config(odev, type, config);
		if (odev->external) {
			system_if_apply_settings(odev, &odev->settings);
			change = DEV_CONFIG_APPLIED;
		}
		switch (change) {
		case DEV_CONFIG_RESTART:
		case DEV_CONFIG_APPLIED:
			D(DEVICE, "Device '%s': config applied\n", odev->ifname);
			free(odev->config);
			odev->config = config;
			if (change == DEV_CONFIG_RESTART && odev->present) {
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
	} else
		D(DEVICE, "Create new device '%s' (%s)\n", name, type->name);

	dev = type->create(name, config);
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

void
device_dump_status(struct blob_buf *b, struct device *dev)
{
	struct device_settings st;
	void *c, *s;

	if (!dev) {
		avl_for_each_element(&devices, dev, avl) {
			if (!dev->present)
				continue;
			c = blobmsg_open_table(b, dev->ifname);
			device_dump_status(b, dev);
			blobmsg_close_table(b, c);
		}

		return;
	}

	blobmsg_add_u8(b, "external", dev->external);
	blobmsg_add_u8(b, "present", dev->present);
	blobmsg_add_string(b, "type", dev->type->name);

	if (!dev->present)
		return;

	blobmsg_add_u8(b, "up", !!dev->active);
	if (dev->type->dump_info)
		dev->type->dump_info(dev, b);
	else
		system_if_dump_info(dev, b);

	if (dev->active) {
		device_merge_settings(dev, &st);
		if (st.flags & DEV_OPT_MTU)
			blobmsg_add_u32(b, "mtu", st.mtu);
		if (st.flags & DEV_OPT_MACADDR)
			blobmsg_add_string(b, "macaddr", format_macaddr(st.macaddr));
		if (st.flags & DEV_OPT_TXQUEUELEN)
			blobmsg_add_u32(b, "txqueuelen", st.txqueuelen);
	}

	s = blobmsg_open_table(b, "statistics");
	if (dev->type->dump_stats)
		dev->type->dump_stats(dev, b);
	else
		system_if_dump_stats(dev, b);
	blobmsg_close_table(b, s);
}
