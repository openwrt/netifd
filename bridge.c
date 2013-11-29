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
#include <errno.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "system.h"

enum {
	BRIDGE_ATTR_IFNAME,
	BRIDGE_ATTR_STP,
	BRIDGE_ATTR_FORWARD_DELAY,
	BRIDGE_ATTR_PRIORITY,
	BRIDGE_ATTR_IGMP_SNOOP,
	BRIDGE_ATTR_AGEING_TIME,
	BRIDGE_ATTR_HELLO_TIME,
	BRIDGE_ATTR_MAX_AGE,
	BRIDGE_ATTR_BRIDGE_EMPTY,
	__BRIDGE_ATTR_MAX
};

static const struct blobmsg_policy bridge_attrs[__BRIDGE_ATTR_MAX] = {
	[BRIDGE_ATTR_IFNAME] = { "ifname", BLOBMSG_TYPE_ARRAY },
	[BRIDGE_ATTR_STP] = { "stp", BLOBMSG_TYPE_BOOL },
	[BRIDGE_ATTR_FORWARD_DELAY] = { "forward_delay", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_PRIORITY] = { "priority", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_AGEING_TIME] = { "ageing_time", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_HELLO_TIME] = { "hello_time", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_MAX_AGE] = { "max_age", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_IGMP_SNOOP] = { "igmp_snooping", BLOBMSG_TYPE_BOOL },
	[BRIDGE_ATTR_BRIDGE_EMPTY] = { "bridge_empty", BLOBMSG_TYPE_BOOL },
};

static const struct uci_blob_param_info bridge_attr_info[__BRIDGE_ATTR_MAX] = {
	[BRIDGE_ATTR_IFNAME] = { .type = BLOBMSG_TYPE_STRING },
};

static const struct uci_blob_param_list bridge_attr_list = {
	.n_params = __BRIDGE_ATTR_MAX,
	.params = bridge_attrs,
	.info = bridge_attr_info,

	.n_next = 1,
	.next = { &device_attr_list },
};

static struct device *bridge_create(const char *name, struct blob_attr *attr);
static void bridge_config_init(struct device *dev);
static void bridge_free(struct device *dev);
static void bridge_dump_info(struct device *dev, struct blob_buf *b);
enum dev_change_type
bridge_reload(struct device *dev, struct blob_attr *attr);

const struct device_type bridge_device_type = {
	.name = "Bridge",
	.config_params = &bridge_attr_list,

	.create = bridge_create,
	.config_init = bridge_config_init,
	.reload = bridge_reload,
	.free = bridge_free,
	.dump_info = bridge_dump_info,
};

struct bridge_state {
	struct device dev;
	device_state_cb set_state;

	struct blob_attr *config_data;
	struct bridge_config config;
	struct blob_attr *ifnames;
	bool active;
	bool force_active;

	struct bridge_member *primary_port;
	struct vlist_tree members;
	int n_present;
};

struct bridge_member {
	struct vlist_node node;
	struct bridge_state *bst;
	struct device_user dev;
	bool present;
	char name[];
};

static void
bridge_reset_primary(struct bridge_state *bst)
{
	struct bridge_member *bm;

	if (!bst->primary_port &&
	    (bst->dev.settings.flags & DEV_OPT_MACADDR))
		return;

	bst->primary_port = NULL;
	bst->dev.settings.flags &= ~DEV_OPT_MACADDR;
	vlist_for_each_element(&bst->members, bm, node) {
		uint8_t *macaddr;

		if (!bm->present)
			continue;

		bst->primary_port = bm;
		if (bm->dev.dev->settings.flags & DEV_OPT_MACADDR)
			macaddr = bm->dev.dev->settings.macaddr;
		else
			macaddr = bm->dev.dev->orig_settings.macaddr;
		memcpy(bst->dev.settings.macaddr, macaddr, 6);
		bst->dev.settings.flags |= DEV_OPT_MACADDR;
		return;
	}
}

static int
bridge_disable_member(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;

	if (!bm->present)
		return 0;

	system_bridge_delif(&bst->dev, bm->dev.dev);
	device_release(&bm->dev);

	return 0;
}

static int
bridge_enable_member(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;
	int ret;

	if (!bm->present)
		return 0;

	ret = device_claim(&bm->dev);
	if (ret < 0)
		goto error;

	ret = system_bridge_addif(&bst->dev, bm->dev.dev);
	if (ret < 0) {
		D(DEVICE, "Bridge device %s could not be added\n", bm->dev.dev->ifname);
		goto error;
	}

	return 0;

error:
	bm->present = false;
	bst->n_present--;
	return ret;
}

static void
bridge_remove_member(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;

	if (!bm->present)
		return;

	if (bm == bst->primary_port)
		bridge_reset_primary(bst);

	if (bst->dev.active)
		bridge_disable_member(bm);

	bm->present = false;
	bm->bst->n_present--;

	if (bst->config.bridge_empty)
		return;

	bst->force_active = false;
	if (bst->n_present == 0)
		device_set_present(&bst->dev, false);
}

static void
bridge_free_member(struct bridge_member *bm)
{
	struct device *dev = bm->dev.dev;

	bridge_remove_member(bm);
	device_remove_user(&bm->dev);

	/*
	 * When reloading the config and moving a device from one bridge to
	 * another, the other bridge may have tried to claim this device
	 * before it was removed here.
	 * Ensure that claiming the device is retried by toggling its present
	 * state
	 */
	if (dev->present) {
		device_set_present(dev, false);
		device_set_present(dev, true);
	}

	free(bm);
}

static void
bridge_member_cb(struct device_user *dev, enum device_event ev)
{
	struct bridge_member *bm = container_of(dev, struct bridge_member, dev);
	struct bridge_state *bst = bm->bst;

	switch (ev) {
	case DEV_EVENT_ADD:
		assert(!bm->present);

		bm->present = true;
		bst->n_present++;

		if (bst->dev.active)
			bridge_enable_member(bm);
		else if (bst->n_present == 1)
			device_set_present(&bst->dev, true);

		break;
	case DEV_EVENT_REMOVE:
		if (dev->hotplug) {
			vlist_delete(&bst->members, &bm->node);
			return;
		}

		if (bm->present)
			bridge_remove_member(bm);

		break;
	default:
		return;
	}
}

static int
bridge_set_down(struct bridge_state *bst)
{
	struct bridge_member *bm;

	bst->set_state(&bst->dev, false);

	vlist_for_each_element(&bst->members, bm, node)
		bridge_disable_member(bm);

	system_bridge_delbr(&bst->dev);

	return 0;
}

static int
bridge_set_up(struct bridge_state *bst)
{
	struct bridge_member *bm;
	int ret;

	if (!bst->force_active && !bst->n_present)
		return -ENOENT;

	ret = system_bridge_addbr(&bst->dev, &bst->config);
	if (ret < 0)
		goto out;

	vlist_for_each_element(&bst->members, bm, node)
		bridge_enable_member(bm);

	if (!bst->force_active && !bst->n_present) {
		/* initialization of all member interfaces failed */
		system_bridge_delbr(&bst->dev);
		device_set_present(&bst->dev, false);
		return -ENOENT;
	}

	bridge_reset_primary(bst);
	ret = bst->set_state(&bst->dev, true);
	if (ret < 0)
		bridge_set_down(bst);

out:
	return ret;
}

static int
bridge_set_state(struct device *dev, bool up)
{
	struct bridge_state *bst;

	bst = container_of(dev, struct bridge_state, dev);

	if (up)
		return bridge_set_up(bst);
	else
		return bridge_set_down(bst);
}

static struct bridge_member *
bridge_create_member(struct bridge_state *bst, struct device *dev, bool hotplug)
{
	struct bridge_member *bm;

	bm = calloc(1, sizeof(*bm) + strlen(dev->ifname) + 1);
	if (!bm)
		return NULL;

	bm->bst = bst;
	bm->dev.cb = bridge_member_cb;
	bm->dev.hotplug = hotplug;
	strcpy(bm->name, dev->ifname);
	bm->dev.dev = dev;
	vlist_add(&bst->members, &bm->node, bm->name);
	if (hotplug)
		bm->node.version = -1;

	return bm;
}

static void
bridge_member_update(struct vlist_tree *tree, struct vlist_node *node_new,
		     struct vlist_node *node_old)
{
	struct bridge_member *bm;
	struct device *dev;

	if (node_new) {
		bm = container_of(node_new, struct bridge_member, node);

		if (node_old) {
			free(bm);
			return;
		}

		dev = bm->dev.dev;
		bm->dev.dev = NULL;
		device_add_user(&bm->dev, dev);
	}


	if (node_old) {
		bm = container_of(node_old, struct bridge_member, node);
		bridge_free_member(bm);
	}
}


static void
bridge_add_member(struct bridge_state *bst, const char *name)
{
	struct device *dev;

	dev = device_get(name, true);
	if (!dev)
		return;

	bridge_create_member(bst, dev, false);
}

static int
bridge_hotplug_add(struct device *dev, struct device *member)
{
	struct bridge_state *bst = container_of(dev, struct bridge_state, dev);

	bridge_create_member(bst, member, true);

	return 0;
}

static int
bridge_hotplug_del(struct device *dev, struct device *member)
{
	struct bridge_state *bst = container_of(dev, struct bridge_state, dev);
	struct bridge_member *bm;

	bm = vlist_find(&bst->members, member->ifname, bm, node);
	if (!bm)
		return UBUS_STATUS_NOT_FOUND;

	vlist_delete(&bst->members, &bm->node);
	return 0;
}

static int
bridge_hotplug_prepare(struct device *dev)
{
	struct bridge_state *bst;

	bst = container_of(dev, struct bridge_state, dev);
	bst->force_active = true;
	device_set_present(&bst->dev, true);

	return 0;
}

static const struct device_hotplug_ops bridge_ops = {
	.prepare = bridge_hotplug_prepare,
	.add = bridge_hotplug_add,
	.del = bridge_hotplug_del
};

static void
bridge_free(struct device *dev)
{
	struct bridge_state *bst;

	bst = container_of(dev, struct bridge_state, dev);
	vlist_flush_all(&bst->members);
	free(bst);
}

static void
bridge_dump_info(struct device *dev, struct blob_buf *b)
{
	struct bridge_state *bst;
	struct bridge_member *bm;
	void *list;

	bst = container_of(dev, struct bridge_state, dev);

	system_if_dump_info(dev, b);
	list = blobmsg_open_array(b, "bridge-members");

	vlist_for_each_element(&bst->members, bm, node)
		blobmsg_add_string(b, NULL, bm->dev.dev->ifname);

	blobmsg_close_array(b, list);
}

static void
bridge_config_init(struct device *dev)
{
	struct bridge_state *bst;
	struct blob_attr *cur;
	int rem;

	bst = container_of(dev, struct bridge_state, dev);

	if (bst->config.bridge_empty) {
		bst->force_active = true;
		device_set_present(&bst->dev, true);
	}

	vlist_update(&bst->members);
	if (bst->ifnames) {
		blobmsg_for_each_attr(cur, bst->ifnames, rem) {
			bridge_add_member(bst, blobmsg_data(cur));
		}
	}
	vlist_flush(&bst->members);
}

static void
bridge_apply_settings(struct bridge_state *bst, struct blob_attr **tb)
{
	struct bridge_config *cfg = &bst->config;
	struct blob_attr *cur;

	/* defaults */
	cfg->stp = false;
	cfg->forward_delay = 2;
	cfg->igmp_snoop = false;
	cfg->bridge_empty = false;
	cfg->priority = 0x7FFF;

	if ((cur = tb[BRIDGE_ATTR_STP]))
		cfg->stp = blobmsg_get_bool(cur);

	if ((cur = tb[BRIDGE_ATTR_FORWARD_DELAY]))
		cfg->forward_delay = blobmsg_get_u32(cur);

	if ((cur = tb[BRIDGE_ATTR_PRIORITY]))
		cfg->priority = blobmsg_get_u32(cur);

	if ((cur = tb[BRIDGE_ATTR_IGMP_SNOOP]))
		cfg->igmp_snoop = blobmsg_get_bool(cur);

	if ((cur = tb[BRIDGE_ATTR_AGEING_TIME])) {
		cfg->ageing_time = blobmsg_get_u32(cur);
		cfg->flags |= BRIDGE_OPT_AGEING_TIME;
	}

	if ((cur = tb[BRIDGE_ATTR_HELLO_TIME])) {
		cfg->hello_time = blobmsg_get_u32(cur);
		cfg->flags |= BRIDGE_OPT_HELLO_TIME;
	}

	if ((cur = tb[BRIDGE_ATTR_MAX_AGE])) {
		cfg->max_age = blobmsg_get_u32(cur);
		cfg->flags |= BRIDGE_OPT_MAX_AGE;
	}

	if ((cur = tb[BRIDGE_ATTR_BRIDGE_EMPTY]))
		cfg->bridge_empty = blobmsg_get_bool(cur);
}

enum dev_change_type
bridge_reload(struct device *dev, struct blob_attr *attr)
{
	struct blob_attr *tb_dev[__DEV_ATTR_MAX];
	struct blob_attr *tb_br[__BRIDGE_ATTR_MAX];
	enum dev_change_type ret = DEV_CONFIG_APPLIED;
	unsigned long diff;
	struct bridge_state *bst;

	BUILD_BUG_ON(sizeof(diff) < __BRIDGE_ATTR_MAX / 8);
	BUILD_BUG_ON(sizeof(diff) < __DEV_ATTR_MAX / 8);

	bst = container_of(dev, struct bridge_state, dev);

	blobmsg_parse(device_attr_list.params, __DEV_ATTR_MAX, tb_dev,
		blob_data(attr), blob_len(attr));
	blobmsg_parse(bridge_attrs, __BRIDGE_ATTR_MAX, tb_br,
		blob_data(attr), blob_len(attr));

	bst->ifnames = tb_br[BRIDGE_ATTR_IFNAME];
	device_init_settings(dev, tb_dev);
	bridge_apply_settings(bst, tb_br);

	if (bst->config_data) {
		struct blob_attr *otb_dev[__DEV_ATTR_MAX];
		struct blob_attr *otb_br[__BRIDGE_ATTR_MAX];

		blobmsg_parse(device_attr_list.params, __DEV_ATTR_MAX, otb_dev,
			blob_data(bst->config_data), blob_len(bst->config_data));

		diff = 0;
		uci_blob_diff(tb_dev, otb_dev, &device_attr_list, &diff);
		if (diff & ~(1 << DEV_ATTR_IFNAME))
		    ret = DEV_CONFIG_RESTART;

		blobmsg_parse(bridge_attrs, __BRIDGE_ATTR_MAX, otb_br,
			blob_data(bst->config_data), blob_len(bst->config_data));

		diff = 0;
		uci_blob_diff(tb_br, otb_br, &bridge_attr_list, &diff);
		if (diff & ~(1 << BRIDGE_ATTR_IFNAME))
		    ret = DEV_CONFIG_RESTART;

		bridge_config_init(dev);
	}

	bst->config_data = attr;
	return ret;
}

static struct device *
bridge_create(const char *name, struct blob_attr *attr)
{
	struct bridge_state *bst;
	struct device *dev = NULL;

	bst = calloc(1, sizeof(*bst));
	if (!bst)
		return NULL;

	dev = &bst->dev;
	device_init(dev, &bridge_device_type, name);
	dev->config_pending = true;

	bst->set_state = dev->set_state;
	dev->set_state = bridge_set_state;

	dev->hotplug_ops = &bridge_ops;

	vlist_init(&bst->members, avl_strcmp, bridge_member_update);
	bst->members.keep_old = true;
	bridge_reload(dev, attr);

	return dev;
}
