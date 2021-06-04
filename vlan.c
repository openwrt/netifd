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
#include "system.h"

static struct blob_buf b;

struct vlan_device {
	struct device dev;
	struct device_user dep;

	device_state_cb set_state;
	int id;
};

static void free_vlan_if(struct device *iface)
{
	struct vlan_device *vldev;

	vldev = container_of(iface, struct vlan_device, dev);
	device_remove_user(&vldev->dep);
	device_cleanup(&vldev->dev);
	free(vldev);
}

static int
__vlan_hotplug_op(struct device *dev, struct device *member, struct blob_attr *vlan, bool add)
{
	struct vlan_device *vldev = container_of(dev, struct vlan_device, dev);
	void *a;

	dev = vldev->dep.dev;
	if (!dev || !dev->hotplug_ops)
		return UBUS_STATUS_NOT_SUPPORTED;

	blob_buf_init(&b, 0);
	a = blobmsg_open_array(&b, "vlans");
	blobmsg_printf(&b, NULL, "%d", vldev->id);
	blobmsg_close_array(&b, a);

	if (add)
		return dev->hotplug_ops->add(dev, member, blobmsg_data(b.head));
	else
		return dev->hotplug_ops->del(dev, member, blobmsg_data(b.head));
}

static int
vlan_hotplug_add(struct device *dev, struct device *member, struct blob_attr *vlan)
{
	return __vlan_hotplug_op(dev, member, vlan, true);
}

static int
vlan_hotplug_del(struct device *dev, struct device *member, struct blob_attr *vlan)
{
	return __vlan_hotplug_op(dev, member, vlan, false);
}

static int
vlan_hotplug_prepare(struct device *dev, struct device **bridge_dev)
{
	struct vlan_device *vldev = container_of(dev, struct vlan_device, dev);

	dev = vldev->dep.dev;
	if (!dev || !dev->hotplug_ops)
		return UBUS_STATUS_NOT_SUPPORTED;

	return dev->hotplug_ops->prepare(dev, bridge_dev);
}

static void vlan_hotplug_check(struct vlan_device *vldev, struct device *dev)
{
	static const struct device_hotplug_ops hotplug_ops = {
		.prepare = vlan_hotplug_prepare,
		.add = vlan_hotplug_add,
		.del = vlan_hotplug_del
	};

	if (!dev || !dev->hotplug_ops || avl_is_empty(&dev->vlans.avl)) {
		vldev->dev.hotplug_ops = NULL;
		return;
	}

	vldev->dev.hotplug_ops = &hotplug_ops;
}


static int vlan_set_device_state(struct device *dev, bool up)
{
	struct vlan_device *vldev;
	int ret = 0;

	vldev = container_of(dev, struct vlan_device, dev);
	if (!up) {
		vldev->set_state(dev, false);
		system_vlan_del(dev);
		device_release(&vldev->dep);
		return 0;
	}

	ret = device_claim(&vldev->dep);
	if (ret < 0)
		return ret;

	system_vlan_add(vldev->dep.dev, vldev->id);
	ret = vldev->set_state(dev, true);
	if (ret)
		device_release(&vldev->dep);

	return ret;
}

static void vlan_dev_cb(struct device_user *dep, enum device_event ev)
{
	char name[IFNAMSIZ + 1];
	struct vlan_device *vldev;

	vldev = container_of(dep, struct vlan_device, dep);
	switch(ev) {
	case DEV_EVENT_ADD:
		device_set_present(&vldev->dev, true);
		break;
	case DEV_EVENT_REMOVE:
		device_set_present(&vldev->dev, false);
		break;
	case DEV_EVENT_UPDATE_IFNAME:
		vlan_hotplug_check(vldev, dep->dev);
		vldev->dev.hidden = dep->dev->hidden;
		if (snprintf(name, sizeof(name), "%s.%d", dep->dev->ifname,
			     vldev->id) >= sizeof(name) - 1 ||
		    device_set_ifname(&vldev->dev, name))
			free_vlan_if(&vldev->dev);
		break;
	case DEV_EVENT_TOPO_CHANGE:
		/* Propagate topo changes */
		device_broadcast_event(&vldev->dev, DEV_EVENT_TOPO_CHANGE);
		break;
	default:
		break;
	}
}

static void
vlan_config_init(struct device *dev)
{
	struct vlan_device *vldev;

	vldev = container_of(dev, struct vlan_device, dev);
	vlan_hotplug_check(vldev, vldev->dep.dev);
}

static struct device *get_vlan_device(struct device *dev, char *id_str, bool create)
{
	static struct device_type vlan_type = {
		.name = "VLAN",
		.config_params = &device_attr_list,
		.config_init = vlan_config_init,
		.free = free_vlan_if,
	};
	struct vlan_device *vldev;
	struct device_user *dep;
	char name[IFNAMSIZ + 1];
	char *err = NULL;
	int id, *alias_id;

	id = strtoul(id_str, &err, 10);
	if (err && *err) {
		alias_id = kvlist_get(&dev->vlan_aliases, id_str);
		if (!alias_id)
			return NULL;

		id = *alias_id;
	}

	/* look for an existing interface before creating a new one */
	list_for_each_entry(dep, &dev->users.list, list.list) {
		if (dep->cb != vlan_dev_cb)
			continue;

		vldev = container_of(dep, struct vlan_device, dep);
		if (vldev->id != id)
			continue;

		return &vldev->dev;
	}

	if (!create)
		return NULL;

	if (snprintf(name, sizeof(name), "%s.%d", dev->ifname, id) >= sizeof(name) - 1)
		return NULL;

	D(DEVICE, "Create vlan device '%s'\n", name);

	vldev = calloc(1, sizeof(*vldev));
	if (!vldev)
		return NULL;

	vldev->id = id;
	vldev->dev.hidden = dev->hidden;
	strcpy(vldev->dev.ifname, name);

	if (device_init(&vldev->dev, &vlan_type, NULL) < 0)
		goto error;

	vldev->dev.default_config = true;
	vldev->dev.config_pending = true;

	vldev->set_state = vldev->dev.set_state;
	vldev->dev.set_state = vlan_set_device_state;

	vldev->dep.cb = vlan_dev_cb;
	vlan_hotplug_check(vldev, vldev->dep.dev);
	device_add_user(&vldev->dep, dev);

	return &vldev->dev;

error:
	device_cleanup(&vldev->dev);
	free(vldev);
	return NULL;
}

static char *split_vlan(char *s)
{
	s = strchr(s, '.');
	if (!s)
		goto out;

	*s = 0;
	s++;

out:
	return s;
}

struct device *get_vlan_device_chain(const char *ifname, bool create)
{
	struct device *dev = NULL;
	char *buf, *s, *next;

	buf = strdup(ifname);
	if (!buf)
		return NULL;

	s = split_vlan(buf);
	dev = device_get(buf, create);
	if (!dev)
		goto error;

	do {
		next = split_vlan(s);
		dev = get_vlan_device(dev, s, create);
		if (!dev)
			goto error;

		s = next;
		if (!s)
			goto out;
	} while (1);

error:
	dev = NULL;
out:
	free(buf);
	return dev;
}
