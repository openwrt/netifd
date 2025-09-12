/*
 * netifd - network interface daemon
 * Copyright (C) 2014 Gioacchino Mazzurco <gio@eigenlab.org>
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
#include <inttypes.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "system.h"
#include "utils.h"

enum {
	VLANDEV_ATTR_IFNAME,
	VLANDEV_ATTR_VID,
	VLANDEV_ATTR_INGRESS_QOS_MAPPING,
	VLANDEV_ATTR_EGRESS_QOS_MAPPING,
	__VLANDEV_ATTR_MAX
};

static const struct blobmsg_policy vlandev_attrs[__VLANDEV_ATTR_MAX] = {
	[VLANDEV_ATTR_IFNAME] = { "ifname", BLOBMSG_TYPE_STRING },
	[VLANDEV_ATTR_VID] = { "vid", BLOBMSG_TYPE_STRING },
	[VLANDEV_ATTR_INGRESS_QOS_MAPPING] = { "ingress_qos_mapping", BLOBMSG_TYPE_ARRAY },
	[VLANDEV_ATTR_EGRESS_QOS_MAPPING] = { "egress_qos_mapping", BLOBMSG_TYPE_ARRAY },
};

static const struct uci_blob_param_list vlandev_attr_list = {
	.n_params = __VLANDEV_ATTR_MAX,
	.params = vlandev_attrs,

	.n_next = 1,
	.next = { &device_attr_list },
};

static struct device_type vlan8021q_device_type;
static struct blob_buf b;

struct vlandev_device {
	struct device dev;
	struct device_user parent;

	device_state_cb set_state;

	struct blob_attr *config_data;
	struct blob_attr *ifname;
	struct blob_attr *vid;

	struct vlandev_config config;
};

static int
__vlandev_hotplug_op(struct device *dev, struct device *member, struct blob_attr *vlan, bool add)
{
	struct vlandev_device *mvdev = container_of(dev, struct vlandev_device, dev);
	void *a;

	dev = mvdev->parent.dev;
	if (!dev || !dev->hotplug_ops)
		return UBUS_STATUS_NOT_SUPPORTED;

	blob_buf_init(&b, 0);
	a = blobmsg_open_array(&b, "vlans");
	blobmsg_printf(&b, NULL, "%d:u", mvdev->config.vid);
	if (vlan && blobmsg_len(vlan))
		blob_put_raw(&b, blobmsg_data(vlan), blobmsg_len(vlan));
	blobmsg_close_array(&b, a);

	if (add)
		return dev->hotplug_ops->add(dev, member, blobmsg_data(b.head));
	else
		return dev->hotplug_ops->del(dev, member, blobmsg_data(b.head));
}

static int
vlandev_hotplug_add(struct device *dev, struct device *member, struct blob_attr *vlan)
{
	return __vlandev_hotplug_op(dev, member, vlan, true);
}

static int
vlandev_hotplug_del(struct device *dev, struct device *member, struct blob_attr *vlan)
{
	return __vlandev_hotplug_op(dev, member, vlan, false);
}

static int
vlandev_hotplug_prepare(struct device *dev, struct device **bridge_dev)
{
	struct vlandev_device *mvdev = container_of(dev, struct vlandev_device, dev);

	dev = mvdev->parent.dev;
	if (!dev || !dev->hotplug_ops)
		return UBUS_STATUS_NOT_SUPPORTED;

	return dev->hotplug_ops->prepare(dev, bridge_dev);
}

static void vlandev_hotplug_check(struct vlandev_device *mvdev)
{
	static const struct device_hotplug_ops hotplug_ops = {
		.prepare = vlandev_hotplug_prepare,
		.add = vlandev_hotplug_add,
		.del = vlandev_hotplug_del
	};
	struct device *dev = mvdev->parent.dev;

	if (!dev || !dev->hotplug_ops || avl_is_empty(&dev->vlans.avl) ||
		mvdev->dev.type != &vlan8021q_device_type) {
		mvdev->dev.hotplug_ops = NULL;
		return;
	}

	mvdev->dev.hotplug_ops = &hotplug_ops;
}


static void
vlandev_base_cb(struct device_user *dev, enum device_event ev)
{
	struct vlandev_device *mvdev = container_of(dev, struct vlandev_device, parent);

	switch (ev) {
	case DEV_EVENT_ADD:
		device_set_present(&mvdev->dev, true);
		break;
	case DEV_EVENT_REMOVE:
		device_set_present(&mvdev->dev, false);
		break;
	case DEV_EVENT_UPDATE_IFNAME:
		vlandev_hotplug_check(mvdev);
		break;
	case DEV_EVENT_TOPO_CHANGE:
		/* Propagate topo changes */
		device_broadcast_event(&mvdev->dev, DEV_EVENT_TOPO_CHANGE);
		break;
	default:
		return;
	}
}

static int
vlandev_set_down(struct vlandev_device *mvdev)
{
	mvdev->set_state(&mvdev->dev, false);
	system_vlandev_del(&mvdev->dev);
	device_release(&mvdev->parent);

	return 0;
}

static int
vlandev_set_up(struct vlandev_device *mvdev)
{
	int ret;

	ret = device_claim(&mvdev->parent);
	if (ret < 0)
		return ret;

	ret = system_vlandev_add(&mvdev->dev, mvdev->parent.dev, &mvdev->config);
	if (ret < 0)
		goto release;

	ret = mvdev->set_state(&mvdev->dev, true);
	if (ret)
		goto delete;

	return 0;

delete:
	system_vlandev_del(&mvdev->dev);
release:
	device_release(&mvdev->parent);
	return ret;
}

static int
vlandev_set_state(struct device *dev, bool up)
{
	struct vlandev_device *mvdev;

	D(SYSTEM, "vlandev_set_state(%s, %u)", dev->ifname, up);

	mvdev = container_of(dev, struct vlandev_device, dev);
	if (up)
		return vlandev_set_up(mvdev);
	else
		return vlandev_set_down(mvdev);
}

static void
vlandev_free(struct device *dev)
{
	struct vlandev_device *mvdev;

	mvdev = container_of(dev, struct vlandev_device, dev);
	device_remove_user(&mvdev->parent);
	free(mvdev->config_data);
	vlist_simple_flush_all(&mvdev->config.ingress_qos_mapping_list);
	vlist_simple_flush_all(&mvdev->config.egress_qos_mapping_list);
	free(mvdev);
}

static void vlandev_qos_mapping_dump(struct blob_buf *b, const char *name, const struct vlist_simple_tree *qos_mapping_li)
{
	const struct vlan_qos_mapping *elem;
	void *a, *t;

	a = blobmsg_open_array(b, name);

	vlist_simple_for_each_element(qos_mapping_li, elem, node) {
		t = blobmsg_open_table(b, NULL);

		blobmsg_add_u32(b, "from", elem->from);
		blobmsg_add_u32(b, "to", elem->to);

		blobmsg_close_table(b, t);
	}

	blobmsg_close_array(b, a);
}

static void
vlandev_dump_info(struct device *dev, struct blob_buf *b)
{
	struct vlandev_device *mvdev;

	mvdev = container_of(dev, struct vlandev_device, dev);
	blobmsg_add_string(b, "parent", mvdev->parent.dev->ifname);
	system_if_dump_info(dev, b);
	blobmsg_add_u32(b, "vid", mvdev->config.vid);
	vlandev_qos_mapping_dump(b, "ingress_qos_mapping", &mvdev->config.ingress_qos_mapping_list);
	vlandev_qos_mapping_dump(b, "egress_qos_mapping", &mvdev->config.egress_qos_mapping_list);
}

static uint16_t
vlandev_get_vid(struct device *dev, const char *id_str)
{
	unsigned long id;
	uint16_t *alias_id;
	char *err;

	id = strtoul(id_str, &err, 10);
	if (err && *err) {
		if (!dev)
			return 1;

		alias_id = kvlist_get(&dev->vlan_aliases, id_str);
		if (!alias_id)
			return 1;

		id = *alias_id;
	}

	return (uint16_t)id;
}

static void
vlandev_config_init(struct device *dev)
{
	struct vlandev_device *mvdev;
	struct device *basedev = NULL;

	mvdev = container_of(dev, struct vlandev_device, dev);
	if (mvdev->ifname)
		basedev = device_get(blobmsg_data(mvdev->ifname), true);

	if (mvdev->vid)
		mvdev->config.vid = vlandev_get_vid(basedev, blobmsg_get_string(mvdev->vid));
	else
		mvdev->config.vid = 1;

	device_add_user(&mvdev->parent, basedev);
	vlandev_hotplug_check(mvdev);
}

static void vlandev_qos_mapping_list_apply(struct vlist_simple_tree *qos_mapping_li, struct blob_attr *list)
{
	struct blob_attr *cur;
	struct vlan_qos_mapping *qos_mapping;
	size_t rem;
	int rc;

	blobmsg_for_each_attr(cur, list, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		if (!blobmsg_check_attr(cur, false))
			continue;

		qos_mapping = calloc(1, sizeof(*qos_mapping));
		if (!qos_mapping)
			continue;

		rc = sscanf(blobmsg_data(cur), "%" PRIu32 ":%" PRIu32, &qos_mapping->from, &qos_mapping->to);
		if (rc != 2) {
			free(qos_mapping);
			continue;
		}
		vlist_simple_add(qos_mapping_li, &qos_mapping->node);
	}
}

static void
vlandev_apply_settings(struct vlandev_device *mvdev, struct blob_attr **tb)
{
	struct vlandev_config *cfg = &mvdev->config;
	struct blob_attr *cur;

	cfg->proto = (mvdev->dev.type == &vlan8021q_device_type) ?
		VLAN_PROTO_8021Q : VLAN_PROTO_8021AD;

	vlist_simple_update(&cfg->ingress_qos_mapping_list);
	vlist_simple_update(&cfg->egress_qos_mapping_list);

	if ((cur = tb[VLANDEV_ATTR_INGRESS_QOS_MAPPING]))
		vlandev_qos_mapping_list_apply(&cfg->ingress_qos_mapping_list, cur);

	if ((cur = tb[VLANDEV_ATTR_EGRESS_QOS_MAPPING]))
		vlandev_qos_mapping_list_apply(&cfg->egress_qos_mapping_list, cur);

	vlist_simple_flush(&cfg->ingress_qos_mapping_list);
	vlist_simple_flush(&cfg->egress_qos_mapping_list);
}

static enum dev_change_type
vlandev_reload(struct device *dev, struct blob_attr *attr)
{
	struct blob_attr *tb_dev[__DEV_ATTR_MAX];
	struct blob_attr *tb_mv[__VLANDEV_ATTR_MAX];
	enum dev_change_type ret = DEV_CONFIG_APPLIED;
	struct vlandev_device *mvdev;

	mvdev = container_of(dev, struct vlandev_device, dev);
	attr = blob_memdup(attr);

	blobmsg_parse_attr(device_attr_list.params, __DEV_ATTR_MAX, tb_dev, attr);
	blobmsg_parse_attr(vlandev_attrs, __VLANDEV_ATTR_MAX, tb_mv, attr);

	device_init_settings(dev, tb_dev);
	vlandev_apply_settings(mvdev, tb_mv);
	mvdev->ifname = tb_mv[VLANDEV_ATTR_IFNAME];
	mvdev->vid = tb_mv[VLANDEV_ATTR_VID];

	if (mvdev->config_data) {
		struct blob_attr *otb_dev[__DEV_ATTR_MAX];
		struct blob_attr *otb_mv[__VLANDEV_ATTR_MAX];

		blobmsg_parse_attr(device_attr_list.params, __DEV_ATTR_MAX, otb_dev,
				   mvdev->config_data);

		if (uci_blob_diff(tb_dev, otb_dev, &device_attr_list, NULL))
		    ret = DEV_CONFIG_RESTART;

		blobmsg_parse_attr(vlandev_attrs, __VLANDEV_ATTR_MAX, otb_mv,
				   mvdev->config_data);

		if (uci_blob_diff(tb_mv, otb_mv, &vlandev_attr_list, NULL))
		    ret = DEV_CONFIG_RESTART;

		vlandev_config_init(dev);
	}

	free(mvdev->config_data);
	mvdev->config_data = attr;
	return ret;
}

static struct device *
vlandev_create(const char *name, struct device_type *devtype,
	       struct blob_attr *attr)
{
	D(DEVICE, "%s\n", __func__);

	struct vlandev_device *mvdev;
	struct device *dev = NULL;

	mvdev = calloc(1, sizeof(*mvdev));
	if (!mvdev)
		return NULL;

	vlist_simple_init(&mvdev->config.ingress_qos_mapping_list,
			  struct vlan_qos_mapping, node);
	vlist_simple_init(&mvdev->config.egress_qos_mapping_list,
			  struct vlan_qos_mapping, node);

	dev = &mvdev->dev;

	if (device_init(dev, devtype, name) < 0) {
		device_cleanup(dev);
		free(mvdev);
		return NULL;
	}

	dev->config_pending = true;

	mvdev->set_state = dev->set_state;
	dev->set_state = vlandev_set_state;

	dev->hotplug_ops = NULL;
	mvdev->parent.cb = vlandev_base_cb;

	vlandev_reload(dev, attr);

	return dev;
}

static struct device_type vlan8021ad_device_type = {
	.name = "8021ad",
	.config_params = &vlandev_attr_list,
	.create = vlandev_create,
	.config_init = vlandev_config_init,
	.reload = vlandev_reload,
	.free = vlandev_free,
	.dump_info = vlandev_dump_info,
};

static struct device_type vlan8021q_device_type = {
	.name = "8021q",
	.config_params = &vlandev_attr_list,
	.create = vlandev_create,
	.config_init = vlandev_config_init,
	.reload = vlandev_reload,
	.free = vlandev_free,
	.dump_info = vlandev_dump_info,
};

static void __init vlandev_device_type_init(void)
{
	device_type_add(&vlan8021ad_device_type);
	device_type_add(&vlan8021q_device_type);
}
