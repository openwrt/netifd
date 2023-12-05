/*
 * netifd - network interface daemon
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
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
#include "system.h"

struct bonding_device {
	struct device dev;
	device_state_cb set_state;

	struct blob_attr *port_list;
	struct vlist_tree ports;
	int n_present;
	int n_failed;

	struct bonding_port *primary_port;
	struct uloop_timeout retry;

	struct bonding_config config;
	struct blob_attr *config_data;
	bool has_macaddr;
	bool force_active;
	bool active;
};

struct bonding_port {
	struct vlist_node node;
	struct bonding_device *bdev;
	struct device_user dev;
	bool set_primary;
	bool present;
	bool active;
	char name[];
};

enum {
	BOND_ATTR_PORTS,

	BOND_ATTR_POLICY,
	BOND_ATTR_XMIT_HASH_POLICY,
	BOND_ATTR_ALL_PORTS_ACTIVE,

	BOND_ATTR_MIN_LINKS,
	BOND_ATTR_AD_ACTOR_SYSTEM,
	BOND_ATTR_AD_ACTOR_SYS_PRIO,
	BOND_ATTR_AD_SELECT,
	BOND_ATTR_LACP_RATE,

	BOND_ATTR_PACKETS_PER_PORT,
	BOND_ATTR_LP_INTERVAL,
	BOND_ATTR_DYNAMIC_LB,
	BOND_ATTR_RESEND_IGMP,

	BOND_ATTR_NUM_PEER_NOTIF,
	BOND_ATTR_PRIMARY,
	BOND_ATTR_PRIMARY_RESELECT,
	BOND_ATTR_FAILOVER_MAC,

	BOND_ATTR_MON_MODE,
	BOND_ATTR_MON_INTERVAL,
	BOND_ATTR_ARP_TARGET,
	BOND_ATTR_ARP_ALL_TARGETS,
	BOND_ATTR_ARP_VALIDATE,
	BOND_ATTR_USE_CARRIER,
	BOND_ATTR_UPDELAY,
	BOND_ATTR_DOWNDELAY,

	__BOND_ATTR_MAX,
};

static const struct blobmsg_policy bonding_attrs[__BOND_ATTR_MAX] = {
	[BOND_ATTR_PORTS] = { "ports", BLOBMSG_TYPE_ARRAY },
	[BOND_ATTR_POLICY] = { "policy", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_XMIT_HASH_POLICY] = { "xmit_hash_policy", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_ALL_PORTS_ACTIVE] = { "all_ports_active", BLOBMSG_TYPE_BOOL },
	[BOND_ATTR_MIN_LINKS] = { "min_links", BLOBMSG_TYPE_INT32 },
	[BOND_ATTR_AD_ACTOR_SYSTEM] = { "ad_actor_system", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_AD_ACTOR_SYS_PRIO] = { "ad_actor_sys_prio", BLOBMSG_TYPE_INT32 },
	[BOND_ATTR_AD_SELECT] = { "ad_select", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_LACP_RATE] = { "lacp_rate", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_PACKETS_PER_PORT] = { "packets_per_port", BLOBMSG_TYPE_INT32 },
	[BOND_ATTR_LP_INTERVAL] = { "lp_interval", BLOBMSG_TYPE_INT32 },
	[BOND_ATTR_DYNAMIC_LB] = { "dynamic_lb", BLOBMSG_TYPE_BOOL },
	[BOND_ATTR_RESEND_IGMP] = { "resend_igmp", BLOBMSG_TYPE_INT32 },
	[BOND_ATTR_NUM_PEER_NOTIF] = { "num_peer_notif", BLOBMSG_TYPE_INT32 },
	[BOND_ATTR_PRIMARY] = { "primary", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_PRIMARY_RESELECT] = { "primary_reselect", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_FAILOVER_MAC] = { "failover_mac", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_MON_MODE] = { "monitor_mode", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_MON_INTERVAL] = { "monitor_interval", BLOBMSG_TYPE_INT32 },
	[BOND_ATTR_ARP_TARGET] = { "arp_target", BLOBMSG_TYPE_ARRAY },
	[BOND_ATTR_ARP_ALL_TARGETS] = { "arp_all_targets", BLOBMSG_TYPE_BOOL },
	[BOND_ATTR_ARP_VALIDATE] = { "arp_validate", BLOBMSG_TYPE_STRING },
	[BOND_ATTR_USE_CARRIER] = { "use_carrier", BLOBMSG_TYPE_BOOL },
	[BOND_ATTR_UPDELAY] = { "updelay", BLOBMSG_TYPE_INT32 },
	[BOND_ATTR_DOWNDELAY] = { "downdelay", BLOBMSG_TYPE_INT32 },
};

static const struct uci_blob_param_info bonding_attr_info[__BOND_ATTR_MAX] = {
	[BOND_ATTR_PORTS] = { .type = BLOBMSG_TYPE_STRING },
	[BOND_ATTR_ARP_TARGET] = { .type = BLOBMSG_TYPE_STRING },
};

static const struct uci_blob_param_list bonding_attr_list = {
	.n_params = __BOND_ATTR_MAX,
	.params = bonding_attrs,
	.info = bonding_attr_info,

	.n_next = 1,
	.next = { &device_attr_list },
};

static void
bonding_reset_primary(struct bonding_device *bdev)
{
	struct bonding_port *bp;

	bdev->primary_port = NULL;
	if (!bdev->has_macaddr)
		bdev->dev.settings.flags &= ~DEV_OPT_MACADDR;

	vlist_for_each_element(&bdev->ports, bp, node) {
		uint8_t *macaddr;

		if (!bp->present)
			continue;

		if (bdev->primary_port && !bp->set_primary)
			continue;

		bdev->primary_port = bp;
		if (bdev->has_macaddr)
			continue;

		if (bp->dev.dev->settings.flags & DEV_OPT_MACADDR)
			macaddr = bp->dev.dev->settings.macaddr;
		else
			macaddr = bp->dev.dev->orig_settings.macaddr;
		memcpy(bdev->dev.settings.macaddr, macaddr, 6);
		bdev->dev.settings.flags |= DEV_OPT_MACADDR;
	}
}

static int
bonding_disable_port(struct bonding_port *bp, bool keep_dev)
{
	struct bonding_device *bdev = bp->bdev;

	if (!bp->present || !bp->active)
		return 0;

	bp->active = false;

	system_bonding_set_port(&bdev->dev, bp->dev.dev, false, bp->set_primary);
	if (!keep_dev)
		device_release(&bp->dev);

	return 0;
}

static void
bonding_remove_port(struct bonding_port *bp)
{
	struct bonding_device *bdev = bp->bdev;

	if (!bp->present)
		return;

	if (bdev->dev.active)
		bonding_disable_port(bp, false);

	bp->present = false;
	bp->bdev->n_present--;

	if (bp == bdev->primary_port)
		bonding_reset_primary(bdev);

	bdev->force_active = false;
	if (bdev->n_present == 0)
		device_set_present(&bdev->dev, false);
}

static int
bonding_set_active(struct bonding_device *bdev, bool active)
{
	int ret;

	if (bdev->active == active)
		return 0;

	ret = system_bonding_set_device(&bdev->dev, active ? &bdev->config : NULL);
	if (ret < 0)
		return ret;

	bdev->active = active;
	return 0;
}

static int
bonding_enable_port(struct bonding_port *bp)
{
	struct bonding_device *bdev = bp->bdev;
	struct device *dev;
	int ret;

	if (!bp->present)
		return 0;

	/* Disable IPv6 for bonding ports */
	if (!(bp->dev.dev->settings.flags & DEV_OPT_IPV6)) {
		bp->dev.dev->settings.ipv6 = 0;
		bp->dev.dev->settings.flags |= DEV_OPT_IPV6;
	}

	ret = device_claim(&bp->dev);
	if (ret < 0)
		return ret;

	ret = bonding_set_active(bdev, true);
	if (ret)
		goto release;

	dev = bp->dev.dev;
	if (dev->settings.auth && !dev->auth_status)
		return -1;

	if (bp->active)
		return 0;

	ret = system_bonding_set_port(&bdev->dev, bp->dev.dev, true, bp->set_primary);
	if (ret < 0) {
		D(DEVICE, "Bonding port %s could not be added", bp->dev.dev->ifname);
		goto error;
	}

	bp->active = true;
	device_set_present(&bdev->dev, true);

	return 0;

error:
	bdev->n_failed++;
	bp->present = false;
	bdev->n_present--;
release:
	device_release(&bp->dev);

	return ret;
}

static void
bonding_port_cb(struct device_user *dep, enum device_event ev)
{
	struct bonding_port *bp = container_of(dep, struct bonding_port, dev);
	struct bonding_device *bdev = bp->bdev;
	struct device *dev = dep->dev;

	switch (ev) {
	case DEV_EVENT_ADD:
		if (bp->present)
			break;

		bp->present = true;
		bdev->n_present++;

		if (bdev->n_present == 1)
			device_set_present(&bdev->dev, true);
		fallthrough;
	case DEV_EVENT_AUTH_UP:
		if (!bdev->dev.active)
			break;

		if (bonding_enable_port(bp))
			break;

		/*
		 * Adding a bonding port can overwrite the bonding device mtu
		 * in the kernel, apply the bonding settings in case the
		 * bonding device mtu is set
		 */
		system_if_apply_settings(&bdev->dev, &bdev->dev.settings,
					 DEV_OPT_MTU | DEV_OPT_MTU6);
		break;
	case DEV_EVENT_LINK_DOWN:
		if (!dev->settings.auth)
			break;

		bonding_disable_port(bp, true);
		break;
	case DEV_EVENT_REMOVE:
		if (dep->hotplug && !dev->sys_present) {
			vlist_delete(&bdev->ports, &bp->node);
			return;
		}

		if (bp->present)
			bonding_remove_port(bp);

		break;
	default:
		return;
	}
}

static struct bonding_port *
bonding_create_port(struct bonding_device *bdev, const char *name,
		    struct device *dev, bool hotplug)
{
	struct bonding_port *bp;

	bp = calloc(1, sizeof(*bp) + strlen(name) + 1);
	if (!bp)
		return NULL;

	bp->bdev = bdev;
	bp->dev.cb = bonding_port_cb;
	bp->dev.hotplug = hotplug;
	strcpy(bp->name, name);
	bp->dev.dev = dev;
	vlist_add(&bdev->ports, &bp->node, bp->name);
	/*
	 * Need to look up the bonding port again as the above
	 * created pointer will be freed in case the bonding port
	 * already existed
	 */
	if (!hotplug)
		return bp;

	bp = vlist_find(&bdev->ports, name, bp, node);
	if (bp)
		bp->node.version = -1;

	return bp;
}

static void
bonding_config_init(struct device *dev)
{
	struct bonding_device *bdev;
	struct blob_attr *cur;
	size_t rem;

	bdev = container_of(dev, struct bonding_device, dev);

	bdev->n_failed = 0;

	vlist_update(&bdev->ports);
	blobmsg_for_each_attr(cur, bdev->port_list, rem) {
		const char *name = blobmsg_get_string(cur);

		dev = device_get(name, true);
		if (!dev)
			continue;

		bonding_create_port(bdev, name, dev, false);
	}
	vlist_flush(&bdev->ports);

	if (bdev->n_failed)
		uloop_timeout_set(&bdev->retry, 100);
}

static void
bonding_apply_settings(struct bonding_device *bdev, struct blob_attr **tb)
{
	struct bonding_config *cfg = &bdev->config;
	struct blob_attr *cur;

	/* defaults */
	memset(cfg, 0, sizeof(*cfg));
	cfg->resend_igmp = 1;
	cfg->ad_actor_sys_prio = 65535;
	cfg->lp_interval = 1;
	cfg->num_peer_notif = 1;

#define cfg_item(_type, _field, _attr)				\
	do {							\
		if ((cur = tb[BOND_ATTR_##_attr]) != NULL)	\
			cfg->_field = blobmsg_get_##_type(cur);	\
	} while (0)

	if ((cur = tb[BOND_ATTR_POLICY]) != NULL) {
		const char *policy = blobmsg_get_string(cur);
		size_t i;

		for (i = 0; i < ARRAY_SIZE(bonding_policy_str); i++) {
			if (strcmp(policy, bonding_policy_str[i]) != 0)
				continue;

			cfg->policy = i;
			break;
		}
	}

	cfg_item(string, xmit_hash_policy, XMIT_HASH_POLICY);
	cfg_item(bool, all_ports_active, ALL_PORTS_ACTIVE);
	cfg_item(u32, min_links, MIN_LINKS);
	cfg_item(string, ad_actor_system, AD_ACTOR_SYSTEM);
	cfg_item(u32, ad_actor_sys_prio, AD_ACTOR_SYS_PRIO);
	cfg_item(string, ad_select, AD_SELECT);
	cfg_item(string, lacp_rate, LACP_RATE);
	cfg_item(u32, packets_per_port, PACKETS_PER_PORT);
	cfg_item(u32, lp_interval, LP_INTERVAL);
	cfg_item(bool, dynamic_lb, DYNAMIC_LB);
	cfg_item(u32, resend_igmp, RESEND_IGMP);
	cfg_item(u32, num_peer_notif, NUM_PEER_NOTIF);
	cfg_item(string, primary, PRIMARY);
	cfg_item(string, primary_reselect, PRIMARY_RESELECT);
	cfg_item(string, failover_mac, FAILOVER_MAC);
	cfg_item(u32, monitor_interval, MON_INTERVAL);
	cfg_item(bool, arp_all_targets, ARP_ALL_TARGETS);
	cfg_item(string, arp_validate, ARP_VALIDATE);
	cfg_item(bool, use_carrier, USE_CARRIER);
	cfg_item(u32, updelay, UPDELAY);
	cfg_item(u32, downdelay, DOWNDELAY);

	if ((cur = tb[BOND_ATTR_MON_MODE]) != NULL &&
	    !strcmp(blobmsg_get_string(cur), "arp"))
		cfg->monitor_arp = true;
	cfg->arp_target = tb[BOND_ATTR_ARP_TARGET];
#undef cfg_item
}

static enum dev_change_type
bonding_reload(struct device *dev, struct blob_attr *attr)
{
	struct blob_attr *tb_dev[__DEV_ATTR_MAX];
	struct blob_attr *tb_b[__BOND_ATTR_MAX];
	enum dev_change_type ret = DEV_CONFIG_APPLIED;
	unsigned long diff[2] = {};
	struct bonding_device *bdev;

	BUILD_BUG_ON(sizeof(diff[0]) < __BOND_ATTR_MAX / 8);
	BUILD_BUG_ON(sizeof(diff) < __DEV_ATTR_MAX / 8);

	bdev = container_of(dev, struct bonding_device, dev);
	attr = blob_memdup(attr);

	blobmsg_parse(device_attr_list.params, __DEV_ATTR_MAX, tb_dev,
		blob_data(attr), blob_len(attr));
	blobmsg_parse(bonding_attrs, __BOND_ATTR_MAX, tb_b,
		blob_data(attr), blob_len(attr));

	bdev->has_macaddr = tb_dev[DEV_ATTR_MACADDR];
	if (bdev->primary_port && !bdev->primary_port->set_primary &&
	    tb_dev[DEV_ATTR_MACADDR])
		bdev->primary_port = NULL;

	bdev->port_list = tb_b[BOND_ATTR_PORTS];
	device_init_settings(dev, tb_dev);
	bonding_apply_settings(bdev, tb_b);

	if (bdev->config_data) {
		struct blob_attr *otb_dev[__DEV_ATTR_MAX];
		struct blob_attr *otb_b[__BOND_ATTR_MAX];

		blobmsg_parse(device_attr_list.params, __DEV_ATTR_MAX, otb_dev,
			blob_data(bdev->config_data), blob_len(bdev->config_data));

		uci_blob_diff(tb_dev, otb_dev, &device_attr_list, diff);
		if (diff[0] | diff[1])
		    ret = DEV_CONFIG_RESTART;

		blobmsg_parse(bonding_attrs, __BOND_ATTR_MAX, otb_b,
			blob_data(bdev->config_data), blob_len(bdev->config_data));

		diff[0] = 0;
		uci_blob_diff(tb_b, otb_b, &bonding_attr_list, diff);
		if (diff[0] & ~(1 << BOND_ATTR_PORTS))
		    ret = DEV_CONFIG_RESTART;

		bonding_config_init(dev);
	}

	free(bdev->config_data);
	bdev->config_data = attr;

	return ret;
}

static int
bonding_hotplug_add(struct device *dev, struct device *port, struct blob_attr *vlan)
{
	struct bonding_device *bdev = container_of(dev, struct bonding_device, dev);
	struct bonding_port *bp;

	bp = vlist_find(&bdev->ports, port->ifname, bp, node);
	if (!bp)
		bonding_create_port(bdev, port->ifname, port, true);

	return 0;
}

static int
bonding_hotplug_del(struct device *dev, struct device *port, struct blob_attr *vlan)
{
	struct bonding_device *bdev = container_of(dev, struct bonding_device, dev);
	struct bonding_port *bp;

	bp = vlist_find(&bdev->ports, port->ifname, bp, node);
	if (!bp)
		return UBUS_STATUS_NOT_FOUND;

	if (bp->dev.hotplug)
		vlist_delete(&bdev->ports, &bp->node);

	return 0;
}

static int
bonding_hotplug_prepare(struct device *dev, struct device **bonding_dev)
{
	struct bonding_device *bdev;

	if (bonding_dev)
		*bonding_dev = dev;

	bdev = container_of(dev, struct bonding_device, dev);
	bdev->force_active = true;
	device_set_present(&bdev->dev, true);

	return 0;
}

static void
bonding_retry_ports(struct uloop_timeout *timeout)
{
	struct bonding_device *bdev = container_of(timeout, struct bonding_device, retry);
	struct bonding_port *bp;

	bdev->n_failed = 0;
	vlist_for_each_element(&bdev->ports, bp, node) {
		if (bp->present)
			continue;

		if (!bp->dev.dev->present)
			continue;

		bp->present = true;
		bdev->n_present++;
		bonding_enable_port(bp);
	}
}


static void
bonding_free_port(struct bonding_port *bp)
{
	struct device *dev = bp->dev.dev;

	bonding_remove_port(bp);

	device_remove_user(&bp->dev);

	/*
	 * When reloading the config and moving a device from one master to
	 * another, the other master may have tried to claim this device
	 * before it was removed here.
	 * Ensure that claiming the device is retried by toggling its present
	 * state
	 */
	if (dev->present) {
		device_set_present(dev, false);
		device_set_present(dev, true);
	}

	free(bp);
}

static void
bonding_port_update(struct vlist_tree *tree, struct vlist_node *node_new,
		     struct vlist_node *node_old)
{
	struct bonding_port *bp;
	struct device *dev;

	if (node_new) {
		bp = container_of(node_new, struct bonding_port, node);

		if (node_old) {
			free(bp);
			return;
		}

		dev = bp->dev.dev;
		bp->dev.dev = NULL;
		device_add_user(&bp->dev, dev);
	}


	if (node_old) {
		bp = container_of(node_old, struct bonding_port, node);
		bonding_free_port(bp);
	}
}

static int
bonding_set_down(struct bonding_device *bdev)
{
	struct bonding_port *bp;

	bdev->set_state(&bdev->dev, false);

	vlist_for_each_element(&bdev->ports, bp, node)
		bonding_disable_port(bp, false);

	bonding_set_active(bdev, false);

	return 0;
}

static int
bonding_set_up(struct bonding_device *bdev)
{
	struct bonding_port *bp;
	int ret;

	if (!bdev->n_present) {
		if (!bdev->force_active)
			return -ENOENT;

		ret = bonding_set_active(bdev, true);
		if (ret)
			return ret;
	}

	bdev->n_failed = 0;
	vlist_for_each_element(&bdev->ports, bp, node)
		bonding_enable_port(bp);
	if (bdev->n_failed)
		uloop_timeout_set(&bdev->retry, 100);

	if (!bdev->force_active && !bdev->n_present) {
		/* initialization of all port interfaces failed */
		bonding_set_active(bdev, false);
		device_set_present(&bdev->dev, false);
		return -ENOENT;
	}

	bonding_reset_primary(bdev);
	ret = bdev->set_state(&bdev->dev, true);
	if (ret < 0)
		bonding_set_down(bdev);

	return ret;
}

static int
bonding_set_state(struct device *dev, bool up)
{
	struct bonding_device *bdev;

	bdev = container_of(dev, struct bonding_device, dev);

	if (up)
		return bonding_set_up(bdev);
	else
		return bonding_set_down(bdev);
}

static struct device *
bonding_create(const char *name, struct device_type *devtype,
	struct blob_attr *attr)
{
	static const struct device_hotplug_ops bonding_ops = {
		.prepare = bonding_hotplug_prepare,
		.add = bonding_hotplug_add,
		.del = bonding_hotplug_del
	};
	struct bonding_device *bdev;
	struct device *dev = NULL;

	bdev = calloc(1, sizeof(*bdev));
	if (!bdev)
		return NULL;

	dev = &bdev->dev;

	if (device_init(dev, devtype, name) < 0) {
		device_cleanup(dev);
		free(bdev);
		return NULL;
	}

	dev->config_pending = true;
	bdev->retry.cb = bonding_retry_ports;

	bdev->set_state = dev->set_state;
	dev->set_state = bonding_set_state;

	dev->hotplug_ops = &bonding_ops;

	vlist_init(&bdev->ports, avl_strcmp, bonding_port_update);
	bdev->ports.keep_old = true;

	bonding_reload(dev, attr);

	return dev;
}

static void
bonding_free(struct device *dev)
{
	struct bonding_device *bdev;

	bdev = container_of(dev, struct bonding_device, dev);
	vlist_flush_all(&bdev->ports);
	free(bdev->config_data);
	free(bdev);
}

static struct device_type bonding_device_type = {
	.name = "bonding",
	.config_params = &bonding_attr_list,

	.bridge_capability = true,

	.create = bonding_create,
	.config_init = bonding_config_init,
	.reload = bonding_reload,
	.free = bonding_free,
};

static void __init bonding_device_type_init(void)
{
	device_type_add(&bonding_device_type);
}
