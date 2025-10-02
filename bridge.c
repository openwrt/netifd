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
#include "ubus.h"

enum {
	BRIDGE_ATTR_PORTS,
	BRIDGE_ATTR_STP,
	BRIDGE_ATTR_FORWARD_DELAY,
	BRIDGE_ATTR_PRIORITY,
	BRIDGE_ATTR_IGMP_SNOOP,
	BRIDGE_ATTR_AGEING_TIME,
	BRIDGE_ATTR_HELLO_TIME,
	BRIDGE_ATTR_MAX_AGE,
	BRIDGE_ATTR_BRIDGE_EMPTY,
	BRIDGE_ATTR_MULTICAST_QUERIER,
	BRIDGE_ATTR_HASH_MAX,
	BRIDGE_ATTR_ROBUSTNESS,
	BRIDGE_ATTR_QUERY_INTERVAL,
	BRIDGE_ATTR_QUERY_RESPONSE_INTERVAL,
	BRIDGE_ATTR_LAST_MEMBER_INTERVAL,
	BRIDGE_ATTR_VLAN_FILTERING,
	BRIDGE_ATTR_HAS_VLANS,
	BRIDGE_ATTR_STP_KERNEL,
	BRIDGE_ATTR_STP_PROTO,
	__BRIDGE_ATTR_MAX
};

static const struct blobmsg_policy bridge_attrs[__BRIDGE_ATTR_MAX] = {
	[BRIDGE_ATTR_PORTS] = { "ports", BLOBMSG_TYPE_ARRAY },
	[BRIDGE_ATTR_STP] = { "stp", BLOBMSG_TYPE_BOOL },
	[BRIDGE_ATTR_FORWARD_DELAY] = { "forward_delay", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_PRIORITY] = { "priority", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_AGEING_TIME] = { "ageing_time", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_HELLO_TIME] = { "hello_time", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_MAX_AGE] = { "max_age", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_IGMP_SNOOP] = { "igmp_snooping", BLOBMSG_TYPE_BOOL },
	[BRIDGE_ATTR_BRIDGE_EMPTY] = { "bridge_empty", BLOBMSG_TYPE_BOOL },
	[BRIDGE_ATTR_MULTICAST_QUERIER] = { "multicast_querier", BLOBMSG_TYPE_BOOL },
	[BRIDGE_ATTR_HASH_MAX] = { "hash_max", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_ROBUSTNESS] = { "robustness", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_QUERY_INTERVAL] = { "query_interval", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_QUERY_RESPONSE_INTERVAL] = { "query_response_interval", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_LAST_MEMBER_INTERVAL] = { "last_member_interval", BLOBMSG_TYPE_INT32 },
	[BRIDGE_ATTR_VLAN_FILTERING] = { "vlan_filtering", BLOBMSG_TYPE_BOOL },
	[BRIDGE_ATTR_HAS_VLANS] = { "__has_vlans", BLOBMSG_TYPE_BOOL }, /* internal */
	[BRIDGE_ATTR_STP_KERNEL] = { "stp_kernel", BLOBMSG_TYPE_BOOL },
	[BRIDGE_ATTR_STP_PROTO] = { "stp_proto", BLOBMSG_TYPE_STRING },
};

static const struct uci_blob_param_info bridge_attr_info[__BRIDGE_ATTR_MAX] = {
	[BRIDGE_ATTR_PORTS] = { .type = BLOBMSG_TYPE_STRING },
};

static const struct uci_blob_param_list bridge_attr_list = {
	.n_params = __BRIDGE_ATTR_MAX,
	.params = bridge_attrs,
	.info = bridge_attr_info,

	.n_next = 1,
	.next = { &device_attr_list },
};

static struct blob_buf b;
static struct device *bridge_create(const char *name, struct device_type *devtype,
	struct blob_attr *attr);
static void bridge_config_init(struct device *dev);
static void bridge_dev_vlan_update(struct device *dev);
static void bridge_free(struct device *dev);
static void bridge_stp_init(struct device *dev);
static void bridge_dump_info(struct device *dev, struct blob_buf *b);
static enum dev_change_type
bridge_reload(struct device *dev, struct blob_attr *attr);

static struct device_type bridge_device_type = {
	.name = "bridge",
	.config_params = &bridge_attr_list,

	.bridge_capability = true,
	.name_prefix = "br",

	.create = bridge_create,
	.config_init = bridge_config_init,
	.vlan_update = bridge_dev_vlan_update,
	.reload = bridge_reload,
	.free = bridge_free,
	.dump_info = bridge_dump_info,
	.stp_init = bridge_stp_init,
};

struct bridge_state {
	struct device dev;
	device_state_cb set_state;

	struct blob_attr *config_data;
	struct bridge_config config;
	struct blob_attr *ports;
	bool active;
	bool force_active;
	bool has_vlans;

	struct uloop_timeout retry;
	struct bridge_member *primary_port;
	struct vlist_tree members;
	int n_present;
	int n_failed;
};

struct bridge_member {
	struct vlist_node node;
	struct bridge_state *bst;
	struct device_user dev;
	struct uloop_timeout check_timer;
	struct device_vlan_range *extra_vlan;
	int n_extra_vlan;
	uint16_t pvid;
	bool present;
	bool active;
	bool has_link_down;
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

static struct bridge_vlan_port *
bridge_find_vlan_member_port(struct bridge_member *bm, struct bridge_vlan *vlan)
{
	struct bridge_vlan_hotplug_port *port;
	const char *ifname = bm->dev.dev->ifname;
	int i;

	for (i = 0; i < vlan->n_ports; i++) {
		if (strcmp(vlan->ports[i].ifname, ifname) != 0)
			continue;

		return &vlan->ports[i];
	}

	list_for_each_entry(port, &vlan->hotplug_ports, list) {
		if (strcmp(port->port.ifname, ifname) != 0)
			continue;

		return &port->port;
	}

	return NULL;
}

static bool
bridge_member_vlan_is_pvid(struct bridge_member *bm, struct bridge_vlan_port *port)
{
	return (!bm->pvid && (port->flags & BRVLAN_F_UNTAGGED)) ||
	       (port->flags & BRVLAN_F_PVID);
}

static void
__bridge_set_member_vlan(struct bridge_member *bm, struct bridge_vlan *vlan,
			 struct bridge_vlan_port *port, bool add)
{
	uint16_t flags;

	flags = port->flags;
	if (bm->pvid == vlan->vid)
		flags |= BRVLAN_F_PVID;

	system_bridge_vlan(port->ifname, vlan->vid, -1, add, flags);
}

static void
bridge_set_member_vlan(struct bridge_member *bm, struct bridge_vlan *vlan, bool add)
{
	struct bridge_vlan_port *port;

	if (!bm->present)
		return;

	port = bridge_find_vlan_member_port(bm, vlan);
	if (!port)
		return;

	if (!add && bm->pvid == vlan->vid)
		bm->pvid = 0;
	else if (add && bridge_member_vlan_is_pvid(bm, port))
		bm->pvid = vlan->vid;

	__bridge_set_member_vlan(bm, vlan, port, add);
}

static void
bridge_set_local_vlan(struct bridge_state *bst, struct bridge_vlan *vlan, bool add)
{
	if (!vlan->local && add)
		return;

	system_bridge_vlan(bst->dev.ifname, vlan->vid, -1, add, BRVLAN_F_SELF);
}

static void
bridge_set_local_vlans(struct bridge_state *bst, bool add)
{
	struct bridge_vlan *vlan;

	vlist_for_each_element(&bst->dev.vlans, vlan, node)
		bridge_set_local_vlan(bst, vlan, add);
}

static struct bridge_vlan *
bridge_recalc_member_pvid(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;
	struct bridge_vlan_port *port;
	struct bridge_vlan *vlan, *ret = NULL;

	vlist_for_each_element(&bst->dev.vlans, vlan, node) {
		port = bridge_find_vlan_member_port(bm, vlan);
		if (!port)
			continue;

		if (!bridge_member_vlan_is_pvid(bm, port))
			continue;

		ret = vlan;
		if (port->flags & BRVLAN_F_PVID)
			break;
	}

	return ret;
}

static void
bridge_set_vlan_state(struct bridge_state *bst, struct bridge_vlan *vlan, bool add)
{
	struct bridge_member *bm;
	struct bridge_vlan *vlan2;
	bool clear_pvid = false;

	bridge_set_local_vlan(bst, vlan, add);

	vlist_for_each_element(&bst->members, bm, node) {
		struct bridge_vlan_port *port;

		port = bridge_find_vlan_member_port(bm, vlan);
		if (!port)
			continue;

		if (add) {
			if (bridge_member_vlan_is_pvid(bm, port))
				bm->pvid = vlan->vid;
		} else if (bm->pvid == vlan->vid) {
			vlan2 = bridge_recalc_member_pvid(bm);
			if (vlan2 && vlan2->vid != vlan->vid) {
				bridge_set_member_vlan(bm, vlan2, false);
				bm->pvid = vlan2->vid;
				bridge_set_member_vlan(bm, vlan2, true);
			} else if (!vlan2) {
				clear_pvid = true;
			}
		}

		if (bm->present)
			__bridge_set_member_vlan(bm, vlan, port, add);

		if (clear_pvid)
			bm->pvid = 0;
	}
}

static int
bridge_disable_member(struct bridge_member *bm, bool keep_dev)
{
	struct bridge_state *bst = bm->bst;
	struct bridge_vlan *vlan;

	if (!bm->present || !bm->active)
		return 0;

	bm->active = false;
	vlist_for_each_element(&bst->dev.vlans, vlan, node)
		bridge_set_member_vlan(bm, vlan, false);

	system_bridge_delif(&bst->dev, bm->dev.dev);
	if (!keep_dev)
		device_release(&bm->dev);

	if (bm->dev.dev->settings.flags & DEV_OPT_IPV6) {
		bm->dev.dev->settings.ipv6 = 1;
		bm->dev.dev->settings.flags &= ~DEV_OPT_IPV6;
	}

	device_broadcast_event(&bst->dev, DEV_EVENT_TOPO_CHANGE);

	return 0;
}

static void bridge_stp_notify(struct bridge_state *bst)
{
	struct bridge_config *cfg = &bst->config;

	if (!cfg->stp || cfg->stp_kernel)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", bst->dev.ifname);
	if (cfg->stp_proto)
		blobmsg_add_string(&b, "proto", cfg->stp_proto);
	blobmsg_add_u32(&b, "forward_delay", cfg->forward_delay);
	blobmsg_add_u32(&b, "hello_time", cfg->hello_time);
	blobmsg_add_u32(&b, "max_age", cfg->max_age);
	if (cfg->flags & BRIDGE_OPT_AGEING_TIME)
		blobmsg_add_u32(&b, "ageing_time", cfg->ageing_time);
	netifd_ubus_device_notify("stp_init", b.head, 1000);
}

static int
bridge_enable_interface(struct bridge_state *bst)
{
	struct device *dev = &bst->dev;
	int i, ret;

	if (bst->active)
		return 0;

	bridge_stp_notify(bst);
	ret = system_bridge_addbr(dev, &bst->config);
	if (ret < 0)
		return ret;

	if (bst->has_vlans) {
		/* delete default VLAN 1 */
		system_bridge_vlan(bst->dev.ifname, 1, -1, false, BRVLAN_F_SELF);

		bridge_set_local_vlans(bst, true);
	}

	for (i = 0; i < dev->n_extra_vlan; i++)
		system_bridge_vlan(dev->ifname, dev->extra_vlan[i].start,
				   dev->extra_vlan[i].end, true, BRVLAN_F_SELF);

	bst->active = true;
	return 0;
}

static void
bridge_stp_init(struct device *dev)
{
	struct bridge_state *bst;

	bst = container_of(dev, struct bridge_state, dev);
	if (!bst->config.stp || !bst->active)
		return;

	bridge_stp_notify(bst);
	system_bridge_set_stp_state(&bst->dev, false);
	system_bridge_set_stp_state(&bst->dev, true);
}

static void
bridge_disable_interface(struct bridge_state *bst)
{
	if (!bst->active)
		return;

	system_bridge_delbr(&bst->dev);
	bst->active = false;
}

static struct bridge_vlan *
bridge_hotplug_get_vlan(struct bridge_state *bst, uint16_t vid, bool create)
{
	struct bridge_vlan *vlan;

	vlan = vlist_find(&bst->dev.vlans, &vid, vlan, node);
	if (vlan || !create)
		return vlan;

	vlan = calloc(1, sizeof(*vlan));
	vlan->vid = vid;
	vlan->local = true;
	INIT_LIST_HEAD(&vlan->hotplug_ports);
	vlist_add(&bst->dev.vlans, &vlan->node, &vlan->vid);
	vlan->node.version = -1;

	return vlan;
}

static struct bridge_vlan_hotplug_port *
bridge_hotplug_get_vlan_port(struct bridge_vlan *vlan, const char *ifname)
{
	struct bridge_vlan_hotplug_port *port;

	list_for_each_entry(port, &vlan->hotplug_ports, list)
		if (!strcmp(port->port.ifname, ifname))
			return port;

	return NULL;
}

static void
bridge_hotplug_set_member_vlans(struct bridge_state *bst, struct blob_attr *vlans,
				struct bridge_member *bm, bool add, bool untracked)
{
	const char *ifname = bm->name;
	struct device_vlan_range *r;
	struct bridge_vlan *vlan;
	struct blob_attr *cur;
	int n_vlans;
	size_t rem;

	if (!vlans)
		return;

	if (add) {
		bm->n_extra_vlan = 0;
		n_vlans = blobmsg_check_array(vlans, BLOBMSG_TYPE_STRING);
		if (n_vlans < 1)
			return;

		bm->extra_vlan = realloc(bm->extra_vlan, n_vlans * sizeof(*bm->extra_vlan));
	}

	blobmsg_for_each_attr(cur, vlans, rem) {
		struct bridge_vlan_hotplug_port *port;
		unsigned int vid, vid_end;
		uint16_t flags = 0;
		char *name_buf;
		char *end;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		vid = strtoul(blobmsg_get_string(cur), &end, 0);
		vid_end = vid;
		if (!vid || vid > 4095)
			continue;

		if (*end == '-') {
			vid_end = strtoul(end + 1, &end, 0);
			if (vid_end < vid)
				continue;
		}

		if (end && *end) {
			if (*end != ':')
				continue;

			for (end++; *end; end++) {
				switch (*end) {
				case 'u':
					flags |= BRVLAN_F_UNTAGGED;
					fallthrough;
				case '*':
					flags |= BRVLAN_F_PVID;
					break;
				}
			}
		}

		vlan = bridge_hotplug_get_vlan(bst, vid, !!flags);
		if (!vlan || vid_end > vid || untracked) {
			if (add) {
				if (!untracked) {
					r = &bm->extra_vlan[bm->n_extra_vlan++];
					r->start = vid;
					r->end = vid_end;
				}
				if (bm->active)
					system_bridge_vlan(ifname, vid, vid_end, true, flags);
			} else if (bm->active) {
				system_bridge_vlan(ifname, vid, vid_end, false, 0);
			}
			continue;
		}

		if (vlan->pending) {
			vlan->pending = false;
			bridge_set_vlan_state(bst, vlan, true);
		}

		port = bridge_hotplug_get_vlan_port(vlan, ifname);
		if (!add) {
			if (!port)
				continue;

			__bridge_set_member_vlan(bm, vlan, &port->port, false);
			list_del(&port->list);
			free(port);
			continue;
		}

		if (port) {
			if (port->port.flags == flags)
				continue;

			__bridge_set_member_vlan(bm, vlan, &port->port, false);
			port->port.flags = flags;
			__bridge_set_member_vlan(bm, vlan, &port->port, true);
			continue;
		}

		port = calloc_a(sizeof(*port), &name_buf, strlen(ifname) + 1);
		if (!port)
			continue;

		port->port.flags = flags;
		port->port.ifname = strcpy(name_buf, ifname);
		list_add_tail(&port->list, &vlan->hotplug_ports);

		if (!bm)
			continue;

		__bridge_set_member_vlan(bm, vlan, &port->port, true);
	}
}


static void
bridge_member_add_extra_vlans(struct bridge_member *bm)
{
	struct device *dev = bm->dev.dev;
	int i;

	for (i = 0; i < dev->n_extra_vlan; i++)
		system_bridge_vlan(dev->ifname, dev->extra_vlan[i].start,
				   dev->extra_vlan[i].end, true, 0);
	for (i = 0; i < bm->n_extra_vlan; i++)
		system_bridge_vlan(dev->ifname, bm->extra_vlan[i].start,
				   bm->extra_vlan[i].end, true, 0);
}

static void
bridge_member_enable_vlans(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;
	struct device *dev = bm->dev.dev;
	struct bridge_vlan *vlan;

	if (dev->settings.auth) {
		bridge_hotplug_set_member_vlans(bst, dev->config_auth_vlans, bm,
						!dev->auth_status, true);
		bridge_hotplug_set_member_vlans(bst, dev->auth_vlans, bm,
						dev->auth_status, true);
	}

	if (dev->settings.auth && !dev->auth_status)
		return;

	bridge_member_add_extra_vlans(bm);
	vlist_for_each_element(&bst->dev.vlans, vlan, node)
		bridge_set_member_vlan(bm, vlan, true);
}

static int
bridge_enable_member(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;
	struct device *dev;
	int ret;

	if (!bm->present)
		return 0;

	ret = bridge_enable_interface(bst);
	if (ret)
		goto error;

	/* Disable IPv6 for bridge members */
	if (!(bm->dev.dev->settings.flags & DEV_OPT_IPV6)) {
		bm->dev.dev->settings.ipv6 = 0;
		bm->dev.dev->settings.flags |= DEV_OPT_IPV6;
	}

	ret = device_claim(&bm->dev);
	if (ret < 0)
		goto error;

	dev = bm->dev.dev;
	if (dev->settings.auth && !bst->has_vlans && !dev->auth_status)
		return -1;

	if (!bm->active) {
		ret = system_bridge_addif(&bst->dev, bm->dev.dev);
		if (ret < 0) {
			D(DEVICE, "Bridge device %s could not be added", bm->dev.dev->ifname);
			goto error;
		}

		bm->active = true;
	}

	if (bst->has_vlans) {
		/* delete default VLAN 1 */
		system_bridge_vlan(bm->dev.dev->ifname, 1, -1, false, 0);

		bridge_member_enable_vlans(bm);
	}

	device_set_present(&bst->dev, true);
	if (!dev->settings.auth || dev->auth_status)
		device_broadcast_event(&bst->dev, DEV_EVENT_TOPO_CHANGE);

	return 0;

error:
	bst->n_failed++;
	bm->present = false;
	bst->n_present--;
	device_release(&bm->dev);

	return ret;
}

static void
bridge_remove_member(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;

	if (!bm->present)
		return;

	if (bst->dev.active)
		bridge_disable_member(bm, false);

	bm->present = false;
	bm->bst->n_present--;

	if (bm == bst->primary_port)
		bridge_reset_primary(bst);

	if (bst->config.bridge_empty)
		return;

	bst->force_active = false;
	if (bst->n_present == 0)
		device_set_present(&bst->dev, false);
}

static void
bridge_free_member(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;
	struct device *dev = bm->dev.dev;
	const char *ifname = dev->ifname;
	struct bridge_vlan *vlan;

	bridge_remove_member(bm);

restart:
	vlist_for_each_element(&bst->dev.vlans, vlan, node) {
		struct bridge_vlan_hotplug_port *port, *tmp;
		bool free_port = false;

		list_for_each_entry_safe(port, tmp, &vlan->hotplug_ports, list) {
			if (strcmp(port->port.ifname, ifname) != 0)
				continue;

			list_del(&port->list);
			free(port);
			free_port = true;
		}

		if (!free_port || !list_empty(&vlan->hotplug_ports) ||
		    vlan->n_ports || vlan->node.version != -1)
			continue;

		vlist_delete(&bst->dev.vlans, &vlan->node);
		goto restart;
	}

	device_remove_user(&bm->dev);
	uloop_timeout_cancel(&bm->check_timer);

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
bridge_check_retry(struct bridge_state *bst)
{
	if (!bst->n_failed)
		return;

	uloop_timeout_set(&bst->retry, 100);
}

static void
bridge_member_check_cb(struct uloop_timeout *t)
{
	struct bridge_member *bm;
	struct bridge_state *bst;

	bm = container_of(t, struct bridge_member, check_timer);
	bst = bm->bst;

	if (system_bridge_vlan_check(&bst->dev, bm->dev.dev->ifname) <= 0)
		return;

	bridge_disable_member(bm, true);
	bridge_enable_member(bm);
}

static void
bridge_member_cb(struct device_user *dep, enum device_event ev)
{
	struct bridge_member *bm = container_of(dep, struct bridge_member, dev);
	struct bridge_state *bst = bm->bst;
	struct device *dev = dep->dev;

	switch (ev) {
	case DEV_EVENT_ADD:
		assert(!bm->present);

		bm->present = true;
		bst->n_present++;

		if (bst->n_present == 1)
			device_set_present(&bst->dev, true);
		fallthrough;
	case DEV_EVENT_AUTH_UP:
		if (!bst->dev.active)
			break;

		if (bridge_enable_member(bm))
			break;

		/*
		 * Adding a bridge member can overwrite the bridge mtu
		 * in the kernel, apply the bridge settings in case the
		 * bridge mtu is set
		 */
		system_if_apply_settings(&bst->dev, &bst->dev.settings,
					 DEV_OPT_MTU | DEV_OPT_MTU6);
		break;
	case DEV_EVENT_LINK_UP:
		if (!bst->has_vlans && !dev->settings.auth && bm->has_link_down) {
			device_broadcast_event(&bst->dev, DEV_EVENT_TOPO_CHANGE);
		}
		bm->has_link_down = false;

		if (!bst->has_vlans)
			break;

		if (dev->settings.auth)
			bridge_enable_member(bm);

		uloop_timeout_set(&bm->check_timer, 1000);
		break;
	case DEV_EVENT_LINK_DOWN:
		bm->has_link_down = true;

		if (dev->settings.auth)
			bridge_disable_member(bm, true);

		break;
	case DEV_EVENT_REMOVE:
		if (dep->hotplug && !dev->sys_present) {
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
		bridge_disable_member(bm, false);

	bridge_disable_interface(bst);

	return 0;
}

static int
bridge_set_up(struct bridge_state *bst)
{
	struct bridge_member *bm;
	int ret;

	bst->has_vlans = !avl_is_empty(&bst->dev.vlans.avl);
	if (!bst->n_present) {
		if (!bst->force_active)
			return -ENOENT;

		ret = bridge_enable_interface(bst);
		if (ret)
			return ret;
	}

	bst->n_failed = 0;
	vlist_for_each_element(&bst->members, bm, node)
		bridge_enable_member(bm);
	bridge_check_retry(bst);

	if (!bst->force_active && !bst->n_present) {
		/* initialization of all member interfaces failed */
		bridge_disable_interface(bst);
		device_set_present(&bst->dev, false);
		return -ENOENT;
	}

	bridge_reset_primary(bst);
	ret = bst->set_state(&bst->dev, true);
	if (ret < 0)
		bridge_set_down(bst);

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
bridge_alloc_member(struct bridge_state *bst, const char *name,
		    struct device *dev, bool hotplug)
{
	struct bridge_member *bm;

	bm = calloc(1, sizeof(*bm) + strlen(name) + 1);
	if (!bm)
		return NULL;

	bm->bst = bst;
	bm->dev.cb = bridge_member_cb;
	bm->dev.hotplug = hotplug;
	bm->check_timer.cb = bridge_member_check_cb;
	strcpy(bm->name, name);
	bm->dev.dev = dev;

	return bm;
}

static void bridge_insert_member(struct bridge_member *bm, const char *name)
{
	struct bridge_state *bst = bm->bst;
	bool hotplug = bm->dev.hotplug;

	vlist_add(&bst->members, &bm->node, bm->name);
	/*
	 * Need to look up the bridge member again as the above
	 * created pointer will be freed in case the bridge member
	 * already existed
	 */
	bm = vlist_find(&bst->members, name, bm, node);
	if (hotplug && bm)
		bm->node.version = -1;
}

static void
bridge_create_member(struct bridge_state *bst, const char *name,
		     struct device *dev, bool hotplug)
{
	struct bridge_member *bm;

	bm = bridge_alloc_member(bst, name, dev, hotplug);
	if (bm)
		bridge_insert_member(bm, name);
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
			struct device *dev = bm->dev.dev;

			free(bm);

			bm = container_of(node_old, struct bridge_member, node);
			if (!dev || dev == bm->dev.dev)
				return;

			bridge_remove_member(bm);
			device_add_user(&bm->dev, dev);
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

	bridge_create_member(bst, name, dev, false);
}

static int
bridge_hotplug_add(struct device *dev, struct device *member, struct blob_attr *vlan)
{
	struct bridge_state *bst = container_of(dev, struct bridge_state, dev);
	struct bridge_member *bm;
	bool new_entry = false;

	bm = vlist_find(&bst->members, member->ifname, bm, node);
	if (!bm) {
	    new_entry = true;
	    bm = bridge_alloc_member(bst, member->ifname, member, true);
	}
	bridge_hotplug_set_member_vlans(bst, vlan, bm, true, false);
	if (new_entry)
		bridge_insert_member(bm, member->ifname);

	return 0;
}

static int
bridge_hotplug_del(struct device *dev, struct device *member, struct blob_attr *vlan)
{
	struct bridge_state *bst = container_of(dev, struct bridge_state, dev);
	struct bridge_member *bm;

	bm = vlist_find(&bst->members, member->ifname, bm, node);
	if (!bm)
		return UBUS_STATUS_NOT_FOUND;

	bridge_hotplug_set_member_vlans(bst, vlan, bm, false, false);
	if (!bm->dev.hotplug)
		return 0;

	vlist_delete(&bst->members, &bm->node);
	return 0;
}

static int
bridge_hotplug_prepare(struct device *dev, struct device **bridge_dev)
{
	struct bridge_state *bst;

	if (bridge_dev)
		*bridge_dev = dev;

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
	vlist_flush_all(&dev->vlans);
	kvlist_free(&dev->vlan_aliases);
	free(bst->config_data);
	free(bst);
}

static void
bridge_dump_port(struct blob_buf *b, struct bridge_vlan_port *port)
{
	bool tagged = !(port->flags & BRVLAN_F_UNTAGGED);
	bool pvid = (port->flags & BRVLAN_F_PVID);

	blobmsg_printf(b, NULL, "%s%s%s%s", port->ifname,
		tagged || pvid ? ":" : "",
		tagged ? "t" : "",
		pvid ? "*" : "");
}

static void
bridge_dump_vlan(struct blob_buf *b, struct bridge_vlan *vlan)
{
	struct bridge_vlan_hotplug_port *port;
	void *c, *p;
	int i;

	c = blobmsg_open_table(b, NULL);

	blobmsg_add_u32(b, "id", vlan->vid);
	blobmsg_add_u8(b, "local", vlan->local);

	p = blobmsg_open_array(b, "ports");

	for (i = 0; i < vlan->n_ports; i++)
	    bridge_dump_port(b, &vlan->ports[i]);

	list_for_each_entry(port, &vlan->hotplug_ports, list)
		bridge_dump_port(b, &port->port);

	blobmsg_close_array(b, p);

	blobmsg_close_table(b, c);
}

static void
bridge_dump_info(struct device *dev, struct blob_buf *b)
{
	struct bridge_config *cfg;
	struct bridge_state *bst;
	struct bridge_member *bm;
	struct bridge_vlan *vlan;
	void *list;
	void *c;

	bst = container_of(dev, struct bridge_state, dev);
	cfg = &bst->config;

	system_if_dump_info(dev, b);
	list = blobmsg_open_array(b, "bridge-members");

	vlist_for_each_element(&bst->members, bm, node) {
		if (bm->dev.dev->hidden)
			continue;

		blobmsg_add_string(b, NULL, bm->dev.dev->ifname);
	}

	blobmsg_close_array(b, list);

	c = blobmsg_open_table(b, "bridge-attributes");

	blobmsg_add_u8(b, "stp", cfg->stp);
	blobmsg_add_u32(b, "forward_delay", cfg->forward_delay);
	blobmsg_add_u32(b, "priority", cfg->priority);
	blobmsg_add_u32(b, "ageing_time", cfg->ageing_time);
	blobmsg_add_u32(b, "hello_time", cfg->hello_time);
	blobmsg_add_u32(b, "max_age", cfg->max_age);
	blobmsg_add_u8(b, "igmp_snooping", cfg->igmp_snoop);
	blobmsg_add_u8(b, "bridge_empty", cfg->bridge_empty);
	blobmsg_add_u8(b, "multicast_querier", cfg->multicast_querier);
	blobmsg_add_u32(b, "hash_max", cfg->hash_max);
	blobmsg_add_u32(b, "robustness", cfg->robustness);
	blobmsg_add_u32(b, "query_interval", cfg->query_interval);
	blobmsg_add_u32(b, "query_response_interval", cfg->query_response_interval);
	blobmsg_add_u32(b, "last_member_interval", cfg->last_member_interval);
	blobmsg_add_u8(b, "vlan_filtering", cfg->vlan_filtering);
	blobmsg_add_u8(b, "stp_kernel", cfg->stp_kernel);
	if (cfg->stp_proto)
		blobmsg_add_string(b, "stp_proto", cfg->stp_proto);

	blobmsg_close_table(b, c);

	if (avl_is_empty(&dev->vlans.avl))
		return;

	list = blobmsg_open_array(b, "bridge-vlans");

	vlist_for_each_element(&bst->dev.vlans, vlan, node)
		bridge_dump_vlan(b, vlan);

	blobmsg_close_array(b, list);
}

static void
bridge_config_init(struct device *dev)
{
	struct bridge_state *bst;
	struct bridge_vlan *vlan;
	struct blob_attr *cur;
	size_t rem;
	int i;

	bst = container_of(dev, struct bridge_state, dev);

	if (bst->config.bridge_empty) {
		bst->force_active = true;
		device_set_present(&bst->dev, true);
	}

	bst->n_failed = 0;
	vlist_update(&bst->members);
	if (bst->ports) {
		blobmsg_for_each_attr(cur, bst->ports, rem) {
			bridge_add_member(bst, blobmsg_data(cur));
		}
	}

	vlist_for_each_element(&bst->dev.vlans, vlan, node)
		for (i = 0; i < vlan->n_ports; i++)
			bridge_add_member(bst, vlan->ports[i].ifname);

	vlist_flush(&bst->members);
	bridge_check_retry(bst);
}

static void
bridge_apply_settings(struct bridge_state *bst, struct blob_attr **tb)
{
	struct bridge_config *cfg = &bst->config;
	struct blob_attr *cur;

	/* defaults */
	memset(cfg, 0, sizeof(*cfg));
	cfg->stp = false;
	cfg->stp_kernel = false;
	cfg->robustness = 2;
	cfg->igmp_snoop = false;
	cfg->multicast_querier = false;
	cfg->query_interval = 12500;
	cfg->query_response_interval = 1000;
	cfg->last_member_interval = 100;
	cfg->hash_max = 512;
	cfg->bridge_empty = false;
	cfg->priority = 0x7FFF;
	cfg->vlan_filtering = false;

	cfg->forward_delay = 8;
	cfg->max_age = 10;
	cfg->hello_time = 1;

	if ((cur = tb[BRIDGE_ATTR_STP]))
		cfg->stp = blobmsg_get_bool(cur);

	if ((cur = tb[BRIDGE_ATTR_STP_KERNEL]))
		cfg->stp = blobmsg_get_bool(cur);

	if ((cur = tb[BRIDGE_ATTR_STP_PROTO]))
		cfg->stp_proto = blobmsg_get_string(cur);

	if ((cur = tb[BRIDGE_ATTR_FORWARD_DELAY]))
		cfg->forward_delay = blobmsg_get_u32(cur);

	if ((cur = tb[BRIDGE_ATTR_PRIORITY]))
		cfg->priority = blobmsg_get_u32(cur);

	if ((cur = tb[BRIDGE_ATTR_IGMP_SNOOP]))
		cfg->multicast_querier = cfg->igmp_snoop = blobmsg_get_bool(cur);

	if ((cur = tb[BRIDGE_ATTR_MULTICAST_QUERIER]))
		cfg->multicast_querier = blobmsg_get_bool(cur);

	if ((cur = tb[BRIDGE_ATTR_HASH_MAX]))
		cfg->hash_max = blobmsg_get_u32(cur);

	if ((cur = tb[BRIDGE_ATTR_ROBUSTNESS])) {
		cfg->robustness = blobmsg_get_u32(cur);
		cfg->flags |= BRIDGE_OPT_ROBUSTNESS;
	}

	if ((cur = tb[BRIDGE_ATTR_QUERY_INTERVAL])) {
		cfg->query_interval = blobmsg_get_u32(cur);
		cfg->flags |= BRIDGE_OPT_QUERY_INTERVAL;
	}

	if ((cur = tb[BRIDGE_ATTR_QUERY_RESPONSE_INTERVAL])) {
		cfg->query_response_interval = blobmsg_get_u32(cur);
		cfg->flags |= BRIDGE_OPT_QUERY_RESPONSE_INTERVAL;
	}

	if ((cur = tb[BRIDGE_ATTR_LAST_MEMBER_INTERVAL])) {
		cfg->last_member_interval = blobmsg_get_u32(cur);
		cfg->flags |= BRIDGE_OPT_LAST_MEMBER_INTERVAL;
	}

	if ((cur = tb[BRIDGE_ATTR_AGEING_TIME])) {
		cfg->ageing_time = blobmsg_get_u32(cur);
		cfg->flags |= BRIDGE_OPT_AGEING_TIME;
	}

	if ((cur = tb[BRIDGE_ATTR_HELLO_TIME]))
		cfg->hello_time = blobmsg_get_u32(cur);

	if ((cur = tb[BRIDGE_ATTR_MAX_AGE]))
		cfg->max_age = blobmsg_get_u32(cur);

	if ((cur = tb[BRIDGE_ATTR_BRIDGE_EMPTY]))
		cfg->bridge_empty = blobmsg_get_bool(cur);

	if ((cur = tb[BRIDGE_ATTR_VLAN_FILTERING]))
		cfg->vlan_filtering = blobmsg_get_bool(cur);
}

static enum dev_change_type
bridge_reload(struct device *dev, struct blob_attr *attr)
{
	struct blob_attr *tb_dev[__DEV_ATTR_MAX];
	struct blob_attr *tb_br[__BRIDGE_ATTR_MAX];
	enum dev_change_type ret = DEV_CONFIG_APPLIED;
	struct bridge_state *bst;
	unsigned long diff[2] = {};

	BUILD_BUG_ON(sizeof(diff) < __BRIDGE_ATTR_MAX / BITS_PER_LONG);
	BUILD_BUG_ON(sizeof(diff) < __DEV_ATTR_MAX / BITS_PER_LONG);

	bst = container_of(dev, struct bridge_state, dev);
	attr = blob_memdup(attr);

	blobmsg_parse_attr(device_attr_list.params, __DEV_ATTR_MAX, tb_dev, attr);
	blobmsg_parse_attr(bridge_attrs, __BRIDGE_ATTR_MAX, tb_br, attr);

	if (tb_dev[DEV_ATTR_MACADDR])
		bst->primary_port = NULL;

	bst->ports = tb_br[BRIDGE_ATTR_PORTS];
	device_init_settings(dev, tb_dev);
	bridge_apply_settings(bst, tb_br);

	if (bst->config_data) {
		struct blob_attr *otb_dev[__DEV_ATTR_MAX];
		struct blob_attr *otb_br[__BRIDGE_ATTR_MAX];

		blobmsg_parse_attr(device_attr_list.params, __DEV_ATTR_MAX, otb_dev,
				   bst->config_data);

		uci_blob_diff(tb_dev, otb_dev, &device_attr_list, diff);
		if (diff[0] | diff[1]) {
			ret = DEV_CONFIG_RESTART;
			D(DEVICE, "Bridge %s device attributes have changed, diff=[%lx %lx]",
			  dev->ifname, diff[1], diff[0]);
		}

		blobmsg_parse_attr(bridge_attrs, __BRIDGE_ATTR_MAX, otb_br, bst->config_data);

		diff[0] = diff[1] = 0;
		uci_blob_diff(tb_br, otb_br, &bridge_attr_list, diff);
		if (diff[0] & ~(1 << BRIDGE_ATTR_PORTS)) {
			ret = DEV_CONFIG_RESTART;
			D(DEVICE, "Bridge %s attributes have changed, diff=[%lx %lx]",
			  dev->ifname, diff[1], diff[0]);
		}

		dev->config_pending = true;
	}

	free(bst->config_data);
	bst->config_data = attr;
	return ret;
}

static void
bridge_retry_members(struct uloop_timeout *timeout)
{
	struct bridge_state *bst = container_of(timeout, struct bridge_state, retry);
	struct bridge_member *bm;

	bst->n_failed = 0;
	vlist_for_each_element(&bst->members, bm, node) {
		if (bm->present)
			continue;

		if (!bm->dev.dev->present)
			continue;

		bm->present = true;
		bst->n_present++;
		bridge_enable_member(bm);
	}
}

static int bridge_avl_cmp_u16(const void *k1, const void *k2, void *ptr)
{
	const uint16_t *i1 = k1, *i2 = k2;

	return *i1 - *i2;
}

static bool
bridge_vlan_equal(struct bridge_vlan *v1, struct bridge_vlan *v2)
{
	int i;

	if (v1->n_ports != v2->n_ports || v1->local != v2->local)
		return false;

	for (i = 0; i < v1->n_ports; i++)
		if (v1->ports[i].flags != v2->ports[i].flags ||
		    strcmp(v1->ports[i].ifname, v2->ports[i].ifname) != 0)
			return false;

	return true;
}

static void
bridge_vlan_free(struct bridge_vlan *vlan)
{
	struct bridge_vlan_hotplug_port *port, *tmp;

	if (!vlan)
		return;

	list_for_each_entry_safe(port, tmp, &vlan->hotplug_ports, list)
		free(port);

	free(vlan);
}

static void
bridge_vlan_update(struct vlist_tree *tree, struct vlist_node *node_new,
		   struct vlist_node *node_old)
{
	struct bridge_state *bst = container_of(tree, struct bridge_state, dev.vlans);
	struct bridge_vlan *vlan_new = NULL, *vlan_old = NULL;

	if (node_old)
		vlan_old = container_of(node_old, struct bridge_vlan, node);
	if (node_new)
		vlan_new = container_of(node_new, struct bridge_vlan, node);

	if (!bst->has_vlans || !bst->active)
		goto out;

	if (node_new && node_old && bridge_vlan_equal(vlan_old, vlan_new)) {
		list_splice_init(&vlan_old->hotplug_ports, &vlan_new->hotplug_ports);
		goto out;
	}

	if (node_old)
		bridge_set_vlan_state(bst, vlan_old, false);

	if (node_old && node_new)
		list_splice_init(&vlan_old->hotplug_ports, &vlan_new->hotplug_ports);

	if (node_new)
		vlan_new->pending = true;

out:
	bst->dev.config_pending = true;
	bridge_vlan_free(vlan_old);
}

static void
bridge_dev_vlan_update(struct device *dev)
{
	struct bridge_state *bst = container_of(dev, struct bridge_state, dev);
	struct bridge_vlan *vlan;

	vlist_for_each_element(&dev->vlans, vlan, node) {
		if (!vlan->pending)
			continue;

		vlan->pending = false;
		bridge_set_vlan_state(bst, vlan, true);
	}
}

static struct device *
bridge_create(const char *name, struct device_type *devtype,
	struct blob_attr *attr)
{
	struct bridge_state *bst;
	struct device *dev = NULL;

	bst = calloc(1, sizeof(*bst));
	if (!bst)
		return NULL;

	dev = &bst->dev;

	if (device_init(dev, devtype, name) < 0) {
		device_cleanup(dev);
		free(bst);
		return NULL;
	}

	dev->config_pending = true;
	bst->retry.cb = bridge_retry_members;

	bst->set_state = dev->set_state;
	dev->set_state = bridge_set_state;

	dev->hotplug_ops = &bridge_ops;

	vlist_init(&bst->members, avl_strcmp, bridge_member_update);
	bst->members.keep_old = true;

	vlist_init(&dev->vlans, bridge_avl_cmp_u16, bridge_vlan_update);

	bridge_reload(dev, attr);

	return dev;
}

static void __init bridge_device_type_init(void)
{
	device_type_add(&bridge_device_type);
}
