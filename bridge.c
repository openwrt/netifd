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
	BRIDGE_ATTR_VLANS,
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
	[BRIDGE_ATTR_VLANS] = { "vlans", BLOBMSG_TYPE_TABLE },
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

enum {
	BRVLAN_ATTR_VID,
	BRVLAN_ATTR_LOCAL,
	BRVLAN_ATTR_PORTS,
	BRVLAN_ATTR_ALIAS,
	__BRVLAN_ATTR_MAX,
};

static const struct blobmsg_policy bridge_vlan_attrs[__BRVLAN_ATTR_MAX] = {
	[BRVLAN_ATTR_VID] = { "vlan", BLOBMSG_TYPE_INT32 },
	[BRVLAN_ATTR_LOCAL] = { "local", BLOBMSG_TYPE_BOOL },
	[BRVLAN_ATTR_PORTS] = { "ports", BLOBMSG_TYPE_ARRAY },
	[BRVLAN_ATTR_ALIAS] = { "alias", BLOBMSG_TYPE_ARRAY },
};

static const struct uci_blob_param_info bridge_vlan_attr_info[__BRVLAN_ATTR_MAX] = {
	[BRVLAN_ATTR_PORTS] = { .type = BLOBMSG_TYPE_STRING },
	[BRVLAN_ATTR_ALIAS] = { .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list bridge_vlan_attr_list = {
	.n_params = __BRVLAN_ATTR_MAX,
	.params = bridge_vlan_attrs,
	.info = bridge_vlan_attr_info,
};

static struct blob_buf b;
static struct device *bridge_create(const char *name, struct device_type *devtype,
	struct blob_attr *attr);
static void bridge_config_init(struct device *dev);
static void bridge_free(struct device *dev);
static void bridge_stp_init(struct device *dev);
static void bridge_dump_info(struct device *dev, struct blob_buf *b);
static enum dev_change_type
bridge_reload(struct device *dev, struct blob_attr *attr,
	      struct blob_attr **tb_dev);

static struct device_type bridge_device_type = {
	.name = "bridge",
	.config_params = &bridge_attr_list,

	.bridge_capability = true,
	.bridge_vlans = true,
	.name_prefix = "br",

	.create = bridge_create,
	.config_init = bridge_config_init,
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
	bool vlan_filtering;
	bool vlans_configured;

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
	struct bridge_member_range *extra_vlan;
	int n_extra_vlan;
	struct avl_tree hotplug_vlans;
	struct bridge_port_vlan *applied;
	int n_applied;
	bool present;
	bool active;
	bool set_ipv6;
	char name[];
};

struct bridge_member_vlan {
	struct avl_node node;
	uint16_t vid;
	uint16_t flags;
	bool seen;
};

struct bridge_member_range {
	uint16_t start;
	uint16_t end;
	uint16_t flags;
};

#define BRIDGE_VLAN_FLAGS_UNKNOWN	0xffff

static int bridge_avl_cmp_u16(const void *k1, const void *k2, void *ptr)
{
	const uint16_t *i1 = k1, *i2 = k2;

	return *i1 - *i2;
}

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

static bool
bridge_member_vlan_flags(struct bridge_member *bm, struct bridge_vlan *vlan,
			 uint16_t *flags)
{
	const char *ifname = bm->dev.dev->ifname;
	struct bridge_member_vlan *mv;
	int i;

	for (i = 0; i < vlan->n_ports; i++) {
		if (strcmp(vlan->ports[i].ifname, ifname) != 0)
			continue;

		*flags = vlan->ports[i].flags;
		return true;
	}

	mv = avl_find_element(&bm->hotplug_vlans, &vlan->vid, mv, node);
	if (!mv)
		return false;

	*flags = mv->flags;
	return true;
}

static bool
bridge_vlan_hotplug_used(struct bridge_state *bst, uint16_t vid)
{
	struct bridge_member_vlan *mv;
	struct bridge_member *bm;

	vlist_for_each_element(&bst->members, bm, node) {
		mv = avl_find_element(&bm->hotplug_vlans, &vid, mv, node);
		if (mv)
			return true;
	}

	return false;
}

static bool
bridge_member_authorized(struct bridge_member *bm)
{
	struct device *dev = bm->dev.dev;

	return !dev->settings.auth || dev->auth_status;
}

static bool
bridge_member_vlans_enabled(struct bridge_member *bm)
{
	if (!bm->present || !bm->active || !bm->bst->vlan_filtering)
		return false;

	return bridge_member_authorized(bm);
}

/*
 * The last vlan with an explicit pvid flag wins, otherwise the first
 * untagged one. This is the result of adding all vlans in order.
 */
static int
bridge_member_vlans_get(struct bridge_member *bm, struct bridge_port_vlan *vlans)
{
	struct bridge_vlan *vlan;
	uint16_t pvid = 0, untagged = 0;
	uint16_t flags;
	int i, n = 0;

	vlist_for_each_element(&bm->bst->dev.vlans, vlan, node) {
		if (!bridge_member_vlan_flags(bm, vlan, &flags))
			continue;

		if (flags & BRVLAN_F_PVID)
			pvid = vlan->vid;
		else if (!untagged && (flags & BRVLAN_F_UNTAGGED))
			untagged = vlan->vid;

		vlans[n].vid = vlan->vid;
		vlans[n].flags = flags & ~BRVLAN_F_PVID;
		n++;
	}

	if (!pvid)
		pvid = untagged;

	for (i = 0; i < n; i++)
		if (vlans[i].vid == pvid)
			vlans[i].flags |= BRVLAN_F_PVID;

	return n;
}

/*
 * Used after vlans in the range were written outside of the sync, so that
 * the next sync writes the wanted state of these vlans again.
 */
static void
bridge_member_vlans_invalidate(struct bridge_member *bm, uint16_t start,
			       uint16_t end)
{
	int i;

	for (i = 0; i < bm->n_applied; i++)
		if (bm->applied[i].vid >= start && bm->applied[i].vid <= end)
			bm->applied[i].flags = BRIDGE_VLAN_FLAGS_UNKNOWN;
}

static void
bridge_member_vlan_add(struct bridge_member *bm, const struct bridge_port_vlan *vlan)
{
	const struct bridge_port_vlan *old;

	old = bridge_port_vlan_find(bm->applied, bm->n_applied, vlan->vid);
	if (old && old->flags == vlan->flags)
		return;

	system_bridge_vlan(bm->dev.dev->ifname, vlan->vid, -1, true, vlan->flags);
}

static bool
bridge_member_range_flags(struct bridge_member *bm, uint16_t vid,
			  uint16_t *flags)
{
	struct device *dev = bm->dev.dev;
	int i;

	/* match bridge_member_add_extra_vlans(), where the last range wins */
	for (i = bm->n_extra_vlan - 1; i >= 0; i--) {
		if (vid < bm->extra_vlan[i].start || vid > bm->extra_vlan[i].end)
			continue;

		*flags = bm->extra_vlan[i].flags;
		return true;
	}

	for (i = 0; i < dev->n_extra_vlan; i++) {
		if (vid < dev->extra_vlan[i].start || vid > dev->extra_vlan[i].end)
			continue;

		*flags = 0;
		return true;
	}

	return false;
}

/* a range of the port can still need a vlan that is no longer tracked */
static void
bridge_member_vlan_del(struct bridge_member *bm, uint16_t vid)
{
	const char *ifname = bm->dev.dev->ifname;
	uint16_t flags;

	if (bm->active && bridge_member_range_flags(bm, vid, &flags))
		system_bridge_vlan(ifname, vid, -1, true, flags);
	else
		system_bridge_vlan(ifname, vid, -1, false, 0);
}

static void
bridge_member_vlan_sync(struct bridge_member *bm)
{
	struct bridge_port_vlan *vlans = NULL;
	int count = bm->bst->dev.vlans.avl.count;
	int i, n = 0;

	if (count && bridge_member_vlans_enabled(bm)) {
		vlans = calloc(count, sizeof(*vlans));
		if (!vlans)
			return;

		n = bridge_member_vlans_get(bm, vlans);
	}

	/* set the new pvid first, so that the port always has one */
	for (i = 0; i < n; i++)
		if (vlans[i].flags & BRVLAN_F_PVID)
			bridge_member_vlan_add(bm, &vlans[i]);

	for (i = 0; i < n; i++)
		if (!(vlans[i].flags & BRVLAN_F_PVID))
			bridge_member_vlan_add(bm, &vlans[i]);

	for (i = 0; i < bm->n_applied; i++)
		if (!bridge_port_vlan_find(vlans, n, bm->applied[i].vid))
			bridge_member_vlan_del(bm, bm->applied[i].vid);

	free(bm->applied);
	bm->applied = vlans;
	bm->n_applied = n;
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

static int
bridge_disable_member(struct bridge_member *bm, bool keep_dev)
{
	struct bridge_state *bst = bm->bst;

	if (!bm->present || !bm->active)
		return 0;

	bm->active = false;
	bridge_member_vlan_sync(bm);

	system_bridge_delif(&bst->dev, bm->dev.dev);
	if (!keep_dev)
		device_release(&bm->dev);

	if (bm->set_ipv6) {
		bm->set_ipv6 = false;
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

	/* delete default VLAN 1 */
	if (bst->has_vlans)
		system_bridge_vlan(bst->dev.ifname, 1, -1, false, BRVLAN_F_SELF);

	if (bst->vlan_filtering) {
		bridge_set_local_vlans(bst, true);

		for (i = 0; i < dev->n_extra_vlan; i++)
			system_bridge_vlan(dev->ifname, dev->extra_vlan[i].start,
					   dev->extra_vlan[i].end, true,
					   BRVLAN_F_SELF);
	}

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
	if (!vlan)
		return NULL;

	vlan->vid = vid;
	vlan->local = true;
	vlist_add(&bst->dev.vlans, &vlan->node, &vlan->vid);
	vlan->node.version = -1;

	return vlan;
}

static void
bridge_hotplug_del_member_vlan(struct bridge_member *bm,
			       struct bridge_member_vlan *mv)
{
	struct bridge_state *bst = bm->bst;
	struct bridge_vlan *vlan;
	uint16_t vid = mv->vid;

	avl_delete(&bm->hotplug_vlans, &mv->node);
	free(mv);

	vlan = vlist_find(&bst->dev.vlans, &vid, vlan, node);
	if (!vlan || vlan->n_ports || vlan->node.version != -1 ||
	    bridge_vlan_hotplug_used(bst, vid))
		return;

	vlist_delete(&bst->dev.vlans, &vlan->node);
}

static bool
bridge_hotplug_set_member_vlan(struct bridge_member *bm, uint16_t vid,
			       uint16_t flags, bool add)
{
	struct bridge_member_vlan *mv;

	mv = avl_find_element(&bm->hotplug_vlans, &vid, mv, node);
	if (!add) {
		if (!mv)
			return false;

		bridge_hotplug_del_member_vlan(bm, mv);
		return true;
	}

	if (mv) {
		mv->seen = true;
		if (mv->flags == flags)
			return false;

		mv->flags = flags;
		return true;
	}

	mv = calloc(1, sizeof(*mv));
	if (!mv)
		return false;

	mv->vid = vid;
	mv->flags = flags;
	mv->seen = true;
	mv->node.key = &mv->vid;
	avl_insert(&bm->hotplug_vlans, &mv->node);
	return true;
}

static struct bridge_member_range *
bridge_member_range_find(struct bridge_member_range *ranges, int n,
			 uint16_t start, uint16_t end)
{
	int i;

	for (i = 0; i < n; i++)
		if (ranges[i].start == start && ranges[i].end == end)
			return &ranges[i];

	return NULL;
}

static bool
__bridge_member_range_write(struct bridge_member *bm,
			    const struct bridge_member_range *r, bool add)
{
	if (!bm->active || !bm->bst->vlan_filtering)
		return false;

	system_bridge_vlan(bm->dev.dev->ifname, r->start, r->end, add,
			   add ? r->flags : 0);
	bridge_member_vlans_invalidate(bm, r->start, r->end);
	return true;
}

/* auth vlans use __bridge_member_range_write(), they apply without auth */
static bool
bridge_member_range_write(struct bridge_member *bm,
			  const struct bridge_member_range *r, bool add)
{
	if (!bridge_member_authorized(bm))
		return false;

	return __bridge_member_range_write(bm, r, add);
}

static bool
bridge_member_range_del(struct bridge_member *bm, uint16_t start, uint16_t end)
{
	struct bridge_member_range *r;
	bool found = false;

	while ((r = bridge_member_range_find(bm->extra_vlan, bm->n_extra_vlan,
					     start, end)) != NULL) {
		*r = bm->extra_vlan[--bm->n_extra_vlan];
		found = true;
	}

	return found;
}

/*
 * Deleting a range can also remove vlans that another range of the port
 * still needs, so all of them are written again after a delete.
 */
static void
bridge_member_add_extra_vlans(struct bridge_member *bm)
{
	struct device *dev = bm->dev.dev;
	struct bridge_member_range r = {};
	int i;

	for (i = 0; i < dev->n_extra_vlan; i++) {
		r.start = dev->extra_vlan[i].start;
		r.end = dev->extra_vlan[i].end;
		bridge_member_range_write(bm, &r, true);
	}

	for (i = 0; i < bm->n_extra_vlan; i++)
		bridge_member_range_write(bm, &bm->extra_vlan[i], true);
}

static bool
bridge_member_ranges_set(struct bridge_member *bm,
			 struct bridge_member_range *ranges, int n)
{
	struct bridge_member_range *old = bm->extra_vlan;
	int i, n_old = bm->n_extra_vlan;
	bool deleted = false, written = false;
	uint16_t vid;

	for (i = 0; i < n_old; i++) {
		if (bridge_member_range_find(ranges, n, old[i].start, old[i].end))
			continue;

		/* a single vlan that is now tracked is rewritten by the sync */
		vid = old[i].start;
		if (old[i].end == vid &&
		    avl_find(&bm->hotplug_vlans, &vid)) {
			bridge_member_vlans_invalidate(bm, vid, vid);
			written = true;
			continue;
		}

		deleted |= bridge_member_range_write(bm, &old[i], false);
	}

	for (i = 0; i < n && !deleted; i++) {
		struct bridge_member_range *prev;

		prev = bridge_member_range_find(old, n_old, ranges[i].start,
						ranges[i].end);
		if (prev && prev->flags == ranges[i].flags)
			continue;

		written |= bridge_member_range_write(bm, &ranges[i], true);
	}

	free(old);
	bm->extra_vlan = ranges;
	bm->n_extra_vlan = n;

	if (deleted)
		bridge_member_add_extra_vlans(bm);

	return deleted || written;
}

static bool
bridge_hotplug_vlan_parse(struct blob_attr *attr, struct bridge_member_range *r)
{
	unsigned int vid, vid_end;
	uint16_t flags = 0;
	char *end;

	if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
		return false;

	vid = strtoul(blobmsg_get_string(attr), &end, 0);
	vid_end = vid;
	if (!vid || vid > 4095)
		return false;

	if (*end == '-') {
		vid_end = strtoul(end + 1, &end, 0);
		if (vid_end < vid || vid_end > 4095)
			return false;
	}

	if (end && *end) {
		if (*end != ':')
			return false;

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

	/* the kernel rejects a pvid flag on a range */
	if (vid_end > vid)
		flags &= ~BRVLAN_F_PVID;

	r->start = vid;
	r->end = vid_end;
	r->flags = flags;

	return true;
}

/*
 * An add sets the complete list of hotplug vlans of the member. With
 * untracked set (auth vlans), entries are only written to the port.
 */
static void
bridge_hotplug_set_member_vlans(struct bridge_state *bst, struct blob_attr *vlans,
				struct bridge_member *bm, bool add, bool untracked)
{
	bool replace = add && !untracked;
	struct bridge_member_range *ranges = NULL;
	struct bridge_member_vlan *mv, *tmp;
	struct bridge_vlan *vlan;
	struct blob_attr *cur;
	bool range_deleted = false;
	bool changed = false;
	bool written = false;
	int n_ranges = 0;
	int n_vlans = 0;
	size_t rem;

	if (vlans) {
		n_vlans = blobmsg_check_array(vlans, BLOBMSG_TYPE_STRING);
		if (n_vlans < 0)
			return;
	} else if (!replace) {
		return;
	}

	if (replace) {
		if (n_vlans) {
			ranges = calloc(n_vlans, sizeof(*ranges));
			if (!ranges)
				return;
		}

		avl_for_each_element(&bm->hotplug_vlans, mv, node)
			mv->seen = false;
	}

	blobmsg_for_each_attr(cur, vlans, rem) {
		struct bridge_member_range range;
		uint16_t vid, vid_end, flags;
		bool tracked;

		if (!bridge_hotplug_vlan_parse(cur, &range))
			continue;

		vid = range.start;
		vid_end = range.end;
		flags = range.flags;

		tracked = !untracked && vid_end == vid;
		vlan = bridge_hotplug_get_vlan(bst, vid, add && tracked && flags);
		if (vlan && tracked) {
			if (bridge_hotplug_set_member_vlan(bm, vid, flags, add)) {
				changed = true;
				continue;
			}

			/* added as a range before its vlan existed */
			if (add || !bridge_member_range_find(bm->extra_vlan,
							     bm->n_extra_vlan, vid, vid))
				continue;
		}

		if (replace) {
			ranges[n_ranges++] = range;
			continue;
		}

		if (untracked) {
			__bridge_member_range_write(bm, &range, add);
			continue;
		}

		if (!add)
			range_deleted |= bridge_member_range_del(bm, vid, vid_end);

		written |= bridge_member_range_write(bm, &range, add);
	}

	if (range_deleted)
		bridge_member_add_extra_vlans(bm);

	if (replace) {
		avl_for_each_element_safe(&bm->hotplug_vlans, mv, node, tmp) {
			if (mv->seen)
				continue;

			bridge_hotplug_del_member_vlan(bm, mv);
			changed = true;
		}

		written |= bridge_member_ranges_set(bm, ranges, n_ranges);
	}

	/* with untracked set, the caller syncs after all its changes */
	if (!untracked && (changed || written))
		bridge_member_vlan_sync(bm);
}

static void
bridge_member_enable_vlans(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;
	struct device *dev = bm->dev.dev;

	if (dev->settings.auth) {
		bridge_hotplug_set_member_vlans(bst, dev->config_auth_vlans, bm,
						!dev->auth_status, true);
		bridge_hotplug_set_member_vlans(bst, dev->auth_vlans, bm,
						dev->auth_status, true);
	}

	if (dev->settings.auth && !dev->auth_status) {
		bridge_member_vlan_sync(bm);
		return;
	}

	bridge_member_add_extra_vlans(bm);

	/*
	 * Enabling deleted vlan 1 and wrote the ranges again, which can
	 * overlap applied vlans, so the port state no longer matches what was
	 * applied before.
	 */
	bridge_member_vlans_invalidate(bm, 1, 4095);
	bridge_member_vlan_sync(bm);
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
		bm->set_ipv6 = true;
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

	if (bst->vlan_filtering) {
		/* delete default VLAN 1 */
		if (bst->has_vlans)
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

	if (bst->active)
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
	struct device *dev = bm->dev.dev;
	struct bridge_member_vlan *mv;

	bridge_remove_member(bm);

	while (!avl_is_empty(&bm->hotplug_vlans)) {
		mv = avl_first_element(&bm->hotplug_vlans, mv, node);
		bridge_hotplug_del_member_vlan(bm, mv);
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
	if (dev->present && !dev->active) {
		device_set_present(dev, false);
		device_set_present(dev, true);
	}

	free(bm->applied);
	free(bm->extra_vlan);
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
	struct blob_attr *auth_vlans = NULL, *cur;
	struct device_vlan_range *ranges;
	struct bridge_member_range r;
	struct bridge_member *bm;
	struct bridge_state *bst;
	struct device *dev;
	int i, n = 0, n_auth = 0;
	size_t rem;
	int ret;

	bm = container_of(t, struct bridge_member, check_timer);
	bst = bm->bst;
	dev = bm->dev.dev;

	if (!bm->active)
		return;

	if (dev->settings.auth)
		auth_vlans = dev->auth_status ? dev->auth_vlans :
			     dev->config_auth_vlans;
	if (auth_vlans)
		n_auth = blobmsg_check_array(auth_vlans, BLOBMSG_TYPE_STRING);
	if (n_auth < 0)
		n_auth = 0;

	ranges = calloc(dev->n_extra_vlan + bm->n_extra_vlan + n_auth + 1,
			sizeof(*ranges));
	if (!ranges)
		return;

	for (i = 0; i < dev->n_extra_vlan; i++)
		ranges[n++] = dev->extra_vlan[i];

	for (i = 0; i < bm->n_extra_vlan; i++) {
		ranges[n].start = bm->extra_vlan[i].start;
		ranges[n++].end = bm->extra_vlan[i].end;
	}

	if (n_auth) {
		blobmsg_for_each_attr(cur, auth_vlans, rem) {
			if (!bridge_hotplug_vlan_parse(cur, &r))
				continue;

			ranges[n].start = r.start;
			ranges[n++].end = r.end;
		}
	}

	ret = system_bridge_vlan_check(&bst->dev, dev->ifname, bm->applied,
				       bm->n_applied, ranges, n);
	free(ranges);
	if (ret <= 0)
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
		if (!bst->has_vlans)
			break;

		if (dev->settings.auth)
			bridge_enable_member(bm);

		uloop_timeout_set(&bm->check_timer, 1000);
		break;
	case DEV_EVENT_LINK_DOWN:
		if (!dev->settings.auth)
			break;

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

	uloop_timeout_cancel(&bst->retry);
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

	bst->vlan_filtering = bst->config.vlan_filtering;
	bst->has_vlans = bst->vlan_filtering && bst->vlans_configured;
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
	avl_init(&bm->hotplug_vlans, bridge_avl_cmp_u16, false, NULL);
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
		if (!bm)
			return UBUS_STATUS_UNKNOWN_ERROR;
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
	uloop_timeout_cancel(&bst->retry);
	vlist_flush_all(&bst->members);
	vlist_flush_all(&dev->vlans);

	system_bridge_delbr(dev);

	kvlist_free(&dev->vlan_aliases);
	free(bst->config_data);
	free(bst);
}

static void
bridge_dump_port(struct blob_buf *b, const char *ifname, uint16_t flags)
{
	bool tagged = !(flags & BRVLAN_F_UNTAGGED);
	bool pvid = (flags & BRVLAN_F_PVID);

	blobmsg_printf(b, NULL, "%s%s%s%s", ifname,
		tagged || pvid ? ":" : "",
		tagged ? "t" : "",
		pvid ? "*" : "");
}

static void
bridge_dump_vlan(struct blob_buf *b, struct bridge_state *bst,
		 struct bridge_vlan *vlan)
{
	struct bridge_member_vlan *mv;
	struct bridge_member *bm;
	void *c, *p;
	int i;

	c = blobmsg_open_table(b, NULL);

	blobmsg_add_u32(b, "id", vlan->vid);
	blobmsg_add_u8(b, "local", vlan->local);

	p = blobmsg_open_array(b, "ports");

	for (i = 0; i < vlan->n_ports; i++)
		bridge_dump_port(b, vlan->ports[i].ifname, vlan->ports[i].flags);

	vlist_for_each_element(&bst->members, bm, node) {
		mv = avl_find_element(&bm->hotplug_vlans, &vlan->vid, mv, node);
		if (mv)
			bridge_dump_port(b, bm->name, mv->flags);
	}

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
		bridge_dump_vlan(b, bst, vlan);

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

static int
bridge_vlan_alias_len(struct kvlist *kv, const void *data)
{
	return sizeof(unsigned int);
}

static void
bridge_vlan_add(struct device *dev, struct blob_attr *data)
{
	struct blob_attr *tb[__BRVLAN_ATTR_MAX];
	struct blob_attr *cur;
	struct bridge_vlan_port *port;
	struct bridge_vlan *vlan;
	unsigned int vid;
	char *name_buf;
	int name_len = 0;
	int n_ports = 0;
	size_t rem;

	blobmsg_parse_attr(bridge_vlan_attrs, __BRVLAN_ATTR_MAX, tb, data);

	if (!tb[BRVLAN_ATTR_VID])
		return;

	vid = blobmsg_get_u32(tb[BRVLAN_ATTR_VID]);
	if (!vid || vid > 4095)
		return;

	blobmsg_for_each_attr(cur, tb[BRVLAN_ATTR_PORTS], rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING ||
		    !blobmsg_check_attr(cur, false))
			continue;

		name_len += strlen(blobmsg_get_string(cur)) + 1;
		n_ports++;
	}

	vlan = calloc(1, sizeof(*vlan) + n_ports * sizeof(*port) + name_len);
	if (!vlan)
		return;

	vlan->vid = vid;
	vlan->local = true;
	if (tb[BRVLAN_ATTR_LOCAL])
		vlan->local = blobmsg_get_bool(tb[BRVLAN_ATTR_LOCAL]);

	vlan->n_ports = n_ports;
	vlan->ports = port = (struct bridge_vlan_port *)&vlan[1];
	name_buf = (char *)&port[n_ports];

	blobmsg_for_each_attr(cur, tb[BRVLAN_ATTR_PORTS], rem) {
		char *sep;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING ||
		    !blobmsg_check_attr(cur, false))
			continue;

		port->ifname = name_buf;
		port->flags = BRVLAN_F_UNTAGGED;
		strcpy(name_buf, blobmsg_get_string(cur));

		sep = strchr(name_buf, ':');
		if (sep) {
			for (*sep = 0, sep++; *sep; sep++)
				switch (*sep) {
				case '*':
					port->flags |= BRVLAN_F_PVID;
					break;
				case 't':
					port->flags &= ~BRVLAN_F_UNTAGGED;
					break;
				}
		}

		name_buf += strlen(name_buf) + 1;
		port++;
	}

	blobmsg_for_each_attr(cur, tb[BRVLAN_ATTR_ALIAS], rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING ||
		    !blobmsg_check_attr(cur, false))
			continue;

		kvlist_set(&dev->vlan_aliases, blobmsg_get_string(cur), &vid);
	}

	vlist_add(&dev->vlans, &vlan->node, &vlan->vid);
}

/*
 * A config vlan that the new config no longer has, but that hotplug members
 * still use, becomes a hotplug vlan instead of being flushed, so that the
 * bridge's own vid is not removed and added again.
 */
static void
bridge_vlan_keep_hotplug(struct bridge_state *bst, uint16_t vid)
{
	struct bridge_vlan *vlan;

	vlan = vlist_find(&bst->dev.vlans, &vid, vlan, node);
	if (!vlan || vlan->node.version == -1 ||
	    vlan->node.version == bst->dev.vlans.version)
		return;

	vlan->node.version = -1;
	vlan->n_ports = 0;
}

static void
bridge_vlans_set(struct bridge_state *bst, struct blob_attr *vlans)
{
	struct device *dev = &bst->dev;
	struct bridge_member_vlan *mv;
	struct bridge_member *bm;
	struct blob_attr *cur;
	size_t rem;

	kvlist_free(&dev->vlan_aliases);
	vlist_update(&dev->vlans);
	blobmsg_for_each_attr(cur, vlans, rem)
		if (blobmsg_type(cur) == BLOBMSG_TYPE_TABLE)
			bridge_vlan_add(dev, cur);

	vlist_for_each_element(&bst->members, bm, node)
		avl_for_each_element(&bm->hotplug_vlans, mv, node)
			bridge_vlan_keep_hotplug(bst, mv->vid);

	vlist_flush(&dev->vlans);

	vlist_for_each_element(&bst->members, bm, node)
		bridge_member_vlan_sync(bm);

	device_broadcast_event(dev, DEV_EVENT_VLAN_UPDATE);
}

static bool
bridge_vlans_present(struct blob_attr **tb)
{
	return blobmsg_data_len(tb[BRIDGE_ATTR_VLANS]) > 0;
}

static void
bridge_apply_settings(struct bridge_state *bst, struct blob_attr **tb)
{
	struct bridge_config *cfg = &bst->config;
	struct blob_attr *cur;
	bool was_empty = cfg->bridge_empty;

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
	cfg->vlan_filtering = bridge_vlans_present(tb);

	cfg->forward_delay = 8;
	cfg->max_age = 10;
	cfg->hello_time = 1;

	if ((cur = tb[BRIDGE_ATTR_STP]))
		cfg->stp = blobmsg_get_bool(cur);

	if ((cur = tb[BRIDGE_ATTR_STP_KERNEL]))
		cfg->stp_kernel = blobmsg_get_bool(cur);

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

	/* only revert the config driven force_active here; the hotplug
	 * prepare path sets it independently of the empty option */
	if (was_empty && !cfg->bridge_empty)
		bst->force_active = false;

	if ((cur = tb[BRIDGE_ATTR_VLAN_FILTERING]))
		cfg->vlan_filtering = blobmsg_get_bool(cur);

	bst->vlans_configured = bridge_vlans_present(tb);

	bst->dev.vlan_filtering = cfg->vlan_filtering;
}

static enum dev_change_type
bridge_reload(struct device *dev, struct blob_attr *attr,
	      struct blob_attr **tb_dev)
{
	struct blob_attr *tb_br[__BRIDGE_ATTR_MAX];
	enum dev_change_type ret = DEV_CONFIG_APPLIED;
	struct bridge_state *bst;
	unsigned long diff[2] = {};

	BUILD_BUG_ON(sizeof(diff) < __BRIDGE_ATTR_MAX / BITS_PER_LONG);

	bst = container_of(dev, struct bridge_state, dev);
	attr = blob_memdup(attr);

	blobmsg_parse_attr(bridge_attrs, __BRIDGE_ATTR_MAX, tb_br, attr);

	if (tb_dev[DEV_ATTR_MACADDR])
		bst->primary_port = NULL;

	bst->ports = tb_br[BRIDGE_ATTR_PORTS];
	bridge_apply_settings(bst, tb_br);

	if (bst->config_data) {
		struct blob_attr *otb_br[__BRIDGE_ATTR_MAX];

		blobmsg_parse_attr(bridge_attrs, __BRIDGE_ATTR_MAX, otb_br, bst->config_data);

		uci_blob_diff(tb_br, otb_br, &bridge_attr_list, diff);
		if ((diff[0] & ~((1 << BRIDGE_ATTR_PORTS) | (1 << BRIDGE_ATTR_VLANS))) ||
		    bridge_vlans_present(tb_br) != bridge_vlans_present(otb_br)) {
			ret = DEV_CONFIG_RESTART;
			D(DEVICE, "Bridge %s attributes have changed, diff=[%lx %lx]",
			  dev->ifname, diff[1], diff[0]);
		}

		dev->config_pending = true;
	}

	bridge_vlans_set(bst, tb_br[BRIDGE_ATTR_VLANS]);

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

static void
bridge_vlan_update(struct vlist_tree *tree, struct vlist_node *node_new,
		   struct vlist_node *node_old)
{
	struct bridge_state *bst = container_of(tree, struct bridge_state, dev.vlans);
	struct bridge_vlan *vlan_new = NULL, *vlan_old = NULL;
	bool apply = bst->vlan_filtering && bst->active;

	if (node_old)
		vlan_old = container_of(node_old, struct bridge_vlan, node);
	if (node_new)
		vlan_new = container_of(node_new, struct bridge_vlan, node);

	if (apply && vlan_old &&
	    (!vlan_new || (vlan_old->local && !vlan_new->local)))
		bridge_set_local_vlan(bst, vlan_old, false);

	if (apply && vlan_new && (!vlan_old || !vlan_old->local))
		bridge_set_local_vlan(bst, vlan_new, true);

	bst->dev.config_pending = true;
	free(vlan_old);
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
	kvlist_init(&dev->vlan_aliases, bridge_vlan_alias_len);

	device_init_config(dev, attr);

	return dev;
}

static void __init bridge_device_type_init(void)
{
	device_type_add(&bridge_device_type);
}
