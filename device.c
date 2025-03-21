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

#include <libubox/list.h>

#include "netifd.h"
#include "system.h"
#include "config.h"
#include "ucode.h"
#include "ubus.h"

static struct list_head devtypes = LIST_HEAD_INIT(devtypes);
static struct avl_tree devices;
static struct blob_buf b;

static const struct blobmsg_policy dev_attrs[__DEV_ATTR_MAX] = {
	[DEV_ATTR_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
	[DEV_ATTR_MTU] = { .name = "mtu", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_MTU6] = { .name = "mtu6", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_MACADDR] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
	[DEV_ATTR_TXQUEUELEN] = { .name = "txqueuelen", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_ENABLED] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_IPV6] = { .name = "ipv6", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_IP6SEGMENTROUTING] = { .name = "ip6segmentrouting", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_PROMISC] = { .name = "promisc", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_RPFILTER] = { .name = "rpfilter", .type = BLOBMSG_TYPE_STRING },
	[DEV_ATTR_ACCEPTLOCAL] = { .name = "acceptlocal", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_IGMPVERSION] = { .name = "igmpversion", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_MLDVERSION] = { .name = "mldversion", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_NEIGHREACHABLETIME] = { .name = "neighreachabletime", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_NEIGHGCSTALETIME] = { .name = "neighgcstaletime", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_DADTRANSMITS] = { .name = "dadtransmits", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_MULTICAST_TO_UNICAST] = { .name = "multicast_to_unicast", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_MULTICAST_ROUTER] = { .name = "multicast_router", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_MULTICAST_FAST_LEAVE] = { .name = "multicast_fast_leave", . type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_MULTICAST] = { .name ="multicast", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_LEARNING] = { .name ="learning", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_UNICAST_FLOOD] = { .name ="unicast_flood", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_SENDREDIRECTS] = { .name = "sendredirects", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_NEIGHLOCKTIME] = { .name = "neighlocktime", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_ISOLATE] = { .name = "isolate", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_DROP_V4_UNICAST_IN_L2_MULTICAST] = { .name = "drop_v4_unicast_in_l2_multicast", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_DROP_V6_UNICAST_IN_L2_MULTICAST] = { .name = "drop_v6_unicast_in_l2_multicast", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_DROP_GRATUITOUS_ARP] = { .name = "drop_gratuitous_arp", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_DROP_UNSOLICITED_NA] = { .name = "drop_unsolicited_na", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_ARP_ACCEPT] = { .name = "arp_accept", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_AUTH] = { .name = "auth", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_AUTH_VLAN] = { .name = "auth_vlan", BLOBMSG_TYPE_ARRAY },
	[DEV_ATTR_SPEED] = { .name = "speed", .type = BLOBMSG_TYPE_INT32 },
	[DEV_ATTR_DUPLEX] = { .name = "duplex", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_VLAN] = { .name = "vlan", .type = BLOBMSG_TYPE_ARRAY },
	[DEV_ATTR_PAUSE] = { .name = "pause", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_ASYM_PAUSE] = { .name = "asym_pause", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_RXPAUSE] = { .name = "rxpause", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_TXPAUSE] = { .name = "txpause", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_AUTONEG] = { .name = "autoneg", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_GRO] = { .name = "gro", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_MASTER] = { .name = "conduit", .type = BLOBMSG_TYPE_STRING },
	[DEV_ATTR_EEE] = { .name = "eee", .type = BLOBMSG_TYPE_BOOL },
	[DEV_ATTR_TAGS] = { .name = "tags", .type = BLOBMSG_TYPE_ARRAY },
};

const struct uci_blob_param_list device_attr_list = {
	.n_params = __DEV_ATTR_MAX,
	.params = dev_attrs,
};

static int __devlock = 0;

int device_type_add(struct device_type *devtype)
{
	if (device_type_get(devtype->name)) {
		netifd_log_message(L_WARNING, "Device handler '%s' already exists\n",
				   devtype->name);
		return 1;
	}

	netifd_log_message(L_NOTICE, "Added device handler type: %s\n",
		devtype->name);

	list_add(&devtype->list, &devtypes);
	return 0;
}

struct device_type *
device_type_get(const char *tname)
{
	struct device_type *cur;

	list_for_each_entry(cur, &devtypes, list)
		if (!strcmp(cur->name, tname))
			return cur;

	return NULL;
}

static int device_vlan_len(struct kvlist *kv, const void *data)
{
	return sizeof(unsigned int);
}

void device_vlan_update(bool done)
{
	struct device *dev;

	avl_for_each_element(&devices, dev, avl) {
		if (!dev->vlans.update)
			continue;

		if (!done) {
			if (dev->vlan_aliases.get_len)
				kvlist_free(&dev->vlan_aliases);
			else
				kvlist_init(&dev->vlan_aliases, device_vlan_len);
			vlist_update(&dev->vlans);
		} else {
			vlist_flush(&dev->vlans);

			if (dev->type->vlan_update)
				dev->type->vlan_update(dev);
		}
	}
}

void device_stp_init(void)
{
	struct device *dev;

	avl_for_each_element(&devices, dev, avl) {
		if (!dev->type->stp_init)
			continue;

		dev->type->stp_init(dev);
	}
}

static int set_device_state(struct device *dev, bool state)
{
	if (state) {
		/* Get ifindex for all devices being enabled so a valid  */
		/* ifindex is in place avoiding possible race conditions */
		device_set_ifindex(dev, system_if_resolve(dev));
		if (!dev->ifindex)
			return -1;

		system_if_get_settings(dev, &dev->orig_settings);
		/* Only keep orig settings based on what needs to be set */
		dev->orig_settings.valid_flags = dev->orig_settings.flags;
		dev->orig_settings.flags &= dev->settings.flags;
		system_if_apply_settings(dev, &dev->settings, dev->settings.flags);

		if (!dev->external)
			system_if_up(dev);

		system_if_apply_settings_after_up(dev, &dev->settings);
	} else {
		if (!dev->external)
			system_if_down(dev);
		system_if_apply_settings(dev, &dev->orig_settings, dev->orig_settings.flags);

		/* Restore any settings present in UCI which may have
		 * failed to apply so that they will be re-attempted
		 * the next time the device is brought up */
		dev->settings.flags |= dev->settings.valid_flags;
	}

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
simple_device_create(const char *name, struct device_type *devtype,
		     struct blob_attr *attr)
{
	struct blob_attr *tb[__DEV_ATTR_MAX];
	struct device *dev = NULL;

	/* device type is unused for simple devices */
	devtype = NULL;

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

struct device_type simple_device_type = {
	.name = "Network device",
	.config_params = &device_attr_list,

	.create = simple_device_create,
	.check_state = system_if_check,
	.free = simple_device_free,
};

void
device_merge_settings(struct device *dev, struct device_settings *n)
{
	struct device_settings *os = &dev->orig_settings;
	struct device_settings *s = &dev->settings;

	memset(n, 0, sizeof(*n));
	n->mtu = s->flags & DEV_OPT_MTU ? s->mtu : os->mtu;
	n->mtu6 = s->flags & DEV_OPT_MTU6 ? s->mtu6 : os->mtu6;
	n->txqueuelen = s->flags & DEV_OPT_TXQUEUELEN ?
		s->txqueuelen : os->txqueuelen;
	memcpy(n->macaddr,
		(s->flags & (DEV_OPT_MACADDR|DEV_OPT_DEFAULT_MACADDR) ? s->macaddr : os->macaddr),
		sizeof(n->macaddr));
	n->ipv6 = s->flags & DEV_OPT_IPV6 ? s->ipv6 : os->ipv6;
	n->ip6segmentrouting = s->flags & DEV_OPT_IP6SEGMENTROUTING ? s->ip6segmentrouting : os->ip6segmentrouting;
	n->promisc = s->flags & DEV_OPT_PROMISC ? s->promisc : os->promisc;
	n->rpfilter = s->flags & DEV_OPT_RPFILTER ? s->rpfilter : os->rpfilter;
	n->acceptlocal = s->flags & DEV_OPT_ACCEPTLOCAL ? s->acceptlocal : os->acceptlocal;
	n->igmpversion = s->flags & DEV_OPT_IGMPVERSION ? s->igmpversion : os->igmpversion;
	n->mldversion = s->flags & DEV_OPT_MLDVERSION ? s->mldversion : os->mldversion;
	n->neigh4reachabletime = s->flags & DEV_OPT_NEIGHREACHABLETIME ?
		s->neigh4reachabletime : os->neigh4reachabletime;
	n->neigh6reachabletime = s->flags & DEV_OPT_NEIGHREACHABLETIME ?
		s->neigh6reachabletime : os->neigh6reachabletime;
	n->neigh4gcstaletime = s->flags & DEV_OPT_NEIGHGCSTALETIME ?
		s->neigh4gcstaletime : os->neigh4gcstaletime;
	n->neigh6gcstaletime = s->flags & DEV_OPT_NEIGHGCSTALETIME ?
		s->neigh6gcstaletime : os->neigh6gcstaletime;
	n->neigh4locktime = s->flags & DEV_OPT_NEIGHLOCKTIME ?
		s->neigh4locktime : os->neigh4locktime;
	n->dadtransmits = s->flags & DEV_OPT_DADTRANSMITS ?
		s->dadtransmits : os->dadtransmits;
	n->multicast = s->flags & DEV_OPT_MULTICAST ?
		s->multicast : os->multicast;
	n->multicast_to_unicast = s->multicast_to_unicast;
	n->multicast_router = s->multicast_router;
	n->multicast_fast_leave = s->multicast_fast_leave;
	n->learning = s->learning;
	n->unicast_flood = s->unicast_flood;
	n->sendredirects = s->flags & DEV_OPT_SENDREDIRECTS ?
		s->sendredirects : os->sendredirects;
	n->drop_v4_unicast_in_l2_multicast = s->flags & DEV_OPT_DROP_V4_UNICAST_IN_L2_MULTICAST ?
		s->drop_v4_unicast_in_l2_multicast : os->drop_v4_unicast_in_l2_multicast;
	n->drop_v6_unicast_in_l2_multicast = s->flags & DEV_OPT_DROP_V6_UNICAST_IN_L2_MULTICAST ?
		s->drop_v6_unicast_in_l2_multicast : os->drop_v6_unicast_in_l2_multicast;
	n->drop_gratuitous_arp = s->flags & DEV_OPT_DROP_GRATUITOUS_ARP ?
		s->drop_gratuitous_arp : os->drop_gratuitous_arp;
	n->drop_unsolicited_na = s->flags & DEV_OPT_DROP_UNSOLICITED_NA ?
		s->drop_unsolicited_na : os->drop_unsolicited_na;
	n->arp_accept = s->flags & DEV_OPT_ARP_ACCEPT ?
		s->arp_accept : os->arp_accept;
	n->auth = s->flags & DEV_OPT_AUTH ? s->auth : os->auth;
	n->speed = s->flags & DEV_OPT_SPEED ? s->speed : os->speed;
	n->duplex = s->flags & DEV_OPT_DUPLEX ? s->duplex : os->duplex;
	n->pause = s->flags & DEV_OPT_PAUSE ? s->pause : os->pause;
	n->asym_pause = s->flags & DEV_OPT_ASYM_PAUSE ? s->asym_pause : os->asym_pause;
	n->rxpause = s->flags & DEV_OPT_RXPAUSE ? s->rxpause : os->rxpause;
	n->txpause = s->flags & DEV_OPT_TXPAUSE ? s->txpause : os->txpause;
	n->autoneg = s->flags & DEV_OPT_AUTONEG ? s->autoneg : os->autoneg;
	n->gro = s->flags & DEV_OPT_GRO ? s->gro : os->gro;
	n->eee = s->flags & DEV_OPT_EEE ? s->eee : os->eee;
	n->master_ifindex = s->flags & DEV_OPT_MASTER ? s->master_ifindex : os->master_ifindex;
	n->flags = s->flags | os->flags | os->valid_flags;
}

static bool device_fill_vlan_range(struct device_vlan_range *r, const char *val)
{
	unsigned long cur_start, cur_end;
	char *sep;

	cur_start = strtoul(val, &sep, 0);
	cur_end = cur_start;

	if (*sep == '-')
		cur_end = strtoul(sep + 1, &sep, 0);
	if (*sep || cur_end < cur_start)
		return false;

	r->start = cur_start;
	r->end = cur_end;

	return true;
}

static void
device_set_extra_vlans(struct device *dev, struct blob_attr *data)
{
	struct blob_attr *cur;
	int n_vlans;
	size_t rem;

	dev->n_extra_vlan = 0;
	if (!data)
		return;

	n_vlans = blobmsg_check_array(data, BLOBMSG_TYPE_STRING);
	if (n_vlans < 1)
		return;

	dev->extra_vlan = realloc(dev->extra_vlan, n_vlans * sizeof(*dev->extra_vlan));
	blobmsg_for_each_attr(cur, data, rem)
		if (device_fill_vlan_range(&dev->extra_vlan[dev->n_extra_vlan],
					   blobmsg_get_string(cur)))
			dev->n_extra_vlan++;
}

void
device_init_settings(struct device *dev, struct blob_attr **tb)
{
	struct device_settings *s = &dev->settings;
	struct blob_attr *cur;
	struct ether_addr *ea;
	bool disabled = false;

	if (dev->wireless)
		s->flags &= DEV_OPT_ISOLATE;
	else
		s->flags = 0;
	if ((cur = tb[DEV_ATTR_ENABLED]))
		disabled = !blobmsg_get_bool(cur);

	if ((cur = tb[DEV_ATTR_MTU]) && blobmsg_get_u32(cur) >= 68) {
		s->mtu = blobmsg_get_u32(cur);
		s->flags |= DEV_OPT_MTU;
	}

	if ((cur = tb[DEV_ATTR_MTU6]) && blobmsg_get_u32(cur) >= 1280) {
		s->mtu6 = blobmsg_get_u32(cur);
		s->flags |= DEV_OPT_MTU6;
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

	if ((cur = tb[DEV_ATTR_IPV6])) {
		s->ipv6 = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_IPV6;
	}

	if ((cur = tb[DEV_ATTR_IP6SEGMENTROUTING])) {
		s->ip6segmentrouting = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_IP6SEGMENTROUTING;
	}

	if ((cur = tb[DEV_ATTR_PROMISC])) {
		s->promisc = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_PROMISC;
	}

	if ((cur = tb[DEV_ATTR_RPFILTER])) {
		if (system_resolve_rpfilter(blobmsg_data(cur), &s->rpfilter))
			s->flags |= DEV_OPT_RPFILTER;
		else
			D(DEVICE, "Failed to resolve rpfilter: %s", (char *) blobmsg_data(cur));
	}

	if ((cur = tb[DEV_ATTR_ACCEPTLOCAL])) {
		s->acceptlocal = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_ACCEPTLOCAL;
	}

	if ((cur = tb[DEV_ATTR_IGMPVERSION])) {
		s->igmpversion = blobmsg_get_u32(cur);
		if (s->igmpversion >= 1 && s->igmpversion <= 3)
			s->flags |= DEV_OPT_IGMPVERSION;
		else
			D(DEVICE, "Failed to resolve igmpversion: %d", blobmsg_get_u32(cur));
	}

	if ((cur = tb[DEV_ATTR_MLDVERSION])) {
		s->mldversion = blobmsg_get_u32(cur);
		if (s->mldversion >= 1 && s->mldversion <= 2)
			s->flags |= DEV_OPT_MLDVERSION;
		else
			D(DEVICE, "Failed to resolve mldversion: %d", blobmsg_get_u32(cur));
	}

	if ((cur = tb[DEV_ATTR_NEIGHREACHABLETIME])) {
		s->neigh6reachabletime = s->neigh4reachabletime = blobmsg_get_u32(cur);
		s->flags |= DEV_OPT_NEIGHREACHABLETIME;
	}

	if ((cur = tb[DEV_ATTR_NEIGHGCSTALETIME])) {
		s->neigh6gcstaletime = s->neigh4gcstaletime = blobmsg_get_u32(cur);
		s->flags |= DEV_OPT_NEIGHGCSTALETIME;
	}

	if ((cur = tb[DEV_ATTR_NEIGHLOCKTIME])) {
		s->neigh4locktime = blobmsg_get_u32(cur);
		s->flags |= DEV_OPT_NEIGHLOCKTIME;
	}

	if ((cur = tb[DEV_ATTR_DADTRANSMITS])) {
		s->dadtransmits = blobmsg_get_u32(cur);
		s->flags |= DEV_OPT_DADTRANSMITS;
	}

	if ((cur = tb[DEV_ATTR_MULTICAST_TO_UNICAST])) {
		s->multicast_to_unicast = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_MULTICAST_TO_UNICAST;
	}

	if ((cur = tb[DEV_ATTR_MULTICAST_ROUTER])) {
		s->multicast_router = blobmsg_get_u32(cur);
		if (s->multicast_router <= 2)
			s->flags |= DEV_OPT_MULTICAST_ROUTER;
		else
			D(DEVICE, "Invalid value: %d - (Use 0: never, 1: learn, 2: always)", blobmsg_get_u32(cur));
	}

	if ((cur = tb[DEV_ATTR_MULTICAST_FAST_LEAVE])) {
		s->multicast_fast_leave = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_MULTICAST_FAST_LEAVE;
	}

	if ((cur = tb[DEV_ATTR_MULTICAST])) {
		s->multicast = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_MULTICAST;
	}

	if ((cur = tb[DEV_ATTR_LEARNING])) {
		s->learning = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_LEARNING;
	}

	if ((cur = tb[DEV_ATTR_UNICAST_FLOOD])) {
		s->unicast_flood = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_UNICAST_FLOOD;
	}

	if ((cur = tb[DEV_ATTR_SENDREDIRECTS])) {
		s->sendredirects = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_SENDREDIRECTS;
	}

	if ((cur = tb[DEV_ATTR_ISOLATE])) {
		s->isolate = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_ISOLATE;
	}

	if ((cur = tb[DEV_ATTR_DROP_V4_UNICAST_IN_L2_MULTICAST])) {
		s->drop_v4_unicast_in_l2_multicast = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_DROP_V4_UNICAST_IN_L2_MULTICAST;
	}

	if ((cur = tb[DEV_ATTR_DROP_V6_UNICAST_IN_L2_MULTICAST])) {
		s->drop_v6_unicast_in_l2_multicast = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_DROP_V6_UNICAST_IN_L2_MULTICAST;
	}

	if ((cur = tb[DEV_ATTR_DROP_GRATUITOUS_ARP])) {
		s->drop_gratuitous_arp = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_DROP_GRATUITOUS_ARP;
	}

	if ((cur = tb[DEV_ATTR_DROP_UNSOLICITED_NA])) {
		s->drop_unsolicited_na = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_DROP_UNSOLICITED_NA;
	}

	if ((cur = tb[DEV_ATTR_ARP_ACCEPT])) {
		s->arp_accept = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_ARP_ACCEPT;
	}

	if ((cur = tb[DEV_ATTR_AUTH])) {
		s->auth = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_AUTH;
	}

	if ((cur = tb[DEV_ATTR_SPEED])) {
		s->speed = blobmsg_get_u32(cur);
		s->flags |= DEV_OPT_SPEED;
	}

	if ((cur = tb[DEV_ATTR_DUPLEX])) {
		s->duplex = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_DUPLEX;
	}

	if ((cur = tb[DEV_ATTR_PAUSE])) {
		s->pause = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_PAUSE;
	}

	if ((cur = tb[DEV_ATTR_ASYM_PAUSE])) {
		s->asym_pause = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_ASYM_PAUSE;
	}

	if ((cur = tb[DEV_ATTR_RXPAUSE])) {
		s->rxpause = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_RXPAUSE;
	}

	if ((cur = tb[DEV_ATTR_TXPAUSE])) {
		s->txpause = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_TXPAUSE;
	}

	if ((cur = tb[DEV_ATTR_AUTONEG])) {
		s->autoneg = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_AUTONEG;
	}

	if ((cur = tb[DEV_ATTR_GRO])) {
		s->gro = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_GRO;
	}

	if ((cur = tb[DEV_ATTR_MASTER])) {
		char *ifname = blobmsg_get_string(cur);
		s->master_ifindex = if_nametoindex(ifname);
		s->flags |= DEV_OPT_MASTER;
	}

	if ((cur = tb[DEV_ATTR_EEE])) {
		s->eee = blobmsg_get_bool(cur);
		s->flags |= DEV_OPT_EEE;
	}

	/* Remember the settings present in UCI */
	s->valid_flags = s->flags;

	cur = tb[DEV_ATTR_AUTH_VLAN];
	free(dev->config_auth_vlans);
	dev->config_auth_vlans = cur ? blob_memdup(cur) : NULL;

	cur = tb[DEV_ATTR_TAGS];
	free(dev->tags);
	dev->tags = cur ? blob_memdup(cur) : NULL;

	device_set_extra_vlans(dev, tb[DEV_ATTR_VLAN]);
	device_set_disabled(dev, disabled);
}

static void __init dev_init(void)
{
	avl_init(&devices, avl_strcmp, true, NULL);
}

static int device_release_cb(void *ctx, struct safe_list *list)
{
	struct device_user *dep = container_of(list, struct device_user, list);

	if (!dep->dev || !dep->claimed)
		return 0;

	device_release(dep);
	return 0;
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

const char *device_event_name(enum device_event ev)
{
	static const char * const event_names[] = {
		[DEV_EVENT_ADD] = "add",
		[DEV_EVENT_REMOVE] = "remove",
		[DEV_EVENT_UPDATE_IFNAME] = "update_ifname",
		[DEV_EVENT_UPDATE_IFINDEX] = "update_ifindex",
		[DEV_EVENT_SETUP] = "setup",
		[DEV_EVENT_TEARDOWN] = "teardown",
		[DEV_EVENT_UP] = "up",
		[DEV_EVENT_DOWN] = "down",
		[DEV_EVENT_AUTH_UP] = "auth_up",
		[DEV_EVENT_LINK_UP] = "link_up",
		[DEV_EVENT_LINK_DOWN] = "link_down",
		[DEV_EVENT_TOPO_CHANGE] = "topo_change",
	};

	if (ev >= ARRAY_SIZE(event_names) || !event_names[ev])
		return "unknown";

	return event_names[ev];
}

void __device_broadcast_event(struct device *dev, enum device_event ev)
{
	const char *ev_name;
	int dev_ev = ev;

	safe_list_for_each(&dev->aliases, device_broadcast_cb, &dev_ev);
	safe_list_for_each(&dev->users, device_broadcast_cb, &dev_ev);

	switch (ev) {
	case DEV_EVENT_ADD:
	case DEV_EVENT_REMOVE:
	case DEV_EVENT_UP:
	case DEV_EVENT_DOWN:
	case DEV_EVENT_AUTH_UP:
	case DEV_EVENT_LINK_UP:
	case DEV_EVENT_LINK_DOWN:
	case DEV_EVENT_TOPO_CHANGE:
		break;
	default:
		return;
	}

	ev_name = device_event_name(ev);
	if (!dev->ifname[0])
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", dev->ifname);
	blobmsg_add_u8(&b, "auth_status", dev->auth_status);
	blobmsg_add_u8(&b, "present", dev->present);
	blobmsg_add_u8(&b, "active", dev->active);
	blobmsg_add_u8(&b, "link_active", dev->link_active);
	netifd_ubus_device_notify(ev_name, b.head, -1);
}

static void
device_fill_default_settings(struct device *dev)
{
	struct device_settings *s = &dev->settings;
	struct ether_addr *ea;
	const char *master;
	int ret;

	if (!(s->flags & DEV_OPT_MACADDR)) {
		ea = config_get_default_macaddr(dev->ifname);
		if (ea) {
			memcpy(s->macaddr, ea, 6);
			s->flags |= DEV_OPT_DEFAULT_MACADDR;
		}
	}

	if (!(s->flags & DEV_OPT_GRO)) {
		ret = config_get_default_gro(dev->ifname);
		if (ret >= 0) {
			s->gro = ret;
			s->flags |= DEV_OPT_GRO;
		}
	}

	if (!(s->flags & DEV_OPT_MASTER)) {
		master = config_get_default_conduit(dev->ifname);
		if (master) {
			s->master_ifindex = if_nametoindex(master);
			s->flags |= DEV_OPT_MASTER;
		}
	}
}

int device_claim(struct device_user *dep)
{
	struct device *dev = dep->dev;
	int ret = 0;

	if (dep->claimed)
		return 0;

	if (!dev)
		return -1;

	dep->claimed = true;
	D(DEVICE, "Claim %s %s, new active count: %d", dev->type->name, dev->ifname, dev->active + 1);
	if (++dev->active != 1)
		return 0;

	device_broadcast_event(dev, DEV_EVENT_SETUP);
	device_fill_default_settings(dev);
	ret = dev->set_state(dev, true);
	if (ret == 0)
		device_broadcast_event(dev, DEV_EVENT_UP);
	else {
		D(DEVICE, "claim %s %s failed: %d", dev->type->name, dev->ifname, ret);
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
	D(DEVICE, "Release %s %s, new active count: %d", dev->type->name, dev->ifname, dev->active);
	assert(dev->active >= 0);

	if (dev->active)
		return;

	device_broadcast_event(dev, DEV_EVENT_TEARDOWN);
	dev->set_state(dev, false);

	if (dev->active)
		return;

	device_broadcast_event(dev, DEV_EVENT_DOWN);
}

int device_check_state(struct device *dev)
{
	if (!dev->type->check_state)
		return simple_device_type.check_state(dev);

	return dev->type->check_state(dev);
}

int device_init_virtual(struct device *dev, struct device_type *type, const char *name)
{
	assert(dev);
	assert(type);

	D(DEVICE, "Initialize device '%s'", name ? name : "");
	INIT_SAFE_LIST(&dev->users);
	INIT_SAFE_LIST(&dev->aliases);
	dev->type = type;

	if (name) {
		int ret;

		ret = device_set_ifname(dev, name);
		if (ret < 0) {
			netifd_log_message(L_WARNING, "Failed to initalize device '%s'\n", name);
			return ret;
		}
	}

	if (!dev->set_state)
		dev->set_state = set_device_state;

	return 0;
}

int device_init(struct device *dev, struct device_type *type, const char *ifname)
{
	int ret;

	ret = device_init_virtual(dev, type, ifname);
	if (ret < 0)
		return ret;

	dev->avl.key = dev->ifname;

	ret = avl_insert(&devices, &dev->avl);
	if (ret < 0)
		return ret;

	system_if_clear_state(dev);

	return 0;
}

static struct device *
device_create_default(const char *name, bool external)
{
	struct device *dev;

	if (!external && system_if_force_external(name))
		return NULL;

	D(DEVICE, "Create simple device '%s'", name);
	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->external = external;
	dev->set_state = simple_device_set_state;

	if (device_init(dev, &simple_device_type, name) < 0) {
		device_cleanup(dev);
		free(dev);
		return NULL;
	}

	dev->default_config = true;
	device_check_state(dev);

	return dev;
}

struct device *
device_find(const char *name)
{
	struct device *dev;

	return avl_find_element(&devices, name, dev, avl);
}

struct device *
__device_get(const char *name, int create, bool check_vlan)
{
	struct device *dev;

	dev = avl_find_element(&devices, name, dev, avl);

	if (!dev && check_vlan && strchr(name, '.'))
		return get_vlan_device_chain(name, create);

	if (name[0] == '@')
		return device_alias_get(name + 1);

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

	D(DEVICE, "Delete device '%s' from list", dev->ifname);
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
	D(DEVICE, "Clean up device '%s'", dev->ifname);
	safe_list_for_each(&dev->users, device_cleanup_cb, NULL);
	safe_list_for_each(&dev->aliases, device_cleanup_cb, NULL);
	device_delete(dev);
}

static void __device_set_present(struct device *dev, bool state, bool force)
{
	if (dev->present == state && !force)
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

	D(DEVICE, "refresh device %s present: sys=%d disabled=%d deferred=%d",
	  dev->ifname, dev->sys_present, dev->disabled, dev->deferred);
	__device_set_present(dev, state, false);
}

void
device_set_auth_status(struct device *dev, bool value, struct blob_attr *vlans)
{
	if (!value)
		vlans = NULL;
	else if (!blob_attr_equal(vlans, dev->auth_vlans))
		device_set_auth_status(dev, false, NULL);

	free(dev->auth_vlans);
	dev->auth_vlans = vlans ? blob_memdup(vlans) : NULL;

	if (dev->auth_status == value)
		return;

	dev->auth_status = value;
	if (!dev->present)
		return;

	if (dev->auth_status) {
		device_broadcast_event(dev, DEV_EVENT_AUTH_UP);
		return;
	}

	device_broadcast_event(dev, DEV_EVENT_LINK_DOWN);
	if (!dev->link_active)
		return;

	device_broadcast_event(dev, DEV_EVENT_LINK_UP);
}

void _device_set_present(struct device *dev, bool state)
{
	if (dev->sys_present == state)
		return;

	D(DEVICE, "%s '%s' %s present", dev->type->name, dev->ifname, state ? "is now" : "is no longer" );
	dev->sys_present = state;
	if (!state)
		__device_set_present(dev, state, true);
	else
		device_refresh_present(dev);
	if (!state)
		safe_list_for_each(&dev->users, device_release_cb, NULL);
}

void device_set_link(struct device *dev, bool state)
{
	if (dev->link_active == state)
		return;

	netifd_log_message(L_NOTICE, "%s '%s' link is %s\n", dev->type->name, dev->ifname, state ? "up" : "down" );

	dev->link_active = state;
	if (!state)
		dev->auth_status = false;
	device_broadcast_event(dev, state ? DEV_EVENT_LINK_UP : DEV_EVENT_LINK_DOWN);
}

void device_set_ifindex(struct device *dev, int ifindex)
{
	if (dev->ifindex == ifindex)
		return;

	dev->ifindex = ifindex;
	device_broadcast_event(dev, DEV_EVENT_UPDATE_IFINDEX);
}

int device_set_ifname(struct device *dev, const char *name)
{
	int ret = 0;

	if (!strcmp(dev->ifname, name))
		return 0;

	if (strlen(name) > sizeof(dev->ifname) - 1) {
		netifd_log_message(L_WARNING, "Cannot set device name: '%s' is longer than max size %zd\n",
			name, sizeof(dev->ifname) - 1);
		return -1;
	}

	if (dev->avl.key)
		avl_delete(&devices, &dev->avl);

	strcpy(dev->ifname, name);

	if (dev->avl.key)
		ret = avl_insert(&devices, &dev->avl);

	if (ret == 0)
		device_broadcast_event(dev, DEV_EVENT_UPDATE_IFNAME);

	return ret;
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

static void
__device_add_user(struct device_user *dep, struct device *dev)
{
	struct safe_list *head;

	dep->dev = dev;

	if (dep->alias)
		head = &dev->aliases;
	else
		head = &dev->users;

	safe_list_add(&dep->list, head);
	D(DEVICE, "Add user for device '%s', refcount=%d", dev->ifname, device_refcount(dev));

	if (dep->cb && dev->present) {
		dep->cb(dep, DEV_EVENT_ADD);
		if (dev->active)
			dep->cb(dep, DEV_EVENT_UP);

		if (dev->link_active)
			dep->cb(dep, DEV_EVENT_LINK_UP);
	}
}

void device_add_user(struct device_user *dep, struct device *dev)
{
	if (dep->dev == dev)
		return;

	if (dep->dev)
		device_remove_user(dep);

	if (!dev)
		return;

	__device_add_user(dep, dev);
}

static void
device_free(struct device *dev)
{
	__devlock++;
	free(dev->auth_vlans);
	free(dev->config);
	device_cleanup(dev);
	free(dev->tags);
	free(dev->config_auth_vlans);
	free(dev->extra_vlan);
	dev->type->free(dev);
	__devlock--;
}

static void
__device_free_unused(struct uloop_timeout *timeout)
{
	struct device *dev, *tmp;

	avl_for_each_element_safe(&devices, dev, avl, tmp) {
		if (!safe_list_empty(&dev->users) ||
			!safe_list_empty(&dev->aliases) ||
			dev->current_config)
			continue;

		device_free(dev);
	}
}

void device_free_unused(void)
{
	static struct uloop_timeout free_timer = {
		.cb = __device_free_unused,
	};

	uloop_timeout_set(&free_timer, 1);
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
	D(DEVICE, "Remove user for device '%s', refcount=%d", dev->ifname, device_refcount(dev));
	device_free_unused();
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
		device_check_state(dev);
	}
}

bool
device_check_ip6segmentrouting(void)
{
	struct device *dev;
	bool ip6segmentrouting = false;

	avl_for_each_element(&devices, dev, avl)
		ip6segmentrouting |= dev->settings.ip6segmentrouting;

	return ip6segmentrouting;
}

static enum dev_change_type
device_set_config(struct device *dev, struct device_type *type,
		  struct blob_attr *attr)
{
	struct blob_attr *tb[__DEV_ATTR_MAX];
	const struct uci_blob_param_list *cfg = type->config_params;

	if (type != dev->type)
		return DEV_CONFIG_RECREATE;

	if (dev->type->reload)
		return dev->type->reload(dev, attr);

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
device_apply_config(struct device *dev, struct device_type *type,
		    struct blob_attr *config)
{
	enum dev_change_type change;

	change = device_set_config(dev, type, config);
	switch (change) {
		case DEV_CONFIG_RESTART:
		case DEV_CONFIG_APPLIED:
			D(DEVICE, "Device '%s': config applied", dev->ifname);
			config = blob_memdup(config);
			free(dev->config);
			dev->config = config;
			if (change == DEV_CONFIG_RESTART && dev->present) {
				int ret = 0;

				device_set_present(dev, false);
				if (dev->active) {
					ret = dev->set_state(dev, false);
					if (!ret)
						ret = dev->set_state(dev, true);
				}
				if (!ret)
					device_set_present(dev, true);
			}
			break;
		case DEV_CONFIG_NO_CHANGE:
			D(DEVICE, "Device '%s': no configuration change", dev->ifname);
			break;
		case DEV_CONFIG_RECREATE:
			break;
	}

	return change;
}

static void
device_replace(struct device *dev, struct device *odev)
{
	struct device_user *dep;

	__devlock++;
	if (odev->present)
		device_set_present(odev, false);

	while (!list_empty(&odev->users.list)) {
		dep = list_first_entry(&odev->users.list, struct device_user, list.list);
		device_release(dep);
		if (!dep->dev)
			continue;

		safe_list_del(&dep->list);
		__device_add_user(dep, dev);
	}
	__devlock--;

	device_free(odev);
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
		if (!ndev)
			continue;

		device_replace(ndev, dev);
	}
}

struct device *
device_create(const char *name, struct device_type *type,
	      struct blob_attr *config)
{
	struct device *odev = NULL, *dev;
	enum dev_change_type change;

	odev = device_find(name);
	if (odev) {
		odev->current_config = true;
		change = device_apply_config(odev, type, config);
		switch (change) {
		case DEV_CONFIG_RECREATE:
			D(DEVICE, "Device '%s': recreate device", odev->ifname);
			device_delete(odev);
			break;
		default:
			return odev;
		}
	} else
		D(DEVICE, "Create new device '%s' (%s)", name, type->name);

	config = blob_memdup(config);
	if (!config)
		return NULL;

	dev = type->create(name, type, config);
	if (!dev)
		return NULL;

	dev->current_config = true;
	dev->config = config;
	if (odev)
		device_replace(dev, odev);

	if (!config_init && dev->config_pending) {
		type->config_init(dev);
		dev->config_pending = false;
	}

	device_check_state(dev);

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
	blobmsg_add_u8(b, "carrier", !!dev->link_active);
	blobmsg_add_u8(b, "auth_status", !!dev->auth_status);

	if (dev->tags)
		blobmsg_add_blob(b, dev->tags);

	if (dev->type->dump_info)
		dev->type->dump_info(dev, b);
	else
		system_if_dump_info(dev, b);

	if (dev->active) {
		device_merge_settings(dev, &st);
		if (st.flags & DEV_OPT_MASTER) {
			char buf[64], *devname;

			devname = if_indextoname(st.master_ifindex, buf);
			if (devname)
				blobmsg_add_string(b, "conduit", devname);
		}
		if (st.flags & DEV_OPT_MTU)
			blobmsg_add_u32(b, "mtu", st.mtu);
		if (st.flags & DEV_OPT_MTU6)
			blobmsg_add_u32(b, "mtu6", st.mtu6);
		if (st.flags & DEV_OPT_MACADDR)
			blobmsg_add_string(b, "macaddr", format_macaddr(st.macaddr));
		if (st.flags & DEV_OPT_TXQUEUELEN)
			blobmsg_add_u32(b, "txqueuelen", st.txqueuelen);
		if (st.flags & DEV_OPT_IPV6)
			blobmsg_add_u8(b, "ipv6", st.ipv6);
		if (st.flags & DEV_OPT_IP6SEGMENTROUTING)
			blobmsg_add_u8(b, "ip6segmentrouting", st.ip6segmentrouting);
		if (st.flags & DEV_OPT_PROMISC)
			blobmsg_add_u8(b, "promisc", st.promisc);
		if (st.flags & DEV_OPT_RPFILTER)
			blobmsg_add_u32(b, "rpfilter", st.rpfilter);
		if (st.flags & DEV_OPT_ACCEPTLOCAL)
			blobmsg_add_u8(b, "acceptlocal", st.acceptlocal);
		if (st.flags & DEV_OPT_IGMPVERSION)
			blobmsg_add_u32(b, "igmpversion", st.igmpversion);
		if (st.flags & DEV_OPT_MLDVERSION)
			blobmsg_add_u32(b, "mldversion", st.mldversion);
		if (st.flags & DEV_OPT_NEIGHREACHABLETIME) {
			blobmsg_add_u32(b, "neigh4reachabletime", st.neigh4reachabletime);
			blobmsg_add_u32(b, "neigh6reachabletime", st.neigh6reachabletime);
		}
		if (st.flags & DEV_OPT_NEIGHGCSTALETIME) {
			blobmsg_add_u32(b, "neigh4gcstaletime", st.neigh4gcstaletime);
			blobmsg_add_u32(b, "neigh6gcstaletime", st.neigh6gcstaletime);
		}
		if (st.flags & DEV_OPT_NEIGHLOCKTIME)
			blobmsg_add_u32(b, "neigh4locktime", st.neigh4locktime);
		if (st.flags & DEV_OPT_DADTRANSMITS)
			blobmsg_add_u32(b, "dadtransmits", st.dadtransmits);
		if (st.flags & DEV_OPT_MULTICAST_TO_UNICAST)
			blobmsg_add_u8(b, "multicast_to_unicast", st.multicast_to_unicast);
		if (st.flags & DEV_OPT_MULTICAST_ROUTER)
			blobmsg_add_u32(b, "multicast_router", st.multicast_router);
		if (st.flags & DEV_OPT_MULTICAST_FAST_LEAVE)
			blobmsg_add_u8(b, "multicast_fast_leave", st.multicast_fast_leave);
		if (st.flags & DEV_OPT_MULTICAST)
			blobmsg_add_u8(b, "multicast", st.multicast);
		if (st.flags & DEV_OPT_LEARNING)
			blobmsg_add_u8(b, "learning", st.learning);
		if (st.flags & DEV_OPT_UNICAST_FLOOD)
			blobmsg_add_u8(b, "unicast_flood", st.unicast_flood);
		if (st.flags & DEV_OPT_SENDREDIRECTS)
			blobmsg_add_u8(b, "sendredirects", st.sendredirects);
		if (st.flags & DEV_OPT_DROP_V4_UNICAST_IN_L2_MULTICAST)
			blobmsg_add_u8(b, "drop_v4_unicast_in_l2_multicast", st.drop_v4_unicast_in_l2_multicast);
		if (st.flags & DEV_OPT_DROP_V6_UNICAST_IN_L2_MULTICAST)
			blobmsg_add_u8(b, "drop_v6_unicast_in_l2_multicast", st.drop_v6_unicast_in_l2_multicast);
		if (st.flags & DEV_OPT_DROP_GRATUITOUS_ARP)
			blobmsg_add_u8(b, "drop_gratuitous_arp", st.drop_gratuitous_arp);
		if (st.flags & DEV_OPT_DROP_UNSOLICITED_NA)
			blobmsg_add_u8(b, "drop_unsolicited_na", st.drop_unsolicited_na);
		if (st.flags & DEV_OPT_ARP_ACCEPT)
			blobmsg_add_u8(b, "arp_accept", st.arp_accept);
		if (st.flags & DEV_OPT_AUTH)
			blobmsg_add_u8(b, "auth", st.auth);
		if (st.flags & DEV_OPT_GRO)
			blobmsg_add_u8(b, "gro", st.gro);
		if (st.flags & DEV_OPT_EEE)
			blobmsg_add_u8(b, "eee", st.eee);
	}

	s = blobmsg_open_table(b, "statistics");
	if (dev->type->dump_stats)
		dev->type->dump_stats(dev, b);
	else
		system_if_dump_stats(dev, b);
	blobmsg_close_table(b, s);
}

static void __init simple_device_type_init(void)
{
	device_type_add(&simple_device_type);
}

void device_hotplug_event(const char *name, bool add)
{
	struct device *dev;

	netifd_ucode_hotplug_event(name, add);

	dev = device_find(name);
	if (!dev || dev->type != &simple_device_type)
		return;

	device_set_present(dev, add);
}
