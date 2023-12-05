/*
 * netifd - network interface daemon
 * Copyright (C) 2015 Arne Kappen <arne.kappen@hhi.fraunhofer.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 * extdev - external device handler interface
 *
 * This allows to integrate external daemons that configure network devices
 * with netifd. At startup, netifd generates device handler stubs from
 * descriptions in /lib/netifd/extdev-config and adds them to the list of
 * device handlers. A device handler is an instance of struct device_type
 * The descriptions are in JSON format and specify
 *   - names of the device type and of the external device handler on ubus,
 *   - whether the device is bridge-like,
 *   - a prefix for device names,
 *   - the UCI config options for devices of this type, and
 *   - the format of calls to dump() and info()
 * These device handlers stubs act as relays forwarding calls against the
 * device handler interface to the external daemon.
 */

#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <libubus.h>
#include <assert.h>

#include "netifd.h"
#include "handler.h"
#include "device.h"
#include "ubus.h"
#include "extdev.h"
#include "interface.h"
#include "system.h"


static struct blob_buf b;
static int confdir_fd = -1;

struct extdev_type {
	struct device_type handler;

	const char *name;
	uint32_t peer_id;
	struct ubus_subscriber ubus_sub;
	bool subscribed;
	struct ubus_event_handler obj_wait;

	struct uci_blob_param_list *config_params;
	char *config_strbuf;

	struct uci_blob_param_list *info_params;
	char *info_strbuf;

	struct uci_blob_param_list *stats_params;
	char *stats_strbuf;
};

struct extdev_device {
	struct device dev;
	struct extdev_type *etype;
	const char *dep_name;
	struct uloop_timeout retry;
};

struct extdev_bridge {
	struct extdev_device edev;
	device_state_cb set_state;

	struct blob_attr *config;
	bool empty;
	struct blob_attr *ifnames;
	bool active;
	bool force_active;

	struct uloop_timeout retry;
	struct vlist_tree members;
	int n_present;
	int n_failed;
};

struct extdev_bridge_member {
	struct vlist_node node;
	struct extdev_bridge *parent_br;
	struct device_user dev_usr;
	bool present;
	char *name;
};

static void __bridge_config_init(struct extdev_bridge *ebr);
static enum dev_change_type __bridge_reload(struct extdev_bridge *ebr, struct blob_attr *config);

enum {
	METHOD_CREATE,
	METHOD_CONFIG_INIT,
	METHOD_RELOAD,
	METHOD_DUMP_INFO,
	METHOD_DUMP_STATS,
	METHOD_CHECK_STATE,
	METHOD_FREE,
	METHOD_HOTPLUG_PREPARE,
	METHOD_HOTPLUG_ADD,
	METHOD_HOTPLUG_REMOVE,
	__METHODS_MAX
};

static const char *__extdev_methods[__METHODS_MAX] = {
	[METHOD_CREATE] = "create",
	[METHOD_CONFIG_INIT] = "config_init",
	[METHOD_RELOAD] = "reload",
	[METHOD_DUMP_INFO] = "dump_info",
	[METHOD_DUMP_STATS] = "dump_stats",
	[METHOD_CHECK_STATE] = "check_state",
	[METHOD_FREE] = "free",
	[METHOD_HOTPLUG_PREPARE] = "prepare",
	[METHOD_HOTPLUG_ADD] = "add",
	[METHOD_HOTPLUG_REMOVE] = "remove",
};

static inline int
netifd_extdev_create(struct extdev_device *edev, struct blob_attr *msg)
{
	D(DEVICE, "create %s '%s' at external device handler", edev->dev.type->name,
		edev->dev.ifname);
	return netifd_extdev_invoke(edev->etype->peer_id, __extdev_methods[METHOD_CREATE], msg,
				     NULL, NULL);
}

static inline int
netifd_extdev_reload(struct extdev_device *edev, struct blob_attr *msg)
{
	D(DEVICE, "reload %s '%s' at external device handler", edev->dev.type->name,
		edev->dev.ifname);
	return netifd_extdev_invoke(edev->etype->peer_id, __extdev_methods[METHOD_RELOAD], msg,
				     NULL, NULL);
}

static inline int
netifd_extdev_free(struct extdev_device *edev, struct blob_attr *msg)
{
	D(DEVICE, "delete %s '%s' with external device handler", edev->dev.type->name,
		edev->dev.ifname);
	return netifd_extdev_invoke(edev->etype->peer_id, __extdev_methods[METHOD_FREE], msg,
				     NULL, NULL);
}

static inline int
netifd_extdev_prepare(struct extdev_bridge *ebr, struct blob_attr *msg)
{
	D(DEVICE, "prepare %s bridge '%s' at external device handler", ebr->edev.dev.type->name,
		ebr->edev.dev.ifname);
	return netifd_extdev_invoke(ebr->edev.etype->peer_id,
		__extdev_methods[METHOD_HOTPLUG_PREPARE], msg, NULL, NULL);
}

static inline int
netifd_extdev_add(struct extdev_bridge *ebr, struct blob_attr *msg)
{
	D(DEVICE, "add a member to %s bridge '%s' at external device handler",
	  ebr->edev.dev.type->name, ebr->edev.dev.ifname);
	return netifd_extdev_invoke(ebr->edev.etype->peer_id,
		__extdev_methods[METHOD_HOTPLUG_ADD], msg,NULL, NULL);
}

static inline int
netifd_extdev_remove(struct extdev_bridge *ebr, struct blob_attr *msg)
{
	D(DEVICE, "remove a member from %s bridge '%s' at external device handler",
	  ebr->edev.dev.type->name, ebr->edev.dev.ifname);
	return netifd_extdev_invoke(ebr->edev.etype->peer_id,
		__extdev_methods[METHOD_HOTPLUG_REMOVE], msg, NULL, NULL);
}

static inline void
extdev_invocation_error(int error, const char *method, const char *devname)
{
	netifd_log_message(L_CRIT, "'%s' failed for '%s': %s\n",
		method, devname, ubus_strerror(error));
}

static struct ubus_method extdev_ubus_obj_methods[] = {};

static struct ubus_object_type extdev_ubus_object_type =
	UBUS_OBJECT_TYPE("netifd_extdev", extdev_ubus_obj_methods);

static int
extdev_lookup_id(struct extdev_type *etype)
{
	int ret = UBUS_STATUS_UNKNOWN_ERROR;

	if (!etype || !etype->name)
		goto error;

	ret = ubus_lookup_id(ubus_ctx, etype->name, &etype->peer_id);
	if (ret)
		goto error;

	return 0;

error:
	netifd_log_message(L_CRIT, "Could not find '%s' ubus ID: %s\n",
			   etype->name, ubus_strerror(ret));
	return ret;
}

static int
extdev_ext_ubus_obj_wait(struct ubus_event_handler *h)
{
	return ubus_register_event_handler(ubus_ctx, h, "ubus.object.add");
}

static int
extdev_subscribe(struct extdev_type *etype)
{
	int ret;

	ret = extdev_lookup_id(etype);
	if (ret) {
		etype->subscribed = false;
		return ret;
	}

	ret = ubus_subscribe(ubus_ctx, &etype->ubus_sub, etype->peer_id);
	if (ret) {
		etype->subscribed = false;
		extdev_ext_ubus_obj_wait(&etype->obj_wait);
	} else {
		netifd_log_message(L_NOTICE, "subscribed to external device handler '%s'\n",
			etype->name);
		etype->subscribed = true;
	}

	return ret;
}

static void
extdev_wait_ev_cb(struct ubus_context *ctx, struct ubus_event_handler *ev_handler,
	const char *type, struct blob_attr *msg)
{
	static const struct blobmsg_policy wait_policy = {
		"path", BLOBMSG_TYPE_STRING
	};

	struct blob_attr *attr;
	const char *path;
	struct extdev_type *etype;

	etype = container_of(ev_handler, struct extdev_type, obj_wait);

	if (strcmp(type, "ubus.object.add"))
		return;

	blobmsg_parse(&wait_policy, 1, &attr, blob_data(msg), blob_len(msg));
	if (!attr)
		return;

	path = blobmsg_data(attr);
	if (strcmp(etype->name, path))
		return;

	extdev_subscribe(etype);
}

static int
extdev_bridge_disable_interface(struct extdev_bridge *ebr)
{
	int ret;

	if (!ebr->active)
		return 0;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", ebr->edev.dev.ifname);

	ret = netifd_extdev_free(&ebr->edev, b.head);

	if (ret && ret != UBUS_STATUS_NOT_FOUND)
		goto error;

	ebr->active = false;
	return 0;

error:
	extdev_invocation_error(ret, __extdev_methods[METHOD_FREE], ebr->edev.dev.ifname);
	return ret;
}

static int
extdev_bridge_enable_interface(struct extdev_bridge *ebr)
{
	int ret;

	if (ebr->active)
		return 0;

	ret = netifd_extdev_create(&ebr->edev, ebr->config);
	if (ret)
		goto error;

	ebr->active = true;
	return 0;

error:
	extdev_invocation_error(ret, __extdev_methods[METHOD_CREATE], ebr->edev.dev.ifname);
	return ret;
}

static int
extdev_bridge_enable_member(struct extdev_bridge_member *ubm)
{
	int ret;
	struct extdev_bridge *ebr = ubm->parent_br;

	D(DEVICE, "%s enable member %s", ebr->edev.dev.ifname, ubm->name);

	if (!ubm->present)
		return 0;

	ret = extdev_bridge_enable_interface(ebr);
	if (ret)
		goto error;

	ret = device_claim(&ubm->dev_usr);
	if (ret < 0)
		goto error;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "bridge", ebr->edev.dev.ifname);
	blobmsg_add_string(&b, "member", ubm->dev_usr.dev->ifname);

	/* use hotplug add as addif equivalent. Maybe we need a dedicated ubus
	 * method on the external handler for this sort of operation. */
	ret = netifd_extdev_add(ebr, b.head);
	if (ret) {
		extdev_invocation_error(ret, __extdev_methods[METHOD_HOTPLUG_ADD],
					 ubm->dev_usr.dev->ifname);
		goto error;
	}

	device_set_present(&ebr->edev.dev, true);
	device_broadcast_event(&ebr->edev.dev, DEV_EVENT_TOPO_CHANGE);

	return 0;

error:
	D(DEVICE, "%s: failed to enable member '%s'", ebr->edev.dev.ifname, ubm->name);

	ebr->n_failed++;
	ubm->present = false;
	ebr->n_present--;

	return ret;
}

static int
extdev_bridge_disable_member(struct extdev_bridge_member *ubm)
{
	int ret;
	struct extdev_bridge *ebr = ubm->parent_br;

	if (!ubm->present)
		return 0;

	D(DEVICE, "%s disable member %s", ubm->parent_br->edev.dev.ifname, ubm->name);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "bridge", ebr->edev.dev.ifname);
	blobmsg_add_string(&b, "member", ubm->dev_usr.dev->ifname);

	/* use hotplug remove as delif equivalent. Maybe we need a dedicated
	 * ubus method on the external handler for this sort of operation. */
	ret = netifd_extdev_remove(ebr, b.head);

	/* continue in case of NOT FOUND since we're trying to remove anyway */
	if (ret && ret != UBUS_STATUS_NOT_FOUND)
		goto error;

	device_release(&ubm->dev_usr);
	device_broadcast_event(&ebr->edev.dev, DEV_EVENT_TOPO_CHANGE);

	return 0;

error:
	extdev_invocation_error(ret, __extdev_methods[METHOD_HOTPLUG_REMOVE],
			ubm->dev_usr.dev->ifname);

	return ret;
}

static int
extdev_bridge_set_down(struct extdev_bridge *ebr)
{
	D(DEVICE, "set %s bridge %s down", ebr->edev.dev.type->name, ebr->edev.dev.ifname);

	struct extdev_bridge_member *ubm;

	ebr->set_state(&ebr->edev.dev, false);

	vlist_for_each_element(&ebr->members, ubm, node)
		extdev_bridge_disable_member(ubm);

	extdev_bridge_disable_interface(ebr);

	return 0;
}

static void
extdev_bridge_check_retry(struct extdev_bridge *ebr)
{
	if (!ebr->n_failed)
		return;

	uloop_timeout_set(&ebr->retry, 200);
}

static int
extdev_bridge_set_up(struct extdev_bridge *ebr)
{
	D(DEVICE, "set %s bridge %s up", ebr->edev.dev.type->name, ebr->edev.dev.ifname);

	struct extdev_bridge_member *ubm;
	int ret;

	if (!ebr->n_present) {
		if (!ebr->force_active)
			return -ENOENT;

		ret = extdev_bridge_enable_interface(ebr);
		if (ret)
			return ret;
	}

	ebr->n_failed = 0;
	vlist_for_each_element(&ebr->members, ubm, node)
		extdev_bridge_enable_member(ubm);

	extdev_bridge_check_retry(ebr);

	if (!ebr->force_active && !ebr->n_present) {
		extdev_bridge_disable_interface(ebr);
		device_set_present(&ebr->edev.dev, false);
		return -ENOENT;
	}

	return 0;
}

static int
extdev_bridge_set_state(struct device *dev, bool up)
{
	struct extdev_bridge *ebr;

	if (!dev->type->bridge_capability)
		return -1;

	ebr = container_of(dev, struct extdev_bridge, edev.dev);

	if (up)
		return extdev_bridge_set_up(ebr);
	else
		return extdev_bridge_set_down(ebr);
}

static void
extdev_bridge_remove_member(struct extdev_bridge_member *member)
{
	struct extdev_bridge *ebr = member->parent_br;

	if (!member->present)
		return;

	if (ebr->edev.dev.active)
		extdev_bridge_disable_member(member);

	member->present = false;
	ebr->n_present--;

	if (ebr->empty)
		return;

	ebr->force_active = false;
	if (ebr->n_present == 0)
		device_set_present(&ebr->edev.dev, false);
}

static void
extdev_bridge_member_cb(struct device_user *usr, enum device_event event)
{
	int ret;
	struct extdev_bridge_member *ubm;
	struct extdev_bridge *ebr;

	ubm = container_of(usr, struct extdev_bridge_member, dev_usr);
	ebr = ubm->parent_br;

	switch (event) {
		case DEV_EVENT_ADD:
			assert(!ubm->present);

			ubm->present = true;
			ebr->n_present++;

			/* if this member is the first one that is brought up,
			 * create the bridge at the external device handler */
			if (ebr->n_present == 1) {
				ret = netifd_extdev_create(&ebr->edev, ebr->config);
				if (ret)
					goto error;

				ebr->active = true;
				ret = ebr->set_state(&ebr->edev.dev, true);
				if (ret < 0)
					extdev_bridge_set_down(ebr);
				device_set_present(&ebr->edev.dev, true);
			}

			extdev_bridge_enable_member(ubm);
			break;
		case DEV_EVENT_REMOVE:
			if (usr->hotplug) {
				vlist_delete(&ebr->members, &ubm->node);
				return;
			}

			if (ubm->present)
				extdev_bridge_remove_member(ubm);
			break;
		default:
			break;
	}

	return;

error:
	netifd_log_message(L_CRIT, "Failed to create %s bridge %s: %s\n",
			   ebr->edev.dev.type->name, ebr->edev.dev.ifname, ubus_strerror(ret));
	ubm->present = false;
	ebr->n_present--;
}

static void
__bridge_enable_members(struct extdev_bridge *ebr)
{
	struct extdev_bridge_member *cur;

	ebr->n_failed = 0;

	vlist_for_each_element(&ebr->members, cur, node) {
		if (cur->present)
			continue;

		if (!cur->dev_usr.dev->present)
			continue;

		cur->present = true;
		ebr->n_present++;
		extdev_bridge_enable_member(cur);
	}
}

static void
extdev_bridge_retry_enable_members(struct uloop_timeout *timeout)
{
	struct extdev_bridge *ebr = container_of(timeout, struct extdev_bridge, retry);

	D(DEVICE, "%s retry enable members", ebr->edev.dev.ifname);

	__bridge_enable_members(ebr);
}

static struct extdev_bridge_member *
extdev_bridge_create_member(struct extdev_bridge *ebr, struct device *dev)
{
	struct extdev_bridge_member *ubm;
	char *name;

	ubm = calloc_a(sizeof(*ubm), &name, strlen(dev->ifname) + 1);
	if (!ubm)
		return NULL;

	ubm->parent_br = ebr;
	ubm->name = name;
	strcpy(name, dev->ifname);
	ubm->dev_usr.dev = dev;
	ubm->dev_usr.cb = extdev_bridge_member_cb;
	vlist_add(&ebr->members, &ubm->node, ubm->name);
	/* Need to look up the bridge member again as the above
	 * created pointer will be freed in case the bridge member
	 * already existed */
	ubm = vlist_find(&ebr->members, dev->ifname, ubm, node);
	if (!ubm)
		return NULL;

	return ubm;
}

static void
extdev_bridge_add_member(struct extdev_bridge *ebr, const char *name)
{
	D(DEVICE, "%s add member %s", ebr->edev.dev.ifname, name);

	struct device *dev;

	dev = device_get(name, 1);
	if (!dev)
		return;

	extdev_bridge_create_member(ebr, dev);
}

/* TODO: how to handle vlan arg? */
static int
extdev_hotplug_add(struct device *ebr_dev, struct device *ebm_dev, struct blob_attr *vlan)
{
	D(DEVICE, "%s hotplug add member %s", ebr_dev->ifname, ebm_dev->ifname);

	struct extdev_bridge *ebr;
	struct extdev_bridge_member *ubm;

	if (!ebr_dev->type->bridge_capability)
		return UBUS_STATUS_NOT_SUPPORTED;

	ebr = container_of(ebr_dev, struct extdev_bridge, edev.dev);

	if (!ebr->edev.etype->subscribed)
		return UBUS_STATUS_NOT_FOUND;

	ubm = extdev_bridge_create_member(ebr, ebm_dev);
	if (!ubm)
		return UBUS_STATUS_UNKNOWN_ERROR;

	device_broadcast_event(&ebr->edev.dev, DEV_EVENT_TOPO_CHANGE);

	return 0;
}

static int
extdev_hotplug_remove(struct device *dev, struct device *member, struct blob_attr *vlan)
{
	struct extdev_bridge *ebr;
	struct extdev_bridge_member *ubm;

	if (!dev->type->bridge_capability)
		return UBUS_STATUS_NOT_SUPPORTED;

	ebr = container_of(dev, struct extdev_bridge, edev.dev);

	if (!ebr->edev.etype->subscribed)
		return UBUS_STATUS_NOT_FOUND;

	ubm = vlist_find(&ebr->members, member->ifname, ubm, node);
	if (!ubm)
		return UBUS_STATUS_NOT_FOUND;

	vlist_delete(&ebr->members, &ubm->node);
	extdev_bridge_remove_member(ubm);

	return 0;
}

static int
extdev_hotplug_prepare(struct device *dev, struct device **bridge_dev)
{
	struct extdev_bridge *ebr;
	int ret;

	if (!dev->type->bridge_capability)
		return UBUS_STATUS_NOT_SUPPORTED;

	if (bridge_dev)
		*bridge_dev = dev;

	ebr = container_of(dev, struct extdev_bridge, edev.dev);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", dev->ifname);

	ret = netifd_extdev_prepare(ebr, b.head);
	if (ret)
		goto error;

	ebr->force_active = true;
	device_set_present(&ebr->edev.dev, true);

	return 0;

error:
	extdev_invocation_error(ret, __extdev_methods[METHOD_HOTPLUG_PREPARE], dev->ifname);
	return ret;
}

static void
extdev_bridge_free_member(struct extdev_bridge_member *ubm)
{
	struct device *dev = ubm->dev_usr.dev;

	extdev_bridge_remove_member(ubm);
	device_remove_user(&ubm->dev_usr);

	if (dev->present) {
		device_set_present(dev, false);
		device_set_present(dev, true);
	}

	free(ubm);
}

static void
extdev_bridge_member_update(struct vlist_tree *tree, struct vlist_node *node_new,
			     struct vlist_node *node_old)
{
	struct extdev_bridge_member *ubm;
	struct device *dev;

	if (node_new) {
		ubm = container_of(node_new, struct extdev_bridge_member, node);

		if (node_old) {
			free(ubm);
			return;
		}

		dev = ubm->dev_usr.dev;
		ubm->dev_usr.dev = NULL;
		device_add_user(&ubm->dev_usr, dev);
	}

	if (node_old) {
		ubm = container_of(node_old, struct extdev_bridge_member, node);
		extdev_bridge_free_member(ubm);
	}
}


static void
bridge_dependency_retry(struct uloop_timeout *timeout)
{
	struct extdev_bridge *ebr;

	ebr = container_of(timeout, struct extdev_bridge, edev.retry);

	__bridge_reload(ebr, NULL);
}

static void
__buf_add_all(struct blob_attr *attr)
{
	struct blob_attr *cur;
	size_t rem;

	blobmsg_for_each_attr(cur, attr, rem)
		blobmsg_add_field(&b, blobmsg_type(cur), blobmsg_name(cur), blobmsg_data(cur),
			blobmsg_data_len(cur));
}

enum {
	BRIDGE_EMPTY,
	BRIDGE_IFNAMES,
	BRIDGE_DEPENDS_ON,
	__BRIDGE_MAX
};

static const struct blobmsg_policy brpol[__BRIDGE_MAX] = {
	[BRIDGE_EMPTY] = { "empty",  BLOBMSG_TYPE_BOOL },
	[BRIDGE_IFNAMES] = { "ifname", BLOBMSG_TYPE_ARRAY },
	[BRIDGE_DEPENDS_ON] = { "depends_on", BLOBMSG_TYPE_STRING },
};

static enum dev_change_type
__do_bridge_reload(struct extdev_bridge *ebr, struct blob_attr *config)
{
	void *cfg_table;
	int ret;

	blob_buf_init(&b, 0);
	cfg_table = blobmsg_open_table(&b, "old");
	__buf_add_all(ebr->config);
	blobmsg_close_table(&b, cfg_table);
	cfg_table = blobmsg_open_table(&b, "new");
	__buf_add_all(config);
	blobmsg_close_table(&b, cfg_table);

	ret = netifd_extdev_reload(&ebr->edev, b.head);

	if (ret) {
		netifd_log_message(L_WARNING, "%s config reload failed: %s\n",
				   ebr->edev.dev.ifname, ubus_strerror(ret));
		return DEV_CONFIG_RECREATE;
	} else {
		return DEV_CONFIG_RESTART;
	}
}

static enum dev_change_type
__bridge_reload(struct extdev_bridge *ebr, struct blob_attr *config)
{
	int n_params = ebr->edev.dev.type->config_params->n_params;
	struct blob_attr *tb[__BRIDGE_MAX];
	const struct uci_blob_param_list *config_params;
	const struct blobmsg_policy *pol;
	struct blob_attr *old_tb[n_params], *brtb[n_params];
	enum dev_change_type change = DEV_CONFIG_APPLIED;
	struct device *dev;
	unsigned long diff = 0;

	if (config) {
		config = blob_memdup(config);
		blobmsg_parse(brpol, __BRIDGE_MAX, tb, blobmsg_data(config), blobmsg_len(config));
		ebr->edev.dep_name = blobmsg_get_string(tb[BRIDGE_DEPENDS_ON]);

		if (tb[BRIDGE_EMPTY] && blobmsg_get_bool(tb[BRIDGE_EMPTY]))
			ebr->empty = true;

		if (ebr->config) {
			config_params = ebr->edev.dev.type->config_params;
			pol = config_params->params;

			blobmsg_parse(pol, n_params, old_tb, blobmsg_data(ebr->config),
				blobmsg_len(ebr->config));
			blobmsg_parse(pol, n_params, brtb, blobmsg_data(config), blobmsg_len
			(config));

			diff = 0;
			uci_blob_diff(brtb, old_tb, config_params, &diff);
			if (diff) {
				if (diff & ~(1 << BRIDGE_IFNAMES)) {
					change = DEV_CONFIG_RESTART;
				} else {
					change = __do_bridge_reload(ebr, config);
				}

				free(ebr->config);
			}
		}

		ebr->ifnames = tb[BRIDGE_IFNAMES];
		ebr->config = config;
	}

	if (ebr->edev.dep_name) {
		dev = device_get(ebr->edev.dep_name, 0);
		if (!(dev && dev->current_config)) {
			D(DEVICE, "%s: cannot yet init config since dependency '%s' is not ready",
			  ebr->edev.dev.ifname, ebr->edev.dep_name);
			ebr->edev.retry.cb = bridge_dependency_retry;
			uloop_timeout_set(&ebr->edev.retry, 200);
			return DEV_CONFIG_RESTART;
		}
	}

	__bridge_config_init(ebr);
	ebr->edev.dev.config_pending = false;
	uloop_timeout_cancel(&ebr->edev.retry);

	return change;
}

static enum dev_change_type
__reload(struct extdev_device *edev, struct blob_attr *config)
{
	unsigned long diff = 0;
	struct uci_blob_param_list *params;

	params = edev->etype->config_params;

	struct blob_attr *tb[params->n_params];
	struct blob_attr *old_tb[params->n_params];

	blobmsg_parse(params->params, params->n_params,	tb, blobmsg_data(config),
		blobmsg_len(config));
	blobmsg_parse(params->params, params->n_params,	old_tb, blobmsg_data(edev->dev.config),
		blobmsg_len(edev->dev.config));

	uci_blob_diff(tb, old_tb, edev->etype->config_params, &diff);
	if (!diff)
		return DEV_CONFIG_NO_CHANGE;

	// TODO: make reload ubus call with old and new config

	device_set_present(&edev->dev, false);
	device_set_present(&edev->dev, true);

	return DEV_CONFIG_APPLIED;
}

static enum dev_change_type
extdev_reload(struct device *dev, struct blob_attr *config)
{
	struct extdev_type *etype;
	struct extdev_device *edev;
	struct extdev_bridge *ebr;

	etype = container_of(dev->type, struct extdev_type, handler);

	if (!etype->subscribed)
		return DEV_CONFIG_NO_CHANGE;

	edev = container_of(dev, struct extdev_device, dev);

	if (dev->type->bridge_capability) {
		ebr = container_of(edev, struct extdev_bridge, edev);
		return __bridge_reload(ebr, config);
	} else {
		return __reload(edev, config);
	}
}

static struct device*
__create(const char *name, struct device_type *type, struct blob_attr *config)
{
	struct extdev_device *edev;
	struct extdev_type *etype;
	int ret;

	etype = container_of(type, struct extdev_type, handler);
	edev = calloc(1, sizeof(struct extdev_device));
	if (!edev)
		return NULL;

	ret = device_init(&edev->dev, type, name);
	if (ret)
		goto error;

	edev->etype = etype;

	ret = netifd_extdev_create(edev, config);
	if (ret)
		goto inv_error;

	edev->dev.config_pending = false;

	return &edev->dev;

inv_error:
	extdev_invocation_error(ret, __extdev_methods[METHOD_CREATE], name);
error:
	free(edev->dev.config);
	device_cleanup(&edev->dev);
	free(edev);
	netifd_log_message(L_WARNING, "Failed to create %s %s\n", type->name, name);
	return NULL;
}

static const struct device_hotplug_ops extdev_hotplug_ops = {
	.prepare = extdev_hotplug_prepare,
	.add = extdev_hotplug_add,
	.del = extdev_hotplug_remove
};

static struct device*
__bridge_create(const char *name, struct device_type *devtype, struct blob_attr *config)
{
	struct extdev_bridge *ebr;

	ebr = calloc(1, sizeof(*ebr));
	if (!ebr)
		return NULL;

	device_init(&ebr->edev.dev, devtype, name);
	ebr->edev.dev.config_pending = true;
	ebr->retry.cb = extdev_bridge_retry_enable_members;
	ebr->edev.etype = container_of(devtype, struct extdev_type, handler);
	ebr->set_state = ebr->edev.dev.set_state;
	ebr->edev.dev.set_state = extdev_bridge_set_state;
	ebr->edev.dev.hotplug_ops = &extdev_hotplug_ops;
	vlist_init(&ebr->members, avl_strcmp, extdev_bridge_member_update);
	ebr->members.keep_old = true;
	__bridge_reload(ebr, config);

	return &ebr->edev.dev;
}

/* Device creation process:
 * For bridges without dependencies:
 *  1) The bridge state is initialized in netifd. Devices for the members are
 *     created and added to the members vlist by config_init automatically.
 *  2) When the first bridge member device is brought up in
 *     extdev_bridge_enable_member the 'create' call to the external device
 *     handler is issued.
 *  3) After successful device creation the bridge is marked "present" and a
 *     new attempt at adding the member is made.
 * For bridges with dependencies:
 *  1) The bridge state is initialized in netifd. If a dependency is expressed
 *     via the 'depends_on' UCI option and the dependency is not ready (i.e. it
 *     does not exist or config_pending == true) the call to
 *     __bridge_config_init() is postponed and a retry timer is started. Retries
 *     happen until the dependency is ready. Then, __bridge_config_init() gets
 *     called and the process continues as with bridges without dependencies
 * For regular devices:
 *  1) The device structure is created in netifd.
 *  2) config_init is called automatically which issues the 'create' call to the
 *     external device handler.
 */
static struct device *
extdev_create(const char *name, struct device_type *devtype, struct blob_attr *config)
{
	struct extdev_type *etype = container_of(devtype, struct extdev_type, handler);

	if (!etype->subscribed)
		return NULL;

	if (devtype->bridge_capability)
		return __bridge_create(name, devtype, config);
	else
		return __create(name, devtype, config);
}

static void
extdev_free(struct device *dev)
{
	struct extdev_type *etype;
	struct extdev_device *edev;
	struct extdev_bridge *ebr;
	int ret;

	etype = container_of(dev->type, struct extdev_type, handler);
	edev = container_of(dev, struct extdev_device, dev);

	if (!etype->subscribed)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", dev->ifname);

	ret = netifd_extdev_free(edev, b.head);

	if (ret && ret != UBUS_STATUS_NOT_FOUND)
		goto error;

	if (dev->type->bridge_capability) {
		ebr = container_of(dev, struct extdev_bridge, edev.dev);

		vlist_flush_all(&ebr->members);
//		vlist_flush_all(&dev->vlans); TODO: do we need this?

		free(ebr->config);
		free(ebr);
	}

	return;

error:
	extdev_invocation_error(ret, __extdev_methods[METHOD_FREE],
		dev->ifname);
}

static void
__bridge_config_init(struct extdev_bridge *ebr)
{
	int ret;
	size_t rem;
	struct blob_attr *cur;

	if (ebr->empty) {
		ebr->force_active = true;
		ret = netifd_extdev_create(&ebr->edev, ebr->config);
		if (ret)
			goto error;
		device_set_present(&ebr->edev.dev, true);
	}

	ebr->n_failed = 0;
	vlist_update(&ebr->members);
	if (ebr->ifnames) {
		blobmsg_for_each_attr(cur, ebr->ifnames, rem)
			extdev_bridge_add_member(ebr, blobmsg_data(cur));
	}

	vlist_flush(&ebr->members);
	extdev_bridge_check_retry(ebr);
	return;

error:
	fprintf(stderr, "Failed to init config for '%s': %s\n", ebr->edev.dev.ifname,
		ubus_strerror(ret));
}

static void
extdev_config_init(struct device *dev)
{
	struct extdev_type *etype;
	struct extdev_bridge *ebr;

	etype = container_of(dev->type, struct extdev_type, handler);

	if (!etype->subscribed)
		return;

	if (dev->type->bridge_capability) {
		ebr = container_of(dev, struct extdev_bridge, edev.dev);
		__bridge_config_init(ebr);
	}
}

static void
extdev_buf_add_list(struct blob_attr *attr, size_t len, const char *name,
		     struct blob_buf *buf, bool array)
{
	struct blob_attr *cur;
	struct blobmsg_hdr *hdr;
	void *list;
	int type;

	if (array)
		list = blobmsg_open_array(buf, name);
	else
		list = blobmsg_open_table(buf, name);

	blobmsg_for_each_attr(cur, attr, len) {
		hdr = blob_data(cur);
		type = blobmsg_type(cur);
		switch (type) {
			case BLOBMSG_TYPE_STRING:
				blobmsg_add_string(buf, (char *) hdr->name,
					blobmsg_get_string(cur));
				break;
			case BLOBMSG_TYPE_TABLE:
			case BLOBMSG_TYPE_ARRAY:
				extdev_buf_add_list(blobmsg_data(cur), blobmsg_data_len(cur),
					(char *) hdr->name, buf, type == BLOBMSG_TYPE_ARRAY);
				break;
			case BLOBMSG_TYPE_INT64:
				blobmsg_add_u64(buf, (char *) hdr->name, blobmsg_get_u64(cur));
				break;
			case BLOBMSG_TYPE_INT32:
				blobmsg_add_u32(buf, (char *) hdr->name, blobmsg_get_u32(cur));
				break;
			case BLOBMSG_TYPE_INT16:
				blobmsg_add_u16(buf, (char *) hdr->name, blobmsg_get_u16(cur));
				break;
			case BLOBMSG_TYPE_INT8:
				blobmsg_add_u8(buf, (char *) hdr->name, blobmsg_get_u8(cur));
				break;
			default:
				break;
		}
	}

	if (array)
		blobmsg_close_array(buf, list);
	else
		blobmsg_close_table(buf, list);
}

static void
add_parsed_data(struct blob_attr **tb, const struct blobmsg_policy *policy, int n_params,
		struct blob_buf *buf)
{
	for (int i = 0; i < n_params; i++) {
		if (!tb[i])
			continue;

		switch (policy[i].type) {
			case BLOBMSG_TYPE_STRING:
				blobmsg_add_string(buf, policy[i].name, blobmsg_get_string(tb[i]));
				break;
			case BLOBMSG_TYPE_ARRAY:
			case BLOBMSG_TYPE_TABLE:
				extdev_buf_add_list(blobmsg_data(tb[i]), blobmsg_data_len(tb[i]),
					policy[i].name, buf, policy[i].type == BLOBMSG_TYPE_ARRAY);
				break;
			case BLOBMSG_TYPE_INT64:
				blobmsg_add_u64(buf, policy[i].name, blobmsg_get_u64(tb[i]));
				break;
			case BLOBMSG_TYPE_INT32:
				blobmsg_add_u32(buf, policy[i].name, blobmsg_get_u32(tb[i]));
				break;
			case BLOBMSG_TYPE_INT16:
				blobmsg_add_u16(buf, policy[i].name, blobmsg_get_u16(tb[i]));
				break;
			case BLOBMSG_TYPE_INT8:
				blobmsg_add_u8(buf, policy[i].name, blobmsg_get_u8(tb[i]));
				break;
			default:
				break;
		}
	}
}

struct dump_data {
	const struct device *dev;
	struct blob_buf *buf;
};

static void
dump_cb(struct ubus_request *req, int type, struct blob_attr *reply)
{
	struct dump_data *data;
	struct extdev_type *etype;
	const struct blobmsg_policy *info_policy;
	int n_params;
	struct blob_buf *buf;

	data = req->priv;
	etype = container_of(data->dev->type, struct extdev_type, handler);
	info_policy = etype->info_params->params;
	n_params = etype->info_params->n_params;
	buf = data->buf;

	struct blob_attr *tb[n_params];

	blobmsg_parse(info_policy, n_params, tb, blobmsg_data(reply), blobmsg_len(reply));
	add_parsed_data(tb, info_policy, n_params, buf);
}

static void
extdev_dump(const char *method, struct device *dev, struct blob_buf *buf)
{
	static struct dump_data data;
	struct extdev_type *etype;

	etype = container_of(dev->type, struct extdev_type, handler);

	if (!etype->subscribed)
		return;

	data.dev = dev;
	data.buf = buf;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", dev->ifname);

	netifd_extdev_invoke(etype->peer_id, method, b.head, dump_cb, &data);
}

static void
extdev_dump_info(struct device *dev, struct blob_buf *buf)
{
	extdev_dump(__extdev_methods[METHOD_DUMP_INFO], dev, buf);
}

static void
extdev_dump_stats(struct device *dev, struct blob_buf *buf)
{
	extdev_dump(__extdev_methods[METHOD_DUMP_STATS], dev, buf);
}

static void
extdev_ext_handler_remove_cb(struct ubus_context *ctx,
			      struct ubus_subscriber *obj, uint32_t id)
{
	struct extdev_type *etype;
	etype = container_of(obj, struct extdev_type, ubus_sub);

	netifd_log_message(L_NOTICE, "%s: external device handler "
		"'%s' disappeared. Waiting for it to re-appear.\n",
		etype->handler.name, etype->name);

	etype->peer_id = 0;
	etype->subscribed = false;

	extdev_ext_ubus_obj_wait(&etype->obj_wait);
}

static void
extdev_add_devtype(const char *cfg_file, const char *tname, const char *ubus_name,
		    bool bridge_capability, const char *br_prefix, json_object *cfg_obj,
		    json_object *info_obj, json_object *stats_obj)
{
	static const char *OBJ_PREFIX = "network.device.";

	struct extdev_type *etype;
	struct device_type *devtype;
	char *ubus_obj_name, *devtype_name, *ext_dev_handler_name, *name_prefix;
	struct uci_blob_param_list *config_params, *info_params, *stats_params;
	int ret;

	etype = calloc_a(sizeof(*etype),
		&ubus_obj_name, strlen(OBJ_PREFIX) + strlen(ubus_name) + 1,
		&devtype_name, strlen(tname) + 1,
		&ext_dev_handler_name, strlen(ubus_name) + 1,
		&config_params, sizeof(struct uci_blob_param_list),
		&info_params, sizeof(struct uci_blob_param_list),
		&stats_params, sizeof(struct uci_blob_param_list));

	if (!etype)
		return;

	etype->config_params = config_params;
	etype->info_params = info_params;
	etype->name = strcpy(ext_dev_handler_name, ubus_name);

	devtype = &etype->handler;
	devtype->name = strcpy(devtype_name, tname);
	devtype->create = extdev_create;
	devtype->free = extdev_free;
	devtype->config_init = extdev_config_init;
	devtype->reload = extdev_reload;
	devtype->dump_info = extdev_dump_info;
	devtype->dump_stats = extdev_dump_stats;
	devtype->bridge_capability = bridge_capability;
	devtype->config_params = etype->config_params;

	if (bridge_capability) {
		name_prefix = malloc(strlen(br_prefix) + 1);
		if (!name_prefix)
			goto error;

		strcpy(name_prefix, br_prefix);
		devtype->name_prefix = name_prefix;
	}

	/* subscribe to external device handler */
	sprintf(ubus_obj_name, "%s%s", OBJ_PREFIX,  ubus_name);
	etype->ubus_sub.obj.name = ubus_obj_name;
	etype->ubus_sub.obj.type = &extdev_ubus_object_type;
	ret = ubus_register_subscriber(ubus_ctx, &etype->ubus_sub);
	if (ret) {
		fprintf(stderr, "Failed to register subscriber object '%s'\n",
			etype->ubus_sub.obj.name);
		goto error;
	}
	etype->obj_wait.cb = extdev_wait_ev_cb;
	etype->ubus_sub.remove_cb = extdev_ext_handler_remove_cb;
	extdev_subscribe(etype);

	/* parse config params from JSON object */
	etype->config_strbuf = netifd_handler_parse_config(etype->config_params, cfg_obj);
	if (!etype->config_strbuf)
		goto error;

	/* parse info dump params from JSON object */
	if (!info_obj) {
		devtype->dump_info = NULL;
	} else {
		etype->info_strbuf = netifd_handler_parse_config(etype->info_params, info_obj);
		if (!etype->info_strbuf)
			devtype->dump_info = NULL;
	}

	/* parse statistics dump params from JSON object */
	if (!stats_obj) {
		devtype->dump_stats = NULL;
	} else {
		etype->stats_strbuf = netifd_handler_parse_config(etype->stats_params, stats_obj);
		if (!etype->stats_strbuf)
			devtype->dump_stats = NULL;
	}

	ret = device_type_add(devtype);
	if (ret)
		goto config_error;

	return;

config_error:
	free(etype->config_strbuf);
	free(etype->info_strbuf);
	free(etype->stats_strbuf);

error:
	fprintf(stderr, "Failed to create device handler for device"
		"type '%s' from file '%s'\n", tname, cfg_file);
	free(ubus_obj_name);
	free(devtype_name);
	free(etype);
}

/* create extdev device handler stubs from JSON description */
void
extdev_init(void)
{
	confdir_fd = netifd_open_subdir("extdev-config");
	if (confdir_fd < 0)
		return;
	netifd_init_extdev_handlers(confdir_fd, extdev_add_devtype);
}
