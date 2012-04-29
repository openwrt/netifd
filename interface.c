#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"
#include "ubus.h"
#include "config.h"
#include "system.h"

struct vlist_tree interfaces;

enum {
	IFACE_ATTR_IFNAME,
	IFACE_ATTR_PROTO,
	IFACE_ATTR_AUTO,
	IFACE_ATTR_DEFAULTROUTE,
	IFACE_ATTR_METRIC,
	IFACE_ATTR_MAX
};

static const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_AUTO] = { .name = "auto", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_DEFAULTROUTE] = { .name = "defaultroute", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_METRIC] = { .name = "metric", .type = BLOBMSG_TYPE_INT32 },
};

const struct config_param_list interface_attr_list = {
	.n_params = IFACE_ATTR_MAX,
	.params = iface_attrs,
};

static void
interface_clear_errors(struct interface *iface)
{
	struct interface_error *error, *tmp;

	list_for_each_entry_safe(error, tmp, &iface->errors, list) {
		list_del(&error->list);
		free(error);
	}
}

void interface_add_error(struct interface *iface, const char *subsystem,
			 const char *code, const char **data, int n_data)
{
	struct interface_error *error;
	int i, len = 0;
	int *datalen = NULL;
	char *dest;

	if (n_data) {
		len = n_data * sizeof(char *);
		datalen = alloca(len);
		for (i = 0; i < n_data; i++) {
			datalen[i] = strlen(data[i]) + 1;
			len += datalen[i];
		}
	}

	error = calloc(1, sizeof(*error) + sizeof(char *) + len);
	if (!error)
		return;

	list_add_tail(&error->list, &iface->errors);
	error->subsystem = subsystem;
	error->code = code;

	dest = (char *) &error->data[n_data + 1];
	for (i = 0; i < n_data; i++) {
		error->data[i] = dest;
		memcpy(dest, data[i], datalen[i]);
		dest += datalen[i];
	}
	error->data[n_data] = NULL;
}

static void
interface_data_del(struct interface *iface, struct interface_data *data)
{
	avl_delete(&iface->data, &data->node);
	free(data);
}

static void
interface_data_flush(struct interface *iface)
{
	struct interface_data *d, *tmp;

	avl_for_each_element_safe(&iface->data, d, node, tmp)
		interface_data_del(iface, d);
}

int
interface_add_data(struct interface *iface, const struct blob_attr *data)
{
	struct interface_data *n, *o;

	if (!blobmsg_check_attr(data, true))
		return UBUS_STATUS_INVALID_ARGUMENT;

	n = calloc(1, sizeof(*data) + blob_pad_len(data));
	memcpy(n->data, data, blob_pad_len(data));
	n->node.key = blobmsg_name(data);

	o = avl_find_element(&iface->data, n->node.key, o, node);
	if (o)
		interface_data_del(iface, o);

	avl_insert(&iface->data, &n->node);
	return 0;
}

static void
interface_event(struct interface *iface, enum interface_event ev)
{
	struct interface_user *dep, *tmp;

	list_for_each_entry_safe(dep, tmp, &iface->users, list)
		dep->cb(dep, IFEV_UP);

	interface_queue_event(iface, ev);
}

static void
interface_flush_state(struct interface *iface)
{
	if (iface->main_dev.dev)
		device_release(&iface->main_dev);
	if (iface->l3_dev.dev)
		device_release(&iface->l3_dev);
	interface_data_flush(iface);
}

static void
mark_interface_down(struct interface *iface)
{
	if (iface->state == IFS_UP)
		interface_event(iface, IFEV_DOWN);
	interface_ip_set_enabled(&iface->config_ip, false);
	interface_ip_flush(&iface->proto_ip);
	interface_flush_state(iface);
	iface->state = IFS_DOWN;
}

void
__interface_set_down(struct interface *iface, bool force)
{
	interface_clear_errors(iface);

	if (iface->state == IFS_DOWN ||
		iface->state == IFS_TEARDOWN)
		return;

	if (iface->state == IFS_UP)
		interface_event(iface, IFEV_DOWN);
	iface->state = IFS_TEARDOWN;
	interface_proto_event(iface->proto, PROTO_CMD_TEARDOWN, force);
	if (force)
		interface_flush_state(iface);
}

static void
interface_cb(struct device_user *dep, enum device_event ev)
{
	struct interface *iface;
	bool new_state;

	iface = container_of(dep, struct interface, main_dev);
	switch (ev) {
	case DEV_EVENT_ADD:
		new_state = true;
		break;
	case DEV_EVENT_REMOVE:
		new_state = false;
		break;
	default:
		return;
	}

	interface_set_available(iface, new_state);
}

void
interface_set_available(struct interface *iface, bool new_state)
{
	if (iface->available == new_state)
		return;

	D(INTERFACE, "Interface '%s', available=%d\n", iface->name, new_state);
	iface->available = new_state;

	if (new_state) {
		if (iface->autostart && !config_init)
			interface_set_up(iface);
	} else
		__interface_set_down(iface, true);
}

void
interface_add_user(struct interface_user *dep, struct interface *iface)
{
	dep->iface = iface;
	list_add(&dep->list, &iface->users);
	if (iface->state == IFS_UP)
		dep->cb(dep, IFEV_UP);
}

void
interface_remove_user(struct interface_user *dep)
{
	list_del_init(&dep->list);
	dep->iface = NULL;
}

static void
interface_claim_device(struct interface *iface)
{
	struct device *dev;

	if (iface->ifname &&
		!(iface->proto_handler->flags & PROTO_FLAG_NODEV)) {
		dev = device_get(iface->ifname, true);
		if (dev)
			interface_set_main_dev(iface, dev);
	}
	if (iface->proto_handler->flags & PROTO_FLAG_INIT_AVAILABLE)
		interface_set_available(iface, true);
}


static void
interface_cleanup(struct interface *iface, bool reload)
{
	struct interface_user *dep, *tmp;

	list_for_each_entry_safe(dep, tmp, &iface->users, list)
		interface_remove_user(dep);

	interface_dequeue_event(iface);
	interface_ip_flush(&iface->config_ip);
	interface_flush_state(iface);
	interface_clear_errors(iface);
	if (iface->main_dev.dev &&
	    (!reload || !iface->main_dev.hotplug))
		interface_set_main_dev(iface, NULL);
	interface_set_proto_state(iface, NULL);
}

static void
interface_do_free(struct interface *iface)
{
	interface_cleanup(iface, false);
	free(iface->config);
	netifd_ubus_remove_interface(iface);
	avl_delete(&interfaces.avl, &iface->node.avl);
	free(iface);
}

static void
interface_do_reload(struct interface *iface)
{
	interface_cleanup(iface, true);
	proto_init_interface(iface, iface->config);
	interface_claim_device(iface);
}

static void
interface_handle_config_change(struct interface *iface)
{
	switch(iface->config_state) {
	case IFC_NORMAL:
		break;
	case IFC_RELOAD:
		interface_do_reload(iface);
		break;
	case IFC_REMOVE:
		interface_do_free(iface);
		return;
	}
	if (iface->autostart && iface->available)
		interface_set_up(iface);
}

static void
interface_proto_cb(struct interface_proto_state *state, enum interface_proto_event ev)
{
	struct interface *iface = state->iface;

	switch (ev) {
	case IFPEV_UP:
		if (iface->state != IFS_SETUP)
			return;

		interface_ip_set_enabled(&iface->config_ip, true);
		system_flush_routes();
		iface->state = IFS_UP;
		iface->start_time = system_get_rtime();
		interface_event(iface, IFEV_UP);
		interface_write_resolv_conf();
		netifd_log_message(L_NOTICE, "Interface '%s' is now up\n", iface->name);
		break;
	case IFPEV_DOWN:
		if (iface->state == IFS_DOWN)
			return;

		netifd_log_message(L_NOTICE, "Interface '%s' is now down\n", iface->name);
		mark_interface_down(iface);
		system_flush_routes();
		interface_handle_config_change(iface);
		break;
	case IFPEV_LINK_LOST:
		if (iface->state != IFS_UP)
			return;

		netifd_log_message(L_NOTICE, "Interface '%s' has lost the connection\n", iface->name);
		if (iface->state == IFS_UP)
			interface_event(iface, IFEV_DOWN);
		mark_interface_down(iface);
		system_flush_routes();
		iface->state = IFS_SETUP;
		break;
	}
}

void interface_set_proto_state(struct interface *iface, struct interface_proto_state *state)
{
	if (iface->proto) {
		iface->proto->free(iface->proto);
		iface->proto = NULL;
	}
	iface->state = IFS_DOWN;
	iface->proto = state;
	if (!state)
		return;

	state->proto_event = interface_proto_cb;
	state->iface = iface;
}

void
interface_init(struct interface *iface, const char *name,
	       struct blob_attr *config)
{
	struct blob_attr *tb[IFACE_ATTR_MAX];
	struct blob_attr *cur;
	const char *proto_name = NULL;

	strncpy(iface->name, name, sizeof(iface->name) - 1);
	INIT_LIST_HEAD(&iface->errors);
	INIT_LIST_HEAD(&iface->users);
	INIT_LIST_HEAD(&iface->hotplug_list);
	interface_ip_init(&iface->proto_ip, iface);
	interface_ip_init(&iface->config_ip, iface);
	avl_init(&iface->data, avl_strcmp, false, NULL);
	iface->config_ip.enabled = false;

	iface->main_dev.cb = interface_cb;

	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb,
		      blob_data(config), blob_len(config));

	if ((cur = tb[IFACE_ATTR_PROTO]))
		proto_name = blobmsg_data(cur);

	proto_attach_interface(iface, proto_name);

	iface->autostart = blobmsg_get_bool_default(tb[IFACE_ATTR_AUTO], true);
	iface->proto_ip.no_defaultroute =
		!blobmsg_get_bool_default(tb[IFACE_ATTR_DEFAULTROUTE], true);

	iface->config_autostart = iface->autostart;
}

void
interface_add(struct interface *iface, struct blob_attr *config)
{
	struct blob_attr *tb[IFACE_ATTR_MAX];
	struct blob_attr *cur;

	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb,
		      blob_data(config), blob_len(config));

	if ((cur = tb[IFACE_ATTR_IFNAME]))
		iface->ifname = blobmsg_data(cur);

	iface->config = config;
	vlist_add(&interfaces, &iface->node, iface->name);
}

void
interface_set_l3_dev(struct interface *iface, struct device *dev)
{
	bool enabled = iface->config_ip.enabled;
	bool claimed = iface->l3_dev.claimed;

	if (iface->l3_dev.dev == dev)
		return;

	interface_ip_set_enabled(&iface->config_ip, false);
	interface_ip_flush(&iface->proto_ip);
	device_add_user(&iface->l3_dev, dev);

	if (dev) {
		if (claimed)
			device_claim(&iface->l3_dev);
		interface_ip_set_enabled(&iface->config_ip, enabled);
	}
}

void
interface_set_main_dev(struct interface *iface, struct device *dev)
{
	bool set_l3 = (iface->main_dev.dev == iface->l3_dev.dev);
	bool claimed = iface->l3_dev.claimed;

	if (iface->main_dev.dev == dev)
		return;

	if (set_l3)
		interface_set_l3_dev(iface, dev);

	device_add_user(&iface->main_dev, dev);
	if (claimed)
		device_claim(&iface->l3_dev);

	if (!iface->l3_dev.dev)
		interface_set_l3_dev(iface, dev);
}

int
interface_remove_link(struct interface *iface, struct device *dev)
{
	struct device *mdev = iface->main_dev.dev;

	if (mdev && mdev->hotplug_ops)
		return mdev->hotplug_ops->del(mdev, dev);

	if (!iface->main_dev.hotplug)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (dev != iface->main_dev.dev)
		return UBUS_STATUS_INVALID_ARGUMENT;

	device_remove_user(&iface->main_dev);
	return 0;
}

int
interface_add_link(struct interface *iface, struct device *dev)
{
	struct device *mdev = iface->main_dev.dev;

	if (mdev == dev)
		return 0;

	if (iface->main_dev.hotplug)
		device_remove_user(&iface->main_dev);

	if (mdev) {
		if (mdev->hotplug_ops)
			return mdev->hotplug_ops->add(mdev, dev);
		else
			return UBUS_STATUS_NOT_SUPPORTED;
	}

	interface_set_main_dev(iface, dev);
	iface->main_dev.hotplug = true;
	return 0;
}

int
interface_set_up(struct interface *iface)
{
	int ret;

	iface->autostart = true;

	if (iface->state != IFS_DOWN)
		return 0;

	interface_clear_errors(iface);
	if (!iface->available) {
		interface_add_error(iface, "interface", "NO_DEVICE", NULL, 0);
		return -1;
	}

	if (iface->main_dev.dev) {
		ret = device_claim(&iface->main_dev);
		if (ret)
			return ret;
	}

	iface->state = IFS_SETUP;
	ret = interface_proto_event(iface->proto, PROTO_CMD_SETUP, false);
	if (ret) {
		mark_interface_down(iface);
		return ret;
	}

	return 0;
}

int
interface_set_down(struct interface *iface)
{
	if (!iface) {
		vlist_for_each_element(&interfaces, iface, node)
			__interface_set_down(iface, false);
	} else {
		iface->autostart = false;
		__interface_set_down(iface, false);
	}

	return 0;
}

void
interface_start_pending(void)
{
	struct interface *iface;

	vlist_for_each_element(&interfaces, iface, node) {
		if (iface->available && iface->autostart)
			interface_set_up(iface);
	}
}

static void
set_config_state(struct interface *iface, enum interface_config_state s)
{
	iface->config_state = s;
	if (iface->state == IFS_DOWN)
		interface_handle_config_change(iface);
	else
		__interface_set_down(iface, false);
}

void
interface_update_start(struct interface *iface)
{
	interface_ip_update_start(&iface->proto_ip);
}

void
interface_update_complete(struct interface *iface)
{
	interface_ip_update_complete(&iface->proto_ip);
}

static void
interface_change_config(struct interface *if_old, struct interface *if_new)
{
	struct blob_attr *old_config = if_old->config;
	const char *old_ifname = if_old->ifname;
	const struct proto_handler *proto = if_old->proto_handler;

	interface_clear_errors(if_old);
	if_old->config = if_new->config;
	if (!if_old->config_autostart && if_new->config_autostart)
		if_old->autostart = true;

	if_old->config_autostart = if_new->config_autostart;
	if_old->ifname = if_new->ifname;
	if_old->proto_handler = if_new->proto_handler;

	if ((!!old_ifname != !!if_new->ifname) ||
	    (old_ifname && strcmp(old_ifname, if_new->ifname) != 0) ||
	    proto != if_new->proto_handler) {
		D(INTERFACE, "Reload interface '%s' because of ifname/proto change\n",
		  if_old->name);
		goto reload;
	}

	if (!proto->config_params)
		D(INTERFACE, "No config parameters for interface '%s'\n",
		  if_old->name);
	else if (!config_check_equal(old_config, if_new->config,
				proto->config_params)) {
		D(INTERFACE, "Reload interface '%s because of config changes\n",
		  if_old->name);
		goto reload;
	}

#define UPDATE(field) ({						\
		bool __changed = (if_old->field != if_new->field);	\
		if_old->field = if_new->field;				\
		__changed;						\
	})

	if (UPDATE(metric) || UPDATE(proto_ip.no_defaultroute)) {
		interface_ip_set_enabled(&if_old->config_ip, false);
		interface_ip_set_enabled(&if_old->config_ip, if_new->config_ip.enabled);
		interface_ip_set_enabled(&if_old->proto_ip, false);
		interface_ip_set_enabled(&if_old->proto_ip, if_new->proto_ip.enabled);
	}

#undef UPDATE

	goto out;

reload:
	set_config_state(if_old, IFC_RELOAD);
out:
	free(old_config);
	free(if_new);
}

static void
interface_update(struct vlist_tree *tree, struct vlist_node *node_new,
		 struct vlist_node *node_old)
{
	struct interface *if_old = container_of(node_old, struct interface, node);
	struct interface *if_new = container_of(node_new, struct interface, node);

	if (node_old && node_new) {
		D(INTERFACE, "Update interface '%s'\n", if_new->name);
		interface_change_config(if_old, if_new);
	} else if (node_old) {
		D(INTERFACE, "Remove interface '%s'\n", if_old->name);
		set_config_state(if_old, IFC_REMOVE);
	} else if (node_new) {
		D(INTERFACE, "Create interface '%s'\n", if_new->name);
		proto_init_interface(if_new, if_new->config);
		interface_claim_device(if_new);
		netifd_ubus_add_interface(if_new);
	}
}


static void __init
interface_init_list(void)
{
	vlist_init(&interfaces, avl_strcmp, interface_update);
	interfaces.keep_old = true;
	interfaces.no_delete = true;
}
