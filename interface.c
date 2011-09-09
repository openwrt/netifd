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

static LIST_HEAD(interfaces);

enum {
	IFACE_ATTR_IFNAME,
	IFACE_ATTR_PROTO,
	IFACE_ATTR_AUTO,
	IFACE_ATTR_MAX
};

static const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_AUTO] = { .name = "auto", .type = BLOBMSG_TYPE_BOOL },
};

const struct config_param_list interface_attr_list = {
	.n_params = IFACE_ATTR_MAX,
	.params = iface_attrs,
};

static void
clear_interface_errors(struct interface *iface)
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
interface_event(struct interface *iface, enum interface_event ev)
{
	/* TODO */
}

static void
mark_interface_down(struct interface *iface)
{
	vlist_flush_all(&iface->proto_addr);
	vlist_flush_all(&iface->proto_route);
	device_release(&iface->main_dev);
	iface->state = IFS_DOWN;
}

static int
__interface_set_up(struct interface *iface)
{
	int ret;

	if (iface->state != IFS_DOWN)
		return 0;

	ret = device_claim(&iface->main_dev);
	if (ret)
		return ret;

	iface->state = IFS_SETUP;
	ret = interface_proto_event(iface->proto, PROTO_CMD_SETUP, false);
	if (ret) {
		mark_interface_down(iface);
		return ret;
	}

	return 0;

}

static void
__interface_set_down(struct interface *iface, bool force)
{
	clear_interface_errors(iface);

	if (iface->state == IFS_DOWN ||
		iface->state == IFS_TEARDOWN)
		return;

	iface->state = IFS_TEARDOWN;
	interface_event(iface, IFEV_DOWN);
	interface_proto_event(iface->proto, PROTO_CMD_TEARDOWN, force);
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

	if (iface->available == new_state)
		return;

	iface->available = new_state;

	if (new_state) {
		if (iface->autostart && !config_init)
			interface_set_up(iface);
	} else
		__interface_set_down(iface, true);
}

static void
interface_proto_cb(struct interface_proto_state *state, enum interface_proto_event ev)
{
	struct interface *iface = state->iface;

	switch (ev) {
	case IFPEV_UP:
		if (iface->state != IFS_SETUP)
			return;

		iface->state = IFS_UP;
		interface_event(iface, IFEV_UP);
		break;
	case IFPEV_DOWN:
		if (iface->state == IFS_DOWN)
			return;

		mark_interface_down(iface);
		break;
	}
}

void interface_set_proto_state(struct interface *iface, struct interface_proto_state *state)
{
	if (iface->proto) {
		interface_proto_event(iface->proto, PROTO_CMD_TEARDOWN, true);
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

struct interface *
interface_alloc(const char *name, struct blob_attr *attr)
{
	struct interface *iface;
	struct blob_attr *tb[IFACE_ATTR_MAX];
	struct blob_attr *cur;
	struct device *dev;
	const char *proto_name = NULL;

	iface = interface_get(name);
	if (iface)
		return iface;

	iface = calloc(1, sizeof(*iface));
	iface->main_dev.cb = interface_cb;
	iface->l3_iface = &iface->main_dev;
	strncpy(iface->name, name, sizeof(iface->name) - 1);
	list_add_tail(&iface->list, &interfaces);
	INIT_LIST_HEAD(&iface->errors);

	interface_ip_init(iface);

	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb,
		      blob_data(attr), blob_len(attr));

	if ((cur = tb[IFACE_ATTR_PROTO]))
		proto_name = blobmsg_data(cur);

	proto_attach_interface(iface, proto_name);

	if ((cur = tb[IFACE_ATTR_IFNAME])) {
		dev = device_get(blobmsg_data(cur), true);
		if (dev)
			device_add_user(&iface->main_dev, dev);
	}

	if ((cur = tb[IFACE_ATTR_AUTO]))
		iface->autostart = blobmsg_get_bool(cur);
	else
		iface->autostart = true;

	netifd_ubus_add_interface(iface);
	config_set_state(&iface->config, attr);

	return iface;
}

void
interface_free(struct interface *iface)
{
	netifd_ubus_remove_interface(iface);
	list_del(&iface->list);
	if (iface->proto->free)
		iface->proto->free(iface->proto);
	free(iface);
}

struct interface *
interface_get(const char *name)
{
	struct interface *iface;

	list_for_each_entry(iface, &interfaces, list) {
		if (!strcmp(iface->name, name))
			return iface;
	}
	return NULL;
}

void
interface_remove_link(struct interface *iface, struct device *dev)
{
	struct device *mdev = iface->main_dev.dev;

	if (mdev && mdev->hotplug_ops) {
		mdev->hotplug_ops->del(mdev, dev);
		return;
	}

	device_remove_user(&iface->main_dev);
}

int
interface_add_link(struct interface *iface, struct device *dev)
{
	struct device *mdev = iface->main_dev.dev;

	if (mdev && mdev->hotplug_ops)
		return mdev->hotplug_ops->add(mdev, dev);

	if (iface->main_dev.dev)
		interface_remove_link(iface, NULL);

	device_add_user(&iface->main_dev, dev);

	return 0;
}

int
interface_set_up(struct interface *iface)
{
	iface->autostart = true;

	if (!iface->available) {
		interface_add_error(iface, "interface", "NO_DEVICE", NULL, 0);
		return -1;
	}

	if (iface->state != IFS_DOWN)
		return 0;

	return __interface_set_up(iface);
}

int
interface_set_down(struct interface *iface)
{
	iface->autostart = false;
	__interface_set_down(iface, false);

	return 0;
}

void
interface_start_pending(void)
{
	struct interface *iface;

	list_for_each_entry(iface, &interfaces, list) {
		if (iface->available && iface->autostart)
			interface_set_up(iface);
	}
}
