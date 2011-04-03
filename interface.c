#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "proto.h"
#include "ubus.h"

static LIST_HEAD(interfaces);

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
	int *datalen;
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
	release_device(iface->main_dev.dev);
	iface->state = IFS_DOWN;
}

static int
__set_interface_up(struct interface *iface)
{
	int ret;

	if (iface->state != IFS_DOWN)
		return 0;

	ret = claim_device(iface->main_dev.dev);
	if (ret)
		return ret;

	iface->state = IFS_SETUP;
	ret = iface->proto->handler(iface->proto, PROTO_CMD_SETUP, false);
	if (ret) {
		mark_interface_down(iface);
		return ret;
	}

	return 0;

}

static void
__set_interface_down(struct interface *iface, bool force)
{
	clear_interface_errors(iface);

	if (iface->state == IFS_DOWN ||
		iface->state == IFS_TEARDOWN)
		return;

	iface->state = IFS_TEARDOWN;
	interface_event(iface, IFEV_DOWN);

	iface->proto->handler(iface->proto, PROTO_CMD_TEARDOWN, force);
	release_device(iface->main_dev.dev);
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

	if (iface->active == new_state)
		return;

	iface->active = new_state;

	if (new_state) {
		if (iface->autostart)
			set_interface_up(iface);
	} else
		__set_interface_down(iface, true);
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
		iface->proto->handler(iface->proto, PROTO_CMD_TEARDOWN, true);
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
alloc_interface(const char *name)
{
	struct interface *iface;

	iface = get_interface(name);
	if (iface)
		return iface;

	iface = calloc(1, sizeof(*iface));

	interface_set_proto_state(iface, get_default_proto());
	if (!iface->proto) {
		free(iface);
		return NULL;
	}

	iface->main_dev.cb = interface_cb;
	iface->l3_iface = &iface->main_dev;
	strncpy(iface->name, name, sizeof(iface->name) - 1);
	list_add(&iface->list, &interfaces);
	INIT_LIST_HEAD(&iface->errors);

	netifd_ubus_add_interface(iface);

	return iface;
}

void
free_interface(struct interface *iface)
{
	netifd_ubus_remove_interface(iface);
	list_del(&iface->list);
	if (iface->proto->free)
		iface->proto->free(iface->proto);
	free(iface);
}

struct interface *
get_interface(const char *name)
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

	remove_device_user(&iface->main_dev);
}

int
interface_add_link(struct interface *iface, struct device *dev)
{
	struct device *mdev = iface->main_dev.dev;

	if (mdev && mdev->hotplug_ops)
		return mdev->hotplug_ops->add(mdev, dev);

	if (iface->main_dev.dev)
		interface_remove_link(iface, NULL);

	add_device_user(&iface->main_dev, dev);

	return 0;
}

int
set_interface_up(struct interface *iface)
{
	iface->autostart = true;

	if (!iface->active) {
		interface_add_error(iface, "interface", "NO_DEVICE", NULL, 0);
		return -1;
	}

	if (iface->state != IFS_DOWN)
		return 0;

	return __set_interface_up(iface);
}

int
set_interface_down(struct interface *iface)
{
	iface->autostart = false;
	__set_interface_down(iface, false);

	return 0;
}
