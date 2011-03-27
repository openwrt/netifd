#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "ubus.h"

LIST_HEAD(interfaces);

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

static int
interface_event(struct interface *iface, enum interface_event ev)
{
	if (!iface->state || !iface->state->event)
		return 0;

	return iface->state->event(iface, iface->state, ev);
}

static void
__set_interface_up(struct interface *iface)
{
	if (iface->up)
		return;

	if (claim_device(iface->main_dev.dev) < 0)
		return;

	if (interface_event(iface, IFEV_UP) < 0) {
		release_device(iface->main_dev.dev);
		return;
	}

	iface->up = true;
}

static void
__set_interface_down(struct interface *iface)
{
	clear_interface_errors(iface);

	if (!iface->up)
		return;

	iface->up = false;
	interface_event(iface, IFEV_DOWN);
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
			__set_interface_up(iface);
	} else
		__set_interface_down(iface);
}

struct interface *
alloc_interface(const char *name)
{
	struct interface *iface;

	iface = get_interface(name);
	if (iface)
		return iface;

	iface = calloc(1, sizeof(*iface));
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
	if (iface->state && iface->state->free)
		iface->state->free(iface, iface->state);
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
interface_remove_link(struct interface *iface, struct device *llif)
{
	struct device *dev = iface->main_dev.dev;

	if (dev && dev->hotplug_ops) {
		dev->hotplug_ops->del(dev, llif);
		return;
	}

	remove_device_user(&iface->main_dev);
}

int
interface_add_link(struct interface *iface, struct device *llif)
{
	struct device *dev = iface->main_dev.dev;

	if (dev && dev->hotplug_ops)
		return dev->hotplug_ops->add(dev, llif);

	if (iface->main_dev.dev)
		interface_remove_link(iface, NULL);

	add_device_user(&iface->main_dev, llif);

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

	if (iface->up || !iface->active)
		return -1;

	__set_interface_up(iface);
	return 0;
}

int
set_interface_down(struct interface *iface)
{
	iface->autostart = false;
	__set_interface_down(iface);

	return 0;
}
