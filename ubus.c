#include <string.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"
#include "ubus.h"

static struct ubus_context *ctx = NULL;
static struct blob_buf b;

/* global object */

enum {
	DEV_NAME,
	DEV_FORCE,
	__DEV_MAX,
	__DEV_MAX_NOFORCE = __DEV_MAX - 1,
};

static const struct blobmsg_policy dev_policy[__DEV_MAX] = {
	[DEV_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[DEV_FORCE] = { .name = "force", .type = BLOBMSG_TYPE_INT8 },
};

static int
netifd_handle_device(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	struct device *dev;
	struct blob_attr *tb[__DEV_MAX];
	bool add = !strncmp(method, "add", 3);

	blobmsg_parse(dev_policy, __DEV_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[DEV_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	dev = device_get(blobmsg_data(tb[DEV_NAME]), false);
	if (!dev)
		return UBUS_STATUS_NOT_FOUND;

	if (!add || (tb[DEV_FORCE] && blobmsg_get_u8(tb[DEV_FORCE])))
		device_set_present(dev, add);
	else
		device_check_state(dev);

	return 0;
}

static int
netifd_handle_restart(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	netifd_restart();
	return 0;
}

static int
netifd_handle_reload(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	netifd_reload();
	return 0;
}

static struct ubus_method main_object_methods[] = {
	UBUS_METHOD("add_device", netifd_handle_device, dev_policy),
	UBUS_METHOD("remove_device", netifd_handle_device, dev_policy),
	{ .name = "restart", .handler = netifd_handle_restart },
	{ .name = "reload", .handler = netifd_handle_reload },
};

static struct ubus_object_type main_object_type =
	UBUS_OBJECT_TYPE("netifd", main_object_methods);

static struct ubus_object main_object = {
	.name = "network.interface",
	.type = &main_object_type,
	.methods = main_object_methods,
	.n_methods = ARRAY_SIZE(main_object_methods),
};

int
netifd_ubus_init(const char *path)
{
	int ret;

	ctx = ubus_connect(path);
	if (!ctx)
		return -EIO;

	DPRINTF("connected as %08x\n", ctx->local_id);
	uloop_init();
	ubus_add_uloop(ctx);

	ret = ubus_add_object(ctx, &main_object);
	if (ret != 0)
		fprintf(stderr, "Failed to publish object: %s\n", ubus_strerror(ret));

	return 0;
}

void
netifd_ubus_done(void)
{
	ubus_free(ctx);
}


/* per-interface object */

static int
netifd_handle_up(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct interface *iface;

	iface = container_of(obj, struct interface, ubus);
	interface_set_up(iface);

	return 0;
}

static int
netifd_handle_down(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct interface *iface;

	iface = container_of(obj, struct interface, ubus);
	interface_set_down(iface);

	return 0;
}

static void
netifd_add_interface_errors(struct blob_buf *b, struct interface *iface)
{
	struct interface_error *error;
	void *e, *e2, *e3;
	int i;

	e = blobmsg_open_array(b, "errors");
	list_for_each_entry(error, &iface->errors, list) {
		e2 = blobmsg_open_table(b, NULL);

		blobmsg_add_string(b, "subsystem", error->subsystem);
		blobmsg_add_string(b, "code", error->code);
		if (error->data[0]) {
			e3 = blobmsg_open_array(b, "data");
			for (i = 0; error->data[i]; i++)
				blobmsg_add_string(b, NULL, error->data[i]);
			blobmsg_close_array(b, e3);
		}

		blobmsg_close_table(b, e2);
	}
	blobmsg_close_array(b, e);
}

static int
netifd_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	struct interface *iface;

	iface = container_of(obj, struct interface, ubus);

	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "up", iface->state == IFS_UP);
	blobmsg_add_u8(&b, "pending", iface->state == IFS_SETUP);
	blobmsg_add_u8(&b, "available", iface->available);
	blobmsg_add_u8(&b, "autostart", iface->autostart);
	if (iface->main_dev.dev) {
		struct device *dev = iface->main_dev.dev;
		const char *field;
		void *devinfo;

		/* use a different field for virtual devices */
		if (dev->avl.key)
			field = "device";
		else
			field = "link";

		devinfo = blobmsg_open_table(&b, field);
		blobmsg_add_string(&b, "name", dev->ifname);

		if (dev->type->dump_status)
			dev->type->dump_status(dev, &b);

		blobmsg_close_table(&b, devinfo);
	}

	if (!list_is_empty(&iface->errors))
		netifd_add_interface_errors(&b, iface);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
netifd_iface_handle_device(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	struct interface *iface;
	struct device *dev, *main_dev;
	struct blob_attr *tb[__DEV_MAX];
	bool add = !strncmp(method, "add", 3);
	int ret;

	iface = container_of(obj, struct interface, ubus);

	blobmsg_parse(dev_policy, __DEV_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[DEV_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	main_dev = iface->main_dev.dev;
	if (!main_dev)
		return UBUS_STATUS_NOT_FOUND;

	if (!main_dev->hotplug_ops)
		return UBUS_STATUS_NOT_SUPPORTED;

	dev = device_get(blobmsg_data(tb[DEV_NAME]), add);
	if (!dev)
		return UBUS_STATUS_NOT_FOUND;

	if (main_dev != dev) {
		if (add)
			ret = main_dev->hotplug_ops->add(main_dev, dev);
		else
			ret = main_dev->hotplug_ops->del(main_dev, dev);
		if (ret)
			ret = UBUS_STATUS_UNKNOWN_ERROR;
	} else {
		ret = UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (add)
		device_free_unused(dev);

	return ret;
}


static int
netifd_iface_notify_proto(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct interface *iface;

	iface = container_of(obj, struct interface, ubus);

	if (!iface->proto || !iface->proto->notify)
		return UBUS_STATUS_NOT_SUPPORTED;

	return iface->proto->notify(iface->proto, msg);
}

static void
netifd_iface_do_remove(struct uloop_timeout *timeout)
{
	struct interface *iface;

	iface = container_of(timeout, struct interface, remove_timer);
	vlist_delete(&interfaces, &iface->node);
}

static int
netifd_iface_remove(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct interface *iface;

	iface = container_of(obj, struct interface, ubus);
	if (iface->remove_timer.cb)
		return UBUS_STATUS_INVALID_ARGUMENT;

	iface->remove_timer.cb = netifd_iface_do_remove;
	uloop_timeout_set(&iface->remove_timer, 100);
	return 0;
}

static struct ubus_method iface_object_methods[] = {
	{ .name = "up", .handler = netifd_handle_up },
	{ .name = "down", .handler = netifd_handle_down },
	{ .name = "status", .handler = netifd_handle_status },
	{ .name = "add_device", .handler = netifd_iface_handle_device,
	  .policy = dev_policy, .n_policy = __DEV_MAX_NOFORCE },
	{ .name = "remove_device", .handler = netifd_iface_handle_device,
	  .policy = dev_policy, .n_policy = __DEV_MAX_NOFORCE },
	{ .name = "notify_proto", .handler = netifd_iface_notify_proto },
	{ .name = "remove", .handler = netifd_iface_remove }
};

static struct ubus_object_type iface_object_type =
	UBUS_OBJECT_TYPE("netifd_iface", iface_object_methods);


void
netifd_ubus_add_interface(struct interface *iface)
{
	struct ubus_object *obj = &iface->ubus;
	char *name;

	name = malloc(strlen(main_object.name) + strlen(iface->name) + 2);
	if (!name)
		return;

	sprintf(name, "%s.%s", main_object.name, iface->name);
	obj->name = name;
	obj->type = &iface_object_type;
	obj->methods = iface_object_methods;
	obj->n_methods = ARRAY_SIZE(iface_object_methods);
	if (ubus_add_object(ctx, &iface->ubus)) {
		DPRINTF("failed to publish ubus object for interface '%s'\n", iface->name);
		free(name);
		obj->name = NULL;
	}
}

void
netifd_ubus_remove_interface(struct interface *iface)
{
	if (!iface->ubus.name)
		return;

	ubus_remove_object(ctx, &iface->ubus);
	free((void *) iface->ubus.name);
}
