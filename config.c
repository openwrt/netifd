#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#include "netifd.h"
#include "interface.h"

struct uci_context *uci_ctx;
static struct uci_package *uci_network;
bool config_init = false;

static void uci_attr_to_blob(struct blob_buf *b, const char *str,
			     const char *name, enum blobmsg_type type)
{
	char *err;
	int intval;

	switch (type) {
	case BLOBMSG_TYPE_STRING:
		blobmsg_add_string(b, name, str);
		break;
	case BLOBMSG_TYPE_BOOL:
		if (!strcmp(str, "true") || !strcmp(str, "1"))
			intval = 1;
		else if (!strcmp(str, "false") || !strcmp(str, "0"))
			intval = 0;
		else
			return;

		blobmsg_add_u8(b, name, intval);
		break;
	case BLOBMSG_TYPE_INT32:
		intval = strtol(str, &err, 0);
		if (*err)
			return;

		blobmsg_add_u32(b, name, intval);
		break;
	default:
		break;
	}
}

static void uci_array_to_blob(struct blob_buf *b, struct uci_option *o,
			      enum blobmsg_type type)
{
	struct uci_element *e;
	char *str, *next, *word;

	if (o->type == UCI_TYPE_LIST) {
		uci_foreach_element(&o->v.list, e) {
			uci_attr_to_blob(b, e->name, NULL, type);
		}
		return;
	}

	str = strdup(o->v.string);
	next = str;

	while ((word = strsep(&next, " \t")) != NULL) {
		if (!*word)
			continue;

		uci_attr_to_blob(b, word, NULL, type);
	}

	free(str);
}

static void uci_to_blob(struct blob_buf *b, struct uci_section *s,
			const struct config_param_list *p)
{
	const struct blobmsg_policy *attr;
	struct uci_element *e;
	struct uci_option *o;
	void *array;
	int i;

	uci_foreach_element(&s->options, e) {
		for (i = 0; i < p->n_params; i++) {
			attr = &p->params[i];
			if (!strcmp(attr->name, e->name))
				break;
		}

		if (i == p->n_params)
			continue;

		o = uci_to_option(e);

		if (attr->type == BLOBMSG_TYPE_ARRAY) {
			if (!p->info)
				continue;

			array = blobmsg_open_array(b, attr->name);
			uci_array_to_blob(b, o, p->info[i].type);
			blobmsg_close_array(b, array);
			continue;
		}

		if (o->type == UCI_TYPE_LIST)
			continue;

		uci_attr_to_blob(b, o->v.string, attr->name, attr->type);
	}
}

static void
config_parse_interface(struct uci_section *s)
{
	struct blob_buf b = {};

	DPRINTF("Create interface '%s'\n", s->e.name);

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &interface_attr_list);
	alloc_interface(s->e.name, s, b.head);
}

enum {
	SDEV_NAME,
	SDEV_TYPE,
	SDEV_MTU,
	SDEV_MACADDR,
	SDEV_TXQUEUELEN,
	__SDEV_MAX,
};

static const struct uci_parse_option dev_opts[__SDEV_MAX] = {
	[SDEV_NAME] = { "name", UCI_TYPE_STRING },
	[SDEV_TYPE] = { "type", UCI_TYPE_STRING },
	[SDEV_MTU] = { "mtu", UCI_TYPE_STRING },
	[SDEV_MACADDR] = { "macaddr", UCI_TYPE_STRING },
	[SDEV_TXQUEUELEN] = { "txqueuelen", UCI_TYPE_STRING },
};

static bool
add_int_option(struct uci_option *o, unsigned int *dest)
{
	char *error = NULL;
	int val;

	if (!o)
		return false;

	val = strtoul(o->v.string, &error, 0);
	if (error && *error)
		return false;

	*dest = val;
	return true;
}

static void
config_init_device_settings(struct device *dev, struct uci_option **opts)
{
	struct ether_addr *ea;

	dev->flags = 0;

	if (add_int_option(opts[SDEV_MTU], &dev->mtu))
		dev->flags |= DEV_OPT_MTU;

	if (add_int_option(opts[SDEV_TXQUEUELEN], &dev->txqueuelen))
		dev->flags |= DEV_OPT_TXQUEUELEN;

	if (opts[SDEV_MACADDR]) {
		ea = ether_aton(opts[SDEV_MACADDR]->v.string);
		if (ea) {
			memcpy(dev->macaddr, ea, sizeof(dev->macaddr));
			dev->flags |= DEV_OPT_MACADDR;
		}
	}
}

void
config_init_devices(void)
{
	struct uci_element *e;
	struct device *dev;
	struct uci_option *opts[__SDEV_MAX];

	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "device") != 0)
			continue;

		uci_parse_section(s, dev_opts, __SDEV_MAX, opts);
		if (!opts[SDEV_NAME])
			continue;

		dev = NULL;
		if (opts[SDEV_TYPE]) {
			const char *type = opts[SDEV_TYPE]->v.string;

			if (!strcmp(type, "bridge"))
				dev = bridge_create(opts[SDEV_NAME]->v.string, s);
		} else {
			dev = get_device(opts[SDEV_NAME]->v.string, true);
		}

		if (!dev)
			continue;

		config_init_device_settings(dev, opts);
		dev->config_hash = uci_hash_options(opts, __SDEV_MAX);
	}
}

void
config_init_interfaces(const char *name)
{
	struct uci_context *ctx;
	struct uci_package *p = NULL;
	struct uci_element *e;

	ctx = uci_alloc_context();
	uci_ctx = ctx;

	uci_set_confdir(ctx, "./config");

	if (uci_load(ctx, "network", &p)) {
		fprintf(stderr, "Failed to load network config\n");
		return;
	}

	uci_network = p;
	config_init = true;

	config_init_devices();

	uci_foreach_element(&p->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (name && strcmp(s->e.name, name) != 0)
			continue;

		if (!strcmp(s->type, "interface"))
			config_parse_interface(s);
	}
	cleanup_devices();
	config_init = false;

	start_pending_interfaces();
}
