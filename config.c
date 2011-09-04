#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"

struct uci_context *uci_ctx;
static struct uci_package *uci_network;
bool config_init = false;
static struct blob_buf b;


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

static void __uci_to_blob(struct blob_buf *b, struct uci_section *s,
			  const struct config_param_list *p)
{
	const struct blobmsg_policy *attr = NULL;
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

static void uci_to_blob(struct blob_buf *b, struct uci_section *s,
			const struct config_param_list *p)
{
	int i;

	__uci_to_blob(b, s, p);
	for (i = 0; i < p->n_next; i++)
		uci_to_blob(b, s, p->next[i]);
}

static int
config_parse_bridge_interface(struct uci_section *s)
{
	char *name;

	name = alloca(strlen(s->e.name) + 4);
	sprintf(name, "br-%s", s->e.name);
	blobmsg_add_string(&b, "name", name);

	uci_to_blob(&b, s, bridge_device_type.config_params);
	if (!bridge_device_type.create(b.head)) {
		DPRINTF("Failed to create bridge for interface '%s'\n", s->e.name);
		return -EINVAL;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "ifname", name);
	return 0;
}

static void
config_parse_interface(struct uci_section *s)
{
	struct interface *iface;
	const char *type;

	DPRINTF("Create interface '%s'\n", s->e.name);

	blob_buf_init(&b, 0);

	type = uci_lookup_option_string(uci_ctx, s, "type");
	if (type && !strcmp(type, "bridge"))
		if (config_parse_bridge_interface(s))
			return;

	uci_to_blob(&b, s, &interface_attr_list);
	iface = interface_alloc(s->e.name, b.head);
	if (!iface)
		return;

	proto_init_interface(iface, s);
}

void
config_init_devices(void)
{
	struct uci_element *e;

	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const struct device_type *devtype;
		const char *type;

		if (strcmp(s->type, "device") != 0)
			continue;

		blob_buf_init(&b, 0);
		type = uci_lookup_option_string(uci_ctx, s, "type");
		if (type && !strcmp(type, "bridge"))
			devtype = &bridge_device_type;
		else
			devtype = &simple_device_type;

		uci_to_blob(&b, s, devtype->config_params);
		devtype->create(b.head);
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
	device_free_all();
	config_init = false;

	interface_start_pending();
}
