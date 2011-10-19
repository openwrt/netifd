#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <uci.h>

#include "netifd.h"
#include "interface.h"
#include "proto.h"
#include "config.h"

bool config_init = false;

static struct uci_context *uci_ctx;
static struct uci_package *uci_network;
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
	if (!device_create(name, &bridge_device_type, b.head)) {
		D(INTERFACE, "Failed to create bridge for interface '%s'\n", s->e.name);
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
	struct blob_attr *config;
	struct device *dev;

	blob_buf_init(&b, 0);

	type = uci_lookup_option_string(uci_ctx, s, "type");
	if (type && !strcmp(type, "bridge"))
		if (config_parse_bridge_interface(s))
			return;

	uci_to_blob(&b, s, &interface_attr_list);
	iface = calloc(1, sizeof(*iface));
	if (!iface)
		return;

	interface_init(iface, s->e.name, b.head);

	if (iface->proto_handler && iface->proto_handler->config_params)
		uci_to_blob(&b, s, iface->proto_handler->config_params);

	config = malloc(blob_pad_len(b.head));
	if (!config) {
		free(iface);
		return;
	}

	memcpy(config, b.head, blob_pad_len(b.head));
	interface_add(iface, config);

	dev = iface->main_dev.dev;
	if (!dev || !dev->default_config)
		return;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, dev->type->config_params);
	if (blob_len(b.head) == 0)
		return;

	device_set_config(dev, dev->type, b.head);
}

static void
config_init_devices(void)
{
	struct uci_element *e;

	uci_foreach_element(&uci_network->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const struct device_type *devtype;
		const char *type, *name;

		if (strcmp(s->type, "device") != 0)
			continue;

		name = uci_lookup_option_string(uci_ctx, s, "name");
		if (!name)
			continue;

		type = uci_lookup_option_string(uci_ctx, s, "type");
		if (type && !strcmp(type, "bridge"))
			devtype = &bridge_device_type;
		else
			devtype = &simple_device_type;

		blob_buf_init(&b, 0);
		uci_to_blob(&b, s, devtype->config_params);
		device_create(name, devtype, b.head);
	}
}

bool
config_diff(struct blob_attr **tb1, struct blob_attr **tb2,
	    const struct config_param_list *config, unsigned long *diff)
{
	bool ret = false;
	int i;

	for (i = 0; i < config->n_params; i++) {
		if (!tb1[i] && !tb2[i])
			continue;

		if (!!tb1[i] != !!tb2[i])
			goto mark;

		if (blob_len(tb1[i]) != blob_len(tb2[i]))
			goto mark;

		if (memcmp(tb1[i], tb2[i], blob_raw_len(tb1[i])) != 0)
			goto mark;

		continue;

mark:
		ret = true;
		if (diff)
			set_bit(diff, i);
		else
			return ret;
	}

	return ret;
}


static bool
__config_check_equal(struct blob_attr *c1, struct blob_attr *c2,
		     const struct config_param_list *config)
{
	struct blob_attr **tb1, **tb2;

	if (!!c1 ^ !!c2)
		return false;

	if (!c1 && !c2)
		return true;

	tb1 = alloca(config->n_params * sizeof(struct blob_attr *));
	blobmsg_parse(config->params, config->n_params, tb1,
		blob_data(c1), blob_len(c1));

	tb2 = alloca(config->n_params * sizeof(struct blob_attr *));
	blobmsg_parse(config->params, config->n_params, tb2,
		blob_data(c2), blob_len(c2));

	return !config_diff(tb1, tb2, config, NULL);
}

bool
config_check_equal(struct blob_attr *c1, struct blob_attr *c2,
		   const struct config_param_list *config)
{
	int i;

	if (!__config_check_equal(c1, c2, config))
		return false;

	for (i = 0; i < config->n_next; i++) {
		if (!__config_check_equal(c1, c2, config->next[i]))
			return false;
	}

	return true;
}

struct blob_attr *
config_memdup(struct blob_attr *attr)
{
	struct blob_attr *ret;
	int size = blob_pad_len(attr);

	ret = malloc(size);
	if (!ret)
		return NULL;

	memcpy(ret, attr, size);
	return ret;
}

static struct uci_package *
config_init_package(const char *config)
{
	struct uci_context *ctx = uci_ctx;
	struct uci_package *p = NULL;

	if (!ctx) {
		ctx = uci_alloc_context();
		uci_ctx = ctx;

#ifdef DUMMY_MODE
		uci_set_confdir(ctx, "./config");
		uci_set_savedir(ctx, "./tmp");
#endif
	} else {
		p = uci_lookup_package(ctx, config);
		if (p)
			uci_unload(ctx, p);
	}

	if (uci_load(ctx, "network", &p))
		return NULL;

	return p;
}

void
config_init_all(void)
{
	struct uci_package *p = NULL;
	struct uci_element *e;

	p = config_init_package("network");
	if (!p) {
		fprintf(stderr, "Failed to load network config\n");
		return;
	}

	uci_network = p;
	config_init = true;
	device_lock();

	device_reset_config();
	config_init_devices();

	uci_foreach_element(&p->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "interface"))
			config_parse_interface(s);
	}

	config_init = false;
	device_unlock();

	device_reset_old();
	device_init_pending();
	device_free_unused(NULL);
	interface_start_pending();
}
