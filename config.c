#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "interface.h"

struct uci_context *uci_ctx;
bool config_init = false;

static void config_parse_interface(struct uci_section *s)
{
	struct interface *iface;
	const char *type;

	DPRINTF("Create interface '%s'\n", s->e.name);

	iface = alloc_interface(s->e.name);
	type = uci_lookup_option_string(uci_ctx, s, "type");

	if (!type)
		type = "";

	if (!strcmp(type, "bridge"))
		interface_attach_bridge(iface, s);
}

void config_init_interfaces(const char *name)
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

	config_init = true;
	uci_foreach_element(&p->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (name && strcmp(s->e.name, name) != 0)
			continue;

		if (!strcmp(s->type, "interface"))
			config_parse_interface(s);
	}
	config_init = false;

	start_pending_interfaces();
}
