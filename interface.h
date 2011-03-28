#ifndef __NETIFD_INTERFACE_H
#define __NETIFD_INTERFACE_H

struct interface;
struct interface_proto;
struct interface_proto_state;

extern struct list_head interfaces;

enum interface_event {
	IFEV_UP,
	IFEV_DOWN,
};

struct interface_proto_state {
	const struct interface_proto *proto;

	int (*event)(struct interface *, struct interface_proto_state *, enum interface_event ev);
	void (*free)(struct interface *, struct interface_proto_state *);
};

struct interface_error {
	struct list_head list;

	const char *subsystem;
	const char *code;
	const char *data[];
};

/*
 * interface configuration
 */
struct interface {
	struct list_head list;

	char name[IFNAMSIZ];

	bool up;
	bool active;
	bool autostart;

	/* main interface that the interface is bound to */
	struct device_user main_dev;

	/* interface that layer 3 communication will go through */
	struct device_user *l3_iface;

	/* primary protocol state */
	struct interface_proto_state *state;

	/* errors/warnings while trying to bring up the interface */
	struct list_head errors;

	struct ubus_object ubus;
};

struct interface *get_interface(const char *name);
struct interface *alloc_interface(const char *name);
void free_interface(struct interface *iface);

int set_interface_up(struct interface *iface);
int set_interface_down(struct interface *iface);

int interface_add_link(struct interface *iface, struct device *llif);
void interface_remove_link(struct interface *iface, struct device *llif);

void interface_add_error(struct interface *iface, const char *subsystem,
			 const char *code, const char **data, int n_data);

int interface_attach_bridge(struct interface *iface, struct uci_section *s);

#endif
