#ifndef __NETIFD_INTERFACE_H
#define __NETIFD_INTERFACE_H

#include "device.h"
#include "config.h"

struct interface;
struct interface_proto_state;

enum interface_event {
	IFEV_DOWN,
	IFEV_UP,
};

enum interface_state {
	IFS_SETUP,
	IFS_UP,
	IFS_TEARDOWN,
	IFS_DOWN,
};

enum interface_config_state {
	IFC_NORMAL,
	IFC_RELOAD,
	IFC_REMOVE
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
	struct vlist_node node;
	struct list_head hotplug_list;
	enum interface_event hotplug_ev;

	char name[IFNAMSIZ];
	const char *ifname;

	bool available;
	bool autostart;
	bool config_autostart;

	time_t start_time;
	enum interface_state state;
	enum interface_config_state config_state;

	/* main interface that the interface is bound to */
	struct device_user main_dev;

	/* interface that layer 3 communication will go through */
	struct device_user *l3_dev;

	struct blob_attr *config;

	/* primary protocol state */
	const struct proto_handler *proto_handler;
	struct interface_proto_state *proto;

	struct vlist_tree proto_addr;
	struct vlist_tree proto_route;

	struct list_head proto_dns_servers;
	struct list_head proto_dns_search;

	/* errors/warnings while trying to bring up the interface */
	struct list_head errors;

	struct uloop_timeout remove_timer;
	struct ubus_object ubus;
};

extern struct vlist_tree interfaces;
extern const struct config_param_list interface_attr_list;

void interface_init(struct interface *iface, const char *name,
		    struct blob_attr *config);

void interface_add(struct interface *iface, struct blob_attr *config);

void interface_set_proto_state(struct interface *iface, struct interface_proto_state *state);

void interface_set_available(struct interface *iface, bool new_state);
int interface_set_up(struct interface *iface);
int interface_set_down(struct interface *iface);

int interface_add_link(struct interface *iface, struct device *llif);
void interface_remove_link(struct interface *iface, struct device *llif);

void interface_add_error(struct interface *iface, const char *subsystem,
			 const char *code, const char **data, int n_data);

void interface_queue_event(struct interface *iface, enum interface_event ev);
void interface_dequeue_event(struct interface *iface);

void interface_start_pending(void);

#endif
