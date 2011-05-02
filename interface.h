#ifndef __NETIFD_INTERFACE_H
#define __NETIFD_INTERFACE_H

#include <netinet/in.h>
#include "device.h"

struct interface;
struct interface_proto_state;

enum interface_event {
	IFEV_UP,
	IFEV_DOWN,
};

enum interface_state {
	IFS_SETUP,
	IFS_UP,
	IFS_TEARDOWN,
	IFS_DOWN,
};

struct interface_error {
	struct list_head list;

	const char *subsystem;
	const char *code;
	const char *data[];
};

enum interface_addr_flags {
	/* address family for routes and addresses */
	IFADDR_INET4	= (0 << 0),
	IFADDR_INET6	= (1 << 0),
	IFADDR_FAMILY	= IFADDR_INET4 | IFADDR_INET6,

	/* device route (no gateway) */
	IFADDR_DEVICE	= (1 << 1),
};

union if_addr {
	struct in_addr in;
	struct in6_addr in6;
};

struct interface_addr {
	struct list_head list;
	void *ctx;

	enum interface_addr_flags flags;

	unsigned int mask;
	union if_addr addr;
};

struct interface_route {
	struct list_head list;
	void *ctx;

	enum interface_addr_flags flags;

	unsigned int mask;
	union if_addr addr;
	union if_addr nexthop;
};

/*
 * interface configuration
 */
struct interface {
	struct list_head list;

	char name[IFNAMSIZ];

	bool active;
	bool autostart;

	enum interface_state state;

	/* main interface that the interface is bound to */
	struct device_user main_dev;

	/* interface that layer 3 communication will go through */
	struct device_user *l3_iface;

	/* primary protocol state */
	struct interface_proto_state *proto;

	struct list_head address, routes;

	/* errors/warnings while trying to bring up the interface */
	struct list_head errors;

	struct ubus_object ubus;
};

struct interface *get_interface(const char *name);
struct interface *alloc_interface(const char *name, struct uci_section *s);
void free_interface(struct interface *iface);

void interface_set_proto_state(struct interface *iface, struct interface_proto_state *state);

int set_interface_up(struct interface *iface);
int set_interface_down(struct interface *iface);

int interface_add_link(struct interface *iface, struct device *llif);
void interface_remove_link(struct interface *iface, struct device *llif);

void interface_add_error(struct interface *iface, const char *subsystem,
			 const char *code, const char **data, int n_data);

int interface_attach_bridge(struct interface *iface, struct uci_section *s);

int interface_add_address(struct interface *iface, struct interface_addr *addr);
void interface_del_address(struct interface *iface, struct interface_addr *addr);
void interface_del_ctx_addr(struct interface *iface, void *ctx);

void start_pending_interfaces(void);

#endif
