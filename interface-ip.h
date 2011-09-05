#ifndef __INTERFACE_IP_H
#define __INTERFACE_IP_H

enum device_addr_flags {
	/* address family for routes and addresses */
	DEVADDR_INET4	= (0 << 0),
	DEVADDR_INET6	= (1 << 0),
	DEVADDR_FAMILY	= DEVADDR_INET4 | DEVADDR_INET6,

	/* device route (no gateway) */
	DEVADDR_DEVICE	= (1 << 1),
};

union if_addr {
	struct in_addr in;
	struct in6_addr in6;
};

struct device_addr {
	struct list_head list;
	void *ctx;

	enum device_addr_flags flags;

	unsigned int mask;
	union if_addr addr;
};

struct device_route {
	struct list_head list;
	void *ctx;

	enum device_addr_flags flags;

	unsigned int mask;
	union if_addr addr;
	union if_addr nexthop;
};

int interface_add_address(struct interface *iface, struct device_addr *addr);
void interface_del_address(struct interface *iface, struct device_addr *addr);
void interface_del_ctx_addr(struct interface *iface, void *ctx);

int interface_add_route(struct interface *iface, struct device_route *route);
void interface_del_route(struct interface *iface, struct device_route *route);
void interface_del_all_routes(struct interface *iface);

#endif
