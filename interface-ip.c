#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "proto.h"
#include "ubus.h"
#include "system.h"

int interface_add_address(struct interface *iface, struct device_addr *addr)
{
	int family;

	if (addr->flags & DEVADDR_INET6)
		family = AF_INET6;
	else
		family = AF_INET;

	list_add(&addr->list, &iface->address);
	return system_add_address(iface->l3_iface->dev, addr);
}

void interface_del_address(struct interface *iface, struct device_addr *addr)
{
	int family;

	if (addr->flags & DEVADDR_INET6)
		family = AF_INET6;
	else
		family = AF_INET;

	list_del(&addr->list);
	system_del_address(iface->l3_iface->dev, addr);
}

void interface_del_ctx_addr(struct interface *iface, void *ctx)
{
	struct device_addr *addr, *tmp;

	list_for_each_entry_safe(addr, tmp, &iface->address, list) {
		if (ctx && addr->ctx != ctx)
			continue;

		interface_del_address(iface, addr);
	}
}

int interface_add_route(struct interface *iface, struct device_route *route)
{
	list_add(&route->list, &iface->routes);
	return system_add_route(iface->l3_iface->dev, route);
}

void interface_del_route(struct interface *iface, struct device_route *route)
{
	list_del(&route->list);
	system_del_route(iface->l3_iface->dev, route);
}

void interface_del_all_routes(struct interface *iface)
{
	struct device_route *route, *tmp;

	list_for_each_entry_safe(route, tmp, &iface->routes, list)
		interface_del_route(iface, route);
}
