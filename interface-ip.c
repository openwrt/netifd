#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "proto.h"
#include "ubus.h"
#include "system.h"

int interface_add_address(struct interface *iface, struct interface_addr *addr)
{
	int family;

	if (addr->flags & IFADDR_INET6)
		family = AF_INET6;
	else
		family = AF_INET;

	list_add(&addr->list, &iface->address);
	return system_add_address(iface->l3_iface->dev, family, &addr->addr.in, addr->mask);
}

void interface_del_address(struct interface *iface, struct interface_addr *addr)
{
	int family;

	if (addr->flags & IFADDR_INET6)
		family = AF_INET6;
	else
		family = AF_INET;

	list_del(&addr->list);
	system_del_address(iface->l3_iface->dev, family, &addr->addr.in);
}

void interface_del_ctx_addr(struct interface *iface, void *ctx)
{
	struct interface_addr *addr, *tmp;

	list_for_each_entry_safe(addr, tmp, &iface->address, list) {
		if (addr->ctx != ctx)
			continue;

		interface_del_address(iface, addr);
	}
}
