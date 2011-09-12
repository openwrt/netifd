#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"
#include "ubus.h"
#include "system.h"

static void
interface_update_proto_addr(struct vlist_tree *tree,
			    struct vlist_node *node_new,
			    struct vlist_node *node_old)
{
	struct interface *iface;
	struct device *dev;
	struct device_addr *addr;

	iface = container_of(tree, struct interface, proto_addr);
	dev = iface->l3_dev->dev;

	if (node_old) {
		addr = container_of(node_old, struct device_addr, node);
		if (!(addr->flags & DEVADDR_EXTERNAL))
			system_del_address(dev, addr);
		free(addr);
	}

	if (node_new) {
		addr = container_of(node_new, struct device_addr, node);
		if (!(addr->flags & DEVADDR_EXTERNAL))
			system_add_address(dev, addr);
	}
}

static void
interface_update_proto_route(struct vlist_tree *tree,
			     struct vlist_node *node_new,
			     struct vlist_node *node_old)
{
	struct interface *iface;
	struct device *dev;
	struct device_route *route;

	iface = container_of(tree, struct interface, proto_route);
	dev = iface->l3_dev->dev;

	if (node_old) {
		route = container_of(node_old, struct device_route, node);
		if (!(route->flags & DEVADDR_EXTERNAL))
			system_del_route(dev, route);
		free(route);
	}

	if (node_new) {
		route = container_of(node_new, struct device_route, node);
		if (!(route->flags & DEVADDR_EXTERNAL))
			system_add_route(dev, route);
	}
}

void
interface_ip_init(struct interface *iface)
{
	vlist_init(&iface->proto_route, interface_update_proto_route,
		   struct device_route, node, mask, addr);
	vlist_init(&iface->proto_addr, interface_update_proto_addr,
		   struct device_addr, node, mask, addr);
}

