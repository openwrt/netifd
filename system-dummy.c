#include <stdio.h>
#include <string.h>

#include "netifd.h"
#include "device.h"

int system_bridge_addbr(struct device *bridge)
{
	DPRINTF("brctl addbr %s\n", bridge->ifname);
	return 0;
}

int system_bridge_delbr(struct device *bridge)
{
	DPRINTF("brctl delbr %s\n", bridge->ifname);
	return 0;
}

int system_bridge_addif(struct device *bridge, struct device *dev)
{
	DPRINTF("brctl addif %s %s\n", bridge->ifname, dev->ifname);
	return 0;
}

int system_bridge_delif(struct device *bridge, struct device *dev)
{
	DPRINTF("brctl delif %s %s\n", bridge->ifname, dev->ifname);
	return 0;
}

int system_vlan_add(struct device *dev, int id)
{
	DPRINTF("vconfig add %s %d\n", dev->ifname, id);
	return 0;
}

int system_vlan_del(struct device *dev)
{
	DPRINTF("vconfig rem %s\n", dev->ifname);
	return 0;
}

int system_if_up(struct device *dev)
{
	DPRINTF("ifconfig %s up\n", dev->ifname);
	return 0;
}

int system_if_down(struct device *dev)
{
	DPRINTF("ifconfig %s down\n", dev->ifname);
	return 0;
}

int system_if_check(struct device *dev)
{
	dev->ifindex = 0;

	if (!strcmp(dev->ifname, "eth0"))
		device_set_present(dev, true);

	return 0;
}

int system_add_address(struct device *dev, struct device_addr *addr)
{
	uint8_t *a = (uint8_t *) &addr->addr.in;

	if ((addr->flags & DEVADDR_FAMILY) == DEVADDR_INET4) {
		DPRINTF("ifconfig %s add %d.%d.%d.%d/%d\n",
			dev->ifname, a[0], a[1], a[2], a[3], addr->mask);
	} else {
		return -1;
	}

	return 0;
}

int system_del_address(struct device *dev, struct device_addr *addr)
{
	uint8_t *a = (uint8_t *) &addr->addr.in;

	if ((addr->flags & DEVADDR_FAMILY) == DEVADDR_INET4) {
		DPRINTF("ifconfig %s del %d.%d.%d.%d\n",
			dev->ifname, a[0], a[1], a[2], a[3]);
	} else {
		return -1;
	}

	return 0;
}

int system_add_route(struct device *dev, struct device_route *route)
{
	uint8_t *a1 = (uint8_t *) &route->addr.in;
	uint8_t *a2 = (uint8_t *) &route->nexthop.in;
	char addr[40], gw[40] = "", devstr[64] = "";

	if ((route->flags & DEVADDR_FAMILY) != DEVADDR_INET4)
		return -1;

	if (!route->mask)
		sprintf(addr, "default");
	else
		sprintf(addr, "%d.%d.%d.%d/%d",
			a1[0], a1[1], a1[2], a1[3], route->mask);

	if (memcmp(a2, "\x00\x00\x00\x00", 4) != 0)
		sprintf(gw, " gw %d.%d.%d.%d",
			a2[0], a2[1], a2[2], a2[3]);

	if (route->flags & DEVADDR_DEVICE)
		sprintf(devstr, " dev %s", dev->ifname);

	DPRINTF("route add %s%s%s\n", addr, gw, devstr);
	return 0;
}

int system_del_route(struct device *dev, struct device_route *route)
{
	uint8_t *a1 = (uint8_t *) &route->addr.in;
	uint8_t *a2 = (uint8_t *) &route->nexthop.in;
	char addr[40], gw[40] = "", devstr[64] = "";

	if ((route->flags & DEVADDR_FAMILY) != DEVADDR_INET4)
		return -1;

	if (!route->mask)
		sprintf(addr, "default");
	else
		sprintf(addr, "%d.%d.%d.%d/%d",
			a1[0], a1[1], a1[2], a1[3], route->mask);

	if (memcmp(a2, "\x00\x00\x00\x00", 4) != 0)
		sprintf(gw, " gw %d.%d.%d.%d",
			a2[0], a2[1], a2[2], a2[3]);

	if (route->flags & DEVADDR_DEVICE)
		sprintf(devstr, " dev %s", dev->ifname);

	DPRINTF("route del %s%s%s\n", addr, gw, devstr);
	return 0;
}
