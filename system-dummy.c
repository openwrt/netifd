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
		set_device_present(dev, true);

	return 0;
}

int system_add_address(struct device *dev, int family, void *addr, int prefixlen)
{
	uint8_t *a = addr;

	if (family == AF_INET) {
		DPRINTF("ifconfig %s add %d.%d.%d.%d/%d\n",
			dev->ifname, a[0], a[1], a[2], a[3], prefixlen);
	} else {
		return -1;
	}

	return 0;
}

int system_del_address(struct device *dev, int family, void *addr)
{
	uint8_t *a = addr;

	if (family == AF_INET) {
		DPRINTF("ifconfig %s del %d.%d.%d.%d\n",
			dev->ifname, a[0], a[1], a[2], a[3]);
	} else {
		return -1;
	}

	return 0;
}
