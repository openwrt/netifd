#include <stdio.h>
#include <string.h>

#include "netifd.h"

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
