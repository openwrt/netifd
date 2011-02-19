#ifndef __NETIFD_SYSTEM_H
#define __NETIFD_SYSTEM_H

#include "device.h"

int system_bridge_addbr(struct device *bridge);
int system_bridge_delbr(struct device *bridge);
int system_bridge_addif(struct device *bridge, struct device *dev);
int system_bridge_delif(struct device *bridge, struct device *dev);

int system_vlan_add(struct device *dev, int id);
int system_vlan_del(struct device *dev);

int system_if_up(struct device *dev);
int system_if_down(struct device *dev);
int system_if_check(struct device *dev);

#endif
