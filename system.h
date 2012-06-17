/*
 * netifd - network interface daemon
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef __NETIFD_SYSTEM_H
#define __NETIFD_SYSTEM_H

#include <sys/time.h>
#include <sys/socket.h>
#include "device.h"
#include "interface-ip.h"

enum tunnel_param {
	TUNNEL_ATTR_TYPE,
	TUNNEL_ATTR_REMOTE,
	TUNNEL_ATTR_LOCAL,
	TUNNEL_ATTR_TTL,
	TUNNEL_ATTR_6RD_PREFIX,
	TUNNEL_ATTR_6RD_RELAY_PREFIX,
	__TUNNEL_ATTR_MAX
};

const struct config_param_list tunnel_attr_list;

enum bridge_opt {
	/* stp and forward delay always set */
	BRIDGE_OPT_AGEING_TIME = (1 << 0),
	BRIDGE_OPT_HELLO_TIME  = (1 << 1),
	BRIDGE_OPT_MAX_AGE     = (1 << 2),
};

struct bridge_config {
	enum bridge_opt flags;
	bool stp;
	bool igmp_snoop;
	int forward_delay;

	int ageing_time;
	int hello_time;
	int max_age;
};

int system_init(void);

int system_bridge_addbr(struct device *bridge, struct bridge_config *cfg);
int system_bridge_delbr(struct device *bridge);
int system_bridge_addif(struct device *bridge, struct device *dev);
int system_bridge_delif(struct device *bridge, struct device *dev);

int system_vlan_add(struct device *dev, int id);
int system_vlan_del(struct device *dev);

void system_if_clear_state(struct device *dev);
int system_if_up(struct device *dev);
int system_if_down(struct device *dev);
int system_if_check(struct device *dev);
int system_if_dump_info(struct device *dev, struct blob_buf *b);
int system_if_dump_stats(struct device *dev, struct blob_buf *b);
struct device *system_if_get_parent(struct device *dev);
bool system_if_force_external(const char *ifname);

int system_add_address(struct device *dev, struct device_addr *addr);
int system_del_address(struct device *dev, struct device_addr *addr);

int system_add_route(struct device *dev, struct device_route *route);
int system_del_route(struct device *dev, struct device_route *route);
int system_flush_routes(void);

int system_del_ip_tunnel(const char *name);
int system_add_ip_tunnel(const char *name, struct blob_attr *attr);

time_t system_get_rtime(void);

#endif
