/*
 * netifd - network interface daemon
 * Copyright (C) 2025 Felix Fietkau <nbd@nbd.name>
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
#ifndef __NETIFD_SYSTEM_LOG_H
#define __NETIFD_SYSTEM_LOG_H


#define system_if_up(dev) ({ \
	struct device *_dev = dev;					\
	D(SYSTEM, "system_if_up(%s)", _dev ? _dev->ifname : "<none>");	\
	system_if_up(_dev);						\
})

#define system_if_down(dev) ({ \
	struct device *_dev = dev;					\
	D(SYSTEM, "system_if_down(%s)", _dev ? _dev->ifname : "<none>");	\
	system_if_down(_dev);						\
})

#define system_bridge_addbr(bridge, cfg) ({ \
	struct device *_bridge = bridge;					\
	struct bridge_config *_cfg = cfg;					\
	D(SYSTEM, "system_bridge_addbr(%s)", _bridge ? _bridge->ifname : "<none>");	\
	system_bridge_addbr(_bridge, _cfg);					\
})

#define system_bridge_delbr(bridge) ({ \
	struct device *_bridge = bridge;					\
	D(SYSTEM, "system_bridge_delbr(%s)", _bridge ? _bridge->ifname : "<none>");	\
	system_bridge_delbr(_bridge);						\
})

#define system_bridge_addif(bridge, dev) ({ \
	struct device *_bridge = bridge;					\
	struct device *_dev = dev;						\
	D(SYSTEM, "system_bridge_addif(%s, %s)", _bridge ? _bridge->ifname : "<none>", _dev ? _dev->ifname : "<none>");	\
	system_bridge_addif(_bridge, _dev);					\
})

#define system_bridge_delif(bridge, dev) ({ \
	struct device *_bridge = bridge;					\
	struct device *_dev = dev;						\
	D(SYSTEM, "system_bridge_delif(%s, %s)", _bridge ? _bridge->ifname : "<none>", _dev ? _dev->ifname : "<none>");	\
	system_bridge_delif(_bridge, _dev);					\
})

#define system_bridge_vlan(iface, vid, vid_end, add, vflags) ({ \
	const char *_iface = iface;						\
	uint16_t _vid = vid;							\
	int16_t _vid_end = vid_end;						\
	bool _add = add;							\
	unsigned int _vflags = vflags;						\
	D(SYSTEM, "system_bridge_vlan(%s, %s, %s, vid=%d, vid_end=%d, pvid=%d, untag=%d)", \
	  _iface ? _iface : "<none>",						\
	  _add ? "add" : "remove",						\
	  (_vflags & BRVLAN_F_SELF) ? "self" : "master",			\
	  _vid, _vid_end,							\
	  !!(_vflags & BRVLAN_F_PVID),						\
	  !!(_vflags & BRVLAN_F_UNTAGGED));					\
	system_bridge_vlan(_iface, _vid, _vid_end, _add, _vflags);		\
})

#endif
