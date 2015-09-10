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
#ifndef __NETIFD_DEVICE_H
#define __NETIFD_DEVICE_H

#include <libubox/avl.h>
#include <libubox/safe_list.h>
#include <netinet/in.h>

struct device;
struct device_user;
struct device_hotplug_ops;
struct interface;

typedef int (*device_state_cb)(struct device *, bool up);

enum {
	DEV_ATTR_TYPE,
	DEV_ATTR_MTU,
	DEV_ATTR_MTU6,
	DEV_ATTR_MACADDR,
	DEV_ATTR_TXQUEUELEN,
	DEV_ATTR_ENABLED,
	DEV_ATTR_IPV6,
	DEV_ATTR_PROMISC,
	DEV_ATTR_RPFILTER,
	DEV_ATTR_ACCEPTLOCAL,
	DEV_ATTR_IGMPVERSION,
	DEV_ATTR_MLDVERSION,
	DEV_ATTR_NEIGHREACHABLETIME,
	DEV_ATTR_RPS,
	DEV_ATTR_XPS,
	DEV_ATTR_DADTRANSMITS,
	DEV_ATTR_MULTICAST_TO_UNICAST,
	DEV_ATTR_MULTICAST_ROUTER,
	__DEV_ATTR_MAX,
};

enum dev_change_type {
	DEV_CONFIG_NO_CHANGE,
	DEV_CONFIG_APPLIED,
	DEV_CONFIG_RESTART,
	DEV_CONFIG_RECREATE,
};

struct device_type {
	struct list_head list;
	const char *name;

	bool keep_link_status;

	const struct uci_blob_param_list *config_params;

	struct device *(*create)(const char *name, struct blob_attr *attr);
	void (*config_init)(struct device *);
	enum dev_change_type (*reload)(struct device *, struct blob_attr *);
	void (*dump_info)(struct device *, struct blob_buf *buf);
	void (*dump_stats)(struct device *, struct blob_buf *buf);
	int (*check_state)(struct device *);
	void (*free)(struct device *);
};

enum {
	DEV_OPT_MTU			= (1 << 0),
	DEV_OPT_MACADDR			= (1 << 1),
	DEV_OPT_TXQUEUELEN		= (1 << 2),
	DEV_OPT_IPV6			= (1 << 3),
	DEV_OPT_PROMISC			= (1 << 4),
	DEV_OPT_RPFILTER		= (1 << 5),
	DEV_OPT_ACCEPTLOCAL		= (1 << 6),
	DEV_OPT_IGMPVERSION		= (1 << 7),
	DEV_OPT_MLDVERSION		= (1 << 8),
	DEV_OPT_NEIGHREACHABLETIME	= (1 << 9),
	DEV_OPT_RPS			= (1 << 10),
	DEV_OPT_XPS			= (1 << 11),
	DEV_OPT_MTU6			= (1 << 12),
	DEV_OPT_DADTRANSMITS		= (1 << 13),
	DEV_OPT_MULTICAST_TO_UNICAST	= (1 << 14),
	DEV_OPT_MULTICAST_ROUTER	= (1 << 15),
};

/* events broadcasted to all users of a device */
enum device_event {
	DEV_EVENT_ADD,
	DEV_EVENT_REMOVE,

	DEV_EVENT_UPDATE_IFNAME,
	DEV_EVENT_UPDATE_IFINDEX,

	DEV_EVENT_SETUP,
	DEV_EVENT_TEARDOWN,
	DEV_EVENT_UP,
	DEV_EVENT_DOWN,

	DEV_EVENT_LINK_UP,
	DEV_EVENT_LINK_DOWN,

	/* Topology changed (i.e. bridge member added) */
	DEV_EVENT_TOPO_CHANGE,

	__DEV_EVENT_MAX
};

/*
 * device dependency with callbacks
 */
struct device_user {
	struct safe_list list;

	bool claimed;
	bool hotplug;
	bool alias;

	uint8_t ev_idx[__DEV_EVENT_MAX];

	struct device *dev;
	void (*cb)(struct device_user *, enum device_event);
};

struct device_settings {
	unsigned int flags;
	unsigned int mtu;
	unsigned int mtu6;
	unsigned int txqueuelen;
	uint8_t macaddr[6];
	bool ipv6;
	bool promisc;
	unsigned int rpfilter;
	bool acceptlocal;
	unsigned int igmpversion;
	unsigned int mldversion;
	unsigned int neigh4reachabletime;
	unsigned int neigh6reachabletime;
	bool rps;
	bool xps;
	unsigned int dadtransmits;
	bool multicast_to_unicast;
	unsigned int multicast_router;
};

/*
 * link layer device. typically represents a linux network device.
 * can be used to support VLANs as well
 */
struct device {
	const struct device_type *type;

	struct avl_node avl;
	struct safe_list users;
	struct safe_list aliases;

	char ifname[IFNAMSIZ + 1];
	int ifindex;

	struct blob_attr *config;
	bool config_pending;
	bool sys_present;
	/* DEV_EVENT_ADD */
	bool present;
	/* DEV_EVENT_UP */
	int active;
	/* DEV_EVENT_LINK_UP */
	bool link_active;

	bool external;
	bool disabled;
	bool deferred;
	bool hidden;

	bool current_config;
	bool iface_config;
	bool default_config;
	bool wireless;
	bool wireless_ap;
	bool wireless_isolate;

	struct interface *config_iface;

	/* set interface up or down */
	device_state_cb set_state;

	const struct device_hotplug_ops *hotplug_ops;

	struct device_user parent;

	struct device_settings orig_settings;
	struct device_settings settings;
};

struct device_hotplug_ops {
	int (*prepare)(struct device *dev);
	int (*add)(struct device *main, struct device *member);
	int (*del)(struct device *main, struct device *member);
};

extern const struct uci_blob_param_list device_attr_list;
extern const struct device_type simple_device_type;
extern const struct device_type bridge_device_type;
extern const struct device_type tunnel_device_type;
extern const struct device_type macvlan_device_type;
extern const struct device_type vlandev_device_type;

void device_lock(void);
void device_unlock(void);

struct device *device_create(const char *name, const struct device_type *type,
			     struct blob_attr *config);
void device_init_settings(struct device *dev, struct blob_attr **tb);
void device_init_pending(void);

enum dev_change_type
device_apply_config(struct device *dev, const struct device_type *type,
		    struct blob_attr *config);

void device_reset_config(void);
void device_reset_old(void);
void device_set_default_ps(bool state);

void device_init_virtual(struct device *dev, const struct device_type *type, const char *name);
int device_init(struct device *iface, const struct device_type *type, const char *ifname);
void device_cleanup(struct device *iface);
struct device *device_get(const char *name, int create);
void device_add_user(struct device_user *dep, struct device *iface);
void device_remove_user(struct device_user *dep);
void device_broadcast_event(struct device *dev, enum device_event ev);

void device_set_present(struct device *dev, bool state);
void device_set_link(struct device *dev, bool state);
void device_set_ifindex(struct device *dev, int ifindex);
void device_refresh_present(struct device *dev);
int device_claim(struct device_user *dep);
void device_release(struct device_user *dep);
int device_check_state(struct device *dev);
void device_dump_status(struct blob_buf *b, struct device *dev);

void device_free(struct device *dev);
void device_free_unused(struct device *dev);

struct device *get_vlan_device_chain(const char *ifname, bool create);
void alias_notify_device(const char *name, struct device *dev);
struct device *device_alias_get(const char *name);

static inline void
device_set_deferred(struct device *dev, bool value)
{
	dev->deferred = value;
	device_refresh_present(dev);
}

static inline void
device_set_disabled(struct device *dev, bool value)
{
	dev->disabled = value;
	device_refresh_present(dev);
}

#endif
