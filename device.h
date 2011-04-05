#ifndef __LL_H
#define __LL_H

#include <libubox/avl.h>

struct device;
struct device_hotplug_ops;

typedef int (*device_state_cb)(struct device *, bool up);

struct device_type {
	const char *name;

	void (*dump_status)(struct device *, struct blob_buf *buf);
	int (*check_state)(struct device *);
	void (*free)(struct device *);
};

enum {
	DEV_OPT_MTU		= (1 << 0),
	DEV_OPT_MACADDR		= (1 << 1),
	DEV_OPT_TXQUEUELEN	= (1 << 2)
};

/* 
 * link layer device. typically represents a linux network device.
 * can be used to support VLANs as well
 */
struct device {
	const struct device_type *type;

	struct avl_node avl;
	struct list_head users;

	char ifname[IFNAMSIZ + 1];
	int ifindex;

	bool present;
	int active;

	/* set interface up or down */
	device_state_cb set_state;

	const struct device_hotplug_ops *hotplug_ops;

	/* settings */
	unsigned int flags;

	unsigned int mtu;
	unsigned int txqueuelen;
	uint8_t macaddr[6];

	uint32_t config_hash;
};

/* events broadcasted to all users of a device */
enum device_event {
	DEV_EVENT_ADD,
	DEV_EVENT_REMOVE,

	DEV_EVENT_SETUP,
	DEV_EVENT_TEARDOWN,
	DEV_EVENT_UP,
	DEV_EVENT_DOWN,

	DEV_EVENT_LINK_UP,
	DEV_EVENT_LINK_DOWN,
};

/*
 * device dependency with callbacks
 */
struct device_user {
	struct list_head list;

	struct device *dev;
	void (*cb)(struct device_user *, enum device_event);
};

struct device_hotplug_ops {
	int (*add)(struct device *main, struct device *member);
	int (*del)(struct device *main, struct device *member);
};

static inline void
free_device(struct device *dev)
{
	dev->type->free(dev);
}

void init_virtual_device(struct device *dev, const struct device_type *type, const char *name);
int init_device(struct device *iface, const struct device_type *type, const char *ifname);
void cleanup_device(struct device *iface);
struct device *get_device(const char *name, bool create);
void add_device_user(struct device_user *dep, struct device *iface);
void remove_device_user(struct device_user *dep);

void set_device_present(struct device *dev, bool state);
int claim_device(struct device *dev);
void release_device(struct device *dev);
int check_device_state(struct device *dev);

struct device *get_vlan_device_chain(const char *ifname, bool create);
struct device *bridge_create(const char *name, struct uci_section *s);

#endif
