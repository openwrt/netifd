#ifndef __LL_H
#define __LL_H

#include <libubox/avl.h>
#include <netinet/in.h>

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

enum device_addr_flags {
	/* address family for routes and addresses */
	DEVADDR_INET4	= (0 << 0),
	DEVADDR_INET6	= (1 << 0),
	DEVADDR_FAMILY	= DEVADDR_INET4 | DEVADDR_INET6,

	/* device route (no gateway) */
	DEVADDR_DEVICE	= (1 << 1),
};

union if_addr {
	struct in_addr in;
	struct in6_addr in6;
};

struct device_addr {
	struct list_head list;
	void *ctx;

	enum device_addr_flags flags;

	unsigned int mask;
	union if_addr addr;
};

struct device_route {
	struct list_head list;
	void *ctx;

	enum device_addr_flags flags;

	unsigned int mask;
	union if_addr addr;
	union if_addr nexthop;
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

extern const struct config_param_list device_attr_list;

struct device *device_create(struct blob_attr *attr, struct uci_section *s);

void device_init_virtual(struct device *dev, const struct device_type *type, const char *name);
int device_init(struct device *iface, const struct device_type *type, const char *ifname);
void device_cleanup(struct device *iface);
struct device *device_get(const char *name, bool create);
void device_add_user(struct device_user *dep, struct device *iface);
void device_remove_user(struct device_user *dep);

void device_set_present(struct device *dev, bool state);
int device_claim(struct device *dev);
void device_release(struct device *dev);
int check_device_state(struct device *dev);

static inline void
device_free(struct device *dev)
{
	dev->type->free(dev);
}

void device_free_all(void);

struct device *get_vlan_device_chain(const char *ifname, bool create);
struct device *bridge_create(const char *name, struct uci_section *s);

#endif
