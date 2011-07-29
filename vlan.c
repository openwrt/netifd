#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netifd.h"
#include "system.h"

struct vlan_device {
	struct device dev;
	struct device_user dep;

	device_state_cb set_state;
	int id;
};

static void free_vlan_if(struct device *iface)
{
	struct vlan_device *vldev;

	vldev = container_of(iface, struct vlan_device, dev);
	device_remove_user(&vldev->dep);
	cleanup_device(&vldev->dev);
	free(vldev);
}

static int vlan_set_device_state(struct device *dev, bool up)
{
	struct vlan_device *vldev;
	int ret = 0;

	vldev = container_of(dev, struct vlan_device, dev);
	if (!up) {
		vldev->set_state(dev, false);
		system_vlan_del(dev);
		release_device(vldev->dep.dev);
		return 0;
	}

	ret = claim_device(vldev->dep.dev);
	if (ret)
		return ret;

	system_vlan_add(vldev->dep.dev, vldev->id);
	ret = vldev->set_state(dev, true);
	if (ret)
		release_device(vldev->dep.dev);

	return ret;
}

static void vlan_dev_cb(struct device_user *dep, enum device_event ev)
{
	struct vlan_device *vldev;

	vldev = container_of(dep, struct vlan_device, dep);
	switch(ev) {
	case DEV_EVENT_ADD:
		device_set_present(&vldev->dev, true);
		break;
	case DEV_EVENT_REMOVE:
		device_set_present(&vldev->dev, false);
		break;
	default:
		break;
	}
}

static struct device *get_vlan_device(struct device *dev, int id, bool create)
{
	static const struct device_type vlan_type = {
		.name = "VLAN",
		.free = free_vlan_if,
	};
	struct vlan_device *vldev;
	struct device_user *dep;

	/* look for an existing interface before creating a new one */
	list_for_each_entry(dep, &dev->users, list) {
		if (dep->cb != vlan_dev_cb)
			continue;

		vldev = container_of(dep, struct vlan_device, dep);
		if (vldev->id != id)
			continue;

		return &vldev->dev;
	}

	if (!create)
		return NULL;

	vldev = calloc(1, sizeof(*vldev));
	snprintf(vldev->dev.ifname, IFNAMSIZ, "%s.%d", dev->ifname, id);

	init_device(&vldev->dev, &vlan_type, NULL);

	vldev->set_state = vldev->dev.set_state;
	vldev->dev.set_state = vlan_set_device_state;

	vldev->id = id;

	vldev->dep.cb = vlan_dev_cb;
	device_add_user(&vldev->dep, dev);

	return &vldev->dev;
}

static char *split_vlan(char *s)
{
	s = strchr(s, '.');
	if (!s)
		goto out;

	*s = 0;
	s++;

out:
	return s;
}

struct device *get_vlan_device_chain(const char *ifname, bool create)
{
	struct device *iface = NULL;
	char *buf, *s, *next, *err = NULL;
	int id;

	buf = strdup(ifname);
	if (!buf)
		return NULL;

	s = split_vlan(buf);
	iface = get_device(buf, create);
	if (!iface && !create)
		goto error;

	do {
		next = split_vlan(s);
		id = strtoul(s, &err, 10);
		if (err && *err)
			goto error;

		iface = get_vlan_device(iface, id, create);
		if (!iface)
			goto error;

		s = next;
		if (!s)
			goto out;
	} while (1);

error:
	iface = NULL;
out:
	free(buf);
	return iface;
}
