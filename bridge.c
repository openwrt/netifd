#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "system.h"

struct bridge_state {
	struct device dev;
	device_state_cb set_state;

	bool active;

	struct list_head members;
	int n_present;
};

struct bridge_member {
	struct list_head list;
	struct bridge_state *bst;
	struct device_user dev;
	bool present;
};

static int
bridge_disable_member(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;

	if (!bm->present)
		return 0;

	system_bridge_delif(&bst->dev, bm->dev.dev);
	release_device(bm->dev.dev);

	return 0;
}

static int
bridge_enable_member(struct bridge_member *bm)
{
	struct bridge_state *bst = bm->bst;
	int ret;

	if (!bm->present)
		return 0;

	ret = claim_device(bm->dev.dev);
	if (ret < 0)
		goto error;

	ret = system_bridge_addif(&bst->dev, bm->dev.dev);
	if (ret < 0)
		goto error;

	return 0;

error:
	bm->present = false;
	bst->n_present--;
	return ret;
}

static void
bridge_member_cb(struct device_user *dev, enum device_event ev)
{
	struct bridge_member *bm = container_of(dev, struct bridge_member, dev);
	struct bridge_state *bst = bm->bst;

	switch (ev) {
	case DEV_EVENT_ADD:
		assert(!bm->present);

		bm->present = true;
		bst->n_present++;

		if (bst->dev.active)
			bridge_enable_member(bm);
		else if (bst->n_present == 1)
			device_set_present(&bst->dev, true);

		break;
	case DEV_EVENT_REMOVE:
		if (!bm->present)
			return;

		if (bst->dev.active)
			bridge_disable_member(bm);

		bm->present = false;
		bm->bst->n_present--;
		if (bst->n_present == 0)
			device_set_present(&bst->dev, false);

		break;
	default:
		return;
	}
}

static int
bridge_set_down(struct bridge_state *bst)
{
	struct bridge_member *bm;

	bst->set_state(&bst->dev, false);

	list_for_each_entry(bm, &bst->members, list)
		bridge_disable_member(bm);

	system_bridge_delbr(&bst->dev);

	return 0;
}

static int
bridge_set_up(struct bridge_state *bst)
{
	struct bridge_member *bm;
	int ret;

	if (!bst->n_present)
		return -ENOENT;

	ret = system_bridge_addbr(&bst->dev);
	if (ret < 0)
		goto out;

	list_for_each_entry(bm, &bst->members, list)
		bridge_enable_member(bm);

	if (!bst->n_present) {
		/* initialization of all member interfaces failed */
		system_bridge_delbr(&bst->dev);
		device_set_present(&bst->dev, false);
		return -ENOENT;
	}

	ret = bst->set_state(&bst->dev, true);
	if (ret < 0)
		bridge_set_down(bst);

out:
	return ret;
}

static int
bridge_set_state(struct device *dev, bool up)
{
	struct bridge_state *bst;

	bst = container_of(dev, struct bridge_state, dev);

	if (up)
		return bridge_set_up(bst);
	else
		return bridge_set_down(bst);
}

static struct bridge_member *
bridge_create_member(struct bridge_state *bst, struct device *dev)
{
	struct bridge_member *bm;

	bm = calloc(1, sizeof(*bm));
	bm->bst = bst;
	bm->dev.cb = bridge_member_cb;
	device_add_user(&bm->dev, dev);

	list_add(&bm->list, &bst->members);

	if (bst->dev.active)
		bridge_enable_member(bm);

	return bm;
}

static void
bridge_free_member(struct bridge_member *bm)
{
	if (bm->present) {
		bridge_member_cb(&bm->dev, DEV_EVENT_REMOVE);
		bm->bst->n_present--;
		if (bm->bst->dev.active)
			bridge_disable_member(bm);
	}

	list_del(&bm->list);
	device_remove_user(&bm->dev);
	free(bm);
}

static void
bridge_add_member(struct bridge_state *bst, const char *name)
{
	struct device *dev;

	dev = device_get(name, true);
	if (!dev)
		return;

	bridge_create_member(bst, dev);
}

static int
bridge_hotplug_add(struct device *dev, struct device *member)
{
	struct bridge_state *bst = container_of(dev, struct bridge_state, dev);

	bridge_create_member(bst, member);

	return 0;
}

static int
bridge_hotplug_del(struct device *dev, struct device *member)
{
	struct bridge_state *bst = container_of(dev, struct bridge_state, dev);
	struct bridge_member *bm;

	list_for_each_entry(bm, &bst->members, list) {
		if (bm->dev.dev != member)
			continue;

		bridge_free_member(bm);
		return 0;
	}

	return -ENOENT;
}

static const struct device_hotplug_ops bridge_ops = {
	.add = bridge_hotplug_add,
	.del = bridge_hotplug_del
};

static void
bridge_parse_config(struct bridge_state *bst, struct uci_section *s)
{
	struct uci_element *e;
	struct uci_option *o;
	char buf[IFNAMSIZ + 1];
	char *p, *end;
	int len;

	o = uci_lookup_option(uci_ctx, s, "ifname");
	if (!o)
		return;

	if (o->type == UCI_TYPE_LIST) {
		uci_foreach_element(&o->v.list, e)
			bridge_add_member(bst, e->name);
	} else {
		p = o->v.string;
		do {
			if (!*p)
				break;

			if (*p == ' ')
				continue;

			end = strchr(p, ' ');
			if (!end) {
				bridge_add_member(bst, p);
				break;
			}

			len = end - p;
			if (len <= IFNAMSIZ) {
				memcpy(buf, p, len);
				buf[len] = 0;
				bridge_add_member(bst, buf);
			}
			p = end;
		} while (p++);
	}
}

static void
bridge_free(struct device *dev)
{
	struct bridge_state *bst;
	struct bridge_member *bm;

	bst = container_of(dev, struct bridge_state, dev);
	while (!list_empty(&bst->members)) {
		bm = list_first_entry(&bst->members, struct bridge_member, list);
		bridge_free_member(bm);
	}
	free(bst);
}

static void
bridge_dump_status(struct device *dev, struct blob_buf *b)
{
	struct bridge_state *bst;
	struct bridge_member *bm;
	void *list;

	bst = container_of(dev, struct bridge_state, dev);

	list = blobmsg_open_array(b, "bridge-members");
	list_for_each_entry(bm, &bst->members, list) {
		blobmsg_add_string(b, NULL, bm->dev.dev->ifname);
	}
	blobmsg_close_array(b, list);
}

struct device *
bridge_create(const char *name, struct uci_section *s)
{
	static const struct device_type bridge_type = {
		.name = "Bridge",
		.free = bridge_free,
		.dump_status = bridge_dump_status,
	};
	struct bridge_state *bst;
	struct device *dev;

	dev = device_get(name, false);
	if (dev)
		return NULL;

	bst = calloc(1, sizeof(*bst));
	if (!bst)
		return NULL;

	device_init(&bst->dev, &bridge_type, name);

	bst->set_state = bst->dev.set_state;
	bst->dev.set_state = bridge_set_state;

	bst->dev.hotplug_ops = &bridge_ops;

	INIT_LIST_HEAD(&bst->members);

	if (s)
		bridge_parse_config(bst, s);

	return &bst->dev;
}

int
interface_attach_bridge(struct interface *iface, struct uci_section *s)
{
	struct device *dev;
	char brname[IFNAMSIZ];

	snprintf(brname, IFNAMSIZ - 1, "br-%s", iface->name);
	brname[IFNAMSIZ - 1] = 0;

	dev = bridge_create(brname, s);
	if (!dev)
		return -1;

	device_add_user(&iface->main_dev, dev);
	return 0;
}
