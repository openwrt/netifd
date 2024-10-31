#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "netifd.h"
#include "device.h"
#include "system.h"

enum {
	VRF_ATTR_PORTS,
	VRF_ATTR_TABLE,
	__VRF_ATTR_MAX
};

static const struct blobmsg_policy vrf_attrs[__VRF_ATTR_MAX] = {
	[VRF_ATTR_PORTS] = { "ports", BLOBMSG_TYPE_ARRAY },
	[VRF_ATTR_TABLE] = { "table", BLOBMSG_TYPE_STRING },
};

static const struct uci_blob_param_info vrf_attr_info[__VRF_ATTR_MAX] = {
	[VRF_ATTR_PORTS] = { .type = BLOBMSG_TYPE_STRING },
};

static const struct uci_blob_param_list vrf_attr_list = {
	.n_params = __VRF_ATTR_MAX,
	.params = vrf_attrs,
	.info = vrf_attr_info,

	.n_next = 1,
	.next = { &device_attr_list },
};

static struct device *vrf_create(const char *name, struct device_type *devtype,
	struct blob_attr *attr);
static void vrf_config_init(struct device *dev);
static void vrf_free(struct device *dev);
static void vrf_dump_info(struct device *dev, struct blob_buf *b);
static enum dev_change_type
vrf_reload(struct device *dev, struct blob_attr *attr);

static struct device_type vrf_state_type = {
	.name = "vrf",
	.config_params = &vrf_attr_list,

	.bridge_capability = true,

	.create = vrf_create,
	.config_init = vrf_config_init,
	.reload = vrf_reload,
	.free = vrf_free,
	.dump_info = vrf_dump_info,
};

struct vrf_state {
	struct device dev;
	device_state_cb set_state;

	struct blob_attr *config_data;
	unsigned int table;
	bool vrf_empty;
	struct blob_attr *ports;
	bool active;
	bool force_active;

	struct uloop_timeout retry;
	struct vrf_member *primary_port;
	struct vlist_tree members;
	int n_present;
	int n_failed;
};

struct vrf_member {
	struct vlist_node node;
	struct vrf_state *vst;
	struct device_user dev;
	bool present;
	bool active;
	char name[];
};

static void
vrf_reset_primary(struct vrf_state *vst)
{
	struct vrf_member *vm;

	if (!vst->primary_port &&
		(vst->dev.settings.flags & DEV_OPT_MACADDR))
		return;

	vst->primary_port = NULL;
	vst->dev.settings.flags &= ~DEV_OPT_MACADDR;
	vlist_for_each_element(&vst->members, vm, node) {
		uint8_t *macaddr;

		if (!vm->present)
			continue;

		vst->primary_port = vm;
		if (vm->dev.dev->settings.flags & DEV_OPT_MACADDR)
			macaddr = vm->dev.dev->settings.macaddr;
		else
			macaddr = vm->dev.dev->orig_settings.macaddr;
		memcpy(vst->dev.settings.macaddr, macaddr, 6);
		vst->dev.settings.flags |= DEV_OPT_MACADDR;
		return;
	}
}

static int
vrf_disable_member(struct vrf_member *vm, bool keep_dev)
{
	struct vrf_state *vst = vm->vst;

	if (!vm->present || !vm->active)
		return 0;

	vm->active = false;

	system_vrf_delif(&vst->dev, vm->dev.dev);
	if (!keep_dev)
		device_release(&vm->dev);

	device_broadcast_event(&vst->dev, DEV_EVENT_TOPO_CHANGE);

	return 0;
}

static int
vrf_enable_interface(struct vrf_state *vst)
{
	int ret;

	if (vst->active)
		return 0;

	ret = system_vrf_addvrf(&vst->dev, vst->table);
	if (ret < 0)
		return ret;

	vst->active = true;
	return 0;
}

static void
vrf_disable_interface(struct vrf_state *vst)
{
	if (!vst->active)
		return;

	system_vrf_delvrf(&vst->dev);
	vst->active = false;
}

static int
vrf_enable_member(struct vrf_member *vm)
{
	struct vrf_state *vst = vm->vst;
	struct device *dev;
	int ret;

	if (!vm->present)
		return 0;

	ret = vrf_enable_interface(vst);
	if (ret)
		goto error;

	/* Disable IPv6 for vrf ports */
	if (!(vm->dev.dev->settings.flags & DEV_OPT_IPV6)) {
		vm->dev.dev->settings.ipv6 = 0;
		vm->dev.dev->settings.flags |= DEV_OPT_IPV6;
	}

	ret = device_claim(&vm->dev);
	if (ret < 0)
		goto error;

	dev = vm->dev.dev;
	if (dev->settings.auth && !dev->auth_status)
		return -1;

	if (vm->active)
		return 0;

	ret = system_vrf_addif(&vst->dev, vm->dev.dev);
	if (ret < 0) {
		D(DEVICE, "Vrf device %s could not be added\n", vm->dev.dev->ifname);
		goto error;
	}

	vm->active = true;
	device_set_present(&vst->dev, true);
	device_broadcast_event(&vst->dev, DEV_EVENT_TOPO_CHANGE);

	return 0;

error:
	vst->n_failed++;
	vm->present = false;
	vst->n_present--;
	device_release(&vm->dev);

	return ret;
}

static void
vrf_remove_member(struct vrf_member *vm)
{
	struct vrf_state *vst = vm->vst;

	if (!vm->present)
		return;

	if (vst->dev.active)
		vrf_disable_member(vm, false);

	vm->present = false;
	vm->vst->n_present--;

	if (vm == vst->primary_port)
		vrf_reset_primary(vst);

	if (vst->vrf_empty)
		return;

	vst->force_active = false;
	if (vst->n_present == 0)
		device_set_present(&vst->dev, false);
}

static void
vrf_free_member(struct vrf_member *vm)
{
	struct device *dev = vm->dev.dev;

	vrf_remove_member(vm);
	device_remove_user(&vm->dev);

	/*
	 * When reloading the config and moving a device from one vrf to
	 * another, the other vrf may have tried to claim this device
	 * before it was removed here.
	 * Ensure that claiming the device is retried by toggling its present
	 * state
	 */
	if (dev->present) {
		device_set_present(dev, false);
		device_set_present(dev, true);
	}

	free(vm);
}

static void
vrf_check_retry(struct vrf_state *vst)
{
	if (!vst->n_failed)
		return;

	uloop_timeout_set(&vst->retry, 100);
}

static void
vrf_member_cb(struct device_user *dep, enum device_event ev)
{
	struct vrf_member *vm = container_of(dep, struct vrf_member, dev);
	struct vrf_state *vst = vm->vst;
	struct device *dev = dep->dev;

	switch (ev) {
	case DEV_EVENT_ADD:
		assert(!vm->present);

		vm->present = true;
		vst->n_present++;

		if (vst->n_present == 1)
			device_set_present(&vst->dev, true);
		fallthrough;
	case DEV_EVENT_AUTH_UP:
		if (!vst->dev.active)
			break;

		if (vrf_enable_member(vm))
			break;

		/*
		 * Adding a vrf port can overwrite the vrf device mtu
		 * in the kernel, apply the vrf settings in case the
		 * vrf device mtu is set
		 */
		system_if_apply_settings(&vst->dev, &vst->dev.settings,
					 DEV_OPT_MTU | DEV_OPT_MTU6);
		break;
	case DEV_EVENT_LINK_DOWN:
		if (!dev->settings.auth)
			break;

		vrf_disable_member(vm, true);
		break;
	case DEV_EVENT_REMOVE:
		if (dep->hotplug && !dev->sys_present) {
			vlist_delete(&vst->members, &vm->node);
			return;
		}

		if (vm->present)
			vrf_remove_member(vm);

		break;
	default:
		return;
	}
}

static int
vrf_set_down(struct vrf_state *vst)
{
	struct vrf_member *vm;

	vst->set_state(&vst->dev, false);

	vlist_for_each_element(&vst->members, vm, node)
		vrf_disable_member(vm, false);

	vrf_disable_interface(vst);

	return 0;
}

static int
vrf_set_up(struct vrf_state *vst)
{
	struct vrf_member *vm;
	int ret;

	if (!vst->n_present) {
		if (!vst->force_active)
			return -ENOENT;

		ret = vrf_enable_interface(vst);
		if (ret)
			return ret;
	}

	vst->n_failed = 0;
	vlist_for_each_element(&vst->members, vm, node)
		vrf_enable_member(vm);
	vrf_check_retry(vst);

	if (!vst->force_active && !vst->n_present) {
		/* initialization of all port member failed */
		vrf_disable_interface(vst);
		device_set_present(&vst->dev, false);
		return -ENOENT;
	}

	vrf_reset_primary(vst);
	ret = vst->set_state(&vst->dev, true);
	if (ret < 0)
		vrf_set_down(vst);

	return ret;
}

static int
vrf_set_state(struct device *dev, bool up)
{
	struct vrf_state *vst;

	vst = container_of(dev, struct vrf_state, dev);

	if (up)
		return vrf_set_up(vst);
	else
		return vrf_set_down(vst);
}

static struct vrf_member *
vrf_create_member(struct vrf_state *vst, const char *name,
			struct device *dev, bool hotplug)
{
	struct vrf_member *vm;

	vm = calloc(1, sizeof(*vm) + strlen(name) + 1);
	if (!vm)
		return NULL;

	vm->vst = vst;
	vm->dev.cb = vrf_member_cb;
	vm->dev.hotplug = hotplug;
	strcpy(vm->name, name);
	vm->dev.dev = dev;
	vlist_add(&vst->members, &vm->node, vm->name);
	/*
	 * Need to look up the vrf port again as the above
	 * created pointer will be freed in case the vrf port
	 * already existed
	 */
	vm = vlist_find(&vst->members, name, vm, node);
	if (hotplug && vm)
		vm->node.version = -1;

	return vm;
}

static void
vrf_member_update(struct vlist_tree *tree, struct vlist_node *node_new,
			 struct vlist_node *node_old)
{
	struct vrf_member *vm;
	struct device *dev;

	if (node_new) {
		vm = container_of(node_new, struct vrf_member, node);

		if (node_old) {
			free(vm);
			return;
		}

		dev = vm->dev.dev;
		vm->dev.dev = NULL;
		device_add_user(&vm->dev, dev);
	}


	if (node_old) {
		vm = container_of(node_old, struct vrf_member, node);
		vrf_free_member(vm);
	}
}

static void
vrf_add_member(struct vrf_state *vst, const char *name)
{
	struct device *dev;

	dev = device_get(name, true);
	if (!dev)
		return;

	vrf_create_member(vst, name, dev, false);
}

static int
vrf_hotplug_add(struct device *dev, struct device *member, struct blob_attr *vlan)
{
	struct vrf_state *vst = container_of(dev, struct vrf_state, dev);
	struct vrf_member *vm;

	vm = vlist_find(&vst->members, member->ifname, vm, node);
	if (!vm)
		vrf_create_member(vst, member->ifname, member, true);

	return 0;
}

static int
vrf_hotplug_del(struct device *dev, struct device *member, struct blob_attr *vlan)
{
	struct vrf_state *vst = container_of(dev, struct vrf_state, dev);
	struct vrf_member *vm;

	vm = vlist_find(&vst->members, member->ifname, vm, node);
	if (!vm)
		return UBUS_STATUS_NOT_FOUND;

	if (vm->dev.hotplug)
		vlist_delete(&vst->members, &vm->node);

	return 0;
}

static int
vrf_hotplug_prepare(struct device *dev, struct device **vrf_dev)
{
	struct vrf_state *vst;

	if (vrf_dev)
		*vrf_dev = dev;

	vst = container_of(dev, struct vrf_state, dev);
	vst->force_active = true;
	device_set_present(&vst->dev, true);

	return 0;
}

static const struct device_hotplug_ops vrf_ops = {
	.prepare = vrf_hotplug_prepare,
	.add = vrf_hotplug_add,
	.del = vrf_hotplug_del
};

static void
vrf_free(struct device *dev)
{
	struct vrf_state *vst;

	vst = container_of(dev, struct vrf_state, dev);
	vlist_flush_all(&vst->members);
	free(vst->config_data);
	free(vst);
}

static void
vrf_dump_info(struct device *dev, struct blob_buf *b)
{
	struct vrf_state *vst;
	struct vrf_member *vm;
	void *list;

	vst = container_of(dev, struct vrf_state, dev);

	system_if_dump_info(dev, b);
	list = blobmsg_open_array(b, "vrf-members");

	vlist_for_each_element(&vst->members, vm, node) {
		if (vm->dev.dev->hidden)
			continue;

		blobmsg_add_string(b, NULL, vm->dev.dev->ifname);
	}

	blobmsg_close_array(b, list);
}

static void
vrf_config_init(struct device *dev)
{
	struct vrf_state *vst;
	struct blob_attr *cur;
	size_t rem;

	vst = container_of(dev, struct vrf_state, dev);

	if (vst->vrf_empty) {
		vst->force_active = true;
		device_set_present(&vst->dev, true);
	}

	vst->n_failed = 0;
	vlist_update(&vst->members);
	if (vst->ports) {
		blobmsg_for_each_attr(cur, vst->ports, rem) {
			vrf_add_member(vst, blobmsg_data(cur));
		}
	}

	vlist_flush(&vst->members);
	vrf_check_retry(vst);
}

static void
vrf_apply_settings(struct vrf_state *vst, struct blob_attr **tb)
{
	struct blob_attr *cur;

	vst->vrf_empty = true;
	// default vrf routing table
	vst->table = 10;
	if ((cur = tb[VRF_ATTR_TABLE]))
		system_resolve_rt_table(blobmsg_data(cur), &vst->table);
}

static enum dev_change_type
vrf_reload(struct device *dev, struct blob_attr *attr)
{
	struct blob_attr *tb_dev[__DEV_ATTR_MAX];
	struct blob_attr *tb_v[__VRF_ATTR_MAX];
	enum dev_change_type ret = DEV_CONFIG_APPLIED;
	struct vrf_state *vst;
	unsigned long diff[2];

	BUILD_BUG_ON(sizeof(diff) < __VRF_ATTR_MAX / BITS_PER_LONG);
	BUILD_BUG_ON(sizeof(diff) < __DEV_ATTR_MAX / BITS_PER_LONG);

	vst = container_of(dev, struct vrf_state, dev);
	attr = blob_memdup(attr);

	blobmsg_parse(device_attr_list.params, __DEV_ATTR_MAX, tb_dev,
		blob_data(attr), blob_len(attr));
	blobmsg_parse(vrf_attrs, __VRF_ATTR_MAX, tb_v,
		blob_data(attr), blob_len(attr));

	if (tb_dev[DEV_ATTR_MACADDR])
		vst->primary_port = NULL;

	vst->ports = tb_v[VRF_ATTR_PORTS];
	device_init_settings(dev, tb_dev);
	vrf_apply_settings(vst, tb_v);

	if (vst->config_data) {
		struct blob_attr *otb_dev[__DEV_ATTR_MAX];
		struct blob_attr *otb_v[__VRF_ATTR_MAX];

		blobmsg_parse(device_attr_list.params, __DEV_ATTR_MAX, otb_dev,
			blob_data(vst->config_data), blob_len(vst->config_data));

		diff[0] = diff[1] = 0;
		uci_blob_diff(tb_dev, otb_dev, &device_attr_list, diff);
		if (diff[0] | diff[1]) {
			ret = DEV_CONFIG_RESTART;
			D(DEVICE, "Vrf %s device attributes have changed, diff=[%lx %lx]\n",
			  dev->ifname, diff[1], diff[0]);
		}

		blobmsg_parse(vrf_attrs, __VRF_ATTR_MAX, otb_v,
			blob_data(vst->config_data), blob_len(vst->config_data));

		diff[0] = diff[1] = 0;
		uci_blob_diff(tb_v, otb_v, &vrf_attr_list, diff);
		if (diff[0] & ~(1 << VRF_ATTR_PORTS)) {
			ret = DEV_CONFIG_RESTART;
			D(DEVICE, "Vrf %s attributes have changed, diff=[%lx %lx]\n",
			  dev->ifname, diff[1], diff[0]);
		}

		vrf_config_init(dev);
	}

	free(vst->config_data);
	vst->config_data = attr;
	return ret;
}

static void
vrf_retry_members(struct uloop_timeout *timeout)
{
	struct vrf_state *vst = container_of(timeout, struct vrf_state, retry);
	struct vrf_member *vm;

	vst->n_failed = 0;
	vlist_for_each_element(&vst->members, vm, node) {
		if (vm->present)
			continue;

		if (!vm->dev.dev->present)
			continue;

		vm->present = true;
		vst->n_present++;
		vrf_enable_member(vm);
	}
}

static struct device *
vrf_create(const char *name, struct device_type *devtype,
	struct blob_attr *attr)
{
	struct vrf_state *vst;
	struct device *dev = NULL;

	vst = calloc(1, sizeof(*vst));
	if (!vst)
		return NULL;

	dev = &vst->dev;

	if (device_init(dev, devtype, name) < 0) {
		device_cleanup(dev);
		free(vst);
		return NULL;
	}

	dev->config_pending = true;
	vst->retry.cb = vrf_retry_members;

	vst->set_state = dev->set_state;
	dev->set_state = vrf_set_state;

	dev->hotplug_ops = &vrf_ops;

	vlist_init(&vst->members, avl_strcmp, vrf_member_update);
	vst->members.keep_old = true;

	vrf_reload(dev, attr);

	return dev;
}

static void __init vrf_state_type_init(void)
{
	device_type_add(&vrf_state_type);
}
