#include "netifd.h"
#include "device.h"
#include "config.h"
#include "system.h"

struct tunnel {
	struct device dev;
	device_state_cb set_state;
	struct blob_attr *config;
};

static int
tunnel_set_state(struct device *dev, bool up)
{
	struct tunnel *tun = container_of(dev, struct tunnel, dev);
	int ret;

	if (up) {
		ret = system_add_ip_tunnel(dev->ifname, tun->config);
		if (ret != 0)
			return ret;
	}

	ret = tun->set_state(dev, up);
	if (ret || !up)
		system_del_ip_tunnel(dev->ifname);

	return ret;
}

static struct device *
tunnel_create(const char *name, struct blob_attr *attr)
{
	struct tunnel *tun;
	struct device *dev;

	tun = calloc(1, sizeof(*tun));
	dev = &tun->dev;
	tun->config = config_memdup(attr);
	device_init(dev, &tunnel_device_type, name);
	tun->set_state = dev->set_state;
	dev->set_state = tunnel_set_state;
	device_set_present(dev, true);

	return dev;
}

static void
tunnel_free(struct device *dev)
{
	struct tunnel *tun = container_of(dev, struct tunnel, dev);

	free(tun);
}

const struct device_type tunnel_device_type = {
	.name = "IP tunnel",
	.config_params = &tunnel_attr_list,

	.create = tunnel_create,
	.free = tunnel_free,
};


