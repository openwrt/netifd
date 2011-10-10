#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <glob.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <libubox/uloop.h>

#include "netifd.h"
#include "device.h"
#include "system.h"

static int sock_ioctl = -1;
static struct nl_sock *sock_rtnl = NULL;
static struct nl_sock *sock_rtnl_event = NULL;

static void handler_rtnl_event(struct uloop_fd *u, unsigned int events);
static int cb_rtnl_event(struct nl_msg *msg, void *arg);
static struct uloop_fd rtnl_event = {.cb = handler_rtnl_event};
static struct nl_cb *nl_cb_rtnl_event;

int system_init(void)
{
	sock_ioctl = socket(AF_LOCAL, SOCK_DGRAM, 0);
	fcntl(sock_ioctl, F_SETFD, fcntl(sock_ioctl, F_GETFD) | FD_CLOEXEC);

	// Prepare socket for routing / address control
	sock_rtnl = nl_socket_alloc();
	if (!sock_rtnl)
		return -1;

	if (nl_connect(sock_rtnl, NETLINK_ROUTE))
		goto error_free_sock;

	// Prepare socket for link events
	nl_cb_rtnl_event = nl_cb_alloc(NL_CB_DEFAULT);
	if (!nl_cb_rtnl_event)
		goto error_free_sock;

	nl_cb_set(nl_cb_rtnl_event, NL_CB_VALID, NL_CB_CUSTOM,
		  cb_rtnl_event, NULL);

	sock_rtnl_event = nl_socket_alloc();
	if (!sock_rtnl_event)
		goto error_free_cb;

	if (nl_connect(sock_rtnl_event, NETLINK_ROUTE))
		goto error_free_event;

	// Receive network link events form kernel
	nl_socket_add_membership(sock_rtnl_event, RTNLGRP_LINK);

	rtnl_event.fd = nl_socket_get_fd(sock_rtnl_event);
	uloop_fd_add(&rtnl_event, ULOOP_READ | ULOOP_EDGE_TRIGGER);

	return 0;

error_free_event:
	nl_socket_free(sock_rtnl_event);
	sock_rtnl_event = NULL;
error_free_cb:
	nl_cb_put(nl_cb_rtnl_event);
	nl_cb_rtnl_event = NULL;
error_free_sock:
	nl_socket_free(sock_rtnl);
	sock_rtnl = NULL;
	return -1;
}

// If socket is ready for reading parse netlink events
static void handler_rtnl_event(struct uloop_fd *u, unsigned int events)
{
	nl_recvmsgs(sock_rtnl_event, nl_cb_rtnl_event);
}

// Evaluate netlink messages
static int cb_rtnl_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nh = nlmsg_hdr(msg);
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct nlattr *nla[__IFLA_MAX];

	if (nh->nlmsg_type != RTM_DELLINK && nh->nlmsg_type != RTM_NEWLINK)
		goto out;

	nlmsg_parse(nh, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);
	if (!nla[IFLA_IFNAME])
		goto out;

	struct device *dev = device_get(RTA_DATA(nla[IFLA_IFNAME]), false);
	if (!dev)
		goto out;

	dev->ifindex = ifi->ifi_index;
	device_set_present(dev, (nh->nlmsg_type == RTM_NEWLINK));

out:
	return 0;
}

static int system_rtnl_call(struct nl_msg *msg)
{
	int s = -(nl_send_auto_complete(sock_rtnl, msg)
			|| nl_wait_for_ack(sock_rtnl));
	nlmsg_free(msg);
	return s;
}

int system_bridge_delbr(struct device *bridge)
{
	return ioctl(sock_ioctl, SIOCBRDELBR, bridge->ifname);
}

static int system_bridge_if(const char *bridge, struct device *dev, int cmd, void *data)
{
	struct ifreq ifr;
	if (dev)
		ifr.ifr_ifindex = dev->ifindex;
	else
		ifr.ifr_data = data;
	strncpy(ifr.ifr_name, bridge, sizeof(ifr.ifr_name));
	return ioctl(sock_ioctl, cmd, &ifr);
}

int system_bridge_addif(struct device *bridge, struct device *dev)
{
	return system_bridge_if(bridge->ifname, dev, SIOCBRADDIF, NULL);
}

int system_bridge_delif(struct device *bridge, struct device *dev)
{
	return system_bridge_if(bridge->ifname, dev, SIOCBRDELIF, NULL);
}

static bool system_is_bridge(const char *name, char *buf, int buflen)
{
	struct stat st;

	snprintf(buf, buflen, "/sys/devices/virtual/net/%s/bridge", name);
	if (stat(buf, &st) < 0)
		return false;

	return true;
}

static char *system_get_bridge(const char *name, char *buf, int buflen)
{
	char *path;
	ssize_t len;
	glob_t gl;

	snprintf(buf, buflen, "/sys/devices/virtual/net/*/brif/%s/bridge", name);
	if (glob(buf, GLOB_NOSORT, NULL, &gl) < 0)
		return NULL;

	if (gl.gl_pathc == 0)
		return NULL;

	len = readlink(gl.gl_pathv[0], buf, buflen);
	if (len < 0)
		return NULL;

	buf[len] = 0;
	path = strrchr(buf, '/');
	if (!path)
		return NULL;

	return path + 1;
}

static int system_if_resolve(struct device *dev)
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name));
	if (!ioctl(sock_ioctl, SIOCGIFINDEX, &ifr))
		return ifr.ifr_ifindex;
	else
		return 0;
}

static int system_if_flags(const char *ifname, unsigned add, unsigned rem)
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ioctl(sock_ioctl, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= add;
	ifr.ifr_flags &= ~rem;
	return ioctl(sock_ioctl, SIOCSIFFLAGS, &ifr);
}

/*
 * Clear bridge (membership) state and bring down device
 */
void system_if_clear_state(struct device *dev)
{
	char buf[256];
	char *bridge;

	dev->ifindex = system_if_resolve(dev);
	if (!dev->ifindex)
		return;

	system_if_flags(dev->ifname, 0, IFF_UP);

	if (system_is_bridge(dev->ifname, buf, sizeof(buf))) {
		D(SYSTEM, "Delete existing bridge named '%s'\n", dev->ifname);
		system_bridge_delbr(dev);
		return;
	}

	bridge = system_get_bridge(dev->ifname, buf, sizeof(buf));
	if (bridge) {
		D(SYSTEM, "Remove device '%s' from bridge '%s'\n", dev->ifname, bridge);
		system_bridge_if(bridge, dev, SIOCBRDELIF, NULL);
	}
}

static inline unsigned long
sec_to_jiffies(int val)
{
	return (unsigned long) val * 100;
}

int system_bridge_addbr(struct device *bridge, struct bridge_config *cfg)
{
	unsigned long args[4] = {};

	if (ioctl(sock_ioctl, SIOCBRADDBR, bridge->ifname) < 0)
		return -1;

	args[0] = BRCTL_SET_BRIDGE_STP_STATE;
	args[1] = !!cfg->stp;
	system_bridge_if(bridge->ifname, NULL, SIOCDEVPRIVATE, &args);

	args[0] = BRCTL_SET_BRIDGE_FORWARD_DELAY;
	args[1] = sec_to_jiffies(cfg->forward_delay);
	system_bridge_if(bridge->ifname, NULL, SIOCDEVPRIVATE, &args);

	if (cfg->flags & BRIDGE_OPT_AGEING_TIME) {
		args[0] = BRCTL_SET_AGEING_TIME;
		args[1] = sec_to_jiffies(cfg->ageing_time);
		system_bridge_if(bridge->ifname, NULL, SIOCDEVPRIVATE, &args);
	}

	if (cfg->flags & BRIDGE_OPT_HELLO_TIME) {
		args[0] = BRCTL_SET_BRIDGE_HELLO_TIME;
		args[1] = sec_to_jiffies(cfg->hello_time);
		system_bridge_if(bridge->ifname, NULL, SIOCDEVPRIVATE, &args);
	}

	if (cfg->flags & BRIDGE_OPT_MAX_AGE) {
		args[0] = BRCTL_SET_BRIDGE_MAX_AGE;
		args[1] = sec_to_jiffies(cfg->max_age);
		system_bridge_if(bridge->ifname, NULL, SIOCDEVPRIVATE, &args);
	}

	return 0;
}

static int system_vlan(struct device *dev, int id)
{
	struct vlan_ioctl_args ifr = {
		.cmd = SET_VLAN_NAME_TYPE_CMD,
		.u.name_type = VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD,
	};

	ioctl(sock_ioctl, SIOCSIFVLAN, &ifr);

	if (id < 0) {
		ifr.cmd = DEL_VLAN_CMD;
		ifr.u.VID = 0;
	} else {
		ifr.cmd = ADD_VLAN_CMD;
		ifr.u.VID = id;
	}
	strncpy(ifr.device1, dev->ifname, sizeof(ifr.device1));
	return ioctl(sock_ioctl, SIOCSIFVLAN, &ifr);
}

int system_vlan_add(struct device *dev, int id)
{
	return system_vlan(dev, id);
}

int system_vlan_del(struct device *dev)
{
	return system_vlan(dev, -1);
}

int system_if_up(struct device *dev)
{
	dev->ifindex = system_if_resolve(dev);
	return system_if_flags(dev->ifname, IFF_UP, 0);
}

int system_if_down(struct device *dev)
{
	return system_if_flags(dev->ifname, 0, IFF_UP);
}

int system_if_check(struct device *dev)
{
	device_set_present(dev, (system_if_resolve(dev) >= 0));
	return 0;
}

static int system_addr(struct device *dev, struct device_addr *addr, int cmd)
{
	int alen = ((addr->flags & DEVADDR_FAMILY) == DEVADDR_INET4) ? 4 : 16;
	struct ifaddrmsg ifa = {
		.ifa_family = (alen == 4) ? AF_INET : AF_INET6,
		.ifa_prefixlen = addr->mask,
		.ifa_index = dev->ifindex,
	};

	struct nl_msg *msg = nlmsg_alloc_simple(cmd, 0);
	if (!msg)
		return -1;

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);
	nla_put(msg, IFA_LOCAL, alen, &addr->addr);
	return system_rtnl_call(msg);
}

int system_add_address(struct device *dev, struct device_addr *addr)
{
	return system_addr(dev, addr, RTM_NEWADDR);
}

int system_del_address(struct device *dev, struct device_addr *addr)
{
	return system_addr(dev, addr, RTM_DELADDR);
}

static int system_rt(struct device *dev, struct device_route *route, int cmd)
{
	int alen = ((route->flags & DEVADDR_FAMILY) == DEVADDR_INET4) ? 4 : 16;
	bool have_gw;

	if (alen == 4)
		have_gw = !!route->nexthop.in.s_addr;
	else
		have_gw = route->nexthop.in6.s6_addr32[0] ||
			route->nexthop.in6.s6_addr32[1] ||
			route->nexthop.in6.s6_addr32[2] ||
			route->nexthop.in6.s6_addr32[3];

	unsigned char scope = (cmd == RTM_DELROUTE) ? RT_SCOPE_NOWHERE :
			(have_gw) ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;

	struct rtmsg rtm = {
		.rtm_family = (alen == 4) ? AF_INET : AF_INET6,
		.rtm_dst_len = route->mask,
		.rtm_table = RT_TABLE_MAIN,
		.rtm_protocol = RTPROT_BOOT,
		.rtm_scope = scope,
		.rtm_type = (cmd == RTM_DELROUTE) ? 0: RTN_UNICAST,
	};

	struct nl_msg *msg = nlmsg_alloc_simple(cmd, 0);
	if (!msg)
		return -1;

	nlmsg_append(msg, &rtm, sizeof(rtm), 0);

	if (route->mask)
		nla_put(msg, RTA_DST, alen, &route->addr);

	if (have_gw)
		nla_put(msg, RTA_GATEWAY, alen, &route->nexthop);

	if (route->flags & DEVADDR_DEVICE)
		nla_put_u32(msg, RTA_OIF, dev->ifindex);

	return system_rtnl_call(msg);
}

int system_add_route(struct device *dev, struct device_route *route)
{
	return system_rt(dev, route, RTM_NEWROUTE);
}

int system_del_route(struct device *dev, struct device_route *route)
{
	return system_rt(dev, route, RTM_DELROUTE);
}

time_t system_get_rtime(void)
{
	struct timespec ts;
	struct timeval tv;

	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts) == 0)
		return ts.tv_sec;

	if (gettimeofday(&tv, NULL) == 0)
		return tv.tv_sec;

	return 0;
}
