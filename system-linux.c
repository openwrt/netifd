#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/if_vlan.h>

#include <string.h>
#include <fcntl.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
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
	if ((sock_rtnl = nl_socket_alloc())) {
		if (nl_connect(sock_rtnl, NETLINK_ROUTE)) {
			nl_socket_free(sock_rtnl);
			sock_rtnl = NULL;
		}
	}

	// Prepare socket for link events
	if ((nl_cb_rtnl_event = nl_cb_alloc(NL_CB_DEFAULT)))
		nl_cb_set(nl_cb_rtnl_event, NL_CB_VALID, NL_CB_CUSTOM,
							cb_rtnl_event, NULL);

	if (nl_cb_rtnl_event && (sock_rtnl_event = nl_socket_alloc())) {
		if (nl_connect(sock_rtnl_event, NETLINK_ROUTE)) {
			nl_socket_free(sock_rtnl_event);
			sock_rtnl_event = NULL;
		}
		// Receive network link events form kernel
		nl_socket_add_membership(sock_rtnl_event, RTNLGRP_LINK);

		// Synthesize initial link messages
		struct nl_msg *m = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_DUMP);
		if (m && nlmsg_reserve(m, sizeof(struct ifinfomsg), 0)) {
			nl_send_auto_complete(sock_rtnl_event, m);
			nlmsg_free(m);
		}

#ifdef NLA_PUT_DATA
		rtnl_event.fd = nl_socket_get_fd(sock_rtnl_event);
#else
		rtnl_event.fd = sock_rtnl_event->s_fd; // libnl-tiny hack...
#endif
		uloop_fd_add(&rtnl_event, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	}

	return -(sock_ioctl < 0 || !sock_rtnl);
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

int system_bridge_addbr(struct device *bridge)
{
	return ioctl(sock_ioctl, SIOCBRADDBR, bridge->ifname);
}

int system_bridge_delbr(struct device *bridge)
{
	return ioctl(sock_ioctl, SIOCBRDELBR, bridge->ifname);
}

static int system_bridge_if(struct device *bridge, struct device *dev, int cmd)
{
	struct ifreq ifr;
	ifr.ifr_ifindex = dev->ifindex;
	strncpy(ifr.ifr_name, bridge->ifname, sizeof(ifr.ifr_name));
	return ioctl(sock_ioctl, cmd, &ifr);
}

int system_bridge_addif(struct device *bridge, struct device *dev)
{
	return system_bridge_if(bridge, dev, SIOCBRADDIF);
}

int system_bridge_delif(struct device *bridge, struct device *dev)
{
	return system_bridge_if(bridge, dev, SIOCBRDELIF);
}

static int system_vlan(struct device *dev, int id)
{
	struct vlan_ioctl_args ifr = {
		.cmd = (id == 0) ? DEL_VLAN_CMD : ADD_VLAN_CMD,
		.u = {.VID = id},
	};
	strncpy(ifr.device1, dev->ifname, sizeof(ifr.device1));
	return ioctl(sock_ioctl, SIOCSIFVLAN, &ifr);
}

int system_vlan_add(struct device *dev, int id)
{
	return system_vlan(dev, id);
}

int system_vlan_del(struct device *dev)
{
	return system_vlan(dev, 0);
}

static int system_if_flags(struct device *dev, unsigned add, unsigned rem)
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name));
	ioctl(sock_ioctl, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= add;
	ifr.ifr_flags &= ~rem;
	return ioctl(sock_ioctl, SIOCSIFFLAGS, &ifr);
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

int system_if_up(struct device *dev)
{
	dev->ifindex = system_if_resolve(dev);
	return system_if_flags(dev, IFF_UP, 0);
}

int system_if_down(struct device *dev)
{
	return system_if_flags(dev, 0, IFF_UP);
}

int system_if_check(struct device *dev)
{
	return -!(system_if_resolve(dev));
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
