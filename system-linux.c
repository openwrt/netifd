#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/if_vlan.h>

#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <netlink/msg.h>

#include "netifd.h"
#include "device.h"
#include "system.h"

static int sock_ioctl = -1;
static struct nl_sock *sock_rtnl = NULL;

static void __init system_init(void)
{
	sock_ioctl = socket(AF_LOCAL, SOCK_DGRAM, 0);
	fcntl(sock_ioctl, F_SETFD, fcntl(sock_ioctl, F_GETFD) | FD_CLOEXEC);

	if ((sock_rtnl = nl_socket_alloc())) {
		if (nl_connect(sock_rtnl, NETLINK_ROUTE)) {
			nl_socket_free(sock_rtnl);
			sock_rtnl = NULL;
		}
	}
}

static int system_rtnl_call(struct nl_msg *msg)
{
	return -!!(!sock_rtnl || nl_send_auto_complete(sock_rtnl, msg)
					|| nl_wait_for_ack(sock_rtnl));
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

int system_if_up(struct device *dev)
{
	return system_if_flags(dev, IFF_UP, 0);
}

int system_if_down(struct device *dev)
{
	return system_if_flags(dev, 0, IFF_UP);
}

int system_if_check(struct device *dev)
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name));
	if (ioctl(sock_ioctl, SIOCGIFINDEX, &ifr))
		return -1;

	dev->ifindex = ifr.ifr_ifindex;

	/* if (!strcmp(dev->ifname, "eth0"))
		device_set_present(dev, true); */
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
	nla_put(msg, IFA_ADDRESS, alen, &addr->addr);
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
