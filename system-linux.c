/*
 * netifd - network interface daemon
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2013 Jo-Philipp Wich <jow@openwrt.org>
 * Copyright (C) 2013 Steven Barth <steven@midlink.org>
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
#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <net/if.h>
#include <net/if_arp.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/ip.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include <linux/ethtool.h>
#include <linux/fib_rules.h>

#ifndef RTN_FAILED_POLICY
#define RTN_FAILED_POLICY 12
#endif

#include <string.h>
#include <fcntl.h>
#include <glob.h>
#include <time.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <libubox/uloop.h>

#include "netifd.h"
#include "device.h"
#include "system.h"

struct event_socket {
	struct uloop_fd uloop;
	struct nl_sock *sock;
	struct nl_cb *cb;
};

static int sock_ioctl = -1;
static struct nl_sock *sock_rtnl = NULL;

static int cb_rtnl_event(struct nl_msg *msg, void *arg);
static void handle_hotplug_event(struct uloop_fd *u, unsigned int events);

static char dev_buf[256];

static void
handler_nl_event(struct uloop_fd *u, unsigned int events)
{
	struct event_socket *ev = container_of(u, struct event_socket, uloop);
	nl_recvmsgs(ev->sock, ev->cb);
}

static struct nl_sock *
create_socket(int protocol, int groups)
{
	struct nl_sock *sock;

	sock = nl_socket_alloc();
	if (!sock)
		return NULL;

	if (groups)
		nl_join_groups(sock, groups);

	if (nl_connect(sock, protocol))
		return NULL;

	return sock;
}

static bool
create_raw_event_socket(struct event_socket *ev, int protocol, int groups,
			uloop_fd_handler cb)
{
	ev->sock = create_socket(protocol, groups);
	if (!ev->sock)
		return false;

	ev->uloop.fd = nl_socket_get_fd(ev->sock);
	ev->uloop.cb = cb;
	uloop_fd_add(&ev->uloop, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	return true;
}

static bool
create_event_socket(struct event_socket *ev, int protocol,
		    int (*cb)(struct nl_msg *msg, void *arg))
{
	// Prepare socket for link events
	ev->cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!ev->cb)
		return false;

	nl_cb_set(ev->cb, NL_CB_VALID, NL_CB_CUSTOM, cb, NULL);

	return create_raw_event_socket(ev, protocol, 0, handler_nl_event);
}

int system_init(void)
{
	static struct event_socket rtnl_event;
	static struct event_socket hotplug_event;

	sock_ioctl = socket(AF_LOCAL, SOCK_DGRAM, 0);
	fcntl(sock_ioctl, F_SETFD, fcntl(sock_ioctl, F_GETFD) | FD_CLOEXEC);

	// Prepare socket for routing / address control
	sock_rtnl = create_socket(NETLINK_ROUTE, 0);
	if (!sock_rtnl)
		return -1;

	if (!create_event_socket(&rtnl_event, NETLINK_ROUTE, cb_rtnl_event))
		return -1;

	if (!create_raw_event_socket(&hotplug_event, NETLINK_KOBJECT_UEVENT, 1,
				     handle_hotplug_event))
		return -1;

	// Receive network link events form kernel
	nl_socket_add_membership(rtnl_event.sock, RTNLGRP_LINK);

	return 0;
}

static void system_set_sysctl(const char *path, const char *val)
{
	int fd;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return;

	if (write(fd, val, strlen(val))) {}
	close(fd);
}

static void system_set_dev_sysctl(const char *path, const char *device, const char *val)
{
	snprintf(dev_buf, sizeof(dev_buf), path, device);
	system_set_sysctl(dev_buf, val);
}

static void system_set_disable_ipv6(struct device *dev, const char *val)
{
	system_set_dev_sysctl("/proc/sys/net/ipv6/conf/%s/disable_ipv6", dev->ifname, val);
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
	/* TODO: parse link status */

out:
	return 0;
}

static void
handle_hotplug_msg(char *data, int size)
{
	const char *subsystem = NULL, *interface = NULL;
	char *cur, *end, *sep;
	struct device *dev;
	int skip;
	bool add;

	if (!strncmp(data, "add@", 4))
		add = true;
	else if (!strncmp(data, "remove@", 7))
		add = false;
	else
		return;

	skip = strlen(data) + 1;
	end = data + size;

	for (cur = data + skip; cur < end; cur += skip) {
		skip = strlen(cur) + 1;

		sep = strchr(cur, '=');
		if (!sep)
			continue;

		*sep = 0;
		if (!strcmp(cur, "INTERFACE"))
			interface = sep + 1;
		else if (!strcmp(cur, "SUBSYSTEM")) {
			subsystem = sep + 1;
			if (strcmp(subsystem, "net") != 0)
				return;
		}
		if (subsystem && interface)
			goto found;
	}
	return;

found:
	dev = device_get(interface, false);
	if (!dev)
		return;

	if (dev->type != &simple_device_type)
		return;

	if (add && system_if_force_external(dev->ifname))
		return;

	device_set_present(dev, add);
}

static void
handle_hotplug_event(struct uloop_fd *u, unsigned int events)
{
	struct event_socket *ev = container_of(u, struct event_socket, uloop);
	struct sockaddr_nl nla;
	unsigned char *buf = NULL;
	int size;

	while ((size = nl_recv(ev->sock, &nla, &buf, NULL)) > 0) {
		if (nla.nl_pid == 0)
			handle_hotplug_msg((char *) buf, size);

		free(buf);
	}
}

static int system_rtnl_call(struct nl_msg *msg)
{
	int ret;

	ret = nl_send_auto_complete(sock_rtnl, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(sock_rtnl);
}

int system_bridge_delbr(struct device *bridge)
{
	return ioctl(sock_ioctl, SIOCBRDELBR, bridge->ifname);
}

static int system_bridge_if(const char *bridge, struct device *dev, int cmd, void *data)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	if (dev)
		ifr.ifr_ifindex = dev->ifindex;
	else
		ifr.ifr_data = data;
	strncpy(ifr.ifr_name, bridge, sizeof(ifr.ifr_name));
	return ioctl(sock_ioctl, cmd, &ifr);
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

int system_bridge_addif(struct device *bridge, struct device *dev)
{
	char *oldbr;

	system_set_disable_ipv6(dev, "1");
	oldbr = system_get_bridge(dev->ifname, dev_buf, sizeof(dev_buf));
	if (oldbr && !strcmp(oldbr, bridge->ifname))
		return 0;

	return system_bridge_if(bridge->ifname, dev, SIOCBRADDIF, NULL);
}

int system_bridge_delif(struct device *bridge, struct device *dev)
{
	system_set_disable_ipv6(dev, "0");
	return system_bridge_if(bridge->ifname, dev, SIOCBRDELIF, NULL);
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

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ioctl(sock_ioctl, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= add;
	ifr.ifr_flags &= ~rem;
	return ioctl(sock_ioctl, SIOCSIFFLAGS, &ifr);
}

struct clear_data {
	struct nl_msg *msg;
	struct device *dev;
	int type;
	int size;
	int af;
};


static bool check_ifaddr(struct nlmsghdr *hdr, int ifindex)
{
	struct ifaddrmsg *ifa = NLMSG_DATA(hdr);

	return ifa->ifa_index == ifindex;
}

static bool check_route(struct nlmsghdr *hdr, int ifindex)
{
	struct rtmsg *r = NLMSG_DATA(hdr);
	struct nlattr *tb[__RTA_MAX];

	if (r->rtm_protocol == RTPROT_KERNEL &&
	    r->rtm_family == AF_INET6)
		return false;

	nlmsg_parse(hdr, sizeof(struct rtmsg), tb, __RTA_MAX - 1, NULL);
	if (!tb[RTA_OIF])
		return false;

	return *(int *)RTA_DATA(tb[RTA_OIF]) == ifindex;
}

static bool check_rule(struct nlmsghdr *hdr, int ifindex)
{
	return true;
}

static int cb_clear_event(struct nl_msg *msg, void *arg)
{
	struct clear_data *clr = arg;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	bool (*cb)(struct nlmsghdr *, int ifindex);
	int type;

	switch(clr->type) {
	case RTM_GETADDR:
		type = RTM_DELADDR;
		if (hdr->nlmsg_type != RTM_NEWADDR)
			return NL_SKIP;

		cb = check_ifaddr;
		break;
	case RTM_GETROUTE:
		type = RTM_DELROUTE;
		if (hdr->nlmsg_type != RTM_NEWROUTE)
			return NL_SKIP;

		cb = check_route;
		break;
	case RTM_GETRULE:
		type = RTM_DELRULE;
		if (hdr->nlmsg_type != RTM_NEWRULE)
			return NL_SKIP;

		cb = check_rule;
		break;
	default:
		return NL_SKIP;
	}

	if (!cb(hdr, clr->dev ? clr->dev->ifindex : 0))
		return NL_SKIP;

	if (type == RTM_DELRULE)
		D(SYSTEM, "Remove a rule\n");
	else
		D(SYSTEM, "Remove %s from device %s\n",
		  type == RTM_DELADDR ? "an address" : "a route",
		  clr->dev->ifname);
	memcpy(nlmsg_hdr(clr->msg), hdr, hdr->nlmsg_len);
	hdr = nlmsg_hdr(clr->msg);
	hdr->nlmsg_type = type;
	hdr->nlmsg_flags = NLM_F_REQUEST;

	nl_socket_disable_auto_ack(sock_rtnl);
	nl_send_auto_complete(sock_rtnl, clr->msg);
	nl_socket_enable_auto_ack(sock_rtnl);

	return NL_SKIP;
}

static int
cb_finish_event(struct nl_msg *msg, void *arg)
{
	int *pending = arg;
	*pending = 0;
	return NL_STOP;
}

static int
error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *pending = arg;
	*pending = err->error;
	return NL_STOP;
}

static void
system_if_clear_entries(struct device *dev, int type, int af)
{
	struct clear_data clr;
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct rtmsg rtm = {
		.rtm_family = af,
		.rtm_flags = RTM_F_CLONED,
	};
	int flags = NLM_F_DUMP;
	int pending = 1;

	clr.af = af;
	clr.dev = dev;
	clr.type = type;
	switch (type) {
	case RTM_GETADDR:
	case RTM_GETRULE:
		clr.size = sizeof(struct rtgenmsg);
		break;
	case RTM_GETROUTE:
		clr.size = sizeof(struct rtmsg);
		break;
	default:
		return;
	}

	if (!cb)
		return;

	clr.msg = nlmsg_alloc_simple(type, flags);
	if (!clr.msg)
		goto out;

	nlmsg_append(clr.msg, &rtm, clr.size, 0);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_clear_event, &clr);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_finish_event, &pending);
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &pending);

	nl_send_auto_complete(sock_rtnl, clr.msg);
	while (pending > 0)
		nl_recvmsgs(sock_rtnl, cb);

	nlmsg_free(clr.msg);
out:
	nl_cb_put(cb);
}

/*
 * Clear bridge (membership) state and bring down device
 */
void system_if_clear_state(struct device *dev)
{
	static char buf[256];
	char *bridge;

	if (dev->external)
		return;

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

	system_if_clear_entries(dev, RTM_GETROUTE, AF_INET);
	system_if_clear_entries(dev, RTM_GETADDR, AF_INET);
	system_if_clear_entries(dev, RTM_GETROUTE, AF_INET6);
	system_if_clear_entries(dev, RTM_GETADDR, AF_INET6);
	system_set_disable_ipv6(dev, "0");
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

	system_set_dev_sysctl("/sys/devices/virtual/net/%s/bridge/multicast_snooping",
		bridge->ifname, cfg->igmp_snoop ? "1" : "0");

	args[0] = BRCTL_SET_BRIDGE_PRIORITY;
	args[1] = cfg->priority;
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

int system_macvlan_add(struct device *macvlan, struct device *dev, struct macvlan_config *cfg)
{
	struct nl_msg *msg;
	struct nlattr *linkinfo, *data;
	struct ifinfomsg iim = { .ifi_family = AF_INET };
	int ifindex = system_if_resolve(dev);
	int i, rv;
	static const struct {
		const char *name;
		enum macvlan_mode val;
	} modes[] = {
		{ "private", MACVLAN_MODE_PRIVATE },
		{ "vepa", MACVLAN_MODE_VEPA },
		{ "bridge", MACVLAN_MODE_BRIDGE },
		{ "passthru", MACVLAN_MODE_PASSTHRU },
	};

	if (ifindex == 0)
		return -ENOENT;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);

	if (!msg)
		return -1;

	nlmsg_append(msg, &iim, sizeof(iim), 0);

	if (cfg->flags & MACVLAN_OPT_MACADDR)
		nla_put(msg, IFLA_ADDRESS, sizeof(cfg->macaddr), cfg->macaddr);
	nla_put(msg, IFLA_IFNAME, IFNAMSIZ, macvlan->ifname);
	nla_put_u32(msg, IFLA_LINK, ifindex);

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	nla_put(msg, IFLA_INFO_KIND, strlen("macvlan"), "macvlan");

	if (!(data = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (cfg->mode) {
		for (i = 0; i < ARRAY_SIZE(modes); i++) {
			if (strcmp(cfg->mode, modes[i].name) != 0)
				continue;

			nla_put_u32(msg, IFLA_MACVLAN_MODE, modes[i].val);
			break;
		}
	}

	nla_nest_end(msg, data);
	nla_nest_end(msg, linkinfo);

	rv = system_rtnl_call(msg);
	if (rv)
		D(SYSTEM, "Error adding macvlan '%s' over '%s': %d\n", macvlan->ifname, dev->ifname, rv);

	return rv;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOMEM;
}

int system_macvlan_del(struct device *macvlan)
{
	struct nl_msg *msg;
	struct ifinfomsg iim;

	iim.ifi_family = AF_INET;
	iim.ifi_index  = 0;

	msg = nlmsg_alloc_simple(RTM_DELLINK, 0);

	if (!msg)
		return -1;

	nlmsg_append(msg, &iim, sizeof(iim), 0);

	nla_put(msg, IFLA_INFO_KIND, strlen("macvlan"), "macvlan");
	nla_put(msg, IFLA_IFNAME, sizeof(macvlan->ifname), macvlan->ifname);

	system_rtnl_call(msg);

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

static void
system_if_get_settings(struct device *dev, struct device_settings *s)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name));

	if (ioctl(sock_ioctl, SIOCGIFMTU, &ifr) == 0) {
		s->mtu = ifr.ifr_mtu;
		s->flags |= DEV_OPT_MTU;
	}

	if (ioctl(sock_ioctl, SIOCGIFTXQLEN, &ifr) == 0) {
		s->txqueuelen = ifr.ifr_qlen;
		s->flags |= DEV_OPT_TXQUEUELEN;
	}

	if (ioctl(sock_ioctl, SIOCGIFHWADDR, &ifr) == 0) {
		memcpy(s->macaddr, &ifr.ifr_hwaddr.sa_data, sizeof(s->macaddr));
		s->flags |= DEV_OPT_MACADDR;
	}
}

void
system_if_apply_settings(struct device *dev, struct device_settings *s)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name));
	if (s->flags & DEV_OPT_MTU) {
		ifr.ifr_mtu = s->mtu;
		if (ioctl(sock_ioctl, SIOCSIFMTU, &ifr) < 0)
			s->flags &= ~DEV_OPT_MTU;
	}
	if (s->flags & DEV_OPT_TXQUEUELEN) {
		ifr.ifr_qlen = s->txqueuelen;
		if (ioctl(sock_ioctl, SIOCSIFTXQLEN, &ifr) < 0)
			s->flags &= ~DEV_OPT_TXQUEUELEN;
	}
	if ((s->flags & DEV_OPT_MACADDR) && !dev->external) {
		ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
		memcpy(&ifr.ifr_hwaddr.sa_data, s->macaddr, sizeof(s->macaddr));
		if (ioctl(sock_ioctl, SIOCSIFHWADDR, &ifr) < 0)
			s->flags &= ~DEV_OPT_MACADDR;
	}
}

int system_if_up(struct device *dev)
{
	system_if_get_settings(dev, &dev->orig_settings);
	system_if_apply_settings(dev, &dev->settings);
	dev->ifindex = system_if_resolve(dev);
	return system_if_flags(dev->ifname, IFF_UP, 0);
}

int system_if_down(struct device *dev)
{
	int ret = system_if_flags(dev->ifname, 0, IFF_UP);
	dev->orig_settings.flags &= dev->settings.flags;
	system_if_apply_settings(dev, &dev->orig_settings);
	return ret;
}

int system_if_check(struct device *dev)
{
	device_set_present(dev, (system_if_resolve(dev) > 0));
	return 0;
}

struct device *
system_if_get_parent(struct device *dev)
{
	char buf[64], *devname;
	int ifindex, iflink, len;
	FILE *f;

	snprintf(buf, sizeof(buf), "/sys/class/net/%s/iflink", dev->ifname);
	f = fopen(buf, "r");
	if (!f)
		return NULL;

	len = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);

	if (len <= 0)
		return NULL;

	buf[len] = 0;
	iflink = strtoul(buf, NULL, 0);
	ifindex = system_if_resolve(dev);
	if (!iflink || iflink == ifindex)
		return NULL;

	devname = if_indextoname(iflink, buf);
	if (!devname)
		return NULL;

	return device_get(devname, true);
}

static bool
read_string_file(int dir_fd, const char *file, char *buf, int len)
{
	bool ret = false;
	char *c;
	int fd;

	fd = openat(dir_fd, file, O_RDONLY);
	if (fd < 0)
		return false;

retry:
	len = read(fd, buf, len - 1);
	if (len < 0) {
		if (errno == EINTR)
			goto retry;
	} else if (len > 0) {
			buf[len] = 0;

			c = strchr(buf, '\n');
			if (c)
				*c = 0;

			ret = true;
	}

	close(fd);

	return ret;
}

static bool
read_uint64_file(int dir_fd, const char *file, uint64_t *val)
{
	char buf[64];
	bool ret = false;

	ret = read_string_file(dir_fd, file, buf, sizeof(buf));
	if (ret)
		*val = strtoull(buf, NULL, 0);

	return ret;
}

/* Assume advertised flags == supported flags */
static const struct {
	uint32_t mask;
	const char *name;
} ethtool_link_modes[] = {
	{ ADVERTISED_10baseT_Half, "10H" },
	{ ADVERTISED_10baseT_Full, "10F" },
	{ ADVERTISED_100baseT_Half, "100H" },
	{ ADVERTISED_100baseT_Full, "100F" },
	{ ADVERTISED_1000baseT_Half, "1000H" },
	{ ADVERTISED_1000baseT_Full, "1000F" },
};

static void system_add_link_modes(struct blob_buf *b, __u32 mask)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(ethtool_link_modes); i++) {
		if (mask & ethtool_link_modes[i].mask)
			blobmsg_add_string(b, NULL, ethtool_link_modes[i].name);
	}
}

bool
system_if_force_external(const char *ifname)
{
	char buf[64];
	struct stat s;

	snprintf(buf, sizeof(buf), "/sys/class/net/%s/phy80211", ifname);
	return stat(buf, &s) == 0;
}

int
system_if_dump_info(struct device *dev, struct blob_buf *b)
{
	struct ethtool_cmd ecmd;
	struct ifreq ifr;
	char buf[64], *s;
	void *c;
	int dir_fd;
	uint64_t val = 0;

	snprintf(buf, sizeof(buf), "/sys/class/net/%s", dev->ifname);
	dir_fd = open(buf, O_DIRECTORY);

	if (read_uint64_file(dir_fd, "carrier", &val))
		blobmsg_add_u8(b, "link", !!val);

	memset(&ecmd, 0, sizeof(ecmd));
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev->ifname);
	ifr.ifr_data = (caddr_t) &ecmd;
	ecmd.cmd = ETHTOOL_GSET;

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) == 0) {
		c = blobmsg_open_array(b, "link-advertising");
		system_add_link_modes(b, ecmd.advertising);
		blobmsg_close_array(b, c);

		c = blobmsg_open_array(b, "link-supported");
		system_add_link_modes(b, ecmd.supported);
		blobmsg_close_array(b, c);

		s = blobmsg_alloc_string_buffer(b, "speed", 8);
		snprintf(s, 8, "%d%c", ethtool_cmd_speed(&ecmd),
			ecmd.duplex == DUPLEX_HALF ? 'H' : 'F');
		blobmsg_add_string_buffer(b);
	}

	close(dir_fd);
	return 0;
}

int
system_if_dump_stats(struct device *dev, struct blob_buf *b)
{
	const char *const counters[] = {
		"collisions",     "rx_frame_errors",   "tx_compressed",
		"multicast",      "rx_length_errors",  "tx_dropped",
		"rx_bytes",       "rx_missed_errors",  "tx_errors",
		"rx_compressed",  "rx_over_errors",    "tx_fifo_errors",
		"rx_crc_errors",  "rx_packets",        "tx_heartbeat_errors",
		"rx_dropped",     "tx_aborted_errors", "tx_packets",
		"rx_errors",      "tx_bytes",          "tx_window_errors",
		"rx_fifo_errors", "tx_carrier_errors",
	};
	char buf[64];
	int stats_dir;
	int i;
	uint64_t val = 0;

	snprintf(buf, sizeof(buf), "/sys/class/net/%s/statistics", dev->ifname);
	stats_dir = open(buf, O_DIRECTORY);
	if (stats_dir < 0)
		return -1;

	for (i = 0; i < ARRAY_SIZE(counters); i++)
		if (read_uint64_file(stats_dir, counters[i], &val))
			blobmsg_add_u64(b, counters[i], val);

	close(stats_dir);
	return 0;
}

static int system_addr(struct device *dev, struct device_addr *addr, int cmd)
{
	bool v4 = ((addr->flags & DEVADDR_FAMILY) == DEVADDR_INET4);
	int alen = v4 ? 4 : 16;
	unsigned int flags = 0;
	struct ifaddrmsg ifa = {
		.ifa_family = (alen == 4) ? AF_INET : AF_INET6,
		.ifa_prefixlen = addr->mask,
		.ifa_index = dev->ifindex,
	};

	struct nl_msg *msg;
	if (cmd == RTM_NEWADDR)
		flags |= NLM_F_CREATE | NLM_F_REPLACE;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (!msg)
		return -1;

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);
	nla_put(msg, IFA_LOCAL, alen, &addr->addr);
	if (v4) {
		if (addr->broadcast)
			nla_put_u32(msg, IFA_BROADCAST, addr->broadcast);
		if (addr->point_to_point)
			nla_put_u32(msg, IFA_ADDRESS, addr->point_to_point);
	} else {
		time_t now = system_get_rtime();
		struct ifa_cacheinfo cinfo = {0xffffffffU, 0xffffffffU, 0, 0};

		if (addr->preferred_until) {
			int64_t preferred = addr->preferred_until - now;
			if (preferred < 0)
				preferred = 0;
			else if (preferred > UINT32_MAX)
				preferred = UINT32_MAX;

			cinfo.ifa_prefered = preferred;
		}

		if (addr->valid_until) {
			int64_t valid = addr->valid_until - now;
			if (valid <= 0)
				return -1;
			else if (valid > UINT32_MAX)
				valid = UINT32_MAX;

			cinfo.ifa_valid = valid;
		}

		nla_put(msg, IFA_CACHEINFO, sizeof(cinfo), &cinfo);
	}

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
	unsigned int flags = 0;

	if (alen == 4)
		have_gw = !!route->nexthop.in.s_addr;
	else
		have_gw = route->nexthop.in6.s6_addr32[0] ||
			route->nexthop.in6.s6_addr32[1] ||
			route->nexthop.in6.s6_addr32[2] ||
			route->nexthop.in6.s6_addr32[3];

	unsigned char scope = (cmd == RTM_DELROUTE) ? RT_SCOPE_NOWHERE :
			(have_gw) ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;

	unsigned int table = (route->flags & (DEVROUTE_TABLE | DEVROUTE_SRCTABLE))
			? route->table : RT_TABLE_MAIN;

	struct rtmsg rtm = {
		.rtm_family = (alen == 4) ? AF_INET : AF_INET6,
		.rtm_dst_len = route->mask,
		.rtm_src_len = route->sourcemask,
		.rtm_table = (table < 256) ? table : RT_TABLE_UNSPEC,
		.rtm_protocol = (route->flags & DEVADDR_KERNEL) ? RTPROT_KERNEL : RTPROT_STATIC,
		.rtm_scope = scope,
		.rtm_type = (cmd == RTM_DELROUTE) ? 0: RTN_UNICAST,
	};
	struct nl_msg *msg;

	if (cmd == RTM_NEWROUTE) {
		flags |= NLM_F_CREATE | NLM_F_REPLACE;

		if (!dev) { // Add null-route
			rtm.rtm_scope = RT_SCOPE_UNIVERSE;
			rtm.rtm_type = RTN_UNREACHABLE;
		}
	}

	msg = nlmsg_alloc_simple(cmd, flags);
	if (!msg)
		return -1;

	nlmsg_append(msg, &rtm, sizeof(rtm), 0);

	if (route->mask)
		nla_put(msg, RTA_DST, alen, &route->addr);

	if (route->sourcemask)
		nla_put(msg, RTA_SRC, alen, &route->source);

	if (route->metric > 0)
		nla_put_u32(msg, RTA_PRIORITY, route->metric);

	if (have_gw)
		nla_put(msg, RTA_GATEWAY, alen, &route->nexthop);

	if (dev)
		nla_put_u32(msg, RTA_OIF, dev->ifindex);

	if (table >= 256)
		nla_put_u32(msg, RTA_TABLE, table);

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

int system_flush_routes(void)
{
	const char *names[] = {
		"/proc/sys/net/ipv4/route/flush",
		"/proc/sys/net/ipv6/route/flush"
	};
	int fd, i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		fd = open(names[i], O_WRONLY);
		if (fd < 0)
			continue;

		if (write(fd, "-1", 2)) {}
		close(fd);
	}
	return 0;
}

bool system_resolve_rt_table(const char *name, unsigned int *id)
{
	FILE *f;
	char *e, buf[128];
	unsigned int n, table = RT_TABLE_UNSPEC;

	/* first try to parse table as number */
	if ((n = strtoul(name, &e, 0)) > 0 && !*e)
		table = n;

	/* handle well known aliases */
	else if (!strcmp(name, "default"))
		table = RT_TABLE_DEFAULT;
	else if (!strcmp(name, "main"))
		table = RT_TABLE_MAIN;
	else if (!strcmp(name, "local"))
		table = RT_TABLE_LOCAL;

	/* try to look up name in /etc/iproute2/rt_tables */
	else if ((f = fopen("/etc/iproute2/rt_tables", "r")) != NULL)
	{
		while (fgets(buf, sizeof(buf) - 1, f) != NULL)
		{
			if ((e = strtok(buf, " \t\n")) == NULL || *e == '#')
				continue;

			n = strtoul(e, NULL, 10);
			e = strtok(NULL, " \t\n");

			if (e && !strcmp(e, name))
			{
				table = n;
				break;
			}
		}

		fclose(f);
	}

	if (table == RT_TABLE_UNSPEC)
		return false;

	/* do not consider main table special */
	if (table == RT_TABLE_MAIN)
		table = RT_TABLE_UNSPEC;

	*id = table;
	return true;
}

static int system_iprule(struct iprule *rule, int cmd)
{
	int alen = ((rule->flags & IPRULE_FAMILY) == IPRULE_INET4) ? 4 : 16;

	struct nl_msg *msg;
	struct rtmsg rtm = {
		.rtm_family = (alen == 4) ? AF_INET : AF_INET6,
		.rtm_protocol = RTPROT_STATIC,
		.rtm_scope = RT_SCOPE_UNIVERSE,
		.rtm_table = RT_TABLE_UNSPEC,
		.rtm_type = RTN_UNSPEC,
		.rtm_flags = 0,
	};

	if (cmd == RTM_NEWRULE) {
		rtm.rtm_type = RTN_UNICAST;
		rtm.rtm_flags |= NLM_F_REPLACE | NLM_F_EXCL;
	}

	if (rule->invert)
		rtm.rtm_flags |= FIB_RULE_INVERT;

	if (rule->flags & IPRULE_SRC)
		rtm.rtm_src_len = rule->src_mask;

	if (rule->flags & IPRULE_DEST)
		rtm.rtm_dst_len = rule->dest_mask;

	if (rule->flags & IPRULE_TOS)
		rtm.rtm_tos = rule->tos;

	if (rule->flags & IPRULE_LOOKUP) {
		if (rule->lookup < 256)
			rtm.rtm_table = rule->lookup;
	}

	if (rule->flags & IPRULE_ACTION)
		rtm.rtm_type = rule->action;
	else if (rule->flags & IPRULE_GOTO)
		rtm.rtm_type = FR_ACT_GOTO;
	else if (!(rule->flags & (IPRULE_LOOKUP | IPRULE_ACTION | IPRULE_GOTO)))
		rtm.rtm_type = FR_ACT_NOP;

	msg = nlmsg_alloc_simple(cmd, NLM_F_REQUEST);

	if (!msg)
		return -1;

	nlmsg_append(msg, &rtm, sizeof(rtm), 0);

	if (rule->flags & IPRULE_IN)
		nla_put(msg, FRA_IFNAME, strlen(rule->in_dev) + 1, rule->in_dev);

	if (rule->flags & IPRULE_OUT)
		nla_put(msg, FRA_OIFNAME, strlen(rule->out_dev) + 1, rule->out_dev);

	if (rule->flags & IPRULE_SRC)
		nla_put(msg, FRA_SRC, alen, &rule->src_addr);

	if (rule->flags & IPRULE_DEST)
		nla_put(msg, FRA_DST, alen, &rule->dest_addr);

	if (rule->flags & IPRULE_PRIORITY)
		nla_put_u32(msg, FRA_PRIORITY, rule->priority);
	else if (cmd == RTM_NEWRULE)
		nla_put_u32(msg, FRA_PRIORITY, rule->order);

	if (rule->flags & IPRULE_FWMARK)
		nla_put_u32(msg, FRA_FWMARK, rule->fwmark);

	if (rule->flags & IPRULE_FWMASK)
		nla_put_u32(msg, FRA_FWMASK, rule->fwmask);

	if (rule->flags & IPRULE_LOOKUP) {
		if (rule->lookup >= 256)
			nla_put_u32(msg, FRA_TABLE, rule->lookup);
	}

	if (rule->flags & IPRULE_GOTO)
		nla_put_u32(msg, FRA_GOTO, rule->gotoid);

	return system_rtnl_call(msg);
}

int system_add_iprule(struct iprule *rule)
{
	return system_iprule(rule, RTM_NEWRULE);
}

int system_del_iprule(struct iprule *rule)
{
	return system_iprule(rule, RTM_DELRULE);
}

int system_flush_iprules(void)
{
	int rv = 0;
	struct iprule rule;

	system_if_clear_entries(NULL, RTM_GETRULE, AF_INET);
	system_if_clear_entries(NULL, RTM_GETRULE, AF_INET6);

	memset(&rule, 0, sizeof(rule));


	rule.flags = IPRULE_INET4 | IPRULE_PRIORITY | IPRULE_LOOKUP;

	rule.priority = 0;
	rule.lookup = RT_TABLE_LOCAL;
	rv |= system_iprule(&rule, RTM_NEWRULE);

	rule.priority = 32766;
	rule.lookup = RT_TABLE_MAIN;
	rv |= system_iprule(&rule, RTM_NEWRULE);

	rule.priority = 32767;
	rule.lookup = RT_TABLE_DEFAULT;
	rv |= system_iprule(&rule, RTM_NEWRULE);


	rule.flags = IPRULE_INET6 | IPRULE_PRIORITY | IPRULE_LOOKUP;

	rule.priority = 0;
	rule.lookup = RT_TABLE_LOCAL;
	rv |= system_iprule(&rule, RTM_NEWRULE);

	rule.priority = 32766;
	rule.lookup = RT_TABLE_MAIN;
	rv |= system_iprule(&rule, RTM_NEWRULE);

	return rv;
}

bool system_resolve_iprule_action(const char *action, unsigned int *id)
{
	char *e;
	unsigned int n;

	if (!strcmp(action, "local"))
		n = RTN_LOCAL;
	else if (!strcmp(action, "nat"))
		n = RTN_NAT;
	else if (!strcmp(action, "broadcast"))
		n = RTN_BROADCAST;
	else if (!strcmp(action, "anycast"))
		n = RTN_ANYCAST;
	else if (!strcmp(action, "multicast"))
		n = RTN_MULTICAST;
	else if (!strcmp(action, "prohibit"))
		n = RTN_PROHIBIT;
	else if (!strcmp(action, "unreachable"))
		n = RTN_UNREACHABLE;
	else if (!strcmp(action, "blackhole"))
		n = RTN_BLACKHOLE;
	else if (!strcmp(action, "xresolve"))
		n = RTN_XRESOLVE;
	else if (!strcmp(action, "unicast"))
		n = RTN_UNICAST;
	else if (!strcmp(action, "throw"))
		n = RTN_THROW;
	else if (!strcmp(action, "failed_policy"))
		n = RTN_FAILED_POLICY;
	else {
		n = strtoul(action, &e, 0);
		if (!e || *e || e == action || n > 255)
			return false;
	}

	*id = n;
	return true;
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

#ifndef IP_DF
#define IP_DF       0x4000
#endif

static int tunnel_ioctl(const char *name, int cmd, void *p)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_ifru.ifru_data = p;
	return ioctl(sock_ioctl, cmd, &ifr);
}

int system_del_ip_tunnel(const char *name)
{
	return tunnel_ioctl(name, SIOCDELTUNNEL, NULL);
}

int system_update_ipv6_mtu(struct device *dev, int mtu)
{
	int ret = -1;
	char buf[64];
	snprintf(buf, sizeof(buf), "/proc/sys/net/ipv6/conf/%s/mtu",
			dev->ifname);

	int fd = open(buf, O_RDWR);
	ssize_t len = read(fd, buf, sizeof(buf) - 1);
	if (len < 0)
		goto out;

	buf[len] = 0;
	ret = atoi(buf);

	if (!mtu || ret <= mtu)
		goto out;

	lseek(fd, 0, SEEK_SET);
	if (write(fd, buf, snprintf(buf, sizeof(buf), "%i", mtu)) <= 0)
		ret = -1;

out:
	close(fd);
	return ret;
}

int system_add_ip_tunnel(const char *name, struct blob_attr *attr)
{
	struct blob_attr *tb[__TUNNEL_ATTR_MAX];
	struct blob_attr *cur;
	bool set_df = true;
	const char *str;

	system_del_ip_tunnel(name);

	blobmsg_parse(tunnel_attr_list.params, __TUNNEL_ATTR_MAX, tb,
		blob_data(attr), blob_len(attr));

	if (!(cur = tb[TUNNEL_ATTR_TYPE]))
		return -EINVAL;
	str = blobmsg_data(cur);

	if ((cur = tb[TUNNEL_ATTR_DF]))
		set_df = blobmsg_get_bool(cur);

	unsigned int ttl = 0;
	if ((cur = tb[TUNNEL_ATTR_TTL])) {
		ttl = blobmsg_get_u32(cur);
		if (ttl > 255 || (!set_df && ttl))
			return -EINVAL;
	}

	unsigned int link = 0;
	if ((cur = tb[TUNNEL_ATTR_LINK])) {
		struct interface *iface = vlist_find(&interfaces, blobmsg_data(cur), iface, node);
		if (!iface)
			return -EINVAL;

		if (iface->l3_dev.dev)
			link = iface->l3_dev.dev->ifindex;
	}

	if (!strcmp(str, "sit")) {
		struct ip_tunnel_parm p = {
			.link = link,
			.iph = {
				.version = 4,
				.ihl = 5,
				.frag_off = set_df ? htons(IP_DF) : 0,
				.protocol = IPPROTO_IPV6,
				.ttl = ttl
			}
		};

		if ((cur = tb[TUNNEL_ATTR_LOCAL]) &&
				inet_pton(AF_INET, blobmsg_data(cur), &p.iph.saddr) < 1)
			return -EINVAL;

		if ((cur = tb[TUNNEL_ATTR_REMOTE]) &&
				inet_pton(AF_INET, blobmsg_data(cur), &p.iph.daddr) < 1)
			return -EINVAL;

		strncpy(p.name, name, sizeof(p.name));
		if (tunnel_ioctl("sit0", SIOCADDTUNNEL, &p) < 0)
			return -1;

#ifdef SIOCADD6RD
		if ((cur = tb[TUNNEL_ATTR_6RD_PREFIX])) {
			unsigned int mask;
			struct ip_tunnel_6rd p6;

			memset(&p6, 0, sizeof(p6));

			if (!parse_ip_and_netmask(AF_INET6, blobmsg_data(cur),
						&p6.prefix, &mask) || mask > 128)
				return -EINVAL;
			p6.prefixlen = mask;

			if ((cur = tb[TUNNEL_ATTR_6RD_RELAY_PREFIX])) {
				if (!parse_ip_and_netmask(AF_INET, blobmsg_data(cur),
							&p6.relay_prefix, &mask) || mask > 32)
					return -EINVAL;
				p6.relay_prefixlen = mask;
			}

			if (tunnel_ioctl(name, SIOCADD6RD, &p6) < 0) {
				system_del_ip_tunnel(name);
				return -1;
			}
		}
#endif
	} else if (!strcmp(str, "ipip6")) {
		struct ip6_tnl_parm p = {
			.link = link,
			.proto = IPPROTO_IPIP,
			.hop_limit = (ttl) ? ttl : 64,
			.encap_limit = 4,
		};

		if ((cur = tb[TUNNEL_ATTR_LOCAL]) &&
				inet_pton(AF_INET6, blobmsg_data(cur), &p.laddr) < 1)
			return -EINVAL;

		if ((cur = tb[TUNNEL_ATTR_REMOTE]) &&
				inet_pton(AF_INET6, blobmsg_data(cur), &p.raddr) < 1)
			return -EINVAL;

		strncpy(p.name, name, sizeof(p.name));
		if (tunnel_ioctl("ip6tnl0", SIOCADDTUNNEL, &p) < 0)
			return -1;
	} else
		return -EINVAL;

	return 0;
}
