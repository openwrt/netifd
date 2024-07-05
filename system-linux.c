/*
 * netifd - network interface daemon
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2013 Jo-Philipp Wich <jow@openwrt.org>
 * Copyright (C) 2013 Steven Barth <steven@midlink.org>
 * Copyright (C) 2014 Gioacchino Mazzurco <gio@eigenlab.org>
 * Copyright (C) 2017 Matthias Schiffer <mschiffer@universe-factory.net>
 * Copyright (C) 2018 Hans Dedecker <dedeckeh@gmail.com>
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

#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <linux/sockios.h>
#include <linux/ip.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include <linux/ethtool.h>
#include <linux/fib_rules.h>
#include <linux/veth.h>
#include <linux/version.h>

#include <sched.h>

#include "ethtool-modes.h"

#ifndef RTN_FAILED_POLICY
#define RTN_FAILED_POLICY 12
#endif

#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif

#ifndef IFA_FLAGS
#define IFA_FLAGS (IFA_MULTICAST + 1)
#endif

#include <string.h>
#include <fcntl.h>
#include <glob.h>
#include <time.h>
#include <unistd.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <libubox/uloop.h>

#include "netifd.h"
#include "device.h"
#include "system.h"
#include "utils.h"

struct event_socket {
	struct uloop_fd uloop;
	struct nl_sock *sock;
	int bufsize;
};

static int sock_ioctl = -1;
static struct nl_sock *sock_rtnl = NULL;

static int cb_rtnl_event(struct nl_msg *msg, void *arg);
static void handle_hotplug_event(struct uloop_fd *u, unsigned int events);
static int system_add_proto_tunnel(const char *name, const uint8_t proto,
					const unsigned int link, struct blob_attr **tb);

static char dev_buf[256];
static const char *proc_path = "/proc";
static const char *sysfs_path = "/sys";

struct netdev_type {
	unsigned short id;
	const char *name;
};

static const struct netdev_type netdev_types[] = {
	{ARPHRD_NETROM, "netrom"},
	{ARPHRD_ETHER, "ethernet"},
	{ARPHRD_EETHER, "eethernet"},
	{ARPHRD_AX25, "ax25"},
	{ARPHRD_PRONET, "pronet"},
	{ARPHRD_CHAOS, "chaos"},
	{ARPHRD_IEEE802, "ieee802"},
	{ARPHRD_ARCNET, "arcnet"},
	{ARPHRD_APPLETLK, "appletlk"},
	{ARPHRD_DLCI, "dlci"},
	{ARPHRD_ATM, "atm"},
	{ARPHRD_METRICOM, "metricom"},
	{ARPHRD_IEEE1394, "ieee1394"},
	{ARPHRD_EUI64, "eui64"},
	{ARPHRD_INFINIBAND, "infiniband"},
	{ARPHRD_SLIP, "slip"},
	{ARPHRD_CSLIP, "cslip"},
	{ARPHRD_SLIP6, "slip6"},
	{ARPHRD_CSLIP6, "cslip6"},
	{ARPHRD_RSRVD, "rsrvd"},
	{ARPHRD_ADAPT, "adapt"},
	{ARPHRD_ROSE, "rose"},
	{ARPHRD_X25, "x25"},
	{ARPHRD_HWX25, "hwx25"},
	{ARPHRD_PPP, "ppp"},
	{ARPHRD_CISCO, "cisco"},
	{ARPHRD_LAPB, "lapb"},
	{ARPHRD_DDCMP, "ddcmp"},
	{ARPHRD_RAWHDLC, "rawhdlc"},
	{ARPHRD_TUNNEL, "tunnel"},
	{ARPHRD_TUNNEL6, "tunnel6"},
	{ARPHRD_FRAD, "frad"},
	{ARPHRD_SKIP, "skip"},
	{ARPHRD_LOOPBACK, "loopback"},
	{ARPHRD_LOCALTLK, "localtlk"},
	{ARPHRD_FDDI, "fddi"},
	{ARPHRD_BIF, "bif"},
	{ARPHRD_SIT, "sit"},
	{ARPHRD_IPDDP, "ipddp"},
	{ARPHRD_IPGRE, "ipgre"},
	{ARPHRD_PIMREG,"pimreg"},
	{ARPHRD_HIPPI, "hippi"},
	{ARPHRD_ASH, "ash"},
	{ARPHRD_ECONET, "econet"},
	{ARPHRD_IRDA, "irda"},
	{ARPHRD_FCPP, "fcpp"},
	{ARPHRD_FCAL, "fcal"},
	{ARPHRD_FCPL, "fcpl"},
	{ARPHRD_FCFABRIC, "fcfabric"},
	{ARPHRD_IEEE80211, "ieee80211"},
	{ARPHRD_IEEE80211_PRISM, "ie80211-prism"},
	{ARPHRD_IEEE80211_RADIOTAP, "ieee80211-radiotap"},
#ifdef ARPHRD_PHONET
	{ARPHRD_PHONET, "phonet"},
#endif
#ifdef ARPHRD_PHONET_PIPE
	{ARPHRD_PHONET_PIPE, "phonet-pipe"},
#endif
	{ARPHRD_IEEE802154, "ieee802154"},
	{ARPHRD_VOID, "void"},
	{ARPHRD_NONE, "none"}
};

static void
handler_nl_event(struct uloop_fd *u, unsigned int events)
{
	struct event_socket *ev = container_of(u, struct event_socket, uloop);
	int ret;

	ret = nl_recvmsgs_default(ev->sock);
	if (ret >= 0)
		return;

	switch (-ret) {
	case NLE_NOMEM:
		/* Increase rx buffer size on netlink socket */
		ev->bufsize *= 2;
		if (nl_socket_set_buffer_size(ev->sock, ev->bufsize, 0))
			goto abort;

		/* Request full dump since some info got dropped */
		struct rtgenmsg msg = { .rtgen_family = AF_UNSPEC };
		nl_send_simple(ev->sock, RTM_GETLINK, NLM_F_DUMP, &msg, sizeof(msg));
		break;

	default:
		goto abort;
	}
	return;

abort:
	uloop_fd_delete(&ev->uloop);
	return;
}

static void
nl_udebug_cb(void *priv, struct nl_msg *msg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);

	udebug_netlink_msg(priv, nlmsg_get_proto(msg), nlh, nlh->nlmsg_len);
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

	if (nl_connect(sock, protocol)) {
		nl_socket_free(sock);
		return NULL;
	}

	nl_socket_set_tx_debug_cb(sock, nl_udebug_cb, &udb_nl);
	nl_socket_set_rx_debug_cb(sock, nl_udebug_cb, &udb_nl);

	return sock;
}

static bool
create_raw_event_socket(struct event_socket *ev, int protocol, int groups,
			uloop_fd_handler cb, int flags)
{
	ev->sock = create_socket(protocol, groups);
	if (!ev->sock)
		return false;

	ev->uloop.fd = nl_socket_get_fd(ev->sock);
	ev->uloop.cb = cb;
	if (uloop_fd_add(&ev->uloop, ULOOP_READ|flags))
		return false;

	return true;
}

static bool
create_event_socket(struct event_socket *ev, int protocol,
		    int (*cb)(struct nl_msg *msg, void *arg))
{
	if (!create_raw_event_socket(ev, protocol, 0, handler_nl_event, ULOOP_ERROR_CB))
		return false;

	/* Install the valid custom callback handler */
	nl_socket_modify_cb(ev->sock, NL_CB_VALID, NL_CB_CUSTOM, cb, NULL);

	/* Disable sequence number checking on event sockets */
	nl_socket_disable_seq_check(ev->sock);

	/* Increase rx buffer size to 65K on event sockets */
	ev->bufsize = 65535;
	if (nl_socket_set_buffer_size(ev->sock, ev->bufsize, 0))
		return false;

	return true;
}

static bool
create_hotplug_event_socket(struct event_socket *ev, int protocol,
			    void (*cb)(struct uloop_fd *u, unsigned int events))
{
	if (!create_raw_event_socket(ev, protocol, 1, cb, ULOOP_ERROR_CB))
		return false;

	/* Increase rx buffer size to 65K on event sockets */
	ev->bufsize = 65535;
	if (nl_socket_set_buffer_size(ev->sock, ev->bufsize, 0))
		return false;

	return true;
}

static bool
system_rtn_aton(const char *src, unsigned int *dst)
{
	char *e;
	unsigned int n;

	if (!strcmp(src, "local"))
		n = RTN_LOCAL;
	else if (!strcmp(src, "nat"))
		n = RTN_NAT;
	else if (!strcmp(src, "broadcast"))
		n = RTN_BROADCAST;
	else if (!strcmp(src, "anycast"))
		n = RTN_ANYCAST;
	else if (!strcmp(src, "multicast"))
		n = RTN_MULTICAST;
	else if (!strcmp(src, "prohibit"))
		n = RTN_PROHIBIT;
	else if (!strcmp(src, "unreachable"))
		n = RTN_UNREACHABLE;
	else if (!strcmp(src, "blackhole"))
		n = RTN_BLACKHOLE;
	else if (!strcmp(src, "xresolve"))
		n = RTN_XRESOLVE;
	else if (!strcmp(src, "unicast"))
		n = RTN_UNICAST;
	else if (!strcmp(src, "throw"))
		n = RTN_THROW;
	else if (!strcmp(src, "failed_policy"))
		n = RTN_FAILED_POLICY;
	else {
		n = strtoul(src, &e, 0);
		if (!e || *e || e == src || n > 255)
			return false;
	}

	*dst = n;
	return true;
}

static bool
system_tos_aton(const char *src, unsigned *dst)
{
	char *e;

	*dst = strtoul(src, &e, 16);
	if (e == src || *e || *dst > 255)
		return false;

	return true;
}

int system_init(void)
{
	static struct event_socket rtnl_event;
	static struct event_socket hotplug_event;

	sock_ioctl = socket(AF_LOCAL, SOCK_DGRAM, 0);
	system_fd_set_cloexec(sock_ioctl);

	/* Prepare socket for routing / address control */
	sock_rtnl = create_socket(NETLINK_ROUTE, 0);
	if (!sock_rtnl)
		return -1;

	if (!create_event_socket(&rtnl_event, NETLINK_ROUTE, cb_rtnl_event))
		return -1;

	if (!create_hotplug_event_socket(&hotplug_event, NETLINK_KOBJECT_UEVENT,
					 handle_hotplug_event))
		return -1;

	/* Receive network link events form kernel */
	nl_socket_add_membership(rtnl_event.sock, RTNLGRP_LINK);

	return 0;
}

static void write_file(const char *path, const char *val)
{
	int fd;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return;

	if (write(fd, val, strlen(val))) {}
	close(fd);
}

static int read_file(const char *path, char *buf, const size_t buf_sz)
{
	int fd = -1, ret = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;

	ssize_t len = read(fd, buf, buf_sz - 1);
	if (len < 0)
		goto out;

	ret = buf[len] = 0;

out:
	if (fd >= 0)
		close(fd);

	return ret;
}


static const char *
dev_sysctl_path(const char *prefix, const char *ifname, const char *file)
{
	snprintf(dev_buf, sizeof(dev_buf), "%s/sys/net/%s/%s/%s", proc_path, prefix, ifname, file);

	return dev_buf;
}

static const char *
dev_sysfs_path(const char *ifname, const char *file)
{
	snprintf(dev_buf, sizeof(dev_buf), "%s/class/net/%s/%s", sysfs_path, ifname, file);

	return dev_buf;
}

static void
system_set_dev_sysctl(const char *prefix, const char *file, const char *ifname,
		      const char *val)
{
	write_file(dev_sysctl_path(prefix, ifname, file), val);
}

static int
system_get_dev_sysctl(const char *prefix, const char *file, const char *ifname,
		      char *buf, size_t buf_sz)
{
	return read_file(dev_sysctl_path(prefix, ifname, file), buf, buf_sz);
}

static void
system_set_dev_sysfs(const char *file, const char *ifname, const char *val)
{
	if (!val)
		return;

	write_file(dev_sysfs_path(ifname, file), val);
}

static void
system_set_dev_sysfs_int(const char *file, const char *ifname, int val)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", val);
	system_set_dev_sysfs(file, ifname, buf);
}

static int
system_get_dev_sysfs(const char *file, const char *ifname, char *buf, size_t buf_sz)
{
	return read_file(dev_sysfs_path(ifname, file), buf, buf_sz);
}

static void system_set_disable_ipv6(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv6/conf", "disable_ipv6", dev->ifname, val);
}

static void system_set_ip6segmentrouting(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv6/conf", "seg6_enabled", dev->ifname, val);
}

static void system_set_rpfilter(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/conf", "rp_filter", dev->ifname, val);
}

static void system_set_acceptlocal(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/conf", "accept_local", dev->ifname, val);
}

static void system_set_igmpversion(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/conf", "force_igmp_version", dev->ifname, val);
}

static void system_set_mldversion(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv6/conf", "force_mld_version", dev->ifname, val);
}

static void system_set_neigh4reachabletime(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/neigh", "base_reachable_time_ms", dev->ifname, val);
}

static void system_set_neigh6reachabletime(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv6/neigh", "base_reachable_time_ms", dev->ifname, val);
}

static void system_set_neigh4gcstaletime(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/neigh", "gc_stale_time", dev->ifname, val);
}

static void system_set_neigh6gcstaletime(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv6/neigh", "gc_stale_time", dev->ifname, val);
}

static void system_set_neigh4locktime(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/neigh", "locktime", dev->ifname, val);
}

static void system_set_dadtransmits(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv6/conf", "dad_transmits", dev->ifname, val);
}

static void system_set_sendredirects(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/conf", "send_redirects", dev->ifname, val);
}

static void system_set_drop_v4_unicast_in_l2_multicast(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/conf", "drop_unicast_in_l2_multicast", dev->ifname, val);
}

static void system_set_drop_v6_unicast_in_l2_multicast(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv6/conf", "drop_unicast_in_l2_multicast", dev->ifname, val);
}

static void system_set_drop_gratuitous_arp(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/conf", "drop_gratuitous_arp", dev->ifname, val);
}

static void system_set_drop_unsolicited_na(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv6/conf", "drop_unsolicited_na", dev->ifname, val);
}

static void system_set_arp_accept(struct device *dev, const char *val)
{
	system_set_dev_sysctl("ipv4/conf", "arp_accept", dev->ifname, val);
}

static void system_bridge_set_multicast_to_unicast(struct device *dev, const char *val)
{
	system_set_dev_sysfs("brport/multicast_to_unicast", dev->ifname, val);
}

static void system_bridge_set_multicast_fast_leave(struct device *dev, const char *val)
{
	system_set_dev_sysfs("brport/multicast_fast_leave", dev->ifname, val);
}

static void system_bridge_set_hairpin_mode(struct device *dev, const char *val)
{
	system_set_dev_sysfs("brport/hairpin_mode", dev->ifname, val);
}

static void system_bridge_set_proxyarp_wifi(struct device *dev, const char *val)
{
	system_set_dev_sysfs("brport/proxyarp_wifi", dev->ifname, val);
}

static void system_bridge_set_bpdu_filter(struct device *dev, const char *val)
{
	system_set_dev_sysfs("brport/bpdu_filter", dev->ifname, val);
}

static void system_bridge_set_isolated(struct device *dev, const char *val)
{
	system_set_dev_sysfs("brport/isolated", dev->ifname, val);
}

static void system_bridge_set_multicast_router(struct device *dev, const char *val)
{
	system_set_dev_sysfs("brport/multicast_router", dev->ifname, val);
}

void system_bridge_set_stp_state(struct device *dev, bool val)
{
	const char *valstr = val ? "1" : "0";

	system_set_dev_sysfs("bridge/stp_state", dev->ifname, valstr);
}

static void system_bridge_set_learning(struct device *dev, const char *val)
{
	system_set_dev_sysfs("brport/learning", dev->ifname, val);
}

static void system_bridge_set_unicast_flood(struct device *dev, const char *val)
{
	system_set_dev_sysfs("brport/unicast_flood", dev->ifname, val);
}

static int system_get_disable_ipv6(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv6/conf", "disable_ipv6",
				     dev->ifname, buf, buf_sz);
}

static int system_get_ip6segmentrouting(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv6/conf", "seg6_enabled",
				     dev->ifname, buf, buf_sz);
}

static int system_get_rpfilter(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/conf", "rp_filter",
				     dev->ifname, buf, buf_sz);
}

static int system_get_acceptlocal(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/conf", "accept_local",
				     dev->ifname, buf, buf_sz);
}

static int system_get_igmpversion(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/conf", "force_igmp_version",
				     dev->ifname, buf, buf_sz);
}

static int system_get_mldversion(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv6/conf", "force_mld_version",
				     dev->ifname, buf, buf_sz);
}

static int system_get_neigh4reachabletime(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/neigh", "base_reachable_time_ms",
				     dev->ifname, buf, buf_sz);
}

static int system_get_neigh6reachabletime(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv6/neigh", "base_reachable_time_ms",
				     dev->ifname, buf, buf_sz);
}

static int system_get_neigh4gcstaletime(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/neigh", "gc_stale_time",
				     dev->ifname, buf, buf_sz);
}

static int system_get_neigh6gcstaletime(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv6/neigh", "gc_stale_time",
			dev->ifname, buf, buf_sz);
}

static int system_get_neigh4locktime(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/neigh", "locktime",
			dev->ifname, buf, buf_sz);
}

static int system_get_dadtransmits(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv6/conf", "dad_transmits",
			dev->ifname, buf, buf_sz);
}

static int system_get_sendredirects(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/conf", "send_redirects",
			dev->ifname, buf, buf_sz);
}


static int system_get_drop_v4_unicast_in_l2_multicast(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/conf", "drop_unicast_in_l2_multicast",
			dev->ifname, buf, buf_sz);
}

static int system_get_drop_v6_unicast_in_l2_multicast(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv6/conf", "drop_unicast_in_l2_multicast",
			dev->ifname, buf, buf_sz);
}

static int system_get_drop_gratuitous_arp(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/conf", "drop_gratuitous_arp",
			dev->ifname, buf, buf_sz);
}

static int system_get_drop_unsolicited_na(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv6/conf", "drop_unsolicited_na",
			dev->ifname, buf, buf_sz);
}

static int system_get_arp_accept(struct device *dev, char *buf, const size_t buf_sz)
{
	return system_get_dev_sysctl("ipv4/conf", "arp_accept",
			dev->ifname, buf, buf_sz);
}

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

static void
system_set_ethtool_settings(struct device *dev, struct device_settings *s);

static void
system_device_update_state(struct device *dev, unsigned int flags, unsigned int ifindex)
{
	if (dev->type == &simple_device_type) {
		if (dev->external)
			device_set_disabled(dev, !(flags & IFF_UP));

		device_set_present(dev, ifindex > 0);
	}
	device_set_link(dev, flags & IFF_LOWER_UP ? true : false);

	if ((flags & IFF_UP) && !(flags & IFF_LOWER_UP))
		system_set_ethtool_settings(dev, &dev->settings);
}

/* Evaluate netlink messages */
static int cb_rtnl_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nh = nlmsg_hdr(msg);
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct nlattr *nla[__IFLA_MAX];
	struct device *dev;

	if (nh->nlmsg_type != RTM_NEWLINK)
		return 0;

	nlmsg_parse(nh, sizeof(struct ifinfomsg), nla, __IFLA_MAX - 1, NULL);
	if (!nla[IFLA_IFNAME])
		return 0;

	dev = device_find(nla_data(nla[IFLA_IFNAME]));
	if (!dev)
		return 0;

	system_device_update_state(dev, ifi->ifi_flags, ifi->ifi_index);
	return 0;
}

static void
handle_hotplug_msg(char *data, int size)
{
	const char *subsystem = NULL, *interface = NULL, *interface_old = NULL;
	char *cur, *end, *sep;
	int skip;
	bool add;

	if (!strncmp(data, "add@", 4) || !strncmp(data, "move@", 5))
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
		} else if (!strcmp(cur, "DEVPATH_OLD")) {
			interface_old = strrchr(sep + 1, '/');
			if (interface_old)
				interface_old++;
		}
	}

	if (!subsystem || !interface)
		return;

	if (interface_old)
		device_hotplug_event(interface_old, false);

	device_hotplug_event(interface, add);
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

	switch (-size) {
	case 0:
		return;

	case NLE_NOMEM:
		/* Increase rx buffer size on netlink socket */
		ev->bufsize *= 2;
		if (nl_socket_set_buffer_size(ev->sock, ev->bufsize, 0))
			goto abort;
		break;

	default:
		goto abort;
	}
	return;

abort:
	uloop_fd_delete(&ev->uloop);
	return;
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

static struct nl_msg *__system_ifinfo_msg(int af, int index, const char *ifname, uint16_t type, uint16_t flags)
{
	struct nl_msg *msg;
	struct ifinfomsg iim = {
		.ifi_family = af,
		.ifi_index = index,
	};

	msg = nlmsg_alloc_simple(type, flags | NLM_F_REQUEST);
	if (!msg)
		return NULL;

	nlmsg_append(msg, &iim, sizeof(iim), 0);
	if (ifname)
		nla_put_string(msg, IFLA_IFNAME, ifname);

	return msg;
}

static struct nl_msg *system_ifinfo_msg(const char *ifname, uint16_t type, uint16_t flags)
{
	return __system_ifinfo_msg(AF_UNSPEC, 0, ifname, type, flags);
}

static int system_link_del(const char *ifname)
{
	struct nl_msg *msg;

	msg = system_ifinfo_msg(ifname, RTM_DELLINK, 0);
	if (!msg)
		return -1;

	return system_rtnl_call(msg);
}

int system_bridge_delbr(struct device *bridge)
{
	return system_link_del(bridge->ifname);
}

static int system_bridge_if(const char *bridge, struct device *dev, int cmd, void *data)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	if (dev)
		ifr.ifr_ifindex = dev->ifindex;
	else
		ifr.ifr_data = data;
	strncpy(ifr.ifr_name, bridge, sizeof(ifr.ifr_name) - 1);
	return ioctl(sock_ioctl, cmd, &ifr);
}

static bool system_is_bridge(const char *name)
{
	struct stat st;

	return stat(dev_sysfs_path(name, "bridge"), &st) >= 0;
}

static char *system_get_bridge(const char *name, char *buf, int buflen)
{
	char *path;
	ssize_t len = -1;
	glob_t gl;

	snprintf(buf, buflen, "%s/devices/virtual/net/*/brif/%s/bridge", sysfs_path, name);
	if (glob(buf, GLOB_NOSORT, NULL, &gl) < 0)
		return NULL;

	if (gl.gl_pathc > 0)
		len = readlink(gl.gl_pathv[0], buf, buflen);

	globfree(&gl);

	if (len < 0)
		return NULL;

	buf[len] = 0;
	path = strrchr(buf, '/');
	if (!path)
		return NULL;

	return path + 1;
}

static void
system_bridge_set_wireless(struct device *bridge, struct device *dev)
{
	bool mcast_to_ucast = dev->wireless_ap;
	bool hairpin;

	if (dev->settings.flags & DEV_OPT_MULTICAST_TO_UNICAST)
		mcast_to_ucast = dev->settings.multicast_to_unicast;
	else if (bridge->settings.flags & DEV_OPT_MULTICAST_TO_UNICAST &&
	         !bridge->settings.multicast_to_unicast)
		mcast_to_ucast = false;

	hairpin = mcast_to_ucast || dev->wireless_proxyarp;
	if (dev->wireless_isolate)
		hairpin = false;

	system_bridge_set_multicast_to_unicast(dev, mcast_to_ucast ? "1" : "0");
	system_bridge_set_hairpin_mode(dev, hairpin ? "1" : "0");
	system_bridge_set_proxyarp_wifi(dev, dev->wireless_proxyarp ? "1" : "0");
}

int system_bridge_addif(struct device *bridge, struct device *dev)
{
	char buf[64];
	char *oldbr;
	int tries = 0;
	int ret;


	for (tries = 0; tries < 3; tries++) {
		ret = 0;
		oldbr = system_get_bridge(dev->ifname, dev_buf, sizeof(dev_buf));
		if (oldbr && !strcmp(oldbr, bridge->ifname))
			break;

		ret = system_bridge_if(bridge->ifname, dev, SIOCBRADDIF, NULL);
		if (!ret)
			break;

		D(SYSTEM, "Failed to add device '%s' to bridge '%s' (tries=%d): %s",
		  dev->ifname, bridge->ifname, tries, strerror(errno));
	}

	if (dev->wireless)
		system_bridge_set_wireless(bridge, dev);

	if (dev->settings.flags & DEV_OPT_MULTICAST_ROUTER) {
		snprintf(buf, sizeof(buf), "%u", dev->settings.multicast_router);
		system_bridge_set_multicast_router(dev, buf);
	}

	if (dev->settings.flags & DEV_OPT_MULTICAST_FAST_LEAVE &&
	    dev->settings.multicast_fast_leave)
		system_bridge_set_multicast_fast_leave(dev, "1");

	if (dev->settings.flags & DEV_OPT_LEARNING &&
	    !dev->settings.learning)
		system_bridge_set_learning(dev, "0");

	if (dev->settings.flags & DEV_OPT_UNICAST_FLOOD &&
	    !dev->settings.unicast_flood)
		system_bridge_set_unicast_flood(dev, "0");

	if (dev->settings.flags & DEV_OPT_ISOLATE &&
	    dev->settings.isolate)
		system_bridge_set_isolated(dev, "1");

	if (dev->bpdu_filter)
		system_bridge_set_bpdu_filter(dev, dev->bpdu_filter ? "1" : "0");

	return ret;
}

int system_bridge_delif(struct device *bridge, struct device *dev)
{
	return system_bridge_if(bridge->ifname, dev, SIOCBRDELIF, NULL);
}

int system_bridge_vlan(const char *iface, uint16_t vid, int16_t vid_end, bool add, unsigned int vflags)
{
	struct bridge_vlan_info vinfo = { .vid = vid, };
	unsigned short flags = 0;
	struct nlattr *afspec;
	struct nl_msg *nlm;
	int index;
	int ret = 0;

	index = if_nametoindex(iface);
	if (!index)
		return -1;

	nlm = __system_ifinfo_msg(PF_BRIDGE, index, NULL, add ? RTM_SETLINK : RTM_DELLINK, 0);
	if (!nlm)
		return -1;

	if (vflags & BRVLAN_F_SELF)
		flags |= BRIDGE_FLAGS_SELF;

	if (vflags & BRVLAN_F_PVID)
		vinfo.flags |= BRIDGE_VLAN_INFO_PVID;

	if (vflags & BRVLAN_F_UNTAGGED)
		vinfo.flags |= BRIDGE_VLAN_INFO_UNTAGGED;

	afspec = nla_nest_start(nlm, IFLA_AF_SPEC);
	if (!afspec) {
		ret = -ENOMEM;
		goto failure;
	}

	if (flags)
		nla_put_u16(nlm, IFLA_BRIDGE_FLAGS, flags);

	if (vid_end > vid)
		vinfo.flags |= BRIDGE_VLAN_INFO_RANGE_BEGIN;

	nla_put(nlm, IFLA_BRIDGE_VLAN_INFO, sizeof(vinfo), &vinfo);

	if (vid_end > vid) {
		vinfo.flags &= ~BRIDGE_VLAN_INFO_RANGE_BEGIN;
		vinfo.flags |= BRIDGE_VLAN_INFO_RANGE_END;
		vinfo.vid = vid_end;
		nla_put(nlm, IFLA_BRIDGE_VLAN_INFO, sizeof(vinfo), &vinfo);
	}

	nla_nest_end(nlm, afspec);

	return system_rtnl_call(nlm);

failure:
	nlmsg_free(nlm);
	return ret;
}

int system_bonding_set_device(struct device *dev, struct bonding_config *cfg)
{
	const char *ifname = dev->ifname;
	struct blob_attr *cur;
	char op = cfg ? '+' : '-';
	char buf[64];
	size_t rem;

	snprintf(dev_buf, sizeof(dev_buf), "%s/class/net/bonding_masters", sysfs_path);
	snprintf(buf, sizeof(buf), "%c%s", op, ifname);
	write_file(dev_buf, buf);

	if (!cfg)
		return 0;

	system_set_dev_sysfs("bonding/mode", ifname, bonding_policy_str[cfg->policy]);

	system_set_dev_sysfs_int("bonding/all_ports_active", ifname, cfg->all_ports_active);

	if (cfg->policy == BONDING_MODE_BALANCE_XOR ||
	    cfg->policy == BONDING_MODE_BALANCE_TLB ||
	    cfg->policy == BONDING_MODE_8023AD)
		system_set_dev_sysfs("bonding/xmit_hash_policy", ifname, cfg->xmit_hash_policy);

	if (cfg->policy == BONDING_MODE_8023AD) {
		system_set_dev_sysfs("bonding/ad_actor_system", ifname, cfg->ad_actor_system);
		system_set_dev_sysfs_int("bonding/ad_actor_sys_prio", ifname, cfg->ad_actor_sys_prio);
		system_set_dev_sysfs("bonding/ad_select", ifname, cfg->ad_select);
		system_set_dev_sysfs("bonding/lacp_rate", ifname, cfg->lacp_rate);
		system_set_dev_sysfs_int("bonding/min_links", ifname, cfg->min_links);
	}

	if (cfg->policy == BONDING_MODE_BALANCE_RR)
		system_set_dev_sysfs_int("bonding/packets_per_slave", ifname, cfg->packets_per_port);

	if (cfg->policy == BONDING_MODE_BALANCE_TLB ||
	    cfg->policy == BONDING_MODE_BALANCE_ALB)
		system_set_dev_sysfs_int("bonding/lp_interval", ifname, cfg->lp_interval);

	if (cfg->policy == BONDING_MODE_BALANCE_TLB)
		system_set_dev_sysfs_int("bonding/tlb_dynamic_lb", ifname, cfg->dynamic_lb);
	system_set_dev_sysfs_int("bonding/resend_igmp", ifname, cfg->resend_igmp);
	system_set_dev_sysfs_int("bonding/num_grat_arp", ifname, cfg->num_peer_notif);
	system_set_dev_sysfs("bonding/primary_reselect", ifname, cfg->primary_reselect);
	system_set_dev_sysfs("bonding/fail_over_mac", ifname, cfg->failover_mac);

	system_set_dev_sysfs_int((cfg->monitor_arp ?
				  "bonding/arp_interval" :
				  "bonding/miimon"), ifname, cfg->monitor_interval);

	blobmsg_for_each_attr(cur, cfg->arp_target, rem) {
		snprintf(buf, sizeof(buf), "+%s", blobmsg_get_string(cur));
		system_set_dev_sysfs("bonding/arp_ip_target", ifname, buf);
	}

	system_set_dev_sysfs_int("bonding/arp_all_targets", ifname, cfg->arp_all_targets);
	if (cfg->policy < BONDING_MODE_8023AD)
		system_set_dev_sysfs("bonding/arp_validate", ifname, cfg->arp_validate);
	system_set_dev_sysfs_int("bonding/use_carrier", ifname, cfg->use_carrier);
	if (!cfg->monitor_arp && cfg->monitor_interval) {
		system_set_dev_sysfs_int("bonding/updelay", ifname, cfg->updelay);
		system_set_dev_sysfs_int("bonding/downdelay", ifname, cfg->downdelay);
	}

	return 0;
}

int system_bonding_set_port(struct device *dev, struct device *port, bool add, bool primary)
{
	const char *port_name = port->ifname;
	const char op_ch = add ? '+' : '-';
	char buf[IFNAMSIZ + 1];

	snprintf(buf, sizeof(buf), "%c%s", op_ch, port_name);
	system_if_down(port);
	system_set_dev_sysfs("bonding/slaves", dev->ifname, buf);
	system_if_up(port);

	if (primary)
		system_set_dev_sysfs("bonding/primary", dev->ifname,
				     add ? port_name : "");

	return 0;
}

int system_if_resolve(struct device *dev)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);
	if (!ioctl(sock_ioctl, SIOCGIFINDEX, &ifr))
		return ifr.ifr_ifindex;
	else
		return 0;
}

static int system_if_flags(const char *ifname, unsigned add, unsigned rem)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
	if (ioctl(sock_ioctl, SIOCGIFFLAGS, &ifr) < 0)
		return -1;

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

	return (long)ifa->ifa_index == ifindex;
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
	int type, ret;

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
		D(SYSTEM, "Remove a rule");
	else
		D(SYSTEM, "Remove %s from device %s",
		  type == RTM_DELADDR ? "an address" : "a route",
		  clr->dev->ifname);

	memcpy(nlmsg_hdr(clr->msg), hdr, hdr->nlmsg_len);
	hdr = nlmsg_hdr(clr->msg);
	hdr->nlmsg_type = type;
	hdr->nlmsg_flags = NLM_F_REQUEST;

	nl_socket_disable_auto_ack(sock_rtnl);
	ret = nl_send_auto_complete(sock_rtnl, clr->msg);
	if (ret < 0) {
		if (type == RTM_DELRULE)
			D(SYSTEM, "Error deleting a rule: %d", ret);
		else
			D(SYSTEM, "Error deleting %s from device '%s': %d",
				type == RTM_DELADDR ? "an address" : "a route",
				clr->dev->ifname, ret);
	}

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
	struct nl_cb *cb;
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

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		return;

	clr.msg = nlmsg_alloc_simple(type, flags);
	if (!clr.msg)
		goto out;

	nlmsg_append(clr.msg, &rtm, clr.size, 0);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_clear_event, &clr);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, cb_finish_event, &pending);
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &pending);

	if (nl_send_auto_complete(sock_rtnl, clr.msg) < 0)
		goto free;

	while (pending > 0)
		nl_recvmsgs(sock_rtnl, cb);

free:
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
	device_set_ifindex(dev, system_if_resolve(dev));

	if (dev->external || !dev->ifindex)
		return;

	system_if_flags(dev->ifname, 0, IFF_UP);

	if (system_is_bridge(dev->ifname)) {
		D(SYSTEM, "Delete existing bridge named '%s'", dev->ifname);
		system_bridge_delbr(dev);
		return;
	}

	bridge = system_get_bridge(dev->ifname, buf, sizeof(buf));
	if (bridge) {
		D(SYSTEM, "Remove device '%s' from bridge '%s'", dev->ifname, bridge);
		system_bridge_if(bridge, dev, SIOCBRDELIF, NULL);
	}

	system_if_clear_entries(dev, RTM_GETROUTE, AF_INET);
	system_if_clear_entries(dev, RTM_GETADDR, AF_INET);
	system_if_clear_entries(dev, RTM_GETROUTE, AF_INET6);
	system_if_clear_entries(dev, RTM_GETADDR, AF_INET6);
	system_if_clear_entries(dev, RTM_GETNEIGH, AF_INET);
	system_if_clear_entries(dev, RTM_GETNEIGH, AF_INET6);
	system_set_disable_ipv6(dev, "0");
}

static inline unsigned long
sec_to_jiffies(int val)
{
	return (unsigned long) val * 100;
}

int system_bridge_addbr(struct device *bridge, struct bridge_config *cfg)
{
	struct nlattr *linkinfo, *data;
	struct nl_msg *msg;
	uint64_t val;
	int rv;

	msg = system_ifinfo_msg(bridge->ifname, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);
	if (!msg)
		return -1;

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	nla_put_string(msg, IFLA_INFO_KIND, "bridge");

	if (!(data = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	nla_put_u32(msg, IFLA_BR_STP_STATE, cfg->stp);
	nla_put_u32(msg, IFLA_BR_FORWARD_DELAY, sec_to_jiffies(cfg->forward_delay));
	nla_put_u8(msg, IFLA_BR_MCAST_SNOOPING, !!cfg->igmp_snoop);
	nla_put_u8(msg, IFLA_BR_MCAST_QUERIER, !!cfg->multicast_querier);
	nla_put_u32(msg, IFLA_BR_MCAST_HASH_MAX, cfg->hash_max);

	if (bridge->settings.flags & DEV_OPT_MULTICAST_ROUTER)
		nla_put_u8(msg, IFLA_BR_MCAST_ROUTER, !!bridge->settings.multicast_router);

	if (cfg->flags & BRIDGE_OPT_ROBUSTNESS) {
		nla_put_u32(msg, IFLA_BR_MCAST_STARTUP_QUERY_CNT, cfg->robustness);
		nla_put_u32(msg, IFLA_BR_MCAST_LAST_MEMBER_CNT, cfg->robustness);
	}

	if (cfg->flags & BRIDGE_OPT_QUERY_INTERVAL)
		nla_put_u64(msg, IFLA_BR_MCAST_QUERY_INTVL, cfg->query_interval);

	if (cfg->flags & BRIDGE_OPT_QUERY_RESPONSE_INTERVAL)
		nla_put_u64(msg, IFLA_BR_MCAST_QUERY_RESPONSE_INTVL, cfg->query_response_interval);

	if (cfg->flags & BRIDGE_OPT_LAST_MEMBER_INTERVAL)
		nla_put_u64(msg, IFLA_BR_MCAST_LAST_MEMBER_INTVL, cfg->last_member_interval);

	if (cfg->flags & BRIDGE_OPT_ROBUSTNESS ||
	    cfg->flags & BRIDGE_OPT_QUERY_INTERVAL ||
	    cfg->flags & BRIDGE_OPT_QUERY_RESPONSE_INTERVAL) {
		val = cfg->robustness * cfg->query_interval +
			cfg->query_response_interval;

		nla_put_u64(msg, IFLA_BR_MCAST_MEMBERSHIP_INTVL, val);

		val -= cfg->query_response_interval / 2;

		nla_put_u64(msg, IFLA_BR_MCAST_QUERIER_INTVL, val);
	}

	if (cfg->flags & BRIDGE_OPT_QUERY_INTERVAL) {
		val = cfg->query_interval / 4;

		nla_put_u64(msg, IFLA_BR_MCAST_STARTUP_QUERY_INTVL, val);
	}

	nla_put_u8(msg, IFLA_BR_VLAN_FILTERING, !!cfg->vlan_filtering);
	nla_put_u16(msg, IFLA_BR_PRIORITY, cfg->priority);
	nla_put_u32(msg, IFLA_BR_HELLO_TIME, sec_to_jiffies(cfg->hello_time));
	nla_put_u32(msg, IFLA_BR_MAX_AGE, sec_to_jiffies(cfg->max_age));

	if (cfg->flags & BRIDGE_OPT_AGEING_TIME)
		nla_put_u32(msg, IFLA_BR_AGEING_TIME, sec_to_jiffies(cfg->ageing_time));

	nla_nest_end(msg, data);
	nla_nest_end(msg, linkinfo);

	rv = system_rtnl_call(msg);
	if (rv)
		D(SYSTEM, "Error adding bridge '%s': %d", bridge->ifname, rv);

	return rv;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOMEM;
}

int system_macvlan_add(struct device *macvlan, struct device *dev, struct macvlan_config *cfg)
{
	struct nl_msg *msg;
	struct nlattr *linkinfo, *data;
	size_t i;
	int rv;
	static const struct {
		const char *name;
		enum macvlan_mode val;
	} modes[] = {
		{ "private", MACVLAN_MODE_PRIVATE },
		{ "vepa", MACVLAN_MODE_VEPA },
		{ "bridge", MACVLAN_MODE_BRIDGE },
		{ "passthru", MACVLAN_MODE_PASSTHRU },
	};

	msg = system_ifinfo_msg(macvlan->ifname, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);
	if (!msg)
		return -1;

	if (cfg->flags & MACVLAN_OPT_MACADDR)
		nla_put(msg, IFLA_ADDRESS, sizeof(cfg->macaddr), cfg->macaddr);
	nla_put_u32(msg, IFLA_LINK, dev->ifindex);

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	nla_put_string(msg, IFLA_INFO_KIND, "macvlan");

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
		D(SYSTEM, "Error adding macvlan '%s' over '%s': %d", macvlan->ifname, dev->ifname, rv);

	return rv;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOMEM;
}

int system_link_netns_move(struct device *dev, int netns_fd, const char *target_ifname)
{
	struct nl_msg *msg;
	int index;

	if (!dev)
		return -1;

	index = system_if_resolve(dev);
	msg = __system_ifinfo_msg(AF_UNSPEC, index, target_ifname, RTM_NEWLINK, 0);
	if (!msg)
		return -1;

	nla_put_u32(msg, IFLA_NET_NS_FD, netns_fd);
	return system_rtnl_call(msg);
}

int system_macvlan_del(struct device *macvlan)
{
	return system_link_del(macvlan->ifname);
}

int system_netns_open(const pid_t target_ns)
{
	char pid_net_path[PATH_MAX];

	snprintf(pid_net_path, sizeof(pid_net_path), "/proc/%u/ns/net", target_ns);

	return open(pid_net_path, O_RDONLY);
}

int system_netns_set(int netns_fd)
{
	return setns(netns_fd, CLONE_NEWNET);
}

int system_veth_add(struct device *veth, struct veth_config *cfg)
{
	struct nl_msg *msg;
	struct ifinfomsg empty_iim = {0,};
	struct nlattr *linkinfo, *data, *veth_info;
	int rv;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);

	if (!msg)
		return -1;

	nlmsg_append(msg, &empty_iim, sizeof(empty_iim), 0);

	if (cfg->flags & VETH_OPT_MACADDR)
		nla_put(msg, IFLA_ADDRESS, sizeof(cfg->macaddr), cfg->macaddr);
	nla_put_string(msg, IFLA_IFNAME, veth->ifname);

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	nla_put_string(msg, IFLA_INFO_KIND, "veth");

	if (!(data = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	if (!(veth_info = nla_nest_start(msg, VETH_INFO_PEER)))
		goto nla_put_failure;

	nlmsg_append(msg, &empty_iim, sizeof(empty_iim), 0);

	if (cfg->flags & VETH_OPT_PEER_NAME)
		nla_put_string(msg, IFLA_IFNAME, cfg->peer_name);
	if (cfg->flags & VETH_OPT_PEER_MACADDR)
		nla_put(msg, IFLA_ADDRESS, sizeof(cfg->peer_macaddr), cfg->peer_macaddr);

	nla_nest_end(msg, veth_info);
	nla_nest_end(msg, data);
	nla_nest_end(msg, linkinfo);

	rv = system_rtnl_call(msg);
	if (rv) {
		if (cfg->flags & VETH_OPT_PEER_NAME)
			D(SYSTEM, "Error adding veth '%s' with peer '%s': %d", veth->ifname, cfg->peer_name, rv);
		else
			D(SYSTEM, "Error adding veth '%s': %d", veth->ifname, rv);
	}

	return rv;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOMEM;
}

int system_veth_del(struct device *veth)
{
	return system_link_del(veth->ifname);
}

static int system_vlan(struct device *dev, int id)
{
	struct vlan_ioctl_args ifr = {
		.cmd = SET_VLAN_NAME_TYPE_CMD,
		.u.name_type = VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD,
	};

	if (ioctl(sock_ioctl, SIOCSIFVLAN, &ifr) < 0)
		return -1;

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

int system_vlandev_add(struct device *vlandev, struct device *dev, struct vlandev_config *cfg)
{
	struct nl_msg *msg;
	struct nlattr *linkinfo, *data, *qos;
	struct ifinfomsg iim = { .ifi_family = AF_UNSPEC };
	struct vlan_qos_mapping *elem;
	struct ifla_vlan_qos_mapping nl_qos_map;
	int rv;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);

	if (!msg)
		return -1;

	nlmsg_append(msg, &iim, sizeof(iim), 0);
	nla_put_string(msg, IFLA_IFNAME, vlandev->ifname);
	nla_put_u32(msg, IFLA_LINK, dev->ifindex);

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	nla_put_string(msg, IFLA_INFO_KIND, "vlan");

	if (!(data = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	nla_put_u16(msg, IFLA_VLAN_ID, cfg->vid);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	nla_put_u16(msg, IFLA_VLAN_PROTOCOL, htons(cfg->proto));
#else
	if(cfg->proto == VLAN_PROTO_8021AD)
		netifd_log_message(L_WARNING, "%s Your kernel is older than linux 3.10.0, 802.1ad is not supported defaulting to 802.1q", vlandev->type->name);
#endif

	if (!(qos = nla_nest_start(msg, IFLA_VLAN_INGRESS_QOS)))
		goto nla_put_failure;

	vlist_simple_for_each_element(&cfg->ingress_qos_mapping_list, elem, node) {
		nl_qos_map.from = elem->from;
		nl_qos_map.to = elem->to;
		nla_put(msg, IFLA_VLAN_QOS_MAPPING, sizeof(nl_qos_map), &nl_qos_map);
	}
	nla_nest_end(msg, qos);

	if (!(qos = nla_nest_start(msg, IFLA_VLAN_EGRESS_QOS)))
		goto nla_put_failure;

	vlist_simple_for_each_element(&cfg->egress_qos_mapping_list, elem, node) {
		nl_qos_map.from = elem->from;
		nl_qos_map.to = elem->to;
		nla_put(msg, IFLA_VLAN_QOS_MAPPING, sizeof(nl_qos_map), &nl_qos_map);
	}
	nla_nest_end(msg, qos);

	nla_nest_end(msg, data);
	nla_nest_end(msg, linkinfo);

	rv = system_rtnl_call(msg);
	if (rv)
		D(SYSTEM, "Error adding vlandev '%s' over '%s': %d", vlandev->ifname, dev->ifname, rv);

	return rv;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOMEM;
}

int system_vlandev_del(struct device *vlandev)
{
	return system_link_del(vlandev->ifname);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
struct if_get_master_data {
	int ifindex;
	int master_ifindex;
	int pending;
};

static void if_get_master_dsa_linkinfo_attr(struct if_get_master_data *data,
			       struct rtattr *attr)
{
	struct rtattr *cur;
	int rem = RTA_PAYLOAD(attr);

	for (cur = RTA_DATA(attr); RTA_OK(cur, rem); cur = RTA_NEXT(cur, rem)) {
		if (cur->rta_type != IFLA_DSA_MASTER)
			continue;

		data->master_ifindex = *(__u32 *)RTA_DATA(cur);
	}
}

static void if_get_master_linkinfo_attr(struct if_get_master_data *data,
			       struct rtattr *attr)
{
	struct rtattr *cur;
	int rem = RTA_PAYLOAD(attr);

	for (cur = RTA_DATA(attr); RTA_OK(cur, rem); cur = RTA_NEXT(cur, rem)) {
		if (cur->rta_type != IFLA_INFO_KIND && cur->rta_type != IFLA_INFO_DATA)
			continue;

		if (cur->rta_type == IFLA_INFO_KIND && strcmp("dsa", (char *)RTA_DATA(cur)))
			break;

		if (cur->rta_type == IFLA_INFO_DATA)
			if_get_master_dsa_linkinfo_attr(data, cur);
	}
}

static int cb_if_get_master_valid(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nh = nlmsg_hdr(msg);
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct if_get_master_data *data = (struct if_get_master_data *)arg;
	struct rtattr *attr;
	int rem;

	if (nh->nlmsg_type != RTM_NEWLINK)
		return NL_SKIP;

	if (ifi->ifi_family != AF_UNSPEC)
		return NL_SKIP;

	if (ifi->ifi_index != data->ifindex)
		return NL_SKIP;

	attr = IFLA_RTA(ifi);
	rem = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));

	while (RTA_OK(attr, rem)) {
		if (attr->rta_type == IFLA_LINKINFO)
			if_get_master_linkinfo_attr(data, attr);

		attr = RTA_NEXT(attr, rem);
	}

	return NL_OK;
}

static int cb_if_get_master_ack(struct nl_msg *msg, void *arg)
{
	struct if_get_master_data *data = (struct if_get_master_data *)arg;
	data->pending = 0;
	return NL_STOP;
}

static int cb_if_get_master_error(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	struct if_get_master_data *data = (struct if_get_master_data *)arg;
	data->pending = 0;
	return NL_STOP;
}

static int system_if_get_master_ifindex(struct device *dev)
{
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct nl_msg *msg;
	struct ifinfomsg ifi = {
		.ifi_family = AF_UNSPEC,
		.ifi_index = 0,
	};
	struct if_get_master_data data = {
		.ifindex = if_nametoindex(dev->ifname),
		.master_ifindex = -1,
		.pending = 1,
	};
	int ret = -1;

	if (!cb)
		return ret;

	msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST);
	if (!msg)
		goto out;

	if (nlmsg_append(msg, &ifi, sizeof(ifi), 0) ||
	    nla_put_string(msg, IFLA_IFNAME, dev->ifname))
		goto free;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_if_get_master_valid, &data);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, cb_if_get_master_ack, &data);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_if_get_master_error, &data);

	ret = nl_send_auto_complete(sock_rtnl, msg);
	if (ret < 0)
		goto free;

	while (data.pending > 0)
		nl_recvmsgs(sock_rtnl, cb);

	if (data.master_ifindex >= 0)
		ret = data.master_ifindex;

free:
	nlmsg_free(msg);
out:
	nl_cb_put(cb);
	return ret;
}

static void system_refresh_orig_macaddr(struct device *dev, struct device_settings *s)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(sock_ioctl, SIOCGIFHWADDR, &ifr) == 0)
		memcpy(s->macaddr, &ifr.ifr_hwaddr.sa_data, sizeof(s->macaddr));
}

static void system_set_master(struct device *dev, int master_ifindex)
{
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC, };
	struct nl_msg *nlm;

	nlm = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST);
	if (!nlm)
		return;

	nlmsg_append(nlm, &ifi, sizeof(ifi), 0);
	nla_put_string(nlm, IFLA_IFNAME, dev->ifname);

	struct nlattr *linkinfo = nla_nest_start(nlm, IFLA_LINKINFO);
	if (!linkinfo)
		goto failure;

	nla_put_string(nlm, IFLA_INFO_KIND, "dsa");
	struct nlattr *infodata = nla_nest_start(nlm, IFLA_INFO_DATA);
	if (!infodata)
		goto failure;

	nla_put_u32(nlm, IFLA_DSA_MASTER, master_ifindex);

	nla_nest_end(nlm, infodata);
	nla_nest_end(nlm, linkinfo);

	system_rtnl_call(nlm);

	return;

failure:
	nlmsg_free(nlm);
}
#endif

static void ethtool_link_mode_clear_bit(__s8 nwords, int nr, __u32 *mask)
{
	if (nr < 0)
		return;

	if (nr >= (nwords * 32))
		return;

	mask[nr / 32] &= ~(1U << (nr % 32));
}

static bool ethtool_link_mode_test_bit(__s8 nwords, int nr, const __u32 *mask)
{
	if (nr < 0)
		return false;

	if (nr >= (nwords * 32))
		return false;

	return !!(mask[nr / 32] & (1U << (nr % 32)));
}

static int
system_get_ethtool_gro(struct device *dev)
{
	struct ethtool_value ecmd;
	struct ifreq ifr = {
		.ifr_data = (caddr_t)&ecmd,
	};

	memset(&ecmd, 0, sizeof(ecmd));
	ecmd.cmd = ETHTOOL_GGRO;
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr))
		return -1;

	return ecmd.data;
}

static void
system_set_ethtool_gro(struct device *dev, struct device_settings *s)
{
	struct ethtool_value ecmd;
	struct ifreq ifr = {
		.ifr_data = (caddr_t)&ecmd,
	};

	memset(&ecmd, 0, sizeof(ecmd));
	ecmd.cmd = ETHTOOL_SGRO;
	ecmd.data = s->gro;
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);

	ioctl(sock_ioctl, SIOCETHTOOL, &ifr);
}

static void
system_set_ethtool_pause(struct device *dev, struct device_settings *s)
{
	struct ethtool_pauseparam pp;
	struct ifreq ifr = {
		.ifr_data = (caddr_t)&pp,
	};

	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);
	memset(&pp, 0, sizeof(pp));
	pp.cmd = ETHTOOL_GPAUSEPARAM;
	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr))
		return;

	if (s->flags & DEV_OPT_RXPAUSE || s->flags & DEV_OPT_TXPAUSE) {
		pp.autoneg = AUTONEG_DISABLE;

		if (s->flags & DEV_OPT_PAUSE) {
			if (s->flags & DEV_OPT_RXPAUSE)
				pp.rx_pause = s->rxpause && s->pause;
			else
				pp.rx_pause = s->pause;

			if (s->flags & DEV_OPT_TXPAUSE)
				pp.tx_pause = s->txpause && s->pause;
			else
				pp.tx_pause = s->pause;
		} else {
			if (s->flags & DEV_OPT_RXPAUSE)
				pp.rx_pause = s->rxpause;

			if (s->flags & DEV_OPT_TXPAUSE)
				pp.tx_pause = s->txpause;
		}

		if (s->flags & DEV_OPT_ASYM_PAUSE &&
		    !s->asym_pause && (pp.rx_pause != pp.tx_pause))
			pp.rx_pause = pp.tx_pause = false;
	} else {
		pp.autoneg = AUTONEG_ENABLE;
		/* Pause and Asym_Pause advertising bits will be set via
		 * ETHTOOL_SLINKSETTINGS in system_set_ethtool_settings()
		 */
	}

	pp.cmd = ETHTOOL_SPAUSEPARAM;
	ioctl(sock_ioctl, SIOCETHTOOL, &ifr);
}

static void
system_set_ethtool_eee_settings(struct device *dev, struct device_settings *s)
{
	struct ethtool_eee eeecmd;
	struct ifreq ifr = {
		.ifr_data = (caddr_t)&eeecmd,
	};

	memset(&eeecmd, 0, sizeof(eeecmd));
	eeecmd.cmd = ETHTOOL_SEEE;
	eeecmd.eee_enabled = s->eee;
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) != 0)
		netifd_log_message(L_WARNING, "cannot set eee %d for device %s", s->eee, dev->ifname);
}

static void
system_set_ethtool_settings(struct device *dev, struct device_settings *s)
{
	struct {
		struct ethtool_link_settings req;
		__u32 link_mode_data[3 * 127];
	} ecmd;
	struct ifreq ifr = {
		.ifr_data = (caddr_t)&ecmd,
	};
	size_t i;
	__s8 nwords;
	__u32 *supported, *advertising;

	system_set_ethtool_pause(dev, s);

	if (s->flags & DEV_OPT_EEE)
		system_set_ethtool_eee_settings(dev, s);

	memset(&ecmd, 0, sizeof(ecmd));
	ecmd.req.cmd = ETHTOOL_GLINKSETTINGS;
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) < 0 ||
	    ecmd.req.link_mode_masks_nwords >= 0 ||
	    ecmd.req.cmd != ETHTOOL_GLINKSETTINGS)
		return;

	ecmd.req.link_mode_masks_nwords = -ecmd.req.link_mode_masks_nwords;

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) < 0 ||
	    ecmd.req.link_mode_masks_nwords <= 0 ||
	    ecmd.req.cmd != ETHTOOL_GLINKSETTINGS)
		return;

	nwords = ecmd.req.link_mode_masks_nwords;
	supported = &ecmd.link_mode_data[0];
	advertising = &ecmd.link_mode_data[nwords];
	memcpy(advertising, supported, sizeof(__u32) * nwords);

	for (i = 0; i < ARRAY_SIZE(ethtool_modes); i++) {
		if (s->flags & DEV_OPT_DUPLEX) {
			if (s->duplex)
				ethtool_link_mode_clear_bit(nwords, ethtool_modes[i].bit_half, advertising);
			else
				ethtool_link_mode_clear_bit(nwords, ethtool_modes[i].bit_full, advertising);
		}
		if (!(s->flags & DEV_OPT_SPEED) ||
		    s->speed == ethtool_modes[i].speed)
			continue;

		ethtool_link_mode_clear_bit(nwords, ethtool_modes[i].bit_full, advertising);
		ethtool_link_mode_clear_bit(nwords, ethtool_modes[i].bit_half, advertising);
	}

	if (s->flags & DEV_OPT_PAUSE)
		if (!s->pause)
			ethtool_link_mode_clear_bit(nwords, ETHTOOL_LINK_MODE_Pause_BIT, advertising);

	if (s->flags & DEV_OPT_ASYM_PAUSE)
		if (!s->asym_pause)
			ethtool_link_mode_clear_bit(nwords, ETHTOOL_LINK_MODE_Asym_Pause_BIT, advertising);

	if (s->flags & DEV_OPT_AUTONEG) {
		ecmd.req.autoneg = s->autoneg ? AUTONEG_ENABLE : AUTONEG_DISABLE;
		if (!s->autoneg) {
			if (s->flags & DEV_OPT_SPEED)
				ecmd.req.speed = s->speed;

			if (s->flags & DEV_OPT_DUPLEX)
				ecmd.req.duplex = s->duplex ? DUPLEX_FULL : DUPLEX_HALF;
		}
	}

	ecmd.req.cmd = ETHTOOL_SLINKSETTINGS;
	ioctl(sock_ioctl, SIOCETHTOOL, &ifr);
}

static void
system_set_ethtool_settings_after_up(struct device *dev, struct device_settings *s)
{
	if (s->flags & DEV_OPT_GRO)
		system_set_ethtool_gro(dev, s);
}

void
system_if_get_settings(struct device *dev, struct device_settings *s)
{
	struct ifreq ifr;
	char buf[10];
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(sock_ioctl, SIOCGIFMTU, &ifr) == 0) {
		s->mtu = ifr.ifr_mtu;
		s->flags |= DEV_OPT_MTU;
	}

	s->mtu6 = system_update_ipv6_mtu(dev, 0);
	if (s->mtu6 > 0)
		s->flags |= DEV_OPT_MTU6;

	if (ioctl(sock_ioctl, SIOCGIFTXQLEN, &ifr) == 0) {
		s->txqueuelen = ifr.ifr_qlen;
		s->flags |= DEV_OPT_TXQUEUELEN;
	}

	if (ioctl(sock_ioctl, SIOCGIFHWADDR, &ifr) == 0) {
		memcpy(s->macaddr, &ifr.ifr_hwaddr.sa_data, sizeof(s->macaddr));
		s->flags |= DEV_OPT_MACADDR;
	}

	if (!system_get_disable_ipv6(dev, buf, sizeof(buf))) {
		s->ipv6 = !strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_IPV6;
	}

	if (!system_get_ip6segmentrouting(dev, buf, sizeof(buf))) {
		s->ip6segmentrouting = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_IP6SEGMENTROUTING;
	}

	if (ioctl(sock_ioctl, SIOCGIFFLAGS, &ifr) == 0) {
		s->promisc = ifr.ifr_flags & IFF_PROMISC;
		s->flags |= DEV_OPT_PROMISC;

		s->multicast = ifr.ifr_flags & IFF_MULTICAST;
		s->flags |= DEV_OPT_MULTICAST;
	}

	if (!system_get_rpfilter(dev, buf, sizeof(buf))) {
		s->rpfilter = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_RPFILTER;
	}

	if (!system_get_acceptlocal(dev, buf, sizeof(buf))) {
		s->acceptlocal = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_ACCEPTLOCAL;
	}

	if (!system_get_igmpversion(dev, buf, sizeof(buf))) {
		s->igmpversion = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_IGMPVERSION;
	}

	if (!system_get_mldversion(dev, buf, sizeof(buf))) {
		s->mldversion = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_MLDVERSION;
	}

	if (!system_get_neigh4reachabletime(dev, buf, sizeof(buf))) {
		s->neigh4reachabletime = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_NEIGHREACHABLETIME;
	}

	if (!system_get_neigh6reachabletime(dev, buf, sizeof(buf))) {
		s->neigh6reachabletime = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_NEIGHREACHABLETIME;
	}

	if (!system_get_neigh4locktime(dev, buf, sizeof(buf))) {
		s->neigh4locktime = strtol(buf, NULL, 0);
		s->flags |= DEV_OPT_NEIGHLOCKTIME;
	}

	if (!system_get_neigh4gcstaletime(dev, buf, sizeof(buf))) {
		s->neigh4gcstaletime = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_NEIGHGCSTALETIME;
	}

	if (!system_get_neigh6gcstaletime(dev, buf, sizeof(buf))) {
		s->neigh6gcstaletime = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_NEIGHGCSTALETIME;
	}

	if (!system_get_dadtransmits(dev, buf, sizeof(buf))) {
		s->dadtransmits = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_DADTRANSMITS;
	}

	if (!system_get_sendredirects(dev, buf, sizeof(buf))) {
		s->sendredirects = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_SENDREDIRECTS;
	}

	if (!system_get_drop_v4_unicast_in_l2_multicast(dev, buf, sizeof(buf))) {
		s->drop_v4_unicast_in_l2_multicast = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_DROP_V4_UNICAST_IN_L2_MULTICAST;
	}

	if (!system_get_drop_v6_unicast_in_l2_multicast(dev, buf, sizeof(buf))) {
		s->drop_v6_unicast_in_l2_multicast = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_DROP_V6_UNICAST_IN_L2_MULTICAST;
	}

	if (!system_get_drop_gratuitous_arp(dev, buf, sizeof(buf))) {
		s->drop_gratuitous_arp = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_DROP_GRATUITOUS_ARP;
	}

	if (!system_get_drop_unsolicited_na(dev, buf, sizeof(buf))) {
		s->drop_unsolicited_na = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_DROP_UNSOLICITED_NA;
	}

	if (!system_get_arp_accept(dev, buf, sizeof(buf))) {
		s->arp_accept = strtoul(buf, NULL, 0);
		s->flags |= DEV_OPT_ARP_ACCEPT;
	}

	ret = system_get_ethtool_gro(dev);
	if (ret >= 0) {
		s->gro = ret;
		s->flags |= DEV_OPT_GRO;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
	ret = system_if_get_master_ifindex(dev);
	if (ret >= 0) {
		s->master_ifindex = ret;
		s->flags |= DEV_OPT_MASTER;
	}
#endif
}

void
system_if_apply_settings(struct device *dev, struct device_settings *s, uint64_t apply_mask)
{
	struct ifreq ifr;
	char buf[12];

	apply_mask &= s->flags;

	if (apply_mask & DEV_OPT_MASTER) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
		system_set_master(dev, s->master_ifindex);
		if (!(apply_mask & (DEV_OPT_MACADDR | DEV_OPT_DEFAULT_MACADDR)) || dev->external)
			system_refresh_orig_macaddr(dev, &dev->orig_settings);
#else
		netifd_log_message(L_WARNING, "%s Your kernel is older than linux 6.1.0, changing DSA port conduit is not supported!", dev->ifname);
#endif
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);
	if (apply_mask & DEV_OPT_MTU) {
		ifr.ifr_mtu = s->mtu;
		if (ioctl(sock_ioctl, SIOCSIFMTU, &ifr) < 0)
			s->flags &= ~DEV_OPT_MTU;
	}
	if (apply_mask & DEV_OPT_MTU6) {
		system_update_ipv6_mtu(dev, s->mtu6);
	}
	if (apply_mask & DEV_OPT_TXQUEUELEN) {
		ifr.ifr_qlen = s->txqueuelen;
		if (ioctl(sock_ioctl, SIOCSIFTXQLEN, &ifr) < 0)
			s->flags &= ~DEV_OPT_TXQUEUELEN;
	}
	if ((apply_mask & (DEV_OPT_MACADDR | DEV_OPT_DEFAULT_MACADDR)) && !dev->external) {
		ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
		memcpy(&ifr.ifr_hwaddr.sa_data, s->macaddr, sizeof(s->macaddr));
		if (ioctl(sock_ioctl, SIOCSIFHWADDR, &ifr) < 0)
			s->flags &= ~DEV_OPT_MACADDR;
	}
	if (apply_mask & DEV_OPT_IPV6)
		system_set_disable_ipv6(dev, s->ipv6 ? "0" : "1");
	if (s->flags & DEV_OPT_IP6SEGMENTROUTING & apply_mask) {
		struct device dummy = {
			.ifname = "all",
		};
		bool ip6segmentrouting = device_check_ip6segmentrouting();

		system_set_ip6segmentrouting(dev, s->ip6segmentrouting ? "1" : "0");
		system_set_ip6segmentrouting(&dummy, ip6segmentrouting ? "1" : "0");
	}
	if (apply_mask & DEV_OPT_PROMISC) {
		if (system_if_flags(dev->ifname, s->promisc ? IFF_PROMISC : 0,
				    !s->promisc ? IFF_PROMISC : 0) < 0)
			s->flags &= ~DEV_OPT_PROMISC;
	}
	if (apply_mask & DEV_OPT_RPFILTER) {
		snprintf(buf, sizeof(buf), "%u", s->rpfilter);
		system_set_rpfilter(dev, buf);
	}
	if (apply_mask & DEV_OPT_ACCEPTLOCAL)
		system_set_acceptlocal(dev, s->acceptlocal ? "1" : "0");
	if (apply_mask & DEV_OPT_IGMPVERSION) {
		snprintf(buf, sizeof(buf), "%u", s->igmpversion);
		system_set_igmpversion(dev, buf);
	}
	if (apply_mask & DEV_OPT_MLDVERSION) {
		snprintf(buf, sizeof(buf), "%u", s->mldversion);
		system_set_mldversion(dev, buf);
	}
	if (apply_mask & DEV_OPT_NEIGHREACHABLETIME) {
		snprintf(buf, sizeof(buf), "%u", s->neigh4reachabletime);
		system_set_neigh4reachabletime(dev, buf);
		snprintf(buf, sizeof(buf), "%u", s->neigh6reachabletime);
		system_set_neigh6reachabletime(dev, buf);
	}
	if (apply_mask & DEV_OPT_NEIGHLOCKTIME) {
		snprintf(buf, sizeof(buf), "%d", s->neigh4locktime);
		system_set_neigh4locktime(dev, buf);
	}
	if (apply_mask & DEV_OPT_NEIGHGCSTALETIME) {
		snprintf(buf, sizeof(buf), "%u", s->neigh4gcstaletime);
		system_set_neigh4gcstaletime(dev, buf);
		snprintf(buf, sizeof(buf), "%u", s->neigh6gcstaletime);
		system_set_neigh6gcstaletime(dev, buf);
	}
	if (apply_mask & DEV_OPT_DADTRANSMITS) {
		snprintf(buf, sizeof(buf), "%u", s->dadtransmits);
		system_set_dadtransmits(dev, buf);
	}
	if (apply_mask & DEV_OPT_MULTICAST) {
		if (system_if_flags(dev->ifname, s->multicast ? IFF_MULTICAST : 0,
				    !s->multicast ? IFF_MULTICAST : 0) < 0)
			s->flags &= ~DEV_OPT_MULTICAST;
	}
	if (apply_mask & DEV_OPT_SENDREDIRECTS)
		system_set_sendredirects(dev, s->sendredirects ? "1" : "0");
	if (apply_mask & DEV_OPT_DROP_V4_UNICAST_IN_L2_MULTICAST)
		system_set_drop_v4_unicast_in_l2_multicast(dev, s->drop_v4_unicast_in_l2_multicast ? "1" : "0");
	if (apply_mask & DEV_OPT_DROP_V6_UNICAST_IN_L2_MULTICAST)
		system_set_drop_v6_unicast_in_l2_multicast(dev, s->drop_v6_unicast_in_l2_multicast ? "1" : "0");
	if (apply_mask & DEV_OPT_DROP_GRATUITOUS_ARP)
		system_set_drop_gratuitous_arp(dev, s->drop_gratuitous_arp ? "1" : "0");
	if (apply_mask & DEV_OPT_DROP_UNSOLICITED_NA)
		system_set_drop_unsolicited_na(dev, s->drop_unsolicited_na ? "1" : "0");
	if (apply_mask & DEV_OPT_ARP_ACCEPT)
		system_set_arp_accept(dev, s->arp_accept ? "1" : "0");
	system_set_ethtool_settings(dev, s);
}

void system_if_apply_settings_after_up(struct device *dev, struct device_settings *s)
{
	system_set_ethtool_settings_after_up(dev, s);
}

int system_if_up(struct device *dev)
{
	return system_if_flags(dev->ifname, IFF_UP, 0);
}

int system_if_down(struct device *dev)
{
	return system_if_flags(dev->ifname, 0, IFF_UP);
}

struct if_check_data {
	struct device *dev;
	int pending;
	int ret;
};

static int cb_if_check_valid(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nh = nlmsg_hdr(msg);
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct if_check_data *chk = (struct if_check_data *)arg;

	if (nh->nlmsg_type != RTM_NEWLINK)
		return NL_SKIP;

	system_device_update_state(chk->dev, ifi->ifi_flags, ifi->ifi_index);
	return NL_OK;
}

static int cb_if_check_ack(struct nl_msg *msg, void *arg)
{
	struct if_check_data *chk = (struct if_check_data *)arg;
	chk->pending = 0;
	return NL_STOP;
}

static int cb_if_check_error(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	struct if_check_data *chk = (struct if_check_data *)arg;

	if (chk->dev->type == &simple_device_type)
		device_set_present(chk->dev, false);
	device_set_link(chk->dev, false);
	chk->pending = err->error;

	return NL_STOP;
}

struct bridge_vlan_check_data {
	struct device *check_dev;
	int ifindex;
	int ret;
	bool pending;
};

static void bridge_vlan_check_port(struct bridge_vlan_check_data *data,
				   struct bridge_vlan_port *port,
				   struct bridge_vlan_info *vinfo)
{
	uint16_t flags = 0, diff, mask;

	if (port->flags & BRVLAN_F_PVID)
		flags |= BRIDGE_VLAN_INFO_PVID;
	if (port->flags & BRVLAN_F_UNTAGGED)
		flags |= BRIDGE_VLAN_INFO_UNTAGGED;

	diff = vinfo->flags ^ flags;
	mask = BRVLAN_F_UNTAGGED | (flags & BRIDGE_VLAN_INFO_PVID);
	if (diff & mask) {
		data->ret = 1;
		data->pending = false;
	}

	port->check = 1;
}

static void bridge_vlan_check_attr(struct bridge_vlan_check_data *data,
				   struct rtattr *attr)
{
	struct bridge_vlan_hotplug_port *port;
	struct bridge_vlan_info *vinfo;
	struct bridge_vlan *vlan;
	struct rtattr *cur;
	int rem = RTA_PAYLOAD(attr);
	int i;

	for (cur = RTA_DATA(attr); RTA_OK(cur, rem); cur = RTA_NEXT(cur, rem)) {
		if (cur->rta_type != IFLA_BRIDGE_VLAN_INFO)
			continue;

		vinfo = RTA_DATA(cur);
		vlan = vlist_find(&data->check_dev->vlans, &vinfo->vid, vlan, node);
		if (!vlan) {
			data->ret = 1;
			data->pending = false;
			return;
		}

		for (i = 0; i < vlan->n_ports; i++)
			if (!vlan->ports[i].check)
				bridge_vlan_check_port(data, &vlan->ports[i], vinfo);

		list_for_each_entry(port, &vlan->hotplug_ports, list)
			if (!port->port.check)
				bridge_vlan_check_port(data, &port->port, vinfo);
	}
}

static int bridge_vlan_check_cb(struct nl_msg *msg, void *arg)
{
	struct bridge_vlan_check_data *data = arg;
	struct nlmsghdr *nh = nlmsg_hdr(msg);
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct rtattr *attr;
	int rem;

	if (nh->nlmsg_type != RTM_NEWLINK)
		return NL_SKIP;

	if (ifi->ifi_family != AF_BRIDGE)
		return NL_SKIP;

	if (ifi->ifi_index != data->ifindex)
		return NL_SKIP;

	attr = IFLA_RTA(ifi);
	rem = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	while (RTA_OK(attr, rem)) {
		if (attr->rta_type == IFLA_AF_SPEC)
			bridge_vlan_check_attr(data, attr);

		attr = RTA_NEXT(attr, rem);
	}

	return NL_SKIP;
}

static int bridge_vlan_ack_cb(struct nl_msg *msg, void *arg)
{
	struct bridge_vlan_check_data *data = arg;
	data->pending = false;
	return NL_STOP;
}

static int bridge_vlan_error_cb(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	struct bridge_vlan_check_data *data = arg;
	data->pending = false;
	return NL_STOP;
}

int system_bridge_vlan_check(struct device *dev, char *ifname)
{
	struct bridge_vlan_check_data data = {
		.check_dev = dev,
		.ifindex = if_nametoindex(ifname),
		.ret = -1,
		.pending = true,
	};
	static struct ifinfomsg ifi = {
		.ifi_family = AF_BRIDGE
	};
	static struct rtattr ext_req = {
		.rta_type = IFLA_EXT_MASK,
		.rta_len = RTA_LENGTH(sizeof(uint32_t)),
	};
	uint32_t filter = RTEXT_FILTER_BRVLAN;
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct bridge_vlan *vlan;
	struct nl_msg *msg;
	int i;

	if (!data.ifindex)
		return 0;

	msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_DUMP);

	if (nlmsg_append(msg, &ifi, sizeof(ifi), 0) ||
		nlmsg_append(msg, &ext_req, sizeof(ext_req), NLMSG_ALIGNTO) ||
		nlmsg_append(msg, &filter, sizeof(filter), 0))
		goto free;

	vlist_for_each_element(&dev->vlans, vlan, node) {
		struct bridge_vlan_hotplug_port *port;

		for (i = 0; i < vlan->n_ports; i++) {
			if (!strcmp(vlan->ports[i].ifname, ifname))
				vlan->ports[i].check = 0;
			else
				vlan->ports[i].check = -1;
		}

		list_for_each_entry(port, &vlan->hotplug_ports, list) {
			if (!strcmp(port->port.ifname, ifname))
				port->port.check = 0;
			else
				port->port.check = -1;
		}
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, bridge_vlan_check_cb, &data);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, bridge_vlan_ack_cb, &data);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, bridge_vlan_ack_cb, &data);
	nl_cb_err(cb, NL_CB_CUSTOM, bridge_vlan_error_cb, &data);

	if (nl_send_auto_complete(sock_rtnl, msg) < 0)
		goto free;

	data.ret = 0;
	while (data.pending)
		nl_recvmsgs(sock_rtnl, cb);

	vlist_for_each_element(&dev->vlans, vlan, node) {
		struct bridge_vlan_hotplug_port *port;

		for (i = 0; i < vlan->n_ports; i++) {
			if (!vlan->ports[i].check) {
				data.ret = 1;
				break;
			}
		}

		list_for_each_entry(port, &vlan->hotplug_ports, list) {
			if (!port->port.check) {
				data.ret = 1;
				break;
			}
		}
	}

free:
	nlmsg_free(msg);
	nl_cb_put(cb);
	return data.ret;
}

int system_if_check(struct device *dev)
{
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	struct nl_msg *msg;
	struct ifinfomsg ifi = {
		.ifi_family = AF_UNSPEC,
		.ifi_index = 0,
	};
	struct if_check_data chk = {
		.dev = dev,
		.pending = 1,
	};
	int ret = 1;

	if (!cb)
		return ret;

	msg = nlmsg_alloc_simple(RTM_GETLINK, 0);
	if (!msg)
		goto out;

	if (nlmsg_append(msg, &ifi, sizeof(ifi), 0) ||
	    nla_put_string(msg, IFLA_IFNAME, dev->ifname))
		goto free;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cb_if_check_valid, &chk);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, cb_if_check_ack, &chk);
	nl_cb_err(cb, NL_CB_CUSTOM, cb_if_check_error, &chk);

	ret = nl_send_auto_complete(sock_rtnl, msg);
	if (ret < 0)
		goto free;

	while (chk.pending > 0)
		nl_recvmsgs(sock_rtnl, cb);

	ret = chk.pending;

free:
	nlmsg_free(msg);
out:
	nl_cb_put(cb);
	return ret;
}

struct device *
system_if_get_parent(struct device *dev)
{
	char buf[64], *devname;
	int ifindex, iflink;

	if (system_get_dev_sysfs("iflink", dev->ifname, buf, sizeof(buf)) < 0)
		return NULL;

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

bool
system_if_force_external(const char *ifname)
{
	struct stat s;

	return stat(dev_sysfs_path(ifname, "phy80211"), &s) == 0;
}

static const char *
system_netdevtype_name(unsigned short dev_type)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(netdev_types); i++) {
		if (netdev_types[i].id == dev_type)
			return netdev_types[i].name;
	}

	/* the last key is used by default */
	i = ARRAY_SIZE(netdev_types) - 1;

	return netdev_types[i].name;
}

static void
system_add_devtype(struct blob_buf *b, const char *ifname)
{
	char buf[100];
	bool found = false;

	if (!system_get_dev_sysfs("uevent", ifname, buf, sizeof(buf))) {
		const char *info = "DEVTYPE=";
		char *context = NULL;
		const char *line = strtok_r(buf, "\r\n", &context);

		while (line != NULL) {
			char *index = strstr(line, info);

			if (index != NULL) {
				blobmsg_add_string(b, "devtype", index + strlen(info));
				found = true;
				break;
			}

			line = strtok_r(NULL, "\r\n", &context);
		}
	}

	if (!found) {
		unsigned short number = 0;
		const char *name = NULL;

		if (!system_get_dev_sysfs("type", ifname, buf, sizeof(buf))) {
			number = strtoul(buf, NULL, 0);
			name = system_netdevtype_name(number);
			blobmsg_add_string(b, "devtype", name);
		}
	}
}

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

static int32_t
ethtool_feature_count(const char *ifname)
{
	struct {
		struct ethtool_sset_info hdr;
		uint32_t buf;
	} req = {
		.hdr = {
			.cmd = ETHTOOL_GSSET_INFO,
			.sset_mask = 1 << ETH_SS_FEATURES
		}
	};

	struct ifreq ifr = {
		.ifr_data = (void *)&req
	};

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) != 0)
		return -1;

	if (!req.hdr.sset_mask)
		return 0;

	return req.buf;
}

static int32_t
ethtool_feature_index(const char *ifname, const char *keyname)
{
	struct ethtool_gstrings *feature_names;
	struct ifreq ifr = { 0 };
	int32_t n_features;
	uint32_t i;

	n_features = ethtool_feature_count(ifname);

	if (n_features <= 0)
		return -1;

	feature_names = calloc(1, sizeof(*feature_names) + n_features * ETH_GSTRING_LEN);

	if (!feature_names)
		return -1;

	feature_names->cmd = ETHTOOL_GSTRINGS;
	feature_names->string_set = ETH_SS_FEATURES;
	feature_names->len = n_features;

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = (void *)feature_names;

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) != 0) {
		free(feature_names);

		return -1;
	}

	for (i = 0; i < feature_names->len; i++)
		if (!strcmp((char *)&feature_names->data[i * ETH_GSTRING_LEN], keyname))
			break;

	if (i >= feature_names->len)
		i = -1;

	free(feature_names);

	return i;
}

static bool
ethtool_feature_value(const char *ifname, const char *keyname)
{
	struct ethtool_get_features_block *feature_block;
	struct ethtool_gfeatures *feature_values;
	struct ifreq ifr = { 0 };
	int32_t feature_idx;
	bool active;

	feature_idx = ethtool_feature_index(ifname, keyname);

	if (feature_idx < 0)
		return false;

	feature_values = calloc(1,
		sizeof(*feature_values) +
		sizeof(feature_values->features[0]) * DIV_ROUND_UP(feature_idx, 32));

	if (!feature_values)
		return false;

	feature_values->cmd = ETHTOOL_GFEATURES;
	feature_values->size = DIV_ROUND_UP(feature_idx, 32);

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = (void *)feature_values;

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) != 0) {
		free(feature_values);

		return false;
	}

	feature_block = &feature_values->features[feature_idx / 32];
	active = feature_block->active & (1U << feature_idx % 32);

	free(feature_values);

	return active;
}

static void
system_add_link_mode_name(struct blob_buf *b, int i, bool half)
{
	char *buf;

	/* allocate string buffer large enough for the mode name and a suffix
	 * "-F" or "-H" indicating full duplex or half duplex.
	 */
	buf = blobmsg_alloc_string_buffer(b, NULL, strlen(ethtool_modes[i].name) + 3);
	if (!buf)
		return;

	strcpy(buf, ethtool_modes[i].name);
	if (half)
		strcat(buf, "-H");
	else
		strcat(buf, "-F");

	blobmsg_add_string_buffer(b);
}

static void
system_add_link_modes(__s8 nwords, struct blob_buf *b, __u32 *mask)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ethtool_modes); i++) {
		if (ethtool_link_mode_test_bit(nwords, ethtool_modes[i].bit_half, mask))
			system_add_link_mode_name(b, i, true);

		if (ethtool_link_mode_test_bit(nwords, ethtool_modes[i].bit_full, mask))
			system_add_link_mode_name(b, i, false);
	}
}

static void
system_add_pause_modes(__s8 nwords, struct blob_buf *b, __u32 *mask)
{
	if (ethtool_link_mode_test_bit(nwords, ETHTOOL_LINK_MODE_Pause_BIT, mask))
		blobmsg_add_string(b, NULL, "pause");

	if (ethtool_link_mode_test_bit(nwords, ETHTOOL_LINK_MODE_Asym_Pause_BIT, mask))
		blobmsg_add_string(b, NULL, "asym_pause");
}


static void
system_add_ethtool_pause_an(struct blob_buf *b, __s8 nwords,
			    __u32 *advertising, __u32 *lp_advertising)
{
	bool an_rx = false, an_tx = false;
	void *d;

	d = blobmsg_open_array(b, "negotiated");

	/* Work out negotiated pause frame usage per
	 * IEEE 802.3-2005 table 28B-3.
	 */
	if (ethtool_link_mode_test_bit(nwords,
				       ETHTOOL_LINK_MODE_Pause_BIT,
				       advertising) &&
	    ethtool_link_mode_test_bit(nwords,
				       ETHTOOL_LINK_MODE_Pause_BIT,
				       lp_advertising)) {
		an_tx = true;
		an_rx = true;
	} else if (ethtool_link_mode_test_bit(nwords,
					      ETHTOOL_LINK_MODE_Asym_Pause_BIT,
					      advertising) &&
		   ethtool_link_mode_test_bit(nwords,
					      ETHTOOL_LINK_MODE_Asym_Pause_BIT,
					      lp_advertising)) {
		if (ethtool_link_mode_test_bit(nwords,
					       ETHTOOL_LINK_MODE_Pause_BIT,
					       advertising))
			an_rx = true;
		else if (ethtool_link_mode_test_bit(nwords,
						    ETHTOOL_LINK_MODE_Pause_BIT,
						    lp_advertising))
			an_tx = true;
	}
	if (an_tx)
		blobmsg_add_string(b, NULL, "rx");

	if (an_rx)
		blobmsg_add_string(b, NULL, "tx");

	blobmsg_close_array(b, d);
}

static void
system_get_ethtool_pause(struct device *dev, bool *rx_pause, bool *tx_pause, bool *pause_autoneg)
{
	struct ethtool_pauseparam pp;
	struct ifreq ifr = {
		.ifr_data = (caddr_t)&pp,
	};

	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);
	memset(&pp, 0, sizeof(pp));
	pp.cmd = ETHTOOL_GPAUSEPARAM;

	/* may fail */
	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) == -1) {
		*pause_autoneg = true;
		return;
	}

	*rx_pause = pp.rx_pause;
	*tx_pause = pp.tx_pause;
	*pause_autoneg = pp.autoneg;
}

int
system_if_dump_info(struct device *dev, struct blob_buf *b)
{
	__u32 *supported, *advertising, *lp_advertising;
	bool rx_pause, tx_pause, pause_autoneg;
	struct {
		struct ethtool_link_settings req;
		__u32 link_mode_data[3 * 127];
	} ecmd;
	struct ifreq ifr = {
		.ifr_data = (caddr_t)&ecmd,
	};
	__s8 nwords;
	void *c, *d;
	char *s;

	system_get_ethtool_pause(dev, &rx_pause, &tx_pause, &pause_autoneg);

	memset(&ecmd, 0, sizeof(ecmd));
	ecmd.req.cmd = ETHTOOL_GLINKSETTINGS;
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) < 0 ||
	    ecmd.req.link_mode_masks_nwords >= 0 ||
	    ecmd.req.cmd != ETHTOOL_GLINKSETTINGS)
		return -EOPNOTSUPP;

	ecmd.req.link_mode_masks_nwords = -ecmd.req.link_mode_masks_nwords;

	if (ioctl(sock_ioctl, SIOCETHTOOL, &ifr) < 0 ||
	    ecmd.req.link_mode_masks_nwords <= 0 ||
	    ecmd.req.cmd != ETHTOOL_GLINKSETTINGS)
		return -EIO;

	nwords = ecmd.req.link_mode_masks_nwords;
	supported = &ecmd.link_mode_data[0];
	advertising = &ecmd.link_mode_data[nwords];
	lp_advertising = &ecmd.link_mode_data[2 * nwords];

	c = blobmsg_open_array(b, "link-advertising");
	system_add_link_modes(nwords, b, advertising);
	blobmsg_close_array(b, c);

	c = blobmsg_open_array(b, "link-partner-advertising");
	system_add_link_modes(nwords, b, lp_advertising);
	blobmsg_close_array(b, c);

	c = blobmsg_open_array(b, "link-supported");
	system_add_link_modes(nwords, b, supported);
	blobmsg_close_array(b, c);

	if (ethtool_validate_speed(ecmd.req.speed) &&
	    (ecmd.req.speed != (__u32)SPEED_UNKNOWN) &&
	    (ecmd.req.speed != 0)) {
		s = blobmsg_alloc_string_buffer(b, "speed", 10);
		snprintf(s, 8, "%d%c", ecmd.req.speed,
			ecmd.req.duplex == DUPLEX_HALF ? 'H' : 'F');
		blobmsg_add_string_buffer(b);
	}
	blobmsg_add_u8(b, "autoneg", !!ecmd.req.autoneg);

	c = blobmsg_open_table(b, "flow-control");
	blobmsg_add_u8(b, "autoneg", pause_autoneg);

	d = blobmsg_open_array(b, "supported");
	system_add_pause_modes(nwords, b, supported);
	blobmsg_close_array(b, d);

	if (pause_autoneg) {
		d = blobmsg_open_array(b, "link-advertising");
		system_add_pause_modes(nwords, b, advertising);
		blobmsg_close_array(b, d);
	}

	d = blobmsg_open_array(b, "link-partner-advertising");
	system_add_pause_modes(nwords, b, lp_advertising);
	blobmsg_close_array(b, d);

	if (pause_autoneg) {
		system_add_ethtool_pause_an(b, nwords, advertising,
					    lp_advertising);
	} else {
		d = blobmsg_open_array(b, "selected");
		if (rx_pause)
			blobmsg_add_string(b, NULL, "rx");

		if (tx_pause)
			blobmsg_add_string(b, NULL, "tx");

		blobmsg_close_array(b, d);
	}

	blobmsg_close_table(b, c);

	blobmsg_add_u8(b, "hw-tc-offload",
		ethtool_feature_value(dev->ifname, "hw-tc-offload"));

	system_add_devtype(b, dev->ifname);

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
	int stats_dir;
	size_t i;
	uint64_t val = 0;

	stats_dir = open(dev_sysfs_path(dev->ifname, "statistics"), O_DIRECTORY);
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
			if (valid <= 0) {
				nlmsg_free(msg);
				return -1;
			}
			else if (valid > UINT32_MAX)
				valid = UINT32_MAX;

			cinfo.ifa_valid = valid;
		}

		nla_put(msg, IFA_CACHEINFO, sizeof(cinfo), &cinfo);

		if (cmd == RTM_NEWADDR && (addr->flags & DEVADDR_OFFLINK))
			nla_put_u32(msg, IFA_FLAGS, IFA_F_NOPREFIXROUTE);
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

static int system_neigh(struct device *dev, struct device_neighbor *neighbor, int cmd)
{
	int alen = ((neighbor->flags & DEVADDR_FAMILY) == DEVADDR_INET4) ? 4 : 16;
	unsigned int flags = 0;
	struct ndmsg ndm = {
		.ndm_family = (alen == 4) ? AF_INET : AF_INET6,
		.ndm_ifindex = dev->ifindex,
		.ndm_state = NUD_PERMANENT,
		.ndm_flags = (neighbor->proxy ? NTF_PROXY : 0) | (neighbor->router ? NTF_ROUTER : 0),
	};
	struct nl_msg *msg;

	if (cmd == RTM_NEWNEIGH)
		flags |= NLM_F_CREATE | NLM_F_REPLACE;

	msg = nlmsg_alloc_simple(cmd, flags);

	if (!msg)
		return -1;

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);

	nla_put(msg, NDA_DST, alen, &neighbor->addr);
	if (neighbor->flags & DEVNEIGH_MAC)
		nla_put(msg, NDA_LLADDR, sizeof(neighbor->macaddr), &neighbor->macaddr);


	return system_rtnl_call(msg);
}

int system_add_neighbor(struct device *dev, struct device_neighbor *neighbor)
{
	return system_neigh(dev, neighbor, RTM_NEWNEIGH);
}

int system_del_neighbor(struct device *dev, struct device_neighbor *neighbor)
{
	return system_neigh(dev, neighbor, RTM_DELNEIGH);
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

	unsigned int table = (route->flags & (DEVROUTE_TABLE | DEVROUTE_SRCTABLE))
			? route->table : RT_TABLE_MAIN;

	struct rtmsg rtm = {
		.rtm_family = (alen == 4) ? AF_INET : AF_INET6,
		.rtm_dst_len = route->mask,
		.rtm_src_len = route->sourcemask,
		.rtm_table = (table < 256) ? table : RT_TABLE_UNSPEC,
		.rtm_protocol = (route->flags & DEVROUTE_PROTO) ? route->proto : RTPROT_STATIC,
		.rtm_scope = RT_SCOPE_NOWHERE,
		.rtm_type = (cmd == RTM_DELROUTE) ? 0: RTN_UNICAST,
		.rtm_flags = (route->flags & DEVROUTE_ONLINK) ? RTNH_F_ONLINK : 0,
	};
	struct nl_msg *msg;

	if (cmd == RTM_NEWROUTE) {
		flags |= NLM_F_CREATE | NLM_F_REPLACE;

		if (!dev) { /* Add null-route */
			rtm.rtm_scope = RT_SCOPE_UNIVERSE;
			rtm.rtm_type = RTN_UNREACHABLE;
		}
		else
			rtm.rtm_scope = (have_gw) ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
	}

	if (route->flags & DEVROUTE_TYPE) {
		rtm.rtm_type = route->type;
		if (!(route->flags & (DEVROUTE_TABLE | DEVROUTE_SRCTABLE))) {
			if (rtm.rtm_type == RTN_LOCAL || rtm.rtm_type == RTN_BROADCAST ||
			    rtm.rtm_type == RTN_NAT || rtm.rtm_type == RTN_ANYCAST)
				rtm.rtm_table = RT_TABLE_LOCAL;
		}

		if (rtm.rtm_type == RTN_LOCAL || rtm.rtm_type == RTN_NAT) {
			rtm.rtm_scope = RT_SCOPE_HOST;
		} else if (rtm.rtm_type == RTN_BROADCAST || rtm.rtm_type == RTN_MULTICAST ||
				rtm.rtm_type == RTN_ANYCAST) {
			rtm.rtm_scope = RT_SCOPE_LINK;
		} else if (rtm.rtm_type == RTN_BLACKHOLE || rtm.rtm_type == RTN_UNREACHABLE ||
				rtm.rtm_type == RTN_PROHIBIT || rtm.rtm_type == RTN_FAILED_POLICY ||
				rtm.rtm_type == RTN_THROW) {
			rtm.rtm_scope = RT_SCOPE_UNIVERSE;
			dev = NULL;
		}
	}

	if (route->flags & DEVROUTE_NODEV)
		dev = NULL;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (!msg)
		return -1;

	nlmsg_append(msg, &rtm, sizeof(rtm), 0);

	if (route->mask)
		nla_put(msg, RTA_DST, alen, &route->addr);

	if (route->sourcemask) {
		if (rtm.rtm_family == AF_INET)
			nla_put(msg, RTA_PREFSRC, alen, &route->source);
		else
			nla_put(msg, RTA_SRC, alen, &route->source);
	}

	if (route->metric > 0)
		nla_put_u32(msg, RTA_PRIORITY, route->metric);

	if (have_gw)
		nla_put(msg, RTA_GATEWAY, alen, &route->nexthop);

	if (dev)
		nla_put_u32(msg, RTA_OIF, dev->ifindex);

	if (table >= 256)
		nla_put_u32(msg, RTA_TABLE, table);

	if (route->flags & DEVROUTE_MTU) {
		struct nlattr *metrics;

		if (!(metrics = nla_nest_start(msg, RTA_METRICS)))
			goto nla_put_failure;

		nla_put_u32(msg, RTAX_MTU, route->mtu);

		nla_nest_end(msg, metrics);
	}

	return system_rtnl_call(msg);

nla_put_failure:
	nlmsg_free(msg);
	return -ENOMEM;
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
	const char *names[] = { "ipv4", "ipv6" };
	size_t i;
	int fd;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		snprintf(dev_buf, sizeof(dev_buf), "%s/sys/net/%s/route/flush", proc_path, names[i]);
		fd = open(dev_buf, O_WRONLY);
		if (fd < 0)
			continue;

		if (write(fd, "-1", 2)) {}
		close(fd);
	}
	return 0;
}

bool system_resolve_rt_type(const char *type, unsigned int *id)
{
	return system_rtn_aton(type, id);
}

bool system_resolve_rt_proto(const char *type, unsigned int *id)
{
	FILE *f;
	char *e, buf[128];
	unsigned int n, proto = 256;
	n = strtoul(type, &e, 0);
	if (!*e && e != type)
		proto = n;
	else if (!strcmp(type, "unspec"))
		proto = RTPROT_UNSPEC;
	else if (!strcmp(type, "kernel"))
		proto = RTPROT_KERNEL;
	else if (!strcmp(type, "boot"))
		proto = RTPROT_BOOT;
	else if (!strcmp(type, "static"))
		proto = RTPROT_STATIC;
	else if ((f = fopen("/etc/iproute2/rt_protos", "r")) != NULL) {
		while (fgets(buf, sizeof(buf) - 1, f) != NULL) {
			if ((e = strtok(buf, " \t\n")) == NULL || *e == '#')
				continue;

			n = strtoul(e, NULL, 10);
			e = strtok(NULL, " \t\n");

			if (e && !strcmp(e, type)) {
				proto = n;
				break;
			}
		}
		fclose(f);
	}

	if (proto > 255)
		return false;

	*id = proto;
	return true;
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

	*id = table;
	return true;
}

bool system_is_default_rt_table(unsigned int id)
{
	return (id == RT_TABLE_MAIN);
}

bool system_resolve_rpfilter(const char *filter, unsigned int *id)
{
	char *e;
	unsigned int n;

	if (!strcmp(filter, "strict"))
		n = 1;
	else if (!strcmp(filter, "loose"))
		n = 2;
	else {
		n = strtoul(filter, &e, 0);
		if (*e || e == filter || n > 2)
			return false;
	}

	*id = n;
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

	if (cmd == RTM_NEWRULE)
		rtm.rtm_type = RTN_UNICAST;

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

	if (rule->flags & IPRULE_SUP_PREFIXLEN)
		nla_put_u32(msg, FRA_SUPPRESS_PREFIXLEN, rule->sup_prefixlen);

	if (rule->flags & IPRULE_UIDRANGE) {
		struct fib_rule_uid_range uidrange = {
			.start = rule->uidrange_start,
			.end = rule->uidrange_end
		};

		nla_put(msg, FRA_UID_RANGE, sizeof(uidrange), &uidrange);
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
	return system_rtn_aton(action, id);
}

time_t system_get_rtime(void)
{
	struct timespec ts;
	struct timeval tv;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
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
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_ifru.ifru_data = p;
	return ioctl(sock_ioctl, cmd, &ifr);
}

#ifdef IFLA_IPTUN_MAX
static int system_add_ip6_tunnel(const char *name, const unsigned int link,
				 struct blob_attr **tb)
{
	struct nl_msg *nlm = nlmsg_alloc_simple(RTM_NEWLINK,
				NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE);
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC };
	struct blob_attr *cur;
	int ret = 0, ttl = 0;

	if (!nlm)
		return -1;

	nlmsg_append(nlm, &ifi, sizeof(ifi), 0);
	nla_put_string(nlm, IFLA_IFNAME, name);

	if (link)
		nla_put_u32(nlm, IFLA_LINK, link);

	struct nlattr *linkinfo = nla_nest_start(nlm, IFLA_LINKINFO);
	if (!linkinfo) {
		ret = -ENOMEM;
		goto failure;
	}

	nla_put_string(nlm, IFLA_INFO_KIND, "ip6tnl");
	struct nlattr *infodata = nla_nest_start(nlm, IFLA_INFO_DATA);
	if (!infodata) {
		ret = -ENOMEM;
		goto failure;
	}

	if (link)
		nla_put_u32(nlm, IFLA_IPTUN_LINK, link);

	if ((cur = tb[TUNNEL_ATTR_TTL]))
		ttl = blobmsg_get_u32(cur);

	nla_put_u8(nlm, IFLA_IPTUN_PROTO, IPPROTO_IPIP);
	nla_put_u8(nlm, IFLA_IPTUN_TTL, (ttl) ? ttl : 64);

	struct in6_addr in6buf;
	if ((cur = tb[TUNNEL_ATTR_LOCAL])) {
		if (inet_pton(AF_INET6, blobmsg_data(cur), &in6buf) < 1) {
			ret = -EINVAL;
			goto failure;
		}
		nla_put(nlm, IFLA_IPTUN_LOCAL, sizeof(in6buf), &in6buf);
	}

	if ((cur = tb[TUNNEL_ATTR_REMOTE])) {
		if (inet_pton(AF_INET6, blobmsg_data(cur), &in6buf) < 1) {
			ret = -EINVAL;
			goto failure;
		}
		nla_put(nlm, IFLA_IPTUN_REMOTE, sizeof(in6buf), &in6buf);
	}

	if ((cur = tb[TUNNEL_ATTR_DATA])) {
		struct blob_attr *tb_data[__IPIP6_DATA_ATTR_MAX];
		uint32_t tun_flags = IP6_TNL_F_IGN_ENCAP_LIMIT;

		blobmsg_parse(ipip6_data_attr_list.params, __IPIP6_DATA_ATTR_MAX, tb_data,
			blobmsg_data(cur), blobmsg_len(cur));

		if ((cur = tb_data[IPIP6_DATA_ENCAPLIMIT])) {
			char *str = blobmsg_get_string(cur);

			if (strcmp(str, "ignore")) {
				char *e;
				unsigned encap_limit = strtoul(str, &e, 0);

				if (e == str || *e || encap_limit > 255) {
					ret = -EINVAL;
					goto failure;
				}

				nla_put_u8(nlm, IFLA_IPTUN_ENCAP_LIMIT, encap_limit);
				tun_flags &= ~IP6_TNL_F_IGN_ENCAP_LIMIT;
			}
		}

#ifdef IFLA_IPTUN_FMR_MAX
		if ((cur = tb_data[IPIP6_DATA_FMRS])) {
			struct blob_attr *rcur;
			unsigned rrem, fmrcnt = 0;
			struct nlattr *fmrs = nla_nest_start(nlm, IFLA_IPTUN_FMRS);

			if (!fmrs) {
				ret = -ENOMEM;
				goto failure;
			}

			blobmsg_for_each_attr(rcur, cur, rrem) {
				struct blob_attr *tb_fmr[__FMR_DATA_ATTR_MAX], *tb_cur;
				struct in6_addr ip6prefix;
				struct in_addr ip4prefix;
				unsigned ip4len, ip6len, ealen, offset;

				blobmsg_parse(fmr_data_attr_list.params, __FMR_DATA_ATTR_MAX, tb_fmr,
						blobmsg_data(rcur), blobmsg_len(rcur));

				if (!(tb_cur = tb_fmr[FMR_DATA_PREFIX6]) ||
						!parse_ip_and_netmask(AF_INET6,
							blobmsg_data(tb_cur), &ip6prefix,
							&ip6len)) {
					ret = -EINVAL;
					goto failure;
				}

				if (!(tb_cur = tb_fmr[FMR_DATA_PREFIX4]) ||
						!parse_ip_and_netmask(AF_INET,
							blobmsg_data(tb_cur), &ip4prefix,
							&ip4len)) {
					ret = -EINVAL;
					goto failure;
				}

				if (!(tb_cur = tb_fmr[FMR_DATA_EALEN])) {
					ret = -EINVAL;
					goto failure;
				}
				ealen = blobmsg_get_u32(tb_cur);

				if (!(tb_cur = tb_fmr[FMR_DATA_OFFSET])) {
					ret = -EINVAL;
					goto failure;
				}
				offset = blobmsg_get_u32(tb_cur);

				struct nlattr *rule = nla_nest_start(nlm, ++fmrcnt);
				if (!rule) {
					ret = -ENOMEM;
					goto failure;
				}

				nla_put(nlm, IFLA_IPTUN_FMR_IP6_PREFIX, sizeof(ip6prefix), &ip6prefix);
				nla_put(nlm, IFLA_IPTUN_FMR_IP4_PREFIX, sizeof(ip4prefix), &ip4prefix);
				nla_put_u8(nlm, IFLA_IPTUN_FMR_IP6_PREFIX_LEN, ip6len);
				nla_put_u8(nlm, IFLA_IPTUN_FMR_IP4_PREFIX_LEN, ip4len);
				nla_put_u8(nlm, IFLA_IPTUN_FMR_EA_LEN, ealen);
				nla_put_u8(nlm, IFLA_IPTUN_FMR_OFFSET, offset);

				nla_nest_end(nlm, rule);
			}

			nla_nest_end(nlm, fmrs);
		}
#endif
		if (tun_flags)
			nla_put_u32(nlm, IFLA_IPTUN_FLAGS, tun_flags);
	}

	nla_nest_end(nlm, infodata);
	nla_nest_end(nlm, linkinfo);

	return system_rtnl_call(nlm);

failure:
	nlmsg_free(nlm);
	return ret;
}
#endif

#ifdef IFLA_IPTUN_MAX
#define IP6_FLOWINFO_TCLASS	htonl(0x0FF00000)
static int system_add_gre_tunnel(const char *name, const char *kind,
				 const unsigned int link, struct blob_attr **tb, bool v6)
{
	struct nl_msg *nlm;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC, };
	struct blob_attr *cur;
	uint32_t ikey = 0, okey = 0, flowinfo = 0, flags6 = IP6_TNL_F_IGN_ENCAP_LIMIT;
	uint16_t iflags = 0, oflags = 0;
	uint8_t tos = 0;
	int ret = 0, ttl = 0;
	unsigned encap_limit = 0;

	nlm = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE);
	if (!nlm)
		return -1;

	nlmsg_append(nlm, &ifi, sizeof(ifi), 0);
	nla_put_string(nlm, IFLA_IFNAME, name);

	struct nlattr *linkinfo = nla_nest_start(nlm, IFLA_LINKINFO);
	if (!linkinfo) {
		ret = -ENOMEM;
		goto failure;
	}

	nla_put_string(nlm, IFLA_INFO_KIND, kind);
	struct nlattr *infodata = nla_nest_start(nlm, IFLA_INFO_DATA);
	if (!infodata) {
		ret = -ENOMEM;
		goto failure;
	}

	if (link)
		nla_put_u32(nlm, IFLA_GRE_LINK, link);

	if ((cur = tb[TUNNEL_ATTR_TTL]))
		ttl = blobmsg_get_u32(cur);

	if ((cur = tb[TUNNEL_ATTR_TOS])) {
		char *str = blobmsg_get_string(cur);
		if (strcmp(str, "inherit")) {
			unsigned uval;

			if (!system_tos_aton(str, &uval)) {
				ret = -EINVAL;
				goto failure;
			}

			if (v6)
				flowinfo |= htonl(uval << 20) & IP6_FLOWINFO_TCLASS;
			else
				tos = uval;
		} else {
			if (v6)
				flags6 |= IP6_TNL_F_USE_ORIG_TCLASS;
			else
				tos = 1;
		}
	}

	if ((cur = tb[TUNNEL_ATTR_DATA])) {
		struct blob_attr *tb_data[__GRE_DATA_ATTR_MAX];

		blobmsg_parse(gre_data_attr_list.params, __GRE_DATA_ATTR_MAX, tb_data,
			blobmsg_data(cur), blobmsg_len(cur));

		if ((cur = tb_data[GRE_DATA_IKEY])) {
			if ((ikey = blobmsg_get_u32(cur)))
				iflags |= GRE_KEY;
		}

		if ((cur = tb_data[GRE_DATA_OKEY])) {
			if ((okey = blobmsg_get_u32(cur)))
				oflags |= GRE_KEY;
		}

		if ((cur = tb_data[GRE_DATA_ICSUM])) {
			if (blobmsg_get_bool(cur))
				iflags |= GRE_CSUM;
		}

		if ((cur = tb_data[GRE_DATA_OCSUM])) {
			if (blobmsg_get_bool(cur))
				oflags |= GRE_CSUM;
		}

		if ((cur = tb_data[GRE_DATA_ISEQNO])) {
			if (blobmsg_get_bool(cur))
				iflags |= GRE_SEQ;
		}

		if ((cur = tb_data[GRE_DATA_OSEQNO])) {
			if (blobmsg_get_bool(cur))
				oflags |= GRE_SEQ;
		}

		if ((cur = tb_data[GRE_DATA_ENCAPLIMIT])) {
			char *str = blobmsg_get_string(cur);

			if (strcmp(str, "ignore")) {
				char *e;

				encap_limit = strtoul(str, &e, 0);

				if (e == str || *e || encap_limit > 255) {
					ret = -EINVAL;
					goto failure;
				}

				flags6 &= ~IP6_TNL_F_IGN_ENCAP_LIMIT;
			}
		}
	}

	if (v6) {
		struct in6_addr in6buf;
		if ((cur = tb[TUNNEL_ATTR_LOCAL])) {
			if (inet_pton(AF_INET6, blobmsg_data(cur), &in6buf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(nlm, IFLA_GRE_LOCAL, sizeof(in6buf), &in6buf);
		}

		if ((cur = tb[TUNNEL_ATTR_REMOTE])) {
			if (inet_pton(AF_INET6, blobmsg_data(cur), &in6buf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(nlm, IFLA_GRE_REMOTE, sizeof(in6buf), &in6buf);
		}

		if (!(flags6 & IP6_TNL_F_IGN_ENCAP_LIMIT))
			nla_put_u8(nlm, IFLA_GRE_ENCAP_LIMIT, encap_limit);

		if (flowinfo)
			nla_put_u32(nlm, IFLA_GRE_FLOWINFO, flowinfo);

		if (flags6)
			nla_put_u32(nlm, IFLA_GRE_FLAGS, flags6);

		if (!ttl)
			ttl = 64;
	} else {
		struct in_addr inbuf;
		bool set_df = true;

		if ((cur = tb[TUNNEL_ATTR_LOCAL])) {
			if (inet_pton(AF_INET, blobmsg_data(cur), &inbuf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(nlm, IFLA_GRE_LOCAL, sizeof(inbuf), &inbuf);
		}

		if ((cur = tb[TUNNEL_ATTR_REMOTE])) {
			if (inet_pton(AF_INET, blobmsg_data(cur), &inbuf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(nlm, IFLA_GRE_REMOTE, sizeof(inbuf), &inbuf);

			if (IN_MULTICAST(ntohl(inbuf.s_addr))) {
				if (!okey) {
					okey = inbuf.s_addr;
					oflags |= GRE_KEY;
				}

				if (!ikey) {
					ikey = inbuf.s_addr;
					iflags |= GRE_KEY;
				}
			}
		}

		if ((cur = tb[TUNNEL_ATTR_DF]))
			set_df = blobmsg_get_bool(cur);

		if (!set_df) {
			/* ttl != 0 and nopmtudisc are incompatible */
			if (ttl) {
				ret = -EINVAL;
				goto failure;
			}
		} else if (!ttl)
			ttl = 64;

		nla_put_u8(nlm, IFLA_GRE_PMTUDISC, set_df ? 1 : 0);

		nla_put_u8(nlm, IFLA_GRE_TOS, tos);
	}

	if (ttl)
		nla_put_u8(nlm, IFLA_GRE_TTL, ttl);

	if (oflags)
		nla_put_u16(nlm, IFLA_GRE_OFLAGS, oflags);

	if (iflags)
		nla_put_u16(nlm, IFLA_GRE_IFLAGS, iflags);

	if (okey)
		nla_put_u32(nlm, IFLA_GRE_OKEY, htonl(okey));

	if (ikey)
		nla_put_u32(nlm, IFLA_GRE_IKEY, htonl(ikey));

	nla_nest_end(nlm, infodata);
	nla_nest_end(nlm, linkinfo);

	return system_rtnl_call(nlm);

failure:
	nlmsg_free(nlm);
	return ret;
}
#endif

#ifdef IFLA_VTI_MAX
static int system_add_vti_tunnel(const char *name, const char *kind,
				 const unsigned int link, struct blob_attr **tb, bool v6)
{
	struct nl_msg *nlm;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC, };
	struct blob_attr *cur;
	int ret = 0;

	nlm = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE);
	if (!nlm)
		return -1;

	nlmsg_append(nlm, &ifi, sizeof(ifi), 0);
	nla_put_string(nlm, IFLA_IFNAME, name);

	struct nlattr *linkinfo = nla_nest_start(nlm, IFLA_LINKINFO);
	if (!linkinfo) {
		ret = -ENOMEM;
		goto failure;
	}

	nla_put_string(nlm, IFLA_INFO_KIND, kind);
	struct nlattr *infodata = nla_nest_start(nlm, IFLA_INFO_DATA);
	if (!infodata) {
		ret = -ENOMEM;
		goto failure;
	}

	if (link)
		nla_put_u32(nlm, IFLA_VTI_LINK, link);

	if (v6) {
		struct in6_addr in6buf;
		if ((cur = tb[TUNNEL_ATTR_LOCAL])) {
			if (inet_pton(AF_INET6, blobmsg_data(cur), &in6buf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(nlm, IFLA_VTI_LOCAL, sizeof(in6buf), &in6buf);
		}

		if ((cur = tb[TUNNEL_ATTR_REMOTE])) {
			if (inet_pton(AF_INET6, blobmsg_data(cur), &in6buf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(nlm, IFLA_VTI_REMOTE, sizeof(in6buf), &in6buf);
		}

	} else {
		struct in_addr inbuf;

		if ((cur = tb[TUNNEL_ATTR_LOCAL])) {
			if (inet_pton(AF_INET, blobmsg_data(cur), &inbuf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(nlm, IFLA_VTI_LOCAL, sizeof(inbuf), &inbuf);
		}

		if ((cur = tb[TUNNEL_ATTR_REMOTE])) {
			if (inet_pton(AF_INET, blobmsg_data(cur), &inbuf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(nlm, IFLA_VTI_REMOTE, sizeof(inbuf), &inbuf);
		}

	}

	if ((cur = tb[TUNNEL_ATTR_DATA])) {
		struct blob_attr *tb_data[__VTI_DATA_ATTR_MAX];
		uint32_t ikey = 0, okey = 0;

		blobmsg_parse(vti_data_attr_list.params, __VTI_DATA_ATTR_MAX, tb_data,
			blobmsg_data(cur), blobmsg_len(cur));

		if ((cur = tb_data[VTI_DATA_IKEY])) {
			if ((ikey = blobmsg_get_u32(cur)))
				nla_put_u32(nlm, IFLA_VTI_IKEY, htonl(ikey));
		}

		if ((cur = tb_data[VTI_DATA_OKEY])) {
			if ((okey = blobmsg_get_u32(cur)))
				nla_put_u32(nlm, IFLA_VTI_OKEY, htonl(okey));
		}
	}

	nla_nest_end(nlm, infodata);
	nla_nest_end(nlm, linkinfo);

	return system_rtnl_call(nlm);

failure:
	nlmsg_free(nlm);
	return ret;
}
#endif

#ifdef IFLA_XFRM_MAX
static int system_add_xfrm_tunnel(const char *name, const char *kind,
				 const unsigned int link, struct blob_attr **tb)
{
	struct nl_msg *nlm;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC, };
	struct blob_attr *cur;
	int ret = 0;

	nlm = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE);
	if (!nlm)
		return -1;

	nlmsg_append(nlm, &ifi, sizeof(ifi), 0);
	nla_put_string(nlm, IFLA_IFNAME, name);

	struct nlattr *linkinfo = nla_nest_start(nlm, IFLA_LINKINFO);
	if (!linkinfo) {
		ret = -ENOMEM;
		goto failure;
	}

	nla_put_string(nlm, IFLA_INFO_KIND, kind);
	struct nlattr *infodata = nla_nest_start(nlm, IFLA_INFO_DATA);
	if (!infodata) {
		ret = -ENOMEM;
		goto failure;
	}

	if (link)
		nla_put_u32(nlm, IFLA_XFRM_LINK, link);

	if ((cur = tb[TUNNEL_ATTR_DATA])) {
		struct blob_attr *tb_data[__XFRM_DATA_ATTR_MAX];
		uint32_t if_id = 0;

		blobmsg_parse(xfrm_data_attr_list.params, __XFRM_DATA_ATTR_MAX, tb_data,
			blobmsg_data(cur), blobmsg_len(cur));

		if ((cur = tb_data[XFRM_DATA_IF_ID])) {
			if ((if_id = blobmsg_get_u32(cur)))
				nla_put_u32(nlm, IFLA_XFRM_IF_ID, if_id);
		}

	}

	nla_nest_end(nlm, infodata);
	nla_nest_end(nlm, linkinfo);

	return system_rtnl_call(nlm);

failure:
	nlmsg_free(nlm);
	return ret;
}
#endif

#ifdef IFLA_VXLAN_MAX
static void system_vxlan_map_bool_attr(struct nl_msg *msg, struct blob_attr **tb_data, int attrtype, int vxlandatatype, bool invert) {
	struct blob_attr *cur;
	if ((cur = tb_data[vxlandatatype])) {
		bool val = blobmsg_get_bool(cur);
		if (invert)
			val = !val;

		if ((attrtype == IFLA_VXLAN_GBP) && val)
			nla_put_flag(msg, attrtype);
		else 
			nla_put_u8(msg, attrtype, val);

	}
}

static int system_add_vxlan(const char *name, const unsigned int link, struct blob_attr **tb, bool v6)
{
	struct blob_attr *tb_data[__VXLAN_DATA_ATTR_MAX];
	struct nl_msg *msg;
	struct nlattr *linkinfo, *data;
	struct ifinfomsg iim = { .ifi_family = AF_UNSPEC, };
	struct blob_attr *cur;
	int ret = 0;

	if ((cur = tb[TUNNEL_ATTR_DATA]))
		blobmsg_parse(vxlan_data_attr_list.params, __VXLAN_DATA_ATTR_MAX, tb_data,
			blobmsg_data(cur), blobmsg_len(cur));
	else
		return -EINVAL;

	msg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);

	if (!msg)
		return -1;

	nlmsg_append(msg, &iim, sizeof(iim), 0);

	nla_put_string(msg, IFLA_IFNAME, name);

	if ((cur = tb_data[VXLAN_DATA_ATTR_MACADDR])) {
		struct ether_addr *ea = ether_aton(blobmsg_get_string(cur));
		if (!ea) {
			ret = -EINVAL;
			goto failure;
		}

		nla_put(msg, IFLA_ADDRESS, ETH_ALEN, ea);
	}

	if ((cur = tb[TUNNEL_ATTR_MTU])) {
		uint32_t mtu = blobmsg_get_u32(cur);
		nla_put_u32(msg, IFLA_MTU, mtu);
	}

	if (!(linkinfo = nla_nest_start(msg, IFLA_LINKINFO))) {
		ret = -ENOMEM;
		goto failure;
	}

	nla_put_string(msg, IFLA_INFO_KIND, "vxlan");

	if (!(data = nla_nest_start(msg, IFLA_INFO_DATA))) {
		ret = -ENOMEM;
		goto failure;
	}

	if (link)
		nla_put_u32(msg, IFLA_VXLAN_LINK, link);

	if ((cur = tb_data[VXLAN_DATA_ATTR_ID])) {
		uint32_t id = blobmsg_get_u32(cur);
		if (id >= (1u << 24) - 1) {
			ret = -EINVAL;
			goto failure;
		}

		nla_put_u32(msg, IFLA_VXLAN_ID, id);
	}

	if (v6) {
		struct in6_addr in6buf;
		if ((cur = tb[TUNNEL_ATTR_LOCAL])) {
			if (inet_pton(AF_INET6, blobmsg_data(cur), &in6buf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(msg, IFLA_VXLAN_LOCAL6, sizeof(in6buf), &in6buf);
		}

		if ((cur = tb[TUNNEL_ATTR_REMOTE])) {
			if (inet_pton(AF_INET6, blobmsg_data(cur), &in6buf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(msg, IFLA_VXLAN_GROUP6, sizeof(in6buf), &in6buf);
		}
	} else {
		struct in_addr inbuf;

		if ((cur = tb[TUNNEL_ATTR_LOCAL])) {
			if (inet_pton(AF_INET, blobmsg_data(cur), &inbuf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(msg, IFLA_VXLAN_LOCAL, sizeof(inbuf), &inbuf);
		}

		if ((cur = tb[TUNNEL_ATTR_REMOTE])) {
			if (inet_pton(AF_INET, blobmsg_data(cur), &inbuf) < 1) {
				ret = -EINVAL;
				goto failure;
			}
			nla_put(msg, IFLA_VXLAN_GROUP, sizeof(inbuf), &inbuf);
		}
	}

	uint32_t port = 4789;
	if ((cur = tb_data[VXLAN_DATA_ATTR_PORT])) {
		port = blobmsg_get_u32(cur);
		if (port < 1 || port > 65535) {
			ret = -EINVAL;
			goto failure;
		}
	}
	nla_put_u16(msg, IFLA_VXLAN_PORT, htons(port));

	if ((cur = tb_data[VXLAN_DATA_ATTR_SRCPORTMIN])) {
		struct ifla_vxlan_port_range srcports = {0,0};

		uint32_t low = blobmsg_get_u32(cur);
		if (low < 1 || low > 65535 - 1) {
			ret = -EINVAL;
			goto failure;
		}

		srcports.low = htons((uint16_t) low);
		srcports.high = htons((uint16_t) (low+1));

		if ((cur = tb_data[VXLAN_DATA_ATTR_SRCPORTMAX])) {
			uint32_t high = blobmsg_get_u32(cur);
			if (high < 1 || high > 65535) {
				ret = -EINVAL;
				goto failure;
			}

			if (high > low)
				srcports.high = htons((uint16_t) high);
		}

		nla_put(msg, IFLA_VXLAN_PORT_RANGE, sizeof(srcports), &srcports);
	}

	system_vxlan_map_bool_attr(msg, tb_data, IFLA_VXLAN_UDP_CSUM, VXLAN_DATA_ATTR_TXCSUM, false);
	system_vxlan_map_bool_attr(msg, tb_data, IFLA_VXLAN_UDP_ZERO_CSUM6_RX, VXLAN_DATA_ATTR_RXCSUM, true);
	system_vxlan_map_bool_attr(msg, tb_data, IFLA_VXLAN_UDP_ZERO_CSUM6_TX, VXLAN_DATA_ATTR_TXCSUM, true);
	system_vxlan_map_bool_attr(msg, tb_data, IFLA_VXLAN_LEARNING, VXLAN_DATA_ATTR_LEARNING, false);
	system_vxlan_map_bool_attr(msg, tb_data, IFLA_VXLAN_RSC , VXLAN_DATA_ATTR_RSC, false);
	system_vxlan_map_bool_attr(msg, tb_data, IFLA_VXLAN_PROXY , VXLAN_DATA_ATTR_PROXY, false);
	system_vxlan_map_bool_attr(msg, tb_data, IFLA_VXLAN_L2MISS , VXLAN_DATA_ATTR_L2MISS, false);
	system_vxlan_map_bool_attr(msg, tb_data, IFLA_VXLAN_L3MISS , VXLAN_DATA_ATTR_L3MISS, false);
	system_vxlan_map_bool_attr(msg, tb_data, IFLA_VXLAN_GBP , VXLAN_DATA_ATTR_GBP, false);

	if ((cur = tb_data[VXLAN_DATA_ATTR_AGEING])) {
		uint32_t ageing = blobmsg_get_u32(cur);
		nla_put_u32(msg, IFLA_VXLAN_AGEING, ageing);
	}

	if ((cur = tb_data[VXLAN_DATA_ATTR_LIMIT])) {
		uint32_t maxaddress = blobmsg_get_u32(cur);
		nla_put_u32(msg, IFLA_VXLAN_LIMIT, maxaddress);
	}

	if ((cur = tb[TUNNEL_ATTR_TOS])) {
		char *str = blobmsg_get_string(cur);
		unsigned tos = 1;

		if (strcmp(str, "inherit")) {
			if (!system_tos_aton(str, &tos)) {
				ret = -EINVAL;
				goto failure;
			}
		}

		nla_put_u8(msg, IFLA_VXLAN_TOS, tos);
	}

	if ((cur = tb[TUNNEL_ATTR_TTL])) {
		uint32_t ttl = blobmsg_get_u32(cur);
		if (ttl < 1 || ttl > 255) {
			ret = -EINVAL;
			goto failure;
		}

		nla_put_u8(msg, IFLA_VXLAN_TTL, ttl);
	}

	nla_nest_end(msg, data);
	nla_nest_end(msg, linkinfo);

	ret = system_rtnl_call(msg);
	if (ret)
		D(SYSTEM, "Error adding vxlan '%s': %d", name, ret);

	return ret;

failure:
	nlmsg_free(msg);
	return ret;
}
#endif

static int system_add_sit_tunnel(const char *name, const unsigned int link, struct blob_attr **tb)
{
	struct blob_attr *cur;
	int ret = 0;

	if (system_add_proto_tunnel(name, IPPROTO_IPV6, link, tb) < 0)
		return -1;

#ifdef SIOCADD6RD
	if ((cur = tb[TUNNEL_ATTR_DATA])) {
		struct blob_attr *tb_data[__SIXRD_DATA_ATTR_MAX];
		unsigned int mask;
		struct ip_tunnel_6rd p6;

		blobmsg_parse(sixrd_data_attr_list.params, __SIXRD_DATA_ATTR_MAX, tb_data,
			blobmsg_data(cur), blobmsg_len(cur));

		memset(&p6, 0, sizeof(p6));

		if ((cur = tb_data[SIXRD_DATA_PREFIX])) {
			if (!parse_ip_and_netmask(AF_INET6, blobmsg_data(cur),
						&p6.prefix, &mask) || mask > 128) {
				ret = -EINVAL;
				goto failure;
			}

			p6.prefixlen = mask;
		}

		if ((cur = tb_data[SIXRD_DATA_RELAY_PREFIX])) {
			if (!parse_ip_and_netmask(AF_INET, blobmsg_data(cur),
						&p6.relay_prefix, &mask) || mask > 32) {
				ret = -EINVAL;
				goto failure;
			}

			p6.relay_prefixlen = mask;
		}

		if (tunnel_ioctl(name, SIOCADD6RD, &p6) < 0) {
			ret = -1;
			goto failure;
		}
	}
#endif

	return ret;

failure:
	system_link_del(name);
	return ret;
}

static int system_add_proto_tunnel(const char *name, const uint8_t proto, const unsigned int link, struct blob_attr **tb)
{
	struct blob_attr *cur;
	bool set_df = true;
	struct ip_tunnel_parm p  = {
		.link = link,
		.iph = {
			.version = 4,
			.ihl = 5,
			.protocol = proto,
		}
	};

	if ((cur = tb[TUNNEL_ATTR_LOCAL]) &&
			inet_pton(AF_INET, blobmsg_data(cur), &p.iph.saddr) < 1)
		return -EINVAL;

	if ((cur = tb[TUNNEL_ATTR_REMOTE]) &&
			inet_pton(AF_INET, blobmsg_data(cur), &p.iph.daddr) < 1)
		return -EINVAL;

	if ((cur = tb[TUNNEL_ATTR_DF]))
		set_df = blobmsg_get_bool(cur);

	if ((cur = tb[TUNNEL_ATTR_TTL]))
		p.iph.ttl = blobmsg_get_u32(cur);

	if ((cur = tb[TUNNEL_ATTR_TOS])) {
		char *str = blobmsg_get_string(cur);
		if (strcmp(str, "inherit")) {
			unsigned uval;

			if (!system_tos_aton(str, &uval))
				return -EINVAL;

			p.iph.tos = uval;
		} else
			p.iph.tos = 1;
	}

	p.iph.frag_off = set_df ? htons(IP_DF) : 0;
	/* ttl !=0 and nopmtudisc are incompatible */
	if (p.iph.ttl && p.iph.frag_off == 0)
		return -EINVAL;

	strncpy(p.name, name, sizeof(p.name) - 1);

	switch (p.iph.protocol) {
	case IPPROTO_IPIP:
		return tunnel_ioctl("tunl0", SIOCADDTUNNEL, &p);
	case IPPROTO_IPV6:
		return tunnel_ioctl("sit0", SIOCADDTUNNEL, &p);
	default:
		break;
	}
	return -1;
}

int system_del_ip_tunnel(const struct device *dev)
{
	return system_link_del(dev->ifname);
}

int system_update_ipv6_mtu(struct device *dev, int mtu)
{
	int ret = -1;
	char buf[64];
	int fd;

	fd = open(dev_sysctl_path("ipv6/conf", dev->ifname, "mtu"), O_RDWR);
	if (fd < 0)
		return ret;

	if (!mtu) {
		ssize_t len = read(fd, buf, sizeof(buf) - 1);
		if (len < 0)
			goto out;

		buf[len] = 0;
		ret = atoi(buf);
	} else {
		if (write(fd, buf, snprintf(buf, sizeof(buf), "%i", mtu)) > 0)
			ret = mtu;
	}

out:
	close(fd);
	return ret;
}

int system_add_ip_tunnel(const struct device *dev, struct blob_attr *attr)
{
	struct blob_attr *tb[__TUNNEL_ATTR_MAX];
	struct blob_attr *cur;
	const char *str;

	blobmsg_parse(tunnel_attr_list.params, __TUNNEL_ATTR_MAX, tb,
		blob_data(attr), blob_len(attr));

	system_link_del(dev->ifname);

	if (!(cur = tb[TUNNEL_ATTR_TYPE]))
		return -EINVAL;
	str = blobmsg_data(cur);

	unsigned int ttl = 0;
	if ((cur = tb[TUNNEL_ATTR_TTL])) {
		ttl = blobmsg_get_u32(cur);
		if (ttl > 255)
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

	if (!strcmp(str, "sit"))
		return system_add_sit_tunnel(dev->ifname, link, tb);
#ifdef IFLA_IPTUN_MAX
	else if (!strcmp(str, "ipip6")) {
		return system_add_ip6_tunnel(dev->ifname, link, tb);
	} else if (!strcmp(str, "greip")) {
		return system_add_gre_tunnel(dev->ifname, "gre", link, tb, false);
	} else if (!strcmp(str, "gretapip"))  {
		return system_add_gre_tunnel(dev->ifname, "gretap", link, tb, false);
	} else if (!strcmp(str, "greip6")) {
		return system_add_gre_tunnel(dev->ifname, "ip6gre", link, tb, true);
	} else if (!strcmp(str, "gretapip6")) {
		return system_add_gre_tunnel(dev->ifname, "ip6gretap", link, tb, true);
#ifdef IFLA_VTI_MAX
	} else if (!strcmp(str, "vtiip")) {
		return system_add_vti_tunnel(dev->ifname, "vti", link, tb, false);
	} else if (!strcmp(str, "vtiip6")) {
		return system_add_vti_tunnel(dev->ifname, "vti6", link, tb, true);
#endif
#ifdef IFLA_XFRM_MAX
	} else if (!strcmp(str, "xfrm")) {
		return system_add_xfrm_tunnel(dev->ifname, "xfrm", link, tb);
#endif
#ifdef IFLA_VXLAN_MAX
	} else if(!strcmp(str, "vxlan")) {
		return system_add_vxlan(dev->ifname, link, tb, false);
	} else if(!strcmp(str, "vxlan6")) {
		return system_add_vxlan(dev->ifname, link, tb, true);
#endif
#endif
	} else if (!strcmp(str, "ipip")) {
		return system_add_proto_tunnel(dev->ifname, IPPROTO_IPIP, link, tb);
	}
	else
		return -EINVAL;

	return 0;
}
