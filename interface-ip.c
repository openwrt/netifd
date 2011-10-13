#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "netifd.h"
#include "device.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"
#include "ubus.h"
#include "system.h"

static int
addr_cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, sizeof(struct device_addr) -
		      offsetof(struct device_addr, mask));
}

static int
route_cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, sizeof(struct device_route) -
		      offsetof(struct device_route, mask));
}

static void
interface_update_proto_addr(struct vlist_tree *tree,
			    struct vlist_node *node_new,
			    struct vlist_node *node_old)
{
	struct interface *iface;
	struct device *dev;
	struct device_addr *addr;

	iface = container_of(tree, struct interface, proto_addr);
	dev = iface->l3_dev->dev;

	if (node_old) {
		addr = container_of(node_old, struct device_addr, node);
		if (!(addr->flags & DEVADDR_EXTERNAL))
			system_del_address(dev, addr);
		free(addr);
	}

	if (node_new) {
		addr = container_of(node_new, struct device_addr, node);
		if (!(addr->flags & DEVADDR_EXTERNAL))
			system_add_address(dev, addr);
	}
}

static void
interface_update_proto_route(struct vlist_tree *tree,
			     struct vlist_node *node_new,
			     struct vlist_node *node_old)
{
	struct interface *iface;
	struct device *dev;
	struct device_route *route;

	iface = container_of(tree, struct interface, proto_route);
	dev = iface->l3_dev->dev;

	if (node_old) {
		route = container_of(node_old, struct device_route, node);
		if (!(route->flags & DEVADDR_EXTERNAL))
			system_del_route(dev, route);
		free(route);
	}

	if (node_new) {
		route = container_of(node_new, struct device_route, node);
		if (!(route->flags & DEVADDR_EXTERNAL))
			system_add_route(dev, route);
	}
}

void
interface_add_dns_server(struct interface *iface, const char *str)
{
	struct dns_server *s;

	s = calloc(1, sizeof(*s));
	s->af = AF_INET;
	if (inet_pton(s->af, str, &s->addr.in))
		goto add;

	s->af = AF_INET6;
	if (inet_pton(s->af, str, &s->addr.in))
		goto add;

	free(s);
	return;

add:
	D(INTERFACE, "Add IPv%c DNS server: %s\n",
	  s->af == AF_INET6 ? '6' : '4', str);
	list_add_tail(&s->list, &iface->proto_dns_servers);
}

void
interface_add_dns_server_list(struct interface *iface, struct blob_attr *list)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, list, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		if (!blobmsg_check_attr(cur, NULL))
			continue;

		interface_add_dns_server(iface, blobmsg_data(cur));
	}
}

void
interface_add_dns_search_domain(struct interface *iface, const char *str)
{
	struct dns_search_domain *s;
	int len = strlen(str);

	s = calloc(1, sizeof(*s) + len + 1);
	if (!s)
		return;

	D(INTERFACE, "Add DNS search domain: %s\n", str);
	memcpy(s->name, str, len);
	list_add_tail(&s->list, &iface->proto_dns_search);
}

void
interface_add_dns_search_list(struct interface *iface, struct blob_attr *list)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, list, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		if (!blobmsg_check_attr(cur, NULL))
			continue;

		interface_add_dns_server(iface, blobmsg_data(cur));
	}
}

static void
interface_clear_dns_servers(struct interface *iface)
{
	struct dns_server *s, *tmp;

	list_for_each_entry_safe(s, tmp, &iface->proto_dns_servers, list) {
		list_del(&s->list);
		free(s);
	}
}

static void
interface_clear_dns_search(struct interface *iface)
{
	struct dns_search_domain *s, *tmp;

	list_for_each_entry_safe(s, tmp, &iface->proto_dns_search, list) {
		list_del(&s->list);
		free(s);
	}
}

void
interface_clear_dns(struct interface *iface)
{
	interface_clear_dns_servers(iface);
	interface_clear_dns_search(iface);
}

void
interface_write_resolv_conf(void)
{
	struct interface *iface;
	struct dns_server *s;
	struct dns_search_domain *d;
	char *path = alloca(strlen(resolv_conf) + 5);
	const char *str;
	char buf[32];
	FILE *f;

	sprintf(path, "%s.tmp", resolv_conf);
	unlink(path);
	f = fopen(path, "w");
	if (!f) {
		D(INTERFACE, "Failed to open %s for writing\n", path);
		return;
	}

	vlist_for_each_element(&interfaces, iface, node) {
		if (iface->state != IFS_UP)
			continue;

		if (list_empty(&iface->proto_dns_search) &&
		    list_empty(&iface->proto_dns_servers))
			continue;

		fprintf(f, "# Interface %s\n", iface->name);
		list_for_each_entry(s, &iface->proto_dns_servers, list) {
			str = inet_ntop(s->af, &s->addr, buf, sizeof(buf));
			if (!str)
				continue;

			fprintf(f, "nameserver %s\n", str);
		}

		list_for_each_entry(d, &iface->proto_dns_search, list) {
			fprintf(f, "search %s\n", d->name);
		}
	}
	fclose(f);
	if (rename(path, resolv_conf) < 0) {
		D(INTERFACE, "Failed to replace %s\n", resolv_conf);
		unlink(path);
	}
}

void
interface_ip_update_start(struct interface *iface)
{
	interface_clear_dns(iface);
	vlist_update(&iface->proto_route);
	vlist_update(&iface->proto_addr);
}

void
interface_ip_update_complete(struct interface *iface)
{
	vlist_flush(&iface->proto_route);
	vlist_flush(&iface->proto_addr);
}

void
interface_ip_init(struct interface *iface)
{
	vlist_init(&iface->proto_route, route_cmp, interface_update_proto_route,
		   struct device_route, node, mask);
	vlist_init(&iface->proto_addr, addr_cmp, interface_update_proto_addr,
		   struct device_addr, node, mask);
}
