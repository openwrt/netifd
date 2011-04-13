#ifndef __NETIFD_H
#define __NETIFD_H

#include <sys/socket.h>
#include <net/if.h>

#include <stdbool.h>
#include <stdio.h>

#include <libubox/list.h>
#include <libubox/uloop.h>

#include <libubus.h>
#include <uci.h>

#ifdef DEBUG
#define DPRINTF(format, ...) fprintf(stderr, "%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__)
#else
#define DPRINTF(...) do {} while(0)
#endif

struct device;
struct interface;

extern struct uci_context *uci_ctx;
extern bool config_init;

int avl_strcmp(const void *k1, const void *k2, void *ptr);
void config_init_interfaces(const char *name);

#endif
