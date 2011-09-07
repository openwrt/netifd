#ifndef __NETIFD_H
#define __NETIFD_H

#include <sys/socket.h>
#include <net/if.h>

#include <stdbool.h>
#include <stdio.h>

#include <libubox/uloop.h>

#include <libubus.h>
#include <uci.h>

#include "utils.h"

struct device;
struct interface;

extern struct uci_context *uci_ctx;
extern bool config_init;

void config_init_interfaces(const char *name);

#endif
