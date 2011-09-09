#ifndef __NETIFD_H
#define __NETIFD_H

#include <sys/socket.h>
#include <net/if.h>

#include <stdbool.h>
#include <stdio.h>

#include <libubox/uloop.h>

#include <libubus.h>

#include "utils.h"

struct device;
struct interface;

extern const char *main_path;
void netifd_restart(void);

#endif
