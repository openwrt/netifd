#ifndef __NETIFD_H
#define __NETIFD_H

#include <sys/socket.h>
#include <net/if.h>

#include <stdbool.h>
#include <stdio.h>

#include <libubox/uloop.h>

#include <libubus.h>

#include "utils.h"

extern unsigned int debug_mask;

enum {
	DEBUG_SYSTEM	= 0,
	DEBUG_DEVICE	= 1,
	DEBUG_INTERFACE	= 2,
};

#ifdef DEBUG
#define DPRINTF(format, ...) fprintf(stderr, "%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__)
#define D(level, format, ...) do { \
		if (debug_mask & (1 << (DEBUG_ ## level))) \
				DPRINTF(format, ##__VA_ARGS__); \
	} while (0)
#else
#define DPRINTF(format, ...) no_debug(0, format, ## __VA_ARGS__)
#define D(level, format, ...) no_debug(DEBUG_ ## level, format, ## __VA_ARGS__)
#endif

static inline void no_debug(int level, const char *fmt, ...)
{
}

struct device;
struct interface;

extern const char *main_path;
void netifd_restart(void);
void netifd_reload(void);

#endif
