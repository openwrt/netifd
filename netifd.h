#ifndef __NETIFD_H
#define __NETIFD_H

#include <sys/socket.h>
#include <net/if.h>

#include <stdbool.h>
#include <stdio.h>

#include <libubox/uloop.h>

#include <libubus.h>

#include "utils.h"

#ifdef DUMMY_MODE
#define DEFAULT_MAIN_PATH	"./dummy"
#define DEFAULT_HOTPLUG_PATH	"./scripts/hotplug-cmd"
#define DEFAULT_RESOLV_CONF	"./tmp/resolv.conf"
#else
#define DEFAULT_MAIN_PATH	"/lib/netifd"
#define DEFAULT_HOTPLUG_PATH	"/sbin/hotplug-cmd"
#define DEFAULT_RESOLV_CONF	"/tmp/resolv.conf.auto"
#endif

extern const char *resolv_conf;
extern char *hotplug_cmd_path;
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

struct netifd_fd {
	struct list_head list;
	struct netifd_process *proc;
	int fd;
};

struct netifd_process {
	struct list_head list;
	struct uloop_process uloop;
	void (*cb)(struct netifd_process *, int ret);
	int dir_fd;
};

int netifd_start_process(const char **argv, char **env, struct netifd_process *proc);
void netifd_kill_process(struct netifd_process *proc);

void netifd_fd_add(struct netifd_fd *fd);
void netifd_fd_delete(struct netifd_fd *fd);

struct device;
struct interface;

extern const char *main_path;
void netifd_restart(void);
void netifd_reload(void);

#endif
