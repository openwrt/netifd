#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "netifd.h"
#include "ubus.h"
#include "config.h"
#include "system.h"
#include "interface.h"

unsigned int debug_mask = 0;
const char *main_path = DEFAULT_MAIN_PATH;
static char **global_argv;

static void netifd_do_restart(struct uloop_timeout *timeout)
{
	execvp(global_argv[0], global_argv);
}

static void netifd_do_reload(struct uloop_timeout *timeout)
{
	config_init_interfaces(NULL);
}

static struct uloop_timeout main_timer;

void netifd_reload(void)
{
	main_timer.cb = netifd_do_reload;
	uloop_timeout_set(&main_timer, 100);
}

void netifd_restart(void)
{
	main_timer.cb = netifd_do_restart;
	interface_set_down(NULL);
	uloop_timeout_set(&main_timer, 1000);
}

static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		" -d <mask>:		Mask for debug messages\n"
		" -s <path>:		Path to the ubus socket\n"
		" -p <path>:		Path to netifd addons (default: %s)\n"
		" -h <path>:		Path to the hotplug script\n"
		"			(default: "DEFAULT_HOTPLUG_PATH")\n"
		"\n", progname, main_path);

	return 1;
}

int main(int argc, char **argv)
{
	const char *socket = NULL;
	int ch;

	global_argv = argv;

	while ((ch = getopt(argc, argv, "d:s:")) != -1) {
		switch(ch) {
		case 'd':
			debug_mask = strtoul(optarg, NULL, 0);
			break;
		case 's':
			socket = optarg;
			break;
		case 'p':
			main_path = optarg;
			break;
		case 'h':
			hotplug_cmd_path = optarg;
			break;
		default:
			return usage(argv[0]);
		}
	}

	if (netifd_ubus_init(socket) < 0) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return 1;
	}

	if (system_init()) {
		fprintf(stderr, "Failed to initialize system control\n");
		return 1;
	}

	config_init_interfaces(NULL);

	uloop_run();

	netifd_ubus_done();

	return 0;
}
