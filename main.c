#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "netifd.h"
#include "ubus.h"
#include "config.h"

static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		" -s <path>:		Path to the ubus socket\n"
		"\n", progname);

	return 1;
}

int main(int argc, char **argv)
{
	const char *socket = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch(ch) {
		case 's':
			socket = optarg;
			break;
		default:
			return usage(argv[0]);
		}
	}

	if (netifd_ubus_init(NULL) < 0) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return 1;
	}

	config_init_interfaces(NULL);

	uloop_run();

	netifd_ubus_done();

	return 0;
}
