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
const char *resolv_conf = DEFAULT_RESOLV_CONF;
static char **global_argv;
static struct list_head process_list = LIST_HEAD_INIT(process_list);

static void
netifd_process_cb(struct uloop_process *proc, int ret)
{
	struct netifd_process *np;
	np = container_of(proc, struct netifd_process, uloop);
	list_del(&np->list);
	return np->cb(np, ret);
}

int
netifd_start_process(const char **argv, char **env, struct netifd_process *proc)
{
	int pid;

	netifd_kill_process(proc);

	if ((pid = fork()) < 0)
		return -1;

	if (!pid) {
		if (env) {
			while (*env) {
				putenv(*env);
				env++;
			}
		}
		if (proc->dir_fd >= 0)
			fchdir(proc->dir_fd);
		execvp(argv[0], (char **) argv);
		exit(127);
	}

	if (pid < 0)
		return -1;

	proc->uloop.cb = netifd_process_cb;
	proc->uloop.pid = pid;
	uloop_process_add(&proc->uloop);
	list_add_tail(&proc->list, &process_list);

	return 0;
}

void
netifd_kill_process(struct netifd_process *proc)
{
	if (!proc->uloop.pending)
		return;

	kill(proc->uloop.pid, SIGTERM);
	uloop_process_delete(&proc->uloop);
	list_del(&proc->list);
}

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
		" -r <path>:		Path to resolv.conf\n"
		"			(default: "DEFAULT_HOTPLUG_PATH")\n"
		"\n", progname, main_path);

	return 1;
}

static void
netifd_handle_signal(int signo)
{
	uloop_end();
}

static void
netifd_setup_signals(void)
{
	struct sigaction s;

	memset(&s, 0, sizeof(s));
	s.sa_handler = netifd_handle_signal;
	s.sa_flags = 0;
	sigaction(SIGINT, &s, NULL);
	sigaction(SIGTERM, &s, NULL);
	sigaction(SIGUSR1, &s, NULL);
	sigaction(SIGUSR2, &s, NULL);
}

static void
netifd_kill_processes(void)
{
	struct netifd_process *proc, *tmp;

	list_for_each_entry_safe(proc, tmp, &process_list, list)
		netifd_kill_process(proc);
}

int main(int argc, char **argv)
{
	const char *socket = NULL;
	int ch;

	global_argv = argv;

	while ((ch = getopt(argc, argv, "d:s:p:h:r:")) != -1) {
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
		case 'r':
			resolv_conf = optarg;
			break;
		default:
			return usage(argv[0]);
		}
	}

	netifd_setup_signals();
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
	netifd_kill_processes();

	netifd_ubus_done();

	return 0;
}
