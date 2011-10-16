#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>

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
static struct list_head fds = LIST_HEAD_INIT(fds);

#define DEFAULT_LOG_LEVEL L_NOTICE

enum {
	L_CRIT,
	L_WARNING,
	L_NOTICE,
	L_INFO,
	L_DEBUG
};

static int log_level = DEFAULT_LOG_LEVEL;
static const int log_class[] = {
	[L_CRIT] = LOG_CRIT,
	[L_WARNING] = LOG_WARNING,
	[L_NOTICE] = LOG_NOTICE,
	[L_INFO] = LOG_INFO,
	[L_DEBUG] = LOG_DEBUG
};

#ifdef DUMMY_MODE
#define use_syslog false
#else
static bool use_syslog = true;
#endif


static void
netifd_delete_process(struct netifd_process *proc)
{
	if (proc->uloop.pending)
		uloop_process_delete(&proc->uloop);
	list_del(&proc->list);
	netifd_fd_delete(&proc->log_fd);
}

void
netifd_log_message(int priority, const char *format, ...)
{
	va_list vl;

	if (priority > log_level)
		return;

	va_start(vl, format);
	if (use_syslog)
		vsyslog(log_class[priority], format, vl);
	else
		vfprintf(stderr, format, vl);
	va_end(vl);
}

static void
netifd_process_log_cb(struct uloop_fd *fd, unsigned int events)
{
	struct netifd_process *proc;
	const char *log_prefix;
	char *buf, *cur;
	int maxlen, len, read_len;

	proc = container_of(fd, struct netifd_process, log_uloop);

	if (!proc->log_buf)
		proc->log_buf = malloc(LOG_BUF_SIZE + 1);

	buf = proc->log_buf + proc->log_buf_ofs;
	maxlen = LOG_BUF_SIZE - proc->log_buf_ofs;

	log_prefix = proc->log_prefix;
	if (!log_prefix)
		log_prefix = "process";

retry:
	read_len = len = read(fd->fd, buf, maxlen);
	if (len <= 0) {
		if (errno == EINTR)
			goto retry;

		return;
	}
	proc->log_buf_ofs += len;

	cur = buf;
	buf = proc->log_buf;
	while ((cur = memchr(cur, '\n', len))) {
		*cur = 0;

		if (!proc->log_overflow)
			netifd_log_message(L_NOTICE, "%s (%d): %s\n",
				log_prefix, proc->uloop.pid, buf);
		else
			proc->log_overflow = false;

		cur++;
		len -= cur - buf;
		buf = cur;
	}

	if (buf > proc->log_buf && len > 0)
		memmove(buf, proc->log_buf, len);

	if (len == LOG_BUF_SIZE) {
		if (!proc->log_overflow) {
			proc->log_buf[LOG_BUF_SIZE] = 0;
			netifd_log_message(L_NOTICE, "%s (%d): %s [...]\n",
				log_prefix, proc->uloop.pid, proc->log_buf);
			proc->log_overflow = true;
		}
		len = 0;
	}
	proc->log_buf_ofs = len;

	if (read_len == maxlen)
		goto retry;
}

static void
netifd_process_cb(struct uloop_process *proc, int ret)
{
	struct netifd_process *np;
	np = container_of(proc, struct netifd_process, uloop);
	netifd_process_log_cb(&np->log_uloop, 0);
	netifd_delete_process(np);
	return np->cb(np, ret);
}

int
netifd_start_process(const char **argv, char **env, struct netifd_process *proc)
{
	struct netifd_fd *fd;
	int pfds[2];
	int pid;

	netifd_kill_process(proc);

	if (pipe(pfds) < 0)
		return -1;

	if ((pid = fork()) < 0)
		goto error;

	if (!pid) {
		if (env) {
			while (*env) {
				putenv(*env);
				env++;
			}
		}
		if (proc->dir_fd >= 0)
			fchdir(proc->dir_fd);

		/* close all non-essential fds */
		list_for_each_entry(fd, &fds, list) {
			if (fd->proc == proc)
				continue;
			close(fd->fd);
		}

		dup2(pfds[1], 0);
		dup2(pfds[1], 1);
		dup2(pfds[1], 2);

		close(pfds[0]);
		close(pfds[1]);

		execvp(argv[0], (char **) argv);
		exit(127);
	}

	if (pid < 0)
		goto error;

	close(pfds[1]);
	proc->uloop.cb = netifd_process_cb;
	proc->uloop.pid = pid;
	uloop_process_add(&proc->uloop);
	list_add_tail(&proc->list, &process_list);

	proc->log_uloop.fd = proc->log_fd.fd = pfds[0];
	proc->log_uloop.cb = netifd_process_log_cb;
	netifd_fd_add(&proc->log_fd);
	uloop_fd_add(&proc->log_uloop, ULOOP_EDGE_TRIGGER | ULOOP_READ);

	return 0;

error:
	close(pfds[0]);
	close(pfds[1]);
	return -1;
}

void
netifd_kill_process(struct netifd_process *proc)
{
	if (!proc->uloop.pending)
		return;

	kill(proc->uloop.pid, SIGTERM);
	netifd_delete_process(proc);
}

void
netifd_fd_add(struct netifd_fd *fd)
{
	list_add_tail(&fd->list, &fds);
}

void
netifd_fd_delete(struct netifd_fd *fd)
{
	list_del(&fd->list);
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
		" -l <level>:		Log output level (default: %d)\n"
		" -S:			Use stderr instead of syslog for log messages\n"
		"			(default: "DEFAULT_HOTPLUG_PATH")\n"
		"\n", progname, main_path, DEFAULT_LOG_LEVEL);

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

	s.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &s, NULL);
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

	while ((ch = getopt(argc, argv, "d:s:p:h:r:l:S")) != -1) {
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
		case 'l':
			log_level = atoi(optarg);
			if (log_level >= ARRAY_SIZE(log_class))
				log_level = ARRAY_SIZE(log_class) - 1;
			break;
#ifndef DUMMY_MODE
		case 'S':
			use_syslog = false;
			break;
#endif
		default:
			return usage(argv[0]);
		}
	}

	if (use_syslog)
		openlog("netifd", 0, LOG_DAEMON);

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

	if (use_syslog)
		closelog();

	return 0;
}
