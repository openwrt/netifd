/*
 * netifd - network interface daemon
 * Copyright (C) 2012-2013 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE
#include <glob.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "netifd.h"
#include "system.h"
#include "handler.h"

static int
netifd_dir_push(int fd)
{
	int prev_fd = open(".", O_RDONLY | O_DIRECTORY);
	system_fd_set_cloexec(prev_fd);
	if (fd >= 0)
		fchdir(fd);
	return prev_fd;
}

static void
netifd_dir_pop(int prev_fd)
{
	fchdir(prev_fd);
	close(prev_fd);
}

int netifd_open_subdir(const char *name)
{
	int prev_dir;
	int ret = -1;

	prev_dir = netifd_dir_push(-1);
	if (chdir(main_path)) {
		perror("chdir(main path)");
		goto out;
	}

	ret = open(name, O_RDONLY | O_DIRECTORY);
	if (ret >= 0)
		system_fd_set_cloexec(ret);

out:
	netifd_dir_pop(prev_dir);
	return ret;
}

static void
netifd_init_script_handler(const char *name, script_dump_cb cb)
{
	struct json_tokener *tok = NULL;
	json_object *obj;
	static char buf[512];
	char *start, *cmd;
	FILE *f;
	int len;

#define DUMP_SUFFIX	" '' dump"

	cmd = alloca(strlen(name) + 1 + sizeof(DUMP_SUFFIX));
	sprintf(cmd, "%s" DUMP_SUFFIX, name);

	f = popen(cmd, "r");
	if (!f)
		return;

	do {
		start = fgets(buf, sizeof(buf), f);
		if (!start)
			continue;

		len = strlen(start);

		if (!tok)
			tok = json_tokener_new();

		obj = json_tokener_parse_ex(tok, start, len);
		if (!is_error(obj)) {
			cb(name, obj);
			json_object_put(obj);
			json_tokener_free(tok);
			tok = NULL;
		} else if (start[len - 1] == '\n') {
			json_tokener_free(tok);
			tok = NULL;
		}
	} while (!feof(f) && !ferror(f));

	if (tok)
		json_tokener_free(tok);

	pclose(f);
}

void netifd_init_script_handlers(int dir_fd, script_dump_cb cb)
{
	glob_t g;
	int i, prev_fd;

	prev_fd = netifd_dir_push(dir_fd);
	glob("./*.sh", 0, NULL, &g);
	for (i = 0; i < g.gl_pathc; i++)
		netifd_init_script_handler(g.gl_pathv[i], cb);
	netifd_dir_pop(prev_fd);
}
