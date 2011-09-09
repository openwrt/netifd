#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <glob.h>
#include <unistd.h>
#include <fcntl.h>

#include <libubox/blobmsg_json.h>

#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"

static LIST_HEAD(handlers);
static int proto_fd, main_fd;

struct proto_shell_handler {
	struct list_head list;
	struct proto_handler proto;
};

#define DUMP_PREFIX	"./"
#define DUMP_SUFFIX	" dump"

static void proto_shell_add_handler(const char *script, struct json_object *obj)
{
	if (json_object_get_type(obj) != json_type_object)
		return;

	fprintf(stderr, "Add handler for script %s: %s\n", script, json_object_to_json_string(obj));
}

static void proto_shell_add_script(const char *name)
{
	struct json_tokener *tok = NULL;
	struct json_object *obj;
	static char buf[512];
	char *start, *end, *cmd;
	FILE *f;
	int buflen, len;

	cmd = alloca(strlen(name) + 1 + sizeof(DUMP_PREFIX) + sizeof(DUMP_SUFFIX));
	sprintf(cmd, DUMP_PREFIX "%s" DUMP_SUFFIX, name);

	f = popen(cmd, "r");
	if (!f)
		return;

	do {
		buflen = fread(buf, 1, sizeof(buf) - 1, f);
		if (buflen <= 0)
			continue;

		start = buf;
		len = buflen;
		do {
			end = memchr(start, '\n', len);
			if (end)
				len = end - start;

			if (!tok)
				tok = json_tokener_new();

			obj = json_tokener_parse_ex(tok, start, len);
			if (!is_error(obj)) {
				proto_shell_add_handler(name, obj);
				json_object_put(obj);
				json_tokener_free(tok);
				tok = NULL;
			}

			if (end) {
				start = end + 1;
				len = buflen - (start - buf);
			}
		} while (len > 0);
	} while (!feof(f) && !ferror(f));

	if (tok)
		json_tokener_free(tok);

	pclose(f);
}

void __init proto_shell_init(void)
{
	glob_t g;
	int i;

	main_fd = open(".", O_RDONLY | O_DIRECTORY);
	if (main_fd < 0)
		return;

	if (chdir(main_path)) {
		perror("chdir(main path)");
		goto close_cur;
	}

	if (chdir("./proto"))
		goto close_cur;

	proto_fd = open(".", O_RDONLY | O_DIRECTORY);
	if (proto_fd < 0)
		goto close_cur;

	glob("*.sh", 0, NULL, &g);
	for (i = 0; i < g.gl_pathc; i++)
		proto_shell_add_script(g.gl_pathv[i]);

	if (list_empty(&handlers))
		close(proto_fd);

close_cur:
	fchdir(main_fd);
	if (list_empty(&handlers))
		close(main_fd);
}
