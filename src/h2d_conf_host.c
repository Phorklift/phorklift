#include "h2d_main.h"

struct h2d_conf_path *h2d_conf_host_search_pathname(
		struct h2d_conf_host *conf_host, const char *name)
{
	if (conf_host->paths == NULL) {
		return conf_host->default_path;
	}

	struct h2d_conf_path *conf_path;
	for (int i = 0; (conf_path = conf_host->paths[i]) != NULL; i++) {
		char *pathname;
		for (int j = 0; (pathname = conf_path->pathnames[j]) != NULL; j++) {
			if (memcmp(pathname, name, strlen(pathname)) == 0) {
				return conf_path;
			}
		}
	}
	return NULL;
}

static int h2d_conf_host_name(void *data, char *buf, int size)
{
	struct h2d_conf_host *conf_host = data;
	return snprintf(buf, size, "Host(%s)>", conf_host->hostnames[0]);
}

static bool h2d_conf_host_post(void *data)
{
	struct h2d_conf_host *conf_host = data;

	if (conf_host->paths == NULL /* no Path() */
			&& conf_host->hostnames != NULL /* not default_host */
			&& conf_host->default_path->content == NULL) { /* default_path->content not set */
		printf("No path is defined in host\n");
		return false;
	}

	return true;
}

static struct wuy_cflua_command h2d_conf_host_commands[] = {
	{	.name = "_hostnames",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_host, hostnames),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_host, paths),
		.u.table = &h2d_conf_path_table,
	},
	{	.name = "_default_next",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_host, default_path),
		.u.table = &h2d_conf_path_table,
	},
	{	.name = "ssl",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_host, ssl),
		.u.table = &h2d_ssl_conf_table,
	},
	{	.type = WUY_CFLUA_TYPE_END,
		.u.next = h2d_module_next_host_command,
	},
};

struct wuy_cflua_table h2d_conf_host_table = {
	.commands = h2d_conf_host_commands,
	.size = sizeof(struct h2d_conf_host),
	.post = h2d_conf_host_post,
	.name = h2d_conf_host_name,
};
