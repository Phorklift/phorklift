#include "h2d_main.h"

struct h2d_conf_path *h2d_conf_host_search_pathname(
		struct h2d_conf_host *conf_host, const char *name)
{
	struct h2d_conf_path *conf_path;
	wuy_array_iter_ppval(&conf_host->paths, conf_path) {
		const char *pathname;
		wuy_array_iter_ppval(&conf_path->pathnames, pathname) {
			if (memcmp(pathname, name, strlen(pathname)) == 0) {
				return conf_path;
			}
		}
	}
	return NULL;
}

static bool h2d_conf_host_post(void *data)
{
	struct h2d_conf_host *conf_host = data;

	if (wuy_array_count(&conf_host->paths) == 0) {
		printf("No path is defined in host\n");
		return false;
	}

	/* ssl */
	const char *cert = conf_host->ssl.certificate;
	const char *pkey = conf_host->ssl.private_key;
	if (cert[0] != '\0' || pkey[0] != '\0') {
		conf_host->ssl.ctx = h2d_ssl_ctx_new_server(cert, pkey);
		if (conf_host->ssl.ctx == NULL) {
			printf("fail in load certificate or private_key: %s %s\n", cert, pkey);
			return false;
		}
	}

	return true;
}

static struct wuy_cflua_command h2d_conf_host_ssl_commands[] = {
	{	.name = "certificate",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_conf_host, ssl.certificate),
	},
	{	.name = "private_key",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_conf_host, ssl.private_key),
	},
	{	.name = "ticket_secret",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_conf_host, ssl.ticket_secret),
	},
	{	.name = "ticket_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_host, ssl.ticket_timeout),
	},
	{ NULL }
};

static struct wuy_cflua_command h2d_conf_host_commands[] = {
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_host, paths),
		.u.table = &h2d_conf_path_table,
	},
	{	.name = "_hostnames",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_host, hostnames),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.name = "ssl",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_host, ssl),
		.u.table = &(struct wuy_cflua_table) { h2d_conf_host_ssl_commands },
	},
	{	.type = WUY_CFLUA_TYPE_END,
		.u.next = h2d_module_next_host_command,
	},
};

struct wuy_cflua_table h2d_conf_host_table = {
	.commands = h2d_conf_host_commands,
	.size = sizeof(struct h2d_conf_host),
	.post = h2d_conf_host_post,
};
