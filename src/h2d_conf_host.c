#include "h2d_main.h"

void h2d_conf_host_stats(struct h2d_conf_host *conf_host, wuy_json_ctx_t *json)
{
	struct h2d_conf_host_stats *stats = conf_host->stats;
	wuy_json_object_int(json, "fail_no_path", atomic_load(&stats->fail_no_path));
}

static int h2d_conf_host_name(void *data, char *buf, int size)
{
	struct h2d_conf_host *conf_host = data;
	if (conf_host->hostnames == NULL) {
		return 0;
	}
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

	if (conf_host->name == NULL) {
		conf_host->name = conf_host->hostnames ? conf_host->hostnames[0] : "_default";
	}

	conf_host->stats = wuy_shmem_alloc(sizeof(struct h2d_conf_host_stats));

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
		.is_extra_commands = true,
	},
	{	.name = "_default_next",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_host, default_path),
		.u.table = &h2d_conf_path_table,
	},
	{	.name = "name",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_conf_host, name),
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
