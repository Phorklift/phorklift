#include "h2d_main.h"

static int h2d_conf_runtime_name(void *data, char *buf, int size)
{
	return snprintf(buf, size, "Runtime>");
}

static const char *h2d_conf_runtime_worker_post(void *data)
{
	struct h2d_conf_runtime_worker *worker = data;

	if (worker->num < 0) {
		return WUY_CFLUA_OK;
	}
	if (worker->num == 0) {
		worker->num = sysconf(_SC_NPROCESSORS_ONLN);
		if (worker->num <= 0) {
			return "fail to get #CPU";
		}
	}

	return WUY_CFLUA_OK;
}

static const char *h2d_conf_runtime_post(void *data)
{
	struct h2d_conf_runtime *conf_runtime = data;
	conf_runtime->log->is_line_buffer = true;
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_conf_runtime_worker_commands[] = {
	{	.type = WUY_CFLUA_TYPE_INTEGER,
		.is_single_array = true,
		.offset = offsetof(struct h2d_conf_runtime_worker, num),
	},
	{ NULL },
};
static struct wuy_cflua_table h2d_conf_runtime_worker_table = {
	.commands = h2d_conf_runtime_worker_commands,
	.post = h2d_conf_runtime_worker_post,
};

static struct wuy_cflua_command h2d_conf_runtime_commands[] = {
	{	.name = "worker",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_runtime, worker),
		.u.table = &h2d_conf_runtime_worker_table,
	},
	{	.name = "resolver",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_runtime, resolver),
		.u.table = &h2d_conf_runtime_resolver_table,
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_runtime, log),
		.u.table = &h2d_log_conf_table,
	},
	{ NULL },
};

struct wuy_cflua_table h2d_conf_runtime_table = {
	.commands = h2d_conf_runtime_commands,
	.size = sizeof(struct h2d_conf_runtime),
	.name = h2d_conf_runtime_name,
	.post = h2d_conf_runtime_post,
};
