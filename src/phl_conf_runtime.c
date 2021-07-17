#include "phl_main.h"
#include <sys/types.h>
#include <pwd.h>

static int phl_conf_runtime_name(void *data, char *buf, int size)
{
	return snprintf(buf, size, "Runtime>");
}

static const char *phl_conf_runtime_worker_post(void *data)
{
	struct phl_conf_runtime_worker *worker = data;

	if (worker->num < 0) {
		return WUY_CFLUA_OK;
	}
	if (worker->num == 0) {
		worker->num = sysconf(_SC_NPROCESSORS_ONLN);
		if (worker->num <= 0) {
			return "fail to get #CPU";
		}
	}

	if (geteuid() == 0) {
		struct passwd *pwd = getpwnam(worker->user != NULL ? worker->user : "nobody");
		if (pwd == NULL) {
			return "fail to get worker user-id";
		}
		worker->uid = pwd->pw_uid;
	} else if (worker->user != NULL) {
		return "only root can change worker's user";
	}

	return WUY_CFLUA_OK;
}

static const char *phl_conf_runtime_post(void *data)
{
	struct phl_conf_runtime *conf_runtime = data;
	conf_runtime->error_log->is_line_buffer = true;
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_conf_runtime_worker_commands[] = {
	{	.type = WUY_CFLUA_TYPE_INTEGER,
		.description = "Worker process number. "
			"Set 0 for #CPU. Set -1 to disable master-worker mode.",
		.is_single_array = true,
		.offset = offsetof(struct phl_conf_runtime_worker, num),
	},
	{	.name = "user",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_conf_runtime_worker, user),
	},
	{ NULL },
};
static struct wuy_cflua_table phl_conf_runtime_worker_table = {
	.commands = phl_conf_runtime_worker_commands,
	.post = phl_conf_runtime_worker_post,
};

static struct wuy_cflua_command phl_conf_runtime_commands[] = {
	{	.name = "pid",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_conf_runtime, pid),
		.default_value.s = "phorklift.pid",
	},
	{	.name = "worker",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_conf_runtime, worker),
		.u.table = &phl_conf_runtime_worker_table,
	},
	{	.name = "resolver",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_conf_runtime, resolver),
		.u.table = &phl_conf_runtime_resolver_table,
	},
	{	.name = "dynamic_modules",
		.description = "Dynamic request module list.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_conf_runtime, dynamic_modules),
		.u.table = &phl_module_dynamic_table,
	},
	{	.name = "dynamic_upstream_modules",
		.description = "Dynamic upstream loadbalance module list.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_conf_runtime, dynamic_upstream_modules),
		.u.table = &phl_module_dynamic_upstream_table,
	},
	{	.name = "error_log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_conf_runtime, error_log),
		.u.table = &phl_log_conf_table,
	},
	{ NULL },
};

struct wuy_cflua_table phl_conf_runtime_table = {
	.commands = phl_conf_runtime_commands,
	.size = sizeof(struct phl_conf_runtime),
	.name = phl_conf_runtime_name,
	.post = phl_conf_runtime_post,
};
