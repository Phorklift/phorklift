#include "h2d_main.h"

void h2d_conf_path_stats(struct h2d_conf_path *conf_path, wuy_json_t *json)
{
	struct h2d_conf_path_stats *stats = conf_path->stats;
	wuy_json_object_int(json, "total", atomic_load(&stats->total));
	wuy_json_object_int(json, "done", atomic_load(&stats->done));
	wuy_json_object_int(json, "req_acc_ms", atomic_load(&stats->req_acc_ms));
	wuy_json_object_int(json, "react_acc_ms", atomic_load(&stats->react_acc_ms));
	wuy_json_object_int(json, "resp_acc_ms", atomic_load(&stats->resp_acc_ms));
	wuy_json_object_int(json, "total_acc_ms", atomic_load(&stats->total_acc_ms));

	wuy_json_object_object(json, "status_codes");
	int c;
#define X(s, _) c = atomic_load(&stats->status_##s); if (c != 0) wuy_json_object_int(json, #s, c);
	WUY_HTTP_STATUS_CODE_TABLE
#undef X
	c = atomic_load(&stats->status_others);
	if (c != 0) {
		wuy_json_object_int(json, "others", c);
	}
	wuy_json_object_close(json);
}

static bool h2d_conf_path_name_match(const char *def, const char *req)
{
	if (req[0] == '@') {
		return strcmp(def, req) == 0;
	}

	switch (def[0]) {
	case '=':
		return strcmp(def + 1, req) == 0;
	case '/':
		return memcmp(def, req, strlen(def)) == 0;
	case '~':
		return wuy_luastr_find2(req, def + 1);
	case '@':
		return false;
	default:
		abort();
	}
}
struct h2d_conf_path *h2d_conf_path_locate(struct h2d_conf_host *conf_host,
		const char *name)
{
	if (conf_host->paths == NULL) {
		return conf_host->default_path;
	}

	struct h2d_conf_path *conf_path;
	for (int i = 0; (conf_path = conf_host->paths[i]) != NULL; i++) {
		char *pathname;
		for (int j = 0; (pathname = conf_path->pathnames[j]) != NULL; j++) {
			if (h2d_conf_path_name_match(pathname, name)) {
				return conf_path;
			}
		}
	}
	return NULL;
}

bool h2d_conf_path_check_overwrite(struct h2d_conf_host *conf_host,
		int stop, const char *pathname)
{
	char first = pathname[0];
	if (first == '~') {
		return false;
	}
	if (first == '=') {
		pathname++;
	}
	for (int i = 0; i < stop; i++) {
		const char *pattern;
		for (int j = 0; (pattern = conf_host->paths[i]->pathnames[j]) != NULL; j++) {
			if (pattern[0] == '=' && first == '/') {
				continue;
			}
			if (h2d_conf_path_name_match(pattern, pathname)) {
				return true;
			}
		}
	}
	return false;
}

static int h2d_conf_path_name(void *data, char *buf, int size)
{
	struct h2d_conf_path *conf_path = data;
	if (conf_path->pathnames == NULL) {
		return 0;
	}
	return snprintf(buf, size, "Path(%s)>", conf_path->pathnames[0]);
}

static const char *h2d_conf_path_post(void *data)
{
	struct h2d_conf_path *conf_path = data;

	if (conf_path->pathnames != NULL) {
		for (int i = 0; conf_path->pathnames[i] != NULL; i++) {
			char first = conf_path->pathnames[i][0];
			if (first != '=' && first != '~' && first != '/' && first != '@') {
				wuy_cflua_post_arg = conf_path->pathnames[i];
				return "pathname must start with '/', '=', '~' or '@'";
			}
		}
	}

	/* there is one and only one content module is enabled */
	int i = 0;
	struct h2d_module *same_level_mod = NULL;
	struct h2d_module *m = NULL;
	while ((m = h2d_module_next(m)) != NULL) {
		void *mod_conf = conf_path->module_confs[i++];
		if (mod_conf == NULL) {
			continue;
		}
		if (m->content.response_headers == NULL) {
			continue;
		}

		bool enabled = (m->content.is_enabled != NULL) ? m->content.is_enabled(mod_conf)
				: h2d_module_command_is_set(&m->command_path, mod_conf);
		if (!enabled) {
			continue;
		}

		if (conf_path->content == NULL) {
			conf_path->content = m;
			continue;
		}

		/* compare inherit_count, pick the smaller */
		int inherit_count_new = conf_path->content_inherit_counts[i-1];
		int inherit_count_old = conf_path->content_inherit_counts[conf_path->content->index];
		if (inherit_count_new == inherit_count_old) {
			same_level_mod = m;
		} else if (inherit_count_new < inherit_count_old) {
			conf_path->content = m;
			same_level_mod = NULL;
		}
	}
	if (same_level_mod != NULL) {
		static char arg[100];
		snprintf(arg, sizeof(arg), "%s, %s", conf_path->content->name, same_level_mod->name);
		wuy_cflua_post_arg = arg;
		return "duplicate content set";
	}

	if (h2d_dynamic_is_enabled(&conf_path->dynamic)) {
		h2d_dynamic_set_container(&conf_path->dynamic, &h2d_conf_path_table);

	} else if (conf_path->content == NULL && conf_path->pathnames != NULL) {
		return "no content set";
	}

	if (conf_path->name == NULL) {
		conf_path->name = conf_path->pathnames ? conf_path->pathnames[0] : "_default";
	}

	conf_path->stats = wuy_shmpool_alloc(sizeof(struct h2d_conf_path_stats));

	return WUY_CFLUA_OK;
}

static const char *h2d_conf_path_access_log_post(void *data)
{
	struct h2d_conf_access_log *log = data;

	if (log->max_line > log->buf_size) {
		return "expect max_line <= buffer_size";
	}
	if (log->filename == NULL) {
		log->filename = "access.log";
	}
	log->file = h2d_log_file_open(log->filename, log->buf_size);
	if (log->file == NULL) {
		wuy_cflua_post_arg = log->filename;
		return "fail in open file";
	}
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_conf_path_access_log_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.offset = offsetof(struct h2d_conf_access_log, filename),
	},
	{	.name = "sampling_rate",
		.type = WUY_CFLUA_TYPE_DOUBLE,
		.offset = offsetof(struct h2d_conf_access_log, sampling_rate),
		.limits.d = WUY_CFLUA_LIMITS(0, 1),
		.default_value.d = 1,
	},
	{	.name = "format",
		.description = "Log more fields.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_conf_access_log, format),
	},
	{	.name = "replace_format",
		.description = "If set, log `format` only; otherwise append `format` after default fields.",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_conf_access_log, replace_format),
	},
	{	.name = "filter",
		.description = "Log requests only if this function returns true.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_conf_access_log, filter),
	},
	{	.name = "enable_subrequest",
		.description = "Whether log subrequest or not.",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_conf_access_log, enable_subrequest),
	},
	{	.name = "buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_access_log, buf_size),
		.limits.n = WUY_CFLUA_LIMITS_LOWER(4 * 1024),
		.default_value.n = 16 * 1024,
	},
	{	.name = "max_line",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_access_log, max_line),
		.default_value.n = 2 * 1024,
	},
	{ NULL },
};

struct wuy_cflua_table h2d_conf_path_access_log_table = {
	.commands = h2d_conf_path_access_log_commands,
	.size = sizeof(struct h2d_conf_access_log),
	.post = h2d_conf_path_access_log_post,
};

static struct wuy_cflua_command h2d_conf_path_commands[] = {
	{	.name = "_pathnames",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_path, pathnames),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.name = "name",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_conf_path, name),
	},
	{	.name = "dynamic",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_path, dynamic),
		.u.table = &h2d_dynamic_conf_table,
	},
	{	.name = "module_filters",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_path, filters),
		.u.table = &h2d_module_filters_conf_table,
	},
	{	.name = "req_body_sync",
		.description = "If set, process the request only after receiving request body complete. "
			"For example if you want to accept a big-file uploading to the server, "
			"set this to false to write the request body to file in stream mode.",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_conf_path, req_body_sync),
		.default_value.b = true,
	},
	{	.name = "req_body_max",
		.description = "Max memory buffer for request body.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_path, req_body_max),
		.default_value.n = 16 * 1024,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "error_log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_path, error_log),
		.u.table = &h2d_log_conf_table,
	},
	{	.name = "access_log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_path, access_log),
		.u.table = &h2d_conf_path_access_log_table,
	},
	{	.type = WUY_CFLUA_TYPE_END,
		.u.next = h2d_module_next_path_command,
	},
};

struct wuy_cflua_table h2d_conf_path_table = {
	.commands = h2d_conf_path_commands,
	.refer_name = "Path",
	.size = sizeof(struct h2d_conf_path),
	.post = h2d_conf_path_post,
	.name = h2d_conf_path_name,
};
