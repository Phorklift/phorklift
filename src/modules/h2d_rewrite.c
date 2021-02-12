#include "h2d_main.h"

struct h2d_rewrite_conf {
	const char	**strs;
	int		num;
};

struct h2d_module h2d_rewrite_module;

static int h2d_rewrite_process_headers(struct h2d_request *r)
{
	struct h2d_rewrite_conf *conf = r->conf_path->module_confs[h2d_rewrite_module.index];
	if (conf->strs == NULL) {
		return H2D_OK;
	}

	for (int i = 0; i < conf->num; i += 2) {
		const char *pattern = conf->strs[i];
		const char *repl = conf->strs[i + 1];
		const char *new = h2d_lua_api_str_gsub(r->req.uri.path, pattern, repl);
		if (new != NULL) {
			printf("rewrite %s %s\n", r->req.uri.path, new);
			r->req.uri.path = wuy_pool_strdup(r->pool, new);
			r->req.uri.is_rewrited = true;
			break;
		}
	}

	return H2D_OK;
}

static const char *h2d_rewrite_conf_post(void *data)
{
	struct h2d_rewrite_conf *conf = data;

	if (conf->strs == NULL) {
		return WUY_CFLUA_OK;
	}
	if ((conf->num % 2) != 0) {
		return "rewrite rules: (pattern, repl)*";
	}
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_rewrite_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "Rewrite rules list.",
		.offset = offsetof(struct h2d_rewrite_conf, strs),
		.array_number_offset = offsetof(struct h2d_rewrite_conf, num),
	},
	{ NULL }
};

struct h2d_module h2d_rewrite_module = {
	.name = "rewrite",
	.command_path = {
		.name = "rewrite",
		.description = "URL rewrite filter module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_rewrite_conf_commands,
			.size = sizeof(struct h2d_rewrite_conf),
			.post = h2d_rewrite_conf_post,
		}
	},

	.filters = {
		.process_headers = h2d_rewrite_process_headers,
	},
};
