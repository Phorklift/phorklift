#include "phl_main.h"

struct phl_rewrite_conf {
	const char	**strs;
	int		num;
};

struct phl_module phl_rewrite_module;

static int phl_rewrite_process_headers(struct phl_request *r)
{
	struct phl_rewrite_conf *conf = r->conf_path->module_confs[phl_rewrite_module.index];
	if (conf->strs == NULL) {
		return PHL_OK;
	}

	for (int i = 0; i < conf->num; i += 2) {
		const char *pattern = conf->strs[i];
		const char *repl = conf->strs[i + 1];
		const char *new = wuy_luastr_gsub(r->req.uri.path, pattern, repl);
		if (new != NULL) {
			printf("rewrite %s %s\n", r->req.uri.path, new);
			r->req.uri.path = wuy_pool_strdup(r->pool, new);
			r->req.uri.is_rewrited = true;
			break;
		}
	}

	return PHL_OK;
}

static const char *phl_rewrite_conf_post(void *data)
{
	struct phl_rewrite_conf *conf = data;

	if (conf->strs == NULL) {
		return WUY_CFLUA_OK;
	}
	if ((conf->num % 2) != 0) {
		return "rewrite rules: (pattern, repl)*";
	}
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_rewrite_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "Rewrite rules list.",
		.offset = offsetof(struct phl_rewrite_conf, strs),
		.array_number_offset = offsetof(struct phl_rewrite_conf, num),
	},
	{ NULL }
};

struct phl_module phl_rewrite_module = {
	.name = "rewrite",
	.command_path = {
		.name = "rewrite",
		.description = "URL rewrite filter module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_rewrite_conf_commands,
			.size = sizeof(struct phl_rewrite_conf),
			.post = phl_rewrite_conf_post,
		}
	},

	.filters = {
		.process_headers = phl_rewrite_process_headers,
	},
};
