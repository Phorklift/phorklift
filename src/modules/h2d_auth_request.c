#include "h2d_main.h"

struct h2d_auth_request_conf {
	const char	*pathname;
};

struct h2d_module h2d_auth_request_module;

static int h2d_auth_request_process_headers(struct h2d_request *r)
{
	struct h2d_auth_request_conf *conf = r->conf_path->module_confs[h2d_auth_request_module.index];
	if (conf->pathname == NULL) {
		return H2D_OK;
	}

	struct h2d_request *subr = r->module_ctxs[h2d_auth_request_module.index];
	if (subr == NULL) {
		/* first time get in */
		r->module_ctxs[h2d_auth_request_module.index] = h2d_request_subrequest(r, conf->pathname);
		return H2D_AGAIN;
	} else {
		if (subr->resp.status_code == 0) {
			return H2D_AGAIN;
		}
		if (subr->resp.status_code == WUY_HTTP_200) {
			return H2D_OK;
		}
		return WUY_HTTP_401;
	}
}

/* configuration */

static void h2d_auth_request_ctx_free(struct h2d_request *r)
{
	struct h2d_request *subr = r->module_ctxs[h2d_auth_request_module.index];
	h2d_request_close(subr);
}

static const char *h2d_auth_request_conf_post(void *data)
{
	struct h2d_auth_request_conf *conf = data;
	if (conf->pathname == NULL) {
		return WUY_CFLUA_OK;
	}

	char first = conf->pathname[0];
	if (first != '/') {
		return "invalid pathname";
	}

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_auth_request_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.description = "Path name",
		.offset = offsetof(struct h2d_auth_request_conf, pathname),
	},
	{ NULL }
};

struct h2d_module h2d_auth_request_module = {
	.name = "auth_request",
	.command_path = {
		.name = "auth_request",
		.description = "Subrequest authentication filter module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_auth_request_conf_commands,
			.size = sizeof(struct h2d_auth_request_conf),
			.post = h2d_auth_request_conf_post,
		}
	},

	.filters = {
		.process_headers = h2d_auth_request_process_headers,
	},

	.ctx_free = h2d_auth_request_ctx_free,
};
