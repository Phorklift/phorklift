#include "phl_main.h"

struct phl_auth_request_conf {
	const char	*pathname;
};

struct phl_module phl_auth_request_module;

static int phl_auth_request_process_headers(struct phl_request *r)
{
	struct phl_auth_request_conf *conf = r->conf_path->module_confs[phl_auth_request_module.index];
	if (conf->pathname == NULL) {
		return H2D_OK;
	}

	struct phl_request *subr = r->module_ctxs[phl_auth_request_module.index];
	if (subr == NULL) { /* first time get in */
		subr = phl_request_subr_new(r, conf->pathname);
		phl_header_dup_list(&subr->req.headers, &r->req.headers, r->pool);
		// TODO req-body
		// subr->req.method = r->req.method;

		r->module_ctxs[phl_auth_request_module.index] = subr;
		return H2D_AGAIN;
	}

	struct phl_header *h;
	switch (subr->resp.status_code) {
	case 0:
		return H2D_AGAIN;
	case WUY_HTTP_200:
		phl_request_subr_close(subr);
		r->module_ctxs[phl_auth_request_module.index] = NULL;
		return H2D_OK;
	case WUY_HTTP_401:
		phl_header_iter(&subr->resp.headers, h) {
			if (strcasecmp(h->str, "WWW-Authenticate") == 0) {
				phl_header_add(&r->resp.headers, "WWW-Authenticate", 16,
						phl_header_value(h), h->value_len, r->pool);
				break;
			}
		}
		return WUY_HTTP_401;
	case WUY_HTTP_403:
		return WUY_HTTP_403;
	default:
		return H2D_ERROR;
	}
}

/* configuration */

static const char *phl_auth_request_conf_post(void *data)
{
	struct phl_auth_request_conf *conf = data;
	if (conf->pathname == NULL) {
		return WUY_CFLUA_OK;
	}

	char first = conf->pathname[0];
	if (first != '/') {
		return "invalid pathname";
	}

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_auth_request_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.description = "Path name",
		.offset = offsetof(struct phl_auth_request_conf, pathname),
	},
	{ NULL }
};

struct phl_module phl_auth_request_module = {
	.name = "auth_request",
	.command_path = {
		.name = "auth_request",
		.description = "Subrequest authentication filter module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_auth_request_conf_commands,
			.size = sizeof(struct phl_auth_request_conf),
			.post = phl_auth_request_conf_post,
		}
	},

	.filters = {
		.process_headers = phl_auth_request_process_headers,
	},
};
