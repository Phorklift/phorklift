#include <dirent.h>
#include "phl_main.h"

struct phl_save_to_conf {
	const char	*pathname;
	int		max_length;
	int		default_expire;
	int		*status_codes;
	struct phl_log	*log;
};

struct phl_save_to_ctx {
	void		*buffer;
	size_t		buf_size;
	size_t		length;
	time_t		expire_after;
};

#define _log(level, fmt, ...) phl_request_log_at(r, \
		conf->log, level, "save_to: " fmt, ##__VA_ARGS__)

#define _log_conf(level, fmt, ...) phl_log_level(conf->log, \
		level, "save_to: " fmt, ##__VA_ARGS__)

struct phl_module phl_save_to_module;

static int phl_save_to_filter_response_headers(struct phl_request *r)
{
	struct phl_save_to_conf *conf = r->conf_path->module_confs[phl_save_to_module.index];
	if (conf->pathname == NULL) {
		return PHL_OK;
	}
	if (r->resp.status_code != WUY_HTTP_200) { // TODO cache more status_code
		return PHL_OK;
	}

	time_t expire_after = -1;

	struct phl_header *h;
	phl_header_iter(&r->resp.headers, h) {
		const char *value = phl_header_value(h);
		if (strcasecmp(h->str, "Cache-Control") == 0) {
			if (memcmp(value, "max-age=", 8) != 0) {
				return PHL_OK;
			}
			expire_after = atoi(value+8);
		} else if (strcasecmp(h->str, "Expires") == 0) {
			expire_after = wuy_http_date_parse(phl_header_value(h)) - time(NULL);
		}
	}

	if (expire_after == -1) {
		expire_after = conf->default_expire;
	}
	if (expire_after <= 0) {
		return PHL_OK;
	}

	struct phl_save_to_ctx *ctx = wuy_pool_alloc(r->pool, sizeof(struct phl_save_to_ctx));
	ctx->expire_after = expire_after;

	if (r->resp.content_length != PHL_CONTENT_LENGTH_INIT) {
		ctx->buf_size = r->resp.content_length;
		ctx->buffer = wuy_pool_realloc(r->pool, NULL, ctx->buf_size);
	}

	r->module_ctxs[phl_save_to_module.index] = ctx;
	return PHL_OK;
}

static int phl_save_to_filter_response_body(struct phl_request *r,
		uint8_t *data, int data_len, int buf_len, bool *p_is_last)
{
	struct phl_save_to_conf *conf = r->conf_path->module_confs[phl_save_to_module.index];
	struct phl_save_to_ctx *ctx = r->module_ctxs[phl_save_to_module.index];

	if (ctx == NULL) {
		return data_len;
	}

	if (ctx->length + data_len > ctx->buf_size) {
		ctx->buf_size = ctx->length + data_len;
		ctx->buffer = wuy_pool_realloc(r->pool, ctx->buffer, ctx->buf_size);
	}

	memcpy(ctx->buffer + ctx->length, data, data_len);
	ctx->length += data_len;

	if (*p_is_last) {
		struct phl_request *subr = phl_request_subr_new(r, conf->pathname);
		phl_request_subr_detach(subr);

		subr->req.method = WUY_HTTP_POST;
		subr->req.body_buf = (uint8_t *)wuy_pool_strndup(subr->pool, ctx->buffer, ctx->buf_size);
		subr->req.body_len = ctx->buf_size;
	}

	return data_len;
}

static struct wuy_cflua_command phl_save_to_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "The pathname to save to.",
		.is_single_array = true,
		.offset = offsetof(struct phl_save_to_conf, pathname),
	},
	//{	.name = "expire_time",
		//.type = WUY_CFLUA_TYPE_FUNCTION,
		//.offset = offsetof(struct phl_save_to_conf, expire_time),
	//},
	{	.name = "default_expire",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_save_to_conf, default_expire),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "max_length",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_save_to_conf, max_length),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "status_codes",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_save_to_conf, status_codes),
		.u.table = WUY_CFLUA_ARRAY_INTEGER_TABLE,
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_save_to_conf, log),
		.u.table = &phl_log_omit_conf_table,
	},
	{ NULL }
};

struct phl_module phl_save_to_module = {
	.name = "save_to",
	.command_path = {
		.name = "save_to",
		.description = "Save the response to some Path by subrequest.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_save_to_conf_commands,
			.size = sizeof(struct phl_save_to_conf),
		}
	},

	.filters = {
		.response_headers = phl_save_to_filter_response_headers,
		.response_body = phl_save_to_filter_response_body,
	},
};
