#include <dirent.h>
#include "h2d_main.h"

struct h2d_save_to_conf {
	const char	*pathname;
	int		max_length;
	int		default_expire;
	int		*status_codes;
	struct h2d_log	*log;
};

struct h2d_save_to_ctx {
	void		*buffer;
	size_t		buf_size;
	size_t		length;
	time_t		expire_after;

	struct h2d_request	*subr;
};

#define _log(level, fmt, ...) h2d_request_log_at(r, \
		conf->log, level, "save_to: " fmt, ##__VA_ARGS__)

#define _log_conf(level, fmt, ...) h2d_log_level(conf->log, \
		level, "save_to: " fmt, ##__VA_ARGS__)

struct h2d_module h2d_save_to_module;

static void h2d_save_to_ctx_free(struct h2d_request *r)
{
	struct h2d_save_to_ctx *ctx = r->module_ctxs[h2d_save_to_module.index];
	if (ctx->subr != NULL) {
		h2d_request_close(ctx->subr); // TODO not need close subr
	}
	free(ctx->buffer);
}

static int h2d_save_to_filter_response_headers(struct h2d_request *r)
{
	struct h2d_save_to_conf *conf = r->conf_path->module_confs[h2d_save_to_module.index];
	if (conf->pathname == NULL) {
		return H2D_OK;
	}
	if (r->resp.status_code != WUY_HTTP_200) { // TODO cache more status_code
		return H2D_OK;
	}

	time_t expire_after = -1;

	struct h2d_header *h;
	h2d_header_iter(&r->resp.headers, h) {
		const char *value = h2d_header_value(h);
		if (strcasecmp(h->str, "Cache-Control") == 0) {
			if (memcmp(value, "max-age=", 8) != 0) {
				return H2D_OK;
			}
			expire_after = atoi(value+8);
		} else if (strcasecmp(h->str, "Expires") == 0) {
			expire_after = wuy_http_date_parse(h2d_header_value(h)) - time(NULL);
		}
	}

	if (expire_after == -1) {
		expire_after = conf->default_expire;
	}
	if (expire_after <= 0) {
		return H2D_OK;
	}

	struct h2d_save_to_ctx *ctx = wuy_pool_alloc(r->pool, sizeof(struct h2d_save_to_ctx));
	ctx->expire_after = expire_after;

	if (r->resp.content_length != H2D_CONTENT_LENGTH_INIT) {
		ctx->buf_size = r->resp.content_length;
		ctx->buffer = malloc(ctx->buf_size); // TODO user pool
	}

	r->module_ctxs[h2d_save_to_module.index] = ctx;
	return H2D_OK;
}

static int h2d_save_to_filter_response_body(struct h2d_request *r,
		uint8_t *data, int data_len, int buf_len, bool *p_is_last)
{
	struct h2d_save_to_conf *conf = r->conf_path->module_confs[h2d_save_to_module.index];
	struct h2d_save_to_ctx *ctx = r->module_ctxs[h2d_save_to_module.index];

	if (ctx == NULL) {
		return data_len;
	}

	if (ctx->length + data_len > ctx->buf_size) {
		ctx->buf_size = ctx->length + data_len;
		ctx->buffer = realloc(ctx->buffer, ctx->buf_size);
	}

	memcpy(ctx->buffer + ctx->length, data, data_len);
	ctx->length += data_len;

	if (*p_is_last && ctx->subr == NULL) {
		ctx->subr = h2d_request_subrequest(r, conf->pathname);
		ctx->subr->req.method = WUY_HTTP_POST;
	}

	return data_len;
}

static struct wuy_cflua_command h2d_save_to_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "The pathname to save to.",
		.is_single_array = true,
		.offset = offsetof(struct h2d_save_to_conf, pathname),
	},
	//{	.name = "expire_time",
		//.type = WUY_CFLUA_TYPE_FUNCTION,
		//.offset = offsetof(struct h2d_save_to_conf, expire_time),
	//},
	{	.name = "default_expire",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_save_to_conf, default_expire),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "max_length",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_save_to_conf, max_length),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "status_codes",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_save_to_conf, status_codes),
		.u.table = WUY_CFLUA_ARRAY_INTEGER_TABLE,
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_save_to_conf, log),
		.u.table = &h2d_log_conf_table,
	},
	{ NULL }
};

struct h2d_module h2d_save_to_module = {
	.name = "save_to",
	.command_path = {
		.name = "save_to",
		.description = "Save the response to some Path by subrequest.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_save_to_conf_commands,
			.size = sizeof(struct h2d_save_to_conf),
		}
	},

	.filters = {
		.response_headers = h2d_save_to_filter_response_headers,
		.response_body = h2d_save_to_filter_response_body,
	},

	.ctx_free = h2d_save_to_ctx_free,
};
