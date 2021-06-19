#include "phl_main.h"

struct phl_redis_conf {
	struct phl_upstream_conf	*upstream;
	wuy_cflua_function_t		query;
};

struct phl_module phl_redis_module;

static int phl_redis_build_request(struct phl_request *r)
{
	struct phl_redis_conf *conf = r->conf_path->module_confs[phl_redis_module.index];
	struct phl_upstream_content_ctx *ctx = r->module_ctxs[phl_redis_module.index];

	const char *query;
	if (wuy_cflua_is_function_set(conf->query)) {
		query = phl_lua_call_lstring(r, conf->query, &ctx->req_len);
		if (query == NULL) {
			return r->resp.status_code ? r->resp.status_code : WUY_HTTP_500;
		}

	} else { /* use querystring:"q" */
		char q[r->req.uri.query_len];
		ctx->req_len = wuy_http_uri_query_get(r->req.uri.query_pos,
				r->req.uri.query_len, "q", 1, q);
		if (ctx->req_len <= 0) {
			return WUY_HTTP_400;
		}
		q[ctx->req_len++] = '\r';
		q[ctx->req_len++] = '\n';
		query = q;
	}

	ctx->req_buf = wuy_pool_alloc(r->pool, ctx->req_len);
	memcpy(ctx->req_buf, query, ctx->req_len);
	return PHL_OK;
}

static int phl_redis_parse_response_headers(struct phl_request *r,
		const char *buffer, int buf_len, bool *is_done)
{
	*is_done = true;

	if (buffer[0] == '-') {
		r->resp.status_code = WUY_HTTP_500;
		return 1;
	}

	if (memcmp(buffer, "$-1\r\n", 5) == 0) {
		r->resp.status_code = WUY_HTTP_404;
		return 5;
	}

	r->resp.status_code = WUY_HTTP_200;
	return 0;
}

static struct phl_upstream_ops phl_redis_upstream_ops = {
	.build_request = phl_redis_build_request,
	.parse_response_headers = phl_redis_parse_response_headers,
};

static const char *phl_redis_conf_post(void *data)
{
	struct phl_redis_conf *conf = data;
	return phl_upstream_content_set_ops(conf->upstream, &phl_redis_upstream_ops);
}

static struct wuy_cflua_command phl_redis_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.is_single_array = true,
		.offset = offsetof(struct phl_redis_conf, upstream),
		.u.table = &phl_upstream_conf_table,
	},
	{	.name = "query",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_redis_conf, query),
	},
	{ NULL }
};

struct phl_module phl_redis_module = {
	.name = "redis",
	.command_path = {
		.name = "redis",
		.description = "Redis module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_redis_conf_commands,
			.size = sizeof(struct phl_redis_conf),
			.post = phl_redis_conf_post,
		}
	},
	.content = PHL_UPSTREAM_CONTENT,
	.ctx_free = phl_upstream_content_ctx_free,
};
