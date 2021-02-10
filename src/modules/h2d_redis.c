#include "h2d_main.h"

struct h2d_redis_conf {
	struct h2d_upstream_conf	*upstream;
	wuy_cflua_function_t		query;
};

struct h2d_module h2d_redis_module;

static int h2d_redis_build_request(struct h2d_request *r)
{
	struct h2d_redis_conf *conf = r->conf_path->module_confs[h2d_redis_module.index];
	struct h2d_upstream_content_ctx *ctx = r->module_ctxs[h2d_redis_module.index];

	const char *query;
	if (wuy_cflua_is_function_set(conf->query)) {
		query = h2d_lua_api_call_lstring(r, conf->query, &ctx->req_len);
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
	return H2D_OK;
}

static struct h2d_upstream_ops h2d_redis_upstream_ops = {
	.build_request = h2d_redis_build_request,
};

static const char *h2d_redis_conf_post(void *data)
{
	struct h2d_redis_conf *conf = data;
	return h2d_upstream_content_set_ops(conf->upstream, &h2d_redis_upstream_ops);
}

static struct wuy_cflua_command h2d_redis_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.is_single_array = true,
		.offset = offsetof(struct h2d_redis_conf, upstream),
		.u.table = &h2d_upstream_conf_table,
	},
	{	.name = "query",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_redis_conf, query),
	},
	{ NULL }
};

struct h2d_module h2d_redis_module = {
	.name = "redis",
	.command_path = {
		.name = "redis",
		.description = "Redis module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_redis_conf_commands,
			.size = sizeof(struct h2d_redis_conf),
			.post = h2d_redis_conf_post,
		}
	},
	.content = H2D_UPSTREAM_CONTENT,
	.ctx_free = h2d_upstream_content_ctx_free,
};
