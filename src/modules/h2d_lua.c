#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

struct h2d_lua_conf {
	wuy_cflua_function_t	content;
	wuy_cflua_function_t	before_host;
	wuy_cflua_function_t	req_headers;
	wuy_cflua_function_t	req_body;
	wuy_cflua_function_t	resp_headers;
	wuy_cflua_function_t	resp_body;
};

struct h2d_lua_ctx {
	uint8_t 		*body_buf;
	size_t			body_len;
};

struct h2d_module h2d_lua_module;

static int h2d_lua_generate_response_headers(struct h2d_request *r)
{
	struct h2d_lua_conf *conf = r->conf_path->module_confs[h2d_lua_module.index];
	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];

	if (ctx == NULL) {
		ctx = wuy_pool_alloc(r->pool, sizeof(struct h2d_lua_ctx));
		r->module_ctxs[h2d_lua_module.index] = ctx;
	}

	lua_State *L = h2d_lua_thread_run(r, conf->content, NULL);
	if (!H2D_PTR_IS_OK(L)) {
		return H2D_PTR2RET(L);
	}

	const char *data = lua_tolstring(L, -1, &ctx->body_len);
	if (data == NULL) {
		h2d_request_log(r, H2D_LOG_ERROR, "content fail");
		return WUY_HTTP_500;
	}

	ctx->body_buf = wuy_pool_strndup(r->pool, data, ctx->body_len);

	r->resp.status_code = WUY_HTTP_200;
	r->resp.content_length = ctx->body_len;
	return H2D_OK;
}
static int h2d_lua_generate_response_body(struct h2d_request *r, uint8_t *buf, int len)
{
	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];
	memcpy(buf, ctx->body_buf, ctx->body_len);
	return ctx->body_len;
}

/* configuration */

static struct wuy_cflua_command h2d_lua_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_FUNCTION,
		.is_single_array = true,
		.offset = offsetof(struct h2d_lua_conf, content),
	},
	{	.name = "before_host",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, before_host),
	},
	{	.name = "req_headers",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, req_headers),
	},
	{	.name = "req_body",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, req_body),
	},
	{	.name = "resp_headers",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, resp_headers),
	},
	{	.name = "resp_body",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, resp_body),
	},
	{ NULL }
};
struct h2d_module h2d_lua_module = {
	.name = "lua",
	.command_path = {
		.name = "lua",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_lua_conf_commands,
			.size = sizeof(struct h2d_lua_conf),
		}
	},

	.content = {
		.response_headers = h2d_lua_generate_response_headers,
		.response_body = h2d_lua_generate_response_body,
	},
};
