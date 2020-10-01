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
	lua_State		*L;
	uint8_t 		*resp_body_buf;
	size_t			resp_body_len;
};

struct h2d_module h2d_lua_module;

static int h2d_lua_generate_response_headers(struct h2d_request *r)
{
	struct h2d_lua_conf *conf = r->conf_path->module_confs[h2d_lua_module.index];
	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];

	if (ctx == NULL) {
		ctx = calloc(1, sizeof(struct h2d_lua_ctx));
		ctx->L = h2d_lua_api_thread_new(conf->content);
		ctx->resp_body_buf = malloc(4096); // TODO
		r->module_ctxs[h2d_lua_module.index] = ctx;
	}

	int ret = h2d_lua_api_thread_resume(ctx->L, r);
	if (ret != H2D_OK) {
		return ret;
	}

	const char *data = lua_tolstring(ctx->L, -1, &ctx->resp_body_len);
	if (data == NULL) {
		return WUY_HTTP_500;
	}

	memcpy(ctx->resp_body_buf, data, ctx->resp_body_len);
	r->resp.status_code = WUY_HTTP_200;
	r->resp.content_length = ctx->resp_body_len;
	return H2D_OK;
}
static int h2d_lua_generate_response_body(struct h2d_request *r, uint8_t *buf, int len)
{
	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];
	memcpy(buf, ctx->resp_body_buf, ctx->resp_body_len);
	return ctx->resp_body_len;
}

static void h2d_lua_ctx_free(struct h2d_request *r)
{
	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];
	free(ctx->resp_body_buf);
	h2d_lua_api_thread_free(ctx->L);
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

	.ctx_free = h2d_lua_ctx_free,
};
