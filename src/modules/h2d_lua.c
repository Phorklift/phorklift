#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "h2d_main.h"

struct h2d_lua_conf {
	wuy_cflua_function_t	content;
	wuy_cflua_function_t	before_host;
	wuy_cflua_function_t	req_headers;
	wuy_cflua_function_t	req_body;
	wuy_cflua_function_t	resp_headers;
	wuy_cflua_function_t	resp_body;
};

extern struct h2d_module h2d_lua_module;

/* content handlers */

static int h2d_lua_post(struct h2d_request *r)
{
	r->module_ctxs[h2d_lua_module.request_ctx.index] = strdup(lua_tostring(h2d_L, -1));
	h2d_request_active(r); // TODO check r->state
	return 0;
}

static int h2d_lua_process_request_headers(struct h2d_request *r)
{
	struct h2d_lua_conf *conf = r->conf_path->module_confs[h2d_lua_module.index];

	h2d_lua_thread_new(conf->content, 1, h2d_lua_post, r);

	return H2D_OK;
}
static int h2d_lua_process_request_body(struct h2d_request *r)
{
	return H2D_OK;
}
static int h2d_lua_generate_response_headers(struct h2d_request *r)
{
	const char *body = r->module_ctxs[h2d_lua_module.request_ctx.index];
	if (body == NULL) {
		return H2D_AGAIN;
	}
	r->resp.status_code = 200;
	r->resp.content_length = strlen(body);
	return 0;
}
static int h2d_lua_generate_response_body(struct h2d_request *r, uint8_t *buf, int len)
{
	const char *body = r->module_ctxs[h2d_lua_module.request_ctx.index];
	int body_len = strlen(body);
	memcpy(buf, body, body_len);
	return body_len;
}

static void h2d_lua_ctx_free(struct h2d_request *r)
{
	char *body = r->module_ctxs[h2d_lua_module.request_ctx.index];
	free(body);
}


/* configuration */

static bool h2d_lua_conf_is_enable(void *data)
{
	struct h2d_lua_conf *conf = data;
	return !h2d_conf_is_zero_function(conf->content);
}

static struct wuy_cflua_command h2d_lua_conf_commands[] = {
	{	.name = "content",
		.type = WUY_CFLUA_TYPE_FUNCTION,
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
		.is_enable = h2d_lua_conf_is_enable,
		.process_headers = h2d_lua_process_request_headers,
		.process_body = h2d_lua_process_request_body,
		.response_headers = h2d_lua_generate_response_headers,
		.response_body = h2d_lua_generate_response_body,
	},

	.request_ctx = {
		.free = h2d_lua_ctx_free,
	},
};
