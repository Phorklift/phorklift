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

struct h2d_module h2d_lua_module;

static int h2d_lua_generate_response_headers(struct h2d_request *r)
{
	struct h2d_lua_conf *conf = r->conf_path->module_confs[h2d_lua_module.index];

	lua_State *L = h2d_lua_thread_run(r, conf->content, NULL);
	if (!H2D_PTR_IS_OK(L)) {
		return H2D_PTR2RET(L);
	}

	int status_code = WUY_HTTP_200;
	if (lua_type(L, 1) == LUA_TNUMBER) {
		status_code = lua_tointeger(L, 1);
		if (status_code <= WUY_HTTP_200 || status_code >= WUY_HTTP_504) {
			status_code = WUY_HTTP_500;
		}
	}

	size_t len;
	const char *body = lua_tolstring(L, -1, &len);
	if (body == NULL) {
		h2d_request_log(r, H2D_LOG_ERROR, "content fail");
		return WUY_HTTP_500;
	}

	r->resp.easy_str_len = len;
	r->resp.easy_string = wuy_pool_strndup(r->pool, body, len);

	r->resp.status_code = status_code;
	r->resp.content_length = r->resp.easy_str_len;
	return H2D_OK;
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
	},
};
