#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

struct h2d_script_conf {
	wuy_cflua_function_t	content;
	wuy_cflua_function_t	request_headers;
	wuy_cflua_function_t	request_body;
	wuy_cflua_function_t	response_headers;
	wuy_cflua_function_t	response_body;
};

struct h2d_module h2d_script_module;

static int h2d_script_generate_response_headers(struct h2d_request *r)
{
	struct h2d_script_conf *conf = r->conf_path->module_confs[h2d_script_module.index];

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

static int h2d_script_process_headers(struct h2d_request *r)
{
	struct h2d_script_conf *conf = r->conf_path->module_confs[h2d_script_module.index];

	if (!wuy_cflua_is_function_set(conf->request_headers)) {
		return H2D_OK;
	}

	lua_State *L = h2d_lua_thread_run(r, conf->request_headers, NULL);
	if (!H2D_PTR_IS_OK(L)) {
		return H2D_PTR2RET(L);
	}

	if (lua_gettop(L) == 0) {
		return H2D_OK;
	}

	return lua_tointeger(L, 1);
}

static int h2d_script_response_headers(struct h2d_request *r)
{
	struct h2d_script_conf *conf = r->conf_path->module_confs[h2d_script_module.index];

	if (!wuy_cflua_is_function_set(conf->response_headers)) {
		return H2D_OK;
	}

	lua_State *L = h2d_lua_thread_run(r, conf->response_headers, NULL);
	if (!H2D_PTR_IS_OK(L)) {
		return H2D_PTR2RET(L);
	}
	return H2D_OK;
}

/* configuration */

static struct wuy_cflua_command h2d_script_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_FUNCTION,
		.is_single_array = true,
		.offset = offsetof(struct h2d_script_conf, content),
	},
	{	.name = "request_headers",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_script_conf, request_headers),
	},
	{	.name = "request_body",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_script_conf, request_body),
	},
	{	.name = "response_headers",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_script_conf, response_headers),
	},
	{	.name = "response_body",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_script_conf, response_body),
	},
	{ NULL }
};
struct h2d_module h2d_script_module = {
	.name = "script",
	.command_path = {
		.name = "script",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_script_conf_commands,
			.size = sizeof(struct h2d_script_conf),
		}
	},

	.content = {
		.response_headers = h2d_script_generate_response_headers,
	},
	.filters = {
		.process_headers = h2d_script_process_headers,
		.response_headers = h2d_script_response_headers,
	},
};
