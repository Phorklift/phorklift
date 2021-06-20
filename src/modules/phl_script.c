#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "phl_main.h"

struct phl_script_conf {
	wuy_cflua_function_t	content;
	wuy_cflua_function_t	request_headers;
	wuy_cflua_function_t	request_body;
	wuy_cflua_function_t	response_headers;
	wuy_cflua_function_t	response_body;
};

struct phl_module phl_script_module;

static int phl_script_generate_response_headers(struct phl_request *r)
{
	struct phl_script_conf *conf = r->conf_path->module_confs[phl_script_module.index];

	lua_State *L = phl_lua_thread_run(r, conf->content, NULL);
	if (!PHL_PTR_IS_OK(L)) {
		return PHL_PTR2RET(L);
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
		phl_request_log(r, PHL_LOG_ERROR, "script: content fail");
		return WUY_HTTP_500;
	}

	r->resp.easy_str_len = len;
	r->resp.easy_string = wuy_pool_strndup(r->pool, body, len);

	r->resp.status_code = status_code;
	r->resp.content_length = r->resp.easy_str_len;
	return PHL_OK;
}

static int phl_script_process_headers(struct phl_request *r)
{
	struct phl_script_conf *conf = r->conf_path->module_confs[phl_script_module.index];

	if (!wuy_cflua_is_function_set(conf->request_headers)) {
		return PHL_OK;
	}

	lua_State *L = phl_lua_thread_run(r, conf->request_headers, NULL);
	if (!PHL_PTR_IS_OK(L)) {
		return PHL_PTR2RET(L);
	}

	if (lua_gettop(L) == 0) {
		return PHL_OK;
	}

	return lua_tointeger(L, 1);
}

static int phl_script_response_headers(struct phl_request *r)
{
	struct phl_script_conf *conf = r->conf_path->module_confs[phl_script_module.index];

	if (!wuy_cflua_is_function_set(conf->response_headers)) {
		return PHL_OK;
	}

	lua_State *L = phl_lua_thread_run(r, conf->response_headers, NULL);
	if (!PHL_PTR_IS_OK(L)) {
		return PHL_PTR2RET(L);
	}
	return PHL_OK;
}

/* configuration */

static struct wuy_cflua_command phl_script_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_FUNCTION,
		.is_single_array = true,
		.description = "Content handler.",
		.offset = offsetof(struct phl_script_conf, content),
	},
	{	.name = "request_headers",
		.description = "Process request headers filter.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_script_conf, request_headers),
	},
	{	.name = "request_body",
		.description = "Process request body filter.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_script_conf, request_body),
	},
	{	.name = "response_headers",
		.description = "Process response headers filter.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_script_conf, response_headers),
	},
	{	.name = "response_body",
		.description = "Process response body filter.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_script_conf, response_body),
	},
	{ NULL }
};
struct phl_module phl_script_module = {
	.name = "script",
	.command_path = {
		.name = "script",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_script_conf_commands,
			.size = sizeof(struct phl_script_conf),
		}
	},

	.content = {
		.response_headers = phl_script_generate_response_headers,
	},
	.filters = {
		.process_headers = phl_script_process_headers,
		.response_headers = phl_script_response_headers,
	},
};
