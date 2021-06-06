#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

static int h2d_resp_get_header(lua_State *L)
{
	const char *name = lua_tostring(L, -1);
	if (name == NULL) {
		return 0;
	}
	struct h2d_header *h = h2d_header_get(&h2d_lua_api_current->resp.headers, name);
	if (h == NULL) {
		return 0;
	}
	lua_pushlstring(L, h2d_header_value(h), h->value_len);
	return 1;
}

static int h2d_resp_add_header(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current;

	size_t name_len, value_len;
	const char *name_str = lua_tolstring(L, -2, &name_len);
	const char *value_str = lua_tolstring(L, -1, &value_len);
	if (name_str != NULL && value_str != NULL) {
		h2d_header_add(&r->resp.headers, name_str, name_len,
				value_str, value_len, r->pool);
	}
	return 0;
}

static int h2d_resp_delete_header(lua_State *L)
{
	const char *name = lua_tostring(L, -1);
	if (name != NULL) {
		h2d_header_delete(&h2d_lua_api_current->resp.headers, name);
	}
	return 0;
}

static int h2d_resp_set_header(lua_State *L)
{
	h2d_resp_delete_header(L);
	return h2d_resp_add_header(L);
}

static int h2d_resp_mm_index(lua_State *L)
{
	const char *key = lua_tostring(L, -1);
	if (key == NULL) {
		return 0;
	}

	struct h2d_request *r = h2d_lua_api_current;

	if (strcmp(key, "status_code") == 0) {
		lua_pushinteger(L, r->resp.status_code);

	} else if (strcmp(key, "headers") == 0) {
		lua_newtable(L);
		struct h2d_header *h;
		h2d_header_iter(&r->resp.headers, h) {
			lua_pushstring(L, h2d_header_value(h));
			lua_setfield(L, -2, h->str);
		}

	} else if (strcmp(key, "body") == 0) {
		// TODO
		lua_pushnil(L);

	} else if (strcmp(key, "react_ms") == 0) {
		lua_pushinteger(L, r->resp_begin_time - r->req_end_time);

	} else if (strcmp(key, "content_ms") == 0) {
		lua_pushinteger(L, wuy_time_ms() - r->resp_begin_time);
	} else {
		lua_pushnil(L);
	}
	return 1;
}

static const struct h2d_lua_api_reg_func h2d_resp_functions[] = {
	{ "get_header", h2d_resp_get_header },
	{ "add_header", h2d_resp_add_header },
	{ "delete_header", h2d_resp_delete_header },
	{ "set_header", h2d_resp_set_header },

	{ "__index", h2d_resp_mm_index },
	{ NULL }  /* sentinel */
};

const struct h2d_lua_api_package h2d_resp_package = {
	.name = "resp",
	.funcs = h2d_resp_functions,
};
