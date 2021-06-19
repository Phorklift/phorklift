#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "phl_main.h"

#define _log(level, fmt, ...) phl_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

static int phl_resp_get_header(lua_State *L)
{
	const char *name = lua_tostring(L, -1);
	if (name == NULL) {
		return 0;
	}
	struct phl_header *h = phl_header_get(&phl_lua_api_current->resp.headers, name);
	if (h == NULL) {
		return 0;
	}
	lua_pushlstring(L, phl_header_value(h), h->value_len);
	return 1;
}

static int phl_resp_add_header(lua_State *L)
{
	struct phl_request *r = phl_lua_api_current;

	size_t name_len, value_len;
	const char *name_str = lua_tolstring(L, -2, &name_len);
	const char *value_str = lua_tolstring(L, -1, &value_len);
	if (name_str != NULL && value_str != NULL) {
		phl_header_add(&r->resp.headers, name_str, name_len,
				value_str, value_len, r->pool);
	}
	return 0;
}

static int phl_resp_delete_header(lua_State *L)
{
	const char *name = lua_tostring(L, -1);
	if (name != NULL) {
		phl_header_delete(&phl_lua_api_current->resp.headers, name);
	}
	return 0;
}

static int phl_resp_set_header(lua_State *L)
{
	phl_resp_delete_header(L);
	return phl_resp_add_header(L);
}

static int phl_resp_mm_index(lua_State *L)
{
	const char *key = lua_tostring(L, -1);
	if (key == NULL) {
		return 0;
	}

	struct phl_request *r = phl_lua_api_current;

	if (strcmp(key, "status_code") == 0) {
		lua_pushinteger(L, r->resp.status_code);

	} else if (strcmp(key, "headers") == 0) {
		lua_newtable(L);
		struct phl_header *h;
		phl_header_iter(&r->resp.headers, h) {
			lua_pushstring(L, phl_header_value(h));
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

static const struct phl_lua_api_reg_func phl_resp_functions[] = {
	{ "get_header", phl_resp_get_header },
	{ "add_header", phl_resp_add_header },
	{ "delete_header", phl_resp_delete_header },
	{ "set_header", phl_resp_set_header },

	{ "__index", phl_resp_mm_index },
	{ NULL }  /* sentinel */
};

const struct phl_lua_api_package phl_resp_package = {
	.name = "resp",
	.funcs = phl_resp_functions,
};
