#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

static int h2d_req_get_query(lua_State *L, const char *query_str, int query_len)
{
	if (query_str == NULL) {
		return 0;
	}

	size_t key_len;
	const char *key_str = lua_tolstring(L, -1, &key_len);
	if (key_str == NULL) {
		return 0;
	}

	char value_str[query_len];
	int value_len = wuy_http_uri_query_get(query_str, query_len,
			key_str, key_len, value_str);
	if (value_len < 0) {
		return 0;
	}

	lua_pushlstring(L, value_str, value_len);
	return 1;
}

static void h2d_req_queries(lua_State *L, const char *query_str, int query_len)
{
	lua_newtable(L);

	if (query_str == NULL) {
		return;
	}

	const char *p = query_str;
	const char *end = query_str + query_len;

	while (p < end) {
		char value_buf[query_len];
		int key_len, value_len;

		int proc_len = wuy_http_uri_query_first(p, end - p, &key_len, value_buf, &value_len);
		if (proc_len < 0) {
			break;
		}

		lua_pushlstring(L, p + 1, key_len);
		lua_pushlstring(L, value_buf, value_len);
		lua_settable(L, -3);

		p += proc_len;
	}
}

static int h2d_req_get_uri_query(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current;
	return h2d_req_get_query(L, r->req.uri.query_pos, r->req.uri.query_len);
}

static int h2d_req_get_body_query(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current;
	return h2d_req_get_query(L, (const char *)r->req.body_buf, r->req.body_len);
}

static int h2d_req_get_header(lua_State *L)
{
	const char *name = lua_tostring(L, -1);
	if (name == NULL) {
		return 0;
	}
	struct h2d_header *h = h2d_header_get(&h2d_lua_api_current->req.headers, name);
	if (h == NULL) {
		return 0;
	}
	lua_pushlstring(L, h2d_header_value(h), h->value_len);
	return 1;
}

static int h2d_req_add_header(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current;

	size_t name_len, value_len;
	const char *name_str = lua_tolstring(L, -2, &name_len);
	const char *value_str = lua_tolstring(L, -1, &value_len);
	if (name_str != NULL && value_str != NULL) {
		h2d_header_add(&r->req.headers, name_str, name_len,
				value_str, value_len, r->pool);
	}
	return 0;
}

static int h2d_req_delete_header(lua_State *L)
{
	const char *name = lua_tostring(L, -1);
	if (name != NULL) {
		h2d_header_delete(&h2d_lua_api_current->req.headers, name);
	}
	return 0;
}

static int h2d_req_set_header(lua_State *L)
{
	h2d_req_delete_header(L);
	return h2d_req_add_header(L);
}

static int h2d_req_mm_index(lua_State *L)
{
	const char *key = lua_tostring(L, -1);
	if (key == NULL) {
		return 0;
	}

	struct h2d_request *r = h2d_lua_api_current;

	if (strcmp(key, "method") == 0) {
		lua_pushinteger(L, r->req.method);

	} else if (strcmp(key, "uri_raw") == 0) {
		lua_pushstring(L, r->req.uri.raw);

	} else if (strcmp(key, "uri_path") == 0) {
		lua_pushstring(L, r->req.uri.path);

	} else if (strcmp(key, "uri_queries") == 0) {
		h2d_req_queries(L, r->req.uri.query_pos, r->req.uri.query_len);

	} else if (strcmp(key, "host") == 0) {
		lua_pushstring(L, r->req.host);

	} else if (strcmp(key, "headers") == 0) {
		lua_newtable(L);
		struct h2d_header *h;
		h2d_header_iter(&r->req.headers, h) {
			lua_pushstring(L, h2d_header_value(h));
			lua_setfield(L, -2, h->str);
		}

	} else if (strcmp(key, "body") == 0) {
		lua_pushlstring(L, (char *)r->req.body_buf, r->req.body_len);

	} else if (strcmp(key, "body_queries") == 0) {
		h2d_req_queries(L, (char *)r->req.body_buf, r->req.body_len);

	} else {
		lua_pushnil(L);
	}
	return 1;
}

static const struct h2d_lua_api_reg_func h2d_req_functions[] = {
	{ "get_uri_query", h2d_req_get_uri_query },
	{ "get_body_query", h2d_req_get_body_query },
	{ "get_header", h2d_req_get_header },
	{ "add_header", h2d_req_add_header },
	{ "delete_header", h2d_req_delete_header },
	{ "set_header", h2d_req_set_header },

	{ "__index", h2d_req_mm_index },
	{ NULL }  /* sentinel */
};

const struct h2d_lua_api_package h2d_req_package = {
	.name = "req",
	.funcs = h2d_req_functions,
};
