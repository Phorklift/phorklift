#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(h2d_lua_api_current, level, "lua-ups: " fmt, ##__VA_ARGS__)

static wuy_dict_t *h2d_ups_string_dict;
static wuy_dict_t *h2d_ups_table_dict;
static wuy_pool_t *h2d_ups_pool;
static int h2d_ups_meta_ref;

struct h2d_ups_dict_entry {
	struct h2d_upstream_conf	*upstream;
	const void			*key;
	wuy_dict_node_t			dict_node;
};

static void h2d_ups_init(void)
{
	h2d_ups_string_dict = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct h2d_ups_dict_entry, key),
			offsetof(struct h2d_ups_dict_entry, dict_node));
	h2d_ups_table_dict = wuy_dict_new_type(WUY_DICT_KEY_POINTER,
			offsetof(struct h2d_ups_dict_entry, key),
			offsetof(struct h2d_ups_dict_entry, dict_node));
	h2d_ups_pool = wuy_pool_new(4096);
}

static struct h2d_upstream_conf *h2d_ups_get_upstream_string(lua_State *L)
{
	const char *key = lua_tostring(L, 1);
	struct h2d_ups_dict_entry *entry = wuy_dict_get(h2d_ups_string_dict, key);
	if (entry != NULL) {
		_log(H2D_LOG_DEBUG, "string hit: %s", key);
		return entry->upstream;
	}

	lua_createtable(L, 1, 0);
	lua_insert(L, 1);
	lua_rawseti(L, -2, 1);

	struct h2d_upstream_conf *upstream;
	const char *err = wuy_cflua_parse(L, &h2d_upstream_conf_table,
			&upstream, h2d_ups_pool, NULL);
	if (err != WUY_CFLUA_OK) {
		luaL_error(L, "parse error %s", err);
		return NULL;
	}

	entry = wuy_pool_alloc(h2d_ups_pool, sizeof(struct h2d_ups_dict_entry));
	entry->key = wuy_pool_strdup(h2d_ups_pool, key);
	entry->upstream = upstream;
	wuy_dict_add(h2d_ups_string_dict, entry);

	_log(H2D_LOG_DEBUG, "string new: %s", key);
	return upstream;
}

static struct h2d_upstream_conf *h2d_ups_get_upstream_table(lua_State *L)
{
	const void *key = lua_topointer(L, 1);
	struct h2d_ups_dict_entry *entry = wuy_dict_get(h2d_ups_table_dict, key);
	if (entry != NULL) {
		_log(H2D_LOG_DEBUG, "table hit: %p", key);
		return entry->upstream;
	}

	struct h2d_upstream_conf *upstream;
	const char *err = wuy_cflua_parse(L, &h2d_upstream_conf_table,
			&upstream, h2d_ups_pool, NULL);
	if (err != WUY_CFLUA_OK) {
		luaL_error(L, "parse error %s", err);
		return NULL;
	}

	entry = wuy_pool_alloc(h2d_ups_pool, sizeof(struct h2d_ups_dict_entry));
	entry->key = key;
	entry->upstream = upstream;
	wuy_dict_add(h2d_ups_table_dict, entry);

	_log(H2D_LOG_DEBUG, "table new: %p", key);
	return upstream;
}

static int h2d_ups_get_connection_resume(lua_State *L)
{
	struct h2d_upstream_conf *upstream = lua_touserdata(L, -1);

	struct h2d_upstream_connection *upc = h2d_upstream_get_connection(upstream,
			h2d_lua_api_current);

	if (upc == H2D_PTR_ERROR) {
		return 0;
	}
	if (upc == H2D_PTR_AGAIN) {
		if (lua_gettop(L) == 1) {
			/* insert the resume-handler at index=1 in stack */
			lua_pushcfunction(L, h2d_ups_get_connection_resume);
			lua_insert(L, -1);
		}
		/* 2 = 1(resume-hander) + 1(upstream) */
		return lua_yield(L, 2);
	}

	struct h2d_upstream_connection **udata = lua_newuserdata(L,
			sizeof(struct h2d_upstream_connection *));
	*udata = upc;

	lua_rawgeti(L, LUA_REGISTRYINDEX, h2d_ups_meta_ref);
	lua_setmetatable(L, -2);

	return 1;
}

static int h2d_ups_get_connection(lua_State *L)
{
	struct h2d_upstream_conf *upstream;
	switch (lua_type(L, 1)) {
	case LUA_TSTRING:
		upstream = h2d_ups_get_upstream_string(L);
		break;
	case LUA_TTABLE:
		upstream = h2d_ups_get_upstream_table(L);
		break;
	default:
		return luaL_error(L, "invalid argument");
	}

	lua_settop(L, 0); /* pop original argument */
	lua_pushlightuserdata(L, upstream);

	return h2d_ups_get_connection_resume(L);
}

static struct h2d_upstream_connection *h2d_ups_arg_upc(lua_State *L, int i)
{
	struct h2d_upstream_connection **udata = lua_touserdata(L, i);
	if (udata == NULL || *udata == NULL) {
		luaL_error(L, "invalid upc");
		return NULL;
	}
	return *udata;
}

static int h2d_ups_send_resume(lua_State *L)
{
	struct h2d_upstream_connection *upc = h2d_ups_arg_upc(L, -2);

	size_t data_len;
	const char *data = lua_tolstring(L, -1, &data_len);

	int write_len = h2d_upstream_connection_write(upc, data, data_len);
	if (write_len == H2D_ERROR) {
		lua_pushboolean(L, false);
		return 1;
	}
	if (write_len == H2D_AGAIN) {
		if (lua_gettop(L) == 2) {
			/* insert the resume-handler at index=1 in stack */
			lua_pushcfunction(L, h2d_ups_send_resume);
			lua_insert(L, 1);
		}
		/* 3 = 1(resume-hander) + 2(original arguments) */
		return lua_yield(L, 3);
	}

	lua_pushboolean(L, true);
	return 1;
}

static int h2d_ups_send(lua_State *L)
{
	if (lua_gettop(L) != 2 || !lua_isuserdata(L, 1) || !lua_isstring(L, 2)) {
		return luaL_error(L, "invalid argument");
	}
	return h2d_ups_send_resume(L);
}

static int h2d_ups_recv_resume(lua_State *L)
{
	struct h2d_upstream_connection *upc = h2d_ups_arg_upc(L, -2);
	int size = lua_tointeger(L, -1);

	char buffer[size];
	int read_len = h2d_upstream_connection_read(upc, buffer, size);

	if (read_len == H2D_ERROR) {
		return 0;
	}
	if (read_len == H2D_AGAIN) {
		if (lua_gettop(L) == 2) {
			/* insert the resume-handler at index=1 in stack */
			lua_pushcfunction(L, h2d_ups_recv_resume);
			lua_insert(L, 1);
		}
		/* 3 = 1(resume-hander) + 2(original arguments) */
		return lua_yield(L, 3);
	}

	lua_pushlstring(L, buffer, read_len);
	return 1;
}

static int h2d_ups_recv_size(lua_State *L)
{
	if (lua_gettop(L) != 2 || !lua_isuserdata(L, 1) || !lua_isnumber(L, 2)) {
		return luaL_error(L, "invalid argument");
	}
	return h2d_ups_recv_resume(L);
}

static int h2d_ups_close(lua_State *L)
{
	struct h2d_upstream_connection *upc = h2d_ups_arg_upc(L, -1);
	h2d_upstream_release_connection(upc, false);
	return 0;
}

static int h2d_ups_keepalive(lua_State *L)
{
	struct h2d_upstream_connection *upc = h2d_ups_arg_upc(L, -1);
	h2d_upstream_release_connection(upc, true);
	return 0;
}

static const struct h2d_lua_api_reg_func h2d_ups_functions[] = {
	{ "getc", h2d_ups_get_connection },
	{ "send", h2d_ups_send },
	{ "recv_size", h2d_ups_recv_size },
	{ "keepalive", h2d_ups_keepalive },
	{ "close", h2d_ups_close },

	{ "__gc", h2d_ups_close },
	{ NULL }  /* sentinel */
};

const struct h2d_lua_api_package h2d_ups_package = {
	.name = "ups",
	.ref = &h2d_ups_meta_ref,
	.init = h2d_ups_init,
	.funcs = h2d_ups_functions,
};
