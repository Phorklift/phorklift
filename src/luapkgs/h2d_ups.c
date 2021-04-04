#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(h2d_lua_api_current, level, "lua-ups: " fmt, ##__VA_ARGS__)

static wuy_dict_t *h2d_ups_string_dict;
static wuy_dict_t *h2d_ups_table_dict;
static wuy_pool_t *h2d_ups_pool;

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

static struct h2d_upstream_conf *h2d_ups_get_connection_string(lua_State *L)
{
	const char *key = lua_tostring(L, 1);
	struct h2d_ups_dict_entry *ups = wuy_dict_get(h2d_ups_string_dict, key);
	if (ups != NULL) {
		_log(H2D_LOG_DEBUG, "string hit: %s", key);
		return ups->upstream;
	}

	lua_createtable(L, 1, 0);
	lua_insert(L, 1);
	lua_rawseti(L, -2, 1);

	struct h2d_upstream_conf *upstream;
	const char *err = wuy_cflua_parse(L, &h2d_upstream_conf_table,
			&upstream, h2d_ups_pool);
	if (err != WUY_CFLUA_OK) {
		return (void *)(long)luaL_error(L, "parse error %s", err);
	}

	ups = wuy_pool_alloc(h2d_ups_pool, sizeof(struct h2d_ups_dict_entry));
	ups->key = wuy_pool_strdup(h2d_ups_pool, key);
	ups->upstream = upstream;
	wuy_dict_add(h2d_ups_string_dict, ups);

	_log(H2D_LOG_DEBUG, "string new: %s", key);
	return upstream;
}

static struct h2d_upstream_conf *h2d_ups_get_connection_table(lua_State *L)
{
	const void *key = lua_topointer(L, 1);
	struct h2d_ups_dict_entry *ups = wuy_dict_get(h2d_ups_table_dict, key);
	if (ups != NULL) {
		_log(H2D_LOG_DEBUG, "table hit: %p", key);
		return ups->upstream;
	}

	struct h2d_upstream_conf *upstream;
	const char *err = wuy_cflua_parse(L, &h2d_upstream_conf_table,
			&upstream, h2d_ups_pool);
	if (err != WUY_CFLUA_OK) {
		return (void *)(long)luaL_error(L, "parse error %s", err);
	}

	ups = wuy_pool_alloc(h2d_ups_pool, sizeof(struct h2d_ups_dict_entry));
	ups->key = key;
	ups->upstream = upstream;
	wuy_dict_add(h2d_ups_table_dict, ups);

	_log(H2D_LOG_DEBUG, "table new: %p", key);
	return upstream;
}

static int h2d_ups_get_connection(lua_State *L)
{
	struct h2d_upstream_conf *upstream;
	switch (lua_type(L, 1)) {
	case LUA_TSTRING:
		upstream = h2d_ups_get_connection_string(L);
		break;
	case LUA_TTABLE:
		upstream = h2d_ups_get_connection_table(L);
		break;
	default:
		return luaL_error(L, "invalid argument");
	}

	struct h2d_upstream_connection *upc = h2d_upstream_get_connection(upstream,
			h2d_lua_api_current);

	if (upc == H2D_PTR_ERROR) {
		return 0;
	}
	if (upc == H2D_PTR_AGAIN) {
		printf("XXXXX\n");
		return 0;
	}

	lua_pushlightuserdata(L, upc);
	return 1;
}

static int h2d_ups_send_resume(lua_State *L)
{
	struct h2d_upstream_connection *upc = lua_touserdata(L, -2);

	size_t data_len;
	const char *data = lua_tolstring(L, -1, &data_len);

	int write_len = h2d_upstream_connection_write(upc, data, data_len);
	if (write_len == H2D_ERROR) {
		lua_pushboolean(L, false);
		return 0;
	}
	if (write_len == H2D_AGAIN) {
		if (lua_gettop(L) == 2) {
			lua_pushcfunction(L, h2d_ups_send_resume);
			lua_insert(L, 1);
		}
		return lua_yield(L, 3);
	}

	lua_pushboolean(L, true);
	return 0;
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
	struct h2d_upstream_connection *upc = lua_touserdata(L, -2);
	int size = lua_tointeger(L, -1);

	char buffer[size];
	int read_len = h2d_upstream_connection_read(upc, buffer, size);

	if (read_len == H2D_ERROR) {
		return 0;
	}
	if (read_len == H2D_AGAIN) {
		if (lua_gettop(L) == 2) {
			lua_pushcfunction(L, h2d_ups_recv_resume);
			lua_insert(L, 1);
		}
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

static int h2d_ups_keepalive(lua_State *L)
{
	struct h2d_upstream_connection *upc = lua_touserdata(L, 1);
	if (upc == NULL) {
		return luaL_error(L, "invalid argument");
	}
	h2d_upstream_release_connection(upc, true);
	return 0;
}

static const struct h2d_lua_api_reg h2d_ups_functions[] = {
	{ "get", .u.f=h2d_ups_get_connection },
	{ "send", .u.f=h2d_ups_send },
	{ "recv_max", .u.f=NULL },
	{ "recv_size", .u.f=h2d_ups_recv_size },
	{ "recv_line", .u.f=NULL },
	{ "recv_toclose", .u.f=NULL },
	{ "close", .u.f=NULL },
	{ "keepalive", .u.f=h2d_ups_keepalive },
	{ NULL }  /* sentinel */
};

const struct h2d_lua_api_package h2d_ups_package = {
	.name = "ups",
	.fs = h2d_ups_functions,
	.init = h2d_ups_init,
};
