#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "phl_main.h"

#define _log(level, fmt, ...) phl_request_log(phl_lua_api_current, level, "lua-ups: " fmt, ##__VA_ARGS__)

static wuy_dict_t *phl_ups_string_dict;
static wuy_dict_t *phl_ups_table_dict;
static wuy_pool_t *phl_ups_pool;
static int phl_ups_meta_ref;

struct phl_ups_dict_entry {
	struct phl_upstream_conf	*upstream;
	const void			*key;
	wuy_dict_node_t			dict_node;
};

static void phl_ups_init(void)
{
	phl_ups_string_dict = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct phl_ups_dict_entry, key),
			offsetof(struct phl_ups_dict_entry, dict_node));
	phl_ups_table_dict = wuy_dict_new_type(WUY_DICT_KEY_POINTER,
			offsetof(struct phl_ups_dict_entry, key),
			offsetof(struct phl_ups_dict_entry, dict_node));
	phl_ups_pool = wuy_pool_new(4096);
}

static struct phl_upstream_conf *phl_ups_get_upstream_string(lua_State *L)
{
	const char *key = lua_tostring(L, 1);
	struct phl_ups_dict_entry *entry = wuy_dict_get(phl_ups_string_dict, key);
	if (entry != NULL) {
		_log(PHL_LOG_DEBUG, "string hit: %s", key);
		return entry->upstream;
	}

	lua_createtable(L, 1, 0);
	lua_insert(L, 1);
	lua_rawseti(L, -2, 1);

	struct phl_upstream_conf *upstream;
	const char *err = wuy_cflua_parse(L, &phl_upstream_conf_table,
			&upstream, phl_ups_pool, NULL);
	if (err != WUY_CFLUA_OK) {
		luaL_error(L, "parse error %s", err);
		return NULL;
	}

	entry = wuy_pool_alloc(phl_ups_pool, sizeof(struct phl_ups_dict_entry));
	entry->key = wuy_pool_strdup(phl_ups_pool, key);
	entry->upstream = upstream;
	wuy_dict_add(phl_ups_string_dict, entry);

	_log(PHL_LOG_DEBUG, "string new: %s", key);
	return upstream;
}

static struct phl_upstream_conf *phl_ups_get_upstream_table(lua_State *L)
{
	const void *key = lua_topointer(L, 1);
	struct phl_ups_dict_entry *entry = wuy_dict_get(phl_ups_table_dict, key);
	if (entry != NULL) {
		_log(PHL_LOG_DEBUG, "table hit: %p", key);
		return entry->upstream;
	}

	struct phl_upstream_conf *upstream;
	const char *err = wuy_cflua_parse(L, &phl_upstream_conf_table,
			&upstream, phl_ups_pool, NULL);
	if (err != WUY_CFLUA_OK) {
		luaL_error(L, "parse error %s", err);
		return NULL;
	}

	entry = wuy_pool_alloc(phl_ups_pool, sizeof(struct phl_ups_dict_entry));
	entry->key = key;
	entry->upstream = upstream;
	wuy_dict_add(phl_ups_table_dict, entry);

	_log(PHL_LOG_DEBUG, "table new: %p", key);
	return upstream;
}

static int phl_ups_get_connection_resume(lua_State *L)
{
	struct phl_upstream_conf *upstream = lua_touserdata(L, -1);

	struct phl_upstream_connection *upc = phl_upstream_get_connection(upstream,
			phl_lua_api_current);

	if (upc == PHL_PTR_ERROR) {
		return 0;
	}
	if (upc == PHL_PTR_AGAIN) {
		if (lua_gettop(L) == 1) {
			/* insert the resume-handler at index=1 in stack */
			lua_pushcfunction(L, phl_ups_get_connection_resume);
			lua_insert(L, -1);
		}
		/* 2 = 1(resume-hander) + 1(upstream) */
		return lua_yield(L, 2);
	}

	struct phl_upstream_connection **udata = lua_newuserdata(L,
			sizeof(struct phl_upstream_connection *));
	*udata = upc;

	lua_rawgeti(L, LUA_REGISTRYINDEX, phl_ups_meta_ref);
	lua_setmetatable(L, -2);

	return 1;
}

static int phl_ups_get_connection(lua_State *L)
{
	struct phl_upstream_conf *upstream;
	switch (lua_type(L, 1)) {
	case LUA_TSTRING:
		upstream = phl_ups_get_upstream_string(L);
		break;
	case LUA_TTABLE:
		upstream = phl_ups_get_upstream_table(L);
		break;
	default:
		return luaL_error(L, "invalid argument");
	}

	lua_settop(L, 0); /* pop original argument */
	lua_pushlightuserdata(L, upstream);

	return phl_ups_get_connection_resume(L);
}

static struct phl_upstream_connection *phl_ups_arg_upc(lua_State *L, int i)
{
	struct phl_upstream_connection **udata = lua_touserdata(L, i);
	if (udata == NULL || *udata == NULL) {
		luaL_error(L, "invalid upc");
		return NULL;
	}
	return *udata;
}

static int phl_ups_send_resume(lua_State *L)
{
	struct phl_upstream_connection *upc = phl_ups_arg_upc(L, -2);

	size_t data_len;
	const char *data = lua_tolstring(L, -1, &data_len);

	int write_len = phl_upstream_connection_write(upc, data, data_len);
	if (write_len == PHL_ERROR) {
		lua_pushboolean(L, false);
		return 1;
	}
	if (write_len == PHL_AGAIN) {
		if (lua_gettop(L) == 2) {
			/* insert the resume-handler at index=1 in stack */
			lua_pushcfunction(L, phl_ups_send_resume);
			lua_insert(L, 1);
		}
		/* 3 = 1(resume-hander) + 2(original arguments) */
		return lua_yield(L, 3);
	}

	lua_pushboolean(L, true);
	return 1;
}

static int phl_ups_send(lua_State *L)
{
	if (lua_gettop(L) != 2 || !lua_isuserdata(L, 1) || !lua_isstring(L, 2)) {
		return luaL_error(L, "invalid argument");
	}
	return phl_ups_send_resume(L);
}

static int phl_ups_recv_resume(lua_State *L)
{
	struct phl_upstream_connection *upc = phl_ups_arg_upc(L, -2);
	int size = lua_tointeger(L, -1);

	char buffer[size];
	int read_len = phl_upstream_connection_read(upc, buffer, size);

	if (read_len == PHL_ERROR) {
		return 0;
	}
	if (read_len == PHL_AGAIN) {
		if (lua_gettop(L) == 2) {
			/* insert the resume-handler at index=1 in stack */
			lua_pushcfunction(L, phl_ups_recv_resume);
			lua_insert(L, 1);
		}
		/* 3 = 1(resume-hander) + 2(original arguments) */
		return lua_yield(L, 3);
	}

	lua_pushlstring(L, buffer, read_len);
	return 1;
}

static int phl_ups_recv_size(lua_State *L)
{
	if (lua_gettop(L) != 2 || !lua_isuserdata(L, 1) || !lua_isnumber(L, 2)) {
		return luaL_error(L, "invalid argument");
	}
	return phl_ups_recv_resume(L);
}

static int phl_ups_close(lua_State *L)
{
	struct phl_upstream_connection *upc = phl_ups_arg_upc(L, -1);
	phl_upstream_release_connection(upc, false);
	return 0;
}

static int phl_ups_keepalive(lua_State *L)
{
	struct phl_upstream_connection *upc = phl_ups_arg_upc(L, -1);
	phl_upstream_release_connection(upc, true);
	return 0;
}

static const struct phl_lua_api_reg_func phl_ups_functions[] = {
	{ "getc", phl_ups_get_connection },
	{ "send", phl_ups_send },
	{ "recv_size", phl_ups_recv_size },
	{ "keepalive", phl_ups_keepalive },
	{ "close", phl_ups_close },

	{ "__gc", phl_ups_close },
	{ NULL }  /* sentinel */
};

const struct phl_lua_api_package phl_ups_package = {
	.name = "ups",
	.ref = &phl_ups_meta_ref,
	.init = phl_ups_init,
	.funcs = phl_ups_functions,
};
