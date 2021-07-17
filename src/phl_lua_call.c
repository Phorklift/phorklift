#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "phl_main.h"

static bool phl_lua_call(struct phl_request *r, wuy_cflua_function_t f)
{
	phl_lua_api_current = r;

	lua_rawgeti(phl_L, LUA_REGISTRYINDEX, f);
	if (lua_pcall(phl_L, 0, 1, 0) != 0) {
		phl_request_log(r, PHL_LOG_ERROR, "lua_pcall fail: %s", lua_tostring(phl_L, -1));
		lua_pop(phl_L, 1);
		return false;
	}
	return true;
}

const char *phl_lua_call_lstring(struct phl_request *r,
		wuy_cflua_function_t f, int *plen)
{
	if (!phl_lua_call(r, f)) {
		return NULL;
	}

	size_t len;
	const char *str = lua_tolstring(phl_L, -1, &len);
	if (plen != NULL) {
		*plen = len;
	}

	/* Although not documented, lua_pop() does not trigger GC.
	 * So the string is safe until next Lua process. */
	lua_pop(phl_L, 1);

	return str;
}

int phl_lua_call_boolean(struct phl_request *r, wuy_cflua_function_t f)
{
	if (!phl_lua_call(r, f)) {
		return -1;
	}
	if (!lua_isboolean(phl_L, -1)) {
		return -1;
	}

	int ret = lua_toboolean(phl_L, -1);
	lua_pop(phl_L, -1);
	return ret;
}

float phl_lua_call_float(struct phl_request *r, wuy_cflua_function_t f)
{
	if (!phl_lua_call(r, f)) {
		return -1;
	}
	if (!lua_isnumber(phl_L, -1)) {
		return -1;
	}

	float ret = lua_tonumber(phl_L, -1);
	lua_pop(phl_L, -1);
	return ret;
}
