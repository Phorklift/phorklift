#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

static bool h2d_lua_call(struct h2d_request *r, wuy_cflua_function_t f)
{
	h2d_lua_api_current = r;

	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, f);
	if (lua_pcall(h2d_L, 0, 1, 0) != 0) {
		h2d_request_log(r, H2D_LOG_ERROR, "lua_pcall fail: %s", lua_tostring(h2d_L, -1));
		lua_pop(h2d_L, 1);
		return false;
	}
	return true;
}

const char *h2d_lua_call_lstring(struct h2d_request *r,
		wuy_cflua_function_t f, int *plen)
{
	if (!h2d_lua_call(r, f)) {
		return NULL;
	}

	size_t len;
	const char *str = lua_tolstring(h2d_L, -1, &len);
	if (plen != NULL) {
		*plen = len;
	}

	/* Although not documented, lua_pop() does not trigger GC.
	 * So the string is safe until next Lua process. */
	lua_pop(h2d_L, 1);

	return str;
}

int h2d_lua_call_boolean(struct h2d_request *r, wuy_cflua_function_t f)
{
	if (!h2d_lua_call(r, f)) {
		return -1;
	}

	int ret = lua_toboolean(h2d_L, -1);
	lua_pop(h2d_L, -1);
	return ret;
}
