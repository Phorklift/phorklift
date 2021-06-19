#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "phl_main.h"

static int phl_conn_mm_index(lua_State *L)
{
	const char *key = lua_tostring(L, -1);
	if (key == NULL) {
		return 0;
	}

	struct phl_request *r = phl_lua_api_current;

	if (strcmp(key, "client_ip") == 0) {
		char buf[200];
		wuy_sockaddr_dumps_iponly(&r->c->client_addr, buf, sizeof(buf));
		lua_pushstring(L, buf);
	} else {
		lua_pushnil(L);
	}

	return 1;
}

static const struct phl_lua_api_reg_func phl_conn_functions[] = {
	{ "__index", phl_conn_mm_index },
	{ NULL }  /* sentinel */
};

const struct phl_lua_api_package phl_conn_package = {
	.name = "conn",
	.funcs = phl_conn_functions,
};
