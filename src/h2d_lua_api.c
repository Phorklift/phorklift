#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "h2d_main.h"

struct h2d_request *h2d_lua_api_request;

static int h2d_lua_api_sleep(lua_State *L)
{
	return lua_yield(L, 1);
}

static int h2d_lua_api_url(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_request;
	lua_pushstring(L, h2d_header_value(r->req.url));
	return 1;
}

static int h2d_lua_api_headers(lua_State *L)
{
	lua_newtable(L);

	struct h2d_request *r = h2d_lua_api_request;
	struct h2d_header *h;
	for (h = r->req.buffer; h->name_len != 0; h = h2d_header_next(h)) {
		lua_pushstring(L, h2d_header_value(h));
		lua_setfield(L, -2, h->str);
	}

	return 1;
}

static const struct luaL_Reg h2d_lua_api_list [] = {
	{ "url", h2d_lua_api_url },
	{ "headers", h2d_lua_api_headers },
	{ "sleep", h2d_lua_api_sleep },
	{ NULL, NULL }  /* sentinel */
};

void h2d_lua_api_init(void)
{
	luaL_register(h2d_L, "h2d", h2d_lua_api_list);
}
