#ifndef H2D_LUA_API_H
#define H2D_LUA_API_H

#include <lua5.1/lauxlib.h>

#include "h2d_request.h"

struct h2d_lua_api_const_int {
	const char	*name;
	int		n;
};

extern struct h2d_request *h2d_lua_api_current;

void h2d_lua_api_add_object(const char *name, const struct luaL_Reg *list,
		lua_CFunction index_f, lua_CFunction newindex_f);

void h2d_lua_api_init(void);

#endif
