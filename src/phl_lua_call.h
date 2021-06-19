#ifndef H2D_LUA_CALL_H
#define H2D_LUA_CALL_H

#include "phl_request.h"

const char *phl_lua_call_lstring(struct phl_request *r,
		wuy_cflua_function_t f, int *plen);

int phl_lua_call_boolean(struct phl_request *r,
		wuy_cflua_function_t f);

#endif
