#ifndef H2D_LUA_CALL_H
#define H2D_LUA_CALL_H

#include "h2d_request.h"

const char *h2d_lua_call_lstring(struct h2d_request *r,
		wuy_cflua_function_t f, int *plen);

int h2d_lua_call_boolean(struct h2d_request *r,
		wuy_cflua_function_t f);

#endif
