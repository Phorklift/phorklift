#ifndef H2D_LUA_API_H
#define H2D_LUA_API_H

#include <lua5.1/lua.h>
#include "h2d_request.h"

lua_State *h2d_lua_api_thread_new(wuy_cflua_function_t entry);

int h2d_lua_api_thread_resume(lua_State *L, struct h2d_request *r);

void h2d_lua_api_thread_free(lua_State *L);

const char *h2d_lua_api_call_lstring(struct h2d_request *r,
		wuy_cflua_function_t f, size_t *plen);

void h2d_lua_api_init(void);

#endif
