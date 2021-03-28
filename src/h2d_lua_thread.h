#ifndef H2D_LUA_THREAD_H
#define H2D_LUA_THREAD_H

#include <lua5.1/lua.h>

#include "h2d_request.h"

lua_State *h2d_lua_thread_run(struct h2d_request *r,
		wuy_cflua_function_t entry, const char *argf, ...);

bool h2d_lua_thread_in_running(struct h2d_request *r);

void h2d_lua_thread_kill(struct h2d_request *r);

#endif
