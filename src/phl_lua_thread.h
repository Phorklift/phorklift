#ifndef H2D_LUA_THREAD_H
#define H2D_LUA_THREAD_H

#include <lua5.1/lua.h>

#include "phl_request.h"

lua_State *phl_lua_thread_run(struct phl_request *r,
		wuy_cflua_function_t entry, const char *argf, ...);

static inline bool phl_lua_thread_in_running(struct phl_request *r,
		wuy_cflua_function_t entry)
{
	return r->L != NULL && r->current_entry == entry;
}

void phl_lua_thread_kill(struct phl_request *r);

#endif
