#ifndef H2D_LUA_THREAD_H
#define H2D_LUA_THREAD_H

int h2d_lua_thread_new(wuy_cflua_function_t entry, int nresults,
		int (*post)(struct h2d_request *), struct h2d_request *r);

#endif
