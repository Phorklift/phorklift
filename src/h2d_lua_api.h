#ifndef H2D_LUA_API_H
#define H2D_LUA_API_H

#include <lua5.1/lua.h>
#include "h2d_request.h"

struct h2d_lua_api_thread {
	lua_State		*L;
	struct h2d_request	*r;

	loop_timer_t		*timer;

	struct {
		int	(*handler)(void);
		void	*data;
	} resume;
};

struct h2d_lua_api_thread *h2d_lua_api_thread_new(wuy_cflua_function_t entry,
		struct h2d_request *r);

void h2d_lua_api_thread_set_argn(struct h2d_lua_api_thread *lth, int argn);

int h2d_lua_api_thread_resume(struct h2d_lua_api_thread *lth);

void h2d_lua_api_thread_free(struct h2d_lua_api_thread *lth);

const char *h2d_lua_api_call_lstring(struct h2d_request *r,
		wuy_cflua_function_t f, int *plen);

int h2d_lua_api_call_boolean(struct h2d_request *r,
		wuy_cflua_function_t f);

const char *h2d_lua_api_str_gsub(const char *s, const char *pattern, const char *repl);

void h2d_lua_api_init(void);

#endif
