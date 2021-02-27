#ifndef H2D_LUA_API_H
#define H2D_LUA_API_H

#include <lua5.1/lua.h>

#include "h2d_request.h"

/* used by Lua APIs only */
struct h2d_lua_api_thread {
	lua_State	*L;

	int		(*resume_handler)(void);
	void		*data;
};

lua_State *h2d_lua_api_thread_run(struct h2d_request *r,
		wuy_cflua_function_t entry, const char *argf, ...);

bool h2d_lua_api_thread_in_running(struct h2d_request *r);

void h2d_lua_api_thread_clear(struct h2d_request *r);

const char *h2d_lua_api_call_lstring(struct h2d_request *r,
		wuy_cflua_function_t f, int *plen);

int h2d_lua_api_call_boolean(struct h2d_request *r,
		wuy_cflua_function_t f);

const char *h2d_lua_api_str_gsub(const char *s, const char *pattern, const char *repl);
bool h2d_lua_api_str_find(const char *s, const char *pattern);

void h2d_lua_api_init(void); /* before parsing config file */
void h2d_lua_api_init_post(void); /* after */

#endif
