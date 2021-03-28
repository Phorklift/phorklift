#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

#define H2D_LUA_THREAD_RESUME_KEY "_H2D_LTRH"
void h2d_lua_thread_set_resume_handler(lua_State *L, h2d_lua_thread_resume_f handler)
{
	lua_pushlightuserdata(L, handler);
	lua_setglobal(L, H2D_LUA_THREAD_RESUME_KEY);
}
static h2d_lua_thread_resume_f h2d_lua_thread_pop_resume_handler(lua_State *L)
{
	lua_getglobal(L, H2D_LUA_THREAD_RESUME_KEY);
	h2d_lua_thread_resume_f handler = lua_touserdata(L, -1);
	lua_pop(L, 1);

	if (handler != NULL) {
		h2d_lua_thread_set_resume_handler(L, NULL);
	}
	return handler;
}

static int h2d_lua_thread_start(struct h2d_request *r,
		wuy_cflua_function_t entry, const char *argf, ...)
{
	_log(H2D_LOG_DEBUG, "start");
	atomic_fetch_add(&r->conf_path->stats->lua_new, 1);

	r->L = lua_newthread(h2d_L);

	/* mark it to avoid GC */
	/* TODO i am not sure whether this is the right way ... */
	lua_pushlightuserdata(h2d_L, r->L); /* use pointer as key */
	lua_insert(h2d_L, -2); /* use thread as value */
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	/* push entry function */
	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, entry);
	lua_xmove(h2d_L, r->L, 1);

	/* push arguments if any */
	if (argf == NULL) {
		return 0;
	}

	va_list ap;
	va_start(ap, argf);
	for (const char *p = argf; *p != '\0'; p++) {
		switch (*p) {
		case 'b':
			lua_pushinteger(r->L, va_arg(ap, bool));
			break;
		case 'd':
			lua_pushinteger(r->L, va_arg(ap, int));
			break;
		case 'l':
			lua_pushinteger(r->L, va_arg(ap, long));
			break;
		case 's':
			lua_pushstring(r->L, va_arg(ap, char *));
			break;
		default:
			abort();
		}
	}
	va_end(ap);
	return strlen(argf);
}

static int h2d_lua_thread_resume(struct h2d_request *r, int argn)
{
	h2d_lua_api_current = r;

	h2d_lua_thread_resume_f resume_handler = h2d_lua_thread_pop_resume_handler(r->L);
	if (resume_handler != NULL) {
		argn = resume_handler(r->L);
		if (argn < 0) {
			return argn;
		}
	}

	int ret = lua_resume(r->L, argn);
	if (ret == LUA_YIELD) {
		return H2D_AGAIN;
	}
	if (ret != 0) {
		h2d_request_log(r, H2D_LOG_ERROR, "lua_resume fail: %s", lua_tostring(h2d_L, -1));
		return H2D_ERROR;
	}
	return H2D_OK;
}

void h2d_lua_thread_clear(struct h2d_request *r)
{
	if (r->L == NULL) {
		return;
	}

	lua_State *L = r->L;

	_log(H2D_LOG_DEBUG, "stop");
	atomic_fetch_add(&r->conf_path->stats->lua_free, 1);

	/* un-mark it for GC */
	lua_pushlightuserdata(h2d_L, L);
	lua_pushnil(h2d_L);
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	r->L = NULL;

	/* clear resume-data */
	h2d_lua_thread_resume_f resume_handler = h2d_lua_thread_pop_resume_handler(L);
	if (resume_handler != NULL) {
		resume_handler(L);
	}
}

lua_State *h2d_lua_thread_run(struct h2d_request *r,
		wuy_cflua_function_t entry, const char *argf, ...)
{
	int argn = 0;
	if (r->L == NULL) {
		argn = h2d_lua_thread_start(r, entry, argf);
	}

	_log(H2D_LOG_DEBUG, "resume...");

	int ret = h2d_lua_thread_resume(r, argn);

	if (ret == H2D_AGAIN) {
		_log(H2D_LOG_DEBUG, "resume returns AGAIN");
		atomic_fetch_add(&r->conf_path->stats->lua_again, 1);
		return H2D_PTR_AGAIN;
	}
	if (ret == H2D_ERROR) {
		_log(H2D_LOG_ERROR, "resume returns ERROR");
		atomic_fetch_add(&r->conf_path->stats->lua_error, 1);
		h2d_lua_thread_clear(r);
		return H2D_PTR_ERROR;
	}

	_log(H2D_LOG_DEBUG, "resume returns OK");
	lua_State *L = r->L;
	h2d_lua_thread_clear(r);
	return L;
}

bool h2d_lua_thread_in_running(struct h2d_request *r)
{
	return r->L != NULL;
}
