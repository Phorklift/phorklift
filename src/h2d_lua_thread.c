#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

static int h2d_lua_thread_start(struct h2d_request *r,
		wuy_cflua_function_t entry, const char *argf, va_list ap)
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
	lua_rawgeti(r->L, LUA_REGISTRYINDEX, entry);

	/* push arguments if any */
	if (argf == NULL) {
		return 0;
	}

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
	return strlen(argf);
}

static void h2d_lua_thread_close(struct h2d_request *r)
{
	_log(H2D_LOG_DEBUG, "close");
	atomic_fetch_add(&r->conf_path->stats->lua_free, 1);

	/* un-mark it for GC */
	lua_pushlightuserdata(h2d_L, r->L);
	lua_pushnil(h2d_L);
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	r->L = NULL;
}

void h2d_lua_thread_kill(struct h2d_request *r)
{
	if (r->L == NULL) {
		return;
	}

	/* TODO clear resume-data, e.g. delete timer, close subr. is this OK? */
	if (lua_gettop(r->L) > 0) {
		lua_CFunction resume_handler = lua_tocfunction(r->L, 1);
		resume_handler(r->L);
	}

	h2d_lua_thread_close(r);
}

lua_State *h2d_lua_thread_run(struct h2d_request *r,
		wuy_cflua_function_t entry, const char *argf, ...)
{
	h2d_lua_api_current = r;

	int argn = 0;
	if (r->L == NULL) {
		va_list ap;
		va_start(ap, argf);
		argn = h2d_lua_thread_start(r, entry, argf, ap);
		va_end(ap);

	} else if (lua_gettop(r->L) > 0) {
		lua_CFunction resume_handler = lua_tocfunction(r->L, 1);
		argn = resume_handler(r->L);
		if (argn == H2D_AGAIN) {
			_log(H2D_LOG_DEBUG, "resume handler again");
			atomic_fetch_add(&r->conf_path->stats->lua_again, 1);
			return H2D_PTR_AGAIN;
		}
		if (argn == H2D_ERROR) {
			_log(H2D_LOG_ERROR, "resume handler error: %d", argn);
			atomic_fetch_add(&r->conf_path->stats->lua_error, 1);
			h2d_lua_thread_close(r);
			return H2D_PTR_ERROR;
		}
	}

	_log(H2D_LOG_DEBUG, "resume...");
	int ret = lua_resume(r->L, argn);

	if (ret == LUA_YIELD) {
		_log(H2D_LOG_DEBUG, "resume yields");
		atomic_fetch_add(&r->conf_path->stats->lua_again, 1);
		return H2D_PTR_AGAIN;
	}
	if (ret != 0) {
		_log(H2D_LOG_ERROR, "resume error: %s", lua_tostring(r->L, -1));
		atomic_fetch_add(&r->conf_path->stats->lua_error, 1);
		h2d_lua_thread_close(r);
		return H2D_PTR_ERROR;
	}

	_log(H2D_LOG_DEBUG, "resume returns OK");
	lua_State *L = r->L;
	h2d_lua_thread_close(r);
	return L;
}

bool h2d_lua_thread_in_running(struct h2d_request *r)
{
	return r->L != NULL;
}
