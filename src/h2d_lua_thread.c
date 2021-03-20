#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

static int h2d_lua_thread_start(struct h2d_lua_thread *lth,
		wuy_cflua_function_t entry, const char *argf, va_list ap)
{
	lth->L = lua_newthread(h2d_L);

	/* mark it to avoid GC */
	/* TODO i am not sure whether this is the right way ... */
	lua_pushlightuserdata(h2d_L, lth->L); /* use pointer as key */
	lua_insert(h2d_L, -2); /* use thread as value */
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	/* push entry function */
	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, entry);
	lua_xmove(h2d_L, lth->L, 1);

	/* push arguments if any */
	if (argf == NULL) {
		return 0;
	}

	for (const char *p = argf; *p != '\0'; p++) {
		switch (*p) {
		case 'b':
			lua_pushinteger(lth->L, va_arg(ap, bool));
			break;
		case 'd':
			lua_pushinteger(lth->L, va_arg(ap, int));
			break;
		case 'l':
			lua_pushinteger(lth->L, va_arg(ap, long));
			break;
		case 's':
			lua_pushstring(lth->L, va_arg(ap, char *));
			break;
		default:
			abort();
		}
	}
	return strlen(argf);
}

static int h2d_lua_thread_resume(struct h2d_request *r, int argn)
{
	h2d_lua_api_current = r;

	struct h2d_lua_thread *lth = &r->lth;

	if (lth->resume_handler != NULL) {
		argn = lth->resume_handler();
		lth->resume_handler = NULL;

		if (argn < 0) {
			return argn;
		}
	}

	int ret = lua_resume(lth->L, argn);
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
	struct h2d_lua_thread *lth = &r->lth;

	if (lth->L == NULL) {
		return;
	}

	_log(H2D_LOG_DEBUG, "stop");
	atomic_fetch_add(&r->conf_path->stats->lua_free, 1);

	/* un-mark it for GC */
	lua_pushlightuserdata(h2d_L, lth->L);
	lua_pushnil(h2d_L);
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	lth->L = NULL;

	/* clear resume-data */
	if (lth->resume_handler != NULL) {
		lth->resume_handler();
		lth->resume_handler = NULL;
	}
}

lua_State *h2d_lua_thread_run(struct h2d_request *r,
		wuy_cflua_function_t entry, const char *argf, ...)
{
	struct h2d_lua_thread *lth = &r->lth;

	int argn = 0;
	if (lth->L == NULL) {
		_log(H2D_LOG_DEBUG, "start");
		atomic_fetch_add(&r->conf_path->stats->lua_new, 1);

		va_list ap;
		va_start(ap, argf);
		argn = h2d_lua_thread_start(lth, entry, argf, ap);
		va_end(ap);
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
	lua_State *L = lth->L;
	h2d_lua_thread_clear(r);
	return L;
}

bool h2d_lua_thread_in_running(struct h2d_request *r)
{
	return r->lth.L != NULL;
}
