#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "phl_main.h"

#define _log(level, fmt, ...) phl_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

static int phl_lua_thread_start(struct phl_request *r,
		wuy_cflua_function_t entry, const char *argf, va_list ap)
{
	_log(PHL_LOG_DEBUG, "start");
	atomic_fetch_add(&r->conf_path->stats->lua_new, 1);

	r->L = lua_newthread(phl_L);

	/* mark it to avoid GC */
	/* TODO i am not sure whether this is the right way ... */
	lua_pushlightuserdata(phl_L, r->L); /* use pointer as key */
	lua_insert(phl_L, -2); /* use thread as value */
	lua_settable(phl_L, LUA_REGISTRYINDEX);

	/* push entry function */
	lua_rawgeti(r->L, LUA_REGISTRYINDEX, entry);

	/* push arguments if any */
	if (argf == NULL) {
		return 0;
	}

	for (const char *p = argf; *p != '\0'; p++) {
		switch (*p) {
		case 'b':
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

static void phl_lua_thread_close(struct phl_request *r)
{
	_log(PHL_LOG_DEBUG, "close");
	atomic_fetch_add(&r->conf_path->stats->lua_free, 1);

	/* un-mark it for GC */
	lua_pushlightuserdata(phl_L, r->L);
	lua_pushnil(phl_L);
	lua_settable(phl_L, LUA_REGISTRYINDEX);

	r->L = NULL;
}

void phl_lua_thread_kill(struct phl_request *r)
{
	if (r->L == NULL) {
		return;
	}

	/* TODO clear resume-data, e.g. delete timer, close subr. is this OK? */
	if (lua_gettop(r->L) > 0) {
		lua_CFunction resume_handler = lua_tocfunction(r->L, 1);
		resume_handler(r->L);
	}

	phl_lua_thread_close(r);
}

lua_State *phl_lua_thread_run(struct phl_request *r,
		wuy_cflua_function_t entry, const char *argf, ...)
{
	phl_lua_api_current = r;

	int argn = 0;
	if (r->L == NULL || r->current_entry != entry) {
		r->current_entry = entry;

		va_list ap;
		va_start(ap, argf);
		argn = phl_lua_thread_start(r, entry, argf, ap);
		va_end(ap);

	} else if (lua_gettop(r->L) > 0) {
		lua_CFunction resume_handler = lua_tocfunction(r->L, 1);
		argn = resume_handler(r->L);
		if (argn == PHL_AGAIN) {
			_log(PHL_LOG_DEBUG, "resume handler again");
			atomic_fetch_add(&r->conf_path->stats->lua_again, 1);
			return PHL_PTR_AGAIN;
		}
		if (argn == PHL_ERROR) {
			_log(PHL_LOG_ERROR, "resume handler error: %d", argn);
			atomic_fetch_add(&r->conf_path->stats->lua_error, 1);
			phl_lua_thread_close(r);
			return PHL_PTR_ERROR;
		}
	}

	_log(PHL_LOG_DEBUG, "resume...");
	int ret = lua_resume(r->L, argn);

	if (ret == LUA_YIELD) {
		_log(PHL_LOG_DEBUG, "resume yields");
		atomic_fetch_add(&r->conf_path->stats->lua_again, 1);
		return PHL_PTR_AGAIN;
	}
	if (ret != 0) {
		_log(PHL_LOG_ERROR, "resume error: %s", lua_tostring(r->L, -1));
		atomic_fetch_add(&r->conf_path->stats->lua_error, 1);
		phl_lua_thread_close(r);
		return PHL_PTR_ERROR;
	}

	_log(PHL_LOG_DEBUG, "resume returns OK");
	lua_State *L = r->L;
	phl_lua_thread_close(r);
	return L;
}
