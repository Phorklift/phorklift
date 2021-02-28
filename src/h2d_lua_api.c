#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

/* C functions for Lua code to call */

static struct h2d_request *h2d_lua_api_current;

static int h2d_lua_api_thread_start(struct h2d_lua_api_thread *lth,
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

static int h2d_lua_api_thread_resume(struct h2d_request *r, int argn)
{
	h2d_lua_api_current = r;

	struct h2d_lua_api_thread *lth = &r->lth;

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
		return H2D_ERROR;
	}
	return H2D_OK;
}

void h2d_lua_api_thread_clear(struct h2d_request *r)
{
	struct h2d_lua_api_thread *lth = &r->lth;

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

lua_State *h2d_lua_api_thread_run(struct h2d_request *r,
		wuy_cflua_function_t entry, const char *argf, ...)
{
	struct h2d_lua_api_thread *lth = &r->lth;

	int argn = 0;
	if (lth->L == NULL) {
		_log(H2D_LOG_DEBUG, "start");
		atomic_fetch_add(&r->conf_path->stats->lua_new, 1);

		va_list ap;
		va_start(ap, argf);
		argn = h2d_lua_api_thread_start(lth, entry, argf, ap);
		va_end(ap);
	}

	_log(H2D_LOG_DEBUG, "resume...");

	int ret = h2d_lua_api_thread_resume(r, argn);

	_log(H2D_LOG_DEBUG, "resume returns %d", ret);

	if (ret == H2D_AGAIN) {
		atomic_fetch_add(&r->conf_path->stats->lua_again, 1);
		return H2D_PTR_AGAIN;
	}
	if (ret == H2D_ERROR) {
		atomic_fetch_add(&r->conf_path->stats->lua_error, 1);
		h2d_lua_api_thread_clear(r);
		return H2D_PTR_ERROR;
	}

	lua_State *L = lth->L;
	h2d_lua_api_thread_clear(r);
	return L;
}

bool h2d_lua_api_thread_in_running(struct h2d_request *r)
{
	return r->lth.L != NULL;
}

static void h2d_lua_api_check_blocking(lua_State *L, const char *name)
{
	if (L == h2d_L) {
		lua_pushfstring(L, "h2d.%s() is not allowed in blocking context", name);
		lua_error(L);
	}
}

static bool h2d_lua_api_call(struct h2d_request *r, wuy_cflua_function_t f)
{
	h2d_lua_api_current = r;

	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, f);
	if (lua_pcall(h2d_L, 0, 1, 0) != 0) {
		printf("lua_pcall fail: %s\n", lua_tostring(h2d_L, -1));
		lua_pop(h2d_L, 1);
		return false;
	}
	return true;
}

const char *h2d_lua_api_call_lstring(struct h2d_request *r,
		wuy_cflua_function_t f, int *plen)
{
	if (!h2d_lua_api_call(r, f)) {
		return NULL;
	}

	size_t len;
	const char *str = lua_tolstring(h2d_L, -1, &len);
	if (plen != NULL) {
		*plen = len;
	}

	/* Although not documented, lua_pop() does not trigger GC.
	 * So the string is safe until next Lua process. */
	lua_pop(h2d_L, 1);

	return str;
}

int h2d_lua_api_call_boolean(struct h2d_request *r, wuy_cflua_function_t f)
{
	if (!h2d_lua_api_call(r, f)) {
		return -1;
	}

	int ret = lua_toboolean(h2d_L, -1);
	lua_pop(h2d_L, -1);
	return ret;
}

/* APIs */

static int64_t h2d_lua_api_sleep_timeout(int64_t at, void *data)
{
	printf("Lua timer finish.\n");
	h2d_request_active(h2d_lua_api_current, "lua sleep");
	return 0;
}
static int h2d_lua_api_sleep_resume(void)
{
	struct h2d_lua_api_thread *lth = &h2d_lua_api_current->lth;
	loop_timer_delete(lth->data);
	return 0;
}
static int h2d_lua_api_sleep(lua_State *L)
{
	h2d_lua_api_check_blocking(L, "sleep");

	struct h2d_lua_api_thread *lth = &h2d_lua_api_current->lth;

	lth->data = loop_timer_new(h2d_loop, h2d_lua_api_sleep_timeout, NULL);

	lua_Number value = lua_tonumber(L, -1);
	loop_timer_set_after(lth->data, value * 1000); /* second -> ms */
	printf("Lua add timer: %f\n", value);

	lth->resume_handler = h2d_lua_api_sleep_resume;

	return lua_yield(L, 0);
}

static int h2d_lua_api_uri_raw(lua_State *L)
{
	lua_pushstring(L, h2d_lua_api_current->req.uri.raw);
	return 1;
}
static int h2d_lua_api_uri_path(lua_State *L)
{
	lua_pushstring(L, h2d_lua_api_current->req.uri.path);
	return 1;
}
static int h2d_lua_api_host(lua_State *L)
{
	lua_pushstring(L, h2d_lua_api_current->req.host);
	return 1;
}
static int h2d_lua_api_req_body(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current;
	lua_pushlstring(L, (char *)r->req.body_buf, r->req.body_len);
	return 1;
}

static int h2d_lua_api_headers(lua_State *L)
{
	lua_newtable(L);

	struct h2d_request *r = h2d_lua_api_current;
	struct h2d_header *h;
	h2d_header_iter(&r->req.headers, h) {
		lua_pushstring(L, h2d_header_value(h));
		lua_setfield(L, -2, h->str);
	}

	return 1;
}

static int h2d_lua_api_status_code(lua_State *L)
{
	lua_pushinteger(L, h2d_lua_api_current->resp.status_code);
	return 1;
}

static int h2d_lua_api_subrequest_resume(void)
{
	struct h2d_lua_api_thread *lth = &h2d_lua_api_current->lth;
	struct h2d_request *subr = lth->data;
	lua_State *L = lth->L;

	if (L == NULL) { /* just clear */
		goto out;
	}

	lua_newtable(L);

	lua_pushinteger(L, subr->resp.status_code);
	lua_setfield(L, -2, "status_code");

	lua_pushlstring(L, (char *)subr->c->send_buffer, subr->c->send_buf_pos - subr->c->send_buffer);
	lua_setfield(L, -2, "body");

	lua_newtable(L);
	struct h2d_header *h;
	h2d_header_iter(&h2d_lua_api_current->resp.headers, h) {
		lua_pushstring(L, h2d_header_value(h));
		lua_setfield(L, -2, h->str);
	}
	lua_setfield(L, -2, "headers");

out:
	h2d_request_subr_close(subr);

	return 1;
}
static int h2d_lua_api_subrequest(lua_State *L)
{
	h2d_lua_api_check_blocking(L, "subrequest");

	struct h2d_lua_api_thread *lth = &h2d_lua_api_current->lth;

	const char *uri = lua_tostring(L, -1);

	lth->data = h2d_request_subr_new(h2d_lua_api_current, uri);

	lth->resume_handler = h2d_lua_api_subrequest_resume;

	return lua_yield(L, 0);
}

static const struct luaL_Reg h2d_lua_api_list [] = {
	{ "uri_raw", h2d_lua_api_uri_raw},
	{ "uri_path", h2d_lua_api_uri_path },
	{ "host", h2d_lua_api_host },
	{ "req_body", h2d_lua_api_req_body },
	{ "headers", h2d_lua_api_headers },
	{ "status_code", h2d_lua_api_status_code },
	{ "sleep", h2d_lua_api_sleep },
	{ "subrequest", h2d_lua_api_subrequest },
	{ NULL, NULL }  /* sentinel */
};

void h2d_lua_api_init(void)
{
	/* C functions for Lua code to call */
	luaL_register(h2d_L, "h2d", h2d_lua_api_list);
}
