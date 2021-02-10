#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

/* C functions for Lua code to call */

static struct h2d_request *h2d_lua_api_current;

struct h2d_lua_api_thread {
	lua_State		*L;
	loop_timer_t		*timer;
	struct {
		int	(*handler)(void *data);
		void	*data;
	} resume;
};

static int h2d_lua_api_thread_set_argn_handler(void *data)
{
	return (uintptr_t)data;
}

static void h2d_lua_api_thread_start(struct h2d_lua_api_thread *lth,
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
		return;
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

	lth->resume.handler = h2d_lua_api_thread_set_argn_handler;
	lth->resume.data = (void *)strlen(argf);
}

static int h2d_lua_api_thread_resume(struct h2d_request *r)
{
	h2d_lua_api_current = r;

	struct h2d_lua_api_thread *lth = r->lth;

	int argn = 0;
	if (lth->resume.handler != NULL) {
		argn = lth->resume.handler(lth->resume.data);
		if (argn < 0) {
			return argn;
		}
		lth->resume.handler = NULL;
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

static void h2d_lua_api_thread_stop(void *data)
{
	struct h2d_request *r = data;
	struct h2d_lua_api_thread *lth = r->lth;

	if (lth->L == NULL) {
		return;
	}

	_log(H2D_LOG_DEBUG, "stop");
	atomic_fetch_add(&r->conf_path->stats->lua_free, 1);

	/* un-mark it for GC */
	lua_pushlightuserdata(h2d_L, lth->L);
	lua_pushnil(h2d_L);
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	if (lth->timer != NULL) {
		loop_timer_delete(lth->timer);
		lth->timer = NULL;
	}

	lth->L = NULL;
}

lua_State *h2d_lua_api_thread_run(struct h2d_request *r,
		wuy_cflua_function_t entry, const char *argf, ...)
{
	if (r->lth == NULL) {
		r->lth = wuy_pool_alloc(r->pool, sizeof(struct h2d_lua_api_thread));
		wuy_pool_add_free(r->pool, h2d_lua_api_thread_stop, r);
	}
	if (r->lth->L == NULL) {
		_log(H2D_LOG_DEBUG, "start");
		atomic_fetch_add(&r->conf_path->stats->lua_new, 1);

		va_list ap;
		va_start(ap, argf);
		h2d_lua_api_thread_start(r->lth, entry, argf, ap);
		va_end(ap);
	}

	_log(H2D_LOG_DEBUG, "resume...");

	int ret = h2d_lua_api_thread_resume(r);

	_log(H2D_LOG_DEBUG, "resume returns %d", ret);

	if (ret == H2D_AGAIN) {
		atomic_fetch_add(&r->conf_path->stats->lua_again, 1);
		return H2D_PTR_AGAIN;
	}
	if (ret == H2D_ERROR) {
		atomic_fetch_add(&r->conf_path->stats->lua_error, 1);
		h2d_lua_api_thread_stop(r);
		return H2D_PTR_ERROR;
	}

	lua_State *L = r->lth->L;
	h2d_lua_api_thread_stop(r);
	return L;
}

bool h2d_lua_api_thread_in_running(struct h2d_request *r)
{
	return r->lth != NULL && r->lth->L != NULL;
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
static int h2d_lua_api_sleep(lua_State *L)
{
	h2d_lua_api_check_blocking(L, "sleep");

	struct h2d_lua_api_thread *lth = h2d_lua_api_current->lth;

	if (lth->timer == NULL) {
		lth->timer = loop_timer_new(h2d_loop, h2d_lua_api_sleep_timeout, NULL);
	}

	lua_Number value = lua_tonumber(L, -1);
	loop_timer_set_after(lth->timer, value * 1000); /* second -> ms */
	printf("Lua add timer: %f\n", value);
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

static int h2d_lua_api_subrequest_resume(void *data)
{
	struct h2d_lua_api_thread *lth = h2d_lua_api_current->lth;
	lua_State *L = lth->L;

	struct h2d_request *subr;
	wuy_list_first_type(&h2d_lua_api_current->subr_head, subr, subr_node); // XXX maybe other subrequest

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

	subr->father = NULL;
	h2d_request_close(subr);

	return 1;
}
static int h2d_lua_api_subrequest(lua_State *L)
{
	h2d_lua_api_check_blocking(L, "subrequest");

	const char *uri = lua_tostring(L, -1);

	struct h2d_request *subr = h2d_request_subrequest(h2d_lua_api_current, uri);
	subr->req.method = WUY_HTTP_GET;

	h2d_lua_api_current->lth->resume.handler = h2d_lua_api_subrequest_resume;

	return lua_yield(L, 0);
}

static const struct luaL_Reg h2d_lua_api_list [] = {
	{ "uri_raw", h2d_lua_api_uri_raw},
	{ "uri_path", h2d_lua_api_uri_path },
	{ "host", h2d_lua_api_host },
	{ "headers", h2d_lua_api_headers },
	{ "status_code", h2d_lua_api_status_code },
	{ "sleep", h2d_lua_api_sleep },
	{ "subrequest", h2d_lua_api_subrequest },
	{ NULL, NULL }  /* sentinel */
};


/* Lua functions for C code to call */
static lua_State *h2d_lua_api_L;

const char *h2d_lua_api_str_gsub(const char *s, const char *pattern, const char *repl)
{
	lua_getglobal(h2d_lua_api_L, "string");
	lua_getfield(h2d_lua_api_L, -1, "gsub");

	lua_pushstring(h2d_lua_api_L, s);
	lua_pushstring(h2d_lua_api_L, pattern);
	lua_pushstring(h2d_lua_api_L, repl);
	if (lua_pcall(h2d_lua_api_L, 3, 2, 0) != 0){
		printf("error in lua_pcall\n");
		return NULL;
	}

	const char *out = lua_tostring(h2d_lua_api_L, -2);
	int n = lua_tointeger(h2d_lua_api_L, -1);

	/* 2 return values and 1 function */
	lua_pop(h2d_lua_api_L, 3);

	return n != 0 ? out : NULL;
}

bool h2d_lua_api_str_find(const char *s, const char *pattern)
{
	lua_getglobal(h2d_lua_api_L, "string");
	lua_getfield(h2d_lua_api_L, -1, "find");

	lua_pushstring(h2d_lua_api_L, s);
	lua_pushstring(h2d_lua_api_L, pattern);
	if (lua_pcall(h2d_lua_api_L, 2, 2, 0) != 0){
		printf("error in lua_pcall\n");
		return NULL;
	}

	bool found = lua_isnumber(h2d_lua_api_L, -1);

	/* 2 return values and 1 function */
	lua_pop(h2d_lua_api_L, 3);

	return found;
}

void h2d_lua_api_init(void)
{
	/* C functions for Lua code to call */
	luaL_register(h2d_L, "h2d", h2d_lua_api_list);

	/* Lua functions for C code to call */
	h2d_lua_api_L = lua_open();
	luaL_openlibs(h2d_lua_api_L);
}
