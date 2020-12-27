#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

/* C functions for Lua code to call */

static struct h2d_lua_api_thread *h2d_lua_api_current;

struct h2d_lua_api_thread *h2d_lua_api_thread_new(wuy_cflua_function_t entry,
		struct h2d_request *r)
{
	struct h2d_lua_api_thread *lth = calloc(1, sizeof(struct h2d_lua_api_thread));

	lth->r = r;
	lth->L = lua_newthread(h2d_L);

	/* mark it to avoid GC */
	/* TODO i am not sure whether this is the right way ... */
	lua_pushlightuserdata(h2d_L, lth->L); /* use pointer as key */
	lua_insert(h2d_L, -2); /* use thread as value */
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	/* push entry function */
	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, entry);
	lua_xmove(h2d_L, lth->L, 1);

	h2d_request_log(r, H2D_LOG_DEBUG, "new Lua thread %p", lth);

	return lth;
}

static int h2d_lua_api_thread_set_argn_handler(void)
{
	return (uintptr_t)(h2d_lua_api_current->resume.data);
}
void h2d_lua_api_thread_set_argn(struct h2d_lua_api_thread *lth, int argn)
{
	lth->resume.handler = h2d_lua_api_thread_set_argn_handler;
	lth->resume.data = (void *)(uintptr_t)argn;
}

int h2d_lua_api_thread_resume(struct h2d_lua_api_thread *lth)
{
	h2d_lua_api_current = lth;

	h2d_request_log(lth->r, H2D_LOG_DEBUG, "Lua thread resume %p", lth);

	int argn = 0;
	if (lth->resume.handler != NULL) {
		argn = lth->resume.handler();
		if (argn < 0) {
			return argn;
		}
		lth->resume.handler = NULL;
	}

	h2d_request_log(lth->r, H2D_LOG_DEBUG, "call lua_resume args=%d", argn);

	int ret = lua_resume(lth->L, argn);

	h2d_request_log(lth->r, H2D_LOG_DEBUG, "lua_resume returns %d", ret);

	if (ret == LUA_YIELD) {
		return H2D_AGAIN;
	}
	if (ret != 0) {
		return H2D_ERROR;
	}
	return H2D_OK;
}

void h2d_lua_api_thread_free(struct h2d_lua_api_thread *lth)
{
	if (lth == NULL) {
		return;
	}

	h2d_request_log(lth->r, H2D_LOG_DEBUG, "free Lua thread %p", lth);

	/* un-mark it for GC */
	lua_pushlightuserdata(h2d_L, lth->L);
	lua_pushnil(h2d_L);
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	loop_timer_delete(lth->timer);

	free(lth);
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
	struct h2d_lua_api_thread lth = {.r = r};
	h2d_lua_api_current = &lth;

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
	struct h2d_lua_api_thread *lth = data;
	h2d_request_active(lth->r, "lua sleep");
	return 0;
}
static int h2d_lua_api_sleep(lua_State *L)
{
	h2d_lua_api_check_blocking(L, "sleep");

	if (h2d_lua_api_current->timer == NULL) {
		h2d_lua_api_current->timer = loop_timer_new(h2d_loop,
				h2d_lua_api_sleep_timeout,
				h2d_lua_api_current);
	}

	lua_Number value = lua_tonumber(L, -1);
	loop_timer_set_after(h2d_lua_api_current->timer, value * 1000); /* second -> ms */
	printf("Lua add timer: %f\n", value);
	return lua_yield(L, 0);
}

static int h2d_lua_api_uri_raw(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current->r;
	lua_pushstring(L, r->req.uri.raw);
	return 1;
}
static int h2d_lua_api_uri_path(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current->r;
	lua_pushstring(L, r->req.uri.path);
	return 1;
}
static int h2d_lua_api_host(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current->r;
	lua_pushstring(L, r->req.host);
	return 1;
}

static int h2d_lua_api_headers(lua_State *L)
{
	lua_newtable(L);

	struct h2d_request *r = h2d_lua_api_current->r;
	struct h2d_header *h;
	h2d_header_iter(&r->req.headers, h) {
		lua_pushstring(L, h2d_header_value(h));
		lua_setfield(L, -2, h->str);
	}

	return 1;
}

static int h2d_lua_api_status_code(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current->r;
	lua_pushinteger(L, r->resp.status_code);
	return 1;
}

static int h2d_lua_api_subrequest_resume(void)
{
	struct h2d_request *r = h2d_lua_api_current->r;
	lua_State *L = h2d_lua_api_current->L;

	struct h2d_request *subr;
	wuy_list_first_type(&r->subr_head, subr, subr_node); // XXX maybe other subrequest

	lua_newtable(L);

	lua_pushinteger(L, subr->resp.status_code);
	lua_setfield(L, -2, "status_code");

	lua_pushlstring(L, (char *)subr->c->send_buffer, subr->c->send_buf_pos - subr->c->send_buffer);
	lua_setfield(L, -2, "body");

	lua_newtable(L);
	struct h2d_header *h;
	h2d_header_iter(&r->resp.headers, h) {
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

	struct h2d_request *subr = h2d_request_subrequest(h2d_lua_api_current->r, uri);
	subr->req.method = WUY_HTTP_GET;

	h2d_lua_api_current->resume.handler = h2d_lua_api_subrequest_resume;

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
