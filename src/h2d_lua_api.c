#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

static struct h2d_request *h2d_lua_api_current_request;

#define H2D_LUA_API_RESUME_HANDLER_KEY "HLARH_KEY___"

lua_State *h2d_lua_api_thread_new(wuy_cflua_function_t entry)
{
	lua_State *new_L = lua_newthread(h2d_L);

	/* mark it to avoid GC */
	/* TODO i am not sure whether this is the right way ... */
	lua_pushlightuserdata(h2d_L, new_L); /* use pointer as key */
	lua_insert(h2d_L, -2); /* use thread as value */
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	/* push entry function */
	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, entry);
	lua_xmove(h2d_L, new_L, 1);

	return new_L;
}

int h2d_lua_api_thread_resume(lua_State *L, struct h2d_request *r)
{
	h2d_lua_api_current_request = r;

	int argn = 0;

	lua_getfield(L, LUA_REGISTRYINDEX, H2D_LUA_API_RESUME_HANDLER_KEY);
	int (*resume_handler)(lua_State *) = lua_touserdata(L, -1);
	lua_pop(L, 1);
	if (resume_handler != NULL) {
		argn = resume_handler(L);
		if (argn < 0) {
			return H2D_ERROR;
		}

		/* reset resume-handler */
		lua_pushnil(L);
		lua_setfield(L, LUA_REGISTRYINDEX, H2D_LUA_API_RESUME_HANDLER_KEY);
	}

	h2d_request_log(r, H2D_LOG_DEBUG, "lua_resume %d\n", argn);

	int ret = lua_resume(L, argn);
	if (ret == LUA_YIELD) {
		return H2D_AGAIN;
	}
	if (ret != 0) {
		return H2D_ERROR;
	}

	return H2D_OK;
}

void h2d_lua_api_thread_free(lua_State *L)
{
	if (L == NULL) {
		return;
	}
	/* un-mark it for GC */
	lua_pushlightuserdata(h2d_L, L);
	lua_pushnil(h2d_L);
	lua_settable(h2d_L, LUA_REGISTRYINDEX);
}

static bool h2d_lua_api_call(struct h2d_request *r, wuy_cflua_function_t f)
{
	h2d_lua_api_current_request = r;

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
		*plen = -WUY_HTTP_500;
		return NULL;
	}

	size_t len;
	const char *str = lua_tolstring(h2d_L, -1, &len);
	if (plen != NULL) {
		*plen = (str != NULL) ? len : -WUY_HTTP_400;
	}

	/* Although not documented, lua_pop() does not trigger GC.
	 * So the string is safe until next Lua process. */
	lua_pop(h2d_L, 1);

	return str;
}

int h2d_lua_api_call_boolean(struct h2d_request *r,
		wuy_cflua_function_t f)
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
	// XXX the request may closed yet!!!
	// maybe should close the timer in ctx-free
	printf("Lua timer finish.\n");
	lua_State *L = data;

	struct h2d_request *r = NULL;
	h2d_lua_api_thread_resume(L, r); // XXX
	h2d_request_active(r);
	return -1;
}
static int h2d_lua_api_sleep(lua_State *L)
{
	loop_timer_t *timer = loop_timer_new(h2d_loop, h2d_lua_api_sleep_timeout, L);

	lua_Number value = lua_tonumber(L, -1);
	loop_timer_set_after(timer, value * 1000); /* second -> ms */
	printf("Lua add timer: %f\n", value);
	return lua_yield(L, 0);
}

static int h2d_lua_api_uri_raw(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current_request;
	lua_pushstring(L, r->req.uri.raw);
	return 1;
}
static int h2d_lua_api_uri_path(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current_request;
	lua_pushstring(L, r->req.uri.path);
	return 1;
}

static int h2d_lua_api_headers(lua_State *L)
{
	lua_newtable(L);

	struct h2d_request *r = h2d_lua_api_current_request;
	struct h2d_header *h;
	h2d_header_iter(&r->req.headers, h) {
		lua_pushstring(L, h2d_header_value(h));
		lua_setfield(L, -2, h->str);
	}

	return 1;
}

static int h2d_lua_api_status_code(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current_request;
	lua_pushinteger(L, r->resp.status_code);
	return 1;
}

static int h2d_lua_api_subrequest_resume(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current_request;

	struct h2d_request *subr;
	wuy_list_first_type(&r->subr_head, subr, subr_node); // XXX maybe other subrequest

	lua_newtable(L);

	lua_pushinteger(L, subr->resp.status_code);
	lua_setfield(L, -2, "status");

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
	size_t len;
	const char *uri = lua_tolstring(L, -1, &len);

	struct h2d_request *subr = h2d_request_subrequest(h2d_lua_api_current_request);
	h2d_request_set_uri(subr, uri, len);

	lua_pushlightuserdata(L, h2d_lua_api_subrequest_resume);
	lua_setfield(L, LUA_REGISTRYINDEX, H2D_LUA_API_RESUME_HANDLER_KEY);

	return lua_yield(L, 0);
}

static const struct luaL_Reg h2d_lua_api_list [] = {
	{ "uri_raw", h2d_lua_api_uri_raw},
	{ "uri_path", h2d_lua_api_uri_path },
	{ "headers", h2d_lua_api_headers },
	{ "status_code", h2d_lua_api_status_code },
	{ "sleep", h2d_lua_api_sleep },
	{ "subrequest", h2d_lua_api_subrequest },
	{ NULL, NULL }  /* sentinel */
};

void h2d_lua_api_init(void)
{
	luaL_register(h2d_L, "h2d", h2d_lua_api_list);
}
