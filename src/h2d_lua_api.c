#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

struct h2d_request *h2d_lua_api_current;

/* top constants and functions */

static const struct h2d_lua_api_reg_int h2d_lua_api_const_ints[] = {

#define X(m) { "HTTP_"#m, WUY_HTTP_##m },
	WUY_HTTP_METHOD_TABLE
#undef X

#define X(c, d) { "HTTP_"#c, WUY_HTTP_##c },
	WUY_HTTP_STATUS_CODE_TABLE
#undef X

#define X(c, l) { #c, H2D_LOG_##c },
	H2D_LOG_LEVEL_TABLE
#undef X
	{ NULL },

};

static int64_t h2d_lua_api_sleep_timeout(int64_t at, void *data)
{
	h2d_request_run(h2d_lua_api_current, "lua sleep");
	return 0;
}
static int h2d_lua_api_sleep_resume(lua_State *L)
{
	loop_timer_t *timer = lua_touserdata(L, -1);
	loop_timer_delete(timer);
	lua_pop(L, 2); /* pop resume_handler and argument */
	return 0;
}
static int h2d_lua_api_sleep(lua_State *L)
{
	loop_timer_t *timer = loop_timer_new(h2d_loop,
			h2d_lua_api_sleep_timeout, NULL);

	lua_Number value = lua_tonumber(L, -1);
	loop_timer_set_after(timer, value * 1000); /* second -> ms */

	/* push resume_handler and argument */
	lua_pushcfunction(L, h2d_lua_api_sleep_resume);
	lua_pushlightuserdata(L, timer);
	return lua_yield(L, 2);
}

static int h2d_lua_api_subrequest_resume(lua_State *L)
{
	struct h2d_request *subr = lua_touserdata(L, -1);
	lua_pop(L, 2); /* pop resume_handler and argument */

	lua_newtable(L);

	lua_pushinteger(L, subr->resp.status_code);
	lua_setfield(L, -2, "status_code");

	lua_pushlstring(L, (char *)subr->c->send_buffer, subr->c->send_buf_len);
	lua_setfield(L, -2, "body");

	lua_newtable(L);
	struct h2d_header *h;
	h2d_header_iter(&h2d_lua_api_current->resp.headers, h) {
		lua_pushstring(L, h2d_header_value(h));
		lua_setfield(L, -2, h->str);
	}
	lua_setfield(L, -2, "headers");

	h2d_request_subr_close(subr);

	return 1;
}

static bool h2d_lua_api_subrequest_options(lua_State *L, struct h2d_request *subr)
{
	/* parse options one by one */

	lua_getfield(L, 2, "method");
	enum wuy_http_method method = lua_tonumber(L, -1);
	if (method > 0) {
		subr->req.method = method;
	}
	lua_pop(L, 1);

	lua_getfield(L, 2, "queries");
	if (lua_isstring(L, -1)) {
		size_t len;
		const char *str = lua_tolstring(L, -1, &len);
		subr->req.uri.query_len = len;
		subr->req.uri.query_pos = wuy_pool_strndup(subr->pool, str, len);

	} else if (lua_istable(L, -1)) {
		char tmpbuf[4096];
		char *p = tmpbuf, *end = tmpbuf + sizeof(tmpbuf);
		lua_pushnil(L);
		while (lua_next(L, -2) != 0) {
			size_t key_len, value_len;
			const char *key_str = lua_tolstring(L, -2, &key_len);
			const char *value_str = lua_tolstring(L, -1, &value_len);
			p += wuy_http_encode_query(key_str, key_len, value_str, value_len, p, end - p);
			lua_pop(L, 1);
		}
		tmpbuf[0] = '?';
		subr->req.uri.query_len = p - tmpbuf;
		subr->req.uri.query_pos = wuy_pool_strndup(subr->pool, tmpbuf, p - tmpbuf);
	}
	lua_pop(L, 1);

	lua_getfield(L, 2, "headers");
	if (lua_istable(L, -1)) {
		lua_pushnil(L);
		while (lua_next(L, -2) != 0) {
			size_t name_len, value_len;
			const char *name_str = lua_tolstring(L, -2, &name_len);
			const char *value_str = lua_tolstring(L, -1, &value_len);
			h2d_header_add(&subr->req.headers, name_str, name_len,
					value_str, value_len, subr->pool);
			lua_pop(L, 1);
		}
	}
	lua_pop(L, 1);

	lua_getfield(L, 2, "body");
	size_t body_len;
	const void *body_buf = lua_tolstring(L, -1, &body_len);
	if (body_buf != NULL) {
		subr->req.content_length = body_len;
		h2d_request_append_body(subr, body_buf, body_len);
	}
	lua_pop(L, 1);

	lua_getfield(L, 2, "detach"); /* at last */
	if (lua_toboolean(L, -1)) {
		h2d_request_subr_detach(subr);
		return false;
	}
	lua_pop(L, 1);

	return true;
}

static int h2d_lua_api_subrequest(lua_State *L)
{
	/* argument uri @stack:1*/
	const char *uri = lua_tostring(L, 1);

	struct h2d_request *subr = h2d_request_subr_new(h2d_lua_api_current, uri);
	if (subr == NULL) {
		return 0;
	}

	/* options @stack:2 */
	if (lua_istable(L, 2)) {
		if (!h2d_lua_api_subrequest_options(L, subr)) {
			return 0;
		}
	}

	/* push resume_handler and argument */
	lua_pushcfunction(L, h2d_lua_api_subrequest_resume);
	lua_pushlightuserdata(L, subr);
	return lua_yield(L, 2);
}

static int h2d_lua_api_dump(lua_State *L, int start, char *buffer, int buf_size)
{
	char *p = buffer;

	int narg = lua_gettop(L);
	for (int i = start; i <= narg; i++) {
		const char *s;
		size_t len;
		switch (lua_type(L, i)) {
		case LUA_TNUMBER:
		case LUA_TSTRING:
			s = lua_tolstring(L, i, &len);
			break;
		case LUA_TBOOLEAN:
			if (lua_toboolean(L, i)) {
				s = "true";
				len = 4;
			} else {
				s = "false";
				len = 5;
			}
			break;
		case LUA_TNIL:
			s = "nil";
			len = 3;
			break;
		default:
			s = "[not-support-type-object]";
			len = strlen(s);
			break;
		}

		if (len >= buffer + buf_size - p - 4) {
			strcpy(p, "...");
			p += 3;
			break;
		}
		memcpy(p, s, len);
		p += len;
	}
	return p - buffer;
}

static int h2d_lua_api_log(lua_State *L)
{
	enum h2d_log_level level = luaL_checkint(L, 1);

	char buffer[4096];
	int len = h2d_lua_api_dump(L, 2, buffer, sizeof(buffer));

	h2d_request_log(h2d_lua_api_current, level, "[lua-api] %.*s", len, buffer);
	return 0;
}

static int h2d_lua_api_echo(lua_State *L)
{
	size_t len;
	const char *s = lua_tolstring(L, -1, &len);
	if (s == NULL) {
		return 0;
	}

	struct h2d_request *r = h2d_lua_api_current;
	r->resp.easy_string = wuy_pool_strndup(r->pool, s, len);
	r->resp.easy_str_len = len;
	return 0;
}

static int h2d_lua_api_exit(lua_State *L)
{
	int status_code = lua_tointeger(L, -1);
	if (status_code == 0) {
		status_code = WUY_HTTP_500;
	}

	h2d_lua_api_current->resp.status_code = status_code;

	lua_pushstring(L, "h2d.exit()");
	return lua_error(L);
}

static const struct h2d_lua_api_reg_func h2d_lua_api_functions[] = {
	{ "sleep", h2d_lua_api_sleep },
	{ "subrequest", h2d_lua_api_subrequest },
	{ "log", h2d_lua_api_log },
	{ "echo", h2d_lua_api_echo },
	{ "exit", h2d_lua_api_exit },
	{ NULL }  /* sentinel */
};


/* register */

static void h2d_lua_api_add_const_ints(const struct h2d_lua_api_reg_int *list)
{
	for (const struct h2d_lua_api_reg_int *r = list; r->name != NULL; r++) {
		lua_pushinteger(h2d_L, r->n);
		lua_setfield(h2d_L, -2, r->name);
	}
}

static void h2d_lua_api_add_functions(const struct h2d_lua_api_reg_func *list)
{
	for (const struct h2d_lua_api_reg_func *r = list; r->name != NULL; r++) {
		lua_pushcfunction(h2d_L, r->f);
		lua_setfield(h2d_L, -2, r->name);
	}
}

static void h2d_lua_api_register(const struct h2d_lua_api_package *p)
{
	lua_newtable(h2d_L);

	if (p->ref != NULL) {
		lua_pushvalue(h2d_L, -1);
		*p->ref = luaL_ref(h2d_L, LUA_REGISTRYINDEX);

		/* maybe covered by p->funcs */
		lua_pushvalue(h2d_L, -1);
		lua_setfield(h2d_L, -2, "__index");
	}
	if (p->init != NULL) {
		p->init();
	}
	if (p->const_ints != NULL) {
		h2d_lua_api_add_const_ints(p->const_ints);
	}
	if (p->funcs != NULL) {
		h2d_lua_api_add_functions(p->funcs);
	}

	/* for __index and __newindex */
	lua_pushvalue(h2d_L, -1);
	lua_setmetatable(h2d_L, -2);

	lua_setfield(h2d_L, -2, p->name);
}


#define X(p) extern const struct h2d_lua_api_package p;
H2D_LUAAPI_X_LIST
#undef X

void h2d_lua_api_init(void)
{
	lua_newtable(h2d_L);

	h2d_lua_api_add_const_ints(h2d_lua_api_const_ints);
	h2d_lua_api_add_functions(h2d_lua_api_functions);

	#define X(p) h2d_lua_api_register(&p);
	H2D_LUAAPI_X_LIST
	#undef X

	lua_setglobal(h2d_L, "h2d");
}
