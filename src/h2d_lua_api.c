#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)

struct h2d_request *h2d_lua_api_current;

/* top constants and functions */

static const struct h2d_lua_api_const_int h2d_lua_api_top_consts[] = {

#define X(m) { #m, WUY_HTTP_##m },
	WUY_HTTP_METHOD_TABLE
#undef X

#define X(c, l) { #c, H2D_LOG_##c },
	H2D_LOG_LEVEL_TABLE
#undef X
	{ NULL },

};

static int64_t h2d_lua_api_sleep_timeout(int64_t at, void *data)
{
	printf("Lua timer finish.\n");
	h2d_request_active(h2d_lua_api_current, "lua sleep");
	return 0;
}
static int h2d_lua_api_sleep_resume(void)
{
	struct h2d_lua_thread *lth = &h2d_lua_api_current->lth;
	loop_timer_delete(lth->data);
	return 0;
}
static int h2d_lua_api_sleep(lua_State *L)
{
	struct h2d_lua_thread *lth = &h2d_lua_api_current->lth;

	lth->data = loop_timer_new(h2d_loop, h2d_lua_api_sleep_timeout, NULL);

	lua_Number value = lua_tonumber(L, -1);
	loop_timer_set_after(lth->data, value * 1000); /* second -> ms */
	printf("Lua add timer: %f\n", value);

	lth->resume_handler = h2d_lua_api_sleep_resume;

	return lua_yield(L, 0);
}

static int h2d_lua_api_subrequest_resume(void)
{
	struct h2d_lua_thread *lth = &h2d_lua_api_current->lth;
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
	struct h2d_lua_thread *lth = &h2d_lua_api_current->lth;

	const char *uri = lua_tostring(L, -1);

	lth->data = h2d_request_subr_new(h2d_lua_api_current, uri);

	lth->resume_handler = h2d_lua_api_subrequest_resume;

	return lua_yield(L, 0);
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

	h2d_request_log(h2d_lua_api_current, level, "[lua-api] %*s", len, buffer);
	return 0;
}

static int h2d_lua_api_echo(lua_State *L)
{
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

static const struct luaL_Reg h2d_lua_api_top_functions[] = {
	{ "sleep", h2d_lua_api_sleep },
	{ "subrequest", h2d_lua_api_subrequest },
	{ "log", h2d_lua_api_log },
	{ "echo", h2d_lua_api_echo },
	{ "exit", h2d_lua_api_exit },
	{ NULL, NULL }  /* sentinel */
};


/* package: req */

static int h2d_lua_api_req_get_header(lua_State *L)
{
	const char *name = lua_tostring(L, -1);
	if (name == NULL) {
		return 0;
	}

	struct h2d_header *h;
	h2d_header_iter(&h2d_lua_api_current->req.headers, h) {
		if (strcasecmp(name, h->str) == 0) {
			lua_pushstring(L, h2d_header_value(h));
			return 1;
		}
	}
	return 0;
}

static int h2d_lua_api_req_add_header(lua_State *L)
{
	size_t name_len, value_len;
	const char *name_str = lua_tolstring(L, -2, &name_len);
	const char *value_str = lua_tolstring(L, -1, &value_len);
	if (name_str == NULL) {
		return 0;
	}

	h2d_header_add(&h2d_lua_api_current->req.headers, name_str, name_len,
			value_str, value_len, h2d_lua_api_current->pool);
	return 0;
}

static int h2d_lua_api_req_set_header(lua_State *L)
{
	const char *name = lua_tostring(L, -2);
	if (name == NULL) {
		return 0;
	}

	struct h2d_header *h;
	h2d_header_iter(&h2d_lua_api_current->req.headers, h) {
		if (strcasecmp(name, h->str) == 0) {
			// TODO delete
		}
	}

	return h2d_lua_api_req_add_header(L);
}

static const struct luaL_Reg h2d_lua_api_req_functions[] = {
	{ "get_header", h2d_lua_api_req_get_header },
	{ "set_header", h2d_lua_api_req_set_header },
	{ "add_header", h2d_lua_api_req_add_header },
	{ NULL, NULL }  /* sentinel */
};

static int h2d_lua_api_req_mm_index(lua_State *L)
{
	const char *key = lua_tostring(L, -1);
	if (key == NULL) {
		return 0;
	}

	struct h2d_request *r = h2d_lua_api_current;

	if (strcmp(key, "method") == 0) {
		lua_pushinteger(L, r->req.method);

	} else if (strcmp(key, "uri_raw") == 0) {
		lua_pushstring(L, r->req.uri.raw);

	} else if (strcmp(key, "uri_path") == 0) {
		lua_pushstring(L, r->req.uri.path);

	} else if (strcmp(key, "host") == 0) {
		lua_pushstring(L, r->req.host);

	} else if (strcmp(key, "headers") == 0) {
		lua_newtable(L);
		struct h2d_header *h;
		h2d_header_iter(&r->req.headers, h) {
			lua_pushstring(L, h2d_header_value(h));
			lua_setfield(L, -2, h->str);
		}

	} else if (strcmp(key, "body") == 0) {
		lua_pushlstring(L, (char *)r->req.body_buf, r->req.body_len);

	} else {
		lua_pushnil(L);
	}
	return 1;
}

static int h2d_lua_api_req_mm_newindex(lua_State *L)
{
	return 0;
}


/* packet: resp */


/* register */

static void h2d_lua_api_add_const_int(const struct h2d_lua_api_const_int *list)
{
	for (const struct h2d_lua_api_const_int *r = list; r->name != NULL; r++) {
		lua_pushstring(h2d_L, r->name);
		lua_pushinteger(h2d_L, r->n);
		lua_settable(h2d_L, -3);
	}
}

static void h2d_lua_api_add_functions(const struct luaL_Reg *list)
{
	for (const struct luaL_Reg *r = list; r->name != NULL; r++) {
		lua_pushstring(h2d_L, r->name);
		lua_pushcfunction(h2d_L, r->func);
		lua_settable(h2d_L, -3);
	}
}

void h2d_lua_api_add_object(const char *name, const struct luaL_Reg *list,
		lua_CFunction index_f, lua_CFunction newindex_f)
{
	lua_newtable(h2d_L);

	if (list != NULL) {
		h2d_lua_api_add_functions(list);
	}

	if (index_f != NULL) {
		lua_pushcfunction(h2d_L, index_f);
		lua_setfield(h2d_L, -2, "__index");
	}

	if (newindex_f != NULL) {
		lua_pushcfunction(h2d_L, newindex_f);
		lua_setfield(h2d_L, -2, "__newindex");
	}

	lua_pushvalue(h2d_L, -1);
	lua_setmetatable(h2d_L, -2);

	lua_setfield(h2d_L, -2, name);
}

void h2d_lua_api_init(void)
{
	lua_newtable(h2d_L);

	h2d_lua_api_add_const_int(h2d_lua_api_top_consts);
	h2d_lua_api_add_functions(h2d_lua_api_top_functions);

	h2d_lua_api_add_object("req", h2d_lua_api_req_functions,
			h2d_lua_api_req_mm_index, h2d_lua_api_req_mm_newindex);

	lua_setglobal(h2d_L, "h2d");
}
