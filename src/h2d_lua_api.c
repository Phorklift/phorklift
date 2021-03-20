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

	struct h2d_lua_thread *lth = &h2d_lua_api_current->lth;
	lth->data = subr;
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
	r->resp.break_body_len = len;
	r->resp.break_body_buf = wuy_pool_strndup(r->pool, s, len);
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

static int h2d_lua_api_get_header(lua_State *L, wuy_slist_t *headers)
{
	const char *name = lua_tostring(L, -1);
	if (name == NULL) {
		return 0;
	}

	struct h2d_header *h;
	h2d_header_iter(headers, h) {
		if (strcasecmp(name, h->str) == 0) {
			lua_pushstring(L, h2d_header_value(h));
			return 1;
		}
	}
	return 0;
}

static int h2d_lua_api_add_header(lua_State *L, wuy_slist_t *headers)
{
	size_t name_len, value_len;
	const char *name_str = lua_tolstring(L, -2, &name_len);
	const char *value_str = lua_tolstring(L, -1, &value_len);
	if (name_str != NULL && value_str != NULL) {
		h2d_header_add(headers, name_str, name_len,
				value_str, value_len, h2d_lua_api_current->pool);
	}
	return 0;
}

static int h2d_lua_api_delete_header(lua_State *L, wuy_slist_t *headers)
{
	const char *name = lua_tostring(L, -1);
	if (name != NULL) {
		h2d_header_delete(headers, name);
	}
	return 0;
}

static int h2d_lua_api_set_header(lua_State *L, wuy_slist_t *headers)
{
	h2d_lua_api_delete_header(L, headers);
	return h2d_lua_api_add_header(L, headers);
}

static int h2d_lua_api_req_get_query(lua_State *L, const char *query_str, int query_len)
{
	if (query_str == NULL) {
		return 0;
	}

	size_t key_len;
	const char *key_str = lua_tolstring(L, -1, &key_len);
	if (key_str == NULL) {
		return 0;
	}

	char value_str[query_len];
	int value_len = wuy_http_uri_query_get(query_str, query_len,
			key_str, key_len, value_str);
	if (value_len < 0) {
		return 0;
	}

	lua_pushlstring(L, value_str, value_len);
	return 1;
}

static void h2d_lua_api_req_queries(lua_State *L, const char *query_str, int query_len)
{
	lua_newtable(L);

	if (query_str == NULL) {
		return;
	}

	const char *p = query_str;
	const char *end = query_str + query_len;

	while (p < end) {
		char value_buf[query_len];
		int key_len, value_len;

		int proc_len = wuy_http_uri_query_first(p, end - p, &key_len, value_buf, &value_len);
		if (proc_len < 0) {
			break;
		}

		lua_pushlstring(L, p + 1, key_len);
		lua_pushlstring(L, value_buf, value_len);
		lua_settable(L, -3);

		p += proc_len;
	}
}

static int h2d_lua_api_req_get_uri_query(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current;
	return h2d_lua_api_req_get_query(L, r->req.uri.query_pos, r->req.uri.query_len);
}
static int h2d_lua_api_req_get_body_query(lua_State *L)
{
	struct h2d_request *r = h2d_lua_api_current;
	return h2d_lua_api_req_get_query(L, (const char *)r->req.body_buf, r->req.body_len);
}
static int h2d_lua_api_req_get_header(lua_State *L)
{
	return h2d_lua_api_get_header(L, &h2d_lua_api_current->req.headers);
}
static int h2d_lua_api_req_add_header(lua_State *L)
{
	return h2d_lua_api_add_header(L, &h2d_lua_api_current->req.headers);
}
static int h2d_lua_api_req_delete_header(lua_State *L)
{
	return h2d_lua_api_delete_header(L, &h2d_lua_api_current->req.headers);
}
static int h2d_lua_api_req_set_header(lua_State *L)
{
	return h2d_lua_api_set_header(L, &h2d_lua_api_current->req.headers);
}

static const struct luaL_Reg h2d_lua_api_req_functions[] = {
	{ "get_uri_query", h2d_lua_api_req_get_uri_query },
	{ "get_body_query", h2d_lua_api_req_get_body_query },
	{ "get_header", h2d_lua_api_req_get_header },
	{ "add_header", h2d_lua_api_req_add_header },
	{ "delete_header", h2d_lua_api_req_delete_header },
	{ "set_header", h2d_lua_api_req_set_header },
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

	} else if (strcmp(key, "uri_queries") == 0) {
		h2d_lua_api_req_queries(L, r->req.uri.query_pos, r->req.uri.query_len);

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

	} else if (strcmp(key, "body_queries") == 0) {
		h2d_lua_api_req_queries(L, (char *)r->req.body_buf, r->req.body_len);

	} else {
		lua_pushnil(L);
	}
	return 1;
}


/* packet: resp */

static int h2d_lua_api_resp_get_header(lua_State *L)
{
	return h2d_lua_api_get_header(L, &h2d_lua_api_current->resp.headers);
}
static int h2d_lua_api_resp_add_header(lua_State *L)
{
	return h2d_lua_api_add_header(L, &h2d_lua_api_current->resp.headers);
}
static int h2d_lua_api_resp_delete_header(lua_State *L)
{
	return h2d_lua_api_delete_header(L, &h2d_lua_api_current->resp.headers);
}
static int h2d_lua_api_resp_set_header(lua_State *L)
{
	return h2d_lua_api_set_header(L, &h2d_lua_api_current->resp.headers);
}

static const struct luaL_Reg h2d_lua_api_resp_functions[] = {
	{ "get_header", h2d_lua_api_resp_get_header },
	{ "add_header", h2d_lua_api_resp_add_header },
	{ "delete_header", h2d_lua_api_resp_delete_header },
	{ "set_header", h2d_lua_api_resp_set_header },
	{ NULL, NULL }  /* sentinel */
};

static int h2d_lua_api_resp_mm_index(lua_State *L)
{
	const char *key = lua_tostring(L, -1);
	if (key == NULL) {
		return 0;
	}

	struct h2d_request *r = h2d_lua_api_current;

	if (strcmp(key, "status_code") == 0) {
		lua_pushinteger(L, r->resp.status_code);

	} else if (strcmp(key, "headers") == 0) {
		lua_newtable(L);
		struct h2d_header *h;
		h2d_header_iter(&r->resp.headers, h) {
			lua_pushstring(L, h2d_header_value(h));
			lua_setfield(L, -2, h->str);
		}

	} else if (strcmp(key, "body") == 0) {
		// TODO
		lua_pushnil(L);

	} else if (strcmp(key, "react_ms") == 0) {
		lua_pushinteger(L, r->resp_begin_time - r->req_end_time);

	} else if (strcmp(key, "content_ms") == 0) {
		lua_pushinteger(L, wuy_time_ms() - r->resp_begin_time);
	} else {
		lua_pushnil(L);
	}
	return 1;
}


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
			h2d_lua_api_req_mm_index, NULL);
	h2d_lua_api_add_object("resp", h2d_lua_api_resp_functions,
			h2d_lua_api_resp_mm_index, NULL);

	lua_setglobal(h2d_L, "h2d");
}
