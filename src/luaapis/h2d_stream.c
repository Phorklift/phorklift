#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log(r, level, "lua: " fmt, ##__VA_ARGS__)


static void h2d_stream_on_active(loop_stream_t *s)
{
	h2d_request_run(loop_stream_get_app_data(s), "lua h2d.stream active");
}

static loop_stream_ops_t h2d_stream_ops = {
	.on_readable = h2d_stream_on_active,
	.on_writable = h2d_stream_on_active,

	H2D_SSL_LOOP_STREAM_UNDERLYINGS 
};

static int h2d_stream_connect(lua_State *L)
{
	const char *address = lua_tostring(L, 1);
	if (address == NULL) {
		lua_pushstring(L, "stream.connect(): invalid address");
		return lua_error(L);
	}

	loop_stream_t *s = loop_tcp_connect(h2d_loop, address, 0, &h2d_stream_ops);
	if (s == NULL) {
		return 0;
	}

	loop_stream_set_app_data(s, h2d_lua_api_current);

	lua_pushlightuserdata(L, s);
	return 1;
}

static int h2d_stream_send_resume(lua_State *L)
{
	loop_stream_t *s = lua_touserdata(L, 2);

	size_t data_len;
	const char *data = lua_tolstring(L, 3, &data_len);

	int prewrite_len = lua_tointeger(L, 4);

	int write_len = loop_stream_write(s, data + prewrite_len, data_len - prewrite_len);
	if (write_len < 0) {
		lua_pushstring(L, loop_stream_close_string(write_len));
		return 1;
	}
	if (write_len == data_len - prewrite_len) {
		return 0;
	}

	/* write blocks, again */
	lua_pop(L, 1);
	lua_pushinteger(L, prewrite_len + write_len);

	return H2D_AGAIN;
}

static int h2d_stream_send(lua_State *L)
{
	loop_stream_t *s = lua_touserdata(L, 1);
	if (s == NULL) {
		lua_pushstring(L, "stream.send(): invalid address");
		return lua_error(L);
	}

	size_t data_len;
	const char *data = lua_tolstring(L, 2, &data_len);
	if (data == NULL) {
		lua_pushstring(L, "stream.send(): invalid data");
		return lua_error(L);
	}

	int write_len = loop_stream_write(s, data, data_len);
	if (write_len < 0) {
		lua_pushstring(L, loop_stream_close_string(write_len));
		return 1;
	}
	if (write_len == data_len) {
		return 0;
	}

	/* write blocks */
	lua_pushcfunction(L, h2d_stream_send_resume);
	lua_insert(L, 1);
	lua_pushinteger(L, write_len);

	return lua_yield(L, 4);
}

static int h2d_stream_recv_resume(lua_State *L)
{
	loop_stream_t *s = lua_touserdata(L, -1);

	char buffer[4096];
	int read_len = loop_stream_read(s, buffer, sizeof(buffer));
	if (read_len < 0) {
		lua_pushnil(L);
		lua_pushstring(L, loop_stream_close_string(read_len));
		return 2;
	}
	if (read_len > 0) {
		lua_pushlstring(L, buffer, read_len);
		return 1;
	}

	/* read blocks, again */
	return lua_yield(L, 1);
}

static int h2d_stream_recv(lua_State *L)
{
	loop_stream_t *s = lua_touserdata(L, 1);
	if (s == NULL) {
		lua_pushstring(L, "stream.send(): invalid address");
		return lua_error(L);
	}

	char buffer[4096];
	int read_len = loop_stream_read(s, buffer, sizeof(buffer));
	if (read_len < 0) {
		lua_pushnil(L);
		lua_pushstring(L, loop_stream_close_string(read_len));
		return 2;
	}
	if (read_len > 0) {
		lua_pushlstring(L, buffer, read_len);
		return 1;
	}

	/* read blocks */
	lua_pushcfunction(L, h2d_stream_recv_resume);
	lua_insert(L, 1);
	return lua_yield(L, 2);
}

static const struct h2d_lua_api_reg_func h2d_stream_functions[] = {
	{ "connect", h2d_stream_connect },
	{ "send", h2d_stream_send },
	{ "recv", h2d_stream_recv },
	{ "close", h2d_stream_send },
	{ "keepalive", h2d_stream_send },
	{ NULL }  /* sentinel */
};

const struct h2d_lua_api_package h2d_stream_package = {
	.name = "stream",
	.funcs = h2d_stream_functions,
};
