#include <lua5.1/lua.h>
#include <lua5.1/lualib.h>
#include <lua5.1/lauxlib.h>

#include "h2d_main.h"


/* zero value of function type, defined in and returned from h2d_conf.lua */
static const void *h2d_conf_zero_function_pointer;
bool h2d_conf_is_zero_function(wuy_cflua_function_t f)
{
	if (f == 0) {
		return true;
	}

	static wuy_cflua_function_t zero = LUA_NOREF;
	if (zero != LUA_NOREF) {
		return f == zero;
	}

	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, f);
	const void *p = lua_topointer(h2d_L, -1);
	lua_pop(h2d_L, 1);
	if (p == h2d_conf_zero_function_pointer) {
		zero = f;
		return true;
	}

	return false;
}

/* say nothing. for wuy_cflua_strerror() print. */
static int h2d_conf_name(void *data, char *buf, int size)
{
	return 0;
}

/* This holds the global lua state.
 * This is persistent because of the functions defined in config file. */
lua_State *h2d_L;

/* defined in h2d_parse_lua.c */
extern const char *h2d_parse_lua_str;
struct h2d_conf_listen **h2d_conf_parse(const char *defaults_file, const char *conf_file)
{
	h2d_L = lua_open();
	luaL_openlibs(h2d_L);

	int ret = luaL_loadstring(h2d_L, h2d_parse_lua_str);
	if (ret != 0) {
		printf("load conf/parse/parse.lua fail: %d\n", ret);
		exit(H2D_EXIT_CONF);
	}

	/* 3 arguments */
	lua_pushstring(h2d_L, "conf/definitions/");
	lua_pushstring(h2d_L, defaults_file);
	lua_pushstring(h2d_L, conf_file);

	ret = lua_pcall(h2d_L, 3, 2, 0);
	if (ret != 0) {
		const char *errmsg = lua_tostring(h2d_L, -1);
		printf("load config fail: %d. %s\n", ret, errmsg);
		exit(H2D_EXIT_CONF);
	}

	/* There are 2 return values.
	 * The first one is zero-value of function type. */
	h2d_conf_zero_function_pointer = lua_topointer(h2d_L, -1);
	lua_pop(h2d_L, 1);

	/* The second one is listen array, handled by wuy_cflua_parse(). */
	struct wuy_cflua_command listens_commands[] = {
		{	.type = WUY_CFLUA_TYPE_TABLE,
			.u.table = &h2d_conf_listen_table,
		},
		{ NULL },
	};
	struct wuy_cflua_command global = {
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = listens_commands,
			.name = h2d_conf_name,
		},
	};

	static struct h2d_conf_listen **h2d_conf_listens;
	int err = wuy_cflua_parse(h2d_L, &global, &h2d_conf_listens);
	if (err < 0) {
		printf("parse config error: %s\n", wuy_cflua_strerror(h2d_L, err));
		exit(H2D_EXIT_CONF);
	}

	return h2d_conf_listens;
}
