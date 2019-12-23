#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "h2d_main.h"


/* zero value of function type, defined in and returned from h2d_conf.lua */
static const void *h2d_conf_zero_function_pointer;
bool h2d_conf_is_zero_function(wuy_cflua_function_t f)
{
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

/* This holds the global lua state.
 * This is persistent because of the functions defined in config file. */
lua_State *h2d_L;

wuy_array_t *h2d_conf_parse(const char *defaults_file, const char *conf_file)
{
	h2d_L = lua_open();
	luaL_openlibs(h2d_L);

	int ret = luaL_loadfile(h2d_L, "conf/parse/parse.lua");
	if (ret != 0) {
		printf("load h2d_conf.lua fail: %d\n", ret);
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
		.u.table = &(struct wuy_cflua_table) { listens_commands },
	};

	static wuy_array_t h2d_conf_listens;
	int br = wuy_cflua_parse(h2d_L, &global, &h2d_conf_listens);
	if (br < 0) {
		printf("parse: %d\n", br);
		exit(H2D_EXIT_CONF);
	}

	return &h2d_conf_listens;
}
