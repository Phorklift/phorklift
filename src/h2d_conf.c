#include <lua5.1/lua.h>
#include <lua5.1/lualib.h>
#include <lua5.1/lauxlib.h>

#include "h2d_main.h"

/* This holds the global lua state.
 * This is persistent because of the functions defined in config file. */
lua_State *h2d_L;

/* say nothing */
static int h2d_conf_name(void *data, char *buf, int size)
{
	return 0;
}

#include "h2d_conf_parse_lua.h" /* defines h2d_conf_parse_lua_str */
struct h2d_conf_listen **h2d_conf_parse(const char *conf_file)
{
	h2d_L = lua_open();
	luaL_openlibs(h2d_L);

	int ret = luaL_loadstring(h2d_L, h2d_conf_parse_lua_str);
	if (ret != 0) {
		fprintf(stderr, "load h2d_conf_parse.lua fail: %d\n", ret);
		exit(H2D_EXIT_CONF);
	}

	/* two input arguments: listen-table, and conf-file */
	wuy_cflua_build_tables(h2d_L, &h2d_conf_listen_table);
	lua_pushstring(h2d_L, conf_file);

	ret = lua_pcall(h2d_L, 2, 1, 0);
	if (ret != 0) {
		const char *errmsg = lua_tostring(h2d_L, -1);
		fprintf(stderr, "load conf_file fail(%d): %s\n", ret, errmsg);
		exit(H2D_EXIT_CONF);
	}

	/* returned listen array, handled by wuy_cflua_parse(). */
	struct wuy_cflua_command listens_commands[] = {
		{	.type = WUY_CFLUA_TYPE_TABLE,
			.u.table = &h2d_conf_listen_table,
		},
		{ NULL },
	};
	struct wuy_cflua_table global = {
		.commands = listens_commands,
		.name = h2d_conf_name,
	};

	static struct h2d_conf_listen **h2d_conf_listens;
	const char *err = wuy_cflua_parse(h2d_L, &global, &h2d_conf_listens);
	if (err != WUY_CFLUA_OK) {
		fprintf(stderr, "parse conf_file fail: %s\n", err);
		exit(H2D_EXIT_CONF);
	}

	return h2d_conf_listens;
}
