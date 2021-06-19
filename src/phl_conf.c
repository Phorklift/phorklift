#include <lua5.1/lua.h>
#include <lua5.1/lualib.h>
#include <lua5.1/lauxlib.h>

#include "phl_main.h"

/* This holds the global lua state.
 * This is persistent because of the functions defined in config file. */
lua_State *phl_L = NULL;

struct phl_conf_runtime *phl_conf_runtime = NULL;
struct phl_conf_listen **phl_conf_listens = NULL;

int phl_conf_reload_count = 0;

static wuy_pool_t *phl_conf_pool = NULL;

/* say nothing */
static int phl_conf_name(void *data, char *buf, int size)
{
	return 0;
}

static int phl_conf_lua_panic(lua_State *L)
{
	abort();
}

#include "phl_conf_predefs_lua.h" /* defines phl_conf_predefs_lua_str */
bool phl_conf_parse(const char *conf_file)
{
	phl_conf_reload_count++;

	lua_State *L = lua_open();
	luaL_openlibs(L);
	lua_atpanic(L, phl_conf_lua_panic);

	/* load pre-defined functions */
	assert(luaL_dostring(L, phl_conf_predefs_lua_str) == 0);

	/* load conf-file */
	if (luaL_dofile(L, conf_file) != 0) {
		phl_conf_log(PHL_LOG_FATAL, "Fail to load conf-file: %s", lua_tostring(L, -1));
		return false;
	}

	wuy_pool_t *new_pool = wuy_pool_new(4096);

	/* 0. check mistake usage: `Runtime = {...}` */
	lua_getglobal(L, "Runtime");
	if (lua_type(L, -1) != LUA_TFUNCTION) {
		phl_conf_log(PHL_LOG_ERROR, "do not use `=` after Runtime");
		wuy_pool_destroy(new_pool);
		lua_close(L);
		return false;
	}
	lua_pop(L, 1);

	/* 1. parse phl_runtime_conf */
	lua_getglobal(L, "phl_conf_runtime");

	struct phl_conf_runtime *new_runtime;
	const char *err = wuy_cflua_parse(L, &phl_conf_runtime_table, &new_runtime, new_pool, NULL);
	if (err != WUY_CFLUA_OK) {
		phl_conf_log(PHL_LOG_ERROR, "Fail to parse configuration: %s", err);
		wuy_pool_destroy(new_pool);
		lua_close(L);
		return false;
	}

	/* set phl_conf_runtime before parsing phl_conf_listens
	 * because it will be used during the parsing */
	struct phl_conf_runtime *backup_runtime = phl_conf_runtime;
	phl_conf_runtime = new_runtime;

	/* 2. parse phl_conf_listens */
	struct wuy_cflua_command listens_commands[] = {
		{	.type = WUY_CFLUA_TYPE_TABLE,
			.u.table = &phl_conf_listen_table,
		},
		{ NULL },
	};
	struct wuy_cflua_table global = {
		.commands = listens_commands,
		.name = phl_conf_name,
	};

	lua_getglobal(L, "phl_conf_listens");
	struct phl_conf_listen **new_listens;
	err = wuy_cflua_parse(L, &global, &new_listens, new_pool, NULL);
	if (err != WUY_CFLUA_OK) {
		phl_conf_runtime = backup_runtime; /* rollback */
		phl_conf_log(PHL_LOG_ERROR, "Fail to parse configuration: %s", err);
		wuy_pool_destroy(new_pool);
		lua_close(L);
		return false;
	}
	if (new_listens == NULL) {
		phl_conf_runtime = backup_runtime; /* rollback */
		phl_conf_log(PHL_LOG_ERROR, "No Listen is defined in configuration.");
		wuy_pool_destroy(new_pool);
		lua_close(L);
		return false;
	}

	phl_conf_listens = new_listens;

	/* done */
	if (phl_conf_pool != NULL) {
		/* this will free old phl_conf_runtime and phl_conf_listens too */
		wuy_pool_destroy(phl_conf_pool);
		lua_close(phl_L);
	}
	phl_conf_pool = new_pool;
	phl_L = L;
	return true;
}
