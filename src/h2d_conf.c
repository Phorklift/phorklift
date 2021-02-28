#include <lua5.1/lua.h>
#include <lua5.1/lualib.h>
#include <lua5.1/lauxlib.h>

#include "h2d_main.h"

/* This holds the global lua state.
 * This is persistent because of the functions defined in config file. */
lua_State *h2d_L = NULL;

struct h2d_conf_listen **h2d_conf_listens = NULL;

int h2d_conf_reload_count = 0;

static wuy_pool_t *h2d_conf_pool = NULL;

/* say nothing */
static int h2d_conf_name(void *data, char *buf, int size)
{
	return 0;
}

#include "h2d_conf_parse_lua.h" /* defines h2d_conf_parse_lua_str */
bool h2d_conf_parse(const char *conf_file)
{
	h2d_conf_reload_count++;

	lua_State *L = lua_open();
	luaL_openlibs(L);

	int ret = luaL_loadstring(L, h2d_conf_parse_lua_str);
	if (ret != 0) {
		fprintf(stderr, "load h2d_conf_parse.lua fail: %d\n", ret);
		return false;
	}

	/* two input arguments: listen-table, and conf-file */
	wuy_cflua_build_tables(L, &h2d_conf_listen_table);
	lua_pushstring(L, conf_file);

	ret = lua_pcall(L, 2, 1, 0);
	if (ret != 0) {
		const char *errmsg = lua_tostring(L, -1);
		fprintf(stderr, "load conf_file fail(%d): %s\n", ret, errmsg);
		return false;
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

	struct h2d_conf_listen **conf_listens;

	wuy_pool_t *pool = wuy_pool_new(4096);
	const char *err = wuy_cflua_parse(L, &global, &conf_listens, pool);
	if (err != WUY_CFLUA_OK) {
		fprintf(stderr, "parse conf_file fail: %s\n", err);
		wuy_pool_destroy(pool);
		return false;
	}

	if (h2d_conf_pool != NULL) {
		wuy_pool_destroy(h2d_conf_pool); /* free h2d_conf_listens too */
		lua_close(h2d_L);
	}
	h2d_conf_listens = conf_listens;
	h2d_conf_pool = pool;
	h2d_L = L;

	return true;
}

void h2d_conf_doc(void)
{
	printf("# Format\n"
		"\n"
		"Command format in this document:\n"
		"\n"
		"    `name` _(type[: default_value] [min=] [max=])_\n"
		"\n"
		"Lua table supports array members and key-value map entries.\n"
		"For key-value map entries, the `name` is the key.\n"
		"And for array members, the `name` is `SINGLE_ARRAY_MEMBER` if only\n"
		"single member is accepted, or `MULTIPLE_ARRAY_MEMBER` if multiple\n"
		"members are accepted.\n"
		"\n"
		"Supported value types includes:\n"
		"\n"
		"  - table\n"
		"  - integer\n"
		"  - float\n"
		"  - string\n"
		"  - boolean\n"
		"  - function\n"
		"\n"
		"The `default_value` is showed only for non-zero value.\n"
		"\n"
		"The `min` and `max` limits are showed only if any.\n");

	printf("\n# Common component tables\n\n");

	printf("+ LOG _(table)_\n\n");
	wuy_cflua_dump_table_markdown(&h2d_log_conf_table, 1);

	printf("+ UPSTREAM _(table)_\n\n");
	printf("    Used by content modules such as proxy and redis.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_upstream_conf_table, 1);

	printf("+ DYNAMIC _(table)_\n\n");
	printf("    Included by Path and UPSTREAM to enable dynamic configuration.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_dynamic_conf_table, 1);

	printf("\n# Listen scope\n\n");
	printf("This is the top level scope. Accepts one or more addresses to listen on.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_conf_listen_table, 0);

	printf("\n# Host scope\n\n");
	printf("Under Listen scope. Accepts one or more hostnames as virtual server.\n\n"
			"The hostname arguments may start or end with a wildcard `*`.\n"
			"Especial the \"*\" is the default Host under the Listen scope to match any request.\n"
			"Each request is matched in the order of longest match.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_conf_host_table, 0);

	printf("\n# Path scope\n\n");
	printf("Under Host scope. Accepts one or more pathnames to route requests by URL.\n\n"
			"The pathname arguments may start with\n\n"
			"  - `/` means prefix-match;\n"
			"  - `=` means exact-match;\n"
			"  - `~` means regular expression match in Lua's rule.\n\n"
			"Each request is matched in the order of the Paths appearance in Host scope.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_conf_path_table, 0);
}
