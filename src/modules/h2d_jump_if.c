#include "h2d_main.h"

#define H2D_JUMP_IF_MAX 10

struct h2d_jump_if_conf {
	const char	*pathnames[H2D_JUMP_IF_MAX];
	int		status_codes[H2D_JUMP_IF_MAX];
	int		num;
};

struct h2d_module h2d_jump_if_module;

static int h2d_jump_if_filter_response_headers(struct h2d_request *r)
{
	struct h2d_jump_if_conf *conf = r->conf_path->module_confs[h2d_jump_if_module.index];
	if (conf->num == 0) {
		return H2D_OK;
	}

	const char *jump_path = NULL;
	for (int i = 0; i < conf->num; i++) {
		if (r->resp.status_code == conf->status_codes[i]) {
			jump_path = conf->pathnames[i];
			break;
		}
	}
	if (jump_path == NULL) {
		return H2D_OK;
	}

	return h2d_request_redirect(r, jump_path);
}

static const char *h2d_jump_if_arbitrary(lua_State *L, void *data)
{
	struct h2d_jump_if_conf *conf = data;

	int status_code = lua_tointeger(L, -2);
	const char *pathname = lua_tostring(L, -1);

	if (status_code < WUY_HTTP_200 || status_code > 599) {
		return "invalid status code";
	}
	if (pathname == NULL) {
		return "invalid pathname";
	}

	conf->status_codes[conf->num] = status_code;
	conf->pathnames[conf->num] = wuy_pool_strdup(wuy_cflua_pool, pathname);
	conf->num++;

	return WUY_CFLUA_OK;
}

struct h2d_module h2d_jump_if_module = {
	.name = "jump_if",
	.command_path = {
		.name = "jump_if",
		.description = "Save the response to some Path by subrequest.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = (struct wuy_cflua_command[1]) { { NULL } },
			.size = sizeof(struct h2d_jump_if_conf),
			.arbitrary = h2d_jump_if_arbitrary,
		}
	},

	.filters = {
		.response_headers = h2d_jump_if_filter_response_headers,
	},
};
