#include "h2d_main.h"

// TODO support ipv6

struct h2d_acl_rule {
	uint32_t	start;
	uint32_t	end;
	bool		is_deny;
};
struct h2d_acl_conf {
	wuy_array_t		strs;
	struct h2d_acl_rule	*rules;
};

extern struct h2d_module h2d_acl_module;

static int h2d_acl_process_headers(struct h2d_request *r)
{
	struct h2d_acl_conf *conf = r->conf_path->module_confs[h2d_acl_module.index];
	int count = wuy_array_count(&conf->strs);
	if (count != 0) {
		return WUY_HTTP_403;
	}
	return H2D_OK;
}

/* configuration */

static bool h2d_acl_conf_post(void *data)
{
	struct h2d_acl_conf *conf = data;

	int count = wuy_array_count(&conf->strs);
	if (count == 0) {
		return true;
	}

	/*
	conf->rules = malloc(sizeof(struct h2d_acl_rule) * count);

	const char **pstr;
	struct h2d_acl_rule *rule = conf->rules;
	wuy_array_iter(&conf->strs, pstr) {
		const char *str = *pstr;
		if (str[0] == '!') {
			rule->is_deny = true;
			str++;
		}
	}
	*/

	return true;
}

static struct wuy_cflua_command h2d_acl_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_acl_conf, strs),
	},
	{ NULL }
};

struct h2d_module h2d_acl_module = {
	.name = "acl",
	.command_path = {
		.name = "acl",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_acl_conf_commands,
			.size = sizeof(struct h2d_acl_conf),
			.post = h2d_acl_conf_post,
		}
	},

	.filters = {
		.process_headers = h2d_acl_process_headers,
	},
};
