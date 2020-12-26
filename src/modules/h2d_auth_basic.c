#include "h2d_main.h"

struct h2d_auth_basic_conf {
	const char	**users;
	const char	*realm;
};

struct h2d_module h2d_auth_basic_module;

static int h2d_auth_basic_fail(struct h2d_request *r)
{
	struct h2d_auth_basic_conf *conf = r->conf_path->module_confs[h2d_auth_basic_module.index];

	char resp_header[sizeof("Basic realm=\"\"") + strlen(conf->realm)];
	int len = sprintf(resp_header, "Basic realm=\"%s\"", conf->realm);
	h2d_header_add(&r->resp.headers, "WWW-Authenticate",
			sizeof("WWW-Authenticate")-1, resp_header, len);

	return WUY_HTTP_401;
}
static int h2d_auth_basic_process_headers(struct h2d_request *r)
{
	struct h2d_auth_basic_conf *conf = r->conf_path->module_confs[h2d_auth_basic_module.index];
	if (conf->users == NULL) {
		return H2D_OK;
	}

	struct h2d_header *h = h2d_header_get(&r->req.headers, "Authorization");
	if (h == NULL) {
		return h2d_auth_basic_fail(r);
	}

	const char *value = h2d_header_value(h);
	if (h->value_len < 10 || memcmp(value, "Basic ", 6) != 0) {
		return h2d_auth_basic_fail(r);
	}

	unsigned char auth_str[h->value_len];
	int auth_len = wuy_base64_decode(auth_str, value + 6, h->value_len - 6);
	if (auth_len < 0) {
		return h2d_auth_basic_fail(r);
	}

	for (const char **p = conf->users; *p != NULL; p++) {
		const char *user = *p;
		if (memcmp(user, auth_str, auth_len) == 0 && user[auth_len] == '\0') {
			return H2D_OK;
		}
	}

	return h2d_auth_basic_fail(r);
}

/* configuration */

static const char *h2d_auth_basic_conf_post(void *data)
{
	struct h2d_auth_basic_conf *conf = data;
	if (conf->users == NULL) {
		return WUY_CFLUA_OK;
	}

	for (const char **p = conf->users; *p != NULL; p++) {
		if (strchr(*p, ':') == NULL) {
			wuy_cflua_post_arg = *p;
			return "invalid format, should be 'user:password'";
		}
	}

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_auth_basic_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "Entries in user:password format.",
		.offset = offsetof(struct h2d_auth_basic_conf, users),
	},
	{	.name = "realm",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_auth_basic_conf, realm),
		.default_value.s = "hello",
	},
	{ NULL }
};

struct h2d_module h2d_auth_basic_module = {
	.name = "auth_basic",
	.command_path = {
		.name = "auth_basic",
		.description = "Basic access authentication filter module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_auth_basic_conf_commands,
			.size = sizeof(struct h2d_auth_basic_conf),
			.post = h2d_auth_basic_conf_post,
		}
	},

	.filters = {
		.process_headers = h2d_auth_basic_process_headers,
	},
};
