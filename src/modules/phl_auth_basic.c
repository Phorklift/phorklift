#include "phl_main.h"

struct phl_auth_basic_conf {
	const char	**users;
	const char	*realm;
	const char	*page;
	int		page_len;
};

struct phl_module phl_auth_basic_module;

static int phl_auth_basic_fail(struct phl_request *r)
{
	struct phl_auth_basic_conf *conf = r->conf_path->module_confs[phl_auth_basic_module.index];

	char resp_header[sizeof("Basic realm=\"\"") + strlen(conf->realm)];
	int len = sprintf(resp_header, "Basic realm=\"%s\"", conf->realm);
	phl_header_add(&r->resp.headers, "WWW-Authenticate",
			sizeof("WWW-Authenticate")-1, resp_header, len, r->pool);

	if (conf->page != NULL) {
		r->resp.easy_string = conf->page;
		r->resp.content_length = conf->page_len;
	}

	return WUY_HTTP_401;
}
static int phl_auth_basic_process_headers(struct phl_request *r)
{
	struct phl_auth_basic_conf *conf = r->conf_path->module_confs[phl_auth_basic_module.index];
	if (conf->users == NULL) {
		return PHL_OK;
	}

	struct phl_header *h = phl_header_get(&r->req.headers, "Authorization");
	if (h == NULL) {
		return phl_auth_basic_fail(r);
	}

	const char *value = phl_header_value(h);
	if (h->value_len < 10 || memcmp(value, "Basic ", 6) != 0) {
		return phl_auth_basic_fail(r);
	}

	unsigned char auth_str[h->value_len];
	int auth_len = wuy_base64_decode(auth_str, value + 6, h->value_len - 6);
	if (auth_len < 0) {
		return phl_auth_basic_fail(r);
	}

	for (const char **p = conf->users; *p != NULL; p++) {
		const char *user = *p;
		if (memcmp(user, auth_str, auth_len) == 0 && user[auth_len] == '\0') {
			return PHL_OK;
		}
	}

	return phl_auth_basic_fail(r);
}

/* configuration */

static const char *phl_auth_basic_conf_post(void *data)
{
	struct phl_auth_basic_conf *conf = data;
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

static struct wuy_cflua_command phl_auth_basic_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "Entries in user:password format.",
		.offset = offsetof(struct phl_auth_basic_conf, users),
	},
	{	.name = "realm",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_auth_basic_conf, realm),
		.default_value.s = "hello",
	},
	{	.name = "page",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_auth_basic_conf, page),
		.u.length_offset = offsetof(struct phl_auth_basic_conf, page_len),
	},
	{ NULL }
};

struct phl_module phl_auth_basic_module = {
	.name = "auth_basic",
	.command_path = {
		.name = "auth_basic",
		.description = "Basic access authentication filter module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_auth_basic_conf_commands,
			.size = sizeof(struct phl_auth_basic_conf),
			.post = phl_auth_basic_conf_post,
		}
	},

	.filters = {
		.process_headers = phl_auth_basic_process_headers,
	},
};
