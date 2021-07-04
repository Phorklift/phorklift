#include "phl_main.h"

struct phl_set_cookie_id_conf {
	const char	*type;
	const char	*domain;
	const char	*path;
	const char	*key;
	int		max_age;
	bool		secure;
	bool		HttpOnly;
};

struct phl_module phl_set_cookie_id_module;

static int phl_set_cookie_id_response_headers(struct phl_request *r)
{
	struct phl_set_cookie_id_conf *conf = r->conf_path->module_confs[phl_set_cookie_id_module.index];
	if (conf == NULL || conf->type == NULL) {
		return PHL_OK;
	}

	/* search request Cookie headers */
	struct phl_header *h;
	wuy_slist_iter_type(&r->req.headers, h, list_node) {
		if (strcasecmp(h->str, "Cookie") != 0) {
			continue;
		}

		int value_len = h->value_len;
		const char *value_str = wuy_http_cookie_get(phl_header_value(h),
				&value_len, conf->key, strlen(conf->key));
		if (value_str != NULL) {
			return PHL_OK;
		}
	}

	/* Not found in Cookie, so add the ID */
	char buffer[4096], *p = buffer, *end = p + sizeof(buffer);
	p += snprintf(p, end - p, "%s=", conf->key);

	if (strcmp(conf->type, "random32") == 0) {
		p += snprintf(p, end - p, "%ld", random());
	} else if (strcmp(conf->type, "random64") == 0) {
		p += snprintf(p, end - p, "%lx", (random() << 32) | random());
	} else if (strcmp(conf->type, "UUID") == 0) { // TODO
		p += snprintf(p, end - p, "%lx", (random() << 32) | random());
	}

	if (conf->domain != NULL) {
		p += snprintf(p, end - p, ";Domain=%s", conf->domain);
	}
	if (conf->path != NULL) {
		p += snprintf(p, end - p, ";Path=%s", conf->path);
	}
	if (conf->max_age != 0) {
		p += snprintf(p, end - p, ";max-age=%d", conf->max_age);
	}
	if (conf->secure) {
		p += snprintf(p, end - p, ";secure");
	}
	if (conf->HttpOnly) {
		p += snprintf(p, end - p, ";HttpOnly");
	}

	phl_header_add_lite(&r->resp.headers, "Set-Cookie", buffer, end - buffer, r->pool);

	return PHL_OK;
}

/* configuration */

static const char *phl_set_cookie_id_conf_post(void *data)
{
	struct phl_set_cookie_id_conf *conf = data;
	if (conf->type == NULL) {
		return WUY_CFLUA_OK;
	}
	if (strcmp(conf->type, "random32") != 0 &&
			strcmp(conf->type, "random64") != 0 &&
			strcmp(conf->type, "UUID") != 0) {
		return "Only support types: `random32`, `random64` and `UUID`";
	}
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_set_cookie_id_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.offset = offsetof(struct phl_set_cookie_id_conf, type),
		.description = "Support: `random32`, `random64` and `UUID`."
	},
	{	.name = "key",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_set_cookie_id_conf, key),
		.default_value.s = "ID",
	},
	{	.name = "domain",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_set_cookie_id_conf, domain),
	},
	{	.name = "path",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_set_cookie_id_conf, path),
	},
	{	.name = "max_age",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_set_cookie_id_conf, max_age),
	},
	{	.name = "secure",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_set_cookie_id_conf, secure),
	},
	{	.name = "HttpOnly",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_set_cookie_id_conf, HttpOnly),
	},
	{ NULL }
};

struct phl_module phl_set_cookie_id_module = {
	.name = "set_cookie_id",
	.command_path = {
		.name = "set_cookie_id",
		.description = "Set cookie ID in response header",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_set_cookie_id_conf_commands,
			.size = sizeof(struct phl_set_cookie_id_conf),
			.post = phl_set_cookie_id_conf_post,
			.may_omit = true,
		}
	},

	.filters = {
		.response_headers = phl_set_cookie_id_response_headers,
	},
};
