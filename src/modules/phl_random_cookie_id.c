#include "phl_main.h"

struct phl_random_cookie_id_conf {
	bool		check_mode;
	const char	*secret;
	uint64_t	secret_hash;
	const char	*name;

	const char	*domain;
	const char	*path;
	int		max_age;
	bool		secure;
	bool		HttpOnly;
};

struct phl_module phl_random_cookie_id_module;

static const char *phl_random_cookie_id_get(struct phl_request *r, int *p_len)
{
	struct phl_random_cookie_id_conf *conf = r->conf_path->module_confs[phl_random_cookie_id_module.index];

	struct phl_header *h;
	wuy_slist_iter_type(&r->req.headers, h, list_node) {
		if (strcasecmp(h->str, "Cookie") != 0) {
			continue;
		}

		*p_len = h->value_len;
		const char *value_str = wuy_http_cookie_get(phl_header_value(h),
				p_len, conf->name, strlen(conf->name));
		if (value_str != NULL) {
			return value_str;
		}
	}
	return NULL;
}

static int phl_random_cookie_id_process_headers(struct phl_request *r)
{
	struct phl_random_cookie_id_conf *conf = r->conf_path->module_confs[phl_random_cookie_id_module.index];
	if (conf == NULL || !conf->check_mode) {
		return PHL_OK;
	}

	int len;
	const char *str = phl_random_cookie_id_get(r, &len);
	if (str == NULL) {
		return WUY_HTTP_401;
	}

	char *end;
	long rand = strtol(str, &end, 16);
	if (rand == 0 || *end != '-') {
		return WUY_HTTP_401;
	}

	uint16_t checksum_req = strtol(end + 1, &end, 16);
	if (*end != '\0') {
		return WUY_HTTP_401;
	}

	if (conf->secret != NULL) {
		uint16_t checksum_calc = wuy_vhash64(&rand, sizeof(long)) ^ conf->secret_hash;
		if (checksum_calc != checksum_req) {
			return WUY_HTTP_401;
		}
	}

	return PHL_OK;
}

static int phl_random_cookie_id_response_headers(struct phl_request *r)
{
	struct phl_random_cookie_id_conf *conf = r->conf_path->module_confs[phl_random_cookie_id_module.index];
	if (conf == NULL || conf->check_mode) {
		return PHL_OK;
	}

	int len;
	if (phl_random_cookie_id_get(r, &len) != NULL) { /* exist */
		return PHL_OK;
	}

	/* Not found in Cookie, so add it */
	char buffer[4096], *p = buffer, *end = p + sizeof(buffer);

	long rand = random();
	uint16_t checksum = 0;
	if (conf->secret != NULL) {
		checksum = wuy_vhash64(&rand, sizeof(long)) ^ conf->secret_hash;
	}

	p += snprintf(p, end - p, "%s=%lx-%x", conf->name, rand, checksum);

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

	phl_header_add_lite(&r->resp.headers, "Set-Cookie", buffer, p - buffer, r->pool);

	return PHL_OK;
}

/* configuration */

static const char *phl_random_cookie_id_conf_post(void *data)
{
	struct phl_random_cookie_id_conf *conf = data;
	if (conf->secret != NULL) {
		conf->secret_hash = wuy_vhash64(conf->secret, strlen(conf->secret));
	}
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_random_cookie_id_conf_commands[] = {
	{	.name = "check_mode",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_random_cookie_id_conf, check_mode),
		.description = "If set, check the request Cookie header. Otherwise add Set-cookie header if need."
	},
	{	.name = "secret",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_random_cookie_id_conf, secret),
	},
	{	.name = "name",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_random_cookie_id_conf, name),
		.default_value.s = "ID",
	},
	{	.name = "domain",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_random_cookie_id_conf, domain),
	},
	{	.name = "path",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_random_cookie_id_conf, path),
	},
	{	.name = "max_age",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_random_cookie_id_conf, max_age),
	},
	{	.name = "secure",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_random_cookie_id_conf, secure),
	},
	{	.name = "HttpOnly",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_random_cookie_id_conf, HttpOnly),
	},
	{ NULL }
};

struct phl_module phl_random_cookie_id_module = {
	.name = "random_cookie_id",
	.command_path = {
		.name = "random_cookie_id",
		.description = "Set cookie ID in response header",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_random_cookie_id_conf_commands,
			.size = sizeof(struct phl_random_cookie_id_conf),
			.post = phl_random_cookie_id_conf_post,
			.may_omit = true,
		}
	},

	.filters = {
		.process_headers = phl_random_cookie_id_process_headers,
		.response_headers = phl_random_cookie_id_response_headers,
	},
};
