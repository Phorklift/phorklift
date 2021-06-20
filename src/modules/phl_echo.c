#include "phl_main.h"

struct phl_echo_conf {
	const char	*str;
	int		len;
	int		status_code;
};

struct phl_module phl_echo_module;

static int phl_echo_generate_response_headers(struct phl_request *r)
{
	struct phl_echo_conf *conf = r->conf_path->module_confs[phl_echo_module.index];

	phl_header_add_lite(&r->resp.headers, "Server", "phorklift", 5, r->pool);

	r->resp.status_code = conf->status_code;
	r->resp.content_length = conf->len;
	return PHL_OK;
}

static int phl_echo_generate_response_body(struct phl_request *r, uint8_t *buf, int size)
{
	struct phl_echo_conf *conf = r->conf_path->module_confs[phl_echo_module.index];
	if (size < conf->len) {
		return PHL_ERROR;
	}
	memcpy(buf, conf->str, conf->len);
	return conf->len;
}

/* configuration */

static const char *phl_echo_conf_post(void *data)
{
	struct phl_echo_conf *conf = data;
	if (conf->len > 1024) {
		return "too long string while the limit is 1024";
	}
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_echo_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.description = "Response body.",
		.u.length_offset = offsetof(struct phl_echo_conf, len),
		.offset = offsetof(struct phl_echo_conf, str),
	},
	{	.name = "status_code",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_echo_conf, status_code),
		.default_value.n = WUY_HTTP_200,
		.limits.n = WUY_CFLUA_LIMITS(WUY_HTTP_200, 599),
	},
	{ NULL }
};

struct phl_module phl_echo_module = {
	.name = "echo",
	.command_path = {
		.name = "echo",
		.description = "Echo content module. Response a static string.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_echo_conf_commands,
			.size = sizeof(struct phl_echo_conf),
			.post = phl_echo_conf_post,
		}
	},

	.content = {
		.response_headers = phl_echo_generate_response_headers,
		.response_body = phl_echo_generate_response_body,
	},
};
