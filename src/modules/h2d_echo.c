#include "h2d_main.h"

struct h2d_echo_conf {
	const char	*str;
	int		len;
	int		status_code;
};

struct h2d_module h2d_echo_module;

static int h2d_echo_generate_response_headers(struct h2d_request *r)
{
	struct h2d_echo_conf *conf = r->conf_path->module_confs[h2d_echo_module.index];

	h2d_header_add_lite(&r->resp.headers, "Server", "h2tpd", 5, r->pool);

	r->resp.status_code = conf->status_code;
	r->resp.content_length = conf->len;
	return H2D_OK;
}

static int h2d_echo_generate_response_body(struct h2d_request *r, uint8_t *buf, int size)
{
	struct h2d_echo_conf *conf = r->conf_path->module_confs[h2d_echo_module.index];
	if (size < conf->len) {
		return H2D_ERROR;
	}
	memcpy(buf, conf->str, conf->len);
	return conf->len;
}

/* configuration */

static const char *h2d_echo_conf_post(void *data)
{
	struct h2d_echo_conf *conf = data;
	if (conf->len > 1024) {
		return "too long string while the limit is 1024";
	}
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_echo_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.u.length_offset = offsetof(struct h2d_echo_conf, len),
		.offset = offsetof(struct h2d_echo_conf, str),
	},
	{	.name = "status_code",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_echo_conf, status_code),
		.default_value.n = WUY_HTTP_200,
		.limits.n = WUY_CFLUA_LIMITS(WUY_HTTP_200, 599),
	},
	{ NULL }
};

struct h2d_module h2d_echo_module = {
	.name = "echo",
	.command_path = {
		.name = "echo",
		.description = "Echo content module. Response a static string.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_echo_conf_commands,
			.size = sizeof(struct h2d_echo_conf),
			.post = h2d_echo_conf_post,
		}
	},

	.content = {
		.response_headers = h2d_echo_generate_response_headers,
		.response_body = h2d_echo_generate_response_body,
	},
};
