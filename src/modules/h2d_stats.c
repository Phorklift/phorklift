#include "h2d_main.h"

extern struct h2d_module h2d_stats_module;

static int h2d_stats_process_request_headers(struct h2d_request *r)
{
	return H2D_OK;
}
static int h2d_stats_generate_response_headers(struct h2d_request *r)
{
	r->resp.status_code = H2D_HTTP_200;
	return H2D_OK;
}
static int h2d_stats_generate_response_body(struct h2d_request *r, uint8_t *buf, int len)
{
	if (r->module_ctxs[h2d_stats_module.request_ctx.index] != NULL) {
		return 0;
	}
	r->module_ctxs[h2d_stats_module.request_ctx.index] = (void *)1;

	char *pos = (char *)buf;
	char *end = pos + len;

	struct h2d_conf_path **pcp;
	wuy_array_iter(&r->conf_host->paths, pcp) {
		struct h2d_conf_path *conf_path = *pcp;
		pos += h2d_module_path_stats(conf_path->module_confs, pos, end - pos);
	}

	return pos - (char *)buf;
}

static void h2d_stats_ctx_free(struct h2d_request *r)
{
}


/* configuration */

static bool h2d_stats_conf_is_enable(void *data)
{
	return data != NULL;
}

struct h2d_module h2d_stats_module = {
	.name = "stats",
	.command_path = {
		.name = "stats",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = 0, /* reset later */
	},

	.content = {
		.is_enable = h2d_stats_conf_is_enable,
		.process_headers = h2d_stats_process_request_headers,
		.response_headers = h2d_stats_generate_response_headers,
		.response_body = h2d_stats_generate_response_body,
	},

	.request_ctx = {
		.free = h2d_stats_ctx_free,
	},
};
