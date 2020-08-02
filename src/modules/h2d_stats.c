#include "h2d_main.h"

extern struct h2d_module h2d_stats_module;

static int h2d_stats_generate_response_headers(struct h2d_request *r)
{
	r->resp.status_code = WUY_HTTP_200;
	return H2D_OK;
}
static int h2d_stats_generate_response_body(struct h2d_request *r, uint8_t *buf, int len)
{
	if (r->module_ctxs[h2d_stats_module.index] != NULL) {
		return 0;
	}
	r->module_ctxs[h2d_stats_module.index] = (void *)1;

	char *pos = (char *)buf;
	char *end = pos + len;

	struct h2d_conf_host *conf_host;
	for (int i = 0; (conf_host = r->c->conf_listen->hosts[i]) != NULL; i++) {
		const char *hostname = conf_host->hostnames[0];
		pos += sprintf(pos, "== Host: %s\n", hostname);

		struct h2d_conf_path *conf_path;
		for (int j = 0; (conf_path = conf_host->paths[j]) != NULL; j++) {
			const char *pathname = conf_path->pathnames[0];
			pos += sprintf(pos, "= Path: %s\n", pathname);
			pos += h2d_module_path_stats(conf_path->module_confs, pos, end - pos);
		}
	}

	return pos - (char *)buf;
}

/* configuration */

struct h2d_module h2d_stats_module = {
	.name = "stats",
	.command_path = {
		.name = "stats",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = 0, /* reset later */
	},

	.content = {
		.response_headers = h2d_stats_generate_response_headers,
		.response_body = h2d_stats_generate_response_body,
	},
};
