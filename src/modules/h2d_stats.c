#include "h2d_main.h"

struct h2d_stats_ctx {
	int	body_len;
	int	body_sent;
	char	body_buf[16*1024];
};

struct h2d_module h2d_stats_module;

static void h2d_stats_dump_path(struct h2d_conf_path *conf_path, wuy_json_ctx_t *json)
{
	wuy_json_new_object(json);
	wuy_json_object_string(json, "name", conf_path->name);
	h2d_conf_path_stats(conf_path, json);
	h2d_module_stats_path(conf_path, json);
	wuy_json_object_close(json);
}
static void h2d_stats_dump_host(struct h2d_conf_host *conf_host, wuy_json_ctx_t *json)
{
	wuy_json_new_object(json);
	wuy_json_object_string(json, "name", conf_host->name);
	h2d_conf_host_stats(conf_host, json);
	h2d_module_stats_host(conf_host, json);

	wuy_json_object_array(json, "paths");
	struct h2d_conf_path *conf_path;
	for (int i = 0; (conf_path = conf_host->paths[i]) != NULL; i++) {
		h2d_stats_dump_path(conf_path, json);
	}
	wuy_json_array_close(json);

	wuy_json_object_close(json);
}
static void h2d_stats_dump_listen(struct h2d_conf_listen *conf_listen, wuy_json_ctx_t *json)
{
	wuy_json_new_object(json);
	wuy_json_object_string(json, "name", conf_listen->name);
	h2d_conf_listen_stats(conf_listen, json);
	h2d_module_stats_listen(conf_listen, json);

	wuy_json_object_array(json, "hosts");
	struct h2d_conf_host *conf_host;
	for (int i = 0; (conf_host = conf_listen->hosts[i]) != NULL; i++) {
		h2d_stats_dump_host(conf_host, json);
	}
	wuy_json_array_close(json);

	wuy_json_object_close(json);
}

static int h2d_stats_generate_response_headers(struct h2d_request *r)
{
	struct h2d_stats_ctx *ctx = malloc(sizeof(struct h2d_stats_ctx));
	r->module_ctxs[h2d_stats_module.index] = ctx;

	WUY_JSON_CTX(json, ctx->body_buf, sizeof(ctx->body_buf));

	char scope_str[r->req.uri.query_len];
	int scope_len = wuy_http_uri_query_get(r->req.uri.query_pos, r->req.uri.query_len,
			"scope", 5, scope_str);

	if (scope_len < 0) {
		h2d_stats_dump_host(r->conf_host, &json);
	} else if (memcmp(scope_str, "all", scope_len) == 0) {
		// h2d_stats_dump_all(&json);
	} else if (memcmp(scope_str, "listen", scope_len) == 0) {
		h2d_stats_dump_listen(r->c->conf_listen, &json);
	} else if (memcmp(scope_str, "host", scope_len) == 0) {
		h2d_stats_dump_host(r->conf_host, &json);
	} else if (memcmp(scope_str, "upstream", scope_len) == 0) {
		h2d_upstream_stats(&json);
	} else {
		printf("invalid query scope\n");
		return WUY_HTTP_400;
	}

	ctx->body_len = wuy_json_done(&json);
	ctx->body_sent = 0;

	r->resp.content_length = ctx->body_len;
	r->resp.status_code = WUY_HTTP_200;
	return H2D_OK;
}
static int h2d_stats_generate_response_body(struct h2d_request *r, uint8_t *buf, int buf_len)
{
	struct h2d_stats_ctx *ctx = r->module_ctxs[h2d_stats_module.index];

	int body_len = MIN(ctx->body_len - ctx->body_sent, buf_len);
	char *pos = ctx->body_buf + ctx->body_sent;
	ctx->body_sent += body_len;

	memcpy(buf, pos, body_len);
	return body_len;
}

static void h2d_stats_ctx_free(struct h2d_request *r)
{
	struct h2d_stats_ctx *ctx = r->module_ctxs[h2d_stats_module.index];
	free(ctx);
}

/* configuration */

struct h2d_module h2d_stats_module = {
	.name = "stats",
	.command_path = {
		.name = "stats",
		.description = "Statistics content module.",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = 0, /* reset later */
	},

	.content = {
		.response_headers = h2d_stats_generate_response_headers,
		.response_body = h2d_stats_generate_response_body,
	},

	.ctx_free = h2d_stats_ctx_free,
};
