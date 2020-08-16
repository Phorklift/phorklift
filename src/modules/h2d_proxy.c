#include "h2d_main.h"

struct h2d_proxy_conf {
	struct h2d_upstream_conf	upstream;
	bool				x_forwarded_for;
	int				max_retries;
	int				*retry_status_codes;
};

struct h2d_proxy_ctx {
	bool				has_sent_request;
	int				retries;
	wuy_http_chunked_t		chunked;
	struct h2d_upstream_connection	*upc;
};

struct h2d_module h2d_proxy_module;

// TODO move this out
static const char *client_addr(struct h2d_request *r)
{
	static char buf[INET6_ADDRSTRLEN];
	struct sockaddr *sa = &r->c->client_addr;
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sain = (struct sockaddr_in *)sa;
		inet_ntop(AF_INET, &sain->sin_addr, buf, sizeof(buf));
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sain6 = (struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &sain6->sin6_addr, buf, sizeof(buf));
	} else {
		return NULL;
	}
	return buf;
}

static int h2d_proxy_build_request_headers(struct h2d_request *r, char *buffer)
{
	struct h2d_proxy_conf *conf = r->conf_path->module_confs[h2d_proxy_module.index];

	char *pos = buffer;

	pos += sprintf(pos, "%s %s HTTP/1.1\r\n", wuy_http_string_method(r->req.method), r->req.url);

	if (r->req.content_length != H2D_CONTENT_LENGTH_INIT) {
		pos += sprintf(pos, "Content-Length: %ld\r\n", r->req.content_length);
	}

	bool append_xff = false;
	struct h2d_header *h;
	h2d_header_iter(&r->req.headers, h) {
		const char *name = h->str;
		pos += sprintf(pos, "%s: %s\r\n", name, h2d_header_value(h));

		if (conf->x_forwarded_for && strcasecmp(name, "X-Forwarded-For") == 0) {
			append_xff = true;
			pos -= 2;
			pos += sprintf(pos, ", %s\r\n", client_addr(r));
		}
	}

	if (conf->x_forwarded_for && !append_xff) {
		pos += sprintf(pos, "X-Forwarded-For: %s\r\n", client_addr(r));
	}

	pos += sprintf(pos, "\r\n");
	return pos - buffer;
}

static int h2d_proxy_parse_response_headers(struct h2d_request *r,
		const char *buffer, int buf_len, bool *is_done)
{
	const char *p = buffer;
	const char *buf_end = buffer + buf_len;
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.index];

	// printf("upstream headers: %d\n%s\n===\n", buf_len, buffer);

	if (r->resp.status_code == 0) {
		int proc_len = wuy_http_status_line(p, buf_len,
				&r->resp.status_code, &r->resp.version);
		if (proc_len == 0) {
			return H2D_AGAIN;
		}
		if (proc_len < 0) {
			return H2D_ERROR;
		}
		p += proc_len;
	}

	while (1) {
		int name_len, value_len;
		const char *name_str = p;
		const char *value_str;
		int proc_len = wuy_http_header(p, buf_end - p, &name_len,
				&value_str, &value_len);
		if (proc_len < 0) {
			return H2D_ERROR;
		}
		if (proc_len == 0) {
			*is_done = false;
			break;
		}
		p += proc_len;
		if (proc_len == 2) { /* end of headers */
			*is_done = true;
			break;
		}

		/* handle some */
		if (memcmp(name_str, "Content-Length", 14) == 0) {
			r->resp.content_length = atoi(value_str);
			continue;
		}
		if (memcmp(name_str, "Connection", 10) == 0) {
			continue;
		}
		if (memcmp(name_str, "Transfer-Encoding", 17) == 0) {
			wuy_http_chunked_enable(&ctx->chunked);
			continue;
		}

		h2d_header_add(&r->resp.headers, name_str,
				name_len, value_str, value_len);
	}

	return p - buffer;
}

static int h2d_proxy_do_generate_response_headers(struct h2d_request *r)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.index];

	if (!ctx->has_sent_request) {
		if (h2d_upstream_connection_write_blocked(ctx->upc)) {
			return H2D_AGAIN;
		}

		char request_buffer[4096 + r->req.body_len];
		int len = h2d_proxy_build_request_headers(r, request_buffer);
		memcpy(request_buffer + len, r->req.body_buf, r->req.body_len);

		int ret = h2d_upstream_connection_write(ctx->upc, request_buffer,
				len + r->req.body_len);
		if (ret != H2D_OK) {
			return ret;
		}
		ctx->has_sent_request = true;
	}

	char buffer[4096];
	int read_len = h2d_upstream_connection_read(ctx->upc, buffer, sizeof(buffer));
	if (read_len < 0) {
		return read_len;
	}

	bool is_done;
	int proc_len = h2d_proxy_parse_response_headers(r, buffer, read_len, &is_done);
	if (proc_len < 0) {
		return H2D_ERROR;
	}
	if (!is_done) {
		// TODO read again
		printf("too long response header\n");
		return H2D_ERROR;
	}

	h2d_upstream_connection_read_notfinish(ctx->upc, buffer + proc_len,
			read_len - proc_len);
	return H2D_OK;
}

static bool h2d_proxy_status_code_retry(struct h2d_request *r)
{
	struct h2d_proxy_conf *conf = r->conf_path->module_confs[h2d_proxy_module.index];
	for (int *p = conf->retry_status_codes; *p != 0; p++) {
		if (r->resp.status_code == *p) {
			return true;
		}
	}
	return false;
}

static int h2d_proxy_generate_response_headers(struct h2d_request *r)
{
	struct h2d_proxy_conf *conf = r->conf_path->module_confs[h2d_proxy_module.index];
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.index];
	if (ctx == NULL) {
		ctx = calloc(1, sizeof(struct h2d_proxy_ctx));
		r->module_ctxs[h2d_proxy_module.index] = ctx;

		/* get upstream connection */
		ctx->upc = h2d_upstream_get_connection(&conf->upstream, r);
		if (ctx->upc == NULL) {
			return WUY_HTTP_500;
		}
	}

	while (1) {
		int ret = h2d_proxy_do_generate_response_headers(r);
		if (ret == H2D_AGAIN) {
			return ret;
		}
		if (ret == H2D_OK && !h2d_proxy_status_code_retry(r)) {
			return H2D_OK;
		}

		/* increase connection's address fails */
		h2d_upstream_connection_fail(ctx->upc);

		/* retry */
		printf("retry %d %d\n", ctx->retries, conf->max_retries);
		if (ctx->retries++ >= conf->max_retries) {
			return ret;
		}

		ctx->upc = h2d_upstream_retry_connection(ctx->upc);
		if (ctx->upc == NULL) {
			return WUY_HTTP_500;
		}
		ctx->has_sent_request = false;
	}
}

static int h2d_proxy_generate_response_body(struct h2d_request *r, uint8_t *buffer, int buf_len)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.index];

	/* plain case */
	if (!wuy_http_chunked_is_enabled(&ctx->chunked)) {
		return h2d_upstream_connection_read(ctx->upc, buffer, buf_len);
	}

	/* chunked encoding case */
	if (wuy_http_chunked_is_finished(&ctx->chunked)) {
		return 0;
	}

	uint8_t raw_buffer[buf_len];
	int read_len = h2d_upstream_connection_read(ctx->upc, raw_buffer, buf_len);
	if (read_len < 0) {
		return read_len;
	}

	int proc_len = wuy_http_chunked_process(&ctx->chunked, raw_buffer,
			read_len, buffer, &buf_len);
	if (proc_len < 0) {
		printf("invalid chunked: %d\n", proc_len);
		return H2D_ERROR;
	}
	assert(proc_len == read_len);

	if (buf_len == 0 && !wuy_http_chunked_is_finished(&ctx->chunked)) {
		return H2D_AGAIN;
	}

	/* if chunked is finished, this function will be called again
	 * and returns 0 then. */
	return buf_len;
}

static void h2d_proxy_ctx_free(struct h2d_request *r)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.index];
	if (ctx->upc != NULL) {
		h2d_upstream_release_connection(ctx->upc);
	}
	free(ctx);
}

static int h2d_proxy_conf_stats(void *data, char *buf, int len)
{
	struct h2d_proxy_conf *conf = data;
	return h2d_upstream_conf_stats(&conf->upstream, buf, len);
}

/* configuration */

static struct wuy_cflua_command h2d_proxy_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_proxy_conf, upstream.hostnames),
		.array_member_size = sizeof(struct h2d_upstream_hostname),
	},
	{	.name = "upstream",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_proxy_conf, upstream),
		.u.table = &h2d_upstream_conf_table,
	},
	{	.name = "x_forwarded_for",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_proxy_conf, x_forwarded_for),
	},
	{	.name = "max_retries",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_proxy_conf, max_retries),
	},
	{	.name = "retry_status_codes",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_proxy_conf, retry_status_codes),
		.u.table = WUY_CFLUA_ARRAY_INTEGER_TABLE,
	},
	{ NULL }
};

struct h2d_module h2d_proxy_module = {
	.name = "proxy",
	.command_path = {
		.name = "proxy",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_proxy_conf_commands,
			.size = sizeof(struct h2d_proxy_conf),
		}
	},
	.stats_path = h2d_proxy_conf_stats,

	.content = {
		.response_headers = h2d_proxy_generate_response_headers,
		.response_body = h2d_proxy_generate_response_body,
	},

	.ctx_free = h2d_proxy_ctx_free,
};
