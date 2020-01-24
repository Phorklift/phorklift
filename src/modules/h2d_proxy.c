#include "h2d_main.h"

struct h2d_proxy_conf {
	bool			tmp;
	struct h2d_upstream	*upstream;
};

struct h2d_proxy_ctx {
	bool			is_headers_done;
	int			resp_headers_buf_start;
	int			resp_headers_buf_end;
	char			*resp_headers_buffer;
	wuy_http_chunked_t	chunked;

	struct h2d_upstream_connection	*upc;
};

static wuy_pool_t *h2d_proxy_ctx_pool;

extern struct h2d_module h2d_proxy_module;

static int build_headers(struct h2d_request *r, char *buffer)
{
	char *pos = buffer;

	pos += sprintf(pos, "%s %s HTTP/1.1\r\n", wuy_http_string_method(r->req.method),
			h2d_header_value(r->req.url));

	if (r->req.content_length != H2D_CONTENT_LENGTH_INIT) {
		pos += sprintf(pos, "Content-Length: %ld\r\n", r->req.content_length);
	}

	struct h2d_header *h;
	for (h = r->req.buffer; h->name_len != 0; h = h2d_header_next(h)) {
		const char *name = h->str;
		if (name[0] == ':') {
			if (strcmp(name, ":authority") == 0) {
				name = "Host";
			} else {
				continue;
			}
		}
		pos += sprintf(pos, "%s: %s\r\n", name, h2d_header_value(h));
	}
	pos += sprintf(pos, "\r\n");
	return pos - buffer;
}

static int h2d_proxy_read_response_headers(struct h2d_request *r,
		const char *buffer, int buf_len)
{
	const char *p = buffer;
	const char *buf_end = buffer + buf_len;
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];

	// printf("upstream headers:\n%s\n===\n", buffer);

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
		if (proc_len == 0) {
			return H2D_AGAIN;
		}
		if (proc_len < 0) {
			return H2D_ERROR;
		}
		p += proc_len;
		if (proc_len == 2) { /* end of headers */
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

		r->resp.next = h2d_header_add(r->resp.next, name_str,
				name_len, value_str, value_len);
	}

	ctx->is_headers_done = true;
	return p - buffer;
}

static int h2d_proxy_process_request_headers(struct h2d_request *r)
{
	struct h2d_proxy_conf *conf = r->conf_path->module_confs[h2d_proxy_module.index];

	/* get upstream connection */
	struct h2d_upstream_connection *upc = h2d_upstream_get_connection(conf->upstream);
	if (upc == NULL) {
		return H2D_ERROR;
	}
	upc->request = r;

	/* init ctx */
	struct h2d_proxy_ctx *ctx = wuy_pool_alloc(h2d_proxy_ctx_pool);
	bzero(ctx, sizeof(struct h2d_proxy_ctx));
	ctx->upc = upc;
	r->module_ctxs[h2d_proxy_module.request_ctx.index] = ctx;

	/* send header */
	char buffer[4096];
	int len = build_headers(r, buffer);
	len = h2d_upstream_connection_write(upc, buffer, len);
	if (len < 0) {
		return H2D_ERROR;
	}
	return H2D_OK;
}
static int h2d_proxy_process_request_body(struct h2d_request *r)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];
	int len = h2d_upstream_connection_write(ctx->upc, r->req.body_buf, r->req.body_len);
	if (len < 0) {
		return H2D_ERROR;
	}
	return H2D_OK;
}
static int h2d_proxy_generate_response_headers(struct h2d_request *r)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];
	if (ctx->is_headers_done) { /* should not happen */
		return H2D_ERROR;
	}

	/* read response data */
	if (ctx->resp_headers_buffer == NULL) {
		ctx->resp_headers_buffer = malloc(4096);
	}
	int read_len = loop_stream_read(ctx->upc->loop_stream, ctx->resp_headers_buffer, 4096);
	if (read_len < 0) {
		return H2D_ERROR;
	}
	if (read_len == 0) {
		return H2D_AGAIN;
	}

	/* parse response headers */
	int proc_len = h2d_proxy_read_response_headers(r, ctx->resp_headers_buffer, read_len);
	if (proc_len < 0) {
		return H2D_ERROR;
	}
	if (!ctx->is_headers_done) {
		/* TODO */
		printf("not complete response headers in %d\n", read_len);
		return H2D_ERROR;
	}

	if (proc_len == read_len) {
		free(ctx->resp_headers_buffer);
		ctx->resp_headers_buffer = NULL;
	} else {
		ctx->resp_headers_buf_start = proc_len;
		ctx->resp_headers_buf_end = read_len;
	}
	return H2D_OK;
}

static int h2d_proxy_generate_response_body_chunked(struct h2d_request *r,
		uint8_t *buffer, int buf_len)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];

	if (wuy_http_chunked_is_finished(&ctx->chunked)) {
		return H2D_OK;
	}

	uint8_t *buf_pos = buffer;
	if (ctx->resp_headers_buffer != NULL) {
		char *preread_pos = ctx->resp_headers_buffer + ctx->resp_headers_buf_start;
		int preread_len = ctx->resp_headers_buf_end - ctx->resp_headers_buf_start;
		int out_len = buf_len;
		int proc_len = wuy_http_chunked_process(&ctx->chunked, (uint8_t *)preread_pos,
				preread_len, buf_pos, &out_len);
		if (proc_len < 0) {
			printf("invalid chunked preread: %d\n", proc_len);
			return H2D_ERROR;
		}
		if (proc_len < preread_len) {
			ctx->resp_headers_buf_start += proc_len;
			return out_len == 0 ? H2D_AGAIN : out_len;
		}
		if (wuy_http_chunked_is_finished(&ctx->chunked)) {
			return out_len == 0 ? H2D_AGAIN : out_len;
		}

		buf_pos += out_len;
		buf_len -= out_len;

		free(ctx->resp_headers_buffer);
		ctx->resp_headers_buffer = NULL;
	}

	uint8_t raw_buffer[buf_len];
	int read_len = loop_stream_read(ctx->upc->loop_stream, raw_buffer, buf_len);
	if (read_len < 0) {
		return H2D_ERROR;
	}
	int proc_len = wuy_http_chunked_process(&ctx->chunked, raw_buffer,
			read_len, buf_pos, &buf_len);
	if (proc_len < 0) {
		printf("invalid chunked: %d\n", proc_len);
		return H2D_ERROR;
	}
	if (proc_len != read_len) {
		// TODO
		printf("warning: process chunked: %d %d\n", proc_len, read_len);
	}

	int ret = buf_pos - buffer + buf_len;
	return ret == 0 ? H2D_AGAIN : ret;
}
static int h2d_proxy_generate_response_body(struct h2d_request *r,
		uint8_t *buffer, int buf_len)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];
	if (wuy_http_chunked_is_enabled(&ctx->chunked)) {
		return h2d_proxy_generate_response_body_chunked(r, buffer, buf_len);
	}

	uint8_t *buf_pos = buffer;
	if (ctx->resp_headers_buffer != NULL) {
		char *preread_pos = ctx->resp_headers_buffer + ctx->resp_headers_buf_start;
		int preread_len = ctx->resp_headers_buf_end - ctx->resp_headers_buf_start;
		if (preread_len > buf_len) {
			memcpy(buffer, preread_pos, buf_len);
			ctx->resp_headers_buf_start += buf_len;
			return buf_len;
		}

		memcpy(buffer, preread_pos, preread_len);
		free(ctx->resp_headers_buffer);
		ctx->resp_headers_buffer = NULL;
		if (preread_len == buf_len) {
			return buf_len;
		}
		buf_pos += preread_len;
		buf_len -= preread_len;
	}

	int read_len = loop_stream_read(ctx->upc->loop_stream, buf_pos, buf_len);
	if (read_len < 0) {
		return H2D_ERROR;
	}

	return buf_pos - buffer + read_len;
}

static void h2d_proxy_ctx_free(struct h2d_request *r)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];

	if (ctx->upc != NULL) {
		h2d_upstream_release_connection(ctx->upc);
	}

	free(ctx->resp_headers_buffer);
	wuy_pool_free(ctx);
}


/* configuration */

static void h2d_proxy_master_init(void)
{
	h2d_proxy_ctx_pool = wuy_pool_new_type(struct h2d_proxy_ctx);
}

static struct wuy_cflua_command h2d_proxy_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_proxy_conf, tmp),
	},
	{	.name = "upstream",
		.type = WUY_CFLUA_TYPE_TABLE,
		.flags = WUY_CFLUA_FLAG_TABLE_REUSE,
		.offset = offsetof(struct h2d_proxy_conf, upstream),
		.u.table = &h2d_upstream_conf_table,
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

	.content = {
		.process_headers = h2d_proxy_process_request_headers,
		.process_body = h2d_proxy_process_request_body,
		.response_headers = h2d_proxy_generate_response_headers,
		.response_body = h2d_proxy_generate_response_body,
	},

	.request_ctx = {
		.free = h2d_proxy_ctx_free,
	},

	.master_init = h2d_proxy_master_init,
};
