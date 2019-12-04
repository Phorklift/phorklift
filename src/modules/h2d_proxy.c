#include "h2d_main.h"

struct h2d_proxy_conf {
	struct h2d_upstream	*upstream;
};

struct h2d_proxy_ctx {
	bool				is_headers_done;
	wuy_http_chunked_t		chunked;
	struct h2d_upstream_connection	*upc;
};

static wuy_pool_t *h2d_proxy_ctx_pool;

extern struct h2d_module h2d_proxy_module;


static int build_headers(struct h2d_request *r, char *buffer)
{
	char *pos = buffer;

	pos += sprintf(pos, "GET %s HTTP/1.1\r\n", h2d_header_value(r->req.url));
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

static bool h2d_proxy_on_response(struct h2d_request *r)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];
	if (!ctx->is_headers_done) {
		int proc_len = h2d_proxy_read_response_headers(r, (char *)r->resp.body_buffer, r->resp.body_buf_len);
		printf("h2d_proxy_on_response %s %d %d\n", h2d_header_value(r->req.url), r->resp.body_buf_len, proc_len);
		if (proc_len < 0) {
			return false;
		}
		if (proc_len == r->resp.body_buf_len) {
			r->resp.body_buf_len = 0;
			return true;
		}

		r->resp.body_buf_len -= proc_len;
		memmove(r->resp.body_buffer, r->resp.body_buffer + proc_len, r->resp.body_buf_len);
	}

	return true;
}

static int h2d_proxy_process_request_headers(struct h2d_request *r)
{
	struct h2d_proxy_conf *conf = r->conf_path->module_confs[h2d_proxy_module.index];

	struct h2d_upstream_connection *upc = h2d_upstream_get_connection(conf->upstream, r);
	if (upc == NULL) {
		return H2D_ERROR;
	}

	struct h2d_proxy_ctx *ctx = wuy_pool_alloc(h2d_proxy_ctx_pool);
	wuy_http_chunked_init(&ctx->chunked);
	ctx->upc = upc;
	ctx->is_headers_done = false;

	r->module_ctxs[h2d_proxy_module.request_ctx.index] = ctx;

	/* send header */
	char buffer[4096];
	int len = build_headers(r, buffer);
	len = h2d_upstream_connection_write(upc, buffer, len);
	if (len < 0) {
		return H2D_ERROR;
	}
	return 0;
}
static int h2d_proxy_process_request_body(struct h2d_request *r, uint8_t *buf, int len)
{
	return 0;
}
static int h2d_proxy_generate_response_headers(struct h2d_request *r)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];
	return ctx->is_headers_done ? H2D_OK : H2D_AGAIN;
}
static int h2d_proxy_generate_response_body(struct h2d_request *r, uint8_t *buf, int buf_len)
{
	//printf("h2d_proxy_generate_response_body %d\n", buf_len);
	int data_len = r->resp.body_buf_len;

	if (data_len == 0) {
		return H2D_AGAIN;
	}

	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];

	if (wuy_http_chunked_is_enabled(&ctx->chunked)) {
		int proc_len = wuy_http_chunked_process(&ctx->chunked, r->resp.body_buffer,
				data_len, buf, &buf_len);
		if (proc_len < 0) {
			printf("invalid chunked!!!!!!!!!!!! %d %d %d %d %ld %s\n", proc_len, data_len,
					ctx->chunked.state, ctx->chunked.size, r->resp.sent_length,
					h2d_header_value(r->req.url));
			return H2D_ERROR;
		}
		if (proc_len < data_len) {
			memmove(r->resp.body_buffer, r->resp.body_buffer + proc_len, data_len - proc_len);
		}
		r->resp.body_buf_len -= proc_len;
		return buf_len;

	} else if (data_len <= buf_len) {
		memcpy(buf, r->resp.body_buffer, data_len);
		r->resp.body_buf_len = 0;
		return data_len;

	} else {
		memcpy(buf, r->resp.body_buffer, buf_len);
		memmove(r->resp.body_buffer, r->resp.body_buffer + buf_len, data_len - buf_len);
		r->resp.body_buf_len -= buf_len;
		return buf_len;
	}
}

static bool h2d_proxy_is_body_finished(struct h2d_request *r)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];
	return wuy_http_chunked_is_finished(&ctx->chunked);
}

static void h2d_proxy_ctx_free(struct h2d_request *r)
{
	struct h2d_proxy_ctx *ctx = r->module_ctxs[h2d_proxy_module.request_ctx.index];
	if (ctx == NULL) {
		return;
	}

	if (ctx->upc != NULL) {
		h2d_upstream_release_connection(ctx->upc);
	}

	wuy_pool_free(ctx);
}


/* configuration */

static bool h2d_proxy_conf_is_enable(void *data)
{
	struct h2d_proxy_conf *conf = data;
	return h2d_upstream_conf_is_enable(conf->upstream);
}
static bool h2d_proxy_conf_post(void *data)
{
	struct h2d_proxy_conf *conf = data;
	return h2d_upstream_conf_on_response(conf->upstream, h2d_proxy_on_response);
}
static void h2d_proxy_master_init(void)
{
	h2d_proxy_ctx_pool = wuy_pool_new_type(struct h2d_proxy_ctx);
}

static struct wuy_cflua_command h2d_proxy_conf_commands[] = {
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
			.post = h2d_proxy_conf_post,
		}
	},

	.content = {
		.is_enable = h2d_proxy_conf_is_enable,
		.process_headers = h2d_proxy_process_request_headers,
		.process_body = h2d_proxy_process_request_body,
		.response_headers = h2d_proxy_generate_response_headers,
		.response_body = h2d_proxy_generate_response_body,
		.is_body_finished = h2d_proxy_is_body_finished,
	},

	.request_ctx = {
		.free = h2d_proxy_ctx_free,
	},

	.master_init = h2d_proxy_master_init,
};
