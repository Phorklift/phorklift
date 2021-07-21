#include "phl_main.h"

struct phl_proxy_conf {
	struct phl_upstream_conf	*upstream; /* at top! */
	bool				x_forwarded_for;
	bool				replace_host;
};

struct phl_module phl_proxy_module;

// TODO move this out
static const char *client_addr(struct phl_request *r)
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

static int phl_proxy_build_request_headers(struct phl_request *r, char *buffer)
{
	struct phl_proxy_conf *conf = r->conf_path->module_confs[phl_proxy_module.index];

	char *pos = buffer;

	pos += sprintf(pos, "%s ", wuy_http_string_method(r->req.method));

	if (!r->req.uri.is_rewrited) {
		pos += sprintf(pos, "%s HTTP/1.1\r\n", r->req.uri.raw);
	} else if (r->req.uri.query_pos == NULL) {
		pos += sprintf(pos, "%s HTTP/1.1\r\n", r->req.uri.path); // TODO url-encode?
	} else {
		pos += sprintf(pos, "%s%s HTTP/1.1\r\n",
				r->req.uri.path, r->req.uri.query_pos);
	}

	if (conf->replace_host) {
		pos += sprintf(pos, "Host: %s\r\n", conf->upstream->name);
	} else if (r->req.host != NULL) {
		pos += sprintf(pos, "Host: %s\r\n", r->req.host);
	}
	if (r->req.content_length != PHL_CONTENT_LENGTH_INIT) {
		pos += sprintf(pos, "Content-Length: %ld\r\n", r->req.content_length);
	}

	bool append_xff = false;
	struct phl_header *h;
	phl_header_iter(&r->req.headers, h) {
		const char *name = h->str;
		pos += sprintf(pos, "%s: %s\r\n", name, phl_header_value(h));

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

static int phl_proxy_build_request(struct phl_request *r)
{
	struct phl_upstream_content_ctx *ctx = r->module_ctxs[phl_proxy_module.index];

	if (r->req.method != WUY_HTTP_GET && r->req.method != WUY_HTTP_HEAD) {
		ctx->retries = -1;
	}

	ctx->req_buf = wuy_pool_alloc(r->pool, 4096 + r->req.body_len); // TODO
	ctx->req_len = phl_proxy_build_request_headers(r, ctx->req_buf);
	memcpy(ctx->req_buf + ctx->req_len, r->req.body_buf, r->req.body_len);
	ctx->req_len += r->req.body_len;
	phl_request_log(r, PHL_LOG_DEBUG, "proxy request: %.*s", ctx->req_len, ctx->req_buf);
	return PHL_OK;
}

static int phl_proxy_parse_response_headers(struct phl_request *r,
		const char *buffer, int buf_len, bool *is_done)
{
	const char *p = buffer;
	const char *buf_end = buffer + buf_len;
	struct phl_upstream_content_ctx *ctx = r->module_ctxs[phl_proxy_module.index];

	if (r->resp.status_code == 0) {
		int proc_len = wuy_http_status_line(p, buf_len,
				&r->resp.status_code, &r->resp.version);
		if (proc_len == 0) {
			return PHL_AGAIN;
		}
		if (proc_len < 0) {
			return PHL_ERROR;
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
			return PHL_ERROR;
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
			ctx->data = wuy_pool_alloc(r->pool, sizeof(wuy_http_chunked_t));
			wuy_http_chunked_enable(ctx->data);
			continue;
		}

		phl_request_log(r, PHL_LOG_DEBUG, "proxy response header: %.*s %.*s",
				name_len, name_str, value_len, value_str);

		phl_header_add(&r->resp.headers, name_str, name_len,
				value_str, value_len, r->pool);
	}

	return p - buffer;
}

static bool phl_proxy_is_response_body_done(struct phl_request *r)
{
	struct phl_upstream_content_ctx *ctx = r->module_ctxs[phl_proxy_module.index];
	wuy_http_chunked_t *chunked = ctx->data;

	if (chunked != NULL) {
		return wuy_http_chunked_is_finished(chunked);
	}
	return false;
}

static int phl_proxy_build_response_body(struct phl_request *r, uint8_t *buffer,
		int data_len, int buf_size)
{
	struct phl_upstream_content_ctx *ctx = r->module_ctxs[phl_proxy_module.index];
	wuy_http_chunked_t *chunked = ctx->data;

	if (chunked == NULL) {
		/* do nothing for none-chunked */
		return data_len;
	}

	/* decode chunked */
	uint8_t *buf_pos = buffer;
	const uint8_t *data_pos = buffer;
	const uint8_t *buf_end = buffer + data_len;
	while (data_pos < buf_end) {
		int len = wuy_http_chunked_decode(chunked, &data_pos, buf_end);
		if (len < 0) {
			phl_request_log(r, PHL_LOG_ERROR, "proxy chunked error: %d", len);
			return PHL_ERROR;
		}
		if (len == 0) {
			break;
		}

		phl_request_log(r, PHL_LOG_DEBUG, "proxy chunked: %d", len);
		if (data_pos != buf_pos) {
			memmove(buf_pos, data_pos, len);
		}
		data_pos += len;
		buf_pos += len;
	}

	if (buf_pos == buffer && !wuy_http_chunked_is_finished(chunked)) {
		return PHL_AGAIN;
	}

	/* if chunked is finished, this function will be called again
	 * and returns 0 then. */
	return buf_pos - buffer;
}

static struct phl_upstream_ops phl_proxy_upstream_ops = {
	.build_request = phl_proxy_build_request,
	.parse_response_headers = phl_proxy_parse_response_headers,
	.is_response_body_done = phl_proxy_is_response_body_done,
	.build_response_body = phl_proxy_build_response_body,
};

static const char *phl_proxy_conf_post(void *data)
{
	struct phl_proxy_conf *conf = data;
	return phl_upstream_content_set_ops(conf->upstream, &phl_proxy_upstream_ops);
}

static struct wuy_cflua_command phl_proxy_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.is_single_array = true,
		.offset = offsetof(struct phl_proxy_conf, upstream),
		.u.table = &phl_upstream_conf_table,
	},
	{	.name = "x_forwarded_for",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_proxy_conf, x_forwarded_for),
		.description = "Whether to update X-Forwarded-For header.",
	},
	{	.name = "replace_host",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_proxy_conf, replace_host),
		.description = "Whether to replace Host header by upstream server hostname.",
	},
	{ NULL }
};

struct phl_module phl_proxy_module = {
	.name = "proxy",
	.command_path = {
		.name = "proxy",
		.description = "Proxy content module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_proxy_conf_commands,
			.size = sizeof(struct phl_proxy_conf),
			.post = phl_proxy_conf_post,
		}
	},
	.content = PHL_UPSTREAM_CONTENT,
	.ctx_free = phl_upstream_content_ctx_free,
};
