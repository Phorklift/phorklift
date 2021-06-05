#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log_at(r, \
		r->c->conf_listen->http1.log, level, "http1: " fmt, ##__VA_ARGS__)

int h2d_http1_request_headers(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;
	char *buf_base = (char *)c->recv_buffer;

	/* request line */
	if (r->req.method == 0) {
		int url_len;
		const char *url_str;
		int proc_len = wuy_http_request_line(buf_base + c->recv_buf_pos,
				c->recv_buf_end - c->recv_buf_pos,
				&r->req.method, &url_str, &url_len, &r->req.version);
		if (proc_len < 0) {
			_log(H2D_LOG_INFO, "invalid request line");
			return H2D_ERROR;
		}
		if (proc_len == 0) {
			return H2D_AGAIN;
		}

		if (!h2d_request_set_uri(r, url_str, url_len)) {
			return H2D_ERROR;
		}

		_log(H2D_LOG_DEBUG, "request URI %.*s", url_len, url_str);

		c->recv_buf_pos += proc_len;
	}

	/* request headers */
	while (1) {
		int name_len, value_len;
		const char *name_str = buf_base + c->recv_buf_pos;
		const char *value_str;
		int proc_len = wuy_http_header(buf_base + c->recv_buf_pos,
				c->recv_buf_end - c->recv_buf_pos,
				&name_len, &value_str, &value_len);
		if (proc_len < 0) {
			_log(H2D_LOG_INFO, "invalid request header");
			return H2D_ERROR;
		}
		if (proc_len == 0) {
			return H2D_AGAIN;
		}
		c->recv_buf_pos += proc_len;
		if (proc_len == 2) { /* end of headers */
			break;
		}

		_log(H2D_LOG_DEBUG, "request header: %.*s %.*s",
				name_len, name_str, value_len, value_str);

		/* handle some */
		if (memcmp(name_str, "Content-Length", 14) == 0) {
			r->req.content_length = atoi(value_str);
			if (r->req.content_length == 0) {
				return WUY_HTTP_400;
			}
			continue;
		}
		if (memcmp(name_str, "Host", 4) == 0) {
			if (!h2d_request_set_host(r, value_str, value_len)) {
				return H2D_ERROR;
			}
			continue;
		}
		if (memcmp(name_str, "Connection", 10) == 0) {
			continue;
		}
		if (memcmp(name_str, "Transfer-Encoding", 17) == 0) {
			wuy_http_chunked_enable(&r->req.chunked);
			continue;
		}

		h2d_header_add(&r->req.headers, name_str, name_len, value_str, value_len, r->pool);
	}
	return H2D_OK;
}

int h2d_http1_request_body(struct h2d_request *r)
{
	/* no body */
	if (r->req.content_length != H2D_CONTENT_LENGTH_INIT
			&& !wuy_http_chunked_is_enabled(&r->req.chunked)) {
		return H2D_OK;
	}

	/* we assume all received data is body, not supporting pipeline */
	struct h2d_connection *c = r->c;
	const uint8_t *buf_pos = c->recv_buffer + c->recv_buf_pos;
	const uint8_t *buf_end = c->recv_buffer + c->recv_buf_end;
	int buf_len = c->recv_buf_end - c->recv_buf_pos;
	c->recv_buf_pos = c->recv_buf_end;

	/* plain */
	if (r->req.content_length != H2D_CONTENT_LENGTH_INIT) {
		int ret = h2d_request_append_body(r, buf_pos, buf_len);
		if (ret != H2D_OK) {
			return ret;
		}
		return r->req.body_finished ? H2D_OK : H2D_AGAIN;
	}

	/* chunked */
	while (buf_pos < buf_end) {
		int data_len = wuy_http_chunked_decode(&r->req.chunked, &buf_pos, buf_end);
		if (data_len < 0) {
			h2d_request_log(r, H2D_LOG_DEBUG, "chunked error: %d", data_len);
			return WUY_HTTP_400;
		}
		if (data_len == 0) {
			break;
		}
		int ret = h2d_request_append_body(r, buf_pos, data_len);
		if (ret != H2D_OK) {
			return ret;
		}
		buf_pos += data_len;
	}

	if (wuy_http_chunked_is_finished(&r->req.chunked)) {
		r->req.body_finished = true;
		return H2D_OK;
	}
	return H2D_AGAIN;
}

static bool h2d_http1_response_is_chunked(struct h2d_request *r)
{
	return r->req.version != 0 && r->resp.content_length == H2D_CONTENT_LENGTH_INIT;
}
int h2d_http1_response_headers(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;
	int estimate_size = h2d_header_estimate_size(&r->resp.headers) + 100;
	int ret = h2d_connection_make_space(c, estimate_size);
	if (ret < 0) {
		return ret;
	}

	/* response status line */
	char *begin = (char *)c->send_buffer + c->send_buf_len;
	char *p = begin;
	p += sprintf(p, "HTTP/1.1 %d %s\r\n", r->resp.status_code,
			wuy_http_string_status_code(r->resp.status_code));

	if (h2d_http1_response_is_chunked(r)) {
		p += sprintf(p, "Transfer-Encoding: chunked\r\n");
	} else if (r->resp.content_length != H2D_CONTENT_LENGTH_INIT) {
		p += sprintf(p, "Content-Length: %ld\r\n", r->resp.content_length);
	}

	struct h2d_header *h;
	h2d_header_iter(&r->resp.headers, h) {
		p += sprintf(p, "%s: %s\r\n", h->str, h2d_header_value(h));
	}
	p += sprintf(p, "\r\n");

	_log(H2D_LOG_DEBUG, "response headers: %ld", p - begin);

	c->send_buf_len += p - begin;

	return H2D_OK;
}

#define H2D_CHUNKED_PREFIX_LENGTH 10
void h2d_http1_response_body_packfix(struct h2d_request *r,
		uint8_t **p_buf_pos, int *p_buf_len)
{
	if (!h2d_http1_response_is_chunked(r)) {
		return;
	}
	*p_buf_pos += H2D_CHUNKED_PREFIX_LENGTH;
	*p_buf_len -= H2D_CHUNKED_PREFIX_LENGTH + 7;
}
int h2d_http1_response_body_pack(struct h2d_request *r, uint8_t *payload,
		int length, bool is_last)
{
	if (!h2d_http1_response_is_chunked(r)) {
		return length;
	}

	sprintf((char *)payload - H2D_CHUNKED_PREFIX_LENGTH, "%-8x\r", length);
	payload[-1] = '\n';

	if (length != 0 && is_last) {
		memcpy(payload + length, "\r\n0\r\n\r\n", 7);
		return length + H2D_CHUNKED_PREFIX_LENGTH + 7;
	} else {
		memcpy(payload + length, "\r\n", 2);
		return length + H2D_CHUNKED_PREFIX_LENGTH + 2;
	}
}

static void h2d_http1_set_state(struct h2d_connection *c)
{
	enum h2d_connection_state state;
	struct h2d_request *r = c->u.request;
	if (r == NULL) {
		state = H2D_CONNECTION_STATE_IDLE;
	} else if (r->state < H2D_REQUEST_STATE_RESPONSE_HEADERS_1) {
		state = H2D_CONNECTION_STATE_READING;
	} else {
		state = H2D_CONNECTION_STATE_WRITING;
	}

	h2d_connection_set_state(c, state);
}

void h2d_http1_on_readable(struct h2d_connection *c)
{
	if (c->u.request == NULL) {
		c->u.request = h2d_request_new(c);
	}
	h2d_request_run(c->u.request);

	h2d_http1_set_state(c);
}

void h2d_http1_on_writable(struct h2d_connection *c)
{
	struct h2d_request *r = c->u.request;
	if (r == NULL) {
		return;
	}
	h2d_request_run(r);

	h2d_http1_set_state(c);
}

void h2d_http1_request_close(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;
	assert(c->u.request == r);

	c->u.request = NULL;

	if (r->state != H2D_REQUEST_STATE_DONE || r->req.version == 0) {
		h2d_connection_close(c);
	} else {
		h2d_connection_set_state(c, H2D_CONNECTION_STATE_IDLE);
	}
}

struct wuy_cflua_command h2d_conf_listen_http1_commands[] = {
	{	.name = "keepalive_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http1.keepalive_timeout),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "keepalive_min_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http1.keepalive_min_timeout),
		.default_value.n = 30,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, http1.log),
		.u.table = &h2d_log_omit_conf_table,
	},
	{ NULL }
};
