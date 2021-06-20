#include "phl_main.h"

#define _log(level, fmt, ...) phl_request_log_at(r, \
		r->c->conf_listen->http1.log, level, "http1: " fmt, ##__VA_ARGS__)

int phl_http1_request_headers(struct phl_request *r)
{
	struct phl_connection *c = r->c;
	char *buf_base = (char *)c->recv_buffer;

	/* request line */
	if (r->req.method == 0) {
		int url_len;
		const char *url_str;
		int proc_len = wuy_http_request_line(buf_base + c->recv_buf_pos,
				c->recv_buf_end - c->recv_buf_pos,
				&r->req.method, &url_str, &url_len, &r->req.version);
		if (proc_len < 0) {
			_log(PHL_LOG_INFO, "invalid request line");
			return PHL_ERROR;
		}
		if (proc_len == 0) {
			return PHL_AGAIN;
		}

		if (!phl_request_set_uri(r, url_str, url_len)) {
			return PHL_ERROR;
		}

		_log(PHL_LOG_DEBUG, "request URI %.*s", url_len, url_str);

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
			_log(PHL_LOG_INFO, "invalid request header");
			return PHL_ERROR;
		}
		if (proc_len == 0) {
			return PHL_AGAIN;
		}
		c->recv_buf_pos += proc_len;
		if (proc_len == 2) { /* end of headers */
			break;
		}

		_log(PHL_LOG_DEBUG, "request header: %.*s %.*s",
				name_len, name_str, value_len, value_str);

		/* handle some */
		if (memcmp(name_str, "Content-Length", 14) == 0) {
			char *end;
			r->req.content_length = strtol(value_str, &end, 10);
			if (end - value_str != value_len) {
				return WUY_HTTP_400;
			}
			continue;
		}
		if (memcmp(name_str, "Host", 4) == 0) {
			if (!phl_request_set_host(r, value_str, value_len)) {
				return PHL_ERROR;
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

		phl_header_add(&r->req.headers, name_str, name_len, value_str, value_len, r->pool);
	}
	return PHL_OK;
}

int phl_http1_request_body(struct phl_request *r)
{
	/* no body */
	if (r->req.content_length == PHL_CONTENT_LENGTH_INIT
			&& !wuy_http_chunked_is_enabled(&r->req.chunked)) {
		return PHL_OK;
	}

	/* we assume all received data is body, not supporting pipeline */
	struct phl_connection *c = r->c;
	const uint8_t *buf_pos = c->recv_buffer + c->recv_buf_pos;
	const uint8_t *buf_end = c->recv_buffer + c->recv_buf_end;
	int buf_len = c->recv_buf_end - c->recv_buf_pos;
	c->recv_buf_pos = c->recv_buf_end;

	/* plain */
	if (r->req.content_length != PHL_CONTENT_LENGTH_INIT) {
		int ret = phl_request_append_body(r, buf_pos, buf_len);
		if (ret != PHL_OK) {
			return ret;
		}
		return r->req.body_finished ? PHL_OK : PHL_AGAIN;
	}

	/* chunked */
	while (buf_pos < buf_end) {
		int data_len = wuy_http_chunked_decode(&r->req.chunked, &buf_pos, buf_end);
		if (data_len < 0) {
			phl_request_log(r, PHL_LOG_DEBUG, "chunked error: %d", data_len);
			return WUY_HTTP_400;
		}
		if (data_len == 0) {
			break;
		}
		int ret = phl_request_append_body(r, buf_pos, data_len);
		if (ret != PHL_OK) {
			return ret;
		}
		buf_pos += data_len;
	}

	if (wuy_http_chunked_is_finished(&r->req.chunked)) {
		r->req.body_finished = true;
		return PHL_OK;
	}
	return PHL_AGAIN;
}

static bool phl_http1_response_is_chunked(struct phl_request *r)
{
	return r->req.version != 0 && r->resp.content_length == PHL_CONTENT_LENGTH_INIT;
}
int phl_http1_response_headers(struct phl_request *r)
{
	struct phl_connection *c = r->c;
	int estimate_size = phl_header_estimate_size(&r->resp.headers) + 100;
	int ret = phl_connection_make_space(c, estimate_size);
	if (ret < 0) {
		return ret;
	}

	/* response status line */
	char *begin = (char *)c->send_buffer + c->send_buf_len;
	char *p = begin;
	p += sprintf(p, "HTTP/1.1 %d %s\r\n", r->resp.status_code,
			wuy_http_string_status_code(r->resp.status_code));

	if (phl_http1_response_is_chunked(r)) {
		p += sprintf(p, "Transfer-Encoding: chunked\r\n");
	} else if (r->resp.content_length != PHL_CONTENT_LENGTH_INIT) {
		p += sprintf(p, "Content-Length: %ld\r\n", r->resp.content_length);
	}

	struct phl_header *h;
	phl_header_iter(&r->resp.headers, h) {
		p += sprintf(p, "%s: %s\r\n", h->str, phl_header_value(h));
	}
	p += sprintf(p, "\r\n");

	_log(PHL_LOG_DEBUG, "response headers: %ld", p - begin);

	c->send_buf_len += p - begin;

	return PHL_OK;
}

#define PHL_CHUNKED_PREFIX_LENGTH 10
void phl_http1_response_body_packfix(struct phl_request *r,
		uint8_t **p_buf_pos, int *p_buf_len)
{
	if (!phl_http1_response_is_chunked(r)) {
		return;
	}
	*p_buf_pos += PHL_CHUNKED_PREFIX_LENGTH;
	*p_buf_len -= PHL_CHUNKED_PREFIX_LENGTH + 7;
}
int phl_http1_response_body_pack(struct phl_request *r, uint8_t *payload,
		int length, bool is_last)
{
	if (!phl_http1_response_is_chunked(r)) {
		return length;
	}

	sprintf((char *)payload - PHL_CHUNKED_PREFIX_LENGTH, "%-8x\r", length);
	payload[-1] = '\n';

	if (length != 0 && is_last) {
		memcpy(payload + length, "\r\n0\r\n\r\n", 7);
		return length + PHL_CHUNKED_PREFIX_LENGTH + 7;
	} else {
		memcpy(payload + length, "\r\n", 2);
		return length + PHL_CHUNKED_PREFIX_LENGTH + 2;
	}
}

static void phl_http1_set_state(struct phl_connection *c)
{
	enum phl_connection_state state;
	struct phl_request *r = c->u.request;
	if (r == NULL) {
		state = PHL_CONNECTION_STATE_IDLE;
	} else if (r->state < PHL_REQUEST_STATE_RESPONSE_HEADERS_1) {
		state = PHL_CONNECTION_STATE_READING;
	} else {
		state = PHL_CONNECTION_STATE_WRITING;
	}

	phl_connection_set_state(c, state);
}

void phl_http1_on_readable(struct phl_connection *c)
{
	if (c->u.request == NULL) {
		c->u.request = phl_request_new(c);
	}
	phl_request_run(c->u.request, "http1 readable");

	phl_http1_set_state(c);
}

void phl_http1_on_writable(struct phl_connection *c)
{
	struct phl_request *r = c->u.request;
	if (r == NULL) {
		return;
	}
	phl_request_run(r, "http1 writable");

	phl_http1_set_state(c);
}

void phl_http1_request_close(struct phl_request *r)
{
	struct phl_connection *c = r->c;
	assert(c->u.request == r);

	c->u.request = NULL;

	if (r->state != PHL_REQUEST_STATE_DONE || r->req.version == 0) {
		phl_connection_close(c);
	} else {
		phl_connection_set_state(c, PHL_CONNECTION_STATE_IDLE);
	}
}

struct wuy_cflua_command phl_conf_listen_http1_commands[] = {
	{	.name = "keepalive_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_conf_listen, http1.keepalive_timeout),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "keepalive_min_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_conf_listen, http1.keepalive_min_timeout),
		.default_value.n = 30,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_conf_listen, http1.log),
		.u.table = &phl_log_omit_conf_table,
	},
	{ NULL }
};
