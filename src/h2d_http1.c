#include "h2d_main.h"

static int h2d_http1_request_headers(struct h2d_request *r, const char *buffer, int buf_len)
{
	const char *buf_pos = buffer;

	/* request line */
	if (r->req.method == 0) {
		int url_len;
		const char *url_str;
		int proc_len = wuy_http_request_line(buf_pos, buf_len,
				&r->req.method, &url_str, &url_len, &r->req.version);
		if (proc_len < 0) {
			printf("invalid request line !!!!\n");
			return H2D_ERROR;
		}
		if (proc_len == 0) {
			return H2D_AGAIN;
		}

		r->req.url = r->req.next;
		r->req.next = h2d_header_add(r->req.next, ":url", 4, url_str, url_len);

		buf_pos += proc_len;
	}

	/* request headers */
	const char *buf_end = buffer + buf_len;
	while (1) {
		int name_len, value_len;
		const char *name_str = buf_pos;
		const char *value_str;
		int proc_len = wuy_http_header(buf_pos, buf_end - buf_pos, &name_len,
				&value_str, &value_len);
		if (proc_len < 0) {
			return H2D_ERROR;
		}
		if (proc_len == 0) {
			break;
		}
		buf_pos += proc_len;
		if (proc_len == 2) { /* end of headers */
			r->state = H2D_REQUEST_STATE_PROCESS_HEADERS;
			break;
		}

		/* handle some */
		if (memcmp(name_str, "Content-Length", 14) == 0) {
			r->req.content_length = atoi(value_str);
			continue;
		}
		if (memcmp(name_str, "Connection", 10) == 0) {
			continue;
		}
		if (memcmp(name_str, "Transfer-Encoding", 17) == 0) {
			wuy_http_chunked_enable(&r->req.chunked);
			continue;
		}
		if (memcmp(name_str, "Host", 4) == 0) {
			r->req.host = r->req.next;
		}

		r->req.next = h2d_header_add(r->req.next, name_str,
				name_len, value_str, value_len);
	}

	return buf_pos - buffer;
}

static bool h2d_http1_response_is_chunked(struct h2d_request *r)
{
	if (r->req.version == 0) {
		return false;
	}
	return r->resp.is_body_filtered || (r->resp.content_length == H2D_CONTENT_LENGTH_INIT);
}
int h2d_http1_response_headers(struct h2d_request *r)
{
	int estimate_size = (char *)r->resp.next - (char *)r->resp.buffer + 100; // TODO
	int ret = h2d_connection_make_space(r->c, estimate_size);
	if (ret < 0) {
		return ret;
	}

	/* response status line */
	char *p = (char *)r->c->send_buf_pos;
	p += sprintf(p, "HTTP/1.1 %d %s\r\n", r->resp.status_code,
			wuy_http_string_status_code(r->resp.status_code));

	if (h2d_http1_response_is_chunked(r)) {
		p += sprintf(p, "Transfer-Encoding: chunked\r\n");
	} else if (r->resp.content_length != H2D_CONTENT_LENGTH_INIT) {
		p += sprintf(p, "Content-Length: %ld\r\n", r->resp.content_length);
	}

	struct h2d_header *h;
	for (h = r->resp.buffer; h->name_len != 0; h = h2d_header_next(h)) {
		p += sprintf(p, "%s: %s\r\n", h->str, h2d_header_value(h));
	}
	p += sprintf(p, "\r\n");

	r->c->send_buf_pos = (uint8_t *)p;

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
	*p_buf_len -= H2D_CHUNKED_PREFIX_LENGTH + 5;
}
int h2d_http1_response_body_pack(struct h2d_request *r, uint8_t *payload,
		int length, bool is_body_finished)
{
	if (!h2d_http1_response_is_chunked(r)) {
		return length;
	}

	sprintf((char *)payload - H2D_CHUNKED_PREFIX_LENGTH, "%-8x\r", length);
	payload[-1] = '\n';

	if (length != 0 && is_body_finished) {
		memcpy(payload + length, "\r\n0\r\n", 5);
		return length + H2D_CHUNKED_PREFIX_LENGTH + 5;
	} else {
		memcpy(payload + length, "\r\n", 2);
		return length + H2D_CHUNKED_PREFIX_LENGTH + 2;
	}
}

void h2d_http1_on_writable(struct h2d_connection *c)
{
	struct h2d_request *r = c->u.request;
	if (r == NULL) {
		return;
	}
	h2d_request_run(r, -1);
}

int h2d_http1_on_read(struct h2d_connection *c, void *data, int buf_len)
{
	if (c->u.request == NULL) {
		c->u.request = h2d_request_new(c);
	}

	struct h2d_request *r = c->u.request;

	uint8_t *body_buf = data;
	int body_len = buf_len;

	/* parse request headers */
	if (r->state == H2D_REQUEST_STATE_PARSE_HEADERS) {
		int proc_len = h2d_http1_request_headers(r, data, buf_len);
		if (proc_len < 0) {
			return proc_len;
		}
		if (r->state == H2D_REQUEST_STATE_PARSE_HEADERS) {
			h2d_connection_set_recv_timer(c);
			return proc_len;
		}

		body_buf += proc_len;
		body_len -= proc_len;
	}

	/* save request body */
	if (body_len > 0) {
		if (r->req.body_buf == NULL) {
			r->req.body_buf = malloc(4096); // TODO
		}
		memcpy(r->req.body_buf + r->req.body_len, body_buf, body_len);
		r->req.body_len += body_len;

		if (r->req.content_length != H2D_CONTENT_LENGTH_INIT) {
			r->req.body_finished = r->req.body_len >= r->req.content_length;
		} else {
			r->req.body_finished = wuy_http_chunked_is_finished(&r->req.chunked);
		}
	}

	/* run */
	h2d_request_run(r, -1);

	if (!c->closed && c->u.request != NULL && r->state <= H2D_REQUEST_STATE_PROCESS_BODY) {
		h2d_connection_set_recv_timer(c);
	}

	return buf_len;
}

void h2d_http1_request_close(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;
	assert(c->u.request == r);

	if (r->state != H2D_REQUEST_STATE_DONE || r->req.version == 0) {
		h2d_connection_close(c);
	} else {
		c->u.request = NULL;
		h2d_connection_set_idle(c, c->conf_listen->http1.keepalive_timeout);
	}
}
