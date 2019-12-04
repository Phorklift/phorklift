#include "h2d_main.h"

static int h2d_http1_request_headers(struct h2d_request *r, const char *buffer, int buf_len)
{
	const char *buf_pos = buffer;

	/* request line */
	if (r->req.method == 0) {
		int url_len;
		const char *url_str;
		int proc_len = wuy_http_request_line(buf_pos, buf_len,
				&r->req.method, &url_str, &url_len, &r->req.method);
		if (proc_len < 0) {
			printf("invalid request line !!!!\n");
			return H2D_ERROR;
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
			h2d_request_process_headers(r);
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

int h2d_http1_response_headers(struct h2d_request *r)
{
	int estimate_size = (char *)r->resp.next - (char *)r->resp.buffer + 100; // TODO
	int ret = h2d_connection_make_space(r->c, estimate_size);
	if (ret != H2D_OK) {
		return ret;
	}

	/* response status line */
	char *p = (char *)r->c->send_buf_pos;
	p += sprintf(p, "HTTP/1.1 %d xxx\r\n", r->resp.status_code);

	if (r->resp.content_length == H2D_CONTENT_LENGTH_CHUNKED) {
		p += sprintf(p, "Transfer-Encoding: chunked\r\n");
	} else if (r->resp.content_length != H2D_CONTENT_LENGTH_INIT) {
		p += sprintf(p, "Content-Length: %ld\r\n", r->resp.content_length);
	}

	struct h2d_header *h;
	for (h = r->resp.buffer; h->name_len != 0; h = h2d_header_next(h)) {
		p += sprintf("%s: %s\r\n", h->str, h2d_header_value(h));
	}
	p += sprintf(p, "\r\n");

	r->c->send_buf_pos = (uint8_t *)p;

	return H2D_OK;
}

#define H2D_CHUNKED_PREFIX_LENGTH 10
void h2d_http1_response_body_packfix(struct h2d_request *r,
		uint8_t **p_buf_pos, int *p_buf_len)
{
	if (r->resp.content_length != H2D_CONTENT_LENGTH_CHUNKED) {
		return;
	}
	*p_buf_pos += H2D_CHUNKED_PREFIX_LENGTH;
	*p_buf_len -= H2D_CHUNKED_PREFIX_LENGTH + 5;
}
int h2d_http1_response_body_pack(struct h2d_request *r, uint8_t *payload,
		int length, bool is_body_finished)
{
	if (r->resp.content_length != H2D_CONTENT_LENGTH_CHUNKED) {
		return 0;
	}

	sprintf((char *)payload - H2D_CHUNKED_PREFIX_LENGTH, "%-8x\r", length);
	payload[-1] = '\n';

	if (is_body_finished) {
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

	h2d_request_response(r);
}

int h2d_http1_on_read(struct h2d_connection *c, void *data, int buf_len)
{
	if (c->u.request == NULL) {
		c->u.request = h2d_request_new(c);
	}

	struct h2d_request *r = c->u.request;

	if (r->state == H2D_REQUEST_STATE_PROCESS_HEADERS) {
		int proc_len = h2d_http1_request_headers(r, data, buf_len);
		if (proc_len < 0) {
			return proc_len;
		}
	}

	if (r->state == H2D_REQUEST_STATE_RESPONSE_HEADERS) { // TODO
		return buf_len;
	}

	h2d_request_response(r);

	//printf("TODO request %d %d\n", proc_len, buf_len);
	return buf_len;
}
