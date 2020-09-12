#include "h2d_main.h"

static WUY_LIST(h2d_request_defer_run_list);

static struct h2d_log *tmp_log;

struct h2d_request *h2d_request_new(struct h2d_connection *c)
{
	struct h2d_request *r = calloc(1, sizeof(struct h2d_request)
			+ sizeof(void *) * h2d_module_number);
	if (r == NULL) {
		return NULL;
	}

	wuy_slist_init(&r->req.headers);
	wuy_slist_init(&r->resp.headers);
	r->resp.content_length = H2D_CONTENT_LENGTH_INIT;

	r->c = c;
	return r;
}

void h2d_request_reset_response(struct h2d_request *r)
{
	if (r->resp.status_code == 0) {
		return;
	}
	r->resp.status_code = 0;
	r->resp.content_length = H2D_CONTENT_LENGTH_INIT;
	r->resp.content_generate_length = 0;
	r->resp.sent_length = 0;
	h2d_header_free_list(&r->resp.headers);
}

void h2d_request_close(struct h2d_request *r)
{
	if (h2d_request_is_subreq(r) && !r->father->closed) {
		/* father should close me */
		h2d_log_debug(tmp_log, "sub wake up father: %p -> %p", r, r->father);
		h2d_request_active(r->father);
		return;
	}

	if (r->closed) {
		return;
	}
	r->closed = true;

	h2d_log_debug(tmp_log, "request done: %s", r->req.url);

	if (r->subr != NULL) {
		h2d_log_debug(tmp_log, "!!!!!!!!! subrequest %p subr:%p", r, r->subr);
	}

	if (r->h2s != NULL) { /* HTTP/2 */
		h2d_http2_request_close(r);
	} else { /* HTTP/1.x */
		h2d_http1_request_close(r);
	}

	h2d_module_request_ctx_free(r);

	h2d_header_free_list(&r->req.headers);
	h2d_header_free_list(&r->resp.headers);
	free(r->req.body_buf);
	free(r);
}

static int h2d_request_process_headers(struct h2d_request *r)
{
	/* locate host */
	if (r->conf_host == NULL) {
		const char *host = NULL;
		struct h2d_header *h;
		h2d_header_iter(&r->req.headers, h) {
			if (strcmp(h->str, "Host") == 0) {
				r->req.host = h;
				host = h2d_header_value(h);
				break;
			}
		}

		r->conf_host = h2d_conf_listen_search_hostname(r->c->conf_listen, host);
		if (r->conf_host == NULL) {
			h2d_log_debug(tmp_log, "invalid host");
			return H2D_ERROR;
		}
		if (r->c->ssl_sni_conf_host != NULL && r->conf_host != r->c->ssl_sni_conf_host) {
			h2d_log_debug(tmp_log, "wanring: ssl_sni_conf_host not match");
		}
	}

	// h2d_request_log(r, H2D_LOG_DEBUG, "debug only");

	/* locate path */
	if (r->conf_path == NULL) {
		if (r->req.url == NULL) {
			h2d_log_debug(tmp_log, "no path");
			return H2D_ERROR;
		}
		r->conf_path = h2d_conf_host_search_pathname(r->conf_host, r->req.url);
		if (r->conf_path == NULL) {
			h2d_log_debug(tmp_log, "no path matched %s", r->req.url);
			// return WUY_HTTP_404;
			return H2D_ERROR;
		}
	}

	/* begin process */
	int ret = h2d_module_filter_process_headers(r);
	if (ret != H2D_OK) {
		return ret;
	}

	if (r->conf_path->content->content.process_headers == NULL) {
		return H2D_OK;
	}
	return r->conf_path->content->content.process_headers(r);
}

static int h2d_request_process_body(struct h2d_request *r)
{
	if (r->is_broken) { // TODO discard request body
		return H2D_OK;
	}
	if (r->req.content_length == H2D_CONTENT_LENGTH_INIT && !wuy_http_chunked_is_enabled(&r->req.chunked)) {
		return H2D_OK;
	}
	if (r->req.content_length == 0) {
		return H2D_OK;
	}

	if (!r->req.body_finished) {
		return H2D_AGAIN;
	}

	int ret = h2d_module_filter_process_body(r);
	if (ret != H2D_OK) {
		return ret;
	}

	if (r->conf_path->content->content.process_body == NULL) {
		return H2D_OK;
	}
	return r->conf_path->content->content.process_body(r);
}

static inline int h2d_request_simple_response_body(enum wuy_http_status_code code,
		char *buf, int len)
{
#define H2D_STATUS_CODE_RESPONSE_BODY_FORMAT \
	"<html>" \
	"<head><title>%d %s</title></head>" \
	"<body>" \
	"<h1>%d %s</h1>" \
	"<hr><p><em>by h2tpd</em></p>" \
	"</body>" \
	"</html>"

	if (code < WUY_HTTP_400) {
		return 0;
	}
	const char *str = wuy_http_string_status_code(code);
	return snprintf(buf, len, H2D_STATUS_CODE_RESPONSE_BODY_FORMAT,
			code, str, code, str);
}

static int h2d_request_response_headers(struct h2d_request *r)
{
	if (!r->is_broken) {
		int ret = r->conf_path->content->content.response_headers(r);
		if (ret != H2D_OK) {
			return ret;
		}
	} else if (r->resp.broken_body_len != 0) {
		r->resp.content_length = r->resp.broken_body_len;
	} else {
		r->resp.content_length = h2d_request_simple_response_body(r->resp.status_code, NULL, 0);
	}

	int ret = h2d_module_filter_response_headers(r);
	if (ret != H2D_OK) {
		return ret;
	}

	if (h2d_request_is_subreq(r)) {
		/* subrequest does not send response headers out */
		return H2D_OK;
	}

	if (r->c->is_http2) {
		return h2d_http2_response_headers(r);
	} else {
		return h2d_http1_response_headers(r);
	}
}

static int h2d_request_response_body(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;

	int buf_len = h2d_connection_make_space(c, 4096);
	if (buf_len < 0) {
		return buf_len;
	}

	uint8_t *buffer = c->send_buf_pos;
	uint8_t *buf_pos = buffer;

	if (c->is_http2) {
		h2d_http2_response_body_packfix(r, &buf_pos, &buf_len);
	} else {
		h2d_http1_response_body_packfix(r, &buf_pos, &buf_len);
	}

	int body_len = 0;
	bool is_body_finished = false;

	/* generate */
	if (r->resp.content_generate_length >= r->resp.content_length) {
		goto skip_generate;
	}
	if (!r->is_broken) {
		body_len = r->conf_path->content->content.response_body(r, buf_pos, buf_len);
	} else if (r->resp.broken_body_len != 0) {
		memcpy(buf_pos, r->resp.broken_body_buf, r->resp.broken_body_len);
		body_len = r->resp.broken_body_len;
	} else {
		body_len = h2d_request_simple_response_body(r->resp.status_code, (char *)buf_pos, buf_len);
	}

	if (body_len < 0) {
		return body_len;
	}

	r->resp.content_generate_length += body_len;

	/* This checking works only if @r->resp.content_length is set in
	 * content.response_headers() when the response body's length is explicit.
	 * Otherwise (e.g. in chunked encoding) this checking is always false
	 * because @r->resp.content_length was inited as (SIZE_MAX-1). In this
	 * case content.response_body() and h2d_module_filter_response_body()
	 * need to return 0 to indicate @is_body_finished. */
	if (r->resp.content_generate_length >= r->resp.content_length) {
		is_body_finished = true;
	}

skip_generate:

	/* filter */
	body_len = h2d_module_filter_response_body(r, buf_pos, body_len, buf_len);
	if (body_len < 0) {
		return body_len;
	}
	if (body_len == 0) {
		is_body_finished = true;
	}

	/* pack, HTTP2 frame or HTTP1 chunked */
	if (c->is_http2) {
		body_len = h2d_http2_response_body_pack(r, buf_pos, body_len, is_body_finished);
	} else {
		body_len = h2d_http1_response_body_pack(r, buf_pos, body_len, is_body_finished);
	}

	r->resp.sent_length += body_len;
	c->send_buf_pos += body_len;

	return is_body_finished ? H2D_OK : h2d_request_response_body(r);
}

void h2d_request_run(struct h2d_request *r, int window)
{
	if (r->closed) {
		return;
	}

	h2d_log_debug(tmp_log, "{{{ h2d_request_run %d %p %s", r->state, r, r->req.url);

	int ret;
	switch (r->state) {
	case H2D_REQUEST_STATE_PARSE_HEADERS:
		return;
	case H2D_REQUEST_STATE_PROCESS_HEADERS:
		ret = h2d_request_process_headers(r);
		break;
	case H2D_REQUEST_STATE_PROCESS_BODY:
		ret = h2d_request_process_body(r);
		break;
	case H2D_REQUEST_STATE_RESPONSE_HEADERS:
		ret = h2d_request_response_headers(r);
		break;
	case H2D_REQUEST_STATE_RESPONSE_BODY:
		ret = h2d_request_response_body(r);
		break;
	case H2D_REQUEST_STATE_DONE:
		h2d_request_close(r);
		return;
	default:
		abort();
	}

	h2d_log_debug(tmp_log, "}}} %p: state:%d ret:%d", r, r->state, ret);

	if (ret == H2D_AGAIN) {
		return;
	}
	if (ret == H2D_ERROR) {
		if (r->state <= H2D_REQUEST_STATE_RESPONSE_HEADERS) {
			h2d_log_error(tmp_log, "should not be here");
			ret = WUY_HTTP_500;
		} else {
			h2d_request_close(r);
			return;
		}
	}
	if (ret != H2D_OK) { /* returns status code and breaks the normal process */
		r->resp.status_code = ret;
		r->is_broken = true;
		r->state = H2D_REQUEST_STATE_RESPONSE_HEADERS;
	} else {
		r->state++;
	}

	if (window == 0 && r->state >= H2D_REQUEST_STATE_RESPONSE_HEADERS) {
		return;
	}

	return h2d_request_run(r, window);
}

void http2_stream_active_tmp(http2_stream_t *s);
void h2d_request_active(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;
	if (h2d_connection_write_blocked(c)) {
		h2d_log_debug(tmp_log, "======== h2d_request_active"); // XXX coredump if get here 4times
		if (c->is_http2) {
			http2_stream_active_tmp(r->h2s);
		}
		return;
	}

	// XXX timer -> epoll-block -> idle, so pending subreqs will not run
	h2d_log_debug(tmp_log, "active %s", r->req.url);

	// TODO change to:   if (not linked) append;
	wuy_list_del_if(&r->list_node); // TODO need delete?
	wuy_list_append(&h2d_request_defer_run_list, &r->list_node);
}

struct h2d_request *h2d_request_subreq_new(struct h2d_request *father)
{
	/* fake connection */
	struct h2d_connection *c = calloc(1, sizeof(struct h2d_connection));
	c->conf_listen = father->c->conf_listen;

	/* subrequest */
	struct h2d_request *subreq = h2d_request_new(c);
	subreq->conf_host = father->conf_host;
	subreq->state = H2D_REQUEST_STATE_PROCESS_HEADERS;
	subreq->father = father;
	father->subr = subreq;
	c->u.request = subreq;

	h2d_log_debug(tmp_log, "h2d_request_subreq_new %p -> %p", father, subreq);

	h2d_request_active(subreq);
	return subreq;
}

static void h2d_request_defer_run(void *data)
{
	struct h2d_request *r;
	while (wuy_list_pop_type(&h2d_request_defer_run_list, r, list_node)) {
		h2d_request_run(r, -1);
	}
}

void h2d_request_init(void)
{
	tmp_log = h2d_log_new("error.log", H2D_LOG_DEBUG);
	loop_idle_add(h2d_loop, h2d_request_defer_run, NULL);
}
