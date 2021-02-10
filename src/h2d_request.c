#include "h2d_main.h"

static WUY_LIST(h2d_request_defer_run_list);

struct h2d_request *h2d_request_new(struct h2d_connection *c)
{
	wuy_pool_t *pool = wuy_pool_new(4096);

	struct h2d_request *r = wuy_pool_alloc(pool, sizeof(struct h2d_request)
			+ sizeof(void *) * h2d_module_number);
	if (r == NULL) {
		return NULL;
	}

	r->create_time = wuy_time_ms();

	wuy_slist_init(&r->req.headers);
	wuy_slist_init(&r->resp.headers);
	wuy_list_init(&r->subr_head);
	r->resp.content_length = H2D_CONTENT_LENGTH_INIT;

	r->c = c;
	r->pool = pool;
	return r;
}

void h2d_request_reset_response(struct h2d_request *r)
{
	if (r->resp.status_code == 0) {
		return;
	}

	h2d_request_log(r, H2D_LOG_DEBUG, "reset response code=%d", r->resp.status_code);

	r->resp.status_code = 0;
	r->resp.content_generated_length = 0;
	r->resp.sent_length = 0;
	r->resp.content_length = H2D_CONTENT_LENGTH_INIT;
	wuy_slist_init(&r->resp.headers);
}

static void h2d_request_stats(struct h2d_request *r)
{
	/* count */
	if (r->conf_host == NULL) {
		atomic_fetch_add(&r->c->conf_listen->stats->fail_no_host, 1);
		return;
	}
	if (r->conf_path == NULL) {
		atomic_fetch_add(&r->conf_host->stats->fail_no_path, 1);
		return;
	}

	struct h2d_conf_path_stats *stats = r->conf_path->stats;

	atomic_fetch_add(&stats->total, 1);
	if (r->state == H2D_REQUEST_STATE_DONE) {
		atomic_fetch_add(&stats->done, 1);

		/* time */
		long close_time = wuy_time_ms();
		atomic_fetch_add(&stats->req_acc_ms, r->req_end_time - r->create_time);
		atomic_fetch_add(&stats->react_acc_ms, r->resp_begin_time - r->req_end_time);
		atomic_fetch_add(&stats->resp_acc_ms, close_time - r->resp_begin_time);
		atomic_fetch_add(&stats->total_acc_ms, close_time - r->create_time);
	}

	/* status code */
	switch (r->resp.status_code) {
#define X(s, _) case s: atomic_fetch_add(&stats->status_##s, 1); break;
	WUY_HTTP_STATUS_CODE_TABLE
#undef X
	default:
		h2d_request_log(r, H2D_LOG_ERROR, "unknown status code %d", r->resp.status_code);
		atomic_fetch_add(&stats->status_others, 1);
	}
}

static void h2d_request_access_log(struct h2d_request *r)
{
	if (r->conf_path == NULL) {
		return;
	}

	struct h2d_conf_access_log *log = &r->conf_path->access_log;

	if (log->sampling_rate == 0) {
		return;
	}

	if (wuy_cflua_is_function_set(log->filter)) {
		if (!h2d_lua_api_call_boolean(r, log->filter)) {
			return;
		}
	}

	if (log->sampling_rate < 1.0 && !wuy_rand_sample(log->sampling_rate)) {
		return;
	}

	const char *format = "-";
	if (wuy_cflua_is_function_set(log->format)) {
		const char *format = h2d_lua_api_call_lstring(r, log->format, NULL);
		if (format == NULL) {
			format = "-";

		} else if (log->replace_format) {
			h2d_log_file_write(log->file, log->max_line, "%s", format);
		}
	}

#define H2D_DIFF(a, b) (a != 0) ? a - b : -1
#define H2D_DIFF2(a, b) (b != 0) ? a - b : -1
	long close_time = wuy_time_ms();
	h2d_log_file_write(log->file, log->max_line, "%s %s %d %lu %d %ld %ld %ld %ld %s",
			r->req.host ? r->req.host : "-",
			r->req.uri.raw,
			r->resp.status_code,
			r->resp.sent_length,
			r->state,
			H2D_DIFF(r->req_end_time, r->create_time),
			H2D_DIFF(r->resp_begin_time, r->req_end_time),
			H2D_DIFF2(close_time, r->resp_begin_time),
			close_time - r->create_time,
			format);
}

void h2d_request_close(struct h2d_request *r)
{
	if (h2d_request_is_subreq(r) && !r->father->closed) {
		/* father should close me */
		h2d_request_log(r, H2D_LOG_DEBUG, "sub wake up father: %p -> %p", r, r->father);
		h2d_request_active(r->father, "finished subrequest");
		return;
	}

	if (r->closed) {
		return;
	}
	r->closed = true;

	h2d_request_log(r, H2D_LOG_DEBUG, "request done: %s", r->req.uri.raw);

	h2d_request_access_log(r);
	h2d_request_stats(r);

	if (!wuy_list_empty(&r->subr_head)) {
		h2d_request_log(r, H2D_LOG_DEBUG, "!!!!!!!!! subruest %p", r);
	}

	if (r->h2s != NULL) { /* HTTP/2 */
		h2d_http2_request_close(r);
	} else { /* HTTP/1.x */
		h2d_http1_request_close(r);
	}

	wuy_list_del_if(&r->list_node);

	h2d_module_request_ctx_free(r);

	h2d_dynamic_ctx_free(r);

	wuy_pool_release(r->pool);
}

bool h2d_request_set_host(struct h2d_request *r, const char *host_str, int host_len)
{
	if (r->req.host != NULL) {
		if (strncasecmp(r->req.host, host_str, host_len) != 0) {
			return false;
		}
		return true;
	}

	r->req.host = wuy_pool_strndup(r->pool, host_str, host_len);
	// TODO set lower case
	return true;
}

bool h2d_request_set_uri(struct h2d_request *r, const char *uri_str, int uri_len)
{
	r->req.uri.raw = wuy_pool_strndup(r->pool, uri_str, uri_len);

	/* parse uri into host:path:query:fragment */
	const char *host, *fragment;
	int path_len = wuy_http_uri(r->req.uri.raw, uri_len, &host,
			&r->req.uri.path_pos, &r->req.uri.query_pos, &fragment);
	if (path_len < 0) {
		h2d_request_log(r, H2D_LOG_INFO, "invalid request URI");
		return false;
	}

	r->req.uri.path_len = path_len;

	if (r->req.uri.query_pos != NULL) {
		r->req.uri.query_len = (fragment ? fragment : r->req.uri.raw+uri_len)
				- r->req.uri.query_pos;
	}

	if (host != NULL) {
		if (!h2d_request_set_host(r, host, r->req.uri.path_pos - host)) {
			return false;
		}
	}

	/* decode path */
	char *decode = wuy_pool_alloc_align(r->pool, path_len + 1, 1);
	path_len = wuy_http_decode_path(decode, r->req.uri.path_pos, path_len);
	if (path_len < 0) {
		h2d_request_log(r, H2D_LOG_INFO, "invalid request URI path");
		return false;
	}

	r->req.uri.path = decode;
	return true;
}

static int h2d_request_process_headers(struct h2d_request *r)
{
	/* locate host */
	if (r->conf_host == NULL) {
		r->conf_host = h2d_conf_host_locate(r->c->conf_listen, r->req.host);
		if (r->conf_host == NULL) {
			h2d_request_log(r, H2D_LOG_INFO, "no host matched: %s", r->req.host);
			return H2D_ERROR;
		}
		if (r->c->ssl_sni_conf_host != NULL && r->conf_host != r->c->ssl_sni_conf_host) {
			h2d_request_log(r, H2D_LOG_DEBUG, "wanring: ssl_sni_conf_host not match");
		}
	}

	/* locate path */
	if (r->conf_path == NULL) {
		if (r->req.uri.raw == NULL) {
			h2d_request_log(r, H2D_LOG_INFO, "no request path");
			return H2D_ERROR;
		}
		r->conf_path = h2d_conf_path_locate(r->conf_host, r->req.uri.path);
		if (r->conf_path == NULL) {
			r->conf_path = r->conf_host->default_path;
			h2d_request_log(r, H2D_LOG_DEBUG, "no path matched: %s", r->req.uri.raw);
			return WUY_HTTP_404;
		}
		while (h2d_dynamic_is_enabled(&r->conf_path->dynamic)) {
			struct h2d_conf_path *sub_path = h2d_dynamic_get(&r->conf_path->dynamic, r);
			if (sub_path == NULL) {
				h2d_request_log(r, H2D_LOG_DEBUG, "get dynamic sub_path %d", r->resp.status_code);
				return r->resp.status_code != 0 ? r->resp.status_code : H2D_AGAIN;
			}
			h2d_request_log(r, H2D_LOG_DEBUG, "get dynamic sub_path OK: %s", sub_path->dynamic.name);
			r->conf_path = sub_path;
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
	"<html>\n" \
	"<head><title>%d %s</title></head>\n" \
	"<body>\n" \
	"<h1>%d %s</h1>\n" \
	"<hr><p><em>by h2tpd</em></p>\n" \
	"</body>\n" \
	"</html>\n"

	if (code < WUY_HTTP_400) {
		return 0;
	}
	const char *str = wuy_http_string_status_code(code);
	return snprintf(buf, len, H2D_STATUS_CODE_RESPONSE_BODY_FORMAT,
			code, str, code, str);
}

static int h2d_request_response_headers_1(struct h2d_request *r)
{
	if (r->req_end_time == 0) {
		r->req_end_time = wuy_time_ms();
	}

	int ret = H2D_OK;
	if (!r->is_broken) {
		ret = r->conf_path->content->content.response_headers(r);

	} else if (r->filter_terminal && r->filter_terminal->filters.content_headers != NULL) {
		ret = r->filter_terminal->filters.content_headers(r);
	} else {
		r->resp.content_length = h2d_request_simple_response_body(r->resp.status_code, NULL, 0);
	}

	r->resp.content_original_length = r->resp.content_length;

	return ret;
}

static int h2d_request_response_headers_2(struct h2d_request *r)
{
	return h2d_module_filter_response_headers(r);
}

static int h2d_request_response_headers_3(struct h2d_request *r)
{
	if (h2d_request_is_subreq(r)) {
		/* subruest does not send response headers out */
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
	if (r->resp_begin_time == 0) {
		r->resp_begin_time = wuy_time_ms();
	}

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
	bool is_last = true;

	/* generate */
	if (r->resp.content_generated_length >= r->resp.content_original_length) {
		goto skip_generate;
	}
	if (!r->is_broken) {
		body_len = r->conf_path->content->content.response_body(r, buf_pos, buf_len);

	} else if (r->filter_terminal && r->filter_terminal->filters.content_body != NULL) {
		body_len = r->filter_terminal->filters.content_body(r, buf_pos, buf_len);
	} else {
		body_len = h2d_request_simple_response_body(r->resp.status_code, (char *)buf_pos, buf_len);
	}

	if (body_len < 0) {
		return body_len;
	}

	r->resp.content_generated_length += body_len;

	if (r->resp.content_original_length != H2D_CONTENT_LENGTH_INIT) {
		is_last = r->resp.content_generated_length >= r->resp.content_original_length;
	} else {
		is_last = body_len == 0;
	}

skip_generate:

	/* filter */
	body_len = h2d_module_filter_response_body(r, buf_pos, body_len, buf_len, &is_last);
	if (body_len < 0) {
		return body_len;
	}

	/* pack, HTTP2 frame or HTTP1 chunked */
	if (c->is_http2) {
		body_len = h2d_http2_response_body_pack(r, buf_pos, body_len, is_last);
	} else {
		body_len = h2d_http1_response_body_pack(r, buf_pos, body_len, is_last);
	}

	r->resp.sent_length += body_len;
	c->send_buf_pos += body_len;

	return is_last ? H2D_OK : h2d_request_response_body(r);
}

void h2d_request_run(struct h2d_request *r, int window)
{
	if (r->closed) {
		return;
	}

	h2d_request_log(r, H2D_LOG_DEBUG, "{{{ h2d_request_run %d %p %s", r->state, r, r->req.uri.raw);

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
	case H2D_REQUEST_STATE_RESPONSE_HEADERS_1:
		ret = h2d_request_response_headers_1(r);
		break;
	case H2D_REQUEST_STATE_RESPONSE_HEADERS_2:
		ret = h2d_request_response_headers_2(r);
		break;
	case H2D_REQUEST_STATE_RESPONSE_HEADERS_3:
		ret = h2d_request_response_headers_3(r);
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

	h2d_request_log(r, H2D_LOG_DEBUG, "}}} %p: state:%d ret:%d", r, r->state, ret);

	if (ret == H2D_AGAIN) {
		return;
	}
	if (ret == H2D_ERROR) {
		if (r->state == H2D_REQUEST_STATE_PARSE_HEADERS) { // XXX reset the request??
			ret = H2D_OK;
		} else if (r->state <= H2D_REQUEST_STATE_RESPONSE_HEADERS_1) {
			h2d_request_log(r, H2D_LOG_ERROR, "should not be here");
			ret = WUY_HTTP_500;
		} else {
			h2d_request_close(r);
			return;
		}
	}
	if (ret != H2D_OK) { /* returns status code and breaks the normal process */
		r->is_broken = true;
		r->resp.status_code = ret;
		r->state = H2D_REQUEST_STATE_RESPONSE_HEADERS_1;
	} else {
		r->state++;
	}

	if (window == 0 && r->state >= H2D_REQUEST_STATE_RESPONSE_HEADERS_1) {
		return;
	}

	return h2d_request_run(r, window);
}

void h2d_request_active(struct h2d_request *r, const char *from)
{
	struct h2d_connection *c = r->c;
	if (h2d_connection_write_blocked(c)) {
		h2d_request_log(r, H2D_LOG_DEBUG, "======== h2d_request_active not ready"); // XXX coredump if get here 4times
		return;
	}

	// XXX timer -> epoll-block -> idle, so pending subrs will not run
	h2d_request_log(r, H2D_LOG_DEBUG, "active %s from %s", r->req.uri.raw, from);

	// TODO change to:   if (not linked) append;
	wuy_list_del_if(&r->list_node); // TODO need delete?
	wuy_list_append(&h2d_request_defer_run_list, &r->list_node);
}

void h2d_request_active_list(wuy_list_t *list, const char *from)
{
	struct h2d_request *r;
	while (wuy_list_pop_type(list, r, list_node)) {
		h2d_request_active(r, from);
	}
}

struct h2d_request *h2d_request_subrequest(struct h2d_request *father, const char *url)
{
	/* fake connection */
	struct h2d_connection *c = calloc(1, sizeof(struct h2d_connection));
	c->conf_listen = father->c->conf_listen;

	/* init subrequest */
	struct h2d_request *subr = h2d_request_new(c);
	subr->req.host = wuy_pool_strdup(subr->pool, father->req.host);
	subr->conf_host = father->conf_host;
	subr->state = H2D_REQUEST_STATE_PROCESS_HEADERS;
	subr->father = father;
	wuy_list_append(&father->subr_head, &subr->subr_node);

	c->u.request = subr;

	/* set subrequest */
	subr->req.method = WUY_HTTP_GET;
	h2d_request_set_uri(subr, url, strlen(url));

	h2d_request_log(father, H2D_LOG_DEBUG, "h2d_request_subrequest %p -> %p", father, subr);

	h2d_request_active(subr, "new subrequest");
	return subr;
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
	loop_defer_add(h2d_loop, h2d_request_defer_run, NULL);
}
