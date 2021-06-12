#include "h2d_main.h"

static WUY_LIST(h2d_request_defer_run_list);

static struct h2d_request *H2D_REQUEST_DETACHED_SUBR_FATHER = (struct h2d_request *)(-1L);

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
	r->resp.content_length = H2D_CONTENT_LENGTH_INIT;

	r->id = c->request_id++;
	r->c = c;
	r->pool = pool;

	r->conf_host = r->c->conf_listen->default_host;
	r->conf_path = r->conf_host->default_path;

	h2d_request_log(r, H2D_LOG_DEBUG, "new request");

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

static void h2d_request_clear_stuff(struct h2d_request *r)
{
	wuy_list_del_if(&r->list_node);

	h2d_lua_thread_kill(r);

	h2d_module_request_ctx_free(r);
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

	struct h2d_conf_access_log *log = r->conf_path->access_log;

	if (log->sampling_rate == 0) {
		return;
	}

	if (wuy_cflua_is_function_set(log->filter)) {
		if (!h2d_lua_call_boolean(r, log->filter)) {
			return;
		}
	}

	if (log->sampling_rate < 1.0 && !wuy_rand_sample(log->sampling_rate)) {
		return;
	}

	const char *format = "-";
	if (wuy_cflua_is_function_set(log->format)) {
		const char *format = h2d_lua_call_lstring(r, log->format, NULL);
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
	/* detached subrequest: just close it */
	if (r->father == H2D_REQUEST_DETACHED_SUBR_FATHER) {
		h2d_request_log(r, H2D_LOG_DEBUG, "close detached subr: %p", r);
		h2d_request_subr_close(r);
		return;
	}
	/* normal subrequest: wake up father, and should be closed by father later */
	if (r->father != NULL) {
		h2d_request_log(r, H2D_LOG_DEBUG, "subr wake up father: %p -> %p", r, r->father);
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

	if (r->h2s != NULL) { /* HTTP/2 */
		h2d_http2_request_close(r);
	} else { /* HTTP/1.x */
		h2d_http1_request_close(r);
	}

	h2d_request_clear_stuff(r);
	wuy_pool_destroy(r->pool); // TODO use defer
}

void h2d_request_subr_close(struct h2d_request *r)
{
	h2d_request_log(r, H2D_LOG_DEBUG, "subr done: %s", r->req.uri.raw);

	struct h2d_connection *c = r->c;
	wuy_list_del_if(&c->list_node);
	free(c->send_buffer);
	free(c);

	h2d_request_clear_stuff(r);
	wuy_pool_destroy(r->pool);
}

int h2d_request_redirect(struct h2d_request *r, const char *path)
{
	if (r->redirects++ > 10) {
		h2d_request_log(r, H2D_LOG_ERROR, "too many redirect");
		return H2D_ERROR;
	}

	switch (path[0]) {
	case '@':
		r->named_path = path;
		break;
	case '/':
		h2d_request_set_uri(r, path, strlen(path));
		break;
	default:
		h2d_request_log(r, H2D_LOG_ERROR, "invalid redirect: %s", path);
		return H2D_ERROR;
	}

	h2d_request_log(r, H2D_LOG_DEBUG, "redirect %s", path);

	h2d_request_access_log(r);

	h2d_request_reset_response(r);
	h2d_request_clear_stuff(r);

	r->conf_path = NULL;
	r->state = H2D_REQUEST_STATE_RECEIVE_HEADERS;
	r->filter_indexs[0] = r->filter_indexs[1] = r->filter_indexs[2] = 0;
	r->filter_terminal = NULL;
	r->is_broken = false;

	return H2D_BREAK;
}

bool h2d_request_set_host(struct h2d_request *r, const char *host_str, int host_len)
{
	if (r->req.host != NULL) {
		if (strncasecmp(r->req.host, host_str, host_len) != 0) {
			return false;
		}
		return true;
	}

	char *host = wuy_pool_strndup(r->pool, host_str, host_len);

	for (int i = 0; host[i] != '\0'; i++) {
		host[i] = tolower(host[i]);
	}
	r->req.host = host;
	return true;
}

bool h2d_request_set_uri(struct h2d_request *r, const char *uri_str, int uri_len)
{
	r->req.uri.raw = wuy_pool_strndup(r->pool, uri_str, uri_len);

	/* parse uri into host:path:query */
	const char *host, *fragment;
	int path_len = wuy_http_uri(r->req.uri.raw, uri_len, &host,
			&r->req.uri.path_pos, &r->req.uri.query_pos, &fragment);
	if (path_len < 0) {
		h2d_request_log(r, H2D_LOG_INFO, "invalid request URI");
		return false;
	}

	r->req.uri.path_len = path_len;

	if (r->req.uri.query_pos != NULL) {
		const char *query_end = fragment != NULL ? fragment : r->req.uri.raw+uri_len;
		r->req.uri.query_len = query_end - r->req.uri.query_pos;
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

int h2d_request_append_body(struct h2d_request *r, const void *buf, int len)
{
	if (len == 0) {
		return H2D_OK;
	}

	if (r->req.content_length != H2D_CONTENT_LENGTH_INIT) {
		if (r->req.body_len + len > r->req.content_length) {
			return WUY_HTTP_400;
		}
		if (r->req.body_buf == NULL) {
			r->req.body_buf = wuy_pool_alloc(r->pool, r->req.content_length);
		}
		memcpy(r->req.body_buf + r->req.body_len, buf, len);
		r->req.body_len += len;

		r->req.body_finished = r->req.body_len >= r->req.content_length;

	} else {
		int req_body_max = r->conf_path->req_body_max;
		if (req_body_max != 0 && r->req.body_len + len > req_body_max) {
			return WUY_HTTP_413;
		}
		r->req.body_buf = wuy_pool_realloc(r->pool, r->req.body_buf, r->req.body_len + len);
		memcpy(r->req.body_buf + r->req.body_len, buf, len);
		r->req.body_len += len;
	}
	return H2D_OK;
}

static int h2d_request_receive_headers(struct h2d_request *r)
{
	if (r->c->is_http2) {
		return H2D_AGAIN;
	}
	return h2d_http1_request_headers(r);
}

static int h2d_request_receive_body_sync(struct h2d_request *r)
{
	if (!r->conf_path->req_body_sync) {
		return H2D_OK;
	}

	if (r->c->is_http2) {
		return r->req.body_finished ? H2D_OK : H2D_AGAIN;
	}
	return h2d_http1_request_body(r);
}

static int h2d_request_locate_conf_host(struct h2d_request *r)
{
	if (r->conf_host != r->c->conf_listen->default_host) {
		/* subrequests and redirected requests' conf_host has been set */
		return H2D_OK;
	}

	r->conf_host = h2d_conf_host_locate(r->c->conf_listen, r->req.host);
	if (r->conf_host == NULL) {
		h2d_request_log(r, H2D_LOG_INFO, "no host matched: %s", r->req.host);
		return H2D_ERROR;
	}

	r->conf_path = r->conf_host->default_path;

	if (r->c->ssl_sni_conf_host != NULL && r->conf_host != r->c->ssl_sni_conf_host) {
		h2d_request_log(r, H2D_LOG_DEBUG, "wanring: ssl_sni_conf_host not match");
	}
	return H2D_OK;
}

static int h2d_request_locate_conf_path(struct h2d_request *r)
{
	if (r->conf_path != r->conf_host->default_path) {
		goto dynamic_get;
	}

	const char *uri_path = r->named_path ? r->named_path : r->req.uri.path;
	if (uri_path == NULL) {
		h2d_request_log(r, H2D_LOG_INFO, "no request path");
		return H2D_ERROR;
	}
	r->conf_path = h2d_conf_path_locate(r->conf_host, uri_path);
	if (r->conf_path == NULL) {
		r->conf_path = r->conf_host->default_path;
		h2d_request_log(r, H2D_LOG_DEBUG, "no path matched: %s", uri_path);
		return WUY_HTTP_404;
	}

dynamic_get:
	while (h2d_dynamic_is_enabled(&r->conf_path->dynamic)) {
		h2d_request_log(r, H2D_LOG_DEBUG, "get dynamic sub_path");
		struct h2d_conf_path *sub_path = h2d_dynamic_get(&r->conf_path->dynamic, r);
		if (!H2D_PTR_IS_OK(sub_path)) {
			return H2D_PTR2RET(sub_path);
		}
		r->conf_path = sub_path;
	}

	/* check some path-confs */
	if (r->conf_path->req_body_max != 0
			&& r->req.content_length != H2D_CONTENT_LENGTH_INIT
			&& r->req.content_length > r->conf_path->req_body_max) {
		return WUY_HTTP_413;
	}
	return H2D_OK;
}

static int h2d_request_process_headers(struct h2d_request *r)
{
	int ret = h2d_module_filter_process_headers(r);
	if (ret != H2D_OK) {
		return ret;
	}

	if (r->conf_path->content->content.process_headers == NULL) {
		return H2D_OK;
	}
	return r->conf_path->content->content.process_headers(r);
}

static int h2d_request_process_body(struct h2d_request *r) // TODO!!!
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

	} else if (r->resp.break_body_len == 0 && r->resp.break_body_func == NULL) {
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
	if (r->father != NULL) {
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

	uint8_t *buf_pos = c->send_buffer + c->send_buf_len;

	if (c->is_http2) {
		h2d_http2_response_body_packfix(r, &buf_pos, &buf_len);

		int window = http2_stream_window(r->h2s);
		if (window == 0) {
			return H2D_AGAIN;
		}
		if (window < buf_len) {
			buf_len = window;
		}
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

	} else if (r->resp.break_body_len > 0) {
		body_len = r->resp.break_body_len - r->resp.content_generated_length;
		if (body_len > buf_len) {
			body_len = buf_len;
		}
		memcpy(buf_pos, r->resp.break_body_buf + r->resp.content_generated_length, body_len);

	} else if (r->resp.break_body_func != NULL) {
		body_len = r->resp.break_body_func(r, buf_pos, buf_len);

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
	c->send_buf_len += body_len;

	return is_last ? H2D_OK : h2d_request_response_body(r);
}

void h2d_request_run(struct h2d_request *r)
{
	if (r->closed) {
		return;
	}

	h2d_request_log(r, H2D_LOG_DEBUG, "{{{ h2d_request_run %d", r->state);

	int ret;
	switch (r->state) {
	case H2D_REQUEST_STATE_RECEIVE_HEADERS:
		ret = h2d_request_receive_headers(r);
		break;
	case H2D_REQUEST_STATE_LOCATE_CONF_HOST:
		ret = h2d_request_locate_conf_host(r);
		break;
	case H2D_REQUEST_STATE_LOCATE_CONF_PATH:
		ret = h2d_request_locate_conf_path(r);
		break;
	case H2D_REQUEST_STATE_RECEIVE_BODY_SYNC:
		ret = h2d_request_receive_body_sync(r);
		break;
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

	h2d_request_log(r, H2D_LOG_DEBUG, "}}} state:%d ret:%d", r->state, ret);

	if (ret == H2D_OK || ret == H2D_BREAK) {
		r->state++; /* next step */
		return h2d_request_run(r);
	}

	if (ret == H2D_AGAIN) {
		return;
	}

	if (ret == H2D_ERROR) {
		if (r->resp.status_code != 0) {
			ret = r->resp.status_code;
		} else if (r->state <= H2D_REQUEST_STATE_RESPONSE_HEADERS_1) {
			ret = WUY_HTTP_500;
		} else {
			h2d_request_close(r);
			return;
		}
	}

	/* returns status code and breaks the normal process */
	r->is_broken = true;
	r->resp.status_code = ret;
	r->state = H2D_REQUEST_STATE_RESPONSE_HEADERS_1;
	return h2d_request_run(r);
}

void h2d_request_active(struct h2d_request *r, const char *from)
{
	struct h2d_connection *c = r->c;
	if (!h2d_connection_is_write_ready(c)) {
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

struct h2d_request *h2d_request_subr_new(struct h2d_request *father, const char *uri)
{
	struct h2d_connection *c = calloc(1, sizeof(struct h2d_connection));
	c->conf_listen = father->c->conf_listen;

	struct h2d_request *subr = h2d_request_new(c);
	subr->req.host = wuy_pool_strdup(subr->pool, father->req.host);
	subr->conf_host = father->conf_host;
	subr->state = H2D_REQUEST_STATE_PROCESS_HEADERS;
	subr->father = father;

	c->u.request = subr; /* HTTP/1 only */

	/* set request */
	subr->req.method = WUY_HTTP_GET;

	switch (uri[0]) {
	case '@':
		subr->req.uri = father->req.uri;
		subr->named_path = uri;
		break;
	case '/':
		h2d_request_set_uri(subr, uri, strlen(uri));
		break;
	default:
		h2d_request_subr_close(subr);
		h2d_request_log(father, H2D_LOG_ERROR, "subr invalid uri %s", uri);
		return NULL;
	}

	h2d_request_log(father, H2D_LOG_DEBUG, "new subr %p -> %p", father, subr);

	h2d_request_active(subr, "new subrequest");
	return subr;
}

void h2d_request_subr_detach(struct h2d_request *subr)
{
	subr->father = H2D_REQUEST_DETACHED_SUBR_FATHER;
}

int h2d_request_subr_flush_connection(struct h2d_connection *c)
{
	struct h2d_request *subr = c->u.request;
	struct h2d_request *father = subr->father;

	/* drop response for detached subrequests */
	if (father == H2D_REQUEST_DETACHED_SUBR_FATHER) {
		c->send_buf_len = 0;
		return H2D_OK;
	}

	h2d_request_active(father, "subr response");
	return H2D_AGAIN;
}

static void h2d_request_defer_run(void *data)
{
	struct h2d_request *r;
	while (wuy_list_pop_type(&h2d_request_defer_run_list, r, list_node)) {
		h2d_request_run(r);
	}
}

void h2d_request_init(void)
{
	loop_defer_add(h2d_loop, h2d_request_defer_run, NULL);
}
