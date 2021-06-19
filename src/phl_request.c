#include "phl_main.h"

#define PHL_REQUEST_DETACHED_SUBR_FATHER (struct phl_request *)(-1L)

static WUY_LIST(phl_request_defer_list);

struct phl_request *phl_request_new(struct phl_connection *c)
{
	wuy_pool_t *pool = wuy_pool_new(4096);

	struct phl_request *r = wuy_pool_alloc(pool, sizeof(struct phl_request)
			+ sizeof(void *) * phl_module_number);
	if (r == NULL) {
		return NULL;
	}

	r->create_time = wuy_time_ms();

	wuy_list_init(&r->subr_head);
	wuy_slist_init(&r->req.headers);
	wuy_slist_init(&r->resp.headers);
	r->resp.content_length = PHL_CONTENT_LENGTH_INIT;

	r->id = c->request_id++;
	r->c = c;
	r->pool = pool;

	r->conf_host = r->c->conf_listen->default_host;
	r->conf_path = r->conf_host->default_path;

	phl_request_log(r, PHL_LOG_DEBUG, "new request");

	return r;
}

void phl_request_reset_response(struct phl_request *r)
{
	if (r->resp.status_code == 0) {
		return;
	}

	phl_request_log(r, PHL_LOG_DEBUG, "reset response code=%d", r->resp.status_code);

	r->resp.status_code = 0;
	r->resp.content_generated_length = 0;
	r->resp.sent_length = 0;
	r->resp.content_length = PHL_CONTENT_LENGTH_INIT;
	wuy_slist_init(&r->resp.headers);
}

static void phl_request_clear_stuff(struct phl_request *r)
{
	wuy_list_del_if(&r->list_node);

	phl_lua_thread_kill(r);

	phl_module_request_ctx_free(r);
}

static void phl_request_stats(struct phl_request *r)
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

	struct phl_conf_path_stats *stats = r->conf_path->stats;

	atomic_fetch_add(&stats->total, 1);
	if (r->state == PHL_REQUEST_STATE_DONE) {
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
		phl_request_log(r, PHL_LOG_ERROR, "unknown status code %d", r->resp.status_code);
		atomic_fetch_add(&stats->status_others, 1);
	}
}

static void phl_request_access_log(struct phl_request *r)
{
	struct phl_conf_access_log *log = r->conf_path->access_log;

	if (log->sampling_rate == 0) {
		return;
	}
	if (!log->enable_subrequest && r->father != NULL) {
		return;
	}

	if (wuy_cflua_is_function_set(log->filter)) {
		if (!phl_lua_call_boolean(r, log->filter)) {
			return;
		}
	}

	if (log->sampling_rate < 1.0 && !wuy_rand_sample(log->sampling_rate)) {
		return;
	}

	const char *format = "-";
	if (wuy_cflua_is_function_set(log->format)) {
		const char *format = phl_lua_call_lstring(r, log->format, NULL);
		if (format == NULL) {
			format = "-";

		} else if (log->replace_format) {
			phl_log_file_write(log->file, log->max_line, "%s", format);
		}
	}

#define PHL_DIFF(a, b) (a != 0) ? a - b : -1
#define PHL_DIFF2(a, b) (b != 0) ? a - b : -1
	long close_time = wuy_time_ms();
	phl_log_file_write(log->file, log->max_line, "%s %s %d %lu %d %ld %ld %ld %ld %s",
			r->req.host ? r->req.host : "-",
			r->req.uri.raw,
			r->resp.status_code,
			r->resp.sent_length,
			r->state,
			PHL_DIFF(r->req_end_time, r->create_time),
			PHL_DIFF(r->resp_begin_time, r->req_end_time),
			PHL_DIFF2(close_time, r->resp_begin_time),
			close_time - r->create_time,
			format);
}

static void phl_request_do_close(struct phl_request *r)
{
	phl_request_access_log(r);
	phl_request_stats(r);

	struct phl_request *subr;
	while (wuy_list_pop_type(&r->subr_head, subr, list_node)) {
		phl_request_subr_close(subr);
	}

	phl_request_clear_stuff(r);

	wuy_list_append(&phl_request_defer_list, &r->list_node);
}

void phl_request_close(struct phl_request *r)
{
	if (r->closed) {
		return;
	}
	r->closed = true;

	phl_request_log(r, PHL_LOG_DEBUG, "request done: %s", r->req.uri.raw);

	if (r->father != NULL) { /* subrequest */
		if (r->father == PHL_REQUEST_DETACHED_SUBR_FATHER) {
			phl_request_subr_close(r);
		} else { /* wake up father, and should be closed by father later */
			phl_request_run(r->father, "subrequest done");
		}
		return;
	}

	if (r->h2s != NULL) { /* HTTP/2 */
		phl_http2_request_close(r);
	} else { /* HTTP/1.x */
		phl_http1_request_close(r);
	}

	phl_request_do_close(r);
}

void phl_request_subr_close(struct phl_request *r)
{
	phl_request_log(r, PHL_LOG_DEBUG, "subr done: %s", r->req.uri.raw);

	struct phl_connection *c = r->c;
	wuy_list_del_if(&c->list_node);
	free(c->send_buffer);
	free(c);

	phl_request_do_close(r);
}

int phl_request_redirect(struct phl_request *r, const char *path)
{
	if (r->redirects++ > 10) {
		phl_request_log(r, PHL_LOG_ERROR, "too many redirect");
		return PHL_ERROR;
	}

	switch (path[0]) {
	case '@':
		r->named_path = path;
		break;
	case '/':
		phl_request_set_uri(r, path, strlen(path));
		break;
	default:
		phl_request_log(r, PHL_LOG_ERROR, "invalid redirect: %s", path);
		return PHL_ERROR;
	}

	phl_request_log(r, PHL_LOG_DEBUG, "redirect %s", path);

	phl_request_access_log(r);

	phl_request_reset_response(r);
	phl_request_clear_stuff(r);

	r->conf_path = NULL;
	r->state = PHL_REQUEST_STATE_RECEIVE_HEADERS;
	r->filter_indexs[0] = r->filter_indexs[1] = r->filter_indexs[2] = 0;
	r->filter_terminal = NULL;
	r->is_broken = false;

	return PHL_BREAK;
}

bool phl_request_set_host(struct phl_request *r, const char *host_str, int host_len)
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

bool phl_request_set_uri(struct phl_request *r, const char *uri_str, int uri_len)
{
	r->req.uri.raw = wuy_pool_strndup(r->pool, uri_str, uri_len);

	/* parse uri into host:path:query */
	const char *host, *fragment;
	int path_len = wuy_http_uri(r->req.uri.raw, uri_len, &host,
			&r->req.uri.path_pos, &r->req.uri.query_pos, &fragment);
	if (path_len < 0) {
		phl_request_log(r, PHL_LOG_INFO, "invalid request URI");
		return false;
	}

	r->req.uri.path_len = path_len;

	if (r->req.uri.query_pos != NULL) {
		const char *query_end = fragment != NULL ? fragment : r->req.uri.raw+uri_len;
		r->req.uri.query_len = query_end - r->req.uri.query_pos;
	}

	if (host != NULL) {
		if (!phl_request_set_host(r, host, r->req.uri.path_pos - host)) {
			return false;
		}
	}

	/* decode path */
	char *decode = wuy_pool_alloc_align(r->pool, path_len + 1, 1);
	path_len = wuy_http_decode_path(decode, r->req.uri.path_pos, path_len);
	if (path_len < 0) {
		phl_request_log(r, PHL_LOG_INFO, "invalid request URI path");
		return false;
	}

	r->req.uri.path = decode;
	return true;
}

int phl_request_append_body(struct phl_request *r, const void *buf, int len)
{
	if (len == 0) {
		return PHL_OK;
	}

	if (r->req.content_length != PHL_CONTENT_LENGTH_INIT) {
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
	return PHL_OK;
}

static int phl_request_receive_headers(struct phl_request *r)
{
	if (r->c->is_http2) {
		return PHL_AGAIN;
	}
	return phl_http1_request_headers(r);
}

static int phl_request_receive_body_sync(struct phl_request *r)
{
	if (!r->conf_path->req_body_sync) {
		return PHL_OK;
	}

	if (r->c->is_http2) {
		return r->req.body_finished ? PHL_OK : PHL_AGAIN;
	}
	return phl_http1_request_body(r);
}

static int phl_request_locate_conf_host(struct phl_request *r)
{
	if (r->conf_host != r->c->conf_listen->default_host) {
		/* subrequests and redirected requests' conf_host has been set */
		return PHL_OK;
	}

	r->conf_host = phl_conf_host_locate(r->c->conf_listen, r->req.host);
	if (r->conf_host == NULL) {
		phl_request_log(r, PHL_LOG_INFO, "no host matched: %s", r->req.host);
		return PHL_ERROR;
	}

	r->conf_path = r->conf_host->default_path;

	if (r->c->ssl_sni_conf_host != NULL && r->conf_host != r->c->ssl_sni_conf_host) {
		phl_request_log(r, PHL_LOG_DEBUG, "wanring: ssl_sni_conf_host not match");
	}
	return PHL_OK;
}

static int phl_request_locate_conf_path(struct phl_request *r)
{
	if (r->conf_path != r->conf_host->default_path) {
		goto dynamic_get;
	}

	const char *uri_path = r->named_path ? r->named_path : r->req.uri.path;
	if (uri_path == NULL) {
		phl_request_log(r, PHL_LOG_INFO, "no request path");
		return PHL_ERROR;
	}
	r->conf_path = phl_conf_path_locate(r->conf_host, uri_path);
	if (r->conf_path == NULL) {
		r->conf_path = r->conf_host->default_path;
		phl_request_log(r, PHL_LOG_DEBUG, "no path matched: %s", uri_path);
		return WUY_HTTP_404;
	}

dynamic_get:
	while (phl_dynamic_is_enabled(&r->conf_path->dynamic)) {
		phl_request_log(r, PHL_LOG_DEBUG, "get dynamic sub_path");
		struct phl_conf_path *sub_path = phl_dynamic_get(&r->conf_path->dynamic, r);
		if (!PHL_PTR_IS_OK(sub_path)) {
			return PHL_PTR2RET(sub_path);
		}
		r->conf_path = sub_path;
	}

	/* check some path-confs */
	if (r->conf_path->req_body_max != 0
			&& r->req.content_length != PHL_CONTENT_LENGTH_INIT
			&& r->req.content_length > r->conf_path->req_body_max) {
		return WUY_HTTP_413;
	}
	return PHL_OK;
}

static int phl_request_process_headers(struct phl_request *r)
{
	int ret = phl_module_filter_process_headers(r);
	if (ret != PHL_OK) {
		return ret;
	}

	if (r->conf_path->content->content.process_headers == NULL) {
		return PHL_OK;
	}
	return r->conf_path->content->content.process_headers(r);
}

static int phl_request_process_body(struct phl_request *r) // TODO!!!
{
	if (r->is_broken) { // TODO discard request body
		return PHL_OK;
	}
	if (r->req.content_length == PHL_CONTENT_LENGTH_INIT && !wuy_http_chunked_is_enabled(&r->req.chunked)) {
		return PHL_OK;
	}
	if (r->req.content_length == 0) {
		return PHL_OK;
	}

	int ret = phl_module_filter_process_body(r);
	if (ret != PHL_OK) {
		return ret;
	}

	if (r->conf_path->content->content.process_body == NULL) {
		return PHL_OK;
	}
	return r->conf_path->content->content.process_body(r);
}

static inline int phl_request_simple_response_body(enum wuy_http_status_code code,
		char *buf, int len)
{
#define PHL_STATUS_CODE_RESPONSE_BODY_FORMAT \
	"<html>\n" \
	"<head><title>%d %s</title></head>\n" \
	"<body>\n" \
	"<h1>%d %s</h1>\n" \
	"<hr><p><em>by phorklift</em></p>\n" \
	"</body>\n" \
	"</html>\n"

	if (code < WUY_HTTP_400) {
		return 0;
	}
	const char *str = wuy_http_string_status_code(code);
	return snprintf(buf, len, PHL_STATUS_CODE_RESPONSE_BODY_FORMAT,
			code, str, code, str);
}

static int phl_request_response_headers_1(struct phl_request *r)
{
	if (r->req_end_time == 0) {
		r->req_end_time = wuy_time_ms();
	}

	int ret = PHL_OK;
	if (!r->is_broken) {
		ret = r->conf_path->content->content.response_headers(r);

	} else if (r->resp.easy_str_len == 0 && r->resp.easy_fd == 0) {
		r->resp.content_length = phl_request_simple_response_body(r->resp.status_code, NULL, 0);
	}

	r->resp.content_original_length = r->resp.content_length;

	return ret;
}

static int phl_request_response_headers_2(struct phl_request *r)
{
	return phl_module_filter_response_headers(r);
}

static int phl_request_response_headers_3(struct phl_request *r)
{
	if (r->father != NULL) {
		/* subruest does not send response headers out */
		return PHL_OK;
	}
	if (r->c->is_http2) {
		return phl_http2_response_headers(r);
	} else {
		return phl_http1_response_headers(r);
	}
}

static int phl_request_response_body(struct phl_request *r)
{
	if (r->resp_begin_time == 0) {
		r->resp_begin_time = wuy_time_ms();
	}

	struct phl_connection *c = r->c;

	int buf_len = phl_connection_make_space(c, 4096);
	if (buf_len < 0) {
		return buf_len;
	}

	uint8_t *buf_pos = c->send_buffer + c->send_buf_len;

	if (c->is_http2) {
		phl_http2_response_body_packfix(r, &buf_pos, &buf_len);

		int window = http2_stream_window(r->h2s);
		if (window == 0) {
			return PHL_AGAIN;
		}
		if (window < buf_len) {
			buf_len = window;
		}
	} else {
		phl_http1_response_body_packfix(r, &buf_pos, &buf_len);
	}

	int body_len = 0;
	bool is_last = true;

	if (r->resp.content_generated_length >= r->resp.content_original_length) {
		goto skip_generate;
	}

	/* generate body */
	if (r->resp.easy_str_len > 0) {
		body_len = r->resp.easy_str_len - r->resp.content_generated_length;
		if (body_len > buf_len) {
			body_len = buf_len;
		}
		memcpy(buf_pos, r->resp.easy_string + r->resp.content_generated_length, body_len);

	} else if (r->resp.easy_fd != 0) {
		body_len = r->resp.content_length - r->resp.content_generated_length;
		if (body_len > buf_len) {
			body_len = buf_len;
		}
		body_len = read(r->resp.easy_fd, buf_pos, body_len);
		if (body_len < 0) {
			phl_request_log(r, PHL_LOG_ERROR, "read body_fd erro: %s", strerror(errno));
			body_len = PHL_ERROR;
		}

	} else if (!r->is_broken) {
		body_len = r->conf_path->content->content.response_body(r, buf_pos, buf_len);

	} else {
		body_len = phl_request_simple_response_body(r->resp.status_code, (char *)buf_pos, buf_len);
	}

	if (body_len < 0) {
		return body_len;
	}

	r->resp.content_generated_length += body_len;

	if (r->resp.content_original_length != PHL_CONTENT_LENGTH_INIT) {
		is_last = r->resp.content_generated_length >= r->resp.content_original_length;
	} else {
		is_last = body_len == 0;
	}

skip_generate:

	/* filter */
	body_len = phl_module_filter_response_body(r, buf_pos, body_len, buf_len, &is_last);
	if (body_len < 0) {
		return body_len;
	}

	/* pack, HTTP2 frame or HTTP1 chunked */
	if (c->is_http2) {
		body_len = phl_http2_response_body_pack(r, buf_pos, body_len, is_last);
	} else {
		body_len = phl_http1_response_body_pack(r, buf_pos, body_len, is_last);
	}

	r->resp.sent_length += body_len;
	c->send_buf_len += body_len;

	return is_last ? PHL_OK : phl_request_response_body(r);
}

static void phl_request_run_post(struct phl_request *r)
{
	struct phl_request *subr, *safe;
	wuy_list_iter_safe_type(&r->subr_head, subr, safe, list_node) {
		if (subr->state != PHL_REQUEST_STATE_LOCATE_CONF_HOST) {
			break;
		}
		wuy_list_delete(&subr->list_node);
		wuy_list_append(&r->subr_head, &subr->list_node);
		phl_request_run(subr, "run subrequest");
	}
}

static int (*phl_request_steps[])(struct phl_request *) = {
	phl_request_receive_headers,
	phl_request_locate_conf_host,
	phl_request_locate_conf_path,
	phl_request_receive_body_sync,
	phl_request_process_headers,
	phl_request_process_body,
	phl_request_response_headers_1,
	phl_request_response_headers_2,
	phl_request_response_headers_3,
	phl_request_response_body,
};

void phl_request_run(struct phl_request *r, const char *from)
{
	if (r->closed) {
		return;
	}

	phl_request_log(r, PHL_LOG_DEBUG, "{{{ phl_request_run %d, from %s", r->state, from);

	if (r->state == PHL_REQUEST_STATE_DONE) {
		phl_request_close(r);
		return;
	}

	assert(r->state < PHL_REQUEST_STATE_DONE);
	int ret = phl_request_steps[r->state](r);

	phl_request_log(r, PHL_LOG_DEBUG, "}}} state:%d ret:%d", r->state, ret);

	if (ret == PHL_OK || ret == PHL_BREAK) {
		r->state++; /* next step */
		return phl_request_run(r, "again");
	}

	if (ret == PHL_AGAIN) {
		phl_request_run_post(r);
		return;
	}

	if (ret == PHL_ERROR) {
		if (r->resp.status_code != 0) {
			ret = r->resp.status_code;
		} else if (r->state <= PHL_REQUEST_STATE_RESPONSE_HEADERS_1) {
			ret = WUY_HTTP_500;
		} else {
			phl_request_close(r);
			return;
		}
	}

	/* returns status code and breaks the normal process */
	r->is_broken = true;
	r->resp.status_code = ret;
	r->state = PHL_REQUEST_STATE_RESPONSE_HEADERS_1;
	return phl_request_run(r, "break");
}

struct phl_request *phl_request_subr_new(struct phl_request *father, const char *uri)
{
	phl_request_log(father, PHL_LOG_DEBUG, "new subrequest");

	struct phl_connection *c = calloc(1, sizeof(struct phl_connection));
	c->conf_listen = father->c->conf_listen;

	struct phl_request *subr = phl_request_new(c);
	subr->req.host = wuy_pool_strdup(subr->pool, father->req.host);
	subr->conf_host = father->conf_host;
	subr->conf_path = subr->conf_host->default_path;
	subr->state = PHL_REQUEST_STATE_LOCATE_CONF_HOST;
	subr->father = father;
	wuy_list_insert(&father->subr_head, &subr->list_node);

	c->u.request = subr; /* HTTP/1 only */

	/* set request */
	subr->req.method = WUY_HTTP_GET;

	switch (uri[0]) {
	case '@':
		subr->req.uri = father->req.uri;
		subr->named_path = uri;
		break;
	case '/':
		phl_request_set_uri(subr, uri, strlen(uri));
		break;
	default:
		phl_request_subr_close(subr);
		phl_request_log(father, PHL_LOG_ERROR, "subr invalid uri %s", uri);
		return NULL;
	}

	return subr;
}

void phl_request_subr_detach(struct phl_request *subr)
{
	subr->father = PHL_REQUEST_DETACHED_SUBR_FATHER;
}

int phl_request_subr_flush_connection(struct phl_connection *c)
{
	struct phl_request *subr = c->u.request;
	struct phl_request *father = subr->father;

	/* drop response for detached subrequests */
	if (father == PHL_REQUEST_DETACHED_SUBR_FATHER) {
		c->send_buf_len = 0;
		return PHL_OK;
	}

	phl_request_run(father, "subrequest flush");
	return PHL_AGAIN;
}

static void phl_request_defer_free(void *data)
{
	struct phl_request *r;
	while (wuy_list_pop_type(&phl_request_defer_list, r, list_node)) {
		wuy_pool_destroy(r->pool);
	}
}

void phl_request_init(void)
{
	loop_defer_add(phl_loop, phl_request_defer_free, NULL);
}
