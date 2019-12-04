#include "h2d_main.h"

static wuy_pool_t *h2d_request_pool;
static wuy_pool_t *h2d_subreq_conn_pool;

static WUY_LIST(h2d_request_defer_free_list);
static WUY_LIST(h2d_request_defer_run_list);

// TODO do not use H2D_CONF_MODULE_MAX
#define H2D_REQUEST_SIZE (sizeof(struct h2d_request) + h2d_module_ctx_number * sizeof(void *))

struct h2d_request *h2d_request_new(struct h2d_connection *c)
{
	struct h2d_request *r = wuy_pool_alloc(h2d_request_pool);
	if (r == NULL) {
		return NULL;
	}

	bzero(r, H2D_REQUEST_SIZE);
	wuy_list_node_init(&r->list_node);

	r->req.buffer = malloc(4096); // TODO
	r->req.next = r->req.buffer;
	r->req.next->name_len = 0;

	r->resp.buffer = malloc(4096); // TODO
	r->resp.next = r->resp.buffer;
	r->resp.next->name_len = 0;
	r->resp.content_length = H2D_CONTENT_LENGTH_INIT;

	r->c = c;
	return r;
}

void h2d_request_close(struct h2d_request *r)
{
	if (r->state == H2D_REQUEST_STATE_CLOSED) {
		return;
	}
	r->state = H2D_REQUEST_STATE_CLOSED;

	printf("request done: %s\n", h2d_header_value(r->req.url));

	if (h2d_request_is_subreq(r)) {
		printf("sub wake up father: %p -> %p\n", r, r->father);
		h2d_request_active(r->father);
	}

	h2d_module_request_ctx_free(r);

	if (r->h2s != NULL) {
		http2_stream_close(r->h2s);
	} else {
		assert(r->c->u.request == r);
		r->c->u.request = NULL;
	}

	free(r->req.buffer);
	free(r->resp.buffer);
	free(r->resp.body_buffer);

	wuy_list_delete(&r->list_node);
	wuy_list_append(&h2d_request_defer_free_list, &r->list_node);
}

int h2d_request_process_headers(struct h2d_request *r)
{
	assert(r->state == H2D_REQUEST_STATE_PROCESS_HEADERS);

	/* locate host */
	if (r->conf_host == NULL) { /* already set if subrequest */
		r->conf_host = h2d_conf_listen_search_hostname(r->c->conf_listen,
				r->req.host ? h2d_header_value(r->req.host) : NULL);
		if (r->conf_host == NULL) {
			printf("invalid host\n");
			return H2D_ERROR;
		}
		if (r->c->ssl_sni_conf_host != NULL && r->conf_host != r->c->ssl_sni_conf_host) {
			printf("wanring: ssl_sni_conf_host not match\n");
		}
	}

	/* locate path */
	if (r->req.url == NULL) {
		printf("no path\n");
		return false;
	}
	r->conf_path = h2d_conf_host_search_pathname(r->conf_host,
			h2d_header_value(r->req.url));
	if (r->conf_path == NULL) {
		printf("no path matched\n");
		return false;
	}

	/* done */
	int ret = h2d_module_filter_process_headers(r);
	if (ret == H2D_AGAIN || ret == H2D_ERROR) {
		return ret;
	} else if (ret != H2D_OK) { /* status codes */
		// TODO special response
		r->state = H2D_REQUEST_STATE_RESPONSE_HEADERS;
		return ret;
	}

	ret = r->conf_path->content->content.process_headers(r);
	if (ret == H2D_OK && r->state == H2D_REQUEST_STATE_PROCESS_HEADERS) {
		r->state = H2D_REQUEST_STATE_PROCESS_BODY;
	}
	return ret;
}

static int h2d_request_response_headers(struct h2d_request *r)
{
	int ret = r->conf_path->content->content.response_headers(r);
	if (ret != H2D_OK) {
		return ret;
	}

	ret = h2d_module_filter_response_headers(r);
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
static bool h2d_request_is_body_finished(struct h2d_request *r)
{
	if (r->subr != NULL) {
		return false;
	}
	if (r->resp.content_length != H2D_CONTENT_LENGTH_INIT) {
		return r->resp.sent_length >= r->resp.content_length;
		//return r->resp.sent_length == r->resp.content_length;
	}
	return r->conf_path->content->content.is_body_finished(r);
}
static int h2d_request_response_body(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;

	int ret = h2d_connection_make_space(c, 4096);
	if (ret != H2D_OK) {
		return ret;
	}

	uint8_t *buffer = c->send_buf_pos;
	uint8_t *buf_pos = buffer;
	int buf_len = c->send_buffer + H2D_CONNECTION_SENDBUF_SIZE - buffer;

	if (c->is_http2) {
		h2d_http2_response_body_packfix(r, &buf_pos, &buf_len);
	} else if (r->resp.content_length == H2D_CONTENT_LENGTH_CHUNKED) {
		h2d_http1_response_body_packfix(r, &buf_pos, &buf_len);
	}

	buf_len = r->conf_path->content->content.response_body(r, buf_pos, buf_len);
	if (buf_len < 0) {
		return buf_len;
	}

	buf_len = h2d_module_filter_response_body(r, buf_pos, buf_len);
	if (buf_len <= 0) {
		return buf_len;
	}

	r->resp.sent_length += buf_len;

	bool is_body_finished = h2d_request_is_body_finished(r);

	if (c->is_http2) {
		buf_len = h2d_http2_response_body_pack(r, buf_pos, buf_len, is_body_finished);
	} else if (r->resp.content_length == H2D_CONTENT_LENGTH_CHUNKED) {
		buf_len = h2d_http1_response_body_pack(r, buf_pos, buf_len, is_body_finished);
	}

	c->send_buf_pos += buf_len;

	if (is_body_finished) {
		h2d_request_close(r);
	}

	return H2D_OK;
}
void h2d_request_response(struct h2d_request *r)
{
	if (r->state == H2D_REQUEST_STATE_CLOSED) {
		return;
	}

	/* response headers */
	// if (r->state == H2D_REQUEST_STATE_RESPONSE_HEADERS) { // TODO
	if (r->state <= H2D_REQUEST_STATE_RESPONSE_HEADERS) { // FIXME
		int ret = h2d_request_response_headers(r);
		if (ret == H2D_AGAIN) {
			return;
		} else if (ret == H2D_ERROR) {
			h2d_request_close(r);
			return;
		} else if (ret != H2D_OK) {
			// TODO special response
		}

		r->state = H2D_REQUEST_STATE_RESPONSE_BODY;
	}

	/* response body */
	do {
		int ret = h2d_request_response_body(r);
		if (ret == H2D_AGAIN) {
			return;
		} else if (ret == H2D_ERROR) {
			h2d_request_close(r);
			return;
		}

	} while (h2d_connection_flush_if_full(r->c));
}

void http2_stream_active_tmp(http2_stream_t *s);
void h2d_request_active(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;
	if (h2d_connection_write_blocked(c)) {
		printf("======== h2d_request_active\n");
		if (c->is_http2) {
			http2_stream_active_tmp(r->h2s);
		}
		return;
	}

	// XXX timer -> epoll-block -> idle, so pending subreqs will not run
	printf("active %p\n", r);

	wuy_list_delete(&r->list_node);
	wuy_list_append(&h2d_request_defer_run_list, &r->list_node);
}

struct h2d_request *h2d_request_subreq_new(struct h2d_request *father)
{
	/* fake connection */
	struct h2d_connection *c = wuy_pool_alloc(h2d_subreq_conn_pool);
	bzero(c, sizeof(struct h2d_connection));
	c->send_buffer = malloc(H2D_CONNECTION_SENDBUF_SIZE);
	c->send_buf_pos = c->send_buffer;
	c->conf_listen = father->c->conf_listen;

	/* subrequest */
	struct h2d_request *subreq = h2d_request_new(c);
	subreq->conf_host = father->conf_host;
	subreq->father = father;
	father->subr = subreq;
	c->u.request = subreq;

	printf("h2d_request_subreq_new %p -> %p\n", father, subreq);

	h2d_request_active(subreq);
	return subreq;
}

static void h2d_request_defer_routine(void *data)
{
	wuy_list_node_t *node, *safe;
	while ((node = wuy_list_first(&h2d_request_defer_run_list)) != NULL) {
		wuy_list_del_init(node);

		// TODO new function: h2d_request_run() ?
		struct h2d_request *r = wuy_containerof(node, struct h2d_request, list_node);
		if (r->state == H2D_REQUEST_STATE_PROCESS_HEADERS) {
			if (h2d_request_process_headers(r) != H2D_OK) {
				continue;
			}
		}
		h2d_request_response(r);
		h2d_connection_flush(r->c);
	}

	wuy_list_iter_safe(&h2d_request_defer_free_list, node, safe) {
		wuy_list_delete(node);
		wuy_pool_free(wuy_containerof(node, struct h2d_request, list_node));
	}
}

void h2d_request_init(void)
{
	h2d_request_pool = wuy_pool_new(H2D_REQUEST_SIZE);

	h2d_subreq_conn_pool = wuy_pool_new_type(struct h2d_connection);

	loop_idle_add(h2d_loop, h2d_request_defer_routine, NULL);
}
