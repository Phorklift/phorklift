#include <sys/time.h>
#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log_at(r, \
		r->c->conf_listen->http2.log, level, "http2: " fmt, ##__VA_ARGS__)

#define _log_conn(level, fmt, ...) h2d_log_level(c->conf_listen->http2.log, \
		level, "http2: " fmt, ##__VA_ARGS__)

// move other where
#define h2d_litestr_equal(a_str, a_len, b_str) h2d_lenstr_equal(a_str, a_len, b_str, sizeof(b_str)-1)
static bool h2d_lenstr_equal(const char *a_str, int a_len, const char *b_str, int b_len)
{
	return a_len == b_len && memcmp(a_str, b_str, a_len) == 0;
}

/* libhttp2 hooks */

static bool h2d_http2_hook_stream_new(http2_stream_t *h2s, http2_connection_t *h2c)
{
	struct h2d_request *r = h2d_request_new(http2_connection_get_app_data(h2c));

	_log(H2D_LOG_DEBUG, "new stream");

	r->h2s = h2s;
	http2_stream_set_app_data(h2s, r);
	return true;
}

static bool h2d_http2_hook_stream_header(http2_stream_t *h2s, const char *name_str,
		int name_len, const char *value_str, int value_len)
{
	struct h2d_request *r = http2_stream_get_app_data(h2s);

	/* end of headers */
	if (name_str == NULL) {

		if (name_len != 0) { /* end of request */
			if (r->req.content_length != H2D_CONTENT_LENGTH_INIT && r->req.content_length != 0) {
				return false;
			}
		} else { /* request body follows */
			if (r->req.content_length == H2D_CONTENT_LENGTH_INIT) {
				/* just to tell h2d_request_process_body() that there is body */
				wuy_http_chunked_enable(&r->req.chunked);
			}
		}

		r->state = H2D_REQUEST_STATE_PROCESS_HEADERS;
		return true; //  return what ??
	}

	_log(H2D_LOG_DEBUG, "request header: %.*s %.*s",
			name_len, name_str, value_len, value_str);

	/* parse this one header */
	if (name_str[0] == ':') {
		if (h2d_litestr_equal(name_str, name_len, ":path")) {
			return h2d_request_set_uri(r, value_str, value_len);
		} else if (h2d_litestr_equal(name_str, name_len, ":authority")) {
			return h2d_request_set_host(r, value_str, value_len);
		} else if (h2d_litestr_equal(name_str, name_len, ":scheme")) {
			return true;
		} else if (h2d_litestr_equal(name_str, name_len, ":method")) {
			r->req.method = wuy_http_method(value_str, value_len);
			if (r->req.method < 0) {
				return false;
			}
			return true;
		} else {
			return false;
		}
	} else {
		if (h2d_litestr_equal(name_str, name_len, "content-length")) {
			r->req.content_length = atoi(value_str);
			return true;
		}
	}

	h2d_header_add(&r->req.headers, name_str, name_len, value_str, value_len);

	return true;
}

static bool h2d_http2_hook_stream_body(http2_stream_t *h2s, const uint8_t *buf, int len)
{
	struct h2d_request *r = http2_stream_get_app_data(h2s);

	_log(H2D_LOG_DEBUG, "request body %d", len);

	if (buf == NULL) {
		_log(H2D_LOG_DEBUG, "set r->req.body_finished");
		r->req.body_finished = true;
		h2d_request_run(r, -1); // TODO only for POST, should remove this
		return true;
	}

	if (r->req.body_buf == NULL) {
		r->req.body_buf = malloc(4096); // TODO
	}
	memcpy(r->req.body_buf + r->req.body_len, buf, len);
	r->req.body_len += len;
	return true;
}

static void h2d_http2_hook_stream_close(http2_stream_t *h2s)
{
	struct h2d_request *r = http2_stream_get_app_data(h2s);
	if (r != NULL) {
		h2d_request_close(r);
	}
}

int h2d_http2_response_headers(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;

	int estimate_size = 4000; // TODO
	int buf_size = h2d_connection_make_space(c, estimate_size);
	if (buf_size < 0) {
		return buf_size;
	}

	uint8_t *pos_frame = c->send_buf_pos;
	uint8_t *pos_payload = pos_frame + HTTP2_FRAME_HEADER_SIZE;
	uint8_t *pos_end = c->send_buf_pos + buf_size;
	uint8_t *p = pos_payload;

	int proc_len = http2_make_status_code(p, pos_end - p, r->resp.status_code);
	p += proc_len;

	if (r->resp.content_length != H2D_CONTENT_LENGTH_INIT) {
		proc_len = http2_make_content_length(p, pos_end - p, r->resp.content_length);
		p += proc_len;
	}

	struct h2d_header *h;
	h2d_header_iter(&r->resp.headers, h) {
		proc_len = http2_make_header(r->h2s, p, pos_end - p, h->str,
				h->name_len, h2d_header_value(h), h->value_len);
		p += proc_len;
	}

	http2_make_frame_headers(r->h2s, pos_frame, p - pos_payload, r->resp.content_length==0, true);

	c->send_buf_pos += p - pos_frame;

	_log(H2D_LOG_DEBUG, "response headers %ld", p - pos_frame);

	return H2D_OK;
}

void h2d_http2_response_body_packfix(struct h2d_request *r,
		uint8_t **p_buf_pos, int *p_buf_len)
{
	*p_buf_pos += HTTP2_FRAME_HEADER_SIZE;
	*p_buf_len -= HTTP2_FRAME_HEADER_SIZE;
}
int h2d_http2_response_body_pack(struct h2d_request *r, uint8_t *payload,
		int length, bool is_body_finished)
{
	http2_make_frame_body(r->h2s, payload - HTTP2_FRAME_HEADER_SIZE,
			length, is_body_finished);
	return length + HTTP2_FRAME_HEADER_SIZE;
}

static void h2d_http2_response_body_finish(struct h2d_request *r)
{
	if (h2d_connection_make_space(r->c, HTTP2_FRAME_HEADER_SIZE) < 0) {
		return;
	}

	http2_make_frame_body(r->h2s, r->c->send_buf_pos, 0, true);
	r->c->send_buf_pos += HTTP2_FRAME_HEADER_SIZE;
}

static int h2d_http2_hook_stream_response(http2_stream_t *h2s, int window)
{
	h2d_request_run(http2_stream_get_app_data(h2s), -1);
	return 1; // TODO check closed?
}

static bool h2d_http2_hook_control_frame(http2_connection_t *h2c, const uint8_t *buf, int len)
{
	struct h2d_connection *c = http2_connection_get_app_data(h2c);

	_log_conn(H2D_LOG_DEBUG, "send control frame type=%d len=%d", buf[3], len);

	int ret = h2d_connection_make_space(c, len);
	if (ret < 0) {
		// TODO send again if ret==H2D_AGAIN
		return false;
	}

	memcpy(c->send_buf_pos, buf, len);
	c->send_buf_pos += len;
	return true;
}

static void h2d_http2_hook_log(http2_connection_t *h2c,
		enum http2_log_level level, const char *fmt, ...)
{
	struct h2d_connection *c = http2_connection_get_app_data(h2c);
	if (c == NULL) {
		return;
	}

	struct h2d_log *log;
	if (c->conf_listen->http2.log != NULL) {
		log = c->conf_listen->http2.log;
	} else {
		log = c->conf_listen->default_host->default_path->error_log;
	}

	va_list ap;
	va_start(ap, fmt);
	h2d_log_level_v(log, (enum h2d_log_level)level, fmt, ap);
	va_end(ap);
}

void h2d_http2_init(void)
{
	static struct http2_hooks hooks = {
		h2d_http2_hook_stream_new,
		h2d_http2_hook_stream_header,
		h2d_http2_hook_stream_body,
		h2d_http2_hook_stream_close,
		h2d_http2_hook_stream_response,
		h2d_http2_hook_control_frame,
		h2d_http2_hook_log,
	};
	http2_library_init(&hooks);
}

/* connection event handlers */

int h2d_http2_on_read(struct h2d_connection *c, void *data, int len)
{
	http2_connection_t *h2c = c->u.h2c;

	/* h2d_http2_hook_stream_header/_body/_close() are called inside here */
	int proc_len = http2_process_input(h2c, data, len);

	_log_conn(H2D_LOG_DEBUG, "on_read %d, process=%d", len, proc_len);
	if (proc_len < 0) {
		return H2D_ERROR;
	}

	/* h2d_http2_hook_stream_response() is called inside here */
	http2_schedular(h2c);

	if (!c->closed && http2_connection_in_reading(c->u.h2c)) {
		h2d_connection_set_recv_timer(c);
	}

	return proc_len;
}

void h2d_http2_on_writable(struct h2d_connection *c)
{
	_log_conn(H2D_LOG_DEBUG, "on_writable");

	/* h2d_http2_hook_stream_response() is called inside here */
	http2_schedular(c->u.h2c);
}

void h2d_http2_request_close(struct h2d_request *r)
{
	if (r->state != H2D_REQUEST_STATE_DONE) {
		h2d_http2_response_body_finish(r);
	}

	http2_stream_close(r->h2s);

	if (http2_connection_in_idle(r->c->u.h2c)) {
		h2d_connection_set_idle(r->c);
	}
}

/* on the connection negotiated to HTTP/2, by ALPN or Upgrade */
void h2d_http2_connection_init(struct h2d_connection *c)
{
	_log_conn(H2D_LOG_DEBUG, "upgrade!");

	http2_connection_t *h2c = http2_connection_new(&c->conf_listen->http2.settings);
	http2_connection_set_app_data(h2c, c);

	enum h2d_log_level level;
	if (c->conf_listen->http2.log != NULL) {
		level = c->conf_listen->http2.log->level;
	} else {
		level = c->conf_listen->default_host->default_path->error_log->level;
	}
	switch (level) {
	case H2D_LOG_DEBUG:
		http2_connection_set_log_level(h2c, HTTP2_LOG_DEBUG);
		break;
	case H2D_LOG_INFO:
		http2_connection_set_log_level(h2c, HTTP2_LOG_ERROR);
		break;
	default:
		; /* do not log */
	}

	c->is_http2 = true;
	c->u.h2c = h2c;
}

struct wuy_cflua_command h2d_conf_listen_http2_commands[] = {
	{	.name = "idle_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.idle_timeout),
		.default_value.n = 5 * 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "idle_min_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.idle_min_timeout),
		.default_value.n = 2 * 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "ping_interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.ping_interval),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "header_table_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.settings.header_table_size),
		.default_value.n = 4096,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "max_concurrent_streams",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.settings.max_concurrent_streams),
		.default_value.n = 100,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "initial_window_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.settings.initial_window_size),
		.default_value.n = 65535,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "max_frame_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.settings.max_frame_size),
		.default_value.n = 16384,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "max_header_list_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.settings.max_header_list_size),
		.default_value.n = 100,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, http2.log),
		.u.table = &h2d_log_conf_table,
	},
	{ NULL }
};
