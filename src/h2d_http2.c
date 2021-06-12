#include <sys/time.h>
#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log_at(r, \
		r->c->conf_listen->http2.log, level, "http2: " fmt, ##__VA_ARGS__)

#define _log_conn(level, fmt, ...) h2d_conf_log_at(c->conf_listen->http2.log, \
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

		if (name_len != 0) { /* means end-of-stream */
			r->req.body_finished = true;
			if (r->req.content_length != H2D_CONTENT_LENGTH_INIT
					&& r->req.content_length != 0) {
				return false;
			}
		}

		r->state++; /* to H2D_REQUEST_STATE_LOCATE_HEADERS */
		return true;
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
			char *end;
			r->req.content_length = strtol(value_str, &end, 10);
			if (end - value_str != value_len) {
				return WUY_HTTP_400;
			}
			return true;
		}
	}

	h2d_header_add(&r->req.headers, name_str, name_len, value_str, value_len, r->pool);

	return true;
}

static bool h2d_http2_hook_stream_body(http2_stream_t *h2s, const uint8_t *buf, int len)
{
	struct h2d_request *r = http2_stream_get_app_data(h2s);

	_log(H2D_LOG_DEBUG, "request body %d", len);

	if (buf == NULL) {
		_log(H2D_LOG_DEBUG, "set r->req.body_finished");
		r->req.body_finished = true;
		return true;
	}

	int ret = h2d_request_append_body(r, buf, len);
	if (ret != H2D_OK) {
		r->resp.status_code = ret;
		return false;
	}
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

	int estimate_size = h2d_header_estimate_size(&r->resp.headers) + 100;
	int buf_size = h2d_connection_make_space(c, estimate_size);
	if (buf_size < 0) {
		return buf_size;
	}

	uint8_t *pos_frame = c->send_buffer + c->send_buf_len;
	uint8_t *pos_payload = pos_frame + HTTP2_FRAME_HEADER_SIZE;
	uint8_t *pos_end = pos_frame + buf_size;
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

	c->send_buf_len += p - pos_frame;

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
		int length, bool is_last)
{
	http2_make_frame_body(r->h2s, payload - HTTP2_FRAME_HEADER_SIZE, length, is_last);
	return length + HTTP2_FRAME_HEADER_SIZE;
}

static void h2d_http2_response_body_finish(struct h2d_request *r)
{
	struct h2d_connection *c = r->c;

	if (h2d_connection_make_space(c, HTTP2_FRAME_HEADER_SIZE) < 0) {
		return;
	}

	http2_make_frame_body(r->h2s, c->send_buffer + c->send_buf_len, 0, true);
	c->send_buf_len += HTTP2_FRAME_HEADER_SIZE;
}

static bool h2d_http2_hook_stream_response(http2_stream_t *h2s)
{
	struct h2d_request *r = http2_stream_get_app_data(h2s);

	h2d_request_run(r);

	return h2d_connection_is_write_ready(r->c);
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

	memcpy(c->send_buffer + c->send_buf_len, buf, len);
	c->send_buf_len += len;
	return true;
}

static void h2d_http2_hook_log(http2_connection_t *h2c, const char *fmt, ...)
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

	char buffer[1024];

	va_list ap;
	va_start(ap, fmt);
	vsprintf(buffer, fmt, ap);
	va_end(ap);

	h2d_log_level(log, H2D_LOG_DEBUG, "%s", buffer);
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
	};
	http2_library_init(&hooks);
}

/* connection event handlers */

static void h2d_http2_set_state(struct h2d_connection *c)
{
	/* `enum http2_connection_state` happens to be compatible with
	 * `enum h2d_connection_state` */
	enum http2_connection_state state = http2_connection_state(c->u.h2c);
	h2d_connection_set_state(c, (enum h2d_connection_state)state);
}

void h2d_http2_on_readable(struct h2d_connection *c)
{
	uint8_t *buf_pos = c->recv_buffer + c->recv_buf_pos;
	int buf_len = c->recv_buf_end - c->recv_buf_pos;

	http2_connection_t *h2c = c->u.h2c;

	/* h2d_http2_hook_stream_header/_body/_close() are called inside here */
	int proc_len = http2_process_input(h2c, buf_pos, buf_len);

	_log_conn(H2D_LOG_DEBUG, "on_read %d, process=%d", buf_len, proc_len);
	if (proc_len < 0) {
		h2d_connection_close(c);
		return;
	}

	c->recv_buf_pos += proc_len;

	/* h2d_http2_hook_stream_response() is called inside here */
	http2_schedular(h2c);

	h2d_http2_set_state(c);
}

void h2d_http2_on_writable(struct h2d_connection *c)
{
	_log_conn(H2D_LOG_DEBUG, "on_writable");

	/* h2d_http2_hook_stream_response() is called inside here */
	http2_schedular(c->u.h2c);

	h2d_http2_set_state(c);
}

void h2d_http2_request_close(struct h2d_request *r)
{
	if (r->state != H2D_REQUEST_STATE_DONE) {
		h2d_http2_response_body_finish(r);
	}

	http2_stream_close(r->h2s);

	h2d_http2_set_state(r->c);
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
	if (level == H2D_LOG_DEBUG) {
		http2_connection_enable_log(h2c, h2d_http2_hook_log);
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
		.u.table = &h2d_log_omit_conf_table,
	},
	{ NULL }
};
