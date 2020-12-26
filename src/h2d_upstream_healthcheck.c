#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_log_level(upstream->log, level, \
		"upstream active healthcheck: %s " fmt, address->name, ##__VA_ARGS__)

static int h2d_upstream_healthcheck_on_read(loop_stream_t *s, void *data, int data_len)
{
	struct h2d_upstream_address *address = loop_stream_get_app_data(s);
	struct h2d_upstream_conf *upstream = address->upstream;

	int resp_len = upstream->healthcheck.resp_len;
	const char *resp_str = upstream->healthcheck.resp_str;

	bool ok;
	switch (resp_str[0]) {
	case '*':
		ok = true;
		break;
	case '=':
		resp_len--;
		resp_str++;
		if (data_len < resp_len) {
			return 0;
		}
		if (data_len > resp_len) {
			ok = false;
			break;
		}
		ok = memcmp(data, resp_str, resp_len) == 0;
		break;
	case '~':
		ok = h2d_lua_api_str_find(data, resp_str+1);
		break;
	default:
		if (data_len < resp_len) {
			return 0;
		}
		ok = memcmp(data, resp_str, resp_len) == 0;
	}

	_log(H2D_LOG_DEBUG, "done ok=%d %d\n", ok, address->healthchecks);

	if (ok) {
		address->healthchecks++;
	} else {
		address->healthchecks = 0;
	}

	return -1; /* to close the stream */
}

static void h2d_upstream_healthcheck_on_writable(loop_stream_t *s)
{
	struct h2d_upstream_address *address = loop_stream_get_app_data(s);
	struct h2d_upstream_conf *upstream = address->upstream;

	int write_len = loop_stream_write(s, upstream->healthcheck.req_str,
			upstream->healthcheck.req_len);

	if (write_len == 0) { /* write blocks */
		loop_stream_set_timeout(s, upstream->send_timeout * 1000);
		return;
	}
	if (write_len == upstream->healthcheck.req_len) { /* write done, wait for response */
		loop_stream_set_timeout(s, upstream->recv_timeout * 1000);
		return;
	}

	/* neighter blocked nor finished */
	_log(H2D_LOG_ERROR, "loop_stream_write() fail %d %d\n", write_len, upstream->healthcheck.req_len);
	loop_stream_close(s);
}

static void h2d_upstream_healthcheck_set_timer(struct h2d_upstream_address *address)
{
	struct h2d_upstream_conf *upstream = address->upstream;

	_log(H2D_LOG_DEBUG, "set timer");
	loop_timer_set_after(address->active_hc_timer, upstream->healthcheck.interval * 1000);
}

static void h2d_upstream_healthcheck_on_close(loop_stream_t *s, enum loop_stream_close_reason reason)
{
	struct h2d_upstream_address *address = loop_stream_get_app_data(s);
	struct h2d_upstream_conf *upstream = address->upstream;

	if (address->healthchecks < upstream->healthcheck.repeats) {
		h2d_upstream_healthcheck_set_timer(address);
		return;
	}

	_log(H2D_LOG_INFO, "recover!");

	loop_timer_delete(address->active_hc_timer);
	address->active_hc_timer = NULL;
	address->down_time = 0;
	return;
}

static loop_stream_ops_t h2d_upstream_healthcheck_ops = {
	.on_read = h2d_upstream_healthcheck_on_read,
	.on_writable = h2d_upstream_healthcheck_on_writable,
	.on_close = h2d_upstream_healthcheck_on_close,
	H2D_SSL_LOOP_STREAM_UNDERLYINGS,
};

static int64_t h2d_upstream_healthcheck_address_handler(int64_t at, void *data)
{
	struct h2d_upstream_address *address = data;
	struct h2d_upstream_conf *upstream = address->upstream;

	_log(H2D_LOG_DEBUG, "begin");

	loop_stream_t *s = loop_tcp_connect_sockaddr(h2d_loop, &address->sockaddr.s,
			&h2d_upstream_healthcheck_ops);
	if (s == NULL) {
		address->healthchecks = 0;
		return address->upstream->healthcheck.interval * 1000;
	}

	if (address->upstream->ssl_enable) {
		h2d_ssl_stream_set(s, upstream->ssl_ctx, false);
	}

	loop_stream_set_app_data(s, address);

	h2d_upstream_healthcheck_on_writable(s);

	return 0;
}

void h2d_upstream_healthcheck_defer(struct h2d_upstream_address *address)
{
	if (address->active_hc_timer != NULL) {
		return;
	}

	address->active_hc_timer = loop_timer_new(h2d_loop,
			h2d_upstream_healthcheck_address_handler, address);
	if (address->active_hc_timer == NULL) {
		return;
	}

	h2d_upstream_healthcheck_set_timer(address);
}
