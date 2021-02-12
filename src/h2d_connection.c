#include "h2d_main.h"

#define _log_conf(level, fmt, ...) \
	h2d_log_level(conf_listen->default_host->default_path->error_log, \
			level, "connection: " fmt, ##__VA_ARGS__)
#define _log(level, fmt, ...) \
	h2d_log_level(c->conf_listen->default_host->default_path->error_log, \
			level, "connection: " fmt, ##__VA_ARGS__)

static WUY_LIST(h2d_connection_defer_list);

static void h2d_connection_put_defer(struct h2d_connection *c)
{
	if (!wuy_list_node_linked(&c->list_node)) {
		wuy_list_append(&h2d_connection_defer_list, &c->list_node);
	}
}

void h2d_connection_close(struct h2d_connection *c)
{
	if (c->closed) {
		return;
	}
	c->closed = true;

	_log(H2D_LOG_DEBUG, "close");

	if (c->is_http2) {
		http2_connection_close(c->u.h2c);
	} else if (c->u.request != NULL) {
		h2d_request_close(c->u.request);
	}

	atomic_fetch_sub(&c->conf_listen->stats->connections, 1);

	if (c->loop_stream == NULL) {
		goto skip_subr;
	}

	if (c->send_buffer != NULL) {
		loop_stream_write(c->loop_stream, c->send_buffer,
				c->send_buf_pos - c->send_buffer);
		free(c->send_buffer);
	}
	loop_stream_close(c->loop_stream);

	loop_group_timer_delete(c->recv_timer);
	loop_group_timer_delete(c->send_timer);

skip_subr:
	h2d_connection_put_defer(c);
}

void h2d_connection_set_idle(struct h2d_connection *c)
{
	if (c->closed) {
		return;
	}

	_log(H2D_LOG_DEBUG, "set idle");
	loop_group_timer_set(c->is_http2 ? c->conf_listen->http2.idle_timer_group
			: c->conf_listen->http1.keepalive_timer_group, c->recv_timer);
}

static int h2d_connection_flush(struct h2d_connection *c)
{
	if (c->closed) {
		return H2D_ERROR;
	}

	if (c->send_buffer == NULL) {
		return H2D_OK;
	}
	int buf_len = c->send_buf_pos - c->send_buffer;
	if (buf_len == 0) {
		return H2D_OK;
	}

	if (c->loop_stream == NULL) { /* fake connection of subrequest */
		// TODO wake up father request
		return H2D_AGAIN;
	}

	int write_len = loop_stream_write(c->loop_stream, c->send_buffer, buf_len);
	_log(H2D_LOG_DEBUG, "flush %d %d", buf_len, write_len);
	if (write_len < 0) {
		return H2D_ERROR;
	}

	if (write_len < buf_len) {
		if (write_len > 0) {
			memmove(c->send_buffer, c->send_buffer + write_len,
					buf_len - write_len);
			c->send_buf_pos -= write_len;
		}

		loop_group_timer_set(c->conf_listen->network.send_timer_group, c->send_timer);
		return H2D_AGAIN;
	}

	loop_group_timer_suspend(c->send_timer);
	c->send_buf_pos = c->send_buffer;
	return H2D_OK;
}

static void h2d_connection_defer_routine(void *data)
{
	struct h2d_connection *c;
	while (wuy_list_pop_type(&h2d_connection_defer_list, c, list_node)) {
		if (c->closed) {
			free(c);
		} else {
			if (h2d_connection_flush(c) == H2D_OK) {
				free(c->send_buffer);
				c->send_buffer = c->send_buf_pos = NULL;
			}
		}
	}
}

int h2d_connection_make_space(struct h2d_connection *c, int size)
{
	if (c->closed) {
		return H2D_ERROR;
	}

	int buf_size = c->conf_listen->network.send_buffer_size;
	if (c->is_http2) {
		buf_size += HTTP2_FRAME_HEADER_SIZE;
	}

	if (size > buf_size) {
		_log(H2D_LOG_FATAL, "too small buf_size %d", buf_size);
		return H2D_ERROR;
	}

	/* so flush this at h2d_connection_defer_routine() */
	h2d_connection_put_defer(c);

	/* allocate buffer */
	if (c->send_buffer == NULL) {
		c->send_buffer = malloc(buf_size);
		c->send_buf_pos = c->send_buffer;
		return c->send_buffer ? buf_size : H2D_ERROR;
	}

	/* use exist buffer */
	int available = buf_size - (c->send_buf_pos - c->send_buffer);
	if (available >= size) {
		return available;
	}

	int ret = h2d_connection_flush(c);
	if (ret != H2D_OK) {
		return ret;
	}

	return buf_size - (c->send_buf_pos - c->send_buffer);
}

static int h2d_connection_on_read(loop_stream_t *s, void *data, int len)
{
	struct h2d_connection *c = loop_stream_get_app_data(s);

	_log(H2D_LOG_DEBUG, "on_read %d", len);

	loop_group_timer_suspend(c->recv_timer);

	if (c->is_http2) {
		return h2d_http2_on_read(c, data, len);
	} else {
		return h2d_http1_on_read(c, data, len);
	}
}

static void h2d_connection_on_writable(loop_stream_t *s)
{
	struct h2d_connection *c = loop_stream_get_app_data(s);

	_log(H2D_LOG_DEBUG, "on_writable");

	if (h2d_connection_flush(c) != H2D_OK) {
		return;
	}

	if (c->is_http2) {
		h2d_http2_on_writable(c);
	} else {
		h2d_http1_on_writable(c);
	}
}

static void h2d_connection_on_close(loop_stream_t *s, enum loop_stream_close_reason reason)
{
	struct h2d_connection *c = loop_stream_get_app_data(s);

	const char *errstr = "";
	if (reason == LOOP_STREAM_READ_ERROR || reason == LOOP_STREAM_WRITE_ERROR) {
		errstr = strerror(errno);
	}

	_log(H2D_LOG_DEBUG, "on_close %s %s, SSL %s", loop_stream_close_string(reason),
			errstr, h2d_ssl_stream_error_string(s));

	h2d_connection_close(c);
}

static bool h2d_connection_free_idle(struct h2d_conf_listen *conf_listen)
{
	_log_conf(H2D_LOG_DEBUG, "free idle");

	if (loop_group_timer_expire_one_ahead(conf_listen->http1.keepalive_timer_group,
				conf_listen->http1.keepalive_min_timeout)) {
		return true;
	}
	if (loop_group_timer_expire_one_ahead(conf_listen->http2.idle_timer_group,
				conf_listen->http2.idle_min_timeout)) {
		return true;
	}
	return false;
}
static bool h2d_connection_on_accept(loop_tcp_listen_t *loop_listen,
		loop_stream_t *s, struct sockaddr *addr)
{
	struct h2d_conf_listen *conf_listen = loop_tcp_listen_get_app_data(loop_listen);

	if (conf_listen->network.connections != 0 &&
			atomic_load(&conf_listen->stats->connections) >= conf_listen->network.connections) {
		if (!h2d_connection_free_idle(conf_listen)) {
			_log_conf(H2D_LOG_INFO, "full");
			return false;
		}
	}

	atomic_fetch_add(&conf_listen->stats->connections, 1);

	struct h2d_connection *c = calloc(1, sizeof(struct h2d_connection));
	if (c == NULL) {
		return false;
	}
	c->client_addr = *addr;
	c->conf_listen = conf_listen;
	c->loop_stream = s;
	c->recv_timer = loop_group_timer_new(c);
	c->send_timer = loop_group_timer_new(c);
	loop_stream_set_app_data(s, c);

	/* set ssl */
	if (conf_listen->ssl_ctx != NULL) {
		h2d_ssl_stream_set(s, conf_listen->ssl_ctx, true);
	}

	_log(H2D_LOG_DEBUG, "new at %s", conf_listen->name);

	return true;
}

static loop_tcp_listen_ops_t h2d_connection_listen_ops = {
	.on_accept = h2d_connection_on_accept,
};
static loop_stream_ops_t h2d_connection_stream_ops = {
	.on_read = h2d_connection_on_read,
	.on_close = h2d_connection_on_close,
	.on_writable = h2d_connection_on_writable,

	H2D_SSL_LOOP_STREAM_UNDERLYINGS,
};

static int64_t h2d_connection_recv_timedout(int64_t at, void *data)
{
	struct h2d_connection *c = data;
	_log(H2D_LOG_DEBUG, "recv timedout");

	h2d_connection_close(c);
	return 0;
}
static int64_t h2d_connection_send_timedout(int64_t at, void *data)
{
	struct h2d_connection *c = data;
	_log(H2D_LOG_DEBUG, "send timedout");

	h2d_connection_close(c);
	return 0;
}

void h2d_connection_add_listen_event(void)
{
	for (int i = 0; h2d_conf_listens[i] != NULL; i++) {
		struct h2d_conf_listen *conf_listen = h2d_conf_listens[i];

		for (int j = 0; j < conf_listen->address_num; j++) {
			loop_tcp_listen_t *loop_listen = loop_tcp_listen_fd(h2d_loop,
					conf_listen->fds[j], &h2d_connection_listen_ops,
					&h2d_connection_stream_ops);
			assert(loop_listen != NULL);

			loop_tcp_listen_set_app_data(loop_listen, conf_listen);
		}
	}
}

const char *h2d_connection_listen_conf(struct h2d_conf_listen *conf_listen)
{
	for (int i = 0; conf_listen->addresses[i] != NULL; i++) {
		conf_listen->address_num++;
	}

	conf_listen->fds = wuy_pool_alloc(wuy_cflua_pool, conf_listen->address_num * sizeof(int));

	for (int i = 0; i < conf_listen->address_num; i++) {
		const char *address = conf_listen->addresses[i];

		struct sockaddr_storage ss;
		if (!wuy_sockaddr_loads(address, &ss, 0)) {
			errno = EINVAL;
			return address;
		}
		int fd = wuy_tcp_listen((struct sockaddr *)&ss, conf_listen->network.backlog,
				conf_listen->network.reuse_port);
		if (fd < 0) {
			return address;
		}

		wuy_tcp_set_defer_accept(fd, conf_listen->network.defer_accept);

		conf_listen->fds[i] = fd;
	}

	/* group timers */
	conf_listen->http1.keepalive_timer_group = loop_group_timer_head_new(h2d_loop,
			h2d_connection_recv_timedout,
			conf_listen->http1.keepalive_timeout * 1000);
	conf_listen->http2.idle_timer_group = loop_group_timer_head_new(h2d_loop,
			h2d_connection_recv_timedout,
			conf_listen->http2.idle_timeout * 1000);
	conf_listen->network.recv_timer_group = loop_group_timer_head_new(h2d_loop,
			h2d_connection_recv_timedout,
			conf_listen->network.recv_timeout * 1000);
	conf_listen->network.send_timer_group = loop_group_timer_head_new(h2d_loop,
			h2d_connection_send_timedout,
			conf_listen->network.send_timeout * 1000);

	return NULL;
}

struct wuy_cflua_command h2d_conf_listen_network_commands[] = {
	{	.name = "connections",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.connections),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "recv_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.recv_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "send_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.send_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "send_buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.send_buffer_size),
		.default_value.n = 16 * 1024,
		.limits.n = WUY_CFLUA_LIMITS_LOWER(4 * 1024),
	},
	{	.name = "backlog",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.backlog),
		.default_value.n = 1000,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "reuse_port",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_conf_listen, network.reuse_port),
	},
	{	.name = "defer_accept",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.defer_accept),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{ NULL }
};

void h2d_connection_init(void)
{
	loop_defer_add(h2d_loop, h2d_connection_defer_routine, NULL);
}
