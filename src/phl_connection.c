#include "phl_main.h"

#define _log_conf(level, fmt, ...) \
	phl_log_level(conf_listen->default_host->default_path->error_log, \
			level, "connection: " fmt, ##__VA_ARGS__)
#define _log(level, fmt, ...) \
	phl_log_level(c->conf_listen->default_host->default_path->error_log, \
			level, "%lu connection: " fmt, c->id, ##__VA_ARGS__)

static WUY_LIST(phl_connection_defer_list);

static void phl_connection_put_defer(struct phl_connection *c)
{
	if (!wuy_list_node_linked(&c->list_node)) {
		wuy_list_append(&phl_connection_defer_list, &c->list_node);
	}
}

void phl_connection_close(struct phl_connection *c)
{
	if (c->state == H2D_CONNECTION_STATE_CLOSED) {
		return;
	}
	c->state = H2D_CONNECTION_STATE_CLOSED;

	_log(H2D_LOG_DEBUG, "close");

	if (c->is_http2) {
		http2_connection_close(c->u.h2c);
	} else if (c->u.request != NULL) {
		phl_request_close(c->u.request);
	}

	atomic_fetch_sub(&c->conf_listen->stats->connections, 1);

	if (c->send_buffer != NULL) {
		loop_stream_write(c->loop_stream, c->send_buffer, c->send_buf_len);
		free(c->send_buffer);
	}
	free(c->recv_buffer);
	loop_stream_close(c->loop_stream);

	loop_group_timer_delete(c->recv_timer);
	loop_group_timer_delete(c->send_timer);

	phl_connection_put_defer(c);
}

bool phl_connection_is_write_ready(struct phl_connection *c)
{
	if (c->state == H2D_CONNECTION_STATE_CLOSED) {
		return false;
	}
	return !loop_stream_is_write_blocked(c->loop_stream);
}

static int phl_connection_flush(struct phl_connection *c)
{
	if (c->state == H2D_CONNECTION_STATE_CLOSED) {
		return H2D_ERROR;
	}

	if (c->send_buffer == NULL || c->send_buf_len == 0) {
		return H2D_OK;
	}

	if (c->loop_stream == NULL) { /* fake connection of subrequest */
		return phl_request_subr_flush_connection(c);
	}

	int write_len = loop_stream_write(c->loop_stream, c->send_buffer, c->send_buf_len);
	_log(H2D_LOG_DEBUG, "flush %d %d", c->send_buf_len, write_len);
	if (write_len < 0) {
		phl_connection_close(c);
		return H2D_ERROR;
	}

	c->send_buf_len -= write_len;
	if (c->send_buf_len > 0) {
		memmove(c->send_buffer, c->send_buffer + write_len, c->send_buf_len);
		loop_group_timer_set(c->conf_listen->network.send_timer_group, c->send_timer);
		return H2D_AGAIN;
	}

	loop_group_timer_suspend(c->send_timer);
	return H2D_OK;
}

static void phl_connection_defer_routine(void *data)
{
	struct phl_connection *c;
	while (wuy_list_pop_type(&phl_connection_defer_list, c, list_node)) {
		if (c->state == H2D_CONNECTION_STATE_CLOSED) {
			free(c);
		} else {
			if (phl_connection_flush(c) == H2D_OK) {
				free(c->send_buffer);
				c->send_buffer = NULL;
			}
		}
	}
}

int phl_connection_make_space(struct phl_connection *c, int size)
{
	if (c->state == H2D_CONNECTION_STATE_CLOSED) {
		return H2D_ERROR;
	}

	int buf_size = c->conf_listen->network.send_buffer_size;
	if (c->is_http2) {
		buf_size += HTTP2_FRAME_HEADER_SIZE;
	}

	if (size > buf_size) {
		_log(H2D_LOG_FATAL, "too small buf_size %d, %d", buf_size, size);
		return H2D_ERROR;
	}

	/* so flush this at phl_connection_defer_routine() */
	phl_connection_put_defer(c);

	/* allocate buffer */
	if (c->send_buffer == NULL) {
		c->send_buffer = malloc(buf_size);
		c->send_buf_len = 0;
		return c->send_buffer ? buf_size : H2D_ERROR;
	}

	/* use exist buffer */
	int available = buf_size - c->send_buf_len;
	if (available >= size) {
		return available;
	}

	if (phl_connection_flush(c) == H2D_ERROR) {
		return H2D_ERROR;
	}

	available = buf_size - c->send_buf_len;
	return available >= size ? available : H2D_AGAIN;
}

void phl_connection_set_state(struct phl_connection *c,
		enum phl_connection_state state)
{
	if (c->state == H2D_CONNECTION_STATE_CLOSED) {
		return;
	}
	if (c->state == state) {
		return;
	}

	_log(H2D_LOG_DEBUG, "state switch from %d to %d", c->state, state);

	c->state = state;

	switch (state) {
	case H2D_CONNECTION_STATE_READING:
		loop_group_timer_set(c->conf_listen->network.recv_timer_group, c->recv_timer);
		break;
	case H2D_CONNECTION_STATE_WRITING:
		loop_group_timer_suspend(c->send_timer);
		break;
	case H2D_CONNECTION_STATE_IDLE:
		loop_group_timer_set(c->is_http2 ? c->conf_listen->http2.idle_timer_group
				: c->conf_listen->http1.keepalive_timer_group, c->recv_timer);
		break;
	default:
		;
	}
}

static void phl_connection_on_readable(loop_stream_t *s)
{
	struct phl_connection *c = loop_stream_get_app_data(s);

	_log(H2D_LOG_DEBUG, "on readable");

	int buf_size = c->conf_listen->network.recv_buffer_size;
	if (c->recv_buffer == NULL) {
		c->recv_buffer = malloc(buf_size);
	}

	while (1) {
		if (c->recv_buf_pos == c->recv_buf_end) {
			c->recv_buf_pos = c->recv_buf_end = 0;
		} else if (c->recv_buf_pos != 0) {
			c->recv_buf_end -= c->recv_buf_pos;
			memmove(c->recv_buffer, c->recv_buffer + c->recv_buf_pos, c->recv_buf_end);
			c->recv_buf_pos = 0;
		}

		int read_len = loop_stream_read(s, c->recv_buffer + c->recv_buf_end,
				buf_size - c->recv_buf_end);

		_log(H2D_LOG_DEBUG, "read %d, %d %d", read_len, buf_size, c->recv_buf_end);
		if (read_len < 0) {
			phl_connection_close(c);
			return;
		}
		if (read_len == 0) {
			break;
		}

		c->recv_buf_end += read_len;

		if (c->is_http2) {
			phl_http2_on_readable(c);
		} else {
			phl_http1_on_readable(c);
		}
	}

	if (c->recv_buf_pos == c->recv_buf_end) {
		free(c->recv_buffer);
		c->recv_buffer = NULL;
	}
}

static void phl_connection_on_writable(loop_stream_t *s)
{
	struct phl_connection *c = loop_stream_get_app_data(s);

	_log(H2D_LOG_DEBUG, "on_writable");

	if (phl_connection_flush(c) != H2D_OK) {
		return;
	}

	if (c->is_http2) {
		phl_http2_on_writable(c);
	} else {
		phl_http1_on_writable(c);
	}
}

static bool phl_connection_free_idle(struct phl_conf_listen *conf_listen)
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
static bool phl_connection_on_accept(loop_tcp_listen_t *loop_listen,
		loop_stream_t *s, struct sockaddr *addr)
{
	struct phl_conf_listen *conf_listen = loop_tcp_listen_get_app_data(loop_listen);

	if (conf_listen->network.connections != 0 &&
			atomic_load(&conf_listen->stats->connections) >= conf_listen->network.connections) {
		if (!phl_connection_free_idle(conf_listen)) {
			_log_conf(H2D_LOG_INFO, "full");
			return false;
		}
	}

	atomic_fetch_add(&conf_listen->stats->connections, 1);

	struct phl_connection *c = calloc(1, sizeof(struct phl_connection));
	if (c == NULL) {
		return false;
	}
	static uint64_t phl_connection_id = 1;
	c->id = phl_connection_id++;
	c->client_addr = *addr;
	c->conf_listen = conf_listen;
	c->loop_stream = s;
	c->recv_timer = loop_group_timer_new(c);
	c->send_timer = loop_group_timer_new(c);
	loop_stream_set_app_data(s, c);

	/* set ssl */
	if (conf_listen->default_host->ssl != NULL) {
		phl_ssl_stream_set(s, conf_listen->default_host->ssl->ctx, true);
	}

	_log(H2D_LOG_DEBUG, "new at %s", conf_listen->name);

	return true;
}

static loop_tcp_listen_ops_t phl_connection_listen_ops = {
	.on_accept = phl_connection_on_accept,
};
static loop_stream_ops_t phl_connection_stream_ops = {
	.on_readable = phl_connection_on_readable,
	.on_writable = phl_connection_on_writable,

	H2D_SSL_LOOP_STREAM_UNDERLYINGS,
};

static int64_t phl_connection_recv_timedout(int64_t at, void *data)
{
	struct phl_connection *c = data;
	_log(H2D_LOG_DEBUG, "recv timedout");

	phl_connection_close(c);
	return 0;
}
static int64_t phl_connection_send_timedout(int64_t at, void *data)
{
	struct phl_connection *c = data;
	_log(H2D_LOG_DEBUG, "send timedout");

	phl_connection_close(c);
	return 0;
}

void phl_connection_conf_timers_init(struct phl_conf_listen *conf_listen)
{
	conf_listen->http1.keepalive_timer_group = loop_group_timer_head_new(phl_loop,
			phl_connection_recv_timedout,
			conf_listen->http1.keepalive_timeout * 1000);
	conf_listen->http2.idle_timer_group = loop_group_timer_head_new(phl_loop,
			phl_connection_recv_timedout,
			conf_listen->http2.idle_timeout * 1000);
	conf_listen->network.recv_timer_group = loop_group_timer_head_new(phl_loop,
			phl_connection_recv_timedout,
			conf_listen->network.recv_timeout * 1000);
	conf_listen->network.send_timer_group = loop_group_timer_head_new(phl_loop,
			phl_connection_send_timedout,
			conf_listen->network.send_timeout * 1000);
}

void phl_connection_conf_timers_free(struct phl_conf_listen *conf_listen)
{
	if (conf_listen->network.recv_timer_group == NULL) {
		return;
	}
	loop_group_timer_head_delete(conf_listen->network.recv_timer_group);
	loop_group_timer_head_delete(conf_listen->network.send_timer_group);
	loop_group_timer_head_delete(conf_listen->http1.keepalive_timer_group);
	loop_group_timer_head_delete(conf_listen->http2.idle_timer_group);
}

void phl_connection_add_listen_event(int fd, struct phl_conf_listen *conf_listen)
{
	loop_tcp_listen_t *ev = loop_tcp_listen_fd(phl_loop, fd,
			&phl_connection_listen_ops, &phl_connection_stream_ops);

	loop_tcp_listen_set_app_data(ev, conf_listen);
}

struct wuy_cflua_command phl_conf_listen_network_commands[] = {
	{	.name = "connections",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_conf_listen, network.connections),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "recv_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_conf_listen, network.recv_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "send_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_conf_listen, network.send_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "recv_buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_conf_listen, network.recv_buffer_size),
		.default_value.n = 16 * 1024,
		.limits.n = WUY_CFLUA_LIMITS_LOWER(4 * 1024),
	},
	{	.name = "send_buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_conf_listen, network.send_buffer_size),
		.default_value.n = 16 * 1024,
		.limits.n = WUY_CFLUA_LIMITS_LOWER(4 * 1024),
	},
	{	.name = "backlog",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_conf_listen, network.backlog),
		.default_value.n = 1000,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "reuse_port",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_conf_listen, network.reuse_port),
	},
	{	.name = "defer_accept",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_conf_listen, network.defer_accept),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{ NULL }
};

void phl_connection_init(void)
{
	loop_defer_add(phl_loop, phl_connection_defer_routine, NULL);
}
