#include "h2d_main.h"

static void h2d_connection_close(struct h2d_connection *c)
{
	if (c->closed) {
		return;
	}
	c->closed = true;

	if (c->is_http2) {
		http2_connection_close(c->u.h2c);
		c->u.h2c = NULL;

	} else if (c->u.request != NULL) {
		h2d_request_close(c->u.request);
		c->u.request = NULL;
	}

	// TODO loop_stream_write() before close??
	loop_stream_close(c->loop_stream);
	c->loop_stream = NULL;

	free(c->send_buffer);
	c->send_buffer = c->send_buf_pos = NULL;

	free(c);
}

int h2d_connection_flush(struct h2d_connection *c)
{
	if (c->closed) {
		return H2D_ERROR;
	}

	int buf_len = c->send_buf_pos - c->send_buffer;
	if (buf_len == 0) {
		return H2D_OK;
	}

	if (c->loop_stream == NULL) { /* fake connection of subrequest */
		// TODO wake up father request
		return H2D_OK;
	}

	int write_len = loop_stream_write(c->loop_stream, c->send_buffer, buf_len);
	if (write_len < 0) {
		return H2D_ERROR;
	}
	if (write_len == 0) {
		return H2D_AGAIN;
	}

	if (write_len == buf_len) {
		c->send_buf_pos = c->send_buffer;
		return H2D_OK;
	} else {
		memmove(c->send_buffer, c->send_buffer + write_len, buf_len - write_len);
		c->send_buf_pos -= write_len;
		return H2D_AGAIN;
	}
}

int h2d_connection_make_space(struct h2d_connection *c, int size)
{
	assert(size <= H2D_CONNECTION_SENDBUF_SIZE);
	if (c->send_buffer + H2D_CONNECTION_SENDBUF_SIZE - c->send_buf_pos >= size) {
		return H2D_OK;
	}
	return h2d_connection_flush(c);
}

static int h2d_connection_on_read(loop_stream_t *s, void *data, int len)
{
	struct h2d_connection *c = loop_stream_get_app_data(s);
	// printf("on_read %d %p\n", len, c->h2c);

	int proc_len;
	if (c->is_http2) {
		proc_len = h2d_http2_on_read(c, data, len);
	} else {
		proc_len = h2d_http1_on_read(c, data, len);
	}

	h2d_connection_flush(c);

	return proc_len;
}

static void h2d_connection_on_writable(loop_stream_t *s)
{
	struct h2d_connection *c = loop_stream_get_app_data(s);

	if (h2d_connection_flush(c) != H2D_OK) {
		return;
	}

	if (c->is_http2) {
		h2d_http2_on_writable(c);
	} else {
		h2d_http1_on_writable(c);
	}

	h2d_connection_flush(c);
}

static void h2d_connection_on_close(loop_stream_t *s, enum loop_stream_close_reason reason)
{
	printf(" -- stream close %s, SSL: %s\n", loop_stream_close_string(reason),
			h2d_ssl_stream_error_string(s));
	if (reason == LOOP_STREAM_READ_ERROR || reason == LOOP_STREAM_WRITE_ERROR) {
		printf("errno: %s\n", strerror(errno));
	}

	h2d_connection_close(loop_stream_get_app_data(s));
}

static bool h2d_connection_on_accept(loop_tcp_listen_t *loop_listen,
		loop_stream_t *s, struct sockaddr *addr)
{
	struct h2d_conf_listen *conf_listen = loop_tcp_listen_get_app_data(loop_listen);

	struct h2d_connection *c = malloc(sizeof(struct h2d_connection));
	if (c == NULL) {
		return false;
	}
	bzero(c, sizeof(struct h2d_connection));
	c->client_addr = *addr;
	c->send_buffer = malloc(H2D_CONNECTION_SENDBUF_SIZE);
	c->send_buf_pos = c->send_buffer;
	c->conf_listen = conf_listen;
	c->loop_stream = s;
	loop_stream_set_app_data(s, c);

	/* set ssl */
	if (conf_listen->ssl_ctx != NULL) {
		h2d_ssl_stream_set(s, conf_listen->ssl_ctx, true);
	}

	return true;
}

static loop_tcp_listen_ops_t h2d_connection_listen_ops = {
	.reuse_port = true,
	.on_accept = h2d_connection_on_accept,
};
static loop_stream_ops_t h2d_connection_stream_ops = {
	.on_read = h2d_connection_on_read,
	.on_close = h2d_connection_on_close,
	.on_writable = h2d_connection_on_writable,

	.underlying_read = h2d_ssl_stream_underlying_read,
	.underlying_write = h2d_ssl_stream_underlying_write,
	.underlying_close = h2d_ssl_stream_underlying_close,
};

void h2d_connection_listen(wuy_array_t *listens)
{
	struct h2d_conf_listen *conf_listen;
	wuy_array_iter_ppval(listens, conf_listen) {

		const char *addr;
		wuy_array_iter_ppval(&conf_listen->addresses, addr) {
			loop_tcp_listen_t *loop_listen = loop_tcp_listen(h2d_loop,
					addr, &h2d_connection_listen_ops,
					&h2d_connection_stream_ops);

			if (loop_listen == NULL) {
				perror("listen fail");
				exit(H2D_EXIT_LISTEN);
			}

			loop_tcp_listen_set_app_data(loop_listen, conf_listen);
		}
	}
}
