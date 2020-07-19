#include "h2d_main.h"

static void h2d_connection_close(struct h2d_connection *c)
{
	if (c->closed) {
		return;
	}
	c->closed = true;

	if (c->is_http2) {
		http2_connection_close(c->u.h2c);

	} else if (c->u.request != NULL) {
		h2d_request_close(c->u.request);
	}

	// TODO loop_stream_write() before close??
	loop_stream_close(c->loop_stream);
	c->loop_stream = NULL;

	free(c->send_buffer);
	free(c);
}

int h2d_connection_flush(struct h2d_connection *c)
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
		return H2D_OK;
	}

	int write_len = loop_stream_write(c->loop_stream, c->send_buffer, buf_len);
	if (write_len < 0) {
		return H2D_ERROR;
	}
	if (write_len == 0) {
		return H2D_AGAIN;
	}

	if (write_len < buf_len) {
		memmove(c->send_buffer, c->send_buffer + write_len, buf_len - write_len);
		c->send_buf_pos -= write_len;
		printf(" !!! write block: %d %d\n", buf_len, write_len);
		return H2D_AGAIN;
	}

	// TODO  check any pending requests before free
	//free(c->send_buffer);
	//c->send_buf_pos = c->send_buffer = NULL;
	c->send_buf_pos = c->send_buffer;
	return H2D_OK;
}

int h2d_connection_make_space(struct h2d_connection *c, int size)
{
	int buf_size = c->conf_listen->network.send_buffer_size;
	if (c->is_http2) {
		buf_size += HTTP2_FRAME_HEADER_SIZE;
	}

	if (size > buf_size) {
		printf("   !!! fatal: too small buf_size %d\n", buf_size);
		return H2D_ERROR;
	}

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

	// TODO the buffer may be freed after flush

	return buf_size - (c->send_buf_pos - c->send_buffer);
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

	struct h2d_connection *c = calloc(1, sizeof(struct h2d_connection));
	if (c == NULL) {
		return false;
	}
	c->client_addr = *addr;
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

	H2D_SSL_LOOP_STREAM_UNDERLYINGS,
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
