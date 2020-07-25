#ifndef H2D_CONNECTION_H
#define H2D_CONNECTION_H

struct h2d_connection;

struct h2d_connection {
	/* set on created */
	struct h2d_conf_listen	*conf_listen;
	struct sockaddr		client_addr;
	loop_stream_t		*loop_stream;

	/* set by SSL SNI if any */
	struct h2d_conf_host	*ssl_sni_conf_host;

	bool			closed;

	bool			is_http2;
	union {
		http2_connection_t	*h2c;
		struct h2d_request	*request;
	} u;

	loop_timer_t		*recv_timer;
	loop_timer_t		*send_timer;

	time_t			last_recv_ts;

	uint8_t			*send_buffer;
	uint8_t			*send_buf_pos;

	wuy_list_node_t		list_node;
};

void h2d_connection_listen(wuy_array_t *listens);

static inline bool h2d_connection_write_blocked(struct h2d_connection *c)
{
	return c->send_buf_pos != c->send_buffer;
}

int h2d_connection_make_space(struct h2d_connection *c, int size);

void h2d_connection_close(struct h2d_connection *c);

#endif
