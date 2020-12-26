#ifndef H2D_CONNECTION_H
#define H2D_CONNECTION_H

struct h2d_connection;

struct h2d_connection {
	/* set on created */
	struct h2d_conf_listen	*conf_listen;
	struct sockaddr		client_addr; // XXX add padding
	loop_stream_t		*loop_stream;

	/* set by SSL SNI if any */
	struct h2d_conf_host	*ssl_sni_conf_host;

	bool			closed;

	bool			is_http2;
	union {
		http2_connection_t	*h2c;
		struct h2d_request	*request;
	} u;

	loop_group_timer_t	*recv_timer;
	loop_group_timer_t	*send_timer;

	uint8_t			*send_buffer;
	uint8_t			*send_buf_pos;

	wuy_list_node_t		list_node;
};

static inline bool h2d_connection_write_blocked(struct h2d_connection *c)
{
	return c->send_buf_pos != c->send_buffer;
}

static inline void h2d_connection_set_recv_timer(struct h2d_connection *c)
{
	loop_group_timer_set(c->conf_listen->network.recv_timer_group, c->recv_timer);
}

int h2d_connection_make_space(struct h2d_connection *c, int size);

void h2d_connection_set_idle(struct h2d_connection *c);

void h2d_connection_close(struct h2d_connection *c);

const char *h2d_connection_listen_conf(struct h2d_conf_listen *conf_listen);

void h2d_connection_add_listen_event(void);

void h2d_connection_init(void);

extern struct wuy_cflua_command h2d_conf_listen_network_commands[];

#endif
