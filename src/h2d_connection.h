#ifndef H2D_CONNECTION_H
#define H2D_CONNECTION_H

enum h2d_connection_state {
	H2D_CONNECTION_STATE_READING = 0,
	H2D_CONNECTION_STATE_WRITING,
	H2D_CONNECTION_STATE_IDLE,
	H2D_CONNECTION_STATE_CLOSED,
};

struct h2d_connection {
	/* set on created */
	struct h2d_conf_listen	*conf_listen;
	struct sockaddr		client_addr; // XXX add padding
	loop_stream_t		*loop_stream;

	/* set by SSL SNI if any */
	struct h2d_conf_host	*ssl_sni_conf_host;

	uint64_t		id;
	uint32_t		request_id;

	bool			is_http2;
	union {
		http2_connection_t	*h2c;
		struct h2d_request	*request;
	} u;

	enum h2d_connection_state	state;

	loop_group_timer_t	*recv_timer;
	loop_group_timer_t	*send_timer;

	uint8_t			*recv_buffer;
	int			recv_buf_pos;
	int			recv_buf_end;

	uint8_t			*send_buffer;
	int			send_buf_len;

	wuy_list_node_t		list_node;
};

bool h2d_connection_is_write_ready(struct h2d_connection *c);

int h2d_connection_make_space(struct h2d_connection *c, int size);

void h2d_connection_close(struct h2d_connection *c);

void h2d_connection_set_state(struct h2d_connection *c,
		enum h2d_connection_state state);

const char *h2d_connection_listen_conf(struct h2d_conf_listen *conf_listen);

void h2d_connection_add_listen_event(int fd, struct h2d_conf_listen *conf_listen);

void h2d_connection_conf_timers_init(struct h2d_conf_listen *conf_listen);
void h2d_connection_conf_timers_free(struct h2d_conf_listen *conf_listen);

void h2d_connection_init(void);

extern struct wuy_cflua_command h2d_conf_listen_network_commands[];

#endif
