#ifndef PHL_CONNECTION_H
#define PHL_CONNECTION_H

enum phl_connection_state {
	PHL_CONNECTION_STATE_READING = 0,
	PHL_CONNECTION_STATE_WRITING,
	PHL_CONNECTION_STATE_IDLE,
	PHL_CONNECTION_STATE_CLOSED,
};

struct phl_connection {
	/* set on created */
	struct phl_conf_listen	*conf_listen;
	struct sockaddr		client_addr; // XXX add padding
	loop_stream_t		*loop_stream;

	/* set by SSL SNI if any */
	struct phl_conf_host	*ssl_sni_conf_host;

	uint64_t		id;
	uint32_t		request_id;

	bool			is_http2;
	union {
		http2_connection_t	*h2c;
		struct phl_request	*request;
	} u;

	enum phl_connection_state	state;

	loop_group_timer_t	*recv_timer;
	loop_group_timer_t	*send_timer;

	uint8_t			*recv_buffer;
	int			recv_buf_pos;
	int			recv_buf_end;

	uint8_t			*send_buffer;
	int			send_buf_len;

	wuy_list_node_t		list_node;
};

bool phl_connection_is_write_ready(struct phl_connection *c);

int phl_connection_make_space(struct phl_connection *c, int size);

void phl_connection_close(struct phl_connection *c);

void phl_connection_set_state(struct phl_connection *c,
		enum phl_connection_state state);

const char *phl_connection_listen_conf(struct phl_conf_listen *conf_listen);

void phl_connection_add_listen_event(int fd, struct phl_conf_listen *conf_listen);

void phl_connection_conf_timers_init(struct phl_conf_listen *conf_listen);
void phl_connection_conf_timers_free(struct phl_conf_listen *conf_listen);

void phl_connection_init(void);

extern struct wuy_cflua_command phl_conf_listen_network_commands[];

#endif
