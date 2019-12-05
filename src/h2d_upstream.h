#ifndef H2D_UPSTREAM_H
#define H2D_UPSTREAM_H

void h2d_upstream_init(void);

struct h2d_upstream;

struct h2d_upstream_connection {
	struct h2d_upstream	*upstream;

	loop_stream_t		*loop_stream;

	struct h2d_request	*request; /* NULL if in idle state */

	uint8_t			*send_buffer;
	int			send_buf_len;

	wuy_list_node_t		list_node;
};


extern struct wuy_cflua_table h2d_upstream_conf_table;

bool h2d_upstream_conf_is_enable(struct h2d_upstream *conf);

struct h2d_upstream_connection *
h2d_upstream_get_connection(struct h2d_upstream *upstream);

void h2d_upstream_release_connection(struct h2d_upstream_connection *upc);

int h2d_upstream_connection_write(struct h2d_upstream_connection *upc, void *data, int data_len);

#endif
