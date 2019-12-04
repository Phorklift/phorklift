#ifndef H2D_UPSTREAM_H
#define H2D_UPSTREAM_H

void h2d_upstream_init(void);

struct h2d_upstream;

struct h2d_upstream_connection;

extern struct wuy_cflua_table h2d_upstream_conf_table;

bool h2d_upstream_conf_is_enable(struct h2d_upstream *conf);
bool h2d_upstream_conf_on_response(struct h2d_upstream *conf, bool (*on_response)(struct h2d_request *));

struct h2d_upstream_connection *h2d_upstream_get_connection(struct h2d_upstream *upstream,
		struct h2d_request *r);

void h2d_upstream_release_connection(struct h2d_upstream_connection *upc);

int h2d_upstream_connection_write(struct h2d_upstream_connection *upc, void *data, int data_len);

#endif
