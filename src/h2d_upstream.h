#ifndef H2D_UPSTREAM_H
#define H2D_UPSTREAM_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>

struct h2d_upstream_stats {
	atomic_int		total;
	atomic_int		reuse;
	atomic_int		pick_fail;
};

struct h2d_upstream_connection {
	struct h2d_upstream_address	*address;

	loop_stream_t		*loop_stream;

	uint8_t			*preread_buf;
	int			preread_len;

	struct h2d_request	*request; /* NULL if in idle state */

	wuy_list_node_t		list_node;
};

struct h2d_upstream_address {
	union {
		struct sockaddr		s;
		struct sockaddr_in	sin;
		struct sockaddr_in6	sin6;
		struct sockaddr_un	sun;
	} sockaddr;

	bool			deleted;
	bool			down;
	int			idle_num;
	wuy_list_t		idle_head;
	wuy_list_t		active_head;
	wuy_list_node_t		upstream_node;
	wuy_list_node_t		hostname_node;
	struct h2d_upstream_conf	*upstream;
};

struct h2d_upstream_hostname {
	char			*name; /* must at top */
	bool			need_resolved;
	unsigned short		port;
	wuy_list_t		address_head;
};

struct h2d_upstream_loadbalance {
	const char			*name;
	void 				(*init)(struct h2d_upstream_conf *);
	void 				(*update)(struct h2d_upstream_conf *);
	struct h2d_upstream_address *	(*pick)(struct h2d_upstream_conf *, struct h2d_request *);
};

struct h2d_upstream_conf {
	/* configrations */
	struct h2d_upstream_hostname	*hostnames;
	int				recv_buffer_size;
	int				send_buffer_size;
	int				idle_max;
	int				default_port;
	int				resolve_interval;
	int				read_timeout; // read or recv?
	int				write_timeout;
	int				idle_timeout;
	bool				ssl_enable;

	wuy_list_t			address_head;
	int				address_num;

	/* resolve */
	time_t				resolve_last;
	int				resolve_index;
	bool				resolve_updated;
	loop_stream_t			*resolve_stream;

	/* stats */
	struct h2d_upstream_stats	*stats;

	/* loadbalances */
	struct h2d_upstream_loadbalance	*loadbalance;
	void				*lb_ctx;

	/* configrations of loadbalances
	 * Add configrations here if you add a new loadbalance. */
	wuy_cflua_function_t		hash;
};

extern struct wuy_cflua_table h2d_upstream_conf_table;

struct h2d_upstream_connection *
h2d_upstream_get_connection(struct h2d_upstream_conf *upstream, struct h2d_request *r);

void h2d_upstream_release_connection(struct h2d_upstream_connection *upc);

int h2d_upstream_connection_read(struct h2d_upstream_connection *upc,
		void *buffer, int buf_len);
void h2d_upstream_connection_read_notfinish(struct h2d_upstream_connection *upc,
		void *buffer, int buf_len);

int h2d_upstream_connection_write(struct h2d_upstream_connection *upc,
		void *data, int data_len);

int h2d_upstream_conf_stats(void *data, char *buf, int len);

void h2d_upstream_init(void);

#endif
