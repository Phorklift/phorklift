#ifndef H2D_UPSTREAM_H
#define H2D_UPSTREAM_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>

/* calculate H2D_UPSTREAM_LOADBALANCE_STATIC_NUMBER in preprocess */
struct _ups_nonuse {
	#define X(m) char m;
	H2D_UPSTREAM_LOADBALANCE_X_LIST
	#undef X
};
#define H2D_UPSTREAM_LOADBALANCE_STATIC_NUMBER (sizeof(struct _ups_nonuse) / sizeof(char))

#define H2D_UPSTREAM_LOADBALANCE_DYNAMIC_MAX	20
#define H2D_UPSTREAM_LOADBALANCE_MAX		(H2D_MODULE_STATIC_NUMBER + H2D_MODULE_DYNAMIC_MAX)

struct h2d_upstream_stats {
	atomic_int		total;
	atomic_int		reuse;
	atomic_int		retry;
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
	time_t			down_time;
	int			healthchecks;
	int			fails;
	int			idle_num;
	wuy_list_t		idle_head;
	wuy_list_t		active_head;
	wuy_list_node_t		upstream_node;
	wuy_list_node_t		hostname_node;
	wuy_list_node_t		down_node;
	double			weight;
	struct h2d_upstream_conf	*upstream;
};

struct h2d_upstream_hostname {
	char			*name; /* must at top */
	bool			need_resolved;
	unsigned short		port;
	double			weight;
	wuy_list_t		address_head;
};

struct h2d_upstream_loadbalance {
	const char			*name;
	int				index;
	struct wuy_cflua_command	command;
	void 				(*update)(struct h2d_upstream_conf *);
	struct h2d_upstream_address *	(*pick)(struct h2d_upstream_conf *, struct h2d_request *);
};

struct h2d_upstream_conf {
	/* configrations */
	struct h2d_upstream_hostname	*hostnames;
	int				idle_max;
	int				idle_timeout;
	int				recv_timeout;
	int				send_timeout;
	int				fails;
	int				max_retries;
	int				*retry_status_codes;
	int				default_port;
	int				resolve_interval;
	bool				ssl_enable;

	struct {
		int			repeats;
		int			interval;
		const char		*req_str;
		int			req_len;
		const char		*resp_str;
		int			resp_len;
	} healthcheck;

	wuy_list_t			address_head;
	int				address_num;

	wuy_list_t			down_head;

	SSL_CTX				*ssl_ctx;

	/* resolve */
	time_t				resolve_last;
	int				resolve_index;
	bool				resolve_updated;
	loop_stream_t			*resolve_stream;

	/* stats */
	struct h2d_upstream_stats	*stats;

	/* loadbalances */
	struct h2d_upstream_loadbalance	*loadbalance;
	void				*lb_confs[H2D_UPSTREAM_LOADBALANCE_MAX];
};

struct h2d_upstream_ctx {
	bool				has_sent_request;
	int				retries;
	char				*req_buf;
	int				req_len;
	struct h2d_upstream_connection	*upc;
};

typedef int (*parse_f)(struct h2d_request *r,
		const char *buffer, int buf_len, bool *is_done);

int h2d_upstream_generate_response_headers(struct h2d_request *r,
		struct h2d_upstream_ctx *ctx, parse_f parse);
void h2d_upstream_ctx_free(struct h2d_upstream_ctx *ctx);

extern struct wuy_cflua_table h2d_upstream_conf_table;

struct h2d_upstream_connection *
h2d_upstream_get_connection(struct h2d_upstream_conf *upstream, struct h2d_request *r);

struct h2d_upstream_connection *
h2d_upstream_retry_connection(struct h2d_upstream_connection *old);

void h2d_upstream_release_connection(struct h2d_upstream_connection *upc);

int h2d_upstream_connection_read(struct h2d_upstream_connection *upc,
		void *buffer, int buf_len);
void h2d_upstream_connection_read_notfinish(struct h2d_upstream_connection *upc,
		void *buffer, int buf_len);

int h2d_upstream_connection_write(struct h2d_upstream_connection *upc,
		void *data, int data_len);

void h2d_upstream_connection_fail(struct h2d_upstream_connection *upc);

bool h2d_upstream_address_is_pickable(struct h2d_upstream_address *address);

static inline bool h2d_upstream_connection_write_blocked(struct h2d_upstream_connection *upc)
{
	return loop_stream_is_write_blocked(upc->loop_stream);
}

void h2d_upstream_address_add(struct h2d_upstream_conf *upstream,
		struct h2d_upstream_hostname *hostname, struct sockaddr *sockaddr,
		struct h2d_upstream_address *before);
void h2d_upstream_address_delete(struct h2d_upstream_address *address);

int h2d_upstream_conf_stats(void *data, char *buf, int len);

void h2d_upstream_init(void);
void h2d_upstream_worker_init(void);

#endif
