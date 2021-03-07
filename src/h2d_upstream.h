#ifndef H2D_UPSTREAM_H
#define H2D_UPSTREAM_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>

/* calculate H2D_UPSTREAM_LOADBALANCE_STATIC_NUMBER in preprocess */
enum _ups_nonuse {
	#define X(m) h2d_upstream_index_##m,
	H2D_UPSTREAM_LOADBALANCE_X_LIST
	#undef X

	H2D_UPSTREAM_LOADBALANCE_STATIC_NUMBER
};

#define H2D_UPSTREAM_LOADBALANCE_DYNAMIC_MAX	20
#define H2D_UPSTREAM_LOADBALANCE_MAX		(H2D_MODULE_STATIC_NUMBER + H2D_MODULE_DYNAMIC_MAX)

struct h2d_upstream_stats {
	atomic_long		pick_fail;
	atomic_long		retry;
};

struct h2d_upstream_address_stats {
	/* protected by lock */
	uint64_t		key;
	atomic_int		refs;

	time_t			create_time;
	atomic_long		pick;
	atomic_long		reuse;
	atomic_long		failure_down;
	atomic_long		healthcheck_down;
	atomic_long		connected;
	atomic_long		connect_acc_ms;
};

struct h2d_upstream_connection {
	struct h2d_upstream_address	*address;

	loop_stream_t		*loop_stream;

	uint8_t			*preread_buf;
	int			preread_len;

	bool			error;

	struct h2d_request	*request; /* NULL if in idle state */

	long			create_time;

	wuy_list_node_t		list_node;
};

struct h2d_upstream_address {
	const char		*name;
	double			weight;
	union {
		struct sockaddr		s;
		struct sockaddr_in	sin;
		struct sockaddr_in6	sin6;
		struct sockaddr_un	sun;
	} sockaddr;

	bool			resolve_deleted;

	struct {
		time_t		down_time;
		int		fails;
		int		passes;
	} failure; // TODO move to shmem

	struct {
		time_t		down_time;
		int		fails;
		int		passes;
		loop_timer_t	*timer;
		loop_stream_t	*stream;
	} healthcheck; // TODO move to shmem

	/* lists of connections */
	int			idle_num;
	wuy_list_t		idle_head;
	int			active_num;
	wuy_list_t		active_head;

	wuy_list_node_t		upstream_node;
	wuy_list_node_t		hostname_node;

	struct h2d_upstream_conf	*upstream;

	struct h2d_upstream_address_stats	*stats;
};


struct h2d_upstream_hostname {
	const char		*name;
	bool			need_resolved;
	int			host_len;
	unsigned short		port;
	double			weight;
	wuy_list_t		address_head;
};

struct h2d_upstream_loadbalance {
	const char			*name;
	int				index;
	struct wuy_cflua_command	command;
	void *				(*ctx_new)(void);
	void				(*ctx_free)(void *);
	void 				(*update)(struct h2d_upstream_conf *);
	struct h2d_upstream_address *	(*pick)(struct h2d_upstream_conf *, struct h2d_request *);
};

struct h2d_upstream_ops {
	/* build request into h2d_upstream_content_ctx.req_buf/req_len,
	 * and return H2D_OK if successful. */
	int	(*build_request)(struct h2d_request *r);

	/* optional bellow */
	int	(*parse_response_headers)(struct h2d_request *r,
			const char *buffer, int buf_len, bool *is_done);

	bool	(*is_response_body_done)(struct h2d_request *r);

	int	(*build_response_body)(struct h2d_request *r, uint8_t *buffer,
			int data_len, int buf_size);
};

/* make sure the `h2d_upstream_conf *` at top of your module's conf */
struct h2d_upstream_conf {
	/* configrations */
	const char			**hostnames_str; /* FORMAT: host:port#weight */
	const char			*name;
	int				idle_max;
	int				idle_timeout;
	int				recv_timeout;
	int				send_timeout;
	int				max_retries;
	int				*retry_status_codes;
	int				default_port;
	int				resolve_interval;
	int				resolved_addresses_max;
	bool				ssl_enable;

	struct {
		int			fails;
		int			passes;
		int			timeout;
		wuy_cflua_function_t	filter;
	} failure;

	struct {
		int			interval;
		int			fails;
		int			passes;
		const char		*req_str;
		int			req_len;
		const char		*resp_str;
		int			resp_len;
	} healthcheck;

	struct h2d_log			*log;

	struct h2d_dynamic_conf		dynamic;
	wuy_list_t			wait_head;

	struct h2d_upstream_hostname	*hostnames;
	int				hostname_num;

	wuy_list_t			address_head;
	int				address_num;

	pthread_mutex_t				*address_stats_lock;
	struct h2d_upstream_address_stats	*address_stats_start;

	wuy_list_t			deleted_address_defer;

	SSL_CTX				*ssl_ctx;

	/* resolve */
	int				resolve_index;
	bool				resolve_updated;
	loop_stream_t			*resolve_stream;
	loop_timer_t			*resolve_timer;

	/* stats */
	struct h2d_upstream_stats	*stats;

	/* loadbalances */
	struct h2d_upstream_loadbalance	*loadbalance;
	void				*lb_confs[H2D_UPSTREAM_LOADBALANCE_MAX];
	void				*lb_ctx;

	struct h2d_upstream_ops		*ops;

	wuy_list_node_t			list_node;
};


/* {{{ defined in h2d_upstream_content.c and used by other modules, i.e. proxy. */
struct h2d_upstream_content_ctx {
	bool				has_sent_request;
	int				retries;
	char				*req_buf;
	int				req_len;
	struct h2d_upstream_connection	*upc;
	void				*data;
};
void h2d_upstream_content_ctx_free(struct h2d_request *r);

const char *h2d_upstream_content_set_ops(struct h2d_upstream_conf *conf,
		struct h2d_upstream_ops *ops);

int h2d_upstream_content_generate_response_headers(struct h2d_request *r);
int h2d_upstream_content_generate_response_body(struct h2d_request *r,
		uint8_t *buffer, int buf_len);
#define H2D_UPSTREAM_CONTENT { \
	.response_headers = h2d_upstream_content_generate_response_headers, \
	.response_body = h2d_upstream_content_generate_response_body, \
}
/* }}} */


/* {{{ defined in h2d_upstream.c and used by h2d_upstream_content.c */
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

static inline bool h2d_upstream_connection_write_blocked(struct h2d_upstream_connection *upc)
{
	return loop_stream_is_write_blocked(upc->loop_stream);
}
/* }}} */


/* {{{ defined in h2d_upstream_healthcheck.c and used by h2d_upstream_resolve.c */
void h2d_upstream_healthcheck_start(struct h2d_upstream_address *address);
void h2d_upstream_healthcheck_stop(struct h2d_upstream_address *address);

extern struct wuy_cflua_command h2d_upstream_healthcheck_commands[];
/* }}} */


bool h2d_upstream_address_is_pickable(struct h2d_upstream_address *address,
		struct h2d_request *r);

void h2d_upstream_stats(wuy_json_t *json);

void h2d_upstream_init(void);

extern struct wuy_cflua_table h2d_upstream_conf_table;

#endif
