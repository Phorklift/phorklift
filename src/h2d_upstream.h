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
	atomic_long		pick_fail;
	atomic_long		total;
	atomic_long		reuse;
	atomic_long		retry;
};

struct h2d_upstream_connection {
	struct h2d_upstream_address	*address;

	loop_stream_t		*loop_stream;

	uint8_t			*preread_buf;
	int			preread_len;

	struct h2d_request	*request; /* NULL if in idle state */

	long			create_time;

	wuy_list_node_t		list_node;
};

struct h2d_upstream_address {
	union {
		struct sockaddr		s;
		struct sockaddr_in	sin;
		struct sockaddr_in6	sin6;
		struct sockaddr_un	sun;
	} sockaddr;

	const char		*name;

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

	struct {
		time_t		create_time;
		long		pick;
		long		reuse;
		long		down;
		long		connected;
		long		connect_acc_ms;
	} stats;
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

struct h2d_upstream_ops {
	/* build request into h2d_upstream_content_ctx.req_buf/req_len,
	 * and return H2D_OK if successful. */
	int	(*build_request)(struct h2d_request *r);

	/* optional bellow */
	void	*(*new_ctx)(struct h2d_request *r);
	int	(*parse_response_headers)(struct h2d_request *r,
			const char *buffer, int buf_len, bool *is_done);
	bool	(*is_response_body_done)(struct h2d_request *r);
	int	(*build_response_body)(struct h2d_request *r, uint8_t *buffer,
			int data_len, int buf_size);
};

/* make sure the `h2d_upstream_conf *` at top of your module's conf */
struct h2d_upstream_conf {
	/* configrations */
	struct h2d_upstream_hostname	*hostnames;
	const char			*name;
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
		bool			is_name_blocking;
		wuy_cflua_function_t	get_name;
		wuy_cflua_function_t	get_conf;
		wuy_dict_t		*sub_dict;

		wuy_dict_node_t		dict_node;
		wuy_list_t		wait_head;
	} dynamic;

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
	wuy_list_t			deleted_address_defer;

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

	struct h2d_upstream_ops		*ops;

	wuy_list_node_t			list_node;
};


/* {{{ defined in h2d_upstream_content.c and used by other modules, i.e. proxy.
 *     Make sure the `h2d_upstream_content_ctx` at the top of your module ctx. */
struct h2d_upstream_content_ctx {
	bool				has_sent_request;
	int				retries;
	char				*req_buf;
	int				req_len;
	struct h2d_upstream_connection	*upc;
};
void h2d_upstream_content_ctx_free(struct h2d_request *r);

bool h2d_upstream_content_set_ops(struct h2d_upstream_conf *conf,
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

bool h2d_upstream_address_is_pickable(struct h2d_upstream_address *address);

void h2d_upstream_stats(wuy_json_ctx_t *json);

void h2d_upstream_init(void);

extern struct wuy_cflua_table h2d_upstream_conf_table;

#endif
