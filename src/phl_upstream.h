#ifndef PHL_UPSTREAM_H
#define PHL_UPSTREAM_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>

/* calculate PHL_UPSTREAM_LOADBALANCE_STATIC_NUMBER in preprocess */
enum _ups_nonuse {
	#define X(m) phl_upstream_index_##m,
	PHL_UPSTREAM_LOADBALANCE_X_LIST
	#undef X

	PHL_UPSTREAM_LOADBALANCE_STATIC_NUMBER
};

#define PHL_UPSTREAM_LOADBALANCE_MAX	(PHL_MODULE_STATIC_NUMBER + PHL_MODULE_DYNAMIC_MAX)

struct phl_upstream_stats {
	atomic_long		pick_fail;
	atomic_long		retry;
};

struct phl_upstream_address_stats {
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

struct phl_upstream_connection {
	struct phl_upstream_address	*address;

	loop_stream_t		*loop_stream;

	uint8_t			*preread_buf;
	int			preread_len;

	int			prewrite_len;

	bool			error;

	struct phl_request	*request; /* NULL if in idle state */

	long			create_time;

	wuy_list_node_t		list_node;
};

struct phl_upstream_address {
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

	struct phl_upstream_conf	*upstream;

	struct phl_upstream_address_stats	*stats;
};


struct phl_upstream_hostname {
	const char		*name;
	bool			need_resolved;
	int			host_len;
	unsigned short		port;
	double			weight;
	wuy_list_t		address_head;
};

struct phl_upstream_loadbalance {
	const char			*name;
	int				index;
	struct wuy_cflua_command	command;
	void *				(*ctx_new)(void);
	void				(*ctx_free)(void *);
	void 				(*update)(struct phl_upstream_conf *);
	struct phl_upstream_address *	(*pick)(struct phl_upstream_conf *, struct phl_request *);
};

struct phl_upstream_ops {
	/* build request into phl_upstream_content_ctx.req_buf/req_len,
	 * and return PHL_OK if successful. */
	int	(*build_request)(struct phl_request *r);

	/* optional bellow */
	int	(*parse_response_headers)(struct phl_request *r,
			const char *buffer, int buf_len, bool *is_done);

	bool	(*is_response_body_done)(struct phl_request *r);

	int	(*build_response_body)(struct phl_request *r, uint8_t *buffer,
			int data_len, int buf_size);
};

/* make sure the `phl_upstream_conf *` at top of your module's conf */
struct phl_upstream_conf {
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

	struct phl_ssl_client_conf	*ssl;

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

	struct phl_log			*log;

	struct phl_dynamic_conf		dynamic;
	wuy_list_t			wait_head;

	struct phl_upstream_hostname	*hostnames;
	int				hostname_num;

	wuy_list_t			address_head;
	int				address_num;

	pthread_mutex_t				*address_stats_lock;
	struct phl_upstream_address_stats	*address_stats_start;

	wuy_list_t			deleted_address_defer;

	/* resolve */
	int				resolve_index;
	bool				resolve_updated;
	loop_stream_t			*resolve_stream;
	loop_timer_t			*resolve_timer;

	/* stats */
	struct phl_upstream_stats	*stats;

	/* loadbalances */
	struct phl_upstream_loadbalance	*loadbalance;
	void				*lb_confs[PHL_UPSTREAM_LOADBALANCE_MAX];
	void				*lb_ctx;

	struct phl_upstream_ops		*ops;

	wuy_list_node_t			list_node;
};


/* {{{ defined in phl_upstream_content.c and used by other modules, i.e. proxy. */
struct phl_upstream_content_ctx {
	bool				has_sent_request;
	int				retries;
	char				*req_buf;
	int				req_len;
	struct phl_upstream_connection	*upc;
	void				*data;
};
void phl_upstream_content_ctx_free(struct phl_request *r);

const char *phl_upstream_content_set_ops(struct phl_upstream_conf *conf,
		struct phl_upstream_ops *ops);

int phl_upstream_content_generate_response_headers(struct phl_request *r);
int phl_upstream_content_generate_response_body(struct phl_request *r,
		uint8_t *buffer, int buf_len);
#define PHL_UPSTREAM_CONTENT { \
	.response_headers = phl_upstream_content_generate_response_headers, \
	.response_body = phl_upstream_content_generate_response_body, \
}
/* }}} */


/* {{{ defined in phl_upstream.c and used by phl_upstream_content.c */
struct phl_upstream_connection *
phl_upstream_get_connection(struct phl_upstream_conf *upstream, struct phl_request *r);

struct phl_upstream_connection *
phl_upstream_retry_connection(struct phl_upstream_connection *old);

void phl_upstream_release_connection(struct phl_upstream_connection *upc, bool is_clean);

int phl_upstream_connection_read(struct phl_upstream_connection *upc,
		void *buffer, int buf_len);
void phl_upstream_connection_read_notfinish(struct phl_upstream_connection *upc,
		void *buffer, int buf_len);

int phl_upstream_connection_write(struct phl_upstream_connection *upc,
		const void *data, int data_len);

void phl_upstream_connection_fail(struct phl_upstream_connection *upc);
/* }}} */


/* {{{ defined in phl_upstream_healthcheck.c and used by phl_upstream_resolve.c */
void phl_upstream_healthcheck_start(struct phl_upstream_address *address);
void phl_upstream_healthcheck_stop(struct phl_upstream_address *address);

extern struct wuy_cflua_command phl_upstream_healthcheck_commands[];
/* }}} */


bool phl_upstream_address_is_pickable(struct phl_upstream_address *address,
		struct phl_request *r);

void phl_upstream_stats(wuy_json_t *json);

void phl_upstream_init(void);

void phl_upstream_dynamic_module_fix(struct phl_upstream_loadbalance *m, int i);

extern struct wuy_cflua_table phl_upstream_conf_table;

#endif
