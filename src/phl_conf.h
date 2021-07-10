#ifndef PHL_CONF_H
#define PHL_CONF_H

#include <stdbool.h>
#include <lua5.1/lua.h>

#include "phl_module.h"
#include "phl_dynamic.h"

struct phl_conf_path_stats {
	atomic_long	total;
	atomic_long	done;

	atomic_long	lua_new;
	atomic_long	lua_again;
	atomic_long	lua_error;
	atomic_long	lua_done;
	atomic_long	lua_free;

	atomic_long	req_acc_ms;
	atomic_long	react_acc_ms;
	atomic_long	resp_acc_ms;
	atomic_long	total_acc_ms;

#define X(s, _) atomic_long status_##s;
	WUY_HTTP_STATUS_CODE_TABLE
#undef X
	atomic_long	status_others;
};

struct phl_conf_host_stats {
	atomic_long	fail_no_path;
};

struct phl_conf_listen_stats {
	atomic_long	fail_no_host;
	atomic_long	connections;
	atomic_long	total;
};

struct phl_conf_access_log {
	const char		*filename;
	float			sampling_rate;
	bool			replace_format;
	bool			enable_subrequest;
	wuy_cflua_function_t	format;
	wuy_cflua_function_t	filter;
	int			buf_size;
	int			max_line;

	struct phl_log_file	*file;
};

struct phl_conf_path {
	const char		*name;

	char			**pathnames;

	struct phl_dynamic_conf	dynamic;

	int			req_body_max;
	bool			req_body_sync;

	bool			(*req_hook)(void);

	bool			response_internal_error;

	struct phl_log		*error_log;

	struct phl_conf_access_log	*access_log;

	struct phl_module		*content;
	struct phl_module_filters	*filters;

	void				*module_confs[PHL_MODULE_MAX];
	int				content_inherit_counts[PHL_MODULE_MAX];

	struct phl_conf_path_stats	*stats;
};

struct phl_conf_host {
	const char		*name;

	char			**hostnames;

	struct phl_conf_path	**paths;
	struct phl_conf_path	*default_path;

	struct phl_ssl_conf	*ssl;

	void			*module_confs[PHL_MODULE_MAX];

	struct phl_conf_host_stats	*stats;
};

struct phl_conf_listen {
	const char		*name;

	char			**addresses;
	int			address_num;
	int			*fds;
	int			*reuse_magics;

	struct phl_conf_host	**hosts;
	struct phl_conf_host	*default_host;

	wuy_dict_t		*host_dict;
	struct phl_conf_host	*host_wildcard;
	bool			any_prefix_hostname;
	bool			any_subfix_hostname;

	struct {
		int		idle_timeout;
		int		idle_min_timeout;
		int		ping_interval;

		struct phl_log	*log;

		struct http2_settings	settings;

		loop_group_timer_head_t	*idle_timer_group;
	} http2;

	struct {
		int		keepalive_timeout;
		int		keepalive_min_timeout;

		struct phl_log	*log;

		loop_group_timer_head_t	*keepalive_timer_group;
	} http1;

	struct {
		int		connections;
		int		send_timeout;
		int		recv_timeout;
		int		recv_buffer_size;
		int		send_buffer_size;
		int		defer_accept;
		int		backlog;
		bool		reuse_port;

		loop_group_timer_head_t	*send_timer_group;
		loop_group_timer_head_t	*recv_timer_group;
	} network;

	void			*module_confs[PHL_MODULE_MAX];

	struct phl_conf_listen_stats	*stats;
};

struct phl_conf_runtime {
	const char		*pid;

	struct phl_conf_runtime_worker {
		int	num;
	} worker;

	struct phl_conf_runtime_resolver {
		int	ai_family;
	} resolver;

	struct phl_log		*error_log;

	struct phl_module_dynamic *dynamic_modules;
	struct phl_module_dynamic *dynamic_upstream_modules;
};

extern lua_State *phl_L;

extern struct phl_conf_runtime *phl_conf_runtime;
extern struct phl_conf_listen **phl_conf_listens;

extern int phl_conf_reload_count;

bool phl_conf_parse(const char *conf_file);

struct phl_conf_host *phl_conf_host_locate(struct phl_conf_listen *conf_listen,
		const char *name);

struct phl_conf_path *phl_conf_path_locate(struct phl_conf_host *conf_host,
		const char *name);

void phl_conf_listen_init_worker(void);

void phl_conf_path_stats(struct phl_conf_path *conf_path, wuy_json_t *json);
void phl_conf_host_stats(struct phl_conf_host *conf_host, wuy_json_t *json);
void phl_conf_listen_stats(struct phl_conf_listen *conf_listen, wuy_json_t *json);

void phl_conf_doc(void);

#define phl_conf_log(level, fmt, ...) \
	if (phl_conf_runtime == NULL) \
		fprintf(level < PHL_LOG_ERROR ? stdout : stderr, fmt"\n", ##__VA_ARGS__); \
	else \
		phl_log_level(phl_conf_runtime->error_log, level, fmt, ##__VA_ARGS__)

#define phl_conf_log_at(_log, level, fmt, ...) \
	if (_log != NULL) { \
		phl_log_level(_log, level, fmt, ##__VA_ARGS__); \
	} else \
		phl_log_level(phl_conf_runtime->error_log, level, fmt, ##__VA_ARGS__)

/* internal */
extern struct wuy_cflua_table phl_conf_listen_table;
extern struct wuy_cflua_table phl_conf_host_table;
extern struct wuy_cflua_table phl_conf_path_table;
extern struct wuy_cflua_table phl_conf_runtime_table;

#endif
