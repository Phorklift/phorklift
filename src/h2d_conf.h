#ifndef H2D_CONF_H
#define H2D_CONF_H

#include <stdbool.h>
#include <openssl/ossl_typ.h>
#include <lua5.1/lua.h>

#include "h2d_module.h"

struct h2d_conf_path {
	char			**pathnames;

	bool			(*req_hook)(void);

	struct h2d_log		*error_log;

	struct h2d_module	*content;

	void			*module_confs[H2D_MODULE_MAX];
	int			content_meta_levels[H2D_MODULE_MAX];
};

struct h2d_conf_host {
	char			**hostnames;

	struct h2d_conf_path	**paths;
	struct h2d_conf_path	*default_path;

	struct {
		SSL_CTX		*ctx;
		const char	*certificate;
		const char	*private_key;
		const char	*ticket_secret;
		int		ticket_timeout;
	} ssl;

	void			*module_confs[H2D_MODULE_MAX];
};

struct h2d_conf_listen {
	char			**addresses;

	SSL_CTX			*ssl_ctx;

	struct h2d_conf_host	**hosts;
	struct h2d_conf_host	*default_host;

	wuy_dict_t		*host_dict;
	struct h2d_conf_host	*host_wildcard;

	struct {
		int		idle_timeout;
		int		ping_interval;

		loop_group_timer_t	*idle_timer_group;
	} http2;

	struct {
		int		keepalive_timeout;

		loop_group_timer_t	*keepalive_timer_group;
	} http1;

	struct {
		long		current; // TODO shared-mem
		int		connections;
		int		send_timeout;
		int		recv_timeout;
		int		send_buffer_size;

		loop_group_timer_t	*send_timer_group;
		loop_group_timer_t	*recv_timer_group;
	} network;

	void			*module_confs[H2D_MODULE_MAX];
};

extern lua_State *h2d_L;

struct h2d_conf_listen **h2d_conf_parse(const char *conf_file);

struct h2d_conf_host *h2d_conf_listen_search_hostname(
		struct h2d_conf_listen *conf_listen, const char *name);

struct h2d_conf_path *h2d_conf_host_search_pathname(
		struct h2d_conf_host *conf_host, const char *name);

/* internal */
extern struct wuy_cflua_table h2d_conf_listen_table;
extern struct wuy_cflua_table h2d_conf_host_table;
extern struct wuy_cflua_table h2d_conf_path_table;

#endif
