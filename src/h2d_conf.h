#ifndef H2D_CONF_H
#define H2D_CONF_H

#include <stdbool.h>
#include <openssl/ssl.h>
#include <lua.h>

#include "h2d_module.h"

struct h2d_conf_path {
	wuy_array_t		pathnames;

	bool			(*req_hook)(void);

	struct h2d_module	*content;

	void			*module_confs[H2D_MODULE_NUMBER];
};

struct h2d_conf_host {
	wuy_array_t		hostnames;

	wuy_array_t		paths;

	struct {
		SSL_CTX		*ctx;
		const char	*certificate;
		const char	*private_key;
		const char	*ticket_secret;
		int		ticket_timeout;
	} ssl;

	void			*module_confs[H2D_MODULE_NUMBER];
};

struct h2d_conf_listen {
	wuy_array_t		addresses;

	SSL_CTX			*ssl_ctx;

	wuy_array_t		hosts;

	wuy_dict_t		*host_dict;
	struct h2d_conf_host	*host_default;

	struct {
		int		keepalive_timeout;
		int		ping_interval;
	} http2;

	struct {
		int		connections;
		int		read_timeout;
		int		write_timeout;
	} network;

	void			*module_confs[H2D_MODULE_NUMBER];
};

extern lua_State *h2d_L;

wuy_array_t *h2d_conf_parse(const char *defaults_file, const char *conf_file);

bool h2d_conf_is_zero_function(wuy_cflua_function_t f);

struct h2d_conf_host *h2d_conf_listen_search_hostname(
		struct h2d_conf_listen *conf_listen, const char *name);

struct h2d_conf_path *h2d_conf_host_search_pathname(
		struct h2d_conf_host *conf_host, const char *name);

/* internal */
extern struct wuy_cflua_table h2d_conf_listen_table;
extern struct wuy_cflua_table h2d_conf_host_table;
extern struct wuy_cflua_table h2d_conf_path_table;

#endif
