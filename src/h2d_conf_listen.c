#include "h2d_main.h"

void h2d_conf_listen_stats(struct h2d_conf_listen *conf_listen, wuy_json_ctx_t *json)
{
	struct h2d_conf_listen_stats *stats = conf_listen->stats;
	wuy_json_object_int(json, "fail_no_host", atomic_load(&stats->fail_no_host));
	wuy_json_object_int(json, "connections", atomic_load(&stats->connections));
	wuy_json_object_int(json, "total", atomic_load(&stats->total));
}

static int h2d_conf_listen_name(void *data, char *buf, int size)
{
	struct h2d_conf_listen *conf_listen = data;
	return snprintf(buf, size, "Listen(%s)>", conf_listen->addresses[0]);
}

const char *h2d_conf_host_register(struct h2d_conf_listen *conf_listen);

static const char *h2d_conf_listen_post(void *data)
{
	struct h2d_conf_listen *conf_listen = data;

	if (conf_listen->name == NULL) {
		conf_listen->name = conf_listen->addresses[0];
	}

	const char *err_addr = h2d_connection_listen_conf(conf_listen);
	if (err_addr != NULL) {
		wuy_cflua_post_arg = err_addr;
		return "listen address";
	}

	conf_listen->stats = wuy_shmpool_alloc(sizeof(struct h2d_conf_listen_stats));

	/* if no Host() is set in Listen(), use default_host */
	if (conf_listen->hosts == NULL) {
		struct h2d_conf_host *default_host = conf_listen->default_host;
		if (default_host->default_path->content == NULL) {
			return "no Host defined in Listen";
		}
		if (default_host->ssl->ctx != NULL) {
			conf_listen->ssl_ctx = default_host->ssl->ctx;
		}
		return WUY_CFLUA_OK;
	}

	/* register Host() */
	const char *err = h2d_conf_host_register(conf_listen);
	if (err != WUY_CFLUA_OK) {
		return err;
	}

	/* ssl */
	bool is_ssl = false, is_plain = false;
	struct h2d_conf_host *conf_host;
	for (int i = 0; (conf_host = conf_listen->hosts[i]) != NULL; i++) {
		if (conf_host->ssl->ctx != NULL) {
			is_ssl = true;
		} else {
			is_plain = true;
		}
	}
	if (is_ssl) {
		if (is_plain) {
			return "use ssl or not consistent amount Host() under one Listen()";
		}

		if (conf_listen->default_host->ssl->ctx != NULL) {
			conf_listen->ssl_ctx = conf_listen->default_host->ssl->ctx;
		} else if (conf_listen->host_wildcard != NULL) {
			conf_listen->ssl_ctx = conf_listen->host_wildcard->ssl->ctx;
		} else {
			conf_listen->ssl_ctx = h2d_ssl_ctx_empty_server();
		}
	}

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_conf_listen_commands[] = {
	{	.name = "_addresses",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, addresses),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, hosts),
		.u.table = &h2d_conf_host_table,
		.is_extra_commands = true,
	},
	{	.name = "_default_next",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, default_host),
		.u.table = &h2d_conf_host_table,
	},
	{	.name = "name",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_conf_listen, name),
	},
	{	.name = "http1",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { h2d_conf_listen_http1_commands },
	},
	{	.name = "http2",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { h2d_conf_listen_http2_commands },
	},
	{	.name = "network",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { h2d_conf_listen_network_commands },
	},
	{	.type = WUY_CFLUA_TYPE_END,
		.u.next = h2d_module_next_listen_command,
	},
};

struct wuy_cflua_table h2d_conf_listen_table = {
	.commands = h2d_conf_listen_commands,
	.size = sizeof(struct h2d_conf_listen),
	.post = h2d_conf_listen_post,
	.name = h2d_conf_listen_name,
};
