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

void h2d_conf_listen_init_worker(void)
{
	for (int i = 0; h2d_conf_listens[i] != NULL; i++) {
		struct h2d_conf_listen *conf_listen = h2d_conf_listens[i];
		for (int j = 0; j < conf_listen->address_num; j++) {
			h2d_connection_add_listen_event(conf_listen->fds[j], conf_listen);
		}
	}
}

static int h2d_conf_listen_reuse_fd(const char *address)
{
	if (h2d_conf_listens == NULL) {
		return -1;
	}
	for (int i = 0; h2d_conf_listens[i] != NULL; i++) {
		struct h2d_conf_listen *conf_listen = h2d_conf_listens[i];

		for (int j = 0; j < conf_listen->address_num; j++) {
			if (strcmp(conf_listen->addresses[j], address) == 0) {
				conf_listen->reuse_magics[j] = h2d_conf_reload_count;
				return conf_listen->fds[j];
			}
		}
	}
	return -1;
}

static const char *h2d_conf_listen_post(void *data)
{
	struct h2d_conf_listen *conf_listen = data;

	if (conf_listen->name == NULL) {
		conf_listen->name = conf_listen->addresses[0];
	}

	for (int i = 0; conf_listen->addresses[i] != NULL; i++) {
		conf_listen->address_num++;
	}

	conf_listen->fds = wuy_pool_alloc(wuy_cflua_pool, conf_listen->address_num * sizeof(int));
	conf_listen->reuse_magics = wuy_pool_alloc(wuy_cflua_pool, conf_listen->address_num * sizeof(int));

	for (int i = 0; i < conf_listen->address_num; i++) {
		const char *address = conf_listen->addresses[i];

		int fd = h2d_conf_listen_reuse_fd(address);
		if (fd >= 0) {
			conf_listen->reuse_magics[i] = h2d_conf_reload_count;
			conf_listen->fds[i] = fd;
			continue;
		}

		struct sockaddr_storage ss;
		if (!wuy_sockaddr_loads(address, &ss, 0)) {
			errno = EINVAL;
			wuy_cflua_post_arg = address;
			return address;
		}
		fd = wuy_tcp_listen((struct sockaddr *)&ss, conf_listen->network.backlog,
				conf_listen->network.reuse_port);
		if (fd < 0) {
			wuy_cflua_post_arg = address;
			return address;
		}

		wuy_tcp_set_defer_accept(fd, conf_listen->network.defer_accept);

		conf_listen->fds[i] = fd;
	}

	h2d_connection_conf_timers_init(conf_listen);

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

static void h2d_conf_listen_free(void *data)
{
	struct h2d_conf_listen *conf_listen = data;

	for (int i = 0; i < conf_listen->address_num; i++) {
		if (conf_listen->reuse_magics[i] < h2d_conf_reload_count) {
			close(conf_listen->fds[i]);
		}
	}

	h2d_connection_conf_timers_free(conf_listen);
}

static struct wuy_cflua_command h2d_conf_listen_commands[] = {
	{	.name = "_addresses",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, addresses),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.description = "Host scope.",
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
		.description = "Listen name, only for log. The first address is used if not set.",
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
	.free = h2d_conf_listen_free,
	.name = h2d_conf_listen_name,
};
