#include "phl_main.h"

void phl_conf_listen_stats(struct phl_conf_listen *conf_listen, wuy_json_t *json)
{
	struct phl_conf_listen_stats *stats = conf_listen->stats;
	wuy_json_object_int(json, "fail_no_host", atomic_load(&stats->fail_no_host));
	wuy_json_object_int(json, "connections", atomic_load(&stats->connections));
	wuy_json_object_int(json, "total", atomic_load(&stats->total));
}

static int phl_conf_listen_name(void *data, char *buf, int size)
{
	struct phl_conf_listen *conf_listen = data;
	return snprintf(buf, size, "Listen(%s)>", conf_listen->addresses[0]);
}

const char *phl_conf_host_register(struct phl_conf_listen *conf_listen);

void phl_conf_listen_init_worker(void)
{
	for (int i = 0; phl_conf_listens[i] != NULL; i++) {
		struct phl_conf_listen *conf_listen = phl_conf_listens[i];
		for (int j = 0; j < conf_listen->address_num; j++) {
			phl_connection_add_listen_event(conf_listen->fds[j], conf_listen);
		}
	}
}

static int phl_conf_listen_reuse_fd(const char *address)
{
	if (phl_conf_listens == NULL) {
		return -1;
	}
	for (int i = 0; phl_conf_listens[i] != NULL; i++) {
		struct phl_conf_listen *conf_listen = phl_conf_listens[i];

		for (int j = 0; j < conf_listen->address_num; j++) {
			if (strcmp(conf_listen->addresses[j], address) == 0) {
				conf_listen->reuse_magics[j] = phl_conf_reload_count;
				return conf_listen->fds[j];
			}
		}
	}
	return -1;
}

/* If there is no Host defined in Listen, while some Paths are defined directly,
 * then `wuy_cflua` will still create Host (without hostnames) and parse the Path
 * as Host->default_path.
 * This function check this firstly. If yes, then move all the default_paths to
 * the conf_listen->default_host->paths and remove all the Hosts.
 * This is a little tricky. You must know how wuy_cflua works well. */
static const char *phl_conf_listen_fix_bare_paths(struct phl_conf_listen *conf_listen)
{
	/* check first */
	int host_num = 0;
	bool any_def_host = false, any_def_path = false;
	struct phl_conf_host *conf_host;
	for (int i = 0; (conf_host = conf_listen->hosts[i]) != NULL; i++) {
		host_num++;
		bool def_host = conf_host->hostnames != NULL;
		bool def_path = conf_host->default_path->pathnames != NULL;
		assert(def_host != def_path);
		if (def_host) {
			any_def_host = true;
		} else {
			any_def_path = true;

			/* Since wuy_cflua treats the Path as Host, the Host commonds
			 * are considered valid. So we check it here manually.
			 * We assume the configurations bewteen `ssl` and `stats`. */
			if (memcmp(&conf_host->ssl, &conf_listen->default_host->ssl,
					offsetof(struct phl_conf_host, stats) - offsetof(struct phl_conf_host, ssl)) != 0) {
				return "Host command can not in bare Path";
			}
		}
	}

	if (!any_def_path) {
		return WUY_CFLUA_OK;
	}
	if (any_def_host) {
		return "can not mix Host and Path";
	}

	/* move the default_paths */
	struct phl_conf_host *default_host = conf_listen->default_host;

	default_host->paths = wuy_pool_alloc(wuy_cflua_pool,
			sizeof(struct phl_conf_path *) * (host_num + 1));

	for (int i = 0; (conf_host = conf_listen->hosts[i]) != NULL; i++) {
		default_host->paths[i] = conf_host->default_path;
	}

	conf_listen->hosts = NULL; /* clean it */

	return phl_conf_host_table.post(default_host);
}

static const char *phl_conf_listen_post(void *data)
{
	struct phl_conf_listen *conf_listen = data;

	if (conf_listen->name == NULL) {
		conf_listen->name = conf_listen->addresses[0];
	}

	for (int i = 0; conf_listen->addresses[i] != NULL; i++) {
		conf_listen->address_num++;
	}

	conf_listen->fds = wuy_pool_alloc(wuy_cflua_pool,
			conf_listen->address_num * sizeof(int));
	conf_listen->reuse_magics = wuy_pool_alloc(wuy_cflua_pool,
			conf_listen->address_num * sizeof(int));

	/* listen on addresses */
	for (int i = 0; i < conf_listen->address_num; i++) {
		const char *address = conf_listen->addresses[i];

		int fd = phl_conf_listen_reuse_fd(address);
		if (fd >= 0) {
			conf_listen->reuse_magics[i] = phl_conf_reload_count;
			conf_listen->fds[i] = fd;
			continue;
		}

		struct sockaddr_storage ss;
		if (!wuy_sockaddr_loads(address, &ss, 0)) {
			errno = EINVAL;
			wuy_cflua_post_arg = address;
			return "invalid listen address";
		}
		fd = wuy_tcp_listen((struct sockaddr *)&ss, conf_listen->network.backlog,
				conf_listen->network.reuse_port);
		if (fd < 0) {
			wuy_cflua_post_arg = address;
			return "fail to listen";
		}

		wuy_tcp_set_defer_accept(fd, conf_listen->network.defer_accept);

		conf_listen->fds[i] = fd;
	}

	phl_connection_conf_timers_init(conf_listen);

	conf_listen->stats = wuy_shmpool_alloc(sizeof(struct phl_conf_listen_stats));

	/* if no Host() is set in Listen(), use default_host */
	if (conf_listen->hosts == NULL) {
		struct phl_conf_host *default_host = conf_listen->default_host;
		if (default_host->default_path->content == NULL) {
			return "no Host defined in Listen";
		}
		return WUY_CFLUA_OK;
	}

	/* if Path() is set in Listen() directly */
	const char *err = phl_conf_listen_fix_bare_paths(conf_listen);
	if (err != WUY_CFLUA_OK || conf_listen->hosts == NULL) { /* error or fixed(no Host any more) */
		return err;
	}

	/* register Host() */
	err = phl_conf_host_register(conf_listen);
	if (err != WUY_CFLUA_OK) {
		return err;
	}

	/* ssl */
	bool is_ssl = false, is_plain = false;
	struct phl_conf_host *conf_host;
	for (int i = 0; (conf_host = conf_listen->hosts[i]) != NULL; i++) {
		if (conf_host->ssl != NULL) {
			is_ssl = true;
		} else {
			is_plain = true;
		}
	}
	if (is_ssl) {
		if (is_plain) {
			return "can not mix SSL and plain amount Host() under one Listen()";
		}
		if (conf_listen->default_host->ssl == NULL) {
			conf_listen->default_host->ssl = conf_listen->hosts[0]->ssl;
		}
	}

	return WUY_CFLUA_OK;
}

static void phl_conf_listen_free(void *data)
{
	struct phl_conf_listen *conf_listen = data;

	for (int i = 0; i < conf_listen->address_num; i++) {
		if (conf_listen->reuse_magics[i] < phl_conf_reload_count) {
			close(conf_listen->fds[i]);
		}
	}

	phl_connection_conf_timers_free(conf_listen);

	if (conf_listen->host_dict != NULL) {
		wuy_dict_destroy(conf_listen->host_dict);
	}
}

static struct wuy_cflua_command phl_conf_listen_commands[] = {
	{	.name = "_addresses",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_conf_listen, addresses),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.description = "Host scope.",
		.offset = offsetof(struct phl_conf_listen, hosts),
		.inherit_container_offset = offsetof(struct phl_conf_listen, default_host),
		.u.table = &phl_conf_host_table,
	},
	{	.name = "name",
		.description = "Listen name, only for log. The first address is used if not set.",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_conf_listen, name),
	},
	{	.name = "http1",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { phl_conf_listen_http1_commands },
	},
	{	.name = "http2",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { phl_conf_listen_http2_commands },
	},
	{	.name = "network",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { phl_conf_listen_network_commands },
	},
	{	.type = WUY_CFLUA_TYPE_END,
		.u.next = phl_module_next_listen_command,
	},
};

struct wuy_cflua_table phl_conf_listen_table = {
	.commands = phl_conf_listen_commands,
	.size = sizeof(struct phl_conf_listen),
	.post = phl_conf_listen_post,
	.free = phl_conf_listen_free,
	.name = phl_conf_listen_name,
};
