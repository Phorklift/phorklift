#include "h2d_main.h"

struct h2d_conf_listen_hostname {
	const char		*name;
	struct h2d_conf_host	*conf_host;
	long			hits;
	wuy_dict_node_t		dict_node;
};

#define x_strlow(x)

struct h2d_conf_host *h2d_conf_listen_search_hostname(
		struct h2d_conf_listen *conf_listen, const char *name)
{
	if (name == NULL) {
		return conf_listen->host_default;
	}

	struct h2d_conf_listen_hostname *node = wuy_dict_get(conf_listen->host_dict, name);
	if (node != NULL) {
		return node->conf_host;
	}

	return conf_listen->host_default;
}

static bool h2d_conf_listen_add_hostname(struct h2d_conf_listen *conf_listen,
		struct h2d_conf_host *conf_host, char *name)
{
	if (name[0] == '\0') {
		printf("invalid empty host name\n");
		return false;
	}

	/* default hostname */
	if (strcmp(name, "*") == 0) {
		if (conf_listen->host_default != NULL) {
			printf("duplicate default host\n");
			return false;
		}
		conf_listen->host_default = conf_host;
		return true;
	}

	/* case insensitive */
	x_strlow(name);

	/* omit the tail dot */
	int len = strlen(name);
	if (name[len-1] == '.') {
		name[len-1] = '\0';
		len--;
	}

	const char *wild = strchr(name, '*');
	if (wild != NULL) {
		if (wild == name) {
			if (name[1] != '.') {
				printf("`.` must follows leading wildcast `*`\n");
				return false;
			}
			if (strchr(name + 1, '*') != NULL) {
				printf("at most 1 wildcast in hostname\n");
				return false;
			}
		} else if (wild == name + len - 1) {
			if (name[len-2] != '.') {
				printf("`.` must before tail wildcast `*`\n");
				return false;
			}
		} else {
			printf("wildcast `*` is not allowed in middle of hostname\n");
			return false;
		}
	}

	if (wuy_dict_get(conf_listen->host_dict, name) != NULL) {
		printf("duplicate hostname %s\n", name);
		return false;
	}

	struct h2d_conf_listen_hostname *node = malloc(sizeof(struct h2d_conf_listen_hostname));
	node->name = name;
	node->conf_host = conf_host;
	node->hits = 0;
	wuy_dict_add(conf_listen->host_dict, node);
	return true;
}

static int h2d_conf_listen_name(void *data, char *buf, int size)
{
	struct h2d_conf_listen *conf_listen = data;
	return snprintf(buf, size, "Listen(%s)>", conf_listen->addresses[0]);
}

static bool h2d_conf_listen_post(void *data)
{
	struct h2d_conf_listen *conf_listen = data;

	if (conf_listen->hosts == NULL) {
		printf("error: No host defined in listen\n");
		return false;
	}

	/* build hostname:conf_host dict */
	conf_listen->host_dict = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct h2d_conf_listen_hostname, name),
			offsetof(struct h2d_conf_listen_hostname, dict_node));

	bool is_ssl = false, is_plain = false;
	struct h2d_conf_host *conf_host;
	for (int i = 0; (conf_host = conf_listen->hosts[i]) != NULL; i++) {
		for (int j = 0; conf_host->hostnames[j] != NULL; j++) {
			if (!h2d_conf_listen_add_hostname(conf_listen, conf_host,
						conf_host->hostnames[j])) {
				return false;
			}
		}

		if (conf_host->ssl.ctx != NULL) {
			is_ssl = true;
		} else {
			is_plain = true;
		}
	}

	/* ssl */
	if (is_ssl) {
		if (is_plain) {
			printf("plain vs ssl\n");
			return false;
		}

		if (conf_listen->host_default != NULL) {
			conf_listen->ssl_ctx = conf_listen->host_default->ssl.ctx;
		} else {
			conf_listen->ssl_ctx = h2d_ssl_ctx_new_server(NULL, NULL);
		}
	}

	return true;
}

static struct wuy_cflua_command h2d_conf_listen_http2_commands[] = {
	{	.name = "idle_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.idle_timeout),
		.default_value.n = 5 * 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "ping_interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.ping_interval),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{ NULL }
};

static struct wuy_cflua_command h2d_conf_listen_http1_commands[] = {
	{	.name = "keepalive_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http1.keepalive_timeout),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{ NULL }
};

static struct wuy_cflua_command h2d_conf_listen_network_commands[] = {
	{	.name = "connections",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.connections),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "recv_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.recv_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "send_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.send_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "send_buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.send_buffer_size),
		.default_value.n = 16 * 1024,
		.limits.n = WUY_CFLUA_LIMITS_LOWER(4 * 1024),
	},
	{ NULL }
};

static struct wuy_cflua_command h2d_conf_listen_commands[] = {
	{	.name = "_addresses",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, addresses),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, hosts),
		.u.table = &h2d_conf_host_table,
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
