#include <openssl/ssl.h>

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
	if (name == NULL || name[0] == '\0') {
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

static bool h2d_conf_listen_post(void *data)
{
	struct h2d_conf_listen *conf_listen = data;

	if (wuy_array_count(&conf_listen->hosts) == 0) {
		printf("error: No host defined in listen\n");
		return false;
	}

	/* build hostname:conf_host dict */
	conf_listen->host_dict = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct h2d_conf_listen_hostname, name),
			offsetof(struct h2d_conf_listen_hostname, dict_node));

	int ssl_count = 0;
	struct h2d_conf_host *conf_host;
	wuy_array_iter_ppval(&conf_listen->hosts, conf_host) {
		char *hostname;
		wuy_array_iter_ppval(&conf_host->hostnames, hostname) {
			if (!h2d_conf_listen_add_hostname(conf_listen, conf_host, hostname)) {
				return false;
			}
		}

		if (conf_host->ssl.ctx != NULL) {
			ssl_count++;
		}
	}

	/* ssl */
	if (ssl_count > 0) {
		if (ssl_count != wuy_array_count(&conf_listen->hosts)) {
			printf("plain vs ssl\n");
			return false;
		}

		if (conf_listen->host_default != NULL) {
			conf_listen->ssl_ctx = conf_listen->host_default->ssl.ctx;
		} else {
			conf_listen->ssl_ctx = h2d_ssl_ctx_new(NULL, NULL);
		}
	}

	return true;
}

static struct wuy_cflua_command h2d_conf_listen_http2_commands[] = {
	{	.name = "keepalive_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.keepalive_timeout),
	},
	{	.name = "ping_interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, http2.ping_interval),
	},
	{ NULL }
};

static struct wuy_cflua_command h2d_conf_listen_network_commands[] = {
	{	.name = "connections",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.connections),
	},
	{	.name = "write_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.write_timeout),
	},
	{	.name = "read_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_conf_listen, network.read_timeout),
	},
	{ NULL }
};

static struct wuy_cflua_command h2d_conf_listen_commands[] = {
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, hosts),
		.u.table = &h2d_conf_host_table,
	},
	{	.name = "_addresses",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, addresses),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.name = "http2",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, http2),
		.u.table = &(struct wuy_cflua_table) { h2d_conf_listen_http2_commands },
	},
	{	.name = "network",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_listen, network),
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
};
