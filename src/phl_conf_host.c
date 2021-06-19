#include "phl_main.h"

struct phl_conf_host_search_name {
	const char		*name;
	struct phl_conf_host	*conf_host;
	wuy_dict_node_t		dict_node;
};

static const char *phl_conf_host_add_name(struct phl_conf_listen *conf_listen,
		struct phl_conf_host *conf_host, char *name)
{
	if (name[0] == '\0') {
		return "invalid empty host name";
	}

	/* wildcard hostname */
	if (strcmp(name, "*") == 0) {
		if (conf_listen->host_wildcard != NULL) {
			return "duplicate wildcard host";
		}
		conf_listen->host_wildcard = conf_host;
		return WUY_CFLUA_OK;
	}

	for (int i = 0; name[i] != '\0'; i++) {
		name[i] = tolower(name[i]);
	}

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
				return "leading wildcast `*` must be followed by `.`";
			}
			if (strchr(name + 1, '*') != NULL) {
				return "at most 1 wildcast in hostname";
			}
			conf_listen->any_prefix_hostname = true;
		} else if (wild == name + len - 1) {
			if (name[len-2] != '.') {
				return "the front of tail wildcast `*` must be `.`";
			}
			conf_listen->any_subfix_hostname = true;
		} else {
			return "wildcast `*` is not allowed in middle of hostname";
		}
	}

	if (wuy_dict_get(conf_listen->host_dict, name) != NULL) {
		return "duplicate hostname";
	}

	struct phl_conf_host_search_name *node = wuy_pool_alloc(wuy_cflua_pool,
			sizeof(struct phl_conf_host_search_name));
	node->name = name;
	node->conf_host = conf_host;
	wuy_dict_add(conf_listen->host_dict, node);
	return WUY_CFLUA_OK;
}

const char *phl_conf_host_register(struct phl_conf_listen *conf_listen)
{
	conf_listen->host_dict = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct phl_conf_host_search_name, name),
			offsetof(struct phl_conf_host_search_name, dict_node));

	struct phl_conf_host *conf_host;
	for (int i = 0; (conf_host = conf_listen->hosts[i]) != NULL; i++) {
		for (int j = 0; conf_host->hostnames[j] != NULL; j++) {
			const char *err = phl_conf_host_add_name(conf_listen, conf_host,
						conf_host->hostnames[j]);
			if (err != WUY_CFLUA_OK) {
				wuy_cflua_post_arg = conf_host->hostnames[j];
				return err;
			}
		}
	}
	return WUY_CFLUA_OK;
}

struct phl_conf_host *phl_conf_host_locate(struct phl_conf_listen *conf_listen,
		const char *name)
{
	if (conf_listen->host_dict == NULL) {
		return conf_listen->default_host;
	}

	if (name == NULL) {
		return conf_listen->host_wildcard;
	}

	struct phl_conf_host_search_name *node = wuy_dict_get(conf_listen->host_dict, name);
	if (node != NULL) {
		return node->conf_host;
	}

	int name_len = strlen(name);
	if (conf_listen->any_prefix_hostname) {
		char pre_name[name_len + 1], *p = pre_name;
		strcpy(pre_name, name);
		if (p[0] == '.') {
			p++;
		}
		while ((p = strchr(p, '.')) != NULL) {
			p[-1] = '*';
			node = wuy_dict_get(conf_listen->host_dict, p - 1);
			if (node != NULL) {
				return node->conf_host;
			}
			p++;
		}
	}
	if (conf_listen->any_subfix_hostname) {
		char sub_name[name_len + 1], *p;
		strcpy(sub_name, name);
		if (sub_name[name_len - 1] == '.') {
			sub_name[name_len - 1] = '\0';
		}
		while ((p = strrchr(sub_name, '.')) != NULL) {
			p[1] = '*';
			p[2] = '\0';
			node = wuy_dict_get(conf_listen->host_dict, sub_name);
			if (node != NULL) {
				return node->conf_host;
			}
			p[0] = '\0';
		}
	}

	return conf_listen->host_wildcard;
}

void phl_conf_host_stats(struct phl_conf_host *conf_host, wuy_json_t *json)
{
	struct phl_conf_host_stats *stats = conf_host->stats;
	wuy_json_object_int(json, "fail_no_path", atomic_load(&stats->fail_no_path));
}

static int phl_conf_host_name(void *data, char *buf, int size)
{
	struct phl_conf_host *conf_host = data;
	if (conf_host->hostnames == NULL) {
		return 0;
	}
	return snprintf(buf, size, "Host(%s)>", conf_host->hostnames[0]);
}

bool phl_conf_path_check_overwrite(struct phl_conf_host *conf_host,
		int stop, const char *pathname);
static const char *phl_conf_host_check_path_overwrite(struct phl_conf_host *conf_host)
{
	if (conf_host->paths == NULL) {
		return NULL;
	}

	struct phl_conf_path *conf_path;
	for (int i = 0; (conf_path = conf_host->paths[i]) != NULL; i++) {
		char *pathname;
		for (int j = 0; (pathname = conf_path->pathnames[j]) != NULL; j++) {
			if (phl_conf_path_check_overwrite(conf_host, i, pathname)) {
				return pathname;
			}
		}
	}
	return NULL;
}

static const char *phl_conf_host_post(void *data)
{
	struct phl_conf_host *conf_host = data;

	if (conf_host->paths == NULL /* no Path() */
			&& conf_host->hostnames != NULL /* not default_host */
			&& conf_host->default_path->content == NULL /* default_path->content not set */
			&& !phl_dynamic_is_enabled(&conf_host->default_path->dynamic)) { /* none-dynamic */
		return "no Path defined in Host";
	}

	if (conf_host->name == NULL) {
		conf_host->name = conf_host->hostnames ? conf_host->hostnames[0] : "_default";
	}

	const char *pathname = phl_conf_host_check_path_overwrite(conf_host);
	if (pathname != NULL) {
		wuy_cflua_post_arg = pathname;
		return "Path overwrite";
	}

	conf_host->stats = wuy_shmpool_alloc(sizeof(struct phl_conf_host_stats));

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_conf_host_commands[] = {
	{	.name = "_hostnames",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_conf_host, hostnames),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.type = WUY_CFLUA_TYPE_TABLE,
		.description = "Path scope.",
		.offset = offsetof(struct phl_conf_host, paths),
		.inherit_container_offset = offsetof(struct phl_conf_host, default_path),
		.u.table = &phl_conf_path_table,
	},
	{	.name = "name",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_conf_host, name),
	},
	{	.name = "ssl",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_conf_host, ssl),
		.u.table = &phl_ssl_conf_table,
	},
	{	.type = WUY_CFLUA_TYPE_END,
		.u.next = phl_module_next_host_command,
	},
};

struct wuy_cflua_table phl_conf_host_table = {
	.commands = phl_conf_host_commands,
	.refer_name = "Host",
	.size = sizeof(struct phl_conf_host),
	.post = phl_conf_host_post,
	.name = phl_conf_host_name,
};
