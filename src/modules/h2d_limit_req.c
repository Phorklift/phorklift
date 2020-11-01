#include "h2d_main.h"

#include "libwuya/wuy_meter.h"
#include "libwuya/wuy_murmurhash.h"

struct h2d_limit_req_conf {
	wuy_cflua_function_t	key;
	struct wuy_meter_conf	meter;
	struct h2d_log		*log;
	int			log_mod;

	wuy_dict_t		*dict;
	wuy_list_t		lru_list;
};

struct h2d_limit_req_node {
	uint64_t		key;
	struct wuy_meter_node	meter;
	wuy_dict_node_t		dict_node;
	wuy_list_node_t		list_node;
};

struct h2d_module h2d_limit_req_module;

#define _log(level, fmt, ...) h2d_request_log_at(r, \
		conf->log, level, "limit_req: " fmt, ##__VA_ARGS__)

static uint64_t h2d_limit_req_hash_key(const void *raw_key, int len)
{
	union {
		unsigned char out[16];
		uint64_t ret[2];
	} u;

	wuy_murmurhash(raw_key, len, u.out);
	return u.ret[0] ^ u.ret[1];
}

static void h2d_limit_req_expire(struct h2d_request *r)
{
	struct h2d_limit_req_conf *conf = r->conf_path->module_confs[h2d_limit_req_module.index];

	struct h2d_limit_req_node *node;
	while (wuy_list_first_type(&conf->lru_list, node, list_node)) {
		if (!wuy_meter_is_expired(&conf->meter, &node->meter)) {
			break;
		}

		_log(H2D_LOG_DEBUG, "expire meter. %d", wuy_dict_count(conf->dict));
		wuy_dict_delete(conf->dict, &node->dict_node);
		wuy_list_delete(&node->list_node);
		free(node);
	}
}

static int h2d_limit_req_process_headers(struct h2d_request *r)
{
	struct h2d_limit_req_conf *conf = r->conf_path->module_confs[h2d_limit_req_module.index];

	if (conf->dict == NULL) {
		return H2D_OK;
	}

	int len;
	const void *raw_key;
	if (wuy_cflua_is_function_set(conf->key)) {
		raw_key = h2d_lua_api_call_lstring(r, conf->key, &len);
		if (raw_key == NULL) {
			_log(H2D_LOG_ERROR, "fail in key()");
			return H2D_ERROR;
		}
	} else {
		// TODO ipv6 and unix
		raw_key = &((struct sockaddr_in *)(&r->c->client_addr))->sin_addr;
		len = sizeof(struct in_addr);
	}

	uint64_t key = h2d_limit_req_hash_key(raw_key, len);

	struct h2d_limit_req_node *node = wuy_dict_get(conf->dict, key);

	if (node == NULL) {
		h2d_limit_req_expire(r);

		_log(H2D_LOG_DEBUG, "new meter. %d", wuy_dict_count(conf->dict));
		node = malloc(sizeof(struct h2d_limit_req_node));
		node->key = key;
		wuy_meter_init(&node->meter);
		wuy_dict_add(conf->dict, node);
		wuy_list_insert(&conf->lru_list, &node->list_node);
		return H2D_OK;
	}

	if (wuy_meter_check(&conf->meter, &node->meter)) {
		return H2D_OK;
	}

	_log(H2D_LOG_ERROR, "limited!");
	return WUY_HTTP_503;
}

static bool h2d_limit_req_conf_post(void *data)
{
	struct h2d_limit_req_conf *conf = data;

	if (conf->meter.rate == 0) {
		return true;
	}

	if (conf->meter.burst == 0) {
		conf->meter.burst = conf->meter.rate;
	} else if (conf->meter.burst < conf->meter.rate) {
		printf("limit req burst >= rate\n");
		return false;
	}

	wuy_list_init(&conf->lru_list);
	conf->dict = wuy_dict_new_type(WUY_DICT_KEY_UINT64,
			offsetof(struct h2d_limit_req_node, key),
			offsetof(struct h2d_limit_req_node, dict_node));

	return true;
}

static struct wuy_cflua_command h2d_limit_req_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_INTEGER,
		.is_single_array = true,
		.offset = offsetof(struct h2d_limit_req_conf, meter.rate),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "burst",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_limit_req_conf, meter.burst),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "punish",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_limit_req_conf, meter.punish_sec),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "key",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_limit_req_conf, key),
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_limit_req_conf, log),
		.u.table = &h2d_log_conf_table,
	},
	{ NULL }
};

struct h2d_module h2d_limit_req_module = {
	.name = "limit_req",
	.command_path = {
		.name = "limit_req",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_limit_req_conf_commands,
			.size = sizeof(struct h2d_limit_req_conf),
			.post = h2d_limit_req_conf_post,
		}
	},

	.filters = {
		.process_headers = h2d_limit_req_process_headers,
	},
};
