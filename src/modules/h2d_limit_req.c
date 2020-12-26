#include "h2d_main.h"
#include <pthread.h>

#include "libwuya/wuy_meter.h"
#include "libwuya/wuy_murmurhash.h"

struct h2d_limit_req_node {
	struct wuy_meter_node	meter;
	wuy_nop_hlist_node_t	hash_node;
	wuy_nop_list_node_t	list_node; /* on LRU or free list */
	char			key[0]; /* length=conf->key_max_len */
};

struct h2d_limit_req_shared {
	pthread_mutex_t		lock;
	bool			has_inited;
	wuy_nop_list_t		lru_list;
	wuy_nop_list_t		free_list;

	struct h2d_limit_req_node	*used_pos;
	const struct h2d_limit_req_node	*nodes_end;

	long			stats_total;
	long			stats_limited;

	wuy_nop_hlist_t		hash_buckets[0];
};

struct h2d_limit_req_conf {
	wuy_cflua_function_t	key;
	int			key_max_len;
	struct wuy_meter_conf	meter;
	struct h2d_log		*log;
	int			size;
	int			hash_buckets;
	int			log_mod;

	struct h2d_limit_req_shared	*shared;
};

struct h2d_module h2d_limit_req_module;

#define _log(level, fmt, ...) h2d_request_log_at(r, \
		conf->log, level, "limit_req: " fmt, ##__VA_ARGS__)

static void h2d_limit_req_expire(struct h2d_limit_req_conf *conf)
{
	struct h2d_limit_req_shared *shared = conf->shared;

	struct h2d_limit_req_node *node;
	while (wuy_nop_list_first_type(&shared->lru_list, node, list_node)) {
		if (!wuy_meter_is_expired(&conf->meter, &node->meter)) {
			break;
		}

		wuy_nop_hlist_delete(&node->hash_node, shared);
		wuy_nop_list_delete(&shared->lru_list, &node->list_node);
		wuy_nop_list_append(&shared->free_list, &node->list_node);
	}
}

static struct h2d_limit_req_node *h2d_limit_req_alloc_node(struct h2d_limit_req_conf *conf)
{
	h2d_limit_req_expire(conf);

	struct h2d_limit_req_shared *shared = conf->shared;

	/* reuse freed node */
	struct h2d_limit_req_node *node;
	wuy_nop_list_pop_type(&shared->free_list, node, list_node);
	if (node != NULL) {
		return node;
	}

	/* allocate new node */
	if (shared->used_pos < shared->nodes_end) {
		node = shared->used_pos++;
		shared->used_pos = (void *)((char *)shared->used_pos + conf->key_max_len);
		return node;
	}

	/* LRU list */
	wuy_nop_list_pop_type(&shared->lru_list, node, list_node);
	wuy_nop_hlist_delete(&node->hash_node, shared);
	wuy_nop_list_delete(&shared->lru_list, &node->list_node);
	return node;
}

static int h2d_limit_req_process_headers(struct h2d_request *r)
{
	struct h2d_limit_req_conf *conf = r->conf_path->module_confs[h2d_limit_req_module.index];
	struct h2d_limit_req_shared *shared = conf->shared;

	if (shared == NULL) {
		return H2D_OK;
	}

	/* generate key */
	int len;
	const void *key;
	if (wuy_cflua_is_function_set(conf->key)) {
		key = h2d_lua_api_call_lstring(r, conf->key, &len);
		if (key == NULL) {
			_log(H2D_LOG_ERROR, "fail in key()");
			return H2D_ERROR;
		}
	} else {
		// TODO ipv6
		key = &((struct sockaddr_in *)(&r->c->client_addr))->sin_addr;
		len = sizeof(struct in_addr);
	}

	if (len >= conf->key_max_len) {
		_log(H2D_LOG_ERROR, "too long key!");
		return H2D_ERROR;
	}

	/* hash search */
	uint64_t hash = wuy_murmurhash_id(key, len) % conf->hash_buckets;
	wuy_nop_hlist_t *bucket = &shared->hash_buckets[hash];

	pthread_mutex_lock(&shared->lock); /* lock here */
	shared->stats_total++;

	bool found = false;
	struct h2d_limit_req_node *node;
	wuy_nop_hlist_iter_type(bucket, node, hash_node, shared) {
		if (strcmp(node->key, key) == 0) {
			found = true;
			break;
		}
	}

	/* not found, create new meter */
	if (!found) {
		_log(H2D_LOG_DEBUG, "new meter. %d", shared->stats_total);

		node = h2d_limit_req_alloc_node(conf);
		strcpy(node->key, key);
		wuy_meter_init(&node->meter);
		wuy_nop_hlist_insert(bucket, &node->hash_node, shared);
		wuy_nop_list_insert(&shared->lru_list, &node->list_node);

	/* found and limited */
	} else if (!wuy_meter_check(&conf->meter, &node->meter)) {

		shared->stats_limited++;
		pthread_mutex_unlock(&shared->lock); /* unlock here */
		_log(H2D_LOG_INFO, "limited!");
		return WUY_HTTP_503;
	}

	pthread_mutex_unlock(&shared->lock); /* unlock here */
	return H2D_OK;
}

static const char *h2d_limit_req_conf_post(void *data)
{
	struct h2d_limit_req_conf *conf = data;

	if (conf->meter.rate == 0) {
		return WUY_CFLUA_OK;
	}

	if (conf->meter.burst == 0) {
		conf->meter.burst = conf->meter.rate;
	} else if (conf->meter.burst < conf->meter.rate) {
		return "expect burst >= rate";
	}

	conf->shared = wuy_shmpool_alloc(conf->size);

	//pthread_mutex_lock(&h2d_limit_req_conf_lock);
	if (!conf->shared->has_inited) {
		struct h2d_limit_req_shared *shared = conf->shared;

		shared->has_inited = true;

		shared->used_pos = (void *)((char *)shared + sizeof(wuy_nop_hlist_t) * conf->hash_buckets);
		shared->nodes_end = (void *)((char *)shared + conf->size
				- (sizeof(struct h2d_limit_req_node) + conf->key_max_len));

		if (shared->nodes_end <= shared->used_pos) {
			//pthread_mutex_unlock(&h2d_limit_req_conf_lock);
			return "too small size";
		}

		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_setpshared(&attr, 1);
		pthread_mutex_init(&shared->lock, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	//pthread_mutex_unlock(&h2d_limit_req_conf_lock);

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_limit_req_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_INTEGER,
		.description = "Limit rate per second.",
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
		.description = "Deny for such long time if limited.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_limit_req_conf, meter.punish_sec),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "key",
		.description = "Return a string key. Client IP address is used if not set.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_limit_req_conf, key),
	},
	{	.name = "key_max_len",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_limit_req_conf, key_max_len),
		.default_value.n = 40, /* UUID=36, IPv6=39 */
		.limits.n = WUY_CFLUA_LIMITS(8, 255),
	},
	{	.name = "size",
		.description = "Size of shared-memory.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_limit_req_conf, size),
		.default_value.n = 1024*1024, /* 1 MiB*/
		.limits.n = WUY_CFLUA_LIMITS_LOWER(16*1024),
	},
	{	.name = "hash_buckets",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_limit_req_conf, hash_buckets),
		.default_value.n = 1024,
		.limits.n = WUY_CFLUA_LIMITS_LOWER(64),
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
		.description = "Request rate limit filter module.",
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
