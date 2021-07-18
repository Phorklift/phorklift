#include "phl_main.h"
#include <pthread.h>

#include "libwuya/wuy_meter.h"

struct phl_limit_req_node {
	struct wuy_meter_node	meter;
	wuy_nop_hlist_node_t	hash_node;
	wuy_nop_list_node_t	list_node; /* on LRU or free list */
	char			key[0]; /* length=conf->key_max_len */
};

struct phl_limit_req_shared {
	pthread_mutex_t		lock;
	bool			has_inited;
	wuy_nop_list_t		lru_list;
	wuy_nop_list_t		free_list;

	struct phl_limit_req_node	*nodes_begin;
	const struct phl_limit_req_node	*nodes_end;

	long			stats_total;
	long			stats_limited;

	int			hash_bucket_size;
	wuy_nop_hlist_t		hash_buckets[0];
};

struct phl_limit_req_conf {
	wuy_cflua_function_t	key;
	int			key_max_len;
	struct wuy_meter_conf	meter;
	struct phl_log		*log;
	int			size;

	bool			add_headers;
	int			status_code;
	int			page_len;
	const char		*page;

	struct phl_limit_req_shared	*shared;
};

struct phl_module phl_limit_req_module;

#define _log(level, fmt, ...) phl_request_log_at(r, \
		conf->log, level, "limit_req: " fmt, ##__VA_ARGS__)

static void phl_limit_req_expire(struct phl_limit_req_conf *conf)
{
	struct phl_limit_req_shared *shared = conf->shared;

	double now = wuy_meter_now();
	double expire = conf->meter.burst / conf->meter.rate;

	struct phl_limit_req_node *node;
	while (wuy_nop_list_first_type(&shared->lru_list, node, list_node)) {
		if (now - node->meter.reset < expire) {
			break;
		}

		wuy_nop_hlist_delete(&node->hash_node, shared);
		wuy_nop_list_delete(&shared->lru_list, &node->list_node);
		wuy_nop_list_append(&shared->free_list, &node->list_node);
	}
}

static struct phl_limit_req_node *phl_limit_req_alloc_node(struct phl_limit_req_conf *conf)
{
	phl_limit_req_expire(conf);

	struct phl_limit_req_shared *shared = conf->shared;

	/* reuse freed node */
	struct phl_limit_req_node *node;
	wuy_nop_list_pop_type(&shared->free_list, node, list_node);
	if (node != NULL) {
		return node;
	}

	/* allocate new node */
	if (shared->nodes_begin < shared->nodes_end) {
		node = shared->nodes_begin++;
		shared->nodes_begin = (void *)((char *)shared->nodes_begin + conf->key_max_len);
		return node;
	}

	/* LRU list */
	wuy_nop_list_pop_type(&shared->lru_list, node, list_node);
	wuy_nop_hlist_delete(&node->hash_node, shared);
	wuy_nop_list_delete(&shared->lru_list, &node->list_node);
	return node;
}

static int phl_limit_req_process_headers(struct phl_request *r)
{
	struct phl_limit_req_conf *conf = r->conf_path->module_confs[phl_limit_req_module.index];
	struct phl_limit_req_shared *shared = conf->shared;

	if (shared == NULL) {
		return PHL_OK;
	}

	/* generate key */
	int len;
	const void *key;
	float weight = 1;
	if (wuy_cflua_is_function_set(conf->key)) {
		lua_State *L = phl_lua_thread_run(r, conf->key, NULL);
		if (!PHL_PTR_IS_OK(L)) {
			return PHL_PTR2RET(L);
		}

		key = lua_tostring(L, 1);
		if (key == NULL) {
			_log(PHL_LOG_ERROR, "fail in key()");
			return PHL_ERROR;
		}

		/* optional weigth */
		if (lua_gettop(L) == 2) {
			if (!lua_isnumber(L, 2)) {
				_log(PHL_LOG_ERROR, "invalid weight");
				return PHL_ERROR;
			}
			weight = lua_tonumber(L, 2);
		}

	} else {
		// TODO ipv6
		key = &((struct sockaddr_in *)(&r->c->client_addr))->sin_addr;
		len = sizeof(struct in_addr);
	}

	if (len >= conf->key_max_len) {
		_log(PHL_LOG_ERROR, "too long key!");
		return PHL_ERROR;
	}

	/* hash search */
	uint64_t hash = wuy_vhash64(key, len) % shared->hash_bucket_size;
	wuy_nop_hlist_t *bucket = &shared->hash_buckets[hash];

	pthread_mutex_lock(&shared->lock); /* lock here */
	shared->stats_total++;

	bool found = false;
	struct phl_limit_req_node *node;
	wuy_nop_hlist_iter_type(bucket, node, hash_node, shared) {
		if (memcmp(node->key, key, len) == 0 && node->key[len] == '\0') {
			found = true;
			break;
		}
	}

	if (!found) { /* not found, create new meter */
		_log(PHL_LOG_DEBUG, "new meter. %d", shared->stats_total);

		node = phl_limit_req_alloc_node(conf);
		memcpy(node->key, key, len);
		node->key[len] = '\0';
		bzero(&node->meter, sizeof(struct wuy_meter_node));
		wuy_nop_hlist_insert(bucket, &node->hash_node, shared);

		wuy_nop_list_append(&shared->lru_list, &node->list_node);
	} else {
		wuy_nop_list_delete(&shared->lru_list, &node->list_node);
		wuy_nop_list_append(&shared->lru_list, &node->list_node);
	}

	bool ok = wuy_meter_check(&conf->meter, &node->meter, weight);
	if (!ok) {
		shared->stats_limited++;
	}

	pthread_mutex_unlock(&shared->lock);

	if (conf->add_headers) {
		char buf[20];
		int len = sprintf(buf, "%g", conf->meter.rate);
		phl_header_add_lite(&r->resp.headers, "X-RateLimit-Limit", buf, len, r->pool);

		len = sprintf(buf, "%d", (int)node->meter.tokens);
		phl_header_add_lite(&r->resp.headers, "X-RateLimit-Remaining", buf, len, r->pool);

		len = sprintf(buf, "%ld", (long)node->meter.reset);
		phl_header_add_lite(&r->resp.headers, "X-RateLimit-Reset", buf, len, r->pool);
	}

	if (ok) {
		return PHL_OK;
	}

	/* limited */
	_log(PHL_LOG_INFO, "limited!");

	if (conf->page != NULL) {
		r->resp.easy_string = conf->page;
		r->resp.content_length = conf->page_len;
	}
	return conf->status_code;
}

static const char *phl_limit_req_conf_post(void *data)
{
	struct phl_limit_req_conf *conf = data;

	if (conf->meter.rate == 0) {
		return WUY_CFLUA_OK;
	}

	if (conf->meter.burst == 0) {
		conf->meter.burst = conf->meter.rate;
	} else if (conf->meter.burst < conf->meter.rate) {
		return "expect burst >= rate";
	}

	conf->shared = wuy_shmpool_alloc(conf->size);

	//pthread_mutex_lock(&phl_limit_req_conf_lock);
	if (!conf->shared->has_inited) {
		struct phl_limit_req_shared *shared = conf->shared;

		shared->has_inited = true;

		/* calculate shared->hash_bucket_size */
		size_t node_size = sizeof(struct phl_limit_req_node) + conf->key_max_len;
		shared->hash_bucket_size = conf->size / node_size / 4;

		/* calculate shared->nodes_begin/nodes_end */
		shared->nodes_begin = (void *)((char *)(shared + 1) + sizeof(wuy_nop_hlist_t) * shared->hash_bucket_size);
		shared->nodes_end = (void *)((char *)shared + conf->size - node_size);

		if (shared->nodes_end <= shared->nodes_begin) {
			//pthread_mutex_unlock(&phl_limit_req_conf_lock);
			return "too small size";
		}

		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_setpshared(&attr, 1);
		pthread_mutex_init(&shared->lock, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	//pthread_mutex_unlock(&phl_limit_req_conf_lock);

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_limit_req_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_FLOAT,
		.is_single_array = true,
		.offset = offsetof(struct phl_limit_req_conf, meter.rate),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
		.description = "Limit rate per second.",
	},
	{	.name = "burst",
		.type = WUY_CFLUA_TYPE_FLOAT,
		.offset = offsetof(struct phl_limit_req_conf, meter.burst),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
		.description = "Burst rate per second.",
	},
	{	.name = "key",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_limit_req_conf, key),
		.description = "Return a string key and optional weight. Client IP address is used if not set.",
	},
	{	.name = "key_max_len",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_limit_req_conf, key_max_len),
		.default_value.n = 40, /* UUID=36, IPv6=39 */
		.limits.n = WUY_CFLUA_LIMITS(8, 127),
	},
	{	.name = "size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_limit_req_conf, size),
		.default_value.n = 64*1024, /* 64K */
		.limits.n = WUY_CFLUA_LIMITS_LOWER(16*1024),
		.description = "Size of shared-memory.",
	},
	{	.name = "add_headers",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_limit_req_conf, add_headers),
		.default_value.n = true,
		.description = "Add `X-RateLimit-*` response headers."
	},
	{	.name = "status_code",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_limit_req_conf, status_code),
		.default_value.n = WUY_HTTP_503,
		.limits.n = WUY_CFLUA_LIMITS(WUY_HTTP_200, 599),
	},
	{	.name = "page",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_limit_req_conf, page),
		.u.length_offset = offsetof(struct phl_limit_req_conf, page_len),
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_limit_req_conf, log),
		.u.table = &phl_log_omit_conf_table,
	},
	{ NULL }
};

struct phl_module phl_limit_req_module = {
	.name = "limit_req",
	.command_path = {
		.name = "limit_req",
		.description = "Request rate limit filter module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_limit_req_conf_commands,
			.size = sizeof(struct phl_limit_req_conf),
			.post = phl_limit_req_conf_post,
		}
	},

	.filters = {
		.process_headers = phl_limit_req_process_headers,
	},
};
